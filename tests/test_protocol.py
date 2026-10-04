"""Local fake-device tests. No access to a real purifier or cloud account."""
import asyncio
from contextlib import suppress
import hashlib
import hmac
import importlib.util
import json
import sys
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

spec = importlib.util.spec_from_file_location(
    "local_protocol_tests", Path(__file__).parents[1] / "custom_components/sharp_life_air_local/protocol.py"
)
p = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = p
spec.loader.exec_module(p)

diag_spec = importlib.util.spec_from_file_location(
    "local_diagnostics_tests", Path(__file__).parents[1] / "custom_components/sharp_life_air_local/diagnostics.py"
)
diagnostics = importlib.util.module_from_spec(diag_spec)
diag_spec.loader.exec_module(diagnostics)


def response(request, properties, esv=0x72, *, tid=None):
    frame = bytearray(b"\x10\x81" + (request.tid if tid is None else tid).to_bytes(2, "big")
                      + request.destination + request.source + bytes((esv, len(properties))))
    for code, value in properties.items():
        frame.extend((code, len(value)))
        frame.extend(value)
    return bytes(frame)


class FakePurifier(asyncio.DatagramProtocol):
    def __init__(self, *, writable=True, reject=False, wrong_first=False,
                 drop_maps=False, partial_maps=False, drop_batch=False,
                 ignore_write=False):
        self.writable = writable
        self.reject = reject
        self.wrong_first = wrong_first
        self.drop_maps = drop_maps
        self.partial_maps = partial_maps
        self.drop_batch = drop_batch
        self.ignore_write = ignore_write
        self.received = []
        self.object_id = bytes.fromhex("013502")
        self.power = b"\x30"

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        request = p.decode_frame(data)
        self.received.append(request)
        if request.destination == p.NODE:
            props = {0xD6: b"\x01" + self.object_id, 0x8C: b"test-module"}
        elif 0x8A in request.properties:
            props = {0x8A: b"\x00\x00\x05", 0x8C: b"test-purifier",
                     0xF0: b"", 0xFC: b"", 0xFD: b""}
        elif request.esv == 0x61:
            if not self.reject and not self.ignore_write:
                self.power = request.properties[0x80]
            self.transport.sendto(response(request, {0x80: b""}, 0x51 if self.reject else 0x71), address)
            return
        elif 0x9E in request.properties:
            if self.drop_maps:
                return
            if self.partial_maps:
                self.transport.sendto(response(request, {0x9F: b"\x01\x80"}, 0x52), address)
                return
            props = {0x9E: b"\x01\x80" if self.writable else b"\x00",
                     0x9F: b"\x03\x80\x84\xf1"}
        else:
            if self.drop_batch and len(request.properties) > 1:
                return
            props = {0x80: self.power, 0x84: b"\x00\x09", 0xF1: b"\x00\x00\x00\x17\x2d"}
        if self.wrong_first:
            self.transport.sendto(response(request, props, tid=(request.tid + 1) & 0xFFFF), address)
        self.transport.sendto(response(request, props), address)


class ParserTests(unittest.TestCase):
    def test_exact_official_discovery_frame(self):
        self.assertEqual(p.encode_frame(1, p.NODE, 0x62, {0xD6: b"", 0x8C: b""}).hex(),
                         "1081000105fe010ef0016202d6008c00")

    def test_empty_and_truncated_values(self):
        frame = p.encode_frame(1, p.NODE, 0x62, {0x80: b""})
        self.assertEqual(p.decode_frame(frame).properties, {0x80: b""})
        self.assertEqual(p.decode_readings({0x80: b"", 0xF1: b""}), {})
        for malformed in (frame[:-1], frame + b"\x00", b"\x10", bytes(12)):
            with self.assertRaises(p.ProtocolError):
                p.decode_frame(malformed)

    def test_property_maps_and_bitmap_orientation(self):
        self.assertEqual(p.property_map(b"\x02\x80\xf3"), {0x80, 0xF3})
        # 16 bits, high nibble represented by bit, low nibble by byte position.
        self.assertEqual(p.property_map(b"\x10" + bytes([1] * 16)), set(range(0x80, 0x90)))
        bitmap = bytearray([1] * 16)
        bitmap[3] = 0x80
        self.assertIn(0xF3, p.property_map(b"\x10" + bitmap))
        with self.assertRaises(p.ProtocolError):
            p.property_map(b"\x02\x80")
        with self.assertRaises(p.ProtocolError):
            p.property_map(b"\x11" + bytes([1] * 16))

    def test_sensor_reading_sizes_and_unknown_states(self):
        self.assertEqual(p.decode_readings({0x80: b"\x30", 0x84: b"\x00\x09",
                                           0xF1: b"\x00\x00\x00\x17\x2d"}),
                         {"power": "on", "power_watts": 9, "temperature_c": 23, "humidity_pct": 45})
        self.assertEqual(p.decode_readings({0x80: b"\x99", 0x84: b"\xff\xff"}), {})


class TcpTests(unittest.IsolatedAsyncioTestCase):
    async def serve(self, *, tamper=False, wrong_command=False, truncate=False, length=None):
        async def handler(reader, writer):
            try:
                self.assertEqual(await reader.readexactly(8), bytes(8))
                nonce = bytes(range(16))
                hello = nonce + hashlib.md5(nonce).digest()
                for part in (hello[:1], hello[1:17], hello[17:]):
                    writer.write(part)
                    await writer.drain()
                    await asyncio.sleep(0)
                request = await reader.readexactly(36)
                self.assertEqual(request[:2], b"\x00\x24")
                self.assertEqual(request[34:], b"\x00\x02")
                self.assertEqual(request[2:34], hmac.digest(p.protocol_key(), nonce + request[34:], "sha256"))
                payload = (b"\x80\x03" if wrong_command else b"\x80\x02") + b"\x01\x00\x00\x01\x00\x00"
                payload += b"S" * 256 + bytes.fromhex("010203040506") + bytes(5)
                signature = hmac.digest(p.protocol_key(), nonce + payload, "sha256")
                if tamper:
                    signature = bytes(32)
                data = (len(payload) + 34 if length is None else length).to_bytes(2, "big") + signature + payload
                if truncate:
                    data = data[:20]
                for start in range(0, len(data), 7):
                    writer.write(data[start:start + 7])
                    await writer.drain()
                    await asyncio.sleep(0)
            except (ConnectionError, asyncio.IncompleteReadError):
                pass
            finally:
                writer.close()
                with suppress(ConnectionError):
                    await writer.wait_closed()
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        self.addAsyncCleanup(server.wait_closed)
        self.addCleanup(server.close)
        return server.sockets[0].getsockname()[1]

    async def test_fragmented_signed_get_info_and_secret_omission(self):
        port = await self.serve()
        info = await p.get_info("127.0.0.1", port)
        self.assertEqual(info.version, "1.0.1")
        self.assertEqual(info.flags, 0)
        self.assertEqual(info.mac, "010203040506")
        self.assertNotIn(info.mac, repr(info))
        self.assertNotIn("SSSS", repr(info))

    async def test_invalid_signature_command_length_and_truncation(self):
        for options in ({"tamper": True}, {"wrong_command": True}, {"length": 5000}, {"truncate": True}):
            with self.subTest(options=options):
                port = await self.serve(**options)
                with self.assertRaises(p.ProtocolError):
                    await p.get_info("127.0.0.1", port)


class DiagnosticTests(unittest.IsolatedAsyncioTestCase):
    async def test_export_excludes_identity_ip_and_raw_property_values(self):
        state = p.LocalState(p.ModuleInfo("1.0.1", 0, "010203040506"), "read_only",
            b"\x01\x35\x01", {0xF0: b"PRIVATE-VENDOR-DATA", 0x80: b"\x30"},
            udp_diagnostics={"stage": "complete", "received": 3})
        coordinator = SimpleNamespace(data=state, last_update_success=True,
                                     readings=p.decode_readings(state.properties))
        entry = SimpleNamespace(runtime_data=coordinator, data={"host": "192.168.1.32"})
        result = await diagnostics.async_get_config_entry_diagnostics(None, entry)
        encoded = json.dumps(result)
        for secret in ("010203040506", "PRIVATE-VENDOR-DATA", "192.168.1.32"):
            self.assertNotIn(secret, encoded)
        self.assertEqual(result["readings"], {"power": "on"})
        self.assertEqual(result["udp_diagnostics"]["stage"], "complete")


class UdpTests(unittest.IsolatedAsyncioTestCase):
    async def channel(self, **options):
        fake = FakePurifier(**options)
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: fake, local_addr=("127.0.0.1", 0))
        self.addCleanup(transport.close)
        port = transport.get_extra_info("sockname")[1]
        return p.EchonetChannel("127.0.0.1", port=port, bind_port=0, timeout=0.1), fake

    async def test_discovers_actual_instance_and_ignores_other_transaction(self):
        channel, fake = await self.channel(wrong_first=True)
        async with channel:
            object_id, writable, readings = await channel.discover()
        self.assertEqual(object_id, bytes.fromhex("013502"))
        self.assertEqual(writable, {0x80})
        self.assertEqual(p.decode_readings(readings)["power_watts"], 9)
        self.assertTrue(all(frame.esv == 0x62 for frame in fake.received))
        self.assertEqual(list(fake.received[1].properties), [0x8A, 0x8C, 0xF0, 0xFC, 0xFD])

    async def test_read_only_device_has_no_writable_power(self):
        channel, _ = await self.channel(writable=False)
        async with channel:
            object_id, writable, readings = await channel.discover()
        state = p.LocalState(p.ModuleInfo("1.0.1", 0, "fake"), "read_only", object_id, readings, writable)
        self.assertFalse(state.power_controllable)

    async def test_acknowledged_power_write_uses_discovered_instance(self):
        channel, fake = await self.channel()
        async with channel:
            object_id, _, _ = await channel.discover()
            await channel.request(object_id, {0x80: b"\x31"}, esv=0x61)
        self.assertEqual(fake.power, b"\x31")
        self.assertEqual(fake.received[-1].destination, bytes.fromhex("013502"))

    async def test_rejected_write_raises(self):
        channel, fake = await self.channel(reject=True)
        async with channel:
            with self.assertRaises(p.ProtocolError):
                await channel.request(fake.object_id, {0x80: b"\x31"}, esv=0x61)

    async def test_broadcast_fallback_then_real_device_reads(self):
        channel, fake = await self.channel()
        original = channel.request
        calls = []

        async def request(destination, properties, **kwargs):
            calls.append(kwargs.get("target"))
            if len(calls) == 1:
                raise TimeoutError()
            return await original(destination, properties, **kwargs)

        with patch.object(channel, "request", side_effect=request):
            async with channel:
                object_id, writable, readings = await channel.discover(broadcast="127.0.0.1")
        self.assertEqual(calls[:2], ["127.0.0.1", "127.0.0.1"])
        self.assertEqual(channel.diagnostics["discovery_method"], "broadcast")
        self.assertEqual(object_id, fake.object_id)
        self.assertEqual(readings[0x80], b"\x30")
        self.assertEqual(writable, {0x80})

    async def test_missing_maps_and_dropped_batch_still_reads_power(self):
        channel, fake = await self.channel(drop_maps=True, drop_batch=True)
        async with channel:
            object_id, writable, readings = await channel.discover()
        self.assertEqual(object_id, fake.object_id)
        self.assertEqual(writable, set())
        self.assertEqual(readings[0x80], b"\x30")
        self.assertTrue(channel.diagnostics["map_timeout"])
        self.assertTrue(channel.diagnostics["readings_timeout"])
        self.assertFalse(any(frame.esv == 0x61 for frame in fake.received))

    async def test_partial_get_sna_map_is_accepted_as_read_only(self):
        channel, fake = await self.channel(partial_maps=True)
        async with channel:
            object_id, writable, readings = await channel.discover()
        self.assertEqual(object_id, fake.object_id)
        self.assertFalse(writable)
        self.assertEqual(readings[0x80], b"\x30")
        self.assertEqual(channel.diagnostics["readable_codes"], ["80"])

    async def test_power_capability_also_requires_valid_readback(self):
        for properties in ({}, {0x80: b""}, {0x80: b"\x99"}):
            state = p.LocalState(p.ModuleInfo("1.0.1", 0, "fake"), "read_only",
                                 b"\x01\x35\x01", properties, frozenset({0x80}))
            self.assertFalse(state.power_controllable)

    async def test_client_checks_power_readback_without_repeating_write(self):
        for ignore_write in (False, True):
            with self.subTest(ignore_write=ignore_write):
                channel, fake = await self.channel(ignore_write=ignore_write)
                client = p.SharpLocalClient("127.0.0.1")
                client.state = p.LocalState(p.ModuleInfo("1.0.1", 0, "fake"),
                    "power_control_available", fake.object_id, {0x80: b"\x30"}, frozenset({0x80}))
                with patch.object(client, "_channel", return_value=channel):
                    if ignore_write:
                        with self.assertRaises(p.ProtocolError):
                            await client.set_power(False)
                    else:
                        await client.set_power(False)
                writes = [frame for frame in fake.received if frame.esv == 0x61]
                self.assertEqual(len(writes), 1)
                self.assertTrue(any(frame.esv == 0x62 for frame in fake.received))

    async def test_no_udp_capability_prevents_opening_control_socket(self):
        client = p.SharpLocalClient("127.0.0.1")
        with patch.object(client, "_channel") as open_channel:
            with self.assertRaises(p.ProtocolError):
                await client.set_power(False)
            open_channel.assert_not_called()

    async def test_udp_failure_preserves_tcp_diagnostics(self):
        client = p.SharpLocalClient("127.0.0.1", bind_port=0)
        channel = AsyncMock()
        channel.__aenter__.return_value = channel
        channel.discover.side_effect = TimeoutError()
        channel.diagnostics = {"stage": "discovery", "received": 0}
        info = p.ModuleInfo("1.0.1", 0, "fake")
        with patch.object(p, "get_info", new=AsyncMock(return_value=info)), patch.object(client, "_channel", return_value=channel):
            state = await client.update()
        self.assertEqual(state.module.version, "1.0.1")
        self.assertEqual(state.udp_status, "no_response")
        self.assertFalse(state.power_controllable)
        self.assertEqual(state.udp_diagnostics["stage"], "discovery")


if __name__ == "__main__":
    unittest.main()
