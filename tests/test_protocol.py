"""Local fake-device tests. No access to a real purifier or cloud account."""
import asyncio
from contextlib import suppress
import hashlib
import hmac
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

spec = importlib.util.spec_from_file_location(
    "local_protocol_tests", Path(__file__).parents[1] / "custom_components/sharp_life_air_local/protocol.py"
)
p = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = p
spec.loader.exec_module(p)


def response(request, properties, esv=0x72, *, tid=None):
    frame = bytearray(b"\x10\x81" + (request.tid if tid is None else tid).to_bytes(2, "big")
                      + request.destination + request.source + bytes((esv, len(properties))))
    for code, value in properties.items():
        frame.extend((code, len(value)))
        frame.extend(value)
    return bytes(frame)


class FakePurifier(asyncio.DatagramProtocol):
    def __init__(self, *, writable=True, reject=False, wrong_first=False):
        self.writable = writable
        self.reject = reject
        self.wrong_first = wrong_first
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
        elif request.esv == 0x61:
            if not self.reject:
                self.power = request.properties[0x80]
            self.transport.sendto(response(request, {0x80: b""}, 0x51 if self.reject else 0x71), address)
            return
        elif 0x9E in request.properties:
            props = {0x9E: b"\x01\x80" if self.writable else b"\x00",
                     0x9F: b"\x03\x80\x84\xf1"}
        else:
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
        info = p.ModuleInfo("1.0.1", 0, "fake")
        with patch.object(p, "get_info", new=AsyncMock(return_value=info)), patch.object(client, "_channel", return_value=channel):
            state = await client.update()
        self.assertEqual(state.module.version, "1.0.1")
        self.assertEqual(state.udp_status, "no_response")
        self.assertFalse(state.power_controllable)


if __name__ == "__main__":
    unittest.main()
