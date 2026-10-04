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


def response(request, properties, esv=0x72, *, tid=None, destination=None):
    frame = bytearray(b"\x10\x81" + (request.tid if tid is None else tid).to_bytes(2, "big")
                      + request.destination + (destination or request.source) + bytes((esv, len(properties))))
    for code, value in properties.items():
        frame.extend((code, len(value)))
        frame.extend(value)
    return bytes(frame)


class FakePurifier(asyncio.DatagramProtocol):
    def __init__(self, *, writable=True, reject=False, wrong_first=False,
                 drop_maps=False, partial_maps=False, drop_batch=False,
                 ignore_write=False, empty_batch_esv=None, partial_batch=False,
                 empty_all_readings=False, source=None, reply_port=None,
                 wrong_destination=False, drop_read_codes=(), state_source=None,
                 writable_by_source=None, drop_maps_source=None):
        self.writable = writable
        self.reject = reject
        self.wrong_first = wrong_first
        self.drop_maps = drop_maps
        self.partial_maps = partial_maps
        self.drop_batch = drop_batch
        self.ignore_write = ignore_write
        self.empty_batch_esv = empty_batch_esv
        self.partial_batch = partial_batch
        self.empty_all_readings = empty_all_readings
        self.source = source
        self.reply_port = reply_port
        self.wrong_destination = wrong_destination
        self.drop_read_codes = drop_read_codes
        self.state_source = state_source
        self.writable_by_source = writable_by_source or {}
        self.drop_maps_source = drop_maps_source
        self.received = []
        self.object_id = bytes.fromhex("013502")
        self.power = b"\x30"

    def connection_made(self, transport):
        self.transport = transport

    def send(self, packet, address):
        if self.wrong_destination:
            packet = packet[:7] + bytes.fromhex("05aa01") + packet[10:]
        target = (address[0], self.reply_port) if self.reply_port else address
        self.transport.sendto(packet, target)

    def datagram_received(self, data, address):
        request = p.decode_frame(data)
        self.received.append(request)
        if self.source is not None and request.source != self.source:
            return
        state_allowed = self.state_source is None or request.source == self.state_source
        if request.destination == p.NODE:
            props = {0xD6: b"\x01" + self.object_id, 0x8C: b"test-module"}
        elif 0x8A in request.properties:
            props = {0x8A: b"\x00\x00\x05", 0x8C: b"test-purifier",
                     0xF0: b"", 0xFC: b"", 0xFD: b""}
        elif request.esv == 0x61:
            rejected = self.reject or not state_allowed
            if not rejected and not self.ignore_write:
                self.power = request.properties[0x80]
            self.send(response(request, {0x80: b""}, 0x51 if rejected else 0x71), address)
            return
        elif 0x9E in request.properties:
            if self.drop_maps or request.source == self.drop_maps_source:
                return
            if self.partial_maps:
                self.send(response(request, {0x9F: b"\x01\x80"}, 0x52), address)
                return
            writable = self.writable_by_source.get(request.source, self.writable)
            props = {0x9E: b"\x01\x80" if writable else b"\x00",
                     0x9F: b"\x03\x80\x84\xf1"}
        else:
            if len(request.properties) == 1 and next(iter(request.properties)) in self.drop_read_codes:
                return
            if (not state_allowed or self.empty_all_readings
                    or (self.empty_batch_esv is not None and len(request.properties) > 1)):
                props = {code: b"" for code in request.properties}
                self.send(response(request, props, self.empty_batch_esv or 0x52), address)
                return
            if self.partial_batch and len(request.properties) > 1:
                self.send(response(request, {0x80: self.power, 0x84: b"", 0xF1: b""}, 0x52), address)
                return
            if self.drop_batch and len(request.properties) > 1:
                return
            props = {0x80: self.power, 0x84: b"\x00\x09", 0xF1: b"\x00\x00\x00\x17\x2d"}
        if self.wrong_first:
            self.send(response(request, props, tid=(request.tid + 1) & 0xFFFF), address)
        self.send(response(request, props), address)


class ParserTests(unittest.TestCase):
    def test_exact_official_discovery_frame(self):
        self.assertEqual(p.encode_frame(1, p.NODE, 0x62, {0xD6: b"", 0x8C: b""}).hex(),
                         "1081000105fe010ef0016202d6008c00")

    def test_standard_controller_frame_and_fixed_receive_port(self):
        self.assertEqual(p.encode_frame(1, bytes.fromhex("013501"), 0x62,
                         {0x80: b""}, source=p.CONTROLLER).hex(),
                         "1081000105ff0101350162018000")
        client = p.SharpLocalClient("127.0.0.1")
        standard = client._channel()
        self.assertEqual((standard.port, standard.bind_port, standard.source),
                         (3610, 3610, p.CONTROLLER))
        app = client._channel(port=p.UDP_PORT, source=p.SOURCE)
        self.assertEqual((app.port, app.bind_port, app.source), (8766, 8766, p.SOURCE))

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

    async def test_empty_batch_triggers_individual_reads_for_get_res_and_get_sna(self):
        for esv in (0x72, 0x52):
            with self.subTest(esv=esv):
                channel, fake = await self.channel(empty_batch_esv=esv)
                async with channel:
                    object_id, writable, readings = await channel.discover()
                self.assertEqual(object_id, fake.object_id)
                self.assertEqual(p.decode_readings(readings), {
                    "power": "on", "power_watts": 9, "temperature_c": 23, "humidity_pct": 45,
                })
                self.assertEqual(channel.diagnostics["batch_property_lengths"], {"80": 0, "84": 0, "F1": 0})
                self.assertEqual(channel.diagnostics["individual_read_codes"], ["80", "84", "F1"])
                batch = channel.diagnostics["responses"][3]
                self.assertEqual(batch["esv"], f"{esv:02X}")
                state = p.LocalState(p.ModuleInfo("1.0.4", 2, "fake"),
                    "power_control_available", object_id, readings, writable,
                    udp_port=p.UDP_PORT, source_object=p.SOURCE)
                self.assertTrue(state.power_controllable)
                self.assertTrue(all(frame.esv == 0x62 for frame in fake.received))

    async def test_partial_batch_preserves_valid_power_and_reads_only_empty_fields(self):
        channel, fake = await self.channel(partial_batch=True)
        async with channel:
            _, _, readings = await channel.discover()
        self.assertEqual(readings[0x80], b"\x30")
        self.assertEqual(channel.diagnostics["individual_read_codes"], ["84", "F1"])
        self.assertEqual(p.decode_readings(readings)["humidity_pct"], 45)

    async def test_still_empty_individual_reads_do_not_invent_state_or_enable_controls(self):
        channel, fake = await self.channel(empty_all_readings=True)
        async with channel:
            object_id, writable, readings = await channel.discover()
        state = p.LocalState(p.ModuleInfo("1.0.4", 2, "fake"), "no_readings",
                             object_id, readings, writable)
        self.assertEqual(readings, {})
        self.assertFalse(state.power_controllable)
        self.assertEqual(channel.diagnostics["individual_read_codes"], ["80", "84", "F1"])
        self.assertTrue(all(frame.esv == 0x62 for frame in fake.received))

    async def test_power_capability_also_requires_valid_readback(self):
        for properties in ({}, {0x80: b""}, {0x80: b"\x99"}):
            state = p.LocalState(p.ModuleInfo("1.0.1", 0, "fake"), "read_only",
                                 b"\x01\x35\x01", properties, frozenset({0x80}))
            self.assertFalse(state.power_controllable)
        state = p.LocalState(p.ModuleInfo("1.0.4", 2, "fake"), "no_readings",
            b"\x01\x35\x01", {0x80: b"\x30"}, frozenset({0x80}))
        self.assertFalse(state.power_controllable)

    async def test_client_checks_power_readback_without_repeating_write(self):
        for ignore_write in (False, True):
            with self.subTest(ignore_write=ignore_write):
                channel, fake = await self.channel(ignore_write=ignore_write)
                client = p.SharpLocalClient("127.0.0.1")
                client.state = p.LocalState(p.ModuleInfo("1.0.1", 0, "fake"),
                    "power_control_available", fake.object_id, {0x80: b"\x30"}, frozenset({0x80}),
                    udp_port=p.UDP_PORT, source_object=p.SOURCE)
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
        channel.object_id = None
        channel.properties = {}
        channel.writable = frozenset()
        info = p.ModuleInfo("1.0.1", 0, "fake")
        with patch.object(p, "get_info", new=AsyncMock(return_value=info)), patch.object(client, "_channel", return_value=channel):
            state = await client.update()
        self.assertEqual(state.module.version, "1.0.1")
        self.assertEqual(state.udp_status, "no_response")
        self.assertFalse(state.power_controllable)
        self.assertEqual(state.udp_diagnostics["stage"], "discovery")

    async def test_reply_for_different_controller_object_is_ignored(self):
        channel, fake = await self.channel(wrong_destination=True)
        channel.source = p.CONTROLLER
        async with channel:
            with self.assertRaises(TimeoutError):
                await channel.request(p.NODE, {0xD6: b""})
        self.assertEqual(channel.diagnostics["unmatched_frames"], 1)


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def devices(self, *, standard=None, app=None):
        """Simulate fixed-port Sharp replies on a different loopback address."""
        fakes = []
        for port, source, options in ((3610, p.CONTROLLER, standard or {}),
                                     (8766, p.SOURCE, app or {})):
            options = dict(options)
            source = options.pop("source", source)
            fake = FakePurifier(source=source, reply_port=port, **options)
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda fake=fake: fake, local_addr=("127.0.0.2", port))
            self.addCleanup(transport.close)
            fakes.append(fake)
        client = p.SharpLocalClient("127.0.0.2", bind_ip="127.0.0.1")
        info = p.ModuleInfo("1.0.4", 2, "fake")
        return client, fakes, info

    async def test_standard_channel_reads_and_controls_with_fixed_reply_port(self):
        client, (standard, app), info = await self.devices(app={"empty_all_readings": True})
        with patch.object(p, "get_info", new=AsyncMock(return_value=info)):
            state = await client.update(broadcast=None)
        self.assertTrue(state.power_controllable)
        self.assertEqual((state.udp_port, state.source_object), (3610, p.CONTROLLER))
        self.assertEqual(state.object_id, bytes.fromhex("013502"))
        self.assertEqual(p.decode_readings(state.properties)["power"], "on")
        self.assertEqual(state.udp_diagnostics["selected_port"], 3610)
        self.assertFalse(app.received)
        self.assertEqual(standard.received[0].properties, {0xD6: b""})
        self.assertFalse(any(0xFC in frame.properties for frame in standard.received))
        await client.set_power(False)
        self.assertEqual(standard.power, b"\x31")
        self.assertTrue(all(frame.source == p.CONTROLLER for frame in standard.received))
        self.assertEqual(sum(frame.esv == 0x61 for frame in standard.received), 1)

    async def test_app_fallback_write_stays_on_the_transport_that_read_state(self):
        client, (standard, app), info = await self.devices(standard={"empty_all_readings": True})
        with patch.object(p, "get_info", new=AsyncMock(return_value=info)):
            state = await client.update(broadcast=None)
        self.assertTrue(state.power_controllable)
        self.assertEqual((state.udp_port, state.source_object), (8766, p.SOURCE))
        self.assertEqual([item["port"] for item in state.udp_diagnostics["transports"]], [3610, 8766])
        await client.set_power(False)
        self.assertEqual(app.power, b"\x31")
        self.assertFalse(any(frame.esv == 0x61 for frame in standard.received))
        self.assertEqual(sum(frame.esv == 0x61 for frame in app.received), 1)

    async def test_maps_from_app_do_not_enable_writes_on_read_only_standard_channel(self):
        client, (standard, app), info = await self.devices(
            standard={"writable": False}, app={"empty_all_readings": True, "source": None})
        with patch.object(p, "get_info", new=AsyncMock(return_value=info)):
            state = await client.update(broadcast=None)
        self.assertEqual(state.udp_port, 3610)
        self.assertEqual(state.udp_status, "read_only")
        self.assertFalse(state.power_controllable)
        with self.assertRaises(p.ProtocolError):
            await client.set_power(False)
        self.assertTrue(app.received)
        self.assertFalse(any(frame.esv == 0x61 for fake in (standard, app) for frame in fake.received))

    async def test_both_channels_reject_state_without_exposing_controls(self):
        client, fakes, info = await self.devices(
            standard={"empty_all_readings": True}, app={"empty_all_readings": True, "source": None})
        with patch.object(p, "get_info", new=AsyncMock(return_value=info)):
            state = await client.update(broadcast=None)
        self.assertEqual(state.udp_status, "no_readings")
        self.assertEqual(state.properties, {})
        self.assertIsNone(state.udp_port)
        self.assertFalse(state.power_controllable)
        evidence = state.udp_diagnostics["transports"]
        self.assertEqual([item["status"] for item in evidence], ["no_readings"] * 3)
        self.assertEqual(evidence[-1]["source_object"], "05ff01")
        self.assertEqual(evidence[-1]["sent"], 1)
        for item in evidence:
            singles = [entry for entry in item["responses"] if entry["requested_codes"] == ["80"]]
            self.assertEqual(singles[0]["esv"], "52")
        self.assertFalse(any(frame.esv == 0x61 for fake in fakes for frame in fake.received))

    async def test_probe_budget_keeps_completed_power_read(self):
        client, (standard, _), info = await self.devices(
            standard={"partial_batch": True, "drop_read_codes": (0x84, 0xF1)})
        with patch.object(p, "get_info", new=AsyncMock(return_value=info)), \
                patch.object(p, "UDP_PROBE_TIMEOUT", 0.1):
            state = await client.update(broadcast=None)
        self.assertTrue(state.power_controllable)
        self.assertEqual(state.properties, {0x80: b"\x30"})
        self.assertTrue(state.udp_diagnostics["probe_timeout"])
        # The fixed receive port is released after cancellation.
        await client.set_power(False)
        self.assertEqual(standard.power, b"\x31")

    async def test_concurrent_clients_serialize_the_fixed_receive_port(self):
        first, (standard, _), info = await self.devices()
        second = p.SharpLocalClient("127.0.0.2", bind_ip="127.0.0.1")
        with patch.object(p, "get_info", new=AsyncMock(return_value=info)):
            states = await asyncio.gather(first.update(broadcast=None), second.update(broadcast=None))
        self.assertTrue(all(state.power_controllable for state in states))
        self.assertTrue(all(state.udp_port == 3610 for state in states))
        self.assertEqual(len([frame for frame in standard.received if frame.destination == p.NODE]), 2)

    async def test_controller_source_on_app_port_gets_its_own_power_and_permission(self):
        client, (standard, app), info = await self.devices(
            standard={"empty_all_readings": True},
            app={"source": None, "state_source": p.CONTROLLER})
        with patch.object(p, "get_info", new=AsyncMock(return_value=info)):
            state = await client.update(broadcast=None)
        self.assertTrue(state.power_controllable)
        self.assertEqual((state.udp_port, state.source_object), (8766, p.CONTROLLER))
        self.assertEqual(state.object_id, app.object_id)
        controller_reads = [frame for frame in app.received if frame.source == p.CONTROLLER]
        self.assertEqual([list(frame.properties) for frame in controller_reads], [[0x80], [0x9E, 0x9F]])
        self.assertTrue(all(frame.esv == 0x62 for frame in app.received + standard.received))
        await client.set_power(False)
        writes = [frame for frame in app.received if frame.esv == 0x61]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0].source, p.CONTROLLER)
        self.assertEqual(app.power, b"\x31")
        self.assertFalse(any(frame.esv == 0x61 for frame in standard.received))

    async def test_controller_source_cannot_inherit_app_source_set_map(self):
        client, (_, app), info = await self.devices(
            standard={"empty_all_readings": True},
            app={"source": None, "state_source": p.CONTROLLER,
                 "writable_by_source": {p.CONTROLLER: False}})
        with patch.object(p, "get_info", new=AsyncMock(return_value=info)):
            state = await client.update(broadcast=None)
        self.assertEqual(state.udp_status, "read_only")
        self.assertEqual(state.source_object, p.CONTROLLER)
        self.assertEqual(state.properties, {0x80: b"\x30"})
        self.assertFalse(state.power_controllable)
        self.assertEqual(state.udp_diagnostics["transports"][1]["writable_codes"], ["80"])
        self.assertEqual(state.udp_diagnostics["transports"][2]["writable_codes"], [])
        with self.assertRaises(p.ProtocolError):
            await client.set_power(False)
        self.assertFalse(any(frame.esv == 0x61 for frame in app.received))

    async def test_controller_power_read_without_own_map_stays_read_only(self):
        client, (_, app), info = await self.devices(
            standard={"empty_all_readings": True},
            app={"source": None, "state_source": p.CONTROLLER,
                 "drop_maps_source": p.CONTROLLER})
        open_channel = client._channel

        def channel(**kwargs):
            result = open_channel(**kwargs)
            result.timeout = 0.05
            return result

        with patch.object(p, "get_info", new=AsyncMock(return_value=info)), \
                patch.object(client, "_channel", side_effect=channel):
            state = await client.update(broadcast=None)
        self.assertEqual(state.udp_status, "read_only")
        self.assertEqual(state.properties, {0x80: b"\x30"})
        self.assertFalse(state.power_controllable)
        self.assertEqual(state.udp_diagnostics["transports"][-1]["sent"], 2)
        self.assertFalse(any(frame.esv == 0x61 for frame in app.received))

    async def test_controller_source_timeout_preserves_app_evidence_and_tcp(self):
        client, (_, app), info = await self.devices(
            standard={"empty_all_readings": True}, app={"empty_all_readings": True})
        with patch.object(p, "get_info", new=AsyncMock(return_value=info)), \
                patch.object(p, "UDP_POWER_PROBE_TIMEOUT", 0.05):
            state = await client.update(broadcast=None)
        self.assertEqual(state.module.version, "1.0.4")
        self.assertEqual(state.udp_status, "no_readings")
        self.assertFalse(state.power_controllable)
        self.assertEqual(state.udp_diagnostics["transports"][-1]["status"], "no_response")
        self.assertTrue(state.udp_diagnostics["transports"][-1]["probe_timeout"])
        self.assertFalse(any(frame.esv == 0x61 for frame in app.received))

    async def test_confirmed_app_transport_is_tried_first_on_later_polls(self):
        for controller in (False, True):
            with self.subTest(controller=controller):
                client, (standard, app), info = await self.devices(
                    standard={"empty_all_readings": True},
                    app={"source": None, "state_source": p.CONTROLLER} if controller else {})
                with patch.object(p, "get_info", new=AsyncMock(return_value=info)):
                    first = await client.update(broadcast=None)
                    before_standard = len(standard.received)
                    before_app = len(app.received)
                    second = await client.update(broadcast=None)
                self.assertTrue(first.power_controllable and second.power_controllable)
                self.assertEqual(len(standard.received), before_standard)
                self.assertEqual(len(second.udp_diagnostics["transports"]), 1)
                expected_source = p.CONTROLLER if controller else p.SOURCE
                self.assertTrue(all(frame.source == expected_source for frame in app.received[before_app:]))
                self.assertFalse(any(frame.esv == 0x61 for frame in app.received))
                # Close the fake endpoints before reusing their fixed ports.
                standard.transport.close()
                app.transport.close()
                await asyncio.sleep(0)
                await asyncio.sleep(0)

    async def test_lost_cached_controller_capability_falls_back_to_app_source(self):
        client, (standard, app), info = await self.devices(
            standard={"empty_all_readings": True},
            app={"source": None, "state_source": p.CONTROLLER})
        with patch.object(p, "get_info", new=AsyncMock(return_value=info)):
            initial = await client.update(broadcast=None)
            self.assertEqual(initial.source_object, p.CONTROLLER)
            app.state_source = p.SOURCE
            state = await client.update(broadcast=None)
        self.assertTrue(state.power_controllable)
        self.assertEqual(state.source_object, p.SOURCE)
        self.assertEqual([entry["port"] for entry in state.udp_diagnostics["transports"]], [8766, 3610, 8766])
        self.assertFalse(any(frame.esv == 0x61 for frame in app.received + standard.received))

    async def test_changed_tcp_identity_does_not_reuse_cached_controller_profile(self):
        client, (standard, app), info = await self.devices(
            standard={"empty_all_readings": True},
            app={"source": None, "state_source": p.CONTROLLER})
        changed = p.ModuleInfo("1.0.4", 2, "different-module")
        with patch.object(p, "get_info", new=AsyncMock(side_effect=[info, changed])):
            await client.update(broadcast=None)
            before_app = len(app.received)
            standard.empty_all_readings = False
            state = await client.update(broadcast=None)
        self.assertEqual(state.udp_port, 3610)
        self.assertEqual(len(app.received), before_app)
        self.assertEqual(state.udp_diagnostics["transports"][0]["discovery_method"], "unicast")


if __name__ == "__main__":
    unittest.main()
