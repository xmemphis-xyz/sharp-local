"""Exercise direct state reads when a device does not answer node discovery."""
import asyncio
from contextlib import redirect_stdout
import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from test_protocol import FakePurifier

spec = importlib.util.spec_from_file_location(
    "local_direct_probe_tests", Path(__file__).parents[1] / "tools/probe_local.py",
)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
p = probe.protocol


class NoDiscoveryPurifier(FakePurifier):
    def datagram_received(self, data, address):
        frame = p.decode_frame(data)
        if frame.destination == p.NODE:
            self.received.append(frame)
            return
        super().datagram_received(data, address)


class DirectProbeTests(unittest.IsolatedAsyncioTestCase):
    async def read_device(self, **options):
        fake = NoDiscoveryPurifier(source=p.CONTROLLER, reply_port=3610, **options)
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: fake, local_addr=("127.0.0.2", 3610),
        )
        self.addCleanup(transport.close)
        args = SimpleNamespace(
            host="127.0.0.2", bind_ip="127.0.0.1", broadcast=None,
            tcp_only=False, direct_object=fake.object_id,
        )
        info = p.ModuleInfo("1.0.4", 2, "PRIVATE-MODULE-MAC")
        with patch.object(p, "get_info", new=AsyncMock(return_value=info)):
            state = await probe.read_state(args)
        return state, fake, args, info

    async def test_power_can_be_read_without_a_node_discovery_response(self):
        state, fake, args, info = await self.read_device()
        self.assertEqual(state.udp_status, "power_control_available")
        self.assertEqual(p.decode_readings(state.properties), {"power": "on"})
        self.assertTrue(state.power_controllable)
        self.assertEqual((state.udp_port, state.source_object), (3610, p.CONTROLLER))
        self.assertEqual(len(fake.received), 2)
        self.assertEqual(fake.received[0].properties, {0x80: b""})
        self.assertTrue(all(frame.destination == fake.object_id and frame.esv == 0x62
                            and frame.source == p.CONTROLLER for frame in fake.received))
        output = io.StringIO()
        with patch.object(p, "get_info", new=AsyncMock(return_value=info)), redirect_stdout(output):
            self.assertEqual(await probe.main(args), 0)
        self.assertIn("UDP 3610 direct power probe: power_control_available", output.getvalue())
        for private in ("PRIVATE-MODULE-MAC", "127.0.0.2", "test-module", "test-purifier"):
            self.assertNotIn(private, output.getvalue())

    async def test_empty_read_stops_without_maps_or_writes(self):
        state, fake, _, _ = await self.read_device(empty_all_readings=True)
        self.assertEqual(state.udp_status, "no_readings")
        self.assertFalse(state.power_controllable)
        self.assertEqual(state.properties, {})
        self.assertEqual(len(fake.received), 1)
        self.assertEqual(fake.received[0].esv, 0x62)
        self.assertIsNone(state.udp_port)

    async def test_power_read_uses_its_own_read_only_map(self):
        state, fake, _, _ = await self.read_device(writable=False)
        self.assertEqual(state.udp_status, "read_only")
        self.assertEqual(p.decode_readings(state.properties), {"power": "on"})
        self.assertFalse(state.power_controllable)
        self.assertEqual(state.set_map, frozenset())
        self.assertTrue(all(frame.esv == 0x62 for frame in fake.received))

    async def test_tcp_failure_prevents_udp_requests(self):
        args = SimpleNamespace(host="127.0.0.2", bind_ip="127.0.0.1", direct_object=b"\x01\x35\x01")
        with patch.object(p, "get_info", new=AsyncMock(side_effect=p.ProtocolError("bad signature"))), \
                patch.object(p, "EchonetChannel") as channel:
            with self.assertRaises(p.ProtocolError):
                await probe.read_state(args)
        channel.assert_not_called()
