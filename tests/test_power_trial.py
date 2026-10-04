"""Exercise the explicit CLI write experiment against real loopback UDP."""
import asyncio
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

from test_protocol import FakePurifier, response

spec = importlib.util.spec_from_file_location(
    "local_power_trial_tests", Path(__file__).parents[1] / "tools/trial_power.py",
)
trial = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trial)
p = trial.protocol


class TrialPurifier(FakePurifier):
    def __init__(self, *, drop_write_reply=False, invalid_ack=False,
                 wrong_write_reply=False, **kwargs):
        super().__init__(**kwargs)
        self.drop_write_reply = drop_write_reply
        self.invalid_ack = invalid_ack
        self.wrong_write_reply = wrong_write_reply

    def datagram_received(self, data, address):
        request = p.decode_frame(data)
        if request.esv == 0x61 and (self.drop_write_reply or self.invalid_ack
                                    or self.wrong_write_reply):
            self.received.append(request)
            self.power = request.properties[0x80]
            if self.drop_write_reply:
                return
            if self.wrong_write_reply:
                self.send(response(request, {0x80: b""}, esv=0x71,
                                   tid=(request.tid + 1) & 0xFFFF), address)
            value = bytes((0,)) if self.invalid_ack else b""
            self.send(response(request, {0x80: value}, esv=0x71), address)
            return
        super().datagram_received(data, address)


class PowerTrialTests(unittest.IsolatedAsyncioTestCase):
    async def run_device(self, *, power="off", initial_power=None, **options):
        fake = TrialPurifier(**options)
        if initial_power is not None:
            fake.power = initial_power
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: fake, local_addr=("127.0.0.1", 0),
        )
        self.addCleanup(transport.close)
        port = transport.get_extra_info("sockname")[1]
        channel = p.EchonetChannel("127.0.0.1", port=port, bind_port=0, timeout=0.05)
        info = p.ModuleInfo("1.0.4", 2, "PRIVATE-MODULE-MAC")
        with patch.object(p, "get_info", new=AsyncMock(return_value=info)), \
                patch.object(p, "EchonetChannel", return_value=channel) as factory:
            report = await trial.run_trial("127.0.0.1", power)
        factory.assert_called_once_with("127.0.0.1", port=8766, source=p.SOURCE,
                                        bind_ip="0.0.0.0")
        return report, fake

    def writes(self, fake):
        return [frame for frame in fake.received if frame.esv == 0x61]

    async def test_rejected_reads_can_coexist_with_one_acknowledged_write(self):
        report, fake = await self.run_device(empty_all_readings=True)
        self.assertEqual(report["write_result"], "acknowledged")
        self.assertEqual(report["outcome"], "acknowledged_unconfirmed")
        self.assertIsNone(report["power_readback"])
        self.assertEqual(fake.power, bytes((0x31,)))
        writes = self.writes(fake)
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0].destination, fake.object_id)
        self.assertEqual(writes[0].source, p.SOURCE)
        self.assertEqual(writes[0].properties, {0x80: bytes((0x31,))})
        encoded = json.dumps(report)
        for private in ("PRIVATE-MODULE-MAC", "127.0.0.1", "test-module", "test-purifier"):
            self.assertNotIn(private, encoded)

    async def test_matching_readback_verifies_on(self):
        report, fake = await self.run_device(power="on", initial_power=bytes((0x31,)))
        self.assertEqual(report["outcome"], "verified_by_readback")
        self.assertEqual(report["power_readback"], "on")
        self.assertEqual(len(self.writes(fake)), 1)
        self.assertEqual(self.writes(fake)[0].properties, {0x80: bytes((0x30,))})

    async def test_missing_set_permission_never_sends_power(self):
        report, fake = await self.run_device(writable=False, empty_all_readings=True)
        self.assertEqual(report["write_result"], "not_sent")
        self.assertEqual(report["outcome"], "power_write_not_advertised")
        self.assertEqual(self.writes(fake), [])

    async def test_rejection_is_distinct_from_missing_readback(self):
        report, fake = await self.run_device(reject=True, empty_all_readings=True)
        self.assertEqual(report["write_result"], "rejected")
        self.assertEqual(report["outcome"], "write_rejected")
        self.assertEqual(fake.power, bytes((0x30,)))
        self.assertEqual(len(self.writes(fake)), 1)
        self.assertEqual(fake.received[-1].esv, 0x61)

    async def test_lost_acknowledgement_does_not_retry_a_changed_device(self):
        report, fake = await self.run_device(drop_write_reply=True)
        self.assertEqual(report["write_result"], "unknown")
        self.assertEqual(report["outcome"], "write_unconfirmed")
        self.assertEqual(fake.power, bytes((0x31,)))
        self.assertEqual(len(self.writes(fake)), 1)
        self.assertEqual(fake.received[-1].esv, 0x61)

    async def test_acknowledged_but_ignored_write_does_not_claim_success(self):
        report, fake = await self.run_device(ignore_write=True)
        self.assertEqual(report["write_result"], "acknowledged")
        self.assertEqual(report["power_readback"], "on")
        self.assertEqual(report["outcome"], "readback_mismatch")
        self.assertEqual(len(self.writes(fake)), 1)

    async def test_invalid_acknowledgement_does_not_claim_acceptance(self):
        report, fake = await self.run_device(invalid_ack=True)
        self.assertEqual(report["write_result"], "unsupported_acknowledgement")
        self.assertEqual(report["outcome"], "write_unconfirmed")
        self.assertEqual(len(self.writes(fake)), 1)
        self.assertEqual(fake.received[-1].esv, 0x61)

    async def test_wrong_transaction_reply_is_ignored_without_another_write(self):
        report, fake = await self.run_device(wrong_write_reply=True, empty_all_readings=True)
        self.assertEqual(report["write_result"], "acknowledged")
        self.assertEqual(len(self.writes(fake)), 1)
        self.assertEqual(report["udp_diagnostics"]["unmatched_frames"], 1)

    async def test_invalid_tcp_info_does_not_open_a_write_channel(self):
        with patch.object(p, "get_info", new=AsyncMock(side_effect=p.ProtocolError("bad signature"))), \
                patch.object(p, "EchonetChannel") as factory:
            report = await trial.run_trial("127.0.0.1", "off")
        factory.assert_not_called()
        self.assertEqual(report["write_result"], "not_sent")
        self.assertEqual(report["outcome"], "preparation_failed")

    async def test_invalid_direction_does_not_connect(self):
        with patch.object(p, "get_info") as get_info:
            with self.assertRaises(ValueError):
                await trial.run_trial("127.0.0.1", "toggle")
        get_info.assert_not_called()
