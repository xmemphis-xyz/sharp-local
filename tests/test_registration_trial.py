"""Exercise the one-shot registration tool against a local fake TCP module."""
import asyncio
from contextlib import redirect_stderr, suppress
import hashlib
import hmac
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

spec = importlib.util.spec_from_file_location(
    "registration_trial_tests", Path(__file__).parents[1] / "tools/trial_registration.py",
)
trial = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trial)


class RegistrationTests(unittest.IsolatedAsyncioTestCase):
    async def run_with_module(self, *, code=0, fault=None, reply_command=b"\x80\x03"):
        requests = []
        errors = []
        connections = 0
        active = set()
        nonce = bytes(range(16))

        async def handler(reader, writer):
            nonlocal connections
            task = asyncio.current_task()
            active.add(task)
            connections += 1
            connection_number = connections
            try:
                self.assertEqual(await reader.readexactly(8), bytes(8))
                hello = nonce + hashlib.md5(nonce).digest()
                if fault == "handshake" and connection_number == 2:
                    writer.write(hello[:16] + bytes(16))
                    await writer.drain()
                    self.assertEqual(await reader.read(), b"")
                    return
                for part in (hello[:1], hello[1:17], hello[17:]):
                    writer.write(part)
                    await writer.drain()
                    await asyncio.sleep(0)
                request = await reader.readexactly(36)
                requests.append(request[34:])
                self.assertEqual(request[:2], b"\x00\x24")
                self.assertEqual(request[2:34], hmac.digest(
                    trial.protocol.protocol_key(), nonce + request[34:], "sha256"))
                if request[34:] == b"\x00\x02":
                    payload = (b"\x80\x02\x01\x00\x00\x04\x00\x02"
                               + b"S" * 256 + bytes.fromhex("010203040506"))
                else:
                    self.assertEqual(request[34:], b"\x00\x03")
                    if fault == "timeout":
                        self.assertEqual(await reader.read(), b"")
                        return
                    payload = reply_command + code.to_bytes(2, "big", signed=True) + b"\x00\x09"
                signing_nonce = bytes(16) if fault == "wrong_nonce" and connection_number == 2 else nonce
                signature = hmac.digest(trial.protocol.protocol_key(), signing_nonce + payload, "sha256")
                if ((fault == "preflight_signature" and connection_number == 1)
                        or (fault == "signature" and connection_number == 2)):
                    signature = bytes(32)
                size = len(payload) + 34
                if connection_number == 2 and fault == "length":
                    size = 5000
                data = size.to_bytes(2, "big") + signature + payload
                if connection_number == 2 and fault == "truncate":
                    data = data[:37]
                for start in range(0, len(data), 7):
                    writer.write(data[start:start + 7])
                    await writer.drain()
                    await asyncio.sleep(0)
            except (ConnectionError, asyncio.IncompleteReadError):
                pass
            except Exception as error:
                errors.append(error)
            finally:
                writer.close()
                with suppress(ConnectionError):
                    await writer.wait_closed()
                active.discard(task)

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        try:
            report = await trial.run_trial(
                "127.0.0.1", register_on_server=True,
                port=server.sockets[0].getsockname()[1], response_timeout=0.2,
            )
            if active:
                await asyncio.wait_for(asyncio.gather(*tuple(active)), 1)
            self.assertEqual(errors, [])
            return report, requests
        finally:
            server.close()
            await server.wait_closed()

    async def test_signed_fragmented_success_and_secret_omission(self):
        report, requests = await self.run_with_module()
        self.assertEqual(requests, [b"\x00\x02", b"\x00\x03"])
        self.assertEqual(report["registration_request"], "sent")
        self.assertEqual(report["registration_code"], 0)
        self.assertEqual(report["outcome"], "module_registration_reported_success")
        self.assertEqual(report["reply_length"], 40)
        self.assertEqual(report["reply_command"], "8003")
        self.assertEqual(report["module_firmware"], "1.0.4")
        self.assertEqual(report["module_flags"], "0x0002")
        self.assertFalse(report["app_pairing_verified"])
        encoded = json.dumps(report)
        for secret in ("127.0.0.1", "010203040506", "SSSS", trial.protocol.protocol_key().hex()):
            self.assertNotIn(secret, encoded)

    async def test_app_result_codes_are_not_reported_as_success(self):
        for code, meaning in {
            1: "cancelled_by_module", 2: "not_in_cloud_registration_mode",
            3: "cloud_communication_error", 4: "server_rejected_registration",
        }.items():
            with self.subTest(code=code):
                report, requests = await self.run_with_module(code=code)
                self.assertEqual(requests, [b"\x00\x02", b"\x00\x03"])
                self.assertEqual(report["registration_code"], code)
                self.assertEqual(report["outcome"], meaning)
                self.assertFalse(report["app_pairing_verified"])

    async def test_unknown_signed_result_stays_unknown(self):
        for code in (37, -1):
            with self.subTest(code=code):
                report, requests = await self.run_with_module(code=code)
                self.assertEqual(report["registration_code"], code)
                self.assertEqual(report["outcome"], "unknown_registration_code")
                self.assertEqual(requests.count(b"\x00\x03"), 1)

    async def test_generic_module_error_uses_8fff_and_final_detail(self):
        report, requests = await self.run_with_module(reply_command=b"\x8f\xff")
        self.assertIsNone(report["registration_code"])
        self.assertEqual(report["outcome"], "module_error")
        self.assertEqual(report["module_error_code"], 9)
        self.assertEqual(requests.count(b"\x00\x03"), 1)

    async def test_unexpected_signed_reply_does_not_parse_zero_as_success(self):
        report, requests = await self.run_with_module(reply_command=b"\x80\x05")
        self.assertIsNone(report["registration_code"])
        self.assertEqual(report["outcome"], "unexpected_reply_command")
        self.assertEqual(report["reply_command"], "8005")
        self.assertEqual(requests.count(b"\x00\x03"), 1)

    async def test_lost_response_does_not_retry_registration(self):
        report, requests = await self.run_with_module(fault="timeout")
        self.assertEqual(report["outcome"], "registration_unconfirmed")
        self.assertEqual(report["error_type"], "TimeoutError")
        self.assertEqual(report["registration_request"], "sent")
        self.assertIsNone(report["registration_code"])
        self.assertEqual(requests, [b"\x00\x02", b"\x00\x03"])

    async def test_invalid_reply_integrity_and_structure_stay_unconfirmed(self):
        for fault in ("signature", "wrong_nonce", "length", "truncate"):
            with self.subTest(fault=fault):
                report, requests = await self.run_with_module(fault=fault)
                self.assertEqual(report["outcome"], "registration_unconfirmed")
                self.assertIsNone(report["registration_code"])
                self.assertNotIn("reply_command", report)
                self.assertEqual(requests, [b"\x00\x02", b"\x00\x03"])

    async def test_invalid_registration_handshake_sends_no_registration(self):
        report, requests = await self.run_with_module(fault="handshake")
        self.assertEqual(report["outcome"], "preparation_failed")
        self.assertEqual(report["registration_request"], "not_sent")
        self.assertEqual(requests, [b"\x00\x02"])

    async def test_invalid_get_info_sends_no_registration(self):
        report, requests = await self.run_with_module(fault="preflight_signature")
        self.assertEqual(report["outcome"], "preparation_failed")
        self.assertEqual(report["phase"], "preflight")
        self.assertEqual(report["registration_request"], "not_sent")
        self.assertEqual(requests, [b"\x00\x02"])

    async def test_explicit_opt_in_required_before_any_io(self):
        with patch.object(trial.protocol, "get_info", new=AsyncMock()) as get_info:
            with self.assertRaises(ValueError):
                await trial.run_trial("127.0.0.1")
            get_info.assert_not_awaited()
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            trial.build_parser().parse_args(["127.0.0.1"])


if __name__ == "__main__":
    unittest.main()
