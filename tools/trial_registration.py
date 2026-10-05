"""Request one Sharp module cloud-registration attempt and report its result.

This is a state-changing manual experiment, not a read-only local probe.
It can ask the purifier to contact Sharp's cloud. It does not perform the
app's account-binding steps or establish that local control is available.
"""
import argparse
import asyncio
from contextlib import suppress
import hashlib
import hmac
import importlib.util
import ipaddress
import json
import sys
from pathlib import Path

path = Path(__file__).parents[1] / "custom_components/sharp_life_air_local/protocol.py"
spec = importlib.util.spec_from_file_location("sharp_registration_trial_protocol", path)
protocol = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = protocol
spec.loader.exec_module(protocol)

RESULTS = {
    0: "module_registration_reported_success",
    1: "cancelled_by_module",
    2: "not_in_cloud_registration_mode",
    3: "cloud_communication_error",
    4: "server_rejected_registration",
}


async def run_trial(host, *, register_on_server=False, port=protocol.TCP_PORT,
                    response_timeout=30):
    """Verify module info, then send at most one signed 0003 command.

    The official app prepares a cloud tempBoxInfo record before this command
    and performs further account operations after success. This tool cannot
    substitute for that workflow. An unknown reply or timeout stays unknown.
    """
    if not register_on_server:
        raise ValueError("Explicit register_on_server=True is required")
    report = {
        "registration_request": "not_sent",
        "registration_code": None,
        "outcome": "not_run",
        "app_pairing_verified": False,
    }
    writer = None
    phase = "preflight"
    try:
        info = await protocol.get_info(host, port=port)
        # These values are observed before the registration request, not
        # read back afterwards. Flags do not establish registration success.
        report["module_firmware"] = info.version
        report["module_flags"] = f"0x{info.flags:04X}"

        phase = "handshake"
        async with asyncio.timeout(5):
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(bytes(8))
            await writer.drain()
            hello = await reader.readexactly(32)
            nonce = hello[:16]
            if not hmac.compare_digest(hashlib.md5(nonce).digest(), hello[16:]):
                raise protocol.ProtocolError("Invalid Sharp handshake")

        key = protocol.protocol_key()
        command = b"\x00\x03"
        signature = hmac.digest(key, nonce + command, "sha256")
        async with asyncio.timeout(response_timeout):
            phase = "registration"
            writer.write(b"\x00\x24" + signature + command)
            report["registration_request"] = "sent"
            await writer.drain()
            phase = "reply"
            report["reply_stage"] = "header"
            header = await reader.readexactly(2)
            size = int.from_bytes(header, "big")
            report["reply_length"] = size
            # r5/a.h() allocates a 40-byte buffer, while r5/a.d() validates
            # the length declared in the frame (36..40). A normal result
            # needs only 38 bytes: length + HMAC + command + result code.
            if not 36 <= size <= 40:
                raise protocol.ProtocolError("Unexpected registration response length")
            report["reply_stage"] = "body"
            body = await reader.readexactly(size - 2)
            payload = body[32:]
            expected = hmac.digest(key, nonce + payload, "sha256")
            if not hmac.compare_digest(expected, body[:32]):
                raise protocol.ProtocolError("Invalid Sharp response signature")
            report["reply_stage"] = "signature_verified"
            report["reply_command"] = payload[:2].hex()
            if payload[:2] == b"\x8f\xff":
                # The error detail is at frame bytes 38-39, only if present.
                # Do not substitute zero-filled buffer bytes for missing data
                # or interpret this error's first field as a registration result.
                report["module_error_code"] = (int.from_bytes(payload[4:6], "big")
                                               if len(payload) >= 6 else None)
                report["outcome"] = "module_error"
            elif payload[:2] == b"\x80\x03":
                # Expected counterpart of 0003, inferred from the app's
                # request/reply convention; not yet captured on KI-TX100EU.
                if len(payload) < 4:
                    raise protocol.ProtocolError("Missing registration result")
                code = int.from_bytes(payload[2:4], "big", signed=True)
                report["registration_code"] = code
                report["outcome"] = RESULTS.get(code, "unknown_registration_code")
            else:
                report["outcome"] = "unexpected_reply_command"
            phase = "complete"
    except (OSError, TimeoutError, asyncio.IncompleteReadError, protocol.ProtocolError) as error:
        report["error_type"] = type(error).__name__
        if isinstance(error, asyncio.IncompleteReadError):
            # Preserve only counts, never partial bytes (which could contain
            # nonce, signature or other data). An EOF does not authorize retry.
            report["read_expected_bytes"] = error.expected
            report["read_received_bytes"] = len(error.partial)
        if isinstance(error, protocol.ProtocolError):
            report["error_reason"] = str(error)
        if isinstance(error, OSError) and error.errno is not None:
            report["error_number"] = error.errno
        report["outcome"] = ("registration_unconfirmed"
                             if report["registration_request"] == "sent"
                             else "preparation_failed")
    finally:
        report["phase"] = phase
        if writer is not None:
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()
    return report


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", type=lambda value: str(ipaddress.IPv4Address(value)))
    parser.add_argument("--register-on-server", action="store_true", required=True,
                        help="Explicitly request one attempt to register the module with Sharp's cloud")
    return parser


async def main(args):
    print("Manual trial: at most one cloud-registration command to the Sharp module.", flush=True)
    print("This can contact Sharp's cloud; app account pairing remains a separate step.", flush=True)
    report = await run_trial(args.host, register_on_server=args.register_on_server)
    print(json.dumps(report, indent=2))
    print("No automatic registration retry is performed. Share this report and the display status.")
    if report["outcome"] == "module_registration_reported_success":
        return 0
    if report["registration_code"] is not None or report["outcome"] == "module_error":
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main(build_parser().parse_args())))
