"""Send one explicitly requested local power command after fresh discovery.

This is a manual experiment, separate from the read-only HA polling client.
An acknowledgement without valid power readback remains unconfirmed.
"""
import argparse
import asyncio
import importlib.util
import ipaddress
import json
import sys
from pathlib import Path

path = Path(__file__).parents[1] / "custom_components/sharp_life_air_local/protocol.py"
spec = importlib.util.spec_from_file_location("sharp_local_power_trial_protocol", path)
protocol = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = protocol
spec.loader.exec_module(protocol)


async def run_trial(host, power, *, bind_ip="0.0.0.0", broadcast="255.255.255.255"):
    """Report one SetC result; never retry a write or assume a power state."""
    if power not in ("on", "off"):
        raise ValueError("Choose on or off explicitly")
    report = {
        "requested_power": power,
        "write_result": "not_sent",
        "power_readback": None,
        "outcome": "not_run",
    }
    channel = None
    phase = "tcp"
    try:
        module = await protocol.get_info(host)
        report["module_firmware"] = module.version
        report["module_flags"] = f"0x{module.flags:04X}"
        phase = "preparation"
        channel = protocol.EchonetChannel(
            host, port=protocol.UDP_PORT, source=protocol.SOURCE, bind_ip=bind_ip,
        )
        async with channel:
            # Use the actual instance and a fresh Set map from this exact
            # endpoint/source. A rejected Get does not grant write permission.
            async with asyncio.timeout(protocol.UDP_PROBE_TIMEOUT):
                object_id, writable, _ = await channel.discover(broadcast=broadcast)
            report["object_id"] = object_id.hex()
            if 0x80 not in writable:
                report["outcome"] = "power_write_not_advertised"
                return report

            phase = "write"
            channel.diagnostics["stage"] = "power_write"
            # A missing acknowledgement leaves the physical effect unknown.
            report["write_result"] = "unknown"
            acknowledgement = await channel.request(
                object_id, {0x80: bytes((0x30 if power == "on" else 0x31,))}, esv=0x61,
                attempts=1,
            )
            if acknowledgement != {0x80: b""}:
                report["write_result"] = "unsupported_acknowledgement"
                report["outcome"] = "write_unconfirmed"
                return report
            report["write_result"] = "acknowledged"
            report["outcome"] = "acknowledged_unconfirmed"

            phase = "readback"
            await asyncio.sleep(0.5)
            channel.diagnostics["stage"] = "power_readback"
            values = await channel.request(object_id, {0x80: b""}, attempts=1)
            actual = protocol.decode_readings(values).get("power")
            report["power_readback"] = actual
            if actual == power:
                report["outcome"] = "verified_by_readback"
            elif actual is not None:
                report["outcome"] = "readback_mismatch"
    except (OSError, TimeoutError, protocol.ProtocolError) as error:
        report["error_type"] = type(error).__name__
        if isinstance(error, OSError) and error.errno is not None:
            report["error_number"] = error.errno
        if phase == "readback":
            report["outcome"] = "acknowledged_unconfirmed"
        elif phase == "write":
            responses = channel.diagnostics.get("responses", [])
            rejected = any(item["stage"] == "power_write" and item["esv"] == "51"
                           for item in responses)
            if rejected:
                report["write_result"] = "rejected"
                report["outcome"] = "write_rejected"
            else:
                report["outcome"] = "write_unconfirmed"
        else:
            report["outcome"] = "preparation_failed"
    finally:
        report["phase"] = phase
        if channel is not None:
            report["udp_diagnostics"] = channel.diagnostics
    return report


async def main(args):
    print(f"Manual trial: at most one local power {args.power.upper()} command.")
    report = await run_trial(args.host, args.power, bind_ip=args.bind_ip,
                             broadcast=args.broadcast)
    print(json.dumps(report, indent=2))
    print("Check the physical purifier. No automatic power command retry is performed.")
    if report["outcome"] == "verified_by_readback":
        return 0
    if report["write_result"] in ("acknowledged", "unknown", "unsupported_acknowledgement"):
        return 2
    return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", type=lambda value: str(ipaddress.IPv4Address(value)))
    parser.add_argument("power", choices=("on", "off"), help="The one power command to send")
    parser.add_argument("--bind-ip", default="0.0.0.0",
                        type=lambda value: str(ipaddress.IPv4Address(value)))
    parser.add_argument("--broadcast", default="255.255.255.255",
                        type=lambda value: str(ipaddress.IPv4Address(value)))
    raise SystemExit(asyncio.run(main(parser.parse_args())))
