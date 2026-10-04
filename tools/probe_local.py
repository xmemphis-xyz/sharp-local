"""Read-only Sharp LAN probe using only the Python standard library."""
import argparse
import asyncio
import importlib.util
import ipaddress
import sys
from pathlib import Path

path = Path(__file__).parents[1] / "custom_components/sharp_life_air_local/protocol.py"
spec = importlib.util.spec_from_file_location("sharp_local_protocol", path)
protocol = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = protocol
spec.loader.exec_module(protocol)


async def main(args):
    client = protocol.SharpLocalClient(args.host, bind_ip=args.bind_ip)
    try:
        state = await client.update(udp=not args.tcp_only, broadcast=args.broadcast)
    except (OSError, TimeoutError, protocol.ProtocolError) as err:
        print(f"TCP: FAILED ({type(err).__name__})")
        return 1
    print("TCP 8765: signed get_info OK")
    print(f"Module firmware: {state.module.version}")
    print(f"Module flags: 0x{state.module.flags:04X}")
    print(f"UDP 8766: {state.udp_status}")
    if state.object_id:
        print(f"Purifier object: {state.object_id.hex()}")
        print("Writable property codes:", ", ".join(f"{code:02X}" for code in sorted(state.set_map)) or "none")
        print("Returned property lengths:", {f"{code:02X}": len(value) for code, value in state.properties.items()})
        print("Readings:", protocol.decode_readings(state.properties))
    print("No control commands sent. Cloud key and MAC address are omitted.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", type=lambda value: str(ipaddress.IPv4Address(value)))
    parser.add_argument("--bind-ip", default="0.0.0.0", type=lambda value: str(ipaddress.IPv4Address(value)))
    parser.add_argument("--broadcast", type=lambda value: str(ipaddress.IPv4Address(value)), help="Optional directed broadcast in the purifier subnet")
    parser.add_argument("--tcp-only", action="store_true")
    raise SystemExit(asyncio.run(main(parser.parse_args())))
