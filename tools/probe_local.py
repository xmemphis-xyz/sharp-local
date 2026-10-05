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


def air_object(value):
    """Accept only a concrete air-purifier instance confirmed by discovery."""
    try:
        object_id = bytes.fromhex(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("Use a confirmed air-purifier EOJ such as 013501") from error
    if len(object_id) != 3 or object_id[:2] != bytes.fromhex("0135") or not object_id[2]:
        raise argparse.ArgumentTypeError("Use a confirmed air-purifier EOJ such as 013501")
    return object_id


async def read_state(args):
    client = protocol.SharpLocalClient(args.host, bind_ip=args.bind_ip)
    if args.direct_object is not None:
        module = await protocol.get_info(args.host)
        # Reuse the bounded, read-only power probe with its own maps. Unlike
        # normal polling, this explicit test bypasses node-list discovery on
        # 3610 using an instance supplied from a recent discovery report.
        return await client._probe(
            module, protocol.ECHONET_PORT, protocol.CONTROLLER, None,
            known_object=args.direct_object,
        )
    return await client.update(udp=not args.tcp_only, broadcast=args.broadcast)


async def main(args):
    try:
        state = await read_state(args)
    except (OSError, TimeoutError, protocol.ProtocolError) as err:
        print(f"TCP: FAILED ({type(err).__name__})")
        return 1
    print("TCP 8765: signed get_info OK")
    print(f"Module firmware: {state.module.version}")
    print(f"Module flags: 0x{state.module.flags:04X}")
    label = "UDP 3610 direct power probe" if args.direct_object is not None else "UDP 3610 / 8766"
    print(f"{label}: {state.udp_status}")
    print(f"Selected state/control port: {state.udp_port or 'none'}")
    print("UDP diagnostics:", state.udp_diagnostics)
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
    parser.add_argument("--broadcast", default="255.255.255.255", type=lambda value: str(ipaddress.IPv4Address(value)), help="Broadcast address in the purifier subnet (default: limited broadcast)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--tcp-only", action="store_true")
    mode.add_argument(
        "--direct-object", type=air_object,
        help="Read power on UDP 3610 for an EOJ confirmed by recent discovery; bypass node discovery",
    )
    raise SystemExit(asyncio.run(main(parser.parse_args())))
