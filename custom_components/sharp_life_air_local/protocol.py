"""Sharp local protocol, independent of Home Assistant and cloud services.

TCP 8765 get_info and UDP 8766 discovery follow Sharp Life AIR EU 1.0.4.
UDP power control uses ECHONET SetC only after the device advertises EPC 80
in its Set property map. Availability on KI-TX100EU remains unverified.
"""
from __future__ import annotations

import asyncio
import errno
import hashlib
import hmac
import secrets
import socket
from contextlib import suppress
from dataclasses import dataclass, field

TCP_PORT = 8765
UDP_PORT = 8766
SOURCE = bytes.fromhex("05fe01")
NODE = bytes.fromhex("0ef001")
_KEY_DATA = (
    "535d0d560600075a0d510155030a5e07570f0b0a0f54025356550252520b00005d"
    "045808090c030052505354075704530707000001015651075602500402543d"
)
READ_CODES = (0x80, 0x84, 0x85, 0x88, 0xA0, 0xF1, 0xF3)


class ProtocolError(Exception):
    """Invalid or rejected local protocol exchange."""


def protocol_key() -> bytes:
    """Decode the fixed protocol signing key embedded in the official app."""
    encoded = bytes.fromhex(_KEY_DATA)
    result = bytearray(len(encoded))
    previous = 94
    for index in range(len(encoded) - 1, -1, -1):
        previous ^= encoded[index]
        result[index] = previous
    return bytes.fromhex(result.decode("ascii"))


@dataclass(frozen=True)
class ModuleInfo:
    version: str
    flags: int
    mac: str = field(repr=False)


@dataclass(frozen=True)
class Frame:
    tid: int
    source: bytes
    destination: bytes
    esv: int
    properties: dict[int, bytes]


@dataclass(frozen=True)
class LocalState:
    module: ModuleInfo
    udp_status: str
    object_id: bytes | None = None
    properties: dict[int, bytes] = field(default_factory=dict, repr=False)
    set_map: frozenset[int] = frozenset()

    @property
    def power_controllable(self) -> bool:
        return self.object_id is not None and 0x80 in self.set_map


async def get_info(host: str, port: int = TCP_PORT, timeout: float = 10) -> ModuleInfo:
    """Read signed module info; discard the returned 256-byte cloud key."""
    writer = None
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(bytes(8))
            await writer.drain()
            hello = await reader.readexactly(32)
            nonce = hello[:16]
            if not hmac.compare_digest(hashlib.md5(nonce).digest(), hello[16:]):
                raise ProtocolError("Invalid Sharp handshake")
            command = bytes.fromhex("0002")
            key = protocol_key()
            signature = hmac.digest(key, nonce + command, "sha256")
            writer.write(b"\x00\x24" + signature + command)
            await writer.drain()
            header = await reader.readexactly(2)
            size = int.from_bytes(header, "big")
            if not 36 <= size <= 4096:
                raise ProtocolError("Invalid Sharp response length")
            body = await reader.readexactly(size - 2)
            payload = body[32:]
            if not hmac.compare_digest(hmac.digest(key, nonce + payload, "sha256"), body[:32]):
                raise ProtocolError("Invalid Sharp response signature")
            if payload[:2] != bytes.fromhex("8002") or len(payload) < 270:
                raise ProtocolError("Sharp rejected get_info or returned incomplete data")
            mac = payload[264:270]
            if mac in (bytes(6), b"\xff" * 6):
                raise ProtocolError("Invalid Sharp module identity")
            version = f"{payload[2]}.{payload[3]}.{int.from_bytes(payload[4:6], 'big')}"
            return ModuleInfo(version, int.from_bytes(payload[6:8], "big"), mac.hex())
    except asyncio.IncompleteReadError as err:
        raise ProtocolError("Sharp closed the connection before a complete response") from err
    finally:
        if writer is not None:
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()


def encode_frame(tid: int, destination: bytes, esv: int, properties: dict[int, bytes]) -> bytes:
    if len(destination) != 3 or not 0 < len(properties) <= 255:
        raise ProtocolError("Invalid ECHONET request")
    frame = bytearray(b"\x10\x81" + tid.to_bytes(2, "big") + SOURCE + destination)
    frame.extend((esv, len(properties)))
    for code, value in properties.items():
        if len(value) > 255:
            raise ProtocolError("ECHONET value is too long")
        frame.extend((code, len(value)))
        frame.extend(value)
    return bytes(frame)


def decode_frame(data: bytes) -> Frame:
    if len(data) < 12 or data[:2] != b"\x10\x81":
        raise ProtocolError("Invalid ECHONET header")
    offset = 12
    properties = {}
    for _ in range(data[11]):
        if offset + 2 > len(data):
            raise ProtocolError("Truncated ECHONET property")
        code, length = data[offset:offset + 2]
        end = offset + 2 + length
        if end > len(data) or code in properties:
            raise ProtocolError("Truncated or duplicate ECHONET property")
        properties[code] = data[offset + 2:end]
        offset = end
    if offset != len(data):
        raise ProtocolError("Unexpected ECHONET trailing bytes")
    return Frame(int.from_bytes(data[2:4], "big"), data[4:7], data[7:10], data[10], properties)


def property_map(data: bytes) -> frozenset[int]:
    if not data:
        return frozenset()
    count = data[0]
    if count < 16:
        if len(data) != count + 1:
            raise ProtocolError("Invalid ECHONET property list")
        return frozenset(data[1:])
    if len(data) != 17:
        raise ProtocolError("Invalid ECHONET property bitmap")
    result = frozenset(0x80 + (bit << 4) + index
                       for index, value in enumerate(data[1:])
                       for bit in range(8) if value & (1 << bit))
    if len(result) != count:
        raise ProtocolError("ECHONET property map count does not match")
    return result


def decode_readings(properties: dict[int, bytes]) -> dict:
    """Decode only fields with known sizes; empty values remain unknown."""
    result = {}
    power = properties.get(0x80)
    if power in (b"\x30", b"\x31"):
        result["power"] = "on" if power == b"\x30" else "off"
    watts = properties.get(0x84, b"")
    if len(watts) == 2 and watts != b"\xff\xff":
        result["power_watts"] = int.from_bytes(watts, "big")
    detail = properties.get(0xF1, b"")
    if len(detail) >= 5:
        temperature = int.from_bytes(detail[3:4], "big", signed=True)
        if -50 <= temperature <= 80:
            result["temperature_c"] = temperature
        if detail[4] <= 100:
            result["humidity_pct"] = detail[4]
    return result


class _Receiver(asyncio.DatagramProtocol):
    def __init__(self, host: str):
        self.host = host
        self.queue = asyncio.Queue(maxsize=32)

    def datagram_received(self, data, address):
        if address[0] == self.host and not self.queue.full():
            self.queue.put_nowait(data)

    def error_received(self, error):
        if not self.queue.full():
            self.queue.put_nowait(error)


class EchonetChannel:
    """Short-lived UDP socket; validate peer, transaction and object IDs."""

    def __init__(self, host: str, *, port=UDP_PORT, bind_ip="0.0.0.0", bind_port=UDP_PORT, timeout=2):
        self.host = host
        self.port = port
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.timeout = timeout
        self.transport = None
        self.receiver = None
        self.tid = secrets.randbelow(65536)

    async def __aenter__(self):
        loop = asyncio.get_running_loop()
        self.transport, self.receiver = await loop.create_datagram_endpoint(
            lambda: _Receiver(self.host), local_addr=(self.bind_ip, self.bind_port),
            family=socket.AF_INET,
        )
        self.transport.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        return self

    async def __aexit__(self, *args):
        self.transport.close()

    async def request(self, destination, properties, *, esv=0x62, target=None, attempts=1):
        self.tid = (self.tid + 1) & 0xFFFF
        request = encode_frame(self.tid, destination, esv, properties)
        loop = asyncio.get_running_loop()
        for _ in range(attempts):
            self.transport.sendto(request, (target or self.host, self.port))
            deadline = loop.time() + self.timeout
            while loop.time() < deadline:
                try:
                    data = await asyncio.wait_for(self.receiver.queue.get(), deadline - loop.time())
                except TimeoutError:
                    break
                if isinstance(data, OSError):
                    raise data
                try:
                    frame = decode_frame(data)
                except ProtocolError:
                    continue
                expected = (0x72, 0x52) if esv == 0x62 else (0x71, 0x51)
                if (frame.tid != self.tid or frame.source != destination
                        or frame.destination != SOURCE or frame.esv not in expected
                        or not set(properties).issubset(frame.properties)):
                    continue
                if esv == 0x61 and frame.esv != 0x71:
                    raise ProtocolError("Sharp rejected local power control")
                return frame.properties
        raise TimeoutError("No Sharp ECHONET response")

    async def discover(self, *, broadcast=None):
        profile = await self.request(NODE, {0xD6: b"", 0x8C: b""},
                                     target=broadcast, attempts=3)
        objects = profile.get(0xD6, b"")
        if not objects or len(objects) != 1 + objects[0] * 3:
            raise ProtocolError("Sharp returned an invalid object list")
        candidates = [objects[index:index + 3] for index in range(1, len(objects), 3)
                      if objects[index:index + 2] == bytes.fromhex("0135")]
        if len(candidates) != 1:
            raise ProtocolError("Expected exactly one air purifier object")
        object_id = candidates[0]
        maps = await self.request(object_id, {0x9E: b"", 0x9F: b""})
        writable = property_map(maps.get(0x9E, b""))
        readable = property_map(maps.get(0x9F, b""))
        codes = [code for code in READ_CODES if not readable or code in readable]
        readings = await self.request(object_id, {code: b"" for code in codes}) if codes else {}
        return object_id, writable, {code: value for code, value in readings.items() if value}


class SharpLocalClient:
    def __init__(self, host: str, *, tcp_port=TCP_PORT, bind_ip="0.0.0.0", bind_port=UDP_PORT):
        self.host = host
        self.tcp_port = tcp_port
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.lock = asyncio.Lock()
        self.state = None

    def _channel(self):
        return EchonetChannel(self.host, bind_ip=self.bind_ip, bind_port=self.bind_port)

    async def update(self, *, udp=True, broadcast=None) -> LocalState:
        async with self.lock:
            module = await get_info(self.host, self.tcp_port)
            object_id, writable, readings = None, frozenset(), {}
            status = "not_tested"
            if udp:
                try:
                    async with self._channel() as channel:
                        object_id, writable, readings = await channel.discover(broadcast=broadcast)
                    status = "power_control_available" if 0x80 in writable else "read_only"
                except TimeoutError:
                    status = "no_response"
                except ProtocolError:
                    status = "unsupported_response"
                except OSError as err:
                    status = {
                        errno.EPERM: "permission_denied", errno.EACCES: "permission_denied",
                        errno.EADDRINUSE: "port_in_use", errno.ECONNREFUSED: "port_closed",
                    }.get(err.errno, "socket_error")
            self.state = LocalState(module, status, object_id, readings, writable)
            return self.state

    async def set_power(self, on: bool):
        async with self.lock:
            if self.state is None or not self.state.power_controllable:
                raise ProtocolError("Local power control has not been advertised by this device")
            async with self._channel() as channel:
                await channel.request(self.state.object_id, {0x80: b"\x30" if on else b"\x31"}, esv=0x61)
