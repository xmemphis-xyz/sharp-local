"""Sharp local protocol, independent of Home Assistant and cloud services.

TCP 8765 get_info and UDP 8766 discovery follow Sharp Life AIR EU 1.0.4.
Initial state/control probes use standard ECHONET UDP 3610/05ff01, then the
app transport. A bounded 8766/05ff01 power probe is experimental. A write
requires a valid power read and Set map from the same transport. Confirmed
transports are preferred on later polls. KI-TX100EU control is unverified.
"""
from __future__ import annotations

import asyncio
import errno
import hashlib
import hmac
import secrets
import socket
from weakref import WeakKeyDictionary
from contextlib import suppress
from dataclasses import dataclass, field

TCP_PORT = 8765
UDP_PORT = 8766
ECHONET_PORT = 3610
UDP_PROBE_TIMEOUT = 20
UDP_POWER_PROBE_TIMEOUT = 4.5
MULTICAST = "224.0.23.0"
SOURCE = bytes.fromhex("05fe01")
CONTROLLER = bytes.fromhex("05ff01")
NODE = bytes.fromhex("0ef001")
_PORT_LOCKS = WeakKeyDictionary()
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
    udp_diagnostics: dict = field(default_factory=dict)
    udp_port: int | None = None
    source_object: bytes | None = None

    @property
    def power_controllable(self) -> bool:
        return (self.object_id is not None and self.udp_port is not None
                and self.source_object is not None and 0x80 in self.set_map
                and self.properties.get(0x80) in (b"\x30", b"\x31"))


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


def encode_frame(tid: int, destination: bytes, esv: int, properties: dict[int, bytes],
                 *, source: bytes = SOURCE) -> bytes:
    if len(source) != 3 or len(destination) != 3 or not 0 < len(properties) <= 255:
        raise ProtocolError("Invalid ECHONET request")
    frame = bytearray(b"\x10\x81" + tid.to_bytes(2, "big") + source + destination)
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
        self.closed = asyncio.get_running_loop().create_future()

    def connection_lost(self, error):
        if not self.closed.done():
            self.closed.set_result(None)

    def datagram_received(self, data, address):
        if address[0] == self.host and not self.queue.full():
            self.queue.put_nowait(data)

    def error_received(self, error):
        if not self.queue.full():
            self.queue.put_nowait(error)


class EchonetChannel:
    """Short-lived UDP socket; validate peer, transaction and object IDs."""

    def __init__(self, host: str, *, port=UDP_PORT, source=SOURCE,
                 bind_ip="0.0.0.0", bind_port=None, timeout=2):
        self.host = host
        self.port = port
        self.bind_ip = bind_ip
        self.bind_port = port if bind_port is None else bind_port
        self.source = source
        self.timeout = timeout
        self.transport = None
        self.receiver = None
        self.port_lock = None
        self.object_id = None
        self.writable = frozenset()
        self.properties = {}
        self.tid = secrets.randbelow(65536)
        self.diagnostics = {"stage": "socket", "port": port,
                            "source_object": source.hex(), "bind_port": self.bind_port,
                            "sent": 0, "received": 0,
                            "invalid_frames": 0, "unmatched_frames": 0}

    async def __aenter__(self):
        loop = asyncio.get_running_loop()
        if self.bind_port:
            # Fixed reply ports cannot be shared by independent sockets.
            # Serialize this integration's clients; report external conflicts.
            locks = _PORT_LOCKS.setdefault(loop, {})
            port_lock = locks.setdefault(self.bind_port, asyncio.Lock())
            self.diagnostics["stage"] = "waiting_for_port"
            await port_lock.acquire()
            self.port_lock = port_lock
        self.diagnostics["stage"] = "socket"
        try:
            self.transport, self.receiver = await loop.create_datagram_endpoint(
                lambda: _Receiver(self.host), local_addr=(self.bind_ip, self.bind_port),
                family=socket.AF_INET,
            )
            self.transport.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            if self.bind_ip != "0.0.0.0":
                self.transport.get_extra_info("socket").setsockopt(
                    socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self.bind_ip)
                )
        except BaseException:
            await self._close()
            raise
        return self

    async def __aexit__(self, *args):
        await self._close()

    async def _close(self):
        try:
            if self.transport is not None:
                self.transport.close()
                await self.receiver.closed
        finally:
            if self.port_lock is not None:
                self.port_lock.release()
                self.port_lock = None

    async def request(self, destination, properties, *, esv=0x62, target=None, attempts=1):
        self.tid = (self.tid + 1) & 0xFFFF
        request = encode_frame(self.tid, destination, esv, properties, source=self.source)
        loop = asyncio.get_running_loop()
        for _ in range(attempts):
            self.transport.sendto(request, (target or self.host, self.port))
            self.diagnostics["sent"] += 1
            deadline = loop.time() + self.timeout
            while loop.time() < deadline:
                try:
                    data = await asyncio.wait_for(self.receiver.queue.get(), deadline - loop.time())
                except TimeoutError:
                    break
                if isinstance(data, OSError):
                    raise data
                self.diagnostics["received"] += 1
                try:
                    frame = decode_frame(data)
                except ProtocolError:
                    self.diagnostics["invalid_frames"] += 1
                    continue
                expected = (0x72, 0x52) if esv == 0x62 else (0x71, 0x51)
                if (frame.tid != self.tid or frame.source != destination
                        or frame.destination != self.source or frame.esv not in expected
                        or not set(properties).intersection(frame.properties)):
                    self.diagnostics["unmatched_frames"] += 1
                    continue
                response = {
                    "stage": self.diagnostics["stage"],
                    "object_id": destination.hex(),
                    "requested_codes": [f"{code:02X}" for code in properties],
                    "esv": f"{frame.esv:02X}",
                    "property_lengths": {
                        f"{code:02X}": len(value) for code, value in frame.properties.items()
                    },
                }
                history = self.diagnostics.setdefault("responses", [])
                if len(history) < 32:
                    history.append(response)
                if esv == 0x61 and frame.esv != 0x71:
                    raise ProtocolError("Sharp rejected local power control")
                return frame.properties
        raise TimeoutError("No Sharp ECHONET response")

    async def discover(self, *, broadcast=None):
        # The APK sends this Get to the subnet broadcast, with multicast as
        # fallback. Some modules ignore an otherwise identical unicast Get.
        targets = [("unicast", self.host)]
        if broadcast:
            targets.append(("broadcast", broadcast))
        targets.append(("multicast", MULTICAST))
        for method, target in targets:
            self.diagnostics["stage"] = "discovery"
            self.diagnostics["discovery_method"] = method
            try:
                discovery_codes = (0xD6, 0x8C) if self.source == SOURCE else (0xD6,)
                profile = await self.request(NODE, {code: b"" for code in discovery_codes},
                                             target=target, attempts=2)
                break
            except TimeoutError:
                continue
        else:
            raise TimeoutError("No Sharp object-list response")
        objects = profile.get(0xD6, b"")
        if not objects or len(objects) != 1 + objects[0] * 3:
            raise ProtocolError("Sharp returned an invalid object list")
        candidates = [objects[index:index + 3] for index in range(1, len(objects), 3)
                      if objects[index:index + 2] == bytes.fromhex("0135")]
        if len(candidates) != 1:
            raise ProtocolError("Expected exactly one air purifier object")
        object_id = candidates[0]
        self.object_id = object_id
        self.diagnostics["object_id"] = object_id.hex()
        # Vendor identification belongs to the official app's discovery
        # endpoint. Standard ECHONET needs only the instance list and maps.
        if self.source == SOURCE:
            self.diagnostics["stage"] = "identification"
            try:
                identity = await self.request(object_id, {
                    code: b"" for code in (0x8A, 0x8C, 0xF0, 0xFC, 0xFD)
                })
                self.diagnostics["identification_lengths"] = {
                    f"{code:02X}": len(value) for code, value in identity.items()
                }
            except TimeoutError:
                self.diagnostics["identification_timeout"] = True
        self.diagnostics["stage"] = "property_maps"
        # A missing map must not hide otherwise readable purifier data.
        maps = {}
        try:
            maps = await self.request(object_id, {0x9E: b"", 0x9F: b""})
        except TimeoutError:
            self.diagnostics["map_timeout"] = True
        for code in (0x9E, 0x9F):
            if code not in maps:
                try:
                    maps.update(await self.request(object_id, {code: b""}))
                except TimeoutError:
                    self.diagnostics.setdefault("missing_maps", []).append(f"{code:02X}")
        writable = property_map(maps.get(0x9E, b""))
        self.writable = writable
        readable = property_map(maps.get(0x9F, b""))
        self.diagnostics["writable_codes"] = [f"{code:02X}" for code in sorted(writable)]
        self.diagnostics["readable_codes"] = [f"{code:02X}" for code in sorted(readable)]
        codes = [code for code in READ_CODES if not readable or code in readable]
        self.diagnostics["stage"] = "readings"
        readings = {}
        self.properties = readings
        if codes:
            try:
                readings.update(await self.request(object_id, {code: b"" for code in codes}))
            except TimeoutError:
                self.diagnostics["readings_timeout"] = True
            self.diagnostics["batch_property_lengths"] = {
                f"{code:02X}": len(value) for code, value in readings.items()
            }
            # The physical KI-TX returns a valid response with zero-length
            # values for a mixed Get. That must trigger isolated reads too,
            # even though no timeout occurred. Preserve useful batch values.
            for code in codes:
                if readings.get(code):
                    continue
                self.diagnostics.setdefault("individual_read_codes", []).append(f"{code:02X}")
                try:
                    isolated = await self.request(object_id, {code: b""})
                    if code in isolated:
                        readings[code] = isolated[code]
                except TimeoutError:
                    self.diagnostics.setdefault("individual_timeouts", []).append(f"{code:02X}")
        self.diagnostics["property_lengths"] = {
            f"{code:02X}": len(value) for code, value in readings.items()
        }
        self.diagnostics["stage"] = "complete"
        return object_id, writable, {code: value for code, value in readings.items() if value}

    async def probe_power(self, object_id):
        """Compare the controller source on a confirmed app endpoint.

        This is an experimental read-only capability probe. Do not reuse the
        app source's Set map to grant permission to the controller source.
        """
        self.object_id = object_id
        self.diagnostics["object_id"] = object_id.hex()
        self.diagnostics["discovery_method"] = "known_app_object"
        self.diagnostics["stage"] = "power_probe"
        power = await self.request(object_id, {0x80: b""})
        self.diagnostics["property_lengths"] = {"80": len(power.get(0x80, b""))}
        if power.get(0x80) not in (b"\x30", b"\x31"):
            self.diagnostics["stage"] = "complete"
            return
        self.properties[0x80] = power[0x80]
        self.diagnostics["stage"] = "property_maps"
        maps = await self.request(object_id, {0x9E: b"", 0x9F: b""})
        writable = property_map(maps.get(0x9E, b""))
        readable = property_map(maps.get(0x9F, b""))
        self.writable = writable
        self.diagnostics["writable_codes"] = [f"{code:02X}" for code in sorted(writable)]
        self.diagnostics["readable_codes"] = [f"{code:02X}" for code in sorted(readable)]
        self.diagnostics["stage"] = "complete"


class SharpLocalClient:
    def __init__(self, host: str, *, tcp_port=TCP_PORT, bind_ip="0.0.0.0", bind_port=None):
        self.host = host
        self.tcp_port = tcp_port
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.lock = asyncio.Lock()
        self.state = None

    def _channel(self, *, port=ECHONET_PORT, source=CONTROLLER):
        return EchonetChannel(self.host, port=port, source=source,
                              bind_ip=self.bind_ip, bind_port=self.bind_port)

    async def _probe(self, module, port, source, broadcast, *, known_object=None):
        channel = self._channel(port=port, source=source)
        status = "no_readings"
        budget = asyncio.timeout(UDP_POWER_PROBE_TIMEOUT if known_object else UDP_PROBE_TIMEOUT)
        try:
            async with budget, channel:
                if known_object:
                    await channel.probe_power(known_object)
                else:
                    await channel.discover(broadcast=broadcast)
        except TimeoutError:
            status = "no_response"
            if budget.expired():
                channel.diagnostics["probe_timeout"] = True
        except ProtocolError:
            status = "unsupported_response"
        except OSError as err:
            status = {
                errno.EPERM: "permission_denied", errno.EACCES: "permission_denied",
                errno.EADDRINUSE: "port_in_use", errno.ECONNREFUSED: "port_closed",
            }.get(err.errno, "socket_error")
        # Keep completed reads if a later optional field exhausts the budget.
        # Maps and values always belong to this one port/source pair.
        readings = {code: value for code, value in channel.properties.items() if value}
        if readings:
            status = ("power_control_available" if 0x80 in channel.writable
                      and readings.get(0x80) in (b"\x30", b"\x31") else "read_only")
        channel.diagnostics["status"] = status
        return LocalState(module, status, channel.object_id, readings, channel.writable,
                          dict(channel.diagnostics), port if readings else None,
                          source if readings else None)

    async def update(self, *, udp=True, broadcast="255.255.255.255") -> LocalState:
        async with self.lock:
            module = await get_info(self.host, self.tcp_port)
            if not udp:
                self.state = LocalState(module, "not_tested")
                return self.state
            candidates = []
            profiles = [(ECHONET_PORT, CONTROLLER, None), (UDP_PORT, SOURCE, None)]
            previous = self.state
            if (previous is not None and previous.power_controllable
                    and previous.module.mac == module.mac
                    and (previous.udp_port, previous.source_object) in (
                        (ECHONET_PORT, CONTROLLER), (UDP_PORT, SOURCE), (UDP_PORT, CONTROLLER),
                    )):
                known_object = (previous.object_id if (previous.udp_port, previous.source_object)
                                == (UDP_PORT, CONTROLLER) else None)
                profiles.insert(0, (previous.udp_port, previous.source_object, known_object))
            tested = set()
            for port, source, known_object in profiles:
                if (port, source) in tested:
                    continue
                tested.add((port, source))
                candidate = await self._probe(module, port, source, broadcast, known_object=known_object)
                candidates.append(candidate)
                if candidate.power_controllable:
                    break
            if not any(item.power_controllable for item in candidates):
                app_object = next((item.object_id for item in candidates
                                   if item.udp_diagnostics.get("port") == UDP_PORT
                                   and item.udp_diagnostics.get("source_object") == SOURCE.hex()
                                   and item.object_id is not None), None)
                if app_object is not None and (UDP_PORT, CONTROLLER) not in tested:
                    candidates.append(await self._probe(
                        module, UDP_PORT, CONTROLLER, broadcast, known_object=app_object,
                    ))
            # Prefer usable state; retain app metadata when neither can read.
            selected = max(candidates, key=lambda item: (
                item.power_controllable, len(decode_readings(item.properties)),
                bool(item.properties), item.object_id is not None,
            ))
            evidence = dict(selected.udp_diagnostics)
            evidence["selected_port"] = selected.udp_port
            evidence["selected_source_object"] = (selected.source_object.hex()
                                                  if selected.source_object else None)
            evidence["transports"] = [item.udp_diagnostics for item in candidates]
            self.state = LocalState(module, selected.udp_status, selected.object_id,
                                    selected.properties, selected.set_map, evidence,
                                    selected.udp_port, selected.source_object)
            return self.state

    async def set_power(self, on: bool):
        async with self.lock:
            if self.state is None or not self.state.power_controllable:
                raise ProtocolError("Local power control has not been advertised by this device")
            async with self._channel(port=self.state.udp_port, source=self.state.source_object) as channel:
                await channel.request(self.state.object_id, {0x80: b"\x30" if on else b"\x31"}, esv=0x61)
                expected = b"\x30" if on else b"\x31"
                for attempt in range(3):
                    if attempt:
                        await asyncio.sleep(0.5)
                    try:
                        power = await channel.request(self.state.object_id, {0x80: b""})
                    except TimeoutError:
                        continue
                    if power.get(0x80) == expected:
                        return
                raise ProtocolError("Sharp acknowledged power but did not confirm the requested state")
