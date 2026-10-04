# Sharp Life AIR Local

Experimental Home Assistant integration for a direct LAN connection to the
Sharp Life AIR EU Wi-Fi module. No account, Internet access or cloud API is
required. Separate from [Sharp Life AIR cloud](https://github.com/xmemphis-xyz/sharp).

## What is confirmed

KI-TX100EU answered TCP 8765 from another subnet. The official app's handshake,
HMAC-signed `get_info` response and module firmware `1.0.1` were verified on the
physical device. This release implements that exchange and local diagnostics.

**Full local purifier control is not yet confirmed on KI-TX100EU.** The TCP
commands found in the APK configure the Wi-Fi module, rather than control the
fan. This integration does not send firmware, registration, reset or unlink
commands. Do not confuse module firmware with purifier firmware.

UDP 8766 uses the app's ECHONET source object `05fe01` and discovers the actual
purifier object. It reads the Get and Set property maps. A fan entity is added
only if the purifier advertises writable power property `80`. Pressing its
on/off control then uses standard ECHONET SetC and requires an acknowledgement.
There is no guessed TCP power command, no cloud fallback, and no local mode or
humidification write in this release. An advertised capability still needs a
physical-device test to confirm that it changes the requested state.

## Install

HACS → three-dot menu → **Custom repositories** →
`https://github.com/xmemphis-xyz/sharp-local` → **Integration**.
Download **Sharp Life AIR Local**, restart Home Assistant, then
**Settings → Devices & services → Add Integration → Sharp Life AIR Local**.
Enter the purifier IP address, for example `192.168.2.243`.

Manual alternative: extract the release ZIP into `/config`, so the component
is `/config/custom_components/sharp_life_air_local`, and restart HA.

It can coexist with the cloud integration; it never logs into Sharp or changes
cloud terminal registrations. Use a DHCP reservation for the purifier.

## Entities and options

- Module firmware, module flags, and Local protocol diagnostic sensors.
- Refresh local connection button.
- Power, temperature and humidity sensors appear when UDP returns these fields.
- Air purifier fan on/off appears only after confirmed Set-map support.

Polling interval: 60 seconds. Empty, malformed or missing properties stay
unknown. Missing UDP responses do not make a successful TCP connection fail.
Under integration options, disable **Probe UDP purifier protocol** for TCP-only
diagnostics, or set **Home Assistant local IPv4 address**. `0.0.0.0` selects the
interface automatically. A specific bind address must exist on the HA host.

| Local protocol | Meaning |
| --- | --- |
| `not_tested` | UDP probing disabled |
| `no_response` | UDP did not answer; routing, filtering or firmware may be involved |
| `port_closed` | The OS reported the UDP destination unreachable |
| `port_in_use` | Another process uses local UDP 8766 |
| `permission_denied` | The OS blocked the UDP operation |
| `socket_error` | Another local socket error |
| `unsupported_response` | Response cannot be used for this purifier protocol |
| `read_only` | Valid purifier response without writable power support |
| `power_control_available` | Device advertises writable power; physical test still required |

Between VLANs, allow HA ↔ purifier TCP 8765 and UDP 8766 (including replies).
Broadcast normally stays in one subnet. A TCP handshake proves TCP connectivity,
not UDP reachability or full local control. Multicast/broadcast forwarding is
not required for the integration's unicast probe, but some firmware may only
answer discovery on the same subnet.

## Standalone read-only probe

Python 3.12 or newer; no pip packages needed. On diomedes, as root:

```bash
cd /opt
git clone https://github.com/xmemphis-xyz/sharp-local.git
cd /opt/sharp-local
python3 tools/probe_local.py 192.168.2.243
```

If already cloned, use `git pull --ff-only` from `/opt/sharp-local`.
TCP-only test:

```bash
python3 tools/probe_local.py 192.168.2.243 --tcp-only
```

On a machine actually connected to the purifier subnet, a directed broadcast
can also be tested. Example for a /24 network and phone address `192.168.2.157`:

```bash
python tools/probe_local.py 192.168.2.243 --bind-ip 192.168.2.157 --broadcast 192.168.2.255
```

Do not bind diomedes to the phone's address. An Android `permission_denied`
result means no successful UDP test was completed; it does not establish the
purifier's capabilities. Fix the local OS restriction before repeating it.

The probe sends only read requests. Output omits the cloud key, MAC address,
raw packets and unknown property values. Share this output for further analysis.

## Development

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q custom_components tools tests
```

Tests exercise fragmented TCP frames, signatures, ECHONET parsing, capability
gating and UDP request/acknowledgement handling against local fake devices.
They do not replace a test in Home Assistant with the physical purifier.

Protocol references: Sharp Life AIR EU APK 1.0.4 (`r5.a`, `r5.b`, `r5.g`),
[ECHONET specifications](https://echonet.jp/spec-en/), and the Sharp F1 field
mapping documented by [aiosharp-cocoro-air](https://github.com/rsokolowski/aiosharp-cocoro-air).
