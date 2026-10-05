# Sharp Life AIR Local

Experimental Home Assistant integration for a direct LAN connection to the
Sharp Life AIR EU Wi-Fi module. No account, Internet access or cloud API is
required. Separate from [Sharp Life AIR cloud](https://github.com/xmemphis-xyz/sharp).

## What is confirmed

KI-TX100EU answered TCP 8765 from another subnet. The official app's handshake,
HMAC-signed `get_info` response and module firmware `1.0.1` were verified on the
physical device. Module firmware `1.0.4` has since been reported. Physical
UDP discovery, purifier identification and Get/Set maps are also confirmed.
The app endpoint on UDP 8766 advertises power Set support but rejects both
batch and individual state Gets with `Get_SNA (52)` and empty values.
Version 0.1.4 diagnostics also show six unanswered discovery requests on
standard ECHONET UDP 3610 and a rejected power Get from controller source
`05ff01` on the responding app port 8766. Changing the source object alone
did not enable power reads on this physical KI-TX100EU. The selected state
endpoint remains unset and no power write was attempted during those read-only
polls.

A subsequent manual OFF trial on 8766/05fe01 sent one SetC after successful
fresh discovery and maps. Its eleven preparatory reads received replies, but
the power write received none before timeout. The user confirmed that the
purifier did not turn off. Neither power reads nor an effective power command
have been established on this tested firmware/configuration.
The last supplied physical display, before the registration trial, reported
**Pairing not registered**. This
confirms incomplete app registration, but does not establish why local state
reads and the power command failed.

**Full local purifier control is not yet confirmed on KI-TX100EU.** The TCP
commands found in the APK configure the Wi-Fi module, rather than control the
fan. This integration does not send firmware, registration, reset or unlink
commands. Do not confuse module firmware with purifier firmware.

On initial connection, the client first tries standard ECHONET UDP **3610**, with controller object
`05ff01`, and binds local port 3610 to receive standard fixed-port replies.
UDP 8766 with the app's source object `05fe01` is a separate fallback.
Each endpoint discovers the actual purifier object, reads its property maps
and requests supported state fields. Unanswered unicast discovery falls back
to broadcast and multicast. Missing maps do not prevent read-only requests.
A fan entity is added only if one endpoint both advertises writable power
property `80` and returns a valid power state. Maps and readings from different
ports are never combined to grant control. On/off uses that same port/source
pair and requires both a SetC acknowledgement and matching state readback.
If these endpoints cannot establish power capability and app discovery has
confirmed the purifier object, an experimental probe requests power `80` from
that object on **8766/05ff01**. Only a valid on/off value triggers a map read
using that same source. This adds at most two Get requests, with a 4.5-second
total budget. It grants no permission based on the app source's Set map.
The tested KI-TX100EU returned an empty `Get_SNA (52)` to this controller
power probe. A previously confirmed working endpoint is tried
first on subsequent polls, with normal fallback if its capability disappears.
There is no guessed TCP power command, no cloud fallback, and no local mode or
humidification write in this release. An advertised capability still needs a
physical-device test to confirm that it changes the requested state.

## Install

HACS → three-dot menu → **Custom repositories** →
`https://github.com/xmemphis-xyz/sharp-local` → **Integration**.
Download **Sharp Life AIR Local**, restart Home Assistant, then
**Settings → Devices & services → Add Integration → Sharp Life AIR Local**.
Enter the purifier IP address, for example `192.168.1.32`.

Manual alternative: extract the release ZIP into `/config`, so the component
is `/config/custom_components/sharp_life_air_local`, and restart HA.

It can coexist with the cloud integration; it never logs into Sharp or changes
cloud terminal registrations. Use a DHCP reservation for the purifier.

## Entities and options

- Module firmware, module flags, and Local protocol diagnostic sensors.
- Local protocol attributes show discovery method, stage, packet counters,
  property codes, lengths, and response service codes. `selected_port` identifies
  the state/control endpoint; `transports` records each tested port/source pair.
  `selected_source_object` distinguishes the app and controller sources on 8766.
  **Download diagnostics** exports the same evidence
  without keys, module MAC, IP addresses or raw property values.
- Refresh local connection button.
- Power, temperature and humidity sensors appear when UDP returns these fields.
- Air purifier fan on/off appears only after confirmed Set-map support.

Polling interval: 60 seconds. Empty, malformed or missing properties stay
unknown. Missing UDP responses do not make a successful TCP connection fail.
Each UDP endpoint has a 20-second probe budget. Completed readings survive
timeouts on later optional fields. Multiple entries serialize access to the
fixed UDP reply port; conflicts with another process are reported in diagnostics.
The extra controller-source power comparison has its own 4.5-second budget.
Under integration options, disable **Probe UDP purifier protocol** for TCP-only
diagnostics, or set **Home Assistant local IPv4 address**. `0.0.0.0` selects the
interface automatically. A specific bind address must exist on the HA host.

**UDP discovery broadcast address** defaults to `255.255.255.255`. When HA and
the purifier share a subnet, you can set its directed broadcast address, e.g.
`192.168.1.255` for `192.168.1.0/24`. Leave it empty to disable broadcast.
Multicast fallback uses the app's `224.0.23.0` group. Neither crosses VLANs
automatically.

| Local protocol | Meaning |
| --- | --- |
| `not_tested` | UDP probing disabled |
| `no_response` | UDP probe timed out; inspect per-transport evidence |
| `port_closed` | The OS reported the UDP destination unreachable |
| `port_in_use` | Another process uses the tested local UDP reply port |
| `permission_denied` | The OS blocked the UDP operation |
| `socket_error` | Another local socket error |
| `unsupported_response` | Response cannot be used for this purifier protocol |
| `no_readings` | Object discovered, but no requested state values returned |
| `read_only` | Valid readings without confirmed writable power support |
| `power_control_available` | Device advertises writable power; physical test still required |

Between VLANs, allow HA ↔ purifier TCP 8765 and UDP **3610 and 8766** (including replies).
Broadcast normally stays in one subnet. A TCP handshake proves TCP connectivity,
not UDP reachability or full local control. The initial unicast probe works
across routed subnets; broadcast/multicast fallbacks are most useful when HA
and the purifier are on the same subnet.

## Standalone read-only probe

Python 3.12 or newer; no pip packages needed. On diomedes, as root:

```bash
cd /opt
git clone https://github.com/xmemphis-xyz/sharp-local.git
cd /opt/sharp-local
python3 tools/probe_local.py 192.168.1.32
```

If already cloned, use `git pull --ff-only` from `/opt/sharp-local`.
TCP-only test:

```bash
python3 tools/probe_local.py 192.168.1.32 --tcp-only
```

On a machine actually connected to the purifier subnet, a directed broadcast
can also be tested. Example for a /24 network and HA host address `192.168.1.7`:

```bash
python3 tools/probe_local.py 192.168.1.32 --bind-ip 192.168.1.7 --broadcast 192.168.1.255
```

Do not bind diomedes to the phone's address. An Android `permission_denied`
result means no successful UDP test was completed; it does not establish the
purifier's capabilities. Fix the local OS restriction before repeating it.

The probe sends only read requests. Output omits the cloud key, MAC address,
raw packets and unknown property values. Share this output for further analysis.

## Manual power command experiment

The user reports that the KI-TX100EU remains on during the rejected state Gets.
Standby therefore does not explain the current observations. Get_SNA (52) is
a response to a read. The device's Set map advertises property 80, which
provided a basis for an explicit write experiment. The completed OFF trial
received no write acknowledgement and the user reported no physical effect.
Repeating it in unchanged conditions would not establish a working protocol.

The separate tool below verifies signed TCP info, freshly discovers the actual
purifier object on 8766/05fe01, and checks that this endpoint advertises writable
power. It sends at most one requested power command, then attempts one readback.
It can physically turn the purifier off or on. It does not retry a power write,
restore power automatically, change registrations or enable HA fan controls.
The existing HA polling and the read-only probe continue to send only Gets.

On diomedes, from the repository directory:

```bash
git pull --ff-only
python3 tools/trial_power.py 192.168.1.32 off
```

Use on instead of off only when you want to test a separate ON command. Observe
the physical purifier and share both that observation and the JSON report.

| Outcome | Meaning |
| --- | --- |
| preparation_failed | TCP, discovery or map validation failed before a power write |
| power_write_not_advertised | This endpoint did not advertise writable power; no Set sent |
| write_rejected | A matching SetC_SNA (51) explicitly rejected the request |
| write_unconfirmed | No valid acknowledgement; the physical effect is unknown |
| acknowledged_unconfirmed | A matching Set_Res (71) arrived, but no valid power readback |
| readback_mismatch | Acknowledgement arrived, but readback differs from the request |
| verified_by_readback | Acknowledgement and matching on/off readback both arrived |

Exit code 0 means matching readback, 2 means the write's effect remains
unconfirmed, and 1 means preparation failed or the write was rejected. The
report omits IPs, module MAC, keys and raw property values. An acknowledgement
alone is not proof that the physical purifier changed state.

## Manual cloud-registration trial

The supplied official EU app APK 1.0.4 contains a signed TCP 8765 command
`0003` named register_on_server. It returns registration-specific result codes.
`tools/trial_registration.py` sends at most one such command after validating
module info and a fresh handshake. **This can ask the purifier to register
with Sharp's cloud; it is not a read-only local probe.** No power, firmware,
reset or unlink command is sent. The HA component does not run this tool.

The app prepares a temporary cloud record before this command, then performs
further account operations after a successful module response. The tool does
not replace those steps. A reported module success does not prove complete
account pairing or working local purifier control. A refusal outside the
prepared app workflow is not proof that the same refusal caused the app issue.

The first physical trial received a frame header declaring 38 bytes. An earlier
tool version incorrectly required exactly 40 bytes and rejected that header
before reading the result or checking the signature. The corrected parser uses
the declared frame length; a normal result fits in 38 bytes. The earlier report
cannot establish whether registration succeeded. First check the purifier/app
status, and make another manual attempt only if pairing remains incomplete.

Update the clone before starting the attempt:

```bash
git -C /opt/sharp-local pull --ff-only
```

In the official app, resume pairing through **Already connected with a router**
until the screen asks you to press Wi-Fi. Briefly press the dedicated physical
Wi-Fi button and run this once from a computer on the purifier's LAN while
the app remains on that step:

```bash
python3 /opt/sharp-local/tools/trial_registration.py 192.168.1.32 --register-on-server
```

Allow up to 30 seconds for the command reply, in addition to the preliminary
TCP check. The tool never retries registration automatically. Share its JSON
report and any changed purifier/app status. Reports omit keys, MAC addresses,
IP addresses, and raw frames.
Module firmware and flags are read **before** the registration command; they
are not post-command confirmation. `reply_stage` distinguishes reading the
header, reading the body, and a fully signed reply. An IncompleteReadError adds
only `read_expected_bytes` and `read_received_bytes` for that read, never the
partial data. The latest reported trial had preflight flags 0x0003 and ended
before a complete reply header; neither observation proves successful pairing.

| Registration code | Meaning in the app |
| --- | --- |
| 0 | Module reports registration success; account pairing still needs verification |
| 1 | Module requested cancellation |
| 2 | Module is not in cloud-registration mode |
| 3 | Communication error with the cloud server |
| 4 | Cloud server refused registration |

An unknown code, unexpected reply or timeout is not success. Missing result
bytes are not treated as code 0. Signed generic module errors are reported
separately; a missing error detail stays null. Exit
code 0 means reported module success, 1 means a returned failure/unknown code
or generic module error, and 2 means the result could not be established.

## Development

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q custom_components tools tests
```

Tests exercise fragmented TCP frames, signatures, ECHONET parsing, capability
gating, fixed-port UDP replies, transport selection, concurrent clients and
power acknowledgement/readback against local fake devices.
They do not replace a test in Home Assistant with the physical purifier.

Protocol references: Sharp Life AIR EU APK 1.0.4 (`r5.a`, `r5.b`, `r5.g`),
[ECHONET Lite v1.14 Part 2](https://echonet.jp/spec_v114_lite_en/)
(section 1.2 specifies UDP destination 3610 for requests and responses),
[sharp-echonet](https://www.npmjs.com/package/sharp-echonet)
(a primary implementation using 3610 and controller `05ff01` on KI-UX75;
that model's success does not establish KI-TX100EU support), and the Sharp F1 field
mapping documented by [aiosharp-cocoro-air](https://github.com/rsokolowski/aiosharp-cocoro-air).
