# Protocol findings and remaining gaps

## Confirmed TCP exchange

TCP 8765: send eight zero bytes. Receive a 16-byte nonce followed by its
16-byte MD5 digest. A request is a big-endian 16-bit total length, HMAC-SHA256
of nonce + payload, and payload. `0002` is get_info; signed response is `8002`.
Read exact lengths: TCP may fragment every part of the exchange.

Response payload offsets (excluding length and HMAC):

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 2 | Response command `8002` |
| 2 | 1 | Module major version |
| 3 | 1 | Module minor version |
| 4 | 2 | Module patch version, big endian |
| 6 | 2 | Module flags |
| 8 | 256 | Cloud key: discard; never expose in entities or diagnostics |
| 264 | 6 | Module MAC: internal HA identity only |
| 270 | optional | Additional module data: currently ignored |

APK methods additionally use `0003` register_on_server, `0004` update_firmware,
`0005` identify, and `0008` clear cloud link. None are purifier power/mode
commands. They are deliberately absent from this client.

## App discovery transport

Official app discovery: UDP 8766, source `05fe01`, destination node `0ef001`,
Get `62`, properties D6 and 8C. Exact transaction-1 frame:

```text
1081000105fe010ef0016202d6008c00
```

The response D6 supplies the actual purifier EOJ (class `0135`), so do not
assume instance `01`. The APK then requests 8A, 8C, F0, FC and FD from the discovered
purifier object. This client follows that identification read before reading
standard maps 9E/9F and supported state fields. Unanswered unicast discovery
falls back to configurable broadcast and the APK multicast group 224.0.23.0.
Physical 0.1.2 diagnostics confirm discovery, identification and maps on this
endpoint, but all seven state fields return empty `Get_SNA (52)` replies,
even when each field is requested alone. The writable map therefore cannot
establish that this app endpoint permits local state/control. The client never
uses an empty response as a power state.

## Standard ECHONET transport and endpoint selection

ECHONET Lite v1.14 Part 2, section 1.2, specifies UDP destination port **3610**
for requests, responses and notifications. Bind local 3610, since a reply
need not target an ephemeral request source port. The client uses controller
EOJ `05ff01`, as in the primary `sharp-echonet` implementation on KI-UX75.
That implementation is reference evidence, not confirmation for KI-TX100EU.

Version 0.1.3 first probes 3610/05ff01 and then, if power capability is not
established, probes the app endpoint 8766/05fe01 independently. Each endpoint
discovers its air-cleaner instance and reads its own maps and state. A chosen
endpoint must supply both the Set map and a valid power value before any write
is allowed. Never combine app metadata with readings from a different endpoint
to infer write permission. Power commands and readback reuse the selected
port/source pair. Local mode, humidification and firmware writes remain absent.

Missing maps do not gate read-only state reads; a missing Set map prevents
power writes. Partial Get_SNA replies preserve supported values. Empty or
missing fields trigger individual reads. Each endpoint has a 20-second probe
budget; retain already completed values if a later field times out.
Fixed reply ports are serialized across this integration's entries. Another
process already listening on the port produces `port_in_use`, rather than
silently moving to an ephemeral port. Socket closure releases the port before
the next entry starts.

Diagnostics include `selected_port` (null if no state endpoint was selected)
and separate `transports` evidence with the destination port, bind port,
source EOJ, stage, counters, ESV and property lengths. IPs, keys, MAC addresses
and raw property values are excluded.

Power: SetC `61`, property 80 value 30=on or 31=off. Require Set_Res `71` with
the matching transaction, objects and property. A Set_SNA `51`, no response,
or malformed response is an error. Never retry a write automatically. A Set
acknowledgement does not by itself prove that the physical state has changed;
read the state again and compare with the purifier. This client checks power
readback up to three times after one Set command, and raises if the requested
state cannot be confirmed. It never retries the Set command automatically.

Physical KI-TX100EU app discovery reports EOJ 013501. Its Set map advertises
80, 81, A0, F3, F4. Module firmware is currently reported as 1.0.4 and flags
as 0x0002; no interpretation of those flag bits has been verified. Standard
3610 state reads and physical power control still require device validation.
TCP succeeded across VLANs. UDP 8766 was open|filtered from diomedes; the
same-subnet Termux tests failed at sendto with EPERM and therefore cannot
establish whether the purifier answers same-subnet discovery.

## Next evidence needed

Update HACS and restart HA, then use Refresh local connection and Download
diagnostics. Inspect the 3610 transport and `selected_port`. The standalone
probe can provide the same read-only evidence from a host on the purifier LAN.
If valid power state and Set support are returned, test conditional power
off/on in HA and compare with the physical device. Local
modes and humidification require further protocol evidence before adding
writes; neither is inferred from TCP get_info or module flags.
