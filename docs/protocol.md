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

## Separate manual registration experiment

The supplied SHARP Life AIR EU APK 1.0.4 provides primary evidence in
`r5/a.m(int, byte[])`, `r5/a.h()` and `PairingConfirmActivity$b.run()`:

- Builder selector 2 emits a 36-byte signed request with payload `0003` and
  no additional account, MAC or server-address fields.
- `h()` calls this register_on_server command after the usual nonce handshake,
  waits up to 30 seconds for a reply, and uses a 40-byte response buffer.
- The shared `d()` validator accepts the length declared in the frame header,
  from 36 bytes to the buffer capacity. The 40-byte buffer is not a requirement
  for a 40-byte frame. A normal command plus result fits in a 38-byte frame.
- It verifies the response HMAC and recognizes generic error command `8fff`.
  That branch reads a detail code at full-frame bytes 38-39. Other replies use
  a signed big-endian result code at bytes 36-37 (payload offsets 2-3).
- The pairing activity maps codes 0/1/2/3/4 to success, module cancellation,
  not in cloud-registration mode, cloud communication error, and cloud refusal.
  Other codes are internal/unknown results.

The app first creates a `setting/tempBoxInfo` cloud record using the module
identity. Its callback starts the registration loop; after module success it
reads get_info again and proceeds to further cloud/account pairing operations.
Sending `0003` alone is neither complete phone/account pairing nor proof of
local-control capability. An app-prepared cloud context matters when interpreting
the result; a standalone refusal cannot establish the cause of the app failure.

`tools/trial_registration.py` is a separate explicit manual experiment, guarded
by `--register-on-server`. It validates get_info, establishes a new handshake,
and sends one signed `0003`, without retries. It reads exactly the frame length
declared in the header, bounded to 36-40 bytes, and verifies the HMAC before
interpreting its contents. A normal result requires at least 38 bytes; missing
result bytes are never decoded as zero. It expects `8003` as the command
counterpart of `0003`, inferred from
the request/reply convention including the physically verified `0002`/`8002`.
The APK's `h()` does not explicitly check that counterpart and no physical
KI-TX100EU registration reply command or result has yet been verified. A
different signed reply command is reported as unexpected, not as success.
Generic `8fff` errors retain the raw unsigned 16-bit detail code without a
guessed meaning, only when all detail bytes are present. A shorter signed error
still reports module_error, with module_error_code null; it does not borrow
zero-filled bytes from a buffer or decode the error as a registration result.
The report omits identity, keys and raw frames, and always
leaves app_pairing_verified false. Nothing imports this tool into the HA client.

The first physical trial on module 1.0.4, flags 0x0002, sent one registration
request and received a header declaring 38 bytes. The original tool mistakenly
required exactly 40 bytes and rejected the header before reading the body or
verifying its signature. No command, result code or complete raw response was
retained, so that report cannot establish registration success or failure.
The parser fix follows the app's declared-length validation. Check the current
purifier/app status before deciding whether another manual attempt is needed;
do not repeat registration if pairing has already completed.

Local fake TCP tests exercise fragmented headers and signed 38-/40-byte replies,
all five documented codes in both sizes, unknown codes, generic errors with
and without detail, signed replies missing their result, unexpected commands,
invalid signatures, wrong nonces, oversized/undersized/truncated responses,
incorrect declared lengths, handshake/preflight failure and no automatic retry
after a lost reply. These tests validate tool behavior, not the actual device
or a working Sharp cloud registration.

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

The two uploaded 0.1.3 diagnostics have identical results: six discovery
requests on 3610/05ff01 receive zero frames; eleven exchanges on 8766/05fe01
confirm metadata and reject state. This does not prove that port 3610 is closed.

Version 0.1.4 adds one controlled comparison: send a single Get 80
to the air-cleaner EOJ confirmed by app discovery, on port 8766 with controller
source 05ff01. This isolates source-object selection without changing the
responding endpoint or guessing an instance. If power is neither 30 nor 31,
stop. If it is valid, read 9E/9F using the same controller source. A missing,
invalid or read-only controller Set map does not permit writes, regardless of
the app source's map. Power control uses 8766/05ff01 only if both checks succeed.
This experiment sends at most two Get requests in a 4.5-second budget; update
never sends a Set. It initially exposes only power if this profile is selected.

After a successful poll, try the confirmed port/source first on later polls.
Revalidate its state and Set map; do not reuse stale write permission. If it
fails, fall back to the other profiles without repeating a profile in that
poll. A changed TCP module identity disables this preference. This avoids
waiting for silent standard discovery before every working app-port refresh.

Missing maps do not gate read-only state reads; a missing Set map prevents
power writes. Partial Get_SNA replies preserve supported values. Empty or
missing fields trigger individual reads. Each endpoint has a 20-second probe
budget; retain already completed values if a later field times out.
Fixed reply ports are serialized across this integration's entries. Another
process already listening on the port produces `port_in_use`, rather than
silently moving to an ephemeral port. Socket closure releases the port before
the next entry starts.

Diagnostics include `selected_port` and `selected_source_object`
(null if no state endpoint was selected)
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
as 0x0002; no interpretation of those flag bits has been verified.
Physical 0.1.4 diagnostics record the following results:

| Destination port / source EOJ | Requests / accepted replies | Result |
| --- | --- | --- |
| 3610 / 05ff01 | 6 / 0 | No replies to unicast, broadcast or multicast discovery |
| 8766 / 05fe01 | 11 / 11 | Identification and maps succeed; batch and individual state Gets return empty Get_SNA (52) |
| 8766 / 05ff01 | 1 / 1 | Power Get 80 returns empty Get_SNA (52) |

Both tested source objects receive valid replies on 8766, but neither returns
the requested power value. The controller-source comparison therefore did not
enable local state reads. `selected_port` and `selected_source_object` remain
null, `power_controllable` is false, and no Set request was sent. These results
establish neither that 3610 is closed nor that all possible local protocols are
unsupported. They do not identify whether firmware, registration state or
another device condition accounts for the rejected reads.

TCP succeeded across VLANs. UDP 8766 was open|filtered from diomedes; the
same-subnet Termux tests failed at sendto with EPERM and therefore cannot
establish whether the purifier answers same-subnet discovery.

## Next evidence needed

The source comparison is complete; repeating the same probe in unchanged
conditions does not resolve the remaining protocol gap. The user subsequently
confirmed that the purifier remains on throughout the tests. Standby does not
explain the rejected Gets. A subsequent physical display observation confirms
that app registration is still incomplete.

Get_SNA (52) applies to Get, while SetC has a separate Set_Res (71) or
SetC_SNA (51) result (ECHONET Lite v1.14 Part 2, tables 3.9-3.11 and section
6.2.5). The advertised Set map provides grounds for a manual power write trial;
it does not establish that such a write will succeed.

tools/trial_power.py is a separate, explicitly invoked experiment on the
confirmed 8766/05fe01 profile. It requires fresh signed TCP info, fresh discovery
and writable 80 in this source's map. It sends one requested SetC, never retries
a write, and attempts one subsequent Get 80. A missing readback does not turn an
acknowledgement into verified physical control. No normal HA capability rule
is relaxed by this tool, and its output does not contain keys or raw values.

The completed manual OFF trial on module 1.0.4, flags 0x0002, discovered EOJ
013501 and fresh writable power on 8766/05fe01. Eleven preparatory Get requests
received matching replies. The twelfth request was the sole SetC 80=31; no
frame arrived before its timeout. The tool reported write_unconfirmed and
did not attempt readback after the missing acknowledgement. The user confirmed
that the purifier remained on. This is an unanswered, ineffective observed
write, not an explicit SetC_SNA rejection and not proof that every possible
local control path is unavailable.

The latest purifier display reports **Wi-Fi network status: Pairing not
registered / Please register your air purifier to the App**, after the firmware
1.0.4 diagnostics and unsuccessful OFF trial. Neither firmware 1.0.4 nor flags
0x0002 proves successful registration. This confirms the missing registration
but does not establish a causal link to the rejected state/control requests.
The separate manual registration experiment above can capture the module's
specific result at the failing app stage; it is not a local power workaround.

Further implementation needs a valid state exchange on this exact model and
firmware, or primary protocol/mode documentation that explains how to obtain one.
The KI-TX100EU manual's Wi-Fi settings do not document an ECHONET or HEMS mode.
Mode-switch instructions for older Sharp wireless adapters are not evidence
for this built-in module. Static inspection of the supplied EU app APK 1.0.4
found discovery/identification UDP calls and the TCP module commands listed
above, but no local purifier power request; that observation alone does not
prove the firmware lacks another local control path.

If valid power state and Set support are returned, test conditional power
off/on in HA and compare with the physical device. Local modes and
humidification require further protocol evidence before adding writes;
neither is inferred from TCP get_info or module flags.
