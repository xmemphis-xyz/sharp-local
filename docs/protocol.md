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

## Experimental UDP extension

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
Missing maps do not gate read-only state reads; a missing Set map still prevents
power writes. Partial Get_SNA replies preserve the supported property values. Those additional reads and a conditional SetC 80 are standards-based
extensions; they have not been confirmed against KI-TX100EU firmware.

Power: SetC `61`, property 80 value 30=on or 31=off. Require Set_Res `71` with
the matching transaction, objects and property. A Set_SNA `51`, no response,
or malformed response is an error. Never retry a write automatically. A Set
acknowledgement does not by itself prove that the physical state has changed;
read the state again and compare with the purifier. This client checks power
readback up to three times after one Set command, and raises if the requested
state cannot be confirmed. It never retries the Set command automatically.

No UDP discovery response has yet been demonstrated on the physical device.
TCP succeeded across VLANs. UDP 8766 was open|filtered from diomedes; the
same-subnet Termux tests failed at sendto with EPERM and therefore cannot
establish whether the purifier answers same-subnet discovery.

## Next evidence needed

Run the standalone probe on diomedes and, if needed, a Linux host in the
purifier subnet. Record its safe output. If UDP answers, test conditional
power off/on in HA and compare the state sensor and physical device. Local
modes and humidification require further protocol evidence before adding
writes; neither is inferred from TCP get_info or module flags.

