# Changelog

## 0.1.2

- Retry every missing or zero-length state field with a single-property Get.
- Preserve valid values from partial batch responses; do not repeat successful reads.
- Record response service codes and property lengths for every accepted exchange.
- Add regressions for empty Get_Res/Get_SNA batches and still-empty individual reads.

A physical KI-TX100EU now confirms unicast UDP discovery, identification and
Get/Set maps. Its batch state response contains seven zero-length values;
individual reads and physical power control still require device verification.

## 0.1.1

- Try broadcast and multicast after unanswered unicast discovery, following the APK.
- Send the official five-property purifier identification request after discovery.
- Preserve read-only data when maps are missing; retry maps individually and power alone.
- Accept partial Get_SNA responses while validating peer, transaction and object IDs.
- Require a valid power reading before exposing controls and verify state after a write.
- Add a configurable broadcast address and safe downloadable HA diagnostics.
- Extend fake-device tests for fallback, missing maps and unconfirmed power writes.

Physical-device UDP and on/off verification is still required.

## 0.1.0

- First experimental Home Assistant integration for a direct Sharp LAN connection.
- Validate TCP 8765 handshake, signed get_info and exact response lengths.
- Display module firmware, flags and UDP protocol status without exposing keys.
- Probe UDP 8766 with the official app's discovery frame and actual purifier EOJ.
- Read standard Get/Set property maps and available purifier readings.
- Expose a local on/off fan only when power Set support is advertised.
- Add a standalone read-only diagnostic script and fake-device protocol tests.

Physical KI-TX100EU tests have confirmed TCP get_info, module firmware 1.0.1.
UDP readings and local power control remain experimental and unconfirmed.

