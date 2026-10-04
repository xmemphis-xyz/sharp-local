# Changelog

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
