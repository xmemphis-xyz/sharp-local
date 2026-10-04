First experimental Sharp Life AIR Local integration, with no account or cloud dependency.

TCP 8765 signed get_info has been confirmed on a physical KI-TX100EU, module firmware 1.0.1. The integration shows module diagnostics and probes the official app's UDP 8766 discovery protocol.

Full local purifier control remains unconfirmed. A local on/off fan is exposed only if a responding purifier advertises writable power support. Modes and humidification are not implemented locally yet.

Add https://github.com/xmemphis-xyz/sharp-local to HACS as an Integration, download, restart Home Assistant, then add Sharp Life AIR Local using the purifier IP. The cloud integration can remain enabled.

A standalone read-only probe is included: python3 tools/probe_local.py 192.168.2.243. It omits keys and raw packets. See README.md for details.

Automated fake-device protocol tests pass. Testing inside Home Assistant and with the physical purifier is still required.

For manual installation, extract sharp_life_air_local.zip into /config.
