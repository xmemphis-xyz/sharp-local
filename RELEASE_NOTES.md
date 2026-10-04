Fix discovery and state handling in the experimental local integration.

UDP discovery now tries unicast, broadcast and the official multicast group, then the app's purifier identification request. Missing property maps and partial Get_SNA responses no longer hide otherwise readable data. Controls still require advertised power Set support and a valid power state. Each power command is sent once and its resulting state must be read back.

Added the "UDP discovery broadcast address" option, Local protocol diagnostic attributes and "Download diagnostics" in HA. Diagnostics omit keys, module MAC, IP addresses and raw property values.

Update Sharp Life AIR Local in HACS and restart Home Assistant. For HA 192.168.1.7 and purifier 192.168.1.32 on a /24 subnet, options may use bind IP 192.168.1.7 and directed broadcast 192.168.1.255. The default limited broadcast works without assuming a subnet mask.

Fake-device protocol regression tests pass. Physical-device UDP readings and power control remain unconfirmed; this release provides the corrected exchange and evidence needed for that test. Modes and humidification are not implemented locally.

For manual installation, extract sharp_life_air_local.zip into /config.
