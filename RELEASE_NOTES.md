Fix empty state reads from the physical KI-TX100EU.

Diagnostics from 0.1.1 confirm UDP discovery, identification and property maps. The purifier advertises writable power but returned seven empty state values in one response. Previously the client only retried after a timeout, so an empty response left all readings unknown and controls unavailable.

Version 0.1.2 individually requests every missing or zero-length field, preserves valid batch data and exports safe response service codes and property lengths. Power controls still require an actual power reading and each write must be confirmed by state readback.

Update in HACS, restart Home Assistant, then press Refresh local connection. Connection options can remain unchanged. If readings are still missing, Download diagnostics now distinguishes successful and rejected individual responses.

21 fake-device regression tests pass, including empty Get_Res and Get_SNA responses. Physical individual reads and on/off still require verification on the purifier.

For manual installation, extract sharp_life_air_local.zip into /config.
