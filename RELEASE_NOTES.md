Compare the controller source on the responding Sharp app endpoint.

Both physical KI-TX100EU diagnostics from 0.1.3 show six unanswered discovery requests on 3610/05ff01. App UDP 8766/05fe01 answers metadata but rejects every state Get with Get_SNA (52). Changing port and source together did not establish a working local state endpoint.

Version 0.1.4 adds an experimental comparison using controller source 05ff01 on the already responding app port 8766 and the discovered air-cleaner instance. It first requests only power. A valid on/off value triggers one map read from the same source; otherwise it stops. This read-only probe has a 4.5-second budget and sends no automatic power commands. Controls require both a valid power value and writable power support from that exact port/source pair.

Once a profile is confirmed, later polls try it first, revalidate its permission and fall back if it stops working. This avoids repeating unanswered standard discovery before every working app-port refresh. Diagnostics report selected_port, selected_source_object and separate transport evidence. This comparison initially adds only power readings; physical KI-TX100EU support remains unverified.

36 protocol tests pass, including source-dependent reads/maps, rejected probes, missing permissions, timeouts and preferred-profile recovery. Update in HACS, restart Home Assistant, then press Refresh local connection and Download diagnostics. Existing IP and connection options can stay unchanged. If power_control_available appears, test off/on against the physical purifier.

For manual installation, extract sharp_life_air_local.zip into /config.
