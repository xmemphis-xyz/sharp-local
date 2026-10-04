Separate Sharp app discovery from standard ECHONET state/control.

On the physical KI-TX100EU, UDP 8766 answers discovery and property maps but rejects every batch and individual state Get with Get_SNA (52). Earlier releases used this app discovery endpoint for all state/control attempts.

Version 0.1.3 first tries standard ECHONET UDP 3610 with controller 05ff01 and listens on local 3610 for fixed-port replies. App UDP 8766/05fe01 remains a separate fallback. Power controls require a valid power reading and Set map from one endpoint, and commands/readback use that same endpoint. Maps from one port cannot grant control on another.

Update in HACS, restart Home Assistant, then press Refresh local connection. The purifier IP remains 192.168.1.32; existing options can stay unchanged. Download diagnostics now contains separate evidence for each tested port and selected_port. If valid power state and Set support appear, test off/on and compare with the physical purifier.

29 protocol tests pass, including actual fixed-port loopback replies, fallback writes, partial-read timeout recovery and concurrent clients. Physical KI-TX100EU reads and power control on 3610 still require verification; success on another Sharp model does not prove support here.

For manual installation, extract sharp_life_air_local.zip into /config.
