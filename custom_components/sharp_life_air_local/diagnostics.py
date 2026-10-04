"""Export local protocol evidence without keys, identities or raw frames."""


async def async_get_config_entry_diagnostics(hass, entry):
    coordinator = entry.runtime_data
    if coordinator.data is None:
        return {"last_update_success": coordinator.last_update_success}
    state = coordinator.data
    return {
        "last_update_success": coordinator.last_update_success,
        "module": {"version": state.module.version, "flags": f"0x{state.module.flags:04X}"},
        "udp_status": state.udp_status,
        "udp_diagnostics": dict(state.udp_diagnostics),
        "object_id": state.object_id.hex() if state.object_id else None,
        "power_controllable": state.power_controllable,
        "readings": coordinator.readings,
    }
