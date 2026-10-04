"""Experimental local Sharp integration, with no cloud dependency."""
from homeassistant.const import Platform

from .coordinator import SharpLocalCoordinator

PLATFORMS = [Platform.SENSOR, Platform.FAN, Platform.BUTTON]


async def async_setup_entry(hass, entry):
    coordinator = SharpLocalCoordinator(hass, entry)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_update_options))
    return True


async def _async_update_options(hass, entry):
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass, entry):
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
