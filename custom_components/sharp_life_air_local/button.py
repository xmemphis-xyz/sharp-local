"""Retry the read-only local probe."""
from homeassistant.components.button import ButtonEntity
from homeassistant.const import EntityCategory

from .entity import SharpLocalEntity


async def async_setup_entry(hass, entry, async_add_entities):
    async_add_entities([SharpLocalRefresh(entry.runtime_data, "refresh")])


class SharpLocalRefresh(SharpLocalEntity, ButtonEntity):
    _attr_name = "Refresh local connection"
    _attr_icon = "mdi:refresh"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    async def async_press(self):
        await self.coordinator.async_request_refresh()
