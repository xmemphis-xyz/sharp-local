"""Expose power only after the device advertises local Set support."""
from homeassistant.components.fan import FanEntity, FanEntityFeature

from .entity import SharpLocalEntity


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = entry.runtime_data
    added = False

    def add_fan():
        nonlocal added
        if not added and coordinator.last_update_success and coordinator.data.power_controllable:
            added = True
            async_add_entities([SharpLocalFan(coordinator, "fan")])

    add_fan()
    entry.async_on_unload(coordinator.async_add_listener(add_fan))


class SharpLocalFan(SharpLocalEntity, FanEntity):
    _attr_name = "Air purifier"
    _attr_supported_features = FanEntityFeature.TURN_ON | FanEntityFeature.TURN_OFF

    @property
    def available(self):
        return super().available and self.coordinator.data.power_controllable

    @property
    def is_on(self):
        power = self.coordinator.readings.get("power")
        return power == "on" if power is not None else None

    async def async_turn_on(self, percentage=None, preset_mode=None, **kwargs):
        await self.coordinator.set_power(True)

    async def async_turn_off(self, **kwargs):
        await self.coordinator.set_power(False)
