"""Local diagnostics and readings when the device returns them."""
from homeassistant.components.sensor import SensorEntity, SensorDeviceClass, SensorStateClass
from homeassistant.const import EntityCategory, UnitOfTemperature, UnitOfPower

from .entity import SharpLocalEntity

READINGS = {
    "power": ("Purifier power", None, None),
    "power_watts": ("Power", SensorDeviceClass.POWER, UnitOfPower.WATT),
    "temperature_c": ("Temperature", SensorDeviceClass.TEMPERATURE, UnitOfTemperature.CELSIUS),
    "humidity_pct": ("Humidity", SensorDeviceClass.HUMIDITY, "%"),
}


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = entry.runtime_data
    async_add_entities(SharpLocalDiagnostic(coordinator, key) for key in ("version", "flags", "udp_status"))
    added = set()

    def add_readings():
        if not coordinator.last_update_success:
            return
        keys = set(coordinator.readings) - added
        added.update(keys)
        async_add_entities(SharpLocalReading(coordinator, key) for key in sorted(keys))

    add_readings()
    entry.async_on_unload(coordinator.async_add_listener(add_readings))


class SharpLocalDiagnostic(SharpLocalEntity, SensorEntity):
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, key):
        super().__init__(coordinator, key)
        self.key = key
        self._attr_name = {"version": "Module firmware", "flags": "Module flags", "udp_status": "Local protocol"}[key]

    @property
    def native_value(self):
        if self.key == "udp_status":
            return self.coordinator.data.udp_status
        if self.key == "flags":
            return f"0x{self.coordinator.data.module.flags:04X}"
        return self.coordinator.data.module.version


class SharpLocalReading(SharpLocalEntity, SensorEntity):
    def __init__(self, coordinator, key):
        super().__init__(coordinator, key)
        self.key = key
        self._attr_name, self._attr_device_class, self._attr_native_unit_of_measurement = READINGS[key]
        if self._attr_native_unit_of_measurement:
            self._attr_state_class = SensorStateClass.MEASUREMENT

    @property
    def native_value(self):
        return self.coordinator.readings.get(self.key)
