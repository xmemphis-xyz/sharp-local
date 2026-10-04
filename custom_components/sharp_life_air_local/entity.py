"""Local module identity and availability."""
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN


class SharpLocalEntity(CoordinatorEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator, suffix):
        super().__init__(coordinator)
        mac = coordinator.data.module.mac
        self._attr_unique_id = f"{mac}_{suffix}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, mac)}, manufacturer="Sharp",
            name="Sharp Life AIR Local", model="Wi-Fi module",
            sw_version=coordinator.data.module.version,
        )
