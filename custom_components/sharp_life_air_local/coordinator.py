"""Poll the local Wi-Fi module and optionally probe ECHONET."""
import asyncio
import logging
from datetime import timedelta

from homeassistant.const import CONF_HOST
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import CONF_BIND_IP, CONF_TEST_UDP
from .protocol import ProtocolError, SharpLocalClient, decode_readings


class SharpLocalCoordinator(DataUpdateCoordinator):
    def __init__(self, hass, entry):
        super().__init__(hass, logging.getLogger(__name__), name="Sharp Life AIR Local",
                         config_entry=entry, update_interval=timedelta(seconds=60))
        self.entry = entry
        self.client = SharpLocalClient(
            entry.data[CONF_HOST], bind_ip=entry.options.get(CONF_BIND_IP, "0.0.0.0")
        )

    @property
    def readings(self):
        return decode_readings(self.data.properties) if self.data else {}

    async def _async_update_data(self):
        try:
            async with asyncio.timeout(25):
                state = await self.client.update(udp=self.entry.options.get(CONF_TEST_UDP, True))
            if self.entry.unique_id and state.module.mac != self.entry.unique_id:
                self.client.state = None
                raise UpdateFailed("A different Sharp module is using this IP address")
            return state
        except (OSError, TimeoutError, ProtocolError) as err:
            raise UpdateFailed("Unable to read the Sharp local module") from err

    async def set_power(self, on):
        if not self.last_update_success or not self.data or not self.data.power_controllable:
            raise HomeAssistantError("Sharp local power control is unavailable")
        try:
            async with asyncio.timeout(10):
                await self.client.set_power(on)
        except (OSError, TimeoutError, ProtocolError) as err:
            raise HomeAssistantError("Sharp local power command was not acknowledged") from err
        await self.async_request_refresh()
