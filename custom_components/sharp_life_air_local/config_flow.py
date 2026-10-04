"""Configure by IPv4 address; never request a Sharp cloud account."""
import ipaddress

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_HOST

from .const import CONF_BIND_IP, CONF_BROADCAST, CONF_TEST_UDP, DOMAIN
from .protocol import ProtocolError, get_info


class SharpLocalConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        errors = {}
        if user_input is not None:
            try:
                host = str(ipaddress.IPv4Address(user_input[CONF_HOST].strip()))
                info = await get_info(host)
                await self.async_set_unique_id(info.mac)
                self._abort_if_unique_id_configured(updates={CONF_HOST: host})
                return self.async_create_entry(title="Sharp Life AIR Local", data={CONF_HOST: host})
            except ValueError:
                errors[CONF_HOST] = "invalid_ip"
            except (OSError, TimeoutError, ProtocolError):
                errors["base"] = "cannot_connect"
        return self.async_show_form(step_id="user", data_schema=vol.Schema({
            vol.Required(CONF_HOST): str,
        }), errors=errors)

    @staticmethod
    def async_get_options_flow(config_entry):
        return SharpLocalOptionsFlow()


class SharpLocalOptionsFlow(config_entries.OptionsFlow):
    async def async_step_init(self, user_input=None):
        errors = {}
        if user_input is not None:
            try:
                user_input[CONF_BIND_IP] = str(ipaddress.IPv4Address(user_input[CONF_BIND_IP].strip()))
                broadcast = user_input.get(CONF_BROADCAST, "255.255.255.255").strip()
                if broadcast:
                    try:
                        broadcast = str(ipaddress.IPv4Address(broadcast))
                    except ValueError:
                        errors[CONF_BROADCAST] = "invalid_ip"
                        raise
                user_input[CONF_BROADCAST] = broadcast
                return self.async_create_entry(title="", data=user_input)
            except ValueError:
                if not errors:
                    errors[CONF_BIND_IP] = "invalid_ip"
        return self.async_show_form(step_id="init", data_schema=vol.Schema({
            vol.Required(CONF_TEST_UDP, default=self.config_entry.options.get(CONF_TEST_UDP, True)): bool,
            vol.Required(CONF_BIND_IP, default=self.config_entry.options.get(CONF_BIND_IP, "0.0.0.0")): str,
            vol.Optional(CONF_BROADCAST, default=self.config_entry.options.get(CONF_BROADCAST, "255.255.255.255")): str,
        }), errors=errors)
