"""Config flow for pfSense integration."""
import logging
from urllib.parse import urlparse
import xmlrpc

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_USERNAME, CONF_NAME, CONF_PASSWORD, CONF_SCAN_INTERVAL, CONF_URL
from homeassistant.core import callback
from homeassistant.util import slugify

from .const import CONF_TLS_INSECURE, CONF_DEVICE_TRACKER_ENABLED, CONF_DEVICE_TRACKER_SCAN_INTERVAL, DEFAULT_DEVICE_TRACKER_ENABLED, DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL, DEFAULT_USERNAME, DEFAULT_TLS_INSECURE, DOMAIN

from .pypfsense import Client

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_URL): str,
        vol.Optional(CONF_TLS_INSECURE): bool,
        vol.Optional(CONF_USERNAME, default=DEFAULT_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_NAME): str,
    }
)


class ConfigFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for pfSense."""
    # gets invoked without user input initially
    # when user submits has user_input
    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}
        if user_input is not None:
            try:
                name = user_input.get(CONF_NAME, False) or None
               
                url = user_input[CONF_URL].strip()
                # ParseResult(scheme='', netloc='', path='f', params='', query='', fragment='')
                url_parts = urlparse(url)
                if len(url_parts.scheme) < 1:
                    raise InvalidURL()
                
                if len(url_parts.netloc) < 1:
                    raise InvalidURL()

                # remove any path etc details
                url = f"{url_parts.scheme}://{url_parts.netloc}"
                
                username = user_input.get(CONF_USERNAME, DEFAULT_USERNAME)
                password = user_input[CONF_PASSWORD]
                tls_insecure = user_input.get(CONF_TLS_INSECURE, DEFAULT_TLS_INSECURE)

                
                client = Client(url, username, password, {"tls_insecure": tls_insecure})
                system_info = await self.hass.async_add_executor_job(client.get_system_info)
                
                if name is None:
                    name = "{}.{}".format(system_info["hostname"], system_info["domain"])
                
                # https://developers.home-assistant.io/docs/config_entries_config_flow_handler#unique-ids
                await self.async_set_unique_id(slugify(system_info["netgate_device_id"]))
                self._abort_if_unique_id_configured()
                
                return self.async_create_entry(
                    title=name,
                    data={CONF_URL: url, CONF_PASSWORD: password, CONF_USERNAME: username, CONF_TLS_INSECURE: tls_insecure},
                )
            except InvalidURL:
                errors["base"] = "invalid_url_format"
            except xmlrpc.client.Fault as err:
                _LOGGER.exception(f"Unexpected {err=}, {type(err)=}")
                if "Invalid username or password" in str(err):
                    errors["base"] = "invalid_auth"
                elif "Authentication failed: not enough privileges" in str(err):
                    errors["base"] = "privilege_missing"
                else:
                    errors["base"] = "cannot_connect"
            except OSError as err:
                _LOGGER.exception(f"Unexpected {err=}, {type(err)=}")
                # bad response from pfSense when creds are valid but authorization is not sufficient
                # non-admin users must have 'System - HA node sync' privilege
                if "unsupported XML-RPC protocol" in str(err):
                    errors["base"] = "privilege_missing"
                elif "timed out" in str(err):
                    errors["base"] = "connect_timeout"
                elif "SSL:" in str(err):
                    """OSError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1129)"""
                    errors["base"] = "cannot_connect_tls"
                else:
                    _LOGGER.error("OSError: {0}".format(err))
                    errors["base"] = "unknown"
            except BaseException as err:
                _LOGGER.exception(f"Unexpected {err=}, {type(err)=}")
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="user", data_schema=CONFIG_SCHEMA, errors=errors
        )

    async def async_step_import(self, user_input):
        """Handle import."""
        return await self.async_step_user(user_input)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        """Get the options flow for this handler."""
        return OptionsFlowHandler(config_entry)

class OptionsFlowHandler(config_entries.OptionsFlow):
    """Handle option flow for pfSense."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(self, user_input=None):
        """Handle options flow."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        scan_interval = self.config_entry.options.get(
            CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
        )
        device_tracker_enabled = self.config_entry.options.get(CONF_DEVICE_TRACKER_ENABLED, DEFAULT_DEVICE_TRACKER_ENABLED)
        device_tracker_scan_interval = self.config_entry.options.get(
            CONF_DEVICE_TRACKER_SCAN_INTERVAL, DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL
        )

        base_schema = {
            vol.Optional(CONF_SCAN_INTERVAL, default=scan_interval): vol.All(
                vol.Coerce(int), vol.Clamp(min=10, max=300)
            ),
            vol.Optional(CONF_DEVICE_TRACKER_ENABLED, default=device_tracker_enabled): bool,
            vol.Optional(CONF_DEVICE_TRACKER_SCAN_INTERVAL, default=device_tracker_scan_interval): vol.All(
                vol.Coerce(int), vol.Clamp(min=30, max=300)
            ),
        }

        return self.async_show_form(step_id="init", data_schema=vol.Schema(base_schema))

class InvalidURL(Exception):
    """InavlidURL."""