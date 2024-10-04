"""Config flow for OPNsense integration."""

import ipaddress
import logging
import socket
import xmlrpc
from collections.abc import Mapping
from typing import Any
from urllib.parse import ParseResult, quote_plus, urlparse

import aiohttp
import awesomeversion
import homeassistant.helpers.config_validation as cv
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import (
    CONF_NAME,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_URL,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
)
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_create_clientsession

from .const import (
    CONF_DEVICE_TRACKER_CONSIDER_HOME,
    CONF_DEVICE_TRACKER_ENABLED,
    CONF_DEVICE_TRACKER_SCAN_INTERVAL,
    CONF_DEVICE_UNIQUE_ID,
    CONF_DEVICES,
    DEFAULT_DEVICE_TRACKER_CONSIDER_HOME,
    DEFAULT_DEVICE_TRACKER_ENABLED,
    DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
    OPNSENSE_MIN_FIRMWARE,
)
from .pyopnsense import OPNsenseClient

_LOGGER = logging.getLogger(__name__)


def is_ip_address(value) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def cleanse_sensitive_data(message, secrets=[]):
    for secret in secrets:
        if secret is not None:
            message = message.replace(secret, "[redacted]")
            message = message.replace(quote_plus(secret), "[redacted]")
    return message


class ConfigFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for OPNsense."""

    # bumping this is what triggers async_migrate_entry for the component
    VERSION = 3

    # gets invoked without user input initially
    # when user submits has user_input
    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}
        if user_input is not None:
            try:
                name = user_input.get(CONF_NAME, False) or None

                url = user_input[CONF_URL].strip()
                # ParseResult(
                #     scheme='', netloc='', path='f', params='', query='', fragment=''
                # )
                url_parts: ParseResult = urlparse(url)
                if not url_parts.scheme and not url_parts.netloc:
                    # raise InvalidURL()
                    url: str = "https://" + url
                    url_parts = urlparse(url)

                if not url_parts.netloc:
                    raise InvalidURL()

                # remove any path etc details
                url = f"{url_parts.scheme}://{url_parts.netloc}"
                username: str = user_input[CONF_USERNAME]
                password: str = user_input[CONF_PASSWORD]
                verify_ssl: bool = user_input.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL)

                client = OPNsenseClient(
                    url=url,
                    username=username,
                    password=password,
                    session=async_create_clientsession(
                        self.hass, raise_for_status=True
                    ),
                    opts={"verify_ssl": verify_ssl},
                    initial=True,
                )

                firmware: str = await client.get_host_firmware_version()
                try:
                    if awesomeversion.AwesomeVersion(
                        firmware
                    ) < awesomeversion.AwesomeVersion(OPNSENSE_MIN_FIRMWARE):
                        raise BelowMinFirmware()
                except awesomeversion.exceptions.AwesomeVersionCompareException:
                    raise UnknownFirmware()

                system_info: Mapping[str, Any] = await client.get_system_info()

                if name is None:
                    name: str = system_info.get("name") or "OPNsense"

                device_unique_id: str | None = await client.get_device_unique_id()
                if not device_unique_id:
                    raise MissingDeviceUniqueID()
                # https://developers.home-assistant.io/docs/config_entries_config_flow_handler#unique-ids
                await self.async_set_unique_id(device_unique_id)
                self._abort_if_unique_id_configured()

            except BelowMinFirmware:
                _LOGGER.error(
                    f"OPNsense Firmware of {firmware} is below the minimum supported version of {OPNSENSE_MIN_FIRMWARE}"
                )
                errors["base"] = "below_min_firmware"
            except UnknownFirmware:
                _LOGGER.error("Unable to get OPNsense Firmware version")
                errors["base"] = "unknown_firmware"
            except MissingDeviceUniqueID as err:
                errors["base"] = "missing_device_unique_id"
                _LOGGER.error(
                    f"Missing Device Unique ID Error. {err.__class__.__qualname__}: {err}"
                )
            except (aiohttp.InvalidURL, InvalidURL) as err:
                errors["base"] = "invalid_url_format"
                _LOGGER.error(f"InvalidURL Error. {err.__class__.__qualname__}: {err}")
            except xmlrpc.client.Fault as err:
                if "Invalid username or password" in str(err):
                    errors["base"] = "invalid_auth"
                elif "Authentication failed: not enough privileges" in str(err):
                    errors["base"] = "privilege_missing"
                elif "opnsense.exec_php does not exist" in str(err):
                    errors["base"] = "plugin_missing"
                else:
                    errors["base"] = "cannot_connect"
                _LOGGER.error(
                    cleanse_sensitive_data(
                        f"XMLRPC Error. {err.__class__.__qualname__}: {err}",
                        [username, password],
                    )
                )
            except aiohttp.ClientConnectorSSLError as err:
                errors["base"] = "cannot_connect_ssl"
                _LOGGER.error(f"Aiohttp Error. {err.__class__.__qualname__}: {err}")
            except (aiohttp.ClientResponseError,) as err:
                if err.status == 401 or err.status == 403:
                    errors["base"] = "invalid_auth"
                else:
                    errors["base"] = "cannot_connect"
                _LOGGER.error(f"Aiohttp Error. {err.__class__.__qualname__}: {err}")
            except (
                aiohttp.ClientError,
                aiohttp.ClientConnectorError,
                socket.gaierror,
            ) as err:
                errors["base"] = "cannot_connect"
                _LOGGER.error(f"Aiohttp Error. {err.__class__.__qualname__}: {err}")
            except xmlrpc.client.ProtocolError as err:
                if "307 Temporary Redirect" in str(err):
                    errors["base"] = "url_redirect"
                elif "301 Moved Permanently" in str(err):
                    errors["base"] = "url_redirect"
                else:
                    errors["base"] = "cannot_connect"
                _LOGGER.error(
                    cleanse_sensitive_data(
                        f"XMLRPC Error. {err.__class__.__qualname__}: {err}",
                        [username, password],
                    )
                )
            except (aiohttp.TooManyRedirects, aiohttp.RedirectClientError) as err:
                _LOGGER.error(f"Redirect Error. {err.__class__.__qualname__}: {err}")
                errors["base"] = "url_redirect"
            except (TimeoutError, aiohttp.ServerTimeoutError) as err:
                _LOGGER.error(f"Timeout Error. {err.__class__.__qualname__}: {err}")
                errors["base"] = "connect_timeout"
            except OSError as err:
                # bad response from OPNsense when creds are valid but authorization is
                # not sufficient non-admin users must have 'System - HA node sync'
                # privilege
                if "unsupported XML-RPC protocol" in str(err):
                    errors["base"] = "privilege_missing"
                elif "timed out" in str(err):
                    errors["base"] = "connect_timeout"
                elif "SSL:" in str(err):
                    """OSError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1129)"""
                    errors["base"] = "cannot_connect_ssl"
                else:
                    errors["base"] = "unknown"
                _LOGGER.error(
                    cleanse_sensitive_data(
                        f"Error. {err.__class__.__qualname__}: {err}",
                        [username, password],
                    )
                )
            except Exception as err:
                _LOGGER.error(
                    cleanse_sensitive_data(
                        f"Other Error. {err.__class__.__qualname__}: {err}",
                        [username, password],
                    )
                )
                errors["base"] = "unknown"
            else:
                return self.async_create_entry(
                    title=name,
                    data={
                        CONF_URL: url,
                        CONF_PASSWORD: password,
                        CONF_USERNAME: username,
                        CONF_VERIFY_SSL: verify_ssl,
                        CONF_DEVICE_UNIQUE_ID: device_unique_id,
                    },
                )

        if not user_input:
            user_input = {}
        schema = vol.Schema(
            {
                vol.Required(
                    CONF_URL, default=user_input.get(CONF_URL, "https://")
                ): str,
                vol.Optional(
                    CONF_VERIFY_SSL,
                    default=user_input.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
                ): bool,
                vol.Required(
                    CONF_USERNAME,
                    default=user_input.get(CONF_USERNAME, ""),
                ): str,
                vol.Required(
                    CONF_PASSWORD, default=user_input.get(CONF_PASSWORD, "")
                ): str,
                vol.Optional(CONF_NAME, default=user_input.get(CONF_NAME, "")): str,
            }
        )

        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                "firmware": firmware if "firmware" in locals() else "Unknown",
                "min_firmware": OPNSENSE_MIN_FIRMWARE,
            },
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
    """Handle option flow for OPNsense."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self.new_options = None
        self.config_entry = config_entry

    async def async_step_init(self, user_input=None):
        """Handle options flow."""
        if user_input is not None:
            if user_input.get(CONF_DEVICE_TRACKER_ENABLED):
                self.new_options = user_input
                return await self.async_step_device_tracker()
            else:
                return self.async_create_entry(title="", data=user_input)

        scan_interval = self.config_entry.options.get(
            CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
        )
        device_tracker_enabled = self.config_entry.options.get(
            CONF_DEVICE_TRACKER_ENABLED, DEFAULT_DEVICE_TRACKER_ENABLED
        )
        device_tracker_scan_interval = self.config_entry.options.get(
            CONF_DEVICE_TRACKER_SCAN_INTERVAL, DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL
        )
        device_tracker_consider_home = self.config_entry.options.get(
            CONF_DEVICE_TRACKER_CONSIDER_HOME, DEFAULT_DEVICE_TRACKER_CONSIDER_HOME
        )

        base_schema = {
            vol.Optional(CONF_SCAN_INTERVAL, default=scan_interval): vol.All(
                vol.Coerce(int), vol.Clamp(min=10, max=300)
            ),
            vol.Optional(
                CONF_DEVICE_TRACKER_ENABLED, default=device_tracker_enabled
            ): bool,
            vol.Optional(
                CONF_DEVICE_TRACKER_SCAN_INTERVAL, default=device_tracker_scan_interval
            ): vol.All(vol.Coerce(int), vol.Clamp(min=30, max=300)),
            vol.Optional(
                CONF_DEVICE_TRACKER_CONSIDER_HOME, default=device_tracker_consider_home
            ): vol.All(vol.Coerce(int), vol.Clamp(min=0, max=600)),
        }

        return self.async_show_form(step_id="init", data_schema=vol.Schema(base_schema))

    async def async_step_device_tracker(self, user_input=None):
        """Handle device tracker list step."""
        url = self.config_entry.data[CONF_URL].strip()
        username: str = self.config_entry.data[CONF_USERNAME]
        password: str = self.config_entry.data[CONF_PASSWORD]
        verify_ssl: bool = self.config_entry.data.get(
            CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL
        )
        client = OPNsenseClient(
            url=url,
            username=username,
            password=password,
            session=async_create_clientsession(self.hass, raise_for_status=False),
            opts={"verify_ssl": verify_ssl},
        )
        if user_input is None and (arp_table := await client.get_arp_table(True)):
            selected_devices: list = self.config_entry.options.get(CONF_DEVICES, [])

            # dicts are ordered so put all previously selected items at the top
            entries: Mapping[str, Any] = {}
            for device in selected_devices:
                entries[device] = device

            # follow with all arp table entries
            for entry in arp_table:
                mac: str = entry.get("mac", "").lower().strip()
                if len(mac) < 1:
                    continue
                hostname: str = entry.get("hostname", "").strip("?").strip()
                ip: str = entry.get("ip", "").strip()
                label: str = f"{ip} {'('+hostname+') ' if hostname else ''}[{mac}]"
                entries[mac] = label

            sorted_entries: Mapping[str, Any] = {
                key: value
                for key, value in sorted(
                    entries.items(),
                    key=lambda item: (
                        (
                            0 if not is_ip_address(item[1].split()[0]) else 1
                        ),  # Sort MAC address only labels first
                        (
                            item[1].split()[0]
                            if not is_ip_address(item[1].split()[0])
                            else ipaddress.ip_address(item[1].split()[0])
                        ),
                    ),
                )
            }

            return self.async_show_form(
                step_id="device_tracker",
                data_schema=vol.Schema(
                    {
                        vol.Optional(
                            CONF_DEVICES, default=selected_devices
                        ): cv.multi_select(sorted_entries),
                    }
                ),
            )
        if user_input:
            self.new_options[CONF_DEVICES] = user_input[CONF_DEVICES]
        return self.async_create_entry(title="", data=self.new_options)


class InvalidURL(Exception):
    """InavlidURL."""


class MissingDeviceUniqueID(Exception):
    pass


class BelowMinFirmware(Exception):
    pass


class UnknownFirmware(Exception):
    pass
