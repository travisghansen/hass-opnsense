"""Config flow for OPNsense integration"""

import ipaddress
import logging
import re
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
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_create_clientsession

from .const import (
    CONF_DEVICE_TRACKER_CONSIDER_HOME,
    CONF_DEVICE_TRACKER_ENABLED,
    CONF_DEVICE_TRACKER_SCAN_INTERVAL,
    CONF_DEVICE_UNIQUE_ID,
    CONF_DEVICES,
    CONF_FIRMWARE_VERSION,
    CONF_MANUAL_DEVICES,
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


def is_valid_mac_address(mac: str) -> bool:
    mac_regex = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
    return bool(mac_regex.match(mac))


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


async def validate_input(
    hass: HomeAssistant, user_input: Mapping[str, Any], errors: Mapping[str, Any]
):
    try:
        fix_url = user_input[CONF_URL].strip()
        # ParseResult(
        #     scheme='', netloc='', path='f', params='', query='', fragment=''
        # )
        url_parts: ParseResult = urlparse(fix_url)
        if not url_parts.scheme and not url_parts.netloc:
            fix_url: str = "https://" + fix_url
            url_parts = urlparse(fix_url)

        if not url_parts.netloc:
            raise InvalidURL()

        # remove any path etc details
        user_input[CONF_URL] = f"{url_parts.scheme}://{url_parts.netloc}"

        client = OPNsenseClient(
            url=user_input[CONF_URL],
            username=user_input[CONF_USERNAME],
            password=user_input[CONF_PASSWORD],
            session=async_create_clientsession(hass, raise_for_status=True),
            opts={"verify_ssl": user_input[CONF_VERIFY_SSL]},
            initial=True,
        )

        user_input[CONF_FIRMWARE_VERSION] = await client.get_host_firmware_version()
        try:
            if awesomeversion.AwesomeVersion(
                user_input[CONF_FIRMWARE_VERSION]
            ) < awesomeversion.AwesomeVersion(OPNSENSE_MIN_FIRMWARE):
                raise BelowMinFirmware()
        except awesomeversion.exceptions.AwesomeVersionCompareException:
            raise UnknownFirmware()

        if not await client.is_plugin_installed():
            raise PluginMissing()

        system_info: Mapping[str, Any] = await client.get_system_info()
        if not user_input.get(CONF_NAME):
            user_input[CONF_NAME] = system_info.get("name") or "OPNsense"

        user_input[CONF_DEVICE_UNIQUE_ID] = await client.get_device_unique_id()
        if not user_input[CONF_DEVICE_UNIQUE_ID]:
            raise MissingDeviceUniqueID()

    except BelowMinFirmware:
        _LOGGER.error(
            f"OPNsense Firmware of {user_input[CONF_FIRMWARE_VERSION]} is below the minimum supported version of {OPNSENSE_MIN_FIRMWARE}"
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
    except PluginMissing:
        errors["base"] = "plugin_missing"
        _LOGGER.error("OPNsense Plugin Missing")
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
                [user_input[CONF_USERNAME], user_input[CONF_PASSWORD]],
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
                [user_input[CONF_USERNAME], user_input[CONF_PASSWORD]],
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
                [user_input[CONF_USERNAME], user_input[CONF_PASSWORD]],
            )
        )
    except Exception as err:
        _LOGGER.error(
            cleanse_sensitive_data(
                f"Other Error. {err.__class__.__qualname__}: {err}",
                [user_input[CONF_USERNAME], user_input[CONF_PASSWORD]],
            )
        )
        errors["base"] = "unknown"
    return errors


class ConfigFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for OPNsense"""

    # bumping this is what triggers async_migrate_entry for the component
    VERSION = 4

    # gets invoked without user input initially
    # when user submits has user_input
    async def async_step_user(self, user_input: Mapping[str, Any] | None = None):
        """Handle the initial step"""
        errors: Mapping[str, Any] = {}
        firmware = "Unknown"
        if user_input is not None:
            errors = await validate_input(
                hass=self.hass, user_input=user_input, errors=errors
            )
            firmware = user_input[CONF_FIRMWARE_VERSION]
            if not errors:
                # https://developers.home-assistant.io/docs/config_entries_config_flow_handler#unique-ids
                await self.async_set_unique_id(user_input[CONF_DEVICE_UNIQUE_ID])
                self._abort_if_unique_id_configured()

                return self.async_create_entry(
                    title=user_input[CONF_NAME],
                    data={
                        CONF_URL: user_input[CONF_URL],
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                        CONF_USERNAME: user_input[CONF_USERNAME],
                        CONF_VERIFY_SSL: user_input[CONF_VERIFY_SSL],
                        CONF_DEVICE_UNIQUE_ID: user_input[CONF_DEVICE_UNIQUE_ID],
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
                "firmware": firmware,
                "min_firmware": OPNSENSE_MIN_FIRMWARE,
            },
        )

    async def async_step_reconfigure(self, user_input: Mapping[str, Any] | None = None):
        reconfigure_entry = self._get_reconfigure_entry()
        prev_data = reconfigure_entry.data
        errors: Mapping[str, Any] = {}
        firmware = "Unknown"
        if user_input is not None:
            user_input[CONF_NAME] = prev_data.get(CONF_NAME, "")
            errors = await validate_input(
                hass=self.hass, user_input=user_input, errors=errors
            )
            firmware = user_input[CONF_FIRMWARE_VERSION]
            if not errors:
                # https://developers.home-assistant.io/docs/config_entries_config_flow_handler#unique-ids
                await self.async_set_unique_id(user_input[CONF_DEVICE_UNIQUE_ID])
                self._abort_if_unique_id_mismatch()

                return self.async_create_entry(
                    title=user_input[CONF_NAME],
                    data={
                        CONF_URL: user_input[CONF_URL],
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                        CONF_USERNAME: user_input[CONF_USERNAME],
                        CONF_VERIFY_SSL: user_input[CONF_VERIFY_SSL],
                        CONF_DEVICE_UNIQUE_ID: user_input[CONF_DEVICE_UNIQUE_ID],
                    },
                )

        if not user_input:
            user_input = {}
        schema = vol.Schema(
            {
                vol.Required(
                    CONF_URL,
                    default=user_input.get(
                        CONF_URL, prev_data.get(CONF_URL, "https://")
                    ),
                ): str,
                vol.Optional(
                    CONF_VERIFY_SSL,
                    default=user_input.get(
                        CONF_VERIFY_SSL,
                        prev_data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
                    ),
                ): bool,
                vol.Required(
                    CONF_USERNAME,
                    default=user_input.get(
                        CONF_USERNAME, prev_data.get(CONF_USERNAME, "")
                    ),
                ): str,
                vol.Required(
                    CONF_PASSWORD,
                    default=user_input.get(
                        CONF_PASSWORD, prev_data.get(CONF_PASSWORD, "")
                    ),
                ): str,
            }
        )

        return self.async_show_form(
            step_id="reconfigure",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                "firmware": firmware,
                "min_firmware": OPNSENSE_MIN_FIRMWARE,
            },
        )

    async def async_step_import(self, user_input):
        """Handle import"""
        return await self.async_step_user(user_input)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        """Get the options flow for this handler"""
        return OptionsFlowHandler(config_entry)


class OptionsFlowHandler(config_entries.OptionsFlow):
    """Handle option flow for OPNsense"""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow"""
        self.new_options = None
        self.config_entry = config_entry

    async def async_step_init(self, user_input=None):
        """Handle options flow"""
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
        """Handle device tracker list step"""
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
                label: str = f"{ip} {'(' + hostname + ') ' if hostname else ''}[{mac}]"
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
                        vol.Optional(CONF_MANUAL_DEVICES): selector.TextSelector(
                            selector.TextSelectorConfig()
                        ),
                    }
                ),
            )
        if user_input:
            macs: list = []
            if isinstance(
                user_input.get(CONF_MANUAL_DEVICES, None), str
            ) and user_input.get(CONF_MANUAL_DEVICES, None):
                for item in user_input[CONF_MANUAL_DEVICES].split(","):
                    if not isinstance(item, str) or not item:
                        continue
                    item = item.strip()
                    if is_valid_mac_address(item):
                        macs.append(item)
                _LOGGER.debug(f"[async_step_device_tracker] Manual Devices: {macs}")
            _LOGGER.debug(
                f"[async_step_device_tracker] Devices: {user_input[CONF_DEVICES]}"
            )
            self.new_options[CONF_DEVICES] = user_input[CONF_DEVICES] + macs
        return self.async_create_entry(title="", data=self.new_options)


class InvalidURL(Exception):
    """InavlidURL"""


class MissingDeviceUniqueID(Exception):
    pass


class BelowMinFirmware(Exception):
    pass


class UnknownFirmware(Exception):
    pass


class PluginMissing(Exception):
    pass
