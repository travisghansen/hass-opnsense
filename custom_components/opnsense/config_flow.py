"""Config flow for OPNsense integration."""

from collections.abc import MutableMapping
import ipaddress
import logging
import re
import socket
from typing import Any
from urllib.parse import ParseResult, quote_plus, urlparse
import xmlrpc

import aiohttp
import awesomeversion
import voluptuous as vol

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
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
import homeassistant.helpers.config_validation as cv

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

_LOGGER: logging.Logger = logging.getLogger(__name__)


def is_valid_mac_address(mac: str) -> bool:
    """Check if string is a valid MAC address."""
    mac_regex = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
    return bool(mac_regex.match(mac))


def is_ip_address(value) -> bool:
    """Check if string is a valid IP address."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    else:
        return True


def cleanse_sensitive_data(message: str, secrets: list | None = None) -> str:
    """Remove sensitive data from logging messages."""
    secrets = secrets or []
    for secret in secrets:
        if secret is not None:
            message = message.replace(secret, "[redacted]")
            message = message.replace(quote_plus(secret), "[redacted]")
    return message


async def validate_input(
    hass: HomeAssistant,
    user_input: MutableMapping[str, Any],
    errors: MutableMapping[str, Any],
) -> MutableMapping[str, Any]:
    """Check user input for errors."""
    filtered_user_input: MutableMapping[str, Any] = {
        key: value for key, value in user_input.items() if key != CONF_PASSWORD
    }

    _LOGGER.debug("[config_flow] user_input: %s", filtered_user_input)

    try:
        await _handle_user_input(user_input, hass)
    except BelowMinFirmware:
        _log_and_set_error(
            errors=errors,
            key="below_min_firmware",
            message=f"OPNsense Firmware of {user_input.get(CONF_FIRMWARE_VERSION)} is below the minimum supported version of {OPNSENSE_MIN_FIRMWARE}",
        )
    except UnknownFirmware:
        _log_and_set_error(
            errors=errors,
            key="unknown_firmware",
            message="Unable to get OPNsense Firmware version",
        )
    except MissingDeviceUniqueID as err:
        _log_and_set_error(
            errors=errors,
            key="missing_device_unique_id",
            message=f"Missing Device Unique ID Error. {err.__class__.__qualname__}: {err}",
        )
    except PluginMissing:
        _log_and_set_error(
            errors=errors, key="plugin_missing", message="OPNsense Plugin Missing"
        )
    except (aiohttp.InvalidURL, InvalidURL) as err:
        _log_and_set_error(
            errors=errors,
            key="invalid_url_format",
            message=f"InvalidURL Error. {err.__class__.__qualname__}: {err}",
        )
    except xmlrpc.client.Fault as err:
        error_message = str(err)
        if "Invalid username or password" in error_message:
            errors["base"] = "invalid_auth"
        elif "Authentication failed: not enough privileges" in error_message:
            errors["base"] = "privilege_missing"
        elif "opnsense.exec_php does not exist" in error_message:
            errors["base"] = "plugin_missing"
        else:
            errors["base"] = "cannot_connect"
        _LOGGER.error(
            cleanse_sensitive_data(
                f"XMLRPC Error. {err.__class__.__qualname__}: {err}",
                [user_input.get(CONF_USERNAME), user_input.get(CONF_PASSWORD)],
            )
        )
    except aiohttp.ClientConnectorSSLError as err:
        _log_and_set_error(
            errors=errors,
            key="cannot_connect_ssl",
            message=f"Aiohttp Error. {err.__class__.__qualname__}: {err}",
        )
    except aiohttp.ClientResponseError as err:
        if err.status in {401, 403}:
            errors["base"] = "invalid_auth"
        else:
            errors["base"] = "cannot_connect"
        _LOGGER.error("Aiohttp Error. %s: %s", err.__class__.__qualname__, err)
    except (aiohttp.ClientError, aiohttp.ClientConnectorError, socket.gaierror) as err:
        _log_and_set_error(
            errors=errors,
            key="cannot_connect",
            message=f"Aiohttp Error. {err.__class__.__qualname__}: {err}",
        )
    except xmlrpc.client.ProtocolError as err:
        error_message = str(err)
        if (
            "307 Temporary Redirect" in error_message
            or "301 Moved Permanently" in error_message
        ):
            errors["base"] = "url_redirect"
        else:
            errors["base"] = "cannot_connect"
        _LOGGER.error(
            cleanse_sensitive_data(
                f"XMLRPC Error. {err.__class__.__qualname__}: {err}",
                [user_input.get(CONF_USERNAME), user_input.get(CONF_PASSWORD)],
            )
        )
    except (aiohttp.TooManyRedirects, aiohttp.RedirectClientError) as err:
        _log_and_set_error(
            errors=errors,
            key="url_redirect",
            message=f"Redirect Error. {err.__class__.__qualname__}: {err}",
        )
    except (TimeoutError, aiohttp.ServerTimeoutError) as err:
        _log_and_set_error(
            errors=errors,
            key="connect_timeout",
            message=f"Timeout Error. {err.__class__.__qualname__}: {err}",
        )
    except OSError as err:
        error_message = str(err)
        if "unsupported XML-RPC protocol" in error_message:
            errors["base"] = "privilege_missing"
        elif "timed out" in error_message:
            errors["base"] = "connect_timeout"
        elif "SSL:" in error_message:
            errors["base"] = "cannot_connect_ssl"
        else:
            errors["base"] = "unknown"
        _LOGGER.error(
            cleanse_sensitive_data(
                f"Error. {err.__class__.__qualname__}: {err}",
                [user_input.get(CONF_USERNAME), user_input.get(CONF_PASSWORD)],
            )
        )
    return errors


async def _clean_and_parse_url(user_input: MutableMapping[str, Any]) -> None:
    """Clean and parse the URL."""
    fix_url: str = user_input.get(CONF_URL, "").strip()
    url_parts: ParseResult = urlparse(fix_url)

    if not url_parts.scheme and not url_parts.netloc:
        fix_url = "https://" + fix_url
        url_parts = urlparse(fix_url)

    if not url_parts.netloc:
        raise InvalidURL

    user_input[CONF_URL] = f"{url_parts.scheme}://{url_parts.netloc}"
    _LOGGER.debug("[config_flow] Cleaned URL: %s", user_input[CONF_URL])


async def _get_client(
    user_input: MutableMapping[str, Any], hass: HomeAssistant
) -> OPNsenseClient:
    """Create and return the OPNsense client."""
    return OPNsenseClient(
        url=user_input[CONF_URL],
        username=user_input[CONF_USERNAME],
        password=user_input[CONF_PASSWORD],
        session=async_create_clientsession(
            hass=hass, raise_for_status=True, cookie_jar=aiohttp.CookieJar(unsafe=True)
        ),
        opts={"verify_ssl": user_input.get(CONF_VERIFY_SSL)},
        initial=True,
    )


def _validate_firmware_version(firmware_version: str) -> None:
    """Validate the firmware version."""
    if awesomeversion.AwesomeVersion(firmware_version) < awesomeversion.AwesomeVersion(
        OPNSENSE_MIN_FIRMWARE
    ):
        raise BelowMinFirmware


async def _handle_user_input(
    user_input: MutableMapping[str, Any], hass: HomeAssistant
) -> None:
    """Handle and validate the user input."""
    await _clean_and_parse_url(user_input)

    client: OPNsenseClient = await _get_client(user_input, hass)

    user_input[CONF_FIRMWARE_VERSION] = await client.get_host_firmware_version()
    _LOGGER.debug(
        "[config_flow] Firmware Version: %s", user_input[CONF_FIRMWARE_VERSION]
    )

    try:
        _validate_firmware_version(user_input[CONF_FIRMWARE_VERSION])
    except awesomeversion.exceptions.AwesomeVersionCompareException as e:
        raise UnknownFirmware from e

    if not await client.is_plugin_installed():
        raise PluginMissing

    system_info: MutableMapping[str, Any] = await client.get_system_info()
    _LOGGER.debug("[config_flow] system_info: %s", system_info)

    if not user_input.get(CONF_NAME):
        user_input[CONF_NAME] = system_info.get("name") or "OPNsense"

    user_input[CONF_DEVICE_UNIQUE_ID] = await client.get_device_unique_id()
    _LOGGER.debug(
        "[config_flow] Device Unique ID: %s", user_input[CONF_DEVICE_UNIQUE_ID]
    )

    if not user_input.get(CONF_DEVICE_UNIQUE_ID):
        raise MissingDeviceUniqueID


def _log_and_set_error(
    errors: MutableMapping[str, Any], key: str, message: str
) -> None:
    """Log the error and set it in the errors dictionary."""
    _LOGGER.error(message)
    errors["base"] = key


class OPNsenseConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for OPNsense."""

    # bumping this is what triggers async_migrate_entry for the component
    VERSION = 4

    # gets invoked without user input initially
    # when user submits has user_input
    async def async_step_user(
        self, user_input: MutableMapping[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: MutableMapping[str, Any] = {}
        firmware: str = "Unknown"
        if user_input is not None:
            errors = await validate_input(
                hass=self.hass, user_input=user_input, errors=errors
            )
            firmware = user_input.get(CONF_FIRMWARE_VERSION, "Unknown")
            if not errors:
                # https://developers.home-assistant.io/docs/config_entries_config_flow_handler#unique-ids
                await self.async_set_unique_id(user_input.get(CONF_DEVICE_UNIQUE_ID))
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
            errors=dict(errors),
            description_placeholders={
                "firmware": firmware,
                "min_firmware": OPNSENSE_MIN_FIRMWARE,
            },
        )

    async def async_step_reconfigure(
        self, user_input: MutableMapping[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Config flow reconfigure step."""
        reconfigure_entry = self._get_reconfigure_entry()
        prev_data = reconfigure_entry.data
        errors: MutableMapping[str, Any] = {}
        firmware: str = "Unknown"
        if user_input is not None:
            user_input[CONF_NAME] = prev_data.get(CONF_NAME, "")
            errors = await validate_input(
                hass=self.hass, user_input=user_input, errors=errors
            )
            firmware = user_input.get(CONF_FIRMWARE_VERSION, "Unknown")
            if not errors:
                # https://developers.home-assistant.io/docs/config_entries_config_flow_handler#unique-ids
                await self.async_set_unique_id(user_input.get(CONF_DEVICE_UNIQUE_ID))
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
            errors=dict(errors),
            description_placeholders={
                "firmware": firmware,
                "min_firmware": OPNSENSE_MIN_FIRMWARE,
            },
        )

    async def async_step_import(self, user_input) -> ConfigFlowResult:
        """Handle import."""
        return await self.async_step_user(user_input)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        """Get the options flow for this handler."""
        return OPNsenseOptionsFlow(config_entry)


class OPNsenseOptionsFlow(OptionsFlow):
    """Handle option flow for OPNsense."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        """Initialize options flow."""
        self.new_options: MutableMapping[str, Any] = {}
        self.config_entry = config_entry

    async def async_step_init(self, user_input=None) -> ConfigFlowResult:
        """Handle options flow."""
        if user_input is not None:
            _LOGGER.debug("[options_flow init] user_input: %s", user_input)
            if user_input.get(CONF_DEVICE_TRACKER_ENABLED):
                self.new_options = user_input
                return await self.async_step_device_tracker()
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

    async def async_step_device_tracker(self, user_input=None) -> ConfigFlowResult:
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
            session=async_create_clientsession(
                hass=self.hass,
                raise_for_status=False,
                cookie_jar=aiohttp.CookieJar(unsafe=True),
            ),
            opts={"verify_ssl": verify_ssl},
        )
        if user_input is None and (arp_table := await client.get_arp_table(True)):
            selected_devices: list = self.config_entry.options.get(CONF_DEVICES, [])

            # dicts are ordered so put all previously selected items at the top
            entries: MutableMapping[str, Any] = {}
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

            sorted_entries: MutableMapping[str, Any] = dict(
                sorted(
                    entries.items(),
                    key=lambda item: (
                        0
                        if not is_ip_address(item[1].split()[0])
                        else 1,  # Sort MAC address only labels first
                        item[1].split()[0]
                        if not is_ip_address(item[1].split()[0])
                        else ipaddress.ip_address(item[1].split()[0]),
                    ),
                )
            )

            return self.async_show_form(
                step_id="device_tracker",
                data_schema=vol.Schema(
                    {
                        vol.Optional(
                            CONF_DEVICES, default=selected_devices
                        ): cv.multi_select(dict(sorted_entries)),
                        vol.Optional(CONF_MANUAL_DEVICES): selector.TextSelector(
                            selector.TextSelectorConfig()
                        ),
                    }
                ),
            )
        if user_input:
            _LOGGER.debug("[options_flow device_tracker] user_input: %s", user_input)
            macs: list = []
            if isinstance(
                user_input.get(CONF_MANUAL_DEVICES, None), str
            ) and user_input.get(CONF_MANUAL_DEVICES, None):
                for item in user_input.get(CONF_MANUAL_DEVICES).split(","):
                    if not isinstance(item, str) or not item:
                        continue
                    item = item.strip()
                    if is_valid_mac_address(item):
                        macs.append(item)
                _LOGGER.debug("[async_step_device_tracker] Manual Devices: %s", macs)
            _LOGGER.debug(
                "[async_step_device_tracker] Devices: %s", user_input.get(CONF_DEVICES)
            )
            self.new_options[CONF_DEVICES] = user_input.get(CONF_DEVICES) + macs
        return self.async_create_entry(title="", data=self.new_options)


class InvalidURL(Exception):
    """InvalidURL."""


class MissingDeviceUniqueID(Exception):
    """Missing the Device Unique ID."""


class BelowMinFirmware(Exception):
    """Current firmware is below the Minimum supported version."""


class UnknownFirmware(Exception):
    """Unknown current firmware version."""


class PluginMissing(Exception):
    """OPNsense plugin missing."""
