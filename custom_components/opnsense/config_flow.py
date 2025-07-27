"""Config flow for OPNsense integration."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
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

from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult, OptionsFlow
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
    CONF_GRANULAR_SYNC_OPTIONS,
    CONF_MANUAL_DEVICES,
    DEFAULT_DEVICE_TRACKER_CONSIDER_HOME,
    DEFAULT_DEVICE_TRACKER_ENABLED,
    DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL,
    DEFAULT_GRANULAR_SYNC_OPTIONS,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SYNC_OPTION_VALUE,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
    GRANULAR_SYNC_ITEMS,
    OPNSENSE_MIN_FIRMWARE,
    SYNC_ITEMS_REQUIRING_PLUGIN,
    TRACKED_MACS,
)
from .helpers import is_private_ip
from .pyopnsense import OPNsenseClient

_LOGGER: logging.Logger = logging.getLogger(__name__)


def is_valid_mac_address(mac: str) -> bool:
    """Check if string is a valid MAC address."""
    mac_regex = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
    return bool(mac_regex.match(mac))


def is_ip_address(value: str) -> bool:
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
    errors: dict[str, Any],
) -> dict[str, Any]:
    """Check user input for errors."""
    # filtered_user_input: MutableMapping[str, Any] = {key: value for key, value in user_input.items() if key != CONF_PASSWORD}
    # _LOGGER.debug("[validate_input] user_input: %s", filtered_user_input)

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
    except MissingDeviceUniqueID as e:
        _log_and_set_error(
            errors=errors,
            key="missing_device_unique_id",
            message=f"Missing Device Unique ID Error. {type(e).__name__}: {e}",
        )
    except PluginMissing:
        _log_and_set_error(errors=errors, key="plugin_missing", message="OPNsense Plugin Missing")
    except (aiohttp.InvalidURL, InvalidURL) as e:
        _log_and_set_error(
            errors=errors,
            key="invalid_url_format",
            message=f"InvalidURL Error. {type(e).__name__}: {e}",
        )
    except xmlrpc.client.Fault as e:
        error_message = str(e)
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
                f"XMLRPC Error. {type(e).__name__}: {e}",
                [user_input.get(CONF_USERNAME), user_input.get(CONF_PASSWORD)],
            )
        )
    except aiohttp.ClientConnectorSSLError as e:
        _log_and_set_error(
            errors=errors,
            key="cannot_connect_ssl",
            message=f"Aiohttp Error. {type(e).__name__}: {e}",
        )
    except aiohttp.ClientResponseError as e:
        if e.status == 401:
            errors["base"] = "invalid_auth"
        elif e.status == 403:
            errors["base"] = "privilege_missing"
        else:
            errors["base"] = "cannot_connect"
        _LOGGER.error("Aiohttp Error. %s: %s", type(e).__name__, e)
    except (aiohttp.ClientError, aiohttp.ClientConnectorError, socket.gaierror) as e:
        _log_and_set_error(
            errors=errors,
            key="cannot_connect",
            message=f"Aiohttp Error. {type(e).__name__}: {e}",
        )
    except xmlrpc.client.ProtocolError as e:
        error_message = str(e)
        if "307 Temporary Redirect" in error_message or "301 Moved Permanently" in error_message:
            errors["base"] = "url_redirect"
        else:
            errors["base"] = "cannot_connect"
        _LOGGER.error(
            cleanse_sensitive_data(
                f"XMLRPC Error. {type(e).__name__}: {e}",
                [user_input.get(CONF_USERNAME), user_input.get(CONF_PASSWORD)],
            )
        )
    except (aiohttp.TooManyRedirects, aiohttp.RedirectClientError) as e:
        _log_and_set_error(
            errors=errors,
            key="url_redirect",
            message=f"Redirect Error. {type(e).__name__}: {e}",
        )
    except (TimeoutError, aiohttp.ServerTimeoutError) as e:
        _log_and_set_error(
            errors=errors,
            key="connect_timeout",
            message=f"Timeout Error. {type(e).__name__}: {e}",
        )
    except OSError as e:
        error_message = str(e)
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
                f"Error. {type(e).__name__}: {e}",
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


async def _get_client(user_input: MutableMapping[str, Any], hass: HomeAssistant) -> OPNsenseClient:
    """Create and return the OPNsense client."""
    return OPNsenseClient(
        url=user_input[CONF_URL],
        username=user_input[CONF_USERNAME],
        password=user_input[CONF_PASSWORD],
        session=async_create_clientsession(
            hass=hass,
            raise_for_status=True,
            cookie_jar=aiohttp.CookieJar(unsafe=is_private_ip(user_input[CONF_URL])),
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


async def _handle_user_input(user_input: MutableMapping[str, Any], hass: HomeAssistant) -> None:
    """Handle and validate the user input."""
    await _clean_and_parse_url(user_input)

    client: OPNsenseClient = await _get_client(user_input, hass)

    user_input[CONF_FIRMWARE_VERSION] = await client.get_host_firmware_version()
    _LOGGER.debug("[config_flow] Firmware Version: %s", user_input[CONF_FIRMWARE_VERSION])

    try:
        _validate_firmware_version(user_input[CONF_FIRMWARE_VERSION])
    except awesomeversion.exceptions.AwesomeVersionCompareException as e:
        raise UnknownFirmware from e

    require_plugin = any(
        user_input.get(item, DEFAULT_SYNC_OPTION_VALUE) for item in SYNC_ITEMS_REQUIRING_PLUGIN
    )
    if require_plugin and not await client.is_plugin_installed():
        raise PluginMissing

    system_info: MutableMapping[str, Any] = await client.get_system_info()
    _LOGGER.debug("[config_flow] system_info: %s", system_info)

    if not user_input.get(CONF_NAME):
        user_input[CONF_NAME] = system_info.get("name") or "OPNsense"

    user_input[CONF_DEVICE_UNIQUE_ID] = await client.get_device_unique_id()
    _LOGGER.debug("[config_flow] Device Unique ID: %s", user_input[CONF_DEVICE_UNIQUE_ID])

    if not user_input.get(CONF_DEVICE_UNIQUE_ID):
        raise MissingDeviceUniqueID


def _log_and_set_error(errors: MutableMapping[str, Any], key: str, message: str) -> None:
    """Log the error and set it in the errors dictionary."""
    _LOGGER.error(message)
    errors["base"] = key


def _build_user_input_schema(
    user_input: MutableMapping[str, Any] | None,
    fallback: MutableMapping[str, Any] | None = None,
    reconf: bool = False,
) -> vol.Schema:
    if user_input is None:
        user_input = {}
    if fallback is None:
        fallback = {}

    schema = vol.Schema(
        {
            vol.Required(
                CONF_URL, default=user_input.get(CONF_URL, fallback.get(CONF_URL, "https://"))
            ): str,
            vol.Optional(
                CONF_VERIFY_SSL,
                default=user_input.get(
                    CONF_VERIFY_SSL, fallback.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL)
                ),
            ): bool,
            vol.Required(
                CONF_USERNAME,
                default=user_input.get(CONF_USERNAME, fallback.get(CONF_USERNAME, "")),
            ): str,
            vol.Required(
                CONF_PASSWORD,
                default=user_input.get(CONF_PASSWORD, fallback.get(CONF_PASSWORD, "")),
            ): str,
        }
    )
    if not reconf:
        schema = schema.extend(
            {
                vol.Optional(
                    CONF_NAME, default=user_input.get(CONF_NAME, fallback.get(CONF_NAME, ""))
                ): str,
                vol.Required(
                    CONF_GRANULAR_SYNC_OPTIONS,
                    default=user_input.get(
                        CONF_GRANULAR_SYNC_OPTIONS,
                        fallback.get(CONF_GRANULAR_SYNC_OPTIONS, DEFAULT_GRANULAR_SYNC_OPTIONS),
                    ),
                ): selector.BooleanSelector(selector.BooleanSelectorConfig()),
            }
        )
    return schema


def _build_granular_sync_schema(
    user_input: MutableMapping[str, Any] | None,
    fallback: MutableMapping[str, Any] | None = None,
) -> vol.Schema:
    if user_input is None:
        user_input = {}
    if fallback is None:
        fallback = {}

    schema_dict: MutableMapping[Any, Any] = {}

    for conf in GRANULAR_SYNC_ITEMS:
        schema_dict[
            vol.Optional(
                conf,
                default=user_input.get(
                    conf,
                    fallback.get(conf, DEFAULT_SYNC_OPTION_VALUE),
                ),
            )
        ] = selector.BooleanSelector(selector.BooleanSelectorConfig())

    return vol.Schema(schema_dict)


def _build_options_init_schema(
    user_input: MutableMapping[str, Any] | None,
    fallback_config: MutableMapping[str, Any] | None = None,
    fallback_options: MutableMapping[str, Any] | None = None,
) -> vol.Schema:
    if user_input is None:
        user_input = {}
    if fallback_config is None:
        fallback_config = {}
    if fallback_options is None:
        fallback_options = {}

    return vol.Schema(
        {
            vol.Optional(
                CONF_SCAN_INTERVAL,
                default=user_input.get(
                    CONF_SCAN_INTERVAL,
                    fallback_options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                ),
            ): vol.All(vol.Coerce(int), vol.Clamp(min=10, max=300)),
            vol.Optional(
                CONF_DEVICE_TRACKER_ENABLED,
                default=user_input.get(
                    CONF_DEVICE_TRACKER_ENABLED,
                    fallback_options.get(
                        CONF_DEVICE_TRACKER_ENABLED, DEFAULT_DEVICE_TRACKER_ENABLED
                    ),
                ),
            ): selector.BooleanSelector(selector.BooleanSelectorConfig()),
            vol.Optional(
                CONF_DEVICE_TRACKER_SCAN_INTERVAL,
                default=user_input.get(
                    CONF_DEVICE_TRACKER_SCAN_INTERVAL,
                    fallback_options.get(
                        CONF_DEVICE_TRACKER_SCAN_INTERVAL, DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL
                    ),
                ),
            ): vol.All(vol.Coerce(int), vol.Clamp(min=30, max=300)),
            vol.Optional(
                CONF_DEVICE_TRACKER_CONSIDER_HOME,
                default=user_input.get(
                    CONF_DEVICE_TRACKER_CONSIDER_HOME,
                    fallback_options.get(
                        CONF_DEVICE_TRACKER_CONSIDER_HOME, DEFAULT_DEVICE_TRACKER_CONSIDER_HOME
                    ),
                ),
            ): vol.All(vol.Coerce(int), vol.Clamp(min=0, max=600)),
            vol.Optional(
                CONF_GRANULAR_SYNC_OPTIONS,
                default=user_input.get(
                    CONF_GRANULAR_SYNC_OPTIONS,
                    fallback_config.get(CONF_GRANULAR_SYNC_OPTIONS, DEFAULT_GRANULAR_SYNC_OPTIONS),
                ),
            ): selector.BooleanSelector(selector.BooleanSelectorConfig()),
        }
    )


async def _get_dt_entries(
    hass: HomeAssistant, config: Mapping[str, Any], selected_devices: list
) -> MutableMapping[str, Any]:
    url = config[CONF_URL].strip()
    username: str = config[CONF_USERNAME]
    password: str = config[CONF_PASSWORD]
    verify_ssl: bool = config.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL)
    client = OPNsenseClient(
        url=url,
        username=username,
        password=password,
        session=async_create_clientsession(
            hass=hass,
            raise_for_status=False,
            cookie_jar=aiohttp.CookieJar(unsafe=is_private_ip(url)),
        ),
        opts={"verify_ssl": verify_ssl},
    )
    # dicts are ordered so put all previously selected items at the top
    entries: MutableMapping[str, Any] = {}
    for device in selected_devices:
        entries[device] = device
    arp_table: list = await client.get_arp_table(resolve_hostnames=True)
    if arp_table:
        # follow with all arp table entries
        for entry in arp_table:
            mac: str = entry.get("mac", "").lower().strip()
            if len(mac) < 1:
                continue
            hostname: str = entry.get("hostname", "").strip("?").strip()
            ip: str = entry.get("ip", "").strip()
            label: str = f"{ip} {'(' + hostname + ') ' if hostname else ''}[{mac}]"
            entries[mac] = label

        # Sort entries: MAC-only labels first, then by IP address (ascending)
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
        return sorted_entries
    return entries


class OPNsenseConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for OPNsense."""

    # bumping this is what triggers async_migrate_entry for the component
    VERSION = 4

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._errors: dict[str, Any] = {}
        self._config: MutableMapping[str, Any] = {}

    # gets invoked without user input initially
    # when user submits has user_input
    async def async_step_user(
        self, user_input: MutableMapping[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        if user_input is not None:
            self._errors = await validate_input(
                hass=self.hass, user_input=user_input, errors=self._errors
            )
            if not self._errors:
                # https://developers.home-assistant.io/docs/config_entries_config_flow_handler#unique-ids
                await self.async_set_unique_id(user_input.get(CONF_DEVICE_UNIQUE_ID))
                self._abort_if_unique_id_configured()

                if user_input[CONF_GRANULAR_SYNC_OPTIONS]:
                    self._config = user_input
                    return await self.async_step_granular_sync()

                return self.async_create_entry(
                    title=user_input[CONF_NAME],
                    data=user_input,
                )

        if not user_input:
            user_input = {}
        firmware = user_input.get(CONF_FIRMWARE_VERSION, "Unknown")

        return self.async_show_form(
            step_id="user",
            data_schema=_build_user_input_schema(user_input=user_input),
            errors=self._errors,
            description_placeholders={
                "firmware": firmware,
                "min_firmware": OPNSENSE_MIN_FIRMWARE,
            },
        )

    async def async_step_granular_sync(
        self, user_input: MutableMapping[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the step for initial granular sync options."""
        if user_input is not None:
            # _LOGGER.debug("[config_flow granular_sync] raw user_input: %s", user_input)
            self._config.update(user_input)
            # _LOGGER.debug("[config_flow granular_sync] merged config: %s", self._config)
            self._errors = await validate_input(
                hass=self.hass, user_input=self._config, errors=self._errors
            )
            if not self._errors:
                return self.async_create_entry(
                    title=self._config[CONF_NAME],
                    data=self._config,
                )

        if not user_input:
            user_input = {}

        return self.async_show_form(
            step_id="granular_sync",
            data_schema=_build_granular_sync_schema(user_input=user_input),
            errors=self._errors,
        )

    async def async_step_reconfigure(
        self, user_input: MutableMapping[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Config flow reconfigure step."""
        reconfigure_entry = self._get_reconfigure_entry()
        self._config = dict(reconfigure_entry.data)

        if user_input is not None:
            # _LOGGER.debug("[config_flow reconfigure] raw user_input: %s", user_input)
            self._config.update(user_input)
            # _LOGGER.debug("[config_flow reconfigure] merged config: %s", self._config)
            self._errors = await validate_input(
                hass=self.hass, user_input=self._config, errors=self._errors
            )

            if not self._errors:
                # https://developers.home-assistant.io/docs/config_entries_config_flow_handler#unique-ids
                await self.async_set_unique_id(self._config.get(CONF_DEVICE_UNIQUE_ID))
                self._abort_if_unique_id_mismatch()

                return self.async_update_reload_and_abort(
                    entry=reconfigure_entry,
                    data=self._config,
                )

        if not user_input:
            user_input = {}
        firmware = user_input.get(CONF_FIRMWARE_VERSION, "Unknown")

        return self.async_show_form(
            step_id="reconfigure",
            data_schema=_build_user_input_schema(
                user_input=user_input, fallback=self._config, reconf=True
            ),
            errors=self._errors,
            description_placeholders={
                "firmware": firmware,
                "min_firmware": OPNSENSE_MIN_FIRMWARE,
            },
        )

    async def async_step_import(self, user_input: MutableMapping[str, Any]) -> ConfigFlowResult:
        """Handle import."""
        return await self.async_step_user(user_input)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OPNsenseOptionsFlow:
        """Get the options flow for this handler."""
        return OPNsenseOptionsFlow(config_entry)


class OPNsenseOptionsFlow(OptionsFlow):
    """Handle option flow for OPNsense."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        """Initialize options flow."""
        self._errors: dict[str, Any] = {}
        self._config: MutableMapping[str, Any] = {}
        self._options: MutableMapping[str, Any] = {}

    async def async_step_init(
        self, user_input: MutableMapping[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle options flow."""
        self._config = dict(self.config_entry.data)
        self._options = dict(self.config_entry.options)
        if user_input is not None:
            # _LOGGER.debug("[options_flow init] raw user_input: %s", user_input)
            self._options.update(user_input)
            self._config[CONF_GRANULAR_SYNC_OPTIONS] = self._options.pop(
                CONF_GRANULAR_SYNC_OPTIONS, DEFAULT_GRANULAR_SYNC_OPTIONS
            )
            # _LOGGER.debug("[options_flow init] merged user_input. config: %s. options: %s", self._config, self._options)
            if self._config.get(CONF_GRANULAR_SYNC_OPTIONS):
                return await self.async_step_granular_sync()
            for item in GRANULAR_SYNC_ITEMS:
                self._config.pop(item, None)
            if self._options.get(CONF_DEVICE_TRACKER_ENABLED):
                return await self.async_step_device_tracker()
            # _LOGGER.debug("Updating options from init. user_input: %s", self._config)

            self.hass.config_entries.async_update_entry(
                entry=self.config_entry, data=self._config, options=self._options
            )
            return self.async_create_entry(data=self._options)

        return self.async_show_form(
            step_id="init",
            data_schema=_build_options_init_schema(
                user_input=user_input, fallback_config=self._config, fallback_options=self._options
            ),
        )

    async def async_step_granular_sync(
        self, user_input: MutableMapping[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the step for granular sync options."""
        if user_input is not None:
            # _LOGGER.debug("[options_flow granular_sync] raw user_input: %s", user_input)
            self._config.update(user_input)
            # _LOGGER.debug("[options_flow granular_sync] merged user_input. config: %s. options: %s", self._config, self._options)
            self._errors = await validate_input(
                hass=self.hass, user_input=self._config, errors=self._errors
            )
            if not self._errors:
                if self._options.get(CONF_DEVICE_TRACKER_ENABLED):
                    return await self.async_step_device_tracker()
                _LOGGER.debug("Updating options from granular sync. user_input: %s", self._config)

                self.hass.config_entries.async_update_entry(
                    entry=self.config_entry, data=self._config, options=self._options
                )
                return self.async_create_entry(data=self._options)

        if not user_input:
            user_input = {}

        return self.async_show_form(
            step_id="granular_sync",
            data_schema=_build_granular_sync_schema(
                user_input=user_input,
                fallback=self._config,
            ),
            errors=self._errors,
        )

    async def async_step_device_tracker(
        self, user_input: MutableMapping[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle device tracker list step."""
        if user_input is not None:
            # _LOGGER.debug("[options_flow device_tracker] raw user_input: %s", user_input)
            self._options.update(user_input)
            # _LOGGER.debug("[options_flow device_tracker] merged user_input. config: %s. options: %s", self._config, self._options)
            macs: list = []
            manual_devices: str | None = self._options.pop(CONF_MANUAL_DEVICES, None)
            if isinstance(manual_devices, str):
                for item in manual_devices.split(","):
                    if not isinstance(item, str) or not item:
                        continue
                    item = item.strip()
                    if is_valid_mac_address(item):
                        macs.append(item)
                _LOGGER.debug("[options_flow device_tracker] Manual Devices: %s", macs)
            _LOGGER.debug("[options_flow device_tracker] Devices: %s", user_input.get(CONF_DEVICES))
            self._options[CONF_DEVICES] = user_input.get(CONF_DEVICES, []) + macs
            if not self._options.get(CONF_DEVICE_TRACKER_ENABLED):
                self._options.pop(CONF_DEVICES, None)
                self._config.pop(TRACKED_MACS, None)

            self.hass.config_entries.async_update_entry(
                entry=self.config_entry, data=self._config, options=self._options
            )
            return self.async_create_entry(data=self._options)

        selected_devices: list = self.config_entry.options.get(CONF_DEVICES, [])
        dt_entries: MutableMapping[str, Any] = await _get_dt_entries(
            hass=self.hass, config=self.config_entry.data, selected_devices=selected_devices
        )

        if not user_input:
            user_input = {}

        return self.async_show_form(
            step_id="device_tracker",
            data_schema=vol.Schema(
                {
                    vol.Optional(CONF_DEVICES, default=selected_devices): cv.multi_select(
                        dict(dt_entries)
                    ),
                    vol.Optional(CONF_MANUAL_DEVICES): selector.TextSelector(
                        selector.TextSelectorConfig()
                    ),
                }
            ),
            errors=self._errors,
        )


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
