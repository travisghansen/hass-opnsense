"""Helper methods for OPNsense."""

from collections.abc import MutableMapping
import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

import aiohttp
from aiopnsense import OPNsenseClient
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_URL, CONF_USERNAME, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_create_clientsession

from .const import DEFAULT_VERIFY_SSL


def dict_get(data: MutableMapping[str, Any], path: str, default: Any | None = None) -> Any | None:
    """Parse the path to get the desired value out of the data."""
    path_list: list = re.split(r"\.", path, flags=re.IGNORECASE)
    result: Any | None = data

    for key in path_list:
        if key.isnumeric():
            key = int(key)
        if isinstance(result, MutableMapping | list) and key in result:
            result = result[key]
        else:
            result = default
            break

    return result


def is_private_ip(url: str) -> bool:
    """Check if the address in the given URL is a private IP address."""
    parsed_url = urlparse(url)
    addr = parsed_url.hostname
    if not addr:
        return False

    try:
        ip_obj = ipaddress.ip_address(addr)
    except ValueError:
        return False
    else:
        return ip_obj.is_private


def create_opnsense_client(
    *,
    hass: HomeAssistant,
    url: str,
    username: str,
    password: str,
    verify_ssl: bool | None,
    throw_errors: bool = False,
    name: str | None = None,
) -> OPNsenseClient:
    """Create an OPNsense client with Home Assistant session settings.

    Args:
        hass: Home Assistant instance used to create the aiohttp session.
        url: OPNsense base URL.
        username: OPNsense API username.
        password: OPNsense API password.
        verify_ssl: Whether the client should verify TLS certificates.
        throw_errors: Whether aiopnsense should propagate request/decorator errors.
        name: Optional client display name used for logging and diagnostics.

    Returns:
        OPNsenseClient: Configured aiopnsense client.
    """
    client_kwargs: dict[str, Any] = {}
    if name is not None:
        client_kwargs["name"] = name

    return OPNsenseClient(
        url=url,
        username=username,
        password=password,
        session=async_create_clientsession(
            hass=hass,
            raise_for_status=False,
            cookie_jar=aiohttp.CookieJar(unsafe=is_private_ip(url)),
        ),
        opts={"verify_ssl": verify_ssl},
        throw_errors=throw_errors,
        **client_kwargs,
    )


def create_opnsense_client_from_config_entry(
    *,
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    throw_errors: bool = False,
) -> OPNsenseClient:
    """Create an OPNsense client from a Home Assistant config entry.

    Args:
        hass: Home Assistant instance used to create the aiohttp session.
        config_entry: Config entry containing the OPNsense connection settings.
        throw_errors: Whether aiopnsense should propagate request/decorator errors.

    Returns:
        OPNsenseClient: Configured aiopnsense client.
    """
    return create_opnsense_client(
        hass=hass,
        url=config_entry.data[CONF_URL],
        username=config_entry.data[CONF_USERNAME],
        password=config_entry.data[CONF_PASSWORD],
        verify_ssl=config_entry.data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
        throw_errors=throw_errors,
        name=config_entry.title,
    )


def coerce_bool(value: Any) -> bool | None:
    """Normalize values that may represent booleans.

    Args:
        value: Arbitrary state value returned by backend APIs.

    Returns:
        bool | None: Parsed boolean interpretation for common numeric/string variants.
            Returns ``None`` when the value is missing or not bool-like.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return value != 0
    if isinstance(value, str):
        normalized_value = value.strip().lower()
        if normalized_value in {"1", "true", "yes", "on"}:
            return True
        if normalized_value in {"0", "false", "no", "off"}:
            return False
    return None
