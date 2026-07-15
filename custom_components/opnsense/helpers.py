"""Helper methods for OPNsense."""

from collections.abc import Mapping, MutableMapping
import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

import aiohttp
from aiopnsense import OPNsenseClient
from homeassistant.config_entries import ConfigEntries, ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_URL, CONF_USERNAME, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.helpers.device_registry import DeviceEntry, DeviceRegistry
from homeassistant.util import slugify

from .const import (
    CONF_DEVICE_UNIQUE_ID,
    CONF_ENTRY_TYPE,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
    ENTRY_TYPE_CARP,
    ENTRY_TYPE_DEVICE,
)


def dict_get(data: MutableMapping[str, Any], path: str, default: Any | None = None) -> Any | None:
    """Parse a dotted path to get a value from nested mapping or list data.

    Args:
        data: Mutable mapping containing the value to retrieve.
        path: Case-insensitive dotted path, including numeric list indexes.
        default: Value returned when any path segment is unavailable.

    Returns:
        Any | None: Value found at the path, or ``default`` when absent.
    """
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


def normalize_arp_mac(mac: object) -> str:
    """Normalize a MAC address from an ARP payload."""
    if not isinstance(mac, str):
        return ""
    return mac.strip().lower().replace("-", ":")


def get_arp_mac(entry: Mapping[str, Any]) -> str:
    """Return a normalized MAC address from an ARP payload."""
    mac: object = entry.get("mac")
    if not isinstance(mac, str):
        mac = entry.get("mac-address")
    return normalize_arp_mac(mac)


def get_arp_ip(entry: Mapping[str, Any]) -> str:
    """Return an IP address from an ARP payload."""
    ip: object = entry.get("ip")
    if not isinstance(ip, str):
        ip = entry.get("ip-address")
    return ip.strip() if isinstance(ip, str) else ""


def get_smart_device_name(smart_device: Mapping[str, Any]) -> str:
    """Return a SMART device identifier, preferring ``device`` over ``ident``."""
    device_name = smart_device.get("device")
    if not isinstance(device_name, str) or not device_name.strip():
        device_name = smart_device.get("ident")
    if not isinstance(device_name, str):
        return ""
    return device_name.strip()


def firewall_rule_id_from_payload(rule_key: object, rule: object) -> str | None:
    """Get a firewall rule ID from an aiopnsense rule payload."""
    if not isinstance(rule, Mapping):
        return None

    rule_id = rule.get("uuid")
    if not isinstance(rule_id, str) or not rule_id:
        rule_id = rule_key if isinstance(rule_key, str) else None
    return rule_id


def firewall_rule_switch_unique_ids_from_payload(
    device_unique_id: str,
    rules: Mapping[Any, Any],
) -> set[str]:
    """Build current firewall rule switch unique IDs from a firewall payload.

    Args:
        device_unique_id: Device unique ID prefix used by this config entry.
        rules: Firewall rule mapping returned by aiopnsense.

    Returns:
        set[str]: Unique IDs for firewall rule switches still present in the payload.
    """
    unique_ids: set[str] = set()
    for rule_key, rule in rules.items():
        if not isinstance(rule, Mapping):
            continue

        interface = rule.get("%interface", rule.get("interface", ""))
        if not isinstance(interface, str):
            continue

        rule_id = firewall_rule_id_from_payload(rule_key, rule)
        if rule_id:
            unique_ids.add(slugify(f"{device_unique_id}_firewall.rule.{rule_id}"))
    return unique_ids


def firewall_nat_switch_unique_ids_from_payload(
    device_unique_id: str,
    nat_rule_type: str,
    nat_rules: Mapping[Any, Any],
) -> set[str]:
    """Build current native NAT rule switch unique IDs from a firewall NAT payload.

    Args:
        device_unique_id: Device unique ID prefix used by this config entry.
        nat_rule_type: NAT section name such as ``source_nat`` or ``d_nat``.
        nat_rules: NAT rule mapping from a firewall payload section.

    Returns:
        set[str]: Unique IDs for NAT rule switches still present in the payload.
    """
    unique_ids: set[str] = set()
    for rule_key, rule in nat_rules.items():
        if not isinstance(rule, Mapping):
            continue

        rule_id = firewall_rule_id_from_payload(rule_key, rule)
        if not rule_id:
            continue
        unique_ids.add(slugify(f"{device_unique_id}_firewall.nat.{nat_rule_type}.{rule_id}"))
    return unique_ids


def is_private_ip(url: str) -> bool:
    """Check whether the host address in a URL is private.

    Args:
        url: URL whose hostname should be inspected.

    Returns:
        bool: ``True`` when the URL hostname is a private IP address.
    """
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


def find_replacement_router_device_id(
    shared_config_entry_id: str,
    shared_device_entry: DeviceEntry,
    config_entries: ConfigEntries,
    device_registry: DeviceRegistry,
) -> str | None:
    """Find a replacement OPNsense router device id for a shared tracked device.

    Args:
        shared_config_entry_id: The config entry currently being detached.
        shared_device_entry: Device registry entry shared by multiple integrations.
        config_entries: HA config-entry registry object.
        device_registry: HA device registry for router lookup by identifier.

    Returns:
        str | None: Replacement router ``device_id`` if a surviving OPNsense entry
            can be resolved, otherwise ``None``.
    """
    remaining_config_entries = sorted(shared_device_entry.config_entries)
    for owner_entry_id in remaining_config_entries:
        if owner_entry_id == shared_config_entry_id:
            continue
        owner_entry = config_entries.async_get_entry(owner_entry_id)
        if owner_entry is None or owner_entry.domain != DOMAIN:
            continue
        owner_device_unique_id = owner_entry.data.get(CONF_DEVICE_UNIQUE_ID)
        if not isinstance(owner_device_unique_id, str):
            continue
        owner_router = device_registry.async_get_device(
            identifiers={(DOMAIN, owner_device_unique_id)}
        )
        if owner_router is not None:
            return owner_router.id
    return None


def detach_shared_router_parent(
    *,
    shared_config_entry_id: str,
    shared_device_entry: DeviceEntry,
    router_device_id: str | None,
    config_entries: ConfigEntries,
    device_registry: DeviceRegistry,
) -> tuple[bool, str | None]:
    """Detach a shared tracker device from a removed router config entry.

    Args:
        shared_config_entry_id: The config entry being detached from the shared device.
        shared_device_entry: Shared device entry associated with one or more OPNsense
            integrations.
        router_device_id: The current router device ID for the detaching integration.
        config_entries: HA config-entry registry used for surviving router lookup.
        device_registry: HA device registry used for updating tracker relationships.

    Returns:
        tuple[bool, str | None]: ``True`` when device was parented through the
        current router, with optional replacement router id for reparenting.
    """
    is_device_from_router: bool = (
        shared_device_entry.via_device_id is not None
        and router_device_id is not None
        and shared_device_entry.via_device_id == router_device_id
    )
    replacement_router_id: str | None = None
    if is_device_from_router:
        replacement_router_id = find_replacement_router_device_id(
            shared_config_entry_id=shared_config_entry_id,
            shared_device_entry=shared_device_entry,
            config_entries=config_entries,
            device_registry=device_registry,
        )

    if replacement_router_id is not None:
        device_registry.async_update_device(
            shared_device_entry.id,
            remove_config_entry_id=shared_config_entry_id,
            via_device_id=replacement_router_id,
        )
        return is_device_from_router, replacement_router_id

    if is_device_from_router:
        device_registry.async_update_device(
            shared_device_entry.id,
            remove_config_entry_id=shared_config_entry_id,
            via_device_id=None,
        )
        return is_device_from_router, None

    device_registry.async_update_device(
        shared_device_entry.id,
        remove_config_entry_id=shared_config_entry_id,
    )
    return is_device_from_router, None


def is_carp_entry(config_entry: ConfigEntry) -> bool:
    """Return whether a config entry represents a CARP virtual endpoint.

    Args:
        config_entry: Config entry to classify.

    Returns:
        bool: ``True`` when the entry type is CARP.
    """
    return config_entry.data.get(CONF_ENTRY_TYPE, ENTRY_TYPE_DEVICE) == ENTRY_TYPE_CARP


def config_entry_identity(config_entry: ConfigEntry) -> str:
    """Return the stable Home Assistant identity prefix for a config entry.

    Args:
        config_entry: Config entry whose device or entry identity is needed.

    Returns:
        str: Device unique ID for normal entries, otherwise the entry ID.
    """
    device_id = config_entry.data.get(CONF_DEVICE_UNIQUE_ID)
    return device_id if isinstance(device_id, str) and device_id else config_entry.entry_id


def is_usable_carp_vip(value: object) -> bool:
    """Return whether a CARP row has a usable VHID and subnet identity.

    Args:
        value: Raw CARP VIP row returned by the OPNsense API.

    Returns:
        bool: ``True`` when normalized VHID and subnet values are non-empty.
    """
    if not isinstance(value, Mapping):
        return False

    vhid = value.get("vhid")
    if isinstance(vhid, bool) or not isinstance(vhid, (int, str)):
        return False
    normalized_vhid = str(vhid).strip()
    subnet = value.get("subnet")
    normalized_subnet = subnet.strip() if isinstance(subnet, str) else ""
    return bool(normalized_vhid and normalized_subnet)


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
