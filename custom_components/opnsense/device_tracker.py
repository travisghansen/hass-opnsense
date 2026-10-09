"""Support for tracking for OPNsense devices."""

from collections.abc import Mapping, MutableMapping
import contextlib
from datetime import datetime, timedelta, timezone
import ipaddress
import logging
from typing import Any

from homeassistant.components.device_tracker import ScannerEntity, SourceType
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.device_registry import (
    CONNECTION_NETWORK_MAC,
    DeviceRegistry,
    async_get as async_get_dev_reg,
)
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity
from homeassistant.util import slugify

from .config_flow import normalize_mac_address
from .const import (
    CONF_DEVICE_TRACKER_CONSIDER_HOME,
    CONF_DEVICE_TRACKER_ENABLED,
    CONF_DEVICE_UNIQUE_ID,
    CONF_DEVICES,
    DEFAULT_DEVICE_TRACKER_CONSIDER_HOME,
    DEFAULT_DEVICE_TRACKER_ENABLED,
    DEVICE_TRACKER_COORDINATOR,
    DOMAIN,
    SHOULD_RELOAD,
    TRACKED_ARP_MACS,
    TRACKED_MACS,
    TRACKED_NDP_MACS,
)
from .coordinator import OPNsenseDataUpdateCoordinator
from .entity import OPNsenseBaseEntity
from .helpers import (
    async_get_device_by_connection,
    async_get_device_by_identifier,
    async_get_devices_by_connection,
    detach_shared_router_parent,
    dict_get,
    get_arp_ip,
    get_arp_mac,
    normalize_arp_mac,
)
from .repair_reconciliation import is_reconciliation_active, record_desired_entities

_LOGGER: logging.Logger = logging.getLogger(__name__)


def _normalize_mac_for_device_tracker(mac_address: str) -> str:
    """Normalize a user-facing or payload MAC with canonical fallback.

    Args:
        mac_address (str): A raw MAC-like input.

    Returns:
        str: Canonical MAC when possible, otherwise permissive lower-case normalized value.
    """
    normalized_mac = normalize_mac_address(mac_address)
    if normalized_mac is not None:
        return normalized_mac
    return normalize_arp_mac(mac_address)


def _device_data_from_arp_entry(
    mac_address: str,
    arp_entry: MutableMapping[str, Any],
) -> dict[str, Any]:
    """Build tracked device data from an ARP table entry.

    Args:
        mac_address (str): MAC address used as the tracked-device identity.
        arp_entry (MutableMapping[str, Any]): ARP entry containing optional metadata.

    Returns:
        dict[str, Any]: A device dictionary populated with the MAC address and metadata.
    """
    device: dict[str, Any] = {"mac": mac_address}

    hostname = _hostname_from_arp_entry(arp_entry)
    if hostname is not None:
        device["hostname"] = hostname

    manufacturer = arp_entry.get("manufacturer")
    if isinstance(manufacturer, str) and manufacturer:
        device["manufacturer"] = manufacturer

    return device


def _device_data_from_ndp_entry(
    mac_address: str,
    ndp_entry: MutableMapping[str, Any],
) -> dict[str, Any]:
    """Build tracked-device metadata from an NDP table entry.

    Args:
        mac_address (str): Canonical MAC address used as the tracked-device identity.
        ndp_entry (MutableMapping[str, Any]): NDP entry containing optional vendor metadata.

    Returns:
        dict[str, Any]: A device dictionary populated with the MAC address and metadata.
    """
    device: dict[str, Any] = {"mac": mac_address}
    manufacturer = ndp_entry.get("manufacturer")
    if isinstance(manufacturer, str) and manufacturer:
        device["manufacturer"] = manufacturer
    return device


def _device_from_tracker_entries(
    mac_address: str,
    arp_entries: list[Any],
    ndp_entries: list[Any],
) -> dict[str, Any]:
    """Build configured tracker metadata from matching ARP and NDP rows.

    Args:
        mac_address (str): Configured MAC address for the tracker entity.
        arp_entries (list[Any]): Raw ARP entries returned by OPNsense.
        ndp_entries (list[Any]): Raw NDP entries returned by OPNsense.

    Returns:
        dict[str, Any]: Device metadata from either table, or a MAC-only fallback.
    """
    device: dict[str, Any] = {"mac": mac_address}
    normalized_mac = _normalize_mac_for_device_tracker(mac_address)
    for arp_entry in arp_entries:
        if not isinstance(arp_entry, MutableMapping):
            continue
        arp_mac = get_arp_mac(arp_entry)
        if not arp_mac or _normalize_mac_for_device_tracker(arp_mac) != normalized_mac:
            continue
        device.update(_device_data_from_arp_entry(mac_address, arp_entry))
        break

    for ndp_entry in ndp_entries:
        if not isinstance(ndp_entry, MutableMapping):
            continue
        ndp_mac = get_arp_mac(ndp_entry)
        normalized_ndp_mac = normalize_mac_address(ndp_mac)
        if (
            normalized_ndp_mac != normalized_mac
            or _normalized_ip_address(get_arp_ip(ndp_entry), version=6) is None
        ):
            continue
        ndp_device = _device_data_from_ndp_entry(mac_address, ndp_entry)
        if "manufacturer" not in device and "manufacturer" in ndp_device:
            device["manufacturer"] = ndp_device["manufacturer"]
        break
    return device


def _devices_from_tracker_entries(
    arp_entries: list[Any],
    ndp_entries: list[Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Build tracked-device data from unique MAC addresses in either neighbor table.

    Args:
        arp_entries (list[Any]): Raw ARP entries returned by OPNsense.
        ndp_entries (list[Any]): Raw NDP entries returned by OPNsense.

    Returns:
        tuple[list[dict[str, Any]], list[str]]: Devices and their canonical MAC addresses, with
            dual-stack rows merged into one device.
    """
    devices_by_mac: dict[str, dict[str, Any]] = {}
    for table_entries, is_ndp in ((arp_entries, False), (ndp_entries, True)):
        for entry in table_entries:
            if not isinstance(entry, MutableMapping):
                continue
            raw_mac = get_arp_mac(entry)
            if not raw_mac:
                continue
            normalized_mac = (
                normalize_mac_address(raw_mac)
                if is_ndp
                else _normalize_mac_for_device_tracker(raw_mac)
            )
            if not normalized_mac or (
                is_ndp and _normalized_ip_address(get_arp_ip(entry), version=6) is None
            ):
                continue
            device = devices_by_mac.setdefault(normalized_mac, {"mac": normalized_mac})
            entry_device = (
                _device_data_from_ndp_entry(normalized_mac, entry)
                if is_ndp
                else _device_data_from_arp_entry(normalized_mac, entry)
            )
            for key in ("hostname", "manufacturer"):
                if key not in device and key in entry_device:
                    device[key] = entry_device[key]
    devices = list(devices_by_mac.values())
    return devices, list(devices_by_mac)


def _mac_addresses_from_table_entries(entries: list[Any], *, ndp: bool) -> list[str]:
    """Return unique normalized MAC addresses from one neighbor table.

    Args:
        entries (list[Any]): Neighbor rows returned by OPNsense.
        ndp (bool): Whether to require complete MAC addresses from NDP rows.

    Returns:
        list[str]: MAC addresses in table order.
    """
    arp_entries = [] if ndp else entries
    ndp_entries = entries if ndp else []
    _devices, mac_addresses = _devices_from_tracker_entries(arp_entries, ndp_entries)
    return mac_addresses


def _track_all_table_entries_are_complete(entries: object, *, ndp: bool) -> bool:
    """Return whether a neighbor-table response can safely reconcile track-all devices.

    Args:
        entries (object): Raw ARP or NDP response to validate.
        ndp (bool): Whether the response is an NDP table, whose MACs must be complete.

    Returns:
        bool: Whether the response is a usable authoritative list.
    """
    if not isinstance(entries, list):
        return False
    for entry in entries:
        if not isinstance(entry, MutableMapping):
            return False
        if not ndp:
            continue
        mac_address = get_arp_mac(entry)
        if not mac_address or normalize_mac_address(mac_address) is None:
            return False
        if _normalized_ip_address(get_arp_ip(entry), version=6) is None:
            return False
    return True


def _has_configured_macs(config_entry: ConfigEntry) -> bool:
    """Return whether the options pin at least one non-blank tracker MAC.

    Args:
        config_entry (ConfigEntry): Config entry whose options hold the configured MACs.

    Returns:
        bool: ``True`` when at least one configured MAC is a non-blank string.
    """
    configured_macs = config_entry.options.get(CONF_DEVICES, [])
    return bool(
        isinstance(configured_macs, list)
        and any(
            isinstance(mac_address, str) and mac_address.strip() for mac_address in configured_macs
        )
    )


def _unavailable_device_tracker_tables(state: Mapping[str, Any]) -> list[str]:
    """Return the neighbor-table keys the coordinator reported as failed this poll.

    Args:
        state (Mapping[str, Any]): Latest coordinator state.

    Returns:
        list[str]: Failed table keys, or an empty list when the state carries none.
    """
    unavailable_tables = state.get("unavailable_device_tracker_tables", [])
    return unavailable_tables if isinstance(unavailable_tables, list) else []


def _hostname_from_arp_entry(entry: MutableMapping[str, Any]) -> str | None:
    """Return the normalized hostname from an ARP entry.

    Args:
        entry (MutableMapping[str, Any]): ARP entry to normalize.

    Returns:
        str | None: The stripped hostname, or ``None`` when no usable hostname exists.
    """
    hostname = entry.get("hostname")
    if not isinstance(hostname, str):
        return None
    hostname = hostname.strip("?")
    return hostname or None


def _arp_expires_attribute(value: object) -> str | datetime | None:
    """Return the Home Assistant attribute value for an ARP expiry.

    Args:
        value (object): Raw expiry value from OPNsense.

    Returns:
        str | datetime | None: ``"Never"`` for permanent entries, a datetime for relative
            expiry, or ``None``.
    """
    if value == -1:
        return "Never"
    if isinstance(value, int | float):
        return datetime.now().astimezone() + timedelta(seconds=value)
    return None


def _normalized_ip_address(value: object, *, version: int) -> str | None:
    """Return a canonical address when the input matches the requested IP version.

    Args:
        value (object): Raw address from a neighbor-table row.
        version (int): Expected IP version, either 4 or 6.

    Returns:
        str | None: Compressed IP address, or ``None`` for invalid or wrong-family input.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if address.version != version:
        return None
    return address.compressed


def _addresses_from_entries(entries: list[MutableMapping[str, Any]], *, version: int) -> list[str]:
    """Return unique canonical IP addresses from neighbor-table rows.

    Args:
        entries (list[MutableMapping[str, Any]]): Neighbor rows for one tracked MAC.
        version (int): Expected IP version, either 4 or 6.

    Returns:
        list[str]: Unique compressed addresses in table order.
    """
    addresses: list[str] = []
    for entry in entries:
        address = _normalized_ip_address(get_arp_ip(entry), version=version)
        if address and address not in addresses:
            addresses.append(address)
    return addresses


def _entries_for_mac(
    entries: list[Any],
    mac_address: str,
    *,
    require_valid_mac: bool = False,
) -> list[MutableMapping[str, Any]]:
    """Return neighbor rows matching a tracker MAC.

    Args:
        entries (list[Any]): Neighbor rows returned by OPNsense.
        mac_address (str): Tracker MAC address.
        require_valid_mac (bool): Whether to reject rows with incomplete MAC addresses.

    Returns:
        list[MutableMapping[str, Any]]: Matching usable rows.
    """
    normalized_tracker_mac = _normalize_mac_for_device_tracker(mac_address)
    matching_entries: list[MutableMapping[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, MutableMapping):
            continue
        raw_mac = get_arp_mac(entry)
        if require_valid_mac:
            normalized_entry_mac = normalize_mac_address(raw_mac)
            if _normalized_ip_address(get_arp_ip(entry), version=6) is None:
                continue
        else:
            normalized_entry_mac = _normalize_mac_for_device_tracker(raw_mac)
        if normalized_entry_mac == normalized_tracker_mac:
            matching_entries.append(entry)
    return matching_entries


def _update_arp_extra_state_attributes(
    attributes: dict[str, Any],
    entry: MutableMapping[str, Any],
) -> None:
    """Update optional ARP extra state attributes from a coordinator entry.

    Args:
        attributes (dict[str, Any]): Entity attributes to mutate in place.
        entry (MutableMapping[str, Any]): ARP entry providing optional metadata.
    """
    for attr in ("interface", "expires", "type"):
        attributes.pop(attr, None)

    interface = entry.get("intf_description", entry.get("intf"))
    if interface:
        attributes["interface"] = interface

    expires = _arp_expires_attribute(entry.get("expires"))
    if expires is not None:
        attributes["expires"] = expires

    arp_type = entry.get("type")
    if arp_type:
        attributes["type"] = arp_type


def _compile_tracked_devices(
    config_entry: ConfigEntry,
    arp_entries: list[Any],
    ndp_entries: list[Any] | None = None,
) -> tuple[list[dict[str, Any]], list[str], bool]:
    """Compile device tracker source data from options and ARP entries.

    Args:
        config_entry (ConfigEntry): Config entry containing device-tracker options.
        arp_entries (list[Any]): Raw ARP entries returned by OPNsense.
        ndp_entries (list[Any] | None): Raw NDP entries returned by OPNsense.

    Returns:
        tuple[list[dict[str, Any]], list[str], bool]: A tuple of devices, MAC addresses, and
            the default enabled flag.
    """
    if not config_entry.options.get(CONF_DEVICE_TRACKER_ENABLED, DEFAULT_DEVICE_TRACKER_ENABLED):
        return [], [], False

    configured_mac_addresses: list[str] = []
    for mac_address in config_entry.options.get(CONF_DEVICES, []):
        if not isinstance(mac_address, str):
            continue
        normalized_mac = _normalize_mac_for_device_tracker(mac_address)
        if not normalized_mac or normalized_mac in configured_mac_addresses:
            continue
        configured_mac_addresses.append(normalized_mac)

    if configured_mac_addresses:
        _LOGGER.debug(
            "[device_tracker async_setup_entry] configured_mac_addresses: %s",
            configured_mac_addresses,
        )
        devices = [
            _device_from_tracker_entries(mac_address, arp_entries, ndp_entries or [])
            for mac_address in configured_mac_addresses
        ]
        return devices, list(configured_mac_addresses), True

    devices, mac_addresses = _devices_from_tracker_entries(arp_entries, ndp_entries or [])
    return devices, mac_addresses, False


def _normalize_mac_inventory(value: object, *, ndp: bool) -> list[str]:
    """Normalize a stored family inventory, keeping only unique usable MAC addresses.

    Args:
        value (object): Stored MAC inventory from config-entry data.
        ndp (bool): Whether this is an NDP inventory requiring complete MAC addresses.

    Returns:
        list[str]: Normalized MAC addresses in their stored order.
    """
    if not isinstance(value, list):
        return []
    normalized_macs: list[str] = []
    for mac_address in value:
        if not isinstance(mac_address, str):
            continue
        normalized_mac = (
            normalize_mac_address(mac_address)
            if ndp
            else _normalize_mac_for_device_tracker(mac_address)
        )
        if normalized_mac and normalized_mac not in normalized_macs:
            normalized_macs.append(normalized_mac)
    return normalized_macs


def _update_track_all_source_inventory(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    state: object,
) -> None:
    """Update family provenance for already tracked MACs from complete table results.

    Failed or malformed family tables retain their last persisted inventory. Successful table
    results replace that family's membership, intersected with the existing tracked-MAC union,
    so coordinator polling never discovers new entities.

    Args:
        hass (HomeAssistant): Home Assistant runtime used to persist config-entry data.
        config_entry (ConfigEntry): Config entry owning the tracked devices.
        state (object): Latest coordinator state containing ARP and NDP table results.
    """
    if not isinstance(state, MutableMapping):
        return
    options = config_entry.options
    has_configured_macs = _has_configured_macs(config_entry)
    if not options.get(CONF_DEVICE_TRACKER_ENABLED, DEFAULT_DEVICE_TRACKER_ENABLED) or (
        has_configured_macs
    ):
        return

    tracked_macs = _normalize_mac_inventory(config_entry.data.get(TRACKED_MACS), ndp=False)
    if not tracked_macs:
        return

    arp_entries = state.get("arp_table")
    ndp_entries = state.get("ndp_table")
    failed_tables = _unavailable_device_tracker_tables(state)
    arp_authoritative = (
        isinstance(arp_entries, list)
        and "arp_table" not in failed_tables
        and _track_all_table_entries_are_complete(arp_entries, ndp=False)
    )
    ndp_authoritative = (
        isinstance(ndp_entries, list)
        and "ndp_table" not in failed_tables
        and _track_all_table_entries_are_complete(ndp_entries, ndp=True)
    )
    if not arp_authoritative and not ndp_authoritative:
        return

    stored_arp_macs = config_entry.data.get(TRACKED_ARP_MACS, tracked_macs)
    stored_ndp_macs = config_entry.data.get(TRACKED_NDP_MACS, [])
    previous_arp_macs = set(_normalize_mac_inventory(stored_arp_macs, ndp=False))
    previous_ndp_macs = set(_normalize_mac_inventory(stored_ndp_macs, ndp=True))
    current_arp_macs = set(
        _mac_addresses_from_table_entries(arp_entries, ndp=False)
        if isinstance(arp_entries, list)
        else []
    )
    current_ndp_macs = set(
        _mac_addresses_from_table_entries(ndp_entries, ndp=True)
        if isinstance(ndp_entries, list)
        else []
    )
    updated_arp_macs = [
        mac_address
        for mac_address in tracked_macs
        if mac_address in (current_arp_macs if arp_authoritative else previous_arp_macs)
    ]
    updated_ndp_macs = [
        mac_address
        for mac_address in tracked_macs
        if mac_address in (current_ndp_macs if ndp_authoritative else previous_ndp_macs)
    ]
    if (
        config_entry.data.get(TRACKED_ARP_MACS) == updated_arp_macs
        and config_entry.data.get(TRACKED_NDP_MACS) == updated_ndp_macs
    ):
        return

    setattr(config_entry.runtime_data, SHOULD_RELOAD, False)
    updated_data = config_entry.data.copy()
    updated_data[TRACKED_ARP_MACS] = updated_arp_macs
    updated_data[TRACKED_NDP_MACS] = updated_ndp_macs
    hass.config_entries.async_update_entry(config_entry, data=updated_data)


def _register_track_all_source_inventory_listener(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
) -> None:
    """Register an unload-scoped listener to persist existing devices' source provenance.

    Args:
        hass (HomeAssistant): Home Assistant runtime used to persist config-entry data.
        config_entry (ConfigEntry): Config entry owning the tracked devices.
        coordinator (OPNsenseDataUpdateCoordinator): Coordinator providing neighbor-table state.
    """

    @callback
    def update_track_all_source_inventory() -> None:
        """Refresh family provenance from the latest coordinator poll."""
        _update_track_all_source_inventory(hass, config_entry, coordinator.data)

    config_entry.async_on_unload(coordinator.async_add_listener(update_track_all_source_inventory))


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up device tracker entities for the OPNsense component.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        config_entry (ConfigEntry): Config entry being set up.
        async_add_entities (AddEntitiesCallback): Callback used to register new entities.
    """
    dev_reg = async_get_dev_reg(hass)

    previous_mac_addresses: list = config_entry.data.get(TRACKED_MACS, [])
    coordinator: OPNsenseDataUpdateCoordinator = getattr(
        config_entry.runtime_data, DEVICE_TRACKER_COORDINATOR
    )
    state: dict[str, Any] = coordinator.data
    if not isinstance(state, MutableMapping):
        _LOGGER.error("Missing state data in device tracker async_setup_entry")
        return
    reconciliation_complete = True
    entities: list = []

    arp_entries = dict_get(state, "arp_table")
    ndp_entries = dict_get(state, "ndp_table", [])
    has_configured_macs = _has_configured_macs(config_entry)
    table_response_available = isinstance(state.get("arp_table"), list) or isinstance(
        state.get("ndp_table"), list
    )
    if not has_configured_macs:
        reconciliation_complete = table_response_available
    arp_table_unavailable = not isinstance(arp_entries, list)
    ndp_table_unavailable = "ndp_table" not in state or not isinstance(ndp_entries, list)
    unavailable_tables = _unavailable_device_tracker_tables(state)
    arp_table_unavailable = arp_table_unavailable or "arp_table" in unavailable_tables
    ndp_table_unavailable = ndp_table_unavailable or "ndp_table" in unavailable_tables
    if not isinstance(arp_entries, list):
        arp_entries = []
    if not isinstance(ndp_entries, list):
        ndp_entries = []
    devices, mac_addresses, enabled_default = _compile_tracked_devices(
        config_entry, arp_entries, ndp_entries
    )
    track_all_enabled = bool(
        config_entry.options.get(CONF_DEVICE_TRACKER_ENABLED, DEFAULT_DEVICE_TRACKER_ENABLED)
        and not has_configured_macs
    )
    if track_all_enabled:
        # Before NDP tracking was added, every persisted auto-discovered MAC came from ARP. Treat
        # that legacy union as ARP provenance until the new per-family lists are recorded.
        stored_arp_macs = config_entry.data.get(TRACKED_ARP_MACS, previous_mac_addresses)
        stored_ndp_macs = config_entry.data.get(TRACKED_NDP_MACS, [])
        if not isinstance(stored_arp_macs, list):
            stored_arp_macs = (
                previous_mac_addresses if isinstance(previous_mac_addresses, list) else []
            )
        previous_arp_macs = _normalize_mac_inventory(stored_arp_macs, ndp=False)
        previous_ndp_macs = _normalize_mac_inventory(stored_ndp_macs, ndp=True)
        current_arp_macs = _mac_addresses_from_table_entries(arp_entries, ndp=False)
        current_ndp_macs = _mac_addresses_from_table_entries(ndp_entries, ndp=True)
        arp_rows_complete = _track_all_table_entries_are_complete(arp_entries, ndp=False)
        ndp_rows_complete = _track_all_table_entries_are_complete(ndp_entries, ndp=True)
        arp_authoritative = not arp_table_unavailable and arp_rows_complete
        ndp_authoritative = not ndp_table_unavailable and ndp_rows_complete
        tracked_arp_macs = list(
            dict.fromkeys(current_arp_macs + ([] if arp_authoritative else previous_arp_macs))
        )
        tracked_ndp_macs = list(
            dict.fromkeys(current_ndp_macs + ([] if ndp_authoritative else previous_ndp_macs))
        )
        mac_addresses = list(dict.fromkeys(tracked_arp_macs + tracked_ndp_macs))
        existing_macs = {device.get("mac") for device in devices}
        for mac_address in mac_addresses:
            if mac_address not in existing_macs:
                devices.append(_device_from_tracker_entries(mac_address, arp_entries, ndp_entries))
        # Per-family persisted inventories make a partial failure safe to reconcile: a failed
        # table keeps its previous MACs while a successful table can still remove stale devices.
        reconciliation_complete = (
            (arp_table_unavailable or arp_rows_complete)
            and (ndp_table_unavailable or ndp_rows_complete)
            and table_response_available
        )
    else:
        tracked_arp_macs = []
        tracked_ndp_macs = []

    router_device_id: str | None = None
    if devices and getattr(dev_reg, "async_get_device_by_identifier", None) is not None:
        router_device = dev_reg.async_get_or_create(
            config_entry_id=config_entry.entry_id,
            identifiers={(DOMAIN, config_entry.data[CONF_DEVICE_UNIQUE_ID])},
        )
        router_device_id = router_device.id

    for device in devices:
        mac = device.get("mac")
        if not isinstance(mac, str):
            continue
        entity = OPNsenseScannerEntity(
            config_entry=config_entry,
            coordinator=coordinator,
            enabled_default=enabled_default,
            mac=mac,
            mac_vendor=device.get("manufacturer", None),
            hostname=device.get("hostname", None),
            router_device_id=router_device_id,
        )
        entities.append(entity)
    if not is_reconciliation_active(config_entry) and (
        not track_all_enabled or arp_authoritative or ndp_authoritative
    ):
        _cleanup_stale_tracked_devices(
            hass=hass,
            config_entry=config_entry,
            device_registry=dev_reg,
            previous_mac_addresses=previous_mac_addresses,
            current_mac_addresses=mac_addresses,
        )

    source_data_changed = (
        table_response_available
        and (
            config_entry.data.get(TRACKED_ARP_MACS) != tracked_arp_macs
            or config_entry.data.get(TRACKED_NDP_MACS) != tracked_ndp_macs
        )
        if track_all_enabled
        else TRACKED_ARP_MACS in config_entry.data or TRACKED_NDP_MACS in config_entry.data
    )
    if set(mac_addresses) != set(previous_mac_addresses) or source_data_changed:
        new_data = config_entry.data.copy()
        new_data[TRACKED_MACS] = mac_addresses.copy()
        if track_all_enabled:
            new_data[TRACKED_ARP_MACS] = tracked_arp_macs.copy()
            new_data[TRACKED_NDP_MACS] = tracked_ndp_macs.copy()
        else:
            new_data.pop(TRACKED_ARP_MACS, None)
            new_data.pop(TRACKED_NDP_MACS, None)
        hass.config_entries.async_update_entry(config_entry, data=new_data)

    if track_all_enabled:
        _register_track_all_source_inventory_listener(hass, config_entry, coordinator)

    _LOGGER.debug("[device_tracker async_setup_entry] entities: %s", len(entities))
    record_desired_entities(
        config_entry, "device_tracker", entities if reconciliation_complete else None
    )
    async_add_entities(entities)


def _cleanup_stale_tracked_devices(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    device_registry: DeviceRegistry,
    previous_mac_addresses: list[Any],
    current_mac_addresses: list[str],
) -> None:
    """Remove stale tracker entities and reparent shared tracker devices.

    Args:
        hass (HomeAssistant): Home Assistant runtime object.
        config_entry (ConfigEntry): Active integration config entry for this setup run.
        device_registry (DeviceRegistry): Device registry used to query and mutate tracked devices.
        previous_mac_addresses (list[Any]): Previously persisted MAC addresses from config entry
            data.
        current_mac_addresses (list[str]): MAC addresses currently discovered during setup.
    """
    stale_mac_addresses = set(previous_mac_addresses) - set(current_mac_addresses)
    if not stale_mac_addresses:
        return

    entity_registry = er.async_get(hass)
    router_device = async_get_device_by_identifier(
        device_registry,
        (DOMAIN, config_entry.data[CONF_DEVICE_UNIQUE_ID]),
        config_entry.entry_id,
    )
    router_device_id = router_device.id if router_device else None

    for mac_address in stale_mac_addresses:
        rem_device = async_get_device_by_connection(
            device_registry,
            (CONNECTION_NETWORK_MAC, mac_address),
            config_entry.entry_id,
        )
        expected_unique_id = slugify(
            f"{config_entry.data[CONF_DEVICE_UNIQUE_ID]}_mac_{mac_address}"
        )
        if entity_id := entity_registry.async_get_entity_id(
            Platform.DEVICE_TRACKER, DOMAIN, expected_unique_id
        ):
            _LOGGER.debug(
                "[device_tracker async_setup_entry] removing tracker entity_id %s for stale MAC %s",
                entity_id,
                mac_address,
            )
            entity_registry.async_remove(entity_id)

        if rem_device:
            effective_router_device_id: str | None = router_device_id
            if (
                effective_router_device_id is None
                and isinstance(rem_device.via_device_id, str)
                and device_registry.async_get(rem_device.via_device_id) is None
            ):
                effective_router_device_id = rem_device.via_device_id
            _from_current_router, replacement_router_id = detach_shared_router_parent(
                shared_config_entry_id=config_entry.entry_id,
                shared_device_entry=rem_device,
                router_device_id=effective_router_device_id,
                config_entries=hass.config_entries,
                device_registry=device_registry,
            )
            if replacement_router_id is not None:
                _LOGGER.debug(
                    "[device_tracker async_setup_entry] reparenting shared tracker "
                    "device %s from %s to %s",
                    rem_device.id,
                    router_device_id,
                    replacement_router_id,
                )


class OPNsenseScannerEntity(OPNsenseBaseEntity, ScannerEntity, RestoreEntity):
    """Represent a scanned device."""

    def __init__(
        self,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        enabled_default: bool,
        mac: str,
        mac_vendor: str | None,
        hostname: str | None,
        router_device_id: str | None = None,
    ) -> None:
        """Set up the OPNsense scanner entity.

        Args:
            config_entry (ConfigEntry): Config entry owning the entity.
            coordinator (OPNsenseDataUpdateCoordinator): Shared OPNsense data coordinator.
            enabled_default (bool): Whether the entity is enabled by default.
            mac (str): MAC address tracked by the entity.
            mac_vendor (str | None): Vendor name reported for the MAC address.
            hostname (str | None): Hostname reported by OPNsense.
            router_device_id (str | None): Registry id of the parent router on HA 2026.8+.
        """
        super().__init__(config_entry, coordinator, unique_id_suffix=f"mac_{mac}")
        self._mac_vendor: str | None = mac_vendor
        self._attr_name: str | None = None
        self._last_known_ip: str | None = None
        self._last_known_hostname: str | None = None
        self._is_connected: bool = False
        self._last_known_connected_time: datetime | None = None
        self._attr_entity_registry_enabled_default: bool = enabled_default
        self._attr_hostname: str | None = hostname
        self._attr_ip_address: str | None = None
        self._attr_mac_address: str | None = mac
        self._attr_source_type: SourceType = SourceType.ROUTER
        self._attr_icon: str | None = None
        self._fallback_device_info_consumed: bool = False
        self._router_device_id: str | None = router_device_id

    def _has_matching_enabled_mac_device(self) -> bool:
        """Return whether a matching MAC device exists and is not disabled.

        Returns:
            bool: Whether the has matching enabled mac device condition is satisfied.
        """
        if self.mac_address is None:
            return False

        hass = getattr(self, "hass", None)
        if hass is None:
            return False

        device_registry = async_get_dev_reg(hass)
        existing_devices = async_get_devices_by_connection(
            device_registry,
            (CONNECTION_NETWORK_MAC, self.mac_address),
        )
        return any(getattr(device, "disabled_by", None) is None for device in existing_devices)

    @property
    def is_connected(self) -> bool:
        """Return if the tracker is connected.

        Returns:
            bool: ``True`` when the device is currently considered connected.
        """
        return self._is_connected

    @property
    def unique_id(self) -> str | None:
        """Return a stable object-id hint when linking to an existing device.

        Returns:
            str | None: The Home Assistant entity unique ID.
        """
        return self._attr_unique_id

    @property
    def suggested_object_id(self) -> str | None:
        """Return a stable object-id hint when linking to an existing device.

        Returns:
            str | None: Hostname when available, otherwise MAC, but only for the
            auto-link path (enabled matching MAC + new-entity preference disabled).
        """
        if (
            self._has_matching_enabled_mac_device()
            and not self.config_entry.pref_disable_new_entities
        ):
            if self._attr_hostname is not None:
                return self._attr_hostname
            return self._attr_mac_address
        return None

    @property
    def entity_registry_enabled_default(self) -> bool:
        """Return if the entity registry is enabled by default.

        Returns:
            bool: ``True`` when the entity should be enabled by default.
        """
        if self._attr_entity_registry_enabled_default:
            return True
        if self._fallback_device_info_consumed:
            return False
        return self._has_matching_enabled_mac_device()

    @callback
    def _handle_coordinator_update(self) -> None:
        """Refresh tracker state from the latest ARP and NDP tables."""
        state: dict[str, Any] = self.coordinator.data
        arp_table = dict_get(state, "arp_table")
        ndp_table = dict_get(state, "ndp_table")
        if not isinstance(state, MutableMapping) or not any(
            isinstance(table, list) for table in (arp_table, ndp_table)
        ):
            self._mark_unavailable()
            return
        arp_table_lookup_failed = not isinstance(arp_table, list)
        ndp_table_lookup_failed = not isinstance(ndp_table, list)
        self._available = True
        arp_table = arp_table if isinstance(arp_table, list) else []
        ndp_table = ndp_table if isinstance(ndp_table, list) else []
        failed_tables = _unavailable_device_tracker_tables(state)
        arp_failed = "arp_table" in failed_tables or arp_table_lookup_failed
        ndp_failed = "ndp_table" in failed_tables or ndp_table_lookup_failed
        tracker_mac = self._attr_mac_address
        arp_entries = (
            _entries_for_mac(arp_table, tracker_mac) if isinstance(tracker_mac, str) else []
        )
        ndp_entries = (
            _entries_for_mac(ndp_table, tracker_mac, require_valid_mac=True)
            if isinstance(tracker_mac, str)
            else []
        )
        fresh_arp_entries = [] if arp_failed else arp_entries
        fresh_ndp_entries = [] if ndp_failed else ndp_entries
        ipv4_addresses = _addresses_from_entries(arp_entries, version=4)
        ipv6_addresses = _addresses_from_entries(ndp_entries, version=6)
        last_ipv4_addresses = self._attr_extra_state_attributes.get("ipv4_addresses", [])
        last_ipv6_addresses = self._attr_extra_state_attributes.get("ipv6_addresses", [])
        if arp_failed and isinstance(last_ipv4_addresses, list):
            ipv4_addresses = [item for item in last_ipv4_addresses if isinstance(item, str)]
        if ndp_failed and isinstance(last_ipv6_addresses, list):
            saved_addresses = [item for item in last_ipv6_addresses if isinstance(item, str)]
            ipv6_addresses = list(dict.fromkeys(saved_addresses + ipv6_addresses))
        self._attr_extra_state_attributes["ipv4_addresses"] = ipv4_addresses
        self._attr_extra_state_attributes["ipv6_addresses"] = ipv6_addresses
        self._attr_ip_address = next(iter(ipv4_addresses or ipv6_addresses), None)

        if self._attr_ip_address:
            self._last_known_ip = self._attr_ip_address

        arp_entry = arp_entries[0] if arp_entries else {}
        ndp_entry = ndp_entries[0] if ndp_entries else {}
        self._attr_hostname = _hostname_from_arp_entry(arp_entry)

        if self._attr_hostname:
            self._last_known_hostname = self._attr_hostname

        fresh_arp_present = any(not entry.get("expired", False) for entry in fresh_arp_entries)
        fresh_ndp_present = bool(fresh_ndp_entries)
        if (
            not fresh_arp_present
            and not fresh_ndp_present
            and (
                (arp_failed and ndp_failed)
                or (arp_failed and bool(ipv4_addresses))
                or (ndp_failed and bool(ipv6_addresses))
            )
        ):
            # Either both lookups failed (no successful refresh at all, regardless of cached
            # addresses) or the family that previously confirmed this device is unavailable.
            # Preserve last-known address attributes and report the tracker as unavailable
            # instead of treating a missing row as an away observation.
            _update_arp_extra_state_attributes(
                self._attr_extra_state_attributes,
                arp_entry or ndp_entry,
            )
            self._mark_unavailable()
            return
        if not (fresh_arp_present or fresh_ndp_present):
            was_connected = self._is_connected
            self._is_connected = False
            device_tracker_consider_home = self.config_entry.options.get(
                CONF_DEVICE_TRACKER_CONSIDER_HOME, DEFAULT_DEVICE_TRACKER_CONSIDER_HOME
            )
            if device_tracker_consider_home > 0 and isinstance(
                self._last_known_connected_time, datetime
            ):
                elapsed: timedelta = datetime.now().astimezone() - self._last_known_connected_time
                if elapsed.total_seconds() < device_tracker_consider_home:
                    self._is_connected = True
            elif (arp_failed or ndp_failed) and self._last_known_connected_time is None:
                self._is_connected = was_connected

        else:
            update_time = state.get("update_time")
            if isinstance(update_time, float):
                self._last_known_connected_time = datetime.fromtimestamp(
                    int(update_time),
                    tz=timezone(datetime.now().astimezone().utcoffset() or timedelta()),
                )
            self._is_connected = True

        _update_arp_extra_state_attributes(
            self._attr_extra_state_attributes,
            arp_entry or ndp_entry,
        )

        if self._attr_hostname is None and self._last_known_hostname:
            self._attr_extra_state_attributes["last_known_hostname"] = self._last_known_hostname
        else:
            self._attr_extra_state_attributes.pop("last_known_hostname", None)

        if self._attr_ip_address is None and self._last_known_ip:
            self._attr_extra_state_attributes["last_known_ip"] = self._last_known_ip
        else:
            self._attr_extra_state_attributes.pop("last_known_ip", None)

        if self._last_known_connected_time is not None:
            self._attr_extra_state_attributes["last_known_connected_time"] = (
                self._last_known_connected_time
            )

        self._attr_icon = "mdi:lan-connect" if self.is_connected else "mdi:lan-disconnect"

        self.async_write_ha_state()

    @property  # type: ignore[misc] # overriding final from ScannerEntity
    def device_info(self) -> DeviceInfo | None:
        """Return device registry metadata for the tracker.

        Home Assistant's ``ScannerEntity`` can automatically attach a scanner
        entity to an existing device when the device registry already has a
        matching network MAC connection. That auto-link path only runs when
        the scanner entity does not provide its own device info.

        When a matching enabled device exists, return ``None`` so the base
        scanner implementation links this tracker to that device, unless
        ``pref_disable_new_entities`` is enabled on the config entry.
        In that preference-enabled case, return device info so the entity is
        linked to an existing device during registry creation while the entity
        remains disabled by preference.

        When no matching enabled device exists, return the historical
        hass-opnsense device info so Home Assistant still creates the manually
        associated tracker device or preserves disabled-device behavior.

        Returns:
            DeviceInfo | None: ``None`` for an existing enabled MAC-matched device, except when
            ``pref_disable_new_entities`` is enabled, otherwise fallback
            device registry metadata for the tracked MAC address.
        """
        # Returning None here opts into ScannerEntity's existing-device linking
        # path. Returning DeviceInfo below preserves the previous fallback
        # behavior for trackers whose MAC is not already in the device registry.
        has_matching_enabled_mac_device = self._has_matching_enabled_mac_device()
        if has_matching_enabled_mac_device and not self.config_entry.pref_disable_new_entities:
            return None

        if not has_matching_enabled_mac_device:
            self._fallback_device_info_consumed = True

        connections: set[tuple[str, str]] = set()
        if self.mac_address is not None:
            connections.add((CONNECTION_NETWORK_MAC, self.mac_address))

        device_info = DeviceInfo(
            connections=connections,
            manufacturer=self._mac_vendor or "",
            name=self.hostname or self.mac_address or "",
        )
        if self._router_device_id is not None:
            device_info["via_device_id"] = self._router_device_id
            return device_info

        # Home Assistant 2026.3-2026.7 resolves parent devices by identifier.
        legacy_device_info_factory: Any = DeviceInfo
        return legacy_device_info_factory(
            **device_info,
            via_device=(DOMAIN, self._device_unique_id),
        )

    async def _restore_last_state(self) -> None:
        """Restore tracker state from Home Assistant's last saved snapshot."""
        last_state = await self.async_get_last_state()
        if last_state is None or last_state.attributes is None:
            return

        state = last_state.attributes
        if not isinstance(state, Mapping):
            return

        self._last_known_hostname = state.get("last_known_hostname", None)
        last_known_ip = state.get("last_known_ip")
        if not isinstance(last_known_ip, str) or not last_known_ip:
            last_known_ip = state.get("ip")
        self._last_known_ip = last_known_ip if isinstance(last_known_ip, str) else None

        if "ipv4_addresses" not in state:
            ipv4_address = _normalized_ip_address(self._last_known_ip, version=4)
            if ipv4_address is not None:
                self._attr_extra_state_attributes["ipv4_addresses"] = [ipv4_address]
        if "ipv6_addresses" not in state:
            ipv6_address = _normalized_ip_address(self._last_known_ip, version=6)
            if ipv6_address is not None:
                self._attr_extra_state_attributes["ipv6_addresses"] = [ipv6_address]

        for attr in ("ipv4_addresses", "ipv6_addresses"):
            addresses = state.get(attr)
            if isinstance(addresses, list):
                self._attr_extra_state_attributes[attr] = [
                    address for address in addresses if isinstance(address, str)
                ]

        for attr in ("interface", "expires", "type"):
            value = state.get(attr, None)
            if value:
                self._attr_extra_state_attributes[attr] = value

        lkct = state.get("last_known_connected_time", None)
        parsed_last_known_connected_time: datetime | None = None
        if isinstance(lkct, datetime):
            parsed_last_known_connected_time = lkct
        elif isinstance(lkct, str):
            with contextlib.suppress(ValueError):
                parsed_last_known_connected_time = datetime.fromisoformat(lkct)

        if (
            parsed_last_known_connected_time is not None
            and parsed_last_known_connected_time.tzinfo is not None
            and parsed_last_known_connected_time.utcoffset() is not None
        ):
            self._last_known_connected_time = parsed_last_known_connected_time
            self._attr_extra_state_attributes["last_known_connected_time"] = (
                parsed_last_known_connected_time
            )

    async def async_added_to_hass(self) -> None:
        """Commands to run after entity is created."""
        await self._restore_last_state()
        await super().async_added_to_hass()
