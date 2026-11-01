"""Support for tracking for OPNsense devices."""

from collections.abc import Mapping, MutableMapping
import contextlib
from datetime import datetime, timedelta, timezone
import ipaddress
import logging
from typing import Any

from aiopnsense import OPNsenseClient
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

from .const import (
    CONF_DEVICE_TRACKER_CONSIDER_HOME,
    CONF_DEVICE_TRACKER_ENABLED,
    CONF_DEVICE_TRACKER_SCAN_INTERVAL,
    CONF_DEVICE_UNIQUE_ID,
    CONF_DEVICES,
    DEFAULT_DEVICE_TRACKER_CONSIDER_HOME,
    DEFAULT_DEVICE_TRACKER_ENABLED,
    DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL,
    DEVICE_TRACKER_COORDINATOR,
    DEVICE_TRACKER_NDP_MAX_SECS,
    DOMAIN,
    SHOULD_RELOAD,
    TRACKED_ARP_MACS,
    TRACKED_MACS,
    TRACKED_NDP_MACS,
)
from .coordinator import OPNsenseDataUpdateCoordinator
from .device_tracker_evidence import (
    DeviceTrackerEvidenceSnapshot,
    normalize_tracked_mac_inventory,
    poll_arp_ndp_provenance,
    setup_arp_ndp_provenance,
)
from .entity import OPNsenseBaseEntity
from .helpers import (
    async_get_device_by_connection,
    async_get_device_by_identifier,
    async_get_devices_by_connection,
    detach_shared_router_parent,
    has_configured_tracker_macs,
)
from .repair_reconciliation import is_reconciliation_active, record_desired_entities

_LOGGER: logging.Logger = logging.getLogger(__name__)


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
        value (object): Raw address from a ARP/NDP table row.
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


def _update_arp_extra_state_attributes(
    attributes: dict[str, Any],
    entry: OPNsenseClient.ArpNdpEntry | None,
) -> None:
    """Update optional ARP extra state attributes from a coordinator entry.

    Args:
        attributes (dict[str, Any]): Entity attributes to mutate in place.
        entry (OPNsenseClient.ArpNdpEntry | None): Normalized ARP/NDP row providing
            optional metadata.
    """
    for attr in ("interface", "expires", "type"):
        attributes.pop(attr, None)

    if entry is None:
        return

    if entry.interface:
        attributes["interface"] = entry.interface

    expires = _arp_expires_attribute(entry.expires)
    if expires is not None:
        attributes["expires"] = expires

    if entry.arp_type:
        attributes["type"] = entry.arp_type


def _update_track_all_source_inventory(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    snapshot: DeviceTrackerEvidenceSnapshot,
) -> None:
    """Update family provenance for already tracked MACs from complete table results.

    Failed or malformed family tables retain their last persisted inventory. Successful table
    results replace a MAC's membership only when that MAC is seen in an authoritative scan;
    otherwise its last known family membership is kept. Membership is limited to the existing
    tracked-MAC union, so coordinator polling never discovers new entities.

    Args:
        hass (HomeAssistant): Home Assistant runtime used to persist config-entry data.
        config_entry (ConfigEntry): Config entry owning the tracked devices.
        snapshot (DeviceTrackerEvidenceSnapshot): Latest normalized tracker evidence.
    """
    options = config_entry.options
    has_configured_macs = has_configured_tracker_macs(config_entry)
    if not options.get(CONF_DEVICE_TRACKER_ENABLED, DEFAULT_DEVICE_TRACKER_ENABLED) or (
        has_configured_macs
    ):
        return

    tracked_macs = list(normalize_tracked_mac_inventory(config_entry.data.get(TRACKED_MACS)))
    if not tracked_macs:
        return

    if not snapshot.arp.authoritative and not snapshot.ndp.authoritative:
        return

    stored_arp_macs = config_entry.data.get(TRACKED_ARP_MACS, tracked_macs)
    stored_ndp_macs = config_entry.data.get(TRACKED_NDP_MACS, [])
    provenance = poll_arp_ndp_provenance(
        snapshot,
        tracked_macs=tracked_macs,
        previous_arp_macs=stored_arp_macs,
        previous_ndp_macs=stored_ndp_macs,
    )
    updated_arp_macs = list(provenance.arp_macs)
    updated_ndp_macs = list(provenance.ndp_macs)
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
        coordinator (OPNsenseDataUpdateCoordinator): Coordinator providing ARP/NDP table state.
    """

    @callback
    def update_track_all_source_inventory() -> None:
        """Refresh family provenance from the latest coordinator poll."""
        snapshot = coordinator.device_tracker_evidence
        if snapshot is None:
            return
        _update_track_all_source_inventory(hass, config_entry, snapshot)

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
    state = coordinator.data
    if not isinstance(state, MutableMapping):
        _LOGGER.error("Missing state data in device tracker async_setup_entry")
        return
    snapshot = coordinator.device_tracker_evidence
    if snapshot is None:
        # A failed initial refresh can leave no current snapshot. Continue with persisted tracker
        # identities, but do not use the previous coordinator payload as fresh discovery data.
        snapshot = DeviceTrackerEvidenceSnapshot.from_tables()
    reconciliation_complete = True
    entities: list = []

    has_configured_macs = has_configured_tracker_macs(config_entry)
    table_response_available = snapshot.arp.has_payload or snapshot.ndp.has_payload
    if not has_configured_macs:
        reconciliation_complete = table_response_available
    track_all_enabled = bool(
        config_entry.options.get(CONF_DEVICE_TRACKER_ENABLED, DEFAULT_DEVICE_TRACKER_ENABLED)
        and not has_configured_macs
    )
    tracker_enabled = bool(
        config_entry.options.get(CONF_DEVICE_TRACKER_ENABLED, DEFAULT_DEVICE_TRACKER_ENABLED)
    )
    configured_macs = config_entry.options.get(CONF_DEVICES, [])
    configured_macs = (
        [mac for mac in configured_macs if isinstance(mac, str)]
        if isinstance(configured_macs, list)
        else []
    )
    if tracker_enabled:
        selected_macs = configured_macs if has_configured_macs else None
        tracker_devices = list(snapshot.devices(selected_macs))
        mac_addresses = [device.mac for device in tracker_devices]
        enabled_default = has_configured_macs
    else:
        tracker_devices = []
        mac_addresses = []
        enabled_default = False

    arp_authoritative = snapshot.arp.authoritative
    ndp_authoritative = snapshot.ndp.authoritative
    if track_all_enabled:
        provenance = setup_arp_ndp_provenance(snapshot, config_entry.data)
        tracked_arp_macs = list(provenance.arp_macs)
        tracked_ndp_macs = list(provenance.ndp_macs)
        mac_addresses = list(dict.fromkeys(tracked_arp_macs + tracked_ndp_macs))
        devices_by_mac = {device.mac: device for device in tracker_devices}
        for mac_address in mac_addresses:
            if mac_address not in devices_by_mac:
                devices_by_mac[mac_address] = snapshot.devices((mac_address,))[0]
        tracker_devices = list(devices_by_mac.values())
        # Per-family persisted inventories make a partial failure safe to reconcile: a failed
        # table keeps its previous MACs while a successful table can still remove stale devices.
        reconciliation_complete = (
            (not snapshot.arp.successful or arp_authoritative)
            and (not snapshot.ndp.successful or ndp_authoritative)
            and table_response_available
        )
    else:
        tracked_arp_macs = []
        tracked_ndp_macs = []

    router_device_id: str | None = None
    if tracker_devices and getattr(dev_reg, "async_get_device_by_identifier", None) is not None:
        router_device = dev_reg.async_get_or_create(
            config_entry_id=config_entry.entry_id,
            identifiers={(DOMAIN, config_entry.data[CONF_DEVICE_UNIQUE_ID])},
        )
        router_device_id = router_device.id

    for device in tracker_devices:
        entity = OPNsenseScannerEntity(
            config_entry=config_entry,
            coordinator=coordinator,
            enabled_default=enabled_default,
            mac=device.mac,
            mac_vendor=device.manufacturer,
            hostname=device.hostname,
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
        self._device_info_without_enabled_match: bool = False
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
        if self._device_info_without_enabled_match:
            return False
        return self._has_matching_enabled_mac_device()

    def _ndp_freshness_window_secs(self) -> int:
        """Return how old a discovery timestamp may be while still confirming NDP presence.

        The window is the larger of ``DEVICE_TRACKER_NDP_MAX_SECS`` and twice the configured
        device-tracker scan interval, so long intervals do not outlive the evidence between scans.

        Returns:
            int: Freshness window in seconds.
        """
        scan_interval = self.config_entry.options.get(
            CONF_DEVICE_TRACKER_SCAN_INTERVAL, DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL
        )
        if not isinstance(scan_interval, (int, float)) or isinstance(scan_interval, bool):
            scan_interval = DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL
        return max(DEVICE_TRACKER_NDP_MAX_SECS, int(2 * scan_interval))

    @callback
    def _handle_coordinator_update(self) -> None:
        """Refresh tracker state from the latest ARP and NDP tables."""
        snapshot = getattr(self.coordinator, "device_tracker_evidence", None)
        if snapshot is None or not (snapshot.arp.has_payload or snapshot.ndp.has_payload):
            self._attr_extra_state_attributes["ndp_presence_source"] = "no_evidence"
            self._mark_unavailable()
            return
        self._available = True
        last_ipv4_addresses = self._attr_extra_state_attributes.get("ipv4_addresses", [])
        last_ipv6_addresses = self._attr_extra_state_attributes.get("ipv6_addresses", [])
        if not isinstance(last_ipv4_addresses, list):
            last_ipv4_addresses = []
        if not isinstance(last_ipv6_addresses, list):
            last_ipv6_addresses = []
        presence = snapshot.presence_for_mac(
            self._attr_mac_address or "",
            now=datetime.now().astimezone(),
            max_age=timedelta(seconds=self._ndp_freshness_window_secs()),
            previous_ipv4_addresses=last_ipv4_addresses,
            previous_ipv6_addresses=last_ipv6_addresses,
        )
        ipv4_addresses = list(presence.ipv4_addresses)
        ipv6_addresses = list(presence.ipv6_addresses)
        self._attr_extra_state_attributes["ndp_presence_source"] = presence.ndp_presence_source
        self._attr_extra_state_attributes["ipv4_addresses"] = ipv4_addresses
        self._attr_extra_state_attributes["ipv6_addresses"] = ipv6_addresses
        self._attr_ip_address = next(iter(ipv4_addresses or ipv6_addresses), None)

        if self._attr_ip_address:
            self._last_known_ip = self._attr_ip_address

        arp_entry = presence.arp_entry
        ndp_entry = presence.ndp_entry
        self._attr_hostname = arp_entry.hostname if arp_entry is not None else None

        if self._attr_hostname:
            self._last_known_hostname = self._attr_hostname

        if presence.status == "unknown":
            # A matching NDP row without a usable per-MAC timestamp, both lookups failing, or a
            # previously confirming family becoming unavailable means presence is unknown.
            # Preserve last-known address attributes and report unavailable instead of treating
            # that uncertainty as an away observation.
            _update_arp_extra_state_attributes(
                self._attr_extra_state_attributes,
                arp_entry or ndp_entry,
            )
            self._mark_unavailable()
            return
        if presence.status == "absent":
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
            elif (presence.arp_failed or presence.ndp_failed) and (
                self._last_known_connected_time is None
            ):
                self._is_connected = was_connected

        else:
            state = self.coordinator.data
            update_time = state.get("update_time") if isinstance(state, Mapping) else None
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

    @property  # type: ignore[misc] # ScannerEntity marks this final before HA 2026.11.
    def device_info(self) -> DeviceInfo:
        """Return device registry metadata for the tracker.

        Explicit metadata registers the client device on HA 2026.3+ without
        depending on ScannerEntity's MAC-linking hook, removed in HA 2026.11.
        Remember when no enabled MAC match existed before device registration
        so the newly created device cannot enable its own discovered tracker.

        Returns:
            DeviceInfo: Client MAC and name, optional manufacturer, and parent router
                metadata.
        """
        if not self._has_matching_enabled_mac_device():
            self._device_info_without_enabled_match = True

        connections: set[tuple[str, str]] = set()
        if self.mac_address is not None:
            connections.add((CONNECTION_NETWORK_MAC, self.mac_address))

        device_info = DeviceInfo(
            connections=connections,
            name=self.hostname or self.mac_address or "",
        )
        if self._mac_vendor:
            device_info["manufacturer"] = self._mac_vendor
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
