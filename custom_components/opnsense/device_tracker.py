"""Support for tracking for OPNsense devices."""

from collections.abc import MutableMapping
import contextlib
from datetime import datetime, timedelta, timezone
import logging
from typing import Any

from homeassistant.components.device_tracker import SourceType
from homeassistant.components.device_tracker.config_entry import ScannerEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import (
    CONNECTION_NETWORK_MAC,
    async_get as async_get_dev_reg,
)
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity

from .const import (
    CONF_DEVICE_TRACKER_CONSIDER_HOME,
    CONF_DEVICE_TRACKER_ENABLED,
    CONF_DEVICES,
    DEFAULT_DEVICE_TRACKER_CONSIDER_HOME,
    DEFAULT_DEVICE_TRACKER_ENABLED,
    DEVICE_TRACKER_COORDINATOR,
    DOMAIN,
    SHOULD_RELOAD,
    TRACKED_MACS,
)
from .coordinator import OPNsenseDataUpdateCoordinator
from .entity import OPNsenseBaseEntity
from .helpers import dict_get

_LOGGER: logging.Logger = logging.getLogger(__name__)


def _device_data_from_arp_entry(
    mac_address: str,
    arp_entry: MutableMapping[str, Any],
) -> dict[str, Any]:
    """Build tracked device data from an ARP table entry."""
    device: dict[str, Any] = {"mac": mac_address}
    for attr in ("hostname", "manufacturer"):
        value = arp_entry.get(attr)
        if value:
            device[attr] = value
    return device


def _device_from_arp_entry(mac_address: str, arp_entries: list[Any]) -> dict[str, Any]:
    """Build tracked device data from a configured MAC and matching ARP entry."""
    device: dict[str, Any] = {"mac": mac_address}
    for arp_entry in arp_entries:
        if not isinstance(arp_entry, MutableMapping):
            continue
        if mac_address != arp_entry.get("mac", ""):
            continue
        device.update(_device_data_from_arp_entry(mac_address, arp_entry))
        break
    return device


def _devices_from_arp_entries(arp_entries: list[Any]) -> tuple[list[dict[str, Any]], list[str]]:
    """Build tracked device data from unique ARP table MAC addresses."""
    devices: list[dict[str, Any]] = []
    mac_addresses: list[str] = []

    for arp_entry in arp_entries:
        if not isinstance(arp_entry, MutableMapping):
            continue
        mac_address = arp_entry.get("mac")
        if not isinstance(mac_address, str) or not mac_address or mac_address in mac_addresses:
            continue
        mac_addresses.append(mac_address)
        devices.append(_device_data_from_arp_entry(mac_address, arp_entry))

    return devices, mac_addresses


def _compile_tracked_devices(
    config_entry: ConfigEntry,
    arp_entries: list[Any],
) -> tuple[list[dict[str, Any]], list[str], bool]:
    """Compile device tracker source data from options and ARP entries."""
    if not config_entry.options.get(CONF_DEVICE_TRACKER_ENABLED, DEFAULT_DEVICE_TRACKER_ENABLED):
        return [], [], False

    configured_mac_addresses = config_entry.options.get(CONF_DEVICES, [])
    if configured_mac_addresses:
        _LOGGER.debug(
            "[device_tracker async_setup_entry] configured_mac_addresses: %s",
            configured_mac_addresses,
        )
        devices = [
            _device_from_arp_entry(mac_address, arp_entries)
            for mac_address in configured_mac_addresses
        ]
        return devices, list(configured_mac_addresses), True

    devices, mac_addresses = _devices_from_arp_entries(arp_entries)
    return devices, mac_addresses, False


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up device tracker for OPNsense component."""
    dev_reg = async_get_dev_reg(hass)

    previous_mac_addresses: list = config_entry.data.get(TRACKED_MACS, [])
    coordinator: OPNsenseDataUpdateCoordinator = getattr(
        config_entry.runtime_data, DEVICE_TRACKER_COORDINATOR
    )
    state: dict[str, Any] = coordinator.data
    if not isinstance(state, MutableMapping):
        _LOGGER.error("Missing state data in device tracker async_setup_entry")
        return
    entities: list = []

    arp_entries = dict_get(state, "arp_table")
    if not isinstance(arp_entries, list):
        arp_entries = []
    devices, mac_addresses, enabled_default = _compile_tracked_devices(config_entry, arp_entries)

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
        )
        entities.append(entity)

    for mac_address in list(set(previous_mac_addresses) - set(mac_addresses)):
        rem_device = dev_reg.async_get_device(connections={(CONNECTION_NETWORK_MAC, mac_address)})
        if rem_device:
            dev_reg.async_remove_device(rem_device.id)

    if set(mac_addresses) != set(previous_mac_addresses):
        setattr(config_entry.runtime_data, SHOULD_RELOAD, False)
        new_data = config_entry.data.copy()
        new_data[TRACKED_MACS] = mac_addresses.copy()
        hass.config_entries.async_update_entry(config_entry, data=new_data)

    _LOGGER.debug("[device_tracker async_setup_entry] entities: %s", len(entities))
    async_add_entities(entities)


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
    ) -> None:
        """Set up the OPNsense scanner entity."""
        super().__init__(config_entry, coordinator, unique_id_suffix=f"mac_{mac}")
        self._mac_vendor: str | None = mac_vendor
        self._attr_name: str | None = f"{self.opnsense_device_name} {hostname or mac}"
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

    @property
    def source_type(self) -> SourceType:
        """Return the tracker source type."""
        return self._attr_source_type

    @property
    def is_connected(self) -> bool:
        """Return if the tracker is connected."""
        return self._is_connected

    @property
    def ip_address(self) -> str | None:
        """Return the IP address."""
        return self._attr_ip_address

    @property
    def mac_address(self) -> str | None:
        """Return the MAC address."""
        return self._attr_mac_address

    @property
    def hostname(self) -> str | None:
        """Return the hostname."""
        return self._attr_hostname

    @property
    def unique_id(self) -> str | None:
        """Return the unique id."""
        return self._attr_unique_id

    @property
    def entity_registry_enabled_default(self) -> bool:
        """Return if the entity registry is enabled by default."""
        return self._attr_entity_registry_enabled_default

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update."""
        state: dict[str, Any] = self.coordinator.data
        arp_table = dict_get(state, "arp_table")
        if not isinstance(arp_table, list) or not isinstance(state, MutableMapping):
            self._available = False
            self.async_write_ha_state()
            return
        self._available = True
        entry: MutableMapping[str, Any] | None = None
        for arp_entry in arp_table:
            if not isinstance(arp_entry, MutableMapping):
                continue
            if arp_entry.get("mac", "").lower() == self._attr_mac_address:
                entry = arp_entry
                break
        if not entry:
            entry = {}
        try:
            self._attr_ip_address = entry.get("ip") if len(entry.get("ip", 0)) > 0 else None
        except TypeError, KeyError, AttributeError:
            self._attr_ip_address = None

        if self._attr_ip_address:
            self._last_known_ip = self._attr_ip_address

        try:
            self._attr_hostname = (
                entry.get("hostname", "").strip("?")
                if len(entry.get("hostname", "").strip("?")) > 0
                else None
            )
        except TypeError, KeyError, AttributeError:
            self._attr_hostname = None

        if self._attr_hostname:
            self._last_known_hostname = self._attr_hostname

        if not isinstance(entry, MutableMapping) or not entry or entry.get("expired", False):
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

        else:
            update_time = state.get("update_time")
            if isinstance(update_time, float):
                self._last_known_connected_time = datetime.fromtimestamp(
                    int(update_time),
                    tz=timezone(datetime.now().astimezone().utcoffset() or timedelta()),
                )
            self._is_connected = True

        ha_to_opnsense: dict[str, Any] = {
            "interface": "intf_description",
            "expires": "expires",
            "type": "type",
        }
        try:
            for prop_name in ("interface", "expires", "type"):
                prop = entry.get(ha_to_opnsense[prop_name])
                if prop:
                    if prop_name == "expires":
                        if prop == -1:
                            self._attr_extra_state_attributes[prop_name] = "Never"
                        else:
                            self._attr_extra_state_attributes[prop_name] = (
                                datetime.now().astimezone() + timedelta(seconds=prop)
                            )
                    else:
                        self._attr_extra_state_attributes[prop_name] = prop
        except TypeError, KeyError, AttributeError:
            pass

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

        try:
            self._attr_icon = "mdi:lan-connect" if self.is_connected else "mdi:lan-disconnect"
        except TypeError, KeyError, AttributeError:
            self._attr_icon = "mdi:lan-disconnect"

        self.async_write_ha_state()

    @property  # type: ignore[misc] # overriding final from ScannerEntity
    def device_info(self) -> DeviceInfo | None:
        """Return the device info."""
        return DeviceInfo(
            connections={(CONNECTION_NETWORK_MAC, self.mac_address or "")},
            default_manufacturer=self._mac_vendor or "",
            default_name=self.name if isinstance(self.name, str) else "",
            via_device=(DOMAIN, self._device_unique_id),
        )

    async def _restore_last_state(self) -> None:
        """Restore last state."""
        last_state = await self.async_get_last_state()
        if last_state is None or last_state.attributes is None:
            return

        state = last_state.attributes

        self._last_known_hostname = state.get("last_known_hostname", None)
        self._last_known_ip = state.get("last_known_ip", None)

        try:
            for attr in ("interface", "expires", "type"):
                value = state.get(attr, None)
                if value:
                    self._attr_extra_state_attributes[attr] = value
        except TypeError, KeyError, AttributeError:
            pass

        lkct = state.get("last_known_connected_time", None)
        if isinstance(lkct, datetime):
            self._attr_extra_state_attributes["last_known_connected_time"] = lkct
        elif isinstance(lkct, str):
            with contextlib.suppress(ValueError):
                self._attr_extra_state_attributes["last_known_connected_time"] = (
                    datetime.fromisoformat(lkct)
                )

    async def async_added_to_hass(self) -> None:
        """Commands to run after entity is created."""
        await self._restore_last_state()
        await super().async_added_to_hass()
