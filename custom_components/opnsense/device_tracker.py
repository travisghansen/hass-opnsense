"""Support for tracking for OPNsense devices."""

import logging
import time
from datetime import datetime, timedelta
from typing import Any, Mapping

from homeassistant.components.device_tracker import SourceType
from homeassistant.components.device_tracker.config_entry import ScannerEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_platform
from homeassistant.helpers.device_registry import (
    CONNECTION_NETWORK_MAC,
)
from homeassistant.helpers.device_registry import (
    async_get as async_get_dev_reg,
)
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.restore_state import RestoreEntity

from . import OPNsenseEntity
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
from .helpers import dict_get

_LOGGER: logging.Logger = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: entity_platform.AddEntitiesCallback,
) -> None:
    """Set up device tracker for OPNsense component."""

    dev_reg = async_get_dev_reg(hass)

    data = hass.data[DOMAIN][config_entry.entry_id]
    previous_mac_addresses: list = config_entry.data.get(TRACKED_MACS, [])
    coordinator: OPNsenseDataUpdateCoordinator = data[DEVICE_TRACKER_COORDINATOR]
    state = coordinator.data

    enabled_default = False
    entities: list = []
    mac_addresses: list = []

    # use configured mac addresses if setup, otherwise create an entity per arp entry
    arp_entries: list = dict_get(state, "arp_table")
    if not isinstance(arp_entries, list):
        arp_entries = []
    devices: list = []
    mac_addresses = []
    configured_mac_addresses = config_entry.options.get(CONF_DEVICES, [])
    if configured_mac_addresses and config_entry.options.get(
        CONF_DEVICE_TRACKER_ENABLED, DEFAULT_DEVICE_TRACKER_ENABLED
    ):
        _LOGGER.debug(
            f"[device_tracker async_setup_entry] configured_mac_addresses: {configured_mac_addresses}"
        )
        enabled_default = True
        mac_addresses = configured_mac_addresses
        for mac_address in mac_addresses:
            device: Mapping[str, Any] = {"mac": mac_address}
            for arp_entry in arp_entries:
                if mac_address == arp_entry.get("mac", ""):
                    for attr in ["hostname", "manufacturer"]:
                        try:
                            if arp_entry.get(attr, None):
                                device.update({attr: arp_entry.get(attr, None)})
                        except (TypeError, KeyError, AttributeError):
                            pass
            devices.append(device)
    elif config_entry.options.get(
        CONF_DEVICE_TRACKER_ENABLED, DEFAULT_DEVICE_TRACKER_ENABLED
    ):
        for arp_entry in arp_entries:
            mac_address = arp_entry.get("mac", None)
            if mac_address and mac_address not in mac_addresses:
                device: Mapping[str, Any] = {"mac": mac_address}
                for attr in ["hostname", "manufacturer"]:
                    try:
                        if arp_entry.get(attr, None):
                            device.update({attr: arp_entry.get(attr, None)})
                    except (TypeError, KeyError, AttributeError):
                        pass
                mac_addresses.append(mac_address)
                devices.append(device)

    for device in devices:
        entity = OPNsenseScannerEntity(
            config_entry=config_entry,
            coordinator=coordinator,
            enabled_default=enabled_default,
            mac=device.get("mac", None),
            mac_vendor=device.get("manufacturer", None),
            hostname=device.get("hostname", None),
        )
        entities.append(entity)

    # Get the MACs that need to be removed and remove their devices
    for mac_address in list(set(previous_mac_addresses) - set(mac_addresses)):
        device = dev_reg.async_get_device({}, {(CONNECTION_NETWORK_MAC, mac_address)})
        if device:
            dev_reg.async_remove_device(device.id)

    if set(mac_addresses) != set(previous_mac_addresses):
        data[SHOULD_RELOAD] = False
        new_data = config_entry.data.copy()
        new_data[TRACKED_MACS] = mac_addresses.copy()
        hass.config_entries.async_update_entry(config_entry, data=new_data)

    _LOGGER.debug(f"[device_tracker async_setup_entry] entities: {len(entities)}")
    async_add_entities(entities)


class OPNsenseScannerEntity(OPNsenseEntity, ScannerEntity, RestoreEntity):
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
        self._last_known_connected_time: str | None = None
        self._attr_entity_registry_enabled_default: bool = enabled_default
        self._attr_hostname: str | None = hostname
        self._attr_ip_address: str | None = None
        self._attr_mac_address: str | None = mac
        self._attr_source_type: SourceType = SourceType.ROUTER

    @property
    def source_type(self) -> SourceType:
        return self._attr_source_type

    @property
    def is_connected(self) -> bool:
        return self._is_connected

    @property
    def ip_address(self) -> str | None:
        return self._attr_ip_address

    @property
    def mac_address(self) -> str | None:
        return self._attr_mac_address

    @property
    def hostname(self) -> str | None:
        return self._attr_hostname

    @property
    def unique_id(self) -> str | None:
        return self._attr_unique_id

    @property
    def entity_registry_enabled_default(self) -> bool:
        return self._attr_entity_registry_enabled_default

    @callback
    def _handle_coordinator_update(self) -> None:
        state = self.coordinator.data
        arp_table = dict_get(state, "arp_table")
        if not isinstance(arp_table, list):
            self._available = False
            return
        self._available = True
        entry: Mapping[str:Any] | None = None
        for arp_entry in arp_table:
            if arp_entry.get("mac", "").lower() == self._attr_mac_address:
                entry = arp_entry
                break

        # _LOGGER.debug(f"[OPNsenseScannerEntity handle_coordinator_update] entry: {entry}")
        try:
            self._attr_ip_address = (
                entry.get("ip") if len(entry.get("ip")) > 0 else None
            )
        except (TypeError, KeyError, AttributeError):
            self._attr_ip_address = None

        if self._attr_ip_address:
            self._last_known_ip = self._attr_ip_address

        try:
            self._attr_hostname = (
                entry.get("hostname").strip("?")
                if len(entry.get("hostname").strip("?")) > 0
                else None
            )
        except (TypeError, KeyError, AttributeError):
            self._attr_hostname = None

        if self._attr_hostname:
            self._last_known_hostname = self._attr_hostname

        update_time = state["update_time"]
        if entry is None:
            if self._last_known_ip:
                # force a ping to _last_known_ip to possibly recreate arp entry?
                pass

            device_tracker_consider_home = self.config_entry.options.get(
                CONF_DEVICE_TRACKER_CONSIDER_HOME, DEFAULT_DEVICE_TRACKER_CONSIDER_HOME
            )
            if (
                device_tracker_consider_home > 0
                and self._last_known_connected_time is not None
            ):
                current_time = int(time.time())
                elapsed = current_time - self._last_known_connected_time
                if elapsed < device_tracker_consider_home:
                    self._is_connected = True

            self._is_connected = False
        else:
            # TODO: check "expires" here to add more honed in logic?
            # TODO: clear cache under certain scenarios?

            # Why was this being done? Remove it?
            # ip_address = entry.get("ip")
            # if ip_address is not None and len(ip_address) > 0:
            #     self.hass.add_job(self._client.delete_arp_entry, ip_address)

            self._last_known_connected_time = datetime.fromtimestamp(
                int(update_time),
                tz=datetime.now().astimezone().tzinfo,
            )
            self._is_connected = True

        ha_to_opnsense: Mapping[str, Any] = {
            "interface": "intf_description",
            "expires": "expires",
            "type": "type",
        }
        for prop_name in ["interface", "expires", "type"]:
            try:
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
            except (TypeError, KeyError, AttributeError):
                pass

        if self._attr_hostname is None and self._last_known_hostname:
            self._attr_extra_state_attributes["last_known_hostname"] = (
                self._last_known_hostname
            )
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
            self._attr_icon = (
                "mdi:lan-connect" if self.is_connected else "mdi:lan-disconnect"
            )
        except (TypeError, KeyError, AttributeError):
            self._attr_icon = "mdi:lan-disconnect"

        self.async_write_ha_state()
        _LOGGER.debug(
            f"[OPNsenseScannerEntity handle_coordinator_update] Name: {self.name}, "
            f"unique_id: {self.unique_id}, attr_unique_id: {self._attr_unique_id}, "
            f"available: {self.available}, is_connected: {self.is_connected}, "
            f"hostname: {self.hostname}, ip_address: {self.ip_address}, "
            f"last_known_hostname: {self._last_known_hostname}, last_known_ip: {self._last_known_ip}, "
            f"last_known_connected_time: {self._last_known_connected_time}, icon: {self.icon}, "
            f"extra_state_atrributes: {self.extra_state_attributes}"
        )

    @property
    def device_info(self) -> DeviceInfo:
        """Return the device info."""
        return DeviceInfo(
            connections={(CONNECTION_NETWORK_MAC, self.mac_address)},
            default_manufacturer=self._mac_vendor,
            default_name=self.name,
            via_device=(DOMAIN, self._device_unique_id),
        )

    async def _restore_last_state(self) -> None:
        state = await self.async_get_last_state()
        if state is None or state.attributes is None:
            return

        state = state.attributes

        self._last_known_hostname = state.get("last_known_hostname", None)
        self._last_known_ip = state.get("last_known_ip", None)

        for attr in [
            "interface",
            "expires",
            "type",
            "last_known_connected_time",
        ]:
            try:
                value = state.get(attr, None)
                if value:
                    self._attr_extra_state_attributes[attr] = value
            except (TypeError, KeyError, AttributeError):
                pass

    async def async_added_to_hass(self) -> None:
        await self._restore_last_state()
        await super().async_added_to_hass()
