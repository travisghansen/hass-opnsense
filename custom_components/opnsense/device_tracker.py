"""Support for tracking for pfSense devices."""
from __future__ import annotations

import logging
import time
from typing import Any, Mapping

from homeassistant.components.device_tracker import SOURCE_TYPE_ROUTER
from homeassistant.components.device_tracker.config_entry import ScannerEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_platform
from homeassistant.helpers.device_registry import (
    CONNECTION_NETWORK_MAC,
    async_get as async_get_dev_reg,
)
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import slugify
from mac_vendor_lookup import AsyncMacLookup

from . import CoordinatorEntityManager, OPNSenseEntity, dict_get
from .const import (
    CONF_DEVICE_TRACKER_CONSIDER_HOME,
    CONF_DEVICES,
    DEFAULT_DEVICE_TRACKER_CONSIDER_HOME,
    DEVICE_TRACKER_COORDINATOR,
    DOMAIN,
    SHOULD_RELOAD,
    TRACKED_MACS,
)

_LOGGER = logging.getLogger(__name__)


def lookup_mac(mac_vendor_lookup: AsyncMacLookup, mac: str) -> str:
    mac = mac_vendor_lookup.sanitise(mac)
    if type(mac) == str:
        mac = mac.encode("utf8")
    return mac_vendor_lookup.prefixes[mac[:6]].decode("utf8")


def get_device_tracker_unique_id(mac: str, device_id: str):
    """Generate device_tracker unique ID."""
    return slugify(f"{device_id}_mac_{mac}")


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: entity_platform.AddEntitiesCallback,
) -> None:
    """Set up device tracker for pfSense component."""
    mac_vendor_lookup = AsyncMacLookup()
    try:
        await mac_vendor_lookup.update_vendors()
    except:
        try:
            await mac_vendor_lookup.load_vendors()
        except:
            pass

    dev_reg = async_get_dev_reg(hass)

    @callback
    def process_entities_callback(
        hass: HomeAssistant, config_entry: ConfigEntry
    ) -> list[OPNSenseScannerEntity]:
        # options = config_entry.options
        data = hass.data[DOMAIN][config_entry.entry_id]
        previous_mac_addresses = config_entry.data.get(TRACKED_MACS, [])
        coordinator = data[DEVICE_TRACKER_COORDINATOR]
        state = coordinator.data
        # seems unlikely *all* devices are intended to be monitored
        # disable by default and let users enable specific entries they care about
        enabled_default = False
        device_per_arp_entry = False

        entities = []
        mac_addresses = []

        # use configured mac addresses if setup, otherwise create an entity per arp entry
        configured_mac_addresses = config_entry.options.get(CONF_DEVICES, [])
        if configured_mac_addresses:
            mac_addresses = configured_mac_addresses
            enabled_default = True
        else:
            if device_per_arp_entry:
                arp_entries = dict_get(state, "arp_table")
                if not arp_entries:
                    return []

                mac_addresses = [
                    mac_address.lower()
                    for arp_entry in arp_entries
                    if (mac_address := arp_entry.get("mac-address"))
                ]

        for mac_address in mac_addresses:
            mac_vendor = None
            try:
                mac_vendor = lookup_mac(mac_vendor_lookup, mac_address)
            except:
                pass

            entity = OPNSenseScannerEntity(
                hass,
                config_entry,
                coordinator,
                enabled_default,
                mac_address,
                mac_vendor,
            )

            entities.append(entity)

        # Get the MACs that need to be removed and remove their devices
        for mac_address in list(set(previous_mac_addresses) - set(mac_addresses)):
            device = dev_reg.async_get_device(
                {}, {(CONNECTION_NETWORK_MAC, mac_address)}
            )
            if device:
                dev_reg.async_remove_device(device.id)

        if set(mac_addresses) != set(previous_mac_addresses):
            data[SHOULD_RELOAD] = False
            new_data = config_entry.data.copy()
            new_data[TRACKED_MACS] = mac_addresses.copy()
            hass.config_entries.async_update_entry(config_entry, data=new_data)

        return entities

    cem = CoordinatorEntityManager(
        hass,
        hass.data[DOMAIN][config_entry.entry_id][DEVICE_TRACKER_COORDINATOR],
        config_entry,
        process_entities_callback,
        async_add_entities,
    )
    cem.process_entities()


class OPNSenseScannerEntity(OPNSenseEntity, ScannerEntity):
    """Represent a scanned device."""

    def __init__(
        self,
        hass: HomeAssistant,
        config_entry: ConfigEntry,
        coordinator: DataUpdateCoordinator,
        enabled_default: bool,
        mac: str,
        mac_vendor: str,
    ) -> None:
        """Set up the pfSense scanner entity."""
        self.hass = hass
        self.config_entry = config_entry
        self.coordinator = coordinator
        self._mac_address = mac
        self._mac_vendor = mac_vendor
        self._last_known_ip = None
        self._last_known_hostname = None
        self._last_known_connected_time = None
        self._extra_state = {}

        self._attr_entity_registry_enabled_default = enabled_default
        self._attr_unique_id = get_device_tracker_unique_id(
            mac, self.opnsense_device_unique_id
        )

    def _get_opnsense_arp_entry(self) -> dict[str, str]:
        state = self.coordinator.data
        arp_table = dict_get(state, "arp_table")
        if arp_table is None:
            return None
        for entry in arp_table:
            if entry.get("mac-address", "").lower() == self._mac_address:
                return entry

        return None

    @property
    def available(self) -> bool:
        state = self.coordinator.data
        arp_table = dict_get(state, "arp_table")
        if arp_table is None:
            return False
        return super().available

    @property
    def source_type(self) -> str:
        """Return the source type, eg gps or router, of the device."""
        return SOURCE_TYPE_ROUTER

    @property
    def extra_state_attributes(self) -> Mapping[str, Any] | None:
        """Return extra state attributes."""
        return self._extra_state_attributes

    @property
    def _extra_state_attributes(self) -> Mapping[str, Any] | None:
        """Return extra state attributes."""
        entry = self._get_opnsense_arp_entry()
        if entry is not None:
            for property in ["interface", "expires", "type"]:
                self._extra_state[property] = entry.get(property)

        if self._last_known_hostname is not None:
            self._extra_state["last_known_hostname"] = self._last_known_hostname

        if self._last_known_ip is not None:
            self._extra_state["last_known_ip"] = self._last_known_ip

        if self._last_known_connected_time is not None:
            self._extra_state[
                "last_known_connected_time"
            ] = self._last_known_connected_time

        return self._extra_state

    @property
    def ip_address(self) -> str | None:
        """Return the primary ip address of the device."""
        return self._ip_address

    @property
    def _ip_address(self) -> str | None:
        """Return the primary ip address of the device."""
        entry = self._get_opnsense_arp_entry()
        if entry is None:
            return None

        ip_address = entry.get("ip-address")
        if ip_address is not None and len(ip_address) > 0:
            self._last_known_ip = ip_address
        return ip_address

    @property
    def mac_address(self) -> str | None:
        """Return the mac address of the device."""
        return self._mac_address

    @property
    def hostname(self) -> str | None:
        """Return hostname of the device."""
        return self._hostname

    @property
    def _hostname(self) -> str | None:
        """Return hostname of the device."""
        entry = self._get_opnsense_arp_entry()
        if entry is None:
            return None
        value = entry.get("hostname").strip("?")
        if len(value) > 0:
            self._last_known_hostname = value
            return value
        return None

    @property
    def name(self) -> str:
        """Return the name of the device."""
        identifier = self.hostname or self._last_known_hostname or self._mac_address
        return f"{self.opnsense_device_name} {identifier}"

    @property
    def device_info(self) -> DeviceInfo:
        """Return the device info."""
        return DeviceInfo(
            connections={(CONNECTION_NETWORK_MAC, self.mac_address)},
            default_manufacturer=self._mac_vendor,
            default_name=self.name,
            via_device=(DOMAIN, self.opnsense_device_unique_id),
        )

    @property
    def icon(self) -> str:
        """Return device icon."""
        try:
            return "mdi:lan-connect" if self.is_connected else "mdi:lan-disconnect"
        except:
            return "mdi:lan-disconnect"

    @property
    def is_connected(self) -> bool:
        """Return true if the device is connected to the network."""
        state = self.coordinator.data
        update_time = state["update_time"]
        entry = self._get_opnsense_arp_entry()
        if entry is None:
            if self._last_known_ip is not None and len(self._last_known_ip) > 0:
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
                    return True

            return False
        # TODO: check "expires" here to add more honed in logic?
        # TODO: clear cache under certain scenarios?
        ip_address = entry.get("ip-address")
        if ip_address is not None and len(ip_address) > 0:
            client = self._get_opnsense_client()
            self.hass.add_job(client.delete_arp_entry, ip_address)

        self._last_known_connected_time = int(update_time)

        return True

    async def async_added_to_hass(self) -> None:
        """Handle entity which will be added."""
        await super().async_added_to_hass()
        state = await self.async_get_last_state()
        if state is None:
            return

        if state.attributes is None:
            return

        state = state.attributes
        for attr in [
            "interface",
            "expires",
            "type",
            "last_known_ip",
            "last_known_hostname",
        ]:
            value = state.get(attr, None)
            if value is not None:
                self._extra_state[attr] = value
                if attr == "last_known_hostname":
                    self._last_known_hostname = value

                if attr == "last_known_ip":
                    self._last_known_ip = value

                if attr == "last_known_connected_time":
                    self._last_known_connected_time = value
