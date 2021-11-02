"""Support for tracking for pfSense devices."""
from __future__ import annotations

from homeassistant.components.device_tracker import SOURCE_TYPE_ROUTER
from homeassistant.components.device_tracker.config_entry import ScannerEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import slugify
from mac_vendor_lookup import AsyncMacLookup

from . import CoordinatorEntityManager, PfSenseEntity, dict_get
from .const import DEVICE_TRACKER_COORDINATOR, DOMAIN, PFSENSE_CLIENT
from .utils import add_method


@add_method(AsyncMacLookup)
def sync_lookup(self, mac):
    mac = self.sanitise(mac)
    if type(mac) == str:
        mac = mac.encode("utf8")
    return self.prefixes[mac[:6]].decode("utf8")


async def async_setup_entry(
    hass: HomeAssistant, config_entry: ConfigEntry, async_add_entities
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

    def process_entities_callback(hass, config_entry):
        # options = config_entry.options
        data = hass.data[DOMAIN][config_entry.entry_id]
        coordinator = data[DEVICE_TRACKER_COORDINATOR]
        state = coordinator.data
        # seems unlikely *all* devices are intended to be monitored
        # disable by default and let users enable specific entries they care about
        enabled_default = False

        entities = []
        entries = dict_get(state, "arp_table")
        if isinstance(entries, list):
            for entry in entries:
                entry_mac = entry.get("mac-address")
                if entry_mac is None:
                    continue

                entry_mac = entry_mac.lower()
                mac_vendor = None
                try:
                    mac_vendor = mac_vendor_lookup.sync_lookup(entry_mac)
                except:
                    pass

                entity = PfSenseScannerEntity(
                    config_entry,
                    coordinator,
                    enabled_default,
                    entry_mac,
                    mac_vendor,
                )
                entities.append(entity)

        return entities

    cem = CoordinatorEntityManager(
        hass,
        hass.data[DOMAIN][config_entry.entry_id][DEVICE_TRACKER_COORDINATOR],
        config_entry,
        process_entities_callback,
        async_add_entities,
    )
    cem.process_entities()


class PfSenseScannerEntity(PfSenseEntity, ScannerEntity):
    """Represent a scanned device."""

    def __init__(
        self,
        config_entry,
        coordinator: DataUpdateCoordinator,
        enabled_default: bool,
        mac,
        mac_vendor,
    ) -> None:
        """Set up the pfSense scanner entity."""
        self.config_entry = config_entry
        self.coordinator = coordinator
        self._mac = mac
        self._mac_vendor = mac_vendor
        self._last_known_ip = None

        self._attr_entity_registry_enabled_default = enabled_default
        self._attr_unique_id = slugify(f"{self.pfsense_device_unique_id}_mac_{mac}")

    def _get_pfsense_arp_entry(self):
        state = self.coordinator.data
        for entry in state["arp_table"]:
            if entry.get("mac-address") == self._mac:
                return entry

    @property
    def source_type(self) -> str:
        """Return the source type, eg gps or router, of the device."""
        return SOURCE_TYPE_ROUTER

    @property
    def extra_state_attributes(self):
        entry = self._get_pfsense_arp_entry()
        if entry is None:
            return None

        attrs = {}
        for property in ["interface", "expires", "type"]:
            attrs[property] = entry.get(property)

        return attrs

    @property
    def ip_address(self) -> str | None:
        """Return the primary ip address of the device."""
        entry = self._get_pfsense_arp_entry()
        if entry is None:
            return None

        ip_address = entry.get("ip-address")
        if ip_address is not None and len(ip_address) > 0:
            self._last_known_ip = ip_address
        return ip_address

    @property
    def mac_address(self) -> str | None:
        """Return the mac address of the device."""
        return self._mac

    @property
    def hostname(self) -> str | None:
        """Return hostname of the device."""
        entry = self._get_pfsense_arp_entry()
        if entry is None:
            return None
        value = entry.get("hostname").strip("?")
        if len(value) > 0:
            return value
        return None

    @property
    def name(self) -> str:
        """Return the name of the device."""
        # return self.hostname or f"{self.mac_address}"
        # return self.hostname or f"{self.pfsense_device_name} {self._mac}"
        return self.hostname or self._mac

    @property
    def device_info(self) -> DeviceInfo:
        """Return the device info."""
        return DeviceInfo(
            connections={(CONNECTION_NETWORK_MAC, self.mac_address)},
            default_manufacturer=self._mac_vendor,
            default_name=self.name,
            via_device=(DOMAIN, self.pfsense_device_unique_id),
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
        entry = self._get_pfsense_arp_entry()
        if entry is None:
            if self._last_known_ip is not None and len(self._last_known_ip) > 0:
                # force a ping to _last_known_ip to possibly recreate arp entry?
                pass

            return False
        # TODO: check "expires" here to add more honed in logic?
        # TODO: clear cache under certain scenarios?
        ip_address = entry.get("ip-address")
        if ip_address is not None and len(ip_address) > 0:
            client = self.hass.data[DOMAIN][self.config_entry.entry_id][PFSENSE_CLIENT]
            self.hass.async_add_executor_job(client.delete_arp_entry, ip_address)

        return True
