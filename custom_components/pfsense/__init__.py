"""Support for pfSense."""
import logging
import copy
from datetime import timedelta
import re
import time

import async_timeout

from homeassistant.const import CONF_USERNAME, CONF_PASSWORD, CONF_SCAN_INTERVAL, CONF_URL
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.restore_state import RestoreEntity
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
    UpdateFailed,
)

from .const import CONF_DEVICE_TRACKER_SCAN_INTERVAL, CONF_TLS_INSECURE, CONF_DEVICE_TRACKER_ENABLED, COORDINATOR, DEFAULT_DEVICE_TRACKER_ENABLED, DEFAULT_SCAN_INTERVAL, DEFAULT_TLS_INSECURE, DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL, DEVICE_TRACKER_COORDINATOR, DOMAIN, PLATFORMS, PFSENSE_CLIENT, UNDO_UPDATE_LISTENER

from .pypfsense import Client as pfSenseClient

_LOGGER = logging.getLogger(__name__)


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry):
    """Handle options update."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Set up pfSense from a config entry."""
    config = entry.data
    options = entry.options

    url = config[CONF_URL]
    username = config[CONF_USERNAME]
    password = config[CONF_PASSWORD]
    tls_insecure = config.get(CONF_TLS_INSECURE, DEFAULT_TLS_INSECURE)
    device_tracker_enabled = options.get(
        CONF_DEVICE_TRACKER_ENABLED, DEFAULT_DEVICE_TRACKER_ENABLED)
    client = pfSenseClient(url, username, password, {
                           "tls_insecure": tls_insecure})
    data = PfSenseData(client)

    async def async_update_data():
        """Fetch data from pfSense."""
        async with async_timeout.timeout(10):
            await hass.async_add_executor_job(
                lambda:
                    data.update()
            )

            if not data.state:
                raise UpdateFailed("Error fetching UPS state")

            return data.state

    scan_interval = options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        name="pfSense state",
        update_method=async_update_data,
        update_interval=timedelta(seconds=scan_interval),
    )

    platforms = PLATFORMS.copy()
    device_tracker_coordinator = None
    if not device_tracker_enabled:
        platforms.remove("device_tracker")
    else:
        device_tracker_data = PfSenseData(client)
        device_tracker_scan_interval = options.get(
            CONF_DEVICE_TRACKER_SCAN_INTERVAL, DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL)

        async def async_update_device_tracker_data():
            """Fetch data from pfSense."""
            async with async_timeout.timeout(10):
                await hass.async_add_executor_job(
                    lambda:
                        device_tracker_data.update({"scope": "device_tracker"})
                )

                if not device_tracker_data.state:
                    raise UpdateFailed("Error fetching UPS state")

                return device_tracker_data.state
        device_tracker_coordinator = DataUpdateCoordinator(
            hass,
            _LOGGER,
            name="pfSense device tracker state",
            update_method=async_update_device_tracker_data,
            update_interval=timedelta(seconds=device_tracker_scan_interval),
        )

    undo_listener = entry.add_update_listener(_async_update_listener)

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        COORDINATOR: coordinator,
        DEVICE_TRACKER_COORDINATOR: device_tracker_coordinator,
        PFSENSE_CLIENT: client,
        UNDO_UPDATE_LISTENER: [undo_listener],
    }

    # Fetch initial data so we have data when entities subscribe
    await coordinator.async_config_entry_first_refresh()
    if device_tracker_enabled:
        # Fetch initial data so we have data when entities subscribe
        await device_tracker_coordinator.async_config_entry_first_refresh()

    hass.config_entries.async_setup_platforms(entry, platforms)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    options = entry.options
    device_tracker_enabled = options.get(
        CONF_DEVICE_TRACKER_ENABLED, DEFAULT_DEVICE_TRACKER_ENABLED)

    platforms = PLATFORMS.copy()
    if not device_tracker_enabled:
        platforms.remove("device_tracker")

    unload_ok = await hass.config_entries.async_unload_platforms(entry, platforms)
    
    for listener in hass.data[DOMAIN][entry.entry_id][UNDO_UPDATE_LISTENER]:
        listener()

    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok


def dict_get(data: dict, path: str, default=None):
    pathList = re.split(r'\.', path, flags=re.IGNORECASE)
    result = data
    for key in pathList:
        try:
            key = int(key) if key.isnumeric() else key
            result = result[key]
        except:
            result = default
            break

    return result


class PfSenseData:
    def __init__(self, client: pfSenseClient):
        """Initialize the data object."""
        self._client = client
        self._state = {}

    @property
    def state(self):
        return self._state

    def _get_system_info(self):
        return self._client.get_system_info()

    def _get_telemetry(self):
        return self._client.get_telemetry()

    def _get_host_firmware_version(self):
        return self._client.get_host_firmware_version()

    def _get_config(self):
        return self._client.get_config()

    def update(self, opts={}):
        """Fetch the latest state from pfSense."""
        # copy the old data to have around
        previous_state = copy.deepcopy(self._state)
        if "previous_state" in previous_state.keys():
            del previous_state["previous_state"]

        self._state["system_info"] = self._get_system_info()
        self._state["host_firmware_version"] = self._get_host_firmware_version()
        self._state["update_time"] = time.time()
        self._state["previous_state"] = previous_state

        if "scope" in opts.keys() and opts["scope"] == "device_tracker":
            self._state["arp_table"] = self._client.get_arp_table(True)
        else:
            self._state["telemetry"] = self._get_telemetry()
            self._state["config"] = self._get_config()
            self._state["interfaces"] = self._client.get_interfaces()
            self._state["services"] = self._client.get_services()
            self._state["carp_interfaces"] = self._client.get_carp_interfaces()
            self._state["carp_status"] = self._client.get_carp_status()

            # calcule pps and kbps
            for interface_name in self._state["telemetry"]["interfaces"].keys():
                interface = dict_get(
                    self._state, f"telemetry.interfaces.{interface_name}")
                previous_interface = dict_get(
                    self._state, f"previous_state.telemetry.interfaces.{interface_name}")
                if previous_interface is None:
                    break
                update_time = dict_get(self._state, "update_time")
                previous_update_time = dict_get(
                    self._state, "previous_state.update_time")
                elapsed_time = update_time - previous_update_time

                for property in ["inpkts", "outpkts", "inpktspass", "outpktspass", "inpktsblock", "outpktsblock"]:
                    value = interface[property]
                    previous_value = previous_interface[property]
                    change = abs(value - previous_value)
                    pps = change / elapsed_time
                    interface[f"{property}_packets_per_second"] = int(round(pps, 0))

                for property in ["inbytes", "outbytes", "inbytespass", "outbytespass", "inbytesblock", "outbytesblock"]:
                    value = interface[property]
                    previous_value = previous_interface[property]
                    change = abs(value - previous_value)
                    # 1 Byte = 8 bits
                    # 1 byte is equal to 0.001 kilobytes
                    Bs = (change / elapsed_time)
                    
                    KBs = Bs / 1000
                    interface[f"{property}_kilobytes_per_second"] = int(round(KBs, 0))

                    #Kbs = KBs * 8
                    #interface[f"{property}_kilobits_per_second"] = round(Kbs, 2)
                    


class CoordinatorEntityManager():
    def __init__(self, hass: HomeAssistant, coordinator: DataUpdateCoordinator, config_entry: ConfigEntry, process_entities_callback, async_add_entities) -> None:
        self.hass = hass
        self.coordinator = coordinator
        self.config_entry = config_entry
        self.process_entities_callback = process_entities_callback
        self.async_add_entities = async_add_entities
        hass.data[DOMAIN][config_entry.entry_id][UNDO_UPDATE_LISTENER].append(coordinator.async_add_listener(self.process_entities))
        self.entity_unique_ids = set()

    def process_entities(self):
        entities = self.process_entities_callback(self.hass, self.config_entry)
        for entity in entities:
            unique_id = entity.unique_id
            if unique_id is None:
                raise Exception("unique_id is missing from entity")
            if unique_id not in self.entity_unique_ids:
                self.async_add_entities([entity])
                self.entity_unique_ids.add(unique_id)
                #print(f"{unique_id} registered")
            else:
                #print(f"{unique_id} already registered")
                pass

class PfSenseEntity(CoordinatorEntity, RestoreEntity):
    """base entity for pfSense"""
    @property
    def device_info(self):
        """Device info for the firewall."""
        state = self.coordinator.data
        model = state["host_firmware_version"]["platform"]
        manufacturer = "netgate"
        firmware = state["host_firmware_version"]["firmware"]["version"]

        device_info = {
            "identifiers": {(DOMAIN, self.pfsense_device_unique_id)},
            "name": self.pfsense_device_name,
        }

        device_info["model"] = model
        device_info["manufacturer"] = manufacturer
        device_info["sw_version"] = firmware

        return device_info

    @property
    def pfsense_device_name(self):
        if self.config_entry.title and len(self.config_entry.title) > 0:
            return self.config_entry.title
        return "{}.{}".format(self._get_pfsense_state_value("system_info.hostname"), self._get_pfsense_state_value("system_info.domain"))

    @property
    def pfsense_device_unique_id(self):
        return self._get_pfsense_state_value("system_info.netgate_device_id")

    def _get_pfsense_state_value(self, path, default=None):
        state = self.coordinator.data
        value = dict_get(state, path, default)

        return value
