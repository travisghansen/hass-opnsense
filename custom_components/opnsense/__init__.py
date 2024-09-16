"""Support for OPNsense."""

from collections.abc import Mapping
from datetime import timedelta
import logging
from typing import Any, Callable

from awesomeversion import AwesomeVersion
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_URL,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.entity_registry import async_get
from homeassistant.helpers.issue_registry import IssueSeverity, async_create_issue
from homeassistant.helpers.restore_state import RestoreEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    CONF_DEVICE_TRACKER_ENABLED,
    CONF_DEVICE_TRACKER_SCAN_INTERVAL,
    CONF_TLS_INSECURE,
    COORDINATOR,
    DEFAULT_DEVICE_TRACKER_ENABLED,
    DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_TLS_INSECURE,
    DEFAULT_VERIFY_SSL,
    DEVICE_TRACKER_COORDINATOR,
    DOMAIN,
    LOADED_PLATFORMS,
    OPNSENSE_CLIENT,
    OPNSENSE_MIN_FIRMWARE,
    PLATFORMS,
    SHOULD_RELOAD,
    UNDO_UPDATE_LISTENER,
    VERSION,
)
from .coordinator import OPNsenseDataUpdateCoordinator
from .helpers import dict_get
from .pyopnsense import OPNsenseClient
from .services import ServiceRegistrar

_LOGGER: logging.Logger = logging.getLogger(__name__)


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle options update."""
    if hass.data[DOMAIN][entry.entry_id].get(SHOULD_RELOAD, True):
        hass.async_create_task(hass.config_entries.async_reload(entry.entry_id))
    else:
        hass.data[DOMAIN][entry.entry_id][SHOULD_RELOAD] = True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up OPNsense from a config entry."""
    config = entry.data
    options = entry.options

    url: str = config[CONF_URL]
    username: str = config[CONF_USERNAME]
    password: str = config[CONF_PASSWORD]
    verify_ssl: bool = config.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL)
    device_tracker_enabled: bool = options.get(
        CONF_DEVICE_TRACKER_ENABLED, DEFAULT_DEVICE_TRACKER_ENABLED
    )
    client = OPNsenseClient(
        url=url,
        username=username,
        password=password,
        session=async_create_clientsession(hass, raise_for_status=False),
        opts={"verify_ssl": verify_ssl},
    )

    scan_interval: int = options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    _LOGGER.info(f"Starting hass-opnsense {VERSION}")

    coordinator = OPNsenseDataUpdateCoordinator(
        hass=hass,
        name=f"{entry.title} state",
        update_interval=timedelta(seconds=scan_interval),
        client=client,
    )

    platforms: list = PLATFORMS.copy()
    device_tracker_coordinator = None
    if not device_tracker_enabled and "device_tracker" in platforms:
        platforms.remove("device_tracker")
    else:
        device_tracker_scan_interval = options.get(
            CONF_DEVICE_TRACKER_SCAN_INTERVAL, DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL
        )

        device_tracker_coordinator = OPNsenseDataUpdateCoordinator(
            hass=hass,
            name=f"{entry.title} Device Tracker state",
            update_interval=timedelta(seconds=device_tracker_scan_interval),
            client=client,
            device_tracker_coordinator=True,
        )

    undo_listener = entry.add_update_listener(_async_update_listener)

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        COORDINATOR: coordinator,
        DEVICE_TRACKER_COORDINATOR: device_tracker_coordinator,
        OPNSENSE_CLIENT: client,
        UNDO_UPDATE_LISTENER: [undo_listener],
        LOADED_PLATFORMS: platforms,
    }

    # Fetch initial data so we have data when entities subscribe
    await coordinator.async_config_entry_first_refresh()
    if device_tracker_enabled:
        # Fetch initial data so we have data when entities subscribe
        await device_tracker_coordinator.async_config_entry_first_refresh()

    firmware: str | None = coordinator.data.get("host_firmware_version", None)
    _LOGGER.info(f"OPNsense Firmware {firmware}")

    if AwesomeVersion(firmware) < AwesomeVersion(OPNSENSE_MIN_FIRMWARE):
        async_create_issue(
            hass,
            DOMAIN,
            f"opnsense_{firmware}_below_min_firmware_{OPNSENSE_MIN_FIRMWARE}",
            is_fixable=False,
            is_persistent=False,
            issue_domain=DOMAIN,
            severity=IssueSeverity.WARNING,
            translation_key="below_min_firmware",
            translation_placeholders={
                "version": VERSION,
                "min_firmware": OPNSENSE_MIN_FIRMWARE,
                "firmware": firmware,
            },
        )

    await hass.config_entries.async_forward_entry_setups(entry, platforms)

    service_registar = ServiceRegistrar(hass)
    service_registar.async_register()

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    platforms = hass.data[DOMAIN][entry.entry_id][LOADED_PLATFORMS]
    unload_ok = await hass.config_entries.async_unload_platforms(entry, platforms)

    for listener in hass.data[DOMAIN][entry.entry_id][UNDO_UPDATE_LISTENER]:
        listener()

    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok


async def async_migrate_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Migrate an old config entry."""
    version = config_entry.version

    _LOGGER.debug("Migrating from version %s", version)

    # 1 -> 2: tls_insecure to verify_ssl
    if version == 1:
        version = config_entry.version = 2
        tls_insecure = config_entry.data.get(CONF_TLS_INSECURE, DEFAULT_TLS_INSECURE)
        data = dict(config_entry.data)

        # remove tls_insecure
        if CONF_TLS_INSECURE in data.keys():
            del data[CONF_TLS_INSECURE]

        # add verify_ssl
        if CONF_VERIFY_SSL not in data.keys():
            data[CONF_VERIFY_SSL] = not tls_insecure

        hass.config_entries.async_update_entry(
            config_entry,
            data=data,
        )

        _LOGGER.info("Migration to version %s successful", version)

    return True


class CoordinatorEntityManager:

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: OPNsenseDataUpdateCoordinator,
        config_entry: ConfigEntry,
        process_entities_callback: Callable,
        async_add_entities: AddEntitiesCallback,
    ) -> None:
        self.hass = hass
        self.coordinator: OPNsenseDataUpdateCoordinator = coordinator
        self.config_entry = config_entry
        self.process_entities_callback = process_entities_callback
        self.async_add_entities = async_add_entities
        hass.data[DOMAIN][config_entry.entry_id][UNDO_UPDATE_LISTENER].append(
            coordinator.async_add_listener(self.process_entities)
        )
        self.entity_unique_ids = set()
        self.entities = {}

    @callback
    def process_entities(self):
        entities = self.process_entities_callback(self.hass, self.config_entry)
        i_entity_unqiue_ids = set()
        for entity in entities:
            unique_id = entity.unique_id
            if unique_id is None:
                raise Exception("unique_id is missing from entity")
            i_entity_unqiue_ids.add(unique_id)
            if unique_id not in self.entity_unique_ids:
                self.async_add_entities([entity])
                self.entity_unique_ids.add(unique_id)
                self.entities[unique_id] = entity
                # print(f"{unique_id} registered")
            else:
                # print(f"{unique_id} already registered")
                pass

        # check for missing entities
        for entity_unique_id in self.entity_unique_ids:
            if entity_unique_id not in i_entity_unqiue_ids:
                pass
                # print("should remove entity: " + str(self.entities[entity_unique_id].entry_id))
                # print("candidate to remove entity: " + str(entity_unique_id))
                # self.async_remove_entity(self.entities[entity_unique_id])
                # self.entity_unique_ids.remove(entity_unique_id)
                # del self.entities[entity_unique_id]

    async def async_remove_entity(self, entity):
        registry = await async_get(self.hass)
        if entity.entity_id in registry.entities:
            registry.async_remove(entity.entity_id)


class OPNsenseEntity(CoordinatorEntity, RestoreEntity):
    """Base entity for OPNsense"""

    @property
    def coordinator_context(self):
        return None

    @property
    def device_info(self) -> Mapping[str, Any]:
        """Device info for the firewall."""
        state: Mapping[str, Any] = self.coordinator.data
        model: str = "OPNsense"
        manufacturer: str = "Deciso B.V."
        if state is None:
            firmware: str | None = None
        else:
            firmware: str | None = state.get("host_firmware_version", None)

        device_info: Mapping[str, Any] = {
            "identifiers": {(DOMAIN, self.opnsense_device_unique_id)},
            "name": self.opnsense_device_name,
            "configuration_url": self.config_entry.data.get("url", None),
        }

        device_info["model"] = model
        device_info["manufacturer"] = manufacturer
        device_info["sw_version"] = firmware

        return device_info

    @property
    def opnsense_device_name(self) -> str:
        if self.config_entry.title and len(self.config_entry.title) > 0:
            return self.config_entry.title
        return "{}.{}".format(
            self._get_opnsense_state_value("system_info.hostname"),
            self._get_opnsense_state_value("system_info.domain"),
        )

    @property
    def opnsense_device_unique_id(self):
        return self._get_opnsense_state_value("system_info.device_id")

    def _get_opnsense_state_value(self, path, default=None):
        state = self.coordinator.data
        value = dict_get(state, path, default)

        return value

    def _get_opnsense_client(self) -> OPNsenseClient:
        return self.hass.data[DOMAIN][self.config_entry.entry_id][OPNSENSE_CLIENT]

    async def service_close_notice(self, id: int | str | None = None) -> None:
        client = self._get_opnsense_client()
        await client.close_notice(id)

    async def service_file_notice(self, **kwargs) -> None:
        client = self._get_opnsense_client()
        await client.file_notice(**kwargs)

    async def service_start_service(self, service_name: str) -> None:
        client = self._get_opnsense_client()
        await client.start_service(service_name)

    async def service_stop_service(self, service_name: str) -> None:
        client = self._get_opnsense_client()
        await client.stop_service(service_name)

    async def service_restart_service(
        self, service_name: str, only_if_running: bool = False
    ) -> None:
        client = self._get_opnsense_client()
        if only_if_running:
            await client.restart_service_if_running(service_name)
        else:
            await client.restart_service(service_name)

    async def service_system_halt(self) -> None:
        client = self._get_opnsense_client()
        await client.system_halt()

    async def service_system_reboot(self) -> None:
        client = self._get_opnsense_client()
        await client.system_reboot()

    async def service_send_wol(self, interface: str, mac: str) -> None:
        client = self._get_opnsense_client()
        await client.send_wol(interface, mac)
