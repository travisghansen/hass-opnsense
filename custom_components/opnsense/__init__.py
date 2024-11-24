"""Support for OPNsense."""

import logging
from collections.abc import Mapping
from datetime import timedelta
from typing import Any

import awesomeversion
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_URL,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    Platform,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.helpers.typing import ConfigType
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import slugify

from .const import (
    CONF_DEVICE_TRACKER_ENABLED,
    CONF_DEVICE_TRACKER_SCAN_INTERVAL,
    CONF_DEVICE_UNIQUE_ID,
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
    OPNSENSE_LTD_FIRMWARE,
    OPNSENSE_MIN_FIRMWARE,
    PLATFORMS,
    SHOULD_RELOAD,
    UNDO_UPDATE_LISTENER,
    VERSION,
)
from .coordinator import OPNsenseDataUpdateCoordinator
from .helpers import dict_get
from .pyopnsense import OPNsenseClient
from .services import async_setup_services

_LOGGER: logging.Logger = logging.getLogger(__name__)
CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle options update."""
    if hass.data[DOMAIN][entry.entry_id].get(SHOULD_RELOAD, True):
        hass.async_create_task(hass.config_entries.async_reload(entry.entry_id))
    else:
        hass.data[DOMAIN][entry.entry_id][SHOULD_RELOAD] = True


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    await async_setup_services(hass)
    return True


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
    config_device_id: str = config[CONF_DEVICE_UNIQUE_ID]

    client = OPNsenseClient(
        url=url,
        username=username,
        password=password,
        session=async_create_clientsession(hass, raise_for_status=False),
        opts={"verify_ssl": verify_ssl},
        name=entry.title,
    )

    scan_interval: int = options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    _LOGGER.info(f"Starting hass-opnsense {VERSION}")

    coordinator = OPNsenseDataUpdateCoordinator(
        hass=hass,
        name=f"{entry.title} state",
        update_interval=timedelta(seconds=scan_interval),
        client=client,
        device_unique_id=config_device_id,
    )

    # Trigger repair task and shutdown if device id has changed
    router_device_id: str = await client.get_device_unique_id()
    _LOGGER.debug(
        f"[init async_setup_entry]: config device id: {config_device_id}, router device id: {router_device_id}"
    )
    if router_device_id != config_device_id and router_device_id:
        ir.async_create_issue(
            hass=hass,
            domain=DOMAIN,
            issue_id=f"{config_device_id}_device_id_mismatched",
            is_fixable=False,
            is_persistent=False,
            severity=ir.IssueSeverity.ERROR,
            translation_key="device_id_mismatched",
        )
        _LOGGER.error(
            "OPNsense Device ID has changed which indicates new or changed hardware. "
            "In order to accomodate this, hass-opnsense needs to be removed and reinstalled for this router. "
            "hass-opnsense is shutting down."
        )
        await coordinator.async_shutdown()
        return False

    firmware: str | None = await client.get_host_firmware_version()
    _LOGGER.info(f"OPNsense Firmware {firmware}")
    try:
        if awesomeversion.AwesomeVersion(firmware) < awesomeversion.AwesomeVersion(
            OPNSENSE_MIN_FIRMWARE
        ):
            ir.async_create_issue(
                hass,
                DOMAIN,
                f"opnsense_{firmware}_below_min_firmware_{OPNSENSE_MIN_FIRMWARE}",
                is_fixable=False,
                is_persistent=False,
                issue_domain=DOMAIN,
                severity=ir.IssueSeverity.ERROR,
                translation_key="below_min_firmware",
                translation_placeholders={
                    "version": VERSION,
                    "min_firmware": OPNSENSE_MIN_FIRMWARE,
                    "firmware": firmware,
                },
            )
            await coordinator.async_shutdown()
            return False
        if awesomeversion.AwesomeVersion(firmware) < awesomeversion.AwesomeVersion(
            OPNSENSE_LTD_FIRMWARE
        ):
            ir.async_create_issue(
                hass,
                DOMAIN,
                f"opnsense_{firmware}_below_ltd_firmware_{OPNSENSE_LTD_FIRMWARE}",
                is_fixable=False,
                is_persistent=False,
                issue_domain=DOMAIN,
                severity=ir.IssueSeverity.WARNING,
                translation_key="below_ltd_firmware",
                translation_placeholders={
                    "version": VERSION,
                    "ltd_firmware": OPNSENSE_LTD_FIRMWARE,
                    "firmware": firmware,
                },
            )
        else:
            ir.async_delete_issue(
                hass,
                DOMAIN,
                f"opnsense_{firmware}_below_min_firmware_{OPNSENSE_MIN_FIRMWARE}",
            )
            ir.async_delete_issue(
                hass,
                DOMAIN,
                f"opnsense_{firmware}_below_ltd_firmware_{OPNSENSE_LTD_FIRMWARE}",
            )
    except awesomeversion.exceptions.AwesomeVersionCompareException:
        _LOGGER.warning("Unable to confirm OPNsense Firmware version")
        pass

    await coordinator.async_config_entry_first_refresh()

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
            device_unique_id=config_device_id,
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
        CONF_DEVICE_UNIQUE_ID: config_device_id,
    }

    if device_tracker_enabled:
        # Fetch initial data so we have data when entities subscribe
        await device_tracker_coordinator.async_config_entry_first_refresh()

    await hass.config_entries.async_forward_entry_setups(entry, platforms)

    return True


async def async_remove_config_entry_device(
    hass: HomeAssistant, config_entry: ConfigEntry, device_entry: dr.DeviceEntry
) -> bool:
    """Allows removing OPNsense Devices that aren't Device Tracker Devices and without any linked entities"""

    if device_entry.via_device_id:
        _LOGGER.error(
            "Remove OPNsense Device Tracker Devices via the Integration Configuration"
        )
        return False
    entity_registry = er.async_get(hass)
    for ent in er.async_entries_for_config_entry(
        entity_registry, config_entry.entry_id
    ):
        if ent.device_id == device_entry.id:
            _LOGGER.error(
                "Cannot remove OPNsense Devices with linked entities at this time"
            )
            return False
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


async def _migrate_1_to_2(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    tls_insecure = config_entry.data.get(CONF_TLS_INSECURE, DEFAULT_TLS_INSECURE)
    data = dict(config_entry.data)

    # remove tls_insecure
    if CONF_TLS_INSECURE in data.keys():
        del data[CONF_TLS_INSECURE]

    # add verify_ssl
    if CONF_VERIFY_SSL not in data.keys():
        data[CONF_VERIFY_SSL] = not tls_insecure

    hass.config_entries.async_update_entry(config_entry, data=data, version=2)
    return True


async def _migrate_2_to_3(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    _LOGGER.debug(f"[migrate_2_to_3] Initial Version: {config_entry.version}")
    entity_registry = er.async_get(hass)
    device_registry = dr.async_get(hass)

    config = config_entry.data
    url: str = config[CONF_URL]
    username: str = config[CONF_USERNAME]
    password: str = config[CONF_PASSWORD]
    verify_ssl: bool = config.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL)

    client = OPNsenseClient(
        url=url,
        username=username,
        password=password,
        session=async_create_clientsession(hass, raise_for_status=False),
        opts={"verify_ssl": verify_ssl},
    )
    new_device_unique_id: str | None = await client.get_device_unique_id()
    if not new_device_unique_id:
        _LOGGER.error("Missing Device Unique ID for Migration to Version 3")
        return False
    _LOGGER.debug(f"[migrate_2_to_3] new_device_unique_id: {new_device_unique_id}")

    for dev in dr.async_entries_for_config_entry(
        device_registry, config_entry_id=config_entry.entry_id
    ):
        _LOGGER.debug(f"[migrate_2_to_3] dev: {dev}")
        is_main_dev: bool = any(t[0] == "opnsense" for t in dev.identifiers)
        if is_main_dev:
            new_identifiers = {
                (t[0], new_device_unique_id) if t[0] == "opnsense" else t
                for t in dev.identifiers
            }
            _LOGGER.debug(
                f"[migrate_2_to_3] dev.identifiers: {dev.identifiers}, new_identifiers: {new_identifiers}"
            )
            try:
                new_dev = device_registry.async_update_device(
                    dev.id, new_identifiers=new_identifiers
                )
                _LOGGER.debug(f"[migrate_2_to_3] new_main_dev: {new_dev}")
            except dr.DeviceIdentifierCollisionError as e:
                _LOGGER.error(
                    f"Error migrating device: {dev.identifiers}. {e.__class__.__qualname__}: {e}"
                )

    for ent in er.async_entries_for_config_entry(
        entity_registry, config_entry.entry_id
    ):
        # _LOGGER.debug(f"[migrate_2_to_3] ent: {ent}")
        platform = ent.entity_id.split(".")[0]
        try:
            _, unique_id_suffix = ent.unique_id.split("_", 1)
        except ValueError:
            unique_id_suffix: str = f"mac_{ent.unique_id}"
        new_unique_id: str = (
            (f"{new_device_unique_id}_{unique_id_suffix}").replace(":", "_").strip()
        )
        _LOGGER.debug(
            f"[migrate_2_to_3] ent: {ent.entity_id}, platform: {platform}, unique_id: {ent.unique_id}, new_unique_id: {new_unique_id}"
        )
        try:
            new_ent = entity_registry.async_update_entity(
                ent.entity_id, new_unique_id=new_unique_id
            )
            _LOGGER.debug(
                f"[migrate_2_to_3] new_ent: {new_ent.entity_id}, unique_id: {new_ent.unique_id}"
            )
        except ValueError as e:
            _LOGGER.error(
                f"Error migrating entity: {ent.entity_id}. {e.__class__.__qualname__}: {e}"
            )

    new_data: Mapping[str, Any] = dict(config_entry.data)
    new_data.update({CONF_DEVICE_UNIQUE_ID: new_device_unique_id})
    _LOGGER.debug(
        f"[migrate_2_to_3] data: {config_entry.data}, new_data: {new_data}, unique_id: {config_entry.unique_id}, new_unique_id: {new_device_unique_id}"
    )
    new_entry_bool = hass.config_entries.async_update_entry(
        config_entry, data=new_data, unique_id=new_device_unique_id, version=3
    )
    if new_entry_bool:
        _LOGGER.debug("[migrate_2_to_3] config_entry update sucessful")
    else:
        _LOGGER.error("Migration of config_entry to version 3 unsucessful")
        return False
    return True


async def _migrate_3_to_4(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    _LOGGER.debug(f"[migrate_3_to_4] Initial Version: {config_entry.version}")
    entity_registry = er.async_get(hass)

    config = config_entry.data
    url: str = config[CONF_URL]
    username: str = config[CONF_USERNAME]
    password: str = config[CONF_PASSWORD]
    verify_ssl: bool = config.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL)

    client = OPNsenseClient(
        url=url,
        username=username,
        password=password,
        session=async_create_clientsession(hass, raise_for_status=False),
        opts={"verify_ssl": verify_ssl},
    )
    telemetry: str | None = await client.get_telemetry()

    for ent in er.async_entries_for_config_entry(
        entity_registry, config_entry.entry_id
    ):
        platform = ent.entity_id.split(".")[0]
        if platform == Platform.SENSOR:
            # _LOGGER.debug(f"[migrate_3_to_4] ent: {ent}")
            if "_telemetry_interface_" in ent.unique_id:
                new_unique_id: str = ent.unique_id.replace(
                    "_telemetry_interface_", "_interface_"
                )
            elif "_telemetry_gateway_" in ent.unique_id:
                new_unique_id: str = ent.unique_id.replace(
                    "_telemetry_gateway_", "_gateway_"
                )
            elif "_connected_client_count" in ent.unique_id:
                try:
                    entity_registry.async_remove(ent.entity_id)
                    _LOGGER.debug(
                        f"[migrate_3_to_4] removed_entity_id: {ent.entity_id}"
                    )
                except (KeyError, ValueError) as e:
                    _LOGGER.error(
                        f"Error removing entity: {ent.entity_id}. {e.__class__.__qualname__}: {e}"
                    )
                continue
            elif "_telemetry_openvpn_" in ent.unique_id:
                new_unique_id: str = ent.unique_id.replace(
                    "_telemetry_openvpn_", "_openvpn_"
                )
            elif "_telemetry_filesystems_" in ent.unique_id:
                new_unique_id = None
                for filesystem in telemetry.get("filesystems", []):
                    device_name: str = (
                        filesystem.get("device", "").replace("/", "_slash_").strip("_")
                    ).lower()
                    unique_id_device_name: str = (
                        ent.unique_id.split("_telemetry_filesystems_")[1]
                    ).lower()
                    if device_name == unique_id_device_name:
                        mpoint: str = filesystem.get("mountpoint", "")
                        if mpoint == "/":
                            mountpoint = "root"
                        else:
                            mountpoint = mpoint.replace("/", "_").strip("_")
                        new_unique_id = ent.unique_id.replace(device_name, mountpoint)
                        break
                if not new_unique_id or ent.unique_id == new_unique_id:
                    continue
            else:
                continue
            _LOGGER.debug(
                f"[migrate_3_to_4] ent: {ent.entity_id}, platform: {platform}, unique_id: {ent.unique_id}, new_unique_id: {new_unique_id}"
            )
            try:
                updated_ent = entity_registry.async_update_entity(
                    ent.entity_id, new_unique_id=new_unique_id
                )
                _LOGGER.debug(
                    f"[migrate_3_to_4] updated_entity_id: {updated_ent.entity_id}, updated_unique_id: {updated_ent.unique_id}"
                )
            except ValueError as e:
                _LOGGER.error(
                    f"Error migrating entity: {ent.entity_id}. {e.__class__.__qualname__}: {e}"
                )
    new_entry_bool = hass.config_entries.async_update_entry(config_entry, version=4)
    if new_entry_bool:
        _LOGGER.debug("[migrate_3_to_4] config_entry update sucessful")
    else:
        _LOGGER.error("Migration of config_entry to version 4 unsucessful")
        return False
    return True


async def async_migrate_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Migrate an old config entry."""
    version = config_entry.version

    if version > 4:
        # This means the user has downgraded from a future version
        _LOGGER.error(
            "hass-opnsense downgraded and current config not compatible with earlier versions. Integration mut be removed and reinstalled."
        )
        return False

    _LOGGER.debug("Migrating from version %s", version)

    # 1 -> 2: tls_insecure to verify_ssl
    if version == 1:
        v1to2: bool = await _migrate_1_to_2(hass, config_entry)
        if not v1to2:
            return False
        version = 2

    # 2 -> 3: Change unique device id to use lowest MAC address
    if version == 2:
        v2to3: bool = await _migrate_2_to_3(hass, config_entry)
        if not v2to3:
            return False
        version = 3

    # 3 -> 4: Moving interfaces, gateways and openvpn out of telemetry
    if version == 3:
        v3to4: bool = await _migrate_3_to_4(hass, config_entry)
        if not v3to4:
            return False
        version = 4

    _LOGGER.info("Migration to version %s successful", version)
    return True


class OPNsenseEntity(CoordinatorEntity[OPNsenseDataUpdateCoordinator]):
    """Base entity for OPNsense"""

    def __init__(
        self,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        unique_id_suffix: str | None = None,
        name_suffix: str | None = None,
    ) -> None:
        self.config_entry: ConfigEntry = config_entry
        self.coordinator: OPNsenseDataUpdateCoordinator = coordinator
        self._device_unique_id: str = config_entry.data.get(CONF_DEVICE_UNIQUE_ID)
        if unique_id_suffix:
            self._attr_unique_id: str = slugify(
                f"{self._device_unique_id}_{unique_id_suffix}"
            )
        if name_suffix:
            self._attr_name: str = (
                f"{self.opnsense_device_name or 'OPNsense'} {name_suffix}"
            )
        self._client: OPNsenseClient | None = None
        self._attr_extra_state_attributes: Mapping[str, Any] = {}
        self._available: bool = False
        super().__init__(self.coordinator, self._attr_unique_id)

    @property
    def available(self) -> bool:
        return self._available

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
            "identifiers": {(DOMAIN, self._device_unique_id)},
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
        return self._get_opnsense_state_value("system_info.name")

    def _get_opnsense_state_value(self, path, default=None):
        state = self.coordinator.data
        value = dict_get(state, path, default)

        return value

    def _get_opnsense_client(self) -> OPNsenseClient | None:
        if self.hass is None:
            return None
        return self.hass.data[DOMAIN][self.config_entry.entry_id][OPNSENSE_CLIENT]

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        if self._client is None:
            self._client: OPNsenseClient = self._get_opnsense_client()
        if self._client is None:
            _LOGGER.error("Unable to get client in async_added_to_hass.")
        self._handle_coordinator_update()
