"""Home Assistant integration for OPNsense firewalls.

This integration provides monitoring and control of OPNsense firewall devices,
including system information, network interfaces, firewall rules, DHCP leases,
and various other OPNsense features through the Home Assistant interface.
"""

from collections.abc import Mapping
from datetime import timedelta
import logging
from typing import Any

from aiopnsense import OPNsenseClient
from aiopnsense.exceptions import OPNsenseBelowMinFirmware, OPNsenseError, OPNsenseUnknownFirmware
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
from homeassistant.helpers import (
    config_validation as cv,
    device_registry as dr,
    entity_registry as er,
    issue_registry as ir,
)
from homeassistant.helpers.typing import ConfigType

from .const import (
    CONF_DEVICE_TRACKER_ENABLED,
    CONF_DEVICE_TRACKER_SCAN_INTERVAL,
    CONF_DEVICE_UNIQUE_ID,
    CONF_TLS_INSECURE,
    DEFAULT_DEVICE_TRACKER_ENABLED,
    DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SYNC_OPTION_VALUE,
    DEFAULT_TLS_INSECURE,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
    GRANULAR_SYNC_PREFIX,
    LOADED_PLATFORMS,
    OPNSENSE_CLIENT,
    OPNSENSE_LTD_FIRMWARE,
    OPNSENSE_MIN_FIRMWARE,
    PLATFORMS,
    SHOULD_RELOAD,
    VERSION,
)
from .coordinator import OPNsenseDataUpdateCoordinator
from .helpers import create_opnsense_client
from .models import OPNsenseData
from .services import async_setup_services

_LOGGER: logging.Logger = logging.getLogger(__name__)
CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)
LEGACY_RULE_ENTITY_TOKENS: tuple[str, ...] = (
    "_filter_",
    "_nat_port_forward_",
    "_nat_outbound_",
)
NATIVE_RULE_ENTITY_TOKENS: tuple[str, ...] = (
    "_firewall_rule_",
    "_firewall_nat_",
)


def _align_aiopnsense_log_level() -> None:
    """Mirror the integration log level onto aiopnsense when it is unset."""
    aiopnsense_logger = logging.getLogger("aiopnsense")
    if _LOGGER.level == logging.NOTSET or aiopnsense_logger.level != logging.NOTSET:
        return

    aiopnsense_logger.setLevel(_LOGGER.level)


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle config-entry option updates and schedule integration reload.

    Args:
        hass: Home Assistant instance.
        entry: OPNsense config entry whose options were updated.
    """
    # _LOGGER.debug("[async_update_listener] entry: %s", entry.as_dict())
    if getattr(entry.runtime_data, SHOULD_RELOAD, True):
        _LOGGER.info("[async_update_listener] Reloading")

        uid_prefix = entry.unique_id
        # _LOGGER.debug("[async_update_listener] uid_prefix: %s", uid_prefix)
        removal_prefixes: list[str] = []
        for item, prefix in GRANULAR_SYNC_PREFIX.items():
            if not entry.data.get(item, DEFAULT_SYNC_OPTION_VALUE):
                removal_prefixes.extend(prefix)
        _LOGGER.debug("[async_update_listener] removal_prefixes: %s", removal_prefixes)

        entity_registry = er.async_get(hass)
        for ent in er.async_entries_for_config_entry(
            registry=entity_registry, config_entry_id=entry.entry_id
        ):
            # _LOGGER.debug("[async_update_listener] ent: %s", ent)
            for pre in removal_prefixes:
                if ent.unique_id.startswith(f"{uid_prefix}_{pre}"):
                    _LOGGER.debug(
                        "[async_update_listener] removing entity_id: %s, unique_id: %s",
                        ent.entity_id,
                        ent.unique_id,
                    )
                    entity_registry.async_remove(ent.entity_id)
                    break
            else:
                for pre in NATIVE_RULE_ENTITY_TOKENS:
                    if ent.unique_id.startswith(f"{uid_prefix}{pre}"):
                        _LOGGER.debug(
                            "[async_update_listener] removing native entity_id: %s, unique_id: %s",
                            ent.entity_id,
                            ent.unique_id,
                        )
                        entity_registry.async_remove(ent.entity_id)
                        break
        dt_enabled = entry.options.get(CONF_DEVICE_TRACKER_ENABLED, DEFAULT_DEVICE_TRACKER_ENABLED)
        if not dt_enabled:
            device_registry = dr.async_get(hass)
            devices = dr.async_entries_for_config_entry(
                registry=device_registry, config_entry_id=entry.entry_id
            )
            # _LOGGER.debug("[async_update_listener] devices: %s", devices)
            for device in devices:
                if device.via_device_id:
                    _LOGGER.debug("[async_update_listener] removing device: %s", device.name)
                    device_registry.async_remove_device(device.id)
        hass.async_create_task(hass.config_entries.async_reload(entry.entry_id))
    else:
        _LOGGER.info("[async_update_listener] Not Reloading")
        setattr(entry.runtime_data, SHOULD_RELOAD, True)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up domain-level OPNsense services.

    Args:
        hass: Home Assistant instance.
        config: YAML configuration mapping (unused for config-entry setup).

    Returns:
        bool: Always `True` after service setup succeeds.
    """
    _align_aiopnsense_log_level()
    await async_setup_services(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up OPNsense integration state for a config entry.

    Args:
        hass: Home Assistant instance.
        entry: Config entry containing OPNsense connection credentials and options.

    Returns:
        bool: `True` when setup and initial refresh succeed; otherwise `False`.

    Raises:
        OPNsenseError: Raised when validation cannot complete because of
            authentication, privilege, firmware, or transport failures.
        TimeoutError: Raised when an initial OPNsense request times out during
            setup or the first coordinator refresh.
    """
    config: Mapping[str, Any] = entry.data
    options: Mapping[str, Any] = entry.options
    # _LOGGER.debug("[async_setup_entry] entry: %s", entry.as_dict())

    device_tracker_enabled: bool = options.get(
        CONF_DEVICE_TRACKER_ENABLED, DEFAULT_DEVICE_TRACKER_ENABLED
    )
    config_device_id: str = config[CONF_DEVICE_UNIQUE_ID]

    client: OPNsenseClient | None = None
    try:
        client = create_opnsense_client(
            hass=hass,
            url=config[CONF_URL],
            username=config[CONF_USERNAME],
            password=config[CONF_PASSWORD],
            verify_ssl=config.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
            name=entry.title,
        )
        try:
            await client.validate()
        except OPNsenseBelowMinFirmware, OPNsenseUnknownFirmware:
            _LOGGER.debug(
                "Client validation reported firmware issues; continuing to firmware probes"
            )
    except OPNsenseError:
        if client is not None:
            await client.async_close()
        raise

    scan_interval: int = options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    _LOGGER.info("Starting hass-opnsense %s", VERSION)

    coordinator = OPNsenseDataUpdateCoordinator(
        hass=hass,
        name=f"{entry.title} state",
        update_interval=timedelta(seconds=scan_interval),
        client=client,
        device_unique_id=config_device_id,
        config_entry=entry,
    )
    device_tracker_coordinator: OPNsenseDataUpdateCoordinator | None = None

    setup_succeeded: bool = False
    try:
        # Trigger repair task and shutdown if device id has changed
        router_device_id: str | None = await client.get_device_unique_id(
            expected_id=config_device_id
        )
        _LOGGER.debug(
            "[init async_setup_entry]: config device id: %s, router device id: %s",
            config_device_id,
            router_device_id,
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
                "In order to accommodate this, hass-opnsense needs to be removed "
                "and reinstalled for this router. "
                "hass-opnsense is shutting down."
            )
            return False

        firmware: str | None = await client.get_host_firmware_version()
        _LOGGER.info("OPNsense Firmware %s", firmware)
        try:
            if awesomeversion.AwesomeVersion(firmware) < awesomeversion.AwesomeVersion(
                OPNSENSE_MIN_FIRMWARE
            ):
                ir.async_create_issue(
                    hass,
                    DOMAIN,
                    f"{config_device_id}_opnsense_below_min_firmware_{OPNSENSE_MIN_FIRMWARE}",
                    is_fixable=False,
                    is_persistent=False,
                    issue_domain=DOMAIN,
                    severity=ir.IssueSeverity.ERROR,
                    translation_key="below_min_firmware",
                    translation_placeholders={
                        "version": str(VERSION),
                        "min_firmware": str(OPNSENSE_MIN_FIRMWARE),
                        "firmware": firmware or "Unknown",
                    },
                )
                return False
            if awesomeversion.AwesomeVersion(firmware) < awesomeversion.AwesomeVersion(
                OPNSENSE_LTD_FIRMWARE
            ):
                ir.async_create_issue(
                    hass,
                    DOMAIN,
                    f"{config_device_id}_opnsense_below_ltd_firmware_{OPNSENSE_LTD_FIRMWARE}",
                    is_fixable=False,
                    is_persistent=False,
                    issue_domain=DOMAIN,
                    severity=ir.IssueSeverity.WARNING,
                    translation_key="below_ltd_firmware",
                    translation_placeholders={
                        "version": str(VERSION),
                        "ltd_firmware": str(OPNSENSE_LTD_FIRMWARE),
                        "firmware": firmware or "Unknown",
                    },
                )
            else:
                ir.async_delete_issue(
                    hass,
                    DOMAIN,
                    f"{config_device_id}_opnsense_below_min_firmware_{OPNSENSE_MIN_FIRMWARE}",
                )
                ir.async_delete_issue(
                    hass,
                    DOMAIN,
                    f"{config_device_id}_opnsense_below_ltd_firmware_{OPNSENSE_LTD_FIRMWARE}",
                )
        except awesomeversion.exceptions.AwesomeVersionCompareException, TypeError, ValueError:
            _LOGGER.warning("Unable to confirm OPNsense Firmware version")

        await coordinator.async_config_entry_first_refresh()

        platforms: list[Platform] = PLATFORMS.copy()
        if not device_tracker_enabled and Platform.DEVICE_TRACKER in platforms:
            platforms.remove(Platform.DEVICE_TRACKER)
        else:
            device_tracker_scan_interval = options.get(
                CONF_DEVICE_TRACKER_SCAN_INTERVAL, DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL
            )

            device_tracker_coordinator = OPNsenseDataUpdateCoordinator(
                hass=hass,
                name=f"{entry.title} Device Tracker state",
                update_interval=timedelta(seconds=device_tracker_scan_interval),
                client=client,
                config_entry=entry,
                device_unique_id=config_device_id,
                device_tracker_coordinator=True,
            )

        entry.async_on_unload(entry.add_update_listener(_async_update_listener))

        hass.data.setdefault(DOMAIN, {})
        hass.data[DOMAIN][entry.entry_id] = client

        entry.runtime_data = OPNsenseData(
            coordinator=coordinator,
            device_tracker_coordinator=device_tracker_coordinator,
            opnsense_client=client,
            device_unique_id=config_device_id,
            loaded_platforms=platforms,
        )
        setup_succeeded = True

        if device_tracker_enabled and device_tracker_coordinator:
            # Fetch initial data so we have data when entities subscribe
            await device_tracker_coordinator.async_config_entry_first_refresh()

        await hass.config_entries.async_forward_entry_setups(entry, platforms)

        return True
    finally:
        if not setup_succeeded:
            if device_tracker_coordinator is not None:
                await device_tracker_coordinator.async_shutdown()
            await coordinator.async_shutdown()
            if DOMAIN in hass.data:
                hass.data[DOMAIN].pop(entry.entry_id, None)
            await client.async_close()


async def async_remove_config_entry_device(
    hass: HomeAssistant, config_entry: ConfigEntry, device_entry: dr.DeviceEntry
) -> bool:
    """Decide whether a device can be removed from this config entry.

    Args:
        hass: Home Assistant instance.
        config_entry: Config entry owning the target device.
        device_entry: Device registry entry proposed for removal.

    Returns:
        bool: `True` when the device has no linked entities and is not a tracker child.
    """
    if device_entry.via_device_id:
        _LOGGER.error("Remove OPNsense Device Tracker Devices via the Integration Configuration")
        return False
    entity_registry = er.async_get(hass)
    for ent in er.async_entries_for_config_entry(entity_registry, config_entry.entry_id):
        if ent.device_id == device_entry.id:
            _LOGGER.error("Cannot remove OPNsense Devices with linked entities at this time")
            return False
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload all platforms and runtime resources for a config entry.

    Args:
        hass: Home Assistant instance.
        entry: Config entry to unload.

    Returns:
        bool: `True` when platforms unload successfully, otherwise `False`.
    """
    _LOGGER.info("Unloading: %s", entry.as_dict())
    platforms: list[Platform] = getattr(entry.runtime_data, LOADED_PLATFORMS)
    client: OPNsenseClient = getattr(entry.runtime_data, OPNSENSE_CLIENT)
    unload_ok: bool = await hass.config_entries.async_unload_platforms(entry, platforms)

    await client.async_close()

    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)

    return unload_ok


async def _migrate_1_to_2(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Migrate config entry data from version 1 to version 2.

    Args:
        hass: Home Assistant instance.
        config_entry: Config entry being migrated.

    Returns:
        bool: Always `True` after updating entry data.
    """
    tls_insecure = config_entry.data.get(CONF_TLS_INSECURE, DEFAULT_TLS_INSECURE)
    data: dict[str, Any] = dict(config_entry.data)

    # remove tls_insecure
    data.pop(CONF_TLS_INSECURE, None)

    # add verify_ssl
    if CONF_VERIFY_SSL not in data:
        data[CONF_VERIFY_SSL] = not tls_insecure

    hass.config_entries.async_update_entry(config_entry, data=data, version=2)
    return True


async def _migrate_2_to_3(
    hass: HomeAssistant, config_entry: ConfigEntry, client: OPNsenseClient
) -> bool:
    """Migrate config entry identifiers from version 2 to version 3.

    Args:
        hass: Home Assistant instance.
        config_entry: Config entry being migrated.
        client: OPNsense client shared across API-backed migration steps.

    Returns:
        bool: `True` when device/entity identifier migration succeeds.
    """
    _LOGGER.debug("[migrate_2_to_3] Initial Version: %s", config_entry.version)
    entity_registry = er.async_get(hass)
    device_registry = dr.async_get(hass)

    new_device_unique_id: str | None = await client.get_device_unique_id()
    if not new_device_unique_id:
        _LOGGER.error("Missing Device Unique ID for Migration to Version 3")
        return False
    _LOGGER.debug("[migrate_2_to_3] new_device_unique_id: %s", new_device_unique_id)

    for dev in dr.async_entries_for_config_entry(
        device_registry, config_entry_id=config_entry.entry_id
    ):
        _LOGGER.debug("[migrate_2_to_3] dev: %s", dev)
        is_main_dev: bool = any(t[0] == "opnsense" for t in dev.identifiers)
        if is_main_dev:
            new_identifiers = {
                (t[0], new_device_unique_id) if t[0] == "opnsense" else t for t in dev.identifiers
            }
            _LOGGER.debug(
                "[migrate_2_to_3] dev.identifiers: %s, new_identifiers: %s",
                dev.identifiers,
                new_identifiers,
            )
            try:
                new_dev = device_registry.async_update_device(
                    dev.id, new_identifiers=new_identifiers
                )
                _LOGGER.debug("[migrate_2_to_3] new_main_dev: %s", new_dev)
            except dr.DeviceIdentifierCollisionError as e:
                _LOGGER.error(
                    "Error migrating device: %s. %s: %s",
                    dev.identifiers,
                    type(e).__name__,
                    e,
                )

    for ent in er.async_entries_for_config_entry(entity_registry, config_entry.entry_id):
        platform = ent.entity_id.split(".")[0]
        try:
            _, unique_id_suffix = ent.unique_id.split("_", 1)
        except ValueError:
            unique_id_suffix = f"mac_{ent.unique_id}"
        new_unique_id: str = (
            (f"{new_device_unique_id}_{unique_id_suffix}").replace(":", "_").strip()
        )
        _LOGGER.debug(
            "[migrate_2_to_3] ent: %s, platform: %s, unique_id: %s, new_unique_id: %s",
            ent.entity_id,
            platform,
            ent.unique_id,
            new_unique_id,
        )
        try:
            new_ent = entity_registry.async_update_entity(
                ent.entity_id, new_unique_id=new_unique_id
            )
            _LOGGER.debug(
                "[migrate_2_to_3] new_ent: %s, unique_id: %s",
                new_ent.entity_id,
                new_ent.unique_id,
            )
        except ValueError as e:
            _LOGGER.error(
                "Error migrating entity: %s. %s: %s",
                ent.entity_id,
                type(e).__name__,
                e,
            )

    new_data: dict[str, Any] = dict(config_entry.data)
    new_data.update({CONF_DEVICE_UNIQUE_ID: new_device_unique_id})
    _LOGGER.debug(
        "[migrate_2_to_3] data: %s, new_data: %s, unique_id: %s, new_unique_id: %s",
        config_entry.data,
        new_data,
        config_entry.unique_id,
        new_device_unique_id,
    )
    new_entry_bool = hass.config_entries.async_update_entry(
        config_entry, data=new_data, unique_id=new_device_unique_id, version=3
    )
    if new_entry_bool:
        _LOGGER.debug("[migrate_2_to_3] config_entry update successful")
    else:
        _LOGGER.error("Migration of config_entry to version 3 unsuccessful")
        return False
    return True


async def _migrate_3_to_4(
    hass: HomeAssistant, config_entry: ConfigEntry, client: OPNsenseClient
) -> bool:
    """Migrate telemetry entity identifiers from version 3 to version 4.

    Args:
        hass: Home Assistant instance.
        config_entry: Config entry being migrated.
        client: OPNsense client shared across API-backed migration steps.

    Returns:
        bool: `True` when all migration updates complete successfully.
    """
    _LOGGER.debug("[migrate_3_to_4] Initial Version: %s", config_entry.version)
    entity_registry = er.async_get(hass)

    telemetry = await client.get_telemetry()

    for ent in er.async_entries_for_config_entry(entity_registry, config_entry.entry_id):
        platform = ent.entity_id.split(".")[0]
        if platform == Platform.SENSOR:
            if "_telemetry_interface_" in ent.unique_id:
                new_unique_id: str | None = ent.unique_id.replace(
                    "_telemetry_interface_", "_interface_"
                )
            elif "_telemetry_gateway_" in ent.unique_id:
                new_unique_id = ent.unique_id.replace("_telemetry_gateway_", "_gateway_")
            elif "_connected_client_count" in ent.unique_id:
                try:
                    entity_registry.async_remove(ent.entity_id)
                    _LOGGER.debug("[migrate_3_to_4] removed_entity_id: %s", ent.entity_id)
                except (KeyError, ValueError) as e:
                    _LOGGER.error(
                        "Error removing entity: %s. %s: %s",
                        ent.entity_id,
                        type(e).__name__,
                        e,
                    )
                continue
            elif "_telemetry_openvpn_" in ent.unique_id:
                new_unique_id = ent.unique_id.replace("_telemetry_openvpn_", "_openvpn_")
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
                "[migrate_3_to_4] ent: %s, platform: %s, unique_id: %s, new_unique_id: %s",
                ent.entity_id,
                platform,
                ent.unique_id,
                new_unique_id,
            )
            if not new_unique_id:
                _LOGGER.error("Error migrating entity: %s", ent.entity_id)
                continue
            try:
                updated_ent = entity_registry.async_update_entity(
                    ent.entity_id, new_unique_id=new_unique_id
                )
                _LOGGER.debug(
                    "[migrate_3_to_4] updated_entity_id: %s, updated_unique_id: %s",
                    updated_ent.entity_id,
                    updated_ent.unique_id,
                )
            except ValueError as e:
                _LOGGER.error(
                    "Error migrating entity: %s. %s: %s",
                    ent.entity_id,
                    type(e).__name__,
                    e,
                )
    new_entry_bool = hass.config_entries.async_update_entry(config_entry, version=4)
    if new_entry_bool:
        _LOGGER.debug("[migrate_3_to_4] config_entry update successful")
    else:
        _LOGGER.error("Migration of config_entry to version 4 unsuccessful")
        return False
    return True


async def _migrate_4_to_5(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Prune stale legacy rule entities during migration from 4 to 5.

    Args:
        hass: Home Assistant instance.
        config_entry: Config entry being migrated.

    Returns:
        bool: `True` when legacy entities are removed and entry version is updated.
    """
    _LOGGER.debug("[migrate_4_to_5] Initial Version: %s", config_entry.version)
    entity_registry = er.async_get(hass)

    for ent in er.async_entries_for_config_entry(entity_registry, config_entry.entry_id):
        platform = ent.entity_id.split(".")[0]
        if platform != Platform.SWITCH:
            continue
        if any(token in ent.unique_id for token in LEGACY_RULE_ENTITY_TOKENS):
            try:
                entity_registry.async_remove(ent.entity_id)
                _LOGGER.debug("[migrate_4_to_5] removed entity_id: %s", ent.entity_id)
            except (KeyError, ValueError) as e:
                _LOGGER.error(
                    "Error removing entity: %s. %s: %s",
                    ent.entity_id,
                    type(e).__name__,
                    e,
                )

    migration_ok: bool = hass.config_entries.async_update_entry(config_entry, version=5)
    if not migration_ok:
        _LOGGER.error("Migration of config_entry to version 5 unsuccessful")
        return False

    _LOGGER.debug("[migrate_4_to_5] config_entry update successful")
    return True


async def async_migrate_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Migrate a stored config entry to the latest supported schema.

    Args:
        hass: Home Assistant instance.
        config_entry: Config entry to migrate.

    Returns:
        bool: `True` when all required migration steps succeed.
    """
    version = config_entry.version

    if version > 5:
        # This means the user has downgraded from a future version
        _LOGGER.error(
            "hass-opnsense downgraded and current config not compatible with earlier versions. "
            "Integration must be removed and reinstalled."
        )
        return False

    _LOGGER.debug("Migrating from version %s", version)

    # 1 -> 2: tls_insecure to verify_ssl
    if version == 1:
        v1to2: bool = await _migrate_1_to_2(hass, config_entry)
        if not v1to2:
            return False
        version = 2

    migration_client: OPNsenseClient | None = None
    try:
        if version in (2, 3):
            migration_client = create_opnsense_client(
                hass=hass,
                url=config_entry.data[CONF_URL],
                username=config_entry.data[CONF_USERNAME],
                password=config_entry.data[CONF_PASSWORD],
                verify_ssl=config_entry.data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
                name=config_entry.title,
            )

        # 2 -> 3: Change unique device id to use lowest MAC address
        if version == 2:
            if migration_client is None:
                _LOGGER.error("Missing migration client for Migration to Version 3")
                return False
            v2to3: bool = await _migrate_2_to_3(hass, config_entry, migration_client)
            if not v2to3:
                return False
            version = 3

        # 3 -> 4: Moving interfaces, gateways and openvpn out of telemetry
        if version == 3:
            if migration_client is None:
                _LOGGER.error("Missing migration client for Migration to Version 4")
                return False
            v3to4: bool = await _migrate_3_to_4(hass, config_entry, migration_client)
            if not v3to4:
                return False
            version = 4

        if version == 4:
            v4to5: bool = await _migrate_4_to_5(hass, config_entry)
            if not v4to5:
                return False
            version = 5
    finally:
        if migration_client is not None:
            await migration_client.async_close()

    _LOGGER.info("Migration to version %s successful", version)
    return True
