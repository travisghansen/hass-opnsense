"""Home Assistant integration for OPNsense firewalls.

This integration provides monitoring and control of OPNsense firewall devices,
including system information, network interfaces, firewall rules, DHCP leases,
and various other OPNsense features through the Home Assistant interface.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
import logging
from typing import Any

from aiopnsense import OPNsenseClient
from aiopnsense.exceptions import (
    OPNsenseBelowMinFirmware,
    OPNsenseError,
    OPNsenseMissingDeviceUniqueID,
    OPNsenseUnknownFirmware,
)
import awesomeversion
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_SCAN_INTERVAL, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import (
    config_validation as cv,
    device_registry as dr,
    entity_registry as er,
    issue_registry as ir,
)
from homeassistant.helpers.typing import ConfigType
from homeassistant.util import slugify

from .const import (
    CONF_DEVICE_TRACKER_ENABLED,
    CONF_DEVICE_TRACKER_SCAN_INTERVAL,
    CONF_DEVICE_UNIQUE_ID,
    DEFAULT_DEVICE_TRACKER_ENABLED,
    DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SYNC_OPTION_VALUE,
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
from .helpers import create_opnsense_client_from_config_entry
from .migrate import (
    _is_firewall_sync_enabled,
    _migrate_1_to_2,
    _migrate_2_to_3,
    _migrate_3_to_4,
    _migrate_4_to_5,
)
from .services import async_setup_services

_LOGGER: logging.Logger = logging.getLogger(__name__)
CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)
NATIVE_RULE_ENTITY_TOKENS: tuple[str, ...] = (
    "_firewall_rule_",
    "_firewall_nat_",
)


@dataclass
class OPNsenseData:
    """Runtime data for the OPNsense integration."""

    coordinator: OPNsenseDataUpdateCoordinator
    device_tracker_coordinator: OPNsenseDataUpdateCoordinator | None
    opnsense_client: OPNsenseClient
    loaded_platforms: list[Platform]
    device_unique_id: str | None
    should_reload: bool = True


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

        uid_prefix: str | None = slugify(entry.unique_id or "")
        if not uid_prefix:
            _LOGGER.debug("[async_update_listener] Skipping entity cleanup; empty entry uid prefix")
            uid_prefix = None
        sync_firewall_and_nat_enabled = _is_firewall_sync_enabled(entry)
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
            if uid_prefix is None or not ent.unique_id.startswith(f"{uid_prefix}_"):
                continue
            # _LOGGER.debug("[async_update_listener] ent: %s", ent)
            removed = False
            for pre in removal_prefixes:
                if ent.unique_id.startswith(f"{uid_prefix}_{pre}"):
                    _LOGGER.debug(
                        "[async_update_listener] removing entity_id: %s, unique_id: %s",
                        ent.entity_id,
                        ent.unique_id,
                    )
                    entity_registry.async_remove(ent.entity_id)
                    removed = True
                    break
            if removed:
                continue
            if not sync_firewall_and_nat_enabled:
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
        client = create_opnsense_client_from_config_entry(hass=hass, config_entry=entry)
        try:
            await client.validate()
        except OPNsenseMissingDeviceUniqueID:
            _LOGGER.debug(
                "Client validation reported missing device id; continuing to device-id probes"
            )
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

        hass.data.setdefault(DOMAIN, {})
        hass.data[DOMAIN][entry.entry_id] = client

        entry.runtime_data = OPNsenseData(
            coordinator=coordinator,
            device_tracker_coordinator=device_tracker_coordinator,
            opnsense_client=client,
            device_unique_id=config_device_id,
            loaded_platforms=platforms,
        )

        if device_tracker_enabled and device_tracker_coordinator:
            # Fetch initial data so we have data when entities subscribe
            await device_tracker_coordinator.async_config_entry_first_refresh()

        await hass.config_entries.async_forward_entry_setups(entry, platforms)
        entry.async_on_unload(entry.add_update_listener(_async_update_listener))

        setup_succeeded = True
        return True
    finally:
        if not setup_succeeded:
            entry.runtime_data = None
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

    if unload_ok:
        await client.async_close()
        hass.data[DOMAIN].pop(entry.entry_id, None)

    return unload_ok


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
        sync_enabled = _is_firewall_sync_enabled(config_entry)
        if version in (2, 3) or (version == 4 and sync_enabled):
            try:
                migration_client = create_opnsense_client_from_config_entry(
                    hass=hass,
                    config_entry=config_entry,
                    throw_errors=True,
                )
            except OPNsenseError:
                _LOGGER.warning("Deferring migration due to an OPNsense client error")
                return False

        # 2 -> 3: Change unique device id to use lowest MAC address
        if version == 2:
            if migration_client is None:
                _LOGGER.error("Missing migration client for Migration to Version 3")
                return False
            try:
                v2to3: bool = await _migrate_2_to_3(hass, config_entry, migration_client)
            except OPNsenseError:
                _LOGGER.warning("Deferring migration to version 3 due to an OPNsense API error")
                return False
            if not v2to3:
                return False
            version = 3

        # 3 -> 4: Moving interfaces, gateways and openvpn out of telemetry
        if version == 3:
            if migration_client is None:
                _LOGGER.error("Missing migration client for Migration to Version 4")
                return False
            try:
                v3to4: bool = await _migrate_3_to_4(hass, config_entry, migration_client)
            except OPNsenseError:
                _LOGGER.warning("Deferring migration to version 4 due to an OPNsense API error")
                return False
            if not v3to4:
                return False
            version = 4

        if version == 4:
            v4to5: bool = await _migrate_4_to_5(hass, config_entry, migration_client)
            if not v4to5:
                return False
            version = 5
    finally:
        if migration_client is not None:
            await migration_client.async_close()

    _LOGGER.info("Migration to version %s successful", version)
    return True
