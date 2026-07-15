"""Config-entry migrations for the OPNsense integration."""

from collections.abc import Mapping
import logging
from typing import Any

from aiopnsense import OPNsenseClient
from aiopnsense.exceptions import OPNsenseError
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_VERIFY_SSL, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.util import slugify

from .const import (
    CONF_DEVICE_UNIQUE_ID,
    CONF_SYNC_FIREWALL_AND_NAT,
    CONF_TLS_INSECURE,
    DEFAULT_SYNC_OPTION_VALUE,
    DEFAULT_TLS_INSECURE,
)
from .helpers import (
    firewall_nat_switch_unique_ids_from_payload,
    firewall_rule_switch_unique_ids_from_payload,
)

_LOGGER: logging.Logger = logging.getLogger(__name__)
LEGACY_RULE_ENTITY_TOKENS: tuple[str, ...] = (
    "_filter_",
    "_nat_port_forward_",
    "_nat_outbound_",
)
NATIVE_FIREWALL_RULE_ENTITY_MARKER = "_firewall_rule_"
NATIVE_FIREWALL_NAT_ENTITY_MARKER = "_firewall_nat_"
NATIVE_FIREWALL_NAT_SECTIONS: tuple[str, ...] = (
    "d_nat",
    "one_to_one",
    "source_nat",
    "npt",
)


def _is_firewall_sync_enabled(config_entry: ConfigEntry) -> bool:
    """Return whether the version 4 firewall/NAT migration should retain entities.

    The per-category setting is optional because non-granular entries omit all
    individual synchronization keys. Match runtime coordinator and switch setup
    by treating an omitted category key as enabled.

    Args:
        config_entry: Config entry containing synchronization settings.

    Returns:
        bool: ``True`` when firewall and NAT synchronization is enabled.
    """
    data = config_entry.data
    return bool(data.get(CONF_SYNC_FIREWALL_AND_NAT, DEFAULT_SYNC_OPTION_VALUE))


def _infer_native_nat_section_from_unique_id(unique_id: str) -> str | None:
    """Infer the NAT section name from a native NAT unique ID.

    Args:
        unique_id: Native NAT unique identifier from the entity registry.

    Returns:
        str | None: NAT section name when the unique ID is parseable.
    """
    suffix: str | None = (
        unique_id.split(NATIVE_FIREWALL_NAT_ENTITY_MARKER, maxsplit=1)[1]
        if NATIVE_FIREWALL_NAT_ENTITY_MARKER in unique_id
        else None
    )
    if suffix is None:
        return None

    for nat_section in NATIVE_FIREWALL_NAT_SECTIONS:
        prefix: str = f"{nat_section}_"
        if suffix.startswith(prefix):
            return nat_section
    return None


def _get_telemetry_filesystems(telemetry: object) -> list[Mapping[str, Any]] | None:
    """Return valid telemetry filesystem mappings from a migration payload.

    Args:
        telemetry: Raw telemetry payload returned by the OPNsense client.

    Returns:
        list[Mapping[str, Any]] | None: Filesystem mappings usable for entity
            ID remaps, or `None` when the telemetry payload cannot be trusted.
    """
    if not isinstance(telemetry, Mapping):
        return None

    filesystems = telemetry.get("filesystems")
    if not isinstance(filesystems, list):
        return None

    valid_filesystems: list[Mapping[str, Any]] = []
    for filesystem in filesystems:
        if not isinstance(filesystem, Mapping):
            return None
        device = filesystem.get("device")
        if not isinstance(device, str):
            return None
        mountpoint = filesystem.get("mountpoint")
        if not isinstance(mountpoint, str):
            return None
        valid_filesystems.append(filesystem)

    return valid_filesystems


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

    data.pop(CONF_TLS_INSECURE, None)

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
                _LOGGER.exception(
                    "Error migrating device: %s. %s",
                    dev.identifiers,
                    type(e).__name__,
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
            _LOGGER.exception(
                "Error migrating entity: %s. %s",
                ent.entity_id,
                type(e).__name__,
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
    filesystems = _get_telemetry_filesystems(telemetry)
    filesystem_migration_deferred = False

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
                    _LOGGER.exception(
                        "Error removing entity: %s. %s",
                        ent.entity_id,
                        type(e).__name__,
                    )
                continue
            elif "_telemetry_openvpn_" in ent.unique_id:
                new_unique_id = ent.unique_id.replace("_telemetry_openvpn_", "_openvpn_")
            elif "_telemetry_filesystems_" in ent.unique_id:
                telemetry_filesystem_prefix, unique_id_device_name = ent.unique_id.split(
                    "_telemetry_filesystems_", 1
                )
                unique_id_device_name = unique_id_device_name.lower()
                new_unique_id = None
                if filesystems is None:
                    filesystem_migration_deferred = True
                    continue
                for filesystem in filesystems:
                    device: str = filesystem.get("device", "")
                    device_name: str = device.replace("/", "_slash_").strip("_").lower()
                    if device_name == unique_id_device_name:
                        mpoint: str = filesystem.get("mountpoint", "")
                        if mpoint == "/":
                            mountpoint = "root"
                        else:
                            mountpoint = mpoint.replace("/", "_").strip("_")
                        new_unique_id = (
                            f"{telemetry_filesystem_prefix}_telemetry_filesystems_{mountpoint}"
                        )
                        break
            else:
                continue
            if new_unique_id is None:
                continue
            migrated_unique_id = new_unique_id
            if ent.unique_id == migrated_unique_id:
                continue
            _LOGGER.debug(
                "[migrate_3_to_4] ent: %s, platform: %s, unique_id: %s, new_unique_id: %s",
                ent.entity_id,
                platform,
                ent.unique_id,
                migrated_unique_id,
            )
            try:
                updated_ent = entity_registry.async_update_entity(
                    ent.entity_id, new_unique_id=migrated_unique_id
                )
                _LOGGER.debug(
                    "[migrate_3_to_4] updated_entity_id: %s, updated_unique_id: %s",
                    updated_ent.entity_id,
                    updated_ent.unique_id,
                )
            except ValueError as e:
                _LOGGER.exception(
                    "Error migrating entity: %s. %s",
                    ent.entity_id,
                    type(e).__name__,
                )
    if filesystem_migration_deferred:
        _LOGGER.error("Migration to version 4 deferred because filesystem telemetry is unavailable")
        return False
    new_entry_bool = hass.config_entries.async_update_entry(config_entry, version=4)
    if new_entry_bool:
        _LOGGER.debug("[migrate_3_to_4] config_entry update successful")
    else:
        _LOGGER.error("Migration of config_entry to version 4 unsuccessful")
        return False
    return True


async def _migrate_4_to_5(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    migration_client: OPNsenseClient | None,
) -> bool:
    """Prune stale rule switch entities during migration from 4 to 5.

    Args:
        hass: Home Assistant instance.
        config_entry: Config entry being migrated.
        migration_client: Client used to fetch current firewall rules.

    Returns:
        bool: `True` when rule entities are removed and entry version is updated.
    """
    _LOGGER.debug("[migrate_4_to_5] Initial Version: %s", config_entry.version)
    entity_registry = er.async_get(hass)
    entry_device_unique_id = config_entry.data.get(CONF_DEVICE_UNIQUE_ID)
    if not isinstance(entry_device_unique_id, str) or not entry_device_unique_id.strip():
        _LOGGER.warning("Migration to version 5 deferred because device unique ID is unavailable")
        return False
    entry_prefix = slugify(entry_device_unique_id)
    current_firewall_unique_ids: set[str] | None = None
    current_native_nat_unique_ids: dict[str, set[str]] = {}
    sync_firewall_rules = _is_firewall_sync_enabled(config_entry)

    if sync_firewall_rules:
        if migration_client is None:
            _LOGGER.error("Missing migration client for Migration to Version 5")
            return False
        try:
            firewall = await migration_client.get_firewall()
        except OPNsenseError as e:
            _LOGGER.warning(
                "Migration to version 5 deferred because current firewall rules are "
                "unavailable: %s",
                type(e).__name__,
            )
            return False

        if not isinstance(firewall, Mapping):
            _LOGGER.warning(
                "Migration to version 5 skipping native rule pruning because firewall payload is "
                "unavailable"
            )
        else:
            rules = firewall.get("rules")
            if isinstance(rules, Mapping):
                current_firewall_unique_ids = firewall_rule_switch_unique_ids_from_payload(
                    entry_device_unique_id,
                    rules,
                )
            else:
                _LOGGER.warning(
                    "Migration to version 5 skipping native firewall rule pruning because "
                    "firewall rules data is unavailable"
                )

            nat = firewall.get("nat")
            if isinstance(nat, Mapping):
                for nat_section in NATIVE_FIREWALL_NAT_SECTIONS:
                    nat_rules = nat.get(nat_section)
                    if isinstance(nat_rules, Mapping):
                        current_native_nat_unique_ids[nat_section] = (
                            firewall_nat_switch_unique_ids_from_payload(
                                entry_device_unique_id,
                                nat_section,
                                nat_rules,
                            )
                        )
                    else:
                        current_native_nat_unique_ids[nat_section] = set()

            elif nat is not None:
                _LOGGER.warning(
                    "Migration to version 5 skipping native NAT rule pruning because NAT "
                    "data is unavailable"
                )

    for ent in er.async_entries_for_config_entry(entity_registry, config_entry.entry_id):
        platform = ent.entity_id.split(".")[0]
        if platform != Platform.SWITCH:
            continue
        if not ent.unique_id.startswith(f"{entry_prefix}_"):
            continue
        should_remove = any(
            ent.unique_id.startswith(f"{entry_prefix}{token}")
            for token in LEGACY_RULE_ENTITY_TOKENS
        )
        if not should_remove and ent.unique_id.startswith(
            f"{entry_prefix}{NATIVE_FIREWALL_RULE_ENTITY_MARKER}"
        ):
            should_remove = not sync_firewall_rules or (
                current_firewall_unique_ids is not None
                and ent.unique_id not in current_firewall_unique_ids
            )
        elif not should_remove and ent.unique_id.startswith(
            f"{entry_prefix}{NATIVE_FIREWALL_NAT_ENTITY_MARKER}"
        ):
            should_remove = not sync_firewall_rules
            if sync_firewall_rules:
                nat_entity_section = _infer_native_nat_section_from_unique_id(ent.unique_id)
                if (
                    nat_entity_section is not None
                    and nat_entity_section in current_native_nat_unique_ids
                    and ent.unique_id not in current_native_nat_unique_ids[nat_entity_section]
                ):
                    should_remove = True
        if should_remove:
            try:
                entity_registry.async_remove(ent.entity_id)
                _LOGGER.debug("[migrate_4_to_5] removed entity_id: %s", ent.entity_id)
            except (KeyError, ValueError) as e:
                _LOGGER.exception(
                    "Error removing entity: %s. %s",
                    ent.entity_id,
                    type(e).__name__,
                )
                return False

    migration_ok: bool = hass.config_entries.async_update_entry(config_entry, version=5)
    if not migration_ok:
        _LOGGER.error("Migration of config_entry to version 5 unsuccessful")
        return False

    _LOGGER.debug("[migrate_4_to_5] config_entry update successful")
    return True
