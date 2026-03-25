"""Provides sensors to track various status aspects of OPNsense."""

from collections.abc import Mapping, MutableMapping
import inspect
import logging
import re
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    PERCENTAGE,
    UnitOfDataRate,
    UnitOfInformation,
    UnitOfTemperature,
    UnitOfTime,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util import slugify
from homeassistant.util.dt import utc_from_timestamp

from .const import (
    CONF_SYNC_CARP,
    CONF_SYNC_CERTIFICATES,
    CONF_SYNC_DHCP_LEASES,
    CONF_SYNC_GATEWAYS,
    CONF_SYNC_INTERFACES,
    CONF_SYNC_SPEEDTEST,
    CONF_SYNC_TELEMETRY,
    CONF_SYNC_VNSTAT,
    CONF_SYNC_VPN,
    COORDINATOR,
    COUNT,
    DATA_PACKETS,
    DATA_RATE_PACKETS_PER_SECOND,
    DEFAULT_SYNC_OPTION_VALUE,
    OPNSENSE_CLIENT,
    STATIC_CERTIFICATE_SENSORS,
    STATIC_TELEMETRY_SENSORS,
)
from .coordinator import OPNsenseDataUpdateCoordinator
from .entity import OPNsenseEntity
from .helpers import dict_get

_LOGGER: logging.Logger = logging.getLogger(__name__)


def _build_interface_device_description_map(
    interfaces: Mapping[str, Any] | None,
) -> dict[str, str]:
    """Build lookup map from interface device/identifier names to friendly descriptions.

    Args:
        interfaces: Interface payload in ``get_interfaces`` shape.

    Returns:
        dict[str, str]: Mapping of possible interface identifiers (device, logical name, key) to user-facing description names.
    """
    if not isinstance(interfaces, Mapping):
        return {}

    descriptions: dict[str, str] = {}
    for interface_key, interface_data in interfaces.items():
        if not isinstance(interface_data, Mapping):
            continue

        friendly_name = interface_data.get("name")
        if not isinstance(friendly_name, str) or not friendly_name.strip():
            continue
        friendly_name = friendly_name.strip()

        for candidate in (
            interface_data.get("device"),
            interface_data.get("interface"),
            interface_key,
        ):
            if isinstance(candidate, str) and candidate.strip():
                descriptions[candidate.strip()] = friendly_name

    return descriptions


async def _resolve_vnstat_interface_descriptions(
    config_entry: ConfigEntry,
    state: MutableMapping[str, Any],
) -> dict[str, str]:
    """Resolve vnStat interface display names from existing state with client fallback.

    Args:
        config_entry: Config entry containing runtime client reference.
        state: Coordinator state payload.

    Returns:
        dict[str, str]: Interface identifier to description mapping used for sensor naming.
    """
    descriptions = _build_interface_device_description_map(dict_get(state, "interfaces", {}) or {})
    if descriptions:
        return descriptions

    client = getattr(config_entry.runtime_data, OPNSENSE_CLIENT, None)
    if client is None:
        return descriptions

    get_interfaces = getattr(client, "get_interfaces", None)
    if not callable(get_interfaces):
        return descriptions

    maybe_interfaces = get_interfaces()
    if not inspect.isawaitable(maybe_interfaces):
        return descriptions

    interfaces = await maybe_interfaces
    if isinstance(interfaces, Mapping):
        descriptions = _build_interface_device_description_map(interfaces)
    return descriptions


def _vnstat_metric_display_name(metric_name: str) -> str:
    """Return display label for vnStat metric names.

    Args:
        metric_name: Internal vnStat metric key.

    Returns:
        str: Human-readable metric label for the entity name.
    """
    metric_names: dict[str, str] = {
        "vnstat_today": "Today",
        "vnstat_this_month": "This Month",
        "vnstat_yesterday": "Yesterday",
        "vnstat_last_month": "Last Month",
        "vnstat_last_hour": "Last Hour",
    }
    return metric_names.get(metric_name, metric_name)


async def _compile_static_telemetry_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
) -> list:
    """Compile static telemetry sensors.

    Args:
        config_entry: Config entry being exercised by the helper or test.
        coordinator: Data update coordinator that caches OPNsense state for entities.
    """
    entities: list = []
    for static_sensor in STATIC_TELEMETRY_SENSORS.values():
        entity = OPNsenseStaticKeySensor(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=static_sensor,
        )
        entities.append(entity)
    return entities


async def _compile_static_certificate_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
) -> list:
    """Compile static certificate sensors.

    Args:
        config_entry: Config entry being exercised by the helper or test.
        coordinator: Data update coordinator that caches OPNsense state for entities.
    """
    entities: list = []
    for static_sensor in STATIC_CERTIFICATE_SENSORS.values():
        entity = OPNsenseStaticKeySensor(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=static_sensor,
        )
        entities.append(entity)
    return entities


async def _compile_vnstat_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile per-interface vnStat sensors."""
    if not isinstance(state, MutableMapping):
        return []
    vnstat_interfaces = dict_get(state, "vnstat.interfaces", {}) or {}
    if not isinstance(vnstat_interfaces, MutableMapping):
        return []
    interface_descriptions = await _resolve_vnstat_interface_descriptions(config_entry, state)

    metric_defs: dict[str, dict[str, Any]] = {
        "vnstat_today": {
            "state_class": SensorStateClass.TOTAL_INCREASING,
            "icon": "mdi:calendar-today",
        },
        "vnstat_this_month": {
            "state_class": SensorStateClass.TOTAL_INCREASING,
            "icon": "mdi:calendar-month",
        },
        "vnstat_yesterday": {
            "state_class": SensorStateClass.MEASUREMENT,
            "icon": "mdi:calendar-arrow-left",
        },
        "vnstat_last_month": {
            "state_class": SensorStateClass.MEASUREMENT,
            "icon": "mdi:calendar-text",
        },
        "vnstat_last_hour": {
            "state_class": SensorStateClass.MEASUREMENT,
            "icon": "mdi:clock-time-four-outline",
        },
    }

    entities: list = []
    for interface_name in vnstat_interfaces:
        if not isinstance(interface_name, str):
            continue
        interface_display_name = interface_descriptions.get(interface_name, interface_name)
        for metric_name, metric_def in metric_defs.items():
            entity = OPNsenseVnstatSensor(
                config_entry=config_entry,
                coordinator=coordinator,
                entity_description=SensorEntityDescription(
                    key=f"vnstat.{interface_name}.{metric_name}",
                    name=f"vnStat: {interface_display_name}: {_vnstat_metric_display_name(metric_name)}",
                    native_unit_of_measurement=UnitOfInformation.BYTES,
                    device_class=SensorDeviceClass.DATA_SIZE,
                    icon=metric_def["icon"],
                    state_class=metric_def["state_class"],
                    suggested_display_precision=1,
                    suggested_unit_of_measurement=UnitOfInformation.GIBIBYTES,
                    entity_registry_enabled_default=False,
                ),
            )
            entities.append(entity)
    return entities


async def _compile_speedtest_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile speedtest sensors from normalized coordinator state."""
    if not isinstance(state, MutableMapping):
        return []
    speedtest = state.get("speedtest")
    if not isinstance(speedtest, MutableMapping) or not speedtest.get("available", False):
        return []

    metric_definitions: tuple[tuple[str, str, Any, str], ...] = (
        (
            "speedtest.last.download",
            "Speedtest Last Download",
            UnitOfDataRate.MEGABITS_PER_SECOND,
            "mdi:download-network",
        ),
        (
            "speedtest.last.upload",
            "Speedtest Last Upload",
            UnitOfDataRate.MEGABITS_PER_SECOND,
            "mdi:upload-network",
        ),
        (
            "speedtest.last.latency",
            "Speedtest Last Latency",
            UnitOfTime.MILLISECONDS,
            "mdi:timer-outline",
        ),
        (
            "speedtest.average.download",
            "Speedtest Average Download",
            UnitOfDataRate.MEGABITS_PER_SECOND,
            "mdi:download-network",
        ),
        (
            "speedtest.average.upload",
            "Speedtest Average Upload",
            UnitOfDataRate.MEGABITS_PER_SECOND,
            "mdi:upload-network",
        ),
        (
            "speedtest.average.latency",
            "Speedtest Average Latency",
            UnitOfTime.MILLISECONDS,
            "mdi:timer-outline",
        ),
    )
    entities: list = []
    for key, name, native_unit, icon in metric_definitions:
        device_class: SensorDeviceClass | None = None
        if not key.endswith(".latency"):
            device_class = SensorDeviceClass.DATA_RATE

        entities.append(
            OPNsenseSpeedtestSensor(
                config_entry=config_entry,
                coordinator=coordinator,
                entity_description=SensorEntityDescription(
                    key=key,
                    name=name,
                    native_unit_of_measurement=native_unit,
                    device_class=device_class,
                    icon=icon,
                    state_class=SensorStateClass.MEASUREMENT,
                    entity_registry_enabled_default=False,
                ),
            )
        )
    return entities


async def _compile_filesystem_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile filesystem sensors.

    Args:
        config_entry: Config entry being exercised by the helper or test.
        coordinator: Data update coordinator that caches OPNsense state for entities.
        state: Coordinator state snapshot that contains filesystem telemetry data.
    """
    if not isinstance(state, MutableMapping):
        return []
    entities: list = []

    for filesystem in dict_get(state, "telemetry.filesystems", []) or []:
        filesystem_slug: str = slugify_filesystem_mountpoint(filesystem.get("mountpoint", None))
        enabled_default = False
        if filesystem_slug == "root":
            enabled_default = True

        entity = OPNsenseFilesystemSensor(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=SensorEntityDescription(
                key=f"telemetry.filesystems.{filesystem_slug}",
                name=f"Filesystem Used Percentage {normalize_filesystem_mountpoint(filesystem.get('mountpoint', None))}",
                native_unit_of_measurement=PERCENTAGE,
                device_class=None,
                icon="mdi:harddisk",
                state_class=SensorStateClass.MEASUREMENT,
                entity_registry_enabled_default=enabled_default,
                # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            ),
        )
        entities.append(entity)

    return entities


async def _compile_carp_interface_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile carp interface sensors.

    Args:
        config_entry: Config entry being exercised by the helper or test.
        coordinator: Data update coordinator that caches OPNsense state for entities.
        state: Coordinator state snapshot that contains CARP interface status data.
    """
    if not isinstance(state, MutableMapping):
        return []
    entities: list = []

    for interface in state.get("carp_interfaces", []):
        entity = OPNsenseCarpInterfaceSensor(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=SensorEntityDescription(
                key=f"carp.interface.{slugify(interface['subnet'])}",  # subnet is actually the ip
                name=f"CARP Interface Status {slugify(interface['subnet'])} ({interface.get('descr', '')})",
                native_unit_of_measurement=None,
                device_class=None,
                icon="mdi:check-network",
                state_class=None,
                entity_registry_enabled_default=True,
                # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            ),
        )
        entities.append(entity)
    return entities


async def _compile_interface_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile interface sensors.

    Args:
        config_entry: Config entry being exercised by the helper or test.
        coordinator: Data update coordinator that caches OPNsense state for entities.
        state: Coordinator state snapshot that contains network interface statistics.
    """
    if not isinstance(state, MutableMapping):
        return []
    entities: list = []

    # interfaces
    for interface_name, interface in (dict_get(state, "interfaces", {}) or {}).items():
        for prop_name in (
            "status",
            "inerrs",
            "outerrs",
            "collisions",
            "inbytes",
            "inbytes_kilobytes_per_second",
            "outbytes",
            "outbytes_kilobytes_per_second",
            "inpkts",
            "inpkts_packets_per_second",
            "outpkts",
            "outpkts_packets_per_second",
        ):
            state_class: SensorStateClass | None = SensorStateClass.MEASUREMENT
            native_unit_of_measurement = None
            device_class = None
            enabled_default = False
            suggested_display_precision = None
            suggested_unit_of_measurement = None

            # enabled_default
            if prop_name in {
                "status",
                "inbytes_kilobytes_per_second",
                "outbytes_kilobytes_per_second",
            }:
                enabled_default = True

            # native_unit_of_measurement
            if "_packets_per_second" in prop_name:
                native_unit_of_measurement = DATA_RATE_PACKETS_PER_SECOND

            if "_kilobytes_per_second" in prop_name:
                native_unit_of_measurement = UnitOfDataRate.KILOBYTES_PER_SECOND
                device_class = SensorDeviceClass.DATA_RATE

            if native_unit_of_measurement is None:
                if "bytes" in prop_name:
                    native_unit_of_measurement = UnitOfInformation.BYTES
                    device_class = SensorDeviceClass.DATA_SIZE
                    state_class = SensorStateClass.TOTAL_INCREASING
                    suggested_display_precision = 1
                    suggested_unit_of_measurement = UnitOfInformation.GIGABYTES
                if "pkts" in prop_name:
                    native_unit_of_measurement = DATA_PACKETS
                    state_class = SensorStateClass.TOTAL_INCREASING

            if prop_name in {"inerrs", "outerrs", "collisions"}:
                native_unit_of_measurement = COUNT

            # icon
            if "pkts" in prop_name or "bytes" in prop_name:
                icon = "mdi:server-network"
            elif prop_name == "status":
                icon = "mdi:check-network"
                state_class = None
            else:
                icon = "mdi:gauge"

            entity = OPNsenseInterfaceSensor(
                config_entry=config_entry,
                coordinator=coordinator,
                entity_description=SensorEntityDescription(
                    key=f"interface.{interface_name}.{prop_name}",
                    name=f"Interface {interface.get('name', interface_name)} {prop_name}",
                    native_unit_of_measurement=native_unit_of_measurement,
                    device_class=device_class,
                    icon=icon,
                    state_class=state_class,
                    suggested_display_precision=suggested_display_precision,
                    suggested_unit_of_measurement=suggested_unit_of_measurement,
                    entity_registry_enabled_default=enabled_default,
                    # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
                ),
            )
            entities.append(entity)

    return entities


async def _compile_gateway_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile gateway sensors.

    Args:
        config_entry: Config entry being exercised by the helper or test.
        coordinator: Data update coordinator that caches OPNsense state for entities.
        state: Coordinator state snapshot that contains gateway latency, loss, and status data.
    """
    if not isinstance(state, MutableMapping):
        return []
    entities: list = []

    for gateway in (dict_get(state, "gateways", {}) or {}).values():
        for prop_name in ("status", "delay", "stddev", "loss"):
            native_unit_of_measurement = None
            device_class: SensorDeviceClass | None = None
            state_class: SensorStateClass | None = SensorStateClass.MEASUREMENT
            enabled_default = False
            icon = "mdi:router-network"

            if prop_name == "loss":
                native_unit_of_measurement = PERCENTAGE

            if prop_name in {"delay", "stddev"}:
                native_unit_of_measurement = UnitOfTime.MILLISECONDS
                # device_class = SensorDeviceClass.DURATION

            if prop_name == "status":
                icon = "mdi:check-network"
                state_class = None
                enabled_default = True

            entity = OPNsenseGatewaySensor(
                config_entry=config_entry,
                coordinator=coordinator,
                entity_description=SensorEntityDescription(
                    key=f"gateway.{gateway['name']}.{prop_name}",
                    name=f"Gateway {gateway['name']} {prop_name}",
                    native_unit_of_measurement=native_unit_of_measurement,
                    device_class=device_class,
                    icon=icon,
                    state_class=state_class,
                    entity_registry_enabled_default=enabled_default,
                    # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
                ),
            )
            entities.append(entity)

    return entities


async def _compile_temperature_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile temperature sensors.

    Args:
        config_entry: Config entry being exercised by the helper or test.
        coordinator: Data update coordinator that caches OPNsense state for entities.
        state: Coordinator state snapshot that contains hardware temperature telemetry.
    """
    if not isinstance(state, MutableMapping):
        return []
    entities: list = []

    # temperatures
    for temp_device, temp in state.get("telemetry", {}).get("temps", {}).items():
        entity = OPNsenseTempSensor(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=SensorEntityDescription(
                key=f"telemetry.temps.{temp_device}",
                name=f"Temp {temp.get('name', temp_device)}",
                native_unit_of_measurement=UnitOfTemperature.CELSIUS,
                device_class=SensorDeviceClass.TEMPERATURE,
                icon="mdi:thermometer",
                state_class=SensorStateClass.MEASUREMENT,
                suggested_display_precision=1,
                suggested_unit_of_measurement=UnitOfTemperature.CELSIUS,
                entity_registry_enabled_default=True,
                # entity_category=entity_category,
            ),
        )
        entities.append(entity)
    return entities


async def _compile_dhcp_leases_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile dhcp leases sensors.

    Args:
        config_entry: Config entry being exercised by the helper or test.
        coordinator: Data update coordinator that caches OPNsense state for entities.
        state: Coordinator state snapshot that contains DHCP lease counts per interface.
    """
    if not isinstance(state, MutableMapping):
        return []
    entities: list = []

    # interfaces
    for interface, interface_name in (
        dict_get(state, "dhcp_leases.lease_interfaces", {}) or {}
    ).items():
        entity = OPNsenseDHCPLeasesSensor(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=SensorEntityDescription(
                key=f"dhcp_leases.{interface}",
                name=f"DHCP Leases {interface_name}",
                native_unit_of_measurement="leases",
                device_class=None,
                icon="mdi:devices",
                state_class=SensorStateClass.MEASUREMENT,
                entity_registry_enabled_default=False,
                # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            ),
        )
        entities.append(entity)

    entity = OPNsenseDHCPLeasesSensor(
        config_entry=config_entry,
        coordinator=coordinator,
        entity_description=SensorEntityDescription(
            key="dhcp_leases.all",
            name="DHCP Leases All",
            native_unit_of_measurement="leases",
            device_class=None,
            icon="mdi:devices",
            state_class=SensorStateClass.MEASUREMENT,
            entity_registry_enabled_default=True,
            # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
        ),
    )
    entities.append(entity)

    return entities


async def _compile_vpn_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile vpn sensors.

    Args:
        config_entry: Config entry being exercised by the helper or test.
        coordinator: Data update coordinator that caches OPNsense state for entities.
        state: Coordinator state snapshot that contains OpenVPN and WireGuard metrics.
    """
    if not isinstance(state, MutableMapping):
        return []
    entities: list = []

    for vpn_type in ("openvpn", "wireguard"):
        cs = ["servers"]
        if vpn_type == "wireguard":
            cs = ["clients", "servers"]
        for clients_servers in cs:
            for uuid, instance in (
                dict_get(state, f"{vpn_type}.{clients_servers}", {}) or {}
            ).items():
                if not isinstance(instance, MutableMapping) or len(instance) == 0:
                    continue
                properties: list[str] = [
                    "total_bytes_recv",
                    "total_bytes_sent",
                    "total_bytes_recv_kilobytes_per_second",
                    "total_bytes_sent_kilobytes_per_second",
                ]
                if clients_servers == "servers":
                    properties.extend(["status", "connected_clients"])
                if vpn_type == "wireguard" and clients_servers == "clients":
                    properties.append("connected_servers")
                for prop_name in properties:
                    state_class: SensorStateClass | None = None
                    native_unit_of_measurement: UnitOfDataRate | UnitOfInformation | None = None
                    device_class: SensorDeviceClass | None = None
                    enabled_default = False
                    suggested_display_precision = None
                    suggested_unit_of_measurement = None

                    if "_kilobytes_per_second" in prop_name:
                        native_unit_of_measurement = UnitOfDataRate.KILOBYTES_PER_SECOND
                        device_class = SensorDeviceClass.DATA_RATE
                        state_class = SensorStateClass.MEASUREMENT

                    if native_unit_of_measurement is None and "bytes" in prop_name:
                        native_unit_of_measurement = UnitOfInformation.BYTES
                        device_class = SensorDeviceClass.DATA_SIZE
                        state_class = SensorStateClass.TOTAL_INCREASING
                        suggested_display_precision = 1
                        suggested_unit_of_measurement = UnitOfInformation.MEGABYTES

                    if prop_name in {"connected_clients", "connected_servers"}:
                        state_class = SensorStateClass.MEASUREMENT

                    # icon
                    if "bytes" in prop_name:
                        icon = "mdi:server-network"
                    elif prop_name == "status":
                        icon = "mdi:check-network"
                        enabled_default = True
                    elif prop_name == "connected_servers":
                        icon = "mdi:router-network"
                    elif prop_name == "connected_clients":
                        icon = "mdi:account-network"
                    else:
                        icon = "mdi:gauge"

                    entity = OPNsenseVPNSensor(
                        config_entry=config_entry,
                        coordinator=coordinator,
                        entity_description=SensorEntityDescription(
                            key=f"{vpn_type}.{clients_servers}.{uuid}.{prop_name}",
                            name=f"{'OpenVPN' if vpn_type == 'openvpn' else vpn_type.title()} {clients_servers.title().rstrip('s')} {instance['name']} {prop_name}",
                            native_unit_of_measurement=native_unit_of_measurement,
                            device_class=device_class,
                            icon=icon,
                            state_class=state_class,
                            suggested_display_precision=suggested_display_precision,
                            suggested_unit_of_measurement=suggested_unit_of_measurement,
                            entity_registry_enabled_default=enabled_default,
                            # entity_category=entity_category,
                        ),
                    )
                    entities.append(entity)
    return entities


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the OPNsense sensors."""

    coordinator: OPNsenseDataUpdateCoordinator = getattr(config_entry.runtime_data, COORDINATOR)
    state: dict[str, Any] = coordinator.data
    if not isinstance(state, MutableMapping):
        _LOGGER.error("Missing state data in sensor async_setup_entry")
        return
    config: Mapping[str, Any] = config_entry.data

    entities: list = []

    if config.get(CONF_SYNC_TELEMETRY, DEFAULT_SYNC_OPTION_VALUE):
        entities.extend(await _compile_static_telemetry_sensors(config_entry, coordinator))
        entities.extend(await _compile_filesystem_sensors(config_entry, coordinator, state))
        entities.extend(await _compile_temperature_sensors(config_entry, coordinator, state))
    if config.get(CONF_SYNC_VNSTAT, DEFAULT_SYNC_OPTION_VALUE):
        entities.extend(await _compile_vnstat_sensors(config_entry, coordinator, state))
    if config.get(CONF_SYNC_SPEEDTEST, DEFAULT_SYNC_OPTION_VALUE):
        entities.extend(await _compile_speedtest_sensors(config_entry, coordinator, state))
    if config.get(CONF_SYNC_CERTIFICATES, DEFAULT_SYNC_OPTION_VALUE):
        entities.extend(await _compile_static_certificate_sensors(config_entry, coordinator))
    if config.get(CONF_SYNC_VPN, DEFAULT_SYNC_OPTION_VALUE):
        entities.extend(await _compile_vpn_sensors(config_entry, coordinator, state))
    if config.get(CONF_SYNC_GATEWAYS, DEFAULT_SYNC_OPTION_VALUE):
        entities.extend(await _compile_gateway_sensors(config_entry, coordinator, state))
    if config.get(CONF_SYNC_INTERFACES, DEFAULT_SYNC_OPTION_VALUE):
        entities.extend(await _compile_interface_sensors(config_entry, coordinator, state))
    if config.get(CONF_SYNC_CARP, DEFAULT_SYNC_OPTION_VALUE):
        entities.extend(await _compile_carp_interface_sensors(config_entry, coordinator, state))
    if config.get(CONF_SYNC_DHCP_LEASES, DEFAULT_SYNC_OPTION_VALUE):
        entities.extend(await _compile_dhcp_leases_sensors(config_entry, coordinator, state))

    _LOGGER.debug("[sensor async_setup_entry] entities: %s", len(entities))
    async_add_entities(entities)


def slugify_filesystem_mountpoint(mountpoint: str) -> str:
    """Slugify the mountpoint."""
    if not mountpoint:
        return ""
    if mountpoint == "/":
        return "root"
    return mountpoint.replace("/", "_").strip("_")


def normalize_filesystem_mountpoint(mountpoint: str) -> str:
    """Normalize the mountpoint."""
    if not mountpoint:
        return ""
    if mountpoint == "/":
        return "root"
    return mountpoint.rstrip("/")


class OPNsenseSensor(OPNsenseEntity, SensorEntity):
    """Representation of a sensor entity for OPNsense status values."""

    def __init__(
        self,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        entity_description: SensorEntityDescription,
    ) -> None:
        """Initialize the sensor."""
        name_suffix: str | None = (
            entity_description.name if isinstance(entity_description.name, str) else None
        )
        unique_id_suffix: str | None = (
            entity_description.key if isinstance(entity_description.key, str) else None
        )
        super().__init__(
            config_entry,
            coordinator,
            unique_id_suffix=unique_id_suffix,
            name_suffix=name_suffix,
        )
        self.entity_description: SensorEntityDescription = entity_description
        self._previous_value: Any = None
        self._attr_native_value: Any = None


class OPNsenseStaticKeySensor(OPNsenseSensor):
    """Class for OPNsense Sensors with Static Keys."""

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update."""
        value = self._get_opnsense_state_value(self.entity_description.key)
        if value is None:
            self._available = False
            self.async_write_ha_state()
            return

        if (
            value == 0
            and self._previous_value is None
            and self.entity_description.key == "telemetry.cpu.usage_total"
        ):
            self._available = False
            self.async_write_ha_state()
            return

        if self.entity_description.key == "telemetry.system.boottime":
            value = utc_from_timestamp(value) if value else None

        elif self.entity_description.key == "telemetry.cpu.usage_total":
            if value == 0 and self._previous_value is not None:
                value = self._previous_value

            if value == 0:
                self._available = False
                self.async_write_ha_state()
                return
        elif self.entity_description.key == "certificates":
            value = len(value)

        self._available = True
        self._previous_value = value
        self._attr_native_value = value

        self._attr_extra_state_attributes = {}
        if self.entity_description.key == "telemetry.cpu.usage_total":
            temp_attr = self._get_opnsense_state_value("telemetry.cpu")
            # _LOGGER.debug(f"[extra_state_attributes] temp_attr: {temp_attr}")
            if isinstance(temp_attr, MutableMapping):
                for k, v in temp_attr.items():
                    if k.startswith("usage_") and k != "usage_total":
                        self._attr_extra_state_attributes[k.replace("usage_", "")] = f"{v}%"
                # _LOGGER.debug(f"[extra_state_attributes] attributes: {attributes}")
        elif self.entity_description.key == "certificates":
            certs = self._get_opnsense_state_value(self.entity_description.key)
            if isinstance(certs, MutableMapping):
                self._attr_extra_state_attributes = dict(certs)

        self.async_write_ha_state()


class OPNsenseVnstatSensor(OPNsenseSensor):
    """Class for OPNsense vnStat sensors."""

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update."""
        state: dict[str, Any] = self.coordinator.data
        if not isinstance(state, MutableMapping):
            self._available = False
            self.async_write_ha_state()
            return

        key_parts = self.entity_description.key.split(".")
        if len(key_parts) != 3:
            self._available = False
            self.async_write_ha_state()
            return
        _, interface_name, metric_name = key_parts

        metric = dict_get(state, f"vnstat.interfaces.{interface_name}.metrics.{metric_name}", {})
        if not isinstance(metric, MutableMapping):
            self._available = False
            self.async_write_ha_state()
            return

        total = metric.get("total_bytes")
        if not isinstance(total, int):
            self._available = False
            self.async_write_ha_state()
            return

        self._available = True
        self._attr_native_value = total

        self._attr_extra_state_attributes = {"interface": interface_name}
        rx_bytes = metric.get("rx_bytes")
        tx_bytes = metric.get("tx_bytes")
        if isinstance(rx_bytes, int):
            self._attr_extra_state_attributes["rx_bytes"] = rx_bytes
        if isinstance(tx_bytes, int):
            self._attr_extra_state_attributes["tx_bytes"] = tx_bytes

        self.async_write_ha_state()


class OPNsenseSpeedtestSensor(OPNsenseSensor):
    """Class for OPNsense Speedtest sensors."""

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator updates for speedtest sensors."""
        state: dict[str, Any] = self.coordinator.data
        if not isinstance(state, MutableMapping):
            self._available = False
            self.async_write_ha_state()
            return

        key_parts = self.entity_description.key.split(".")
        if len(key_parts) != 3:
            self._available = False
            self.async_write_ha_state()
            return
        _, speedtest_section, metric_name = key_parts

        metric = dict_get(state, f"speedtest.{speedtest_section}.{metric_name}", {})
        if not isinstance(metric, MutableMapping):
            self._available = False
            self.async_write_ha_state()
            return

        value = metric.get("value")
        if not isinstance(value, (int, float)):
            self._available = False
            self.async_write_ha_state()
            return

        self._available = True
        self._attr_native_value = float(value)
        self._attr_extra_state_attributes = {}

        if speedtest_section == "last":
            for attr in ("date", "server_id", "server", "url"):
                if metric.get(attr) is not None:
                    self._attr_extra_state_attributes[attr] = metric.get(attr)
        else:
            for attr in ("min", "max", "oldest", "youngest", "samples"):
                if metric.get(attr) is not None:
                    self._attr_extra_state_attributes[attr] = metric.get(attr)
        self.async_write_ha_state()


class OPNsenseFilesystemSensor(OPNsenseSensor):
    """Class for OPNsense Filesystem Sensors."""

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update."""
        filesystem: dict[str, Any] = {}
        state: dict[str, Any] = self.coordinator.data
        if not isinstance(state, MutableMapping):
            self._available = False
            self.async_write_ha_state()
            return
        for fsystem in state.get("telemetry", {}).get("filesystems", []):
            if (
                self.entity_description.key
                == f"telemetry.filesystems.{slugify_filesystem_mountpoint(fsystem.get('mountpoint', None))}"
            ):
                filesystem = fsystem
        if not filesystem:
            self._available = False
            self.async_write_ha_state()
            return

        try:
            self._attr_native_value = filesystem["used_pct"]
        except TypeError, KeyError, AttributeError:
            self._available = False
            self.async_write_ha_state()
            return
        self._available = True

        self._attr_extra_state_attributes = {}
        for attr in ("mountpoint", "device", "type", "blocks", "used", "available"):
            self._attr_extra_state_attributes[attr] = filesystem[attr]
        self.async_write_ha_state()


class OPNsenseInterfaceSensor(OPNsenseSensor):
    """Class for OPNsense Interface Sensors."""

    def _opnsense_get_interface_property_name(self) -> str:
        """Opnsense get interface property name."""
        return self.entity_description.key.split(".")[2]

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update."""
        state: dict[str, Any] = self.coordinator.data
        if not isinstance(state, MutableMapping):
            self._available = False
            self.async_write_ha_state()
            return
        interface_name: str = self.entity_description.key.split(".")[1]
        interface: dict[str, Any] = {}
        interfaces = state.get("interfaces")
        if not isinstance(interfaces, Mapping):
            self._available = False
            self.async_write_ha_state()
            return
        for i_interface_name, iface in interfaces.items():
            if i_interface_name == interface_name:
                interface = iface
                break
        if not interface:
            self._available = False
            self.async_write_ha_state()
            return
        prop_name: str = self._opnsense_get_interface_property_name()
        try:
            self._attr_native_value = interface[prop_name]
        except TypeError, KeyError, ZeroDivisionError:
            self._available = False
            self.async_write_ha_state()
            return
        self._available = True
        self._attr_extra_state_attributes = {}
        if prop_name == "status":
            properties: list = [
                "enabled",
                "interface",
                "device",
                "ipv4",
                "ipv6",
                "mac",
                "routes",
                "gateways",
                "media",
                "vlan_tag",
            ]
        else:
            properties = ["interface", "device", "ipv4", "ipv6"]
        for attr in properties:
            if interface.get(attr, None):
                self._attr_extra_state_attributes[attr] = interface[attr]
        self.async_write_ha_state()

    @property
    def icon(self) -> str | None:
        """Return the icon for the sensor."""
        prop_name: str = self._opnsense_get_interface_property_name()
        if prop_name == "status" and self.native_value != "up":
            return "mdi:close-network-outline"
        return super().icon


class OPNsenseCarpInterfaceSensor(OPNsenseSensor):
    """Class for OPNsense Carp Sensors."""

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update."""
        carp_interface: dict[str, Any] = {}
        state: dict[str, Any] = self.coordinator.data
        if not isinstance(state, MutableMapping):
            self._available = False
            self.async_write_ha_state()
            return
        carp_interface_name: str = self.entity_description.key.split(".")[2]
        for i_interface in state.get("carp_interfaces", []):
            if slugify(i_interface["subnet"]) == carp_interface_name:
                carp_interface = i_interface
                break
        if not carp_interface:
            self._available = False
            self.async_write_ha_state()
            return

        try:
            self._attr_native_value = carp_interface["status"]
        except TypeError, KeyError, ZeroDivisionError:
            self._available = False
            self.async_write_ha_state()
            return
        self._available = True
        self._attr_extra_state_attributes = {}
        for attr in (
            "interface",
            "vhid",
            "advskew",
            "advbase",
            "subnet_bits",
            "subnet",
            "descr",
        ):
            if attr in carp_interface:
                self._attr_extra_state_attributes[attr] = carp_interface[attr]
        self.async_write_ha_state()

    @property
    def icon(self) -> str | None:
        """Return the icon for the sensor."""
        if self.native_value != "MASTER":
            return "mdi:close-network-outline"
        return super().icon


class OPNsenseGatewaySensor(OPNsenseSensor):
    """Class for OPNsense Gateway Sensors."""

    def _opnsense_get_gateway_property_name(self) -> str:
        """Opnsense get gateway property name."""
        return self.entity_description.key.split(".")[2]

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update."""
        state: dict[str, Any] = self.coordinator.data
        if not isinstance(state, MutableMapping):
            self._available = False
            self.async_write_ha_state()
            return
        gateway: dict[str, Any] = {}
        gateway_name: str = self.entity_description.key.split(".")[1]
        for i_gateway_name, gway in state.get("gateways", {}).items():
            if i_gateway_name == gateway_name:
                gateway = gway
                break
        if not gateway:
            self._available = False
            self.async_write_ha_state()
            return
        prop_name: str = self._opnsense_get_gateway_property_name()
        try:
            value = gateway[prop_name]
            # cleanse "ms", etc from values
            if prop_name in {"stddev", "delay", "loss"} and isinstance(value, str):
                value = re.sub(r"[^0-9\.]*", "", value)
                if len(value) > 0:
                    value = float(value)

            if isinstance(value, str) and len(value) < 1:
                self._available = False
                self.async_write_ha_state()
                return

            self._attr_native_value = value
        except TypeError, KeyError, ZeroDivisionError:
            self._available = False
            self.async_write_ha_state()
            return
        self._available = True
        self._attr_extra_state_attributes = {}
        self.async_write_ha_state()

    @property
    def icon(self) -> str | None:
        """Return the icon for the sensor."""
        prop_name: str = self._opnsense_get_gateway_property_name()
        if prop_name == "status" and self.native_value != "online":
            return "mdi:close-network-outline"
        return super().icon


class OPNsenseVPNSensor(OPNsenseSensor):
    """Class for OPNsense VPN Sensors."""

    def _get_property_name(self) -> str:
        """Return property name."""
        return self.entity_description.key.split(".")[3]

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update."""
        vpn_type: str = self.entity_description.key.split(".")[0]
        clients_servers: str = self.entity_description.key.split(".")[1]
        state: dict[str, Any] = self.coordinator.data
        if not isinstance(state, MutableMapping):
            self._available = False
            self.async_write_ha_state()
            return
        uuid: str = self.entity_description.key.split(".")[2]
        instance: dict[str, Any] = {}
        for instance_uuid, ins in (
            dict_get(state, f"{vpn_type}.{clients_servers}", {}) or {}
        ).items():
            if uuid == instance_uuid:
                instance = ins
                break
        prop_name: str = self._get_property_name()
        if not instance or (
            prop_name != "status"
            and instance.get("enabled", None) is not None
            and not instance.get("enabled")
        ):
            self._available = False
            self.async_write_ha_state()
            return

        try:
            if (
                prop_name == "status"
                and not instance.get(prop_name, None)
                and not instance.get("enabled", True)
            ):
                self._attr_native_value = "disabled"
            else:
                self._attr_native_value = instance.get(prop_name)
        except TypeError, KeyError, ZeroDivisionError:
            self._available = False
            self.async_write_ha_state()
            return
        self._available = True

        self._attr_extra_state_attributes = {}
        if clients_servers == "servers" and prop_name == "status":
            properties: list = [
                "uuid",
                "name",
                "enabled",
                "connected_clients",
                "endpoint",
                "interface",
                "dev_type",
                "pubkey",
                "tunnel_addresses",
                "dns_servers",
                "latest_handshake",
            ]
        elif prop_name == "connected_clients":
            properties = [
                "uuid",
                "name",
                "status",
                "enabled",
                "endpoint",
                "interface",
                "dev_type",
                "pubkey",
                "tunnel_addresses",
                "dns_servers",
                "latest_handshake",
            ]
        elif prop_name == "connected_servers":
            properties = [
                "uuid",
                "name",
                "enabled",
                "connected_servers",
                "endpoint",
                "iterface",
                "pubkey",
                "tunnel_addresses",
                "latest_handshake",
                "servers",
            ]
        else:
            properties = ["uuid", "name"]
        for attr in properties:
            if instance.get(attr, None) is not None:
                self._attr_extra_state_attributes[attr] = instance.get(attr)

        if (
            isinstance(instance.get("clients", None), list)
            and clients_servers == "servers"
            and prop_name in {"connected_clients", "status"}
        ):
            self._attr_extra_state_attributes["clients"] = []
            for clnt in instance.get("clients", {}):
                client: dict[str, Any] = {}
                for client_attr in (
                    "name",
                    "status",
                    "endpoint",
                    "tunnel_addresses",
                    "latest_handshake",
                    "bytes_sent",
                    "bytes_recv",
                ):
                    if clnt.get(client_attr, None) is not None:
                        client[client_attr] = clnt.get(client_attr)
                self._attr_extra_state_attributes["clients"].append(client)
        self.async_write_ha_state()

    @property
    def icon(self) -> str | None:
        """Return the icon for the sensor."""
        prop_name: str = self._get_property_name()
        if prop_name == "status" and self.native_value != "up":
            return "mdi:close-network-outline"
        return super().icon


class OPNsenseTempSensor(OPNsenseSensor):
    """Class for OPNsense Temperature Sensors."""

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update."""
        state: dict[str, Any] = self.coordinator.data
        if not isinstance(state, MutableMapping):
            self._available = False
            self.async_write_ha_state()
            return
        sensor_temp_device: str = self.entity_description.key.split(".")[2]
        temp: dict[str, Any] = {}
        for temp_device, temp_temp in state.get("telemetry", {}).get("temps", {}).items():
            if temp_device == sensor_temp_device:
                temp = temp_temp
                break
        if not temp:
            self._available = False
            self.async_write_ha_state()
            return

        try:
            self._attr_native_value = temp["temperature"]
        except TypeError, KeyError, ZeroDivisionError:
            self._available = False
            self.async_write_ha_state()
            return
        self._available = True

        self._attr_extra_state_attributes = {}
        for attr in ["device_id"]:
            self._attr_extra_state_attributes[attr] = temp.get(attr, None)
        self.async_write_ha_state()


class OPNsenseDHCPLeasesSensor(OPNsenseSensor):
    """Class for OPNsense DHCP Leases Sensors."""

    _unrecorded_attributes = frozenset({"Leases"})

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update."""
        state: dict[str, Any] = self.coordinator.data
        if not isinstance(state, MutableMapping):
            self._available = False
            self.async_write_ha_state()
            return
        if_name: str = self.entity_description.key.split(".")[1].strip()
        # _LOGGER.debug(f"[OPNsenseDHCPLeasesSensor handle_coordinator_update] if_name: {if_name}")
        if if_name.lower() == "all":
            leases = state.get("dhcp_leases", {}).get("leases", {})
            lease_interfaces = state.get("dhcp_leases", {}).get("lease_interfaces", {})
            # _LOGGER.debug(f"[OPNsenseDHCPLeasesSensor handle_coordinator_update] lease_interfaces: {lease_interfaces}")
            # _LOGGER.debug(f"[OPNsenseDHCPLeasesSensor handle_coordinator_update] leases: {leases}")
            if not isinstance(leases, MutableMapping) or not isinstance(
                lease_interfaces, MutableMapping
            ):
                self._available = False
                self.async_write_ha_state()
                return
            self._available = True
            total_lease_count: int = 0
            lease_counts: dict[str, Any] = {}
            try:
                for ifn, if_descr in lease_interfaces.items():
                    if_count: int = sum(
                        1 for d in leases.get(ifn, []) if d.get("address") not in {None, ""}
                    )
                    lease_counts[if_descr] = f"{if_count} leases"
                    total_lease_count += if_count
                    _LOGGER.debug(
                        "[OPNsenseDHCPLeasesSensor handle_coordinator_update] %s: lease_count: %s",
                        if_descr,
                        if_count,
                    )
            except TypeError, KeyError, ZeroDivisionError:
                self._available = False
                self.async_write_ha_state()
                return
            sorted_lease_counts: dict[str, Any] = {
                key: lease_counts[key] for key in sorted(lease_counts)
            }
            self._attr_extra_state_attributes = dict(sorted_lease_counts)
            self._attr_native_value = total_lease_count

        else:
            interface = state.get("dhcp_leases", {}).get("leases", {}).get(if_name, [])
            if not isinstance(interface, list):
                self._available = False
                self.async_write_ha_state()
                return
            try:
                self._attr_native_value = sum(
                    1 for d in interface if d.get("address") not in {None, ""}
                )
            except TypeError, KeyError, ZeroDivisionError:
                self._available = False
                self.async_write_ha_state()
                return
            self._available = True
            self._attr_extra_state_attributes = {"Leases": interface}
        self.async_write_ha_state()
