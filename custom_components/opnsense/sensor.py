"""Provides sensors to track various status aspects of OPNsense."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, MutableMapping
import inspect
import ipaddress
import logging
import re
from typing import Any, Final, TypeIs

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
    CONF_SYNC_LIVE_TRAFFIC,
    CONF_SYNC_SMART,
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
)
from .coordinator import OPNsenseDataUpdateCoordinator
from .entity import OPNsenseEntity, OPNsenseEntityCoordinator
from .helpers import coerce_bool, dict_get, get_smart_device_name, is_carp_entry
from .repair_reconciliation import record_desired_entities
from .traffic_coordinator import OPNsenseLiveTrafficCoordinator

_LOGGER: logging.Logger = logging.getLogger(__name__)


_INTERFACE_SENSOR_PROPERTIES: tuple[str, ...] = (
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
)
_INTERFACE_RATE_SENSOR_PROPERTIES: tuple[str, ...] = (
    "inbytes_kilobytes_per_second",
    "outbytes_kilobytes_per_second",
    "inpkts_packets_per_second",
    "outpkts_packets_per_second",
)
_INTERFACE_TRAFFIC_SENSOR_NAMES: dict[str, str] = {
    "inerrs": "Errors In Total",
    "outerrs": "Errors Out Total",
    "collisions": "Collisions Total",
    "inbytes": "Traffic In Total",
    "inbytes_kilobytes_per_second": "Traffic In Rate",
    "outbytes": "Traffic Out Total",
    "outbytes_kilobytes_per_second": "Traffic Out Rate",
    "inpkts": "Packets In Total",
    "inpkts_packets_per_second": "Packets In Rate",
    "outpkts": "Packets Out Total",
    "outpkts_packets_per_second": "Packets Out Rate",
}

_GATEWAY_SENSOR_PROPERTIES: tuple[str, ...] = ("status", "delay", "stddev", "loss", "address")
_VPN_TRAFFIC_PROPERTIES: tuple[str, ...] = (
    "total_bytes_recv",
    "total_bytes_sent",
    "total_bytes_recv_kilobytes_per_second",
    "total_bytes_sent_kilobytes_per_second",
)
_VPN_SERVER_PROPERTIES: tuple[str, ...] = ("status", "connected_clients")
_VPN_WIREGUARD_CLIENT_PROPERTIES: tuple[str, ...] = ("connected_servers",)
_ICON_MEMORY: Final[str] = "mdi:memory"
_CARP_INTERFACE_ATTRIBUTES: Final[tuple[str, ...]] = (
    "interface",
    "vhid",
    "advskew",
    "advbase",
    "subnet_bits",
    "subnet",
    "descr",
    "mode",
)
_CARP_STATUS_ICONS: Final[Mapping[str, str]] = {
    "MASTER": "mdi:check-network",
    "BACKUP": "mdi:backup-restore",
}


def _is_valid_vnstat_interface_row(interface_name: Any) -> TypeIs[str]:
    """Return whether a vnStat interface key can produce sensors."""
    return isinstance(interface_name, str)


def _is_valid_smart_device_row(smart_device: Any) -> bool:
    """Return whether a SMART device row can produce a sensor."""
    return isinstance(smart_device, Mapping) and bool(get_smart_device_name(smart_device))


def _is_valid_filesystem_row(filesystem: Any) -> bool:
    """Return whether a filesystem row can produce a sensor."""
    return (
        isinstance(filesystem, Mapping)
        and isinstance(filesystem.get("mountpoint"), str)
        and bool(filesystem["mountpoint"].strip())
    )


def _get_runtime_live_traffic_coordinator(
    config_entry: ConfigEntry,
) -> OPNsenseLiveTrafficCoordinator | None:
    """Return the live traffic coordinator when explicitly attached to runtime data."""
    runtime_data = getattr(config_entry, "runtime_data", None)
    coordinator = getattr(runtime_data, "live_traffic_coordinator", None)
    return coordinator if isinstance(coordinator, OPNsenseLiveTrafficCoordinator) else None


def _is_valid_carp_interface_row(interface: Any) -> bool:
    """Return whether a CARP interface row can produce a sensor."""
    return (
        isinstance(interface, MutableMapping)
        and isinstance(interface.get("subnet"), str)
        and bool(interface["subnet"].strip())
    )


def _is_valid_mutable_mapping_row(row: Any) -> bool:
    """Return whether a dynamic inventory row is a mutable mapping."""
    return isinstance(row, MutableMapping)


def _is_valid_vpn_sensor_row(instance: Any) -> bool:
    """Return whether a VPN instance row can produce sensors."""
    return isinstance(instance, MutableMapping) and len(instance) > 0


def _vnstat_rows_are_complete(state: MutableMapping[str, Any]) -> bool:
    """Return whether every consumed vnStat interface row is valid."""
    interfaces = dict_get(state, "vnstat.interfaces", {})
    return isinstance(interfaces, MutableMapping) and all(
        _is_valid_vnstat_interface_row(interface_name) for interface_name in interfaces
    )


def _vpn_sensor_rows_are_complete(state: MutableMapping[str, Any]) -> bool:
    """Return whether every VPN row consumed by the sensor compiler is valid."""
    for vpn_type, groups in (
        ("openvpn", ("servers",)),
        ("wireguard", ("clients", "servers")),
    ):
        for group in groups:
            instances = dict_get(state, f"{vpn_type}.{group}", {})
            if not isinstance(instances, MutableMapping) or not all(
                _is_valid_vpn_sensor_row(instance) for instance in instances.values()
            ):
                return False
    return True


def _telemetry_rows_are_complete(telemetry: Any) -> bool:
    """Return whether telemetry inventories and all consumed rows are valid."""
    return (
        isinstance(telemetry, MutableMapping)
        and "filesystems" in telemetry
        and isinstance(telemetry.get("filesystems"), list)
        and all(_is_valid_filesystem_row(row) for row in telemetry["filesystems"])
        and "temps" in telemetry
        and isinstance(telemetry.get("temps"), MutableMapping)
        and all(_is_valid_mutable_mapping_row(row) for row in telemetry["temps"].values())
    )


STATIC_TELEMETRY_SENSORS: Final[tuple[SensorEntityDescription, ...]] = (
    # pfstate
    SensorEntityDescription(
        key="telemetry.pfstate.used",
        name="pf State Table Used",
        native_unit_of_measurement=COUNT,
        device_class=None,
        icon="mdi:table-network",
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="telemetry.pfstate.total",
        name="pf State Table Total",
        native_unit_of_measurement=COUNT,
        device_class=None,
        icon="mdi:table-network",
        state_class=None,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="telemetry.pfstate.used_percent",
        name="pf State Table Used Percentage",
        native_unit_of_measurement=PERCENTAGE,
        device_class=None,
        icon="mdi:table-network",
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    # mbuf
    SensorEntityDescription(
        key="telemetry.mbuf.used",
        name="Memory Buffers Used",
        native_unit_of_measurement=UnitOfInformation.BYTES,
        device_class=SensorDeviceClass.DATA_SIZE,
        icon=_ICON_MEMORY,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        suggested_unit_of_measurement=UnitOfInformation.KILOBYTES,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="telemetry.mbuf.total",
        name="Memory Buffers Total",
        native_unit_of_measurement=UnitOfInformation.BYTES,
        device_class=SensorDeviceClass.DATA_SIZE,
        icon=_ICON_MEMORY,
        state_class=None,
        suggested_display_precision=1,
        suggested_unit_of_measurement=UnitOfInformation.KILOBYTES,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="telemetry.mbuf.used_percent",
        name="Memory Buffers Used Percentage",
        native_unit_of_measurement=PERCENTAGE,
        device_class=None,
        icon=_ICON_MEMORY,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    # memory with state_class due to being less static
    SensorEntityDescription(
        key="telemetry.memory.swap_reserved",
        name="Memory Swap Reserved",
        native_unit_of_measurement=UnitOfInformation.BYTES,
        device_class=SensorDeviceClass.DATA_SIZE,
        icon=_ICON_MEMORY,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        suggested_unit_of_measurement=UnitOfInformation.MEGABYTES,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    # memory without state_class due to being generally static
    SensorEntityDescription(
        key="telemetry.memory.physmem",
        name="Memory Physmem",
        native_unit_of_measurement=UnitOfInformation.BYTES,
        device_class=SensorDeviceClass.DATA_SIZE,
        icon=_ICON_MEMORY,
        state_class=None,
        suggested_display_precision=1,
        suggested_unit_of_measurement=UnitOfInformation.GIGABYTES,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="telemetry.memory.used",
        name="Memory Used",
        native_unit_of_measurement=UnitOfInformation.BYTES,
        device_class=SensorDeviceClass.DATA_SIZE,
        icon=_ICON_MEMORY,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        suggested_unit_of_measurement=UnitOfInformation.GIGABYTES,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="telemetry.memory.swap_total",
        name="Memory Swap Total",
        native_unit_of_measurement=UnitOfInformation.BYTES,
        device_class=SensorDeviceClass.DATA_SIZE,
        icon=_ICON_MEMORY,
        state_class=None,
        suggested_display_precision=1,
        suggested_unit_of_measurement=UnitOfInformation.MEGABYTES,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    # memory percentages
    SensorEntityDescription(
        key="telemetry.memory.swap_used_percent",
        name="Memory Swap Used Percentage",
        native_unit_of_measurement=PERCENTAGE,
        device_class=None,
        icon=_ICON_MEMORY,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="telemetry.memory.used_percent",
        name="Memory Used Percentage",
        native_unit_of_measurement=PERCENTAGE,
        device_class=None,
        icon=_ICON_MEMORY,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=True,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="telemetry.cpu.count",
        name="CPU Count",
        native_unit_of_measurement=COUNT,
        device_class=None,
        icon="mdi:speedometer-medium",
        state_class=None,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="telemetry.cpu.usage_total",
        name="CPU Usage",
        native_unit_of_measurement=PERCENTAGE,
        device_class=None,
        icon="mdi:speedometer-medium",
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=True,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="telemetry.system.load_average.one_minute",
        name="System Load Average One Minute",
        native_unit_of_measurement=None,
        device_class=None,
        icon="mdi:speedometer-slow",
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=2,
        entity_registry_enabled_default=True,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="telemetry.system.load_average.five_minute",
        name="System Load Average Five Minute",
        native_unit_of_measurement=None,
        device_class=None,
        icon="mdi:speedometer-slow",
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=2,
        entity_registry_enabled_default=True,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="telemetry.system.load_average.fifteen_minute",
        name="System Load Average Fifteen Minute",
        native_unit_of_measurement=None,
        device_class=None,
        icon="mdi:speedometer-slow",
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=2,
        entity_registry_enabled_default=True,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="telemetry.system.boottime",
        name="System Boottime",
        device_class=SensorDeviceClass.TIMESTAMP,
        icon="mdi:clock-outline",
        state_class=None,
        entity_registry_enabled_default=True,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
)

STATIC_CERTIFICATE_SENSORS: Final[tuple[SensorEntityDescription, ...]] = (
    SensorEntityDescription(
        key="certificates",
        name="Certificates",
        device_class=None,
        icon="mdi:certificate-outline",
        state_class=None,
        entity_registry_enabled_default=False,
        # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
    ),
)


def _create_sensor[SensorT: OPNsenseSensor](
    entity_cls: type[SensorT],
    config_entry: ConfigEntry,
    coordinator: OPNsenseEntityCoordinator,
    entity_description: SensorEntityDescription,
) -> SensorT:
    """Create one sensor entity from shared compile context.

    Args:
        entity_cls: Sensor entity class to instantiate.
        config_entry: Home Assistant config entry for the integration.
        coordinator: Coordinator providing the OPNsense data for the entity.
        entity_description: Metadata describing the sensor entity.


    Returns:
        SensorT: Instantiated sensor entity.
    """
    return entity_cls(
        config_entry=config_entry,
        coordinator=coordinator,
        entity_description=entity_description,
    )


def _create_sensors[SensorT: OPNsenseSensor](
    entity_cls: type[SensorT],
    config_entry: ConfigEntry,
    coordinator: OPNsenseEntityCoordinator,
    entity_descriptions: Iterable[SensorEntityDescription],
) -> list[SensorT]:
    """Create sensor entities from shared compile context.

    Args:
        entity_cls: Sensor entity class to instantiate for each description.
        config_entry: Home Assistant config entry for the integration.
        coordinator: Coordinator providing the OPNsense data for each entity.
        entity_descriptions: Metadata describing the sensor entities to create.

    Returns:
        list[SensorT]: Instantiated sensor entities in description order.

    """
    return [
        _create_sensor(entity_cls, config_entry, coordinator, entity_description)
        for entity_description in entity_descriptions
    ]


def _build_interface_device_description_map(
    interfaces: Mapping[str, Any] | None,
) -> dict[str, str]:
    """Build lookup map from interface device/identifier names to friendly descriptions.

    Args:
        interfaces: Interface payload in ``get_interfaces`` shape.

    Returns:
        dict[str, str]: Mapping of possible interface identifiers (device, logical
            name, key) to user-facing description names.
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


def _build_vnstat_sensor_description(
    interface_name: str,
    interface_display_name: str,
    metric_name: str,
    metric_def: Mapping[str, Any],
) -> SensorEntityDescription:
    """Build a vnStat sensor description.

    Args:
        interface_name: OPNsense interface identifier used in the entity key.
        interface_display_name: User-facing interface name used in the entity name.
        metric_name: vnStat metric key used to identify the measurement.
        metric_def: Metric metadata containing its icon and state class.

    Returns:
        SensorEntityDescription: Description for the vnStat sensor entity.

    """
    return SensorEntityDescription(
        key=f"vnstat.{interface_name}.{metric_name}",
        name=f"vnStat: {interface_display_name}: {_vnstat_metric_display_name(metric_name)}",
        native_unit_of_measurement=UnitOfInformation.BYTES,
        device_class=SensorDeviceClass.DATA_SIZE,
        icon=metric_def["icon"],
        state_class=metric_def["state_class"],
        suggested_display_precision=1,
        suggested_unit_of_measurement=UnitOfInformation.GIBIBYTES,
        entity_registry_enabled_default=False,
    )


def _build_speedtest_sensor_description(
    key: str,
    name: str,
    native_unit: UnitOfDataRate | UnitOfTime,
    icon: str,
) -> SensorEntityDescription:
    """Build a speedtest sensor description.

    Args:
        key: Entity key for the speedtest measurement.
        name: User-facing name for the speedtest sensor.
        native_unit: Native unit of the speedtest measurement.
        icon: Material Design icon for the speedtest sensor.

    Returns:
        SensorEntityDescription: Description for the speedtest sensor entity.

    """
    return SensorEntityDescription(
        key=key,
        name=name,
        native_unit_of_measurement=native_unit,
        device_class=None if key.endswith(".latency") else SensorDeviceClass.DATA_RATE,
        icon=icon,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
    )


def _build_smart_sensor_description(device_name: str) -> SensorEntityDescription:
    """Build a SMART temperature sensor description.

    Args:
        device_name: SMART device name used in the entity key and display name.

    Returns:
        SensorEntityDescription: Description for the SMART temperature sensor.

    """
    return SensorEntityDescription(
        key=f"smart.{slugify(device_name) or 'unknown'}.temperature",
        name=f"SMART {device_name} Temperature",
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        device_class=SensorDeviceClass.TEMPERATURE,
        icon="mdi:thermometer",
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        suggested_unit_of_measurement=UnitOfTemperature.CELSIUS,
        entity_registry_enabled_default=False,
    )


def _build_filesystem_sensor_description(filesystem: Mapping[str, Any]) -> SensorEntityDescription:
    """Build a filesystem usage sensor description.

    Args:
        filesystem: Filesystem payload containing its ``mountpoint`` value.

    Returns:
        SensorEntityDescription: Description for the filesystem usage sensor.

    """
    mountpoint = filesystem["mountpoint"]
    filesystem_slug = slugify_filesystem_mountpoint(mountpoint)
    enabled_default = filesystem_slug == "root"
    return SensorEntityDescription(
        key=f"telemetry.filesystems.{filesystem_slug}",
        name=(f"Filesystem Used Percentage {normalize_filesystem_mountpoint(mountpoint)}"),
        native_unit_of_measurement=PERCENTAGE,
        device_class=None,
        icon="mdi:harddisk",
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=enabled_default,
    )


def _build_interface_sensor_description(
    interface_name: str,
    interface: Mapping[str, Any],
    prop_name: str,
) -> SensorEntityDescription:
    """Build an interface sensor description.

    Args:
        interface_name: OPNsense interface identifier used in the entity key.
        interface: Interface payload used for its friendly display name.
        prop_name: Interface property represented by the sensor.

    Returns:
        SensorEntityDescription: Description for the interface sensor.

    """
    state_class: SensorStateClass | None = SensorStateClass.MEASUREMENT
    native_unit_of_measurement = None
    device_class = None
    enabled_default = prop_name in {
        "status",
        "inbytes_kilobytes_per_second",
        "outbytes_kilobytes_per_second",
    }
    suggested_display_precision = None
    suggested_unit_of_measurement: UnitOfDataRate | UnitOfInformation | None = None

    if "_packets_per_second" in prop_name:
        native_unit_of_measurement = DATA_RATE_PACKETS_PER_SECOND

    if "_kilobytes_per_second" in prop_name:
        native_unit_of_measurement = UnitOfDataRate.KILOBYTES_PER_SECOND
        device_class = SensorDeviceClass.DATA_RATE
        suggested_unit_of_measurement = UnitOfDataRate.MEGABITS_PER_SECOND

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

    if "pkts" in prop_name or "bytes" in prop_name:
        icon = "mdi:server-network"
    elif prop_name == "status":
        icon = "mdi:check-network"
        state_class = None
    else:
        icon = "mdi:gauge"

    property_name = _INTERFACE_TRAFFIC_SENSOR_NAMES.get(prop_name, prop_name)
    return SensorEntityDescription(
        key=f"interface.{interface_name}.{prop_name}",
        name=f"Interface {interface.get('name', interface_name)} {property_name}",
        native_unit_of_measurement=native_unit_of_measurement,
        device_class=device_class,
        icon=icon,
        state_class=state_class,
        suggested_display_precision=suggested_display_precision,
        suggested_unit_of_measurement=suggested_unit_of_measurement,
        entity_registry_enabled_default=enabled_default,
    )


def _build_gateway_sensor_description(
    gateway_key: str,
    gateway_name: str,
    prop_name: str,
) -> SensorEntityDescription:
    """Build a gateway sensor description.

    Args:
        gateway_key: Stable gateway identifier used in the entity key.
        gateway_name: Human-readable gateway name used in the entity label.
        prop_name: Gateway property represented by the sensor.

    Returns:
        SensorEntityDescription: Description for the gateway sensor.

    """
    native_unit_of_measurement = None
    device_class: SensorDeviceClass | None = None
    state_class: SensorStateClass | None = SensorStateClass.MEASUREMENT
    enabled_default = False
    icon = "mdi:router-network"

    if prop_name == "loss":
        native_unit_of_measurement = PERCENTAGE
    if prop_name in {"delay", "stddev"}:
        native_unit_of_measurement = UnitOfTime.MILLISECONDS
    if prop_name == "status":
        icon = "mdi:check-network"
        state_class = None
        enabled_default = True
    if prop_name == "address":
        icon = "mdi:ip-network"
        state_class = None

    return SensorEntityDescription(
        key=f"gateway.{gateway_key}.{prop_name}",
        name=f"Gateway {gateway_name} {prop_name}",
        native_unit_of_measurement=native_unit_of_measurement,
        device_class=device_class,
        icon=icon,
        state_class=state_class,
        entity_registry_enabled_default=enabled_default,
    )


def _build_temperature_sensor_description(
    temp_device: str,
    temp: Mapping[str, Any],
) -> SensorEntityDescription:
    """Build a temperature telemetry sensor description.

    Args:
        temp_device: Temperature device identifier used in the entity key.
        temp: Temperature payload used for its friendly display name.

    Returns:
        SensorEntityDescription: Description for the temperature sensor.

    """
    return SensorEntityDescription(
        key=f"telemetry.temps.{temp_device}",
        name=f"Temp {temp.get('name', temp_device)}",
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        device_class=SensorDeviceClass.TEMPERATURE,
        icon="mdi:thermometer",
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        suggested_unit_of_measurement=UnitOfTemperature.CELSIUS,
        entity_registry_enabled_default=True,
    )


def _build_dhcp_leases_sensor_description(
    interface: str,
    interface_name: str,
) -> SensorEntityDescription:
    """Build a per-interface DHCP leases sensor description.

    Args:
        interface: OPNsense interface identifier used in the entity key.
        interface_name: User-facing interface name used in the entity name.

    Returns:
        SensorEntityDescription: Description for the interface lease sensor.

    """
    return SensorEntityDescription(
        key=f"dhcp_leases.{interface}",
        name=f"DHCP Leases {interface_name}",
        native_unit_of_measurement="leases",
        device_class=None,
        icon="mdi:devices",
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
    )


def _build_dhcp_leases_total_sensor_description() -> SensorEntityDescription:
    """Build the aggregate DHCP leases sensor description.

    Returns:
        SensorEntityDescription: Description for the aggregate lease sensor.

    """
    return SensorEntityDescription(
        key="dhcp_leases.all",
        name="DHCP Leases All",
        native_unit_of_measurement="leases",
        device_class=None,
        icon="mdi:devices",
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=True,
    )


def _build_vpn_sensor_description(
    vpn_type: str,
    clients_servers: str,
    uuid: str,
    instance_name: str,
    prop_name: str,
) -> SensorEntityDescription:
    """Build a VPN sensor description.

    Args:
        vpn_type: VPN implementation type, such as ``openvpn`` or ``wireguard``.
        clients_servers: VPN collection type represented by the sensor.
        uuid: VPN instance identifier used in the entity key.
        instance_name: User-facing VPN instance name.
        prop_name: VPN property represented by the sensor.

    Returns:
        SensorEntityDescription: Description for the VPN sensor entity.

    """
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

    return SensorEntityDescription(
        key=f"{vpn_type}.{clients_servers}.{uuid}.{prop_name}",
        name=(
            f"{'OpenVPN' if vpn_type == 'openvpn' else vpn_type.title()} "
            f"{clients_servers.title().rstrip('s')} {instance_name} {prop_name}"
        ),
        native_unit_of_measurement=native_unit_of_measurement,
        device_class=device_class,
        icon=icon,
        state_class=state_class,
        suggested_display_precision=suggested_display_precision,
        suggested_unit_of_measurement=suggested_unit_of_measurement,
        entity_registry_enabled_default=enabled_default,
    )


async def _compile_static_telemetry_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
) -> list:
    """Compile static telemetry sensors.

    Args:
        config_entry: Config entry being exercised by the helper or test.
        coordinator: Data update coordinator that caches OPNsense state for entities.

    Returns:
        list: Compiled static telemetry sensor entities.
    """
    return _create_sensors(
        OPNsenseStaticKeySensor,
        config_entry,
        coordinator,
        STATIC_TELEMETRY_SENSORS,
    )


async def _compile_static_certificate_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
) -> list:
    """Compile static certificate sensors.

    Args:
        config_entry: Config entry being exercised by the helper or test.
        coordinator: Data update coordinator that caches OPNsense state for entities.

    Returns:
        list: Compiled static certificate sensor entities.
    """
    return _create_sensors(
        OPNsenseStaticKeySensor,
        config_entry,
        coordinator,
        STATIC_CERTIFICATE_SENSORS,
    )


async def _compile_vnstat_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile per-interface vnStat sensors.

    Args:
        config_entry: Config entry owning the sensors.
        coordinator: Data update coordinator supplying state.
        state: Coordinator state snapshot containing vnStat interfaces.

    Returns:
        list: Compiled vnStat sensor entities.
    """
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
        if not _is_valid_vnstat_interface_row(interface_name):
            continue
        interface_display_name = interface_descriptions.get(interface_name, interface_name)
        for metric_name, metric_def in metric_defs.items():
            entities.append(
                _create_sensor(
                    OPNsenseVnstatSensor,
                    config_entry,
                    coordinator,
                    _build_vnstat_sensor_description(
                        interface_name,
                        interface_display_name,
                        metric_name,
                        metric_def,
                    ),
                )
            )
    return entities


async def _compile_speedtest_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile speedtest sensors from normalized coordinator state.

    Args:
        config_entry: Config entry owning the sensors.
        coordinator: Data update coordinator supplying state.
        state: Coordinator state snapshot containing speedtest instances.

    Returns:
        list: Compiled speedtest sensor entities.
    """
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
    return _create_sensors(
        OPNsenseSpeedtestSensor,
        config_entry,
        coordinator,
        [
            _build_speedtest_sensor_description(key, name, native_unit, icon)
            for key, name, native_unit, icon in metric_definitions
        ],
    )


async def _compile_smart_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile SMART hard disk sensors from normalized SMART device rows.

    Args:
        config_entry: Config entry being exercised by the helper or test.
        coordinator: Data update coordinator that caches OPNsense state for entities.
        state: Coordinator state snapshot that contains SMART device data.

    Returns:
        list: SMART disk sensor entities disabled by default.
    """
    if not isinstance(state, MutableMapping):
        return []
    if "smart_info" not in state:
        return []
    smart_devices = state.get("smart")
    if not isinstance(smart_devices, list):
        return []
    entities: list = []
    for smart_device in smart_devices:
        if not _is_valid_smart_device_row(smart_device):
            continue
        device_name = get_smart_device_name(smart_device)
        entities.append(
            _create_sensor(
                OPNsenseSmartSensor,
                config_entry,
                coordinator,
                _build_smart_sensor_description(device_name),
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

    Returns:
        list: Compiled filesystem sensor entities.
    """
    if not isinstance(state, MutableMapping):
        return []
    filesystems = dict_get(state, "telemetry.filesystems", []) or []
    if not isinstance(filesystems, list):
        return []
    return _create_sensors(
        OPNsenseFilesystemSensor,
        config_entry,
        coordinator,
        [
            _build_filesystem_sensor_description(filesystem)
            for filesystem in filesystems
            if _is_valid_filesystem_row(filesystem)
        ],
    )


async def _compile_carp_interface_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile CARP interface sensors.

    Args:
        config_entry: Config entry being exercised by the helper or test.
        coordinator: Data update coordinator that caches OPNsense state for entities.
        state: Coordinator state snapshot that contains CARP interface status data.

    Returns:
        list: Compiled CARP interface sensor entities.
    """
    if not isinstance(state, MutableMapping):
        return []
    entities: list[OPNsenseCarpInterfaceSensor] = []

    interface_descriptions = _build_interface_device_description_map(
        dict_get(state, "interfaces", {}) or {}
    )
    carp_interfaces = dict_get(state, "carp.interfaces", []) or []
    for interface in carp_interfaces:
        if not _is_valid_carp_interface_row(interface):
            _LOGGER.debug(
                "Skipping malformed CARP interface entry: %r",
                interface,
            )
            continue
        try:
            subnet = interface["subnet"].strip()

            interface_name = interface.get("interface")
            interface_label = str(interface_name).strip() if interface_name is not None else ""
            if not interface_label:
                interface_label = "unknown"
            friendly_interface_name = interface_descriptions.get(interface_label, interface_label)

            display_name = f"CARP Interface: {friendly_interface_name}: {subnet}"
            entities.append(
                _create_sensor(
                    OPNsenseCarpInterfaceSensor,
                    config_entry,
                    coordinator,
                    SensorEntityDescription(
                        key=_build_carp_interface_sensor_key(interface_label, subnet),
                        name=display_name,
                        native_unit_of_measurement=None,
                        device_class=None,
                        icon="mdi:check-network",
                        state_class=None,
                        entity_registry_enabled_default=False,
                    ),
                )
            )
        except (AttributeError, TypeError, ValueError) as err:
            _LOGGER.debug("Skipping malformed CARP interface entry: %r (%s)", interface, err)
    return entities


def _build_carp_interface_sensor_key(interface_name: str | None, subnet: str) -> str:
    """Build CARP interface sensor key with interface and subnet context.

    Args:
        interface_name: Interface identifier supplied by CARP payload.
        subnet: Virtual IP value from CARP payload.

    Returns:
        str: CARP sensor key in ``carp.interface.<interface_slug>.<subnet_slug>`` format.
    """
    interface_label = interface_name.strip() if isinstance(interface_name, str) else ""
    interface_slug = slugify(interface_label) if interface_label else "unknown"
    if not interface_slug:
        interface_slug = "unknown"
    subnet_slug = slugify(subnet.strip())
    return f"carp.interface.{interface_slug}.{subnet_slug}"


def _parse_carp_interface_sensor_key(key: str) -> tuple[str, str] | None:
    """Parse CARP interface sensor key into interface and subnet slugs.

    Args:
        key: Sensor key from entity description.

    Returns:
        tuple[str, str] | None: Tuple of interface slug and subnet slug when valid.
    """
    key_parts = key.split(".")
    if len(key_parts) != 4 or key_parts[0] != "carp" or key_parts[1] != "interface":
        return None
    interface_slug = key_parts[2].strip() or "unknown"
    subnet_slug = key_parts[3].strip()
    if not subnet_slug:
        return None
    return (interface_slug, subnet_slug)


def _normalize_carp_value(value: Any) -> str:
    """Normalize a CARP identifier or subnet value for matching.

    Args:
        value: Raw CARP value, which may be a number or string.

    Returns:
        str: Trimmed value, or an empty string when it cannot be normalized.
    """
    if value is None:
        return ""
    try:
        return str(value).strip()
    except AttributeError, RuntimeError, TypeError, ValueError:
        return ""


def _normalize_carp_vip_subnet(subnet: str) -> str:
    """Return a stable CARP subnet identity for entity matching and key generation.

    Args:
        subnet: CARP subnet or address value to normalize.

    Returns:
        str: Slugified IP identity, or the normalized raw subnet when parsing fails.
    """
    raw_subnet = subnet.strip()
    if not raw_subnet:
        return ""
    try:
        return slugify(str(ipaddress.ip_interface(raw_subnet).ip))
    except ValueError, TypeError:
        return slugify(raw_subnet)


def _build_carp_vip_sensor_key(vhid: str, subnet: str) -> str:
    """Build a node-independent CARP VIP key from synchronized values.

    Args:
        vhid: CARP virtual host ID.
        subnet: CARP virtual IP or subnet value.

    Returns:
        str: Stable CARP VIP sensor key.
    """
    return f"carp.vip.{slugify(vhid.strip())}.{_normalize_carp_vip_subnet(subnet)}"


def _parse_carp_vip_sensor_key(key: str) -> tuple[str, str] | None:
    """Parse a CARP VIP key into its VHID and subnet slugs.

    Args:
        key: Sensor description key to parse.

    Returns:
        tuple[str, str] | None: VHID and subnet slugs when the key is valid.
    """
    key_parts = key.split(".")
    if len(key_parts) != 4 or key_parts[:2] != ["carp", "vip"]:
        return None
    vhid_slug, subnet_slug = (part.strip() for part in key_parts[2:])
    if not vhid_slug or not subnet_slug:
        return None
    return vhid_slug, subnet_slug


async def _compile_carp_vip_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile stable, read-only CARP VIP sensors.

    Args:
        config_entry: CARP config entry being exercised by the helper or test.
        coordinator: Data update coordinator that caches CARP state.
        state: Coordinator state snapshot that contains CARP interface rows.

    Returns:
        list: CARP VIP sensors disabled by default.
    """
    if not isinstance(state, MutableMapping):
        return []
    carp_interfaces = dict_get(state, "carp.interfaces", []) or []
    if not isinstance(carp_interfaces, list):
        return []

    entities: list[OPNsenseCarpVipSensor] = []
    seen_keys: set[str] = set()
    for interface in carp_interfaces:
        if not isinstance(interface, Mapping):
            continue
        vhid = _normalize_carp_value(interface.get("vhid"))
        subnet = _normalize_carp_value(interface.get("subnet"))
        if not vhid or not subnet:
            continue
        key = _build_carp_vip_sensor_key(vhid, subnet)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        entities.append(
            _create_sensor(
                OPNsenseCarpVipSensor,
                config_entry,
                coordinator,
                SensorEntityDescription(
                    key=key,
                    name=f"CARP VIP {subnet} (VHID {vhid})",
                    translation_key="carp_vip",
                    translation_placeholders={"subnet": subnet, "vhid": vhid},
                    native_unit_of_measurement=None,
                    device_class=None,
                    icon="mdi:ip-network",
                    state_class=None,
                    entity_registry_enabled_default=False,
                ),
            )
        )
    return entities


async def _compile_carp_status_sensor(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: MutableMapping[str, Any],
) -> list:
    """Compile aggregate CARP status sensor.

    Args:
        config_entry: Config entry being exercised by the helper or test.
        coordinator: Data update coordinator that caches OPNsense state for entities.
        state: Coordinator state snapshot that contains CARP summary status data.

    Returns:
        list: Compiled aggregate CARP status sensor entities.
    """
    if not isinstance(state, MutableMapping):
        return []
    return [
        _create_sensor(
            OPNsenseCarpStatusSensor,
            config_entry,
            coordinator,
            SensorEntityDescription(
                key="carp.status_summary",
                name="CARP Status",
                translation_key=("carp_status_summary" if is_carp_entry(config_entry) else None),
                native_unit_of_measurement=None,
                device_class=None,
                icon="mdi:gauge",
                state_class=None,
                entity_registry_enabled_default=False,
            ),
        )
    ]


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

    Returns:
        list: Compiled interface sensor entities.
    """
    if not isinstance(state, MutableMapping):
        return []
    options: Mapping[str, Any] = getattr(config_entry, "data", {})
    sync_interfaces: bool = options.get(CONF_SYNC_INTERFACES, DEFAULT_SYNC_OPTION_VALUE)
    sync_live_traffic: bool = options.get(CONF_SYNC_LIVE_TRAFFIC, DEFAULT_SYNC_OPTION_VALUE)
    live_traffic_coordinator: OPNsenseLiveTrafficCoordinator | None = None
    if sync_interfaces and sync_live_traffic:
        live_traffic_coordinator = _get_runtime_live_traffic_coordinator(config_entry)

    entities: list[OPNsenseInterfaceSensor] = []

    interfaces = dict_get(state, "interfaces", {}) or {}
    if not isinstance(interfaces, MutableMapping):
        return []

    for interface_name, interface in interfaces.items():
        if not _is_valid_mutable_mapping_row(interface):
            continue
        entities.extend(
            _create_sensor(
                (
                    OPNsenseLiveTrafficSensor
                    if prop_name in _INTERFACE_RATE_SENSOR_PROPERTIES
                    and live_traffic_coordinator is not None
                    else OPNsenseInterfaceSensor
                ),
                config_entry,
                (
                    live_traffic_coordinator
                    if prop_name in _INTERFACE_RATE_SENSOR_PROPERTIES
                    and live_traffic_coordinator is not None
                    else coordinator
                ),
                _build_interface_sensor_description(interface_name, interface, prop_name),
            )
            for prop_name in _INTERFACE_SENSOR_PROPERTIES
        )

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

    Returns:
        list: Compiled gateway sensor entities.
    """
    if not isinstance(state, MutableMapping):
        return []
    entities: list[OPNsenseGatewaySensor] = []

    gateways = dict_get(state, "gateways", {}) or {}
    if not isinstance(gateways, MutableMapping):
        return []

    for gateway_key, gateway in gateways.items():
        if not _is_valid_mutable_mapping_row(gateway):
            continue
        gateway_name = OPNsenseEntity.payload_display_name(gateway, str(gateway_key), "name")
        entities.extend(
            OPNsenseGatewaySensor(
                config_entry=config_entry,
                coordinator=coordinator,
                entity_description=_build_gateway_sensor_description(
                    str(gateway_key), gateway_name, prop_name
                ),
                unique_id_suffix=f"gateway.{gateway_name}.{prop_name}",
            )
            for prop_name in _GATEWAY_SENSOR_PROPERTIES
        )

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

    Returns:
        list: Compiled temperature sensor entities.
    """
    if not isinstance(state, MutableMapping):
        return []
    entities: list = []

    temps = dict_get(state, "telemetry.temps", {}) or {}
    if not isinstance(temps, MutableMapping):
        return []

    for temp_device, temp in temps.items():
        if not _is_valid_mutable_mapping_row(temp):
            continue
        entities.append(
            _create_sensor(
                OPNsenseTempSensor,
                config_entry,
                coordinator,
                _build_temperature_sensor_description(temp_device, temp),
            )
        )
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

    Returns:
        list: Compiled DHCP lease sensor entities.
    """
    if not isinstance(state, MutableMapping):
        return []
    entities: list = []

    lease_interfaces = dict_get(state, "dhcp_leases.lease_interfaces", {}) or {}
    if not isinstance(lease_interfaces, MutableMapping):
        lease_interfaces = {}

    lease_interface_items: Iterable[tuple[Any, Any]] = ()
    try:
        lease_interface_items = lease_interfaces.items()
    except AttributeError, RuntimeError, TypeError, ValueError:
        lease_interface_items = ()

    for interface, interface_name in lease_interface_items:
        entities.append(
            _create_sensor(
                OPNsenseDHCPLeasesSensor,
                config_entry,
                coordinator,
                _build_dhcp_leases_sensor_description(interface, interface_name),
            )
        )
    entities.append(
        _create_sensor(
            OPNsenseDHCPLeasesSensor,
            config_entry,
            coordinator,
            _build_dhcp_leases_total_sensor_description(),
        )
    )

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

    Returns:
        list: Compiled VPN sensor entities.
    """
    if not isinstance(state, MutableMapping):
        return []
    entities: list = []

    for vpn_type in ("openvpn", "wireguard"):
        clients_servers_groups = ["servers"] if vpn_type == "openvpn" else ["clients", "servers"]
        for clients_servers in clients_servers_groups:
            vpn_instances = dict_get(state, f"{vpn_type}.{clients_servers}", {}) or {}
            if not isinstance(vpn_instances, MutableMapping):
                continue
            for uuid, instance in vpn_instances.items():
                if not _is_valid_vpn_sensor_row(instance):
                    continue
                instance_name = OPNsenseEntity.payload_display_name(
                    instance,
                    str(uuid),
                    "name",
                    "description",
                    allow_scalar=False,
                )
                properties = list(_VPN_TRAFFIC_PROPERTIES)
                if clients_servers == "servers":
                    properties.extend(_VPN_SERVER_PROPERTIES)
                if vpn_type == "wireguard" and clients_servers == "clients":
                    properties.extend(_VPN_WIREGUARD_CLIENT_PROPERTIES)
                entities.extend(
                    _create_sensor(
                        OPNsenseVPNSensor,
                        config_entry,
                        coordinator,
                        _build_vpn_sensor_description(
                            vpn_type,
                            clients_servers,
                            uuid,
                            instance_name,
                            prop_name,
                        ),
                    )
                    for prop_name in properties
                )
    return entities


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the OPNsense sensors.

    Args:
        hass: Home Assistant instance receiving the entities.
        config_entry: Config entry whose sensors are being set up.
        async_add_entities: Callback used to register compiled entities.
    """
    coordinator: OPNsenseDataUpdateCoordinator = getattr(config_entry.runtime_data, COORDINATOR)
    state: dict[str, Any] = coordinator.data
    if not isinstance(state, MutableMapping):
        _LOGGER.error("Missing state data in sensor async_setup_entry")
        return
    config: Mapping[str, Any] = config_entry.data
    entities: list = []

    if is_carp_entry(config_entry):
        entities = [
            _create_sensor(
                OPNsenseCarpActiveResponderSensor,
                config_entry,
                coordinator,
                SensorEntityDescription(
                    key="carp.active_responder",
                    name="Active CARP Responder",
                    translation_key="carp_active_responder",
                    icon="mdi:server-network",
                    entity_registry_enabled_default=True,
                ),
            )
        ]
        entities.extend(await _compile_carp_status_sensor(config_entry, coordinator, state))
        entities.extend(await _compile_carp_vip_sensors(config_entry, coordinator, state))
        async_add_entities(entities)
        return

    reconciliation_complete = True

    if config.get(CONF_SYNC_TELEMETRY, DEFAULT_SYNC_OPTION_VALUE):
        telemetry = state.get("telemetry")
        entities.extend(await _compile_static_telemetry_sensors(config_entry, coordinator))
        entities.extend(await _compile_filesystem_sensors(config_entry, coordinator, state))
        entities.extend(await _compile_temperature_sensors(config_entry, coordinator, state))
        if "telemetry" not in state or not _telemetry_rows_are_complete(telemetry):
            reconciliation_complete = False
    if config.get(CONF_SYNC_VNSTAT, DEFAULT_SYNC_OPTION_VALUE):
        if "vnstat" in state and isinstance(state.get("vnstat"), MutableMapping):
            entities.extend(await _compile_vnstat_sensors(config_entry, coordinator, state))
            reconciliation_complete &= _vnstat_rows_are_complete(state)
        else:
            reconciliation_complete = False
    if config.get(CONF_SYNC_SPEEDTEST, DEFAULT_SYNC_OPTION_VALUE):
        if "speedtest" in state and isinstance(state.get("speedtest"), MutableMapping):
            entities.extend(await _compile_speedtest_sensors(config_entry, coordinator, state))
        else:
            reconciliation_complete = False
    if config.get(CONF_SYNC_SMART, DEFAULT_SYNC_OPTION_VALUE):
        client = getattr(config_entry.runtime_data, OPNSENSE_CLIENT, None)
        client_supports_smart = callable(getattr(client, "get_smart", None))
        client_supports_smart_info = callable(getattr(client, "get_smart_info", None))
        has_smart = "smart" in state and isinstance(state.get("smart"), list)
        has_smart_info = "smart_info" in state and isinstance(state.get("smart_info"), Mapping)
        if client is None:
            has_smart_inventory = has_smart and has_smart_info
        elif client_supports_smart:
            has_smart_inventory = has_smart and (not client_supports_smart_info or has_smart_info)
        else:
            has_smart_inventory = False
        has_smart_inventory = has_smart_inventory and all(
            _is_valid_smart_device_row(device) for device in state["smart"]
        )
        entities.extend(await _compile_smart_sensors(config_entry, coordinator, state))
        if not has_smart_inventory:
            reconciliation_complete = False
    if config.get(CONF_SYNC_CERTIFICATES, DEFAULT_SYNC_OPTION_VALUE):
        entities.extend(await _compile_static_certificate_sensors(config_entry, coordinator))
    if config.get(CONF_SYNC_VPN, DEFAULT_SYNC_OPTION_VALUE):
        has_openvpn_inventory = "openvpn" in state and isinstance(
            state.get("openvpn"), MutableMapping
        )
        has_wireguard_inventory = "wireguard" in state and isinstance(
            state.get("wireguard"), MutableMapping
        )
        entities.extend(await _compile_vpn_sensors(config_entry, coordinator, state))
        if not (
            has_openvpn_inventory
            and has_wireguard_inventory
            and _vpn_sensor_rows_are_complete(state)
        ):
            reconciliation_complete = False
    if config.get(CONF_SYNC_GATEWAYS, DEFAULT_SYNC_OPTION_VALUE):
        gateways = state.get("gateways")
        if "gateways" in state and isinstance(gateways, MutableMapping):
            entities.extend(await _compile_gateway_sensors(config_entry, coordinator, state))
            reconciliation_complete &= all(
                _is_valid_mutable_mapping_row(row) for row in gateways.values()
            )
        else:
            reconciliation_complete = False
    if config.get(CONF_SYNC_INTERFACES, DEFAULT_SYNC_OPTION_VALUE):
        interfaces = state.get("interfaces")
        if "interfaces" in state and isinstance(interfaces, MutableMapping):
            entities.extend(await _compile_interface_sensors(config_entry, coordinator, state))
            reconciliation_complete &= all(
                _is_valid_mutable_mapping_row(row) for row in interfaces.values()
            )
        else:
            reconciliation_complete = False
    if config.get(CONF_SYNC_CARP, DEFAULT_SYNC_OPTION_VALUE):
        entities.extend(await _compile_carp_status_sensor(config_entry, coordinator, state))
        carp = state.get("carp")
        if (
            "carp" in state
            and isinstance(carp, MutableMapping)
            and "interfaces" in carp
            and isinstance(carp.get("interfaces"), list)
        ):
            entities.extend(await _compile_carp_interface_sensors(config_entry, coordinator, state))
            reconciliation_complete &= all(
                _is_valid_carp_interface_row(interface) for interface in carp["interfaces"]
            )
        else:
            reconciliation_complete = False
    if config.get(CONF_SYNC_DHCP_LEASES, DEFAULT_SYNC_OPTION_VALUE):
        entities.extend(await _compile_dhcp_leases_sensors(config_entry, coordinator, state))
        dhcp_leases = state.get("dhcp_leases")
        if not (
            "dhcp_leases" in state
            and isinstance(dhcp_leases, MutableMapping)
            and "lease_interfaces" in dhcp_leases
            and isinstance(dhcp_leases.get("lease_interfaces"), MutableMapping)
        ):
            reconciliation_complete = False

    _LOGGER.debug("[sensor async_setup_entry] entities: %s", len(entities))
    record_desired_entities(config_entry, "sensor", entities if reconciliation_complete else None)
    async_add_entities(entities)


def slugify_filesystem_mountpoint(mountpoint: str) -> str:
    """Slugify a filesystem mountpoint for use in an entity key.

    Args:
        mountpoint: Filesystem mountpoint to normalize.

    Returns:
        str: Stable mountpoint slug.
    """
    if not mountpoint:
        return ""
    if mountpoint == "/":
        return "root"
    return mountpoint.replace("/", "_").strip("_")


def normalize_filesystem_mountpoint(mountpoint: str) -> str:
    """Normalize a filesystem mountpoint for display.

    Args:
        mountpoint: Filesystem mountpoint to normalize.

    Returns:
        str: Display-friendly mountpoint.
    """
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
        coordinator: OPNsenseEntityCoordinator,
        entity_description: SensorEntityDescription,
        unique_id_suffix: str | None = None,
    ) -> None:
        """Initialize the sensor.

        Args:
            config_entry: Config entry owning the sensor.
            coordinator: Data update coordinator supplying sensor state.
            entity_description: Description of the sensor entity.
            unique_id_suffix: Optional stable suffix for the entity unique ID.
        """
        name_suffix: str | None = (
            entity_description.name
            if isinstance(entity_description.name, str)
            and entity_description.translation_key is None
            else None
        )
        if unique_id_suffix is None:
            unique_id_suffix = (
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
            self._mark_unavailable()
            return

        if (
            value == 0
            and self._previous_value is None
            and self.entity_description.key == "telemetry.cpu.usage_total"
        ):
            self._mark_unavailable()
            return

        if self.entity_description.key == "telemetry.system.boottime":
            value = utc_from_timestamp(value) if value else None

        elif self.entity_description.key == "telemetry.cpu.usage_total":
            if value == 0 and self._previous_value is not None:
                value = self._previous_value

            if value == 0:
                self._mark_unavailable()
                return
        elif self.entity_description.key == "certificates":
            value = len(value)

        self._available = True
        self._previous_value = value
        self._attr_native_value = value

        self._attr_extra_state_attributes = {}
        if self.entity_description.key == "telemetry.cpu.usage_total":
            temp_attr = self._get_opnsense_state_value("telemetry.cpu")
            if isinstance(temp_attr, MutableMapping):
                for k, v in temp_attr.items():
                    if k.startswith("usage_") and k != "usage_total":
                        self._attr_extra_state_attributes[k.replace("usage_", "")] = f"{v}%"
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
            self._mark_unavailable()
            return

        key_parts = self.entity_description.key.split(".")
        if len(key_parts) != 3:
            self._mark_unavailable()
            return
        _, interface_name, metric_name = key_parts

        metric = dict_get(state, f"vnstat.interfaces.{interface_name}.metrics.{metric_name}", {})
        if not isinstance(metric, MutableMapping):
            self._mark_unavailable()
            return

        total = metric.get("total_bytes")
        if not isinstance(total, int):
            self._mark_unavailable()
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
            self._mark_unavailable()
            return

        key_parts = self.entity_description.key.split(".")
        if len(key_parts) != 3:
            self._mark_unavailable()
            return
        _, speedtest_section, metric_name = key_parts

        metric = dict_get(state, f"speedtest.{speedtest_section}.{metric_name}", {})
        if not isinstance(metric, MutableMapping):
            self._mark_unavailable()
            return

        value = metric.get("value")
        if not isinstance(value, (int, float)):
            self._mark_unavailable()
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


class OPNsenseSmartSensor(OPNsenseSensor):
    """Class for OPNsense SMART disk sensors."""

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator updates for SMART disk sensors."""
        state: dict[str, Any] = self.coordinator.data
        if not isinstance(state, MutableMapping):
            self._mark_unavailable()
            return

        key_parts = self.entity_description.key.split(".")
        if len(key_parts) != 3:
            self._mark_unavailable()
            return
        _, expected_device_slug, prop_name = key_parts
        if prop_name != "temperature":
            self._mark_unavailable()
            return

        smart_devices = state.get("smart")
        if not isinstance(smart_devices, list):
            self._mark_unavailable()
            return

        smart_device: Mapping[str, Any] | None = None
        for candidate in smart_devices:
            if not isinstance(candidate, Mapping):
                continue
            device_name = get_smart_device_name(candidate)
            if not device_name:
                continue
            if (slugify(device_name.strip()) or "unknown") == expected_device_slug:
                smart_device = candidate
                break

        if smart_device is None:
            self._mark_unavailable()
            return

        device_name = get_smart_device_name(smart_device)
        smart_info = state.get("smart_info")
        device_info = smart_info.get(device_name) if isinstance(smart_info, Mapping) else None
        if not isinstance(device_info, Mapping):
            self._mark_unavailable()
            return

        temperature_entry = device_info.get("temperature")
        if not isinstance(temperature_entry, (Mapping, int, float)):
            self._mark_unavailable()
            return

        if isinstance(temperature_entry, bool):
            self._mark_unavailable()
            return

        temperature: int | float | None = None
        if isinstance(temperature_entry, int | float):
            temperature = temperature_entry
        elif isinstance(temperature_entry, Mapping):
            current_temp = temperature_entry.get("current")
            if isinstance(current_temp, int | float):
                temperature = current_temp
                if isinstance(temperature, bool):
                    temperature = None

        if temperature is None:
            self._mark_unavailable()
            return

        self._available = True
        self._attr_native_value = temperature
        self._attr_extra_state_attributes = {}
        for attr in ("device", "ident", "model", "serial_number", "serial", "type"):
            attr_value = smart_device.get(attr)
            if attr_value is not None and attr_value != "":
                self._attr_extra_state_attributes[attr] = attr_value
        self.async_write_ha_state()


class OPNsenseFilesystemSensor(OPNsenseSensor):
    """Class for OPNsense Filesystem Sensors."""

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update."""
        filesystem: dict[str, Any] = {}
        filesystems = self._list_at("telemetry.filesystems")
        if filesystems is None:
            self._mark_unavailable()
            return
        for fsystem in filesystems:
            if not isinstance(fsystem, MutableMapping):
                continue
            mountpoint = fsystem.get("mountpoint")
            if (
                isinstance(mountpoint, str)
                and self.entity_description.key
                == f"telemetry.filesystems.{slugify_filesystem_mountpoint(mountpoint)}"
            ):
                filesystem = dict(fsystem)
        if not filesystem:
            self._mark_unavailable()
            return

        try:
            self._attr_native_value = filesystem["used_pct"]
        except TypeError, KeyError, AttributeError:
            self._mark_unavailable()
            return
        self._available = True

        self._attr_extra_state_attributes = {}
        for attr in ("mountpoint", "device", "type", "blocks", "used", "available"):
            if attr in filesystem:
                self._attr_extra_state_attributes[attr] = filesystem[attr]
        self.async_write_ha_state()


class OPNsenseInterfaceSensor(OPNsenseSensor):
    """Class for OPNsense Interface Sensors."""

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update."""
        key_parts = self.entity_description.key.split(".", 1)
        if len(key_parts) != 2:
            self._mark_unavailable()
            return
        interface_and_prop = key_parts[1]
        interface_name_parts = interface_and_prop.rsplit(".", 1)
        if len(interface_name_parts) != 2:
            self._mark_unavailable()
            return
        interface_name, prop_name = interface_name_parts
        interface: dict[str, Any] = {}
        interfaces = self._mapping_at("interfaces")
        if interfaces is None:
            self._mark_unavailable()
            return
        for i_interface_name, iface in interfaces.items():
            if i_interface_name == interface_name:
                interface = iface
                break
        if not interface:
            self._mark_unavailable()
            return
        try:
            self._attr_native_value = interface[prop_name]
        except TypeError, KeyError, ZeroDivisionError:
            self._mark_unavailable()
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
            if attr in interface and (interface[attr] or isinstance(interface[attr], bool)):
                self._attr_extra_state_attributes[attr] = interface[attr]
        if interface.get("enabled") is not None and not coerce_bool(interface.get("enabled")):
            self._attr_native_value = None
            self._mark_unavailable()
            return
        self.async_write_ha_state()

    @property
    def icon(self) -> str | None:
        """Return the icon for the sensor.

        Returns:
            str | None: Icon identifier, or the inherited icon.
        """
        key_parts = self.entity_description.key.rsplit(".", 1)
        if len(key_parts) != 2:
            return super().icon
        prop_name: str = key_parts[1]
        if prop_name == "status" and self.native_value != "up":
            return "mdi:close-network-outline"
        return super().icon


class OPNsenseLiveTrafficSensor(OPNsenseInterfaceSensor):
    """Class for OPNsense live interface rate sensors."""

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update for rate entries with live-update gating."""
        if not self.coordinator.last_update_success:
            self._mark_unavailable()
            return
        super()._handle_coordinator_update()


class OPNsenseCarpActiveResponderSensor(OPNsenseSensor):
    """Class for the active OPNsense node observed by a CARP endpoint."""

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator updates for the active CARP responder."""
        system_info = self._mapping_at("system_info")
        if system_info is None:
            self._mark_unavailable(clear_attributes=True)
            return

        responder_name = system_info.get("name")
        if not isinstance(responder_name, str) or not responder_name.strip():
            self._mark_unavailable(clear_attributes=True)
            return

        self._available = True
        self._attr_native_value = responder_name.strip()
        self._attr_extra_state_attributes = {}
        self.async_write_ha_state()


class OPNsenseCarpInterfaceSensor(OPNsenseSensor):
    """Class for OPNsense Carp Sensors."""

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update."""
        carp_interface: dict[str, Any] = {}
        key_data = _parse_carp_interface_sensor_key(self.entity_description.key)
        if key_data is None:
            self._mark_unavailable()
            return
        expected_interface_slug, expected_subnet_slug = key_data
        carp_interfaces = self._list_at("carp.interfaces")
        if carp_interfaces is None:
            self._mark_unavailable()
            return
        for i_interface in carp_interfaces:
            if not isinstance(i_interface, MutableMapping):
                _LOGGER.debug(
                    "Skipping malformed CARP interface entry that is not a mapping: %r",
                    i_interface,
                )
                continue
            subnet = i_interface.get("subnet")
            if not isinstance(subnet, str) or not subnet.strip():
                _LOGGER.debug("Skipping CARP interface entry with invalid subnet: %r", i_interface)
                continue
            if slugify(subnet.strip()) != expected_subnet_slug:
                continue

            interface_name = i_interface.get("interface")
            interface_label = str(interface_name).strip() if interface_name is not None else ""
            candidate_interface_slug = slugify(interface_label) if interface_label else "unknown"
            if not candidate_interface_slug:
                candidate_interface_slug = "unknown"
            if candidate_interface_slug != expected_interface_slug:
                continue

            carp_interface = dict(i_interface)
            break
        if not carp_interface:
            self._mark_unavailable()
            return

        try:
            self._attr_native_value = carp_interface["status"]
        except TypeError, KeyError, ZeroDivisionError:
            self._mark_unavailable()
            return
        self._available = True
        self._attr_extra_state_attributes = {}
        for attr in _CARP_INTERFACE_ATTRIBUTES:
            if attr in carp_interface:
                self._attr_extra_state_attributes[attr] = carp_interface[attr]
        self.async_write_ha_state()

    @property
    def icon(self) -> str | None:
        """Return the icon for the sensor.

        Returns:
            str | None: Icon identifier, or the inherited icon.
        """
        if not isinstance(self.native_value, str):
            return "mdi:close-network-outline"
        return _CARP_STATUS_ICONS.get(self.native_value.upper(), "mdi:close-network-outline")


class OPNsenseCarpStatusSensor(OPNsenseSensor):
    """Class for OPNsense aggregate CARP status sensor."""

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update."""
        summary_raw = self._mapping_at("carp.status_summary")
        if summary_raw is None:
            self._mark_unavailable()
            return

        summary = dict(summary_raw)
        raw_summary_state = summary.get("state")
        if not isinstance(raw_summary_state, str) or not raw_summary_state:
            self._mark_unavailable()
            return

        self._available = True
        if raw_summary_state in ("unavailable", "unknown"):
            self._attr_native_value = raw_summary_state
        else:
            summary_state = raw_summary_state.strip().replace("_", " ").title()
            self._attr_native_value = summary_state
        self._attr_extra_state_attributes = {
            "enabled": coerce_bool(summary.get("enabled")),
            "maintenance_mode": coerce_bool(summary.get("maintenance_mode")),
            "demotion": summary.get("demotion", 0),
            "status_message": summary.get("status_message", ""),
            "vip_count": summary.get("vip_count", 0),
            "master_count": summary.get("master_count", 0),
            "backup_count": summary.get("backup_count", 0),
            "other_count": summary.get("other_count", 0),
            "interfaces": summary.get("interfaces", []),
            "vips": summary.get("vips", []),
        }
        self.async_write_ha_state()

    @property
    def icon(self) -> str | None:
        """Return the icon for the sensor.

        Returns:
            str | None: Icon identifier, or the inherited icon.
        """
        state_value = str(self.native_value).lower().strip().replace(" ", "_")
        if state_value == "healthy":
            return "mdi:check-network"
        if state_value in {"maintenance", "not_configured"}:
            return "mdi:backup-restore"
        if state_value in {"degraded", "disabled"}:
            return "mdi:close-network-outline"
        return super().icon


class OPNsenseCarpVipSensor(OPNsenseSensor):
    """Class for an individual read-only CARP virtual IP sensor."""

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator updates for a CARP virtual IP."""
        key_data = _parse_carp_vip_sensor_key(self.entity_description.key)
        carp_interfaces = self._list_at("carp.interfaces")
        if key_data is None or carp_interfaces is None:
            self._mark_unavailable(clear_attributes=True)
            return

        expected_vhid_slug, expected_subnet_slug = key_data
        carp_vip: dict[str, Any] = {}
        for interface in carp_interfaces:
            if not isinstance(interface, Mapping):
                continue
            vhid = _normalize_carp_value(interface.get("vhid"))
            subnet = _normalize_carp_value(interface.get("subnet"))
            if not vhid or not subnet:
                continue
            if (
                slugify(vhid) != expected_vhid_slug
                or _normalize_carp_vip_subnet(subnet) != expected_subnet_slug
            ):
                continue
            carp_vip = dict(interface)
            break

        if not carp_vip:
            self._mark_unavailable(clear_attributes=True)
            return

        status = carp_vip.get("status")
        if status is None:
            self._mark_unavailable(clear_attributes=True)
            return

        self._available = True
        self._attr_native_value = status
        self._attr_extra_state_attributes = {}
        for attr in _CARP_INTERFACE_ATTRIBUTES:
            if attr in carp_vip:
                self._attr_extra_state_attributes[attr] = carp_vip[attr]
        self.async_write_ha_state()

    @property
    def icon(self) -> str | None:
        """Return an icon based on the current CARP VIP status.

        Returns:
            str | None: Icon identifier for the current CARP VIP status.
        """
        if not isinstance(self.native_value, str):
            return "mdi:close-network-outline"
        return _CARP_STATUS_ICONS.get(self.native_value.upper(), "mdi:close-network-outline")


class OPNsenseGatewaySensor(OPNsenseSensor):
    """Class for OPNsense Gateway Sensors."""

    def _opnsense_get_gateway_entry(self, gateway_name: str) -> dict[str, Any]:
        """Return a gateway payload matched by mapping key or display name.

        Args:
            gateway_name: Gateway key or configured display name to find.

        Returns:
            dict[str, Any]: Matching gateway payload, or an empty dictionary when
                no matching gateway is available.

        """
        gateways = self._mapping_at("gateways")
        if gateways is None:
            return {}
        if isinstance(gateways.get(gateway_name), Mapping):
            return dict(gateways[gateway_name])
        gateway_name_normalized = gateway_name.strip()
        for gateway_key, gateway in gateways.items():
            if not isinstance(gateway, Mapping):
                continue
            configured_name = OPNsenseEntity.payload_display_name(gateway, str(gateway_key), "name")
            if configured_name == gateway_name_normalized:
                return dict(gateway)
            if configured_name.casefold() == gateway_name_normalized.casefold():
                return dict(gateway)
        return {}

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update."""
        key_parts = self.entity_description.key.split(".", 1)
        if len(key_parts) != 2:
            self._mark_unavailable()
            return
        gateway_and_prop = key_parts[1]
        gateway_name_parts = gateway_and_prop.rsplit(".", 1)
        if len(gateway_name_parts) != 2:
            self._mark_unavailable()
            return
        gateway_name, prop_name = gateway_name_parts
        gateway: dict[str, Any] = self._opnsense_get_gateway_entry(gateway_name)
        if not gateway:
            self._mark_unavailable()
            return
        try:
            value = gateway[prop_name]
            if prop_name in {"stddev", "delay", "loss"} and isinstance(value, str):
                value = re.sub(r"[^0-9\.]*", "", value)
                if len(value) > 0:
                    value = float(value)

            if isinstance(value, str) and len(value) < 1:
                self._mark_unavailable()
                return

            self._attr_native_value = value
        except TypeError, KeyError, ZeroDivisionError, ValueError:
            self._mark_unavailable()
            return
        self._available = True
        self._attr_extra_state_attributes = {}
        self.async_write_ha_state()

    @property
    def icon(self) -> str | None:
        """Return the icon for the sensor.

        Returns:
            str | None: Icon identifier, or the inherited icon.
        """
        key_parts = self.entity_description.key.rsplit(".", 1)
        if len(key_parts) != 2:
            return super().icon
        prop_name: str = key_parts[1]
        if prop_name == "status" and self.native_value != "online":
            return "mdi:close-network-outline"
        return super().icon


class OPNsenseVPNSensor(OPNsenseSensor):
    """Class for OPNsense VPN Sensors."""

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update."""
        key_parts = self.entity_description.key.split(".")
        if len(key_parts) != 4:
            self._mark_unavailable()
            return
        vpn_type = key_parts[0]
        clients_servers = key_parts[1]
        uuid = key_parts[2]
        prop_name = key_parts[3]
        instances = self._mapping_at(f"{vpn_type}.{clients_servers}")
        if instances is None:
            self._mark_unavailable()
            return
        instance: MutableMapping[str, Any] = {}
        for instance_uuid, ins in instances.items():
            if not isinstance(ins, MutableMapping):
                continue
            if uuid == instance_uuid:
                instance = ins
                break
        if (
            not isinstance(instance, MutableMapping)
            or not instance
            or (
                prop_name != "status"
                and instance.get("enabled", None) is not None
                and not instance.get("enabled")
            )
        ):
            self._mark_unavailable()
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
            self._mark_unavailable()
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
                "interface",
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

        clients = instance.get("clients")
        include_clients = clients_servers == "servers" and prop_name in {
            "connected_clients",
            "status",
        }
        if include_clients and clients is not None and not isinstance(clients, list):
            self._mark_unavailable()
            return
        if include_clients and isinstance(clients, list):
            self._attr_extra_state_attributes["clients"] = []
            for clnt in clients:
                if not isinstance(clnt, MutableMapping):
                    continue
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
            if clients and not self._attr_extra_state_attributes["clients"]:
                self._mark_unavailable()
                return
        self.async_write_ha_state()

    @property
    def icon(self) -> str | None:
        """Return the icon for the sensor.

        Returns:
            str | None: Icon identifier, or the inherited icon.
        """
        key_parts = self.entity_description.key.split(".")
        if len(key_parts) != 4:
            return super().icon
        prop_name = key_parts[3]
        if prop_name == "status" and self.native_value != "up":
            return "mdi:close-network-outline"
        return super().icon


class OPNsenseTempSensor(OPNsenseSensor):
    """Class for OPNsense Temperature Sensors."""

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update."""
        key_parts = self.entity_description.key.split(".")
        if len(key_parts) != 3 or key_parts[:2] != ["telemetry", "temps"]:
            self._mark_unavailable()
            return
        sensor_temp_device: str = key_parts[2]
        temps = self._mapping_at("telemetry.temps")
        if temps is None:
            self._mark_unavailable()
            return
        temp: MutableMapping[str, Any] = {}
        for temp_device, temp_temp in temps.items():
            if temp_device == sensor_temp_device:
                if not isinstance(temp_temp, MutableMapping):
                    break
                temp = temp_temp
                break
        if not temp:
            self._mark_unavailable()
            return

        try:
            self._attr_native_value = temp["temperature"]
        except TypeError, KeyError, ZeroDivisionError:
            self._mark_unavailable()
            return
        self._available = True

        self._attr_extra_state_attributes = {}
        for attr in ["device_id"]:
            self._attr_extra_state_attributes[attr] = temp.get(attr, None)
        self.async_write_ha_state()


def _count_active_dhcp_leases(leases: Iterable[Any]) -> int | None:
    """Count DHCP lease rows with a non-empty address.

    Args:
        leases: Iterable of DHCP lease rows represented as mutable mappings.

    Returns:
        int | None: Number of rows with a non-empty ``address``, or ``None`` when
            any row is not a mutable mapping.

    """
    lease_count = 0
    for lease in leases:
        if not isinstance(lease, MutableMapping):
            return None
        if lease.get("address") not in {None, ""}:
            lease_count += 1
    return lease_count


class OPNsenseDHCPLeasesSensor(OPNsenseSensor):
    """Class for OPNsense DHCP Leases Sensors."""

    _unrecorded_attributes = frozenset({"Leases"})

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update."""
        if_name: str = self.entity_description.key.split(".")[1].strip()
        dhcp_leases = self._mapping_at("dhcp_leases")
        if dhcp_leases is None:
            self._mark_unavailable()
            return
        if if_name.lower() == "all":
            leases = dhcp_leases.get("leases", {})
            lease_interfaces = dhcp_leases.get("lease_interfaces", {})
            if not isinstance(leases, MutableMapping) or not isinstance(
                lease_interfaces, MutableMapping
            ):
                self._mark_unavailable()
                return
            self._available = True
            total_lease_count: int = 0
            lease_counts: dict[str, Any] = {}
            try:
                for ifn, if_descr in lease_interfaces.items():
                    if_count = _count_active_dhcp_leases(leases.get(ifn, []))
                    if if_count is None:
                        self._mark_unavailable()
                        return
                    lease_counts[if_descr] = f"{if_count} leases"
                    total_lease_count += if_count
                    _LOGGER.debug(
                        "[OPNsenseDHCPLeasesSensor handle_coordinator_update] %s: lease_count: %s",
                        if_descr,
                        if_count,
                    )
            except TypeError, KeyError, AttributeError, ZeroDivisionError:
                self._mark_unavailable()
                return
            sorted_lease_counts: dict[str, Any] = {
                key: lease_counts[key] for key in sorted(lease_counts)
            }
            self._attr_extra_state_attributes = dict(sorted_lease_counts)
            self._attr_native_value = total_lease_count

        else:
            leases = dhcp_leases.get("leases", {})
            if not isinstance(leases, MutableMapping):
                self._mark_unavailable()
                return
            interface = leases.get(if_name, [])
            if not isinstance(interface, list):
                self._mark_unavailable()
                return
            try:
                lease_count = _count_active_dhcp_leases(interface)
                if lease_count is None:
                    self._mark_unavailable()
                    return
                self._attr_native_value = lease_count
            except TypeError, KeyError, AttributeError, ZeroDivisionError:
                self._mark_unavailable()
                return
            self._available = True
            self._attr_extra_state_attributes = {"Leases": interface}
        self.async_write_ha_state()
