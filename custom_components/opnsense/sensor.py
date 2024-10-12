"""Provides sensors to track various status aspects of OPNsense."""

import asyncio
import logging
import re
import traceback
from collections.abc import Mapping
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (  # ENTITY_CATEGORY_DIAGNOSTIC,
    PERCENTAGE,
    UnitOfDataRate,
    UnitOfInformation,
    UnitOfTemperature,
    UnitOfTime,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_platform
from homeassistant.util import slugify
from homeassistant.util.dt import utc_from_timestamp

from . import OPNsenseEntity
from .const import (
    COORDINATOR,
    COUNT,
    DATA_PACKETS,
    DATA_RATE_PACKETS_PER_SECOND,
    DOMAIN,
    SENSOR_TYPES,
)
from .coordinator import OPNsenseDataUpdateCoordinator
from .helpers import dict_get

_LOGGER: logging.Logger = logging.getLogger(__name__)


async def _compile_static_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
) -> list:
    entities: list = []
    for sensor_type in SENSOR_TYPES:
        enabled_default = False
        if sensor_type in [
            "telemetry.pfstate.used_percent",
            "telemetry.mbuf.used_percent",
            "telemetry.memory.swap_used_percent",
            "telemetry.memory.used_percent",
            "telemetry.cpu.usage_total",
            "telemetry.system.load_average.one_minute",
            "telemetry.system.load_average.five_minute",
            "telemetry.system.load_average.fifteen_minute",
            "telemetry.system.boottime",
        ]:
            enabled_default = True

        entity = OPNsenseStaticKeySensor(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=SENSOR_TYPES[sensor_type],
            enabled_default=enabled_default,
        )
        entities.append(entity)
    return entities


async def _compile_filesystem_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: Mapping[str, Any],
) -> list:
    if not isinstance(state, Mapping):
        return []
    entities: list = []

    for filesystem in dict_get(state, "telemetry.filesystems", []):
        device_clean: str = normalize_filesystem_device_name(filesystem["device"])
        mountpoint_clean: str = normalize_filesystem_device_name(
            filesystem["mountpoint"]
        )
        entity = OPNsenseFilesystemSensor(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=SensorEntityDescription(
                key=f"telemetry.filesystems.{device_clean}",
                name=f"Filesystem Used Percentage {mountpoint_clean}",
                native_unit_of_measurement=PERCENTAGE,
                icon="mdi:harddisk",
                state_class=SensorStateClass.MEASUREMENT,
                # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            ),
            enabled_default=True,
        )
        entities.append(entity)

    return entities


async def _compile_carp_interface_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: Mapping[str, Any],
) -> list:
    if not isinstance(state, Mapping):
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
                icon="mdi:check-network-outline",
                state_class=None,
                # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            ),
            enabled_default=True,
        )
        entities.append(entity)
    return entities


async def _compile_interface_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: Mapping[str, Any],
) -> list:
    if not isinstance(state, Mapping):
        return []
    entities: list = []

    # interfaces
    for interface_name, interface in dict_get(state, "interfaces", {}).items():
        for prop_name in [
            "status",
            "inerrs",
            "outerrs",
            "collisions",
            # "inbytespass",
            # "inbytespass_kilobytes_per_second",
            # "outbytespass",
            # "outbytespass_kilobytes_per_second",
            # "inpktspass",
            # "inpktspass_packets_per_second",
            # "outpktspass",
            # "outpktspass_packets_per_second",
            # "inbytesblock",
            # "inbytesblock_kilobytes_per_second",
            # "outbytesblock",
            # "outbytesblock_kilobytes_per_second",
            # "inpktsblock",
            # "inpktsblock_packets_per_second",
            # "outpktsblock",
            # "outpktsblock_packets_per_second",
            "inbytes",
            "inbytes_kilobytes_per_second",
            "outbytes",
            "outbytes_kilobytes_per_second",
            "inpkts",
            "inpkts_packets_per_second",
            "outpkts",
            "outpkts_packets_per_second",
        ]:
            state_class = None
            native_unit_of_measurement = None
            enabled_default = False

            # enabled_default
            if prop_name in [
                "status",
                "inbytes_kilobytes_per_second",
                "outbytes_kilobytes_per_second",
                "inpkts_packets_per_second",
                "outpkts_packets_per_second",
            ]:
                enabled_default = True

            # state class
            if (
                "_packets_per_second" in prop_name
                or "_kilobytes_per_second" in prop_name
            ):
                state_class = SensorStateClass.MEASUREMENT

            # native_unit_of_measurement
            if "_packets_per_second" in prop_name:
                native_unit_of_measurement = DATA_RATE_PACKETS_PER_SECOND

            if "_kilobytes_per_second" in prop_name:
                native_unit_of_measurement = UnitOfDataRate.KILOBYTES_PER_SECOND

            if native_unit_of_measurement is None:
                if "bytes" in prop_name:
                    native_unit_of_measurement = UnitOfInformation.BYTES
                    state_class = SensorStateClass.TOTAL_INCREASING
                if "pkts" in prop_name:
                    native_unit_of_measurement = DATA_PACKETS
                    state_class = SensorStateClass.TOTAL_INCREASING

            if prop_name in ["inerrs", "outerrs", "collisions"]:
                native_unit_of_measurement = COUNT

            # icon
            if "pkts" in prop_name or "bytes" in prop_name:
                icon = "mdi:server-network"
            elif prop_name == "status":
                icon = "mdi:check-network-outline"
            else:
                icon = "mdi:gauge"

            entity = OPNsenseInterfaceSensor(
                config_entry=config_entry,
                coordinator=coordinator,
                entity_description=SensorEntityDescription(
                    key=f"telemetry.interface.{interface_name}.{prop_name}",  # TODO: Remove telemetry and migrate unique_id
                    name=f"Interface {interface.get('name', interface_name)} {prop_name}",
                    native_unit_of_measurement=native_unit_of_measurement,
                    icon=icon,
                    state_class=state_class,
                    # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
                ),
                enabled_default=enabled_default,
            )
            entities.append(entity)

    return entities


async def _compile_gateway_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: Mapping[str, Any],
) -> list:
    if not isinstance(state, Mapping):
        return []
    entities: list = []

    for gateway in dict_get(state, "telemetry.gateways", {}).values():
        for prop_name in ["status", "delay", "stddev", "loss"]:
            native_unit_of_measurement = None
            icon = "mdi:router-network"

            if prop_name == "loss":
                native_unit_of_measurement = PERCENTAGE

            if prop_name in ["delay", "stddev"]:
                native_unit_of_measurement = UnitOfTime.MILLISECONDS

            if prop_name == "status":
                icon = "mdi:check-network-outline"

            entity = OPNsenseGatewaySensor(
                config_entry=config_entry,
                coordinator=coordinator,
                entity_description=SensorEntityDescription(
                    key=f"telemetry.gateway.{gateway['name']}.{prop_name}",
                    name=f"Gateway {gateway['name']} {prop_name}",
                    native_unit_of_measurement=native_unit_of_measurement,
                    icon=icon,
                    state_class=None,
                    # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
                ),
                enabled_default=True,
            )
            entities.append(entity)

    return entities


async def _compile_openvpn_server_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: Mapping[str, Any],
) -> list:
    if not isinstance(state, Mapping):
        return []
    entities: list = []

    for vpnid, server in dict_get(state, "openvpn.servers", {}).items():
        if not isinstance(server, Mapping) or len(server) == 0:
            continue
        for prop_name in [
            "connected_client_count",
            "total_bytes_recv",
            "total_bytes_sent",
            "total_bytes_recv_kilobytes_per_second",
            "total_bytes_sent_kilobytes_per_second",
        ]:
            state_class = None
            native_unit_of_measurement = None

            # state class
            if "_kilobytes_per_second" in prop_name:
                state_class = SensorStateClass.MEASUREMENT

            if prop_name == "connected_client_count":
                state_class = SensorStateClass.MEASUREMENT

            # native_unit_of_measurement
            if "_kilobytes_per_second" in prop_name:
                native_unit_of_measurement = UnitOfDataRate.KILOBYTES_PER_SECOND

            if native_unit_of_measurement is None and "bytes" in prop_name:
                native_unit_of_measurement = UnitOfInformation.BYTES

            if prop_name in ["connected_client_count"]:
                native_unit_of_measurement = "clients"

            # icon
            if "bytes" in prop_name:
                icon = "mdi:server-network"
            elif prop_name == "connected_client_count":
                icon = "mdi:ip-network-outline"
            else:
                icon = "mdi:gauge"

            entity = OPNsenseOpenVPNServerSensor(
                config_entry=config_entry,
                coordinator=coordinator,
                entity_description=SensorEntityDescription(
                    key=f"telemetry.openvpn.servers.{vpnid}.{prop_name}",  # TODO: Migrate and remove telemetry from key
                    name=f"OpenVPN Server {server['name']} {prop_name}",
                    native_unit_of_measurement=native_unit_of_measurement,
                    icon=icon,
                    state_class=state_class,
                    # entity_category=entity_category,
                ),
                enabled_default=False,
            )
            entities.append(entity)
    return entities


async def _compile_temperature_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: Mapping[str, Any],
) -> list:
    if not isinstance(state, Mapping):
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
                # entity_category=entity_category,
            ),
            enabled_default=True,
        )
        entities.append(entity)
    return entities


async def _compile_dhcp_leases_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
    state: Mapping[str, Any],
) -> list:
    if not isinstance(state, Mapping):
        return []
    entities: list = []

    # interfaces
    for interface, interface_name in dict_get(
        state, "dhcp_leases.lease_interfaces", {}
    ).items():
        entity = OPNsenseDHCPLeasesSensor(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=SensorEntityDescription(
                key=f"dhcp_leases.{interface}",
                name=f"DHCP Leases {interface_name}",
                native_unit_of_measurement="leases",
                icon="mdi:devices",
                state_class=SensorStateClass.MEASUREMENT,
                # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            ),
            enabled_default=False,
        )
        entities.append(entity)

    entity = OPNsenseDHCPLeasesSensor(
        config_entry=config_entry,
        coordinator=coordinator,
        entity_description=SensorEntityDescription(
            key="dhcp_leases.all",
            name="DHCP Leases All",
            native_unit_of_measurement="leases",
            icon="mdi:devices",
            state_class=SensorStateClass.MEASUREMENT,
            # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
        ),
        enabled_default=True,
    )
    entities.append(entity)

    return entities


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: entity_platform.AddEntitiesCallback,
) -> None:
    """Set up the OPNsense sensors."""

    coordinator: OPNsenseDataUpdateCoordinator = hass.data[DOMAIN][
        config_entry.entry_id
    ][COORDINATOR]
    state: Mapping[str, Any] = coordinator.data
    if not isinstance(state, Mapping):
        _LOGGER.error("Missing state data in sensor async_setup_entry")
        return
    results: list = await asyncio.gather(
        _compile_static_sensors(config_entry, coordinator),
        _compile_openvpn_server_sensors(config_entry, coordinator, state),
        _compile_gateway_sensors(config_entry, coordinator, state),
        _compile_interface_sensors(config_entry, coordinator, state),
        _compile_carp_interface_sensors(config_entry, coordinator, state),
        _compile_filesystem_sensors(config_entry, coordinator, state),
        _compile_temperature_sensors(config_entry, coordinator, state),
        _compile_dhcp_leases_sensors(config_entry, coordinator, state),
        return_exceptions=True,
    )

    entities: list = []
    for result in results:
        if isinstance(result, list):
            entities += result
        else:
            _LOGGER.error(
                f"Error in sensor async_setup_entry. {result.__class__.__qualname__}: {result}\n{''.join(traceback.format_tb(result.__traceback__))}"
            )
    _LOGGER.debug(f"[sensor async_setup_entry] entities: {len(entities)}")
    async_add_entities(entities)


def normalize_filesystem_device_name(device_name):
    return device_name.replace("/", "_slash_").strip("_")


class OPNsenseSensor(OPNsenseEntity, SensorEntity):
    """Representation of a sensor entity for OPNsense status values."""

    def __init__(
        self,
        config_entry,
        coordinator: OPNsenseDataUpdateCoordinator,
        entity_description: SensorEntityDescription,
        enabled_default: bool,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(
            config_entry,
            coordinator,
            unique_id_suffix=entity_description.key,
            name_suffix=entity_description.name,
        )
        self.entity_description: SensorEntityDescription = entity_description
        self._attr_entity_registry_enabled_default: bool = enabled_default
        self._previous_value = None
        self._attr_native_value = None


class OPNsenseStaticKeySensor(OPNsenseSensor):

    @callback
    def _handle_coordinator_update(self) -> None:
        value = self._get_opnsense_state_value(self.entity_description.key)
        if value is None:
            self._available = False
            return

        if (
            value == 0
            and self._previous_value is None
            and self.entity_description.key in ("telemetry.cpu.usage_total",)
        ):
            self._available = False
            return

        if self.entity_description.key == "telemetry.system.boottime":
            value = utc_from_timestamp(value) if value else None

        elif self.entity_description.key in ("telemetry.cpu.usage_total",):
            if value == 0 and self._previous_value is not None:
                value = self._previous_value

            if value == 0:
                self._available = False
                return

        self._available = True
        self._previous_value = value
        self._attr_native_value = value

        self._attr_extra_state_attributes = {}
        if self.entity_description.key in ("telemetry.cpu.usage_total"):
            temp_attr = self._get_opnsense_state_value("telemetry.cpu")
            # _LOGGER.debug(f"[extra_state_attributes] temp_attr: {temp_attr}")
            for k, v in temp_attr.items():
                if k.startswith("usage_") and k != "usage_total":
                    self._attr_extra_state_attributes[k.replace("usage_", "")] = f"{v}%"
            # _LOGGER.debug(f"[extra_state_attributes] attributes: {attributes}")
        self.async_write_ha_state()


class OPNsenseFilesystemSensor(OPNsenseSensor):

    def _opnsense_get_filesystem(self) -> Mapping[str, Any]:
        state: Mapping[str, Any] = self.coordinator.data
        if not isinstance(state, Mapping):
            return {}
        for filesystem in state.get("telemetry", {}).get("filesystems", []):
            device_clean: str = normalize_filesystem_device_name(filesystem["device"])
            if self.entity_description.key == f"telemetry.filesystems.{device_clean}":
                return filesystem
        return {}

    @callback
    def _handle_coordinator_update(self) -> None:
        filesystem = self._opnsense_get_filesystem()
        try:
            self._attr_native_value = filesystem["capacity"].strip("%")
        except (TypeError, KeyError, AttributeError):
            self._available = False
            return
        self._available = True

        self._attr_extra_state_attributes = {}
        # TODO: convert total_size to bytes?
        for attr in ["device", "type", "size", "mountpoint", "used", "available"]:
            self._attr_extra_state_attributes[attr] = filesystem[attr]
        self.async_write_ha_state()


class OPNsenseInterfaceSensor(OPNsenseSensor):
    def _opnsense_get_interface_property_name(self) -> str:
        return self.entity_description.key.split(".")[3]

    @callback
    def _handle_coordinator_update(self) -> None:
        state: Mapping[str, Any] = self.coordinator.data
        if not isinstance(state, Mapping):
            return {}
        interface_name: str = self.entity_description.key.split(".")[2]
        interface: Mapping[str, Any] = {}
        for i_interface_name, iface in state.get("interfaces", {}).items():
            if i_interface_name == interface_name:
                interface = iface
        if not interface:
            self._available = False
            return
        prop_name: str = self._opnsense_get_interface_property_name()
        try:
            self._attr_native_value = interface[prop_name]
        except (TypeError, KeyError, ZeroDivisionError):
            self._available = False
            return
        self._available = True
        self._attr_extra_state_attributes = {}
        for attr in ["ipaddr", "media"]:
            self._attr_extra_state_attributes[attr] = interface[attr]
        self.async_write_ha_state()

    @property
    def icon(self) -> str:
        prop_name: str = self._opnsense_get_interface_property_name()
        if prop_name == "status" and self.native_value != "up":
            return "mdi:close-network-outline"
        return super().icon


class OPNsenseCarpInterfaceSensor(OPNsenseSensor):
    def _opnsense_get_carp_interface_name(self) -> str:
        return self.entity_description.key.split(".")[2]

    def _opnsense_get_carp_interface(self) -> Mapping[str, Any]:
        state: Mapping[str, Any] = self.coordinator.data
        if not isinstance(state, Mapping):
            return {}
        carp_interface_name = self._opnsense_get_carp_interface_name()
        for i_interface in state.get("carp_interfaces", []):
            if slugify(i_interface["subnet"]) == carp_interface_name:
                return i_interface
        return {}

    @callback
    def _handle_coordinator_update(self) -> None:
        carp_interface: Mapping[str, Any] = self._opnsense_get_carp_interface()
        try:
            self._attr_native_value = carp_interface["status"]
        except (TypeError, KeyError, ZeroDivisionError):
            self._available = False
            return
        self._available = True
        self._attr_extra_state_attributes = {}
        for attr in [
            "interface",
            "vhid",
            "advskew",
            "advbase",
            "type",
            "subnet_bits",
            "subnet",
            "descr",
        ]:
            if attr in carp_interface:
                self._attr_extra_state_attributes[attr] = carp_interface[attr]
        self.async_write_ha_state()

    @property
    def icon(self) -> str:
        if self.native_value != "MASTER":
            return "mdi:close-network-outline"
        return super().icon


class OPNsenseGatewaySensor(OPNsenseSensor):
    def _opnsense_get_gateway_property_name(self) -> str:
        return self.entity_description.key.split(".")[3]

    def _opnsense_get_gateway_name(self) -> str:
        return self.entity_description.key.split(".")[2]

    def _opnsense_get_gateway(self) -> Mapping[str, Any]:
        state: Mapping[str, Any] = self.coordinator.data
        if not isinstance(state, Mapping):
            return {}
        gateway_name: str = self._opnsense_get_gateway_name()
        for i_gateway_name, gateway in (
            state.get("telemetry", {}).get("gateways", {}).items()
        ):
            if i_gateway_name == gateway_name:
                return gateway
        return {}

    @callback
    def _handle_coordinator_update(self) -> None:
        gateway: Mapping[str, Any] = self._opnsense_get_gateway()
        prop_name: str = self._opnsense_get_gateway_property_name()
        try:
            value = gateway[prop_name]
            # cleanse "ms", etc from values
            if prop_name in ["stddev", "delay", "loss"] and isinstance(value, str):
                value = re.sub(r"[^0-9\.]*", "", value)
                if len(value) > 0:
                    value = float(value)

            if isinstance(value, str) and len(value) < 1:
                self._available = False
                return

            self._attr_native_value = value
        except (TypeError, KeyError, ZeroDivisionError):
            self._available = False
            return
        self._available = True

        self._attr_extra_state_attributes = {}
        gateway = self._opnsense_get_gateway()
        # for attr in ["monitorip", "srcip", "status"]:
        #    value = gateway[attr]
        #    if attr == "substatus" and gateway[attr] == "none":
        #        value = None
        #    self._attr_extra_state_attributes[attr] = value
        self.async_write_ha_state()

    @property
    def icon(self) -> str:
        prop_name: str = self._opnsense_get_gateway_property_name()
        if prop_name == "status" and self.native_value != "online":
            return "mdi:close-network-outline"
        return super().icon


class OPNsenseOpenVPNServerSensor(OPNsenseSensor):
    def _opnsense_get_server_property_name(self) -> str:
        return self.entity_description.key.split(".")[4]

    def _opnsense_get_server_vpnid(self) -> str:
        return self.entity_description.key.split(".")[3]

    def _opnsense_get_server(self) -> Mapping[str, Any]:
        state: Mapping[str, Any] = self.coordinator.data
        if not isinstance(state, Mapping):
            return {}
        vpnid: str = self._opnsense_get_server_vpnid()
        for server_vpnid, server in dict_get(state, "openvpn.servers", {}).items():
            if vpnid == server_vpnid:
                return server
        return {}

    @callback
    def _handle_coordinator_update(self) -> None:
        server: Mapping[str, Any] | None = self._opnsense_get_server()
        prop_name: str = self._opnsense_get_server_property_name()
        try:
            self._attr_native_value = server[prop_name]
        except (TypeError, KeyError, ZeroDivisionError):
            self._available = False
            return
        self._available = True

        self._attr_extra_state_attributes = {}
        for attr in ["vpnid", "name"]:
            self._attr_extra_state_attributes[attr] = server[attr]
        self.async_write_ha_state()


class OPNsenseTempSensor(OPNsenseSensor):
    def _opnsense_get_temp_device(self) -> str:
        return self.entity_description.key.split(".")[2]

    def _opnsense_get_temp(self) -> Mapping[str, Any]:
        state: Mapping[str, Any] = self.coordinator.data
        if not isinstance(state, Mapping):
            return {}
        sensor_temp_device: str = self._opnsense_get_temp_device()
        for temp_device, temp in state.get("telemetry", {}).get("temps", {}).items():
            if temp_device == sensor_temp_device:
                return temp
        return {}

    @callback
    def _handle_coordinator_update(self) -> None:
        temp: Mapping[str, Any] = self._opnsense_get_temp()
        try:
            self._attr_native_value = temp["temperature"]
        except (TypeError, KeyError, ZeroDivisionError):
            self._available = False
            return
        self._available = True

        self._attr_extra_state_attributes = {}
        for attr in ["device_id"]:
            self._attr_extra_state_attributes[attr] = temp.get(attr, None)
        self.async_write_ha_state()


class OPNsenseDHCPLeasesSensor(OPNsenseSensor):
    _unrecorded_attributes = frozenset({"Leases"})

    @callback
    def _handle_coordinator_update(self) -> None:
        state: Mapping[str, Any] = self.coordinator.data
        if not isinstance(state, Mapping):
            return
        if_name: str = self.entity_description.key.split(".")[1].strip()
        # _LOGGER.debug(f"[OPNsenseDHCPLeasesSensor handle_coordinator_update] if_name: {if_name}")
        if if_name.lower() == "all":
            leases = state.get("dhcp_leases", {}).get("leases", {})
            lease_interfaces = state.get("dhcp_leases", {}).get("lease_interfaces", {})
            # _LOGGER.debug(f"[OPNsenseDHCPLeasesSensor handle_coordinator_update] lease_interfaces: {lease_interfaces}")
            # _LOGGER.debug(f"[OPNsenseDHCPLeasesSensor handle_coordinator_update] leases: {leases}")
            if not isinstance(leases, Mapping) or not isinstance(
                lease_interfaces, Mapping
            ):
                self._available = False
                return
            self._available = True
            total_lease_count: int = 0
            lease_counts: Mapping[str, Any] = {}
            try:
                for ifn, if_descr in lease_interfaces.items():
                    if_count: int = sum(
                        1
                        for d in leases.get(ifn, [])
                        if d.get("address") not in (None, "")
                    )
                    lease_counts[if_descr] = f"{if_count} leases"
                    total_lease_count += if_count
                    _LOGGER.debug(
                        f"[OPNsenseDHCPLeasesSensor handle_coordinator_update] if_descr: {if_descr}, lease_count: {if_count}"
                    )
            except (TypeError, KeyError, ZeroDivisionError):
                self._available = False
                return
            sorted_lease_counts: Mapping[str, Any] = {
                key: lease_counts[key] for key in sorted(lease_counts)
            }
            self._attr_extra_state_attributes = sorted_lease_counts
            self._attr_native_value = total_lease_count

        else:
            interface = state.get("dhcp_leases", {}).get("leases", {}).get(if_name, [])
            if not isinstance(interface, list):
                self._available = False
                return
            try:
                self._attr_native_value = sum(
                    1 for d in interface if d.get("address") not in (None, "")
                )
            except (TypeError, KeyError, ZeroDivisionError):
                self._available = False
                return
            self._available = True
            self._attr_extra_state_attributes = {"Leases": interface}
        self.async_write_ha_state()
