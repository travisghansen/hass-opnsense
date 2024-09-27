"""Provides sensors to track various status aspects of OPNsense."""

from collections.abc import Mapping
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
from homeassistant.const import (  # ENTITY_CATEGORY_DIAGNOSTIC,
    PERCENTAGE,
    STATE_UNKNOWN,
    UnitOfDataRate,
    UnitOfInformation,
    UnitOfTemperature,
    UnitOfTime,
    __version__,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_platform
from homeassistant.util import slugify
from homeassistant.util.dt import utc_from_timestamp

from . import CoordinatorEntityManager, OPNsenseEntity
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


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: entity_platform.AddEntitiesCallback,
) -> None:
    """Set up the OPNsense sensors."""

    @callback
    def process_entities_callback(hass, config_entry):
        data = hass.data[DOMAIN][config_entry.entry_id]
        coordinator = data[COORDINATOR]
        state = coordinator.data
        resources: list = [sensor_id for sensor_id in SENSOR_TYPES]

        entities: list = []

        # add standard entities
        for sensor_type in resources:
            enabled_default = False
            if sensor_type in [
                "telemetry.pfstate.used_percent",
                "telemetry.mbuf.used_percent",
                "telemetry.memory.swap_used_percent",
                "telemetry.memory.used_percent",
                "telemetry.cpu.frequency.current",
                "telemetry.cpu.usage_total",
                "telemetry.system.load_average.one_minute",
                "telemetry.system.load_average.five_minute",
                "telemetry.system.load_average.fifteen_minute",
                "telemetry.system.temp",
                "telemetry.system.boottime",
                # "dhcp_stats.leases.total",
                "dhcp_stats.leases.online",
                # "dhcp_stats.leases.offline",
            ]:
                enabled_default = True

            entity = OPNsenseStaticKeySensor(
                config_entry,
                coordinator,
                SENSOR_TYPES[sensor_type],
                enabled_default,
            )
            entities.append(entity)

        # filesystems
        for filesystem in dict_get(state, "telemetry.filesystems", []):
            device_clean: str = normalize_filesystem_device_name(filesystem["device"])
            mountpoint_clean: str = normalize_filesystem_device_name(
                filesystem["mountpoint"]
            )
            entity = OPNsenseFilesystemSensor(
                config_entry,
                coordinator,
                SensorEntityDescription(
                    key=f"telemetry.filesystems.{device_clean}",
                    name="Filesystem Used Percentage {}".format(mountpoint_clean),
                    native_unit_of_measurement=PERCENTAGE,
                    icon="mdi:harddisk",
                    state_class=SensorStateClass.MEASUREMENT,
                    # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
                ),
                True,
            )
            entities.append(entity)

        # carp interfaces
        for interface in state.get("carp_interfaces", []):
            # subnet is actually the ip
            uniqid = slugify(interface["subnet"])
            descr: str = interface.get("descr", "")

            state_class = None
            native_unit_of_measurement = None
            icon = "mdi:check-network-outline"
            enabled_default = True
            # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,

            entity = OPNsenseCarpInterfaceSensor(
                config_entry,
                coordinator,
                SensorEntityDescription(
                    key=f"carp.interface.{uniqid}",
                    name=f"CARP Interface Status {uniqid} ({descr})",
                    native_unit_of_measurement=native_unit_of_measurement,
                    icon=icon,
                    state_class=state_class,
                    # entity_category=entity_category,
                ),
                True,
            )
            entities.append(entity)

        # interfaces
        for interface_name, interface in dict_get(
            state, "telemetry.interfaces", {}
        ).items():
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
                icon = None
                enabled_default = False
                # entity_category = ENTITY_CATEGORY_DIAGNOSTIC

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

                if prop_name == "status":
                    icon = "mdi:check-network-outline"

                if icon is None:
                    icon = "mdi:gauge"

                entity = OPNsenseInterfaceSensor(
                    config_entry,
                    coordinator,
                    SensorEntityDescription(
                        key=f"telemetry.interface.{interface_name}.{prop_name}",
                        name=f"Interface {interface.get('name', interface_name)} {prop_name}",
                        native_unit_of_measurement=native_unit_of_measurement,
                        icon=icon,
                        state_class=state_class,
                        # entity_category=entity_category,
                    ),
                    enabled_default,
                )
                entities.append(entity)

        # gateways
        for gateway in dict_get(state, "telemetry.gateways", {}).values():
            for prop_name in ["status", "delay", "stddev", "loss"]:
                state_class = None
                native_unit_of_measurement = None
                icon = "mdi:router-network"
                enabled_default = True
                # entity_category = ENTITY_CATEGORY_DIAGNOSTIC

                if prop_name == "loss":
                    native_unit_of_measurement = PERCENTAGE

                if prop_name in ["delay", "stddev"]:
                    native_unit_of_measurement = UnitOfTime.MILLISECONDS

                if prop_name == "status":
                    icon = "mdi:check-network-outline"

                entity = OPNsenseGatewaySensor(
                    config_entry,
                    coordinator,
                    SensorEntityDescription(
                        key=f"telemetry.gateway.{gateway["name"]}.{prop_name}",
                        name=f"Gateway {gateway["name"]} {prop_name}",
                        native_unit_of_measurement=native_unit_of_measurement,
                        icon=icon,
                        state_class=state_class,
                        # entity_category=entity_category,
                    ),
                    enabled_default,
                )
                entities.append(entity)

        # openvpn servers
        for vpnid in dict_get(state, "telemetry.openvpn.servers", {}).keys():
            servers: Mapping[str, Any] = dict_get(state, "telemetry.openvpn.servers", {})
            server: Mapping[str, Any] | None = servers.get(vpnid, None)
            if server is None or not isinstance(server, Mapping) or len(server) == 0:
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
                icon = None
                enabled_default = False

                # state class
                if "_kilobytes_per_second" in prop_name:
                    state_class = SensorStateClass.MEASUREMENT

                if prop_name == "connected_client_count":
                    state_class = SensorStateClass.MEASUREMENT

                # native_unit_of_measurement
                if "_kilobytes_per_second" in prop_name:
                    native_unit_of_measurement = UnitOfDataRate.KILOBYTES_PER_SECOND

                if native_unit_of_measurement is None:
                    if "bytes" in prop_name:
                        native_unit_of_measurement = UnitOfInformation.BYTES

                if prop_name in ["connected_client_count"]:
                    native_unit_of_measurement = "clients"

                # icon
                if "bytes" in prop_name:
                    icon = "mdi:server-network"

                if prop_name == "connected_client_count":
                    icon = "mdi:ip-network-outline"

                if icon is None:
                    icon = "mdi:gauge"

                entity = OPNsenseOpenVPNServerSensor(
                    config_entry,
                    coordinator,
                    SensorEntityDescription(
                        key=f"telemetry.openvpn.servers.{vpnid}.{prop_name}",
                        name=f"OpenVPN Server {server["name"]} {prop_name}",
                        native_unit_of_measurement=native_unit_of_measurement,
                        icon=icon,
                        state_class=state_class,
                        # entity_category=entity_category,
                    ),
                    enabled_default,
                )
                entities.append(entity)

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

    cem = CoordinatorEntityManager(
        hass,
        hass.data[DOMAIN][config_entry.entry_id][COORDINATOR],
        config_entry,
        process_entities_callback,
        async_add_entities,
    )
    cem.process_entities()


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
        self.config_entry = config_entry
        self.entity_description = entity_description
        self.coordinator = coordinator
        self._attr_entity_registry_enabled_default = enabled_default
        self._attr_name: str = f"{self.opnsense_device_name} {entity_description.name}"
        self._attr_unique_id: str = slugify(
            f"{self.opnsense_device_unique_id}_{entity_description.key}"
        )
        self._previous_value = None


class OPNsenseStaticKeySensor(OPNsenseSensor):
    @property
    def available(self) -> bool:
        value = self._get_opnsense_state_value(self.entity_description.key)
        if value is None:
            return False

        if value == 0 and self.entity_description.key == "telemetry.system.temp":
            return False

        if (
            value == 0
            and self._previous_value is None
            and self.entity_description.key
            in (
                "telemetry.cpu.frequency.current",
                "telemetry.cpu.usage_total",
            )
        ):
            return False

        return super().available

    @property
    def native_value(self):
        """Return entity state from firewall."""
        value = self._get_opnsense_state_value(self.entity_description.key)
        if value is None:
            if self.entity_description.key == "telemetry.system.boottime":
                return value

            return STATE_UNKNOWN

        if value == 0 and self.entity_description.key == "telemetry.system.temp":
            return STATE_UNKNOWN

        if self.entity_description.key == "telemetry.system.boottime":
            value = utc_from_timestamp(value)

        if self.entity_description.key in (
            "telemetry.cpu.frequency.current",
            "telemetry.cpu.usage_total",
        ):
            if value == 0 and self._previous_value is not None:
                value = self._previous_value

            if value == 0:
                return STATE_UNKNOWN

        self._previous_value = value

        return value

    @property
    def extra_state_attributes(self):
        attributes = {}
        if self.entity_description.key in ("telemetry.cpu.usage_total"):
            temp_attr = self._get_opnsense_state_value("telemetry.cpu")
            # _LOGGER.debug(f"[extra_state_attributes] temp_attr: {temp_attr}")
            for k, v in temp_attr.items():
                if k.startswith("usage_") and k != "usage_total":
                    attributes[k.replace("usage_", "")] = f"{v}%"
            # _LOGGER.debug(f"[extra_state_attributes] attributes: {attributes}")

        return attributes


class OPNsenseFilesystemSensor(OPNsenseSensor):
    def _opnsense_get_filesystem(self):
        state = self.coordinator.data
        for filesystem in state.get("telemetry", {}).get("filesystems", []):
            device_clean: str = normalize_filesystem_device_name(filesystem["device"])
            if self.entity_description.key == f"telemetry.filesystems.{device_clean}":
                return filesystem
        return None

    @property
    def available(self) -> bool:
        filesystem = self._opnsense_get_filesystem()
        if filesystem is None:
            return False

        return super().available

    @property
    def native_value(self):
        filesystem = self._opnsense_get_filesystem()
        return filesystem["capacity"].strip("%")

    @property
    def extra_state_attributes(self):
        attributes = {}
        filesystem = self._opnsense_get_filesystem()
        # TODO: convert total_size to bytes?
        for attr in ["device", "type", "size", "mountpoint", "used", "available"]:
            attributes[attr] = filesystem[attr]

        return attributes


class OPNsenseInterfaceSensor(OPNsenseSensor):
    def _opnsense_get_interface_property_name(self):
        return self.entity_description.key.split(".")[3]

    def _opnsense_get_interface_name(self):
        return self.entity_description.key.split(".")[2]

    def _opnsense_get_interface(self):
        state = self.coordinator.data
        interface_name: str = self._opnsense_get_interface_name()
        for i_interface_name, interface  in state.get("telemetry", {}).get("interfaces", {}).items():
            if i_interface_name == interface_name:
                return interface
        return None

    @property
    def available(self) -> bool:
        interface = self._opnsense_get_interface()
        prop_name = self._opnsense_get_interface_property_name()
        if interface is None or prop_name not in interface.keys():
            return False

        return super().available

    @property
    def extra_state_attributes(self):
        attributes = {}
        interface = self._opnsense_get_interface()
        # for attr in ["hwif", "enable", "if", "macaddr", "mtu"]:
        for attr in ["ipaddr", "media"]:
            attributes[attr] = interface[attr]

        return attributes

    @property
    def icon(self):
        prop_name = self._opnsense_get_interface_property_name()
        if prop_name == "status" and self.native_value != "up":
            return "mdi:close-network-outline"
        return super().icon

    @property
    def native_value(self):
        interface = self._opnsense_get_interface()
        prop_name: str = self._opnsense_get_interface_property_name()
        try:
            return interface[prop_name]
        except (KeyError, TypeError):
            return STATE_UNKNOWN


class OPNsenseCarpInterfaceSensor(OPNsenseSensor):
    def _opnsense_get_interface_name(self):
        return self.entity_description.key.split(".")[2]

    def _opnsense_get_interface(self):
        state = self.coordinator.data
        interface_name = self._opnsense_get_interface_name()
        for i_interface in state.get("carp_interfaces", []):
            if slugify(i_interface["subnet"]) == interface_name:
                return i_interface
        return None

    @property
    def available(self) -> bool:
        interface = self._opnsense_get_interface()
        if interface is None:
            return False

        return super().available

    @property
    def extra_state_attributes(self):
        attributes = {}
        interface = self._opnsense_get_interface()
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
            if attr in interface.keys():
                attributes[attr] = interface[attr]

        return attributes

    @property
    def icon(self):
        if self.native_value != "MASTER":
            return "mdi:close-network-outline"
        return super().icon

    @property
    def native_value(self):
        interface = self._opnsense_get_interface()
        try:
            return interface["status"]
        except KeyError:
            return STATE_UNKNOWN


class OPNsenseGatewaySensor(OPNsenseSensor):
    def _opnsense_get_gateway_property_name(self) -> str:
        return self.entity_description.key.split(".")[3]

    def _opnsense_get_gateway_name(self) -> str:
        return self.entity_description.key.split(".")[2]

    def _opnsense_get_gateway(self):
        state = self.coordinator.data
        gateway_name: str = self._opnsense_get_gateway_name()
        for i_gateway_name, gateway in state.get("telemetry", {}).get("gateways", {}).items():
            if i_gateway_name == gateway_name:
                return gateway
        return None

    @property
    def available(self) -> bool:
        gateway = self._opnsense_get_gateway()
        prop_name: str = self._opnsense_get_gateway_property_name()
        if gateway is None or prop_name not in gateway.keys():
            return False

        if prop_name in ["stddev", "delay", "loss"]:
            value = gateway[prop_name]
            if isinstance(value, str):
                value = re.sub(r"[^0-9\.]*", "", value)
                if len(value) < 1:
                    return False

        return super().available

    @property
    def extra_state_attributes(self):
        attributes = {}
        gateway = self._opnsense_get_gateway()
        # for attr in ["monitorip", "srcip", "status"]:
        #    value = gateway[attr]
        #    if attr == "substatus" and gateway[attr] == "none":
        #        value = None
        #    attributes[attr] = value

        return attributes

    @property
    def icon(self):
        prop_name = self._opnsense_get_gateway_property_name()
        if prop_name == "status" and self.native_value != "online":
            return "mdi:close-network-outline"
        return super().icon

    @property
    def native_value(self):
        gateway = self._opnsense_get_gateway()
        prop_name = self._opnsense_get_gateway_property_name()

        if gateway is None:
            return STATE_UNKNOWN

        try:
            value = gateway[prop_name]
            # cleanse "ms", etc from values
            if prop_name in ["stddev", "delay", "loss"]:
                if isinstance(value, str):
                    value = re.sub(r"[^0-9\.]*", "", value)
                    if len(value) > 0:
                        value = float(value)

            if isinstance(value, str) and len(value) < 1:
                return STATE_UNKNOWN

            return value
        except KeyError:
            return STATE_UNKNOWN


class OPNsenseOpenVPNServerSensor(OPNsenseSensor):
    def _opnsense_get_server_property_name(self) -> str:
        return self.entity_description.key.split(".")[4]

    def _opnsense_get_server_vpnid(self) -> str:
        return self.entity_description.key.split(".")[3]

    def _opnsense_get_server(self):
        state = self.coordinator.data
        vpnid: str = self._opnsense_get_server_vpnid()
        for server_vpnid, server in dict_get(state, "telemetry.openvpn.servers", {}).items():
            if vpnid == server_vpnid:
                return server
        return None

    @property
    def available(self) -> bool:
        server = self._opnsense_get_server()
        prop_name = self._opnsense_get_server_property_name()
        if server is None or prop_name not in server.keys():
            return False

        return super().available

    @property
    def extra_state_attributes(self):
        attributes = {}
        server = self._opnsense_get_server()
        if server is None:
            return attributes

        for attr in ["vpnid", "name"]:
            attributes[attr] = server[attr]

        return attributes

    @property
    def native_value(self):
        server = self._opnsense_get_server()
        prop_name = self._opnsense_get_server_property_name()

        if server is None:
            return STATE_UNKNOWN

        try:
            return server[prop_name]
        except KeyError:
            return STATE_UNKNOWN


class OPNsenseTempSensor(OPNsenseSensor):
    def _opnsense_get_temp_device(self) -> str:
        return self.entity_description.key.split(".")[2]

    def _opnsense_get_temp(self) -> Mapping[str, Any]:
        state = self.coordinator.data
        sensor_temp_device: str = self._opnsense_get_temp_device()
        for temp_device, temp in state.get("telemetry", {}).get("temps", {}).items():
            if temp_device == sensor_temp_device:
                return temp
        return {}

    @property
    def available(self) -> bool:
        if len(self._opnsense_get_temp()) == 0:
            return False
        return super().available

    @property
    def extra_state_attributes(self) -> Mapping[str, Any]:
        temp: Mapping[str, Any] = self._opnsense_get_temp()
        attributes: Mapping[str, Any] = {}
        for attr in ["device_id"]:
            attributes[attr] = temp.get(attr, None)
        return attributes

    @property
    def native_value(self):
        temp: Mapping[str, Any] = self._opnsense_get_temp()
        try:
            return temp.get("temperature", STATE_UNKNOWN)
        except (KeyError, TypeError):
            return STATE_UNKNOWN
