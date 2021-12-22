"""Provides a sensor to track various status aspects of OPNsense."""
import logging
import re

from awesomeversion import AwesomeVersion
from homeassistant.components.sensor import (
    STATE_CLASS_MEASUREMENT,
    SensorEntity,
    SensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (  # ENTITY_CATEGORY_DIAGNOSTIC,
    DATA_BYTES,
    DATA_RATE_KILOBYTES_PER_SECOND,
    PERCENTAGE,
    STATE_UNKNOWN,
    TIME_MILLISECONDS,
    __version__,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_platform
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import slugify
from homeassistant.util.dt import utc_from_timestamp

from . import CoordinatorEntityManager, OPNSenseEntity, dict_get
from .const import (
    COORDINATOR,
    COUNT,
    DATA_PACKETS,
    DATA_RATE_PACKETS_PER_SECOND,
    DOMAIN,
    SENSOR_TYPES,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: entity_platform.AddEntitiesCallback,
):
    """Set up the OPNsense sensors."""

    @callback
    def process_entities_callback(hass, config_entry):
        data = hass.data[DOMAIN][config_entry.entry_id]
        coordinator = data[COORDINATOR]
        state = coordinator.data
        resources = [sensor_id for sensor_id in SENSOR_TYPES]

        entities = []

        # add standard entities
        for sensor_type in resources:
            enabled_default = False
            if sensor_type in [
                "telemetry.pfstate.used_percent",
                "telemetry.mbuf.used_percent",
                "telemetry.memory.swap_used_percent",
                "telemetry.memory.used_percent",
                "telemetry.cpu.frequency.current",
                "telemetry.cpu.load_average.one_minute",
                "telemetry.cpu.load_average.five_minute",
                "telemetry.cpu.load_average.fifteen_minute",
                "telemetry.system.temp",
                "telemetry.system.boottime",
                # "dhcp_stats.leases.total",
                "dhcp_stats.leases.online",
                # "dhcp_stats.leases.offline",
            ]:
                enabled_default = True

            entity = OPNSenseSensor(
                config_entry,
                coordinator,
                SENSOR_TYPES[sensor_type],
                enabled_default,
            )
            entities.append(entity)

        # filesystems
        for filesystem in dict_get(state, "telemetry.filesystems", []):
            device_clean = normalize_filesystem_device_name(filesystem["device"])
            mountpoint_clean = normalize_filesystem_device_name(
                filesystem["mountpoint"]
            )
            entity = OPNSenseFilesystemSensor(
                config_entry,
                coordinator,
                SensorEntityDescription(
                    key=f"telemetry.filesystems.{device_clean}",
                    name="Filesystem Used Percentage {}".format(mountpoint_clean),
                    native_unit_of_measurement=PERCENTAGE,
                    icon="mdi:harddisk",
                    state_class=STATE_CLASS_MEASUREMENT,
                    # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
                ),
                True,
            )
            entities.append(entity)

        # carp interfaces
        for interface in state["carp_interfaces"]:
            # subnet is actually the ip
            uniqid = slugify(interface["subnet"])
            descr = ""
            if "descr" in interface.keys():
                descr = interface["descr"]

            state_class = None
            native_unit_of_measurement = None
            icon = "mdi:check-network-outline"
            enabled_default = True
            # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,

            entity = OPNSenseCarpInterfaceSensor(
                config_entry,
                coordinator,
                SensorEntityDescription(
                    key=f"carp.interface.{uniqid}",
                    name="CARP Interface Status {} ({})".format(uniqid, descr),
                    native_unit_of_measurement=native_unit_of_measurement,
                    icon=icon,
                    state_class=state_class,
                    # entity_category=entity_category,
                ),
                True,
            )
            entities.append(entity)

        # interfaces
        for interface_name in dict_get(state, "telemetry.interfaces", {}).keys():
            interface = state["telemetry"]["interfaces"][interface_name]
            for property in [
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
                if property in [
                    "status",
                    "inbytes_kilobytes_per_second",
                    "outbytes_kilobytes_per_second",
                    "inpkts_packets_per_second",
                    "outpkts_packets_per_second",
                ]:
                    enabled_default = True

                # state class
                if (
                    "_packets_per_second" in property
                    or "_kilobytes_per_second" in property
                ):
                    state_class = STATE_CLASS_MEASUREMENT

                # native_unit_of_measurement
                if "_packets_per_second" in property:
                    native_unit_of_measurement = DATA_RATE_PACKETS_PER_SECOND

                if "_kilobytes_per_second" in property:
                    native_unit_of_measurement = DATA_RATE_KILOBYTES_PER_SECOND

                if native_unit_of_measurement is None:
                    if "bytes" in property:
                        native_unit_of_measurement = DATA_BYTES
                    if "pkts" in property:
                        native_unit_of_measurement = DATA_PACKETS

                if property in ["inerrs", "outerrs", "collisions"]:
                    native_unit_of_measurement = COUNT

                # icon
                if "pkts" in property or "bytes" in property:
                    icon = "mdi:server-network"

                if property == "status":
                    icon = "mdi:check-network-outline"

                if icon is None:
                    icon = "mdi:gauge"

                entity = OPNSenseInterfaceSensor(
                    config_entry,
                    coordinator,
                    SensorEntityDescription(
                        key="telemetry.interface.{}.{}".format(
                            interface_name, property
                        ),
                        name="Interface {} {}".format(interface_name, property),
                        native_unit_of_measurement=native_unit_of_measurement,
                        icon=icon,
                        state_class=state_class,
                        # entity_category=entity_category,
                    ),
                    enabled_default,
                )
                entities.append(entity)

        # gateways
        for gateway_name in dict_get(state, "telemetry.gateways", {}).keys():
            gateway = state["telemetry"]["gateways"][gateway_name]
            for property in ["status", "delay", "stddev", "loss"]:
                state_class = None
                native_unit_of_measurement = None
                icon = "mdi:router-network"
                enabled_default = True
                # entity_category = ENTITY_CATEGORY_DIAGNOSTIC

                if property == "loss":
                    native_unit_of_measurement = PERCENTAGE

                if property in ["delay", "stddev"]:
                    native_unit_of_measurement = TIME_MILLISECONDS

                if property == "status":
                    icon = "mdi:check-network-outline"

                entity = OPNSenseGatewaySensor(
                    config_entry,
                    coordinator,
                    SensorEntityDescription(
                        key="telemetry.gateway.{}.{}".format(gateway["name"], property),
                        name="Gateway {} {}".format(gateway["name"], property),
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
            servers = dict_get(state, "telemetry.openvpn.servers", {})
            server = servers[vpnid]
            for property in [
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
                if "_kilobytes_per_second" in property:
                    state_class = STATE_CLASS_MEASUREMENT

                if property == "connected_client_count":
                    state_class = STATE_CLASS_MEASUREMENT

                # native_unit_of_measurement
                if "_kilobytes_per_second" in property:
                    native_unit_of_measurement = DATA_RATE_KILOBYTES_PER_SECOND

                if native_unit_of_measurement is None:
                    if "bytes" in property:
                        native_unit_of_measurement = DATA_BYTES

                if property in ["connected_client_count"]:
                    native_unit_of_measurement = "clients"

                # icon
                if "bytes" in property:
                    icon = "mdi:server-network"

                if property == "connected_client_count":
                    icon = "mdi:ip-network-outline"

                if icon is None:
                    icon = "mdi:gauge"

                entity = OPNSenseOpenVPNServerSensor(
                    config_entry,
                    coordinator,
                    SensorEntityDescription(
                        key="telemetry.openvpn.servers.{}.{}".format(vpnid, property),
                        name="OpenVPN Server {} ({}) {}".format(
                            vpnid, server["name"], property
                        ),
                        native_unit_of_measurement=native_unit_of_measurement,
                        icon=icon,
                        state_class=state_class,
                        # entity_category=entity_category,
                    ),
                    enabled_default,
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


class OPNSenseSensor(OPNSenseEntity, SensorEntity):
    """Representation of a sensor entity for OPNsense status values."""

    def __init__(
        self,
        config_entry,
        coordinator: DataUpdateCoordinator,
        entity_description: SensorEntityDescription,
        enabled_default: bool,
    ) -> None:
        """Initialize the sensor."""
        self.config_entry = config_entry
        self.entity_description = entity_description
        self.coordinator = coordinator
        self._attr_entity_registry_enabled_default = enabled_default
        self._attr_name = f"{self.opnsense_device_name} {entity_description.name}"
        self._attr_unique_id = slugify(
            f"{self.opnsense_device_unique_id}_{entity_description.key}"
        )
        self._previous_value = None

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
            # For backwards compatibility we will use the string version of the
            # datetime on systems before 2021.12.0b0
            if AwesomeVersion(__version__) < AwesomeVersion("2021.12.0b0"):
                value = value.isoformat()

        if self.entity_description.key == "telemetry.cpu.frequency.current":
            if value == 0 and self._previous_value is not None:
                value = self._previous_value

        if (
            value == 0
            and self.entity_description.key == "telemetry.cpu.frequency.current"
        ):
            return STATE_UNKNOWN

        self._previous_value = value

        return value


class OPNSenseFilesystemSensor(OPNSenseSensor):
    def _opnsense_get_filesystem(self):
        state = self.coordinator.data
        found = None
        for filesystem in state["telemetry"]["filesystems"]:
            device_clean = normalize_filesystem_device_name(filesystem["device"])
            if self.entity_description.key == f"telemetry.filesystems.{device_clean}":
                found = filesystem
                break
        return found

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


class OPNSenseInterfaceSensor(OPNSenseSensor):
    def _opnsense_get_interface_property_name(self):
        return self.entity_description.key.split(".")[3]

    def _opnsense_get_interface_name(self):
        return self.entity_description.key.split(".")[2]

    def _opnsense_get_interface(self):
        state = self.coordinator.data
        found = None
        interface_name = self._opnsense_get_interface_name()
        for i_interface_name in state["telemetry"]["interfaces"].keys():
            if i_interface_name == interface_name:
                found = state["telemetry"]["interfaces"][i_interface_name]
                break
        return found

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
        property = self._opnsense_get_interface_property_name()
        if property == "status" and self.native_value != "up":
            return "mdi:close-network-outline"
        return super().icon

    @property
    def native_value(self):
        interface = self._opnsense_get_interface()
        property = self._opnsense_get_interface_property_name()
        try:
            return interface[property]
        except KeyError:
            return STATE_UNKNOWN


class OPNSenseCarpInterfaceSensor(OPNSenseSensor):
    def _opnsense_get_interface_name(self):
        return self.entity_description.key.split(".")[2]

    def _opnsense_get_interface(self):
        state = self.coordinator.data
        found = None
        interface_name = self._opnsense_get_interface_name()
        for i_interface in state["carp_interfaces"]:
            if slugify(i_interface["subnet"]) == interface_name:
                found = i_interface
                break
        return found

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


class OPNSenseGatewaySensor(OPNSenseSensor):
    def _opnsense_get_gateway_property_name(self):
        return self.entity_description.key.split(".")[3]

    def _opnsense_get_gateway_name(self):
        return self.entity_description.key.split(".")[2]

    def _opnsense_get_gateway(self):
        state = self.coordinator.data
        found = None
        gateway_name = self._opnsense_get_gateway_name()
        for i_gateway_name in state["telemetry"]["gateways"].keys():
            if i_gateway_name == gateway_name:
                found = state["telemetry"]["gateways"][i_gateway_name]
                break
        return found

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
        property = self._opnsense_get_gateway_property_name()
        if property == "status" and self.native_value != "online":
            return "mdi:close-network-outline"
        return super().icon

    @property
    def native_value(self):
        gateway = self._opnsense_get_gateway()
        property = self._opnsense_get_gateway_property_name()

        if gateway is None:
            return STATE_UNKNOWN

        try:
            value = gateway[property]
            # cleanse "ms", etc from values
            if property in ["stddev", "delay", "loss"]:
                value = re.sub("[^0-9\.]*", "", value)

            if len(value) < 1:
                return STATE_UNKNOWN

            return value
        except KeyError:
            return STATE_UNKNOWN


class OPNSenseOpenVPNServerSensor(OPNSenseSensor):
    def _opnsense_get_server_property_name(self):
        return self.entity_description.key.split(".")[4]

    def _opnsense_get_server_vpnid(self):
        return self.entity_description.key.split(".")[3]

    def _opnsense_get_server(self):
        state = self.coordinator.data
        found = None
        vpnid = self._opnsense_get_server_vpnid()
        for server_vpnid in dict_get(state, "telemetry.openvpn.servers", {}).keys():
            if vpnid == server_vpnid:
                found = state["telemetry"]["openvpn"]["servers"][vpnid]
                break
        return found

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
        property = self._opnsense_get_server_property_name()

        if server is None:
            return STATE_UNKNOWN

        try:
            return server[property]
        except KeyError:
            return STATE_UNKNOWN
