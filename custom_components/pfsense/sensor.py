"""Provides a sensor to track various status aspects of pfSense."""
import logging
import re

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
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_platform
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import slugify
from homeassistant.util.dt import utc_from_timestamp

from . import CoordinatorEntityManager, PfSenseEntity
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
    """Set up the pfSense sensors."""

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

            entity = PfSenseSensor(
                config_entry,
                coordinator,
                SENSOR_TYPES[sensor_type],
                enabled_default,
            )
            entities.append(entity)

        # filesystems
        for filesystem in state["telemetry"]["filesystems"]:
            device_clean = normalize_filesystem_device_name(filesystem["device"])
            mountpoint_clean = normalize_filesystem_device_name(
                filesystem["mountpoint"]
            )
            entity = PfSenseFilesystemSensor(
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
            uniqid = interface["uniqid"]
            state_class = None
            native_unit_of_measurement = None
            icon = "mdi:check-network-outline"
            enabled_default = True
            # entity_category=ENTITY_CATEGORY_DIAGNOSTIC,

            entity = PfSenseCarpInterfaceSensor(
                config_entry,
                coordinator,
                SensorEntityDescription(
                    key=f"carp.interface.{uniqid}",
                    name="CARP Interface Status {} ({})".format(
                        uniqid, interface["descr"]
                    ),
                    native_unit_of_measurement=native_unit_of_measurement,
                    icon=icon,
                    state_class=state_class,
                    # entity_category=entity_category,
                ),
                True,
            )
            entities.append(entity)

        # interfaces
        for interface_name in state["telemetry"]["interfaces"].keys():
            interface = state["telemetry"]["interfaces"][interface_name]
            for property in [
                "status",
                "inerrs",
                "outerrs",
                "collisions",
                "inbytespass",
                "inbytespass_kilobytes_per_second",
                "outbytespass",
                "outbytespass_kilobytes_per_second",
                "inpktspass",
                "inpktspass_packets_per_second",
                "outpktspass",
                "outpktspass_packets_per_second",
                "inbytesblock",
                "inbytesblock_kilobytes_per_second",
                "outbytesblock",
                "outbytesblock_kilobytes_per_second",
                "inpktsblock",
                "inpktsblock_packets_per_second",
                "outpktsblock",
                "outpktsblock_packets_per_second",
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

                entity = PfSenseInterfaceSensor(
                    config_entry,
                    coordinator,
                    SensorEntityDescription(
                        key="telemetry.interface.{}.{}".format(
                            interface["ifname"], property
                        ),
                        name="Interface {} {}".format(interface["descr"], property),
                        native_unit_of_measurement=native_unit_of_measurement,
                        icon=icon,
                        state_class=state_class,
                        # entity_category=entity_category,
                    ),
                    enabled_default,
                )
                entities.append(entity)

        # gateways
        for gateway_name in state["telemetry"]["gateways"].keys():
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

                entity = PfSenseGatewaySensor(
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


class PfSenseSensor(PfSenseEntity, SensorEntity):
    """Representation of a sensor entity for pfSense status values."""

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
        self._attr_name = f"{self.pfsense_device_name} {entity_description.name}"
        self._attr_unique_id = slugify(
            f"{self.pfsense_device_unique_id}_{entity_description.key}"
        )

    @property
    def native_value(self):
        """Return entity state from firewall."""
        value = self._get_pfsense_state_value(self.entity_description.key)
        if value is None:
            return STATE_UNKNOWN

        if self.entity_description.key == "telemetry.system.boottime":
            value = utc_from_timestamp(value).isoformat()
        return value


class PfSenseFilesystemSensor(PfSenseSensor):
    def _pfsense_get_filesystem(self):
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
        filesystem = self._pfsense_get_filesystem()
        return filesystem["percent_used"]

    @property
    def extra_state_attributes(self):
        attributes = {}
        filesystem = self._pfsense_get_filesystem()
        # TODO: convert total_size to bytes?
        for attr in ["device", "type", "total_size", "mountpoint"]:
            attributes[attr] = filesystem[attr]

        return attributes


class PfSenseInterfaceSensor(PfSenseSensor):
    def _pfsense_get_interface_property_name(self):
        return self.entity_description.key.split(".")[3]

    def _pfsense_get_interface_name(self):
        return self.entity_description.key.split(".")[2]

    def _pfsense_get_interface(self):
        state = self.coordinator.data
        found = None
        interface_name = self._pfsense_get_interface_name()
        for i_interface_name in state["telemetry"]["interfaces"].keys():
            if i_interface_name == interface_name:
                found = state["telemetry"]["interfaces"][i_interface_name]
                break
        return found

    @property
    def extra_state_attributes(self):
        attributes = {}
        interface = self._pfsense_get_interface()
        for attr in ["hwif", "enable", "if", "macaddr", "mtu"]:
            attributes[attr] = interface[attr]

        return attributes

    @property
    def icon(self):
        property = self._pfsense_get_interface_property_name()
        if property == "status" and self.native_value != "up":
            return "mdi:close-network-outline"
        return super().icon

    @property
    def native_value(self):
        interface = self._pfsense_get_interface()
        property = self._pfsense_get_interface_property_name()
        try:
            return interface[property]
        except KeyError:
            return STATE_UNKNOWN


class PfSenseCarpInterfaceSensor(PfSenseSensor):
    def _pfsense_get_interface_name(self):
        return self.entity_description.key.split(".")[2]

    def _pfsense_get_interface(self):
        state = self.coordinator.data
        found = None
        interface_name = self._pfsense_get_interface_name()
        for i_interface in state["carp_interfaces"]:
            if i_interface["uniqid"] == interface_name:
                found = i_interface
                break
        return found

    @property
    def extra_state_attributes(self):
        attributes = {}
        interface = self._pfsense_get_interface()
        for attr in [
            "interface",
            "vhid",
            "advskew",
            "advbase",
            "type",
            "subnet_bits",
            "subnet",
        ]:
            attributes[attr] = interface[attr]

        return attributes

    @property
    def icon(self):
        if self.native_value != "MASTER":
            return "mdi:close-network-outline"
        return super().icon

    @property
    def native_value(self):
        interface = self._pfsense_get_interface()
        try:
            return interface["status"]
        except KeyError:
            return STATE_UNKNOWN


class PfSenseGatewaySensor(PfSenseSensor):
    def _pfsense_get_gateway_property_name(self):
        return self.entity_description.key.split(".")[3]

    def _pfsense_get_gateway_name(self):
        return self.entity_description.key.split(".")[2]

    def _pfsense_get_gateway(self):
        state = self.coordinator.data
        found = None
        gateway_name = self._pfsense_get_gateway_name()
        for i_gateway_name in state["telemetry"]["gateways"].keys():
            if i_gateway_name == gateway_name:
                found = state["telemetry"]["gateways"][i_gateway_name]
                break
        return found

    @property
    def extra_state_attributes(self):
        attributes = {}
        gateway = self._pfsense_get_gateway()
        for attr in ["monitorip", "srcip", "substatus"]:
            value = gateway[attr]
            if attr == "substatus" and gateway[attr] == "none":
                value = None
            attributes[attr] = value

        return attributes

    @property
    def icon(self):
        property = self._pfsense_get_gateway_property_name()
        if property == "status" and self.native_value != "online":
            return "mdi:close-network-outline"
        return super().icon

    @property
    def native_value(self):
        gateway = self._pfsense_get_gateway()
        property = self._pfsense_get_gateway_property_name()
        try:
            value = gateway[property]
            # cleanse "ms", etc from values
            if property in ["stddev", "delay", "loss"]:
                value = re.sub("[^0-9\.]*", "", value)

            return value
        except KeyError:
            return STATE_UNKNOWN
