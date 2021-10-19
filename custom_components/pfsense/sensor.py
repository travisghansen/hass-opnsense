"""Provides a sensor to track various status aspects of pfSense."""
import logging
import re

from homeassistant.components.sensor import SensorEntity, SensorEntityDescription
from homeassistant.helpers.update_coordinator import (
    DataUpdateCoordinator,
)
from homeassistant.util.dt import utc_from_timestamp
from homeassistant.util import slugify
from homeassistant.components.sensor import (
    STATE_CLASS_MEASUREMENT,
    SensorEntityDescription,
)
from homeassistant.const import (
    #ENTITY_CATEGORY_DIAGNOSTIC,
    PERCENTAGE,
    STATE_UNKNOWN,
)

from . import PfSenseEntity
from .const import (
    COORDINATOR,
    DOMAIN,
    SENSOR_TYPES,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass, config_entry, async_add_entities):
    """Set up the pfSense sensors."""
    data = hass.data[DOMAIN][config_entry.entry_id]
    coordinator = data[COORDINATOR]
    state = coordinator.data
    resources = [sensor_id for sensor_id in SENSOR_TYPES]

    # add standard entities
    entities = [
        PfSenseSensor(
            coordinator,
            SENSOR_TYPES[sensor_type],
            True,
        )
        for sensor_type in resources
    ]

    # filesystems
    for filesystem in state["telemetry"]["filesystems"]:
        device_clean = normalize_filesystem_device_name(filesystem["device"])
        mountpoint_clean = normalize_filesystem_device_name(
            filesystem["mountpoint"])
        entity = PfSenseFilesystemSensor(
            coordinator,
            SensorEntityDescription(
                key=f"telemetry.filesystems.{device_clean}",
                name="Filesystem Used Percentage {}".format(mountpoint_clean),
                native_unit_of_measurement=PERCENTAGE,
                icon="mdi:gauge",
                state_class=STATE_CLASS_MEASUREMENT,
                #entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
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
            "inbytespass_kbs",
            "outbytespass",
            "outbytespass_kbs",
            "inpktspass",
            "inpktspass_pps",
            "outpktspass",
            "outpktspass_pps",
            "inbytesblock",
            "inbytesblock_kbs",
            "outbytesblock",
            "outbytesblock_kbs",
            "inpktsblock",
            "inpktsblock_pps",
            "outpktsblock",
            "outpktsblock_pps",
            "inbytes",
            "inbytes_kbs",
            "outbytes",
            "outbytes_kbs",
            "inpkts",
            "inpkts_pps",
            "outpkts",
            "outpkts_pps",
        ]:
            state_class = None
            native_unit_of_measurement = None
            icon = "mdi:gauge"
            enabled_default = False
            #entity_category = ENTITY_CATEGORY_DIAGNOSTIC

            # enabled_default
            if property in ["status", "inbytes", "inbytes_kbs", "outbytes", "outbytes_kbs", "inpkts", "inpkts_pps", "outpkts", "outpkts_pps"]:
                enabled_default = True

            # state class
            if "_pps" in property or "_kbs" in property:
                state_class = STATE_CLASS_MEASUREMENT

            entity = PfSenseInterfaceSensor(
                coordinator,
                SensorEntityDescription(
                    key="telemetry.interface.{}.{}".format(
                        interface["ifname"], property),
                    name="Interface {} {}".format(
                        interface["descr"], property),
                    native_unit_of_measurement=native_unit_of_measurement,
                    icon=icon,
                    state_class=state_class,
                    #entity_category=entity_category,
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
            icon = "mdi:gauge"
            enabled_default = True
            #entity_category = ENTITY_CATEGORY_DIAGNOSTIC

            if property == "loss":
                native_unit_of_measurement = PERCENTAGE

            entity = PfSenseGatewaySensor(
                coordinator,
                SensorEntityDescription(
                    key="telemetry.gateway.{}.{}".format(
                        gateway["name"], property),
                    name="Gateway {} {}".format(gateway["name"], property),
                    native_unit_of_measurement=native_unit_of_measurement,
                    icon=icon,
                    state_class=state_class,
                    #entity_category=entity_category,
                ),
                enabled_default,
            )
            entities.append(entity)

    async_add_entities(entities)


def normalize_filesystem_device_name(device_name):
    return device_name.replace("/", "_slash_").strip("_")


class PfSenseSensor(PfSenseEntity, SensorEntity):
    """Representation of a sensor entity for pfSense status values."""

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entity_description: SensorEntityDescription,
        enabled_default: bool,
    ) -> None:
        """Initialize the sensor."""
        self.entity_description = entity_description
        self.coordinator = coordinator
        self._attr_entity_registry_enabled_default = enabled_default
        self._attr_name = f"{self.pfsense_device_name} {entity_description.name}"
        self._attr_unique_id = slugify(
            f"{self.pfsense_device_unique_id}_{entity_description.key}")

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
            device_clean = normalize_filesystem_device_name(
                filesystem["device"])
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
    def native_value(self):
        interface = self._pfsense_get_interface()
        property = self._pfsense_get_interface_property_name()
        try:
            return interface[property]
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
