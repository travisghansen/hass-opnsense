"""OPNsense integration."""

import logging

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import STATE_UNKNOWN
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_platform
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import slugify

from . import CoordinatorEntityManager, OPNsenseEntity
from .const import COORDINATOR, DOMAIN
from .helpers import dict_get

_LOGGER: logging.Logger = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: entity_platform.AddEntitiesCallback,
):
    """Set up the OPNsense binary sensors."""

    @callback
    def process_entities_callback(hass, config_entry):
        data = hass.data[DOMAIN][config_entry.entry_id]
        coordinator = data[COORDINATOR]
        entities = []
        entity = OPNsenseCarpStatusBinarySensor(
            config_entry,
            coordinator,
            BinarySensorEntityDescription(
                key="carp.status",
                name="CARP Status",
                # native_unit_of_measurement=native_unit_of_measurement,
                icon="mdi:gauge",
                # state_class=state_class,
                # entity_category=entity_category,
            ),
            False,
        )
        entities.append(entity)

        entity = OPNsensePendingNoticesPresentBinarySensor(
            config_entry,
            coordinator,
            BinarySensorEntityDescription(
                key=f"notices.pending_notices_present",
                name="Pending Notices Present",
                # native_unit_of_measurement=native_unit_of_measurement,
                icon="mdi:alert",
                # state_class=state_class,
                # entity_category=entity_category,
            ),
            True,
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


class OPNsenseBinarySensor(OPNsenseEntity, BinarySensorEntity):
    def __init__(
        self,
        config_entry,
        coordinator: DataUpdateCoordinator,
        entity_description: BinarySensorEntityDescription,
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

    @property
    def is_on(self):
        return False

    @property
    def device_class(self):
        return None

    @property
    def extra_state_attributes(self):
        return None


class OPNsenseCarpStatusBinarySensor(OPNsenseBinarySensor):
    @property
    def available(self) -> bool:
        state = self.coordinator.data
        if dict_get(state, "carp_status") is None:
            return False

        return super().available

    @property
    def is_on(self):
        state = self.coordinator.data
        try:
            return state["carp_status"]
        except KeyError:
            return STATE_UNKNOWN


class OPNsensePendingNoticesPresentBinarySensor(OPNsenseBinarySensor):
    @property
    def available(self) -> bool:
        state = self.coordinator.data
        if dict_get(state, "notices.pending_notices_present") is None:
            return False

        return super().available

    @property
    def is_on(self):
        state = self.coordinator.data
        try:
            return state["notices"]["pending_notices_present"]
        except KeyError:
            return STATE_UNKNOWN

    @property
    def device_class(self):
        return BinarySensorDeviceClass.PROBLEM

    @property
    def extra_state_attributes(self):
        state = self.coordinator.data
        attrs = {}

        notices = dict_get(state, "notices.pending_notices", [])
        attrs["pending_notices"] = notices

        return attrs
