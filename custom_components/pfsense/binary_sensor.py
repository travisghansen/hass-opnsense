"""pfSense integration."""
import logging

from homeassistant.components.binary_sensor import (
    DEVICE_CLASS_PROBLEM,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import STATE_UNKNOWN
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_platform
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import slugify

from . import CoordinatorEntityManager, PfSenseEntity, dict_get
from .const import COORDINATOR, DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: entity_platform.AddEntitiesCallback,
):
    """Set up the pfSense binary sensors."""

    @callback
    def process_entities_callback(hass, config_entry):
        data = hass.data[DOMAIN][config_entry.entry_id]
        coordinator = data[COORDINATOR]
        entities = []
        entity = PfSenseCarpStatusBinarySensor(
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

        entity = PfSensePendingNoticesPresentBinarySensor(
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


class PfSenseBinarySensor(PfSenseEntity, BinarySensorEntity):
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
        self._attr_name = f"{self.pfsense_device_name} {entity_description.name}"
        self._attr_unique_id = slugify(
            f"{self.pfsense_device_unique_id}_{entity_description.key}"
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


class PfSenseCarpStatusBinarySensor(PfSenseBinarySensor):
    @property
    def is_on(self):
        state = self.coordinator.data
        try:
            return state["carp_status"]
        except KeyError:
            return STATE_UNKNOWN


class PfSensePendingNoticesPresentBinarySensor(PfSenseBinarySensor):
    @property
    def is_on(self):
        state = self.coordinator.data
        try:
            return state["notices"]["pending_notices_present"]
        except KeyError:
            return STATE_UNKNOWN

    @property
    def device_class(self):
        return DEVICE_CLASS_PROBLEM

    @property
    def extra_state_attributes(self):
        state = self.coordinator.data
        attrs = {}

        notices = dict_get(state, "notices.pending_notices")
        attrs["pending_notices"] = notices

        return attrs
