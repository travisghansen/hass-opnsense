"""pfSense integration."""
import logging
from typing import Callable

from homeassistant.components.binary_sensor import BinarySensorEntity, BinarySensorEntityDescription
from homeassistant.const import (
    #ENTITY_CATEGORY_DIAGNOSTIC,
    STATE_UNKNOWN,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import (
    DataUpdateCoordinator,
)
from homeassistant.util import slugify

from . import PfSenseEntity

from .const import (
    COORDINATOR,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: dict,
    async_add_entities: Callable,
):
    """Set up the pfSense binary sensors."""
    data = hass.data[DOMAIN][config_entry.entry_id]
    coordinator = data[COORDINATOR]
    #state = coordinator.data
    entities = []

    entity = PfSenseCarpStatusBinarySensor(
        coordinator,
        BinarySensorEntityDescription(
            key=f"carp.status",
            name="CARP Status",
            #native_unit_of_measurement=native_unit_of_measurement,
            icon="mdi:gauge",
            #state_class=state_class,
            #entity_category=entity_category,
        ),
        True,
    )
    entities.append(entity)

    async_add_entities(entities)


class PfSenseBinarySensor(PfSenseEntity, BinarySensorEntity):
    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entity_description: BinarySensorEntityDescription,
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
