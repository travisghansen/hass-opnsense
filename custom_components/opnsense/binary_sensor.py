"""OPNsense integration."""

import logging
from collections.abc import Mapping
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_platform

from . import OPNsenseEntity
from .const import COORDINATOR, DOMAIN
from .coordinator import OPNsenseDataUpdateCoordinator
from .helpers import dict_get

_LOGGER: logging.Logger = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: entity_platform.AddEntitiesCallback,
) -> None:
    """Set up the OPNsense binary sensors."""

    coordinator: OPNsenseDataUpdateCoordinator = hass.data[DOMAIN][
        config_entry.entry_id
    ][COORDINATOR]

    entities: list = []
    entity = OPNsenseCarpStatusBinarySensor(
        config_entry=config_entry,
        coordinator=coordinator,
        entity_description=BinarySensorEntityDescription(
            key="carp.status",
            name="CARP Status",
            icon="mdi:gauge",
            device_class=None,
            # entity_category=entity_category,
            entity_registry_enabled_default=False,
        ),
    )
    entities.append(entity)

    entity = OPNsensePendingNoticesPresentBinarySensor(
        config_entry=config_entry,
        coordinator=coordinator,
        entity_description=BinarySensorEntityDescription(
            key="notices.pending_notices_present",
            name="Pending Notices Present",
            icon="mdi:alert",
            device_class=BinarySensorDeviceClass.PROBLEM,
            # entity_category=entity_category,
            entity_registry_enabled_default=True,
        ),
    )
    entities.append(entity)

    async_add_entities(entities)


class OPNsenseBinarySensor(OPNsenseEntity, BinarySensorEntity):

    def __init__(
        self,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        entity_description: BinarySensorEntityDescription,
    ) -> None:
        super().__init__(
            config_entry=config_entry,
            coordinator=coordinator,
            unique_id_suffix=entity_description.key,
            name_suffix=entity_description.name,
        )
        self.entity_description: BinarySensorEntityDescription = entity_description
        self._attr_is_on: bool = False


class OPNsenseCarpStatusBinarySensor(OPNsenseBinarySensor):
    @callback
    def _handle_coordinator_update(self) -> None:
        state: Mapping[str, Any] = self.coordinator.data
        if not isinstance(state, Mapping):
            self._available = False
            self.async_write_ha_state()
            return
        try:
            self._attr_is_on = state["carp_status"]
        except (TypeError, KeyError, ZeroDivisionError):
            self._available = False
            self.async_write_ha_state()
            return
        self._available = True
        self._attr_extra_state_attributes = {}
        self.async_write_ha_state()


class OPNsensePendingNoticesPresentBinarySensor(OPNsenseBinarySensor):
    @callback
    def _handle_coordinator_update(self) -> None:
        state: Mapping[str, Any] = self.coordinator.data
        if not isinstance(state, Mapping):
            self._available = False
            self.async_write_ha_state()
            return
        try:
            self._attr_is_on = state["notices"]["pending_notices_present"]
        except (TypeError, KeyError, ZeroDivisionError):
            self._available = False
            self.async_write_ha_state()
            return

        self._available = True
        self._attr_extra_state_attributes["pending_notices"] = dict_get(
            state, "notices.pending_notices", []
        )
        self.async_write_ha_state()
