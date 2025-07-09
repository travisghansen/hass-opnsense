"""OPNsense integration."""

from collections.abc import Mapping, MutableMapping
import logging
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import CONF_SYNC_CARP, CONF_SYNC_NOTICES, COORDINATOR, DEFAULT_SYNC_OPTION_VALUE
from .coordinator import OPNsenseDataUpdateCoordinator
from .entity import OPNsenseEntity
from .helpers import dict_get

_LOGGER: logging.Logger = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the OPNsense binary sensors."""

    coordinator: OPNsenseDataUpdateCoordinator = getattr(config_entry.runtime_data, COORDINATOR)
    config: Mapping[str, Any] = config_entry.data

    entities: list = []
    if config.get(CONF_SYNC_CARP, DEFAULT_SYNC_OPTION_VALUE):
        entities.append(
            OPNsenseCarpStatusBinarySensor(
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
        )
    if config.get(CONF_SYNC_NOTICES, DEFAULT_SYNC_OPTION_VALUE):
        entities.append(
            OPNsensePendingNoticesPresentBinarySensor(
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
            ),
        )
    async_add_entities(entities)


class OPNsenseBinarySensor(OPNsenseEntity, BinarySensorEntity):
    """OPNsense Binary Sensor Class."""

    def __init__(
        self,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        entity_description: BinarySensorEntityDescription,
    ) -> None:
        """Initialize OPNsense Binary Sensor entity."""
        name_suffix: str | None = (
            entity_description.name if isinstance(entity_description.name, str) else None
        )
        unique_id_suffix: str | None = (
            entity_description.key if isinstance(entity_description.key, str) else None
        )
        super().__init__(
            config_entry=config_entry,
            coordinator=coordinator,
            unique_id_suffix=unique_id_suffix,
            name_suffix=name_suffix,
        )
        self.entity_description: BinarySensorEntityDescription = entity_description
        self._attr_is_on: bool = False


class OPNsenseCarpStatusBinarySensor(OPNsenseBinarySensor):
    """OPNsense Binary Sensor Carp Class."""

    @callback
    def _handle_coordinator_update(self) -> None:
        state: MutableMapping[str, Any] = self.coordinator.data
        if not isinstance(state, MutableMapping):
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
    """OPNsense Binary Sensor Pending Notices Class."""

    @callback
    def _handle_coordinator_update(self) -> None:
        state: MutableMapping[str, Any] = self.coordinator.data
        if not isinstance(state, MutableMapping):
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
