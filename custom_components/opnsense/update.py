"""pfSense integration."""
import logging
from pydoc import cli
import time
from typing import Any

from homeassistant.components.update import (
    UpdateDeviceClass,
    UpdateEntity,
    UpdateEntityDescription,
)
from homeassistant.components.update.const import UpdateEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_platform
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import slugify

from . import CoordinatorEntityManager, OPNSenseEntity, dict_get
from .const import COORDINATOR, DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: entity_platform.AddEntitiesCallback,
):
    """Set up the OPNSense update entities."""

    @callback
    def process_entities_callback(hass, config_entry):
        data = hass.data[DOMAIN][config_entry.entry_id]
        coordinator = data[COORDINATOR]
        entities = []
        entity = OPNSenseFirmwareUpdatesAvailableUpdate(
            config_entry,
            coordinator,
            UpdateEntityDescription(
                key=f"firmware.update_available",
                name="Firmware Updates Available",
                entity_category=EntityCategory.DIAGNOSTIC,
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


class OPNSenseUpdate(OPNSenseEntity, UpdateEntity):
    def __init__(
        self,
        config_entry,
        coordinator: DataUpdateCoordinator,
        entity_description: UpdateEntityDescription,
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

        self._attr_supported_features |= (
            UpdateEntityFeature.INSTALL
            # | UpdateEntityFeature.BACKUP
            # | UpdateEntityFeature.PROGRESS
            # | UpdateEntityFeature.RELEASE_NOTES
            # | UpdateEntityFeature.SPECIFIC_VERSION
        )

    @property
    def device_class(self):
        return UpdateDeviceClass.FIRMWARE


class OPNSenseFirmwareUpdatesAvailableUpdate(OPNSenseUpdate):
    @property
    def available(self):
        state = self.coordinator.data
        if state["firmware_update_info"] is None:
            return False

        try:
            status = state["firmware_update_info"]["status"]
            if status == "error":
                return False
        except:
            return False

        return super().available

    @property
    def title(self):
        return "OPNSense"

    @property
    def installed_version(self):
        """Version installed and in use."""
        state = self.coordinator.data

        try:
            return dict_get(state, "firmware_update_info.product.product_version")
        except KeyError:
            return None

    @property
    def latest_version(self):
        """Latest version available for install."""
        state = self.coordinator.data

        try:
            # fake a new update
            # return "foobar"
            return dict_get(
                state, "firmware_update_info.product.product_check.product_version"
            )
        except KeyError:
            return None

    @property
    def in_progress(self) -> bool:
        """Update installation in progress."""
        return False

    @property
    def extra_state_attributes(self):
        state = self.coordinator.data
        attrs = {}

        for key in [
            "status",
            "status_msg",
            "last_check",
            "os_version",
            "product_id",
            "product_target",
            "product_version",
            "upgrade_needs_reboot",
            "download_size",
        ]:
            slug_key = slugify(key)
            attrs[f"opnsense_{slug_key}"] = dict_get(
                state, f"firmware_update_info.{key}"
            )

        return attrs

    @property
    def release_url(self):
        return self.config_entry.data.get("url", None) + "/ui/core/firmware#changelog"

    async def async_install(
        self, version: str | None, backup: bool, **kwargs: Any
    ) -> None:
        """Install an update."""
        client = self._get_opnsense_client()
        task_details = await self.hass.async_add_executor_job(client.upgrade_firmware)
        sleep_time = 10
        running = True
        while running:
            await self.hass.async_add_executor_job(time.sleep, sleep_time)
            response = await self.hass.async_add_executor_job(client.upgrade_status)
            running = response["status"] == "running"
