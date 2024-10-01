"""OPNsense integration."""

import asyncio
import logging
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
from homeassistant.util import slugify

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
    """Set up the OPNsense update entities."""
    coordinator: OPNsenseDataUpdateCoordinator = hass.data[DOMAIN][
        config_entry.entry_id
    ][COORDINATOR]
    entities: list = []
    entity = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=config_entry,
        coordinator=coordinator,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available",
            name="Firmware Updates Available",
            entity_category=EntityCategory.DIAGNOSTIC,
            device_class=UpdateDeviceClass.FIRMWARE,
            entity_registry_enabled_default=True,
        ),
    )
    entities.append(entity)

    async_add_entities(entities)


class OPNsenseUpdate(OPNsenseEntity, UpdateEntity):

    def __init__(
        self,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        entity_description: UpdateEntityDescription,
    ) -> None:
        super().__init__(
            config_entry,
            coordinator,
            unique_id_suffix=entity_description.key,
            name_suffix=entity_description.name,
        )
        self.entity_description: UpdateEntityDescription = entity_description
        self._attr_supported_features |= (
            UpdateEntityFeature.INSTALL
            | UpdateEntityFeature.RELEASE_NOTES
            # | UpdateEntityFeature.BACKUP
            # | UpdateEntityFeature.PROGRESS
            # | UpdateEntityFeature.SPECIFIC_VERSION
        )
        self._attr_title: str = "OPNsense"
        self._attr_in_progress: bool = False
        self._attr_installed_version: str | None = None
        self._attr_latest_version: str | None = None
        self._attr_release_url: str | None = None
        self._release_notes: str | None = None


class OPNsenseFirmwareUpdatesAvailableUpdate(OPNsenseUpdate):

    @callback
    def _handle_coordinator_update(self) -> None:
        state = self.coordinator.data
        try:
            if state["firmware_update_info"]["status"] == "error":
                self._available = False
                return
        except (TypeError, KeyError, AttributeError):
            self._available = False
            return
        self._available = True

        try:
            self._attr_installed_version = dict_get(
                state, "firmware_update_info.product.product_version"
            )
        except (TypeError, KeyError, AttributeError):
            self._attr_installed_version = None

        try:
            product_version = dict_get(
                state, "firmware_update_info.product.product_version"
            )
            product_latest = dict_get(
                state, "firmware_update_info.product.product_latest"
            )
            if product_version is None or product_latest is None:
                self._attr_latest_version = None

            if (
                dict_get(state, "firmware_update_info.status") == "update"
                and product_version == product_latest
            ):
                product_latest = product_latest + "+"

            if dict_get(state, "firmware_update_info.status") == "upgrade":
                product_latest = dict_get(
                    state, "firmware_update_info.upgrade_major_version"
                )

            self._attr_latest_version = product_latest
        except (TypeError, KeyError, AttributeError):
            self._attr_latest_version = None

        self._attr_release_url = (
            self.config_entry.data.get("url", None) + "/ui/core/firmware#changelog"
        )

        summary = None
        try:
            if dict_get(state, "firmware_update_info.status") == "update":
                product_name = dict_get(
                    state, "firmware_update_info.product.product_name"
                )
                product_nickname = dict_get(
                    state, "firmware_update_info.product.product_nickname"
                )
                product_version = dict_get(
                    state, "firmware_update_info.product.product_version"
                )
                product_latest = dict_get(
                    state, "firmware_update_info.product.product_latest"
                )
                status_msg = dict_get(state, "firmware_update_info.status_msg")

                needs_reboot: bool = (
                    dict_get(state, "firmware_update_info.needs_reboot") == "1"
                    if dict_get(state, "firmware_update_info.needs_reboot")
                    else False
                )

                total_package_count: int = len(
                    dict_get(state, "firmware_update_info.all_packages", {}).keys()
                )
                new_package_count: int = len(
                    dict_get(state, "firmware_update_info.new_packages", [])
                )
                reinstall_package_count: int = len(
                    dict_get(state, "firmware_update_info.reinstall_packages", [])
                )
                remove_package_count: int = len(
                    dict_get(state, "firmware_update_info.remove_packages", [])
                )
                upgrade_package_count: int = len(
                    dict_get(state, "firmware_update_info.upgrade_packages", [])
                )

                summary: str = f"""
## {product_name} version {product_latest} ({product_nickname})

{status_msg}

- reboot needed: {needs_reboot}
- total affected packages: {total_package_count}
- new packages: {new_package_count}
- reinstalled packages: {reinstall_package_count}
- removed packages: {remove_package_count}
- upgraded packages: {upgrade_package_count}
"""
            if dict_get(state, "firmware_update_info.status") == "upgrade":
                product_name = dict_get(
                    state, "firmware_update_info.product.product_name"
                )
                product_version = dict_get(
                    state, "firmware_update_info.upgrade_major_version"
                )
                status_msg = dict_get(state, "firmware_update_info.status_msg")

                upgrade_needs_reboot: bool = (
                    dict_get(state, "firmware_update_info.upgrade_needs_reboot") == "1"
                    if dict_get(state, "firmware_update_info.upgrade_needs_reboot")
                    else False
                )

                summary: str = f"""
## {product_name} version {product_version}

{status_msg}

- reboot needed: {upgrade_needs_reboot}
"""
        except (TypeError, KeyError, AttributeError):
            self._release_notes = None
        self._release_notes = summary

        self._attr_extra_state_attributes = {}

        for key in [
            "status",
            "status_msg",
            "last_check",
            "os_version",
            "product_id",
            "product_target",
            "product_version",
            "upgrade_needs_reboot",
            "needs_reboot",
            "download_size",
        ]:
            slug_key = slugify(key)
            self._attr_extra_state_attributes[f"opnsense_{slug_key}"] = dict_get(
                state, f"firmware_update_info.{key}"
            )
        self.async_write_ha_state()

    async def async_release_notes(self) -> str | None:
        """Return the release notes of the latest version."""
        return self._release_notes

    async def async_install(
        self, version: str | None = None, backup: bool = False, **kwargs: Any
    ) -> None:
        """Install an update."""
        state = self.coordinator.data
        upgrade_type = dict_get(state, "firmware_update_info.status")
        if upgrade_type not in ["update", "upgrade"]:
            return

        sleep_time = 10
        exceptions = 0
        running = True
        while running:
            await asyncio.sleep(sleep_time)
            try:
                response = self._client.upgrade_status()
                # after finished status is "done"
                running: bool = response["status"] == "running"
            except Exception as e:
                exceptions += 1
                _LOGGER.debug(
                    f"Error #{exceptions} while getting upgrade_status. {e.__class__.__qualname__}: {e}"
                )
                if exceptions > 3:
                    running = False
                pass
            else:
                exceptions = 0

        # check needs_reboot, if yes trigger reboot
        response = self._client.get_firmware_update_info()

        upgrade_needs_reboot: bool = (
            dict_get(response, "needs_reboot") == "1"
            if dict_get(response, "upgrade_needs_reboot")
            else False
        )
        needs_reboot: bool = (
            dict_get(response, "needs_reboot") == "1"
            if dict_get(response, "needs_reboot")
            else False
        )

        if upgrade_needs_reboot or needs_reboot:
            self._client.system_reboot()
