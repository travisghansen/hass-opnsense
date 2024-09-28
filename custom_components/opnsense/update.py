"""OPNsense integration."""

from collections.abc import Mapping
import logging
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
from homeassistant.util import slugify

from . import CoordinatorEntityManager, OPNsenseEntity
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

    @callback
    def process_entities_callback(hass, config_entry) -> list:
        data = hass.data[DOMAIN][config_entry.entry_id]
        coordinator = data[COORDINATOR]
        entities: list = []
        entity = OPNsenseFirmwareUpdatesAvailableUpdate(
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


class OPNsenseUpdate(OPNsenseEntity, UpdateEntity):
    def __init__(
        self,
        config_entry,
        coordinator: OPNsenseDataUpdateCoordinator,
        entity_description: UpdateEntityDescription,
        enabled_default: bool,
    ) -> None:
        super().__init__(
            config_entry,
            coordinator,
            unique_id_suffix=entity_description.key,
            name_suffix=entity_description.name,
        )
        self.entity_description = entity_description
        self._attr_entity_registry_enabled_default = enabled_default
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


class OPNsenseFirmwareUpdatesAvailableUpdate(OPNsenseUpdate):
    @property
    def available(self) -> bool:
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
    def title(self) -> str:
        return "OPNsense"

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
            product_version = dict_get(
                state, "firmware_update_info.product.product_version"
            )
            product_latest = dict_get(
                state, "firmware_update_info.product.product_latest"
            )
            if product_version is None or product_latest is None:
                return None

            if (
                dict_get(state, "firmware_update_info.status") == "update"
                and product_version == product_latest
            ):
                product_latest = product_latest + "+"

            if dict_get(state, "firmware_update_info.status") == "upgrade":
                product_latest = dict_get(
                    state, "firmware_update_info.upgrade_major_version"
                )

            return product_latest
        except KeyError:
            return None

    @property
    def in_progress(self) -> bool:
        """Update installation in progress."""
        return False

    @property
    def extra_state_attributes(self) -> Mapping[str, Any]:
        state = self.coordinator.data
        attrs: Mapping[str, Any] = {}

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
            attrs[f"opnsense_{slug_key}"] = dict_get(
                state, f"firmware_update_info.{key}"
            )

        return attrs

    @property
    def release_url(self) -> str:
        return self.config_entry.data.get("url", None) + "/ui/core/firmware#changelog"

    @property
    def release_summary(self) -> None | str:
        summary = None
        try:
            state = self.coordinator.data

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
                needs_reboot = dict_get(state, "firmware_update_info.needs_reboot")

                if needs_reboot is None or needs_reboot == "0":
                    needs_reboot = False

                if needs_reboot == "1":
                    needs_reboot = True

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

                summary: str = (
                    """
## {} version {} ({})

{}

- reboot needed: {}
- total affected packages: {}
- new packages: {}
- reinstalled packages: {}
- removed packages: {}
- upgraded packages: {}
""".format(
                        product_name,
                        product_latest,
                        product_nickname,
                        status_msg,
                        needs_reboot,
                        total_package_count,
                        new_package_count,
                        reinstall_package_count,
                        remove_package_count,
                        upgrade_package_count,
                    )
                )

            if dict_get(state, "firmware_update_info.status") == "upgrade":
                product_name = dict_get(
                    state, "firmware_update_info.product.product_name"
                )
                product_version = dict_get(
                    state, "firmware_update_info.upgrade_major_version"
                )
                status_msg = dict_get(state, "firmware_update_info.status_msg")
                upgrade_needs_reboot = dict_get(
                    state, "firmware_update_info.upgrade_needs_reboot"
                )

                if upgrade_needs_reboot is None or upgrade_needs_reboot == "0":
                    upgrade_needs_reboot = False

                if upgrade_needs_reboot == "1":
                    upgrade_needs_reboot = True

                summary: str = (
                    """
## {} version {}

{}

- reboot needed: {}
""".format(
                        product_name,
                        product_version,
                        status_msg,
                        upgrade_needs_reboot,
                    )
                )

        except:
            return None
        return summary

    def install(self, version=None, backup=False) -> None:
        """Install an update."""
        state = self.coordinator.data
        upgrade_type = dict_get(state, "firmware_update_info.status")
        if upgrade_type not in ["update", "upgrade"]:
            return

        client = self._get_opnsense_client()
        task_details = client.upgrade_firmware(upgrade_type)
        sleep_time = 10
        running = True
        while running:
            time.sleep(sleep_time)
            try:
                response = client.upgrade_status()
                # after finished status is "done"
                running = response["status"] == "running"
            except:
                pass

        # check needs_reboot, if yes trigger reboot
        response = client.get_firmware_update_info()
        upgrade_needs_reboot = dict_get(response, "upgrade_needs_reboot")
        needs_reboot = dict_get(response, "needs_reboot")

        if upgrade_needs_reboot is None or upgrade_needs_reboot == "0":
            upgrade_needs_reboot = False

        if upgrade_needs_reboot == "1":
            upgrade_needs_reboot = True

        if needs_reboot is None or needs_reboot == "0":
            upgrade_needs_reboot = False

        if needs_reboot == "1":
            needs_reboot = True

        if upgrade_needs_reboot or needs_reboot:
            client.system_reboot()
