"""OPNsense integration."""

import asyncio
from collections.abc import MutableMapping
import logging
from typing import Any

from homeassistant.components.update import UpdateDeviceClass, UpdateEntity, UpdateEntityDescription
from homeassistant.components.update.const import UpdateEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_platform
from homeassistant.helpers.entity import EntityCategory
from homeassistant.util import slugify

from .const import COORDINATOR, DOMAIN
from .coordinator import OPNsenseDataUpdateCoordinator
from .entity import OPNsenseEntity
from .helpers import dict_get

_LOGGER: logging.Logger = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: entity_platform.AddEntitiesCallback,
) -> None:
    """Set up the OPNsense update entities."""
    coordinator: OPNsenseDataUpdateCoordinator = hass.data[DOMAIN][config_entry.entry_id][
        COORDINATOR
    ]
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
    """Class for OPNsense Update entitiy."""

    def __init__(
        self,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        entity_description: UpdateEntityDescription,
    ) -> None:
        """Initialize update entity."""

        name_suffix: str | None = (
            entity_description.name if isinstance(entity_description.name, str) else None
        )
        unique_id_suffix: str | None = (
            entity_description.key if isinstance(entity_description.key, str) else None
        )
        super().__init__(
            config_entry,
            coordinator,
            unique_id_suffix=unique_id_suffix,
            name_suffix=name_suffix,
        )
        self.entity_description: UpdateEntityDescription = entity_description
        self._attr_supported_features |= (
            UpdateEntityFeature.INSTALL | UpdateEntityFeature.RELEASE_NOTES
            # | UpdateEntityFeature.BACKUP
            # | UpdateEntityFeature.PROGRESS
            # | UpdateEntityFeature.SPECIFIC_VERSION
        )
        self._attr_title: str = "OPNsense"
        self._attr_in_progress: bool = False
        self._attr_installed_version: str | None = None
        self._attr_latest_version: str | None = None
        self._attr_release_url: str | None = None
        self._attr_release_summary: str | None = None
        self._release_notes: str | None = None


class OPNsenseFirmwareUpdatesAvailableUpdate(OPNsenseUpdate):
    """Class for OPNsense Firmware Update entity."""

    @callback
    def _handle_coordinator_update(self) -> None:
        state: MutableMapping[str, Any] = self.coordinator.data
        try:
            if state["firmware_update_info"]["status"] == "error":
                self._available = False
                self.async_write_ha_state()
                return
        except (TypeError, KeyError, AttributeError):
            self._available = False
            self.async_write_ha_state()
            return
        self._available = True

        try:
            self._attr_installed_version = dict_get(
                state, "firmware_update_info.product.product_version"
            )
        except (TypeError, KeyError, AttributeError):
            self._attr_installed_version = None

        try:
            product_version = dict_get(state, "firmware_update_info.product.product_version")
            product_latest = dict_get(state, "firmware_update_info.product.product_latest")
            product_series = dict_get(state, "firmware_update_info.product.product_series")
            if product_version is None or product_latest is None:
                self._attr_latest_version = None

            if (
                dict_get(state, "firmware_update_info.status") == "update"
                and product_version == product_latest
            ):
                packages = dict_get(
                    state, "firmware_update_info.product.product_check.upgrade_packages"
                )
                if isinstance(packages, list):
                    package_found: bool = False
                    for package in packages:
                        if package.get("name") == "opnsense" and package.get("new_version"):
                            package_found = True
                            product_latest = package.get("new_version")
                            break
                    if not package_found:
                        product_latest = f"{product_latest}+"
                else:
                    product_latest = f"{product_latest}+"

            if dict_get(state, "firmware_update_info.status") == "upgrade":
                product_latest = dict_get(state, "firmware_update_info.upgrade_major_version")
                if product_latest:
                    product_series = (
                        ".".join(product_latest.split(".")[:2])
                        if "." in product_latest
                        else product_latest
                    )

            if product_latest:
                self._attr_latest_version = product_latest.replace("_", ".")
        except (TypeError, KeyError, AttributeError):
            self._attr_latest_version = None

        product_class: str | None = None
        if product_series:
            try:
                series_minor: str | None = str(product_series).split(".")[1]
            except IndexError:
                series_minor = None
            if series_minor in {"1", "7"}:
                product_class = "community"
            elif series_minor in {"4", "10"}:
                product_class = "business"
        _LOGGER.debug(
            "[Update handle_coordinator_update] product_version: %s, product_latest: %s, product_series: %s, product_class: %s",
            product_version,
            product_latest,
            product_series,
            product_class,
        )

        if product_series and product_latest and product_class:
            self._attr_release_url = f"https://github.com/opnsense/changelog/blob/master/{product_class}/{product_series}/{product_latest.split('+')[0].split('_')[0]}"
        else:
            self._attr_release_url = (
                self.config_entry.data.get("url", None) + "/ui/core/firmware#changelog"
            )

        _LOGGER.debug("[Update handle_coordinator_update] release_url: %s", self._attr_release_url)
        summary: str | None = None
        try:
            if dict_get(state, "firmware_update_info.status") == "update":
                product_name = dict_get(state, "firmware_update_info.product.product_name")
                product_nickname = dict_get(state, "firmware_update_info.product.product_nickname")
                status_msg = dict_get(state, "firmware_update_info.status_msg")

                needs_reboot: bool = (
                    dict_get(state, "firmware_update_info.needs_reboot") == "1"
                    if dict_get(state, "firmware_update_info.needs_reboot")
                    else False
                )

                total_package_count: int = len(
                    (dict_get(state, "firmware_update_info.all_packages", {}) or {}).keys()
                )
                new_package_count: int = len(
                    dict_get(state, "firmware_update_info.new_packages", []) or []
                )
                reinstall_package_count: int = len(
                    dict_get(state, "firmware_update_info.reinstall_packages", []) or []
                )
                remove_package_count: int = len(
                    dict_get(state, "firmware_update_info.remove_packages", []) or []
                )
                upgrade_package_count: int = len(
                    dict_get(state, "firmware_update_info.upgrade_packages", []) or []
                )

                summary = f"""
## {product_name} version {product_latest} ({product_nickname})

{status_msg}

- reboot needed: {needs_reboot}
- total affected packages: {total_package_count}
- new packages: {new_package_count}
- reinstalled packages: {reinstall_package_count}
- removed packages: {remove_package_count}
- upgraded packages: {upgrade_package_count}
"""
            elif dict_get(state, "firmware_update_info.status") == "upgrade":
                product_name = dict_get(state, "firmware_update_info.product.product_name")
                status_msg = dict_get(state, "firmware_update_info.status_msg")

                upgrade_needs_reboot: bool = (
                    dict_get(state, "firmware_update_info.upgrade_needs_reboot") == "1"
                    if dict_get(state, "firmware_update_info.upgrade_needs_reboot")
                    else False
                )

                summary = f"""
## {product_name} version {product_version}

{status_msg}

- reboot needed: {upgrade_needs_reboot}
"""
            else:
                summary = dict_get(state, "firmware_update_info.status_msg")

        except (TypeError, KeyError, AttributeError) as e:
            _LOGGER.error(
                "Error getting release notes. %s: %s",
                e.__class__.__qualname__,
                e,
            )
            self._release_notes = None
        self._release_notes = summary
        self._attr_release_summary = dict_get(state, "firmware_update_info.status_msg")

        self._attr_extra_state_attributes = {}

        for key in (
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
        ):
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
        state: MutableMapping[str, Any] = self.coordinator.data
        if not isinstance(state, MutableMapping):
            _LOGGER.error("Cannot update firmware, state data is missing")
            return
        upgrade_type = dict_get(state, "firmware_update_info.status")
        if upgrade_type not in {"update", "upgrade"}:
            return

        upgrade_details = await self._client.upgrade_firmware(upgrade_type)
        _LOGGER.debug(
            "[async_install] Starting Firmware %s. upgrade_details: %s",
            upgrade_type,
            upgrade_details,
        )
        sleep_time = 10
        exceptions = 0
        running: bool = True
        while running:
            await asyncio.sleep(sleep_time)
            try:
                response = await self._client.upgrade_status()
                _LOGGER.debug("[async_install] upgrade_status: %s", response)
                # after finished status is "done"
                running = response["status"] == "running"
            except Exception as e:  # noqa: BLE001
                exceptions += 1
                _LOGGER.warning(
                    "Error #%s while getting upgrade_status. %s: %s",
                    exceptions,
                    e.__class__.__qualname__,
                    e,
                )
                if exceptions > 3:
                    running = False
            else:
                exceptions = 0

        # check needs_reboot, if yes trigger reboot
        response = await self._client.get_firmware_update_info()
        _LOGGER.debug("[async_install] firmware_update_info: %s", response)

        upgrade_needs_reboot: bool = (
            dict_get(response, "upgrade_needs_reboot") == "1"
            if dict_get(response, "upgrade_needs_reboot")
            else False
        )
        needs_reboot: bool = (
            dict_get(response, "needs_reboot") == "1"
            if dict_get(response, "needs_reboot")
            else False
        )

        if upgrade_needs_reboot or needs_reboot:
            _LOGGER.debug("[async_install] Rebooting")
            await self._client.system_reboot()
