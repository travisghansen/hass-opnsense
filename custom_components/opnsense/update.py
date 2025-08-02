"""OPNsense integration."""

import asyncio
from collections.abc import Mapping, MutableMapping
import logging
from typing import Any

from homeassistant.components.update import UpdateDeviceClass, UpdateEntity, UpdateEntityDescription
from homeassistant.components.update.const import UpdateEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util import slugify

from .const import CONF_SYNC_FIRMWARE_UPDATES, COORDINATOR, DEFAULT_SYNC_OPTION_VALUE
from .coordinator import OPNsenseDataUpdateCoordinator
from .entity import OPNsenseEntity
from .helpers import dict_get

_LOGGER: logging.Logger = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the OPNsense update entities."""
    coordinator: OPNsenseDataUpdateCoordinator = getattr(config_entry.runtime_data, COORDINATOR)
    entities: list = []
    config: Mapping[str, Any] = config_entry.data

    if config.get(CONF_SYNC_FIRMWARE_UPDATES, DEFAULT_SYNC_OPTION_VALUE):
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
        if not self._is_update_available(state):
            self._available = False
            self.async_write_ha_state()
            return
        self._available = True

        self._attr_installed_version = self._get_installed_version(state)
        product_version, product_latest, product_series = self._get_versions(state)
        self._attr_latest_version = product_latest.replace("_", ".") if product_latest else None

        product_class = self._get_product_class(product_series)
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
        self._release_notes = self._get_release_notes(state, product_latest, product_version)
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

    def _is_update_available(self, state: MutableMapping[str, Any]) -> bool:
        try:
            return state["firmware_update_info"]["status"] != "error"
        except (TypeError, KeyError, AttributeError):
            return False

    def _get_installed_version(self, state: MutableMapping[str, Any]) -> str | None:
        try:
            return dict_get(state, "firmware_update_info.product.product_version")
        except (TypeError, KeyError, AttributeError):
            return None

    def _get_versions(
        self, state: MutableMapping[str, Any]
    ) -> tuple[str | None, str | None, str | None]:
        try:
            product_version = dict_get(state, "firmware_update_info.product.product_version")
            product_latest = dict_get(state, "firmware_update_info.product.product_latest")
            product_series = dict_get(state, "firmware_update_info.product.product_series")
            if product_version is None or product_latest is None:
                return product_version, None, product_series

            status = dict_get(state, "firmware_update_info.status")
            if status == "update":
                packages = dict_get(
                    state, "firmware_update_info.product.product_check.upgrade_packages"
                )
                if product_version == product_latest:
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
                elif isinstance(packages, list):
                    for package in packages:
                        if package.get("name") == "opnsense" and package.get("new_version"):
                            product_latest = package.get("new_version")
                            break

            if status == "upgrade":
                product_latest = dict_get(state, "firmware_update_info.upgrade_major_version")
                if product_latest:
                    product_series = (
                        ".".join(product_latest.split(".")[:2])
                        if "." in product_latest
                        else product_latest
                    )
        except (TypeError, KeyError, AttributeError):
            return None, None, None
        else:
            return product_version, product_latest, product_series

    def _get_product_class(self, product_series: str | None) -> str | None:
        if product_series:
            try:
                series_minor: str | None = str(product_series).split(".")[1]
            except IndexError:
                series_minor = None
            if series_minor in {"1", "7"}:
                return "community"
            if series_minor in {"4", "10"}:
                return "business"
        return None

    def _get_release_notes(
        self,
        state: MutableMapping[str, Any],
        product_latest: str | None,
        product_version: str | None,
    ) -> str | None:
        try:
            status = dict_get(state, "firmware_update_info.status")
            if status == "update":
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

                return f"""
## {product_name} version {product_latest} ({product_nickname})

{status_msg}

- reboot needed: {needs_reboot}
- total affected packages: {total_package_count}
- new packages: {new_package_count}
- reinstalled packages: {reinstall_package_count}
- removed packages: {remove_package_count}
- upgraded packages: {upgrade_package_count}
"""
            if status == "upgrade":
                product_name = dict_get(state, "firmware_update_info.product.product_name")
                status_msg = dict_get(state, "firmware_update_info.status_msg")

                upgrade_needs_reboot: bool = (
                    dict_get(state, "firmware_update_info.upgrade_needs_reboot") == "1"
                    if dict_get(state, "firmware_update_info.upgrade_needs_reboot")
                    else False
                )

                return f"""
## {product_name} version {product_version}

{status_msg}

- reboot needed: {upgrade_needs_reboot}
"""
            return dict_get(state, "firmware_update_info.status_msg")
        except (TypeError, KeyError, AttributeError) as e:
            _LOGGER.error(
                "Error getting release notes. %s: %s",
                type(e).__name__,
                e,
            )
            return (
                "Release notes unavailable due to an error. "
                "Check the Read release announcement link above or see the OPNsense web interface for details. "
                f"{type(e).__name__}: {e}"
            )

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
        if upgrade_type not in {"update", "upgrade"} or not self._client:
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
                    type(e).__name__,
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
