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
from .repair_reconciliation import record_desired_entities

_LOGGER: logging.Logger = logging.getLogger(__name__)


def _build_firmware_update_entity_description() -> UpdateEntityDescription:
    """Build the firmware update entity description.

    Returns:
        An update entity description for firmware availability.
    """
    return UpdateEntityDescription(
        key="firmware.update_available",
        name="Firmware Updates Available",
        entity_category=EntityCategory.DIAGNOSTIC,
        device_class=UpdateDeviceClass.FIRMWARE,
        entity_registry_enabled_default=True,
    )


def _mapping_or_empty(value: Any) -> Mapping[str, Any]:
    """Return a mapping value or an empty mapping.

    Args:
        value: Candidate mapping value.

    Returns:
        The mapping when provided, otherwise an empty dict.
    """
    return value if isinstance(value, Mapping) else {}


def _list_or_empty(value: Any) -> list[Any]:
    """Return a list value or an empty list.

    Args:
        value: Candidate list value.

    Returns:
        The list when provided, otherwise an empty list.
    """
    return value if isinstance(value, list) else []


def _affected_package_count(value: Any) -> int:
    """Return the count of affected firmware packages.

    Args:
        value: Candidate package collection from firmware status data.

    Returns:
        The number of packages represented by ``value``.
    """
    if isinstance(value, Mapping):
        return len(value)
    if isinstance(value, list):
        return len(value)
    return 0


def _opnsense_package_version(packages: list[Any]) -> str | None:
    """Return the OPNsense package version from firmware package rows.

    Args:
        packages: Firmware package rows from OPNsense.

    Returns:
        The OPNsense package version, or ``None`` when unavailable.
    """
    for package in packages:
        if not isinstance(package, Mapping):
            continue
        new_version = package.get("new_version")
        if package.get("name") == "opnsense" and isinstance(new_version, str) and new_version != "":
            return new_version
    return None


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the OPNsense update entities.

    Args:
        hass: Home Assistant instance.
        config_entry: Config entry being set up.
        async_add_entities: Callback used to register new entities.
    """
    coordinator: OPNsenseDataUpdateCoordinator = getattr(config_entry.runtime_data, COORDINATOR)
    entities: list[OPNsenseFirmwareUpdatesAvailableUpdate] = []
    config: Mapping[str, Any] = config_entry.data

    if config.get(CONF_SYNC_FIRMWARE_UPDATES, DEFAULT_SYNC_OPTION_VALUE):
        entities.append(
            OPNsenseFirmwareUpdatesAvailableUpdate(
                config_entry=config_entry,
                coordinator=coordinator,
                entity_description=_build_firmware_update_entity_description(),
            )
        )

    record_desired_entities(config_entry, "update", entities)
    async_add_entities(entities)


class OPNsenseUpdate(OPNsenseEntity, UpdateEntity):
    """Class for OPNsense Update entity."""

    def __init__(
        self,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        entity_description: UpdateEntityDescription,
    ) -> None:
        """Initialize update entity.

        Args:
            config_entry: Config entry owning the entity.
            coordinator: Shared OPNsense data coordinator.
            entity_description: Description that defines the entity identity.
        """
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
        """Handle coordinator update."""
        state: dict[str, Any] = self.coordinator.data
        if not self._is_update_available(state):
            self._mark_unavailable()
            return
        self._available = True

        self._attr_installed_version = self._get_installed_version(state)
        product_version, product_latest, product_series = self._get_versions(state)
        self._attr_latest_version = product_latest.replace("_", ".") if product_latest else None

        product_class = self._get_product_class(product_series)

        if product_series and product_latest and product_class:
            self._attr_release_url = f"https://github.com/opnsense/changelog/blob/master/{product_class}/{product_series}/{product_latest.split('+')[0].split('_')[0]}"
        else:
            self._attr_release_url = (
                self.config_entry.data.get("url", None) + "/ui/core/firmware#changelog"
            )

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
        """Return whether an update is available.

        Args:
            state: Current OPNsense state payload.

        Returns:
            ``True`` when firmware update data reports an actionable status.
        """
        if not isinstance(state, Mapping):
            return False
        firmware_update_info = state.get("firmware_update_info")
        if not isinstance(firmware_update_info, Mapping):
            return False
        status = firmware_update_info.get("status")
        return isinstance(status, str) and status not in {"", "error"}

    def _get_installed_version(self, state: MutableMapping[str, Any]) -> str | None:
        """Return the installed firmware version.

        Args:
            state: Current OPNsense state payload.

        Returns:
            The installed firmware version, or ``None`` when unavailable.
        """
        product_version = dict_get(state, "firmware_update_info.product.product_version")
        return product_version if isinstance(product_version, str) else None

    def _get_versions(
        self, state: MutableMapping[str, Any]
    ) -> tuple[str | None, str | None, str | None]:
        """Return installed, latest, and series versions.

        Args:
            state: Current OPNsense state payload.

        Returns:
            A tuple of installed version, latest version, and series version.
        """
        product_version = dict_get(state, "firmware_update_info.product.product_version")
        product_latest = dict_get(state, "firmware_update_info.product.product_latest")
        product_series = dict_get(state, "firmware_update_info.product.product_series")
        product_version = product_version if isinstance(product_version, str) else None
        product_latest = product_latest if isinstance(product_latest, str) else None
        product_series = product_series if isinstance(product_series, str) else None
        if product_version is None or product_latest is None:
            return product_version, None, product_series

        status = dict_get(state, "firmware_update_info.status")
        if status == "update":
            packages = _list_or_empty(
                dict_get(state, "firmware_update_info.product.product_check.upgrade_packages")
            )
            package_version = _opnsense_package_version(packages)
            if package_version is not None:
                product_latest = package_version
            elif product_version == product_latest:
                product_latest = f"{product_latest}+"

        if status == "upgrade":
            upgrade_major_version = dict_get(state, "firmware_update_info.upgrade_major_version")
            if isinstance(upgrade_major_version, str) and upgrade_major_version:
                product_latest = upgrade_major_version
                product_series = (
                    ".".join(product_latest.split(".")[:2])
                    if "." in product_latest
                    else product_latest
                )
        return product_version, product_latest, product_series

    def _get_product_class(self, product_series: str | None) -> str | None:
        """Return product class.

        Args:
            product_series: Firmware product series string.

        Returns:
            The OPNsense product class, or ``None`` when the series is unknown.
        """
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
        """Return firmware release notes.

        Args:
            state: Current OPNsense state payload.
            product_latest: Latest available firmware version.
            product_version: Installed firmware version.

        Returns:
            A formatted release-notes summary, status message, or ``None``.
        """
        firmware_update_info = state.get("firmware_update_info")
        if not isinstance(firmware_update_info, Mapping):
            return None

        status = firmware_update_info.get("status")
        status_msg = firmware_update_info.get("status_msg")
        if status == "update":
            product = _mapping_or_empty(firmware_update_info.get("product"))
            product_name = product.get("product_name")
            product_nickname = product.get("product_nickname")
            needs_reboot = firmware_update_info.get("needs_reboot") == "1"

            total_package_count = _affected_package_count(firmware_update_info.get("all_packages"))
            new_package_count = len(_list_or_empty(firmware_update_info.get("new_packages")))
            reinstall_package_count = len(
                _list_or_empty(firmware_update_info.get("reinstall_packages"))
            )
            remove_package_count = len(_list_or_empty(firmware_update_info.get("remove_packages")))
            upgrade_package_count = len(
                _list_or_empty(firmware_update_info.get("upgrade_packages"))
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
            product = _mapping_or_empty(firmware_update_info.get("product"))
            product_name = product.get("product_name")
            upgrade_needs_reboot = firmware_update_info.get("upgrade_needs_reboot") == "1"

            return f"""
## {product_name} version {product_latest or product_version}

{status_msg}

- reboot needed: {upgrade_needs_reboot}
"""
        return status_msg if isinstance(status_msg, str) else None

    async def async_release_notes(self) -> str | None:
        """Return the release notes of the latest version.

        Returns:
            Cached release notes for the currently available update.
        """
        return self._release_notes

    async def async_install(
        self, version: str | None = None, backup: bool = False, **kwargs: Any
    ) -> None:
        """Install the available firmware update.

        Args:
            version: Requested firmware version, if provided by Home Assistant.
            backup: Whether Home Assistant requested a backup before install.
            **kwargs: Additional keyword arguments from Home Assistant.
        """
        state: dict[str, Any] = self.coordinator.data
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
            except (KeyError, TypeError) as e:
                exceptions += 1
                _LOGGER.warning(
                    "Error #%s while getting upgrade_status. %s: %s",
                    exceptions,
                    type(e).__name__,
                    e,
                )
                if exceptions > 3:
                    return
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
