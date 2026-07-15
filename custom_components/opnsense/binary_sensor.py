"""OPNsense integration binary sensors."""

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
from homeassistant.util import slugify

from .const import (
    CONF_SYNC_INTERFACES,
    CONF_SYNC_NOTICES,
    CONF_SYNC_SMART,
    COORDINATOR,
    DEFAULT_SYNC_OPTION_VALUE,
)
from .coordinator import OPNsenseDataUpdateCoordinator
from .entity import OPNsenseEntity
from .helpers import coerce_bool, dict_get

_LOGGER: logging.Logger = logging.getLogger(__name__)


def _smart_device_slug(device_name: str) -> str:
    """Return the entity key slug for a SMART device name.

    Args:
        device_name: SMART device name to normalize.

    Returns:
        The slugified device name, or ``unknown`` when slugification fails.
    """
    return slugify(device_name) or "unknown"


def _build_interface_enabled_binary_sensor_description(
    interface_name: str,
    interface: Mapping[str, Any],
) -> BinarySensorEntityDescription:
    """Build an interface enabled-state binary sensor description.

    Args:
        interface_name: Interface identifier from the OPNsense state.
        interface: Interface data used to derive the display name.

    Returns:
        A binary sensor description for the interface enabled state.
    """
    return BinarySensorEntityDescription(
        key=f"interface.{interface_name}.enabled",
        name=f"Interface {interface.get('name', interface_name)} Enabled",
        icon="mdi:network",
        entity_registry_enabled_default=False,
    )


def _build_smart_status_binary_sensor_description(
    device_name: str,
) -> BinarySensorEntityDescription:
    """Build a SMART status binary sensor description.

    Args:
        device_name: SMART device name used for the entity key and label.

    Returns:
        A binary sensor description for SMART health state.
    """
    return BinarySensorEntityDescription(
        key=f"smart.{_smart_device_slug(device_name)}.status",
        name=f"SMART {device_name} Status",
        icon="mdi:harddisk",
        device_class=BinarySensorDeviceClass.PROBLEM,
        entity_registry_enabled_default=False,
    )


def _build_pending_notices_present_binary_sensor_description() -> BinarySensorEntityDescription:
    """Build the pending notices presence binary sensor description.

    Returns:
        A binary sensor description for the pending notices indicator.
    """
    return BinarySensorEntityDescription(
        key="notices.pending_notices_present",
        name="Pending Notices Present",
        icon="mdi:alert",
        device_class=BinarySensorDeviceClass.PROBLEM,
        entity_registry_enabled_default=True,
    )


async def _compile_interface_enabled_binary_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
) -> list:
    """Compile per-interface enabled-state binary sensors.

    Args:
        config_entry: Config entry being set up.
        coordinator: Data update coordinator that caches OPNsense state.

    Returns:
        list: Interface enabled binary sensor entities.
    """
    state: dict[str, Any] = coordinator.data
    if not isinstance(state, MutableMapping):
        return []

    interfaces = state.get("interfaces")
    if not isinstance(interfaces, Mapping):
        return []

    entities: list = []
    for interface_name, interface in interfaces.items():
        if not isinstance(interface_name, str) or not isinstance(interface, Mapping):
            continue

        entities.append(
            OPNsenseInterfaceEnabledBinarySensor(
                config_entry=config_entry,
                coordinator=coordinator,
                entity_description=_build_interface_enabled_binary_sensor_description(
                    interface_name,
                    interface,
                ),
            )
        )
    return entities


async def _compile_smart_status_binary_sensors(
    config_entry: ConfigEntry,
    coordinator: OPNsenseDataUpdateCoordinator,
) -> list:
    """Compile SMART status binary sensors.

    Args:
        config_entry: Config entry being set up.
        coordinator: Data update coordinator that caches OPNsense state.

    Returns:
        list: SMART status binary sensor entities.
    """
    state: dict[str, Any] = coordinator.data
    if not isinstance(state, MutableMapping):
        return []

    smart_devices = state.get("smart")
    if not isinstance(smart_devices, list):
        return []

    entities: list = []
    for smart_device in smart_devices:
        if not isinstance(smart_device, Mapping):
            continue
        device_name = smart_device.get("device")
        if not isinstance(device_name, str) or not device_name.strip():
            continue
        device_name = device_name.strip()

        entities.append(
            OPNsenseSmartStatusBinarySensor(
                config_entry=config_entry,
                coordinator=coordinator,
                entity_description=_build_smart_status_binary_sensor_description(device_name),
            )
        )
    return entities


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the OPNsense binary sensors.

    Args:
        hass: Home Assistant instance.
        config_entry: Config entry being set up.
        async_add_entities: Callback used to register new entities.
    """
    coordinator: OPNsenseDataUpdateCoordinator = getattr(config_entry.runtime_data, COORDINATOR)
    config: Mapping[str, Any] = config_entry.data

    entities: list = []
    if config.get(CONF_SYNC_INTERFACES, DEFAULT_SYNC_OPTION_VALUE):
        entities.extend(await _compile_interface_enabled_binary_sensors(config_entry, coordinator))
    if config.get(CONF_SYNC_SMART, DEFAULT_SYNC_OPTION_VALUE):
        entities.extend(await _compile_smart_status_binary_sensors(config_entry, coordinator))
    if config.get(CONF_SYNC_NOTICES, DEFAULT_SYNC_OPTION_VALUE):
        entities.append(
            OPNsensePendingNoticesPresentBinarySensor(
                config_entry=config_entry,
                coordinator=coordinator,
                entity_description=_build_pending_notices_present_binary_sensor_description(),
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
        """Initialize OPNsense Binary Sensor entity.

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
            config_entry=config_entry,
            coordinator=coordinator,
            unique_id_suffix=unique_id_suffix,
            name_suffix=name_suffix,
        )
        self.entity_description: BinarySensorEntityDescription = entity_description
        self._attr_is_on: bool = False


class OPNsenseInterfaceEnabledBinarySensor(OPNsenseBinarySensor):
    """OPNsense binary sensor for interface enabled state."""

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update."""
        state: dict[str, Any] = self.coordinator.data
        if not isinstance(state, MutableMapping):
            self._mark_unavailable()
            return

        key_parts = self.entity_description.key.split(".")
        if len(key_parts) != 3 or key_parts[0] != "interface" or key_parts[2] != "enabled":
            self._mark_unavailable()
            return

        interface_name = key_parts[1]
        interface = dict_get(state, f"interfaces.{interface_name}", {})
        if not isinstance(interface, Mapping):
            self._mark_unavailable()
            return

        enabled = coerce_bool(interface.get("enabled"))
        if enabled is None:
            self._mark_unavailable()
            return

        self._available = True
        self._attr_is_on = enabled
        self._attr_extra_state_attributes = {}
        for attr in ("interface", "device", "ipv4", "ipv6", "mac"):
            if attr in interface and (interface[attr] or isinstance(interface[attr], bool)):
                self._attr_extra_state_attributes[attr] = interface[attr]
        self.async_write_ha_state()


class OPNsenseSmartStatusBinarySensor(OPNsenseBinarySensor):
    """OPNsense binary sensor for SMART device health status."""

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update."""
        state: dict[str, Any] = self.coordinator.data
        if not isinstance(state, MutableMapping):
            self._mark_unavailable()
            return

        key_parts = self.entity_description.key.split(".")
        if len(key_parts) != 3 or key_parts[0] != "smart" or key_parts[2] != "status":
            self._mark_unavailable()
            return
        expected_device_slug = key_parts[1]

        smart_devices = state.get("smart")
        if not isinstance(smart_devices, list):
            self._mark_unavailable()
            return

        smart_device: Mapping[str, Any] | None = None
        for candidate in smart_devices:
            if not isinstance(candidate, Mapping):
                continue
            device_name = candidate.get("device")
            if not isinstance(device_name, str) or not device_name.strip():
                continue
            if _smart_device_slug(device_name.strip()) == expected_device_slug:
                smart_device = candidate
                break

        if smart_device is None:
            self._mark_unavailable()
            return

        device_name = smart_device.get("device")
        smart_info = state.get("smart_info")
        normalized_device_name = device_name.strip() if isinstance(device_name, str) else ""
        device_info = (
            smart_info.get(normalized_device_name) if isinstance(smart_info, Mapping) else None
        )
        if not isinstance(device_info, Mapping):
            device_info = {}

        smart_status = None
        smart_state = smart_device.get("state")
        if isinstance(smart_state, Mapping):
            smart_status = smart_state.get("smart_status")
        if smart_status is None:
            smart_status = device_info.get("smart_status")

        status_passed: bool | None = None
        if isinstance(smart_status, Mapping):
            passed = smart_status.get("passed")
            if isinstance(passed, bool):
                status_passed = passed
            else:
                status = smart_status.get("status")
                if isinstance(status, str) and status.strip():
                    status_passed = status.strip().upper() == "PASSED"
        elif isinstance(smart_status, bool):
            status_passed = smart_status
        elif isinstance(smart_status, str) and smart_status.strip():
            status_passed = smart_status.strip().upper() == "PASSED"

        if status_passed is None:
            self._mark_unavailable()
            return

        self._available = True
        self._attr_is_on = not status_passed
        self._attr_extra_state_attributes = {}
        for attr in ("device", "ident", "model", "serial_number", "serial", "type"):
            attr_value = smart_device.get(attr)
            if attr_value is not None and attr_value != "":
                self._attr_extra_state_attributes[attr] = attr_value

        health_log = device_info.get("nvme_smart_health_information_log")
        if isinstance(health_log, Mapping):
            normalized_health_log = {
                "temperature_celsius" if key == "temperature" else key: value
                for key, value in health_log.items()
            }
            self._attr_extra_state_attributes.update(normalized_health_log)
        self.async_write_ha_state()


class OPNsensePendingNoticesPresentBinarySensor(OPNsenseBinarySensor):
    """OPNsense Binary Sensor Pending Notices Class."""

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update."""
        state: dict[str, Any] = self.coordinator.data
        if not isinstance(state, MutableMapping):
            self._mark_unavailable()
            return
        try:
            self._attr_is_on = state["notices"]["pending_notices_present"]
        except TypeError, KeyError:
            self._mark_unavailable()
            return

        self._available = True
        self._attr_extra_state_attributes["pending_notices"] = dict_get(
            state, "notices.pending_notices", []
        )
        self.async_write_ha_state()
