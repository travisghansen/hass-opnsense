"""Define the base entities for OPNsense."""

import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import slugify

from .client_protocol import OPNsenseClientProtocol
from .const import CONF_DEVICE_UNIQUE_ID, DOMAIN, OPNSENSE_CLIENT
from .coordinator import OPNsenseDataUpdateCoordinator
from .helpers import dict_get

_LOGGER: logging.Logger = logging.getLogger(__name__)


class OPNsenseBaseEntity(CoordinatorEntity[OPNsenseDataUpdateCoordinator]):
    """Base entity for OPNsense."""

    def __init__(
        self,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        unique_id_suffix: str | None = None,
        name_suffix: str | None = None,
    ) -> None:
        """Initialize a base OPNsense entity bound to a coordinator.

        Args:
            config_entry: Config entry that owns this entity and contains device metadata.
            coordinator: Coordinator providing state data and refresh updates.
            unique_id_suffix: Optional suffix appended to the router unique ID for this entity.
            name_suffix: Optional display-name suffix shown in Home Assistant.
        """
        self.config_entry: ConfigEntry = config_entry
        self.coordinator: OPNsenseDataUpdateCoordinator = coordinator
        self._device_unique_id: str = config_entry.data[CONF_DEVICE_UNIQUE_ID]
        if unique_id_suffix:
            self._attr_unique_id: str = slugify(f"{self._device_unique_id}_{unique_id_suffix}")
        if name_suffix:
            self._attr_name: str | None = f"{self.opnsense_device_name or 'OPNsense'} {name_suffix}"
        self._client: OPNsenseClientProtocol | None = None
        self._attr_extra_state_attributes: dict[str, Any] = {}
        self._available: bool = False
        super().__init__(self.coordinator, self._attr_unique_id)

    @property
    def available(self) -> bool:
        """Return whether the entity currently reports as available.

        Returns:
            bool: `True` when the entity is available for state updates.
        """
        return self._available

    @property
    def opnsense_device_name(self) -> str | None:
        """Return the display name for the parent OPNsense device.

        Returns:
            str | None: Config entry title when present, otherwise the runtime device name.
        """
        if self.config_entry.title and len(self.config_entry.title) > 0:
            return self.config_entry.title
        return self._get_opnsense_state_value("system_info.name")

    def _get_opnsense_state_value(self, path: str) -> Any | None:
        """Read a nested value from coordinator state data.

        Args:
            path: Dot-delimited key path inside the coordinator state payload.

        Returns:
            Any | None: Value at the requested path, or `None` when missing.
        """
        state = self.coordinator.data
        return dict_get(state, path)

    async def async_added_to_hass(self) -> None:
        """Attach runtime client and trigger an immediate coordinator update callback."""
        await super().async_added_to_hass()
        if self._client is None:
            self._client = getattr(self.config_entry.runtime_data, OPNSENSE_CLIENT)
        if self._client is None:
            _LOGGER.error("Unable to get client in async_added_to_hass.")
        assert self._client is not None
        self._handle_coordinator_update()


class OPNsenseEntity(OPNsenseBaseEntity):
    """Primary OPNsense Entity including device info."""

    @property
    def device_info(self) -> DeviceInfo | None:
        """Build Home Assistant device metadata for the firewall.

        Returns:
            DeviceInfo | None: Device metadata containing identifiers, display name, and firmware.
        """
        state: dict[str, Any] = self.coordinator.data
        model: str = "OPNsense"
        manufacturer: str = "Deciso B.V."
        if state is None:
            firmware: str | None = None
        else:
            firmware = state.get("host_firmware_version")

        device_info: DeviceInfo = {
            "identifiers": {(DOMAIN, self._device_unique_id)},
            "name": self.opnsense_device_name,
            "configuration_url": self.config_entry.data.get("url", None),
        }

        device_info["model"] = model
        device_info["manufacturer"] = manufacturer
        device_info["sw_version"] = firmware

        return device_info
