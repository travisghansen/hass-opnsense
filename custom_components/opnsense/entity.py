"""Define the base entities for OPNsense."""

from collections.abc import MutableMapping
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import slugify

from .const import CONF_DEVICE_UNIQUE_ID, DOMAIN, OPNSENSE_CLIENT
from .coordinator import OPNsenseDataUpdateCoordinator
from .helpers import dict_get
from .pyopnsense import OPNsenseClient

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
        """Initialize OPNsense Entity."""
        self.config_entry: ConfigEntry = config_entry
        self.coordinator: OPNsenseDataUpdateCoordinator = coordinator
        self._device_unique_id: str = config_entry.data[CONF_DEVICE_UNIQUE_ID]
        if unique_id_suffix:
            self._attr_unique_id: str = slugify(f"{self._device_unique_id}_{unique_id_suffix}")
        if name_suffix:
            self._attr_name: str | None = f"{self.opnsense_device_name or 'OPNsense'} {name_suffix}"
        self._client: OPNsenseClient | None = None
        self._attr_extra_state_attributes: dict[str, Any] = {}
        self._available: bool = False
        super().__init__(self.coordinator, self._attr_unique_id)

    @property
    def available(self) -> bool:
        """Return whether entity is available."""
        return self._available

    @property
    def opnsense_device_name(self) -> str | None:
        """Return the OPNsense device name."""
        if self.config_entry.title and len(self.config_entry.title) > 0:
            return self.config_entry.title
        return self._get_opnsense_state_value("system_info.name")

    def _get_opnsense_state_value(self, path: str) -> Any | None:
        state = self.coordinator.data
        return dict_get(state, path)

    def _get_opnsense_client(self) -> OPNsenseClient | None:
        if self.hass is None:
            return None
        return self.hass.data[DOMAIN][self.config_entry.entry_id][OPNSENSE_CLIENT]

    async def async_added_to_hass(self) -> None:
        """Run once integration has been added to HA."""
        await super().async_added_to_hass()
        if self._client is None:
            self._client = self._get_opnsense_client()
        if self._client is None:
            _LOGGER.error("Unable to get client in async_added_to_hass.")
        assert self._client is not None
        self._handle_coordinator_update()


class OPNsenseEntity(OPNsenseBaseEntity):
    """Primary OPNsense Entity including device info."""

    @property
    def device_info(self) -> DeviceInfo | None:
        """Device info for the firewall."""
        state: MutableMapping[str, Any] = self.coordinator.data
        model: str = "OPNsense"
        manufacturer: str = "Deciso B.V."
        if state is None:
            firmware: str | None = None
        else:
            firmware = state.get("host_firmware_version", None)

        device_info: DeviceInfo = {
            "identifiers": {(DOMAIN, self._device_unique_id)},
            "name": self.opnsense_device_name,
            "configuration_url": self.config_entry.data.get("url", None),
        }

        device_info["model"] = model
        device_info["manufacturer"] = manufacturer
        device_info["sw_version"] = firmware

        return device_info
