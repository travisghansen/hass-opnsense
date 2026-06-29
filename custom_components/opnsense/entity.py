"""Define the base entities for OPNsense."""

from collections.abc import Mapping, MutableMapping
import logging
from typing import TYPE_CHECKING, Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import slugify

from .const import CONF_DEVICE_UNIQUE_ID, DOMAIN, OPNSENSE_CLIENT
from .coordinator import OPNsenseDataUpdateCoordinator
from .helpers import dict_get

if TYPE_CHECKING:
    from aiopnsense import OPNsenseClient

_LOGGER: logging.Logger = logging.getLogger(__name__)


class OPNsenseBaseEntity(CoordinatorEntity[OPNsenseDataUpdateCoordinator]):
    """Base entity for OPNsense."""

    _attr_has_entity_name = True

    @staticmethod
    def payload_display_name(
        payload: Mapping[str, Any],
        fallback: str,
        *fields: str,
        allow_scalar: bool = True,
    ) -> str:
        """Return a stable display label from a dynamic state payload.

        Args:
            payload: Mapping payload that may contain one of the display fields.
            fallback: Value to use when none of the fields contain a displayable value.
            *fields: Ordered field names to prefer for the display label.
            allow_scalar: Whether non-container scalar values should be stringified.

        Returns:
            String display label from the first usable field, otherwise the fallback.
        """
        for field in fields:
            value: Any | None
            try:
                value = payload.get(field)
            except AttributeError, KeyError, RuntimeError, TypeError, ValueError:
                value = None

            if isinstance(value, str):
                try:
                    stripped_value = value.strip()
                except AttributeError, RuntimeError, TypeError, ValueError:
                    stripped_value = ""
                if stripped_value:
                    return stripped_value

            if (
                allow_scalar
                and value is not None
                and not isinstance(value, str | Mapping | list | tuple | set)
            ):
                try:
                    return str(value)
                except AttributeError, RuntimeError, TypeError, ValueError:
                    pass
        return fallback

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
            self._attr_name: str | None = name_suffix
        self._client: OPNsenseClient | None = None
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

    def _get_opnsense_state_value(self, path: str) -> Any | None:
        """Read a nested value from coordinator state data.

        Args:
            path: Dot-delimited key path inside the coordinator state payload.

        Returns:
            Any | None: Value at the requested path, or `None` when missing.
        """
        state = self.coordinator.data
        return dict_get(state, path)

    def _coordinator_mapping(self) -> MutableMapping[str, Any] | None:
        """Return coordinator data when it is a mapping.

        Returns:
            MutableMapping[str, Any] | None: Current coordinator payload, or ``None``
                when the payload shape is not usable for entity updates.
        """
        state = self.coordinator.data
        return state if isinstance(state, MutableMapping) else None

    def _mapping_at(self, path: str) -> MutableMapping[str, Any] | None:
        """Return a nested mapping from coordinator data.

        Args:
            path: Dot-delimited key path inside the coordinator state payload.

        Returns:
            MutableMapping[str, Any] | None: Nested mapping at ``path``, or ``None``
                when the value is missing or malformed.
        """
        state = self._coordinator_mapping()
        if state is None:
            return None
        value = dict_get(state, path)
        return value if isinstance(value, MutableMapping) else None

    def _list_at(self, path: str) -> list[Any] | None:
        """Return a nested list from coordinator data.

        Args:
            path: Dot-delimited key path inside the coordinator state payload.

        Returns:
            list[Any] | None: Nested list at ``path``, or ``None`` when missing or malformed.
        """
        state = self._coordinator_mapping()
        if state is None:
            return None
        value = dict_get(state, path)
        return value if isinstance(value, list) else None

    def _mark_unavailable(self, *, clear_attributes: bool = False) -> None:
        """Mark the entity unavailable and publish the state.

        Args:
            clear_attributes: Whether to clear extra state attributes while marking
                the entity unavailable.
        """
        self._available = False
        if clear_attributes:
            self._attr_extra_state_attributes = {}
        self.async_write_ha_state()

    async def async_added_to_hass(self) -> None:
        """Attach runtime client and trigger an immediate coordinator update callback."""
        await super().async_added_to_hass()
        if self._client is None:
            self._client = getattr(self.config_entry.runtime_data, OPNSENSE_CLIENT)
        if self._client is None:
            _LOGGER.error("Unable to get client in async_added_to_hass.")
            return
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
            "name": self.config_entry.title or self._get_opnsense_state_value("system_info.name"),
            "configuration_url": self.config_entry.data.get("url", None),
        }

        device_info["model"] = model
        device_info["manufacturer"] = manufacturer
        device_info["sw_version"] = firmware

        return device_info
