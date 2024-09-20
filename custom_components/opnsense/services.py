import logging

from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.entity_platform import async_get_platforms
import voluptuous as vol

from .const import (
    DOMAIN,
    SERVICE_CLOSE_NOTICE,
    SERVICE_RESTART_SERVICE,
    SERVICE_SEND_WOL,
    SERVICE_START_SERVICE,
    SERVICE_STOP_SERVICE,
    SERVICE_SYSTEM_HALT,
    SERVICE_SYSTEM_REBOOT,
)

_LOGGER = logging.getLogger(__name__)

_data = set()


def async_get_entities(hass: HomeAssistant) -> dict[str, Entity]:
    """Get entities for a domain."""
    entities: dict[str, Entity] = {}
    for platform in async_get_platforms(hass, DOMAIN):
        entities.update(platform.entities)
    return entities


class ServiceRegistrar:
    def __init__(
        self,
        hass: HomeAssistant,
    ) -> None:
        """Initialize with hass object."""
        self.hass = hass

    @callback
    def async_register(self):
        # services do not need to be reloaded for every config_entry
        if "loaded" in _data:
            return

        _data.add("loaded")

        # Setup services
        async def _async_send_service(call: ServiceCall):
            await self.hass.helpers.service.entity_service_call(
                async_get_entities(self.hass), f"service_{call.service}", call
            )

        self.hass.services.async_register(
            domain=DOMAIN,
            service=SERVICE_CLOSE_NOTICE,
            schema=cv.make_entity_service_schema(
                {
                    vol.Optional("id", default="all"): vol.Any(
                        cv.positive_int, cv.string
                    ),
                }
            ),
            service_func=_async_send_service,
        )

        self.hass.services.async_register(
            domain=DOMAIN,
            service=SERVICE_START_SERVICE,
            schema=cv.make_entity_service_schema(
                {
                    vol.Required("service_name"): vol.Any(cv.string),
                }
            ),
            service_func=_async_send_service,
        )

        self.hass.services.async_register(
            domain=DOMAIN,
            service=SERVICE_STOP_SERVICE,
            schema=cv.make_entity_service_schema(
                {
                    vol.Required("service_name"): vol.Any(cv.string),
                }
            ),
            service_func=_async_send_service,
        )

        self.hass.services.async_register(
            domain=DOMAIN,
            service=SERVICE_RESTART_SERVICE,
            schema=cv.make_entity_service_schema(
                {
                    vol.Required("service_name"): vol.Any(cv.string),
                    vol.Optional("only_if_running"): cv.boolean,
                }
            ),
            service_func=_async_send_service,
        )

        self.hass.services.async_register(
            domain=DOMAIN,
            service=SERVICE_SYSTEM_HALT,
            schema=cv.make_entity_service_schema({}),
            service_func=_async_send_service,
        )

        self.hass.services.async_register(
            domain=DOMAIN,
            service=SERVICE_SYSTEM_REBOOT,
            schema=cv.make_entity_service_schema({}),
            service_func=_async_send_service,
        )

        self.hass.services.async_register(
            domain=DOMAIN,
            service=SERVICE_SEND_WOL,
            schema=cv.make_entity_service_schema(
                {
                    vol.Required("interface"): vol.Any(cv.string),
                    vol.Required("mac"): vol.Any(cv.string),
                }
            ),
            service_func=_async_send_service,
        )
