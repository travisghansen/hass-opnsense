from homeassistant.helpers import config_validation as cv
import voluptuous as vol

from .const import (
    SERVICE_CLOSE_NOTICE,
    SERVICE_RESTART_SERVICE,
    SERVICE_SEND_WOL,
    SERVICE_START_SERVICE,
    SERVICE_STOP_SERVICE,
    SERVICE_SYSTEM_HALT,
    SERVICE_SYSTEM_REBOOT,
)


def register_services(platform):
    platform.async_register_entity_service(
        SERVICE_CLOSE_NOTICE,
        {
            vol.Optional("id", default="all"): vol.Any(cv.positive_int, cv.string),
        },
        "service_close_notice",
    )

    platform.async_register_entity_service(
        SERVICE_START_SERVICE,
        {
            vol.Required("service_name"): vol.Any(cv.string),
        },
        "service_start_service",
    )

    platform.async_register_entity_service(
        SERVICE_STOP_SERVICE,
        {
            vol.Required("service_name"): vol.Any(cv.string),
        },
        "service_stop_service",
    )

    platform.async_register_entity_service(
        SERVICE_RESTART_SERVICE,
        {
            vol.Required("service_name"): vol.Any(cv.string),
            vol.Optional("only_if_running"): cv.boolean,
        },
        "service_restart_service",
    )

    platform.async_register_entity_service(
        SERVICE_SYSTEM_HALT,
        {},
        "service_system_halt",
    )

    platform.async_register_entity_service(
        SERVICE_SYSTEM_REBOOT,
        {},
        "service_system_reboot",
    )

    platform.async_register_entity_service(
        SERVICE_SEND_WOL,
        {
            vol.Required("interface"): vol.Any(cv.string),
            vol.Required("mac"): vol.Any(cv.string),
        },
        "service_send_wol",
    )
