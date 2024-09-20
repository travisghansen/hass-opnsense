from collections.abc import Mapping
import logging

from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers import (
    config_validation as cv,
    device_registry,
    entity_registry,
)
import voluptuous as vol

from .const import (
    DOMAIN,
    OPNSENSE_CLIENT,
    SERVICE_CLOSE_NOTICE,
    SERVICE_RESTART_SERVICE,
    SERVICE_SEND_WOL,
    SERVICE_START_SERVICE,
    SERVICE_STOP_SERVICE,
    SERVICE_SYSTEM_HALT,
    SERVICE_SYSTEM_REBOOT,
)

_LOGGER: logging.Logger = logging.getLogger(__name__)

_data = set()


# def async_get_entities(hass: HomeAssistant) -> dict[str, Entity]:
#     """Get entities for a domain."""
#     entities: dict[str, Entity] = {}
#     for platform in async_get_platforms(hass, DOMAIN):
#         entities.update(platform.entities)
#     return entities


async def async_setup_services(hass: HomeAssistant) -> None:

    if "loaded" in _data:
        return

    _data.add("loaded")

    async def _get_clients(
        opndevice_id: str | None = None, opnentity_id: str | None = None
    ) -> list:
        if (
            DOMAIN not in hass.data
            or not isinstance(hass.data[DOMAIN], Mapping)
            or len(hass.data[DOMAIN]) == 0
        ):
            return []
        # if len(hass.data[DOMAIN]) == 1:
        #     if OPNSENSE_CLIENT in hass.data[DOMAIN][list(hass.data[DOMAIN].keys())[0]]:
        #         _LOGGER.debug(
        #             f"[get_clients] Only 1 entry. entry_id: {list(hass.data[DOMAIN].keys())[0]}"
        #         )
        #         return [
        #             hass.data[DOMAIN][list(hass.data[DOMAIN].keys())[0]][
        #                 OPNSENSE_CLIENT
        #             ]
        #         ]
        #     else:
        #         return []
        clients: list = []
        entry_ids: list = []
        if opndevice_id:
            try:
                device_entry: device_registry.DeviceEntry = device_registry.async_get(
                    hass
                ).async_get(opndevice_id)
            except BaseException:
                pass
            else:
                _LOGGER.debug(
                    f"[get_clients] device_id: {opndevice_id}, device_entry: {device_entry}"
                )
                if device_entry.primary_config_entry not in entry_ids:
                    entry_ids.append(device_entry.primary_config_entry)
        if opnentity_id:
            try:
                entity_entry: entity_registry.RegistryEntry = entity_registry.async_get(
                    hass
                ).async_get(opnentity_id)
            except BaseException:
                pass
            else:
                _LOGGER.debug(
                    f"[get_clients] entity_id: {opnentity_id}, entity_entry: {entity_entry}"
                )
                if entity_entry.config_entry_id not in entry_ids:
                    entry_ids.append(entity_entry.config_entry_id)
        _LOGGER.debug(f"[get_clients] entry_ids: {entry_ids}")
        for entry_id, entry in hass.data[DOMAIN].items():
            _LOGGER.debug(f"[get_clients] entry_id: {entry_id}")
            if (
                len(entry_ids) == 0 or entry_id in entry_ids
            ) and OPNSENSE_CLIENT in entry:
                clients.append(entry[OPNSENSE_CLIENT])
        _LOGGER.debug(f"[get_clients] clients: {clients}")
        return clients

    async def service_close_notice(call: ServiceCall) -> None:
        clients: list = await _get_clients()
        _LOGGER.debug(f"[service_close_notice] clients: {clients}")
        for client in clients:
            _LOGGER.debug(
                f"[service_close_notice] Calling stop_service for {call.data.get('id')}"
            )
            await client.close_notice(call.data.get("id"))

    async def service_start_service(call: ServiceCall) -> None:
        clients: list = await _get_clients()
        _LOGGER.debug(f"[service_start_service] clients: {clients}")
        for client in clients:
            _LOGGER.debug(
                f"[service_start_service] Calling start_service for {call.data.get('service_name')}"
            )
            await client.start_service(call.data.get("service_name"))

    async def service_stop_service(call: ServiceCall) -> None:
        clients: list = await _get_clients()
        _LOGGER.debug(f"[service_stop_service] clients: {clients}")
        for client in clients:
            _LOGGER.debug(
                f"[service_stop_service] Calling stop_service for {call.data.get('service_name')}"
            )
            await client.stop_service(call.data.get("service_name"))

    async def service_restart_service(call: ServiceCall) -> None:
        clients: list = await _get_clients()
        _LOGGER.debug(f"[service_restart_service] clients: {clients}")
        if call.data.get("only_if_running"):
            for client in clients:
                _LOGGER.debug(
                    f"[service_restart_service] Calling restart_service_if_running for {call.data.get('service_name')}"
                )
                await client.restart_service_if_running(call.data.get("service_name"))
        else:
            for client in clients:
                _LOGGER.debug(
                    f"[service_restart_service] Calling restart_service for {call.data.get('service_name')}"
                )
                await client.restart_service(call.data.get("service_name"))

    async def service_system_halt(_: ServiceCall) -> None:
        clients: list = await _get_clients()
        _LOGGER.debug(f"[service_system_halt] clients: {clients}")
        for client in clients:
            _LOGGER.debug("[service_system_halt] Calling System Halt")
            await client.system_halt()

    async def service_system_reboot(_: ServiceCall) -> None:
        clients: list = await _get_clients()
        _LOGGER.debug(f"[service_system_reboot] clients: {clients}")
        for client in clients:
            _LOGGER.debug("[service_system_reboot] Calling System Reboot")
            await client.system_reboot()

    async def service_send_wol(call: ServiceCall) -> None:
        # _LOGGER.debug(f"[service_send_wol] call: {call}")
        clients: list = await _get_clients(
            call.data.get("device_id", []), call.data.get("entity_id", [])
        )
        _LOGGER.debug(f"[service_send_wol] clients: {clients}")
        for client in clients:
            _LOGGER.debug(
                f"[service_send_wol] Calling WOL. interface: {call.data.get('interface')}, mac: {call.data.get('mac')}"
            )
            await client.send_wol(call.data.get("interface"), call.data.get("mac"))

    hass.services.async_register(
        domain=DOMAIN,
        service=SERVICE_CLOSE_NOTICE,
        schema=vol.Schema(
            {
                vol.Optional("id", default="all"): vol.Any(cv.positive_int, cv.string),
                vol.Optional("device_id"): vol.Any(cv.string),
                vol.Optional("entity_id"): vol.Any(cv.string),
            }
        ),
        service_func=service_close_notice,
    )

    hass.services.async_register(
        domain=DOMAIN,
        service=SERVICE_START_SERVICE,
        schema=vol.Schema(
            {
                vol.Required("service_name"): vol.Any(cv.string),
                vol.Optional("device_id"): vol.Any(cv.string),
                vol.Optional("entity_id"): vol.Any(cv.string),
            }
        ),
        service_func=service_start_service,
    )

    hass.services.async_register(
        domain=DOMAIN,
        service=SERVICE_STOP_SERVICE,
        schema=vol.Schema(
            {
                vol.Required("service_name"): vol.Any(cv.string),
                vol.Optional("device_id"): vol.Any(cv.string),
                vol.Optional("entity_id"): vol.Any(cv.string),
            }
        ),
        service_func=service_stop_service,
    )

    hass.services.async_register(
        domain=DOMAIN,
        service=SERVICE_RESTART_SERVICE,
        schema=vol.Schema(
            {
                vol.Required("service_name"): vol.Any(cv.string),
                vol.Optional("only_if_running"): cv.boolean,
                vol.Optional("device_id"): vol.Any(cv.string),
                vol.Optional("entity_id"): vol.Any(cv.string),
            }
        ),
        service_func=service_restart_service,
    )

    hass.services.async_register(
        domain=DOMAIN,
        service=SERVICE_SYSTEM_HALT,
        schema=vol.Schema(
            {
                vol.Optional("device_id"): vol.Any(cv.string),
                vol.Optional("entity_id"): vol.Any(cv.string),
            }
        ),
        service_func=service_system_halt,
    )

    hass.services.async_register(
        domain=DOMAIN,
        service=SERVICE_SYSTEM_REBOOT,
        schema=vol.Schema(
            {
                vol.Optional("device_id"): vol.Any(cv.string),
                vol.Optional("entity_id"): vol.Any(cv.string),
            }
        ),
        service_func=service_system_reboot,
    )

    hass.services.async_register(
        domain=DOMAIN,
        service=SERVICE_SEND_WOL,
        schema=vol.Schema(
            {
                vol.Required("interface"): vol.Any(cv.string),
                vol.Required("mac"): vol.Any(cv.string),
                vol.Optional("device_id"): vol.Any(cv.string),
                vol.Optional("entity_id"): vol.Any(cv.string),
            }
        ),
        service_func=service_send_wol,
    )
