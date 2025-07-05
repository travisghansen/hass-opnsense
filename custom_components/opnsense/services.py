"""The OPNsense HA Services/Actions."""

from collections.abc import MutableMapping
import functools
import logging
from typing import Any

import voluptuous as vol

from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import (
    config_validation as cv,
    device_registry as dr,
    entity_registry as er,
)

from .const import (
    DOMAIN,
    SERVICE_CLOSE_NOTICE,
    SERVICE_GENERATE_VOUCHERS,
    SERVICE_KILL_STATES,
    SERVICE_RELOAD_INTERFACE,
    SERVICE_RESTART_SERVICE,
    SERVICE_SEND_WOL,
    SERVICE_START_SERVICE,
    SERVICE_STOP_SERVICE,
    SERVICE_SYSTEM_HALT,
    SERVICE_SYSTEM_REBOOT,
    SERVICE_TOGGLE_ALIAS,
)
from .pyopnsense import VoucherServerError

_LOGGER: logging.Logger = logging.getLogger(__name__)


async def async_setup_services(hass: HomeAssistant) -> None:
    """Create the OPNsense HA Services/Actions."""

    hass.services.async_register(
        domain=DOMAIN,
        service=SERVICE_CLOSE_NOTICE,
        schema=vol.Schema(
            {
                vol.Required("id", default="all"): vol.Any(cv.positive_int, cv.string),
                vol.Optional("device_id"): vol.Any(cv.string),
                vol.Optional("entity_id"): vol.Any(cv.string),
            }
        ),
        service_func=functools.partial(_service_close_notice, hass),
    )

    hass.services.async_register(
        domain=DOMAIN,
        service=SERVICE_START_SERVICE,
        schema=vol.Schema(
            {
                vol.Exclusive(
                    "service_id",
                    "service_type",
                    msg="Must use service_id or service_name but not both",
                ): cv.string,
                vol.Exclusive(
                    "service_name",
                    "service_type",
                    msg="Must use service_id or service_name but not both",
                ): cv.string,
                vol.Optional("device_id"): vol.Any(cv.string),
                vol.Optional("entity_id"): vol.Any(cv.string),
            }
        ),
        service_func=functools.partial(_service_start_service, hass),
    )

    hass.services.async_register(
        domain=DOMAIN,
        service=SERVICE_STOP_SERVICE,
        schema=vol.Schema(
            {
                vol.Exclusive(
                    "service_id",
                    "service_type",
                    msg="Must use service_id or service_name but not both",
                ): cv.string,
                vol.Exclusive(
                    "service_name",
                    "service_type",
                    msg="Must use service_id or service_name but not both",
                ): cv.string,
                vol.Optional("device_id"): vol.Any(cv.string),
                vol.Optional("entity_id"): vol.Any(cv.string),
            }
        ),
        service_func=functools.partial(_service_stop_service, hass),
    )

    hass.services.async_register(
        domain=DOMAIN,
        service=SERVICE_RESTART_SERVICE,
        schema=vol.Schema(
            {
                vol.Exclusive(
                    "service_id",
                    "service_type",
                    msg="Must use service_id or service_name but not both",
                ): cv.string,
                vol.Exclusive(
                    "service_name",
                    "service_type",
                    msg="Must use service_id or service_name but not both",
                ): cv.string,
                vol.Optional("only_if_running"): cv.boolean,
                vol.Optional("device_id"): vol.Any(cv.string),
                vol.Optional("entity_id"): vol.Any(cv.string),
            }
        ),
        service_func=functools.partial(_service_restart_service, hass),
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
        service_func=functools.partial(_service_system_halt, hass),
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
        service_func=functools.partial(_service_system_reboot, hass),
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
        service_func=functools.partial(_service_send_wol, hass),
    )

    hass.services.async_register(
        domain=DOMAIN,
        service=SERVICE_RELOAD_INTERFACE,
        schema=vol.Schema(
            {
                vol.Required("interface"): vol.Any(cv.string),
                vol.Optional("device_id"): vol.Any(cv.string),
                vol.Optional("entity_id"): vol.Any(cv.string),
            }
        ),
        service_func=functools.partial(_service_reload_interface, hass),
    )

    hass.services.async_register(
        domain=DOMAIN,
        service=SERVICE_GENERATE_VOUCHERS,
        schema=vol.Schema(
            {
                vol.Required("validity"): vol.Any(cv.string),
                vol.Required("expirytime"): vol.Any(cv.string),
                vol.Required("count"): vol.Any(cv.string),
                vol.Required("vouchergroup"): vol.Any(cv.string),
                vol.Optional("voucher_server"): vol.Any(cv.string),
                vol.Optional("device_id"): vol.Any(cv.string),
                vol.Optional("entity_id"): vol.Any(cv.string),
            }
        ),
        service_func=functools.partial(_service_generate_vouchers, hass),
        supports_response=SupportsResponse.ONLY,
    )

    hass.services.async_register(
        domain=DOMAIN,
        service=SERVICE_KILL_STATES,
        schema=vol.Schema(
            {
                vol.Required("ip_addr"): vol.Any(cv.string),
                vol.Optional("device_id"): vol.Any(cv.string),
                vol.Optional("entity_id"): vol.Any(cv.string),
            }
        ),
        service_func=functools.partial(_service_kill_states, hass),
        supports_response=SupportsResponse.OPTIONAL,
    )

    hass.services.async_register(
        domain=DOMAIN,
        service=SERVICE_TOGGLE_ALIAS,
        schema=vol.Schema(
            {
                vol.Required("alias"): vol.Any(cv.string),
                vol.Required("toggle_on_off", default="toggle"): vol.In(
                    {
                        "toggle": "Toggle",
                        "on": "On",
                        "off": "Off",
                    }
                ),
                vol.Optional("device_id"): vol.Any(cv.string),
                vol.Optional("entity_id"): vol.Any(cv.string),
            }
        ),
        service_func=functools.partial(_service_toggle_alias, hass),
    )


async def _get_clients(
    hass: HomeAssistant,
    opndevice_id: str | None = None,
    opnentity_id: str | None = None,
) -> list:
    if (
        DOMAIN not in hass.data
        or not isinstance(hass.data[DOMAIN], MutableMapping)
        or len(hass.data[DOMAIN]) == 0
    ):
        return []
    first_entry_id = next(iter(hass.data[DOMAIN]))
    if len(hass.data[DOMAIN]) == 1:
        # _LOGGER.debug(f"[get_clients] Only 1 entry. entry_id: {first_entry_id}")
        return [hass.data[DOMAIN][first_entry_id]]

    entry_ids: list = []
    if opndevice_id:
        try:
            device_entry = dr.async_get(hass).async_get(opndevice_id)
        except (TypeError, AttributeError, HomeAssistantError):
            pass
        else:
            # _LOGGER.debug(f"[get_clients] device_id: {opndevice_id}, device_entry: {device_entry}")
            if device_entry and device_entry.primary_config_entry not in entry_ids:
                entry_ids.append(device_entry.primary_config_entry)
    if opnentity_id:
        try:
            entity_entry = er.async_get(hass).async_get(opnentity_id)
        except (TypeError, AttributeError, HomeAssistantError):
            pass
        else:
            # _LOGGER.debug(f"[get_clients] entity_id: {opnentity_id}, entity_entry: {entity_entry}")
            if entity_entry and entity_entry.config_entry_id not in entry_ids:
                entry_ids.append(entity_entry.config_entry_id)
    clients: list = []
    # _LOGGER.debug(f"[get_clients] entry_ids: {entry_ids}")
    for entry_id, opnsense_client in hass.data[DOMAIN].items():
        if len(entry_ids) == 0 or entry_id in entry_ids:
            clients.append(opnsense_client)
    _LOGGER.debug("[get_clients] clients: %s", clients)
    return clients


async def _service_close_notice(hass: HomeAssistant, call: ServiceCall) -> None:
    clients: list = await _get_clients(
        hass=hass,
        opndevice_id=call.data.get("device_id", []),
        opnentity_id=call.data.get("entity_id", []),
    )
    for client in clients:
        _LOGGER.debug(
            "[service_close_notice] client: %s, service: %s",
            client.name,
            call.data.get("id"),
        )
        await client.close_notice(call.data.get("id"))


async def _service_start_service(hass: HomeAssistant, call: ServiceCall) -> None:
    clients: list = await _get_clients(
        hass=hass,
        opndevice_id=call.data.get("device_id", []),
        opnentity_id=call.data.get("entity_id", []),
    )
    success: bool | None = None
    for client in clients:
        response = await client.start_service(
            call.data.get("service_id", call.data.get("service_name"))
        )
        _LOGGER.debug(
            "[service_start_service] client: %s, service: %s, response: %s",
            client.name,
            call.data.get("service_id", call.data.get("service_name")),
            response,
        )
        if success is None or success:
            success = response
    if success is None or not success:
        raise ServiceValidationError(
            f"Start Service Failed. service: {call.data.get('service_id', call.data.get('service_name'))}"
        )


async def _service_stop_service(hass: HomeAssistant, call: ServiceCall) -> None:
    clients: list = await _get_clients(
        hass=hass,
        opndevice_id=call.data.get("device_id", []),
        opnentity_id=call.data.get("entity_id", []),
    )
    success: bool | None = None
    for client in clients:
        response = await client.stop_service(
            call.data.get("service_id", call.data.get("service_name"))
        )
        _LOGGER.debug(
            "[service_stop_service] client: %s, service: %s, response: %s",
            client.name,
            call.data.get("service_id", call.data.get("service_name")),
            response,
        )
        if success is None or success:
            success = response
    if success is None or not success:
        raise ServiceValidationError(
            f"Stop Service Failed. service: {call.data.get('service_id', call.data.get('service_name'))}"
        )


async def _service_restart_service(hass: HomeAssistant, call: ServiceCall) -> None:
    clients: list = await _get_clients(
        hass=hass,
        opndevice_id=call.data.get("device_id", []),
        opnentity_id=call.data.get("entity_id", []),
    )
    success: bool | None = None
    if call.data.get("only_if_running"):
        for client in clients:
            response = await client.restart_service_if_running(
                call.data.get(
                    "service_id",
                    call.data.get("service_name"),
                )
            )
            _LOGGER.debug(
                "[service_restart_service] restart_service_if_running, client: %s, service: %s, response: %s",
                client.name,
                call.data.get("service_id", call.data.get("service_name")),
                response,
            )
            if success is None or success:
                success = response
    else:
        for client in clients:
            response = await client.restart_service(
                call.data.get(
                    "service_id",
                    call.data.get("service_name"),
                )
            )
            _LOGGER.debug(
                "[service_restart_service] restart_service, client: %s, service: %s, response: %s",
                client.name,
                call.data.get("service_id", call.data.get("service_name")),
                response,
            )
            if success is None or success:
                success = response
    if success is None or not success:
        raise ServiceValidationError(
            f"Restart Service Failed. client: {client.name}, service: {call.data.get('service_id', call.data.get('service_name'))}"
        )


async def _service_system_halt(hass: HomeAssistant, call: ServiceCall) -> None:
    clients: list = await _get_clients(
        hass=hass,
        opndevice_id=call.data.get("device_id", []),
        opnentity_id=call.data.get("entity_id", []),
    )
    for client in clients:
        _LOGGER.debug("[service_system_halt] client: {client.name}")
        await client.system_halt()


async def _service_system_reboot(hass: HomeAssistant, call: ServiceCall) -> None:
    clients: list = await _get_clients(
        hass=hass,
        opndevice_id=call.data.get("device_id", []),
        opnentity_id=call.data.get("entity_id", []),
    )
    for client in clients:
        _LOGGER.debug("[service_system_reboot] client: {client.name}")
        await client.system_reboot()


async def _service_send_wol(hass: HomeAssistant, call: ServiceCall) -> None:
    clients: list = await _get_clients(
        hass=hass,
        opndevice_id=call.data.get("device_id", []),
        opnentity_id=call.data.get("entity_id", []),
    )
    for client in clients:
        _LOGGER.debug(
            "[service_send_wol] client: %s, interface: %s, mac: %s",
            client.name,
            call.data.get("interface"),
            call.data.get("mac"),
        )
        await client.send_wol(call.data.get("interface"), call.data.get("mac"))


async def _service_reload_interface(hass: HomeAssistant, call: ServiceCall) -> None:
    clients: list = await _get_clients(
        hass=hass,
        opndevice_id=call.data.get("device_id", []),
        opnentity_id=call.data.get("entity_id", []),
    )
    success: bool | None = None
    for client in clients:
        response = await client.reload_interface(call.data.get("interface"))
        _LOGGER.debug(
            "[service_reload_interface] client: %s, interface: %s, response: %s",
            client.name,
            call.data.get("interface"),
            response,
        )
        if success is None or success:
            success = response
    if success is None or not success:
        raise ServiceValidationError(f"Reload Interface Failed: {call.data.get('interface')}")


async def _service_generate_vouchers(hass: HomeAssistant, call: ServiceCall) -> ServiceResponse:
    clients: list = await _get_clients(
        hass=hass,
        opndevice_id=call.data.get("device_id", []),
        opnentity_id=call.data.get("entity_id", []),
    )
    voucher_list: list = []
    for client in clients:
        try:
            vouchers: list = await client.generate_vouchers(call.data)
        except VoucherServerError as e:
            _LOGGER.error("Error getting vouchers from %s. %s", client.name, e)
            raise ServiceValidationError(f"Error getting vouchers from {client.name}. {e}") from e
        _LOGGER.debug(
            "[service_generate_vouchers] client: %s, data: %s, vouchers: %s",
            client.name,
            call.data,
            vouchers,
        )
        if isinstance(vouchers, list):
            for voucher in vouchers:
                if isinstance(voucher, MutableMapping):
                    new_voucher = {"client": client.name}
                    new_voucher.update(voucher)
                    voucher.clear()
                    voucher.update(new_voucher)
            voucher_list.extend(vouchers)
    final_vouchers: dict[str, Any] = {"vouchers": voucher_list}
    _LOGGER.debug("[service_generate_vouchers] vouchers: %s", final_vouchers)
    return final_vouchers


async def _service_kill_states(hass: HomeAssistant, call: ServiceCall) -> ServiceResponse:
    clients: list = await _get_clients(
        hass=hass,
        opndevice_id=call.data.get("device_id", []),
        opnentity_id=call.data.get("entity_id", []),
    )
    success: bool | None = None
    response_list: list = []
    for client in clients:
        response: MutableMapping[str, Any] = await client.kill_states(call.data.get("ip_addr"))
        _LOGGER.debug(
            "[service_kill_states] client: %s, ip_addr: %s, response: %s",
            client.name,
            call.data.get("ip_addr"),
            response,
        )
        if response.get("success", False):
            response_list.append(
                {
                    "client_name": client.name,
                    "dropped_states": response.get("dropped_states", 0),
                }
            )
        if success is None or success:
            success = response.get("success", False)
    if success is None or not success:
        raise ServiceValidationError(f"Kill States Failed: {call.data.get('ip_addr')}")
    return_response: dict[str, Any] = {"dropped_states": response_list}
    _LOGGER.debug("[service_kill_states] return_response: %s", return_response)
    if return_response:
        return return_response
    return None


async def _service_toggle_alias(hass: HomeAssistant, call: ServiceCall) -> None:
    clients: list = await _get_clients(
        hass=hass,
        opndevice_id=call.data.get("device_id", []),
        opnentity_id=call.data.get("entity_id", []),
    )
    success: bool | None = None
    for client in clients:
        response = await client.toggle_alias(call.data.get("alias"), call.data.get("toggle_on_off"))
        _LOGGER.debug(
            "[service_toggle_alias] client: %s, alias: %s, response: %s",
            client.name,
            call.data.get("alias"),
            response,
        )
        if success is None or success:
            success = response
    if success is None or not success:
        raise ServiceValidationError(
            f"Toggle Alias Failed. alias: {call.data.get('alias')}, action: {call.data.get('toggle_on_off')}"
        )
