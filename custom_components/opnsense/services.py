import logging
from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import device_registry, entity_registry

from .const import (
    DOMAIN,
    OPNSENSE_CLIENT,
    SERVICE_CLOSE_NOTICE,
    SERVICE_GENERATE_VOUCHERS,
    SERVICE_RELOAD_INTERFACE,
    SERVICE_RESTART_SERVICE,
    SERVICE_SEND_WOL,
    SERVICE_START_SERVICE,
    SERVICE_STOP_SERVICE,
    SERVICE_SYSTEM_HALT,
    SERVICE_SYSTEM_REBOOT,
)
from .pyopnsense import VoucherServerError

_LOGGER: logging.Logger = logging.getLogger(__name__)


async def async_setup_services(hass: HomeAssistant) -> None:
    async def _get_clients(
        opndevice_id: str | None = None, opnentity_id: str | None = None
    ) -> list:
        if (
            DOMAIN not in hass.data
            or not isinstance(hass.data[DOMAIN], Mapping)
            or len(hass.data[DOMAIN]) == 0
        ):
            return []
        first_entry_id = next(iter(hass.data[DOMAIN]))
        if len(hass.data[DOMAIN]) == 1:
            if OPNSENSE_CLIENT in hass.data[DOMAIN][first_entry_id]:
                # _LOGGER.debug(f"[get_clients] Only 1 entry. entry_id: {first_entry_id}")
                return [hass.data[DOMAIN][first_entry_id][OPNSENSE_CLIENT]]
            return []

        entry_ids: list = []
        if opndevice_id:
            try:
                device_entry: device_registry.DeviceEntry = device_registry.async_get(
                    hass
                ).async_get(opndevice_id)
            except Exception:
                pass
            else:
                # _LOGGER.debug(f"[get_clients] device_id: {opndevice_id}, device_entry: {device_entry}")
                if device_entry.primary_config_entry not in entry_ids:
                    entry_ids.append(device_entry.primary_config_entry)
        if opnentity_id:
            try:
                entity_entry: entity_registry.RegistryEntry = entity_registry.async_get(
                    hass
                ).async_get(opnentity_id)
            except Exception:
                pass
            else:
                # _LOGGER.debug(f"[get_clients] entity_id: {opnentity_id}, entity_entry: {entity_entry}")
                if entity_entry.config_entry_id not in entry_ids:
                    entry_ids.append(entity_entry.config_entry_id)
        clients: list = []
        # _LOGGER.debug(f"[get_clients] entry_ids: {entry_ids}")
        for entry_id, entry in hass.data[DOMAIN].items():
            if (
                len(entry_ids) == 0 or entry_id in entry_ids
            ) and OPNSENSE_CLIENT in entry:
                clients.append(entry[OPNSENSE_CLIENT])
        _LOGGER.debug(f"[get_clients] clients: {clients}")
        return clients

    async def service_close_notice(call: ServiceCall) -> None:
        clients: list = await _get_clients(
            call.data.get("device_id", []), call.data.get("entity_id", [])
        )
        for client in clients:
            _LOGGER.debug(
                f"[service_close_notice] client: {client.name}, service: {call.data.get('id')}"
            )
            await client.close_notice(call.data.get("id"))

    async def service_start_service(call: ServiceCall) -> None:
        clients: list = await _get_clients(
            call.data.get("device_id", []), call.data.get("entity_id", [])
        )
        success = None
        for client in clients:
            response = await client.start_service(
                call.data.get("service_id", call.data.get("service_name"))
            )
            _LOGGER.debug(
                f"[service_start_service] client: {client.name}, service: {call.data.get('service_id', call.data.get('service_name'))}, response: {response}"
            )
            if success is None or success:
                success = response
        if success is None or not success:
            raise ServiceValidationError(
                f"Start Service Failed. client: {client.name}, service: {call.data.get('service_id', call.data.get('service_name'))}"
            )

    async def service_stop_service(call: ServiceCall) -> None:
        clients: list = await _get_clients(
            call.data.get("device_id", []), call.data.get("entity_id", [])
        )
        success = None
        for client in clients:
            response = await client.stop_service(
                call.data.get("service_id", call.data.get("service_name"))
            )
            _LOGGER.debug(
                f"[service_stop_service] client: {client.name}, service: {call.data.get('service_id', call.data.get('service_name'))}, response: {response}"
            )
            if success is None or success:
                success = response
        if success is None or not success:
            raise ServiceValidationError(
                f"Stop Service Failed. client: {client.name}, service: {call.data.get('service_id', call.data.get('service_name'))}"
            )

    async def service_restart_service(call: ServiceCall) -> None:
        clients: list = await _get_clients(
            call.data.get("device_id", []), call.data.get("entity_id", [])
        )
        success = None
        if call.data.get("only_if_running"):
            for client in clients:
                response = await client.restart_service_if_running(
                    call.data.get(
                        "service_id",
                        call.data.get("service_name"),
                    )
                )
                _LOGGER.debug(
                    f"[service_restart_service] restart_service_if_running, client: {client.name}, service: {call.data.get('service_id', call.data.get('service_name'))}, response: {response}"
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
                    f"[service_restart_service] restart_service, client: {client.name}, service: {call.data.get('service_id', call.data.get('service_name'))}, response: {response}"
                )
                if success is None or success:
                    success = response
        if success is None or not success:
            raise ServiceValidationError(
                f"Restart Service Failed. client: {client.name}, service: {call.data.get('service_id', call.data.get('service_name'))}"
            )

    async def service_system_halt(call: ServiceCall) -> None:
        clients: list = await _get_clients(
            call.data.get("device_id", []), call.data.get("entity_id", [])
        )
        for client in clients:
            _LOGGER.debug("[service_system_halt] client: {client.name}")
            await client.system_halt()

    async def service_system_reboot(call: ServiceCall) -> None:
        clients: list = await _get_clients(
            call.data.get("device_id", []), call.data.get("entity_id", [])
        )
        for client in clients:
            _LOGGER.debug("[service_system_reboot] client: {client.name}")
            await client.system_reboot()

    async def service_send_wol(call: ServiceCall) -> None:
        clients: list = await _get_clients(
            call.data.get("device_id", []), call.data.get("entity_id", [])
        )
        for client in clients:
            _LOGGER.debug(
                f"[service_send_wol] client: {client.name}, interface: {call.data.get('interface')}, mac: {call.data.get('mac')}"
            )
            await client.send_wol(call.data.get("interface"), call.data.get("mac"))

    async def service_reload_interface(call: ServiceCall) -> None:
        clients: list = await _get_clients(
            call.data.get("device_id", []), call.data.get("entity_id", [])
        )
        success = None
        for client in clients:
            response = await client.reload_interface(call.data.get("interface"))
            _LOGGER.debug(
                f"[service_reload_interface] client: {client.name}, interface: {call.data.get('interface')}, response: {response}"
            )
            if success is None or success:
                success = response
        if success is None or not success:
            raise ServiceValidationError(
                f"Reload Interface Failed: {call.data.get('interface')}"
            )

    async def service_generate_vouchers(call: ServiceCall) -> Mapping[str, Any]:
        clients: list = await _get_clients(
            call.data.get("device_id", []), call.data.get("entity_id", [])
        )
        voucher_list: list = []
        for client in clients:
            try:
                vouchers: list = await client.generate_vouchers(call.data)
            except VoucherServerError as e:
                _LOGGER.error(f"Error getting vouchers from {client.name}. {e}")
                raise ServiceValidationError(
                    f"Error getting vouchers from {client.name}. {e}"
                ) from e
            _LOGGER.debug(
                f"[service_generate_vouchers] client: {client.name}, data: {call.data}, vouchers: {vouchers}"
            )
            if isinstance(vouchers, list):
                for voucher in vouchers:
                    if isinstance(voucher, Mapping):
                        new_voucher: Mapping[str, Any] = {"client": client.name}
                        new_voucher.update(voucher)
                        voucher.clear()
                        voucher.update(new_voucher)
                voucher_list = voucher_list + vouchers
        final_vouchers: Mapping[str, Any] = {"vouchers": voucher_list}
        _LOGGER.debug(f"[service_generate_vouchers] vouchers: {final_vouchers}")
        return final_vouchers

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
        service_func=service_close_notice,
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
        service_func=service_start_service,
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
        service_func=service_stop_service,
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
        service_func=service_reload_interface,
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
        service_func=service_generate_vouchers,
        supports_response=SupportsResponse.ONLY,
    )
