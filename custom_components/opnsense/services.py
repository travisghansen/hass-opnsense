"""The OPNsense HA Services/Actions."""

from collections.abc import Awaitable, Callable, MutableMapping
import functools
import logging
from typing import Any

from aiopnsense.exceptions import OPNsenseVoucherServerError
from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import (
    config_validation as cv,
    device_registry as dr,
    entity_registry as er,
)
import voluptuous as vol

from .const import (
    DOMAIN,
    SERVICE_CLOSE_NOTICE,
    SERVICE_GENERATE_VOUCHERS,
    SERVICE_GET_VNSTAT_METRICS,
    SERVICE_KILL_STATES,
    SERVICE_RELOAD_INTERFACE,
    SERVICE_RESTART_SERVICE,
    SERVICE_RUN_SPEEDTEST,
    SERVICE_SEND_WOL,
    SERVICE_START_SERVICE,
    SERVICE_STOP_SERVICE,
    SERVICE_SYSTEM_HALT,
    SERVICE_SYSTEM_REBOOT,
    SERVICE_TOGGLE_ALIAS,
)

_LOGGER: logging.Logger = logging.getLogger(__name__)
_VNSTAT_PERIODS: tuple[str, ...] = ("hourly", "daily", "monthly", "yearly")
_SERVICE_IDENTIFIER_ERROR = "Must use service_id or service_name"
_SERVICE_IDENTIFIER_CONFLICT_ERROR = "Must use service_id or service_name but not both"
type OPNsenseServiceClient = Any
type ServiceHandler = Callable[[HomeAssistant, ServiceCall], Awaitable[Any]]
type BooleanClientAction = Callable[[OPNsenseServiceClient], Awaitable[bool]]


def _validate_service_identifier(data: dict[str, Any]) -> dict[str, Any]:
    """Validate that a service control call includes a service identifier.

    Args:
        data: Validated service call payload.

    Returns:
        dict[str, Any]: Original service call payload.

    Raises:
        vol.Invalid: If neither ``service_id`` nor ``service_name`` was supplied.
    """
    if data.get("service_id") or data.get("service_name"):
        return data
    raise vol.Invalid(_SERVICE_IDENTIFIER_ERROR)


def _target_fields() -> dict[Any, Any]:
    """Return the common optional OPNsense target selector fields.

    Returns:
        dict[Any, Any]: Voluptuous field definitions for OPNsense device/entity selectors.
    """
    return {
        vol.Optional("device_id"): vol.Any(cv.string),
        vol.Optional("entity_id"): vol.Any(cv.string),
    }


def _service_identifier_fields() -> dict[Any, Any]:
    """Return fields that identify an OPNsense service.

    Returns:
        dict[Any, Any]: Voluptuous field definitions for service identifiers.
    """
    return {
        vol.Exclusive(
            "service_id",
            "service_type",
            msg=_SERVICE_IDENTIFIER_CONFLICT_ERROR,
        ): cv.string,
        vol.Exclusive(
            "service_name",
            "service_type",
            msg=_SERVICE_IDENTIFIER_CONFLICT_ERROR,
        ): cv.string,
    }


def _service_control_schema(extra_fields: dict[Any, Any] | None = None) -> vol.Schema:
    """Build a schema for service start, stop, and restart actions.

    Args:
        extra_fields: Additional fields to include in the schema.

    Returns:
        vol.Schema: Service control schema with identifier validation.
    """
    fields = _service_identifier_fields() | (extra_fields or {}) | _target_fields()
    return vol.Schema(vol.All(fields, _validate_service_identifier))


def _targeted_schema(fields: dict[Any, Any] | None = None) -> vol.Schema:
    """Build a schema that includes optional OPNsense target selectors.

    Args:
        fields: Service-specific fields to include before target selectors.

    Returns:
        vol.Schema: Service schema with common target selector fields.
    """
    return vol.Schema((fields or {}) | _target_fields())


def _register_service(
    hass: HomeAssistant,
    service: str,
    service_func: ServiceHandler,
    schema: vol.Schema,
    supports_response: SupportsResponse | None = None,
) -> None:
    """Register an OPNsense service with Home Assistant.

    Args:
        hass: Home Assistant instance.
        service: OPNsense service/action name.
        service_func: Handler for the service call.
        schema: Voluptuous schema for validating service data.
        supports_response: Response support declaration for action response data.
    """
    kwargs: dict[str, Any] = {
        "domain": DOMAIN,
        "service": service,
        "schema": schema,
        "service_func": functools.partial(service_func, hass),
    }
    if supports_response is not None:
        kwargs["supports_response"] = supports_response
    hass.services.async_register(**kwargs)


async def async_setup_services(hass: HomeAssistant) -> None:
    """Create the OPNsense HA Services/Actions."""
    _register_service(
        hass,
        SERVICE_CLOSE_NOTICE,
        _service_close_notice,
        _targeted_schema({vol.Required("id", default="all"): vol.Any(cv.positive_int, cv.string)}),
    )

    _register_service(
        hass,
        SERVICE_START_SERVICE,
        _service_start_service,
        _service_control_schema(),
    )

    _register_service(
        hass,
        SERVICE_STOP_SERVICE,
        _service_stop_service,
        _service_control_schema(),
    )

    _register_service(
        hass,
        SERVICE_RESTART_SERVICE,
        _service_restart_service,
        _service_control_schema({vol.Optional("only_if_running"): cv.boolean}),
    )

    _register_service(
        hass,
        SERVICE_SYSTEM_HALT,
        _service_system_halt,
        _targeted_schema(),
    )

    _register_service(
        hass,
        SERVICE_SYSTEM_REBOOT,
        _service_system_reboot,
        _targeted_schema(),
    )

    _register_service(
        hass,
        SERVICE_SEND_WOL,
        _service_send_wol,
        _targeted_schema(
            {
                vol.Required("interface"): vol.Any(cv.string),
                vol.Required("mac"): vol.Any(cv.string),
            }
        ),
    )

    _register_service(
        hass,
        SERVICE_RELOAD_INTERFACE,
        _service_reload_interface,
        _targeted_schema({vol.Required("interface"): vol.Any(cv.string)}),
    )

    _register_service(
        hass,
        SERVICE_GENERATE_VOUCHERS,
        _service_generate_vouchers,
        _targeted_schema(
            {
                vol.Required("validity"): vol.Any(cv.string),
                vol.Required("expirytime"): vol.Any(cv.string),
                vol.Required("count"): vol.Any(cv.string),
                vol.Required("vouchergroup"): vol.Any(cv.string),
                vol.Optional("voucher_server"): vol.Any(cv.string),
            }
        ),
        SupportsResponse.ONLY,
    )

    _register_service(
        hass,
        SERVICE_KILL_STATES,
        _service_kill_states,
        _targeted_schema({vol.Required("ip_addr"): vol.Any(cv.string)}),
        SupportsResponse.OPTIONAL,
    )

    _register_service(
        hass,
        SERVICE_RUN_SPEEDTEST,
        _service_run_speedtest,
        _targeted_schema(),
        SupportsResponse.ONLY,
    )

    _register_service(
        hass,
        SERVICE_GET_VNSTAT_METRICS,
        _service_get_vnstat_metrics,
        _targeted_schema(
            {
                vol.Required("period"): vol.All(cv.string, vol.Lower, vol.In(_VNSTAT_PERIODS)),
            }
        ),
        SupportsResponse.ONLY,
    )

    _register_service(
        hass,
        SERVICE_TOGGLE_ALIAS,
        _service_toggle_alias,
        _targeted_schema(
            {
                vol.Required("alias"): vol.Any(cv.string),
                vol.Required("toggle_on_off", default="toggle"): vol.In(
                    {
                        "toggle": "Toggle",
                        "on": "On",
                        "off": "Off",
                    }
                ),
            }
        ),
    )


async def _get_clients(
    hass: HomeAssistant,
    opndevice_id: str | None = None,
    opnentity_id: str | None = None,
) -> list:
    """Resolve the OPNsense clients targeted by the current request.

    Args:
        hass: Home Assistant instance that owns the integration state, entity registry, and
        services.
        opndevice_id: Device identifier used to target the correct OPNsense device or config entry.
        opnentity_id: Entity identifier used to resolve the matching OPNsense entity.

    Raises:
        ServiceValidationError: If explicit target selectors do not resolve to configured clients.
    """
    if (
        DOMAIN not in hass.data
        or not isinstance(hass.data[DOMAIN], MutableMapping)
        or len(hass.data[DOMAIN]) == 0
    ):
        return []
    first_entry_id = next(iter(hass.data[DOMAIN]))
    if len(hass.data[DOMAIN]) == 1 and not opndevice_id and not opnentity_id:
        # _LOGGER.debug(f"[get_clients] Only 1 entry. entry_id: {first_entry_id}")
        return [hass.data[DOMAIN][first_entry_id]]

    entry_ids: list = []
    if opndevice_id:
        try:
            device_entry = dr.async_get(hass).async_get(opndevice_id)
        except TypeError, AttributeError, HomeAssistantError:
            pass
        else:
            # _LOGGER.debug(f"[get_clients] device_id: {opndevice_id}, device_entry:
            # {device_entry}")
            if device_entry and device_entry.primary_config_entry not in entry_ids:
                entry_ids.append(device_entry.primary_config_entry)
    if opnentity_id:
        try:
            entity_entry = er.async_get(hass).async_get(opnentity_id)
        except TypeError, AttributeError, HomeAssistantError:
            pass
        else:
            # _LOGGER.debug(f"[get_clients] entity_id: {opnentity_id}, entity_entry:
            # {entity_entry}")
            if entity_entry and entity_entry.config_entry_id not in entry_ids:
                entry_ids.append(entity_entry.config_entry_id)

    if (opndevice_id or opnentity_id) and not entry_ids:
        raise ServiceValidationError("No OPNsense clients match the selected target")

    clients: list = []
    # _LOGGER.debug(f"[get_clients] entry_ids: {entry_ids}")
    for entry_id, opnsense_client in hass.data[DOMAIN].items():
        if len(entry_ids) == 0 or entry_id in entry_ids:
            clients.append(opnsense_client)
    if (opndevice_id or opnentity_id) and not clients:
        raise ServiceValidationError("No OPNsense clients match the selected target")
    _LOGGER.debug("[get_clients] clients: %s", clients)
    return clients


async def _get_target_clients(
    hass: HomeAssistant,
    call: ServiceCall,
) -> list[OPNsenseServiceClient]:
    """Return OPNsense clients targeted by a Home Assistant service call.

    Args:
        hass: Home Assistant instance.
        call: Service call payload received from Home Assistant.

    Returns:
        list[OPNsenseServiceClient]: Selected OPNsense clients.
    """
    return await _get_clients(
        hass=hass,
        opndevice_id=call.data.get("device_id"),
        opnentity_id=call.data.get("entity_id"),
    )


def _get_service_identifier(call: ServiceCall) -> str:
    """Return the OPNsense service identifier from a service call.

    Args:
        call: Service call payload received from Home Assistant.

    Returns:
        str: OPNsense service identifier.

    Raises:
        ServiceValidationError: If no service identifier is present.
    """
    service_identifier = call.data.get("service_id", call.data.get("service_name"))
    if not service_identifier:
        raise ServiceValidationError(_SERVICE_IDENTIFIER_ERROR)
    return service_identifier


async def _run_boolean_client_action(
    clients: list[OPNsenseServiceClient],
    log_prefix: str,
    action_name: str | None,
    target_name: str,
    target_value: Any,
    failure_message: str,
    action: BooleanClientAction,
) -> None:
    """Run a boolean-returning action across all selected clients.

    Args:
        clients: OPNsense clients selected for the service call.
        log_prefix: Prefix used in the debug log message.
        action_name: Optional action variant to include after the log prefix.
        target_name: Human-readable target field name for logs.
        target_value: Target value passed to the client action.
        failure_message: Error message to raise if no clients or any client action fails.
        action: Awaitable client action returning success state.

    Raises:
        ServiceValidationError: If no selected clients report success or any selected client fails.
    """
    success: bool | None = None
    for client in clients:
        response = await action(client)
        log_action = f"{action_name}, " if action_name else ""
        _LOGGER.debug(
            "[%s] %sclient: %s, %s: %s, response: %s",
            log_prefix,
            log_action,
            client.name,
            target_name,
            target_value,
            response,
        )
        if success is None or success:
            success = response
    if success is None or not success:
        raise ServiceValidationError(failure_message)


async def _collect_mapping_results(
    clients: list[OPNsenseServiceClient],
    log_prefix: str,
    failure_message: str,
    action: Callable[[OPNsenseServiceClient], Awaitable[Any]],
    action_context: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Collect non-empty mapping responses from selected clients.

    Args:
        clients: OPNsense clients selected for the service call.
        log_prefix: Prefix used in the debug log message.
        failure_message: Error message to raise if no clients return data.
        action: Awaitable client action returning a mapping payload.
        action_context: Optional values to include in debug logs.

    Returns:
        list[dict[str, Any]]: Per-client mapping results with ``client_name`` included.

    Raises:
        ServiceValidationError: If no selected client returns a non-empty mapping.
    """
    response_list: list[dict[str, Any]] = []
    for client in clients:
        response = await action(client)
        _LOGGER.debug(
            "[%s] client: %s, context: %s, response: %s",
            log_prefix,
            client.name,
            action_context or {},
            response,
        )
        if not isinstance(response, MutableMapping) or len(response) == 0:
            continue
        result: dict[str, Any] = {"client_name": client.name}
        result.update(dict(response))
        response_list.append(result)

    if len(response_list) == 0:
        raise ServiceValidationError(failure_message)
    return response_list


async def _service_close_notice(hass: HomeAssistant, call: ServiceCall) -> None:
    """Handle the close notice service call.

    Args:
        hass: Home Assistant instance that owns the integration state, entity registry, and
        services.
        call: Service call payload received from Home Assistant.
    """
    clients = await _get_target_clients(hass, call)
    for client in clients:
        _LOGGER.debug(
            "[service_close_notice] client: %s, service: %s",
            client.name,
            call.data.get("id"),
        )
        await client.close_notice(call.data.get("id"))


async def _service_start_service(hass: HomeAssistant, call: ServiceCall) -> None:
    """Handle the start service call.

    Args:
        hass: Home Assistant instance that owns the integration state, entity registry, and
        services.
        call: Service call payload received from Home Assistant.

    Raises:
        ServiceValidationError: If the service call payload is missing a valid target or
        required value.
    """
    service_identifier = _get_service_identifier(call)
    clients = await _get_target_clients(hass, call)
    await _run_boolean_client_action(
        clients=clients,
        log_prefix="service_start_service",
        action_name=None,
        target_name="service",
        target_value=service_identifier,
        failure_message=f"Start Service Failed. service: {service_identifier}",
        action=lambda client: client.start_service(service_identifier),
    )


async def _service_stop_service(hass: HomeAssistant, call: ServiceCall) -> None:
    """Handle the stop service call.

    Args:
        hass: Home Assistant instance that owns the integration state, entity registry, and
        services.
        call: Service call payload received from Home Assistant.

    Raises:
        ServiceValidationError: If the service call payload is missing a valid target or
        required value.
    """
    service_identifier = _get_service_identifier(call)
    clients = await _get_target_clients(hass, call)
    await _run_boolean_client_action(
        clients=clients,
        log_prefix="service_stop_service",
        action_name=None,
        target_name="service",
        target_value=service_identifier,
        failure_message=f"Stop Service Failed. service: {service_identifier}",
        action=lambda client: client.stop_service(service_identifier),
    )


async def _service_restart_service(hass: HomeAssistant, call: ServiceCall) -> None:
    """Handle the restart service call.

    Args:
        hass: Home Assistant instance that owns the integration state, entity registry, and
        services.
        call: Service call payload received from Home Assistant.

    Raises:
        ServiceValidationError: If the service call payload is missing a valid target or
        required value.
    """
    service_identifier = _get_service_identifier(call)
    clients = await _get_target_clients(hass, call)
    if call.data.get("only_if_running"):
        await _run_boolean_client_action(
            clients=clients,
            log_prefix="service_restart_service",
            action_name="restart_service_if_running",
            target_name="service",
            target_value=service_identifier,
            failure_message=f"Restart Service Failed. service: {service_identifier}",
            action=lambda client: client.restart_service_if_running(service_identifier),
        )
    else:
        await _run_boolean_client_action(
            clients=clients,
            log_prefix="service_restart_service",
            action_name="restart_service",
            target_name="service",
            target_value=service_identifier,
            failure_message=f"Restart Service Failed. service: {service_identifier}",
            action=lambda client: client.restart_service(service_identifier),
        )


async def _service_system_halt(hass: HomeAssistant, call: ServiceCall) -> None:
    """Handle the system halt service call.

    Args:
        hass: Home Assistant instance that owns the integration state, entity registry, and
        services.
        call: Service call payload received from Home Assistant.
    """
    clients = await _get_target_clients(hass, call)
    for client in clients:
        _LOGGER.debug("[service_system_halt] client: %s", client.name)
        await client.system_halt()


async def _service_system_reboot(hass: HomeAssistant, call: ServiceCall) -> None:
    """Handle the system reboot service call.

    Args:
        hass: Home Assistant instance that owns the integration state, entity registry, and
        services.
        call: Service call payload received from Home Assistant.
    """
    clients = await _get_target_clients(hass, call)
    for client in clients:
        _LOGGER.debug("[service_system_reboot] client: %s", client.name)
        await client.system_reboot()


async def _service_send_wol(hass: HomeAssistant, call: ServiceCall) -> None:
    """Handle the send Wake-on-LAN service call.

    Args:
        hass: Home Assistant instance that owns the integration state, entity registry, and
        services.
        call: Service call payload received from Home Assistant.
    """
    clients = await _get_target_clients(hass, call)
    for client in clients:
        _LOGGER.debug(
            "[service_send_wol] client: %s, interface: %s, mac: %s",
            client.name,
            call.data.get("interface"),
            call.data.get("mac"),
        )
        await client.send_wol(call.data.get("interface"), call.data.get("mac"))


async def _service_reload_interface(hass: HomeAssistant, call: ServiceCall) -> None:
    """Handle the reload interface service call.

    Args:
        hass: Home Assistant instance that owns the integration state, entity registry, and
        services.
        call: Service call payload received from Home Assistant.

    Raises:
        ServiceValidationError: If the service call payload is missing a valid target or
        required value.
    """
    clients = await _get_target_clients(hass, call)
    interface = call.data.get("interface")
    await _run_boolean_client_action(
        clients=clients,
        log_prefix="service_reload_interface",
        action_name=None,
        target_name="interface",
        target_value=interface,
        failure_message=f"Reload Interface Failed: {interface}",
        action=lambda client: client.reload_interface(interface),
    )


async def _service_generate_vouchers(hass: HomeAssistant, call: ServiceCall) -> ServiceResponse:
    """Handle the generate vouchers service call.

    Args:
        hass: Home Assistant instance that owns the integration state, entity registry, and
        services.
        call: Service call payload received from Home Assistant.

    Raises:
        ServiceValidationError: If the service call payload is missing a valid target or
        required value.
    """
    clients = await _get_target_clients(hass, call)
    voucher_list: list = []
    for client in clients:
        try:
            vouchers: list = await client.generate_vouchers(call.data)
        except OPNsenseVoucherServerError as e:
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
                    voucher_list.append({"client": client.name, **voucher})
                else:
                    voucher_list.append(voucher)
    final_vouchers: dict[str, Any] = {"vouchers": voucher_list}
    _LOGGER.debug("[service_generate_vouchers] vouchers: %s", final_vouchers)
    return final_vouchers


async def _service_kill_states(hass: HomeAssistant, call: ServiceCall) -> ServiceResponse:
    """Handle the kill states service call.

    Args:
        hass: Home Assistant instance that owns the integration state, entity registry, and
        services.
        call: Service call payload received from Home Assistant.

    Raises:
        ServiceValidationError: If the service call payload is missing a valid target or
        required value.
    """
    clients = await _get_target_clients(hass, call)
    success: bool | None = None
    response_list: list = []
    for client in clients:
        response: dict[str, Any] = await client.kill_states(call.data.get("ip_addr"))
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


async def _service_run_speedtest(hass: HomeAssistant, call: ServiceCall) -> ServiceResponse:
    """Run speedtest and return speedtest results in action response data.

    Args:
        hass: Home Assistant instance.
        call: Service call payload that may contain ``device_id`` or ``entity_id``.

    Returns:
        ServiceResponse: Response payload containing per-client speedtest results.
    """
    clients = await _get_target_clients(hass, call)
    response_list = await _collect_mapping_results(
        clients=clients,
        log_prefix="service_run_speedtest",
        failure_message=(
            "Run Speedtest Failed. No selected OPNsense clients have Speedtest installed"
        ),
        action=lambda client: client.run_speedtest(),
    )
    return_response: dict[str, Any] = {"results": response_list}
    _LOGGER.debug("[service_run_speedtest] return_response: %s", return_response)
    return return_response


async def _service_get_vnstat_metrics(hass: HomeAssistant, call: ServiceCall) -> ServiceResponse:
    """Return parsed vnStat metrics for a selected period as action response data.

    Args:
        hass: Home Assistant instance.
        call: Service call payload containing the required ``period`` and optional OPNsense
        device/entity selectors.

    Returns:
        ServiceResponse: Parsed per-client vnStat payloads from the requested endpoint.
    """
    clients = await _get_target_clients(hass, call)
    requested_period: str = call.data["period"]
    response_list = await _collect_mapping_results(
        clients=clients,
        log_prefix="service_get_vnstat_metrics",
        failure_message="Get vnStat Metrics Failed. No selected OPNsense clients vnStat installed",
        action=lambda client: client.get_vnstat_metrics(requested_period),
        action_context={"period": requested_period},
    )
    return_response: dict[str, Any] = {"results": response_list}
    _LOGGER.debug("[service_get_vnstat_metrics] return_response: %s", return_response)
    return return_response


async def _service_toggle_alias(hass: HomeAssistant, call: ServiceCall) -> None:
    """Handle the toggle alias service call.

    Args:
        hass: Home Assistant instance that owns the integration state, entity registry, and
        services.
        call: Service call payload received from Home Assistant.

    Raises:
        ServiceValidationError: If the service call payload is missing a valid target or
        required value.
    """
    clients = await _get_target_clients(hass, call)
    alias = call.data.get("alias")
    toggle_on_off = call.data.get("toggle_on_off")
    await _run_boolean_client_action(
        clients=clients,
        log_prefix="service_toggle_alias",
        action_name=None,
        target_name="alias",
        target_value=alias,
        failure_message=f"Toggle Alias Failed. alias: {alias}, action: {toggle_on_off}",
        action=lambda client: client.toggle_alias(alias, toggle_on_off),
    )
