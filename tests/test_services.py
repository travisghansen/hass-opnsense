"""Unit tests for the services module of the hass-opnsense integration.

These tests exercise service helpers, validation paths, and error handling
for operations such as starting/stopping services and generating vouchers.
"""

import json
from pathlib import Path
from typing import Any, Never
from unittest.mock import AsyncMock, MagicMock

from aiopnsense.exceptions import OPNsenseVoucherServerError
from homeassistant.core import HomeAssistant, SupportsResponse
from homeassistant.exceptions import ServiceValidationError
from homeassistant.util.yaml import load_yaml_dict
import pytest
import voluptuous as vol

from custom_components.opnsense import services as services_mod
from custom_components.opnsense.const import (
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

_INTEGRATION_ROOT = Path(__file__).parents[1] / "custom_components" / "opnsense"


def _patch_clients(monkeypatch: pytest.MonkeyPatch, clients: list[Any]) -> None:
    """Patch service client resolution to return selected fake clients.

    Args:
        monkeypatch: Pytest monkeypatch fixture used to patch the services module.
        clients: Fake OPNsense clients returned by ``_get_clients``.
    """

    async def fake_get(*_args: Any, **_kwargs: Any) -> list[Any]:
        """Return the selected fake clients for a service handler test.

        Args:
            *_args: Positional arguments forwarded to ``_get_clients`` and ignored.
            **_kwargs: Keyword arguments forwarded to ``_get_clients`` and ignored.
        """
        return clients

    monkeypatch.setattr(services_mod, "_get_clients", fake_get)


def _voucher_call_data() -> dict[str, str]:
    """Return a valid voucher service payload."""
    return {"validity": "1", "expirytime": "2", "count": "2", "vouchergroup": "g1"}


def _service_call(data: dict[str, Any]) -> MagicMock:
    """Return a fake Home Assistant service call with data.

    Args:
        data: Service call data exposed through the fake call.

    Returns:
        MagicMock: Fake Home Assistant service call.
    """
    call = MagicMock()
    call.data = data
    return call


def _iter_service_field_names(service_definition: dict[str, Any]) -> set[str]:
    """Return all top-level and section service field names.

    Args:
        service_definition: Service definition loaded from ``services.yaml``.

    Returns:
        set[str]: Field names that should have service translations.
    """
    fields = service_definition.get("fields", {})
    field_names = set()
    for field_name, field_definition in fields.items():
        if "fields" not in field_definition:
            field_names.add(field_name)
            continue
        field_names.update(field_definition["fields"])
    return field_names


def _patch_device_registry_entry(
    monkeypatch: pytest.MonkeyPatch,
    primary_config_entry: str | None,
    config_entries: set[str] | None = None,
) -> None:
    """Patch device registry lookup to return a fake device entry.

    Args:
        monkeypatch: Pytest monkeypatch fixture used to patch the services module.
        primary_config_entry: Config entry ID exposed by the fake device entry.
        config_entries: Config entry IDs exposed by the fake device entry.
    """

    class DevReg:
        def async_get(self, device_id: Any) -> Any:
            """Return a fake device registry entry.

            Args:
                device_id: Device identifier used to target a config entry.
            """
            device_entry = MagicMock()
            device_entry.primary_config_entry = primary_config_entry
            device_entry.config_entries = config_entries or set()
            return device_entry

    monkeypatch.setattr(services_mod.dr, "async_get", lambda _hass: DevReg())


def _patch_entity_registry_entry(
    monkeypatch: pytest.MonkeyPatch,
    config_entry_id: str | None,
) -> None:
    """Patch entity registry lookup to return a fake entity entry.

    Args:
        monkeypatch: Pytest monkeypatch fixture used to patch the services module.
        config_entry_id: Config entry ID exposed by the fake entity entry.
    """

    class EntReg:
        def async_get(self, entity_id: Any) -> Any:
            """Return a fake entity registry entry.

            Args:
                entity_id: Entity identifier used to target a config entry.
            """
            entity_entry = MagicMock()
            entity_entry.config_entry_id = config_entry_id
            return entity_entry

    monkeypatch.setattr(services_mod.er, "async_get", lambda _hass: EntReg())


def _patch_missing_device_registry_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch device registry lookup to return no device entry.

    Args:
        monkeypatch: Pytest monkeypatch fixture used to patch the services module.
    """

    class DevReg:
        def async_get(self, device_id: Any) -> None:
            """Return no device registry entry.

            Args:
                device_id: Device identifier used to target a config entry.
            """
            return

    monkeypatch.setattr(services_mod.dr, "async_get", lambda _hass: DevReg())


@pytest.mark.asyncio
async def test_async_setup_services_registers_get_vnstat_metrics_case_insensitive_period() -> None:
    """Service setup should register get_vnstat_metrics with normalized period schema."""
    hass = MagicMock(spec=HomeAssistant)
    hass.services = MagicMock()
    hass.services.async_register = MagicMock()

    await services_mod.async_setup_services(hass)

    registered_kwargs = None
    for call in hass.services.async_register.call_args_list:
        kwargs = call.kwargs
        if kwargs.get("service") == SERVICE_GET_VNSTAT_METRICS:
            registered_kwargs = kwargs
            break

    assert registered_kwargs is not None
    assert registered_kwargs["domain"] == DOMAIN
    assert registered_kwargs["supports_response"] == SupportsResponse.ONLY

    schema = registered_kwargs["schema"]
    validated = schema({"period": "Yearly"})
    assert validated["period"] == "yearly"
    with pytest.raises(vol.Invalid):
        schema({"period": "weekly"})


@pytest.mark.asyncio
async def test_async_setup_services_registers_expected_service_contracts() -> None:
    """Service setup registers every OPNsense action with expected response behavior."""
    hass = MagicMock(spec=HomeAssistant)
    hass.services = MagicMock()
    hass.services.async_register = MagicMock()

    await services_mod.async_setup_services(hass)

    registrations = {
        call.kwargs["service"]: call.kwargs for call in hass.services.async_register.call_args_list
    }

    assert list(registrations) == [
        SERVICE_CLOSE_NOTICE,
        SERVICE_START_SERVICE,
        SERVICE_STOP_SERVICE,
        SERVICE_RESTART_SERVICE,
        SERVICE_SYSTEM_HALT,
        SERVICE_SYSTEM_REBOOT,
        SERVICE_SEND_WOL,
        SERVICE_RELOAD_INTERFACE,
        SERVICE_GENERATE_VOUCHERS,
        SERVICE_KILL_STATES,
        SERVICE_RUN_SPEEDTEST,
        SERVICE_GET_VNSTAT_METRICS,
        SERVICE_TOGGLE_ALIAS,
    ]
    assert registrations[SERVICE_GENERATE_VOUCHERS]["supports_response"] == SupportsResponse.ONLY
    assert registrations[SERVICE_KILL_STATES]["supports_response"] == SupportsResponse.OPTIONAL
    assert registrations[SERVICE_RUN_SPEEDTEST]["supports_response"] == SupportsResponse.ONLY
    assert registrations[SERVICE_GET_VNSTAT_METRICS]["supports_response"] == SupportsResponse.ONLY
    for service in (
        SERVICE_CLOSE_NOTICE,
        SERVICE_START_SERVICE,
        SERVICE_STOP_SERVICE,
        SERVICE_RESTART_SERVICE,
        SERVICE_SYSTEM_HALT,
        SERVICE_SYSTEM_REBOOT,
        SERVICE_SEND_WOL,
        SERVICE_RELOAD_INTERFACE,
        SERVICE_TOGGLE_ALIAS,
    ):
        assert "supports_response" not in registrations[service]

    registrations[SERVICE_START_SERVICE]["schema"]({"service_id": "svc"})
    registrations[SERVICE_STOP_SERVICE]["schema"]({"service_name": "svc"})
    registrations[SERVICE_RESTART_SERVICE]["schema"]({"service_id": "svc", "only_if_running": True})
    with pytest.raises(vol.Invalid):
        registrations[SERVICE_START_SERVICE]["schema"]({"service_id": "svc", "service_name": "svc"})
    with pytest.raises(vol.Invalid):
        registrations[SERVICE_STOP_SERVICE]["schema"]({"service_id": "svc", "service_name": "svc"})
    with pytest.raises(vol.Invalid):
        registrations[SERVICE_RESTART_SERVICE]["schema"](
            {"service_id": "svc", "service_name": "svc", "only_if_running": True}
        )
    assert registrations[SERVICE_START_SERVICE]["schema"]({}) == {}


def test_service_metadata_fields_have_translations() -> None:
    """Every service field exposed in services.yaml has an English translation."""
    services_yaml = load_yaml_dict(_INTEGRATION_ROOT / "services.yaml")
    translations = json.loads((_INTEGRATION_ROOT / "translations" / "en.json").read_text())

    translated_services = translations["services"]
    for service_name, service_definition in services_yaml.items():
        assert service_name in translated_services
        translated_fields = translated_services[service_name].get("fields", {})
        for field_name in _iter_service_field_names(service_definition):
            assert field_name in translated_fields, f"{service_name}.{field_name}"


def test_service_validation_error_uses_translation_metadata() -> None:
    """Service validation errors should be localizable by Home Assistant."""
    error = services_mod._service_validation_error("start_service_failed", {"service": "svc"})

    assert error.translation_domain == DOMAIN
    assert error.translation_key == "start_service_failed"
    assert error.translation_placeholders == {"service": "svc"}


@pytest.mark.asyncio
async def test_get_clients_single_and_multiple(monkeypatch: pytest.MonkeyPatch) -> None:
    """_get_clients returns clients from hass.data and supports filtering."""
    # use a plain hass-like object so .data is a real dict
    hass_local = MagicMock(spec=HomeAssistant)
    client = MagicMock()
    client.name = "one"
    hass_local.data = {DOMAIN: {"e1": client}}
    res = await services_mod._get_clients(hass_local)
    assert res == [client]

    # multiple entries and filter by device_id
    client2 = MagicMock()
    client2.name = "two"
    hass_local.data[DOMAIN] = {"e1": client, "e2": client2}

    _patch_device_registry_entry(monkeypatch, "e2")
    res = await services_mod._get_clients(hass_local, opndevice_id="dev123")
    assert res == [client2]

    # filter by entity_id
    _patch_entity_registry_entry(monkeypatch, "e1")
    res = await services_mod._get_clients(hass_local, opnentity_id="ent123")
    assert res == [client]

    _patch_device_registry_entry(monkeypatch, None, {"e1"})
    res = await services_mod._get_clients(hass_local, opndevice_id="dev123")
    assert res == [client]


@pytest.mark.asyncio
async def test_get_clients_registry_errors_raise_for_explicit_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Registry lookup errors must not broaden explicit targets to all clients."""
    hass_local = MagicMock(spec=HomeAssistant)
    c1, c2 = MagicMock(name="c1"), MagicMock(name="c2")
    hass_local.data = {DOMAIN: {"e1": c1, "e2": c2}}

    def _raises(exc: BaseException | None) -> Any:
        """Raises.

        Args:
            exc: Exc provided by pytest or the test case.
        """

        def _r(*_a, **_k) -> Never:
            """Raise the provided registry exception for the patched helper.

            Args:
                *_a: Additional positional arguments forwarded by the function.
                **_k: Additional keyword arguments forwarded by the function.

            Raises:
                Exception: Raised with the exception instance supplied to ``_raises``.
            """
            assert isinstance(exc, BaseException)
            raise exc

        return _r

    monkeypatch.setattr(services_mod.dr, "async_get", _raises(TypeError()))
    monkeypatch.setattr(services_mod.er, "async_get", _raises(AttributeError()))
    with pytest.raises(ServiceValidationError):
        await services_mod._get_clients(hass_local, opndevice_id="d", opnentity_id="e")


@pytest.mark.asyncio
async def test_get_clients_unresolved_explicit_target_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit target selectors must not broaden to all configured clients."""
    hass_local = MagicMock(spec=HomeAssistant)
    c1, c2 = MagicMock(name="c1"), MagicMock(name="c2")
    hass_local.data = {DOMAIN: {"e1": c1, "e2": c2}}

    _patch_missing_device_registry_entry(monkeypatch)

    with pytest.raises(ServiceValidationError):
        await services_mod._get_clients(hass_local, opndevice_id="missing-device")


@pytest.mark.asyncio
async def test_get_clients_registry_entries_without_config_entry_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit registry targets without config entries must not broaden to all clients."""
    hass_local = MagicMock(spec=HomeAssistant)
    c1, c2 = MagicMock(name="c1"), MagicMock(name="c2")
    hass_local.data = {DOMAIN: {"e1": c1, "e2": c2}}

    _patch_device_registry_entry(monkeypatch, None)
    _patch_entity_registry_entry(monkeypatch, None)

    with pytest.raises(ServiceValidationError):
        await services_mod._get_clients(hass_local, opndevice_id="dev123")

    with pytest.raises(ServiceValidationError):
        await services_mod._get_clients(hass_local, opnentity_id="ent123")


@pytest.mark.asyncio
async def test_get_clients_unloaded_registry_entry_id_raises_no_target_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit targets resolving to unloaded config entries should fail with no_target_clients."""
    hass_local = MagicMock(spec=HomeAssistant)
    c1, c2 = MagicMock(name="c1"), MagicMock(name="c2")
    hass_local.data = {DOMAIN: {"e1": c1, "e2": c2}}

    _patch_device_registry_entry(monkeypatch, "missing")

    with pytest.raises(ServiceValidationError) as exc_info:
        await services_mod._get_clients(hass_local, opndevice_id="dev123")

    assert exc_info.value.translation_key == "no_target_clients"


@pytest.mark.asyncio
async def test_get_clients_empty_data_raises_for_explicit_target() -> None:
    """Explicit target selectors fail clearly when no clients are loaded."""
    hass_local = MagicMock(spec=HomeAssistant)
    hass_local.data = {DOMAIN: {}}

    with pytest.raises(ServiceValidationError) as exc_info:
        await services_mod._get_clients(hass_local, opndevice_id="dev123")

    assert exc_info.value.translation_key == "no_target_clients"


@pytest.mark.asyncio
async def test_service_start_stop_restart_success_and_failure(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any
) -> None:
    """Start/stop/restart service handlers call client methods correctly."""
    hass = ph_hass
    hass.data = {}
    # make both clients return True initially so the service calls succeed
    c1 = MagicMock()
    c1.name = "c1"
    c1.start_service = AsyncMock(return_value=True)
    c1.stop_service = AsyncMock(return_value=True)
    c1.restart_service = AsyncMock(return_value=True)
    c1.restart_service_if_running = AsyncMock(return_value=True)
    c2 = MagicMock()
    c2.name = "c2"
    c2.start_service = AsyncMock(return_value=True)
    c2.stop_service = AsyncMock(return_value=True)
    c2.restart_service = AsyncMock(return_value=True)
    c2.restart_service_if_running = AsyncMock(return_value=True)
    hass.data[DOMAIN] = {"e1": c1, "e2": c2}

    call = _service_call({"service_id": "svc"})

    _patch_clients(monkeypatch, [c1, c2])
    # start should succeed because c2 returns True
    await services_mod._service_start_service(hass, call)
    # stop should succeed
    await services_mod._service_stop_service(hass, call)

    # restart without only_if_running uses restart_service
    await services_mod._service_restart_service(hass, call)
    c1.start_service.assert_awaited_once_with("svc")
    c2.start_service.assert_awaited_once_with("svc")
    c1.stop_service.assert_awaited_once_with("svc")
    c2.stop_service.assert_awaited_once_with("svc")
    c1.restart_service.assert_awaited_once_with("svc")
    c2.restart_service.assert_awaited_once_with("svc")
    c1.restart_service_if_running.assert_not_awaited()
    c2.restart_service_if_running.assert_not_awaited()

    # Also verify the service_name identifier path works
    call2 = _service_call({"service_name": "svc"})
    await services_mod._service_start_service(hass, call2)
    await services_mod._service_stop_service(hass, call2)
    await services_mod._service_restart_service(hass, call2)

    # Confirm service_name invoked client methods again with same arg
    c1.start_service.assert_awaited_with("svc")
    c2.start_service.assert_awaited_with("svc")
    assert c1.start_service.await_count == 2
    assert c2.start_service.await_count == 2
    c1.stop_service.assert_awaited_with("svc")
    c2.stop_service.assert_awaited_with("svc")
    assert c1.stop_service.await_count == 2
    assert c2.stop_service.await_count == 2
    c1.restart_service.assert_awaited_with("svc")
    c2.restart_service.assert_awaited_with("svc")
    assert c1.restart_service.await_count == 2
    assert c2.restart_service.await_count == 2


@pytest.mark.asyncio
async def test_service_restart_only_if_running_and_reload_interface(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """Restart service honors only_if_running and reload_interface behavior."""
    c1 = MagicMock()
    c1.name = "c1"
    c1.restart_service_if_running = AsyncMock(return_value=True)
    c1.restart_service = AsyncMock(return_value=True)
    c1.reload_interface = AsyncMock(return_value=True)
    hass = ph_hass
    hass.data = {}
    hass.data[DOMAIN] = {"e1": c1}
    call = _service_call({"service_id": "svc", "only_if_running": True})

    _patch_clients(monkeypatch, [c1])
    # should not raise
    caplog.set_level("DEBUG", logger=services_mod.__name__)
    await services_mod._service_restart_service(hass, call)
    c1.restart_service_if_running.assert_awaited_once_with("svc")
    assert "[service_restart_service] restart_service_if_running, client: c1" in caplog.text
    assert "[service_restart_service] restart_service_if_running] client: c1" not in caplog.text
    # Ensure the non-conditional restart path was not used
    c1.restart_service.assert_not_awaited()

    # Failure path: client reports not running -> should raise ServiceValidationError
    c1.restart_service_if_running = AsyncMock(return_value=False)

    with pytest.raises(ServiceValidationError):
        await services_mod._service_restart_service(hass, call)

    # reload_interface success
    call_iface = _service_call({"interface": "igb0"})
    await services_mod._service_reload_interface(hass, call_iface)
    c1.reload_interface.assert_awaited_once_with("igb0")

    # reload_interface failure should raise
    c1.reload_interface = AsyncMock(return_value=False)
    with pytest.raises(ServiceValidationError):
        await services_mod._service_reload_interface(hass, call_iface)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method_name", "method_attr"),
    [
        ("_service_start_service", "start_service"),
        ("_service_stop_service", "stop_service"),
        ("_service_restart_service", "restart_service"),
    ],
)
async def test_service_start_stop_restart_failure_variants(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any, method_name: Any, method_attr: Any
) -> None:
    """Parameterized failure tests for start/stop/restart service handlers. For each handler, ensure that if any client returns False the handler raises ServiceValidationError."""
    hass = ph_hass
    hass.data = {}
    # ok client returns True, bad client returns False for the method under test
    ok_client = MagicMock()
    ok_client.name = "ok"
    bad_client = MagicMock()
    bad_client.name = "bad"

    setattr(ok_client, method_attr, AsyncMock(return_value=True))
    setattr(bad_client, method_attr, AsyncMock(return_value=False))

    _patch_clients(monkeypatch, [ok_client, bad_client])
    call = _service_call({"service_id": "svc"})

    handler = getattr(services_mod, method_name)
    with pytest.raises(ServiceValidationError):
        await handler(hass, call)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method_name",
    [
        "_service_start_service",
        "_service_stop_service",
        "_service_restart_service",
    ],
)
async def test_service_start_stop_restart_require_service_identifier(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    method_name: str,
) -> None:
    """Service control handlers require either service_id or service_name."""
    client = MagicMock()
    client.name = "c1"
    client.start_service = AsyncMock(return_value=True)
    client.stop_service = AsyncMock(return_value=True)
    client.restart_service = AsyncMock(return_value=True)

    _patch_clients(monkeypatch, [client])
    call = _service_call({})

    handler = getattr(services_mod, method_name)
    with pytest.raises(ServiceValidationError) as exc_info:
        await handler(ph_hass, call)

    assert exc_info.value.translation_key == "service_identifier_required"
    client.start_service.assert_not_awaited()
    client.stop_service.assert_not_awaited()
    client.restart_service.assert_not_awaited()


@pytest.mark.asyncio
async def test_generate_vouchers_success_and_server_error(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any
) -> None:
    """Generating vouchers returns assembled list and handles server errors."""
    hass = ph_hass
    hass.data = {}
    # client returns a list of mapping vouchers
    vouchers = [{"code": "A1"}, {"code": "B2"}]
    c1 = MagicMock()
    c1.name = "svc1"
    c1.generate_vouchers = AsyncMock(return_value=vouchers)
    hass.data[DOMAIN] = {"e1": c1}
    call = _service_call(_voucher_call_data())

    _patch_clients(monkeypatch, [c1])
    resp = await services_mod._service_generate_vouchers(hass, call)
    assert resp is not None
    assert "vouchers" in resp and isinstance(resp["vouchers"], list)
    response_vouchers: list[Any] = resp["vouchers"]
    # confirm client name was injected into voucher entries
    assert all(isinstance(v, dict) and v.get("client") == "svc1" for v in response_vouchers)

    # server error should raise ServiceValidationError
    c1.generate_vouchers = AsyncMock(side_effect=OPNsenseVoucherServerError("boom"))
    with pytest.raises(ServiceValidationError):
        await services_mod._service_generate_vouchers(hass, call)


@pytest.mark.asyncio
async def test_generate_vouchers_no_clients_raises(
    ph_hass: Any,
    fake_get_empty: None,
) -> None:
    """Generating vouchers requires at least one selected OPNsense client."""
    call = _service_call(_voucher_call_data())

    with pytest.raises(ServiceValidationError):
        await services_mod._service_generate_vouchers(ph_hass, call)


@pytest.mark.asyncio
async def test_generate_vouchers_empty_selected_client_response_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
) -> None:
    """A selected client returning no vouchers is a valid empty voucher response."""
    client = MagicMock()
    client.name = "svc1"
    client.generate_vouchers = AsyncMock(return_value=[])
    call = _service_call(_voucher_call_data())

    _patch_clients(monkeypatch, [client])

    assert await services_mod._service_generate_vouchers(ph_hass, call) == {"vouchers": []}


@pytest.mark.asyncio
async def test_generate_vouchers_does_not_mutate_client_voucher_response(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
) -> None:
    """Client voucher mappings are copied before adding Home Assistant metadata."""
    voucher = {"code": "A1"}
    client = MagicMock()
    client.name = "svc1"
    client.generate_vouchers = AsyncMock(return_value=[voucher])
    call = _service_call(_voucher_call_data())

    _patch_clients(monkeypatch, [client])

    response = await services_mod._service_generate_vouchers(ph_hass, call)

    assert voucher == {"code": "A1"}
    assert response == {"vouchers": [{"client": "svc1", "code": "A1"}]}


@pytest.mark.asyncio
async def test_kill_states_success_and_failure(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any
) -> None:
    """Killing states returns dropped state counts and handles failures."""
    hass = ph_hass
    hass.data = {}
    c1 = MagicMock()
    c1.name = "c1"
    c1.kill_states = AsyncMock(return_value={"success": True, "dropped_states": 5})
    hass.data[DOMAIN] = {"e1": c1}
    call = _service_call({"ip_addr": "1.2.3.4"})

    _patch_clients(monkeypatch, [c1])
    resp = await services_mod._service_kill_states(hass, call)
    # Expect a payload containing the client name and dropped_states value
    expected = {"dropped_states": [{"client_name": "c1", "dropped_states": 5}]}
    assert resp == expected

    # failure -> raise
    c1.kill_states = AsyncMock(return_value={"success": False})
    with pytest.raises(ServiceValidationError):
        await services_mod._service_kill_states(hass, call)


@pytest.mark.asyncio
async def test_run_speedtest_success_and_unavailable(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any
) -> None:
    """run_speedtest should return per-client results and raise when unavailable."""
    hass = ph_hass
    hass.data = {}
    c1 = MagicMock()
    c1.name = "c1"
    c1.run_speedtest = AsyncMock(
        return_value={"timestamp": "2026-03-14T03:09:45Z", "download": 836.05, "upload": 832.97}
    )
    c2 = MagicMock()
    c2.name = "c2"
    c2.run_speedtest = AsyncMock(return_value={})

    _patch_clients(monkeypatch, [c1, c2])
    call = _service_call({})

    response = await services_mod._service_run_speedtest(hass, call)
    assert response is not None
    assert "results" in response
    results = response["results"]
    assert isinstance(results, list)
    assert len(results) == 1
    first_result = results[0]
    assert isinstance(first_result, dict)
    assert first_result["client_name"] == "c1"
    assert first_result["download"] == 836.05

    c1.run_speedtest = AsyncMock(return_value={})
    c2.run_speedtest = AsyncMock(return_value={})
    with pytest.raises(ServiceValidationError):
        await services_mod._service_run_speedtest(hass, call)


@pytest.mark.asyncio
async def test_get_vnstat_metrics_success_and_unavailable(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any
) -> None:
    """get_vnstat_metrics should return parsed per-client data or raise when unavailable."""
    hass = ph_hass
    hass.data = {}
    c1 = MagicMock()
    c1.name = "c1"
    c1.get_vnstat_metrics = AsyncMock(
        return_value={
            "period": "yearly",
            "interfaces": {
                "igc0": [{"label": "2026", "rx_bytes": 1, "tx_bytes": 2, "total_bytes": 3}],
            },
        }
    )
    c2 = MagicMock()
    c2.name = "c2"
    c2.get_vnstat_metrics = AsyncMock(return_value={})

    _patch_clients(monkeypatch, [c1, c2])
    call = _service_call({"period": "yearly"})

    response = await services_mod._service_get_vnstat_metrics(hass, call)
    assert response is not None
    assert "results" in response
    results = response["results"]
    assert isinstance(results, list)
    assert len(results) == 1
    first_result = results[0]
    assert isinstance(first_result, dict)
    assert first_result["client_name"] == "c1"
    assert first_result["period"] == "yearly"
    c1.get_vnstat_metrics.assert_awaited_once_with("yearly")
    c2.get_vnstat_metrics.assert_awaited_once_with("yearly")

    c1.get_vnstat_metrics = AsyncMock(return_value={})
    c2.get_vnstat_metrics = AsyncMock(return_value={})
    with pytest.raises(ServiceValidationError):
        await services_mod._service_get_vnstat_metrics(hass, call)


@pytest.mark.asyncio
async def test_get_clients_no_data_returns_empty() -> None:
    """_get_clients returns an empty list when hass.data has no domain."""
    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    res = await services_mod._get_clients(hass)
    assert res == []


@pytest.fixture
def fake_get_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fixture that monkeypatches services_mod._get_clients to return an empty list."""
    _patch_clients(monkeypatch, [])


@pytest.mark.asyncio
async def test_restart_service_no_clients_raises(ph_hass: Any, fake_get_empty: None) -> None:
    """If no clients are found, restarting a service should raise ServiceValidationError."""
    hass = ph_hass
    hass.data = {}

    call = _service_call({"service_id": "svc"})

    with pytest.raises(ServiceValidationError):
        await services_mod._service_restart_service(hass, call)


@pytest.mark.asyncio
async def test_start_service_no_clients_raises(ph_hass: Any, fake_get_empty: None) -> None:
    """If no clients are found, starting a service should raise ServiceValidationError."""
    hass = ph_hass
    hass.data = {}

    call = _service_call({"service_id": "svc"})

    with pytest.raises(ServiceValidationError):
        await services_mod._service_start_service(hass, call)


@pytest.mark.asyncio
async def test_stop_service_no_clients_raises(ph_hass: Any, fake_get_empty: None) -> None:
    """If no clients are found, stopping a service should raise ServiceValidationError."""
    hass = ph_hass
    hass.data = {}

    call = _service_call({"service_id": "svc"})

    with pytest.raises(ServiceValidationError):
        await services_mod._service_stop_service(hass, call)


@pytest.mark.asyncio
async def test_close_send_wol_and_system_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    """Close/send_wol/system calls are forwarded to clients."""
    # single client that should receive calls
    c = MagicMock()
    c.name = "one"
    c.close_notice = AsyncMock(return_value=None)
    c.send_wol = AsyncMock(return_value=None)
    c.system_halt = AsyncMock(return_value=None)
    c.system_reboot = AsyncMock(return_value=None)

    _patch_clients(monkeypatch, [c])

    hass = MagicMock(spec=HomeAssistant)
    hass.data = {DOMAIN: {"e1": c}}

    # close notice
    call = _service_call({"id": "all"})
    await services_mod._service_close_notice(hass, call)
    c.close_notice.assert_awaited_once_with("all")

    # send wol
    call_wol = _service_call({"interface": "lan", "mac": "aa:bb:cc:dd:ee:ff"})
    await services_mod._service_send_wol(hass, call_wol)
    c.send_wol.assert_awaited_once_with("lan", "aa:bb:cc:dd:ee:ff")

    # system halt and reboot
    call_sys = _service_call({})
    await services_mod._service_system_halt(hass, call_sys)
    c.system_halt.assert_awaited_once()
    await services_mod._service_system_reboot(hass, call_sys)
    c.system_reboot.assert_awaited_once()


@pytest.mark.asyncio
async def test_toggle_alias_success_and_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Toggle alias success and failure paths raise or not appropriately."""
    # success path
    c1 = MagicMock()
    c1.name = "c1"
    c1.toggle_alias = AsyncMock(return_value=True)

    _patch_clients(monkeypatch, [c1])
    hass = MagicMock(spec=HomeAssistant)
    hass.data = {DOMAIN: {"e1": c1}}
    call = _service_call({"alias": "a1", "toggle_on_off": "on"})
    # should not raise
    await services_mod._service_toggle_alias(hass, call)

    # failure path
    c2 = MagicMock()
    c2.name = "c2"
    c2.toggle_alias = AsyncMock(return_value=False)

    _patch_clients(monkeypatch, [c2])
    hass.data = {DOMAIN: {"e2": c2}}
    with pytest.raises(ServiceValidationError):
        await services_mod._service_toggle_alias(hass, call)
