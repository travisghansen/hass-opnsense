"""Unit tests for the services module of the hass-opnsense integration.

These tests exercise service helpers, validation paths, and error handling
for operations such as starting/stopping services and generating vouchers.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.opnsense import services as services_mod
from custom_components.opnsense.const import DOMAIN
from custom_components.opnsense.pyopnsense import VoucherServerError
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ServiceValidationError


@pytest.mark.asyncio
async def test_get_clients_single_and_multiple(monkeypatch):
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

    class DevReg:
        def async_get(self, device_id):
            m = MagicMock()
            m.primary_config_entry = "e2"
            return m

    monkeypatch.setattr(services_mod.dr, "async_get", lambda hass_in: DevReg())
    res = await services_mod._get_clients(hass_local, opndevice_id="dev123")
    assert res == [client2]

    # filter by entity_id
    class EntReg:
        def async_get(self, entity_id):
            m = MagicMock()
            m.config_entry_id = "e1"
            return m

    monkeypatch.setattr(services_mod.er, "async_get", lambda hass_in: EntReg())
    res = await services_mod._get_clients(hass_local, opnentity_id="ent123")
    assert res == [client]


@pytest.mark.asyncio
async def test_service_start_stop_restart_success_and_failure(monkeypatch, ph_hass):
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

    call = MagicMock()
    call.data = {"service_id": "svc"}

    # monkeypatch _get_clients to return our clients
    async def fake_get(*args, **kwargs):
        return [c1, c2]

    monkeypatch.setattr(services_mod, "_get_clients", fake_get)
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


@pytest.mark.asyncio
async def test_service_restart_only_if_running_and_reload_interface(monkeypatch, ph_hass):
    """Restart service honors only_if_running and reload_interface behavior."""
    c1 = MagicMock()
    c1.name = "c1"
    c1.restart_service_if_running = AsyncMock(return_value=True)
    c1.restart_service = AsyncMock(return_value=True)
    c1.reload_interface = AsyncMock(return_value=True)
    hass = ph_hass
    hass.data = {}
    hass.data[DOMAIN] = {"e1": c1}
    call = MagicMock()
    call.data = {"service_id": "svc", "only_if_running": True}

    async def fake_get(*args, **kwargs):
        return [c1]

    monkeypatch.setattr(services_mod, "_get_clients", fake_get)
    # should not raise
    await services_mod._service_restart_service(hass, call)
    c1.restart_service_if_running.assert_awaited_once_with("svc")

    # Failure path: client reports not running -> should raise ServiceValidationError
    c1.restart_service_if_running = AsyncMock(return_value=False)

    # ensure _get_clients still returns our single client
    async def fake_get_single(*args, **kwargs):
        return [c1]

    monkeypatch.setattr(services_mod, "_get_clients", fake_get_single)

    with pytest.raises(ServiceValidationError):
        await services_mod._service_restart_service(hass, call)

    # reload_interface success
    call_iface = MagicMock()
    call_iface.data = {"interface": "igb0"}
    await services_mod._service_reload_interface(hass, call_iface)
    c1.reload_interface.assert_awaited_once_with("igb0")

    # reload_interface failure should raise
    c1.reload_interface = AsyncMock(return_value=False)
    with pytest.raises(ServiceValidationError):
        await services_mod._service_reload_interface(hass, call_iface)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method_name,ok_attr,bad_attr",
    [
        ("_service_start_service", "start_service", "start_service"),
        ("_service_stop_service", "stop_service", "stop_service"),
        ("_service_restart_service", "restart_service", "restart_service"),
    ],
)
async def test_service_start_stop_restart_failure_variants(
    monkeypatch, ph_hass, method_name, ok_attr, bad_attr
):
    """Parameterized failure tests for start/stop/restart service handlers.

    For each handler, ensure that if any client returns False the handler
    raises ServiceValidationError.
    """
    hass = ph_hass
    hass.data = {}
    # ok client returns True, bad client returns False for the method under test
    ok_client = MagicMock()
    ok_client.name = "ok"
    bad_client = MagicMock()
    bad_client.name = "bad"

    setattr(ok_client, ok_attr, AsyncMock(return_value=True))
    setattr(bad_client, bad_attr, AsyncMock(return_value=False))

    async def fake_get(*args, **kwargs):
        return [ok_client, bad_client]

    monkeypatch.setattr(services_mod, "_get_clients", fake_get)
    call = MagicMock()
    call.data = {"service_id": "svc"}

    handler = getattr(services_mod, method_name)
    with pytest.raises(ServiceValidationError):
        await handler(hass, call)


@pytest.mark.asyncio
async def test_generate_vouchers_success_and_server_error(monkeypatch, ph_hass):
    """Generating vouchers returns assembled list and handles server errors."""
    hass = ph_hass
    hass.data = {}
    # client returns a list of mapping vouchers
    vouchers = [{"code": "A1"}, {"code": "B2"}]
    c1 = MagicMock()
    c1.name = "svc1"
    c1.generate_vouchers = AsyncMock(return_value=vouchers)
    hass.data[DOMAIN] = {"e1": c1}
    call = MagicMock()
    call.data = {"validity": "1", "expirytime": "2", "count": "2", "vouchergroup": "g1"}

    async def fake_get(*args, **kwargs):
        return [c1]

    monkeypatch.setattr(services_mod, "_get_clients", fake_get)
    resp = await services_mod._service_generate_vouchers(hass, call)
    assert "vouchers" in resp and isinstance(resp["vouchers"], list)
    # confirm client name was injected into voucher entries
    assert all(v.get("client") == "svc1" for v in resp["vouchers"])

    # server error should raise ServiceValidationError
    c1.generate_vouchers = AsyncMock(side_effect=VoucherServerError("boom"))
    with pytest.raises(ServiceValidationError):
        await services_mod._service_generate_vouchers(hass, call)


@pytest.mark.asyncio
async def test_kill_states_success_and_failure(monkeypatch, ph_hass):
    """Killing states returns dropped state counts and handles failures."""
    hass = ph_hass
    hass.data = {}
    c1 = MagicMock()
    c1.name = "c1"
    c1.kill_states = AsyncMock(return_value={"success": True, "dropped_states": 5})
    hass.data[DOMAIN] = {"e1": c1}
    call = MagicMock()
    call.data = {"ip_addr": "1.2.3.4"}

    async def fake_get(*args, **kwargs):
        return [c1]

    monkeypatch.setattr(services_mod, "_get_clients", fake_get)
    resp = await services_mod._service_kill_states(hass, call)
    # Expect a payload containing the client name and dropped_states value
    expected = {"dropped_states": [{"client_name": "c1", "dropped_states": 5}]}
    assert resp == expected

    # failure -> raise
    c1.kill_states = AsyncMock(return_value={"success": False})
    with pytest.raises(ServiceValidationError):
        await services_mod._service_kill_states(hass, call)


@pytest.mark.asyncio
async def test_toggle_alias_failure(monkeypatch, ph_hass):
    """Toggling alias failure raises ServiceValidationError."""
    hass = ph_hass
    hass.data = {}
    c1 = MagicMock()
    c1.name = "c1"
    c1.toggle_alias = AsyncMock(return_value=False)
    hass.data[DOMAIN] = {"e1": c1}
    call = MagicMock()
    call.data = {"alias": "a1", "toggle_on_off": "on"}

    async def fake_get(*args, **kwargs):
        return [c1]

    monkeypatch.setattr(services_mod, "_get_clients", fake_get)
    with pytest.raises(ServiceValidationError):
        await services_mod._service_toggle_alias(hass, call)


@pytest.mark.asyncio
async def test_get_clients_no_data_returns_empty():
    """_get_clients returns an empty list when hass.data has no domain."""
    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    res = await services_mod._get_clients(hass)
    assert res == []


@pytest.fixture
def fake_get_empty(monkeypatch):
    """Fixture that monkeypatches services_mod._get_clients to return an empty list."""

    async def _fake_get_empty(*args, **kwargs):
        return []

    monkeypatch.setattr(services_mod, "_get_clients", _fake_get_empty)
    return _fake_get_empty


@pytest.mark.asyncio
async def test_restart_service_no_clients_raises(ph_hass, fake_get_empty):
    """If no clients are found, restarting a service should raise ServiceValidationError."""
    hass = ph_hass
    hass.data = {}

    call = MagicMock()
    call.data = {"service_id": "svc"}

    with pytest.raises(ServiceValidationError):
        await services_mod._service_restart_service(hass, call)


@pytest.mark.asyncio
async def test_start_service_no_clients_raises(ph_hass, fake_get_empty):
    """If no clients are found, starting a service should raise ServiceValidationError."""
    hass = ph_hass
    hass.data = {}

    call = MagicMock()
    call.data = {"service_id": "svc"}

    with pytest.raises(ServiceValidationError):
        await services_mod._service_start_service(hass, call)


@pytest.mark.asyncio
async def test_stop_service_no_clients_raises(ph_hass, fake_get_empty):
    """If no clients are found, stopping a service should raise ServiceValidationError."""
    hass = ph_hass
    hass.data = {}

    call = MagicMock()
    call.data = {"service_id": "svc"}

    with pytest.raises(ServiceValidationError):
        await services_mod._service_stop_service(hass, call)


@pytest.mark.asyncio
async def test_close_send_wol_and_system_calls(monkeypatch):
    """Close/send_wol/system calls are forwarded to clients."""
    # single client that should receive calls
    c = MagicMock()
    c.name = "one"
    c.close_notice = AsyncMock(return_value=None)
    c.send_wol = AsyncMock(return_value=None)
    c.system_halt = AsyncMock(return_value=None)
    c.system_reboot = AsyncMock(return_value=None)

    async def fake_get(*args, **kwargs):
        return [c]

    monkeypatch.setattr(services_mod, "_get_clients", fake_get)

    hass = MagicMock(spec=HomeAssistant)
    hass.data = {DOMAIN: {"e1": c}}

    # close notice
    call = MagicMock()
    call.data = {"id": "all"}
    await services_mod._service_close_notice(hass, call)
    c.close_notice.assert_awaited_once_with("all")

    # send wol
    call_wol = MagicMock()
    call_wol.data = {"interface": "lan", "mac": "aa:bb:cc:dd:ee:ff"}
    await services_mod._service_send_wol(hass, call_wol)
    c.send_wol.assert_awaited_once_with("lan", "aa:bb:cc:dd:ee:ff")

    # system halt and reboot
    call_sys = MagicMock()
    call_sys.data = {}
    await services_mod._service_system_halt(hass, call_sys)
    c.system_halt.assert_awaited_once()
    await services_mod._service_system_reboot(hass, call_sys)
    c.system_reboot.assert_awaited_once()


@pytest.mark.asyncio
async def test_toggle_alias_success_and_failure(monkeypatch):
    """Toggle alias success and failure paths raise or not appropriately."""
    # success path
    c1 = MagicMock()
    c1.name = "c1"
    c1.toggle_alias = AsyncMock(return_value=True)

    async def fake_get_ok(*args, **kwargs):
        return [c1]

    monkeypatch.setattr(services_mod, "_get_clients", fake_get_ok)
    hass = MagicMock(spec=HomeAssistant)
    hass.data = {DOMAIN: {"e1": c1}}
    call = MagicMock()
    call.data = {"alias": "a1", "toggle_on_off": "on"}
    # should not raise
    await services_mod._service_toggle_alias(hass, call)

    # failure path
    c2 = MagicMock()
    c2.name = "c2"
    c2.toggle_alias = AsyncMock(return_value=False)

    async def fake_get_fail(*args, **kwargs):
        return [c2]

    monkeypatch.setattr(services_mod, "_get_clients", fake_get_fail)
    hass.data = {DOMAIN: {"e2": c2}}
    with pytest.raises(ServiceValidationError):
        await services_mod._service_toggle_alias(hass, call)
