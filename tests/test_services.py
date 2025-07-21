from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from custom_components.opnsense import services as services_mod
from custom_components.opnsense.const import DOMAIN
from custom_components.opnsense.pyopnsense import VoucherServerError
from homeassistant.exceptions import ServiceValidationError


@pytest.mark.asyncio
async def test_get_clients_single_and_multiple(monkeypatch):
    # use a plain hass-like object so .data is a real dict
    hass_local = SimpleNamespace()
    client = SimpleNamespace(name="one")
    hass_local.data = {DOMAIN: {"e1": client}}
    res = await services_mod._get_clients(hass_local)
    assert res == [client]

    # multiple entries and filter by device_id
    client2 = SimpleNamespace(name="two")
    hass_local.data[DOMAIN] = {"e1": client, "e2": client2}

    class DevReg:
        def async_get(self, device_id):
            return SimpleNamespace(primary_config_entry="e2")

    monkeypatch.setattr(services_mod.dr, "async_get", lambda hass_in: DevReg())
    res = await services_mod._get_clients(hass_local, opndevice_id="dev123")
    assert res == [client2]

    # filter by entity_id
    class EntReg:
        def async_get(self, entity_id):
            return SimpleNamespace(config_entry_id="e1")

    monkeypatch.setattr(services_mod.er, "async_get", lambda hass_in: EntReg())
    res = await services_mod._get_clients(hass_local, opnentity_id="ent123")
    assert res == [client]


@pytest.mark.asyncio
async def test_service_start_stop_restart_success_and_failure(monkeypatch, hass):
    # prepare two clients: first returns False then second True
    hass.data = {}
    # make both clients return True initially so the service calls succeed
    c1 = SimpleNamespace(
        name="c1",
        start_service=AsyncMock(return_value=True),
        stop_service=AsyncMock(return_value=True),
        restart_service=AsyncMock(return_value=True),
        restart_service_if_running=AsyncMock(return_value=True),
    )
    c2 = SimpleNamespace(
        name="c2",
        start_service=AsyncMock(return_value=True),
        stop_service=AsyncMock(return_value=True),
        restart_service=AsyncMock(return_value=True),
        restart_service_if_running=AsyncMock(return_value=True),
    )
    hass.data[DOMAIN] = {"e1": c1, "e2": c2}

    call = SimpleNamespace(data={"service_id": "svc"})

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

    # now make both clients fail for start -> should raise
    c1.start_service = AsyncMock(return_value=False)
    c2.start_service = AsyncMock(return_value=False)
    with pytest.raises(ServiceValidationError):
        await services_mod._service_start_service(hass, call)


@pytest.mark.asyncio
async def test_service_restart_only_if_running_and_reload_interface(monkeypatch, hass):
    c1 = SimpleNamespace(
        name="c1",
        restart_service_if_running=AsyncMock(return_value=True),
        restart_service=AsyncMock(return_value=True),
        reload_interface=AsyncMock(return_value=True),
    )
    hass.data = {}
    hass.data[DOMAIN] = {"e1": c1}
    call = SimpleNamespace(data={"service_id": "svc", "only_if_running": True})

    async def fake_get(*args, **kwargs):
        return [c1]

    monkeypatch.setattr(services_mod, "_get_clients", fake_get)
    # should not raise
    await services_mod._service_restart_service(hass, call)

    # reload_interface success
    call_iface = SimpleNamespace(data={"interface": "igb0"})
    await services_mod._service_reload_interface(hass, call_iface)

    # reload_interface failure should raise
    c1.reload_interface = AsyncMock(return_value=False)
    with pytest.raises(ServiceValidationError):
        await services_mod._service_reload_interface(hass, call_iface)


@pytest.mark.asyncio
async def test_generate_vouchers_success_and_server_error(monkeypatch, hass):
    hass.data = {}
    # client returns a list of mapping vouchers
    vouchers = [{"code": "A1"}, {"code": "B2"}]
    c1 = SimpleNamespace(name="svc1", generate_vouchers=AsyncMock(return_value=vouchers))
    hass.data[DOMAIN] = {"e1": c1}
    call = SimpleNamespace(
        data={"validity": "1", "expirytime": "2", "count": "2", "vouchergroup": "g1"}
    )

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
async def test_kill_states_success_and_failure(monkeypatch, hass):
    hass.data = {}
    c1 = SimpleNamespace(
        name="c1", kill_states=AsyncMock(return_value={"success": True, "dropped_states": 5})
    )
    hass.data[DOMAIN] = {"e1": c1}
    call = SimpleNamespace(data={"ip_addr": "1.2.3.4"})

    async def fake_get(*args, **kwargs):
        return [c1]

    monkeypatch.setattr(services_mod, "_get_clients", fake_get)
    resp = await services_mod._service_kill_states(hass, call)
    assert "dropped_states" in resp

    # failure -> raise
    c1.kill_states = AsyncMock(return_value={"success": False})
    with pytest.raises(ServiceValidationError):
        await services_mod._service_kill_states(hass, call)


@pytest.mark.asyncio
async def test_toggle_alias_failure(monkeypatch, hass):
    hass.data = {}
    c1 = SimpleNamespace(name="c1", toggle_alias=AsyncMock(return_value=False))
    hass.data[DOMAIN] = {"e1": c1}
    call = SimpleNamespace(data={"alias": "a1", "toggle_on_off": "toggle"})

    async def fake_get(*args, **kwargs):
        return [c1]

    monkeypatch.setattr(services_mod, "_get_clients", fake_get)
    with pytest.raises(ServiceValidationError):
        await services_mod._service_toggle_alias(hass, call)


@pytest.mark.asyncio
async def test_get_clients_no_data_returns_empty():
    hass = SimpleNamespace()
    hass.data = {}
    res = await services_mod._get_clients(hass)
    assert res == []


@pytest.mark.asyncio
async def test_close_send_wol_and_system_calls(monkeypatch):
    # single client that should receive calls
    c = SimpleNamespace(
        name="one",
        close_notice=AsyncMock(return_value=None),
        send_wol=AsyncMock(return_value=None),
        system_halt=AsyncMock(return_value=None),
        system_reboot=AsyncMock(return_value=None),
    )

    async def fake_get(*args, **kwargs):
        return [c]

    monkeypatch.setattr(services_mod, "_get_clients", fake_get)

    hass = SimpleNamespace()
    hass.data = {DOMAIN: {"e1": c}}

    # close notice
    call = SimpleNamespace(data={"id": "all"})
    await services_mod._service_close_notice(hass, call)
    c.close_notice.assert_called()

    # send wol
    call_wol = SimpleNamespace(data={"interface": "lan", "mac": "aa:bb:cc:dd:ee:ff"})
    await services_mod._service_send_wol(hass, call_wol)
    c.send_wol.assert_called()

    # system halt and reboot
    call_sys = SimpleNamespace(data={})
    await services_mod._service_system_halt(hass, call_sys)
    c.system_halt.assert_called()
    await services_mod._service_system_reboot(hass, call_sys)
    c.system_reboot.assert_called()


@pytest.mark.asyncio
async def test_toggle_alias_success_and_failure(monkeypatch):
    # success path
    c1 = SimpleNamespace(name="c1", toggle_alias=AsyncMock(return_value=True))

    async def fake_get_ok(*args, **kwargs):
        return [c1]

    monkeypatch.setattr(services_mod, "_get_clients", fake_get_ok)
    hass = SimpleNamespace()
    hass.data = {DOMAIN: {"e1": c1}}
    call = SimpleNamespace(data={"alias": "a1", "toggle_on_off": "toggle"})
    # should not raise
    await services_mod._service_toggle_alias(hass, call)

    # failure path
    c2 = SimpleNamespace(name="c2", toggle_alias=AsyncMock(return_value=False))

    async def fake_get_fail(*args, **kwargs):
        return [c2]

    monkeypatch.setattr(services_mod, "_get_clients", fake_get_fail)
    hass.data = {DOMAIN: {"e2": c2}}
    with pytest.raises(ServiceValidationError):
        await services_mod._service_toggle_alias(hass, call)
