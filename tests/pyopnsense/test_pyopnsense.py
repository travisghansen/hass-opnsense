"""Broad cross-module and e2e-style tests for the composed pyopnsense client."""

from collections.abc import MutableMapping
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

from custom_components.opnsense import (
    device_tracker as device_tracker_mod,
    pyopnsense,
    sensor as sensor_mod,
    switch as switch_mod,
)
from custom_components.opnsense.const import CONF_SYNC_FIREWALL_AND_NAT


@pytest.mark.asyncio
async def test_telemetry_and_temps_and_notices_and_unbound_blocklist(make_client) -> None:
    """Exercise telemetry harvesters, notices and unbound blocklist helper flows."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        # mbuf
        client._safe_list_post = AsyncMock(return_value=[])
        client._safe_dict_post = AsyncMock(
            return_value={"mbuf-statistics": {"mbuf-current": 1, "mbuf-total": 2}}
        )
        mbuf = await client._get_telemetry_mbuf()
        assert mbuf["used"] == 1

        # pfstate
        client._safe_dict_post = AsyncMock(return_value={"current": 1, "limit": 2})
        pf = await client._get_telemetry_pfstate()
        assert pf["used"] == 1

        # memory
        client._use_snake_case = False
        client._safe_dict_post = AsyncMock(
            side_effect=[
                {"memory": {"total": 100, "used": 50}},
                {"swap": [{"total": 10, "used": 5}]},
            ]
        )
        mem = await client._get_telemetry_memory()
        assert mem.get("physmem") == 100

        # temps
        client._use_snake_case = False
        client._safe_list_get = AsyncMock(
            return_value=[
                {"temperature": "30", "type_translated": "T", "device_seq": 1, "device": "dev1"}
            ]
        )
        temps = await client._get_telemetry_temps()
        assert isinstance(temps, MutableMapping)

        # notices
        client._safe_dict_get = AsyncMock(
            return_value={"a": {"statusCode": 1, "message": "m", "timestamp": 0}}
        )
        notices = await client.get_notices()
        assert notices["pending_notices_present"] is True

        # close_notice failure
        client._use_snake_case = True
        client._safe_dict_post = AsyncMock(return_value={"status": "failed"})
        assert await client.close_notice("x") is False

        # unbound blocklist _set when empty
        client.get_unbound_blocklist_legacy = AsyncMock(return_value={})
        assert await client._set_unbound_blocklist_legacy(True) is False
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_generate_vouchers_and_kill_states_toggle_alias(make_client) -> None:
    """Generate vouchers, kill states and toggle alias flows."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    # generate_vouchers when voucher server provided
    data = {"username": 1, "voucher_server": "mysrv"}
    client._safe_list_post = AsyncMock(
        return_value=[
            {
                "username": "u",
                "password": "p",
                "vouchergroup": "g",
                "starttime": 0,
                "expirytime": 0,
                "validity": 60,
            }
        ]
    )
    vouchers = await client.generate_vouchers(data)
    assert isinstance(vouchers, list) and vouchers[0]["username"] == "u"

    # kill_states
    client._safe_dict_post = AsyncMock(return_value={"result": "ok", "dropped_states": 5})
    res = await client.kill_states("1.2.3.4")
    assert res["success"] is True and res["dropped_states"] == 5
    await client.async_close()


@pytest.mark.asyncio
async def test_notices_close_notice_and_unbound_blocklist(make_client) -> None:
    """Test notice listing/closing and the unbound blocklist wrapper helpers."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    # get_notices: no pending
    client._safe_dict_get = AsyncMock(return_value={"a": {"statusCode": 2}})
    notices = await client.get_notices()
    assert notices["pending_notices_present"] is False

    # close_notice: id specific fails
    client._safe_dict_post = AsyncMock(return_value={"status": "failed"})
    ok = await client.close_notice("x")
    assert ok is False

    # close_notice all: iterate and one fails
    client._safe_dict_get = AsyncMock(return_value={"n1": {"statusCode": 1}})
    client._safe_dict_post = AsyncMock(return_value={"status": "failed"})
    ok = await client.close_notice("all")
    assert ok is False

    # set_unbound_blocklist_legacy: return False when get_unbound_blocklist_legacy empty
    client.get_unbound_blocklist_legacy = AsyncMock(return_value={})
    res = await client._set_unbound_blocklist_legacy(True)
    assert res is False

    # enable/disable wrappers
    client._firmware_version = "25.1.0"
    client.get_unbound_blocklist_legacy = AsyncMock(return_value={"enabled": "0", "status": "OK"})
    client._post = AsyncMock(
        side_effect=[
            {"result": "saved"},
            {"response": "OK"},
            {"result": "saved"},
            {"response": "OK"},
        ]
    )
    client._get = AsyncMock(return_value={"status": "OK"})
    client._safe_dict_post = AsyncMock(return_value={"response": "OK"})
    # Call enable/disable; these call _set_unbound_blocklist_legacy which now returns based on our mocks
    res_on = await client.enable_unbound_blocklist()
    res_off = await client.disable_unbound_blocklist()
    assert res_on is True
    assert res_off is True
    await client.async_close()


@pytest.mark.asyncio
async def test_call_many_client_methods_to_exercise_branches(make_client) -> None:
    """Exercise a curated set of public client methods with explicit assertions."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        # Positive: gateway parsing normalizes status strings.
        client._safe_dict_get = AsyncMock(
            return_value={"items": [{"name": "gw1", "status_translated": "Online"}]}
        )
        gateways = await client.get_gateways()
        assert gateways["gw1"]["status"] == "online"

        # Positive + negative: service discovery and running-state lookup.
        client._safe_dict_get = AsyncMock(
            return_value={"rows": [{"name": "svc1", "running": 1, "id": "svc1"}]}
        )
        services = await client.get_services()
        assert len(services) == 1 and services[0]["status"] is True
        assert await client.get_service_is_running("svc1") is True
        assert await client.get_service_is_running("svc2") is False

        # Positive + negative: notice parsing and close behavior.
        client._safe_dict_get = AsyncMock(
            return_value={
                "n1": {
                    "statusCode": 1,
                    "message": "notice",
                    "timestamp": int(datetime.now().timestamp()),
                }
            }
        )
        notices = await client.get_notices()
        assert notices["pending_notices_present"] is True
        client._safe_dict_get = AsyncMock(return_value={"n1": {"statusCode": 1}})
        client._safe_dict_post = AsyncMock(return_value={"status": "ok"})
        assert await client.close_notice("all") is True
        client._safe_dict_post = AsyncMock(return_value={"status": "failed"})
        assert await client.close_notice("n1") is False

        # Negative: unknown VPN type is rejected deterministically.
        assert await client.toggle_vpn_instance("unknown", "servers", "uuid") is False
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_certificates_kill_states_and_unbound_blocklist(make_client) -> None:
    """Cover get_certificates, kill_states and unbound blocklist toggles."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        certs_raw = {
            "rows": [
                {
                    "descr": "cert1",
                    "uuid": "u1",
                    "caref": "ca",
                    "rfc3280_purpose": "srv",
                    "in_use": "1",
                    "valid_from": 1600000000,
                    "valid_to": 1700000000,
                }
            ]
        }

        client._safe_dict_get = AsyncMock(return_value=certs_raw)
        certs = await client.get_certificates()
        assert "cert1" in certs and certs["cert1"]["uuid"] == "u1"

        client._safe_dict_post = AsyncMock(return_value={"result": "ok", "dropped_states": 3})
        res = await client.kill_states("1.2.3.4")
        assert res.get("success") is True and res.get("dropped_states") == 3

        # enable/disable unbound blocklist: patch underlying _set_unbound_blocklist_legacy
        client._set_unbound_blocklist_legacy = AsyncMock(return_value=True)
        assert await client.enable_unbound_blocklist() is True
        assert await client.disable_unbound_blocklist() is True
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_scanner_entity_handle_coordinator_update_missing_state_sets_unavailable(
    make_client,
    make_config_entry,
) -> None:
    """OPNsenseScannerEntity should mark unavailable when coordinator state missing or invalid."""

    # minimal coordinator-like object
    class FakeCoord:
        data: object | None = None

    cfg = make_config_entry()
    coord = FakeCoord()
    ent = device_tracker_mod.OPNsenseScannerEntity(
        config_entry=cfg,
        coordinator=coord,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )
    # ensure async_write_ha_state won't raise due to missing hass during unit test
    ent.hass = MagicMock()
    ent.async_write_ha_state = MagicMock()
    ent._handle_coordinator_update()
    assert ent._available is False


@pytest.mark.asyncio
async def test_compile_filesystem_sensors_and_filter_switches(make_config_entry) -> None:
    """Test sensor and switch compilation helpers for simple cases."""
    # Use the public async_setup_entry to exercise creation rather than
    # directly calling private helpers. Create a minimal config entry and
    # coordinator for the setup path.
    cfg = make_config_entry()
    coord = MagicMock()
    setattr(cfg.runtime_data, "coordinator", coord)

    # filesystem sensors: invalid state -> setup should not create filesystem entities
    coord.data = None
    created: list = []

    async def run_setup():
        """Run setup."""

        def add_entities(ents):
            """Add entities.

            Args:
                ents: Ents provided by pytest or the test case.
            """
            created.extend(ents)

        await sensor_mod.async_setup_entry(MagicMock(), cfg, add_entities)

    await run_setup()
    assert created == []

    # valid filesystem state -> expect filesystem entities created
    state = {"telemetry": {"filesystems": [{"mountpoint": "/"}]}}
    coord.data = state
    created = []
    await run_setup()
    assert isinstance(created, list) and len(created) >= 1

    # filter switches: validate via public switch setup path as a smoke test
    state2 = {
        "host_firmware_version": "25.7.8",
        "firewall": {
            "config": {
                "filter": {
                    "rule": [
                        {"description": "Anti-Lockout Rule", "created": {"time": "t1"}},
                        {
                            "description": "Normal",
                            "created": {"time": "t2"},
                            "associated-rule-id": "r1",
                        },
                        {"description": "Ok", "created": {"time": "t3"}},
                    ]
                }
            }
        },
    }
    # prepare a switch config entry with filter sync enabled
    switch_cfg = make_config_entry(
        data={
            "device_unique_id": "dev1",
            CONF_SYNC_FIREWALL_AND_NAT: True,
            "sync_unbound": False,
            "sync_vpn": False,
            "sync_services": False,
        }
    )
    setattr(switch_cfg.runtime_data, "coordinator", coord)
    coord.data = state2
    created_switches: list = []

    async def run_switch_setup():
        """Run switch setup."""

        def add_switches(ents):
            """Add switches.

            Args:
                ents: Ents provided by pytest or the test case.
            """
            created_switches.extend(ents)

        await switch_mod.async_setup_entry(MagicMock(), switch_cfg, add_switches)

    await run_switch_setup()
    # Only one valid filter rule should produce a switch entity
    assert isinstance(created_switches, list) and len(created_switches) == 1


@pytest.mark.asyncio
async def test_exercise_many_misc_branches() -> None:
    """Call many client methods with patched internals to exercise branches en-masse."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        # firmware update info: set product_latest > product_version and matching status_msg
        status = {
            "product": {"product_version": "1.0.0", "product_latest": "2.0.0", "product_check": {}},
            "status_msg": "There are no updates available on the selected mirror.",
            "last_check": None,
        }
        client._safe_dict_get = AsyncMock(return_value=status)
        client._post = AsyncMock(return_value={})
        await client.get_firmware_update_info()
        client._post.assert_awaited_once()

        # telemetry system with valid boottime string and uptime regex
        ti = {
            "datetime": datetime.now().isoformat(),
            "uptime": "1 days, 01:02:03",
            "boottime": (datetime.now() - timedelta(days=1)).isoformat(),
            "loadavg": "1, 2, 3",
        }
        client._safe_dict_post = AsyncMock(return_value=ti)
        sys = await client._get_telemetry_system()
        assert isinstance(sys, MutableMapping)

        # reload_interface paths (snake_case vs camelCase)
        client._use_snake_case = True
        client._safe_dict_post = AsyncMock(return_value={"message": "OK"})
        assert await client.reload_interface("em0") is True
        client._use_snake_case = False
        client._safe_dict_post = AsyncMock(return_value={"message": "OK"})
        assert await client.reload_interface("em0") is True

        # toggle_vpn_instance unknown type should return False
        assert await client.toggle_vpn_instance("unknown", "servers", "u1") is False

        # call get_telemetry which will invoke many telemetry subcalls; patch them to return simple values
        client._get_telemetry_mbuf = AsyncMock(return_value={})
        client._get_telemetry_pfstate = AsyncMock(return_value={})
        client._get_telemetry_memory = AsyncMock(return_value={})
        client._get_telemetry_system = AsyncMock(return_value={})
        client._get_telemetry_cpu = AsyncMock(return_value={})
        client._get_telemetry_filesystems = AsyncMock(return_value={})
        client._get_telemetry_temps = AsyncMock(return_value={})
        telem = await client.get_telemetry()
        assert isinstance(telem, MutableMapping)

        # call get_openvpn with empty dicts to exercise early return and processing functions
        client._safe_dict_get = AsyncMock(
            side_effect=[{"rows": []}, {"rows": []}, {}, {"rows": []}, {}]
        )
        res = await client.get_openvpn()
        assert isinstance(res, MutableMapping)
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_arp_table_and_manage_service_upgrade_flow() -> None:
    """Test get_arp_table and upgrade_firmware branches for update/upgrade."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        # ARP table
        client._safe_dict_post = AsyncMock(
            return_value={
                "rows": [{"ip-address": "1.2.3.4", "mac-address": "aa:bb:cc", "hostname": "h"}]
            }
        )
        arp = await client.get_arp_table(resolve_hostnames=True)
        assert isinstance(arp, list) and arp[0].get("ip-address") == "1.2.3.4"

        # upgrade_firmware: update -> calls safe_list_post
        client._safe_dict_post = AsyncMock(return_value={"status": "ok"})
        res = await client.upgrade_firmware("update")
        assert isinstance(res, MutableMapping)

        # upgrade_firmware: unknown type returns None
        assert await client.upgrade_firmware("noop") is None
    finally:
        await client.async_close()
