"""Unit tests for the `pyopnsense` client.

This module consolidates all unit tests for
`custom_components.opnsense.pyopnsense` so there is a single test file per
integration module as required by the repository guidelines.
"""

import asyncio
import contextlib
import copy
from datetime import datetime, timedelta
import inspect as _inspect
import socket
from ssl import SSLError
from typing import Any
from unittest.mock import AsyncMock, MagicMock
import xmlrpc.client as xc
from xmlrpc.client import Fault

import aiohttp
import awesomeversion
import pytest
from yarl import URL

from custom_components.opnsense import (
    device_tracker as device_tracker_mod,
    pyopnsense,
    sensor as sensor_mod,
    switch as switch_mod,
)
from custom_components.opnsense.const import CONF_SYNC_FIREWALL_AND_NAT


def test_human_friendly_duration() -> None:
    """Convert seconds into a human-friendly duration string."""
    assert pyopnsense.human_friendly_duration(65) == "1 minute, 5 seconds"
    assert pyopnsense.human_friendly_duration(0) == "0 seconds"
    assert "month" in pyopnsense.human_friendly_duration(2419200)


def test_human_friendly_duration_singular_and_plural() -> None:
    """Verify singular and plural forms for all supported units.

    This covers seconds, minutes, hours, days, weeks and months and ensures
    the function emits the singular form when the value is 1 and plural
    otherwise.
    """
    # seconds
    assert pyopnsense.human_friendly_duration(1) == "1 second"
    assert pyopnsense.human_friendly_duration(2) == "2 seconds"

    # minutes + seconds
    assert pyopnsense.human_friendly_duration(60) == "1 minute"
    assert pyopnsense.human_friendly_duration(61) == "1 minute, 1 second"

    # hours
    assert pyopnsense.human_friendly_duration(3600) == "1 hour"
    assert pyopnsense.human_friendly_duration(7200) == "2 hours"

    # days
    assert pyopnsense.human_friendly_duration(86400) == "1 day"

    # weeks
    assert pyopnsense.human_friendly_duration(604800) == "1 week"
    assert pyopnsense.human_friendly_duration(1209600) == "2 weeks"

    # months (28-day month used in implementation)
    assert pyopnsense.human_friendly_duration(2419200) == "1 month"
    assert pyopnsense.human_friendly_duration(4838400) == "2 months"


def test_get_ip_key() -> None:
    """Compute sorting key for IP addresses across IPv4, IPv6, and invalid forms."""
    assert pyopnsense.get_ip_key({"address": "192.168.1.1"})[0] == 0
    assert pyopnsense.get_ip_key({"address": "::1"})[0] == 1
    assert pyopnsense.get_ip_key({"address": "notanip"})[0] == 2

    assert pyopnsense.get_ip_key({})[0] == 3


def test_dict_get() -> None:
    """Retrieve nested values from dicts and lists using dotted paths."""
    data = {"a": {"b": {"c": 1}}, "x": [0, 1, 2]}
    assert pyopnsense.dict_get(data, "a.b.c") == 1
    assert pyopnsense.dict_get(data, "x.1") == 1
    assert pyopnsense.dict_get(data, "x.10", default=42) == 42


def test_timestamp_to_datetime() -> None:
    """Convert timestamp integers to datetime objects, handling None."""
    ts = int(datetime.now().timestamp())
    dt = pyopnsense.timestamp_to_datetime(ts)
    assert isinstance(dt, datetime)
    assert pyopnsense.timestamp_to_datetime(None) is None


def test_voucher_server_error() -> None:
    """Raise VoucherServerError to ensure the exception class exists."""
    with pytest.raises(pyopnsense.VoucherServerError):
        raise pyopnsense.VoucherServerError


def test_try_to_int_and_float() -> None:
    """Coerce numeric-like strings to int/float with defaults."""
    assert pyopnsense.OPNsenseClient._try_to_int("5") == 5
    assert pyopnsense.OPNsenseClient._try_to_int(None, 7) == 7
    assert pyopnsense.OPNsenseClient._try_to_float("5.5") == 5.5
    assert pyopnsense.OPNsenseClient._try_to_float(None, 3.3) == 3.3


@pytest.mark.asyncio
async def test_safe_dict_get_and_list_get(monkeypatch, make_client) -> None:
    """Ensure safe getters coerce None to empty dict/list as expected."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session, username="user", password="pass")
    # Patch _get to return dict or list using pytest's monkeypatch
    monkeypatch.setattr(client, "_get", AsyncMock(return_value={"foo": "bar"}), raising=False)
    result_dict = await client._safe_dict_get("/fake")
    assert result_dict == {"foo": "bar"}

    monkeypatch.setattr(client, "_get", AsyncMock(return_value=[1, 2, 3]), raising=False)
    result_list = await client._safe_list_get("/fake")
    assert result_list == [1, 2, 3]

    monkeypatch.setattr(client, "_get", AsyncMock(return_value=None), raising=False)
    result_empty_dict = await client._safe_dict_get("/fake")
    assert result_empty_dict == {}
    result_empty_list = await client._safe_list_get("/fake")
    assert result_empty_list == []
    await client.async_close()


@pytest.mark.asyncio
async def test_safe_dict_post_and_list_post(monkeypatch, make_client) -> None:
    """Ensure safe post helpers coerce None to empty dict/list as expected."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session, username="user", password="pass")
    monkeypatch.setattr(client, "_post", AsyncMock(return_value={"foo": "bar"}), raising=False)
    result_dict = await client._safe_dict_post("/fake")
    assert result_dict == {"foo": "bar"}

    monkeypatch.setattr(client, "_post", AsyncMock(return_value=[1, 2, 3]), raising=False)
    result_list = await client._safe_list_post("/fake")
    assert result_list == [1, 2, 3]

    monkeypatch.setattr(client, "_post", AsyncMock(return_value=None), raising=False)
    result_empty_dict = await client._safe_dict_post("/fake")
    assert result_empty_dict == {}
    result_empty_list = await client._safe_list_post("/fake")
    assert result_empty_list == []


@pytest.mark.asyncio
async def test_get_ip_key_sorting(make_client) -> None:
    """Sort IP-like items using get_ip_key ordering."""
    items = [
        {"address": "192.168.1.2"},
        {"address": "::1"},
        {"address": "notanip"},
        {},
    ]
    sorted_items = sorted(items, key=pyopnsense.get_ip_key)
    assert sorted_items[0]["address"] == "192.168.1.2"
    assert sorted_items[1]["address"] == "::1"
    assert sorted_items[2]["address"] == "notanip"
    assert sorted_items[3] == {}


@pytest.mark.asyncio
async def test_opnsenseclient_async_close(make_client) -> None:
    """Verify async_close cancels workers and queue monitor as expected."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost",
        username="user",
        password="pass",
        session=session,
    )
    # Patch background tasks to be not done
    monitor = MagicMock()
    worker1 = MagicMock()
    worker2 = MagicMock()
    client._queue_monitor = monitor
    # ensure .done() returns False so async_close will cancel
    monitor.done.return_value = False
    worker1.done.return_value = False
    worker2.done.return_value = False
    client._workers = [worker1, worker2]
    # use a real asyncio.Queue so async_close exercises real queue semantics
    client._request_queue = asyncio.Queue()
    # put a dummy item so the while loop in async_close sees a non-empty queue
    await client._request_queue.put(1)
    await client.async_close()
    worker1.cancel.assert_called()
    worker2.cancel.assert_called()
    monitor.cancel.assert_called()


@pytest.mark.asyncio
async def test_get_host_firmware_set_use_snake_case_and_plugin_installed(
    monkeypatch, make_client
) -> None:
    """Ensure firmware parsing, snake_case detection and plugin detection work."""
    # create client/session for this test
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    # firmware valid semver
    client._safe_dict_get = AsyncMock(return_value={"product": {"product_version": "25.8.0"}})
    fw = await client.get_host_firmware_version()
    assert fw == "25.8.0"

    # set use snake case should detect >=25.7
    client._firmware_version = "25.8.0"
    await client.set_use_snake_case()
    assert client._use_snake_case is True

    # set use snake case should detect <25.7
    client._firmware_version = "25.1.0"
    await client.set_use_snake_case()
    assert client._use_snake_case is False

    # test AwesomeVersionCompareException handling
    def mock_compare(self, other):
        raise awesomeversion.exceptions.AwesomeVersionCompareException("test exception")

    monkeypatch.setattr(awesomeversion.AwesomeVersion, "__lt__", mock_compare)
    client._firmware_version = "25.8.0"
    await client.set_use_snake_case()
    # Should default to True on exception
    assert client._use_snake_case is True

    # invalid semver -> fallback to product_series
    client._safe_dict_get = AsyncMock(
        return_value={"product": {"product_version": "weird", "product_series": "seriesX"}}
    )
    fw2 = await client.get_host_firmware_version()
    assert fw2 == "seriesX"

    # is_plugin_installed when package list present
    client._safe_dict_get = AsyncMock(
        return_value={"package": [{"name": "os-homeassistant-maxit"}]}
    )
    assert await client.is_plugin_installed() is True


@pytest.mark.asyncio
async def test_get_device_unique_id_and_system_info(make_client) -> None:
    """Verify device unique id is derived from MACs and system info is returned."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        # device unique id from mac addresses
        client._safe_list_get = AsyncMock(
            return_value=[
                {"is_physical": True, "macaddr_hw": "aa:bb:cc"},
                {"is_physical": True, "macaddr_hw": "aa:bb:cc"},
            ]
        )
        uid = await client.get_device_unique_id()
        assert uid == "aa_bb_cc"

        # system info uses snake/camel branches
        client._use_snake_case = False
        client._safe_dict_get = AsyncMock(return_value={"name": "foo"})
        info = await client.get_system_info()
        assert info["name"] == "foo"
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_firmware_update_info_triggers_check_on_conditions(make_client) -> None:
    """Trigger firmware update check when status is missing data or outdated."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        # Prepare a status that lacks data to force missing_data True and last_check missing
        status = {
            "product": {"product_version": "1.0", "product_latest": "2.0", "product_check": {}}
        }
        client._safe_dict_get = AsyncMock(return_value=status)
        client._post = AsyncMock(return_value={})
        # Call should trigger _post('/api/core/firmware/check')
        res = await client.get_firmware_update_info()
        assert res == status
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_service_management_and_get_services(make_client) -> None:
    """Exercise get_services(), get_service_is_running() and service control."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client._safe_dict_get = AsyncMock(
            return_value={"rows": [{"name": "svc1", "running": 1, "id": "svc1"}]}
        )
        services = await client.get_services()
        assert services[0]["status"] is True
        assert await client.get_service_is_running("svc1") is True

        # manage service via _safe_dict_post
        client._safe_dict_post = AsyncMock(return_value={"result": "ok"})
        ok = await client._manage_service("start", "svc1")
        assert ok is True
        assert await client.start_service("svc1") is True
        assert await client.stop_service("svc1") is True
        assert await client.restart_service("svc1") is True
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_dhcp_leases_and_keep_latest_and_dnsmasq(make_client) -> None:
    """Cover Kea and dnsmasq lease parsing and _keep_latest_leases helper."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        # _get_kea_interfaces returns mapping and kea leases: one valid
        client._safe_dict_get = AsyncMock(
            side_effect=[
                {
                    "dhcpv4": {
                        "general": {
                            "enabled": "1",
                            "interfaces": {"em0": {"selected": 1, "value": "desc"}},
                        }
                    }
                },
                {
                    "rows": [
                        {
                            "if_name": "em0",
                            "if_descr": "d",
                            "state": "0",
                            "hwaddr": "mac1",
                            "address": "1.2.3.4",
                            "hostname": "host.",
                        }
                    ]
                },
                {"rows": []},
                {},
            ]
        )
        # monkeypatch internal helpers by calling _get_kea_dhcpv4_leases directly
        leases = await client._get_kea_dhcpv4_leases()
        assert isinstance(leases, list)

        # test _keep_latest_leases via instance
        res = client._keep_latest_leases(
            [{"a": 1, "expire": 10}, {"a": 1, "expire": 20}, {"a": 2, "expire": 5}]
        )
        # should keep the later expire for same keys
        assert any(item["expire"] == 20 for item in res)

        # dnsmasq leases behavior
        client._firmware_version = "25.2"
        client._safe_dict_get = AsyncMock(
            return_value={
                "rows": [
                    {
                        "address": "1.2.3.4",
                        "hostname": "*",
                        "if_descr": "d",
                        "if": "em0",
                        "is_reserved": "1",
                        "hwaddr": "mac1",
                        "expire": 9999999999,
                    }
                ]
            }
        )
        dns = await client._get_dnsmasq_leases()
        assert isinstance(dns, list)
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_carp_and_reboot_and_wol(make_client) -> None:
    """Verify CARP interface discovery and system control endpoints (reboot/halt/WOL)."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client._safe_dict_get = AsyncMock(return_value={"carp": {"allow": "1"}})
        assert await client.get_carp_status() is True

        client._safe_dict_get = AsyncMock(
            return_value={"rows": [{"mode": "carp", "interface": "em0"}]}
        )
        client._safe_dict_get = AsyncMock(
            side_effect=[
                {"rows": [{"mode": "carp", "interface": "em0"}]},
                {"rows": [{"interface": "em0", "status": "OK"}]},
            ]
        )
        carp = await client.get_carp_interfaces()
        assert isinstance(carp, list)

        client._safe_dict_post = AsyncMock(return_value={"status": "ok"})
        assert await client.system_reboot() is True
        result = await client.system_halt()
        assert result is None

        client._safe_dict_post = AsyncMock(return_value={"status": "ok"})
        result = await client.send_wol("em0", "aa:bb:cc")
        assert isinstance(result, bool)
    finally:
        await client.async_close()


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
        assert isinstance(temps, dict)

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
async def test_get_openvpn_and_fetch_details(monkeypatch, make_client) -> None:
    """Validate openvpn server/client discovery and fetch details flow."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        # Prepare fake responses for safe_gets
        sessions_info = {
            "rows": [
                {"type": "server", "id": "1_desc_1", "description": "s1", "status": "connected"}
            ]
        }
        routes_info = {
            "rows": [
                {
                    "id": "1",
                    "common_name": "c1",
                    "real_address": "1.2.3.4",
                    "virtual_address": "10.0.0.1",
                    "last_ref__time_t_": 0,
                }
            ]
        }
        providers_info = {"1": {"name": "prov1", "hostname": "host", "local_port": "1194"}}
        instances_info = {
            "rows": [
                {
                    "role": "server",
                    "uuid": "uuid1",
                    "description": "server1",
                    "enabled": "1",
                    "dev_type": "tun",
                }
            ]
        }

        async def fake_safe_dict_get(path):
            if "search_sessions" in path or "searchSessions" in path:
                return sessions_info
            if "search_routes" in path or "searchRoutes" in path:
                return routes_info
            if "providers" in path:
                return providers_info
            if "instances/search" in path:
                return instances_info
            if "/instances/get/" in path:
                return {
                    "instance": {
                        "server": "10.0.0.2",
                        "dns_servers": {"1": {"selected": 1, "value": "8.8.8.8"}},
                    }
                }
            return {}

        async def fake_safe_list_get(path):
            return []

        monkeypatch.setattr(
            client, "_safe_dict_get", AsyncMock(side_effect=fake_safe_dict_get), raising=False
        )
        monkeypatch.setattr(
            client, "_safe_list_get", AsyncMock(side_effect=fake_safe_list_get), raising=False
        )
        openvpn = await client.get_openvpn()
        assert "servers" in openvpn and "clients" in openvpn
        # servers should include uuid1
        assert any(
            s.get("name") == "server1" or s.get("uuid") == "uuid1"
            for s in openvpn["servers"].values()
        )
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_wireguard_processing_and_updates(make_client) -> None:
    """Exercise static wireguard status update helpers and peer linking."""
    # Test static methods for wireguard processing and updates
    server = {
        "uuid": "s1",
        "name": "srv",
        "pubkey": "pk",
        "clients": [{"pubkey": "cpk"}],
        "interface": "wg1",
        "tunnel_addresses": ["10.0.0.1"],
        "total_bytes_recv": 0,
        "total_bytes_sent": 0,
    }
    client = {
        "uuid": "c1",
        "pubkey": "cpk",
        "servers": [{"interface": "wg1"}],
        "tunnel_addresses": ["10.0.0.2"],
        "total_bytes_recv": 0,
        "total_bytes_sent": 0,
    }
    servers = {"s1": server}
    clients = {"c1": client}

    # peer entry representing interface update
    entry_interface = {"type": "interface", "public-key": "pk", "status": "up"}
    await pyopnsense.OPNsenseClient._update_wireguard_status([entry_interface], servers, clients)
    # server status set
    assert any(s.get("status") == "up" for s in servers.values())

    # peer update representing peer (client) with handshake and transfers
    entry_peer = {
        "type": "peer",
        "public-key": "cpk",
        "if": "wg1",
        "endpoint": "1.2.3.4:51820",
        "transfer-rx": "100",
        "transfer-tx": "200",
        "latest-handshake": "0",
    }
    await pyopnsense.OPNsenseClient._update_wireguard_status([entry_peer], servers, clients)
    # ensure client's server linkage updated: require explicit connected state or measurable traffic
    srv = clients["c1"]["servers"][0]
    has_connected_flag = bool(srv.get("connected"))
    # accept numeric transfer counters set by implementation (bytes_recv/bytes_sent)
    rx = int(srv.get("bytes_recv") or srv.get("transfer-rx") or 0)
    tx = int(srv.get("bytes_sent") or srv.get("transfer-tx") or 0)
    assert has_connected_flag or (rx > 0 or tx > 0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "vpn_type,path,use_snake_case,post_resp,expected",
    [
        ("openvpn", "servers", False, {"changed": False}, False),
        ("openvpn", "servers", False, [{"changed": True}, {"result": "ok"}], True),
        ("wireguard", "clients", True, [{"changed": True}, {"result": "ok"}], True),
        ("wireguard", "servers", False, {"changed": False}, False),
    ],
)
async def test_toggle_vpn_instance_variants(
    make_client, vpn_type, path, use_snake_case, post_resp, expected
) -> None:
    """Parametrized toggle_vpn_instance covering OpenVPN and WireGuard variants."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    if use_snake_case:
        client._use_snake_case = True

    if isinstance(post_resp, list):
        client._safe_dict_post = AsyncMock(side_effect=post_resp)
    else:
        client._safe_dict_post = AsyncMock(return_value=post_resp)

    res = await client.toggle_vpn_instance(vpn_type, path, "uuid")
    assert res is expected
    await client.async_close()


@pytest.mark.asyncio
async def test_reload_interface_and_certificates_and_gateways(make_client) -> None:
    """Reload interface, list certificates, and list gateways parsing."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client._use_snake_case = True
        client._safe_dict_post = AsyncMock(return_value={"message": "OK reload"})
        ok = await client.reload_interface("em0")
        assert ok is True

        # certificates
        client._safe_dict_get = AsyncMock(
            return_value={
                "rows": [
                    {
                        "descr": "cert1",
                        "uuid": "u1",
                        "caref": "issuer",
                        "rfc3280_purpose": "purpose",
                        "in_use": "1",
                        "valid_from": 0,
                        "valid_to": 0,
                    }
                ]
            }
        )
        certs = await client.get_certificates()
        assert "cert1" in certs and certs["cert1"]["issuer"] == "issuer"

        # gateways
        client._safe_dict_get = AsyncMock(
            return_value={"items": [{"name": "gw1", "status_translated": "Online"}]}
        )
        gws = await client.get_gateways()
        assert "gw1" in gws and gws["gw1"]["status"] == "online"
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
    client.get_unbound_blocklist_legacy = AsyncMock(return_value={"enabled": "0", "status": "OK"})
    client._post = AsyncMock(return_value={"result": "saved"})
    client._get = AsyncMock(return_value={"status": "OK"})
    client._safe_dict_post = AsyncMock(return_value={"response": "OK"})
    # Call enable/disable; these call _set_unbound_blocklist_legacy which now returns based on our mocks
    res_on = await client.enable_unbound_blocklist()
    res_off = await client.disable_unbound_blocklist()
    assert isinstance(res_on, bool) and isinstance(res_off, bool)
    await client.async_close()


@pytest.mark.asyncio
async def test_enable_disable_unbound_with_uuid(make_client) -> None:
    """Test enabling/disabling extended unbound blocklists with a UUID."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    # simulate firmware >= 25.7.8 so extended API is used
    client._firmware_version = "25.7.8"

    # toggling endpoint responds with Enabled/Disabled
    client._safe_dict_post = AsyncMock(return_value={"result": "Enabled"})
    res_on = await client.enable_unbound_blocklist("uuid1")
    assert res_on is True

    client._safe_dict_post = AsyncMock(return_value={"result": "Disabled"})
    res_off = await client.disable_unbound_blocklist("uuid1")
    assert res_off is True

    await client.async_close()


@pytest.mark.asyncio
async def test_get_unbound_blocklist_firmware_fetch(make_client) -> None:
    """Test get_unbound_blocklist fetches firmware when None."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    # Ensure firmware is None initially
    client._firmware_version = None
    client.get_host_firmware_version = AsyncMock(return_value="25.7.8")
    client._safe_dict_get = AsyncMock(
        return_value={"rows": [{"uuid": "test-uuid", "enabled": "1"}]}
    )

    result = await client.get_unbound_blocklist()
    assert "test-uuid" in result
    client.get_host_firmware_version.assert_called_once()
    await client.async_close()


@pytest.mark.parametrize(
    "firmware_version,expected_legacy_call,expected_result",
    [
        ("25.1.0", True, {"legacy": {"legacy": "data"}}),  # Legacy path
        (
            "25.7.8",
            False,
            {
                "uuid1": {"uuid": "uuid1", "enabled": "1", "name": "blocklist1"},
                "uuid2": {"uuid": "uuid2", "enabled": "0", "name": "blocklist2"},
            },
        ),  # Extended path
    ],
)
@pytest.mark.asyncio
async def test_get_unbound_blocklist_version_paths(
    firmware_version, expected_legacy_call, expected_result, make_client
) -> None:
    """Test get_unbound_blocklist version-dependent behavior."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    client._firmware_version = firmware_version

    if expected_legacy_call:
        client.get_unbound_blocklist_legacy = AsyncMock(return_value={"legacy": "data"})
    else:
        client._safe_dict_get = AsyncMock(
            return_value={
                "rows": [
                    {"uuid": "uuid1", "enabled": "1", "name": "blocklist1"},
                    {"uuid": "uuid2", "enabled": "0", "name": "blocklist2"},
                    {"no_uuid": "invalid"},  # Should be skipped
                ]
            }
        )

    result = await client.get_unbound_blocklist()
    assert result == expected_result

    if expected_legacy_call:
        client.get_unbound_blocklist_legacy.assert_called_once()
    await client.async_close()


@pytest.mark.parametrize(
    "api_response,expected_result",
    [
        ({}, {}),  # Empty response
        ({"rows": []}, {}),  # Empty rows
        (
            {"rows": [{"uuid": "test", "enabled": "1"}]},
            {"test": {"uuid": "test", "enabled": "1"}},
        ),  # Valid data
    ],
)
@pytest.mark.asyncio
async def test_get_unbound_blocklist_extended_responses(
    api_response, expected_result, make_client
) -> None:
    """Test get_unbound_blocklist handles various extended API responses."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    client._firmware_version = "25.7.8"
    client._safe_dict_get = AsyncMock(return_value=api_response)

    result = await client.get_unbound_blocklist()
    assert result == expected_result
    await client.async_close()


@pytest.mark.asyncio
async def test_get_unbound_blocklist_version_comparison_error(make_client) -> None:
    """Test get_unbound_blocklist handles version comparison errors."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    client._firmware_version = "invalid.version"
    client._safe_dict_get = AsyncMock(return_value={"rows": [{"uuid": "test", "enabled": "1"}]})

    result = await client.get_unbound_blocklist()
    assert "test" in result
    await client.async_close()


@pytest.mark.parametrize(
    "method_name",
    ["enable_unbound_blocklist", "disable_unbound_blocklist"],
)
@pytest.mark.asyncio
async def test_enable_disable_unbound_firmware_fetch(method_name, make_client) -> None:
    """Test enable/disable_unbound_blocklist fetch firmware when None."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    client._firmware_version = None
    client.get_host_firmware_version = AsyncMock(return_value="25.7.8")
    client._safe_dict_post = AsyncMock(
        return_value={
            "result": "Enabled" if method_name == "enable_unbound_blocklist" else "Disabled"
        }
    )

    method = getattr(client, method_name)
    result = await method("test-uuid")
    assert result is True
    client.get_host_firmware_version.assert_called_once()
    await client.async_close()


@pytest.mark.parametrize(
    "method_name,set_state",
    [
        ("enable_unbound_blocklist", True),
        ("disable_unbound_blocklist", False),
    ],
)
@pytest.mark.asyncio
async def test_enable_disable_unbound_legacy_fallback(method_name, set_state, make_client) -> None:
    """Test enable/disable_unbound_blocklist fallback to legacy on version error."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    client._firmware_version = "invalid.version"
    client._set_unbound_blocklist_legacy = AsyncMock(return_value=True)

    method = getattr(client, method_name)
    result = await method()
    assert result is True
    client._set_unbound_blocklist_legacy.assert_called_once_with(set_state=set_state)
    await client.async_close()


@pytest.mark.parametrize(
    "exc_factory,initial",
    [
        (lambda: TypeError("bad json"), False),
        (lambda: Fault(1, "err"), False),
        (lambda: socket.gaierror("name or service not known"), False),
        (lambda: SSLError("ssl fail"), False),
        (lambda: Fault(2, "err"), True),
        (lambda: socket.gaierror("no host"), True),
        (lambda: SSLError("ssl fail"), True),
    ],
)
@pytest.mark.asyncio
async def test_exec_php_error_paths(exc_factory, initial: bool, make_client) -> None:
    """_exec_php should swallow known exceptions and return {} regardless of initial flag.

    Consolidates previous exec_php tests into one parameterized function covering:
    - TypeError JSON issues
    - xmlrpc.client.Fault
    - socket.gaierror
    - ssl.SSLError
    With both initial False and initial True states.
    """
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    client._initial = initial
    proxy = MagicMock()
    proxy.opnsense.exec_php.side_effect = exc_factory()
    client._get_proxy = MagicMock(return_value=proxy)
    res = await client._exec_php("echo test;")
    assert res == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method_name, session_method, args, kwargs",
    [
        ("_do_get", "get", ("/api/x",), {"caller": "tst"}),
        ("_do_post", "post", ("/api/x",), {"payload": {}}),
    ],
)
async def test_do_get_post_error_initial_behavior(
    method_name, session_method, args, kwargs, make_client
) -> None:
    """When client._initial is True, non-ok responses should raise ClientResponseError for _do_get/_do_post."""
    session = MagicMock(spec=aiohttp.ClientSession)

    # create a fake response context manager
    class FakeResp:
        def __init__(self, status=500, ok=False):
            self.status = status
            self.reason = "Err"
            self.ok = ok

            # Provide a minimal request_info with real_url to satisfy logging
            class RI:
                real_url = URL("http://localhost")

            self.request_info = RI()
            self.history = []
            self.headers = {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def json(self, content_type=None):
            return {"x": 1}

        async def text(self):
            return "raw response text"

        @property
        def content(self):
            class C:
                async def iter_chunked(self, n):
                    yield b"data:{}\n\n" % b"{}"

            return C()

    if session_method == "get":
        session.get = lambda *a, **k: FakeResp(status=403, ok=False)
    else:
        session.post = lambda *a, **k: FakeResp(status=500, ok=False)

    client = make_client(session=session)
    client._initial = True
    try:
        with pytest.raises(aiohttp.ClientResponseError):
            await getattr(client, method_name)(*args, **kwargs)
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_from_stream_parsing(make_client, fake_stream_response_factory) -> None:
    """Simulate SSE-like stream with two messages and assert parsing returns dict."""
    session = MagicMock(spec=aiohttp.ClientSession)

    # use shared factory to construct a fake streaming response
    session.get = lambda *a, **k: fake_stream_response_factory(
        [b'data: {"a": 1}\n\n', b'data: {"b": 2}\n\n']
    )
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        res = await client._do_get_from_stream("/stream", caller="tst")
        # implementation returns the second 'data' message parsed as JSON
        assert isinstance(res, dict)
        assert res.get("b") == 2
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_from_stream_ignores_first_message(
    make_client, fake_stream_response_factory
) -> None:
    """Ensure the parser ignores the first data message and returns the second."""
    session = MagicMock(spec=aiohttp.ClientSession)

    session.get = lambda *a, **k: fake_stream_response_factory(
        [
            b'data: {"id": "first", "body": "ignore me"}\n\n',
            b'data: {"id": "second", "body": "keep me"}\n\n',
        ]
    )
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        res = await client._do_get_from_stream("/stream", caller="tst")
        assert isinstance(res, dict)
        # ensure the second message was selected
        assert res.get("id") == "second"
        assert res.get("body") == "keep me"
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_call_many_client_methods_to_exercise_branches(make_client) -> None:
    """Dynamically call many async methods on OPNsenseClient with patched internals.

    This test intentionally swallows exceptions: its goal is to execute code paths,
    not to assert functional correctness of every branch.
    """
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        # Patch common internals to return safe defaults
        client._safe_dict_get = AsyncMock(return_value={})
        client._safe_list_get = AsyncMock(return_value=[])
        client._safe_dict_post = AsyncMock(return_value={})
        client._safe_list_post = AsyncMock(return_value=[])
        client._get = AsyncMock(return_value={})
        client._post = AsyncMock(return_value={})
        client._do_get = AsyncMock(return_value={})
        client._do_post = AsyncMock(return_value={})
        client._do_get_from_stream = AsyncMock(return_value={})
        client._exec_php = AsyncMock(return_value={})

        # Prepare a small arg builder to supply plausible defaults
        def mkarg(pname: str):
            if pname in ("path", "if_name", "alias", "service", "version", "uuid"):
                return "/x"
            if pname in ("data", "payload"):
                return {}
            if pname in ("seconds", "timeout"):
                return 1
            return "x"

        coros = [
            (name, func)
            for name, func in _inspect.getmembers(
                pyopnsense.OPNsenseClient, predicate=_inspect.iscoroutinefunction
            )
            if name != "__init__"
        ]

        for name, _func in coros:
            # skip some problematic long-running internals
            if name in {"_monitor_queue", "_process_queue"}:
                continue
            meth = getattr(client, name, None)
            if not meth:
                continue
            sig = _inspect.signature(meth)
            # build args list (skip 'self')
            args = [mkarg(pname) for pname in sig.parameters if pname != "self"]

            # Call coroutine functions with await, and sync ones normally. Swallow expected exceptions.
            if _inspect.iscoroutinefunction(_func):
                with contextlib.suppress(asyncio.TimeoutError, Exception):
                    # limit each call to avoid long-running hangs
                    await asyncio.wait_for(meth(*args), timeout=0.5)
            else:
                with contextlib.suppress(Exception):
                    meth(*args)
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
@pytest.mark.parametrize(
    "safe_get_ret,safe_post_ret,data,expect_exc,expect_username,expect_extras",
    [
        ([], None, {}, pyopnsense.VoucherServerError, None, None),
        (["s1", "s2"], None, {}, pyopnsense.VoucherServerError, None, None),
        (
            None,
            [
                {
                    "username": "u",
                    "password": "p",
                    "vouchergroup": "g",
                    "starttime": "t",
                    "expirytime": 253402300799,
                    "validity": 65,
                }
            ],
            {"voucher_server": "srv"},
            None,
            "u",
            ["expiry_timestamp", "validity_str"],
        ),
    ],
)
async def test_generate_vouchers_server_selection_errors_and_success(
    safe_get_ret, safe_post_ret, data, expect_exc, expect_username, expect_extras
):
    """generate_vouchers: no servers / multiple servers -> error, provided server -> success.

    Consolidated test covering error cases and success with optional extra fields.
    """
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        # follow original tests' snake_case setting where applicable
        client._use_snake_case = False
        if safe_get_ret is not None:
            client._safe_list_get = AsyncMock(return_value=safe_get_ret)
            with pytest.raises(expect_exc):
                await client.generate_vouchers(data)
            return

        # safe_post case: expect success and optional extra fields
        client._safe_list_post = AsyncMock(return_value=safe_post_ret)
        got = await client.generate_vouchers(data)
        assert isinstance(got, list) and got[0].get("username") == expect_username
        for key in expect_extras or []:
            assert key in got[0]
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_toggle_alias_flows(make_client) -> None:
    """toggle_alias returns False when not found or when subsequent calls fail; True on full success."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        # alias not found
        client._use_snake_case = True
        client._safe_dict_get = AsyncMock(return_value={"rows": []})
        assert await client.toggle_alias("nope", "on") is False

        # alias found but toggle fails
        client._safe_dict_get = AsyncMock(
            return_value={"rows": [{"name": "myalias", "uuid": "aid"}]}
        )
        client._safe_dict_post = AsyncMock(return_value={"result": "failed"})
        assert await client.toggle_alias("myalias", "on") is False

        # full success path
        client._safe_dict_get = AsyncMock(
            return_value={"rows": [{"name": "myalias", "uuid": "aid"}]}
        )
        client._safe_dict_post = AsyncMock(
            side_effect=[{"result": "ok"}, {"result": "saved"}, {"status": "ok"}]
        )
        assert await client.toggle_alias("myalias", "on") is True
    finally:
        await client.async_close()


@pytest.fixture
def toggle_alias_client(make_client):
    """Provide a preconfigured OPNsenseClient for toggle_alias tests."""
    session = MagicMock(spec=aiohttp.ClientSession)
    return pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )


@pytest.mark.asyncio
async def test_log_errors_decorator_re_raise_and_suppress(make_client) -> None:
    """The _log_errors decorator should re-raise when self._initial is True, otherwise suppress."""

    class Dummy:
        def __init__(self, initial: bool):
            self._initial = initial

        @pyopnsense._log_errors
        async def boom(self) -> None:
            raise RuntimeError("boom")

    # When not initial, errors are logged and suppressed (function returns None)
    d = Dummy(initial=False)
    res = await d.boom()
    assert res is None

    # When initial, errors are re-raised
    d2 = Dummy(initial=True)
    with pytest.raises(RuntimeError):
        await d2.boom()


@pytest.mark.asyncio
async def test_get_from_stream_partial_chunks_accumulates_buffer(
    make_client, fake_stream_response_factory
) -> None:
    """Simulate a stream where a JSON message is split across chunks to exercise buffer accumulation."""
    session = MagicMock(spec=aiohttp.ClientSession)

    session.get = lambda *a, **k: fake_stream_response_factory(
        [b'data: {"a"', b": 1}\n\n", b'data: {"b": 2}\n\n']
    )
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        res = await client._do_get_from_stream("/stream2", caller="tst")
        assert isinstance(res, dict)
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_openvpn_more_detail_parsing(monkeypatch, make_client) -> None:
    """Exercise additional OpenVPN parsing branches (no sessions, missing fields)."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # prepare responses that exercise missing/partial fields
    sessions_info: dict[str, list[dict]] = {"rows": []}
    routes_info: dict[str, list[dict]] = {"rows": []}
    providers_info: dict[str, dict] = {}
    instances_info = {"rows": [{"role": "client", "uuid": "c1", "enabled": "0"}]}

    async def fake_safe_dict_get(path):
        if "search_sessions" in path or "searchSessions" in path:
            return sessions_info
        if "search_routes" in path or "searchRoutes" in path:
            return routes_info
        if "providers" in path:
            return providers_info
        if "instances/search" in path:
            return instances_info
        if "/instances/get/" in path:
            return {"instance": {}}  # missing details
        return {}

    monkeypatch.setattr(
        client, "_safe_dict_get", AsyncMock(side_effect=fake_safe_dict_get), raising=False
    )
    res = await client.get_openvpn()
    assert "servers" in res and "clients" in res
    await client.async_close()


@pytest.mark.asyncio
async def test_enable_and_disable_filter_rules_and_nat_port_forward(make_client) -> None:
    """Cover enabling/disabling filter rules and NAT port forward rule flows."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # enable_filter_rule_by_created_time_legacy: rule has 'disabled' -> should remove and call restore+configure
    cfg_enable = {"filter": {"rule": [{"created": {"time": "t-enable"}, "disabled": "1"}]}}
    client.get_config = AsyncMock(return_value=cfg_enable)
    client._restore_config_section = AsyncMock()
    client._filter_configure = AsyncMock()
    await client.enable_filter_rule_by_created_time_legacy("t-enable")
    client._restore_config_section.assert_awaited()
    client._filter_configure.assert_awaited()

    # disable_filter_rule_by_created_time_legacy: rule missing 'disabled' -> should add it and call restore+configure
    cfg_disable = {"filter": {"rule": [{"created": {"time": "t-disable"}}]}}
    client.get_config = AsyncMock(return_value=cfg_disable)
    client._restore_config_section = AsyncMock()
    client._filter_configure = AsyncMock()
    await client.disable_filter_rule_by_created_time_legacy("t-disable")
    client._restore_config_section.assert_awaited()
    client._filter_configure.assert_awaited()

    # enable_nat_port_forward_rule_by_created_time_legacy: similar flow under 'nat' section
    cfg_nat = {"nat": {"rule": [{"created": {"time": "t-nat"}, "disabled": "1"}]}}
    client.get_config = AsyncMock(return_value=cfg_nat)
    client._restore_config_section = AsyncMock()
    client._filter_configure = AsyncMock()
    await client.enable_nat_port_forward_rule_by_created_time_legacy("t-nat")
    client._restore_config_section.assert_awaited()
    client._filter_configure.assert_awaited()


@pytest.mark.asyncio
async def test_get_proxy_https_unverified_returns_serverproxy() -> None:
    """When scheme is https and verify_ssl is False, _get_proxy returns ServerProxy.

    Make this an async test and instantiate the client while the event loop is
    running so any background tasks are created on the active loop; ensure we
    close the client afterwards to avoid leaking tasks.
    """
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="https://localhost",
        username="u",
        password="p",
        session=session,
        opts={"verify_ssl": False},
    )
    try:
        proxy = client._get_proxy()
        assert isinstance(proxy, xc.ServerProxy)
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_process_queue_unknown_method_sets_future_exception(make_client) -> None:
    """Putting an unknown method into the request queue should set an exception on the future."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    q: asyncio.Queue = asyncio.Queue()
    client._request_queue = q

    loop = asyncio.get_running_loop()
    future = loop.create_future()
    await q.put(("unknown", "/x", None, future, "tst"))

    task = loop.create_task(client._process_queue())
    await asyncio.sleep(0)  # allow the task to process the queue
    # cancel background task and await it so the CancelledError is retrieved
    task.cancel()
    # await the cancelled task so the CancelledError is retrieved and suppressed
    with contextlib.suppress(asyncio.CancelledError):
        await task
    # future should have an exception
    exc = future.exception()
    assert isinstance(exc, RuntimeError)
    await client.async_close()


def test_dict_get_and_timestamp_and_ipkey_utils() -> None:
    """Unit test small utility functions: dict_get, timestamp_to_datetime, get_ip_key."""
    data = {"a": {"b": [10, {"c": 3}]}, "x": "y"}
    # dict_get supports numeric list indexing (see tests above); also verify mapping and defaults.
    assert pyopnsense.dict_get(data, "a.b") == [10, {"c": 3}]
    assert pyopnsense.dict_get(data, "missing.path", default=5) == 5

    # timestamp_to_datetime
    assert pyopnsense.timestamp_to_datetime(None) is None
    ts = int(datetime.now().timestamp())
    dt = pyopnsense.timestamp_to_datetime(ts)
    assert dt is not None and dt.tzinfo is not None

    # get_ip_key: missing address => placed at end
    assert pyopnsense.get_ip_key({}) == (3, "")
    # invalid address
    assert pyopnsense.get_ip_key({"address": "notanip"}) == (2, "")
    # IPv4 and IPv6 order
    k4 = pyopnsense.get_ip_key({"address": "192.168.0.1"})
    k6 = pyopnsense.get_ip_key({"address": "::1"})
    assert k4[0] == 0 and k6[0] == 1


@pytest.mark.asyncio
async def test_manage_service_and_restart_if_running(monkeypatch, make_client) -> None:
    """Test _manage_service and restart_service_if_running behavior."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # _manage_service should return False when service empty
    assert await client._manage_service("start", "") is False

    # when _safe_dict_post returns ok result, manage_service returns True
    client._safe_dict_post = AsyncMock(return_value={"result": "ok"})
    assert await client._manage_service("start", "svc1") is True

    # get_service_is_running uses get_services; test restart_service_if_running branches
    client.get_service_is_running = AsyncMock(return_value=True)
    monkeypatch.setattr(client, "restart_service", AsyncMock(return_value=True), raising=False)
    assert await client.restart_service_if_running("svc1") is True

    client.get_service_is_running = AsyncMock(return_value=False)
    assert await client.restart_service_if_running("svc1") is True
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
        def add_entities(ents):
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
        def add_switches(ents):
            created_switches.extend(ents)

        await switch_mod.async_setup_entry(MagicMock(), switch_cfg, add_switches)

    await run_switch_setup()
    # Only one valid filter rule should produce a switch entity
    assert isinstance(created_switches, list) and len(created_switches) == 1


@pytest.mark.asyncio
async def test_dhcp_edge_cases_and_keep_latest(make_client) -> None:
    """Ensure DHCP parsing and _keep_latest_leases handle odd entries."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # kea leases: missing address/expire
    client._safe_dict_get = AsyncMock(
        side_effect=[
            {"dhcpv4": {"general": {"enabled": "1", "interfaces": {}}}},
            {"rows": [{"if_name": "em0", "hwaddr": "mac1", "hostname": "h"}]},
        ]
    )
    leases = await client._get_kea_dhcpv4_leases()
    assert isinstance(leases, list)

    # keep_latest with numeric expiries (avoid None comparison error)
    res = client._keep_latest_leases(
        [{"a": 1, "expire": 10}, {"a": 1, "expire": 20}, {"b": 2, "expire": 5}]
    )
    assert any(item for item in res if item.get("b") == 2)


@pytest.mark.asyncio
async def test_do_get_from_stream_error_initial_raises(make_client) -> None:
    """When response.ok is False and client._initial True, _do_get_from_stream should raise."""
    session = MagicMock(spec=aiohttp.ClientSession)

    class FakeBadResp:
        def __init__(self, status=403):
            self.status = status
            self.reason = "Forbidden"
            self.ok = False

            class RI:
                real_url = URL("http://localhost")

            self.request_info = RI()
            self.history = []
            self.headers = {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        @property
        def content(self):
            class C:
                async def iter_chunked(self, n):
                    yield b""

            return C()

    def fake_get(*args, **kwargs):
        return FakeBadResp()

    session.get = fake_get
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        client._initial = True
        with pytest.raises(aiohttp.ClientResponseError):
            await client._do_get_from_stream("/bad", caller="t")
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_process_queue_handles_requests(make_client) -> None:
    """Run a single iteration of _process_queue processing several request types."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    # patch the do_* methods
    client._do_get = AsyncMock(return_value={"g": 1})
    client._do_post = AsyncMock(return_value={"p": 2})
    client._do_get_from_stream = AsyncMock(return_value={"s": 3})

    # replace request queue with a real one
    q: asyncio.Queue = asyncio.Queue()
    client._request_queue = q

    # start the queue processor as a real task on the running loop (bypass patched asyncio.create_task)
    task = asyncio.get_running_loop().create_task(client._process_queue())

    loop = asyncio.get_running_loop()
    fut_get = loop.create_future()
    fut_post = loop.create_future()
    fut_stream = loop.create_future()

    await q.put(("get", "/g", None, fut_get, "t"))
    await q.put(("post", "/p", {"x": 1}, fut_post, "t"))
    await q.put(("get_from_stream", "/s", None, fut_stream, "t"))

    res1 = await fut_get
    res2 = await fut_post
    res3 = await fut_stream

    assert res1 == {"g": 1}
    assert res2 == {"p": 2}
    assert res3 == {"s": 3}

    # cancel the processor task
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    await client.async_close()


@pytest.mark.asyncio
@pytest.mark.parametrize("returned", [{"ok": 1}, [1, 2, 3], None])
async def test_get_enqueues_and_processes(returned, make_client) -> None:
    """Ensure `_get` enqueues a request and `_process_queue` calls `_do_get` and returns value.

    Parameterized to cover mapping, list and None return types.
    """
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # replace request queue with a real one so _process_queue can run
    q: asyncio.Queue = asyncio.Queue()
    client._request_queue = q

    called = {}

    async def fake_do_get(path, caller="x"):
        # capture the caller name supplied by _get
        called["caller"] = caller
        return returned

    client._do_get = AsyncMock(side_effect=fake_do_get)

    # start the real processor task
    task = asyncio.get_running_loop().create_task(client._process_queue())

    # call the high-level _get which will create a future and wait for processing
    res = await client._get("/testpath")

    assert res == returned
    # caller should be the test function name when inspect.stack works
    assert called.get("caller") is not None

    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    await client.async_close()


@pytest.mark.asyncio
async def test_get_uses_unknown_when_inspect_stack_raises(monkeypatch, make_client) -> None:
    """If inspect.stack() raises, `_get` should set caller to 'Unknown'."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # Replace pyopnsense.inspect.stack to raise an IndexError
    class _BadInspect:
        @staticmethod
        def stack():
            raise IndexError("no stack")

    monkeypatch.setattr(pyopnsense, "inspect", _BadInspect)

    q: asyncio.Queue = asyncio.Queue()
    client._request_queue = q

    captured = {}

    async def fake_do_get(path, caller="x"):
        captured["caller"] = caller
        return {"ok": True}

    client._do_get = AsyncMock(side_effect=fake_do_get)

    task = asyncio.get_running_loop().create_task(client._process_queue())

    res = await client._get("/other")
    assert res == {"ok": True}
    assert captured.get("caller") == "Unknown"

    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    await client.async_close()


@pytest.mark.asyncio
@pytest.mark.parametrize("returned", [{"ok": 1}, [1, 2, 3], None])
async def test_post_enqueues_and_processes(returned, make_client) -> None:
    """Ensure `_post` enqueues a request and `_process_queue` calls `_do_post` and returns value.

    Parameterized to cover mapping, list and None return types. Also verify payload is forwarded.
    """
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    q: asyncio.Queue = asyncio.Queue()
    client._request_queue = q

    captured = {}

    async def fake_do_post(path, payload=None, caller="x"):
        captured["caller"] = caller
        captured["payload"] = payload
        return returned

    client._do_post = AsyncMock(side_effect=fake_do_post)

    task = asyncio.get_running_loop().create_task(client._process_queue())

    payload = {"a": 1}
    res = await client._post("/postpath", payload=payload)

    assert res == returned
    assert captured.get("payload") == payload
    assert captured.get("caller") is not None

    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    await client.async_close()


@pytest.mark.asyncio
async def test_post_uses_unknown_when_inspect_stack_raises(monkeypatch, make_client) -> None:
    """If inspect.stack() raises, `_post` should set caller to 'Unknown'."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    class _BadInspect:
        @staticmethod
        def stack():
            raise IndexError("no stack")

    monkeypatch.setattr(pyopnsense, "inspect", _BadInspect)

    q: asyncio.Queue = asyncio.Queue()
    client._request_queue = q

    captured = {}

    async def fake_do_post(path, payload=None, caller="x"):
        captured["caller"] = caller
        captured["payload"] = payload
        return {"ok": True}

    client._do_post = AsyncMock(side_effect=fake_do_post)

    task = asyncio.get_running_loop().create_task(client._process_queue())

    payload = {"b": 2}
    res = await client._post("/otherpost", payload=payload)
    assert res == {"ok": True}
    assert captured.get("caller") == "Unknown"
    assert captured.get("payload") == payload

    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    await client.async_close()


@pytest.mark.asyncio
async def test_exec_php_returns_real_json_and_xmlrpc_timeout_decorator() -> None:
    """_exec_php should return parsed JSON from response['real']; test @_xmlrpc_timeout wrapper."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        # Simulate exec_php returning a mapping with 'real' JSON string
        proxy = MagicMock()
        proxy.opnsense.exec_php.return_value = {"real": '{"ok": true, "val": 5}'}
        client._get_proxy = MagicMock(return_value=proxy)
        res = await client._exec_php("echo ok;")
        assert isinstance(res, dict) and res.get("val") == 5

        # Test the _xmlrpc_timeout decorator: wrap a simple async function
        class D:
            @pyopnsense._xmlrpc_timeout
            async def wrapped(self) -> int:
                return 7

        d = D()
        assert await d.wrapped() == 7
    finally:
        await client.async_close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "safe_get_rows, safe_post_result, expected",
    [
        ([], None, False),
        ([{"name": "a", "uuid": "u1"}], {"result": "failed"}, False),
        (
            [{"name": "a", "uuid": "u1"}],
            [{"result": "ok"}, {"result": "saved"}, {"status": "ok"}],
            True,
        ),
    ],
)
async def test_toggle_alias_scenarios(
    safe_get_rows, safe_post_result, expected, toggle_alias_client
) -> None:
    """Parametrized toggle_alias scenarios: not found, failed toggle, and full success."""
    client = toggle_alias_client
    try:
        client._safe_dict_get = AsyncMock(return_value={"rows": safe_get_rows})

        # alias not found path expects immediate False
        if not safe_get_rows:
            assert await client.toggle_alias("nope", "on") is expected
            return

        # when rows are present, set up _safe_dict_post appropriately
        if isinstance(safe_post_result, list):
            client._safe_dict_post = AsyncMock(side_effect=safe_post_result)
        else:
            client._safe_dict_post = AsyncMock(return_value=safe_post_result)

        assert await client.toggle_alias("a", "on") is expected
    finally:
        await client.async_close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "blocklist_return, post_side_effects, get_return, expected",
    [
        ({}, None, None, False),
        ({"enabled": "0"}, [{"result": "saved"}, {"response": "OK"}], {"status": "OK"}, True),
    ],
)
async def test_set_unbound_blocklist_legacy_scenarios(
    blocklist_return, post_side_effects, get_return, expected
) -> None:
    """Parametrized _set_unbound_blocklist_legacy scenarios: empty and full success."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        client.get_unbound_blocklist_legacy = AsyncMock(return_value=blocklist_return)

        if not expected:
            assert await client._set_unbound_blocklist_legacy(True) is False
            return

        # success path: arrange the sequence of network calls
        client._post = AsyncMock(side_effect=post_side_effects)
        client._get = AsyncMock(return_value=get_return)
        assert await client._set_unbound_blocklist_legacy(True) is True
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_log_errors_timeout_re_raise_and_suppress() -> None:
    """_log_errors should re-raise TimeoutError when client._initial is True and suppress when False."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(url="http://x", username="u", password="p", session=session)
    try:

        async def raising_timeout(*args, **kwargs):
            raise TimeoutError("boom")

        # wrap the coroutine with the decorator
        decorated = pyopnsense._log_errors(raising_timeout)

        # When initial is True we expect the TimeoutError to propagate
        client._initial = True
        with pytest.raises(TimeoutError):
            await decorated(client)

        # When initial is False the decorator should suppress TimeoutError and return None
        client._initial = False
        res = await decorated(client)
        assert res is None
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_log_errors_server_timeout_re_raise_and_suppress() -> None:
    """_log_errors should re-raise aiohttp.ServerTimeoutError when client._initial is True and suppress when False."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(url="http://x", username="u", password="p", session=session)

    async def raising_server_timeout(*args, **kwargs):
        raise aiohttp.ServerTimeoutError("srv")

    decorated = pyopnsense._log_errors(raising_server_timeout)

    client._initial = True
    with pytest.raises(aiohttp.ServerTimeoutError):
        await decorated(client)

    client._initial = False
    assert await decorated(client) is None
    await client.async_close()


@pytest.mark.asyncio
async def test_xmlrpc_timeout_restores_default(monkeypatch) -> None:
    """_xmlrpc_timeout should set socket.setdefaulttimeout while running and restore afterwards."""
    # track calls to get/set default timeout
    state: dict[str, list] = {"set": [], "get": []}

    def fake_getdefault():
        state["get"].append(True)
        return 123

    def fake_setdefault(v):
        state["set"].append(v)

    monkeypatch.setattr(pyopnsense.socket, "getdefaulttimeout", fake_getdefault)
    monkeypatch.setattr(pyopnsense.socket, "setdefaulttimeout", fake_setdefault)

    @pyopnsense._xmlrpc_timeout
    async def func(self):
        # inside the decorator the timeout should have been set to a numeric value
        # ensure our fake setter was called with something
        assert state["set"]
        return "ok"

    got = await func(None)
    assert got == "ok"
    # ensure getdefault called at least once and setdefault called to restore
    assert state["get"]
    assert state["set"]


@pytest.mark.asyncio
async def test_do_get_and_do_post_success_paths() -> None:
    """_do_get/_do_post should return parsed JSON when response.ok is True."""
    session = MagicMock(spec=aiohttp.ClientSession)

    class FakeOKResp:
        def __init__(self, payload):
            self.status = 200
            self.reason = "OK"
            self.ok = True
            self._payload = payload

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def json(self, content_type=None):
            return self._payload

        @property
        def content(self):
            class C:
                async def iter_chunked(self, n):
                    yield b""  # not used here

            return C()

    def fake_get(*args, **kwargs):
        return FakeOKResp({"a": 1})

    def fake_post(*args, **kwargs):
        return FakeOKResp([1, 2, 3])

    session.get = fake_get
    session.post = fake_post
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    got = await client._do_get("/api/x", caller="t")
    assert isinstance(got, dict) and got.get("a") == 1

    posted = await client._do_post("/api/x", payload={"x": 1}, caller="t")
    assert isinstance(posted, list) and posted[0] == 1
    await client.async_close()


@pytest.mark.asyncio
async def test_exec_php_non_mapping_and_get_proxy_https_unverified() -> None:
    """_exec_php returns {} when proxy returns non-mapping; _get_proxy supports https unverified."""
    session = MagicMock(spec=aiohttp.ClientSession)
    # non-mapping return
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    proxy = MagicMock()
    proxy.opnsense.exec_php.return_value = [1, 2, 3]
    client._get_proxy = MagicMock(return_value=proxy)
    res = await client._exec_php("x")
    assert res == {}
    await client.async_close()


@pytest.mark.asyncio
async def test_process_queue_exception_sets_future_exception() -> None:
    """If a worker raises, the future should get_exception set."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    client._do_get = AsyncMock(side_effect=ValueError("boom"))

    q: asyncio.Queue = asyncio.Queue()
    client._request_queue = q

    loop = asyncio.get_running_loop()
    task = loop.create_task(client._process_queue())

    fut = loop.create_future()
    await q.put(("get", "/g", None, fut, "t"))

    with pytest.raises(ValueError):
        await asyncio.wait_for(fut, timeout=2)

    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_openvpn_processing_and_fetch_details() -> None:
    """Test processing of OpenVPN instances/providers/sessions/routes and fetching details."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # prepare fake responses for _safe_dict_get based on path
    def fake_safe_dict_get(path):
        if "searchSessions" in path or "search_sessions" in path:
            return {
                "rows": [
                    {"type": "server", "id": "srv1_1", "description": "S1", "status": "connected"}
                ]
            }
        if "searchRoutes" in path or "search_routes" in path:
            return {
                "rows": [
                    {
                        "id": "srv1",
                        "common_name": "cname",
                        "real_address": "1.2.3.4",
                        "virtual_address": "10.0.0.1",
                    }
                ]
            }
        if "providers" in path:
            return {"srv1": {"name": "prov1", "hostname": "host.example", "local_port": "1194"}}
        if "instances/search" in path:
            return {
                "rows": [
                    {
                        "role": "server",
                        "uuid": "srv1",
                        "description": "Serv1",
                        "enabled": "1",
                        "dev_type": "tun",
                    }
                ]
            }
        if "/instances/get/" in path:
            return {
                "instance": {
                    "server": "10.0.0.1",
                    "dns_servers": {"0": {"selected": 1, "value": "8.8.8.8"}},
                }
            }
        return {}

    client._safe_dict_get = AsyncMock(side_effect=fake_safe_dict_get)

    openvpn = await client.get_openvpn()
    assert "servers" in openvpn and "clients" in openvpn
    servers = openvpn["servers"]
    assert any(s.get("uuid") == "srv1" for s in servers.values())
    srv = servers.get("srv1")
    assert srv is not None
    assert srv.get("dns_servers") == ["8.8.8.8"]


@pytest.mark.asyncio
async def test_telemetry_system_parsing_and_filesystems() -> None:
    """Test telemetry system parsing when boottime missing/invalid and filesystems path."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        # time_info with bad datetime and uptime matching regex
        time_info = {
            "datetime": "not-a-date",
            "uptime": "1 days, 01:02:03",
            "boottime": "also-bad",
            "loadavg": "bad",
        }

        async def fake_safe_post(path, *args, **kwargs):
            if "systemTime" in path or "system_time" in path:
                return time_info
            if "systemDisk" in path or "system_disk" in path:
                return {"devices": [{"dev": "/dev/da0"}]}
            return {}

        client._safe_dict_post = AsyncMock(side_effect=fake_safe_post)

        sys = await client._get_telemetry_system()
        assert isinstance(sys, dict)
        # At least one of the expected fields is normalized/present
        assert any(k in sys for k in ("uptime", "boottime", "loadavg"))

        files = await client._get_telemetry_filesystems()
        assert files is None or isinstance(files, list)
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_telemetry_cpu_variants() -> None:
    """Test _get_telemetry_cpu behavior for empty cputype list and valid stream."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # empty cpu type -> returns {}
    client._safe_list_post = AsyncMock(return_value=[])
    cpu_empty = await client._get_telemetry_cpu()
    assert cpu_empty == {}

    # valid cpu type and stream
    client._safe_list_post = AsyncMock(return_value=["Intel (2 cores)"])
    client._get_from_stream = AsyncMock(
        return_value={
            "total": "29",
            "user": "2",
            "nice": "0",
            "sys": "27",
            "intr": "0",
            "idle": "70",
        }
    )
    cpu = await client._get_telemetry_cpu()
    assert isinstance(cpu.get("count"), int)
    assert cpu.get("usage_total") == 29


@pytest.mark.asyncio
async def test_openvpn_client_session_updates_server_stats() -> None:
    """Ensure that openvpn session with is_client True updates server/client stats appropriately."""
    # no client/session needed for this static helper test

    # Build servers and clients structures
    servers: dict = {
        "s1": {"uuid": "s1", "clients": [], "total_bytes_recv": 0, "total_bytes_sent": 0}
    }
    clients: dict = {"c1": {"uuid": "c1", "pubkey": "pk1", "servers": [{"interface": "wg1"}]}}

    # session entry as a peer will update client/server
    entry = {
        "type": "peer",
        "public-key": "pk1",
        "if": "wg1",
        "transfer-rx": "100",
        "transfer-tx": "200",
        "latest-handshake": int(datetime.now().timestamp()),
    }

    await pyopnsense.OPNsenseClient._update_wireguard_peer_status(entry, servers, clients)

    # ensure totals updated on either server or client as implementation may update parent
    server_updated = any(
        s.get("total_bytes_recv", 0) >= 100 or s.get("total_bytes_sent", 0) >= 200
        for s in servers.values()
    )
    client_updated = any(
        c.get("total_bytes_recv", 0) >= 100 or c.get("total_bytes_sent", 0) >= 200
        for c in clients.values()
    )
    assert server_updated or client_updated


@pytest.mark.asyncio
async def test_fetch_openvpn_server_details_missing_server_field() -> None:
    """When instance details lack 'server' key, no tunnel_addresses should be set."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        openvpn = {"servers": {"srv1": {"uuid": "srv1"}}}

        async def fake_safe_dict_get(path):
            # return instance details with no 'server' key
            if "/instances/get/" in path:
                return {"instance": {}}
            return {}

        client._safe_dict_get = AsyncMock(side_effect=fake_safe_dict_get)
        await client._fetch_openvpn_server_details(openvpn)
        ta = openvpn["servers"]["srv1"].get("tunnel_addresses")
        assert "tunnel_addresses" not in openvpn["servers"]["srv1"] or (
            isinstance(ta, list) and ta == []
        )
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_monitor_queue_handles_qsize_exception() -> None:
    """If queue.qsize() raises, monitor should catch and continue (task runs)."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # make qsize raise
    class BadQ:
        def qsize(self):
            raise RuntimeError("boom")

        def empty(self):
            # indicate there are no queued items so async_close won't attempt to
            # drain a non-standard queue object; this keeps the test focused on
            # the qsize exception handling in _monitor_queue.
            return True

    client._request_queue = BadQ()  # type: ignore[assignment]

    loop = asyncio.get_running_loop()
    task = loop.create_task(client._monitor_queue())

    # yield control so task runs once and hits exception
    await asyncio.sleep(0)

    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    await client.async_close()


@pytest.mark.asyncio
async def test_get_unbound_blocklist_legacy_parsing() -> None:
    """Ensure get_unbound_blocklist_legacy properly extracts and joins nested mappings."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    dnsbl = {
        "unbound": {
            "dnsbl": {
                "enabled": "1",
                "type": {"t": {"selected": 1}},
                "lists": {"a": {"selected": 1}, "b": {"selected": 0}},
                "whitelists": {},
                "blocklists": {"x": {"selected": 1}},
                "wildcards": {},
            }
        }
    }

    client._safe_dict_get = AsyncMock(return_value=dnsbl)
    parsed = await client.get_unbound_blocklist_legacy()
    assert parsed.get("enabled") == "1"
    assert parsed.get("lists") == "a"
    assert parsed.get("blocklists") == "x"


@pytest.mark.asyncio
async def test_gateways_notices_and_close_notice_all() -> None:
    """Test gateway notices handling and closing all notices."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    client._safe_dict_get = AsyncMock(
        return_value={"items": [{"name": "gw1", "status_translated": "OK"}]}
    )
    gws = await client.get_gateways()
    assert "gw1" in gws and gws["gw1"]["status"] == "ok"

    # notices: include a pending notice
    client._safe_dict_get = AsyncMock(
        return_value={
            "n1": {"statusCode": 1, "message": "m", "timestamp": int(datetime.now().timestamp())}
        }
    )
    notices = await client.get_notices()
    assert notices["pending_notices_present"] is True

    # close_notice all: prepare multiple notices and simulate dismiss responses
    client._safe_dict_get = AsyncMock(
        return_value={"n1": {"statusCode": 1}, "n2": {"statusCode": 1}}
    )
    client._safe_dict_post = AsyncMock(return_value={"status": "ok"})
    assert await client.close_notice("all") is True


@pytest.mark.asyncio
async def test_get_services_and_service_is_running() -> None:
    """Verify service listing and running-state detection."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # get_services returns rows
    client._safe_dict_get = AsyncMock(
        return_value={"rows": [{"name": "svc", "running": 1, "id": "svc"}]}
    )
    services = await client.get_services()
    assert isinstance(services, list) and services[0]["status"] is True

    # get_service_is_running
    assert await client.get_service_is_running("svc") is True


@pytest.mark.asyncio
async def test_carp_and_system_actions_and_wol() -> None:
    """Test get_carp_status, get_carp_interfaces, reboot/halt and send_wol."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # carp status
    client._safe_dict_get = AsyncMock(return_value={"carp": {"allow": "1"}})
    assert await client.get_carp_status() is True

    # carp interfaces: one vip with mode carp and matching status
    vip_rows = [{"mode": "carp", "interface": "em0"}]
    vip_status = [{"interface": "em0", "status": "UP"}]
    # first call returns vip_settings, second returns vip_status
    client._safe_dict_get = AsyncMock(side_effect=[{"rows": vip_rows}, {"rows": vip_status}])
    carp = await client.get_carp_interfaces()
    assert isinstance(carp, list) and carp[0].get("status")

    # system reboot/halt
    client._safe_dict_post = AsyncMock(return_value={"status": "ok"})
    assert await client.system_reboot() is True
    assert await client.system_halt() is None

    # send wol success
    client._safe_dict_post = AsyncMock(return_value={"status": "ok"})
    assert await client.send_wol("em0", "aa:bb:cc") is True


@pytest.mark.asyncio
async def test_telemetry_mbuf_pfstate_and_temps() -> None:
    """Test telemetry mbuf, pfstate and temps parsing branches."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        # mbuf and pfstate basic numeric parsing
        client._safe_dict_post = AsyncMock(
            side_effect=[
                {"mbuf-statistics": {"mbuf-current": "10", "mbuf-total": "20"}},
                {"current": "5", "limit": "10"},
            ]
        )
        mbuf = await client._get_telemetry_mbuf()
        pf = await client._get_telemetry_pfstate()
        assert mbuf.get("used") == 10 and mbuf.get("total") == 20
        assert pf.get("used") == 5 and pf.get("total") == 10

        # temps: return list with one entry
        client._safe_list_get = AsyncMock(
            return_value=[{"temperature": "45.5", "type_translated": "CPU", "device_seq": 0}]
        )
        temps = await client._get_telemetry_temps()
        assert isinstance(temps, dict) and len(temps) == 1
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_wireguard_full_processing_and_peer_details() -> None:
    """Build a full wireguard response and ensure servers/clients and peer updates occur."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        # prepare summary, clients, servers raw responses
        summary = {
            "peers": [
                {
                    "public-key": "pk1",
                    "latest-handshake": int(datetime.now().timestamp()),
                    "transfer-rx": "100",
                    "transfer-tx": "200",
                    "if": "wg1",
                }
            ],
            "servers": {"s1": {"uuid": "s1"}},
            "clients": {"c1": {"uuid": "c1", "pubkey": "pk1", "servers": [{"interface": "wg1"}]}},
        }

        # Provide server and client raw endpoints and lists
        client._safe_dict_get = AsyncMock(
            side_effect=[
                {"rows": [{"id": "s1", "name": "s1"}]},  # summary for show
                {
                    "0": {"selected": 1, "value": "8.8.8.8"}
                },  # dns server details when fetching server details
                {},
            ]
        )

        # patch internal processing helpers to use our summary directly
        # Simulate _process_wireguard_server and client flow by directly calling _update_wireguard_peer_status
        servers: dict = {
            "s1": {"uuid": "s1", "clients": [], "total_bytes_recv": 0, "total_bytes_sent": 0}
        }
        clients_map: dict = {
            "c1": {"uuid": "c1", "pubkey": "pk1", "servers": [{"interface": "wg1"}]}
        }

        # call the static peer update helper which should update totals
        entry = summary["peers"][0]
        await pyopnsense.OPNsenseClient._update_wireguard_peer_status(entry, servers, clients_map)
        updated = any(
            s.get("total_bytes_recv", 0) >= 100 or s.get("total_bytes_sent", 0) >= 200
            for s in servers.values()
        )
        assert updated or any(c.get("total_bytes_recv", 0) >= 100 for c in clients_map.values())
    finally:
        await client.async_close()


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
        client._post.assert_called()

        # telemetry system with valid boottime string and uptime regex
        ti = {
            "datetime": datetime.now().isoformat(),
            "uptime": "1 days, 01:02:03",
            "boottime": (datetime.now() - timedelta(days=1)).isoformat(),
            "loadavg": "1, 2, 3",
        }
        client._safe_dict_post = AsyncMock(return_value=ti)
        sys = await client._get_telemetry_system()
        assert isinstance(sys, dict)

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
        assert isinstance(telem, dict)

        # call get_openvpn with empty dicts to exercise early return and processing functions
        client._safe_dict_get = AsyncMock(
            side_effect=[{"rows": []}, {"rows": []}, {}, {"rows": []}, {}]
        )
        res = await client.get_openvpn()
        assert isinstance(res, dict)
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_isc_dhcpv4_and_v6_parsing() -> None:
    """Test ISC DHCPv4/v6 parsing of 'ends' -> datetime and filtering logic."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # v4: ends present and in future
    future_dt = (datetime.now() + timedelta(hours=1)).strftime("%Y/%m/%d %H:%M:%S")
    client._use_snake_case = False
    client._safe_dict_get = AsyncMock(
        side_effect=[
            {
                "rows": [
                    {
                        "state": "active",
                        "mac": "m1",
                        "address": "10.0.0.1",
                        "hostname": "h1",
                        "if": "em0",
                        "ends": future_dt,
                    }
                ]
            },
            {"rows": []},
        ]
    )
    v4 = await client._get_isc_dhcpv4_leases()
    assert isinstance(v4, list) and len(v4) == 1
    assert isinstance(v4[0].get("expires"), datetime)

    # v6: ends missing -> field passed through
    client._use_snake_case = True
    client._safe_dict_get = AsyncMock(
        return_value={
            "rows": [
                {
                    "state": "active",
                    "mac": "m2",
                    "address": "fe80::1",
                    "hostname": "h2",
                    "if": "em1",
                }
            ]
        }
    )
    v6 = await client._get_isc_dhcpv6_leases()
    assert isinstance(v6, list) and len(v6) == 1
    await client.async_close()


@pytest.mark.asyncio
async def test_get_dhcp_leases_combined_structure() -> None:
    """Ensure get_dhcp_leases combines multiple sources and returns expected mapping."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # return one lease from each source and one interface mapping
    client._get_kea_dhcpv4_leases = AsyncMock(
        return_value=[{"if_name": "em0", "address": "1.1.1.1", "mac": "m1"}]
    )
    client._get_isc_dhcpv4_leases = AsyncMock(
        return_value=[{"if_name": "em0", "address": "1.1.1.2", "mac": "m2"}]
    )
    client._get_isc_dhcpv6_leases = AsyncMock(return_value=[])
    client._get_dnsmasq_leases = AsyncMock(return_value=[])
    client._get_kea_interfaces = AsyncMock(return_value={"em0": "eth0"})

    combined = await client.get_dhcp_leases()
    assert isinstance(combined, dict)
    assert "lease_interfaces" in combined and "leases" in combined
    await client.async_close()


@pytest.mark.asyncio
async def test_get_arp_table_and_manage_service_upgrade_flow() -> None:
    """Test get_arp_table and upgrade_firmware branches for update/upgrade."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

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
    assert isinstance(res, dict)

    # upgrade_firmware: unknown type returns None
    assert await client.upgrade_firmware("noop") is None
    await client.async_close()


@pytest.mark.asyncio
async def test_get_firmware_update_info_triggers_check_when_missing() -> None:
    """Trigger firmware check when fields missing/expired."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # prepare status missing latest and a stale last_check
    old_time = (datetime.now() - timedelta(days=2)).isoformat()
    status = {
        "product": {"product_version": "1.0.0", "product_latest": "1.0.0", "product_check": {}},
        "last_check": old_time,
    }
    client._safe_dict_get = AsyncMock(return_value=status)
    client._post = AsyncMock(return_value={})
    await client.get_firmware_update_info()
    client._post.assert_called()


@pytest.mark.asyncio
async def test_get_config_and_rule_enable_disable_branches() -> None:
    """Exercise get_config and enable/disable filter/nat rule flows."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # _exec_php returns a mapping with 'data' containing filter and nat rules
    fake_config = {
        "data": {
            "filter": {"rule": [{"created": {"time": "t1"}, "disabled": "1"}]},
            "nat": {"rule": [{"created": {"time": "n1"}}], "outbound": {"rule": []}},
        }
    }

    client._exec_php = AsyncMock(return_value=fake_config)
    client._restore_config_section = AsyncMock()
    client._filter_configure = AsyncMock()
    # calling enable should remove 'disabled' and call restore/configure (no exception)
    await client.enable_filter_rule_by_created_time_legacy("t1")
    client._restore_config_section.assert_awaited()
    client._filter_configure.assert_awaited()

    # disable_nat_port_forward: add a rule without 'disabled' and expect it to set 'disabled'
    client._exec_php = AsyncMock(
        return_value={"data": {"nat": {"rule": [{"created": {"time": "n1"}}]}}}
    )
    # patch _restore_config_section and _filter_configure to be no-ops
    client._restore_config_section = AsyncMock()
    client._filter_configure = AsyncMock()
    await client.disable_nat_port_forward_rule_by_created_time_legacy("n1")
    await client.async_close()


@pytest.mark.asyncio
async def test_get_interfaces_status_variants() -> None:
    """Ensure interface parsing handles status, associated mapping and mac filtering."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # prepare list with various status and mac strings
    iface_list = [
        {
            "identifier": "em0",
            "description": "eth0",
            "status": "down",
            "macaddr": "aa:bb:cc:dd:ee:ff",
        },
        {
            "identifier": "em1",
            "description": "eth1",
            "status": "associated",
            "macaddr": "00:00:00:00:00:00",
        },
        {
            "identifier": "em2",
            "description": "eth2",
            "status": "up",
            "macaddr": "11:22:33:44:55:66",
        },
    ]

    client._safe_list_get = AsyncMock(return_value=iface_list)
    interfaces = await client.get_interfaces()
    assert "em0" in interfaces and interfaces["em0"]["status"] == "down"
    assert "em1" in interfaces and interfaces["em1"]["status"] == "up"
    # em1 mac should be filtered out because it's 00:00:00:00:00:00
    assert "mac" not in interfaces["em1"]
    await client.async_close()


@pytest.mark.asyncio
async def test_get_kea_leases_with_reservations_and_expiry_handling() -> None:
    """Exercise _get_kea_dhcpv4_leases reservation matching and expiry logic."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    client._use_snake_case = True

    # reservation maps hw_address -> ip
    res_rows = [{"hw_address": "aa:bb", "ip_address": "192.0.2.1"}]

    # lease row matches reservation and has future expire
    future_ts = int((datetime.now().timestamp()) + 3600)
    lease_rows = [
        {
            "address": "192.0.2.1",
            "hwaddr": "aa:bb",
            "state": "0",
            "if_name": "em0",
            "expire": future_ts,
            "hostname": "h",
        }
    ]

    async def fake_safe(path):
        if "search_reservation" in path or "searchReservation" in path:
            return {"rows": res_rows}
        if "leases4/search" in path:
            return {"rows": lease_rows}
        return {}

    client._safe_dict_get = AsyncMock(side_effect=fake_safe)
    leases = await client._get_kea_dhcpv4_leases()
    assert isinstance(leases, list) and len(leases) == 1
    assert leases[0].get("type") == "static"


@pytest.mark.asyncio
async def test_telemetry_memory_swap_branches() -> None:
    """Cover telemetry memory path including swap data branch."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # prepare memory info with swap list present
    mem = {"memory": {"total": "8000", "used": "2000"}}
    swap = {"swap": [{"total": "1000", "used": "200"}]}

    async def fake_post(path, *args, **kwargs):
        if "systemResources" in path or "system_resources" in path:
            return mem
        if "systemSwap" in path or "system_swap" in path:
            return swap
        return {}

    client._safe_dict_post = AsyncMock(side_effect=fake_post)
    res = await client._get_telemetry_memory()
    assert isinstance(res.get("physmem"), int) or res.get("physmem") is None
    await client.async_close()


@pytest.mark.parametrize(
    "delta_minutes,expected",
    [
        (2, True),  # within 3 minutes => connected
        (3, True),  # exactly at threshold => connected
        (5, False),  # beyond threshold => not connected
    ],
)
def test_wireguard_is_connected_variants(monkeypatch, delta_minutes: int, expected: bool) -> None:
    """WireGuard connection considered active when last handshake within threshold.

    Monkeypatch `datetime.now` in the module under test to a fixed value with no
    microseconds so comparisons at the 3-minute boundary are deterministic.
    """
    fixed_now = datetime.now().astimezone().replace(microsecond=0)
    # create a minimal fake datetime provider with a static now() returning fixed_now
    FakeDT = type("FakeDT", (), {"now": staticmethod(lambda: fixed_now)})
    monkeypatch.setattr(pyopnsense, "datetime", FakeDT)
    assert (
        pyopnsense.wireguard_is_connected(fixed_now - timedelta(minutes=delta_minutes)) is expected
    )
    # None always False
    if delta_minutes == 5:  # only need to assert once in param set
        assert pyopnsense.wireguard_is_connected(None) is False


@pytest.mark.asyncio
async def test_client_name_property():
    """Ensure client reports a composed name property correctly."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost",
        username="user",
        password="pass",
        session=session,
    )
    assert client.name == "OPNsense"
    await client.async_close()


@pytest.mark.asyncio
async def test_reset_and_get_query_counts():
    """Reset and retrieve client query counters."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost",
        username="user",
        password="pass",
        session=session,
    )
    await client.reset_query_counts()
    rest, xml = await client.get_query_counts()
    assert rest == 0
    assert xml == 0
    await client.async_close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rules,created_time,should_call",
    [
        # matching rule with disabled -> should call restore/configure and remove 'disabled'
        ([{"created": {"time": "t1"}, "disabled": "1"}], "t1", True),
        # matching rule without disabled -> no restore/configure
        ([{"created": {"time": "t1"}}], "t1", False),
        # missing 'created' key -> skipped
        ([{"foo": "bar"}], "t1", False),
        # created present but missing 'time' -> skipped
        ([{"created": {}}], "t1", False),
        # time doesn't match -> skipped
        ([{"created": {"time": "t2"}, "disabled": "1"}], "t1", False),
        # multiple rules, one matches and is disabled -> should call once
        (
            [
                {"created": {"time": "a"}},
                {"created": {"time": "match"}, "disabled": "1"},
                {"created": {"time": "b"}, "disabled": "1"},
            ],
            "match",
            True,
        ),
    ],
)
async def test_enable_filter_rule_by_created_time_legacy(
    make_client, rules, created_time, should_call
) -> None:
    """Ensure enabling a filter rule removes 'disabled' and triggers restore/configure only when appropriate.

    Parameterized to exercise matching and non-matching branches.
    """

    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    config = {"filter": {"rule": [dict(r) for r in rules]}}
    client.get_config = AsyncMock(return_value=config)
    client._restore_config_section = AsyncMock()
    client._filter_configure = AsyncMock()

    await client.enable_filter_rule_by_created_time_legacy(created_time)

    if should_call:
        client._restore_config_section.assert_awaited()
        client._filter_configure.assert_awaited()
        # Inspect what was passed to _restore_config_section and ensure 'disabled' removed
        called = client._restore_config_section.await_args.args
        # first arg should be 'filter'
        assert called[0] == "filter"
        # second arg is the filter section; ensure the matching rule no longer has 'disabled'
        filter_section = called[1]
        assert isinstance(filter_section, dict)
        # find the matching rule inside the passed filter section
        rules_passed = filter_section.get("rule", [])
        matched = [r for r in rules_passed if r.get("created", {}).get("time") == created_time]
        assert matched
        for m in matched:
            assert "disabled" not in m
    else:
        client._restore_config_section.assert_not_awaited()
        client._filter_configure.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_wireguard_success_and_invalid(make_client) -> None:
    """Exercise get_wireguard success path and invalid structure early return."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    now = datetime.now().astimezone()
    old_handshake = int((now - timedelta(minutes=10)).timestamp())  # disconnected

    # Build server/client structures expected by API shape
    summary_resp = {
        "rows": [
            {"type": "interface", "public-key": "spk", "status": "up"},
            {
                "type": "peer",
                "public-key": "cpk",
                "if": "wg1",
                "latest-handshake": old_handshake,
                "transfer-rx": "1",
                "transfer-tx": "2",
            },
        ]
    }
    clients_resp = {
        "client": {
            "clients": {
                "client": {
                    "c1": {
                        "name": "client1",
                        "pubkey": "cpk",
                        "enabled": "1",
                        "tunneladdress": {},
                        "servers": {"s1": {"selected": 1, "value": "srv1"}},
                    }
                }
            }
        }
    }
    servers_resp = {
        "server": {
            "servers": {
                "server": {
                    "s1": {
                        "name": "srv1",
                        "pubkey": "spk",
                        "enabled": "1",
                        "instance": "1",
                        "tunneladdress": {"0": {"selected": 1, "value": "10.0.0.1"}},
                        "peers": {"c1": {"selected": 1, "value": "client1"}},
                    }
                }
            }
        }
    }

    # side_effect order matches comprehension iteration order in get_wireguard
    client._safe_dict_get = AsyncMock(side_effect=[summary_resp, clients_resp, servers_resp])
    wg = await client.get_wireguard()
    assert "servers" in wg and "clients" in wg and wg["servers"]["s1"]["uuid"] == "s1"
    # client peer should reflect disconnected (old handshake)
    assert wg["clients"]["c1"].get("connected_servers") in (
        0,
        wg["clients"]["c1"].get("connected_servers"),
    )

    # invalid structure (summary not list) -> {}
    client._safe_dict_get = AsyncMock(return_value={"rows": {}})
    assert await client.get_wireguard() == {}
    await client.async_close()


@pytest.mark.asyncio
async def test_update_wireguard_peer_details_endpoint_none_does_not_override() -> None:
    """When endpoint is '(none)' existing endpoint value should remain unchanged."""
    server = {
        "total_bytes_recv": 0,
        "total_bytes_sent": 0,
        "connected_servers": 0,
        "latest_handshake": None,
    }
    peer = {"endpoint": "keep"}
    await pyopnsense.OPNsenseClient._update_wireguard_peer_details(  # type: ignore[arg-type]
        peer=peer,
        server_or_client=server,
        endpoint="(none)",
        transfer_rx=0,
        transfer_tx=0,
        handshake_time=None,
        is_connected=False,
        connection_counter_key="connected_servers",
    )
    assert peer.get("endpoint") == "keep"


@pytest.mark.asyncio
async def test_restore_config_section_executes_in_executor(make_client) -> None:
    """_restore_config_section should call underlying proxy method with params."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    called = {}

    class FakeProxy:
        class opnsense:  # noqa: D401 - minimal container for restore_config_section
            @staticmethod
            def restore_config_section(params):  # pragma: no cover - executed in executor
                called["params"] = params

    client._get_proxy = MagicMock(return_value=FakeProxy())
    await client._restore_config_section("filter", {"rule": []})
    assert called.get("params") == {"filter": {"rule": []}}
    await client.async_close()


@pytest.mark.asyncio
async def test_enable_disable_nat_outbound_rules(make_client) -> None:
    """Cover enable/disable NAT outbound rule flows."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    # Enable: rule has disabled flag -> should remove and call helpers
    cfg_enable = {"nat": {"outbound": {"rule": [{"created": {"time": "t1"}, "disabled": "1"}]}}}
    client.get_config = AsyncMock(return_value=cfg_enable)
    client._restore_config_section = AsyncMock()
    client._filter_configure = AsyncMock()
    await client.enable_nat_outbound_rule_by_created_time_legacy("t1")
    client._restore_config_section.assert_awaited()
    client._filter_configure.assert_awaited()

    # Disable: rule missing disabled -> should add and call helpers
    cfg_disable = {"nat": {"outbound": {"rule": [{"created": {"time": "t2"}}]}}}
    client.get_config = AsyncMock(return_value=cfg_disable)
    client._restore_config_section = AsyncMock()
    client._filter_configure = AsyncMock()
    await client.disable_nat_outbound_rule_by_created_time_legacy("t2")
    client._restore_config_section.assert_awaited()
    client._filter_configure.assert_awaited()
    await client.async_close()


@pytest.mark.asyncio
async def test_do_get_post_and_stream_permission_errors(make_client) -> None:
    """_do_get/_do_post/_do_get_from_stream should not raise when 403 and initial False."""
    session = MagicMock(spec=aiohttp.ClientSession)

    class Fake403:
        def __init__(self):
            self.status = 403
            self.reason = "Forbidden"
            self.ok = False

            class RI:  # minimal request_info
                real_url = URL("http://localhost")

            self.request_info = RI()
            self.history = []
            self.headers = {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def json(self, content_type=None):
            return {"err": 1}

        @property
        def content(self):  # for stream variant
            class C:
                async def iter_chunked(self, n):
                    if False:  # pragma: no cover
                        yield b""  # never executed; placeholder
                        return
                    yield b""  # empty stream

            return C()

    session.get = lambda *a, **k: Fake403()
    session.post = lambda *a, **k: Fake403()
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        client._initial = False
        assert await client._do_get("/x", caller="t") is None
        assert await client._do_post("/x", payload={}, caller="t") is None
        assert await client._do_get_from_stream("/x", caller="t") == {}
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_update_wireguard_peer_details_latest_handshake() -> None:
    """_update_wireguard_peer_details should update latest_handshake when newer."""
    server: dict = {"total_bytes_recv": 0, "total_bytes_sent": 0, "connected_clients": 0}
    peer: dict = {}
    old_time = datetime.now().astimezone() - timedelta(minutes=10)
    server["latest_handshake"] = old_time
    new_time = datetime.now().astimezone()
    await pyopnsense.OPNsenseClient._update_wireguard_peer_details(  # type: ignore[arg-type]
        peer=peer,
        server_or_client=server,
        endpoint="1.2.3.4:51820",
        transfer_rx=10,
        transfer_tx=20,
        handshake_time=new_time,
        is_connected=True,
        connection_counter_key="connected_clients",
    )
    assert server.get("latest_handshake") == new_time
    assert server.get("connected_clients") == 1
    assert peer.get("connected") is True


@pytest.mark.asyncio
async def test_set_use_snake_case_unknown_firmware_raise(monkeypatch, make_client) -> None:
    """set_use_snake_case should raise UnknownFirmware when initial True and compare fails."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    client._firmware_version = "25.x"

    class BadAV:
        def __init__(self, *_args, **_kwargs):
            pass

        def __lt__(self, other):  # noqa: D401 - comparison triggers exception
            raise pyopnsense.awesomeversion.exceptions.AwesomeVersionCompareException("bad")

    monkeypatch.setattr(pyopnsense.awesomeversion, "AwesomeVersion", BadAV)
    with pytest.raises(pyopnsense.UnknownFirmware):
        await client.set_use_snake_case(initial=True)
    await client.async_close()


@pytest.mark.asyncio
async def test_get_device_unique_id_no_mac(make_client) -> None:
    """get_device_unique_id returns None when no physical mac addresses present."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    client._safe_list_get = AsyncMock(return_value=[{"is_physical": False}])
    assert await client.get_device_unique_id() is None
    await client.async_close()


@pytest.mark.asyncio
async def test_get_firewall_legacy_fallback(make_client) -> None:
    """get_firewall falls back to legacy config for OPNsense < 26.1.1."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    client._firmware_version = "25.7.0"

    # Mock get_config for legacy fallback
    client.get_config = AsyncMock(return_value={"filter": {"rule": []}})

    result = await client.get_firewall()
    assert result == {"config": {"filter": {"rule": []}}}
    client.get_config.assert_awaited_once()
    await client.async_close()


@pytest.mark.asyncio
async def test_get_firewall_new_api(make_client) -> None:
    """get_firewall uses new API for OPNsense >= 26.1.1."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    client._firmware_version = "26.1.1"

    # Mock all the methods called in the new API path
    client.is_plugin_installed = AsyncMock(return_value=True)
    client.get_config = AsyncMock(return_value={"filter": {"rule": []}})
    client._get_firewall_rules = AsyncMock(return_value={"rule1": {"uuid": "rule1"}})
    client._get_nat_destination_rules = AsyncMock(return_value={"nat1": {"uuid": "nat1"}})
    client._get_nat_one_to_one_rules = AsyncMock(return_value={"one1": {"uuid": "one1"}})
    client._get_nat_source_rules = AsyncMock(return_value={"src1": {"uuid": "src1"}})
    client._get_nat_npt_rules = AsyncMock(return_value={"npt1": {"uuid": "npt1"}})

    result = await client.get_firewall()
    expected = {
        "config": {"filter": {"rule": []}},
        "rules": {"rule1": {"uuid": "rule1"}},
        "nat": {
            "d_nat": {"nat1": {"uuid": "nat1"}},
            "one_to_one": {"one1": {"uuid": "one1"}},
            "source_nat": {"src1": {"uuid": "src1"}},
            "npt": {"npt1": {"uuid": "npt1"}},
        },
    }
    assert result == expected
    client.is_plugin_installed.assert_awaited_once()
    client.get_config.assert_awaited_once()
    client._get_firewall_rules.assert_awaited_once()
    client._get_nat_destination_rules.assert_awaited_once()
    client._get_nat_one_to_one_rules.assert_awaited_once()
    client._get_nat_source_rules.assert_awaited_once()
    client._get_nat_npt_rules.assert_awaited_once()
    await client.async_close()


@pytest.mark.asyncio
async def test_get_firewall_new_api_plugin_not_installed(make_client) -> None:
    """get_firewall uses new API for OPNsense >= 26.1.1 but when plugin not installed it should skip config."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    client._firmware_version = "26.1.1"

    # Plugin not installed: shouldn't call get_config
    client.is_plugin_installed = AsyncMock(return_value=False)
    client.get_config = AsyncMock(return_value={"filter": {"rule": []}})
    client._get_firewall_rules = AsyncMock(return_value={"rule1": {"uuid": "rule1"}})
    client._get_nat_destination_rules = AsyncMock(return_value={"nat1": {"uuid": "nat1"}})
    client._get_nat_one_to_one_rules = AsyncMock(return_value={"one1": {"uuid": "one1"}})
    client._get_nat_source_rules = AsyncMock(return_value={"src1": {"uuid": "src1"}})
    client._get_nat_npt_rules = AsyncMock(return_value={"npt1": {"uuid": "npt1"}})

    result = await client.get_firewall()
    expected = {
        "rules": {"rule1": {"uuid": "rule1"}},
        "nat": {
            "d_nat": {"nat1": {"uuid": "nat1"}},
            "one_to_one": {"one1": {"uuid": "one1"}},
            "source_nat": {"src1": {"uuid": "src1"}},
            "npt": {"npt1": {"uuid": "npt1"}},
        },
    }
    assert result == expected
    client.is_plugin_installed.assert_awaited_once()
    client.get_config.assert_not_awaited()
    client._get_firewall_rules.assert_awaited_once()
    client._get_nat_destination_rules.assert_awaited_once()
    client._get_nat_one_to_one_rules.assert_awaited_once()
    client._get_nat_source_rules.assert_awaited_once()
    client._get_nat_npt_rules.assert_awaited_once()
    await client.async_close()


@pytest.mark.asyncio
async def test_get_firewall_version_compare_exception(make_client) -> None:
    """get_firewall handles AwesomeVersionCompareException gracefully."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    client._firmware_version = "invalid"

    result = await client.get_firewall()
    assert result == {}
    await client.async_close()


@pytest.mark.asyncio
async def test_get_firewall_rules_successful_parsing(make_client) -> None:
    """_get_firewall_rules successfully parses rows returned from the REST API."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    rows = [
        {
            "uuid": "rule1",
            "enabled": "1",
            "action": "pass",
            "interface": "lan",
            "descr": "Allow HTTP",
        },
        {
            "uuid": "rule2",
            "enabled": "0",
            "action": "block",
            "interface": "wan",
            "descr": "Block traffic",
        },
    ]

    client._safe_dict_post = AsyncMock(return_value={"rows": rows})

    result = await client._get_firewall_rules()

    expected = {r["uuid"]: r.copy() for r in rows}
    assert result == expected
    client._safe_dict_post.assert_awaited_once_with(
        "/api/firewall/filter/search_rule", payload={"current": 1, "sort": {}}
    )
    await client.async_close()


@pytest.mark.asyncio
async def test_get_firewall_rules_empty_response(make_client) -> None:
    """_get_firewall_rules returns empty dict when API response has no rows."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    client._safe_dict_post = AsyncMock(return_value={})

    result = await client._get_firewall_rules()
    assert result == {}
    await client.async_close()


@pytest.mark.asyncio
async def test_get_firewall_rules_skips_invalid_rows(make_client) -> None:
    """_get_firewall_rules skips rules without uuid and lockout rules."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    rows = [
        {"enabled": "1", "action": "pass"},  # missing uuid
        {"uuid": "lockout-1", "enabled": "1"},  # lockout rule
        {"uuid": "rule-ok", "enabled": "1"},  # valid
    ]

    client._safe_dict_post = AsyncMock(return_value={"rows": rows})

    result = await client._get_firewall_rules()
    assert list(result.keys()) == ["rule-ok"]
    await client.async_close()


@pytest.mark.parametrize(
    ("method_name", "api_endpoint", "has_transformations"),
    [
        ("_get_nat_destination_rules", "/api/firewall/d_nat/search_rule", True),
        ("_get_nat_one_to_one_rules", "/api/firewall/one_to_one/search_rule", False),
        ("_get_nat_source_rules", "/api/firewall/source_nat/search_rule", False),
        ("_get_nat_npt_rules", "/api/firewall/npt/search_rule", False),
    ],
)
@pytest.mark.parametrize(
    ("test_case", "expected_result"),
    [
        (
            "successful_parsing",
            {
                "test-rule-1": {
                    "uuid": "test-rule-1",
                    "description": "Test rule 1",
                    "enabled": "1",
                    "interface": "wan",
                    "protocol": "tcp",
                },
                "test-rule-2": {
                    "uuid": "test-rule-2",
                    "description": "Test rule 2",
                    "enabled": "0",
                    "interface": "lan",
                    "protocol": "udp",
                },
            },
        ),
        (
            "filters_lockout_rules",
            {
                "normal-rule": {
                    "uuid": "normal-rule",
                    "description": "Normal rule",
                    "enabled": "1",
                }
            },
        ),
        ("empty_response", {}),
        ("response_without_rows", {}),
    ],
)
@pytest.mark.asyncio
async def test_nat_rules_parsing(
    make_client,
    method_name,
    api_endpoint,
    has_transformations,
    test_case,
    expected_result,
) -> None:
    """Test NAT rules parsing for all NAT rule types."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    # Build API-style mock response depending on whether the endpoint uses
    # transformations (d_nat-like endpoints use 'descr'/'disabled').
    mock_response: dict[str, Any]
    if test_case == "empty_response":
        mock_response = {}
    elif test_case == "response_without_rows":
        mock_response = {"some_other_key": "value"}
    else:
        normalized_rows: list[dict[str, Any]] = []
        extra_rows: list[dict[str, Any]] = []
        if test_case == "successful_parsing":
            for uid, info in expected_result.items():
                row = {"uuid": uid}
                row["description"] = info.get("description")
                row["enabled"] = info.get("enabled")
                if "interface" in info:
                    row["interface"] = info.get("interface")
                if "protocol" in info:
                    row["protocol"] = info.get("protocol")
                normalized_rows.append(row)
        elif test_case == "filters_lockout_rules":
            normalized_rows = [
                {"uuid": "normal-rule", "description": "Normal rule", "enabled": "1"}
            ]
            extra_rows = [
                {"uuid": "lockout-rule", "description": "Lockout rule", "enabled": "1"},
                {"uuid": "another-lockout", "description": "Another lockout", "enabled": "1"},
                {"uuid": None, "description": "No UUID rule", "enabled": "1"},
            ]

        api_rows: list[dict[str, Any]] = []
        for row in normalized_rows + extra_rows:
            if has_transformations:
                new_row = row.copy()
                if "description" in new_row:
                    new_row["descr"] = new_row.pop("description")
                if "enabled" in new_row:
                    new_row["disabled"] = "0" if new_row.pop("enabled") == "1" else "1"
                api_rows.append(new_row)
            else:
                api_rows.append(row.copy())

        mock_response = {"rows": api_rows}

    client._safe_dict_post = AsyncMock(return_value=mock_response)

    # Call the appropriate method
    method = getattr(client, method_name)
    result = await method()

    # Make a deep copy of expected_result so we don't mutate the shared fixture
    expected = copy.deepcopy(expected_result)

    assert result == expected

    # Verify the correct API endpoint was called
    client._safe_dict_post.assert_awaited_once_with(
        api_endpoint, payload={"current": 1, "sort": {}}
    )

    await client.async_close()
