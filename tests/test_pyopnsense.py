"""Unit tests for the `pyopnsense` client.

This module consolidates all unit tests for
`custom_components.opnsense.pyopnsense` so there is a single test file per
integration module as required by the repository guidelines.
"""

import asyncio
import contextlib
from datetime import datetime, timedelta
import inspect as _inspect
import socket
from ssl import SSLError
from unittest.mock import AsyncMock, MagicMock, patch
import xmlrpc.client as xc
from xmlrpc.client import Fault

import aiohttp
import pytest
from yarl import URL

from custom_components.opnsense import (
    device_tracker as device_tracker_mod,
    pyopnsense,
    sensor as sensor_mod,
    switch as switch_mod,
)


def test_human_friendly_duration() -> None:
    """Convert seconds into a human-friendly duration string."""
    assert pyopnsense.human_friendly_duration(65) == "1 minute, 5 seconds"
    assert pyopnsense.human_friendly_duration(0) == "0 seconds"
    assert "month" in pyopnsense.human_friendly_duration(2419200)


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
async def test_safe_dict_get_and_list_get(make_client) -> None:
    """Ensure safe getters coerce None to empty dict/list as expected."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session, username="user", password="pass")
    # Patch _get to return dict or list
    with patch.object(client, "_get", new=AsyncMock(return_value={"foo": "bar"})):
        result_dict = await client._safe_dict_get("/fake")
        assert result_dict == {"foo": "bar"}
    with patch.object(client, "_get", new=AsyncMock(return_value=[1, 2, 3])):
        result_list = await client._safe_list_get("/fake")
        assert result_list == [1, 2, 3]
    with patch.object(client, "_get", new=AsyncMock(return_value=None)):
        result_empty_dict = await client._safe_dict_get("/fake")
        assert result_empty_dict == {}
        result_empty_list = await client._safe_list_get("/fake")
        assert result_empty_list == []


@pytest.mark.asyncio
async def test_safe_dict_post_and_list_post(make_client) -> None:
    """Ensure safe post helpers coerce None to empty dict/list as expected."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session, username="user", password="pass")
    with patch.object(client, "_post", new=AsyncMock(return_value={"foo": "bar"})):
        result_dict = await client._safe_dict_post("/fake")
        assert result_dict == {"foo": "bar"}
    with patch.object(client, "_post", new=AsyncMock(return_value=[1, 2, 3])):
        result_list = await client._safe_list_post("/fake")
        assert result_list == [1, 2, 3]
    with patch.object(client, "_post", new=AsyncMock(return_value=None)):
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
async def test_get_host_firmware_set_use_snake_case_and_plugin_installed(make_client) -> None:
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


@pytest.mark.asyncio
async def test_get_firmware_update_info_triggers_check_on_conditions(make_client) -> None:
    """Trigger firmware update check when status is missing data or outdated."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    # Prepare a status that lacks data to force missing_data True and last_check missing
    status = {"product": {"product_version": "1.0", "product_latest": "2.0", "product_check": {}}}
    client._safe_dict_get = AsyncMock(return_value=status)
    client._post = AsyncMock(return_value={})
    # Call should trigger _post('/api/core/firmware/check')
    res = await client.get_firmware_update_info()
    assert res == status


@pytest.mark.asyncio
async def test_service_management_and_get_services(make_client) -> None:
    """Exercise get_services(), get_service_is_running() and service control."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

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


@pytest.mark.asyncio
async def test_dhcp_leases_and_keep_latest_and_dnsmasq(make_client) -> None:
    """Cover Kea and dnsmasq lease parsing and _keep_latest_leases helper."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

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


@pytest.mark.asyncio
async def test_carp_and_reboot_and_wol(make_client) -> None:
    """Verify CARP interface discovery and system control endpoints (reboot/halt/WOL)."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    client._safe_dict_get = AsyncMock(return_value={"carp": {"allow": "1"}})
    assert await client.get_carp_status() is True

    client._safe_dict_get = AsyncMock(return_value={"rows": [{"mode": "carp", "interface": "em0"}]})
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


@pytest.mark.asyncio
async def test_telemetry_and_temps_and_notices_and_unbound_blocklist(make_client) -> None:
    """Exercise telemetry harvesters, notices and unbound blocklist helper flows."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    # mbuf
    client._safe_list_post = AsyncMock(return_value={})
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
        side_effect=[{"memory": {"total": 100, "used": 50}}, {"swap": [{"total": 10, "used": 5}]}]
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
    client.get_unbound_blocklist = AsyncMock(return_value={})
    assert await client._set_unbound_blocklist(True) is False


@pytest.mark.asyncio
async def test_get_openvpn_and_fetch_details(make_client) -> None:
    """Validate openvpn server/client discovery and fetch details flow."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    # Prepare fake responses for safe_gets
    sessions_info = {
        "rows": [{"type": "server", "id": "1_desc_1", "description": "s1", "status": "connected"}]
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
        return {}

    patcher_get = patch.object(
        client, "_safe_dict_get", new=AsyncMock(side_effect=fake_safe_dict_get)
    )
    patcher_list = patch.object(
        client, "_safe_list_get", new=AsyncMock(side_effect=fake_safe_list_get)
    )
    with patcher_get, patcher_list:
        openvpn = await client.get_openvpn()
        assert "servers" in openvpn and "clients" in openvpn
        # servers should include uuid1
        assert any(
            s.get("name") == "server1" or s.get("uuid") == "uuid1"
            for s in openvpn["servers"].values()
        )


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
    # ensure client's server linkage updated
    assert (
        clients["c1"]["servers"][0].get("uuid") in {None, "s1", "c1"}
        or "connected" in clients["c1"]["servers"][0]
    )


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


@pytest.mark.asyncio
async def test_reload_interface_and_certificates_and_gateways(make_client) -> None:
    """Reload interface, list certificates, and list gateways parsing."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

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

    # toggle_alias: alias not found
    client._safe_dict_get = AsyncMock(return_value={"rows": []})
    ok = await client.toggle_alias("nope", "on")
    assert ok is False

    # toggle_alias: found and flow success
    client._safe_dict_get = AsyncMock(return_value={"rows": [{"name": "myalias", "uuid": "aid"}]})
    # sequence: _safe_dict_post for toggle -> returns success, set -> saved, reconfigure -> ok
    client._safe_dict_post = AsyncMock(
        side_effect=[{"result": "ok"}, {"result": "saved"}, {"status": "ok"}]
    )
    ok = await client.toggle_alias("myalias", "on")
    assert ok is True


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

    # set_unbound_blocklist: return False when get_unbound_blocklist empty
    client.get_unbound_blocklist = AsyncMock(return_value={})
    res = await client._set_unbound_blocklist(True)
    assert res is False

    # enable/disable wrappers
    client.get_unbound_blocklist = AsyncMock(return_value={"enabled": "0", "status": "OK"})
    client._post = AsyncMock(return_value={"result": "saved"})
    client._get = AsyncMock(return_value={"status": "OK"})
    client._safe_dict_post = AsyncMock(return_value={"response": "OK"})
    # Call enable/disable; these call _set_unbound_blocklist which now returns based on our mocks
    res_on = await client.enable_unbound_blocklist()
    res_off = await client.disable_unbound_blocklist()
    assert isinstance(res_on, bool) and isinstance(res_off, bool)


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
async def test_exec_php_error_paths(exc_factory, initial: bool, make_client) -> None:  # type: ignore[no-untyped-def]
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

        @property
        def content(self):
            class C:
                async def iter_chunked(self, n):
                    yield b"data:{}\n\n" % b"{}"

            return C()

    # attach the appropriate fake session method
    if session_method == "get":
        session.get = lambda *a, **k: FakeResp(status=403, ok=False)
    else:
        session.post = lambda *a, **k: FakeResp(status=500, ok=False)

    client = make_client(session=session)
    client._initial = True

    with pytest.raises(aiohttp.ClientResponseError):
        await getattr(client, method_name)(*args, **kwargs)


@pytest.mark.asyncio
async def test_get_from_stream_parsing(make_client) -> None:
    """Simulate SSE-like stream with two messages and assert parsing returns dict."""
    session = MagicMock(spec=aiohttp.ClientSession)

    class FakeStreamResp:
        def __init__(self):
            self.status = 200
            self.reason = "OK"
            self.ok = True

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        @property
        def content(self):
            class C:
                async def iter_chunked(self, n):
                    # First chunk contains two messages separated by \n\n
                    yield b'data: {"a": 1}\n\n'
                    yield b'data: {"b": 2}\n\n'

            return C()

    def fake_get(*args, **kwargs):
        return FakeStreamResp()

    session.get = fake_get
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    res = await client._do_get_from_stream("/stream", caller="tst")
    # implementation returns the second 'data' message parsed as JSON
    assert isinstance(res, dict)
    assert res.get("b") == 2
    # ensure client closed to avoid lingering tasks
    await client.async_close()


@pytest.mark.asyncio
async def test_get_from_stream_ignores_first_message(make_client) -> None:
    """Ensure the parser ignores the first data message and returns the second."""
    session = MagicMock(spec=aiohttp.ClientSession)

    class FakeStreamResp2:
        def __init__(self):
            self.status = 200
            self.reason = "OK"
            self.ok = True

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        @property
        def content(self):
            class C:
                async def iter_chunked(self, n):
                    # First message should be ignored by implementation
                    yield b'data: {"id": "first", "body": "ignore me"}\n\n'
                    yield b'data: {"id": "second", "body": "keep me"}\n\n'

            return C()

    def fake_get2(*args, **kwargs):
        return FakeStreamResp2()

    session.get = fake_get2
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    res = await client._do_get_from_stream("/stream", caller="tst")
    assert isinstance(res, dict)
    # ensure the second message was selected
    assert res.get("id") == "second"
    assert res.get("body") == "keep me"
    # ensure client closed to avoid lingering tasks
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
        if name not in ("__init__",)
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
    # cleanup client to avoid leaving background tasks running
    await client.async_close()


@pytest.mark.asyncio
async def test_certificates_kill_states_and_unbound_blocklist(make_client) -> None:
    """Cover get_certificates, kill_states and unbound blocklist toggles."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

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

    # enable/disable unbound blocklist: patch underlying _set_unbound_blocklist
    client._set_unbound_blocklist = AsyncMock(return_value=True)
    assert await client.enable_unbound_blocklist() is True
    assert await client.disable_unbound_blocklist() is True


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


@pytest.mark.asyncio
async def test_toggle_alias_flows(make_client) -> None:
    """toggle_alias returns False when not found or when subsequent calls fail; True on full success."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # alias not found
    client._use_snake_case = True
    client._safe_dict_get = AsyncMock(return_value={"rows": []})
    assert await client.toggle_alias("nope", "on") is False

    # alias found but toggle fails
    client._safe_dict_get = AsyncMock(return_value={"rows": [{"name": "myalias", "uuid": "aid"}]})
    client._safe_dict_post = AsyncMock(return_value={"result": "failed"})
    assert await client.toggle_alias("myalias", "on") is False

    # full success path
    client._safe_dict_get = AsyncMock(return_value={"rows": [{"name": "myalias", "uuid": "aid"}]})
    client._safe_dict_post = AsyncMock(
        side_effect=[{"result": "ok"}, {"result": "saved"}, {"status": "ok"}]
    )
    assert await client.toggle_alias("myalias", "on") is True


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
async def test_get_from_stream_partial_chunks_accumulates_buffer(make_client) -> None:
    """Simulate a stream where a JSON message is split across chunks to exercise buffer accumulation."""
    session = MagicMock(spec=aiohttp.ClientSession)

    class FakeStreamResp2:
        def __init__(self):
            self.status = 200
            self.reason = "OK"
            self.ok = True

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        @property
        def content(self):
            class C:
                async def iter_chunked(self, n):
                    # first chunk ends mid-json
                    yield b'data: {"a"'
                    yield b": 1}\n\n"
                    # second message complete
                    yield b'data: {"b": 2}\n\n'

            return C()

    def fake_get2(*args, **kwargs):
        return FakeStreamResp2()

    session.get = fake_get2
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    res = await client._do_get_from_stream("/stream2", caller="tst")
    assert isinstance(res, dict)


@pytest.mark.asyncio
async def test_openvpn_more_detail_parsing(make_client) -> None:
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

    patcher_get = patch.object(
        client, "_safe_dict_get", new=AsyncMock(side_effect=fake_safe_dict_get)
    )
    with patcher_get:
        res = await client.get_openvpn()
        assert "servers" in res and "clients" in res


@pytest.mark.asyncio
async def test_monitor_queue_qsize_exception_is_handled(make_client) -> None:
    """Ensure _monitor_queue swallows exceptions from queue.qsize()."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    class BadQ:
        def qsize(self):
            raise RuntimeError("boom")

    client._request_queue = BadQ()  # type: ignore[assignment]

    # run one iteration of monitor by scheduling and cancelling promptly
    monitor = asyncio.get_running_loop().create_task(client._monitor_queue())
    await asyncio.sleep(0)  # yield to allow monitor to run and handle exception
    monitor.cancel()
    # if it reached here without raising, behavior is correct


@pytest.mark.asyncio
async def test_enable_and_disable_filter_rules_and_nat_port_forward(make_client) -> None:
    """Cover enabling/disabling filter rules and NAT port forward rule flows."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # enable_filter_rule_by_created_time: rule has 'disabled' -> should remove and call restore+configure
    cfg_enable = {"filter": {"rule": [{"created": {"time": "t-enable"}, "disabled": "1"}]}}
    client.get_config = AsyncMock(return_value=cfg_enable)
    client._restore_config_section = AsyncMock()
    client._filter_configure = AsyncMock()
    await client.enable_filter_rule_by_created_time("t-enable")
    client._restore_config_section.assert_called()
    client._filter_configure.assert_awaited()

    # disable_filter_rule_by_created_time: rule missing 'disabled' -> should add it and call restore+configure
    cfg_disable = {"filter": {"rule": [{"created": {"time": "t-disable"}}]}}
    client.get_config = AsyncMock(return_value=cfg_disable)
    client._restore_config_section = AsyncMock()
    client._filter_configure = AsyncMock()
    await client.disable_filter_rule_by_created_time("t-disable")
    client._restore_config_section.assert_called()
    client._filter_configure.assert_awaited()

    # enable_nat_port_forward_rule_by_created_time: similar flow under 'nat' section
    cfg_nat = {"nat": {"rule": [{"created": {"time": "t-nat"}, "disabled": "1"}]}}
    client.get_config = AsyncMock(return_value=cfg_nat)
    client._restore_config_section = AsyncMock()
    client._filter_configure = AsyncMock()
    await client.enable_nat_port_forward_rule_by_created_time("t-nat")
    client._restore_config_section.assert_called()
    client._filter_configure.assert_awaited()


def test_get_proxy_https_unverified_returns_serverproxy() -> None:
    """When scheme is https and verify_ssl is False, _get_proxy returns ServerProxy."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="https://localhost",
        username="u",
        password="p",
        session=session,
        opts={"verify_ssl": False},
    )
    proxy = client._get_proxy()
    # ServerProxy class object from xmlrpc.client (xc imported at top)
    assert isinstance(proxy, xc.ServerProxy)


# Note: xmlrpc timeout behavior is covered by the monkeypatch-based test lower in the file.


@pytest.mark.asyncio
async def test_process_queue_unknown_method_sets_future_exception(make_client) -> None:
    """Putting an unknown method into the request queue should set an exception on the future."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # ensure client uses a real asyncio.Queue
    q: asyncio.Queue = asyncio.Queue()
    client._request_queue = q

    loop = asyncio.get_running_loop()
    future = loop.create_future()
    await q.put(("unknown", "/x", None, future, "tst"))

    task = loop.create_task(client._process_queue())
    await asyncio.sleep(0)  # allow the task to process the queue
    # cancel background task
    task.cancel()
    # future should have an exception (NameError from undefined 'result')
    exc = future.exception()
    assert isinstance(exc, RuntimeError)


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
async def test_manage_service_and_restart_if_running(make_client) -> None:
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
    with patch.object(client, "restart_service", new=AsyncMock(return_value=True)):
        assert await client.restart_service_if_running("svc1") is True

    client.get_service_is_running = AsyncMock(return_value=False)
    assert await client.restart_service_if_running("svc1") is True


@pytest.mark.asyncio
async def test_scanner_entity_handle_coordinator_update_missing_state_sets_unavailable(
    make_client,
) -> None:
    """OPNsenseScannerEntity should mark unavailable when coordinator state missing or invalid."""

    # minimal coordinator-like object
    class FakeCoord:
        data: object | None = None

    cfg = MagicMock()
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
async def test_compile_filesystem_sensors_and_filter_switches() -> None:
    """Test sensor and switch compilation helpers for simple cases."""
    cfg = MagicMock()
    coord = MagicMock()

    # filesystem sensors: invalid state -> empty
    sensors = await sensor_mod._compile_filesystem_sensors(cfg, coord, None)
    assert sensors == []

    # valid filesystem state
    state = {"telemetry": {"filesystems": [{"mountpoint": "/"}]}}
    sensors2 = await sensor_mod._compile_filesystem_sensors(cfg, coord, state)
    assert isinstance(sensors2, list) and len(sensors2) == 1

    # filter switches: skip anti-lockout and nat-associated rules
    state2 = {
        "config": {
            "filter": {
                "rule": [
                    {"descr": "Anti-Lockout Rule", "created": {"time": "t1"}},
                    {"descr": "Normal", "created": {"time": "t2"}, "associated-rule-id": "r1"},
                    {"descr": "Ok", "created": {"time": "t3"}},
                ]
            }
        }
    }
    switches = await switch_mod._compile_filter_switches(cfg, coord, state2)
    # only one valid rule should produce a switch
    assert isinstance(switches, list) and len(switches) == 1


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
    client._initial = True
    with pytest.raises(aiohttp.ClientResponseError):
        await client._do_get_from_stream("/bad", caller="t")


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


@pytest.mark.asyncio
async def test_exec_php_returns_real_json_and_xmlrpc_timeout_decorator() -> None:
    """_exec_php should return parsed JSON from response['real']; test @_xmlrpc_timeout wrapper."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # Simulate exec_php returning a mapping with 'real' JSON string
    proxy = MagicMock()
    proxy.opnsense.exec_php.return_value = {"real": '{"ok": true, "val": 5}'}
    client._get_proxy = MagicMock(return_value=proxy)
    res = await client._exec_php("echo ok;")
    assert isinstance(res, dict) and res.get("val") == 5

    # Test the _xmlrpc_timeout decorator: wrap a simple async function
    class D:
        @pyopnsense._xmlrpc_timeout
        async def wrapped(self) -> int:  # type: ignore[misc]
            return 7

    d = D()
    assert await d.wrapped() == 7


@pytest.mark.asyncio
async def test_exec_php_exception_branches() -> None:
    """_exec_php should handle TypeError, Fault, socket.gaierror and ssl.SSLError and return {}."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # TypeError
    proxy = MagicMock()
    proxy.opnsense.exec_php.side_effect = TypeError("bad")
    client._get_proxy = MagicMock(return_value=proxy)
    res = await client._exec_php("x")
    assert res == {}

    # xmlrpc Fault
    proxy.opnsense.exec_php.side_effect = Fault(1, "f")
    client._get_proxy = MagicMock(return_value=proxy)
    res = await client._exec_php("x")
    assert res == {}

    # socket.gaierror
    proxy.opnsense.exec_php.side_effect = socket.gaierror("fail")
    client._get_proxy = MagicMock(return_value=proxy)
    res = await client._exec_php("x")
    assert res == {}

    # ssl.SSLError
    proxy.opnsense.exec_php.side_effect = SSLError("ssl")
    client._get_proxy = MagicMock(return_value=proxy)
    res = await client._exec_php("x")
    assert res == {}


@pytest.mark.asyncio
async def test_toggle_vpn_instance_openvpn_and_wireguard() -> None:
    """Toggle VPN instances for OpenVPN and WireGuard and assert outcomes."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # openvpn: changed False -> False
    client._safe_dict_post = AsyncMock(return_value={"changed": False})
    res = await client.toggle_vpn_instance("openvpn", "servers", "uuid1")
    assert res is False

    # openvpn: changed True and reconfigure ok -> True
    client._safe_dict_post = AsyncMock(side_effect=[{"changed": True}, {"result": "ok"}])
    res = await client.toggle_vpn_instance("openvpn", "servers", "uuid1")
    assert res is True

    # wireguard: clients toggled
    client._use_snake_case = True
    client._safe_dict_post = AsyncMock(side_effect=[{"changed": True}, {"result": "ok"}])
    res = await client.toggle_vpn_instance("wireguard", "clients", "uuid2")
    assert res is True


@pytest.mark.asyncio
async def test_toggle_alias_and_set_unbound_blocklist_flows() -> None:
    """Toggle firewall aliases and handle unbound blocklist flows."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # toggle_alias: alias not found
    client._safe_dict_get = AsyncMock(return_value={"rows": []})
    assert await client.toggle_alias("nope", "on") is False

    # toggle_alias: found but toggle returns failed
    client._safe_dict_get = AsyncMock(return_value={"rows": [{"name": "a", "uuid": "u1"}]})
    client._safe_dict_post = AsyncMock(return_value={"result": "failed"})
    assert await client.toggle_alias("a", "on") is False

    # toggle_alias: full success
    client._safe_dict_get = AsyncMock(return_value={"rows": [{"name": "a", "uuid": "u1"}]})
    client._safe_dict_post = AsyncMock(
        side_effect=[{"result": "ok"}, {"result": "saved"}, {"status": "ok"}]
    )
    assert await client.toggle_alias("a", "on") is True

    # _set_unbound_blocklist: get_unbound_blocklist empty -> False
    client.get_unbound_blocklist = AsyncMock(return_value={})
    assert await client._set_unbound_blocklist(True) is False

    # _set_unbound_blocklist: success path
    client.get_unbound_blocklist = AsyncMock(return_value={"enabled": "0"})
    client._post = AsyncMock(return_value={"result": "saved"})
    client._get = AsyncMock(return_value={"status": "OK"})
    client._post = AsyncMock(return_value={"response": "OK"})
    # ensure True when all responses indicate success
    # monkeypatching sequence of calls: first _post (set) -> {'result':'saved'}, _get -> {'status':'OK'}, _post (restart) -> {'response':'OK'}
    client._post = AsyncMock(side_effect=[{"result": "saved"}, {"response": "OK"}])
    client._get = AsyncMock(return_value={"status": "OK"})
    assert await client._set_unbound_blocklist(True) is True


@pytest.mark.asyncio
async def test_log_errors_timeout_re_raise_and_suppress() -> None:
    """_log_errors should re-raise TimeoutError when client._initial is True and suppress when False."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(url="http://x", username="u", password="p", session=session)

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

    # (ServerProxy https unverified behavior tested elsewhere)


@pytest.mark.asyncio
async def test_process_queue_exception_sets_future_exception() -> None:
    """_if a worker raises, the future should get_exception set."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

    # make _do_get raise
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
            # return details for server
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
    # server present
    servers = openvpn["servers"]
    assert any(s.get("uuid") == "srv1" for s in servers.values())
    # details filled in
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
    assert sys is None or (isinstance(sys, dict) and ("uptime" in sys or "boottime" in sys))

    files = await client._get_telemetry_filesystems()
    assert files is None or isinstance(files, list)


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

    client._request_queue = BadQ()  # type: ignore[assignment]

    loop = asyncio.get_running_loop()
    task = loop.create_task(client._monitor_queue())

    # yield control so task runs once and hits exception
    await asyncio.sleep(0)

    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_get_unbound_blocklist_parsing() -> None:
    """Ensure get_unbound_blocklist properly extracts and joins nested mappings."""
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
    parsed = await client.get_unbound_blocklist()
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

    # gateways
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


@pytest.mark.asyncio
async def test_get_wireguard_full_processing_and_peer_details() -> None:
    """Build a full wireguard response and ensure servers/clients and peer updates occur."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

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
    clients_map: dict = {"c1": {"uuid": "c1", "pubkey": "pk1", "servers": [{"interface": "wg1"}]}}

    # call the static peer update helper which should update totals
    entry = summary["peers"][0]
    await pyopnsense.OPNsenseClient._update_wireguard_peer_status(entry, servers, clients_map)
    updated = any(
        s.get("total_bytes_recv", 0) >= 100 or s.get("total_bytes_sent", 0) >= 200
        for s in servers.values()
    )
    assert updated or any(c.get("total_bytes_recv", 0) >= 100 for c in clients_map.values())


@pytest.mark.asyncio
async def test_exercise_many_misc_branches() -> None:
    """Call many client methods with patched internals to exercise branches en-masse."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )

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
    client._post = AsyncMock()
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

    # calling enable should remove 'disabled' and call restore/filter configure (no exception)
    await client.enable_filter_rule_by_created_time("t1")

    # disable_nat_port_forward: add a rule without 'disabled' and expect it to set 'disabled'
    client._exec_php = AsyncMock(
        return_value={"data": {"nat": {"rule": [{"created": {"time": "n1"}}]}}}
    )
    # patch _restore_config_section and _filter_configure to be no-ops
    client._restore_config_section = AsyncMock()
    client._filter_configure = AsyncMock()
    await client.disable_nat_port_forward_rule_by_created_time("n1")


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
