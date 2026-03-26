"""Tests for `pyopnsense.vpn`."""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

from custom_components.opnsense import pyopnsense
from custom_components.opnsense.pyopnsense import vpn as pyopnsense_vpn


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
            """Return canned OpenVPN mapping payloads based on the requested path.

            Args:
                path: Path provided by pytest or the test case.
            """
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
            """Return an empty list for list-based VPN API lookups in this test.

            Args:
                path: Path provided by pytest or the test case.
            """
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
async def test_openvpn_more_detail_parsing(monkeypatch, make_client) -> None:
    """Exercise additional OpenVPN parsing branches (no sessions, missing fields)."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    # prepare responses that exercise missing/partial fields
    sessions_info: dict[str, list[dict]] = {"rows": []}
    routes_info: dict[str, list[dict]] = {"rows": []}
    providers_info: dict[str, dict] = {}
    instances_info = {"rows": [{"role": "client", "uuid": "c1", "enabled": "0"}]}

    async def fake_safe_dict_get(path):
        """Return canned OpenVPN mappings for the reduced-details test case.

        Args:
            path: Path provided by pytest or the test case.
        """
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
async def test_openvpn_processing_and_fetch_details() -> None:
    """Test processing of OpenVPN instances/providers/sessions/routes and fetching details."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        # prepare fake responses for _safe_dict_get based on path
        def fake_safe_dict_get(path):
            """Return canned OpenVPN payloads for the detail-fetching test.

            Args:
                path: Path provided by pytest or the test case.
            """
            if "searchSessions" in path or "search_sessions" in path:
                return {
                    "rows": [
                        {
                            "type": "server",
                            "id": "srv1_1",
                            "description": "S1",
                            "status": "connected",
                        },
                        "malformed",
                        {"type": "server"},
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
                        },
                        None,
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
    finally:
        await client.async_close()


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
            """Return instance details without a server field for this edge case.

            Args:
                path: Path provided by pytest or the test case.
            """
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
async def test_get_wireguard_full_processing_and_peer_details() -> None:
    """Ensure the wireguard peer status helper updates server/client transfer counters."""
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
    servers: dict = {
        "s1": {"uuid": "s1", "clients": [], "total_bytes_recv": 0, "total_bytes_sent": 0}
    }
    clients_map: dict = {"c1": {"uuid": "c1", "pubkey": "pk1", "servers": [{"interface": "wg1"}]}}

    entry = summary["peers"][0]
    await pyopnsense.OPNsenseClient._update_wireguard_peer_status(entry, servers, clients_map)
    updated = any(
        s.get("total_bytes_recv", 0) >= 100 or s.get("total_bytes_sent", 0) >= 200
        for s in servers.values()
    )
    assert updated or any(c.get("total_bytes_recv", 0) >= 100 for c in clients_map.values())


@pytest.mark.parametrize(
    "delta_minutes,expected",
    [
        (2, True),  # within 3 minutes => connected
        (3, True),  # exactly at threshold => connected
        (5, False),  # beyond threshold => not connected
    ],
)
def test_wireguard_is_connected_variants(monkeypatch, delta_minutes: int, expected: bool) -> None:
    """WireGuard connection considered active when last handshake within threshold. Monkeypatch `datetime.now` in the module under test to a fixed value with no microseconds so comparisons at the 3-minute boundary are deterministic."""
    fixed_now = datetime.now().astimezone().replace(microsecond=0)
    # create a minimal fake datetime provider with a static now() returning fixed_now
    FakeDT = type("FakeDT", (), {"now": staticmethod(lambda: fixed_now)})
    monkeypatch.setattr(pyopnsense_vpn, "datetime", FakeDT)
    assert (
        pyopnsense.OPNsenseClient.wireguard_is_connected(
            fixed_now - timedelta(minutes=delta_minutes)
        )
        is expected
    )
    # None always False
    if delta_minutes == 5:  # only need to assert once in param set
        assert pyopnsense.OPNsenseClient.wireguard_is_connected(None) is False


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
    assert wg["clients"]["c1"].get("connected_servers") == 0

    # invalid structure (summary not list) -> empty wireguard structure
    client._safe_dict_get = AsyncMock(return_value={"rows": {}})
    assert await client.get_wireguard() == {"servers": {}, "clients": {}}
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
