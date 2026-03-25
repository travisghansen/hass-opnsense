"""Tests for `pyopnsense.dhcp`."""

from collections.abc import MutableMapping
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

from custom_components.opnsense import pyopnsense


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
        # should keep a single latest lease for duplicate keys
        filtered = [item for item in res if item.get("a") == 1]
        assert len(filtered) == 1
        assert filtered[0]["expire"] == 20

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
        assert len(dns) > 0
        assert dns[0]["address"] == "1.2.3.4"
        assert dns[0]["mac"] == "mac1"
        assert dns[0]["type"] == "static"
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_isc_dhcp_endpoint_unavailable(make_client) -> None:
    """ISC DHCP lease methods should return empty list when endpoints are unavailable."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client.is_endpoint_available = AsyncMock(return_value=False)
        client._safe_dict_get = AsyncMock()

        # Test DHCPv4
        leases_v4 = await client._get_isc_dhcpv4_leases()
        assert leases_v4 == []
        client._safe_dict_get.assert_not_awaited()

        # Test DHCPv6
        client._safe_dict_get.reset_mock()
        leases_v6 = await client._get_isc_dhcpv6_leases()
        assert leases_v6 == []
        client._safe_dict_get.assert_not_awaited()
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_dhcp_edge_cases_and_keep_latest(make_client) -> None:
    """Ensure DHCP parsing and _keep_latest_leases handle odd entries."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
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
        filtered = [item for item in res if item.get("a") == 1]
        assert len(filtered) == 1
        assert filtered[0]["expire"] == 20
        assert any(item for item in res if item.get("b") == 2)
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_isc_dhcpv4_and_v6_parsing() -> None:
    """Test ISC DHCPv4/v6 parsing of 'ends' -> datetime and filtering logic."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        local_tz = datetime.now().astimezone().tzinfo
        assert local_tz is not None
        client._get_opnsense_timezone = AsyncMock(return_value=local_tz)

        # v4: ends present and in future
        future_dt = (datetime.now() + timedelta(hours=1)).strftime("%Y/%m/%d %H:%M:%S")
        client._use_snake_case = False
        client.is_endpoint_available = AsyncMock(return_value=True)
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
        assert v4[0]["address"] == "10.0.0.1"
        assert v4[0]["mac"] == "m1"
        assert v4[0]["hostname"] == "h1"
        assert isinstance(v4[0].get("expires"), datetime)

        # v6: ends missing -> field passed through
        client._use_snake_case = True
        client.is_endpoint_available = AsyncMock(return_value=True)
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
        assert v6[0]["address"] == "fe80::1"
        assert v6[0]["mac"] == "m2"
        assert v6[0]["hostname"] == "h2"
        assert "ends" not in v6[0]
        assert v6[0].get("expires") is None
        assert "ends_at" not in v6[0] or v6[0]["ends_at"] is None
        assert "expiry" not in v6[0] or v6[0]["expiry"] is None
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_dhcp_leases_combined_structure() -> None:
    """Ensure get_dhcp_leases combines multiple sources and returns expected mapping."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        local_tz = datetime.now().astimezone().tzinfo
        assert local_tz is not None
        client._get_opnsense_timezone = AsyncMock(return_value=local_tz)

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
        assert isinstance(combined, MutableMapping)
        assert "em0" in combined["lease_interfaces"]
        assert combined["lease_interfaces"]["em0"] is None
        assert isinstance(combined["leases"], MutableMapping)
        assert "em0" in combined["leases"]
        assert len(combined["leases"]["em0"]) > 0
        assert any(
            lease.get("address") == "1.1.1.1" and lease.get("mac") == "m1"
            for lease in combined["leases"]["em0"]
        )
        assert any(
            lease.get("address") == "1.1.1.2" and lease.get("mac") == "m2"
            for lease in combined["leases"]["em0"]
        )
        client._get_opnsense_timezone.assert_awaited_once_with()
        client._get_kea_dhcpv4_leases.assert_awaited_once_with(opnsense_tz=local_tz)
        client._get_isc_dhcpv4_leases.assert_awaited_once_with(opnsense_tz=local_tz)
        client._get_isc_dhcpv6_leases.assert_awaited_once_with(opnsense_tz=local_tz)
        client._get_dnsmasq_leases.assert_awaited_once_with(opnsense_tz=local_tz)
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_dhcp_leases_calls_isc_methods_independently() -> None:
    """get_dhcp_leases should call both ISC helpers regardless of top-level endpoint status."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        local_tz = datetime.now().astimezone().tzinfo
        assert local_tz is not None
        client._get_opnsense_timezone = AsyncMock(return_value=local_tz)
        client._get_kea_dhcpv4_leases = AsyncMock(
            return_value=[{"if_name": "em0", "address": "1.1.1.1", "mac": "m1"}]
        )
        client._get_dnsmasq_leases = AsyncMock(return_value=[])
        client._get_isc_dhcpv4_leases = AsyncMock(return_value=[])
        client._get_isc_dhcpv6_leases = AsyncMock(return_value=[])
        client._get_kea_interfaces = AsyncMock(return_value={"em0": "eth0"})

        combined = await client.get_dhcp_leases()

        assert "em0" in combined["leases"]
        client._get_isc_dhcpv4_leases.assert_awaited_once_with(opnsense_tz=local_tz)
        client._get_isc_dhcpv6_leases.assert_awaited_once_with(opnsense_tz=local_tz)
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_kea_leases_with_reservations_and_expiry_handling() -> None:
    """Exercise _get_kea_dhcpv4_leases reservation matching and expiry logic."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
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
            """Return the canned reservation search payload for matching DHCP paths.

            Args:
                path: Path provided by pytest or the test case.
            """
            if "search_reservation" in path or "searchReservation" in path:
                return {"rows": res_rows}
            if "leases4/search" in path:
                return {"rows": lease_rows}
            return {}

        client._safe_dict_get = AsyncMock(side_effect=fake_safe)
        leases = await client._get_kea_dhcpv4_leases()
        assert isinstance(leases, list) and len(leases) == 1
        assert leases[0].get("type") == "static"
    finally:
        await client.async_close()
