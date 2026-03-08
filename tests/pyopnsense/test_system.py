"""Tests for `pyopnsense.system`."""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

from custom_components.opnsense import pyopnsense


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
async def test_carp_and_reboot_and_wol(make_client) -> None:
    """Verify CARP interface discovery and system control endpoints (reboot/halt/WOL)."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client._safe_dict_get = AsyncMock(return_value={"carp": {"allow": "1"}})
        assert await client.get_carp_status() is True

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
async def test_gateways_notices_and_close_notice_all() -> None:
    """Test gateway notices handling and closing all notices."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        client._safe_dict_get = AsyncMock(
            return_value={"items": [{"name": "gw1", "status_translated": "OK"}]}
        )
        gws = await client.get_gateways()
        assert "gw1" in gws and gws["gw1"]["status"] == "ok"

        # notices: include a pending notice
        client._safe_dict_get = AsyncMock(
            return_value={
                "n1": {
                    "statusCode": 1,
                    "message": "m",
                    "timestamp": int(datetime.now().timestamp()),
                }
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
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_carp_and_system_actions_and_wol() -> None:
    """Test get_carp_status, get_carp_interfaces, reboot/halt and send_wol."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
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
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_device_unique_id_no_mac(make_client) -> None:
    """get_device_unique_id returns None when no physical mac addresses present."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client._safe_list_get = AsyncMock(return_value=[{"is_physical": False}])
        assert await client.get_device_unique_id() is None
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_device_unique_id_expected(make_client) -> None:
    """get_device_unique_id returns expected_id if present even if not the first."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        # aa_bb_cc is smaller than bb_cc_dd
        client._safe_list_get = AsyncMock(
            return_value=[
                {"is_physical": True, "macaddr_hw": "aa:bb:cc"},
                {"is_physical": True, "macaddr_hw": "bb:cc:dd"},
            ]
        )
        # Without expected_id, it returns the first one (aa_bb_cc)
        assert await client.get_device_unique_id() == "aa_bb_cc"

        # With expected_id bb_cc_dd, it returns bb_cc_dd even if aa_bb_cc is smaller
        assert await client.get_device_unique_id(expected_id="bb_cc_dd") == "bb_cc_dd"

        # With expected_id not present, it returns the first one
        assert await client.get_device_unique_id(expected_id="cc_dd_ee") == "aa_bb_cc"
    finally:
        await client.async_close()
