"""Tests for `pyopnsense.system`."""

from datetime import datetime, timedelta
from typing import Any
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
async def test_get_opnsense_timezone_parse_and_fallback(make_client) -> None:
    """_get_opnsense_timezone should parse valid timezone strings and fallback on errors."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client._use_snake_case = True
        client._safe_dict_post = AsyncMock(return_value={"datetime": "2026-03-07 12:00:00 EST"})
        parsed_tz = await client._get_opnsense_timezone()
        assert parsed_tz is not None
        parsed_dt = datetime(2026, 3, 7, 12, 0, 0, tzinfo=parsed_tz)
        assert parsed_tz.utcoffset(parsed_dt) == timedelta(hours=-5)

        client._safe_dict_post = AsyncMock(return_value={"datetime": "not-a-datetime"})
        fallback_tz = await client._get_opnsense_timezone()
        assert fallback_tz is not None
        local_tz = datetime.now().astimezone().tzinfo
        assert local_tz is not None
        now_local = datetime.now().astimezone()
        assert fallback_tz == local_tz or fallback_tz.utcoffset(now_local) == local_tz.utcoffset(
            now_local
        )

        client._safe_dict_post = AsyncMock(side_effect=aiohttp.ClientError("transient fetch error"))
        fetch_fallback_tz = await client._get_opnsense_timezone()
        assert fetch_fallback_tz is not None
        assert fetch_fallback_tz == local_tz or fetch_fallback_tz.utcoffset(
            now_local
        ) == local_tz.utcoffset(now_local)
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_carp_summary_and_reboot_and_wol(make_client) -> None:
    """Verify CARP summary/discovery and system control endpoints (reboot/halt/WOL)."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client._safe_dict_get = AsyncMock(
            return_value={
                "rows": [
                    {
                        "interface": "em0",
                        "subnet": "10.0.0.1",
                        "status": "MASTER",
                        "mode": "carp",
                        "vhid": "1",
                        "advbase": "1",
                        "advskew": "0",
                    }
                ],
                "carp": {
                    "allow": "1",
                    "demotion": "0",
                    "maintenancemode": False,
                    "status_msg": "",
                },
            }
        )
        summary = dict((await client.get_carp()).get("status_summary", {}))
        assert summary["state"] == "healthy"
        assert summary["enabled"] is True
        assert summary["vip_count"] == 1
        assert summary["master_count"] == 1

        client._safe_dict_get = AsyncMock(
            side_effect=[
                {
                    "rows": [
                        {
                            "mode": "carp",
                            "interface": "em0",
                            "subnet": "10.0.0.1",
                            "vhid": "1",
                            "status": "MASTER",
                        }
                    ]
                },
                {"rows": [{"mode": "carp", "interface": "em0", "subnet": "10.0.0.1", "vhid": "1"}]},
            ]
        )
        carp = (await client.get_carp()).get("interfaces", [])
        assert isinstance(carp, list)
        assert carp[0]["status"] == "MASTER"
        assert carp[0]["interface"] == "em0"

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
async def test_get_carp_handles_invalid_payloads_and_default_status() -> None:
    """Verify CARP parsing tolerates malformed payloads and missing status values."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        client._safe_dict_get = AsyncMock(side_effect=[{"rows": "bad"}, {"rows": "bad"}])
        assert (await client.get_carp()).get("interfaces", []) == []

        client._safe_dict_get = AsyncMock(
            side_effect=[
                {
                    "rows": [
                        {"mode": "other", "interface": "em9"},
                        {"mode": "carp", "interface": "em0", "subnet": "10.0.0.1", "vhid": "11"},
                    ]
                },
                {
                    "rows": [
                        {"mode": "carp", "interface": "em1", "subnet": "10.0.0.9", "vhid": "12"}
                    ]
                },
            ]
        )
        carp = (await client.get_carp()).get("interfaces", [])
        assert len(carp) == 1
        assert carp[0]["interface"] == "em0"
        assert carp[0]["status"] == "DISABLED"

        client._safe_dict_get = AsyncMock(
            side_effect=[
                {
                    "rows": [
                        {
                            "mode": "carp",
                            "interface": "wan",
                            "subnet": "192.0.2.10",
                            "vhid": "20",
                            "status": "BACKUP",
                        }
                    ]
                },
                {"rows": "not-a-list"},
            ]
        )
        carp = (await client.get_carp()).get("interfaces", [])
        assert len(carp) == 1
        assert carp[0]["interface"] == "wan"
        assert carp[0]["status"] == "BACKUP"

        client._safe_dict_get = AsyncMock(
            side_effect=[
                {
                    "rows": [
                        {
                            "mode": "carp",
                            "interface": "opt1",
                            "vhid": "30",
                            "status": "MASTER",
                        }
                    ]
                },
                {"rows": []},
            ]
        )
        assert (await client.get_carp()).get("interfaces", []) == []
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_carp_matches_multiple_vips_on_same_interface() -> None:
    """Verify CARP enrichment matches by VIP identity, not interface alone."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        client._safe_dict_get = AsyncMock(
            side_effect=[
                {
                    "rows": [
                        {
                            "mode": "carp",
                            "interface": "lan",
                            "subnet": "10.0.0.1",
                            "vhid": "1",
                            "status": "MASTER",
                        },
                        {
                            "mode": "carp",
                            "interface": "lan",
                            "subnet": "10.0.0.2",
                            "vhid": "2",
                            "status": "BACKUP",
                        },
                    ]
                },
                {
                    "rows": [
                        {
                            "mode": "carp",
                            "interface": "lan",
                            "subnet": "10.0.0.1",
                            "vhid": "1",
                            "descr": "first",
                        },
                        {
                            "mode": "carp",
                            "interface": "lan",
                            "subnet": "10.0.0.2",
                            "vhid": "2",
                            "descr": "second",
                        },
                    ]
                },
            ]
        )
        carp = (await client.get_carp()).get("interfaces", [])
        assert len(carp) == 2
        by_subnet = {entry["subnet"]: entry for entry in carp}
        assert by_subnet["10.0.0.1"]["status"] == "MASTER"
        assert by_subnet["10.0.0.1"]["descr"] == "first"
        assert by_subnet["10.0.0.2"]["status"] == "BACKUP"
        assert by_subnet["10.0.0.2"]["descr"] == "second"
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_carp_returns_no_match_for_ambiguous_partial_key_collisions() -> None:
    """Verify fallback selection rejects ambiguous VIP setting candidates.

    Returns:
        None: This test validates ambiguous fallback matching behavior.
    """
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        client._safe_dict_get = AsyncMock(
            side_effect=[
                {
                    "rows": [
                        {
                            "mode": "carp",
                            "interface": "lan",
                            "vhid": "10",
                            "status": "MASTER",
                        }
                    ]
                },
                {
                    "rows": [
                        {
                            "mode": "carp",
                            "interface": "lan",
                            "subnet": "10.0.0.1",
                            "vhid": "10",
                            "descr": "first-candidate",
                        },
                        {
                            "mode": "carp",
                            "interface": "lan",
                            "subnet": "10.0.0.2",
                            "vhid": "10",
                            "descr": "second-candidate",
                        },
                    ]
                },
            ]
        )
        carp = (await client.get_carp()).get("interfaces", [])
        assert carp == []
    finally:
        await client.async_close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "expected_state"),
    [
        (
            {
                "rows": [
                    {"mode": "carp", "status": "MASTER", "interface": "wan", "subnet": "1.2.3.4"}
                ],
                "carp": {
                    "allow": "1",
                    "maintenancemode": False,
                    "demotion": "0",
                    "status_msg": "",
                },
            },
            "healthy",
        ),
        (
            {
                "rows": [],
                "carp": {
                    "allow": "1",
                    "maintenancemode": False,
                    "demotion": "0",
                    "status_msg": "",
                },
            },
            "not_configured",
        ),
        (
            {
                "rows": [
                    {"mode": "carp", "status": "MASTER", "interface": "wan", "subnet": "1.2.3.4"}
                ],
                "carp": {
                    "allow": "1",
                    "maintenancemode": True,
                    "demotion": "0",
                    "status_msg": "",
                },
            },
            "maintenance",
        ),
        (
            {
                "rows": [
                    {"mode": "carp", "status": "INIT", "interface": "wan", "subnet": "1.2.3.4"}
                ],
                "carp": {
                    "allow": "1",
                    "maintenancemode": False,
                    "demotion": "2",
                    "status_msg": "demoted",
                },
            },
            "degraded",
        ),
        (
            {
                "rows": [
                    {"mode": "carp", "status": "MASTER", "interface": "wan", "subnet": "1.2.3.4"}
                ],
                "carp": {
                    "allow": "0",
                    "maintenancemode": False,
                    "demotion": "0",
                    "status_msg": "",
                },
            },
            "disabled",
        ),
        (
            {
                "rows": [
                    {"mode": "carp", "status": "MASTER", "interface": "wan", "subnet": "1.2.3.4"}
                ],
                "carp": {
                    "allow": "1",
                    "maintenancemode": False,
                    "demotion": "0",
                    "status_msg": 0,
                },
            },
            "healthy",
        ),
        (
            {
                "rows": "bad",
                "carp": "bad",
            },
            "unknown",
        ),
        (
            {
                "rows": [{"mode": "carp", "status": "MASTER", "interface": "wan"}],
            },
            "unknown",
        ),
        (
            {
                "rows": [
                    {"mode": "carp", "status": "MASTER", "interface": "wan", "subnet": ""},
                    {"mode": "carp", "status": "BACKUP", "subnet": "1.2.3.4"},
                ],
                "carp": {
                    "allow": "1",
                    "maintenancemode": False,
                    "demotion": "0",
                    "status_msg": "",
                },
            },
            "not_configured",
        ),
    ],
)
async def test_get_carp_status_states(
    payload: dict[str, Any],
    expected_state: str,
) -> None:
    """Verify CARP summary state mapping across common health scenarios."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        client._safe_dict_get = AsyncMock(return_value=payload)
        summary = dict((await client.get_carp()).get("status_summary", {}))
        assert summary["state"] == expected_state
        assert "vips" in summary
        assert "vip_count" in summary
        if isinstance(payload.get("carp"), dict) and not isinstance(
            payload["carp"].get("status_msg", ""),
            str,
        ):
            assert summary["status_message"] == ""
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_carp_skips_whitespace_interface_values() -> None:
    """Verify CARP merge drops entries whose interface is blank after normalization.

    Returns:
        None: This test validates normalized interface filtering behavior.
    """
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        client._safe_dict_get = AsyncMock(
            return_value={
                "rows": [
                    {
                        "mode": "carp",
                        "status": "MASTER",
                        "interface": "   ",
                        "subnet": "1.2.3.4",
                    },
                    {
                        "mode": "carp",
                        "status": "BACKUP",
                        "interface": "  wan  ",
                        "subnet": "5.6.7.8",
                    },
                ],
                "carp": {
                    "allow": "1",
                    "maintenancemode": False,
                    "demotion": "0",
                    "status_msg": "",
                },
            }
        )
        snapshot = await client.get_carp()
        assert snapshot["interfaces"] == [
            {
                "interface": "wan",
                "mode": "carp",
                "status": "BACKUP",
                "subnet": "5.6.7.8",
            }
        ]
        assert snapshot["status_summary"]["vip_count"] == 1
        assert snapshot["status_summary"]["interfaces"] == ["wan"]
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_carp_status_uses_settings_merge_for_partial_rows(make_client) -> None:
    """Ensure summary reconstructs partial status rows using VIP settings merge."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client._safe_dict_get = AsyncMock(
            side_effect=[
                {
                    "rows": [
                        {
                            "mode": "carp",
                            "status": "MASTER",
                            "interface": "wan",
                            "vhid": "1",
                        }
                    ],
                    "carp": {
                        "allow": "1",
                        "maintenancemode": False,
                        "demotion": "0",
                        "status_msg": "",
                    },
                },
                {
                    "rows": [
                        {
                            "mode": "carp",
                            "interface": "wan",
                            "subnet": "1.2.3.4",
                            "vhid": "1",
                        }
                    ]
                },
            ]
        )
        summary = dict((await client.get_carp()).get("status_summary", {}))
        assert summary["state"] == "healthy"
        assert summary["vip_count"] == 1
        assert summary["interfaces"] == ["wan"]
        assert summary["vips"][0]["subnet"] == "1.2.3.4"
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_carp_returns_interfaces_and_summary_from_one_fetch(
    make_client,
) -> None:
    """Ensure one CARP call returns both interface and summary payloads."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client._safe_dict_get = AsyncMock(
            side_effect=[
                {
                    "rows": [{"mode": "carp", "status": "MASTER", "interface": "wan", "vhid": "1"}],
                    "carp": {
                        "allow": "1",
                        "maintenancemode": False,
                        "demotion": "0",
                        "status_msg": "",
                    },
                },
                {"rows": [{"mode": "carp", "interface": "wan", "subnet": "1.2.3.4", "vhid": "1"}]},
            ]
        )
        snapshot = await client.get_carp()
        assert snapshot["interfaces"][0]["subnet"] == "1.2.3.4"
        assert snapshot["status_summary"]["state"] == "healthy"
        assert client._safe_dict_get.await_count == 2
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
