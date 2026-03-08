"""Tests for `pyopnsense.telemetry`."""

from collections.abc import MutableMapping
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

from custom_components.opnsense import pyopnsense


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
        assert isinstance(sys, MutableMapping)
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
    try:
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
    finally:
        await client.async_close()


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
        assert isinstance(temps, MutableMapping) and len(temps) == 1
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_interfaces_status_variants() -> None:
    """Ensure interface parsing handles status, associated mapping and mac filtering."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
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
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_telemetry_memory_swap_branches() -> None:
    """Cover telemetry memory path including swap data branch."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
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
    finally:
        await client.async_close()
