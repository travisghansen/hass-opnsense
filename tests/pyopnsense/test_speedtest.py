"""Tests for `pyopnsense.speedtest`."""

from unittest.mock import AsyncMock, MagicMock, call

import aiohttp
import pytest


@pytest.mark.asyncio
async def test_get_speedtest_skips_calls_when_endpoint_missing(make_client) -> None:
    """get_speedtest should skip speedtest API calls when endpoint is unavailable."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client.is_endpoint_available = AsyncMock(return_value=False)
        client._safe_dict_get = AsyncMock()

        result = await client.get_speedtest()

        assert result == {"available": False}
        client._safe_dict_get.assert_not_awaited()
        client.is_endpoint_available.assert_awaited_once_with("/api/speedtest/service/showrecent")
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_speedtest_normalizes_recent_and_stat_payloads(make_client) -> None:
    """get_speedtest should normalize showrecent and showstat payload fields."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client.is_endpoint_available = AsyncMock(side_effect=[True, True])
        client._safe_dict_get = AsyncMock(
            side_effect=[
                {
                    "date": "2026-03-14T03:09:45",
                    "server": "72800 RippleFiber, Newark, NJ",
                    "download": "836.05",
                    "upload": "832.97",
                    "latency": "4.0",
                    "url": "https://www.speedtest.net/result/c/abc",
                },
                {
                    "samples": 10717,
                    "period": {"oldest": "2023-01-22 00:29:00", "youngest": "2026-03-14 03:09:45"},
                    "latency": {"avg": 13.42, "min": 2.35, "max": 1266.74},
                    "download": {"avg": 723.83, "min": 4.18, "max": 942.02},
                    "upload": {"avg": 706.7, "min": 1.54, "max": 890.32},
                },
            ]
        )

        result = await client.get_speedtest()

        assert result["available"] is True
        assert result["last"]["download"]["value"] == 836.05
        assert result["last"]["download"]["server_id"] == "72800"
        assert result["last"]["download"]["server"] == "RippleFiber, Newark, NJ"
        assert result["average"]["download"]["value"] == 723.83
        assert result["average"]["download"]["min"] == 4.18
        assert result["average"]["download"]["max"] == 942.02
        assert result["average"]["download"]["samples"] == 10717
        assert result["average"]["download"]["oldest"] == "2023-01-22 00:29:00"
        assert result["average"]["download"]["youngest"] == "2026-03-14 03:09:45"
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_speedtest_fetches_showstat_without_endpoint_probe(make_client) -> None:
    """get_speedtest should only probe showrecent and then fetch both payloads."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client.is_endpoint_available = AsyncMock(return_value=True)
        client._safe_dict_get = AsyncMock(
            side_effect=[
                {"download": "1", "upload": "2", "latency": "3"},
                {},
            ]
        )

        result = await client.get_speedtest()

        assert result["available"] is True
        assert client.is_endpoint_available.await_args_list == [
            call("/api/speedtest/service/showrecent")
        ]
        assert client._safe_dict_get.await_args_list == [
            call("/api/speedtest/service/showrecent"),
            call("/api/speedtest/service/showstat"),
        ]
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_speedtest_normalizes_malformed_payloads(make_client) -> None:
    """get_speedtest should coerce malformed or missing values to None safely."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client.is_endpoint_available = AsyncMock(side_effect=[True, True])
        client._safe_dict_get = AsyncMock(
            side_effect=[
                {
                    "date": 12345,
                    "server": "Regional POP - NYC",
                    "download": "bad-number",
                    "upload": "12.5",
                    "latency": None,
                    "url": 999,
                },
                {
                    "samples": "not-an-int",
                    "period": "bad-period-shape",
                    "download": "bad-download-shape",
                    "upload": None,
                    "latency": ["bad-latency-shape"],
                },
            ]
        )

        result = await client.get_speedtest()

        assert result["available"] is True
        assert result["last"]["download"]["server_id"] is None
        assert result["last"]["download"]["server"] == "Regional POP - NYC"
        assert result["last"]["download"]["date"] is None
        assert result["last"]["download"]["url"] is None
        assert result["last"]["download"]["value"] is None
        assert result["last"]["upload"]["value"] == 12.5
        assert result["last"]["latency"]["value"] is None

        assert result["average"]["download"]["value"] is None
        assert result["average"]["download"]["min"] is None
        assert result["average"]["download"]["max"] is None
        assert result["average"]["download"]["samples"] is None
        assert result["average"]["download"]["oldest"] is None
        assert result["average"]["download"]["youngest"] is None
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_parse_recent_server_variants(make_client) -> None:
    """_parse_recent_server should parse known server formats safely."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        assert client._parse_recent_server(None) == (None, None)
        assert client._parse_recent_server("   ") == (None, None)
        assert client._parse_recent_server("10001 Test ISP, NY") == ("10001", "Test ISP, NY")
        assert client._parse_recent_server("Unstructured Server Name") == (
            None,
            "Unstructured Server Name",
        )
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_run_speedtest_uses_extended_timeout(make_client) -> None:
    """run_speedtest should use custom timeout helper for long-running endpoint calls."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client.is_endpoint_available = AsyncMock(return_value=True)
        client._safe_dict_get_with_timeout = AsyncMock(return_value={"timestamp": "x"})

        result = await client.run_speedtest()

        assert result == {"timestamp": "x"}
        client._safe_dict_get_with_timeout.assert_awaited_once_with(
            "/api/speedtest/service/run", timeout_seconds=180
        )
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_run_speedtest_returns_empty_when_endpoint_missing(make_client) -> None:
    """run_speedtest should return an empty payload when endpoint is unavailable."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client.is_endpoint_available = AsyncMock(return_value=False)
        client._safe_dict_get_with_timeout = AsyncMock()

        result = await client.run_speedtest()

        assert result == {}
        client._safe_dict_get_with_timeout.assert_not_awaited()
        client.is_endpoint_available.assert_awaited_once_with("/api/speedtest/service/showrecent")
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_run_speedtest_returns_empty_for_non_mapping_response(make_client) -> None:
    """run_speedtest should return an empty payload for non-mapping responses."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client.is_endpoint_available = AsyncMock(return_value=True)
        client._safe_dict_get_with_timeout = AsyncMock(return_value=["not", "a", "mapping"])

        result = await client.run_speedtest()

        assert result == {}
        client.is_endpoint_available.assert_awaited_once_with("/api/speedtest/service/showrecent")
        client._safe_dict_get_with_timeout.assert_awaited_once_with(
            "/api/speedtest/service/run", timeout_seconds=180
        )
    finally:
        await client.async_close()
