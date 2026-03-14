"""Tests for `pyopnsense.firmware` behaviors."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

from custom_components.opnsense import pyopnsense


@pytest.mark.asyncio
async def test_get_host_firmware_version_and_fallback(make_client) -> None:
    """Verify firmware resolution uses version when valid and series fallback when invalid."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    # valid semver
    client._safe_dict_get = AsyncMock(return_value={"product": {"product_version": "25.8.0"}})
    fw = await client.get_host_firmware_version()
    assert fw == "25.8.0"
    await client.async_close()

    # use a fresh client to validate fallback resolution (version is cached after first call)
    fallback_client = make_client(session=session)
    fallback_client._safe_dict_get = AsyncMock(
        return_value={"product": {"product_version": "weird", "product_series": "seriesX"}}
    )
    fw2 = await fallback_client.get_host_firmware_version()
    assert fw2 == "seriesX"
    await fallback_client.async_close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "package_list,expected",
    [
        ({"package": [{"name": "os-homeassistant-maxit", "installed": "1"}]}, True),
        ({"package": [{"name": "os-homeassistant-maxit", "installed": "0"}]}, False),
        ({}, False),
        ({"package": [{"name": "some-other", "installed": "1"}]}, False),
    ],
)
async def test_is_plugin_installed_various(make_client, package_list, expected) -> None:
    """Parameterize plugin installation detection for several package list shapes."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client._safe_dict_get = AsyncMock(return_value=package_list)
        assert await client.is_plugin_installed() is expected
    finally:
        await client.async_close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "plugin_name,expected",
    [
        ("os-homeassistant-maxit", True),
        ("os-vnstat", True),
        ("os-isc-dhcp", False),
    ],
)
async def test_is_named_plugin_installed(make_client, plugin_name, expected) -> None:
    """Detect named plugin installation from firmware package payload."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client._safe_dict_get = AsyncMock(
            return_value={
                "package": [
                    {"name": "os-homeassistant-maxit", "installed": "1"},
                    {"name": "os-vnstat", "installed": "1"},
                    {"name": "os-isc-dhcp", "installed": "0"},
                ]
            }
        )
        assert await client.is_named_plugin_installed(plugin_name) is expected
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_plugin_cache_ttl_avoids_repeated_refresh(make_client) -> None:
    """Plugin checks within TTL should refresh firmware info only once."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client._safe_dict_get = AsyncMock(
            return_value={"package": [{"name": "os-vnstat", "installed": "1"}]}
        )
        assert await client.is_named_plugin_installed("os-vnstat") is True
        assert await client.is_named_plugin_installed("os-vnstat2") is False
        client._safe_dict_get.assert_awaited_once_with("/api/core/firmware/info")
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_plugin_cache_ttl_refreshes_when_expired(make_client) -> None:
    """Plugin checks should refresh when cached plugin list is expired."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client._safe_dict_get = AsyncMock(
            side_effect=[
                {"package": [{"name": "os-vnstat", "installed": "1"}]},
                {"package": [{"name": "os-vnstat", "installed": "0"}]},
            ]
        )
        assert await client.is_named_plugin_installed("os-vnstat") is True
        client._plugin_cache_ttl_seconds = 1
        client._installed_plugins_updated_at = datetime.now(UTC) - timedelta(seconds=2)
        assert await client.is_named_plugin_installed("os-vnstat") is False
        assert client._safe_dict_get.await_count == 2
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_plugin_cache_not_poisoned_by_empty_firmware_info(make_client) -> None:
    """Keep existing plugin cache when firmware info refresh returns an empty payload."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client._safe_dict_get = AsyncMock(
            side_effect=[
                {"package": [{"name": "os-vnstat", "installed": "1"}]},
                {},
            ]
        )
        assert await client.is_named_plugin_installed("os-vnstat") is True
        client._plugin_cache_ttl_seconds = 1
        client._installed_plugins_updated_at = datetime.now(UTC) - timedelta(seconds=2)
        assert await client.is_named_plugin_installed("os-vnstat") is True
        assert client._safe_dict_get.await_count == 2
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
        client._post.assert_awaited_once_with("/api/core/firmware/check")
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_firmware_update_info_triggers_check_when_missing() -> None:
    """Trigger firmware check when fields missing/expired."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        # prepare status missing latest and a stale last_check
        old_time = (datetime.now() - timedelta(days=2)).isoformat()
        status = {
            "product": {"product_version": "1.0.0", "product_latest": "1.0.0", "product_check": {}},
            "last_check": old_time,
        }
        client._safe_dict_get = AsyncMock(return_value=status)
        client._get_opnsense_timezone = AsyncMock(return_value=UTC)
        client._post = AsyncMock(return_value={})
        await client.get_firmware_update_info()
        client._get_opnsense_timezone.assert_awaited_once_with()
        client._post.assert_awaited_once_with("/api/core/firmware/check")
    finally:
        await client.async_close()
