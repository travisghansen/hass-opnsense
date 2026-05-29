"""Tests for `pyopnsense.firmware` behaviors."""

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

from custom_components.opnsense import pyopnsense

TEST_PASSWORD = "p"


@pytest.mark.asyncio
async def test_get_host_firmware_version_and_fallback(make_client: Any) -> None:
    """Verify firmware resolution uses version when valid and series fallback when invalid."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    # valid semver
    object.__setattr__(
        client, "_safe_dict_get", AsyncMock(return_value={"product": {"product_version": "25.8.0"}})
    )
    fw = await client.get_host_firmware_version()
    assert fw == "25.8.0"
    await client.async_close()

    # use a fresh client to validate fallback resolution (version is cached after first call)
    fallback_client = make_client(session=session)
    object.__setattr__(
        fallback_client,
        "_safe_dict_get",
        AsyncMock(
            return_value={"product": {"product_version": "weird", "product_series": "seriesX"}}
        ),
    )
    fw2 = await fallback_client.get_host_firmware_version()
    assert fw2 == "seriesX"
    await fallback_client.async_close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("package_list", "expected"),
    [
        ({"package": [{"name": "os-homeassistant-maxit", "installed": "1"}]}, True),
        ({"package": [{"name": "os-homeassistant-maxit", "installed": "0"}]}, False),
        ({}, False),
        ({"package": [{"name": "some-other", "installed": "1"}]}, False),
    ],
)
async def test_is_plugin_installed_various(
    make_client: Any, package_list: Any, expected: Any
) -> None:
    """Parameterize plugin installation detection for several package list shapes."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        object.__setattr__(client, "_safe_dict_get", AsyncMock(return_value=package_list))
        assert await client.is_plugin_installed() is expected
    finally:
        await client.async_close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("plugin_name", "expected"),
    [
        ("os-homeassistant-maxit", True),
        ("os-vnstat", True),
        ("os-isc-dhcp", False),
    ],
)
async def test_is_named_plugin_installed(make_client: Any, plugin_name: Any, expected: Any) -> None:
    """Detect named plugin installation from firmware package payload."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        object.__setattr__(
            client,
            "_safe_dict_get",
            AsyncMock(
                return_value={
                    "package": [
                        {"name": "os-homeassistant-maxit", "installed": "1"},
                        {"name": "os-vnstat", "installed": "1"},
                        {"name": "os-isc-dhcp", "installed": "0"},
                    ]
                }
            ),
        )
        assert await client.is_named_plugin_installed(plugin_name) is expected
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_plugin_cache_ttl_avoids_repeated_refresh(make_client: Any) -> None:
    """Plugin checks within TTL should refresh firmware info only once."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        object.__setattr__(
            client,
            "_safe_dict_get",
            AsyncMock(return_value={"package": [{"name": "os-vnstat", "installed": "1"}]}),
        )
        assert await client.is_named_plugin_installed("os-vnstat") is True
        assert await client.is_named_plugin_installed("os-vnstat2") is False
        client._safe_dict_get.assert_awaited_once_with("/api/core/firmware/info")
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_plugin_cache_ttl_refreshes_when_expired(make_client: Any) -> None:
    """Plugin checks should refresh when cached plugin list is expired."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        object.__setattr__(
            client,
            "_safe_dict_get",
            AsyncMock(
                side_effect=[
                    {"package": [{"name": "os-vnstat", "installed": "1"}]},
                    {"package": [{"name": "os-vnstat", "installed": "0"}]},
                ]
            ),
        )
        assert await client.is_named_plugin_installed("os-vnstat") is True
        client._plugin_cache_ttl_seconds = 1
        client._installed_plugins_updated_at = datetime.now(UTC) - timedelta(seconds=2)
        assert await client.is_named_plugin_installed("os-vnstat") is False
        assert client._safe_dict_get.await_count == 2
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_plugin_cache_not_poisoned_by_empty_firmware_info(make_client: Any) -> None:
    """Keep existing plugin cache when firmware info refresh returns an empty payload."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        object.__setattr__(
            client,
            "_safe_dict_get",
            AsyncMock(
                side_effect=[
                    {"package": [{"name": "os-vnstat", "installed": "1"}]},
                    {},
                ]
            ),
        )
        assert await client.is_named_plugin_installed("os-vnstat") is True
        client._plugin_cache_ttl_seconds = 1
        client._installed_plugins_updated_at = datetime.now(UTC) - timedelta(seconds=2)
        assert await client.is_named_plugin_installed("os-vnstat") is True
        assert client._safe_dict_get.await_count == 2
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_plugin_cache_retries_after_failed_forced_refresh(make_client: Any) -> None:
    """Failed refresh attempts should be retried on the next plugin check."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        object.__setattr__(
            client,
            "_safe_dict_get",
            AsyncMock(
                side_effect=[
                    {"package": [{"name": "os-vnstat", "installed": "1"}]},
                    {},
                    {"package": [{"name": "os-vnstat", "installed": "1"}]},
                ]
            ),
        )
        assert await client.is_named_plugin_installed("os-vnstat") is True
        assert client._installed_plugins_refresh_succeeded is True

        # Force a refresh attempt that fails to mark cache as retry-required.
        await client._refresh_installed_plugins(force=True)
        assert client._installed_plugins_refresh_succeeded is False

        # Next call should retry immediately even though the last successful
        # timestamp is still recent.
        assert await client.is_named_plugin_installed("os-vnstat") is True
        assert client._safe_dict_get.await_count == 3
        assert client._installed_plugins_refresh_succeeded is True
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_firmware_update_info_triggers_check_on_conditions(make_client: Any) -> None:
    """Trigger firmware update check when status is missing data or outdated."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        # Prepare a status that lacks data to force missing_data True and last_check missing
        status = {
            "product": {"product_version": "1.0", "product_latest": "2.0", "product_check": {}}
        }
        object.__setattr__(client, "_safe_dict_get", AsyncMock(return_value=status))
        object.__setattr__(client, "_post", AsyncMock(return_value={}))
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
        url="http://localhost", username="u", password=TEST_PASSWORD, session=session
    )
    try:
        # prepare status missing latest and a stale last_check
        old_time = (datetime.now(UTC) - timedelta(days=2)).isoformat()
        status = {
            "product": {"product_version": "1.0.0", "product_latest": "1.0.0", "product_check": {}},
            "last_check": old_time,
        }
        safe_dict_get = AsyncMock(return_value=status)
        get_timezone = AsyncMock(return_value=UTC)
        post = AsyncMock(return_value={})
        object.__setattr__(client, "_safe_dict_get", safe_dict_get)
        object.__setattr__(client, "_get_opnsense_timezone", get_timezone)
        object.__setattr__(client, "_post", post)
        await client.get_firmware_update_info()
        get_timezone.assert_not_awaited()
        post.assert_awaited_once_with("/api/core/firmware/check")
    finally:
        await client.async_close()
