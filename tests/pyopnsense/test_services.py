"""Tests for `pyopnsense.services`."""

from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

from custom_components.opnsense import pyopnsense


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
async def test_manage_service_and_restart_if_running(monkeypatch, make_client) -> None:
    """Test _manage_service and restart_service_if_running behavior."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        # _manage_service should return False when service empty
        assert await client._manage_service("start", "") is False

        # when _safe_dict_post returns ok result, manage_service returns True
        client._safe_dict_post = AsyncMock(return_value={"result": "ok"})
        assert await client._manage_service("start", "svc1") is True
        assert client._safe_dict_post.await_args.args[0] == "/api/core/service/start/svc1"

        # service identifiers are URL-encoded before endpoint construction
        assert await client._manage_service("restart", "svc /name") is True
        assert (
            client._safe_dict_post.await_args.args[0] == "/api/core/service/restart/svc%20%2Fname"
        )

        # get_service_is_running uses get_services; test restart_service_if_running branches
        restart_service_mock = AsyncMock(return_value=True)
        monkeypatch.setattr(client, "restart_service", restart_service_mock, raising=False)
        client.get_service_is_running = AsyncMock(return_value=True)
        assert await client.restart_service_if_running("svc1") is True
        restart_service_mock.assert_awaited_once_with("svc1")

        restart_service_mock.reset_mock()
        client.get_service_is_running = AsyncMock(return_value=False)
        assert await client.restart_service_if_running("svc1") is True
        restart_service_mock.assert_not_awaited()
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_services_and_service_is_running() -> None:
    """Verify service listing and running-state detection."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        # get_services returns rows
        client._safe_dict_get = AsyncMock(
            return_value={
                "rows": [
                    {"name": "svc", "running": 1, "id": "svc"},
                    "malformed",
                    123,
                    None,
                ]
            }
        )
        services = await client.get_services()
        assert isinstance(services, list)
        assert len(services) == 1
        assert services[0]["status"] is True

        # get_service_is_running
        assert await client.get_service_is_running("svc") is True
    finally:
        await client.async_close()
