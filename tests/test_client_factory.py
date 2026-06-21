"""Tests for direct aiopnsense client construction."""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import aiohttp
import pytest

from custom_components.opnsense import client_factory as factory_mod

TEST_PASSWORD = "p"


class FakeExternalClient:
    """Minimal fake aiopnsense client that captures construction kwargs."""

    def __init__(self, **kwargs: Any) -> None:
        """Store constructor kwargs and provide async close method."""
        self.kwargs = kwargs
        self.async_close = AsyncMock()


@pytest.mark.asyncio
async def test_create_opnsense_client_constructs_aiopnsense_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Direct construction should pass url, username, password, session, opts, initial, name."""
    monkeypatch.setattr(
        factory_mod,
        "import_module",
        lambda module_name: SimpleNamespace(OPNsenseClient=FakeExternalClient),
    )
    session = cast("aiohttp.ClientSession", SimpleNamespace())

    client = await factory_mod.create_opnsense_client(
        url="https://router",
        username="u",
        password=TEST_PASSWORD,
        session=session,
        opts={"verify_ssl": True},
        initial=True,
        name="Test Router",
    )

    assert isinstance(client, FakeExternalClient)
    assert client.kwargs == {
        "url": "https://router",
        "username": "u",
        "password": TEST_PASSWORD,
        "session": session,
        "opts": {"verify_ssl": True},
        "initial": True,
        "name": "Test Router",
    }


@pytest.mark.asyncio
async def test_create_opnsense_client_logs_without_resolved_aiopnsense_version(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Direct construction should log a generic backend message when version is unavailable."""
    monkeypatch.setattr(
        factory_mod,
        "import_module",
        lambda module_name: SimpleNamespace(OPNsenseClient=FakeExternalClient),
    )
    monkeypatch.setattr(
        factory_mod,
        "_get_external_aiopnsense_version",
        AsyncMock(return_value=None),
    )
    session = cast("aiohttp.ClientSession", SimpleNamespace())
    caplog.set_level(logging.INFO, logger=factory_mod.__name__)

    await factory_mod.create_opnsense_client(
        url="https://router",
        username="u",
        password=TEST_PASSWORD,
        session=session,
    )

    assert "Using aiopnsense" in caplog.text


@pytest.mark.asyncio
async def test_create_opnsense_client_raises_when_aiopnsense_client_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing aiopnsense.OPNsenseClient should raise MissingExternalAiopnsenseDependency."""
    monkeypatch.setattr(factory_mod, "import_module", lambda module_name: SimpleNamespace())

    with pytest.raises(factory_mod.MissingExternalAiopnsenseDependency):
        await factory_mod.create_opnsense_client(
            url="https://router",
            username="u",
            password=TEST_PASSWORD,
            session=cast("aiohttp.ClientSession", SimpleNamespace()),
            opts={"verify_ssl": True},
        )


@pytest.mark.asyncio
async def test_create_opnsense_client_raises_when_aiopnsense_import_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Import failure should raise MissingExternalAiopnsenseDependency."""

    def _raise_import_error(module_name: str) -> Any:
        raise ImportError("missing")

    monkeypatch.setattr(factory_mod, "import_module", _raise_import_error)

    with pytest.raises(factory_mod.MissingExternalAiopnsenseDependency):
        await factory_mod.create_opnsense_client(
            url="https://router",
            username="u",
            password=TEST_PASSWORD,
            session=cast("aiohttp.ClientSession", SimpleNamespace()),
            opts={"verify_ssl": True},
        )


@pytest.mark.asyncio
async def test_create_opnsense_client_reraises_constructor_typeerror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Constructor TypeError should propagate and not be wrapped as dependency error."""

    class _FailingClient:
        def __init__(self, **kwargs: Any) -> None:
            raise TypeError("constructor failure")

    monkeypatch.setattr(
        factory_mod,
        "import_module",
        lambda module_name: SimpleNamespace(OPNsenseClient=_FailingClient),
    )

    with pytest.raises(TypeError, match="constructor failure"):
        await factory_mod.create_opnsense_client(
            url="https://router",
            username="u",
            password=TEST_PASSWORD,
            session=cast("aiohttp.ClientSession", SimpleNamespace()),
            opts={"verify_ssl": True},
        )
