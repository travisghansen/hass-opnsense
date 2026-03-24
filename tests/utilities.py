"""Shared testing utilities for hass-opnsense test modules."""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import Any

import aiohttp
import pytest


def patch_client_factory(monkeypatch: pytest.MonkeyPatch, module: Any, client_ctor: Any) -> None:
    """Patch ``create_opnsense_client`` with a deterministic async wrapper.

    Parameters
    ----------
    monkeypatch : pytest.MonkeyPatch
        Pytest monkeypatch fixture.
    module : Any
        Target module exposing ``create_opnsense_client``.
    client_ctor : Any
        Callable/class used to construct fake clients.

    Returns
    -------
    None

    """

    async def _create_opnsense_client(
        *,
        url: str,
        username: str,
        password: str,
        session: aiohttp.ClientSession,
        opts: MutableMapping[str, Any] | None = None,
        initial: bool = False,
        name: str | None = None,
    ) -> Any:
        return client_ctor(
            url=url,
            username=username,
            password=password,
            session=session,
            opts=opts,
            initial=initial,
            name=name,
        )

    monkeypatch.setattr(module, "create_opnsense_client", _create_opnsense_client)
