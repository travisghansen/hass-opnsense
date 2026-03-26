"""Shared testing utilities for hass-opnsense test modules."""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import Any

import aiohttp
import pytest


def patch_client_factory(monkeypatch: pytest.MonkeyPatch, module: Any, client_ctor: Any) -> None:
    """Patch `create_opnsense_client` with a deterministic async constructor.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        module: Target module exposing `create_opnsense_client`.
        client_ctor: Callable/class used to construct fake clients for tests.
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
        """Create a fake OPNsense client using the provided constructor.

        Args:
            url: OPNsense base URL from caller input.
            username: Username from caller input.
            password: Password from caller input.
            session: aiohttp session passed by caller.
            opts: Optional connection options passed by caller.
            initial: Whether the caller marks this as initial setup.
            name: Optional client display name passed by caller.

        Returns:
            Any: Fake client instance returned by `client_ctor`.
        """
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
