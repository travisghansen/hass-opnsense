"""Shared testing utilities for hass-opnsense test modules."""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import Any

import aiohttp
import pytest


def stub_async_write_ha_state(entity: Any) -> None:
    """Replace Home Assistant state writes with a no-op for unit-level entity tests.

    Args:
        entity: Entity instance under test.
    """
    object.__setattr__(entity, "async_write_ha_state", lambda: None)


def patch_opnsense_client(monkeypatch: pytest.MonkeyPatch, module: Any, client_ctor: Any) -> None:
    """Patch OPNsense client construction with a deterministic constructor.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        module: Target module exposing client construction helpers.
        client_ctor: Callable/class used to construct fake clients for tests.
    """

    def _create_opnsense_client(
        *,
        hass: Any | None = None,
        url: str,
        username: str,
        password: str,
        session: aiohttp.ClientSession | None = None,
        verify_ssl: bool | None = None,
        throw_errors: bool = False,
        opts: MutableMapping[str, Any] | None = None,
        name: str | None = None,
    ) -> Any:
        """Create a fake OPNsense client using the provided constructor.

        Args:
            hass: Home Assistant instance passed by production code.
            url: OPNsense base URL from caller input.
            username: Username from caller input.
            password: Password from caller input.
            session: Optional aiohttp session forwarded to the fake client.
            verify_ssl: Optional TLS verification value passed by shared helper callers.
            throw_errors: Error propagation behavior passed by shared helper callers.
            opts: Optional connection options passed by caller.
            name: Optional client display name passed by caller.

        Returns:
            Any: Fake client instance returned by `client_ctor`.
        """
        del hass
        resolved_opts = opts if opts is not None else {"verify_ssl": verify_ssl}
        return client_ctor(
            url=url,
            username=username,
            password=password,
            session=session,
            opts=resolved_opts,
            throw_errors=throw_errors,
            name=name,
        )

    monkeypatch.setattr(module, "create_opnsense_client", _create_opnsense_client, raising=False)
