"""Shared testing utilities for hass-opnsense test modules."""

from __future__ import annotations

from typing import Any

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
        hass: Any,
        url: str,
        username: str,
        password: str,
        verify_ssl: bool | None,
        throw_errors: bool = False,
        name: str | None = None,
    ) -> Any:
        """Create a fake OPNsense client using the provided constructor.

        Args:
            hass: Home Assistant instance passed by production code.
            url: OPNsense base URL from caller input.
            username: Username from caller input.
            password: Password from caller input.
            verify_ssl: Optional TLS verification value passed by shared helper callers.
            throw_errors: Error propagation behavior passed by shared helper callers.
            name: Optional client display name passed by caller.

        Returns:
            Any: Fake client instance returned by `client_ctor`.
        """
        del hass
        return client_ctor(
            url=url,
            username=username,
            password=password,
            verify_ssl=verify_ssl,
            throw_errors=throw_errors,
            name=name,
        )

    monkeypatch.setattr(module, "create_opnsense_client", _create_opnsense_client)
