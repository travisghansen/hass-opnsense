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

    def _create_opnsense_client_from_config_entry(
        *,
        hass: Any,
        config_entry: Any,
        throw_errors: bool = False,
    ) -> Any:
        """Create a fake OPNsense client from a config entry.

        Args:
            hass: Home Assistant instance passed by production code.
            config_entry: Config entry with connection settings.
            throw_errors: Error propagation behavior passed by shared helper callers.

        Returns:
            Any: Fake client instance returned by `client_ctor`.
        """
        return _create_opnsense_client(
            hass=hass,
            url=config_entry.data["url"],
            username=config_entry.data["username"],
            password=config_entry.data["password"],
            verify_ssl=config_entry.data.get("verify_ssl"),
            throw_errors=throw_errors,
            name=config_entry.title,
        )

    if hasattr(module, "create_opnsense_client_from_config_entry"):
        monkeypatch.setattr(
            module,
            "create_opnsense_client_from_config_entry",
            _create_opnsense_client_from_config_entry,
        )
    if hasattr(module, "create_opnsense_client"):
        monkeypatch.setattr(module, "create_opnsense_client", _create_opnsense_client)
