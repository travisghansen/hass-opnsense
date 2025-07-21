import asyncio
import contextlib
from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.fixture(autouse=True)
def _patch_asyncio_create_task(monkeypatch):
    """Patch asyncio.create_task to avoid creating background workers for pyopnsense during tests.

    For coroutines created by pyopnsense, close the coroutine object and return a dummy task-like
    object to prevent "coroutine was never awaited" warnings while avoiding scheduling real
    background work during tests.
    """

    def _fake_create_task(coro):
        # If the coroutine originates from pyopnsense background workers, close it to avoid
        # 'coroutine was never awaited' warnings and return a dummy task-like object.
        frame = getattr(coro, "cr_frame", None)
        filename = getattr(getattr(frame, "f_code", None), "co_filename", "") if frame else ""
        if "pyopnsense" in filename:
            # closing a coroutine suppresses the "never awaited" warning; ignore
            # any exceptions while doing so.

            with contextlib.suppress(Exception):
                coro.close()
            m = MagicMock()
            m.done.return_value = True
            m.cancel = MagicMock()
            return m
        # otherwise schedule the real task on the running loop
        return asyncio.get_running_loop().create_task(coro)

    monkeypatch.setattr(asyncio, "create_task", _fake_create_task)


@pytest.fixture
def coordinator():
    """Provide a lightweight coordinator mock for tests.

    Use MagicMock so that registering listeners (which happens synchronously) does not
    produce AsyncMock "never awaited" warnings. Tests that need async behavior can
    set specific async methods on the mock to AsyncMock.
    """
    return MagicMock()


@pytest.fixture
def hass():
    """Canonical Home Assistant mock fixture with common attributes."""
    hass_instance = MagicMock()
    hass_instance.config_entries = MagicMock()
    # async_forward_entry_setups is awaited by setup flows; keep it as AsyncMock.
    hass_instance.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    # async_reload is a coroutine in Home Assistant; provide an AsyncMock so that
    # scheduling it via hass.async_create_task will schedule an awaitable coroutine
    # rather than an un-awaited mock.
    hass_instance.config_entries.async_reload = AsyncMock(return_value=None)
    hass_instance.services = MagicMock()
    # Provide an async_create_task that schedules coroutines on the running loop
    # but is a MagicMock so tests can assert it was called. The side_effect
    # schedules the coroutine on the running loop so behavior matches Home
    # Assistant while remaining observable in tests.
    hass_instance.async_create_task = MagicMock(
        side_effect=lambda coro: asyncio.get_running_loop().create_task(coro)
    )
    return hass_instance
