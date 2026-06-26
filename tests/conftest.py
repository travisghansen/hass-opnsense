"""Test fixtures and helpers for the hass-opnsense integration.

This module provides pytest fixtures, fake clients, and monkeypatch helpers
used across the integration's test suite to avoid network IO, neutralize
background tasks, and simplify Home Assistant testing.
"""

import asyncio
from collections.abc import AsyncIterator
import contextlib
from typing import Any
from unittest.mock import MagicMock

from homeassistant.core import HomeAssistant
import homeassistant.helpers.aiohttp_client as _ha_aiohttp_client
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

import custom_components.opnsense as _init_mod
from custom_components.opnsense import helpers as _helpers_mod
from custom_components.opnsense.const import CONF_DEVICE_UNIQUE_ID


# Provide a shared FakeClientSession for tests to avoid creating real aiohttp sessions
class FakeClientSession:
    """Minimal fake client session used by tests in lieu of aiohttp.ClientSession."""

    def __init__(self, *args, **kwargs) -> None:
        """Initialize the fake client session (no-op)."""

    async def __aenter__(self) -> Any:
        """Enter async context and return the session-like object."""
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: object
    ) -> bool:
        """Exit async context, close the session and propagate exceptions."""
        await self.close()
        return False

    async def close(self) -> bool:
        """Close the fake session (no-op)."""
        return True


def _ensure_async_create_task_mock(real: Any, side_effect: Any) -> None:
    """Ensure ``real.async_create_task`` is mocked with the requested side effect.

    The helper attempts three strategies in the same order as the production
    test logic.

    1. Direct assignment: ``real.async_create_task = MagicMock(side_effect=...)``.
    2. Use ``object.__setattr__`` to bypass attribute protections.
    3. If an existing callable exists, wrap it with
       ``MagicMock(side_effect=lambda coro: orig(coro))``.
    """
    with contextlib.suppress(AttributeError, TypeError):
        real.async_create_task = MagicMock(side_effect=side_effect)
    if not hasattr(real, "async_create_task") or not isinstance(
        getattr(real, "async_create_task", None), MagicMock
    ):
        # Try object.__setattr__ in case of attribute protections.
        with contextlib.suppress(AttributeError, TypeError):
            object.__setattr__(real, "async_create_task", MagicMock(side_effect=side_effect))
    if not hasattr(real, "async_create_task") or not isinstance(
        getattr(real, "async_create_task", None), MagicMock
    ):
        # As a last resort, wrap an existing callable if present.
        orig = getattr(real, "async_create_task", None)
        if callable(orig):
            with contextlib.suppress(AttributeError, TypeError):
                object.__setattr__(
                    real,
                    "async_create_task",
                    MagicMock(side_effect=orig),
                )


@pytest.fixture(autouse=True)
def _patch_async_create_clientsession(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch shared client-session construction so tests never open network resources."""

    def create_clientsession(*args: Any, **kwargs: Any) -> FakeClientSession:
        """Return a fake client session for all patched session helper surfaces."""
        return FakeClientSession()

    monkeypatch.setattr(
        _ha_aiohttp_client,
        "async_create_clientsession",
        create_clientsession,
        raising=False,
    )
    monkeypatch.setattr(
        "homeassistant.helpers.aiohttp_client.async_create_clientsession",
        create_clientsession,
        raising=False,
    )
    monkeypatch.setattr(
        _init_mod,
        "async_create_clientsession",
        create_clientsession,
        raising=False,
    )
    monkeypatch.setattr(
        _helpers_mod,
        "async_create_clientsession",
        create_clientsession,
        raising=False,
    )
    monkeypatch.setattr(
        _helpers_mod.aiohttp,
        "CookieJar",
        lambda *a, **k: object(),
        raising=False,
    )


@pytest.fixture
def coordinator_capture() -> Any:
    """Provide a reusable capture for created coordinator instances.

    Returns a small namespace-like object with two attributes:
        instances: A list that each created coordinator is appended to.
        factory: A callable for monkeypatch that creates the fake coordinator,
            records it in ``instances``, and returns it.
    """

    class _C:
        def __init__(self) -> None:
            """Initialize _C."""
            self.instances: list[Any] = []

        def factory(self, coord_cls: Any = None) -> Any:
            # Return a factory function bound to coord_cls that captures instances.
            """Factory.

            Args:
                coord_cls: Coord cls provided by pytest or the test case.
            """

            def _f(**kwargs) -> Any:
                """F.

                Args:
                    **kwargs: Additional keyword arguments forwarded by the function.
                """
                inst = (coord_cls or MagicMock)(**kwargs)
                self.instances.append(inst)
                return inst

            return _f

    return _C()


@pytest.fixture
def fake_stream_response_factory() -> Any:
    """Provide a factory that builds fake streaming HTTP responses.

    The returned factory creates response objects with ``status``, ``reason``,
    and ``ok`` attributes, async context-manager support, and a
    ``content.iter_chunked()`` async generator for yielding the supplied byte
    chunks.
    """

    def _make(chunks: list[bytes], status: int = 200, reason: str = "OK", ok: bool = True) -> Any:
        """Create a fake streamed HTTP response with the supplied byte chunks."""

        class _Resp:
            def __init__(self) -> None:
                """Store the response metadata used by stream-reading tests."""
                self.status = status
                self.reason = reason
                self.ok = ok

            async def __aenter__(self) -> Any:
                """Enter the fake response context and return the response object."""
                return self

            async def __aexit__(
                self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: object
            ) -> bool:
                """Exit the fake response context without suppressing exceptions.

                Args:
                    exc_type: Exception type raised inside the context manager, if any.
                    exc: Exception instance raised inside the context manager, if any.
                    tb: Traceback associated with ``exc``, if any.
                """
                return False

            @property
            def content(self) -> Any:
                """Expose a minimal async stream reader for the supplied chunks."""

                class C:
                    def __init__(self, chunks: list[bytes]) -> None:
                        """Store the chunks that the fake stream reader will yield.

                        Args:
                            chunks: Raw byte chunks to emit through ``iter_chunked``.
                        """
                        self._chunks = chunks

                    async def iter_chunked(self, _n: Any) -> AsyncIterator[Any]:
                        """Yield each preloaded chunk regardless of requested chunk size.

                        Args:
                            _n: Chunk size requested by the caller and ignored by this fake stream.
                        """
                        for c in self._chunks:
                            yield c

                return C(list(chunks))

        return _Resp()

    return _make


@pytest.fixture
def coordinator() -> Any:
    """Provide a lightweight coordinator mock for tests. Use MagicMock so that registering listeners (which happens synchronously) does not produce AsyncMock "never awaited" warnings. Tests that need async behavior can set specific async methods on the mock to AsyncMock."""
    return MagicMock()


class DummyCoordinator(MagicMock):
    """Lightweight coordinator mock used by the tests.

    Use a MagicMock so that callbacks registered synchronously do not create
    AsyncMock coroutines that are never awaited. Tests can set async
    attributes individually to AsyncMock when they need awaitable behavior.
    """


@pytest.fixture
def dummy_coordinator() -> Any:
    """Provide a fresh DummyCoordinator instance for a test. Tests can request this fixture when they need a lightweight coordinator mock that behaves like the previous `DummyCoordinator()` constructor."""
    return DummyCoordinator()


@pytest.fixture
def fake_client() -> Any:
    """Provide a factory that creates lightweight fake OPNsense clients.

    The returned factory can be used to override the device identifier,
    firmware version, telemetry payload, and close result for a test case.
    """

    def _make(
        device_id: Any = "dev1",
        firmware_version: str = "99.0",
        telemetry: dict | None = None,
        close_result: bool = True,
    ) -> Any:
        """Build a fake client class configured with deterministic test responses.

        Args:
            device_id: Device identifier returned by the fake client.
            firmware_version: Firmware version returned by the fake client.
            telemetry: Telemetry payload returned by ``get_telemetry``.
            close_result: Result returned by ``async_close``.
        """

        class FakeClient:
            def __init__(self, **kwargs) -> None:
                # allow explicit overrides via kwargs when tests call the production
                # client factory with parameters; prefer explicit args passed to
                # the fixture factory above.
                """Initialize the fake client instance used by coordinator tests.

                Args:
                    **kwargs: Constructor arguments accepted for compatibility
                        with the production client signature and ignored here.
                """
                self._device_id = device_id
                self._firmware = firmware_version
                self._telemetry = telemetry or {}
                self._close_result = close_result

                self._query_counts = 0

            async def get_device_unique_id(self, expected_id: str | None = None) -> Any:
                """Return the fake device identifier configured for this client.

                Args:
                    expected_id: Expected device identifier supplied by the caller
                        and ignored by this fake implementation.
                """
                return self._device_id

            async def validate(self) -> bool:
                """Perform a no-op validation check for setup-time assertions."""
                return True

            async def get_host_firmware_version(self) -> Any:
                """Return the configured firmware version for test assertions."""
                return self._firmware

            async def async_close(self) -> Any:
                """Return the configured close result for shutdown tests."""
                return self._close_result

            async def get_telemetry(self) -> Any:
                """Return the preloaded telemetry payload for coordinator tests."""
                return self._telemetry

            async def reset_query_counts(self) -> None:
                # mark reset and return None (used by coordinator)
                """Mark that the query counters were reset during a coordinator update."""
                self._query_counts_reset = True

            async def get_query_counts(self) -> int:
                """Return the stored number of fake REST/API query calls."""
                return self._query_counts

            async def get_interfaces(self) -> Any:
                """Return a minimal interface payload with traffic counters."""
                return {"eth0": {"inbytes": 200, "outbytes": 100}}

            async def get_vnstat(self) -> Any:
                """Return an empty vnStat payload for tests that expect no interfaces."""
                return {"interface_count": 0, "interfaces": {}}

            async def get_smart(self) -> Any:
                """Return an empty SMART payload for coordinator tests."""
                return []

            async def get_smart_info(self, device: str, info_type: str = "a") -> dict[str, Any]:
                """Return an empty SMART info payload for coordinator tests.

                Args:
                    device: SMART device name requested by the coordinator.
                    info_type: SMART info selector requested by the coordinator.
                """
                assert device is not None
                assert info_type is not None
                return {}

            async def get_openvpn(self) -> Any:
                """Return an empty OpenVPN payload for coordinator tests."""
                return {"servers": {}}

            async def get_wireguard(self) -> Any:
                """Return an empty WireGuard payload for coordinator tests."""
                return {"servers": {}}

            async def get_carp(self) -> dict[str, Any]:
                """Return one fake CARP payload with interfaces and aggregate summary."""
                return {
                    "interfaces": [],
                    "status_summary": {
                        "state": "not_configured",
                        "enabled": True,
                        "maintenance_mode": False,
                        "demotion": 0,
                        "status_message": "",
                        "vip_count": 0,
                        "master_count": 0,
                        "backup_count": 0,
                        "other_count": 0,
                        "interfaces": [],
                        "vips": [],
                    },
                }

        return FakeClient

    return _make


@pytest.fixture
def fake_reg_factory() -> Any:
    """Provide a factory that builds configurable fake device registries.

    The returned registry object exposes ``async_get_device()``,
    ``async_remove_device()``, and a ``removed`` flag so tests can assert how
    registry cleanup behaves.
    """

    def _make(
        device_exists: bool = False,
        device_id: str = "dev",
        remove_result: Any | None = None,
        config_entries: set[str] | None = None,
        disabled_by: str | None = None,
    ) -> Any:
        """Create a fake device registry with configurable lookup and removal behavior.

        Args:
            device_exists: Whether ``async_get_device`` should return a device record.
            device_id: Device identifier returned when ``device_exists`` is true.
            remove_result: Value returned by ``async_remove_device``.
            config_entries: Config entries already linked to the fake device.
            disabled_by: Disable source reported by the fake device entry.
        """

        class _FakeReg:
            def __init__(self) -> None:
                """Initialize _FakeReg."""
                self.removed = False
                self.updated_devices: list[tuple[str, dict[str, Any]]] = []
                self._device_exists = device_exists
                self._device_id = device_id
                self._remove_result = remove_result
                self._config_entries = config_entries or set()
                self._disabled_by = disabled_by

            def async_get_device(self, *args, **kwargs) -> Any:
                """Return a fake device entry when the fixture is configured to find one.

                Args:
                    *args: Positional lookup arguments accepted for API compatibility.
                    **kwargs: Keyword lookup arguments accepted for API compatibility.
                """
                if self._device_exists:

                    class _D:
                        id = self._device_id
                        config_entries = self._config_entries
                        disabled_by = self._disabled_by

                    return _D()
                return None

            def async_update_device(self, device_id: str, **kwargs: Any) -> None:
                """Record device updates for assertions.

                Args:
                    device_id: Device identifier being updated.
                    **kwargs: Device update keyword arguments.
                """
                self.updated_devices.append((device_id, kwargs))

            def async_remove_device(self, *args, **kwargs) -> Any:
                # mirror previous tests which sometimes inspect a `removed` flag
                """Record device removal and return the configured removal result.

                Args:
                    *args: Positional removal arguments accepted for API compatibility.
                    **kwargs: Keyword removal arguments accepted for API compatibility.
                """
                self.removed = True
                return self._remove_result

        return _FakeReg()

    return _make


@pytest.fixture
def fake_flow_client() -> Any:
    """Return a factory that constructs a lightweight FakeClient used in flow tests."""

    def _make(
        device_id: str = "unique-id",
        firmware: str = "25.1",
    ) -> Any:
        """Build a lightweight flow-test client class with configurable identity.

        Args:
            device_id: Device identifier returned by the fake client.
            firmware: Firmware version returned by the fake client.
        """

        class FakeFlowClient:
            """Configurable fake client for flow tests.

            Attributes:
                last_instance: class var pointing to last created instance

            """

            last_instance: FakeFlowClient | None = None

            def __init__(self, *args, **kwargs) -> None:
                """Initialize FakeFlowClient.

                Args:
                    *args: Additional positional arguments forwarded by the function.
                    **kwargs: Additional keyword arguments forwarded by the function.
                """
                FakeFlowClient.last_instance = self
                self._device_id = device_id
                self._firmware = firmware

            async def get_host_firmware_version(self) -> str:
                """Return the configured firmware version for flow validation."""
                return self._firmware

            async def get_system_info(self) -> dict:
                """Return minimal system information for config-flow validation."""
                return {"name": "OPNsense"}

            async def get_device_unique_id(self, expected_id: str | None = None) -> str:
                """Return the fake device identifier configured for the flow test.

                Args:
                    expected_id: Expected device identifier supplied by the caller and ignored.
                """
                return self._device_id

            async def async_close(self) -> None:
                """Record a successful close operation for flow-client assertions."""
                return

        return FakeFlowClient

    return _make


@pytest.fixture
def fake_coordinator() -> Any:
    """Return a simple FakeCoordinator class tests can pass to coordinator_capture.factory. The class records when its refresh/shutdown methods are called and accepts kwargs such as `device_tracker_coordinator` to mirror prior test-local coordinator implementations."""

    class FakeCoordinator:
        def __init__(self, **kwargs) -> None:
            # mirror existing tests which inspect this flag
            """Initialize FakeCoordinator.

            Args:
                **kwargs: Additional keyword arguments forwarded by the function.
            """
            self._is_device_tracker = kwargs.get("device_tracker_coordinator", False)

        async def async_config_entry_first_refresh(self) -> bool:
            # mark that initial refresh happened for assertions
            """Async config entry first refresh."""
            self.refreshed = True
            return True

        async def async_shutdown(self) -> bool:
            # record that shutdown was invoked
            """Async shutdown."""
            self.shut = True
            return True

    return FakeCoordinator


@pytest.fixture
def make_config_entry() -> Any:
    """Provide a factory that creates ``MockConfigEntry`` instances for tests.

    The returned factory accepts overrides for the entry data, metadata, and
    runtime data so each test can construct a config entry that matches the
    scenario under test.
    """

    def _make(
        data: dict | None = None,
        *,
        title: str | None = None,
        unique_id: str | None = None,
        entry_id: str | None = None,
        version: int | None = None,
        options: dict | None = None,
        runtime_data: Any | None = None,
    ) -> MockConfigEntry:
        """Create a ``MockConfigEntry`` with sensible defaults for integration tests.

        Args:
            data: Config entry data mapping, or a default device ID when omitted.
            title: Optional config entry title.
            unique_id: Identifier for unique.
            entry_id: Config entry identifier for the integration instance being referenced.
            version: Optional config entry version override.
            options: Options mapping that stores the integration settings being updated.
            runtime_data: Optional runtime data object attached to the entry.
        """
        data = data or {CONF_DEVICE_UNIQUE_ID: "test-device-123"}
        entry = MockConfigEntry(
            domain="opnsense", data=data, title=(title if title is not None else "OPNSense Test")
        )

        # Apply optional attributes using object.__setattr__ to bypass property protections.
        if unique_id is not None:
            object.__setattr__(entry, "unique_id", unique_id)
        if entry_id is not None:
            object.__setattr__(entry, "entry_id", entry_id)
        if version is not None:
            object.__setattr__(entry, "version", version)
        if options is not None:
            object.__setattr__(entry, "options", options)
        # runtime_data default is a MagicMock to support attribute-style access in tests
        entry.runtime_data = runtime_data if runtime_data is not None else MagicMock()
        return entry

    return _make


@pytest.fixture
def ph_hass(hass: HomeAssistant) -> HomeAssistant:
    """Return the PHCC Home Assistant fixture with task creation observable by tests."""

    # Helper used to schedule coroutines on the running loop when possible.
    def _schedule_or_return(coro: Any) -> Any:
        """Schedule or return.

        Args:
            coro: Coro provided by pytest or the test case.
        """
        try:
            loop = asyncio.get_running_loop()
            return loop.create_task(coro)
        except RuntimeError:
            # No running loop available (unlikely in async tests); fall
            # back to returning the coroutine so callers can decide.
            return coro

    _ensure_async_create_task_mock(hass, _schedule_or_return)
    return hass


@pytest.fixture
def expected_lingering_timers() -> bool:
    """Allow switch delay timers that tests intentionally leave scheduled."""
    return True
