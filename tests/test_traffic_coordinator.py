"""Unit tests for live-interface traffic coordinator stream handling."""

import asyncio
from collections.abc import AsyncIterator, Callable
import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from aiopnsense import OPNsenseClient
from aiopnsense.exceptions import OPNsenseError
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.opnsense.const import CONF_DEVICE_UNIQUE_ID, CONF_SYNC_LIVE_TRAFFIC
from custom_components.opnsense.traffic_coordinator import OPNsenseLiveTrafficCoordinator


class _FakeStreamClient(OPNsenseClient):
    """Fake OPNsense client for streaming traffic coordinator tests."""

    def __init__(self, payloads: list[dict[str, Any]]) -> None:
        """Store streamed payloads and track stream invocations.

        Args:
            payloads: Pre-baked payloads emitted by
                :meth:`stream_interface_traffic`.
        """
        self._payloads = payloads
        self.stream_calls: list[int] = []

    def stream_interface_traffic(self, poll_interval: int = 1) -> AsyncIterator[dict[str, Any]]:
        """Return an async iterator for the configured payload sequence.

        Args:
            poll_interval: Requested polling interval in seconds.

        Returns:
            AsyncIterator[dict[str, Any]]: Iterator over the configured stream payloads.
        """
        self.stream_calls.append(poll_interval)

        async def _stream() -> AsyncIterator[dict[str, Any]]:
            """Yield payloads from the configured stream.

            Yields:
                dict[str, Any]: Payload frames from ``self._payloads``.
            """
            for payload in self._payloads:
                yield payload

        return _stream()


def _build_test_coordinator(
    make_config_entry: Callable[..., MockConfigEntry],
    *,
    entry_data: dict[str, Any] | None = None,
    main_coordinator_data: dict[str, Any] | None = None,
    client: Any | None = None,
    poll_interval: int = 1,
) -> tuple[OPNsenseLiveTrafficCoordinator, MagicMock]:
    """Build a traffic coordinator and its parent coordinator with defaults."""
    if entry_data is None:
        entry_data = {CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_LIVE_TRAFFIC: True}
    if main_coordinator_data is None:
        main_coordinator_data = {"interfaces": {"wan": {"name": "WAN"}}}

    main_coordinator = MagicMock()
    main_coordinator.data = main_coordinator_data

    coordinator = OPNsenseLiveTrafficCoordinator(
        hass=MagicMock(),
        config_entry=make_config_entry(entry_data),
        coordinator=main_coordinator,
        client=MagicMock() if client is None else client,
        poll_interval=poll_interval,
    )
    return coordinator, main_coordinator


@pytest.mark.parametrize(
    "raw_rate",
    [
        pytest.param(-1, id="negative"),
        pytest.param(float("nan"), id="nan"),
        pytest.param(float("inf"), id="infinity"),
        pytest.param(float("-inf"), id="negative-infinity"),
        pytest.param("bad-rate", id="non-numeric"),
        pytest.param(None, id="none"),
    ],
)
def test_live_traffic_coordinator_rejects_invalid_rates(raw_rate: Any) -> None:
    """Rate conversion errors should be treated as unavailable values."""
    assert OPNsenseLiveTrafficCoordinator._map_stream_rate("rx_bytes_per_second", raw_rate) is None


def test_live_traffic_coordinator_aggregates_sample_logging(
    caplog: pytest.LogCaptureFixture,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Live samples should notify listeners without logging every pushed update."""
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_LIVE_TRAFFIC: True})
    main_coordinator = MagicMock()
    main_coordinator.data = {"interfaces": {"wan": {"name": "WAN"}}}
    coordinator = OPNsenseLiveTrafficCoordinator(
        hass=MagicMock(),
        config_entry=entry,
        coordinator=main_coordinator,
        client=_FakeStreamClient(payloads=[]),
    )
    listener = MagicMock()
    coordinator.async_add_listener(listener)
    caplog.set_level(logging.DEBUG, logger="custom_components.opnsense.traffic_coordinator")

    payload = {"interfaces": {"wan": {"rx_bytes_per_second": 1000}}}
    for _ in range(60):
        assert coordinator._consume_payload(payload) is True

    assert listener.call_count == 60
    messages = [record.getMessage() for record in caplog.records]
    assert not any("Manually updated" in message for message in messages)
    assert (
        messages.count("Processed 60 live interface traffic samples covering 60 interface updates")
        == 1
    )


@pytest.mark.asyncio
async def test_live_traffic_coordinator_merges_rates_with_interface_metadata(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Rate payloads should merge into live coordinator data with interface metadata."""
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_LIVE_TRAFFIC: True})
    main_coordinator = MagicMock()
    main_coordinator.data = {
        "interfaces": {
            "wan": {
                "name": "WAN",
                "status": "up",
                "description": "uplink",
                "enabled": True,
                "interface": "igc0",
                "device": "em0",
                "ipv4": ["10.0.0.1"],
                "ipv6": ["fd00::1"],
                "media": "1000baseT",
                "vlan_tag": 20,
                "mac": "aa:bb:cc:dd:ee:ff",
                "inbytes": 1,
                "outbytes": 2,
            },
            "lan": {
                "name": "LAN",
                "status": "down",
                "inbytes": 5,
                "outbytes": 9,
            },
        },
        "host_firmware_version": "25.1.3",
    }

    client = _FakeStreamClient(
        [
            {
                "interfaces": {
                    "wan": {
                        "rx_bytes_per_second": 1536,
                        "tx_bytes_per_second": 2500,
                        "rx_packets_per_second": 100,
                        "tx_packets_per_second": 200,
                        "unexpected_field": "ignore",
                    },
                    "missing_metadata": {"rx_bytes_per_second": 100},
                }
            }
        ]
    )

    coordinator = OPNsenseLiveTrafficCoordinator(
        hass=MagicMock(),
        config_entry=entry,
        coordinator=main_coordinator,
        client=client,
        poll_interval=1,
    )

    has_sample = await coordinator._consume_stream()

    assert has_sample is True
    state = coordinator.data
    interfaces = state.get("interfaces")
    assert isinstance(interfaces, dict)
    assert interfaces["wan"]["name"] == "WAN"
    assert interfaces["wan"]["status"] == "up"
    assert interfaces["wan"]["enabled"] is True
    assert interfaces["wan"]["interface"] == "igc0"
    assert interfaces["wan"]["device"] == "em0"
    assert interfaces["wan"]["ipv4"] == ["10.0.0.1"]
    assert interfaces["wan"]["ipv6"] == ["fd00::1"]
    assert interfaces["wan"]["media"] == "1000baseT"
    assert interfaces["wan"]["vlan_tag"] == 20
    assert interfaces["wan"]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert state["host_firmware_version"] == "25.1.3"
    assert "host_firmware_version" not in interfaces["wan"]
    assert interfaces["wan"]["inbytes_kilobytes_per_second"] == 1.54
    assert interfaces["wan"]["outbytes_kilobytes_per_second"] == 2.5
    assert interfaces["wan"]["inpkts_packets_per_second"] == 100
    assert interfaces["wan"]["outpkts_packets_per_second"] == 200
    assert "description" not in interfaces["wan"]
    assert "inbytes" not in interfaces["wan"]
    assert "outbytes" not in interfaces["wan"]
    assert "missing_metadata" not in interfaces
    assert coordinator.last_update_success is False
    assert coordinator._failure_count == 0
    assert client.stream_calls == [1]


@pytest.mark.asyncio
async def test_live_traffic_coordinator_start_is_idempotent(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """A second async_start call should not replace an active background task."""
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id"})
    main_coordinator = MagicMock()
    main_coordinator.data = {"interfaces": {"wan": {"name": "WAN"}}}
    client = _FakeStreamClient(payloads=[])

    active_tasks: list[asyncio.Task[None]] = []

    def _create_task(_hass: Any, _coro: Any, _name: str) -> asyncio.Task[None]:
        """Capture an async task created by the test harness.

        Args:
            _hass: Home Assistant instance from the coordinator API.
            _coro: Coroutine body scheduled by the coordinator.
            _name: Task name requested by the caller (unused in this test).

        Returns:
            asyncio.Task[None]: The created asyncio task.
        """
        task = asyncio.create_task(_coro)
        active_tasks.append(task)
        return task

    entry.async_create_background_task = MagicMock(side_effect=_create_task)

    coordinator = OPNsenseLiveTrafficCoordinator(
        hass=MagicMock(),
        config_entry=entry,
        coordinator=main_coordinator,
        client=client,
    )

    await coordinator.async_start()
    first_task = coordinator._task
    await coordinator.async_start()

    assert first_task is not None
    assert coordinator._task is first_task
    assert entry.async_create_background_task.call_count == 1

    await coordinator.async_shutdown()
    assert coordinator._task is None
    assert all(task.cancelled() for task in active_tasks)


@pytest.mark.asyncio
async def test_live_traffic_coordinator_records_update_error_on_missing_payload(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """No valid stream payload should mark coordinator update as failed."""
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_LIVE_TRAFFIC: True})
    main_coordinator = MagicMock()
    main_coordinator.data = {"interfaces": {"wan": {"name": "WAN"}}}
    client = _FakeStreamClient(payloads=[])

    coordinator = OPNsenseLiveTrafficCoordinator(
        hass=MagicMock(),
        config_entry=entry,
        coordinator=main_coordinator,
        client=client,
    )

    has_sample = await coordinator._consume_stream()

    assert has_sample is False
    assert coordinator.last_update_success is False
    assert coordinator.data == {"interfaces": {}}


@pytest.mark.parametrize(
    ("payload", "main_coordinator_data"),
    [
        pytest.param([], {"interfaces": {"wan": {"name": "WAN"}}}, id="payload-non-mapping"),
        pytest.param(
            {"foo": "bar"},
            {"interfaces": {"wan": {"name": "WAN"}}},
            id="payload-missing-interfaces-key",
        ),
        pytest.param(
            {"interfaces": "bad"},
            {"interfaces": {"wan": {"name": "WAN"}}},
            id="payload-interfaces-not-mapping",
        ),
        pytest.param(
            {"interfaces": {1: {"rx_bytes_per_second": 100}}},
            {"interfaces": {"wan": {"name": "WAN"}}},
            id="payload-non-string-interface-name",
        ),
        pytest.param(
            {"interfaces": {"wan": "bad"}},
            {"interfaces": {"wan": {"name": "WAN"}}},
            id="payload-interface-entry-not-mapping",
        ),
        pytest.param(
            {"interfaces": {"wan": {"rx_bytes_per_second": 100}}},
            "bad-main-state",
            id="main-state-not-mapping",
        ),
        pytest.param(
            {"interfaces": {"wan": {"rx_bytes_per_second": 100}}},
            {"interfaces": "bad"},
            id="main-interfaces-not-mapping",
        ),
        pytest.param(
            {
                "interfaces": {
                    "wan": {"rx_bytes_per_second": "bad", "tx_bytes_per_second": float("nan")}
                }
            },
            {"interfaces": {"wan": {"name": "WAN"}}},
            id="rates-no-usable-rate",
        ),
    ],
)
def test_live_traffic_coordinator_rejects_bad_payload_context_matrix(
    make_config_entry: Callable[..., MockConfigEntry],
    payload: Any,
    main_coordinator_data: dict[str, Any] | Any,
) -> None:
    """Malformed payload/context combinations should be rejected without publishing."""
    coordinator, _ = _build_test_coordinator(
        make_config_entry,
        main_coordinator_data=main_coordinator_data,
    )

    assert coordinator._consume_payload(payload) is False
    assert coordinator.data == {"interfaces": {}}


@pytest.mark.asyncio
async def test_live_traffic_coordinator_consumes_stream_cancelled_error(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CancelledError from the stream should propagate to the caller."""

    async def _stream() -> AsyncIterator[dict[str, Any]]:
        """Raise ``asyncio.CancelledError`` as soon as stream iteration starts.

        Raises:
            asyncio.CancelledError: Stream iteration is intentionally cancelled.
        """
        raise asyncio.CancelledError
        yield {}

    client = MagicMock()
    client.stream_interface_traffic = MagicMock(return_value=_stream())

    coordinator, _ = _build_test_coordinator(make_config_entry, client=client)

    with pytest.raises(asyncio.CancelledError):
        await coordinator._consume_stream()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stream_exception",
    [
        pytest.param(OPNsenseError("boom"), id="opnsense-error"),
        pytest.param(ValueError("bad stream payload"), id="value-error"),
    ],
)
async def test_live_traffic_coordinator_consumes_stream_records_update_error(
    make_config_entry: Callable[..., MockConfigEntry],
    stream_exception: Exception,
) -> None:
    """Stream-time exceptions should be captured as update failures."""

    async def _stream() -> AsyncIterator[dict[str, Any]]:
        """Raise a stream error as soon as stream iteration starts.

        Raises:
            Exception: Stream iteration raises a transport or payload exception.
        """
        raise stream_exception
        yield {}

    client = MagicMock()
    client.stream_interface_traffic = MagicMock(return_value=_stream())

    coordinator, _ = _build_test_coordinator(make_config_entry, client=client)

    has_sample = await coordinator._consume_stream()

    assert has_sample is False
    assert coordinator.last_update_success is False


@pytest.mark.asyncio
async def test_live_traffic_run_breaks_when_shutdown_requested_inside_consume_stream(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """A shutdown request set during stream consumption should exit without sleeping."""
    coordinator, _ = _build_test_coordinator(make_config_entry)

    async def _consume_and_request_shutdown() -> bool:
        """Request shutdown and report no payload consumed.

        Returns:
            bool: ``False`` because no payload was consumed.
        """
        coordinator._shutdown_requested = True
        return False

    monkeypatch.setattr(
        coordinator,
        "_consume_stream",
        AsyncMock(side_effect=_consume_and_request_shutdown),
    )
    sleep_mock = AsyncMock()
    monkeypatch.setattr("custom_components.opnsense.traffic_coordinator.asyncio.sleep", sleep_mock)

    await coordinator._run()

    assert sleep_mock.await_count == 0
    assert coordinator._shutdown_requested is True


@pytest.mark.asyncio
async def test_live_traffic_run_sleeps_poll_interval_when_live_traffic_disabled(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """When live traffic is disabled, the retry loop should wait poll interval before exit."""
    coordinator, _ = _build_test_coordinator(make_config_entry, poll_interval=2)
    coordinator.last_update_success = False
    monkeypatch.setattr(coordinator, "_read_live_traffic_flag", MagicMock(return_value=False))

    async def _consume_stream() -> bool:
        """Return ``False`` to indicate no payload was consumed.

        Returns:
            bool: ``False`` because nothing was consumed.
        """
        return False

    async def _sleep(duration: float) -> None:
        """Wait expected interval and then request shutdown.

        Args:
            duration: Delay requested by the coordinator's run loop.
        """
        assert duration == 2
        coordinator._shutdown_requested = True

    consume_stream = AsyncMock(side_effect=_consume_stream)
    monkeypatch.setattr(coordinator, "_consume_stream", consume_stream)
    monkeypatch.setattr("custom_components.opnsense.traffic_coordinator.asyncio.sleep", _sleep)

    await coordinator._run()

    assert consume_stream.await_count == 1
    assert coordinator._shutdown_requested is True


@pytest.mark.asyncio
async def test_live_traffic_run_reconnects_after_finite_valid_stream(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """A finite valid stream should mark unavailable and schedule minimum backoff."""
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_LIVE_TRAFFIC: True})
    main_coordinator = MagicMock()
    main_coordinator.data = {"interfaces": {"wan": {"name": "WAN"}}}
    client = _FakeStreamClient(
        [
            {
                "interfaces": {
                    "wan": {
                        "rx_bytes_per_second": 1000,
                    },
                },
            }
        ]
    )

    coordinator = OPNsenseLiveTrafficCoordinator(
        hass=MagicMock(),
        config_entry=entry,
        coordinator=main_coordinator,
        client=client,
    )

    sleep_calls: list[int] = []

    async def _fake_sleep(delay: int) -> None:
        """Capture the reconnect delay and stop the loop after first retry."""
        sleep_calls.append(delay)
        coordinator._shutdown_requested = True

    monkeypatch.setattr("custom_components.opnsense.traffic_coordinator.asyncio.sleep", _fake_sleep)

    await coordinator._run()

    assert sleep_calls == [5]
    assert coordinator._failure_count == 1
    assert coordinator.last_update_success is False
    assert client.stream_calls == [1]
    assert coordinator.data["interfaces"]["wan"]["name"] == "WAN"
    assert coordinator.data["interfaces"]["wan"]["inbytes_kilobytes_per_second"] == 1.0


def test_live_traffic_retry_delay_caps_at_max_interval(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Retry delay should grow through backoff values and then cap."""
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_LIVE_TRAFFIC: True})
    main_coordinator = MagicMock()
    main_coordinator.data = {"interfaces": {"wan": {"name": "WAN"}}}
    client = _FakeStreamClient(payloads=[])

    coordinator = OPNsenseLiveTrafficCoordinator(
        hass=MagicMock(),
        config_entry=entry,
        coordinator=main_coordinator,
        client=client,
    )

    assert coordinator._get_retry_delay() == 5
    coordinator._failure_count = 1
    assert coordinator._get_retry_delay() == 5
    coordinator._failure_count = 2
    assert coordinator._get_retry_delay() == 10
    coordinator._failure_count = 3
    assert coordinator._get_retry_delay() == 20
    coordinator._failure_count = 4
    assert coordinator._get_retry_delay() == 30
    coordinator._failure_count = 10
    assert coordinator._get_retry_delay() == 30


@pytest.mark.asyncio
async def test_live_traffic_run_applies_and_caps_backoff_sequence(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """The retry loop should walk the full backoff sequence and cap at the maximum."""
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_LIVE_TRAFFIC: True})
    main_coordinator = MagicMock()
    main_coordinator.data = {"interfaces": {"wan": {"name": "WAN"}}}
    client = _FakeStreamClient(payloads=[])

    coordinator = OPNsenseLiveTrafficCoordinator(
        hass=MagicMock(),
        config_entry=entry,
        coordinator=main_coordinator,
        client=client,
    )

    sleep_calls: list[int] = []

    async def _fake_sleep(delay: int) -> None:
        """Record sleep delay and request shutdown after retry backoff caps.

        Args:
            delay: Delay requested by the coordinator's retry sleep helper.
        """
        sleep_calls.append(delay)
        if len(sleep_calls) >= 5:
            coordinator._shutdown_requested = True

    monkeypatch.setattr("custom_components.opnsense.traffic_coordinator.asyncio.sleep", _fake_sleep)

    monkeypatch.setattr(coordinator, "_consume_stream", AsyncMock(return_value=False))
    coordinator.last_update_success = False
    await coordinator._run()

    assert sleep_calls == [5, 10, 20, 30, 30]
    assert coordinator._failure_count == 4
