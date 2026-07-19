"""Unit tests for live-interface traffic coordinator stream handling."""

import asyncio
from collections.abc import AsyncIterator, Callable
import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from aiopnsense import OPNsenseClient
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.opnsense.const import CONF_DEVICE_UNIQUE_ID, CONF_SYNC_LIVE_TRAFFIC
from custom_components.opnsense.traffic_coordinator import OPNsenseLiveTrafficCoordinator


class _FakeStreamClient(OPNsenseClient):
    """Fake OPNsense client for streaming traffic coordinator tests."""

    def __init__(self, payloads: list[dict[str, Any]]) -> None:
        """Store streamed payloads and track stream invocations."""
        self._payloads = payloads
        self.stream_calls: list[int] = []

    def stream_interface_traffic(self, poll_interval: int = 1) -> AsyncIterator[dict[str, Any]]:
        """Return an async iterator for the configured payload sequence."""
        self.stream_calls.append(poll_interval)

        async def _stream() -> AsyncIterator[dict[str, Any]]:
            for payload in self._payloads:
                yield payload

        return _stream()


@pytest.mark.parametrize("raw_rate", [-1, float("nan"), float("inf"), float("-inf")])
def test_live_traffic_coordinator_rejects_invalid_rates(raw_rate: float) -> None:
    """Negative and non-finite stream rates should not enter coordinator data."""
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
    assert coordinator.last_update_success is False
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
async def test_live_traffic_coordinator_async_shutdown_cancels_running_task(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Shutdown should cancel an in-progress stream task and clear task state."""
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id"})
    main_coordinator = MagicMock()
    main_coordinator.data = {"interfaces": {"wan": {"name": "WAN"}}}
    client = _FakeStreamClient(payloads=[])

    coordinator = OPNsenseLiveTrafficCoordinator(
        hass=MagicMock(),
        config_entry=entry,
        coordinator=main_coordinator,
        client=client,
    )
    coordinator._task = asyncio.create_task(asyncio.sleep(3600))

    await coordinator.async_shutdown()

    assert coordinator._task is None
    assert coordinator._shutdown_requested is True


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


@pytest.mark.asyncio
async def test_live_traffic_coordinator_returns_no_sample_when_stream_method_missing() -> None:
    """A missing client streaming method should mark the coordinator as failed."""
    entry = MockConfigEntry(
        domain="opnsense",
        title="OPNsense",
        data={CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_LIVE_TRAFFIC: True},
        options={},
        entry_id="x",
    )
    main_coordinator = MagicMock()
    main_coordinator.data = {"interfaces": {"wan": {"name": "WAN"}}}
    client = object()

    coordinator = OPNsenseLiveTrafficCoordinator(
        hass=MagicMock(),
        config_entry=entry,
        coordinator=main_coordinator,
        client=client,  # type: ignore[arg-type]
    )

    has_sample = await coordinator._consume_stream()

    assert has_sample is False
    assert coordinator.last_update_success is False


@pytest.mark.asyncio
async def test_live_traffic_coordinator_records_update_error_on_stream_exceptions(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Stream-time exceptions from the live stream should be captured as update errors."""
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_LIVE_TRAFFIC: True})
    main_coordinator = MagicMock()
    main_coordinator.data = {"interfaces": {"wan": {"name": "WAN"}}}

    class _BadClient(OPNsenseClient):
        """Client that raises ValueError while iterating the stream."""

        def __init__(self) -> None:
            """Initialize the stream-error test double without a network session."""

        def stream_interface_traffic(self, poll_interval: int = 1) -> AsyncIterator[dict[str, Any]]:
            """Async iterator that raises a stream parsing exception."""

            async def _stream() -> AsyncIterator[dict[str, Any]]:
                raise ValueError("bad stream payload")
                yield {}

            return _stream()

    coordinator = OPNsenseLiveTrafficCoordinator(
        hass=MagicMock(),
        config_entry=entry,
        coordinator=main_coordinator,
        client=_BadClient(),
    )

    has_sample = await coordinator._consume_stream()

    assert has_sample is False
    assert coordinator.last_update_success is False
    assert coordinator.data == {"interfaces": {}}


@pytest.mark.asyncio
async def test_live_traffic_retry_delay_caps_at_max_interval(
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
async def test_live_traffic_run_applies_backoff_sequence_and_resets_on_success(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """The retry loop should walk 5/10/20/30 and reset after a success sample."""
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
        sleep_calls.append(delay)
        if len(sleep_calls) >= 5:
            coordinator._shutdown_requested = True

    monkeypatch.setattr("custom_components.opnsense.traffic_coordinator.asyncio.sleep", _fake_sleep)

    monkeypatch.setattr(coordinator, "_consume_stream", AsyncMock(return_value=False))
    coordinator.last_update_success = False
    await coordinator._run()

    assert sleep_calls == [5, 10, 20, 30, 30]
    assert coordinator._failure_count == 4

    async def _fake_success_sleep(delay: int) -> None:
        coordinator._shutdown_requested = True

    coordinator._failure_count = 7

    async def _consume_valid_sample() -> bool:
        return coordinator._consume_payload({"interfaces": {"wan": {"rx_bytes_per_second": 1000}}})

    monkeypatch.setattr(
        coordinator,
        "_consume_stream",
        AsyncMock(side_effect=_consume_valid_sample),
    )
    coordinator._shutdown_requested = False
    monkeypatch.setattr(
        "custom_components.opnsense.traffic_coordinator.asyncio.sleep", _fake_success_sleep
    )
    await coordinator._run()
    assert coordinator._failure_count == 0
