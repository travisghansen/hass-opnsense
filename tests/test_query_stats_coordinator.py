"""Unit tests for the Unbound Query Stats coordinator."""

from collections.abc import Callable
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from aiopnsense import OPNsenseClient
import pytest

from custom_components.opnsense.query_stats_coordinator import OPNsenseQueryStatsCoordinator
from tests.common import MockConfigEntry

STATS = OPNsenseClient.QueryStats(
    last_minute=OPNsenseClient.BucketCounts(queries=10, blocked=2, dropped=0),
    last_24h=OPNsenseClient.BucketCounts(queries=1000, blocked=100, dropped=5),
)
BLOCKED = OPNsenseClient.QueryLog(entries=())


def _make_client(stats: Any, blocked: Any) -> MagicMock:
    """Create a client double returning the given DNS reads.

    Args:
        stats (Any): Result of ``get_unbound_query_stats``.
        blocked (Any): Result of ``get_unbound_queries``.

    Returns:
        MagicMock: Client double.
    """
    client = MagicMock()
    client.get_unbound_query_stats = AsyncMock(return_value=stats)
    client.get_unbound_queries = AsyncMock(return_value=blocked)
    return client


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("stats", "blocked"),
    [
        (STATS, BLOCKED),
        (None, BLOCKED),
        (STATS, None),
        (OPNsenseClient.QueryStats(absent="disabled"), OPNsenseClient.QueryLog(absent="disabled")),
    ],
    ids=["data", "stats-failed", "blocked-failed", "absent"],
)
async def test_query_stats_coordinator_reports_both_reads(
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
    stats: Any,
    blocked: Any,
) -> None:
    """Each refresh reads Query Stats and the 20 latest Blocked queries and keeps both results.

    Args:
        ph_hass (Any): Patched Home Assistant test instance.
        make_config_entry (Callable[..., MockConfigEntry]): Fixture that creates a mock configuration entry.
        stats (Any): Query Stats read result.
        blocked (Any): Recently blocked read result.
    """
    client = _make_client(stats, blocked)
    coordinator = OPNsenseQueryStatsCoordinator(
        ph_hass,
        config_entry=make_config_entry(),
        coordinator=MagicMock(data=None),
        client=client,
    )

    await coordinator.async_refresh()

    assert coordinator.last_update_success is True
    assert coordinator.data == {"stats": stats, "blocked": blocked}
    client.get_unbound_queries.assert_awaited_once_with(action="block", limit=20)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("main_state", "expected"),
    [
        ({"host_firmware_version": "26.7.8"}, {"host_firmware_version": "26.7.8"}),
        ({"host_firmware_version": None}, {}),
        (None, {}),
    ],
    ids=["known", "unknown", "main-state-missing"],
)
async def test_query_stats_coordinator_copies_firmware_version(
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
    main_state: dict[str, Any] | None,
    expected: dict[str, Any],
) -> None:
    """Data carries the main coordinator's firmware version, for device info, when known.

    Args:
        ph_hass (Any): Patched Home Assistant test instance.
        make_config_entry (Callable[..., MockConfigEntry]): Fixture that creates a mock configuration entry.
        main_state (dict[str, Any] | None): Main coordinator data.
        expected (dict[str, Any]): Expected firmware entries in the Query Stats data.
    """
    coordinator = OPNsenseQueryStatsCoordinator(
        ph_hass,
        config_entry=make_config_entry(),
        coordinator=MagicMock(data=main_state),
        client=_make_client(STATS, BLOCKED),
    )

    await coordinator.async_refresh()

    assert coordinator.data == {"stats": STATS, "blocked": BLOCKED, **expected}
