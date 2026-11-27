"""Unit tests for the Unbound Query Stats coordinator."""

from collections.abc import Callable
from datetime import timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from aiopnsense import OPNsenseClient
import pytest
from pytest_homeassistant.common import MockConfigEntry

from custom_components.opnsense.query_stats_coordinator import OPNsenseQueryStatsCoordinator

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


def test_query_stats_coordinator_polls_every_minute(
    ph_hass: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """The coordinator polls on a fixed 60 s interval.

    Args:
        ph_hass (Any): Patched Home Assistant test instance.
        make_config_entry (Callable[..., MockConfigEntry]): Fixture that creates a mock configuration entry.
    """
    coordinator = OPNsenseQueryStatsCoordinator(
        ph_hass, config_entry=make_config_entry(), client=_make_client(STATS, BLOCKED)
    )

    assert coordinator.update_interval == timedelta(seconds=60)


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
        ph_hass, config_entry=make_config_entry(), client=client
    )

    await coordinator.async_refresh()

    assert coordinator.last_update_success is True
    assert coordinator.data == {"stats": stats, "blocked": blocked}
    client.get_unbound_queries.assert_awaited_once_with(action="block", limit=20)
