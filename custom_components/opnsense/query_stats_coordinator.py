"""Coordinator for Unbound Query Stats and recently blocked queries."""

from __future__ import annotations

from datetime import timedelta
import logging
from typing import TYPE_CHECKING, Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

if TYPE_CHECKING:
    from aiopnsense import OPNsenseClient

_LOGGER: logging.Logger = logging.getLogger(__name__)

QUERY_STATS_SCAN_INTERVAL: timedelta = timedelta(seconds=60)
RECENTLY_BLOCKED_LIMIT: int = 20


class OPNsenseQueryStatsCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Poll Unbound Query Stats and the recently blocked queries every minute.

    Data is ``{"stats": QueryStats | None, "blocked": QueryLog | None}``. ``None``
    means the read failed this time; a result with ``absent`` set means the Router
    cannot provide the data (endpoint missing, not permitted, or statistics off).
    """

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        config_entry: ConfigEntry,
        client: OPNsenseClient,
    ) -> None:
        """Initialize the Query Stats coordinator.

        Args:
            hass (HomeAssistant): Home Assistant instance.
            config_entry (ConfigEntry): Config entry that owns this coordinator.
            client (OPNsenseClient): OPNsense API client with errors disabled.
        """
        super().__init__(
            hass=hass,
            logger=_LOGGER,
            name=f"{config_entry.title} Query Stats",
            update_interval=QUERY_STATS_SCAN_INTERVAL,
            config_entry=config_entry,
        )
        self._client: OPNsenseClient = client

    async def _async_update_data(self) -> dict[str, Any]:
        """Read Query Stats and the recently blocked queries.

        Returns:
            dict[str, Any]: ``stats`` and ``blocked`` results, each ``None`` when the
                read failed this time.
        """
        stats = await self._client.get_unbound_query_stats()
        blocked = await self._client.get_unbound_queries(
            action="block", limit=RECENTLY_BLOCKED_LIMIT
        )
        if stats is None or blocked is None:
            _LOGGER.debug(
                "Query Stats read failed (stats: %s, recently blocked: %s)",
                "failed" if stats is None else "ok",
                "failed" if blocked is None else "ok",
            )
        return {"stats": stats, "blocked": blocked}
