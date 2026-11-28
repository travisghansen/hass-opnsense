"""Coordinator for Unbound Query Stats and recently blocked queries."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import timedelta
import logging
from typing import TYPE_CHECKING, Any, Literal

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .coordinator import OPNsenseDataUpdateCoordinator

if TYPE_CHECKING:
    from aiopnsense import OPNsenseClient

_LOGGER: logging.Logger = logging.getLogger(__name__)

QUERY_STATS_SCAN_INTERVAL: timedelta = timedelta(seconds=60)
RECENTLY_BLOCKED_LIMIT: int = 20

type DnsReadStatus = Literal["data", "absent", "failed"]


def dns_read_status(
    result: OPNsenseClient.QueryStats | OPNsenseClient.QueryLog | None,
) -> DnsReadStatus:
    """Classify a DNS read result from aiopnsense.

    Args:
        result (OPNsenseClient.QueryStats | OPNsenseClient.QueryLog | None): Read result,
            or None when the read failed.

    Returns:
        DnsReadStatus: ``failed`` for None, ``absent`` when the Router cannot provide
            the data, otherwise ``data``.
    """
    if result is None:
        return "failed"
    return "absent" if result.absent is not None else "data"


def query_log_rows(query_log: OPNsenseClient.QueryLog) -> list[dict[str, Any]]:
    """Convert Query Log entries to plain rows for attributes and action responses.

    Args:
        query_log (OPNsenseClient.QueryLog): Query Log with data.

    Returns:
        list[dict[str, Any]]: One mapping per entry, newest first.
    """
    return [
        {
            "time": entry.time.isoformat(),
            "client": entry.client,
            "domain": entry.domain,
            "action": entry.action,
            "blocklist": entry.blocklist,
            "policy": entry.policy,
        }
        for entry in query_log.entries
    ]


class OPNsenseQueryStatsCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Poll Unbound Query Stats and the recently blocked queries every minute.

    Data is ``{"stats": QueryStats | None, "blocked": QueryLog | None}`` plus the main
    coordinator's ``host_firmware_version`` when known, so entities on this coordinator
    get the same device info as the rest. ``None`` means the read failed this time; a
    result with ``absent`` set means the Router cannot provide the data (endpoint
    missing, not permitted, or statistics off).

    A failed read is reported in the data, not raised, so ``last_update_success``
    (also in diagnostics) stays true even when both reads fail.
    """

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        config_entry: ConfigEntry,
        coordinator: OPNsenseDataUpdateCoordinator,
        client: OPNsenseClient,
    ) -> None:
        """Initialize the Query Stats coordinator.

        Args:
            hass (HomeAssistant): Home Assistant instance.
            config_entry (ConfigEntry): Config entry that owns this coordinator.
            coordinator (OPNsenseDataUpdateCoordinator): Main coordinator whose firmware
                version is copied into this coordinator's data.
            client (OPNsenseClient): OPNsense API client with errors disabled.
        """
        super().__init__(
            hass=hass,
            logger=_LOGGER,
            name=f"{config_entry.title} Query Stats",
            update_interval=QUERY_STATS_SCAN_INTERVAL,
            config_entry=config_entry,
        )
        self._coordinator: OPNsenseDataUpdateCoordinator = coordinator
        self._client: OPNsenseClient = client

    async def _async_update_data(self) -> dict[str, Any]:
        """Read Query Stats and the recently blocked queries.

        Returns:
            dict[str, Any]: ``stats`` and ``blocked`` results, each ``None`` when the
                read failed this time, and ``host_firmware_version`` when known.
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
        data: dict[str, Any] = {"stats": stats, "blocked": blocked}
        main_state = self._coordinator.data
        if isinstance(main_state, Mapping):
            host_firmware_version = main_state.get("host_firmware_version")
            if host_firmware_version is not None:
                data["host_firmware_version"] = host_firmware_version
        return data
