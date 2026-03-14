"""Speedtest methods for OPNsenseClient."""

# Endpoints (GET):
# /api/speedtest/service/showstat
# /api/speedtest/service/showlog
# /api/speedtest/service/showrecent
# /api/speedtest/service/version
# /api/speedtest/service/serverlist
# /api/speedtest/service/run/[$serverid]
#
# Sources:
# https://github.com/mimugmail/opn-repo/blob/main/net-mgmt/speedtest-community/src/opnsense/mvc/app/controllers/OPNsense/Speedtest/Api/ServiceController.php
# https://github.com/mihakralj/opnsense-speedtest/blob/main/src/opnsense/mvc/app/controllers/OPNsense/Speedtest/Api/ServiceController.php

from __future__ import annotations

from collections.abc import MutableMapping
from typing import Any

from ._typing import PyOPNsenseClientProtocol
from .helpers import _LOGGER, _log_errors, try_to_float, try_to_int


class SpeedtestMixin(PyOPNsenseClientProtocol):
    """Speedtest methods for OPNsenseClient."""

    @_log_errors
    async def get_speedtest(self) -> dict[str, Any]:
        """Return normalized speedtest summary payload for sensors.

        Returns
        -------
        dict[str, Any]
            Normalized speedtest state including last and average metrics.

        """
        if not await self.is_endpoint_available("/api/speedtest/service/showrecent"):
            _LOGGER.debug("Speedtest not installed")
            return {"available": False}

        show_recent = await self._safe_dict_get("/api/speedtest/service/showrecent")
        show_stat = await self._safe_dict_get("/api/speedtest/service/showstat")

        server_id, server_name = self._parse_recent_server(show_recent.get("server"))
        date = show_recent.get("date") if isinstance(show_recent.get("date"), str) else None
        url = show_recent.get("url") if isinstance(show_recent.get("url"), str) else None

        samples = try_to_int(show_stat.get("samples"))
        period = show_stat.get("period", {})
        oldest = period.get("oldest") if isinstance(period, MutableMapping) else None
        youngest = period.get("youngest") if isinstance(period, MutableMapping) else None

        output: dict[str, Any] = {
            "available": True,
            "last": {},
            "average": {},
        }
        for metric in ("download", "upload", "latency"):
            recent_value = try_to_float(show_recent.get(metric))
            stat_metric = show_stat.get(metric, {})

            output["last"][metric] = {
                "value": recent_value,
                "date": date,
                "server_id": server_id,
                "server": server_name,
                "url": url,
            }
            output["average"][metric] = {
                "value": try_to_float(
                    stat_metric.get("avg") if isinstance(stat_metric, MutableMapping) else None
                ),
                "min": try_to_float(
                    stat_metric.get("min") if isinstance(stat_metric, MutableMapping) else None
                ),
                "max": try_to_float(
                    stat_metric.get("max") if isinstance(stat_metric, MutableMapping) else None
                ),
                "oldest": oldest,
                "youngest": youngest,
                "samples": samples,
            }
        return output

    def _parse_recent_server(self, server_text: Any) -> tuple[str | None, str | None]:
        """Parse the ``showrecent.server`` field into server ID and name.

        Parameters
        ----------
        server_text : Any
            Raw ``server`` field from the speedtest ``showrecent`` endpoint.

        Returns
        -------
        tuple[str | None, str | None]
            Parsed ``(server_id, server_name)`` tuple.

        """
        if not isinstance(server_text, str):
            return None, None
        cleaned = server_text.strip()
        if not cleaned:
            return None, None

        parts = cleaned.split(" ", 1)
        if len(parts) == 2 and parts[0].isdigit():
            return parts[0], parts[1].strip()
        return None, cleaned

    @_log_errors
    async def run_speedtest(self) -> dict[str, Any]:
        """Run speedtest and return the endpoint response payload.

        Returns
        -------
        dict[str, Any]
            Raw speedtest run result payload. Empty dictionary when unavailable.

        """
        if not await self.is_endpoint_available("/api/speedtest/service/showrecent"):
            _LOGGER.debug("Speedtest not installed")
            return {}

        response = await self._safe_dict_get_with_timeout(
            "/api/speedtest/service/run",
            timeout_seconds=180,
        )
        if not isinstance(response, MutableMapping):
            return {}
        return dict(response)
