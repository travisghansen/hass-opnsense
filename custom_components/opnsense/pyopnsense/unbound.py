"""Unbound DNS blocklist methods for OPNsenseClient."""

from collections.abc import MutableMapping
from typing import Any

import aiohttp
import awesomeversion

from ._typing import PyOPNsenseClientProtocol
from .helpers import _LOGGER, _log_errors


class UnboundMixin(PyOPNsenseClientProtocol):
    """Unbound DNS blocklist methods for OPNsenseClient."""

    @_log_errors
    async def get_unbound_blocklist_legacy(self) -> MutableMapping[str, Any]:
        """Return the Unbound Blocklist details.

        Returns:
            MutableMapping[str, Any]: Parsed unbound blocklist legacy payload
            returned by OPNsense APIs.
        """
        response = await self._safe_dict_get("/api/unbound/settings/get")
        dnsbl_settings = response.get("unbound", {}).get("dnsbl", {})
        if not isinstance(dnsbl_settings, MutableMapping):
            return {}
        dnsbl = {}
        for attr in ("enabled", "safesearch", "nxdomain", "address"):
            dnsbl[attr] = dnsbl_settings.get(attr, "")
        for attr in ("type", "lists", "whitelists", "blocklists", "wildcards"):
            if isinstance(dnsbl_settings.get(attr, None), MutableMapping):
                dnsbl[attr] = ",".join(
                    [
                        key
                        for key, value in dnsbl_settings.get(attr, {}).items()
                        if isinstance(value, MutableMapping) and value.get("selected", 0) == 1
                    ]
                )
            else:
                dnsbl[attr] = ""
        return dnsbl

    async def _set_unbound_blocklist_legacy(self, set_state: bool) -> bool:
        """Enable or disable legacy Unbound DNS blocklist settings.

        Args:
            set_state: Desired enabled state to apply.

        Returns:
            bool: ``True`` when legacy DNSBL configuration and restart both
            succeed.
        """
        payload: dict[str, Any] = {}
        payload["unbound"] = {}
        payload["unbound"]["dnsbl"] = await self.get_unbound_blocklist_legacy()
        if not payload["unbound"]["dnsbl"]:
            _LOGGER.error("Unable to get Unbound Blocklist Status")
            return False
        if set_state:
            payload["unbound"]["dnsbl"]["enabled"] = "1"
        else:
            payload["unbound"]["dnsbl"]["enabled"] = "0"
        response = await self._post("/api/unbound/settings/set", payload=payload)
        dnsbl_resp = await self._get("/api/unbound/service/dnsbl")
        restart_resp = await self._post("/api/unbound/service/restart")
        _LOGGER.debug(
            "[set_unbound_blocklist_legacy] set_state: %s, payload: %s, response: %s, dnsbl_resp: %s, restart_resp: %s",
            "On" if set_state else "Off",
            payload,
            response,
            dnsbl_resp,
            restart_resp,
        )
        return (
            isinstance(response, MutableMapping)
            and isinstance(dnsbl_resp, MutableMapping)
            and isinstance(restart_resp, MutableMapping)
            and response.get("result", "failed") == "saved"
            and dnsbl_resp.get("status", "failed").startswith("OK")
            and restart_resp.get("response", "failed") == "OK"
        )

    @_log_errors
    async def get_unbound_blocklist(self) -> dict[str, Any]:
        """Return the Unbound Blocklist details.

        Returns:
            dict[str, Any]: Parsed unbound blocklist payload returned by
            OPNsense APIs.
        """
        firmware = await self.get_host_firmware_version()
        try:
            if awesomeversion.AwesomeVersion(firmware) < awesomeversion.AwesomeVersion("25.7.8"):
                _LOGGER.debug("Getting Unbound Regular Blocklists for OPNsense < 25.7.8")
                return {"legacy": await self.get_unbound_blocklist_legacy()}
        except (
            awesomeversion.exceptions.AwesomeVersionCompareException,
            TypeError,
            ValueError,
        ) as e:
            _LOGGER.error(
                "Error comparing firmware version %s when determining which Unbound Blocklist method to use. %s: %s",
                firmware,
                type(e).__name__,
                e,
            )
        dnsbl_raw = await self._safe_dict_get("/api/unbound/settings/search_dnsbl")
        if not isinstance(dnsbl_raw, MutableMapping):
            return {}
        dnsbl_rows = dnsbl_raw.get("rows", [])
        if not isinstance(dnsbl_rows, list) or not len(dnsbl_rows) > 0:
            return {}
        dnsbl_full: dict[str, Any] = {}
        for dnsbl in dnsbl_rows:
            if not isinstance(dnsbl, MutableMapping):
                continue
            _LOGGER.debug("[get_unbound_blocklist] dnsbl: %s", dnsbl)
            if dnsbl.get("uuid"):
                dnsbl_full.update({dnsbl["uuid"]: dnsbl})
        _LOGGER.debug("[get_unbound_blocklist] dnsbl_full: %s", dnsbl_full)
        return dnsbl_full

    async def _toggle_unbound_blocklist(self, set_state: bool, uuid: str | None) -> bool:
        """Enable or disable the unbound blocklist.

        Args:
            set_state: Desired enabled state to apply.
            uuid: Target object UUID returned by OPNsense.

        Returns:
            bool: ``True`` when the target blocklist toggles successfully and
            DNSBL reports OK.
        """
        if not uuid:
            _LOGGER.error("Blocklist uuid must be provided for Unbound Extended Blocklists")
            return False
        endpoint = f"/api/unbound/settings/toggle_dnsbl/{uuid}/{'1' if set_state else '0'}"
        response = await self._safe_dict_post(endpoint)
        result = response.get("result")
        if (set_state and result == "Enabled") or (not set_state and result == "Disabled"):
            try:
                dnsbl_resp = await self._get("/api/unbound/service/dnsbl")
                _LOGGER.debug(
                    "[_toggle_unbound_blocklist] uuid: %s, set_state: %s, response: %s, dnsbl_resp: %s",
                    uuid,
                    "On" if set_state else "Off",
                    response,
                    dnsbl_resp,
                )
                if isinstance(dnsbl_resp, MutableMapping) and dnsbl_resp.get(
                    "status", "failed"
                ).startswith("OK"):
                    return True
            except (TimeoutError, aiohttp.ClientError, ValueError, TypeError) as e:
                _LOGGER.error(
                    "Error applying unbound blocklist change for uuid %s. %s: %s",
                    uuid,
                    type(e).__name__,
                    e,
                )
        return False

    @_log_errors
    async def enable_unbound_blocklist(self, uuid: str | None = None) -> bool:
        """Enable the unbound blocklist.

        Args:
            uuid: Target object UUID returned by OPNsense. Defaults to None.

        Returns:
            bool: True when OPNsense reports the requested action succeeded;
            otherwise False.
        """
        firmware = await self.get_host_firmware_version()
        try:
            if awesomeversion.AwesomeVersion(firmware) < awesomeversion.AwesomeVersion("25.7.8"):
                _LOGGER.debug("Using Unbound Regular Blocklists for OPNsense < 25.7.8")
                return await self._set_unbound_blocklist_legacy(set_state=True)
            _LOGGER.debug("Using Unbound Extended Blocklists for OPNsense >= 25.7.8")
            return await self._toggle_unbound_blocklist(set_state=True, uuid=uuid)
        except (
            awesomeversion.exceptions.AwesomeVersionCompareException,
            TypeError,
            ValueError,
        ) as e:
            _LOGGER.error(
                "Error comparing firmware version %s when determining which Unbound Blocklist method to use. %s: %s",
                firmware,
                type(e).__name__,
                e,
            )
            if uuid:
                return await self._toggle_unbound_blocklist(set_state=True, uuid=uuid)
            return await self._set_unbound_blocklist_legacy(set_state=True)

    @_log_errors
    async def disable_unbound_blocklist(self, uuid: str | None = None) -> bool:
        """Disable the unbound blocklist.

        Args:
            uuid: Target object UUID returned by OPNsense. Defaults to None.

        Returns:
            bool: True when OPNsense reports the requested action succeeded;
            otherwise False.
        """
        firmware = await self.get_host_firmware_version()
        try:
            if awesomeversion.AwesomeVersion(firmware) < awesomeversion.AwesomeVersion("25.7.8"):
                _LOGGER.debug("Using Unbound Regular Blocklists for OPNsense < 25.7.8")
                return await self._set_unbound_blocklist_legacy(set_state=False)
            _LOGGER.debug("Using Unbound Extended Blocklists for OPNsense >= 25.7.8")
            return await self._toggle_unbound_blocklist(set_state=False, uuid=uuid)
        except (
            awesomeversion.exceptions.AwesomeVersionCompareException,
            TypeError,
            ValueError,
        ) as e:
            _LOGGER.error(
                "Error comparing firmware version %s when determining which Unbound Blocklist method to use. %s: %s",
                firmware,
                type(e).__name__,
                e,
            )
            if uuid:
                return await self._toggle_unbound_blocklist(set_state=False, uuid=uuid)
            return await self._set_unbound_blocklist_legacy(set_state=False)
