"""Firmware and plugin-related methods for OPNsenseClient."""

from collections.abc import MutableMapping
from datetime import datetime, timedelta, timezone
from typing import Any

import awesomeversion
from dateutil.parser import ParserError, UnknownTimezoneWarning, parse

from ._typing import PyOPNsenseClientProtocol
from .const import AMBIGUOUS_TZINFOS
from .helpers import _LOGGER, _log_errors, dict_get


class FirmwareMixin(PyOPNsenseClientProtocol):
    """Firmware methods for OPNsenseClient."""

    _firmware_version: str | None
    _plugin_installed: bool | None
    _plugin_deprecated: bool | None

    async def _store_host_firmware_version(self) -> None:
        firmware_info = await self._safe_dict_get("/api/core/firmware/status")
        firmware: str | None = dict_get(firmware_info, "product.product_version")
        if not firmware or not awesomeversion.AwesomeVersion(firmware).valid:
            old = firmware
            firmware = dict_get(firmware_info, "product.product_series", old)
            if firmware != old:
                _LOGGER.debug(
                    "[get_host_firmware_version] firmware: %s not valid SemVer, using %s",
                    old,
                    firmware,
                )
        else:
            _LOGGER.debug("[get_host_firmware_version] firmware: %s", firmware)
        self._firmware_version = firmware

    @_log_errors
    async def get_host_firmware_version(self) -> None | str:
        """Return the OPNsense Firmware version.

        Returns
        -------
        None | str
        Parsed host firmware version payload returned by OPNsense APIs.


        """
        if self._firmware_version is None:
            await self._store_host_firmware_version()
        return self._firmware_version

    async def _check_if_plugin_installed(self) -> bool:
        """Check using OPNsense API if plugin is installed or not.

        Returns
        -------
        bool
        ``True`` when the Home Assistant plugin package is installed.

        """
        firmware_info = await self._safe_dict_get("/api/core/firmware/info")
        if not isinstance(firmware_info.get("package"), list):
            return False
        for pkg in firmware_info.get("package", []):
            if pkg.get("name") == "os-homeassistant-maxit" and pkg.get("installed") == "1":
                return True
        return False

    async def is_plugin_installed(self) -> bool:
        """Return whether the Home Assistant OPNsense plugin is installed.

        Returns
        -------
        bool
            ``True`` when plugin installation is detected, otherwise ``False``.

        """
        if self._plugin_installed is None:
            self._plugin_installed = await self._check_if_plugin_installed()
        return self._plugin_installed

    async def _check_if_plugin_deprecated(self) -> bool:
        try:
            if awesomeversion.AwesomeVersion(
                await self.get_host_firmware_version()
            ) > awesomeversion.AwesomeVersion("26.1.2"):
                return True
        except (
            awesomeversion.exceptions.AwesomeVersionCompareException,
            TypeError,
            ValueError,
        ) as e:
            _LOGGER.info(
                "Unable to compare firmware version when checking if plugin is deprecated. %s: %s",
                type(e).__name__,
                e,
            )
        return False

    async def is_plugin_deprecated(self) -> bool:
        """Return whether the installed plugin is considered deprecated.

        Returns
        -------
        bool
            ``True`` when the plugin is deprecated for the detected firmware.

        """
        if self._plugin_deprecated is None:
            self._plugin_deprecated = await self._check_if_plugin_deprecated()
        return self._plugin_deprecated

    @_log_errors
    async def get_firmware_update_info(self) -> MutableMapping[str, Any]:
        """Get the details of available firmware updates.

        Returns
        -------
        MutableMapping[str, Any]
        Parsed firmware update info payload returned by OPNsense APIs.


        """
        status = await self._safe_dict_get("/api/core/firmware/status")

        # if error or too old trigger check (only if check is not already in progress)
        # {'status_msg': 'Firmware status check was aborted internally. Please try again.', 'status': 'error'}
        # error could be because data has not been refreshed at all OR an upgrade is currently in progress
        # _LOGGER.debug("[get_firmware_update_info] status: %s", status)

        if error_status := bool(status.get("status") == "error"):
            _LOGGER.debug("Last firmware status check returned an error")

        product_version = dict_get(status, "product.product_version")
        product_latest = dict_get(status, "product.product_latest")
        missing_data = False
        if (
            not product_version
            or not product_latest
            or not isinstance(dict_get(status, "product.product_check"), MutableMapping)
            or not dict_get(status, "product.product_check")
        ):
            _LOGGER.debug("Missing data in firmware status")
            missing_data = True

        update_needs_info = False
        try:
            if (
                awesomeversion.AwesomeVersion(product_latest)
                > awesomeversion.AwesomeVersion(product_version)
                and status.get("status_msg", "").strip()
                == "There are no updates available on the selected mirror."
            ):
                _LOGGER.debug("Update available but missing details")
                update_needs_info = True
        except (
            awesomeversion.exceptions.AwesomeVersionCompareException,
            TypeError,
            ValueError,
        ) as e:
            _LOGGER.debug("Error checking firmware versions. %s: %s", type(e).__name__, e)
            update_needs_info = True

        last_check_str = status.get("last_check")
        last_check_expired = True
        if last_check_str:
            try:
                last_check_dt = parse(last_check_str, tzinfos=AMBIGUOUS_TZINFOS)
                if last_check_dt.tzinfo is None:
                    last_check_dt = last_check_dt.replace(
                        tzinfo=timezone(datetime.now().astimezone().utcoffset() or timedelta())
                    )
                last_check_expired = (datetime.now().astimezone() - last_check_dt) > timedelta(
                    days=1
                )
                if last_check_expired:
                    _LOGGER.debug("Firmware status last check > 1 day ago")
            except (ValueError, TypeError, ParserError, UnknownTimezoneWarning) as e:
                _LOGGER.debug(
                    "Error getting firmware status last check. %s: %s", type(e).__name__, e
                )
        else:
            _LOGGER.debug("Firmware status last check is missing")

        if error_status or last_check_expired or missing_data or update_needs_info:
            _LOGGER.info("Triggering firmware check")
            self._plugin_installed = None
            self._plugin_deprecated = None
            self._firmware_version = None
            await self._post("/api/core/firmware/check")

        return status

    @_log_errors
    async def upgrade_firmware(self, type: str = "update") -> MutableMapping[str, Any] | None:
        """Trigger a firmware upgrade.

        Parameters
        ----------
        type : str
            Firmware upgrade type (for example update or upgrade). Defaults to 'update'.

        Returns
        -------
        MutableMapping[str, Any] | None
        True when OPNsense reports the requested action succeeded; otherwise False.


        """
        # update = minor updates of the same opnsense version
        # upgrade = major updates to a new opnsense version
        if type in ("update", "upgrade"):
            self._plugin_installed = None
            self._plugin_deprecated = None
            self._firmware_version = None
            return await self._safe_dict_post(f"/api/core/firmware/{type}")
        return None

    @_log_errors
    async def upgrade_status(self) -> MutableMapping[str, Any]:
        """Return the status of the firmware upgrade.

        Returns
        -------
        MutableMapping[str, Any]
        True when OPNsense reports the requested action succeeded; otherwise False.


        """
        return await self._safe_dict_post("/api/core/firmware/upgradestatus")

    @_log_errors
    async def firmware_changelog(self, version: str) -> MutableMapping[str, Any]:
        """Return the changelog for the firmware upgrade.

        Parameters
        ----------
        version : str
            Firmware version string to fetch a changelog for.

        Returns
        -------
        MutableMapping[str, Any]
        Firmware changelog payload returned by OPNsense.


        """
        return await self._safe_dict_post(f"/api/core/firmware/changelog/{version}")
