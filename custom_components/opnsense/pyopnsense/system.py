"""System and configuration methods for OPNsenseClient."""

from collections.abc import Mapping, MutableMapping
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any
import warnings

import aiohttp
from dateutil.parser import ParserError, UnknownTimezoneWarning, parse

from ._typing import PyOPNsenseClientProtocol
from .const import AMBIGUOUS_TZINFOS
from .helpers import (
    _LOGGER,
    _log_errors,
    coerce_bool,
    normalize_lookup_token,
    timestamp_to_datetime,
    try_to_int,
)


class SystemMixin(PyOPNsenseClientProtocol):
    """System methods for OPNsenseClient."""

    def _parse_carp_vip_rows(self, rows: list[Any]) -> list[dict[str, Any]]:
        """Normalize CARP VIP rows from OPNsense responses.

        Args:
            rows: Raw VIP rows returned by OPNsense endpoints.

        Returns:
            list[dict[str, Any]]: Filtered CARP VIP rows with normalized status values.
        """
        parsed_rows: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, MutableMapping):
                continue
            mode = normalize_lookup_token(row.get("mode", ""))
            if mode and mode != "carp":
                continue
            row_copy = dict(row)
            raw_status = row_copy.get("status")
            status_str = str(raw_status).strip() if raw_status is not None else ""
            if not status_str:
                row_copy["status"] = "DISABLED"
            else:
                row_copy["status"] = status_str.upper()
            parsed_rows.append(row_copy)
        return parsed_rows

    @staticmethod
    def _classify_carp_state(
        has_carp_block: bool,
        has_rows: bool,
        enabled: bool,
        maintenance_mode: bool,
        vip_count: int,
        demotion: int,
        status_message: str,
        other_count: int,
    ) -> str:
        """Classify aggregate CARP state from normalized summary values.

        Args:
            has_carp_block: Whether the response contains a CARP metadata block.
            has_rows: Whether the response contains VIP rows.
            enabled: Whether CARP is enabled.
            maintenance_mode: Whether CARP maintenance mode is active.
            vip_count: Number of CARP VIP entries.
            demotion: Current CARP demotion counter.
            status_message: CARP status message from OPNsense.
            other_count: Count of VIPs in neither MASTER nor BACKUP state.

        Returns:
            str: Derived CARP state classification.
        """
        if not has_carp_block and not has_rows:
            return "unknown"
        if not enabled:
            return "disabled"
        if maintenance_mode:
            return "maintenance"
        if vip_count == 0:
            return "not_configured"
        if demotion != 0 or bool(status_message.strip()) or other_count > 0:
            return "degraded"
        return "healthy"

    @staticmethod
    def _select_carp_setting_candidate(
        candidates: list[dict[str, Any]],
        interface_key: str,
        vhid_key: str,
        subnet_key: str,
    ) -> dict[str, Any] | None:
        """Select the best fallback VIP setting candidate for a status row.

        Args:
            candidates: Candidate VIP settings with partial key collisions.
            interface_key: Normalized interface key from the status row.
            vhid_key: Normalized VHID key from the status row.
            subnet_key: Normalized subnet key from the status row.

        Returns:
            dict[str, Any] | None: Best-matching candidate, or None when unavailable.
        """
        best_candidate: dict[str, Any] | None = None
        best_score = -1
        has_ambiguous_tie = False
        for candidate in candidates:
            score = 0
            candidate_interface = normalize_lookup_token(candidate.get("interface", ""))
            candidate_vhid = normalize_lookup_token(candidate.get("vhid", ""))
            candidate_subnet = normalize_lookup_token(candidate.get("subnet", ""))
            if interface_key and candidate_interface == interface_key:
                score += 1
            if vhid_key and candidate_vhid == vhid_key:
                score += 1
            if subnet_key and candidate_subnet == subnet_key:
                score += 1
            if score > best_score:
                best_candidate = candidate
                best_score = score
                has_ambiguous_tie = False
            elif score == best_score:
                best_candidate = None
                has_ambiguous_tie = True
        if has_ambiguous_tie:
            return None
        return best_candidate

    def _merge_carp_vip_rows(
        self,
        vip_status_rows: list[Any],
        vip_settings_rows: list[Any],
    ) -> list[dict[str, Any]]:
        """Merge CARP VIP status rows with VIP settings rows.

        Args:
            vip_status_rows: Raw rows from the VIP status endpoint.
            vip_settings_rows: Raw rows from the VIP settings endpoint.

        Returns:
            list[dict[str, Any]]: Merged CARP VIP rows with normalized subnet values.
        """
        vip_status = self._parse_carp_vip_rows(vip_status_rows)

        vip_settings: list[dict[str, Any]] = []
        for row in vip_settings_rows:
            if not isinstance(row, MutableMapping):
                continue
            mode = normalize_lookup_token(row.get("mode", ""))
            if mode and mode != "carp":
                continue
            vip_settings.append(dict(row))

        settings_indexes = self._build_carp_settings_indexes(vip_settings)

        merged_vips: list[dict[str, Any]] = []
        for status_vip in vip_status:
            settings_match = self._find_carp_settings_match(status_vip, settings_indexes)

            if settings_match is None:
                merged_vip = dict(status_vip)
            else:
                merged_vip = dict(settings_match)
                merged_vip.update(status_vip)

            subnet_value = merged_vip.get("subnet")
            if isinstance(subnet_value, str):
                subnet_value = subnet_value.strip()
                if subnet_value:
                    merged_vip["subnet"] = subnet_value
            if not subnet_value:
                continue
            interface_value = merged_vip.get("interface")
            if isinstance(interface_value, str):
                interface_value = interface_value.strip()
                if interface_value:
                    merged_vip["interface"] = interface_value
            if not interface_value:
                continue
            merged_vips.append(merged_vip)

        return merged_vips

    def _build_carp_settings_indexes(
        self,
        vip_settings: list[dict[str, Any]],
    ) -> tuple[
        dict[tuple[str, str, str], dict[str, Any]],
        dict[tuple[str, str], list[dict[str, Any]]],
        dict[tuple[str, str], list[dict[str, Any]]],
        dict[str, list[dict[str, Any]]],
        dict[str, list[dict[str, Any]]],
    ]:
        """Build CARP setting indexes used by fallback matching.

        Args:
            vip_settings: Normalized CARP VIP settings rows.

        Returns:
            tuple: Lookup dictionaries keyed by full identity and partial keys.
        """
        settings_by_full: dict[tuple[str, str, str], dict[str, Any]] = {}
        settings_by_if_subnet: dict[tuple[str, str], list[dict[str, Any]]] = {}
        settings_by_if_vhid: dict[tuple[str, str], list[dict[str, Any]]] = {}
        settings_by_subnet: dict[str, list[dict[str, Any]]] = {}
        settings_by_vhid: dict[str, list[dict[str, Any]]] = {}
        for setting in vip_settings:
            interface_key = normalize_lookup_token(setting.get("interface"))
            vhid_key = normalize_lookup_token(setting.get("vhid"))
            subnet_key = normalize_lookup_token(setting.get("subnet"))
            settings_by_full[(interface_key, vhid_key, subnet_key)] = setting
            if interface_key and subnet_key:
                settings_by_if_subnet.setdefault((interface_key, subnet_key), []).append(setting)
            if interface_key and vhid_key:
                settings_by_if_vhid.setdefault((interface_key, vhid_key), []).append(setting)
            if subnet_key:
                settings_by_subnet.setdefault(subnet_key, []).append(setting)
            if vhid_key:
                settings_by_vhid.setdefault(vhid_key, []).append(setting)
        return (
            settings_by_full,
            settings_by_if_subnet,
            settings_by_if_vhid,
            settings_by_subnet,
            settings_by_vhid,
        )

    def _find_carp_settings_match(
        self,
        status_vip: dict[str, Any],
        settings_indexes: tuple[
            dict[tuple[str, str, str], dict[str, Any]],
            dict[tuple[str, str], list[dict[str, Any]]],
            dict[tuple[str, str], list[dict[str, Any]]],
            dict[str, list[dict[str, Any]]],
            dict[str, list[dict[str, Any]]],
        ],
    ) -> dict[str, Any] | None:
        """Find the best settings row for one CARP status row.

        Args:
            status_vip: Parsed CARP status row.
            settings_indexes: Lookup dictionaries generated from CARP settings rows.

        Returns:
            dict[str, Any] | None: Best matching settings row, or ``None`` when no unambiguous fallback exists.
        """
        (
            settings_by_full,
            settings_by_if_subnet,
            settings_by_if_vhid,
            settings_by_subnet,
            settings_by_vhid,
        ) = settings_indexes
        interface_key = normalize_lookup_token(status_vip.get("interface"))
        vhid_key = normalize_lookup_token(status_vip.get("vhid"))
        subnet_key = normalize_lookup_token(status_vip.get("subnet"))

        settings_match = settings_by_full.get((interface_key, vhid_key, subnet_key))
        if settings_match is None and interface_key and subnet_key:
            settings_match = self._select_carp_setting_candidate(
                settings_by_if_subnet.get((interface_key, subnet_key), []),
                interface_key,
                vhid_key,
                subnet_key,
            )
        if settings_match is None and interface_key and vhid_key:
            settings_match = self._select_carp_setting_candidate(
                settings_by_if_vhid.get((interface_key, vhid_key), []),
                interface_key,
                vhid_key,
                subnet_key,
            )
        if settings_match is None and subnet_key:
            settings_match = self._select_carp_setting_candidate(
                settings_by_subnet.get(subnet_key, []),
                interface_key,
                vhid_key,
                subnet_key,
            )
        if settings_match is None and vhid_key:
            settings_match = self._select_carp_setting_candidate(
                settings_by_vhid.get(vhid_key, []),
                interface_key,
                vhid_key,
                subnet_key,
            )
        return settings_match

    def _get_local_timezone(self) -> tzinfo:
        """Return a local timezone fallback with fixed UTC offset.

        Returns:
            tzinfo: Local timezone fallback using the host UTC offset.
        """
        return timezone(datetime.now().astimezone().utcoffset() or timedelta())

    async def _get_opnsense_timezone(self, datetime_str: str | None = None) -> tzinfo:
        """Resolve timezone information from OPNsense system time data.

        Args:
            datetime_str: Optional datetime string from the system-time endpoint. When omitted, the method queries OPNsense for current system-time data.

        Returns:
            tzinfo: Parsed timezone from OPNsense datetime output, or a local fixed-offset fallback when parsing fails.
        """
        if datetime_str is None:
            path = (
                "/api/diagnostics/system/system_time"
                if self._use_snake_case
                else "/api/diagnostics/system/systemTime"
            )
            try:
                datetime_raw = (await self._safe_dict_post(path)).get("datetime")
            except (aiohttp.ClientError, TimeoutError) as err:
                _LOGGER.debug(
                    "Failed to fetch OPNsense system time for timezone resolution: %s: %s",
                    type(err).__name__,
                    err,
                )
                return self._get_local_timezone()
            datetime_str = datetime_raw if isinstance(datetime_raw, str) else None

        if datetime_str:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("error", UnknownTimezoneWarning)
                    parsed_time = parse(datetime_str, tzinfos=AMBIGUOUS_TZINFOS)
                if parsed_time.tzinfo is not None:
                    return parsed_time.tzinfo
                _LOGGER.debug(
                    "No timezone data in OPNsense datetime '%s', using local fallback",
                    datetime_str,
                )
            except (ValueError, TypeError, ParserError, UnknownTimezoneWarning) as err:
                _LOGGER.debug(
                    "Failed to parse OPNsense timezone from datetime '%s': %s: %s",
                    datetime_str,
                    type(err).__name__,
                    err,
                )
        return self._get_local_timezone()

    @_log_errors
    async def _filter_configure(self) -> None:
        """Apply pending firewall/NAT filter configuration changes."""
        script: str = r"""
filter_configure();
clear_subsystem_dirty('natconf');
clear_subsystem_dirty('filter');
"""
        await self._exec_php(script)

    @_log_errors
    async def get_device_unique_id(self, expected_id: str | None = None) -> str | None:
        """Get the OPNsense Unique ID.

        Args:
            expected_id: Previously stored unique ID used to prefer a stable match. Defaults to None.

        Returns:
            str | None: Stable unique identifier derived from physical interface MAC addresses, or None when unavailable.
        """
        instances = await self._safe_list_get("/api/interfaces/overview/export")
        mac_addresses: set[str] = set()
        for item in instances:
            if not isinstance(item, MutableMapping):
                continue
            mac = item.get("macaddr_hw")
            if item.get("is_physical") and isinstance(mac, str) and mac:
                mac_addresses.add(mac.replace(":", "_").strip())

        if not mac_addresses:
            _LOGGER.debug("[get_device_unique_id] device_unique_id: None")
            return None

        if expected_id and expected_id in mac_addresses:
            _LOGGER.debug(
                "[get_device_unique_id] device_unique_id (matched expected): %s", expected_id
            )
            return expected_id

        device_unique_id = sorted(mac_addresses)[0]
        _LOGGER.debug("[get_device_unique_id] device_unique_id (first): %s", device_unique_id)
        return device_unique_id

    @_log_errors
    async def get_system_info(self) -> dict[str, Any]:
        """Return the system info from OPNsense.

        Returns:
            dict[str, Any]: Parsed system info payload returned by OPNsense APIs.
        """
        system_info: dict[str, Any] = {}
        if self._use_snake_case:
            response = await self._safe_dict_get("/api/diagnostics/system/system_information")
        else:
            response = await self._safe_dict_get("/api/diagnostics/system/systemInformation")
        system_info["name"] = response.get("name", None)
        return system_info

    @_log_errors
    async def get_config(self) -> dict[str, Any]:
        """XMLRPC call to return all the config settings.

        Returns:
            dict[str, Any]: Parsed config payload returned by OPNsense APIs.
        """
        script: str = r"""
global $config;

$toreturn = [
  "data" => $config,
];
"""
        response: dict[str, Any] = await self._exec_php(script)
        ret_data = response.get("data", {})
        if not isinstance(ret_data, MutableMapping):
            return {}
        return dict(ret_data)

    @_log_errors
    async def get_carp(self) -> dict[str, Any]:
        """Fetch one CARP snapshot and return both interfaces and aggregate summary.

        Returns:
            dict[str, Any]: Snapshot payload containing ``interfaces`` and
            ``status_summary`` derived from one backend fetch.
        """
        response, vips = await self._fetch_and_merge_carp_vips()
        return {
            "interfaces": vips,
            "status_summary": self._build_carp_status_summary(response=response, vips=vips),
        }

    async def _fetch_and_merge_carp_vips(self) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Fetch CARP status/settings and return merged normalized VIP rows.

        Returns:
            tuple[dict[str, Any], list[dict[str, Any]]]: The raw VIP status response and
            merged/normalized CARP VIP rows derived from status + settings endpoints.
        """
        vip_status_raw = await self._safe_dict_get("/api/diagnostics/interface/get_vip_status")
        vip_settings_raw = await self._safe_dict_get("/api/interfaces/vip_settings/get")

        vip_status = dict(vip_status_raw) if isinstance(vip_status_raw, MutableMapping) else {}
        vip_status_rows = vip_status.get("rows")
        vip_settings_rows = (
            vip_settings_raw.get("rows") if isinstance(vip_settings_raw, MutableMapping) else None
        )
        merged_vips = self._merge_carp_vip_rows(
            vip_status_rows if isinstance(vip_status_rows, list) else [],
            vip_settings_rows if isinstance(vip_settings_rows, list) else [],
        )
        return vip_status, merged_vips

    def _build_carp_status_summary(
        self,
        response: dict[str, Any],
        vips: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Build aggregate CARP status summary using one merged VIP snapshot.

        Args:
            response: Raw response from ``get_vip_status`` endpoint.
            vips: Merged/normalized CARP VIP rows from status + settings endpoints.

        Returns:
            dict[str, Any]: Aggregate CARP health/status payload for Home Assistant sensors.
        """
        summary: dict[str, Any] = {
            "state": "unknown",
            "enabled": False,
            "maintenance_mode": False,
            "demotion": 0,
            "status_message": "",
            "vip_count": 0,
            "master_count": 0,
            "backup_count": 0,
            "other_count": 0,
            "interfaces": [],
            "vips": [],
        }
        if not response:
            return summary

        carp_raw = response.get("carp")
        if isinstance(carp_raw, Mapping):
            has_carp_block = True
            carp_block: dict[str, Any] = dict(carp_raw)
        else:
            has_carp_block = False
            carp_block = {}
        has_rows = bool(vips)

        enabled = coerce_bool(carp_block.get("allow")) if has_carp_block else bool(vips)
        maintenance_mode = (
            coerce_bool(carp_block.get("maintenancemode")) if has_carp_block else False
        )
        demotion_raw = try_to_int(carp_block.get("demotion"), 0) if has_carp_block else 0
        demotion = demotion_raw if isinstance(demotion_raw, int) else 0
        status_message_raw = carp_block.get("status_msg", "") if has_carp_block else ""
        status_message = (
            status_message_raw.strip()
            if isinstance(status_message_raw, str) and status_message_raw.strip()
            else ""
        )
        master_count = 0
        backup_count = 0
        other_count = 0
        interfaces: set[str] = set()
        for vip in vips:
            status = str(vip.get("status", "")).strip().upper()
            if status == "MASTER":
                master_count += 1
            elif status == "BACKUP":
                backup_count += 1
            else:
                other_count += 1
            interface_name = vip.get("interface")
            if isinstance(interface_name, str) and interface_name.strip():
                interfaces.add(interface_name.strip())

        vip_count = len(vips)
        state = self._classify_carp_state(
            has_carp_block=has_carp_block,
            has_rows=has_rows,
            enabled=enabled,
            maintenance_mode=maintenance_mode,
            vip_count=vip_count,
            demotion=demotion,
            status_message=status_message,
            other_count=other_count,
        )

        summary.update(
            {
                "state": state,
                "enabled": enabled,
                "maintenance_mode": maintenance_mode,
                "demotion": demotion,
                "status_message": status_message,
                "vip_count": vip_count,
                "master_count": master_count,
                "backup_count": backup_count,
                "other_count": other_count,
                "interfaces": sorted(interfaces),
                "vips": vips,
            }
        )
        return summary

    @_log_errors
    async def system_reboot(self) -> bool:
        """Reboot OPNsense.

        Returns:
            bool: True when OPNsense reports the requested action succeeded; otherwise False.
        """
        response = await self._safe_dict_post("/api/core/system/reboot")
        _LOGGER.debug("[system_reboot] response: %s", response)
        if response.get("status", "") == "ok":
            return True
        return False

    @_log_errors
    async def system_halt(self) -> None:
        """Shutdown OPNsense."""
        response = await self._safe_dict_post("/api/core/system/halt")
        _LOGGER.debug("[system_halt] response: %s", response)
        if response.get("status", "") == "ok":
            return
        return

    @_log_errors
    async def send_wol(self, interface: str, mac: str) -> bool:
        """Send a wake on lan packet to the specified MAC address.

        Args:
            interface: Interface identifier used by the Wake-on-LAN endpoint.
            mac: MAC address of the target device.

        Returns:
            bool: True when OPNsense reports the requested action succeeded; otherwise False.
        """
        payload: dict[str, Any] = {"wake": {"interface": interface, "mac": mac}}
        _LOGGER.debug("[send_wol] payload: %s", payload)
        response = await self._safe_dict_post("/api/wol/wol/set", payload)
        _LOGGER.debug("[send_wol] response: %s", response)
        if response.get("status", "") == "ok":
            return True
        return False

    @_log_errors
    async def get_notices(self) -> dict[str, Any]:
        """Get active OPNsense notices.

        Returns:
            dict[str, Any]: Parsed notices payload returned by OPNsense APIs.
        """
        notices_info = await self._safe_dict_get("/api/core/system/status")
        # _LOGGER.debug(f"[get_notices] notices_info: {notices_info}")
        pending_notices_present = False
        pending_notices: list = []
        for key, notice in notices_info.items():
            if isinstance(notice, MutableMapping) and notice.get("statusCode", 2) != 2:
                pending_notices_present = True
                pending_notices.append(
                    {
                        "notice": notice.get("message", None),
                        "id": key,
                        "created_at": timestamp_to_datetime(
                            try_to_int(notice.get("timestamp", None))
                        ),
                    }
                )

        return {
            "pending_notices_present": pending_notices_present,
            "pending_notices": pending_notices,
        }

    @_log_errors
    async def close_notice(self, id: str) -> bool:
        """Close selected notices.

        Args:
            id: Notice identifier to dismiss, or ``"all"`` to dismiss all active notices.

        Returns:
            bool: True when OPNsense reports the requested action succeeded; otherwise False.
        """

        dismiss_endpoint = (
            "/api/core/system/dismiss_status"
            if self._use_snake_case
            else "/api/core/system/dismissStatus"
        )

        # id = "all" to close all notices
        success = True
        if id.lower() == "all":
            notices = await self._safe_dict_get("/api/core/system/status")
            # _LOGGER.debug(f"[close_notice] notices: {notices}")
            for key, notice in notices.items():
                if not isinstance(notice, MutableMapping):
                    continue
                if notice.get("statusCode", 2) != 2:
                    dismiss = await self._safe_dict_post(dismiss_endpoint, payload={"subject": key})
                    # _LOGGER.debug(f"[close_notice] id: {key}, dismiss: {dismiss}")
                    if dismiss.get("status", "failed") != "ok":
                        success = False
        else:
            dismiss = await self._safe_dict_post(dismiss_endpoint, payload={"subject": id})
            _LOGGER.debug("[close_notice] id: %s, dismiss: %s", id, dismiss)
            if dismiss.get("status", "failed") != "ok":
                success = False
        _LOGGER.debug("[close_notice] success: %s", success)
        return success

    @_log_errors
    async def reload_interface(self, if_name: str) -> bool:
        """Reload the specified interface.

        Args:
            if_name: Interface name to reload.

        Returns:
            bool: True when OPNsense reports the requested action succeeded; otherwise False.
        """
        if self._use_snake_case:
            reload = await self._safe_dict_post(
                f"/api/interfaces/overview/reload_interface/{if_name}"
            )
        else:
            reload = await self._safe_dict_post(
                f"/api/interfaces/overview/reloadInterface/{if_name}"
            )
        return reload.get("message", "").startswith("OK")

    @_log_errors
    async def get_certificates(self) -> dict[str, Any]:
        """Return the active encryption certificates.

        Returns:
            dict[str, Any]: Parsed certificates payload returned by OPNsense APIs.
        """
        certs_raw = await self._safe_dict_get("/api/trust/cert/search")
        cert_rows = certs_raw.get("rows")
        if not isinstance(cert_rows, list):
            return {}
        certs: dict[str, Any] = {}
        for cert in cert_rows:
            if cert.get("descr", None):
                certs[cert.get("descr")] = {
                    "uuid": cert.get("uuid", None),
                    "issuer": cert.get("caref", None),
                    "purpose": cert.get("rfc3280_purpose", None),
                    "in_use": bool(cert.get("in_use", "0") == "1"),
                    "valid_from": timestamp_to_datetime(try_to_int(cert.get("valid_from", None))),
                    "valid_to": timestamp_to_datetime(try_to_int(cert.get("valid_to", None))),
                }
        _LOGGER.debug("[get_certificates] certs: %s", certs)
        return certs
