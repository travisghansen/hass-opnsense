"""Telemetry and interface statistics methods for OPNsenseClient."""

from collections.abc import MutableMapping
from datetime import datetime, timedelta
import re
from typing import Any

from dateutil.parser import ParserError, UnknownTimezoneWarning, parse

from ._typing import PyOPNsenseClientProtocol
from .const import AMBIGUOUS_TZINFOS
from .helpers import _LOGGER, _log_errors, try_to_float, try_to_int


class TelemetryMixin(PyOPNsenseClientProtocol):
    """Telemetry methods for OPNsenseClient."""

    @_log_errors
    async def get_telemetry(self) -> MutableMapping[str, Any]:
        """Get telemetry data from OPNsense.

        Returns
        -------
        MutableMapping[str, Any]
        Parsed telemetry payload returned by OPNsense APIs.


        """
        telemetry: dict[str, Any] = {}
        telemetry["mbuf"] = await self._get_telemetry_mbuf()
        telemetry["pfstate"] = await self._get_telemetry_pfstate()
        telemetry["memory"] = await self._get_telemetry_memory()
        telemetry["system"] = await self._get_telemetry_system()
        telemetry["cpu"] = await self._get_telemetry_cpu()
        telemetry["filesystems"] = await self._get_telemetry_filesystems()
        telemetry["temps"] = await self._get_telemetry_temps()
        # _LOGGER.debug(f"[get_telemetry] telemetry: {telemetry}")
        return telemetry

    @_log_errors
    async def get_interfaces(self) -> MutableMapping[str, Any]:
        """Return all OPNsense interfaces.

        Returns
        -------
        MutableMapping[str, Any]
        Parsed interfaces payload returned by OPNsense APIs.


        """
        interface_info = await self._safe_list_get("/api/interfaces/overview/export")
        # _LOGGER.debug(f"[get_interfaces] interface_info: {interface_info}")
        if not len(interface_info) > 0:
            return {}
        interfaces: dict[str, Any] = {}
        for ifinfo in interface_info:
            interface: dict[str, Any] = {}
            if not isinstance(ifinfo, MutableMapping) or ifinfo.get("identifier", "") == "":
                continue
            interface["inpkts"] = try_to_int(
                ifinfo.get("statistics", {}).get("packets received", None)
            )
            interface["outpkts"] = try_to_int(
                ifinfo.get("statistics", {}).get("packets transmitted", None)
            )
            interface["inbytes"] = try_to_int(
                ifinfo.get("statistics", {}).get("bytes received", None)
            )
            interface["outbytes"] = try_to_int(
                ifinfo.get("statistics", {}).get("bytes transmitted", None)
            )
            interface["inbytes_frmt"] = try_to_int(
                ifinfo.get("statistics", {}).get("bytes received", None)
            )
            interface["outbytes_frmt"] = try_to_int(
                ifinfo.get("statistics", {}).get("bytes transmitted", None)
            )
            interface["inerrs"] = try_to_int(ifinfo.get("statistics", {}).get("input errors", None))
            interface["outerrs"] = try_to_int(
                ifinfo.get("statistics", {}).get("output errors", None)
            )
            interface["collisions"] = try_to_int(
                ifinfo.get("statistics", {}).get("collisions", None)
            )
            interface["interface"] = ifinfo.get("identifier", "")
            interface["name"] = ifinfo.get("description", "")
            interface["status"] = ""
            if ifinfo.get("status", "") in {"down", "no carrier", "up"}:
                interface["status"] = ifinfo.get("status", "")
            elif ifinfo.get("status", "") == "associated":
                interface["status"] = "up"
            interface["ipv4"] = ifinfo.get("addr4", None)
            interface["ipv6"] = ifinfo.get("addr6", None)
            interface["media"] = ifinfo.get("media", None)
            interface["gateways"] = ifinfo.get("gateways", [])
            interface["routes"] = ifinfo.get("routes", [])
            interface["device"] = ifinfo.get("device", None)
            if ifinfo.get("macaddr", None) and ifinfo.get("macaddr", None) != "00:00:00:00:00:00":
                interface["mac"] = ifinfo.get("macaddr", None)
            interface["enabled"] = ifinfo.get("enabled", None)
            interface["vlan_tag"] = ifinfo.get("vlan_tag", None)
            interfaces[ifinfo.get("identifier", "")] = interface
        # _LOGGER.debug(f"[get_interfaces] interfaces: {interfaces}")
        return interfaces

    @_log_errors
    async def _get_telemetry_mbuf(self) -> MutableMapping[str, Any]:
        """Collect mbuf usage telemetry.

        Returns
        -------
        MutableMapping[str, Any]
        Parsed telemetry mbuf payload returned by OPNsense APIs.


        """
        mbuf_info = await self._safe_dict_post("/api/diagnostics/system/system_mbuf")
        # _LOGGER.debug(f"[get_telemetry_mbuf] mbuf_info: {mbuf_info}")
        mbuf: dict[str, Any] = {}
        mbuf["used"] = try_to_int(mbuf_info.get("mbuf-statistics", {}).get("mbuf-current", None))
        mbuf["total"] = try_to_int(mbuf_info.get("mbuf-statistics", {}).get("mbuf-total", None))
        mbuf["used_percent"] = (
            round(mbuf["used"] / mbuf["total"] * 100)
            if isinstance(mbuf["used"], int)
            and isinstance(mbuf["total"], int)
            and mbuf["total"] > 0
            else None
        )
        # _LOGGER.debug(f"[get_telemetry_mbuf] mbuf: {mbuf}")
        return mbuf

    @_log_errors
    async def _get_telemetry_pfstate(self) -> MutableMapping[str, Any]:
        """Collect PF state table telemetry.

        Returns
        -------
        MutableMapping[str, Any]
        Parsed telemetry pfstate payload returned by OPNsense APIs.


        """
        pfstate_info = await self._safe_dict_post("/api/diagnostics/firewall/pf_states")
        # _LOGGER.debug(f"[get_telemetry_pfstate] pfstate_info: {pfstate_info}")
        pfstate: dict[str, Any] = {}
        pfstate["used"] = try_to_int(pfstate_info.get("current", None))
        pfstate["total"] = try_to_int(pfstate_info.get("limit", None))
        pfstate["used_percent"] = (
            round(pfstate["used"] / pfstate["total"] * 100)
            if isinstance(pfstate["used"], int)
            and isinstance(pfstate["total"], int)
            and pfstate["total"] > 0
            else None
        )
        # _LOGGER.debug(f"[get_telemetry_pfstate] pfstate: {pfstate}")
        return pfstate

    @_log_errors
    async def _get_telemetry_memory(self) -> MutableMapping[str, Any]:
        """Collect memory and swap telemetry.

        Returns
        -------
        MutableMapping[str, Any]
        Parsed telemetry memory payload returned by OPNsense APIs.


        """
        if self._use_snake_case:
            memory_info = await self._safe_dict_post("/api/diagnostics/system/system_resources")
        else:
            memory_info = await self._safe_dict_post("/api/diagnostics/system/systemResources")
        # _LOGGER.debug(f"[get_telemetry_memory] memory_info: {memory_info}")
        memory: dict[str, Any] = {}
        memory["physmem"] = try_to_int(memory_info.get("memory", {}).get("total", None))
        memory["used"] = try_to_int(memory_info.get("memory", {}).get("used", None))
        memory["used_percent"] = (
            round(memory["used"] / memory["physmem"] * 100)
            if isinstance(memory["used"], int)
            and isinstance(memory["physmem"], int)
            and memory["physmem"] > 0
            else None
        )
        swap_info = await self._safe_dict_post("/api/diagnostics/system/system_swap")
        if (
            not isinstance(swap_info.get("swap", None), list)
            or not len(swap_info.get("swap", [])) > 0
            or not isinstance(swap_info.get("swap", [])[0], MutableMapping)
        ):
            return memory
        # _LOGGER.debug(f"[get_telemetry_memory] swap_info: {swap_info}")
        memory["swap_total"] = try_to_int(swap_info.get("swap", [])[0].get("total", None))
        memory["swap_reserved"] = try_to_int(swap_info["swap"][0].get("used", None))
        memory["swap_used_percent"] = (
            round(memory["swap_reserved"] / memory["swap_total"] * 100)
            if isinstance(memory["swap_reserved"], int)
            and isinstance(memory["swap_total"], int)
            and memory["swap_total"] > 0
            else 0
        )
        # _LOGGER.debug(f"[get_telemetry_memory] memory: {memory}")
        return memory

    @_log_errors
    async def _get_telemetry_system(self) -> MutableMapping[str, Any]:
        """Collect system time, uptime, boottime, and load telemetry.

        Returns
        -------
        MutableMapping[str, Any]
        Parsed telemetry system payload returned by OPNsense APIs.


        """
        if self._use_snake_case:
            time_info = await self._safe_dict_post("/api/diagnostics/system/system_time")
        else:
            time_info = await self._safe_dict_post("/api/diagnostics/system/systemTime")
        # _LOGGER.debug("[get_telemetry_system] time_info: %s", time_info)
        system: dict[str, Any] = {}
        opnsense_tz = await self._get_opnsense_timezone(time_info.get("datetime"))

        try:
            systemtime: datetime = parse(time_info["datetime"], tzinfos=AMBIGUOUS_TZINFOS)
            if systemtime.tzinfo is None:
                systemtime = systemtime.replace(tzinfo=opnsense_tz)
        except (KeyError, ValueError, TypeError, ParserError, UnknownTimezoneWarning) as e:
            _LOGGER.warning(
                "Failed to parse opnsense system time (aka. datetime), using HA system time instead: %s. %s: %s",
                time_info.get("datetime"),
                type(e).__name__,
                e,
            )
            systemtime = datetime.now().astimezone()

        pattern = re.compile(r"^(?:(\d+)\s+days?,\s+)?(\d{2}):(\d{2}):(\d{2})$")
        match = pattern.match(time_info.get("uptime", ""))
        if match:
            days_str, hours_str, minutes_str, seconds_str = match.groups()
            days = try_to_int(days_str, 0) or 0
            hours = try_to_int(hours_str, 0) or 0
            minutes = try_to_int(minutes_str, 0) or 0
            seconds = try_to_int(seconds_str, 0) or 0

            uptime = days * 86400 + hours * 3600 + minutes * 60 + seconds

        boottime: datetime | None = None
        if "boottime" in time_info:
            try:
                boottime = parse(time_info["boottime"], tzinfos=AMBIGUOUS_TZINFOS)
                if boottime and boottime.tzinfo is None:
                    boottime = boottime.replace(tzinfo=opnsense_tz)
            except (ValueError, TypeError, ParserError, UnknownTimezoneWarning) as e:
                _LOGGER.info(
                    "Failed to parse opnsense boottime: %s. %s: %s",
                    time_info["boottime"],
                    type(e).__name__,
                    e,
                )

        if boottime:
            system["boottime"] = boottime.timestamp()
            if match:
                system["uptime"] = uptime
            else:
                system["uptime"] = int((systemtime - boottime).total_seconds())
        elif match:
            system["uptime"] = uptime
            boottime = systemtime - timedelta(seconds=system["uptime"])
            system["boottime"] = boottime.timestamp()
        else:
            _LOGGER.warning("Invalid uptime format")

        load_str: str = time_info.get("loadavg", "")
        load_list: list[str] = load_str.split(", ")
        if len(load_list) == 3:
            system["load_average"] = {
                "one_minute": try_to_float(load_list[0]),
                "five_minute": try_to_float(load_list[1]),
                "fifteen_minute": try_to_float(load_list[2]),
            }
        else:
            system["load_average"] = {
                "one_minute": None,
                "five_minute": None,
                "fifteen_minute": None,
            }
        # _LOGGER.debug(f"[get_telemetry_system] system: {system}")
        return system

    @_log_errors
    async def _get_telemetry_cpu(self) -> MutableMapping[str, Any]:
        """Collect CPU core count and usage telemetry.

        Returns
        -------
        MutableMapping[str, Any]
        Parsed telemetry cpu payload returned by OPNsense APIs.


        """
        if self._use_snake_case:
            cputype_info = await self._safe_list_post("/api/diagnostics/cpu_usage/get_c_p_u_type")
        else:
            cputype_info = await self._safe_list_post("/api/diagnostics/cpu_usage/getCPUType")
        # _LOGGER.debug(f"[get_telemetry_cpu] cputype_info: {cputype_info}")
        if not len(cputype_info) > 0:
            return {}
        cpu: dict[str, Any] = {}
        cores_match = re.search(r"\((\d+) cores", cputype_info[0])
        cpu["count"] = try_to_int(cores_match.group(1)) if cores_match else 0

        cpustream_info = await self._get_from_stream("/api/diagnostics/cpu_usage/stream")
        # {"total":29,"user":2,"nice":0,"sys":27,"intr":0,"idle":70}
        # _LOGGER.debug(f"[get_telemetry_cpu] cpustream_info: {cpustream_info}")
        cpu["usage_total"] = try_to_int(cpustream_info.get("total", None))
        cpu["usage_user"] = try_to_int(cpustream_info.get("user", None))
        cpu["usage_nice"] = try_to_int(cpustream_info.get("nice", None))
        cpu["usage_system"] = try_to_int(cpustream_info.get("sys", None))
        cpu["usage_interrupt"] = try_to_int(cpustream_info.get("intr", None))
        cpu["usage_idle"] = try_to_int(cpustream_info.get("idle", None))
        # _LOGGER.debug(f"[get_telemetry_cpu] cpu: {cpu}")
        return cpu

    @_log_errors
    async def _get_telemetry_filesystems(self) -> list:
        """Collect filesystem telemetry entries from diagnostics.

        Returns
        -------
        list
        Parsed telemetry filesystems payload returned by OPNsense APIs.


        """
        if self._use_snake_case:
            filesystems_info = await self._safe_dict_post("/api/diagnostics/system/system_disk")
        else:
            filesystems_info = await self._safe_dict_post("/api/diagnostics/system/systemDisk")
        # _LOGGER.debug(f"[get_telemetry_filesystems] filesystems_info: {filesystems_info}")
        filesystems: list = filesystems_info.get("devices", [])
        # _LOGGER.debug(f"[get_telemetry_filesystems] filesystems: {filesystems}")
        return filesystems

    @_log_errors
    async def get_gateways(self) -> MutableMapping[str, Any]:
        """Return OPNsense Gateway details.

        Returns
        -------
        MutableMapping[str, Any]
        Parsed gateways payload returned by OPNsense APIs.


        """
        gateways_info = await self._safe_dict_get("/api/routes/gateway/status")
        # _LOGGER.debug(f"[get_gateways] gateways_info: {gateways_info}")
        gateways: dict[str, Any] = {}
        for gw_info in gateways_info.get("items", []):
            if isinstance(gw_info, MutableMapping) and "name" in gw_info:
                gateways[gw_info["name"]] = gw_info
        for gateway in gateways.values():
            gateway["status"] = gateway.pop("status_translated", gateway.get("status", "")).lower()
        # _LOGGER.debug(f"[get_gateways] gateways: {gateways}")
        return gateways

    @_log_errors
    async def _get_telemetry_temps(self) -> MutableMapping[str, Any]:
        """Collect temperature sensor telemetry.

        Returns
        -------
        MutableMapping[str, Any]
        Parsed telemetry temps payload returned by OPNsense APIs.


        """
        if self._use_snake_case:
            temps_info = await self._safe_list_get("/api/diagnostics/system/system_temperature")
        else:
            temps_info = await self._safe_list_get("/api/diagnostics/system/systemTemperature")
        # _LOGGER.debug(f"[get_telemetry_temps] temps_info: {temps_info}")
        if not len(temps_info) > 0:
            return {}
        temps: dict[str, Any] = {}
        for i, temp_info in enumerate(temps_info):
            temp: dict[str, Any] = {}
            temp["temperature"] = try_to_float(temp_info.get("temperature", 0), 0)
            temp["name"] = (
                f"{temp_info.get('type_translated', 'Num')} {temp_info.get('device_seq', i)}"
            )
            temp["device_id"] = temp_info.get("device", str(i))
            temps[temp_info.get("device", str(i)).replace(".", "_")] = temp
        # _LOGGER.debug(f"[get_telemetry_temps] temps: {temps}")
        return temps
