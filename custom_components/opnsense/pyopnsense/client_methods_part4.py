"""Method definitions for OPNsenseClient (part 4)."""

from .client_shared import *

@_log_errors
async def get_interfaces(self) -> MutableMapping[str, Any]:
    """Return all OPNsense interfaces.

    Returns
    -------
    MutableMapping[str, Any]
    Normalized get interfaces data returned by OPNsense APIs.


    """
    interface_info = await self._safe_list_get("/api/interfaces/overview/export")
    # _LOGGER.debug(f"[get_interfaces] interface_info: {interface_info}")
    if not len(interface_info) > 0:
        return {}
    interfaces: MutableMapping[str, Any] = {}
    for ifinfo in interface_info:
        interface: MutableMapping[str, Any] = {}
        if not isinstance(ifinfo, MutableMapping) or ifinfo.get("identifier", "") == "":
            continue
        interface["inpkts"] = OPNsenseClient._try_to_int(
            ifinfo.get("statistics", {}).get("packets received", None)
        )
        interface["outpkts"] = OPNsenseClient._try_to_int(
            ifinfo.get("statistics", {}).get("packets transmitted", None)
        )
        interface["inbytes"] = OPNsenseClient._try_to_int(
            ifinfo.get("statistics", {}).get("bytes received", None)
        )
        interface["outbytes"] = OPNsenseClient._try_to_int(
            ifinfo.get("statistics", {}).get("bytes transmitted", None)
        )
        interface["inbytes_frmt"] = OPNsenseClient._try_to_int(
            ifinfo.get("statistics", {}).get("bytes received", None)
        )
        interface["outbytes_frmt"] = OPNsenseClient._try_to_int(
            ifinfo.get("statistics", {}).get("bytes transmitted", None)
        )
        interface["inerrs"] = OPNsenseClient._try_to_int(
            ifinfo.get("statistics", {}).get("input errors", None)
        )
        interface["outerrs"] = OPNsenseClient._try_to_int(
            ifinfo.get("statistics", {}).get("output errors", None)
        )
        interface["collisions"] = OPNsenseClient._try_to_int(
            ifinfo.get("statistics", {}).get("collisions", None)
        )
        interface["interface"] = ifinfo.get("identifier", "")
        interface["name"] = ifinfo.get("description", "")
        interface["status"] = ""
        if ifinfo.get("status", "") in {"down", "no carrier", "up"}:
            interface["status"] = ifinfo.get("status", "")
        elif ifinfo.get("status", "") in ("associated"):
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
    Normalized  get telemetry mbuf data returned by OPNsense APIs.


    """
    mbuf_info = await self._safe_dict_post("/api/diagnostics/system/system_mbuf")
    # _LOGGER.debug(f"[get_telemetry_mbuf] mbuf_info: {mbuf_info}")
    mbuf: MutableMapping[str, Any] = {}
    mbuf["used"] = OPNsenseClient._try_to_int(
        mbuf_info.get("mbuf-statistics", {}).get("mbuf-current", None)
    )
    mbuf["total"] = OPNsenseClient._try_to_int(
        mbuf_info.get("mbuf-statistics", {}).get("mbuf-total", None)
    )
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
    Normalized  get telemetry pfstate data returned by OPNsense APIs.


    """
    pfstate_info = await self._safe_dict_post("/api/diagnostics/firewall/pf_states")
    # _LOGGER.debug(f"[get_telemetry_pfstate] pfstate_info: {pfstate_info}")
    pfstate: MutableMapping[str, Any] = {}
    pfstate["used"] = OPNsenseClient._try_to_int(pfstate_info.get("current", None))
    pfstate["total"] = OPNsenseClient._try_to_int(pfstate_info.get("limit", None))
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
    Normalized  get telemetry memory data returned by OPNsense APIs.


    """
    if self._use_snake_case:
        memory_info = await self._safe_dict_post("/api/diagnostics/system/system_resources")
    else:
        memory_info = await self._safe_dict_post("/api/diagnostics/system/systemResources")
    # _LOGGER.debug(f"[get_telemetry_memory] memory_info: {memory_info}")
    memory: MutableMapping[str, Any] = {}
    memory["physmem"] = OPNsenseClient._try_to_int(
        memory_info.get("memory", {}).get("total", None)
    )
    memory["used"] = OPNsenseClient._try_to_int(memory_info.get("memory", {}).get("used", None))
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
    memory["swap_total"] = OPNsenseClient._try_to_int(
        swap_info.get("swap", [])[0].get("total", None)
    )
    memory["swap_reserved"] = OPNsenseClient._try_to_int(swap_info["swap"][0].get("used", None))
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
    Normalized  get telemetry system data returned by OPNsense APIs.


    """
    if self._use_snake_case:
        time_info = await self._safe_dict_post("/api/diagnostics/system/system_time")
    else:
        time_info = await self._safe_dict_post("/api/diagnostics/system/systemTime")
    # _LOGGER.debug("[get_telemetry_system] time_info: %s", time_info)
    system: MutableMapping[str, Any] = {}

    try:
        systemtime: datetime = parse(time_info["datetime"], tzinfos=AMBIGUOUS_TZINFOS)
        if systemtime.tzinfo is None:
            systemtime = systemtime.replace(
                tzinfo=timezone(datetime.now().astimezone().utcoffset() or timedelta())
            )
    except (ValueError, TypeError, ParserError, UnknownTimezoneWarning) as e:
        _LOGGER.warning(
            "Failed to parse opnsense system time (aka. datetime), using HA system time instead: %s. %s: %s",
            time_info["datetime"],
            type(e).__name__,
            e,
        )
        systemtime = datetime.now().astimezone()

    pattern = re.compile(r"^(?:(\d+)\s+days?,\s+)?(\d{2}):(\d{2}):(\d{2})$")
    match = pattern.match(time_info.get("uptime", ""))
    if match:
        days_str, hours_str, minutes_str, seconds_str = match.groups()
        days = OPNsenseClient._try_to_int(days_str, 0) or 0
        hours = OPNsenseClient._try_to_int(hours_str, 0) or 0
        minutes = OPNsenseClient._try_to_int(minutes_str, 0) or 0
        seconds = OPNsenseClient._try_to_int(seconds_str, 0) or 0

        uptime = days * 86400 + hours * 3600 + minutes * 60 + seconds

    boottime: datetime | None = None
    if "boottime" in time_info:
        try:
            boottime = parse(time_info["boottime"], tzinfos=AMBIGUOUS_TZINFOS)
            if boottime and boottime.tzinfo is None:
                boottime = boottime.replace(
                    tzinfo=timezone(datetime.now().astimezone().utcoffset() or timedelta())
                )
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
            "one_minute": float(load_list[0]),
            "five_minute": float(load_list[1]),
            "fifteen_minute": float(load_list[2]),
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
    Normalized  get telemetry cpu data returned by OPNsense APIs.


    """
    if self._use_snake_case:
        cputype_info = await self._safe_list_post("/api/diagnostics/cpu_usage/get_c_p_u_type")
    else:
        cputype_info = await self._safe_list_post("/api/diagnostics/cpu_usage/getCPUType")
    # _LOGGER.debug(f"[get_telemetry_cpu] cputype_info: {cputype_info}")
    if not len(cputype_info) > 0:
        return {}
    cpu: MutableMapping[str, Any] = {}
    cores_match = re.search(r"\((\d+) cores", cputype_info[0])
    cpu["count"] = OPNsenseClient._try_to_int(cores_match.group(1)) if cores_match else 0

    cpustream_info = await self._get_from_stream("/api/diagnostics/cpu_usage/stream")
    # {"total":29,"user":2,"nice":0,"sys":27,"intr":0,"idle":70}
    # _LOGGER.debug(f"[get_telemetry_cpu] cpustream_info: {cpustream_info}")
    cpu["usage_total"] = OPNsenseClient._try_to_int(cpustream_info.get("total", None))
    cpu["usage_user"] = OPNsenseClient._try_to_int(cpustream_info.get("user", None))
    cpu["usage_nice"] = OPNsenseClient._try_to_int(cpustream_info.get("nice", None))
    cpu["usage_system"] = OPNsenseClient._try_to_int(cpustream_info.get("sys", None))
    cpu["usage_interrupt"] = OPNsenseClient._try_to_int(cpustream_info.get("intr", None))
    cpu["usage_idle"] = OPNsenseClient._try_to_int(cpustream_info.get("idle", None))
    # _LOGGER.debug(f"[get_telemetry_cpu] cpu: {cpu}")
    return cpu

@_log_errors
async def _get_telemetry_filesystems(self) -> list:
    """Collect filesystem telemetry entries from diagnostics.

    Returns
    -------
    list
    Normalized  get telemetry filesystems data returned by OPNsense APIs.


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
async def get_openvpn(self) -> MutableMapping[str, Any]:
    """Return OpenVPN information.

    Returns
    -------
    MutableMapping[str, Any]
    Normalized get openvpn data returned by OPNsense APIs.


    """
    # https://docs.opnsense.org/development/api/core/openvpn.html
    # https://github.com/opnsense/core/blob/master/src/opnsense/www/js/widgets/OpenVPNClients.js
    # https://github.com/opnsense/core/blob/master/src/opnsense/www/js/widgets/OpenVPNServers.js
    openvpn: MutableMapping[str, Any] = {"servers": {}, "clients": {}}

    # Fetch data
    if self._use_snake_case:
        sessions_info = await self._safe_dict_get("/api/openvpn/service/search_sessions")
        routes_info = await self._safe_dict_get("/api/openvpn/service/search_routes")
    else:
        sessions_info = await self._safe_dict_get("/api/openvpn/service/searchSessions")
        routes_info = await self._safe_dict_get("/api/openvpn/service/searchRoutes")
    providers_info = await self._safe_dict_get("/api/openvpn/export/providers")
    instances_info = await self._safe_dict_get("/api/openvpn/instances/search")

    await OPNsenseClient._process_openvpn_instances(instances_info, openvpn)
    await OPNsenseClient._process_openvpn_providers(providers_info, openvpn)
    await OPNsenseClient._process_openvpn_sessions(sessions_info, openvpn)
    await OPNsenseClient._process_openvpn_routes(routes_info, openvpn)
    # _LOGGER.debug(f"[get_openvpn] sessions_info: {sessions_info}")
    # _LOGGER.debug(f"[get_openvpn] routes_info: {routes_info}")
    # _LOGGER.debug(f"[get_openvpn] providers_info: {providers_info}")
    # _LOGGER.debug(f"[get_openvpn] instances_info: {instances_info}")

    await self._fetch_openvpn_server_details(openvpn)

    _LOGGER.debug("[get_openvpn] openvpn: %s", openvpn)
    return openvpn

@staticmethod
async def _process_openvpn_instances(
    instances_info: MutableMapping[str, Any], openvpn: MutableMapping[str, Any]
) -> None:
    """Process OpenVPN instances into servers and clients.

    Parameters
    ----------
    instances_info : MutableMapping[str, Any]
        Raw OpenVPN instance payload returned by the API.
    openvpn : MutableMapping[str, Any]
        Mutable OpenVPN result structure updated in place.

    """
    for instance in instances_info.get("rows", []):
        if not isinstance(instance, MutableMapping):
            continue
        role = instance.get("role", "").lower()
        uuid = instance.get("uuid")
        if role == "server":
            await OPNsenseClient._add_openvpn_server(instance, openvpn)
        elif role == "client" and uuid:
            openvpn["clients"][uuid] = {
                "name": instance.get("description"),
                "uuid": uuid,
                "enabled": instance.get("enabled") == "1",
            }

@staticmethod
async def _add_openvpn_server(
    instance: MutableMapping[str, Any], openvpn: MutableMapping[str, Any]
) -> None:
    """Add a server to the OpenVPN structure.

    Parameters
    ----------
    instance : MutableMapping[str, Any]
        Single OpenVPN instance record to transform.
    openvpn : MutableMapping[str, Any]
        Mutable OpenVPN result structure updated in place.

    """
    uuid = instance.get("uuid")
    if not uuid:
        return
    if uuid not in openvpn["servers"]:
        openvpn["servers"][uuid] = {
            "uuid": uuid,
            "name": instance.get("description"),
            "enabled": instance.get("enabled") == "1",
            "dev_type": instance.get("dev_type"),
            "clients": [],
        }

@staticmethod
async def _process_openvpn_providers(
    providers_info: MutableMapping[str, Any], openvpn: MutableMapping[str, Any]
) -> None:
    """Process OpenVPN providers.

    Parameters
    ----------
    providers_info : MutableMapping[str, Any]
        Raw OpenVPN provider payload returned by the API.
    openvpn : MutableMapping[str, Any]
        Mutable OpenVPN result structure updated in place.

    """
    for uuid, vpn_info in providers_info.items():
        if not uuid or not isinstance(vpn_info, MutableMapping):
            continue
        server = openvpn["servers"].setdefault(uuid, {"uuid": uuid, "clients": []})
        server.update({"name": vpn_info.get("name")})
        if vpn_info.get("hostname") and vpn_info.get("local_port"):
            server["endpoint"] = f"{vpn_info['hostname']}:{vpn_info['local_port']}"

@staticmethod
async def _process_openvpn_sessions(
    sessions_info: MutableMapping[str, Any], openvpn: MutableMapping[str, Any]
) -> None:
    """Process OpenVPN sessions.

    Parameters
    ----------
    sessions_info : MutableMapping[str, Any]
        Raw OpenVPN session payload returned by the API.
    openvpn : MutableMapping[str, Any]
        Mutable OpenVPN result structure updated in place.

    """
    for session in sessions_info.get("rows", []):
        if session.get("type") != "server":
            continue
        server_id = str(session["id"]).split("_", 1)[0]
        server = openvpn["servers"].setdefault(server_id, {"uuid": server_id, "clients": []})
        server["name"] = session.get("description", "")
        await OPNsenseClient._update_openvpn_server_status(server, session)

@staticmethod
async def _update_openvpn_server_status(
    server: MutableMapping[str, Any], session: MutableMapping[str, Any]
) -> None:
    """Update server status based on session data.

    Parameters
    ----------
    server : MutableMapping[str, Any]
        OpenVPN server record to update.
    session : MutableMapping[str, Any]
        Shared aiohttp client session used for HTTP requests.

    """
    status = session.get("status")
    if not session.get("is_client", False):
        server["status"] = (
            "disabled"
            if not server.get("enabled", True)
            else "up"
            if status in {"connected", "ok"}
            else "failed"
            if status == "failed"
            else status or "down"
        )
    else:
        server.update(
            {
                "status": "up",
                "latest_handshake": timestamp_to_datetime(
                    session.get("connected_since__time_t_")
                ),
                "total_bytes_recv": OPNsenseClient._try_to_int(
                    session.get("bytes_received", 0), 0
                ),
                "total_bytes_sent": OPNsenseClient._try_to_int(session.get("bytes_sent", 0), 0),
            }
        )

@staticmethod
async def _process_openvpn_routes(
    routes_info: MutableMapping[str, Any], openvpn: MutableMapping[str, Any]
) -> None:
    """Process OpenVPN routes.

    Parameters
    ----------
    routes_info : MutableMapping[str, Any]
        Raw OpenVPN route payload returned by the API.
    openvpn : MutableMapping[str, Any]
        Mutable OpenVPN result structure updated in place.

    """
    for route in routes_info.get("rows", []):
        server_id = route.get("id")
        if not isinstance(route, MutableMapping) or server_id not in openvpn["servers"]:
            continue
        openvpn["servers"][server_id]["clients"].append(
            {
                "name": route.get("common_name"),
                "endpoint": route.get("real_address"),
                "tunnel_addresses": [route.get("virtual_address")],
                "latest_handshake": timestamp_to_datetime(route.get("last_ref__time_t_", 0)),
            }
        )

async def _fetch_openvpn_server_details(self, openvpn: MutableMapping[str, Any]) -> None:
    """Fetch detailed server information.

    Parameters
    ----------
    openvpn : MutableMapping[str, Any]
        Mutable OpenVPN result structure updated in place.

    """
    for uuid, server in openvpn["servers"].items():
        server.setdefault("total_bytes_sent", 0)
        server.setdefault("total_bytes_recv", 0)
        server["connected_clients"] = len(server.get("clients", []))
        details_info = await self._safe_dict_get(f"/api/openvpn/instances/get/{uuid}")
        details = (
            details_info.get("instance", {}) if isinstance(details_info, MutableMapping) else {}
        )
        if details.get("server"):
            server["tunnel_addresses"] = [details["server"]]
        server["dns_servers"] = [
            dns["value"]
            for dns in details.get("dns_servers", {}).values()
            if dns.get("selected") == 1 and dns.get("value")
        ]

@_log_errors
async def get_gateways(self) -> MutableMapping[str, Any]:
    """Return OPNsense Gateway details.

    Returns
    -------
    MutableMapping[str, Any]
    Normalized get gateways data returned by OPNsense APIs.


    """
    gateways_info = await self._safe_dict_get("/api/routes/gateway/status")
    # _LOGGER.debug(f"[get_gateways] gateways_info: {gateways_info}")
    gateways: MutableMapping[str, Any] = {}
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
    Normalized  get telemetry temps data returned by OPNsense APIs.


    """
    if self._use_snake_case:
        temps_info = await self._safe_list_get("/api/diagnostics/system/system_temperature")
    else:
        temps_info = await self._safe_list_get("/api/diagnostics/system/systemTemperature")
    # _LOGGER.debug(f"[get_telemetry_temps] temps_info: {temps_info}")
    if not len(temps_info) > 0:
        return {}
    temps: MutableMapping[str, Any] = {}
    for i, temp_info in enumerate(temps_info):
        temp: MutableMapping[str, Any] = {}
        temp["temperature"] = OPNsenseClient._try_to_float(temp_info.get("temperature", 0), 0)
        temp["name"] = (
            f"{temp_info.get('type_translated', 'Num')} {temp_info.get('device_seq', i)}"
        )
        temp["device_id"] = temp_info.get("device", str(i))
        temps[temp_info.get("device", str(i)).replace(".", "_")] = temp
    # _LOGGER.debug(f"[get_telemetry_temps] temps: {temps}")
    return temps

@_log_errors
async def get_notices(self) -> MutableMapping[str, Any]:
    """Get active OPNsense notices.

    Returns
    -------
    MutableMapping[str, Any]
    Normalized get notices data returned by OPNsense APIs.


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
                    "created_at": (
                        timestamp_to_datetime(int(notice.get("timestamp", 0)))
                        if notice.get("timestamp", None)
                        else None
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

    Parameters
    ----------
    id : str
        Id used by `close_notice`.

    Returns
    -------
    bool
    True when OPNsense reports the requested action succeeded; otherwise False.


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
            if "statusCode" in notice:
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
async def get_unbound_blocklist_legacy(self) -> MutableMapping[str, Any]:
    """Return the Unbound Blocklist details.

    Returns
    -------
    MutableMapping[str, Any]
    Normalized get unbound blocklist legacy data returned by OPNsense APIs.


    """
    response = await self._safe_dict_get("/api/unbound/settings/get")
    # _LOGGER.debug(f"[get_unbound_blocklist_legacy] response: {response}")
    dnsbl_settings = response.get("unbound", {}).get("dnsbl", {})
    # _LOGGER.debug(f"[get_unbound_blocklist_legacy] dnsbl_settings: {dnsbl_settings}")
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
    # _LOGGER.debug(f"[get_unbound_blocklist_legacy] dnsbl: {dnsbl}")
    return dnsbl

__all__ = [
    "get_interfaces",
    "_get_telemetry_mbuf",
    "_get_telemetry_pfstate",
    "_get_telemetry_memory",
    "_get_telemetry_system",
    "_get_telemetry_cpu",
    "_get_telemetry_filesystems",
    "get_openvpn",
    "_process_openvpn_instances",
    "_add_openvpn_server",
    "_process_openvpn_providers",
    "_process_openvpn_sessions",
    "_update_openvpn_server_status",
    "_process_openvpn_routes",
    "_fetch_openvpn_server_details",
    "get_gateways",
    "_get_telemetry_temps",
    "get_notices",
    "close_notice",
    "get_unbound_blocklist_legacy",
]
