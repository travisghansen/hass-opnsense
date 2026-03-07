"""Method definitions for OPNsenseClient (part 3)."""

from .client_shared import *

@_log_errors
async def get_arp_table(self, resolve_hostnames: bool = False) -> list:
    """Return the active ARP table.

    Parameters
    ----------
    resolve_hostnames : bool
        Whether reverse-DNS names should be resolved for ARP entries. Defaults to False.

    Returns
    -------
    list
    Normalized get arp table data returned by OPNsense APIs.


    """
    # [{'hostname': '?', 'ip-address': '<ip>', 'mac-address': '<mac>', 'interface': 'em0', 'expires': 1199, 'type': 'ethernet'}, ...]
    request_body: MutableMapping[str, Any] = {"resolve": "yes"}
    arp_table_info = await self._safe_dict_post(
        "/api/diagnostics/interface/search_arp", payload=request_body
    )
    # _LOGGER.debug(f"[get_arp_table] arp_table_info: {arp_table_info}")
    arp_table: list = arp_table_info.get("rows", [])
    # _LOGGER.debug(f"[get_arp_table] arp_table: {arp_table}")
    return arp_table

@_log_errors
async def get_services(self) -> list:
    """Get the list of OPNsense services.

    Returns
    -------
    list
    Normalized get services data returned by OPNsense APIs.


    """
    response = await self._safe_dict_get("/api/core/service/search")
    # _LOGGER.debug(f"[get_services] response: {response}")
    services: list = response.get("rows", [])
    for service in services:
        service["status"] = service.get("running", 0) == 1
    # _LOGGER.debug(f"[get_services] services: {services}")
    return services

@_log_errors
async def get_service_is_running(self, service: str) -> bool:
    """Return if the OPNsense service is running.

    Parameters
    ----------
    service : str
        Service name or identifier recognized by OPNsense.

    Returns
    -------
    bool
    Normalized get service is running data returned by OPNsense APIs.


    """
    services: list = await self.get_services()
    if services is None or not isinstance(services, list):
        return False
    for svc in services:
        if (svc.get("name", None) == service or svc.get("id", None) == service) and svc.get(
            "status", False
        ):
            return True
    return False

async def _manage_service(self, action: str, service: str) -> bool:
    """Run a service control action for a named service.

    Parameters
    ----------
    action : str
        Service action to perform (start, stop, restart, etc.).
    service : str
        Service name or identifier recognized by OPNsense.

    Returns
    -------
    bool
    Result produced by this method.


    """
    if not service:
        return False
    api_addr: str = f"/api/core/service/{action}/{service}"
    response = await self._safe_dict_post(api_addr)
    _LOGGER.debug("[%s_service] service: %s, response: %s", action, service, response)
    return response.get("result", "failed") == "ok"

@_log_errors
async def start_service(self, service: str) -> bool:
    """Start OPNsense service.

    Parameters
    ----------
    service : str
        Service name or identifier recognized by OPNsense.

    Returns
    -------
    bool
    True when OPNsense reports the requested action succeeded; otherwise False.


    """
    return await self._manage_service("start", service)

@_log_errors
async def stop_service(self, service: str) -> bool:
    """Stop OPNsense service.

    Parameters
    ----------
    service : str
        Service name or identifier recognized by OPNsense.

    Returns
    -------
    bool
    True when OPNsense reports the requested action succeeded; otherwise False.


    """
    return await self._manage_service("stop", service)

@_log_errors
async def restart_service(self, service: str) -> bool:
    """Restart OPNsense service.

    Parameters
    ----------
    service : str
        Service name or identifier recognized by OPNsense.

    Returns
    -------
    bool
    True when OPNsense reports the requested action succeeded; otherwise False.


    """
    return await self._manage_service("restart", service)

@_log_errors
async def restart_service_if_running(self, service: str) -> bool:
    """Restart OPNsense service only if it is running.

    Parameters
    ----------
    service : str
        Service name or identifier recognized by OPNsense.

    Returns
    -------
    bool
    True when OPNsense reports the requested action succeeded; otherwise False.


    """
    if await self.get_service_is_running(service):
        return await self.restart_service(service)
    return True

@_log_errors
async def get_dhcp_leases(self) -> MutableMapping[str, Any]:
    """Return list of DHCP leases.

    Returns
    -------
    MutableMapping[str, Any]
    Normalized get dhcp leases data returned by OPNsense APIs.


    """
    leases_raw: list = (
        await self._get_kea_dhcpv4_leases()
        + await self._get_isc_dhcpv4_leases()
        + await self._get_isc_dhcpv6_leases()
        + await self._get_dnsmasq_leases()
    )
    # TODO: Add Kea dhcpv6 leases if API ever gets added

    # _LOGGER.debug(f"[get_dhcp_leases] leases_raw: {leases_raw}")
    leases: MutableMapping[str, Any] = {}
    lease_interfaces: MutableMapping[str, Any] = await self._get_kea_interfaces()
    for lease in leases_raw:
        if (
            not isinstance(lease, MutableMapping)
            or not isinstance(lease.get("if_name", None), str)
            or len(lease.get("if_name", "")) == 0
        ):
            continue
        if_name = lease.pop("if_name", None)
        if_descr = lease.pop("if_descr", None)
        if if_name not in leases:
            lease_interfaces[if_name] = if_descr
            leases[if_name] = []
        leases[if_name].append(lease)

    sorted_lease_interfaces: MutableMapping[str, Any] = {
        key: lease_interfaces[key] for key in sorted(lease_interfaces)
    }
    sorted_leases: MutableMapping[str, Any] = {key: leases[key] for key in sorted(leases)}
    for if_subnet in sorted_leases.values():
        sorted_if: list = sorted(if_subnet, key=get_ip_key)
        if_subnet = sorted_if

    dhcp_leases: MutableMapping[str, Any] = {
        "lease_interfaces": sorted_lease_interfaces,
        "leases": sorted_leases,
    }
    # _LOGGER.debug(f"[get_dhcp_leases] dhcp_leases: {dhcp_leases}")

    return dhcp_leases

async def _get_kea_interfaces(self) -> MutableMapping[str, Any]:
    """Return interfaces setup for Kea.

    Returns
    -------
    MutableMapping[str, Any]
    Normalized  get kea interfaces data returned by OPNsense APIs.


    """
    response = await self._safe_dict_get("/api/kea/dhcpv4/get")
    lease_interfaces: MutableMapping[str, Any] = {}
    general: MutableMapping[str, Any] = response.get("dhcpv4", {}).get("general", {})
    if general.get("enabled", "0") != "1":
        return {}
    for if_name, iface in general.get("interfaces", {}).items():
        if not isinstance(iface, MutableMapping):
            continue
        if iface.get("selected", 0) == 1 and iface.get("value", None):
            lease_interfaces[if_name] = iface.get("value")
    # _LOGGER.debug(f"[get_kea_interfaces] lease_interfaces: {lease_interfaces}")
    return lease_interfaces

async def _get_kea_dhcpv4_leases(self) -> list:
    """Return IPv4 DHCP Leases by Kea.

    Returns
    -------
    list
    Normalized  get kea dhcpv4 leases data returned by OPNsense APIs.


    """
    response = await self._safe_dict_get("/api/kea/leases4/search")
    if not isinstance(response.get("rows", None), list):
        return []
    if self._use_snake_case:
        res_resp = await self._safe_dict_get("/api/kea/dhcpv4/search_reservation")
    else:
        res_resp = await self._safe_dict_get("/api/kea/dhcpv4/searchReservation")
    if not isinstance(res_resp.get("rows", None), list):
        res_info = []
    else:
        res_info = res_resp.get("rows", [])
    reservations = {}
    for res in res_info:
        if res.get("hw_address", None):
            reservations.update({res.get("hw_address"): res.get("ip_address", "")})
    # _LOGGER.debug(f"[get_kea_dhcpv4_leases] reservations: {reservations}")
    leases_info: list = response.get("rows", [])
    # _LOGGER.debug(f"[get_kea_dhcpv4_leases] leases_info: {leases_info}")
    leases: list = []
    for lease_info in leases_info:
        if (
            lease_info is None
            or not isinstance(lease_info, MutableMapping)
            or lease_info.get("state", "0") != "0"
            or not lease_info.get("hwaddr", None)
        ):
            continue
        lease: MutableMapping[str, Any] = {}
        lease["address"] = lease_info.get("address", None)
        lease["hostname"] = (
            lease_info.get("hostname", None).strip(".")
            if isinstance(lease_info.get("hostname", None), str)
            and len(lease_info.get("hostname", "")) > 0
            else None
        )
        lease["if_descr"] = lease_info.get("if_descr", None)
        lease["if_name"] = lease_info.get("if_name", None)
        if (
            lease_info.get("hwaddr", None)
            and lease_info.get("hwaddr") in reservations
            and reservations[lease_info.get("hwaddr")] == lease_info.get("address", None)
        ):
            lease["type"] = "static"
        else:
            lease["type"] = "dynamic"
        lease["mac"] = lease_info.get("hwaddr", None)
        if OPNsenseClient._try_to_int(lease_info.get("expire", None)):
            lease["expires"] = timestamp_to_datetime(
                OPNsenseClient._try_to_int(lease_info.get("expire", None)) or 0
            )
            if lease["expires"] < datetime.now().astimezone():
                continue
        else:
            lease["expires"] = lease_info.get("expire", None)
        leases.append(lease)
    # _LOGGER.debug(f"[get_kea_dhcpv4_leases] leases: {leases}")
    return leases

def _keep_latest_leases(self, reservations: list[dict]) -> list[dict]:
    """Deduplicate leases and keep the entry with the latest expiration.

    Parameters
    ----------
    reservations : list[dict]
        Reservations used by `_keep_latest_leases`.

    Returns
    -------
    list[dict]
    Result produced by this method.


    """
    seen: dict[tuple, dict] = {}

    for entry in reservations:
        # Create a key from all fields except 'expire'
        key = tuple((k, v) for k, v in entry.items() if k != "expire")

        # Keep the entry with the latest expiration time
        if key not in seen or entry["expire"] > seen[key]["expire"]:
            seen[key] = entry

    return list(seen.values())

async def _get_dnsmasq_leases(self) -> list:
    """Return Dnsmasq IPv4 and IPv6 DHCP Leases.

    Returns
    -------
    list
    Normalized  get dnsmasq leases data returned by OPNsense APIs.


    """
    if self._firmware_version is None:
        await self.get_host_firmware_version()

    try:
        if awesomeversion.AwesomeVersion(
            self._firmware_version
        ) < awesomeversion.AwesomeVersion("25.1"):
            _LOGGER.debug("Skipping get_dnsmasq_leases for OPNsense < 25.1")
            return []
        if awesomeversion.AwesomeVersion(
            self._firmware_version
        ) < awesomeversion.AwesomeVersion("25.1.7"):
            _LOGGER.debug("Skipping get_dnsmasq_leases for OPNsense < 25.1.7")
            return []
    except (awesomeversion.exceptions.AwesomeVersionCompareException, TypeError, ValueError):
        pass

    response = await self._safe_dict_get("/api/dnsmasq/leases/search")
    leases_info: list = response.get("rows", [])
    if not isinstance(leases_info, list):
        return []
    # _LOGGER.debug("[get_dnsmasq_leases] leases_info: %s", leases_info)
    cleaned_leases = self._keep_latest_leases(leases_info)
    # _LOGGER.debug("[get_dnsmasq_leases] cleaned_leases: %s", cleaned_leases)

    leases: list = []
    for lease_info in cleaned_leases:
        # _LOGGER.debug("[get_dnsmasq_leases] lease_info: %s", lease_info)
        if not isinstance(lease_info, MutableMapping):
            continue
        lease: MutableMapping[str, Any] = {}
        lease["address"] = lease_info.get("address", None)
        lease["hostname"] = (
            lease_info.get("hostname", None)
            if isinstance(lease_info.get("hostname", None), str)
            and lease_info.get("hostname", None) != "*"
            and len(lease_info.get("hostname", "")) > 0
            else None
        )
        lease["if_descr"] = lease_info.get("if_descr", None)
        lease["if_name"] = lease_info.get("if", None)
        if lease_info.get("is_reserved", "0") == "1":
            lease["type"] = "static"
        else:
            lease["type"] = "dynamic"
        lease["mac"] = (
            lease_info.get("hwaddr", None)
            if isinstance(lease_info.get("hwaddr", None), str)
            and len(lease_info.get("hwaddr", "")) > 0
            else None
        )

        if OPNsenseClient._try_to_int(lease_info.get("expire", None)):
            lease["expires"] = timestamp_to_datetime(
                OPNsenseClient._try_to_int(lease_info.get("expire", None)) or 0
            )
            if lease["expires"] < datetime.now().astimezone():
                continue
        else:
            lease["expires"] = lease_info.get("expire", None)
        leases.append(lease)
    # _LOGGER.debug("[get_dnsmasq_leases] leases: %s", leases)
    return leases

async def _get_isc_dhcpv4_leases(self) -> list:
    """Return IPv4 DHCP Leases by ISC.

    Returns
    -------
    list
    Normalized  get isc dhcpv4 leases data returned by OPNsense APIs.


    """
    if not await self._get_check("/api/dhcpv4/service/status"):
        _LOGGER.debug("ISC DHCPv4 plugin/service not available, skipping lease retrieval")
        return []
    if self._use_snake_case:
        response = await self._safe_dict_get("/api/dhcpv4/leases/search_lease")
    else:
        response = await self._safe_dict_get("/api/dhcpv4/leases/searchLease")
    leases_info: list = response.get("rows", [])
    if not isinstance(leases_info, list):
        return []
    # _LOGGER.debug(f"[get_isc_dhcpv4_leases] leases_info: {leases_info}")
    leases: list = []
    for lease_info in leases_info:
        # _LOGGER.debug(f"[get_isc_dhcpv4_leases] lease_info: {lease_info}")
        if (
            not isinstance(lease_info, MutableMapping)
            or lease_info.get("state", "") != "active"
            or not lease_info.get("mac", None)
        ):
            continue
        lease: MutableMapping[str, Any] = {}
        lease["address"] = lease_info.get("address", None)
        lease["hostname"] = (
            lease_info.get("hostname", None)
            if isinstance(lease_info.get("hostname", None), str)
            and len(lease_info.get("hostname", "")) > 0
            else None
        )
        lease["if_descr"] = lease_info.get("if_descr", None)
        lease["if_name"] = lease_info.get("if", None)
        lease["type"] = lease_info.get("type", None)
        lease["mac"] = lease_info.get("mac", None)
        if lease_info.get("ends", None):
            dt: datetime = datetime.strptime(lease_info.get("ends", None), "%Y/%m/%d %H:%M:%S")
            lease["expires"] = dt.replace(
                tzinfo=timezone(datetime.now().astimezone().utcoffset() or timedelta())
            )
            if lease["expires"] < datetime.now().astimezone():
                continue
        else:
            lease["expires"] = lease_info.get("ends", None)
        leases.append(lease)
    # _LOGGER.debug(f"[get_isc_dhcpv4_leases] leases: {leases}")
    return leases

async def _get_isc_dhcpv6_leases(self) -> list:
    """Return IPv6 DHCP Leases by ISC.

    Returns
    -------
    list
    Normalized  get isc dhcpv6 leases data returned by OPNsense APIs.


    """
    if not await self._get_check("/api/dhcpv6/service/status"):
        _LOGGER.debug("ISC DHCPv6 plugin/service not available, skipping lease retrieval")
        return []
    if self._use_snake_case:
        response = await self._safe_dict_get("/api/dhcpv6/leases/search_lease")
    else:
        response = await self._safe_dict_get("/api/dhcpv6/leases/searchLease")
    leases_info: list = response.get("rows", [])
    if not isinstance(leases_info, list):
        return []
    # _LOGGER.debug(f"[get_isc_dhcpv6_leases] leases_info: {leases_info}")
    leases: list = []
    for lease_info in leases_info:
        # _LOGGER.debug(f"[get_isc_dhcpv6_leases] lease_info: {lease_info}")
        if (
            not isinstance(lease_info, MutableMapping)
            or lease_info.get("state", "") != "active"
            or not lease_info.get("mac", None)
        ):
            continue
        lease: MutableMapping[str, Any] = {}
        lease["address"] = lease_info.get("address", None)
        lease["hostname"] = (
            lease_info.get("hostname", None)
            if isinstance(lease_info.get("hostname", None), str)
            and len(lease_info.get("hostname", "")) > 0
            else None
        )
        lease["if_descr"] = lease_info.get("if_descr", None)
        lease["if_name"] = lease_info.get("if", None)
        lease["type"] = lease_info.get("type", None)
        lease["mac"] = lease_info.get("mac", None)
        if lease_info.get("ends", None):
            dt: datetime = datetime.strptime(lease_info.get("ends", None), "%Y/%m/%d %H:%M:%S")
            lease["expires"] = dt.replace(
                tzinfo=timezone(datetime.now().astimezone().utcoffset() or timedelta())
            )
            if lease["expires"] < datetime.now().astimezone():
                continue
        else:
            lease["expires"] = lease_info.get("ends", None)
        leases.append(lease)
    # _LOGGER.debug(f"[get_isc_dhcpv6_leases] leases: {leases}")
    return leases

@_log_errors
async def get_carp_status(self) -> bool:
    """Return the Carp status.

    Returns
    -------
    bool
    Normalized get carp status data returned by OPNsense APIs.


    """
    response = await self._safe_dict_get("/api/diagnostics/interface/get_vip_status")
    # _LOGGER.debug(f"[get_carp_status] response: {response}")
    return response.get("carp", {}).get("allow", "0") == "1"

@_log_errors
async def get_carp_interfaces(self) -> list:
    """Return the interfaces used by Carp.

    Returns
    -------
    list
    Normalized get carp interfaces data returned by OPNsense APIs.


    """
    vip_settings_raw = await self._safe_dict_get("/api/interfaces/vip_settings/get")
    if not isinstance(vip_settings_raw.get("rows", None), list):
        vip_settings: list = []
    else:
        vip_settings = vip_settings_raw.get("rows", [])
    # _LOGGER.debug(f"[get_carp_interfaces] vip_settings: {vip_settings}")

    vip_status_raw = await self._safe_dict_get("/api/diagnostics/interface/get_vip_status")
    if not isinstance(vip_status_raw.get("rows", None), list):
        vip_status: list = []
    else:
        vip_status = vip_status_raw.get("rows", [])
    # _LOGGER.debug(f"[get_carp_interfaces] vip_status: {vip_status}")
    carp = []
    for vip in vip_settings:
        if vip.get("mode", "").lower() != "carp":
            continue

        for status in vip_status:
            if vip.get("interface", "").lower() == status.get("interface", "_").lower():
                vip["status"] = status.get("status", None)
                break
        if "status" not in vip or not vip.get("status"):
            vip["status"] = "DISABLED"

        carp.append(vip)
    _LOGGER.debug("[get_carp_interfaces] carp: %s", carp)
    return carp

@_log_errors
async def system_reboot(self) -> bool:
    """Reboot OPNsense.

    Returns
    -------
    bool
    True when OPNsense reports the requested action succeeded; otherwise False.


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

    Parameters
    ----------
    interface : str
        Interface identifier used by the Wake-on-LAN endpoint.
    mac : str
        MAC address of the target device.

    Returns
    -------
    bool
    True when OPNsense reports the requested action succeeded; otherwise False.


    """
    payload: MutableMapping[str, Any] = {"wake": {"interface": interface, "mac": mac}}
    _LOGGER.debug("[send_wol] payload: %s", payload)
    response = await self._safe_dict_post("/api/wol/wol/set", payload)
    _LOGGER.debug("[send_wol] response: %s", response)
    if response.get("status", "") == "ok":
        return True
    return False

@staticmethod
def _try_to_int(input: Any | None, retval: int | None = None) -> int | None:
    """Return field to int."""
    return try_to_int(input, retval)

@staticmethod
def _try_to_float(input: Any | None, retval: float | None = None) -> float | None:
    """Return field to float."""
    return try_to_float(input, retval)

@_log_errors
async def get_telemetry(self) -> MutableMapping[str, Any]:
    """Get telemetry data from OPNsense.

    Returns
    -------
    MutableMapping[str, Any]
    Normalized get telemetry data returned by OPNsense APIs.


    """
    telemetry: MutableMapping[str, Any] = {}
    telemetry["mbuf"] = await self._get_telemetry_mbuf()
    telemetry["pfstate"] = await self._get_telemetry_pfstate()
    telemetry["memory"] = await self._get_telemetry_memory()
    telemetry["system"] = await self._get_telemetry_system()
    telemetry["cpu"] = await self._get_telemetry_cpu()
    telemetry["filesystems"] = await self._get_telemetry_filesystems()
    telemetry["temps"] = await self._get_telemetry_temps()
    # _LOGGER.debug(f"[get_telemetry] telemetry: {telemetry}")
    return telemetry

__all__ = [
    "get_arp_table",
    "get_services",
    "get_service_is_running",
    "_manage_service",
    "start_service",
    "stop_service",
    "restart_service",
    "restart_service_if_running",
    "get_dhcp_leases",
    "_get_kea_interfaces",
    "_get_kea_dhcpv4_leases",
    "_keep_latest_leases",
    "_get_dnsmasq_leases",
    "_get_isc_dhcpv4_leases",
    "_get_isc_dhcpv6_leases",
    "get_carp_status",
    "get_carp_interfaces",
    "system_reboot",
    "system_halt",
    "send_wol",
    "_try_to_int",
    "_try_to_float",
    "get_telemetry",
]
