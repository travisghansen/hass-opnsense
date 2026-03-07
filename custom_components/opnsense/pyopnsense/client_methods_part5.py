"""Method definitions for OPNsenseClient (part 5)."""

from .client_shared import *

async def _set_unbound_blocklist_legacy(self, set_state: bool) -> bool:
    """Enable or disable legacy Unbound DNS blocklist settings.

    Parameters
    ----------
    set_state : bool
        Desired enabled state to apply.

    Returns
    -------
    bool
    Result produced by this method.


    """
    payload: MutableMapping[str, Any] = {}
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

async def get_unbound_blocklist(self) -> dict[str, Any]:
    """Return the Unbound Blocklist details.

    Returns
    -------
    dict[str, Any]
    Normalized get unbound blocklist data returned by OPNsense APIs.


    """
    if self._firmware_version is None:
        await self.get_host_firmware_version()
    try:
        if awesomeversion.AwesomeVersion(
            self._firmware_version
        ) < awesomeversion.AwesomeVersion("25.7.8"):
            _LOGGER.debug("Getting Unbound Regular Blocklists for OPNsense < 25.7.8")
            return {"legacy": await self.get_unbound_blocklist_legacy()}
    except (
        awesomeversion.exceptions.AwesomeVersionCompareException,
        TypeError,
        ValueError,
    ) as e:
        _LOGGER.error(
            "Error comparing firmware version %s when determining which Unbound Blocklist method to use. %s: %s",
            self._firmware_version,
            type(e).__name__,
            e,
        )
    dnsbl_raw = await self._safe_dict_get("/api/unbound/settings/search_dnsbl")
    # _LOGGER.debug(f"[get_unbound_blocklist] dnsbl_raw: {dnsbl_raw}")
    if not isinstance(dnsbl_raw, dict):
        return {}
    dnsbl_rows = dnsbl_raw.get("rows", [])
    if not isinstance(dnsbl_rows, list) or not len(dnsbl_rows) > 0:
        return {}
    dnsbl_full: dict[str, Any] = {}
    for dnsbl in dnsbl_rows:
        if not isinstance(dnsbl, dict):
            continue
        _LOGGER.debug("[get_unbound_blocklist] dnsbl: %s", dnsbl)
        if dnsbl.get("uuid"):
            dnsbl_full.update({dnsbl["uuid"]: dnsbl})
    _LOGGER.debug("[get_unbound_blocklist] dnsbl_full: %s", dnsbl_full)
    return dnsbl_full

async def _toggle_unbound_blocklist(self, set_state: bool, uuid: str | None) -> bool:
    """Enable or disable the unbound blocklist.

    Parameters
    ----------
    set_state : bool
        Desired enabled state to apply.
    uuid : str | None
        Target object UUID returned by OPNsense.

    Returns
    -------
    bool
    Result produced by this method.


    """
    if not uuid:
        _LOGGER.error("Blocklist uuid must be provided for Unbound Extended Blocklists")
        return False
    endpoint = f"/api/unbound/settings/toggle_dnsbl/{uuid}/{'1' if set_state else '0'}"
    response = await self._safe_dict_post(endpoint)
    result = response.get("result")
    if set_state and result == "Enabled":
        return True
    if not set_state and result == "Disabled":
        return True
    return False

@_log_errors
async def enable_unbound_blocklist(self, uuid: str | None = None) -> bool:
    """Enable the unbound blocklist.

    Parameters
    ----------
    uuid : str | None
        Target object UUID returned by OPNsense. Defaults to None.

    Returns
    -------
    bool
    True when OPNsense reports the requested action succeeded; otherwise False.


    """
    if self._firmware_version is None:
        await self.get_host_firmware_version()
    try:
        if awesomeversion.AwesomeVersion(
            self._firmware_version
        ) < awesomeversion.AwesomeVersion("25.7.8"):
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
            self._firmware_version,
            type(e).__name__,
            e,
        )
        if uuid:
            return await self._toggle_unbound_blocklist(set_state=True, uuid=uuid)
        return await self._set_unbound_blocklist_legacy(set_state=True)

@_log_errors
async def disable_unbound_blocklist(self, uuid: str | None = None) -> bool:
    """Disable the unbound blocklist.

    Parameters
    ----------
    uuid : str | None
        Target object UUID returned by OPNsense. Defaults to None.

    Returns
    -------
    bool
    True when OPNsense reports the requested action succeeded; otherwise False.


    """
    if self._firmware_version is None:
        await self.get_host_firmware_version()
    try:
        if awesomeversion.AwesomeVersion(
            self._firmware_version
        ) < awesomeversion.AwesomeVersion("25.7.8"):
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
            self._firmware_version,
            type(e).__name__,
            e,
        )
        if uuid:
            return await self._toggle_unbound_blocklist(set_state=False, uuid=uuid)
        return await self._set_unbound_blocklist_legacy(set_state=False)

@_log_errors
async def get_wireguard(self) -> MutableMapping[str, Any]:
    """Get the details of the WireGuard services.

    Returns
    -------
    MutableMapping[str, Any]
    Normalized get wireguard data returned by OPNsense APIs.


    """
    data_sources = {
        "summary_raw": "/api/wireguard/service/show",
        "clients_raw": "/api/wireguard/client/get",
        "servers_raw": "/api/wireguard/server/get",
    }
    data = {key: await self._safe_dict_get(path) for key, path in data_sources.items()}

    summary = data["summary_raw"].get("rows", [])
    client_summ = data["clients_raw"].get("client", {}).get("clients", {}).get("client", {})
    server_summ = data["servers_raw"].get("server", {}).get("servers", {}).get("server", {})

    if (
        not isinstance(summary, list)
        or not isinstance(client_summ, MutableMapping)
        or not isinstance(server_summ, MutableMapping)
    ):
        return {}

    servers = {
        uid: await OPNsenseClient._process_wireguard_server(uid, srv, client_summ)
        for uid, srv in server_summ.items()
        if isinstance(srv, MutableMapping)
    }
    clients = {
        uid: await OPNsenseClient._process_wireguard_client(uid, clnt, servers)
        for uid, clnt in client_summ.items()
        if isinstance(clnt, MutableMapping)
    }

    await OPNsenseClient._update_wireguard_status(summary, servers, clients)

    wireguard = {"servers": servers, "clients": clients}
    _LOGGER.debug("[get_wireguard] wireguard: %s", wireguard)
    return wireguard

@staticmethod
async def _process_wireguard_server(
    uid: str, srv: MutableMapping[str, Any], client_summ: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Process a single WireGuard server entry.

    Parameters
    ----------
    uid : str
        UUID key for the current WireGuard/OpenVPN object.
    srv : MutableMapping[str, Any]
        WireGuard server record being processed.
    client_summ : MutableMapping[str, Any]
        WireGuard client summary mapping from API results.

    Returns
    -------
    MutableMapping[str, Any]
    None. Updates the supplied data structures in place.


    """
    return {
        "uuid": uid,
        "name": srv.get("name"),
        "pubkey": srv.get("pubkey"),
        "enabled": srv.get("enabled", "") == "1",
        "interface": f"wg{srv.get('instance', '')}",
        "dns_servers": [srv.get("peer_dns")] if srv.get("peer_dns") else [],
        "tunnel_addresses": [
            addr.get("value")
            for addr in srv.get("tunneladdress", {}).values()
            if addr.get("selected") == 1 and addr.get("value")
        ],
        "clients": [
            {
                "name": peer.get("value"),
                "uuid": peer_id,
                "pubkey": client_summ.get(peer_id, {}).get("pubkey"),
                "connected": False,
            }
            for peer_id, peer in srv.get("peers", {}).items()
            if peer.get("selected") == 1 and peer.get("value")
        ],
        "connected_clients": 0,
        "total_bytes_recv": 0,
        "total_bytes_sent": 0,
    }

@staticmethod
async def _process_wireguard_client(
    uid: str, clnt: MutableMapping[str, Any], servers: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Process a single WireGuard client entry.

    Parameters
    ----------
    uid : str
        UUID key for the current WireGuard/OpenVPN object.
    clnt : MutableMapping[str, Any]
        WireGuard client record being processed.
    servers : MutableMapping[str, Any]
        WireGuard servers mapping keyed by UUID.

    Returns
    -------
    MutableMapping[str, Any]
    None. Updates the supplied data structures in place.


    """
    return {
        "uuid": uid,
        "name": clnt.get("name"),
        "pubkey": clnt.get("pubkey"),
        "enabled": clnt.get("enabled", "") == "1",
        "tunnel_addresses": [
            addr.get("value")
            for addr in clnt.get("tunneladdress", {}).values()
            if addr.get("selected") == 1 and addr.get("value")
        ],
        "servers": [
            await OPNsenseClient._link_wireguard_client_to_server(srv_id, servers, srv)
            for srv_id, srv in clnt.get("servers", {}).items()
            if srv.get("selected") == 1 and srv.get("value")
        ],
        "connected_servers": 0,
        "total_bytes_recv": 0,
        "total_bytes_sent": 0,
    }

@staticmethod
async def _link_wireguard_client_to_server(
    srv_id: str, servers: MutableMapping[str, Any], srv: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Link a WireGuard client to its corresponding server.

    Parameters
    ----------
    srv_id : str
        WireGuard server UUID used for linkage.
    servers : MutableMapping[str, Any]
        WireGuard servers mapping keyed by UUID.
    srv : MutableMapping[str, Any]
        WireGuard server record being processed.

    Returns
    -------
    MutableMapping[str, Any]
    None. Updates the supplied data structures in place.


    """
    if srv_id in servers:
        server = servers[srv_id]
        return {
            "name": server.get("name"),
            "uuid": srv_id,
            "connected": False,
            "pubkey": server.get("pubkey"),
            "interface": server.get("interface"),
            "tunnel_addresses": server.get("tunnel_addresses"),
        }
    return {
        "name": srv.get("value"),
        "uuid": srv_id,
        "connected": False,
    }

@staticmethod
async def _update_wireguard_status(
    summary: list[MutableMapping[str, Any]],
    servers: MutableMapping[str, Any],
    clients: MutableMapping[str, Any],
) -> None:
    """Update WireGuard server and client statuses based on the summary.

    Parameters
    ----------
    summary : list[MutableMapping[str, Any]]
        WireGuard summary rows returned by the API.
    servers : MutableMapping[str, Any]
        WireGuard servers mapping keyed by UUID.
    clients : MutableMapping[str, Any]
        WireGuard clients mapping keyed by UUID.

    """
    for entry in summary:
        if entry.get("type") == "interface":
            for server in servers.values():
                if server.get("pubkey") == entry.get("public-key"):
                    server["status"] = entry.get("status")
        elif entry.get("type") == "peer":
            await OPNsenseClient._update_wireguard_peer_status(entry, servers, clients)

@staticmethod
async def _update_wireguard_peer_status(
    entry: MutableMapping[str, Any],
    servers: MutableMapping[str, Any],
    clients: MutableMapping[str, Any],
) -> None:
    """Update the WireGuard peer status for clients and servers.

    Parameters
    ----------
    entry : MutableMapping[str, Any]
        WireGuard summary row currently being processed.
    servers : MutableMapping[str, Any]
        WireGuard servers mapping keyed by UUID.
    clients : MutableMapping[str, Any]
        WireGuard clients mapping keyed by UUID.

    """
    pubkey = entry.get("public-key", "-")
    interface = entry.get("if", "-")
    endpoint = entry.get("endpoint", None)
    transfer_rx = int(entry.get("transfer-rx", 0))
    transfer_tx = int(entry.get("transfer-tx", 0))
    latest_handshake = int(entry.get("latest-handshake", 0))
    handshake_time = timestamp_to_datetime(latest_handshake)
    is_connected = wireguard_is_connected(handshake_time)

    # Update servers
    for server in servers.values():
        if server.get("interface") == interface:
            for client in server.get("clients", []):
                if client.get("pubkey") == pubkey:
                    await OPNsenseClient._update_wireguard_peer_details(
                        peer=client,
                        server_or_client=server,
                        endpoint=endpoint,
                        transfer_rx=transfer_rx,
                        transfer_tx=transfer_tx,
                        handshake_time=handshake_time,
                        is_connected=is_connected,
                        connection_counter_key="connected_clients",
                    )

    # Update clients
    for client in clients.values():
        if client.get("pubkey") == pubkey:
            for server in client.get("servers", []):
                if server.get("interface") == interface:
                    await OPNsenseClient._update_wireguard_peer_details(
                        peer=server,
                        server_or_client=client,
                        endpoint=endpoint,
                        transfer_rx=transfer_rx,
                        transfer_tx=transfer_tx,
                        handshake_time=handshake_time,
                        is_connected=is_connected,
                        connection_counter_key="connected_servers",
                    )

@staticmethod
async def _update_wireguard_peer_details(
    peer: MutableMapping[str, Any],
    server_or_client: MutableMapping[str, Any],
    endpoint: str,
    transfer_rx: int,
    transfer_tx: int,
    handshake_time: datetime | None,
    is_connected: bool,
    connection_counter_key: str,
) -> None:
    """Update details of WireGuard peers.

    Parameters
    ----------
    peer : MutableMapping[str, Any]
        WireGuard peer record being updated.
    server_or_client : MutableMapping[str, Any]
        WireGuard server/client record owning the peer.
    endpoint : str
        Peer endpoint string (host:port) if available.
    transfer_rx : int
        Received byte counter for the peer.
    transfer_tx : int
        Transmitted byte counter for the peer.
    handshake_time : datetime | None
        Timestamp of the most recent peer handshake.
    is_connected : bool
        Whether the peer is currently considered connected.
    connection_counter_key : str
        Key name used to increment connection statistics.

    """
    if endpoint and endpoint != "(none)":
        peer["endpoint"] = endpoint
    peer["bytes_recv"] = transfer_rx
    peer["bytes_sent"] = transfer_tx
    peer["latest_handshake"] = handshake_time
    peer["connected"] = is_connected

    # Update the parent (server or client) stats
    server_or_client["total_bytes_recv"] = (
        server_or_client.get("total_bytes_recv", 0) + transfer_rx
    )
    server_or_client["total_bytes_sent"] = (
        server_or_client.get("total_bytes_sent", 0) + transfer_tx
    )

    if is_connected:
        server_or_client[connection_counter_key] = (
            server_or_client.get(connection_counter_key, 0) + 1
        )
        # Update the latest handshake time if it's newer
        if (
            server_or_client.get("latest_handshake") is None
            or server_or_client["latest_handshake"] < handshake_time
        ):
            server_or_client["latest_handshake"] = handshake_time

async def toggle_vpn_instance(self, vpn_type: str, clients_servers: str, uuid: str) -> bool:
    """Toggle the specified VPN instance on or off.

    Parameters
    ----------
    vpn_type : str
        VPN family to toggle (openvpn or wireguard).
    clients_servers : str
        VPN instance group endpoint (clients or servers).
    uuid : str
        Target object UUID returned by OPNsense.

    Returns
    -------
    bool
    True when OPNsense reports the requested action succeeded; otherwise False.


    """
    if vpn_type == "openvpn":
        success = await self._safe_dict_post(f"/api/openvpn/instances/toggle/{uuid}")
        if not success.get("changed", False):
            return False
        reconfigure = await self._safe_dict_post("/api/openvpn/service/reconfigure")
        return reconfigure.get("result", "") == "ok"
    if vpn_type == "wireguard":
        if clients_servers == "clients":
            endpoint = (
                f"/api/wireguard/client/toggle_client/{uuid}"
                if self._use_snake_case
                else f"/api/wireguard/client/toggleClient/{uuid}"
            )
        elif clients_servers == "servers":
            endpoint = (
                f"/api/wireguard/server/toggle_server/{uuid}"
                if self._use_snake_case
                else f"/api/wireguard/server/toggleServer/{uuid}"
            )
        success = await self._safe_dict_post(endpoint)
        if not success.get("changed", False):
            return False
        reconfigure = await self._safe_dict_post("/api/wireguard/service/reconfigure")
        return reconfigure.get("result", "") == "ok"
    return False

async def reload_interface(self, if_name: str) -> bool:
    """Reload the specified interface.

    Parameters
    ----------
    if_name : str
        Interface name to reload.

    Returns
    -------
    bool
    True when OPNsense reports the requested action succeeded; otherwise False.


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

async def get_certificates(self) -> MutableMapping[str, Any]:
    """Return the active encryption certificates.

    Returns
    -------
    MutableMapping[str, Any]
    Normalized get certificates data returned by OPNsense APIs.


    """
    certs_raw = await self._safe_dict_get("/api/trust/cert/search")
    if not isinstance(certs_raw.get("rows", None), list):
        return {}
    certs: MutableMapping[str, Any] = {}
    for cert in certs_raw.get("rows", None):
        if cert.get("descr", None):
            certs[cert.get("descr")] = {
                "uuid": cert.get("uuid", None),
                "issuer": cert.get("caref", None),
                "purpose": cert.get("rfc3280_purpose", None),
                "in_use": bool(cert.get("in_use", "0") == "1"),
                "valid_from": timestamp_to_datetime(
                    OPNsenseClient._try_to_int(cert.get("valid_from", None)) or 0
                ),
                "valid_to": timestamp_to_datetime(
                    OPNsenseClient._try_to_int(cert.get("valid_to", None)) or 0
                ),
            }
    _LOGGER.debug("[get_certificates] certs: %s", certs)
    return certs

async def generate_vouchers(self, data: MutableMapping[str, Any]) -> list:
    """Generate vouchers from the Voucher Server.

    Parameters
    ----------
    data : MutableMapping[str, Any]
        Input mapping used to build the request payload.

    Returns
    -------
    list
    List of generated voucher entries returned by the voucher service.


    """
    if data.get("voucher_server", None):
        server = data.get("voucher_server")
    else:
        if self._use_snake_case:
            servers = await self._safe_list_get("/api/captiveportal/voucher/list_providers")
        else:
            servers = await self._safe_list_get("/api/captiveportal/voucher/listProviders")
        if len(servers) == 0:
            raise VoucherServerError("No voucher servers exist")
        if len(servers) != 1:
            raise VoucherServerError(
                "More than one voucher server. Must specify voucher server name"
            )
        server = servers[0]
    server_slug = quote(str(server))
    payload: MutableMapping[str, Any] = dict(data).copy()
    payload.pop("voucher_server", None)
    if self._use_snake_case:
        voucher_url: str = f"/api/captiveportal/voucher/generate_vouchers/{server_slug}/"
    else:
        voucher_url = f"/api/captiveportal/voucher/generateVouchers/{server_slug}/"
    _LOGGER.debug("[generate_vouchers] url: %s, payload: %s", voucher_url, payload)
    vouchers = await self._safe_list_post(
        voucher_url,
        payload=payload,
    )
    ordered_keys: list = [
        "username",
        "password",
        "vouchergroup",
        "starttime",
        "expirytime",
        "expiry_timestamp",
        "validity_str",
        "validity",
    ]
    for voucher in vouchers:
        if voucher.get("validity", None):
            voucher["validity_str"] = human_friendly_duration(voucher.get("validity"))
        if voucher.get("expirytime", None):
            voucher["expiry_timestamp"] = voucher.get("expirytime")
            voucher["expirytime"] = timestamp_to_datetime(
                OPNsenseClient._try_to_int(voucher.get("expirytime")) or 0
            )

        rearranged_voucher: MutableMapping[str, Any] = {
            key: voucher[key] for key in ordered_keys if key in voucher
        }
        voucher.clear()
        voucher.update(rearranged_voucher)

    _LOGGER.debug("[generate_vouchers] vouchers: %s", vouchers)
    return vouchers

async def kill_states(self, ip_addr: str) -> MutableMapping[str, Any]:
    """Kill the active states of the IP address.

    Parameters
    ----------
    ip_addr : str
        IP address whose states should be terminated.

    Returns
    -------
    MutableMapping[str, Any]
    Result produced by this method.


    """
    payload: MutableMapping[str, Any] = {"filter": ip_addr}
    response = await self._safe_dict_post(
        "/api/diagnostics/firewall/kill_states/",
        payload=payload,
    )
    _LOGGER.debug("[kill_states] ip_addr: %s, response: %s", ip_addr, response)
    return {
        "success": bool(response.get("result", "") == "ok"),
        "dropped_states": response.get("dropped_states", 0),
    }

async def toggle_alias(self, alias: str, toggle_on_off: str | None = None) -> bool:
    """Toggle alias on and off.

    Parameters
    ----------
    alias : str
        Firewall alias name to toggle.
    toggle_on_off : str | None
        Explicit toggle directive ("on"/"off"); uses API toggle when omitted. Defaults to None.

    Returns
    -------
    bool
    True when OPNsense reports the requested action succeeded; otherwise False.


    """
    if self._use_snake_case:
        alias_list_resp = await self._safe_dict_get("/api/firewall/alias/search_item")
    else:
        alias_list_resp = await self._safe_dict_get("/api/firewall/alias/searchItem")
    alias_list: list = alias_list_resp.get("rows", [])
    if not isinstance(alias_list, list):
        return False
    uuid: str | None = None
    for item in alias_list:
        if not isinstance(item, MutableMapping):
            continue
        if item.get("name") == alias:
            uuid = item.get("uuid")
            break
    if not uuid:
        return False
    payload: MutableMapping[str, Any] = {}
    if self._use_snake_case:
        url: str = f"/api/firewall/alias/toggle_item/{uuid}"
    else:
        url = f"/api/firewall/alias/toggleItem/{uuid}"
    if toggle_on_off == "on":
        url = f"{url}/1"
    elif toggle_on_off == "off":
        url = f"{url}/0"
    response = await self._safe_dict_post(
        url,
        payload=payload,
    )
    _LOGGER.debug(
        "[toggle_alias] alias: %s, uuid: %s, action: %s, url: %s, response: %s",
        alias,
        uuid,
        toggle_on_off,
        url,
        response,
    )
    if response.get("result") == "failed":
        return False

    set_resp = await self._safe_dict_post("/api/firewall/alias/set")
    if set_resp.get("result") != "saved":
        return False

    reconfigure_resp = await self._safe_dict_post("/api/firewall/alias/reconfigure")
    if reconfigure_resp.get("status") != "ok":
        return False

    return True

async def async_close(self) -> None:
    """Cancel all running background tasks and clear the request queue."""
    _LOGGER.debug("Closing OPNsenseClient and cancelling background tasks")

    tasks_to_cancel = []

    if self._queue_monitor and not self._queue_monitor.done():
        self._queue_monitor.cancel()
        tasks_to_cancel.append(self._queue_monitor)

    if self._workers:
        for worker in self._workers:
            if not worker.done():
                worker.cancel()
            tasks_to_cancel.append(worker)

    if tasks_to_cancel:
        try:
            await asyncio.gather(*tasks_to_cancel, return_exceptions=True)
            _LOGGER.debug("All background tasks cancelled successfully")
        except Exception as e:  # noqa: BLE001
            _LOGGER.warning(
                "Error during background task cancellation. %s: %s", type(e).__name__, e
            )

    while not self._request_queue.empty():
        try:
            self._request_queue.get_nowait()
        except asyncio.QueueEmpty:
            break
    _LOGGER.debug("Request queue cleared")

__all__ = [
    "_set_unbound_blocklist_legacy",
    "get_unbound_blocklist",
    "_toggle_unbound_blocklist",
    "enable_unbound_blocklist",
    "disable_unbound_blocklist",
    "get_wireguard",
    "_process_wireguard_server",
    "_process_wireguard_client",
    "_link_wireguard_client_to_server",
    "_update_wireguard_status",
    "_update_wireguard_peer_status",
    "_update_wireguard_peer_details",
    "toggle_vpn_instance",
    "reload_interface",
    "get_certificates",
    "generate_vouchers",
    "kill_states",
    "toggle_alias",
    "async_close",
]
