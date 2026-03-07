"""VPN and tunnel-management methods for OPNsenseClient."""

from .client_methods_part4 import (
    _add_openvpn_server,
    _fetch_openvpn_server_details,
    _process_openvpn_instances,
    _process_openvpn_providers,
    _process_openvpn_routes,
    _process_openvpn_sessions,
    _update_openvpn_server_status,
    get_openvpn,
)
from .client_methods_part5 import (
    _link_wireguard_client_to_server,
    _process_wireguard_client,
    _process_wireguard_server,
    _update_wireguard_peer_details,
    _update_wireguard_peer_status,
    _update_wireguard_status,
    get_wireguard,
    toggle_vpn_instance,
)

__all__ = [
    "get_openvpn",
    "_process_openvpn_instances",
    "_add_openvpn_server",
    "_process_openvpn_providers",
    "_process_openvpn_sessions",
    "_update_openvpn_server_status",
    "_process_openvpn_routes",
    "_fetch_openvpn_server_details",
    "get_wireguard",
    "_process_wireguard_server",
    "_process_wireguard_client",
    "_link_wireguard_client_to_server",
    "_update_wireguard_status",
    "_update_wireguard_peer_status",
    "_update_wireguard_peer_details",
    "toggle_vpn_instance",
]
