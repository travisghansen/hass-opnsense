"""DHCP lease collection and normalization methods for OPNsenseClient."""

from .client_methods_part3 import (
    _get_dnsmasq_leases,
    _get_isc_dhcpv4_leases,
    _get_isc_dhcpv6_leases,
    _get_kea_dhcpv4_leases,
    _get_kea_interfaces,
    _keep_latest_leases,
    get_dhcp_leases,
)

__all__ = [
    "get_dhcp_leases",
    "_get_kea_interfaces",
    "_get_kea_dhcpv4_leases",
    "_keep_latest_leases",
    "_get_dnsmasq_leases",
    "_get_isc_dhcpv4_leases",
    "_get_isc_dhcpv6_leases",
]
