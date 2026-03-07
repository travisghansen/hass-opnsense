"""Telemetry and runtime status methods for OPNsenseClient."""

from .client_methods_part3 import _try_to_float, _try_to_int, get_telemetry
from .client_methods_part4 import (
    _get_telemetry_cpu,
    _get_telemetry_filesystems,
    _get_telemetry_mbuf,
    _get_telemetry_memory,
    _get_telemetry_pfstate,
    _get_telemetry_system,
    _get_telemetry_temps,
    get_gateways,
    get_interfaces,
)

__all__ = [
    "get_interfaces",
    "_get_telemetry_mbuf",
    "_get_telemetry_pfstate",
    "_get_telemetry_memory",
    "_get_telemetry_system",
    "_get_telemetry_cpu",
    "_get_telemetry_filesystems",
    "_get_telemetry_temps",
    "get_gateways",
    "_try_to_int",
    "_try_to_float",
    "get_telemetry",
]
