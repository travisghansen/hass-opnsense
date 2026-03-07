"""pyopnsense to manage OPNsense from HA."""

from datetime import datetime
import inspect
import socket

import awesomeversion

from .client import (
    FIRMWARE_CHECK_INTERVAL,
    FIRMWARE_INFO_PATH,
    FIRMWARE_STATUS_PATH,
    OPNsenseClient,
    UnknownFirmware,
    VoucherServerError,
)
from .helpers import (
    DEFAULT_TIMEOUT,
    dict_get,
    get_ip_key,
    human_friendly_duration,
    log_errors as _log_errors,
    timestamp_to_datetime,
    wireguard_is_connected,
    xmlrpc_timeout as _xmlrpc_timeout,
)

__all__ = [
    "DEFAULT_TIMEOUT",
    "FIRMWARE_CHECK_INTERVAL",
    "FIRMWARE_INFO_PATH",
    "FIRMWARE_STATUS_PATH",
    "OPNsenseClient",
    "UnknownFirmware",
    "VoucherServerError",
    "_log_errors",
    "_xmlrpc_timeout",
    "dict_get",
    "get_ip_key",
    "human_friendly_duration",
    "timestamp_to_datetime",
    "wireguard_is_connected",
    # Expose for tests that monkeypatch module attributes.
    "awesomeversion",
    "datetime",
    "inspect",
    "socket",
]
