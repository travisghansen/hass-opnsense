"""pyopnsense package to manage OPNsense from HA."""

from .client import OPNsenseClient
from .exceptions import UnknownFirmware, VoucherServerError

__all__ = [
    "OPNsenseClient",
    "UnknownFirmware",
    "VoucherServerError",
]
