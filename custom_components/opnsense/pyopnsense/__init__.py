"""pyopnsense package to manage OPNsense from HA."""

from .client import OPNsenseClient
from .exceptions import OPNsenseUnknownFirmware, OPNsenseVoucherServerError

__all__ = [
    "OPNsenseClient",
    "OPNsenseUnknownFirmware",
    "OPNsenseVoucherServerError",
]
