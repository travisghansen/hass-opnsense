"""pyopnsense to manage OPNsense from HA."""

from abc import ABC

from .client_shared import (
    FIRMWARE_CHECK_INTERVAL,
    FIRMWARE_INFO_PATH,
    FIRMWARE_STATUS_PATH,
    VoucherServerError,
    inspect,
)
from . import core as _core
from . import dhcp as _dhcp
from . import firewall as _firewall
from . import firmware as _firmware
from . import system as _system
from . import telemetry as _telemetry
from . import vpn as _vpn

# Compatibility shims for function globals while methods still originate in these modules.
from . import client_methods_part1 as _client_methods_part1
from . import client_methods_part2 as _client_methods_part2
from . import client_methods_part3 as _client_methods_part3
from . import client_methods_part4 as _client_methods_part4
from . import client_methods_part5 as _client_methods_part5


class OPNsenseClient(ABC):
    """Async client for OPNsense REST and XMLRPC endpoints."""


for _module in (_core, _firmware, _firewall, _dhcp, _telemetry, _vpn, _system):
    for _name in _module.__all__:
        setattr(OPNsenseClient, _name, getattr(_module, _name))


class UnknownFirmware(Exception):
    """Error to indicate unknown firmware version."""


class _InspectProxy:
    @staticmethod
    def stack() -> list:
        return inspect.stack()


for _mod in (
    _client_methods_part1,
    _client_methods_part2,
    _client_methods_part3,
    _client_methods_part4,
    _client_methods_part5,
):
    _mod.OPNsenseClient = OPNsenseClient
    _mod.UnknownFirmware = UnknownFirmware
    _mod.inspect = _InspectProxy

del _mod
del _module
del _name
del _InspectProxy
