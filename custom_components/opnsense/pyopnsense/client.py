"""pyopnsense to manage OPNsense from HA."""

from abc import ABC

from .client_shared import (
    FIRMWARE_CHECK_INTERVAL,
    FIRMWARE_INFO_PATH,
    FIRMWARE_STATUS_PATH,
    VoucherServerError,
    inspect,
)
from . import client_methods_part1 as _client_methods_part1
from . import client_methods_part2 as _client_methods_part2
from . import client_methods_part3 as _client_methods_part3
from . import client_methods_part4 as _client_methods_part4
from . import client_methods_part5 as _client_methods_part5


class OPNsenseClient(ABC):
    """Async client for OPNsense REST and XMLRPC endpoints."""


for _name in _client_methods_part1.__all__:
    setattr(OPNsenseClient, _name, getattr(_client_methods_part1, _name))

for _name in _client_methods_part2.__all__:
    setattr(OPNsenseClient, _name, getattr(_client_methods_part2, _name))

for _name in _client_methods_part3.__all__:
    setattr(OPNsenseClient, _name, getattr(_client_methods_part3, _name))

for _name in _client_methods_part4.__all__:
    setattr(OPNsenseClient, _name, getattr(_client_methods_part4, _name))

for _name in _client_methods_part5.__all__:
    setattr(OPNsenseClient, _name, getattr(_client_methods_part5, _name))


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
del _name
del _InspectProxy
