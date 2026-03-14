"""Public OPNsense client class composed from domain mixins."""

from .client_base import ClientBaseMixin
from .dhcp import DHCPMixin
from .firewall import FirewallMixin
from .firmware import FirmwareMixin
from .services import ServicesMixin
from .speedtest import SpeedtestMixin
from .system import SystemMixin
from .telemetry import TelemetryMixin
from .unbound import UnboundMixin
from .vnstat import VnstatMixin
from .vouchers import VouchersMixin
from .vpn import VPNMixin


class OPNsenseClient(
    ClientBaseMixin,
    FirmwareMixin,
    FirewallMixin,
    DHCPMixin,
    ServicesMixin,
    SpeedtestMixin,
    SystemMixin,
    UnboundMixin,
    VouchersMixin,
    TelemetryMixin,
    VnstatMixin,
    VPNMixin,
):
    """Async client for OPNsense REST and XMLRPC endpoints."""
