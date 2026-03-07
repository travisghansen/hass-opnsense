"""System, service, notice, and utility methods for OPNsenseClient."""

from .client_methods_part2 import get_config, get_device_unique_id, get_system_info
from .client_methods_part3 import (
    _manage_service,
    get_arp_table,
    get_carp_interfaces,
    get_carp_status,
    get_service_is_running,
    get_services,
    restart_service,
    restart_service_if_running,
    send_wol,
    start_service,
    stop_service,
    system_halt,
    system_reboot,
)
from .client_methods_part4 import close_notice, get_notices, get_unbound_blocklist_legacy
from .client_methods_part5 import (
    _set_unbound_blocklist_legacy,
    _toggle_unbound_blocklist,
    disable_unbound_blocklist,
    enable_unbound_blocklist,
    generate_vouchers,
    get_certificates,
    get_unbound_blocklist,
    reload_interface,
)

__all__ = [
    "get_device_unique_id",
    "get_system_info",
    "get_config",
    "get_arp_table",
    "get_services",
    "get_service_is_running",
    "_manage_service",
    "start_service",
    "stop_service",
    "restart_service",
    "restart_service_if_running",
    "get_carp_status",
    "get_carp_interfaces",
    "system_reboot",
    "system_halt",
    "send_wol",
    "reload_interface",
    "get_certificates",
    "generate_vouchers",
    "get_notices",
    "close_notice",
    "get_unbound_blocklist_legacy",
    "_set_unbound_blocklist_legacy",
    "get_unbound_blocklist",
    "_toggle_unbound_blocklist",
    "enable_unbound_blocklist",
    "disable_unbound_blocklist",
]
