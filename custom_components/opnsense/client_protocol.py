"""Protocol definitions for backend-agnostic OPNsense clients."""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import Any, Protocol


class OPNsenseClientProtocol(Protocol):
    """Structural contract used by hass-opnsense integration modules."""

    async def async_close(self) -> None:
        """Close client resources."""

    async def set_use_snake_case(self, initial: bool = False) -> None:
        """Configure API field naming mode."""

    async def reset_query_counts(self) -> None:
        """Reset accumulated query counters."""

    async def get_query_counts(self) -> tuple[int, int]:
        """Return REST and XML-RPC query counts."""

    async def get_device_unique_id(self, expected_id: str | None = None) -> str | None:
        """Return the device unique identifier."""

    async def get_host_firmware_version(self) -> str | None:
        """Return detected firmware version."""

    async def get_system_info(self) -> dict[str, Any]:
        """Return system information payload."""

    async def get_telemetry(self) -> MutableMapping[str, Any]:
        """Return telemetry payload."""

    async def get_arp_table(self, resolve_hostnames: bool = True) -> list:
        """Return ARP table entries."""

    async def is_plugin_installed(self) -> bool:
        """Return plugin install status."""

    async def is_plugin_deprecated(self) -> bool:
        """Return plugin deprecation status."""

    async def close_notice(self, id: str) -> bool:
        """Close one or all OPNsense notices."""

    async def start_service(self, service: str) -> bool:
        """Start a service by name."""

    async def stop_service(self, service: str) -> bool:
        """Stop a service by name."""

    async def restart_service(self, service: str) -> bool:
        """Restart a service by name."""

    async def restart_service_if_running(self, service: str) -> bool:
        """Restart a running service by name."""

    async def system_halt(self) -> None:
        """Halt the system."""

    async def system_reboot(self) -> bool:
        """Reboot the system."""

    async def send_wol(
        self,
        interface: str,
        mac: str,
    ) -> bool:
        """Send a WOL packet."""

    async def reload_interface(self, if_name: str) -> bool:
        """Reload an interface by name."""

    async def generate_vouchers(self, data: MutableMapping[str, Any]) -> list:
        """Generate captive-portal vouchers."""

    async def kill_states(self, ip_addr: str) -> MutableMapping[str, Any]:
        """Kill firewall states for an IP address."""

    async def run_speedtest(self) -> dict[str, Any]:
        """Run and return a speedtest result."""

    async def get_vnstat_metrics(self, period: str) -> dict[str, Any]:
        """Return vnStat metrics for the requested period."""

    async def toggle_alias(self, alias: str, toggle_on_off: str | None = None) -> bool:
        """Toggle, enable, or disable an alias."""

    async def toggle_firewall_rule(self, uuid: str, toggle_on_off: str | None = None) -> bool:
        """Toggle a firewall rule."""

    async def toggle_nat_rule(
        self, nat_rule_type: str, uuid: str, toggle_on_off: str | None = None
    ) -> bool:
        """Toggle a NAT rule."""

    async def enable_filter_rule_by_created_time_legacy(self, created_time: str) -> None:
        """Enable legacy filter rule by created-time value."""

    async def disable_filter_rule_by_created_time_legacy(self, created_time: str) -> None:
        """Disable legacy filter rule by created-time value."""

    async def enable_nat_port_forward_rule_by_created_time_legacy(self, created_time: str) -> None:
        """Enable legacy NAT port-forward rule by created-time value."""

    async def disable_nat_port_forward_rule_by_created_time_legacy(self, created_time: str) -> None:
        """Disable legacy NAT port-forward rule by created-time value."""

    async def enable_nat_outbound_rule_by_created_time_legacy(self, created_time: str) -> None:
        """Enable legacy NAT outbound rule by created-time value."""

    async def disable_nat_outbound_rule_by_created_time_legacy(self, created_time: str) -> None:
        """Disable legacy NAT outbound rule by created-time value."""

    async def enable_unbound_blocklist(self, uuid: str | None = None) -> bool:
        """Enable unbound blocklist entry."""

    async def disable_unbound_blocklist(self, uuid: str | None = None) -> bool:
        """Disable unbound blocklist entry."""

    async def toggle_vpn_instance(
        self,
        vpn_type: str,
        clients_servers: str,
        uuid: str,
    ) -> bool:
        """Toggle a VPN instance."""

    async def upgrade_firmware(self, type: str = "update") -> MutableMapping[str, Any] | None:
        """Trigger firmware update or upgrade."""

    async def upgrade_status(self) -> MutableMapping[str, Any]:
        """Return firmware upgrade status."""

    async def get_firmware_update_info(self) -> MutableMapping[str, Any]:
        """Return firmware update metadata."""
