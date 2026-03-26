"""Protocol definitions for backend-agnostic OPNsense clients."""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import Any, Protocol


class OPNsenseClientProtocol(Protocol):
    """Structural contract used by hass-opnsense integration modules."""

    async def async_close(self) -> None:
        """Close network resources and background tasks held by the client."""

    async def set_use_snake_case(self, initial: bool = False) -> None:
        """Set API field naming mode based on firmware support.

        Args:
            initial: Whether this call runs during initial setup validation.
        """

    async def reset_query_counts(self) -> None:
        """Reset REST and XML-RPC query counters tracked by the client."""

    async def get_query_counts(self) -> tuple[int, int]:
        """Return accumulated query counters.

        Returns:
            tuple[int, int]: Tuple of `(rest_api_count, xmlrpc_count)`.
        """

    async def get_device_unique_id(self, expected_id: str | None = None) -> str | None:
        """Return router unique identifier used for registry/entity IDs.

        Args:
            expected_id: Optional expected ID used by backends that validate ID stability.

        Returns:
            str | None: Router unique identifier when available.
        """

    async def get_host_firmware_version(self) -> str | None:
        """Return detected OPNsense firmware version string.

        Returns:
            str | None: Firmware version reported by the firewall.
        """

    async def get_system_info(self) -> dict[str, Any]:
        """Fetch general system information from the firewall.

        Returns:
            dict[str, Any]: System metadata such as hostname and platform details.
        """

    async def get_telemetry(self) -> MutableMapping[str, Any]:
        """Fetch telemetry payload from OPNsense.

        Returns:
            MutableMapping[str, Any]: Telemetry sections and counters keyed by subsystem.
        """

    async def get_arp_table(self, resolve_hostnames: bool = True) -> list:
        """Fetch ARP table entries used by the device tracker.

        Args:
            resolve_hostnames: Whether hostnames should be resolved for returned entries.

        Returns:
            list: ARP entry collection containing MAC/IP/device metadata.
        """

    async def is_plugin_installed(self) -> bool:
        """Report whether the Home Assistant OPNsense plugin is installed.

        Returns:
            bool: `True` when plugin package is installed.
        """

    async def is_plugin_deprecated(self) -> bool:
        """Report whether installed plugin is considered deprecated.

        Returns:
            bool: `True` when plugin should be treated as deprecated.
        """

    async def close_notice(self, id: str) -> bool:
        """Close a single notice or all notices, depending on backend semantics.

        Args:
            id: Notice identifier or backend-specific sentinel value.

        Returns:
            bool: `True` when the close request succeeded.
        """

    async def start_service(self, service: str) -> bool:
        """Start a named OPNsense service.

        Args:
            service: Service name as understood by the backend API.

        Returns:
            bool: `True` when the service start request succeeded.
        """

    async def stop_service(self, service: str) -> bool:
        """Stop a named OPNsense service.

        Args:
            service: Service name as understood by the backend API.

        Returns:
            bool: `True` when the service stop request succeeded.
        """

    async def restart_service(self, service: str) -> bool:
        """Restart a named OPNsense service.

        Args:
            service: Service name as understood by the backend API.

        Returns:
            bool: `True` when the service restart request succeeded.
        """

    async def restart_service_if_running(self, service: str) -> bool:
        """Restart a named service only if it is currently running.

        Args:
            service: Service name as understood by the backend API.

        Returns:
            bool: `True` when restart check/request completed successfully.
        """

    async def system_halt(self) -> None:
        """Request a system halt operation on the firewall."""

    async def system_reboot(self) -> bool:
        """Request a system reboot operation on the firewall.

        Returns:
            bool: `True` when reboot request was accepted.
        """

    async def send_wol(
        self,
        interface: str,
        mac: str,
    ) -> bool:
        """Send a Wake-on-LAN magic packet.

        Args:
            interface: Interface name used to send the packet.
            mac: Target device MAC address.

        Returns:
            bool: `True` when wake packet dispatch succeeded.
        """

    async def reload_interface(self, if_name: str) -> bool:
        """Reload a network interface configuration.

        Args:
            if_name: Interface identifier/name to reload.

        Returns:
            bool: `True` when interface reload succeeded.
        """

    async def generate_vouchers(self, data: MutableMapping[str, Any]) -> list:
        """Generate captive-portal vouchers.

        Args:
            data: Voucher generation payload including count, validity, and template fields.

        Returns:
            list: Generated voucher records returned by OPNsense.
        """

    async def kill_states(self, ip_addr: str) -> MutableMapping[str, Any]:
        """Terminate firewall states for a specific host IP.

        Args:
            ip_addr: IPv4 or IPv6 address whose states should be killed.

        Returns:
            MutableMapping[str, Any]: Backend response with state-kill result details.
        """

    async def run_speedtest(self) -> dict[str, Any]:
        """Run a speed test and return resulting metrics.

        Returns:
            dict[str, Any]: Speed test result payload from OPNsense.
        """

    async def get_vnstat_metrics(self, period: str) -> dict[str, Any]:
        """Fetch vnStat metrics for a requested aggregation period.

        Args:
            period: vnStat period key, such as hourly/daily/monthly.

        Returns:
            dict[str, Any]: vnStat metrics payload for the selected period.
        """

    async def toggle_alias(self, alias: str, toggle_on_off: str | None = None) -> bool:
        """Toggle or explicitly set firewall alias enabled state.

        Args:
            alias: Alias name to modify.
            toggle_on_off: Optional explicit target state (`on`/`off`) when supported.

        Returns:
            bool: `True` when alias state change succeeded.
        """

    async def toggle_firewall_rule(self, uuid: str, toggle_on_off: str | None = None) -> bool:
        """Toggle or explicitly set firewall rule enabled state.

        Args:
            uuid: Rule UUID to modify.
            toggle_on_off: Optional explicit target state (`on`/`off`) when supported.

        Returns:
            bool: `True` when firewall rule state change succeeded.
        """

    async def toggle_nat_rule(
        self, nat_rule_type: str, uuid: str, toggle_on_off: str | None = None
    ) -> bool:
        """Toggle or explicitly set NAT rule enabled state.

        Args:
            nat_rule_type: NAT rule group, such as `port_forward` or `outbound`.
            uuid: NAT rule UUID to modify.
            toggle_on_off: Optional explicit target state (`on`/`off`) when supported.

        Returns:
            bool: `True` when NAT rule state change succeeded.
        """

    async def enable_filter_rule_by_created_time_legacy(self, created_time: str) -> None:
        """Enable a legacy filter rule identified by created-time metadata.

        Args:
            created_time: Legacy created-time token identifying the target rule.
        """

    async def disable_filter_rule_by_created_time_legacy(self, created_time: str) -> None:
        """Disable a legacy filter rule identified by created-time metadata.

        Args:
            created_time: Legacy created-time token identifying the target rule.
        """

    async def enable_nat_port_forward_rule_by_created_time_legacy(self, created_time: str) -> None:
        """Enable a legacy NAT port-forward rule by created-time metadata.

        Args:
            created_time: Legacy created-time token identifying the target rule.
        """

    async def disable_nat_port_forward_rule_by_created_time_legacy(self, created_time: str) -> None:
        """Disable a legacy NAT port-forward rule by created-time metadata.

        Args:
            created_time: Legacy created-time token identifying the target rule.
        """

    async def enable_nat_outbound_rule_by_created_time_legacy(self, created_time: str) -> None:
        """Enable a legacy NAT outbound rule by created-time metadata.

        Args:
            created_time: Legacy created-time token identifying the target rule.
        """

    async def disable_nat_outbound_rule_by_created_time_legacy(self, created_time: str) -> None:
        """Disable a legacy NAT outbound rule by created-time metadata.

        Args:
            created_time: Legacy created-time token identifying the target rule.
        """

    async def enable_unbound_blocklist(self, uuid: str | None = None) -> bool:
        """Enable an Unbound blocklist entry or global blocklist state.

        Args:
            uuid: Optional blocklist entry UUID for targeted enable operations.

        Returns:
            bool: `True` when blocklist enable request succeeded.
        """

    async def disable_unbound_blocklist(self, uuid: str | None = None) -> bool:
        """Disable an Unbound blocklist entry or global blocklist state.

        Args:
            uuid: Optional blocklist entry UUID for targeted disable operations.

        Returns:
            bool: `True` when blocklist disable request succeeded.
        """

    async def toggle_vpn_instance(
        self,
        vpn_type: str,
        clients_servers: str,
        uuid: str,
    ) -> bool:
        """Toggle a VPN client/server instance state.

        Args:
            vpn_type: VPN subsystem type, such as `openvpn` or `wireguard`.
            clients_servers: Group selector identifying clients or servers.
            uuid: VPN instance UUID.

        Returns:
            bool: `True` when instance state change succeeded.
        """

    async def upgrade_firmware(self, type: str = "update") -> MutableMapping[str, Any] | None:
        """Trigger firmware update/upgrade workflow.

        Args:
            type: Upgrade action type accepted by the backend (default: `update`).

        Returns:
            MutableMapping[str, Any] | None: Upgrade request response payload when available.
        """

    async def upgrade_status(self) -> MutableMapping[str, Any]:
        """Fetch current firmware upgrade status.

        Returns:
            MutableMapping[str, Any]: Upgrade status payload including progress/state details.
        """

    async def get_firmware_update_info(self) -> MutableMapping[str, Any]:
        """Fetch firmware update metadata and available package information.

        Returns:
            MutableMapping[str, Any]: Firmware update information payload.
        """
