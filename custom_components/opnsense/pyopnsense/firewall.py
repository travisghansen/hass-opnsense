"""Firewall, NAT, alias, and state-management methods for OPNsenseClient."""

from .client_methods_part2 import (
    _get_firewall_rules,
    _get_nat_destination_rules,
    _get_nat_npt_rules,
    _get_nat_one_to_one_rules,
    _get_nat_source_rules,
    disable_filter_rule_by_created_time_legacy,
    disable_nat_outbound_rule_by_created_time_legacy,
    disable_nat_port_forward_rule_by_created_time_legacy,
    enable_filter_rule_by_created_time_legacy,
    enable_nat_outbound_rule_by_created_time_legacy,
    enable_nat_port_forward_rule_by_created_time_legacy,
    get_firewall,
    toggle_firewall_rule,
    toggle_nat_rule,
)
from .client_methods_part5 import kill_states, toggle_alias

__all__ = [
    "enable_filter_rule_by_created_time_legacy",
    "disable_filter_rule_by_created_time_legacy",
    "enable_nat_port_forward_rule_by_created_time_legacy",
    "disable_nat_port_forward_rule_by_created_time_legacy",
    "enable_nat_outbound_rule_by_created_time_legacy",
    "disable_nat_outbound_rule_by_created_time_legacy",
    "get_firewall",
    "_get_firewall_rules",
    "_get_nat_destination_rules",
    "_get_nat_one_to_one_rules",
    "_get_nat_source_rules",
    "_get_nat_npt_rules",
    "toggle_firewall_rule",
    "toggle_nat_rule",
    "kill_states",
    "toggle_alias",
]
