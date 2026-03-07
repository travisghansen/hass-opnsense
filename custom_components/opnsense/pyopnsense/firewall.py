"""Firewall, NAT, alias, and state methods for OPNsenseClient."""

from collections.abc import MutableMapping
from typing import Any

import awesomeversion

from ._typing import PyOPNsenseClientProtocol
from .helpers import _LOGGER, _log_errors


class FirewallMixin(PyOPNsenseClientProtocol):
    """Firewall methods for OPNsenseClient."""

    @_log_errors
    async def enable_filter_rule_by_created_time_legacy(self, created_time: str) -> None:
        """Enable a filter rule.

        Parameters
        ----------
        created_time : str
            Rule creation timestamp used as a legacy unique identifier.

        """
        config: dict[str, Any] = await self.get_config()
        for rule in config.get("filter", {}).get("rule", []):
            if "created" not in rule:
                continue
            if "time" not in rule["created"]:
                continue
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" in rule:
                del rule["disabled"]
                await self._restore_config_section("filter", config.get("filter", {}))
                await self._filter_configure()

    @_log_errors
    async def disable_filter_rule_by_created_time_legacy(self, created_time: str) -> None:
        """Disable a filter rule.

        Parameters
        ----------
        created_time : str
            Rule creation timestamp used as a legacy unique identifier.

        """
        config: dict[str, Any] = await self.get_config()

        for rule in config.get("filter", {}).get("rule", []):
            if "created" not in rule:
                continue
            if "time" not in rule["created"]:
                continue
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" not in rule:
                rule["disabled"] = "1"
                await self._restore_config_section("filter", config.get("filter", {}))
                await self._filter_configure()

    @_log_errors
    async def enable_nat_port_forward_rule_by_created_time_legacy(self, created_time: str) -> None:
        """Enable a NAT Port Forward rule.

        Parameters
        ----------
        created_time : str
            Rule creation timestamp used as a legacy unique identifier.

        """
        config: dict[str, Any] = await self.get_config()
        for rule in config.get("nat", {}).get("rule", []):
            if "created" not in rule:
                continue
            if "time" not in rule["created"]:
                continue
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" in rule:
                del rule["disabled"]
                await self._restore_config_section("nat", config.get("nat", {}))
                await self._filter_configure()

    @_log_errors
    async def disable_nat_port_forward_rule_by_created_time_legacy(self, created_time: str) -> None:
        """Disable a NAT Port Forward rule.

        Parameters
        ----------
        created_time : str
            Rule creation timestamp used as a legacy unique identifier.

        """
        config: dict[str, Any] = await self.get_config()
        for rule in config.get("nat", {}).get("rule", []):
            if "created" not in rule:
                continue
            if "time" not in rule["created"]:
                continue
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" not in rule:
                rule["disabled"] = "1"
                await self._restore_config_section("nat", config.get("nat", {}))
                await self._filter_configure()

    @_log_errors
    async def enable_nat_outbound_rule_by_created_time_legacy(self, created_time: str) -> None:
        """Enable NAT Outbound rule.

        Parameters
        ----------
        created_time : str
            Rule creation timestamp used as a legacy unique identifier.

        """
        config: dict[str, Any] = await self.get_config()
        for rule in config.get("nat", {}).get("outbound", {}).get("rule", []):
            if "created" not in rule:
                continue
            if "time" not in rule["created"]:
                continue
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" in rule:
                del rule["disabled"]
                await self._restore_config_section("nat", config.get("nat", {}))
                await self._filter_configure()

    @_log_errors
    async def disable_nat_outbound_rule_by_created_time_legacy(self, created_time: str) -> None:
        """Disable NAT Outbound Rule.

        Parameters
        ----------
        created_time : str
            Rule creation timestamp used as a legacy unique identifier.

        """
        config: dict[str, Any] = await self.get_config()
        for rule in config.get("nat", {}).get("outbound", {}).get("rule", []):
            if "created" not in rule or "time" not in rule["created"]:
                continue
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" not in rule:
                rule["disabled"] = "1"
                await self._restore_config_section("nat", config.get("nat", {}))
                await self._filter_configure()

    @_log_errors
    async def get_firewall(self) -> dict[str, Any]:
        """Retrieve all firewall and NAT rules from OPNsense.

        Returns
        -------
        dict[str, Any]
        Parsed firewall payload returned by OPNsense APIs.


        """
        firmware = await self.get_host_firmware_version()

        try:
            if awesomeversion.AwesomeVersion(firmware) < awesomeversion.AwesomeVersion("26.1.1"):
                _LOGGER.debug("Using legacy plugin for firewall filters for OPNsense < 26.1.1")
                return {"config": await self.get_config()}
        except (awesomeversion.exceptions.AwesomeVersionCompareException, TypeError, ValueError):
            _LOGGER.warning("Error comparing firmware version. Skipping get_firewall.")
            return {}
        firewall: dict[str, Any] = {"nat": {}}
        if await self.is_plugin_installed() and not await self.is_plugin_deprecated():
            firewall["config"] = await self.get_config()
        firewall["rules"] = await self._get_firewall_rules()
        firewall["nat"]["d_nat"] = await self._get_nat_destination_rules()
        firewall["nat"]["one_to_one"] = await self._get_nat_one_to_one_rules()
        firewall["nat"]["source_nat"] = await self._get_nat_source_rules()
        firewall["nat"]["npt"] = await self._get_nat_npt_rules()
        # _LOGGER.debug("[get_firewall] firewall: %s", firewall)
        return firewall

    @_log_errors
    async def _get_firewall_rules(self) -> dict[str, Any]:
        """Retrieve firewall rules from OPNsense.

        Returns
        -------
        dict[str, Any]
        Parsed firewall rules payload returned by OPNsense APIs.


        """
        request_body: dict[str, Any] = {"current": 1, "sort": {}}
        response = await self._safe_dict_post(
            "/api/firewall/filter/search_rule", payload=request_body
        )
        # _LOGGER.debug("[get_firewall_rules] response: %s", response)
        rules: list = response.get("rows", [])
        # _LOGGER.debug("[get_firewall_rules] rules: %s", rules)
        rules_dict: dict[str, Any] = {}
        for rule in rules:
            if not isinstance(rule, MutableMapping):
                continue
            uuid = rule.get("uuid")
            if not uuid or "lockout" in str(uuid):
                continue
            new_rule = dict(rule)
            # Add any transforms here
            rules_dict[str(new_rule["uuid"])] = new_rule
        _LOGGER.debug("[get_firewall_rules] rules_dict: %s", rules_dict)
        return rules_dict

    @_log_errors
    async def _get_nat_destination_rules(self) -> dict[str, Any]:
        """Retrieve NAT destination rules from OPNsense.

        Returns
        -------
        dict[str, Any]
        Parsed nat destination rules payload returned by OPNsense APIs.


        """
        request_body: dict[str, Any] = {"current": 1, "sort": {}}
        response = await self._safe_dict_post(
            "/api/firewall/d_nat/search_rule", payload=request_body
        )
        # _LOGGER.debug("[get_nat_destination_rules] response: %s", response)
        rules: list = response.get("rows", [])
        # _LOGGER.debug("[get_nat_destination_rules] rules: %s", rules)
        rules_dict: dict[str, Any] = {}
        for rule in rules:
            if not isinstance(rule, MutableMapping):
                continue
            uuid = rule.get("uuid")
            if not uuid or "lockout" in str(uuid):
                continue  # skip lockout rules
            new_rule = dict(rule)
            new_rule["description"] = new_rule.pop("descr", "")
            new_rule["enabled"] = "1" if new_rule.pop("disabled", "0") == "0" else "0"
            rules_dict[str(new_rule["uuid"])] = new_rule
        _LOGGER.debug("[get_nat_destination_rules] rules_dict: %s", rules_dict)
        return rules_dict

    @_log_errors
    async def _get_nat_one_to_one_rules(self) -> dict[str, Any]:
        """Retrieve NAT one-to-one rules from OPNsense.

        Returns
        -------
        dict[str, Any]
        Parsed nat one to one rules payload returned by OPNsense APIs.


        """
        request_body: dict[str, Any] = {"current": 1, "sort": {}}
        response = await self._safe_dict_post(
            "/api/firewall/one_to_one/search_rule", payload=request_body
        )
        # _LOGGER.debug("[get_nat_one_to_one_rules] response: %s", response)
        rules: list = response.get("rows", [])
        # _LOGGER.debug("[get_nat_one_to_one_rules] rules: %s", rules)
        rules_dict: dict[str, Any] = {}
        for rule in rules:
            if not isinstance(rule, MutableMapping):
                continue
            uuid = rule.get("uuid")
            if not uuid or "lockout" in str(uuid):
                continue
            new_rule = dict(rule)
            # Add any transforms here
            rules_dict[str(new_rule["uuid"])] = new_rule
        _LOGGER.debug("[get_nat_one_to_one_rules] rules_dict: %s", rules_dict)
        return rules_dict

    @_log_errors
    async def _get_nat_source_rules(self) -> dict[str, Any]:
        """Retrieve NAT source rules from OPNsense.

        Returns
        -------
        dict[str, Any]
        Parsed nat source rules payload returned by OPNsense APIs.


        """
        request_body: dict[str, Any] = {"current": 1, "sort": {}}
        response = await self._safe_dict_post(
            "/api/firewall/source_nat/search_rule", payload=request_body
        )
        # _LOGGER.debug("[get_nat_source_rules] response: %s", response)
        rules: list = response.get("rows", [])
        # _LOGGER.debug("[get_nat_source_rules] rules: %s", rules)
        rules_dict: dict[str, Any] = {}
        for rule in rules:
            if not isinstance(rule, MutableMapping):
                continue
            uuid = rule.get("uuid")
            if not uuid or "lockout" in str(uuid):
                continue
            new_rule = dict(rule)
            # Add any transforms here
            rules_dict[str(new_rule["uuid"])] = new_rule
        _LOGGER.debug("[get_nat_source_rules] rules_dict: %s", rules_dict)
        return rules_dict

    @_log_errors
    async def _get_nat_npt_rules(self) -> dict[str, Any]:
        """Retrieve NAT NPT rules from OPNsense.

        Returns
        -------
        dict[str, Any]
        Parsed nat npt rules payload returned by OPNsense APIs.


        """
        request_body: dict[str, Any] = {"current": 1, "sort": {}}
        response = await self._safe_dict_post("/api/firewall/npt/search_rule", payload=request_body)
        # _LOGGER.debug("[get_nat_npt_rules] response: %s", response)
        rules: list = response.get("rows", [])
        # _LOGGER.debug("[get_nat_npt_rules] rules: %s", rules)
        rules_dict: dict[str, Any] = {}
        for rule in rules:
            if not isinstance(rule, MutableMapping):
                continue
            uuid = rule.get("uuid")
            if not uuid or "lockout" in str(uuid):
                continue
            new_rule = dict(rule)
            # Add any transforms here
            rules_dict[str(new_rule["uuid"])] = new_rule
        _LOGGER.debug("[get_nat_npt_rules] rules_dict: %s", rules_dict)
        return rules_dict

    async def toggle_firewall_rule(self, uuid: str, toggle_on_off: str | None = None) -> bool:
        """Toggle Firewall Rule on and off.

        Parameters
        ----------
        uuid : str
            Target object UUID returned by OPNsense.
        toggle_on_off : str | None
            Explicit toggle directive ("on"/"off"); uses API toggle when omitted. Defaults to None.

        Returns
        -------
        bool
        True when OPNsense reports the requested action succeeded; otherwise False.


        """
        payload: dict[str, Any] = {}
        url = f"/api/firewall/filter/toggle_rule/{uuid}"
        if toggle_on_off == "on":
            url = f"{url}/1"
        elif toggle_on_off == "off":
            url = f"{url}/0"
        response = await self._safe_dict_post(
            url,
            payload=payload,
        )
        _LOGGER.debug(
            "[toggle_firewall_rule] uuid: %s, action: %s, url: %s, response: %s",
            uuid,
            toggle_on_off,
            url,
            response,
        )
        if response.get("result") == "failed":
            return False

        apply_resp = await self._safe_dict_post("/api/firewall/filter/apply")
        if apply_resp.get("status", "").strip() != "OK":
            return False

        return True

    async def toggle_nat_rule(
        self, nat_rule_type: str, uuid: str, toggle_on_off: str | None = None
    ) -> bool:
        """Toggle NAT Rule on and off.

        Parameters
        ----------
        nat_rule_type : str
            NAT rule type endpoint segment to target.
        uuid : str
            Target object UUID returned by OPNsense.
        toggle_on_off : str | None
            Explicit toggle directive ("on"/"off"); uses API toggle when omitted. Defaults to None.

        Returns
        -------
        bool
        True when OPNsense reports the requested action succeeded; otherwise False.


        """
        payload: dict[str, Any] = {}
        url = f"/api/firewall/{nat_rule_type}/toggle_rule/{uuid}"
        # d_nat uses opposite logic for on/off
        if nat_rule_type == "d_nat" and toggle_on_off is not None:
            if toggle_on_off == "on":
                url = f"{url}/0"
            elif toggle_on_off == "off":
                url = f"{url}/1"
        elif toggle_on_off == "on":
            url = f"{url}/1"
        elif toggle_on_off == "off":
            url = f"{url}/0"
        response = await self._safe_dict_post(
            url,
            payload=payload,
        )
        _LOGGER.debug(
            "[toggle_nat_rule] uuid: %s, action: %s, url: %s, response: %s",
            uuid,
            toggle_on_off,
            url,
            response,
        )
        if response.get("result") == "failed":
            return False

        apply_resp = await self._safe_dict_post(f"/api/firewall/{nat_rule_type}/apply")
        if apply_resp.get("status", "").strip() != "OK":
            return False

        return True

    async def kill_states(self, ip_addr: str) -> MutableMapping[str, Any]:
        """Kill the active states of the IP address.

        Parameters
        ----------
        ip_addr : str
            IP address whose states should be terminated.

        Returns
        -------
        MutableMapping[str, Any]
        API response describing whether matching states were terminated.


        """
        payload: dict[str, Any] = {"filter": ip_addr}
        response = await self._safe_dict_post(
            "/api/diagnostics/firewall/kill_states/",
            payload=payload,
        )
        _LOGGER.debug("[kill_states] ip_addr: %s, response: %s", ip_addr, response)
        return {
            "success": bool(response.get("result", "") == "ok"),
            "dropped_states": response.get("dropped_states", 0),
        }

    async def toggle_alias(self, alias: str, toggle_on_off: str | None = None) -> bool:
        """Toggle alias on and off.

        Parameters
        ----------
        alias : str
            Firewall alias name to toggle.
        toggle_on_off : str | None
            Explicit toggle directive ("on"/"off"); uses API toggle when omitted. Defaults to None.

        Returns
        -------
        bool
        True when OPNsense reports the requested action succeeded; otherwise False.


        """
        if self._use_snake_case:
            alias_list_resp = await self._safe_dict_get("/api/firewall/alias/search_item")
        else:
            alias_list_resp = await self._safe_dict_get("/api/firewall/alias/searchItem")
        alias_list: list = alias_list_resp.get("rows", [])
        if not isinstance(alias_list, list):
            return False
        uuid: str | None = None
        for item in alias_list:
            if not isinstance(item, MutableMapping):
                continue
            if item.get("name") == alias:
                uuid = item.get("uuid")
                break
        if not uuid:
            return False
        payload: dict[str, Any] = {}
        if self._use_snake_case:
            url: str = f"/api/firewall/alias/toggle_item/{uuid}"
        else:
            url = f"/api/firewall/alias/toggleItem/{uuid}"
        if toggle_on_off == "on":
            url = f"{url}/1"
        elif toggle_on_off == "off":
            url = f"{url}/0"
        response = await self._safe_dict_post(
            url,
            payload=payload,
        )
        _LOGGER.debug(
            "[toggle_alias] alias: %s, uuid: %s, action: %s, url: %s, response: %s",
            alias,
            uuid,
            toggle_on_off,
            url,
            response,
        )
        if response.get("result") == "failed":
            return False

        set_resp = await self._safe_dict_post("/api/firewall/alias/set")
        if set_resp.get("result") != "saved":
            return False

        reconfigure_resp = await self._safe_dict_post("/api/firewall/alias/reconfigure")
        if reconfigure_resp.get("status") != "ok":
            return False

        return True
