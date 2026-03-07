"""Method definitions for OPNsenseClient (part 2)."""

from .client_shared import *

async def _safe_list_post(
    self, path: str, payload: MutableMapping[str, Any] | None = None
) -> list:
    """Fetch data from the given path, ensuring the result is a list.

    Parameters
    ----------
    path : str
        API endpoint path to call on the OPNsense host.
    payload : MutableMapping[str, Any] | None
        JSON payload body sent with the API request. Defaults to None.

    Returns
    -------
    list
    List payload from the POST request, or an empty list if the response is not a list.


    """
    result = await self._post(path=path, payload=payload)
    return result if isinstance(result, list) else []

async def _get_check(self, path: str) -> bool:
    """Check if the given API path is accessible.

    Parameters
    ----------
    path : str
        API endpoint path to call on the OPNsense host.

    Returns
    -------
    bool
    True when the endpoint responds successfully; otherwise False.


    """
    # /api/<module>/<controller>/<command>/[<param1>/[<param2>/...]]
    self._rest_api_query_count += 1
    url: str = f"{self._url}{path}"
    _LOGGER.debug("[get_check] url: %s", url)
    try:
        async with self._session.get(
            url,
            auth=aiohttp.BasicAuth(self._username, self._password),
            timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
            ssl=self._verify_ssl,
        ) as response:
            _LOGGER.debug("[get_check] Response %s: %s", response.status, response.reason)
            if response.ok:
                return True
            if response.status == 403:
                _LOGGER.error(
                    "Permission Error in get_check. Path: %s. Ensure the OPNsense user connected to HA has appropriate access. Recommend full admin access",
                    url,
                )
            return False
    except aiohttp.ClientError as e:
        _LOGGER.error("Client error. %s: %s", type(e).__name__, e)
        if self._initial:
            raise

    return False

@_log_errors
async def _filter_configure(self) -> None:
    """Apply pending firewall/NAT filter configuration changes."""
    script: str = r"""
filter_configure();
clear_subsystem_dirty('natconf');
clear_subsystem_dirty('filter');
"""
    await self._exec_php(script)

@_log_errors
async def get_device_unique_id(self, expected_id: str | None = None) -> str | None:
    """Get the OPNsense Unique ID.

    Parameters
    ----------
    expected_id : str | None
        Previously stored unique ID used to prefer a stable match. Defaults to None.

    Returns
    -------
    str | None
    Stable unique identifier derived from physical interface MAC addresses, or None when unavailable.


    """
    instances = await self._safe_list_get("/api/interfaces/overview/export")
    mac_addresses = {
        d.get("macaddr_hw").replace(":", "_").strip()
        for d in instances
        if d.get("is_physical") and d.get("macaddr_hw")
    }

    if not mac_addresses:
        _LOGGER.debug("[get_device_unique_id] device_unique_id: None")
        return None

    if expected_id and expected_id in mac_addresses:
        _LOGGER.debug(
            "[get_device_unique_id] device_unique_id (matched expected): %s", expected_id
        )
        return expected_id

    device_unique_id = sorted(mac_addresses)[0]
    _LOGGER.debug("[get_device_unique_id] device_unique_id (first): %s", device_unique_id)
    return device_unique_id

@_log_errors
async def get_system_info(self) -> MutableMapping[str, Any]:
    """Return the system info from OPNsense.

    Returns
    -------
    MutableMapping[str, Any]
    Normalized get system info data returned by OPNsense APIs.


    """
    system_info: MutableMapping[str, Any] = {}
    if self._use_snake_case:
        response = await self._safe_dict_get("/api/diagnostics/system/system_information")
    else:
        response = await self._safe_dict_get("/api/diagnostics/system/systemInformation")
    system_info["name"] = response.get("name", None)
    return system_info

@_log_errors
async def get_firmware_update_info(self) -> MutableMapping[str, Any]:
    """Get the details of available firmware updates.

    Returns
    -------
    MutableMapping[str, Any]
    Normalized get firmware update info data returned by OPNsense APIs.


    """
    status = await self._safe_dict_get("/api/core/firmware/status")

    # if error or too old trigger check (only if check is not already in progress)
    # {'status_msg': 'Firmware status check was aborted internally. Please try again.', 'status': 'error'}
    # error could be because data has not been refreshed at all OR an upgrade is currently in progress
    # _LOGGER.debug("[get_firmware_update_info] status: %s", status)

    if error_status := bool(status.get("status") == "error"):
        _LOGGER.debug("Last firmware status check returned an error")

    product_version = dict_get(status, "product.product_version")
    product_latest = dict_get(status, "product.product_latest")
    missing_data = False
    if (
        not product_version
        or not product_latest
        or not isinstance(dict_get(status, "product.product_check"), MutableMapping)
        or not dict_get(status, "product.product_check")
    ):
        _LOGGER.debug("Missing data in firmware status")
        missing_data = True

    update_needs_info = False
    try:
        if (
            awesomeversion.AwesomeVersion(product_latest)
            > awesomeversion.AwesomeVersion(product_version)
            and status.get("status_msg", "").strip()
            == "There are no updates available on the selected mirror."
        ):
            _LOGGER.debug("Update available but missing details")
            update_needs_info = True
    except (
        awesomeversion.exceptions.AwesomeVersionCompareException,
        TypeError,
        ValueError,
    ) as e:
        _LOGGER.debug("Error checking firmware versions. %s: %s", type(e).__name__, e)
        update_needs_info = True

    last_check_str = status.get("last_check")
    last_check_expired = True
    if last_check_str:
        try:
            last_check_dt = parse(last_check_str, tzinfos=AMBIGUOUS_TZINFOS)
            if last_check_dt.tzinfo is None:
                last_check_dt = last_check_dt.replace(
                    tzinfo=timezone(datetime.now().astimezone().utcoffset() or timedelta())
                )
            last_check_expired = (
                datetime.now().astimezone() - last_check_dt
            ) > FIRMWARE_CHECK_INTERVAL
            if last_check_expired:
                _LOGGER.debug("Firmware status last check > %s", FIRMWARE_CHECK_INTERVAL)
        except (ValueError, TypeError, ParserError, UnknownTimezoneWarning) as e:
            _LOGGER.debug(
                "Error getting firmware status last check. %s: %s", type(e).__name__, e
            )
    else:
        _LOGGER.debug("Firmware status last check is missing")

    should_trigger_check = error_status or last_check_expired
    if missing_data and not should_trigger_check:
        _LOGGER.debug(
            "Firmware status missing data but last check is recent; delaying an immediate re-check"
        )
    if update_needs_info and not should_trigger_check:
        _LOGGER.debug(
            "Firmware update info needs more detail but last check is recent; will wait until the next scheduled trigger"
        )
    if should_trigger_check:
        _LOGGER.info("Triggering firmware check")
        await self._post("/api/core/firmware/check")

    return status

@_log_errors
async def upgrade_firmware(self, type: str = "update") -> MutableMapping[str, Any] | None:
    """Trigger a firmware upgrade.

    Parameters
    ----------
    type : str
        Firmware upgrade type (for example update or upgrade). Defaults to 'update'.

    Returns
    -------
    MutableMapping[str, Any] | None
    True when OPNsense reports the requested action succeeded; otherwise False.


    """
    # minor updates of the same opnsense version
    if type == "update":
        # can watch the progress on the 'Updates' tab in the UI
        return await self._safe_dict_post("/api/core/firmware/update")

    # major updates to a new opnsense version
    if type == "upgrade":
        # can watch the progress on the 'Updates' tab in the UI
        return await self._safe_dict_post("/api/core/firmware/upgrade")
    return None

@_log_errors
async def upgrade_status(self) -> MutableMapping[str, Any]:
    """Return the status of the firmware upgrade.

    Returns
    -------
    MutableMapping[str, Any]
    True when OPNsense reports the requested action succeeded; otherwise False.


    """
    return await self._safe_dict_post("/api/core/firmware/upgradestatus")

@_log_errors
async def firmware_changelog(self, version: str) -> MutableMapping[str, Any]:
    """Return the changelog for the firmware upgrade.

    Parameters
    ----------
    version : str
        Firmware version string to fetch a changelog for.

    Returns
    -------
    MutableMapping[str, Any]
    Result produced by this method.


    """
    return await self._safe_dict_post(f"/api/core/firmware/changelog/{version}")

@_log_errors
async def get_config(self) -> MutableMapping[str, Any]:
    """XMLRPC call to return all the config settings.

    Returns
    -------
    MutableMapping[str, Any]
    Normalized get config data returned by OPNsense APIs.


    """
    script: str = r"""
global $config;

$toreturn = [
  "data" => $config,
];
"""
    response: MutableMapping[str, Any] = await self._exec_php(script)
    if not isinstance(response, MutableMapping):
        return {}
    ret_data = response.get("data", {})
    if not isinstance(ret_data, MutableMapping):
        return {}
    return ret_data

@_log_errors
async def enable_filter_rule_by_created_time_legacy(self, created_time: str) -> None:
    """Enable a filter rule.

    Parameters
    ----------
    created_time : str
        Rule creation timestamp used as a legacy unique identifier.

    """
    config = await self.get_config()
    for rule in config["filter"]["rule"]:
        if "created" not in rule:
            continue
        if "time" not in rule["created"]:
            continue
        if rule["created"]["time"] != created_time:
            continue

        if "disabled" in rule:
            del rule["disabled"]
            await self._restore_config_section("filter", config["filter"])
            await self._filter_configure()

@_log_errors
async def disable_filter_rule_by_created_time_legacy(self, created_time: str) -> None:
    """Disable a filter rule.

    Parameters
    ----------
    created_time : str
        Rule creation timestamp used as a legacy unique identifier.

    """
    config: MutableMapping[str, Any] = await self.get_config()

    for rule in config.get("filter", {}).get("rule", []):
        if "created" not in rule:
            continue
        if "time" not in rule["created"]:
            continue
        if rule["created"]["time"] != created_time:
            continue

        if "disabled" not in rule:
            rule["disabled"] = "1"
            await self._restore_config_section("filter", config["filter"])
            await self._filter_configure()

@_log_errors
async def enable_nat_port_forward_rule_by_created_time_legacy(self, created_time: str) -> None:
    """Enable a NAT Port Forward rule.

    Parameters
    ----------
    created_time : str
        Rule creation timestamp used as a legacy unique identifier.

    """
    config: MutableMapping[str, Any] = await self.get_config()
    for rule in config.get("nat", {}).get("rule", []):
        if "created" not in rule:
            continue
        if "time" not in rule["created"]:
            continue
        if rule["created"]["time"] != created_time:
            continue

        if "disabled" in rule:
            del rule["disabled"]
            await self._restore_config_section("nat", config["nat"])
            await self._filter_configure()

@_log_errors
async def disable_nat_port_forward_rule_by_created_time_legacy(self, created_time: str) -> None:
    """Disable a NAT Port Forward rule.

    Parameters
    ----------
    created_time : str
        Rule creation timestamp used as a legacy unique identifier.

    """
    config: MutableMapping[str, Any] = await self.get_config()
    for rule in config.get("nat", {}).get("rule", []):
        if "created" not in rule:
            continue
        if "time" not in rule["created"]:
            continue
        if rule["created"]["time"] != created_time:
            continue

        if "disabled" not in rule:
            rule["disabled"] = "1"
            await self._restore_config_section("nat", config["nat"])
            await self._filter_configure()

@_log_errors
async def enable_nat_outbound_rule_by_created_time_legacy(self, created_time: str) -> None:
    """Enable NAT Outbound rule.

    Parameters
    ----------
    created_time : str
        Rule creation timestamp used as a legacy unique identifier.

    """
    config: MutableMapping[str, Any] = await self.get_config()
    for rule in config.get("nat", {}).get("outbound", {}).get("rule", []):
        if "created" not in rule:
            continue
        if "time" not in rule["created"]:
            continue
        if rule["created"]["time"] != created_time:
            continue

        if "disabled" in rule:
            del rule["disabled"]
            await self._restore_config_section("nat", config["nat"])
            await self._filter_configure()

@_log_errors
async def disable_nat_outbound_rule_by_created_time_legacy(self, created_time: str) -> None:
    """Disable NAT Outbound Rule.

    Parameters
    ----------
    created_time : str
        Rule creation timestamp used as a legacy unique identifier.

    """
    config: MutableMapping[str, Any] = await self.get_config()
    for rule in config.get("nat", {}).get("outbound", {}).get("rule", []):
        if "created" not in rule or "time" not in rule["created"]:
            continue
        if rule["created"]["time"] != created_time:
            continue

        if "disabled" not in rule:
            rule["disabled"] = "1"
            await self._restore_config_section("nat", config["nat"])
            await self._filter_configure()

@_log_errors
async def get_firewall(self) -> dict[str, Any]:
    """Retrieve all firewall and NAT rules from OPNsense.

    Returns
    -------
    dict[str, Any]
    Normalized get firewall data returned by OPNsense APIs.


    """
    if self._firmware_version is None:
        await self.get_host_firmware_version()

    try:
        if awesomeversion.AwesomeVersion(
            self._firmware_version
        ) < awesomeversion.AwesomeVersion("26.1.1"):
            _LOGGER.debug("Using legacy plugin for firewall filters for OPNsense < 26.1.1")
            return {"config": await self.get_config()}
    except (awesomeversion.exceptions.AwesomeVersionCompareException, TypeError, ValueError):
        _LOGGER.warning("Error comparing firmware version. Skipping get_firewall.")
        return {}
    firewall: dict[str, Any] = {"nat": {}}
    if await self.is_plugin_installed():
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
    Normalized  get firewall rules data returned by OPNsense APIs.


    """
    request_body: MutableMapping[str, Any] = {"current": 1, "sort": {}}
    response = await self._safe_dict_post(
        "/api/firewall/filter/search_rule", payload=request_body
    )
    # _LOGGER.debug("[get_firewall_rules] response: %s", response)
    rules: list = response.get("rows", [])
    # _LOGGER.debug("[get_firewall_rules] rules: %s", rules)
    rules_dict: dict[str, Any] = {}
    for rule in rules:
        if not rule.get("uuid") or "lockout" in rule.get("uuid"):
            continue
        new_rule = rule.copy()
        # Add any transforms here
        rules_dict[new_rule["uuid"]] = new_rule
    _LOGGER.debug("[get_firewall_rules] rules_dict: %s", rules_dict)
    return rules_dict

@_log_errors
async def _get_nat_destination_rules(self) -> dict[str, Any]:
    """Retrieve NAT destination rules from OPNsense.

    Returns
    -------
    dict[str, Any]
    Normalized  get nat destination rules data returned by OPNsense APIs.


    """
    request_body: MutableMapping[str, Any] = {"current": 1, "sort": {}}
    response = await self._safe_dict_post(
        "/api/firewall/d_nat/search_rule", payload=request_body
    )
    # _LOGGER.debug("[get_nat_destination_rules] response: %s", response)
    rules: list = response.get("rows", [])
    # _LOGGER.debug("[get_nat_destination_rules] rules: %s", rules)
    rules_dict: dict[str, Any] = {}
    for rule in rules:
        if not rule.get("uuid") or "lockout" in rule.get("uuid"):
            continue  # skip lockout rules
        new_rule = rule.copy()
        new_rule["description"] = new_rule.pop("descr", "")
        new_rule["enabled"] = "1" if new_rule.pop("disabled", "0") == "0" else "0"
        rules_dict[new_rule["uuid"]] = new_rule
    _LOGGER.debug("[get_nat_destination_rules] rules_dict: %s", rules_dict)
    return rules_dict

@_log_errors
async def _get_nat_one_to_one_rules(self) -> dict[str, Any]:
    """Retrieve NAT one-to-one rules from OPNsense.

    Returns
    -------
    dict[str, Any]
    Normalized  get nat one to one rules data returned by OPNsense APIs.


    """
    request_body: MutableMapping[str, Any] = {"current": 1, "sort": {}}
    response = await self._safe_dict_post(
        "/api/firewall/one_to_one/search_rule", payload=request_body
    )
    # _LOGGER.debug("[get_nat_one_to_one_rules] response: %s", response)
    rules: list = response.get("rows", [])
    # _LOGGER.debug("[get_nat_one_to_one_rules] rules: %s", rules)
    rules_dict: dict[str, Any] = {}
    for rule in rules:
        if not rule.get("uuid") or "lockout" in rule.get("uuid"):
            continue
        new_rule = rule.copy()
        # Add any transforms here
        rules_dict[new_rule["uuid"]] = new_rule
    _LOGGER.debug("[get_nat_one_to_one_rules] rules_dict: %s", rules_dict)
    return rules_dict

@_log_errors
async def _get_nat_source_rules(self) -> dict[str, Any]:
    """Retrieve NAT source rules from OPNsense.

    Returns
    -------
    dict[str, Any]
    Normalized  get nat source rules data returned by OPNsense APIs.


    """
    request_body: MutableMapping[str, Any] = {"current": 1, "sort": {}}
    response = await self._safe_dict_post(
        "/api/firewall/source_nat/search_rule", payload=request_body
    )
    # _LOGGER.debug("[get_nat_source_rules] response: %s", response)
    rules: list = response.get("rows", [])
    # _LOGGER.debug("[get_nat_source_rules] rules: %s", rules)
    rules_dict: dict[str, Any] = {}
    for rule in rules:
        if not rule.get("uuid") or "lockout" in rule.get("uuid"):
            continue
        new_rule = rule.copy()
        # Add any transforms here
        rules_dict[new_rule["uuid"]] = new_rule
    _LOGGER.debug("[get_nat_source_rules] rules_dict: %s", rules_dict)
    return rules_dict

@_log_errors
async def _get_nat_npt_rules(self) -> dict[str, Any]:
    """Retrieve NAT NPT rules from OPNsense.

    Returns
    -------
    dict[str, Any]
    Normalized  get nat npt rules data returned by OPNsense APIs.


    """
    request_body: MutableMapping[str, Any] = {"current": 1, "sort": {}}
    response = await self._safe_dict_post("/api/firewall/npt/search_rule", payload=request_body)
    # _LOGGER.debug("[get_nat_npt_rules] response: %s", response)
    rules: list = response.get("rows", [])
    # _LOGGER.debug("[get_nat_npt_rules] rules: %s", rules)
    rules_dict: dict[str, Any] = {}
    for rule in rules:
        if not rule.get("uuid") or "lockout" in rule.get("uuid"):
            continue
        new_rule = rule.copy()
        # Add any transforms here
        rules_dict[new_rule["uuid"]] = new_rule
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
    payload: MutableMapping[str, Any] = {}
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
    payload: MutableMapping[str, Any] = {}
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

__all__ = [
    "_safe_list_post",
    "_get_check",
    "_filter_configure",
    "get_device_unique_id",
    "get_system_info",
    "get_firmware_update_info",
    "upgrade_firmware",
    "upgrade_status",
    "firmware_changelog",
    "get_config",
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
]
