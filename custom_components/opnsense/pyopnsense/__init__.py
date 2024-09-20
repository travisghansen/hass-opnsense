from abc import ABC
import asyncio
from collections.abc import Mapping
from datetime import datetime, timedelta
import inspect
import json
import logging
import re
import socket
import ssl
import time
from typing import Any
from urllib.parse import quote_plus, urlparse
import xmlrpc.client
import zoneinfo

import aiohttp
import awesomeversion
from dateutil.parser import parse

# value to set as the socket timeout
DEFAULT_TIMEOUT = 60

_LOGGER: logging.Logger = logging.getLogger(__name__)

tzinfos: Mapping[str, Any] = {}
for tname in zoneinfo.available_timezones():
    tzinfos[tname] = zoneinfo.ZoneInfo(tname)


def dict_get(data: Mapping[str, Any], path: str, default=None):
    pathList = re.split(r"\.", path, flags=re.IGNORECASE)
    result = data
    for key in pathList:
        try:
            key = int(key) if key.isnumeric() else key
            result = result[key]
        except:
            result = default
            break

    return result


class OPNsenseClient(ABC):
    """OPNsense Client"""

    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        session: aiohttp.ClientSession,
        opts: Mapping[str, Any] = None,
    ) -> None:
        """OPNsense Client initializer."""

        self._username: str = username
        self._password: str = password

        self._opts: Mapping[str, Any] = opts or {}
        self._verify_ssl: bool = self._opts.get("verify_ssl", True)
        parts = urlparse(url.rstrip("/"))
        self._url: str = f"{parts.scheme}://{parts.netloc}"
        self._xmlrpc_url: str = (
            f"{parts.scheme}://{quote_plus(username)}:{quote_plus(password)}@{parts.netloc}"
        )
        self._scheme: str = parts.scheme
        self._session: aiohttp.ClientSession = session
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)

    def _xmlrpc_timeout(func):
        async def inner(self, *args, **kwargs):
            response = None
            # timout applies to each recv() call, not the whole request
            default_timeout = socket.getdefaulttimeout()
            try:
                socket.setdefaulttimeout(DEFAULT_TIMEOUT)
                response = await func(self, *args, **kwargs)
            finally:
                socket.setdefaulttimeout(default_timeout)
            return response

        return inner

    def _log_errors(func):
        async def inner(self, *args, **kwargs):
            try:
                return await func(self, *args, **kwargs)
            except asyncio.CancelledError as e:
                raise e
            except BaseException as e:
                _LOGGER.error(
                    f"Error in {func.__name__.strip('_')}. {e.__class__.__qualname__}: {e}"
                )
                # raise err

        return inner

    # https://stackoverflow.com/questions/64983392/python-multiple-patch-gives-http-client-cannotsendrequest-request-sent
    def _get_proxy(self) -> xmlrpc.client.ServerProxy:
        # https://docs.python.org/3/library/xmlrpc.client.html#module-xmlrpc.client
        # https://stackoverflow.com/questions/30461969/disable-default-certificate-verification-in-python-2-7-9
        context = None

        if self._scheme == "https" and not self._verify_ssl:
            context = ssl._create_unverified_context()

        # set to True if necessary during development
        verbose = False

        proxy = xmlrpc.client.ServerProxy(
            f"{self._xmlrpc_url}/xmlrpc.php", context=context, verbose=verbose
        )
        return proxy

    # @_xmlrpc_timeout
    async def _get_config_section(self, section) -> Mapping[str, Any]:
        config: Mapping[str, Any] = await self.get_config()
        if config is None or not isinstance(config, Mapping):
            _LOGGER.error("Invalid data returned from get_config_section")
            return {}
        return config.get(section, {})

    @_xmlrpc_timeout
    async def _restore_config_section(self, section_name, data):
        params: Mapping[str, Any] = {section_name: data}
        response = await self._loop.run_in_executor(
            None, self._get_proxy().opnsense.restore_config_section, params
        )
        return response

    @_xmlrpc_timeout
    async def _exec_php(self, script) -> Mapping[str, Any]:
        script: str = (
            r"""
ini_set('display_errors', 0);

{}

// wrapping this in json_encode and then unwrapping in python prevents funny XMLRPC NULL encoding errors
// https://github.com/travisghansen/hass-pfsense/issues/35
$toreturn_real = $toreturn;
$toreturn = [];
$toreturn["real"] = json_encode($toreturn_real);
""".format(
                script
            )
        )
        try:
            response = await self._loop.run_in_executor(
                None, self._get_proxy().opnsense.exec_php, script
            )
            response_json = json.loads(response["real"])
            return response_json
        except TypeError as e:
            _LOGGER.error(
                f"Invalid data returned from exec_php for {inspect.currentframe().f_back.f_code.co_qualname.strip('_')}. {e.__class__.__qualname__}: {e}. Ensure the OPNsense user connected to HA either has full Admin access or specifically has the 'XMLRPC Library' privilege."
            )
            return {}
        except xmlrpc.client.Fault as e:
            _LOGGER.error(
                f"Error running exec_php script for {inspect.currentframe().f_back.f_code.co_qualname.strip('_')}. {e.__class__.__qualname__}: {e}. Ensure the 'os-homeassistant-maxit' plugin has been installed on OPNsense ."
            )
            return {}

    @_log_errors
    async def get_host_firmware_version(self) -> None | str:
        firmware_info: Mapping[str, Any] | list = await self._get(
            "/api/core/firmware/status"
        )
        if not isinstance(firmware_info, Mapping):
            return None
        firmware: str | None = firmware_info.get("product_version", None)
        _LOGGER.debug(f"[get_host_firmware_version] firmware: {firmware}")
        return firmware

    @_xmlrpc_timeout
    @_log_errors
    async def _list_services(self):
        response = await self._loop.run_in_executor(
            None, self._get_proxy().opnsense.list_services
        )
        if response is None or not isinstance(response, Mapping):
            _LOGGER.error("Invalid data returned from list_services")
            return {}
        return response

    @_xmlrpc_timeout
    @_log_errors
    async def _start_service(self, params):
        return await self._loop.run_in_executor(
            None, self._get_proxy().opnsense.start_services, params
        )

    @_xmlrpc_timeout
    @_log_errors
    async def _stop_service(self, params):
        return await self._loop.run_in_executor(
            None, self._get_proxy().opnsense.stop_services, params
        )

    @_xmlrpc_timeout
    @_log_errors
    async def _restart_service(self, params):
        return await self._loop.run_in_executor(
            None, self._get_proxy().opnsense.restart_services, params
        )

    async def _get_from_stream(self, path: str) -> Mapping[str, Any] | list:
        url: str = f"{self._url}{path}"
        _LOGGER.debug(f"[get_from_stream] url: {url}")
        try:
            async with self._session.get(
                url,
                auth=aiohttp.BasicAuth(self._username, self._password),
                timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
                ssl=self._verify_ssl,
            ) as response:
                _LOGGER.debug(
                    f"[get_from_stream] Response {response.status}: {response.reason}"
                )

                if response.ok:
                    buffer = ""
                    message_count = 0

                    async for chunk in response.content.iter_chunked(1024):
                        buffer += chunk.decode("utf-8")

                        if "\n\n" in buffer:
                            message, buffer = buffer.split("\n\n", 1)
                            lines = message.splitlines()

                            for line in lines:
                                if line.startswith("data:"):
                                    message_count += 1
                                    if message_count == 2:
                                        response_str: str = line[len("data:") :].strip()
                                        response_json: Mapping[str, Any] | list = (
                                            json.loads(response_str)
                                        )

                                        _LOGGER.debug(
                                            f"[get_from_stream] response_json ({type(response_json).__name__}): {response_json}"
                                        )
                                        return response_json  # Exit after processing the second message

                elif response.status == 403:
                    _LOGGER.error(
                        f"Permission Error in {inspect.currentframe().f_back.f_code.co_qualname.strip('_')}. Path: {url}. Ensure the OPNsense user connected to HA has full Admin access."
                    )
                else:
                    _LOGGER.error(
                        f"Error in {inspect.currentframe().f_back.f_code.co_qualname.strip('_')}. Path: {url}. Response {response.status}: {response.reason}"
                    )
        except aiohttp.ClientError as e:
            _LOGGER.error(f"Client error: {str(e)}")

        return {}

    async def _get(self, path: str) -> Mapping[str, Any] | list:
        # /api/<module>/<controller>/<command>/[<param1>/[<param2>/...]]
        url: str = f"{self._url}{path}"
        _LOGGER.debug(f"[get] url: {url}")
        try:
            async with self._session.get(
                url,
                auth=aiohttp.BasicAuth(self._username, self._password),
                timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
                ssl=self._verify_ssl,
            ) as response:
                _LOGGER.debug(f"[get] Response {response.status}: {response.reason}")
                if response.ok:
                    response_json: Mapping[str, Any] | list = await response.json(
                        content_type=None
                    )
                    return response_json
                if response.status == 403:
                    _LOGGER.error(
                        f"Permission Error in {inspect.currentframe().f_back.f_code.co_qualname.strip('_')}. Path: {url}. Ensure the OPNsense user connected to HA has full Admin access."
                    )
                else:
                    _LOGGER.error(
                        f"Error in {inspect.currentframe().f_back.f_code.co_qualname.strip('_')}. Path: {url}. Response {response.status}: {response.reason}"
                    )
        except aiohttp.ClientError as e:
            _LOGGER.error(f"Client error: {str(e)}")

        return {}

    async def _post(self, path: str, payload=None) -> Mapping[str, Any] | list:
        # /api/<module>/<controller>/<command>/[<param1>/[<param2>/...]]
        url: str = f"{self._url}{path}"
        _LOGGER.debug(f"[post] url: {url}")
        _LOGGER.debug(f"[post] payload: {payload}")
        try:
            async with self._session.post(
                url,
                json=payload,
                auth=aiohttp.BasicAuth(self._username, self._password),
                timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
                ssl=self._verify_ssl,
            ) as response:
                _LOGGER.debug(f"[post] Response {response.status}: {response.reason}")
                if response.ok:
                    response_json: Mapping[str, Any] | list = await response.json(
                        content_type=None
                    )
                    return response_json
                elif response.status == 403:
                    _LOGGER.error(
                        f"Permission Error in {inspect.currentframe().f_back.f_code.co_qualname.strip('_')}. Path: {url}. Ensure the OPNsense user connected to HA has full Admin access."
                    )
                else:
                    _LOGGER.error(
                        f"Error in {inspect.currentframe().f_back.f_code.co_qualname.strip('_')}. Path: {url}. Response {response.status}: {response.reason}"
                    )
        except aiohttp.ClientError as e:
            _LOGGER.error(f"Client error: {str(e)}")

        return {}

    @_log_errors
    async def _filter_configure(self) -> None:
        script: str = r"""
filter_configure();
clear_subsystem_dirty('natconf');
clear_subsystem_dirty('filter');
"""
        await self._exec_php(script)

    @_log_errors
    async def _get_device_id(self) -> str | None:
        script: str = r"""
$file = "/conf/hassid";
$id;
if (!file_exists($file)) {
    $id = bin2hex(openssl_random_pseudo_bytes(10));
    file_put_contents($file, $id);
} else {
    $id = file_get_contents($file);
}
$toreturn = [
  "data" => $id,
];
"""
        response: Mapping[str, Any] = await self._exec_php(script)
        if response is None or not isinstance(response, Mapping):
            _LOGGER.error("Invalid data returned from get_device_id")
            return {}
        return response.get("data", None)

    @_log_errors
    async def get_system_info(self) -> Mapping[str, Any]:
        # TODO: add bios details here
        firmware: str | None = await self.get_host_firmware_version()
        try:
            if awesomeversion.AwesomeVersion(firmware) < awesomeversion.AwesomeVersion(
                "24.7"
            ):
                _LOGGER.info(f"Using legacy get_system_info method for OPNsense < 24.7")
                return await self._get_system_info_legacy()
        except awesomeversion.exceptions.AwesomeVersionCompareException:
            pass
        system_info: Mapping[str, Any] = {}
        system_info["device_id"] = await self._get_device_id()
        response: Mapping[str, Any] | list = await self._get(
            "/api/diagnostics/system/systemInformation"
        )
        system_info["name"] = response.get("name", None)
        return system_info

    @_log_errors
    async def _get_system_info_legacy(self) -> Mapping[str, Any]:
        # TODO: add bios details here
        script: str = r"""
global $config;

$file = "/conf/hassid";
$id;
if (!file_exists($file)) {
    $id = bin2hex(openssl_random_pseudo_bytes(10));
    file_put_contents($file, $id);
} else {
    $id = file_get_contents($file);
}

$toreturn = [
  "hostname" => $config["system"]["hostname"],
  "domain" => $config["system"]["domain"],
  "device_id" => $id,
];
"""
        response: Mapping[str, Any] = await self._exec_php(script)
        response["name"] = f"{response.pop('hostname','')}.{response.pop('domain','')}"
        return response

    @_log_errors
    async def get_firmware_update_info(self):
        current_time = time.time()
        refresh_triggered = False
        refresh_interval = 2 * 60 * 60  # 2 hours

        status = None
        upgradestatus = None

        # GET /api/core/firmware/status
        status = await self._get("/api/core/firmware/status")
        # print(status)

        # if error or too old trigger check (only if check is not already in progress)
        # {'status_msg': 'Firmware status check was aborted internally. Please try again.', 'status': 'error'}
        # error could be because data has not been refreshed at all OR an upgrade is currently in progress
        if (
            status["status"] == "error"
            or "last_check" not in status.keys()
            or not isinstance(dict_get(status, "product.product_check"), dict)
            or dict_get(status, "product.product_check") is None
            or dict_get(status, "product.product_check") == ""
        ):
            await self._post("/api/core/firmware/check")
            refresh_triggered = True
        elif "last_check" in status.keys():
            # "last_check": "Wed Dec 22 16:56:20 UTC 2021"
            # "last_check": "Mon Jan 16 00:08:28 CET 2023"
            # "last_check": "Sun Jan 15 22:05:55 UTC 2023"
            last_check = status["last_check"]
            last_check_timestamp = parse(last_check, tzinfos=tzinfos).timestamp()

            # https://bugs.python.org/issue22377
            # format = "%a %b %d %H:%M:%S %Z %Y"
            # last_check_timestamp = int(
            #    calendar.timegm(time.strptime(last_check, format))
            # )

            stale = (current_time - last_check_timestamp) > refresh_interval
            # stale = True
            if stale:
                upgradestatus = await self._get("/api/core/firmware/upgradestatus")
                # print(upgradestatus)
                if "status" in upgradestatus.keys():
                    # status = running (package refresh in progress OR upgrade in progress)
                    # status = done (refresh/upgrade done)
                    if upgradestatus["status"] == "done":
                        # tigger repo update
                        # should this be /api/core/firmware/upgrade
                        check = await self._post("/api/core/firmware/check")
                        # print(check)
                        refresh_triggered = True
                    else:
                        # print("upgrade already running")
                        pass

        wait_for_refresh = False
        if refresh_triggered and wait_for_refresh:
            # print("refresh triggered, waiting for it to finish")
            pass

        return status

    @_log_errors
    async def upgrade_firmware(self, type="update"):
        # minor updates of the same opnsense version
        if type == "update":
            # can watch the progress on the 'Updates' tab in the UI
            return await self._post("/api/core/firmware/update")

        # major updates to a new opnsense version
        if type == "upgrade":
            # can watch the progress on the 'Updates' tab in the UI
            return await self._post("/api/core/firmware/upgrade")

    @_log_errors
    async def upgrade_status(self):
        return await self._post("/api/core/firmware/upgradestatus")

    @_log_errors
    async def firmware_changelog(self, version):
        return await self._post("/api/core/firmware/changelog/" + version)

    @_log_errors
    async def get_config(self) -> Mapping[str, Any]:
        script: str = r"""
global $config;

$toreturn = [
  "data" => $config,
];
"""
        response: Mapping[str, Any] = await self._exec_php(script)
        if response is None or not isinstance(response, Mapping):
            return {}
        return response.get("data", {})

    @_log_errors
    async def get_interfaces(self) -> Mapping[str, Any]:
        return await self._get_config_section("interfaces")

    @_log_errors
    async def get_interface(self, interface) -> Mapping[str, Any]:
        interfaces: Mapping[str, Any] = await self.get_interfaces()
        return interfaces.get(interface, {})

    @_log_errors
    async def get_interface_by_description(self, interface):
        interfaces: Mapping[str, Any] = await self.get_interfaces()
        for i, i_interface in enumerate(interfaces.keys()):
            if "descr" not in interfaces[i_interface]:
                continue

            if interfaces[i_interface]["descr"] is None:
                continue

            if interfaces[i_interface]["descr"] == interface:
                return interfaces[i_interface]

    @_log_errors
    async def enable_filter_rule_by_created_time(self, created_time) -> None:
        config = await self.get_config()
        for rule in config["filter"]["rule"]:
            if "created" not in rule.keys():
                continue
            if "time" not in rule["created"].keys():
                continue
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" in rule.keys():
                del rule["disabled"]
                await self._restore_config_section("filter", config["filter"])
                await self._filter_configure()

    @_log_errors
    async def disable_filter_rule_by_created_time(self, created_time) -> None:
        config: Mapping[str, Any] = await self.get_config()

        for rule in config.get("filter", {}).get("rule", []):
            if "created" not in rule.keys():
                continue
            if "time" not in rule["created"].keys():
                continue
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" not in rule.keys():
                rule["disabled"] = "1"
                await self._restore_config_section("filter", config["filter"])
                await self._filter_configure()

    # use created_time as a unique_id since none other exists
    @_log_errors
    async def enable_nat_port_forward_rule_by_created_time(self, created_time) -> None:
        config: Mapping[str, Any] = await self.get_config()
        for rule in config.get("nat", {}).get("rule", []):
            if "created" not in rule.keys():
                continue
            if "time" not in rule["created"].keys():
                continue
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" in rule.keys():
                del rule["disabled"]
                await self._restore_config_section("nat", config["nat"])
                await self._filter_configure()

    # use created_time as a unique_id since none other exists
    @_log_errors
    async def disable_nat_port_forward_rule_by_created_time(self, created_time) -> None:
        config: Mapping[str, Any] = await self.get_config()
        for rule in config.get("nat", {}).get("rule", []):
            if "created" not in rule.keys():
                continue
            if "time" not in rule["created"].keys():
                continue
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" not in rule.keys():
                rule["disabled"] = "1"
                await self._restore_config_section("nat", config["nat"])
                await self._filter_configure()

    # use created_time as a unique_id since none other exists
    @_log_errors
    async def enable_nat_outbound_rule_by_created_time(self, created_time) -> None:
        config: Mapping[str, Any] = await self.get_config()
        for rule in config.get("nat", {}).get("outbound", {}).get("rule", []):
            if "created" not in rule.keys():
                continue
            if "time" not in rule["created"].keys():
                continue
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" in rule.keys():
                del rule["disabled"]
                await self._restore_config_section("nat", config["nat"])
                await self._filter_configure()

    # use created_time as a unique_id since none other exists
    @_log_errors
    async def disable_nat_outbound_rule_by_created_time(self, created_time) -> None:
        config: Mapping[str, Any] = await self.get_config()
        for rule in config.get("nat", {}).get("outbound", {}).get("rule", []):
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" not in rule.keys():
                rule["disabled"] = "1"
                await self._restore_config_section("nat", config["nat"])
                await self._filter_configure()

    @_log_errors
    async def get_configured_interface_descriptions(self) -> Mapping[str, Any]:
        script: str = r"""
$toreturn = [
  "data" => get_configured_interface_with_descr(),
];
"""
        response: Mapping[str, Any] = await self._exec_php(script)
        if response is None or not isinstance(response, Mapping):
            _LOGGER.error(
                "Invalid data returned from get_configured_interface_descriptions"
            )
            return {}
        return response.get("data", {})

    @_log_errors
    async def get_gateways(self) -> Mapping[str, Any]:
        # {'GW_WAN': {'interface': '<if>', 'gateway': '<ip>', 'name': 'GW_WAN', 'weight': '1', 'ipprotocol': 'inet', 'interval': '', 'descr': 'Interface wan Gateway', 'monitor': '<ip>', 'friendlyiface': 'wan', 'friendlyifdescr': 'WAN', 'isdefaultgw': True, 'attribute': 0, 'tiername': 'Default (IPv4)'}}
        script: str = r"""
$gateways = new \OPNsense\Routing\Gateways(legacy_interfaces_details());
//$default_gwv4 = $gateways->getDefaultGW(return_down_gateways(), "inet");
//$default_gwv6 = $gateways->getDefaultGW(return_down_gateways(), "inet6");
$a_gateways = array_values($gateways->gatewaysIndexedByName(true, false, true));

$result = [];
if (is_iterable($a_gateways)) {
    foreach ($a_gateways as $g) {
        $result[$g["name"]] = $g;
    }
}

$toreturn = [
  "data" => $result,
];
"""
        response: Mapping[str, Any] = await self._exec_php(script)
        if response is None or not isinstance(response, Mapping):
            _LOGGER.error("Invalid data returned from get_gateways")
            return {}
        return response.get("data", {})

    @_log_errors
    async def get_gateway(self, gateway):
        gateways = await self.get_gateways()
        for g in gateways.keys():
            if g == gateway:
                return gateways[g]

    @_log_errors
    async def get_gateways_status(self) -> Mapping[str, Any]:
        # {'GW_WAN': {'monitorip': '<ip>', 'srcip': '<ip>', 'name': 'GW_WAN', 'delay': '0.387ms', 'stddev': '0.097ms', 'loss': '0.0%', 'status': 'online', 'substatus': 'none'}}
        script: str = r"""
$toreturn = [
  // function return_gateways_status($byname = false, $gways = false)
  "data" => return_gateways_status(true),
];
"""
        response: Mapping[str, Any] = await self._exec_php(script)
        if response is None or not isinstance(response, Mapping):
            _LOGGER.error("Invalid data returned from get_gateways_status")
            return {}
        for gateway_name, gateway in response.get("data", {}).items():
            if gateway["status"] == "none":
                gateway["status"] = "online"
        return response.get("data", {})

    @_log_errors
    async def get_gateway_status(self, gateway):
        gateways = await self.get_gateways_status()
        for g in gateways.keys():
            if g == gateway:
                if gateways[g]["status"] == "none":
                    gateways[g]["status"] = "online"
                return gateways[g]

    @_log_errors
    async def get_arp_table(self, resolve_hostnames=False) -> Mapping[str, Any]:
        # [{'hostname': '?', 'ip-address': '<ip>', 'mac-address': '<mac>', 'interface': 'em0', 'expires': 1199, 'type': 'ethernet'}, ...]
        request_body: Mapping[str, Any] = {"resolve": "yes"}
        arp_table_info: Mapping[str, Any] | list = await self._post(
            "/api/diagnostics/interface/search_arp", payload=request_body
        )
        if not isinstance(arp_table_info, Mapping):
            return []
        _LOGGER.debug(f"[get_arp_table] arp_table_info: {arp_table_info}")
        arp_table: list = arp_table_info.get("rows", [])
        _LOGGER.debug(f"[get_arp_table] arp_table: {arp_table}")
        return arp_table

    @_log_errors
    async def get_services(self):
        response = await self._list_services()
        services = []
        for key in response.keys():
            services.append(response[key])

        return services

    @_log_errors
    async def get_service_is_running(self, service_name):
        services = await self.get_services()
        for service in services:
            if service["name"] == service_name:
                return service["status"]

        return False

    @_log_errors
    async def start_service(self, service_name):
        self._start_service({"service": service_name})

    @_log_errors
    async def stop_service(self, service_name):
        await self._stop_service({"service": service_name})

    @_log_errors
    async def restart_service(self, service_name):
        await self._restart_service({"service": service_name})

    @_log_errors
    async def restart_service_if_running(self, service_name):
        if await self.get_service_is_running(service_name):
            await self.restart_service(service_name)

    @_log_errors
    async def get_dhcp_leases(self):
        # function system_get_dhcpleases()
        # {'lease': [], 'failover': []}
        # {"lease":[{"ip":"<ip>","type":"static","mac":"<mac>","if":"lan","starts":"","ends":"","hostname":"<hostname>","descr":"","act":"static","online":"online","staticmap_array_index":48} ...
        script: str = r"""
require_once '/usr/local/etc/inc/plugins.inc.d/dhcpd.inc';

$toreturn = [
  "data" => dhcpd_leases(4),
];
"""
        response: Mapping[str, Any] = await self._exec_php(script)
        if (
            response is None
            or not isinstance(response, Mapping)
            or not isinstance(response.get("data", None), Mapping)
        ):
            _LOGGER.error("Invalid data returned from get_dhcp_leases")
            return []
        return response.get("data", {}).get("lease", [])

    @_log_errors
    async def get_carp_status(self) -> Mapping[str, Any]:
        # carp enabled or not
        # readonly attribute, cannot be set directly
        # function get_carp_status()
        script: str = r"""
function get_carp_status() {
        /* grab the current status of carp */
        $status = get_single_sysctl('net.inet.carp.allow');
        return (intval($status) > 0);
}

$toreturn = [
  "data" => get_carp_status(),
];
"""
        response: Mapping[str, Any] = await self._exec_php(script)
        if response is None or not isinstance(response, Mapping):
            _LOGGER.error("Invalid data returned from list_services")
            return {}
        return response.get("data", {})

    @_log_errors
    async def get_carp_interfaces(self) -> Mapping[str, Any]:
        script: str = r"""
global $config;

$vips = [];
if ($config['virtualip'] && is_iterable($config['virtualip']['vip'])) {
    foreach ($config['virtualip']['vip'] as $vip) {
        if ($vip["mode"] != "carp") {
            continue;
        }
        $vips[] = $vip;
    }
}

$intf_details = legacy_interfaces_details();

foreach ($vips as &$vip) {
  $intf = get_real_interface($vip['interface']);
  if (!empty($intf_details[$intf]) && !empty($intf_details[$intf]['carp'][$vip['vhid']])) {
    $status = $intf_details[$intf]['carp'][$vip['vhid']]['status'];
  } else {
    $status = "DISABLED";
  }

  $vip["status"] = $status;
}

$toreturn = [
  "data" => $vips,
];
"""
        response: Mapping[str, Any] = await self._exec_php(script)
        if response is None or not isinstance(response, Mapping):
            _LOGGER.error("Invalid data returned from get_carp_interfaces")
            return {}
        return response.get("data", {})

    @_log_errors
    async def delete_arp_entry(self, ip) -> None:
        if len(ip) < 1:
            return
        script: str = (
            r"""
$data = json_decode('{}', true);
$ip = trim($data["ip"]);
$ret = mwexec("arp -d " . $ip, true);
$toreturn = [
  "data" => $ret,
];
""".format(
                json.dumps(
                    {
                        "ip": ip,
                    }
                )
            )
        )
        await self._exec_php(script)

    @_log_errors
    async def system_reboot(self) -> bool:
        response: Mapping[str, Any] | list = await self._post("/api/core/system/reboot")
        _LOGGER.debug(f"[system_reboot] response: {response}")
        if isinstance(response, Mapping) and response.get("status", "") == "ok":
            return True
        return False

    @_log_errors
    async def system_halt(self) -> None:
        response: Mapping[str, Any] | list = await self._post("/api/core/system/halt")
        _LOGGER.debug(f"[system_halt] response: {response}")
        if isinstance(response, Mapping) and response.get("status", "") == "ok":
            return True
        return False

    @_log_errors
    async def send_wol(self, interface, mac) -> bool:
        """
        interface should be wan, lan, opt1, opt2 etc, not the description
        """
        payload: Mapping[str, Any] = {"wake": {"interface": interface, "mac": mac}}
        _LOGGER.debug(f"[send_wol] payload: {payload}")
        response = await self._post("/api/wol/wol/set", payload)
        _LOGGER.debug(f"[send_wol] response: {response}")
        if isinstance(response, Mapping) and response.get("status", "") == "ok":
            return True
        return False

    def _try_to_int(self, input, retval=None) -> int | None:
        try:
            return int(input)
        except (ValueError, TypeError):
            return retval

    def _try_to_float(self, input, retval=None) -> int | None:
        try:
            return float(input)
        except (ValueError, TypeError):
            return retval

    @_log_errors
    async def get_telemetry(self) -> Mapping[str, Any]:
        firmware: str | None = await self.get_host_firmware_version()
        try:
            if awesomeversion.AwesomeVersion(firmware) < awesomeversion.AwesomeVersion(
                "24.7"
            ):
                _LOGGER.info(f"Using legacy get_telemetry method for OPNsense < 24.7")
                return await self._get_telemetry_legacy()
        except awesomeversion.exceptions.AwesomeVersionCompareException:
            pass
        telemetry: Mapping[str, Any] = {}
        telemetry["interfaces"] = await self._get_telemetry_interfaces()
        telemetry["mbuf"] = await self._get_telemetry_mbuf()
        telemetry["pfstate"] = await self._get_telemetry_pfstate()
        telemetry["memory"] = await self._get_telemetry_memory()
        telemetry["system"] = await self._get_telemetry_system()
        telemetry["cpu"] = await self._get_telemetry_cpu()
        telemetry["filesystems"] = await self._get_telemetry_filesystems()
        telemetry["openvpn"] = await self._get_telemetry_openvpn()
        telemetry["gateways"] = await self._get_telemetry_gateways()
        telemetry["temps"] = await self._get_telemetry_temps()
        _LOGGER.debug(f"[get_telemetry] telemetry: {telemetry}")
        return telemetry

    @_log_errors
    async def _get_telemetry_interfaces(self) -> Mapping[str, Any]:
        interface_info: Mapping[str, Any] | list = await self._post(
            "/api/interfaces/overview/export"
        )
        _LOGGER.debug(f"[get_telemetry_interfaces] interface_info: {interface_info}")
        if not isinstance(interface_info, list) or not len(interface_info) > 0:
            return {}
        interfaces: Mapping[str, Any] = {}
        for ifinfo in interface_info:
            interface: Mapping[str, Any] = {}
            if (
                ifinfo is None
                or not isinstance(ifinfo, Mapping)
                or ifinfo.get("identifier", "") == ""
            ):
                continue
            interface["inpkts"] = self._try_to_int(
                ifinfo.get("statistics", {}).get("packets received", None)
            )
            interface["outpkts"] = self._try_to_int(
                ifinfo.get("statistics", {}).get("packets transmitted", None)
            )
            interface["inbytes"] = self._try_to_int(
                ifinfo.get("statistics", {}).get("bytes received", None)
            )
            interface["outbytes"] = self._try_to_int(
                ifinfo.get("statistics", {}).get("bytes transmitted", None)
            )
            interface["inbytes_frmt"] = self._try_to_int(
                ifinfo.get("statistics", {}).get("bytes received", None)
            )
            interface["outbytes_frmt"] = self._try_to_int(
                ifinfo.get("statistics", {}).get("bytes transmitted", None)
            )
            interface["inerrs"] = self._try_to_int(
                ifinfo.get("statistics", {}).get("input errors", None)
            )
            interface["outerrs"] = self._try_to_int(
                ifinfo.get("statistics", {}).get("output errors", None)
            )
            interface["collisions"] = self._try_to_int(
                ifinfo.get("statistics", {}).get("collisions", None)
            )
            interface["descr"] = ifinfo.get("identifier", "")
            interface["name"] = ifinfo.get("description", "")
            interface["status"] = ""
            if ifinfo.get("status", "") in ("down", "no carrier", "up"):
                interface["status"] = ifinfo.get("status", "")
            elif ifinfo.get("status", "") in ("associated"):
                interface["status"] = "up"
            interface["ipaddr"] = ifinfo.get("addr4", "")
            interface["media"] = ifinfo.get("media", "")
            interfaces[ifinfo.get("identifier", "")] = interface
        _LOGGER.debug(f"[get_telemetry_interfaces] interfaces: {interfaces}")
        return interfaces

    @_log_errors
    async def _get_telemetry_mbuf(self) -> Mapping[str, Any]:
        mbuf_info: Mapping[str, Any] | list = await self._post(
            "/api/diagnostics/system/system_mbuf"
        )
        _LOGGER.debug(f"[get_telemetry_mbuf] mbuf_info: {mbuf_info}")
        if not isinstance(mbuf_info, Mapping):
            return {}
        mbuf: Mapping[str, Any] = {}
        mbuf["used"] = self._try_to_int(
            mbuf_info.get("mbuf-statistics", {}).get("mbuf-current", None)
        )
        mbuf["total"] = self._try_to_int(
            mbuf_info.get("mbuf-statistics", {}).get("mbuf-total", None)
        )
        mbuf["used_percent"] = (
            round(mbuf["used"] / mbuf["total"] * 100)
            if isinstance(mbuf["used"], int)
            and isinstance(mbuf["total"], int)
            and mbuf["total"] > 0
            else None
        )
        _LOGGER.debug(f"[get_telemetry_mbuf] mbuf: {mbuf}")
        return mbuf

    @_log_errors
    async def _get_telemetry_pfstate(self) -> Mapping[str, Any]:
        pfstate_info: Mapping[str, Any] | list = await self._post(
            "/api/diagnostics/firewall/pf_states"
        )
        _LOGGER.debug(f"[get_telemetry_pfstate] pfstate_info: {pfstate_info}")
        if not isinstance(pfstate_info, Mapping):
            return {}
        pfstate: Mapping[str, Any] = {}
        pfstate["used"] = self._try_to_int(pfstate_info.get("current", None))
        pfstate["total"] = self._try_to_int(pfstate_info.get("limit", None))
        pfstate["used_percent"] = (
            round(pfstate["used"] / pfstate["total"] * 100)
            if isinstance(pfstate["used"], int)
            and isinstance(pfstate["total"], int)
            and pfstate["total"] > 0
            else None
        )
        _LOGGER.debug(f"[get_telemetry_pfstate] pfstate: {pfstate}")
        return pfstate

    @_log_errors
    async def _get_telemetry_memory(self) -> Mapping[str, Any]:
        memory_info: Mapping[str, Any] | list = await self._post(
            "/api/diagnostics/system/systemResources"
        )
        _LOGGER.debug(f"[get_telemetry_memory] memory_info: {memory_info}")
        if not isinstance(memory_info, Mapping):
            return {}
        memory: Mapping[str, Any] = {}
        memory["physmem"] = self._try_to_int(
            memory_info.get("memory", {}).get("total", None)
        )
        memory["used"] = self._try_to_int(
            memory_info.get("memory", {}).get("used", None)
        )
        memory["used_percent"] = (
            round(memory["used"] / memory["physmem"] * 100)
            if isinstance(memory["used"], int)
            and isinstance(memory["physmem"], int)
            and memory["physmem"] > 0
            else None
        )
        swap_info: Mapping[str, Any] = await self._post(
            "/api/diagnostics/system/system_swap"
        )
        if (
            not isinstance(swap_info, Mapping)
            or not isinstance(swap_info.get("swap", None), list)
            or not len(swap_info.get("swap", [])) > 0
            or not isinstance(swap_info.get("swap", [])[0], Mapping)
        ):
            return memory
        _LOGGER.debug(f"[get_telemetry_memory] swap_info: {swap_info}")
        memory["swap_total"] = self._try_to_int(
            swap_info.get("swap", [])[0].get("total", None)
        )
        memory["swap_reserved"] = self._try_to_int(
            swap_info["swap"][0].get("used", None)
        )
        memory["swap_used_percent"] = (
            round(memory["swap_reserved"] / memory["swap_total"] * 100)
            if isinstance(memory["swap_reserved"], int)
            and isinstance(memory["swap_total"], int)
            and memory["swap_total"] > 0
            else 0
        )
        _LOGGER.debug(f"[get_telemetry_memory] memory: {memory}")
        return memory

    @_log_errors
    async def _get_telemetry_system(self) -> Mapping[str, Any]:
        time_info: Mapping[str, Any] | list = await self._post(
            "/api/diagnostics/system/systemTime"
        )
        _LOGGER.debug(f"[get_telemetry_system] time_info: {time_info}")
        if not isinstance(time_info, Mapping):
            return {}
        system: Mapping[str, Any] = {}
        pattern = re.compile(r"^(?:(\d+)\s+days?,\s+)?(\d{2}):(\d{2}):(\d{2})$")
        match = pattern.match(time_info.get("uptime", ""))
        if not match:
            raise ValueError("Invalid uptime format")
        days_str, hours_str, minutes_str, seconds_str = match.groups()
        days: int = self._try_to_int(days_str, 0)
        hours: int = self._try_to_int(hours_str, 0)
        minutes: int = self._try_to_int(minutes_str, 0)
        seconds: int = self._try_to_int(seconds_str, 0)
        system["uptime"] = days * 86400 + hours * 3600 + minutes * 60 + seconds

        boottime: datetime = datetime.now() - timedelta(seconds=system["uptime"])
        system["boottime"] = boottime.timestamp()
        load_str: str = time_info.get("loadavg", "")
        load_list: list[str] = load_str.split(", ")
        if len(load_list) == 3:
            system["load_average"] = {
                "one_minute": float(load_list[0]),
                "five_minute": float(load_list[1]),
                "fifteen_minute": float(load_list[2]),
            }
        else:
            system["load_average"] = {
                "one_minute": None,
                "five_minute": None,
                "fifteen_minute": None,
            }
        _LOGGER.debug(f"[get_telemetry_system] system: {system}")
        return system

    @_log_errors
    async def _get_telemetry_cpu(self) -> Mapping[str, Any]:
        cputype_info: Mapping[str, Any] | list = await self._post(
            "/api/diagnostics/cpu_usage/getCPUType"
        )
        _LOGGER.debug(f"[get_telemetry_cpu] cputype_info: {cputype_info}")
        if not isinstance(cputype_info, list) or not len(cputype_info) > 0:
            return {}
        cpu: Mapping[str, Any] = {}
        cores_match = re.search(r"\((\d+) cores", cputype_info[0])
        cpu["count"] = self._try_to_int(cores_match.group(1)) if cores_match else 0

        cpustream_info: Mapping[str, Any] | list = await self._get_from_stream(
            "/api/diagnostics/cpu_usage/stream"
        )
        # {"total":29,"user":2,"nice":0,"sys":27,"intr":0,"idle":70}
        _LOGGER.debug(f"[get_telemetry_cpu] cpustream_info: {cpustream_info}")
        if not isinstance(cpustream_info, Mapping):
            return cpu
        cpu["usage_total"] = self._try_to_int(cpustream_info.get("total", None))
        cpu["usage_user"] = self._try_to_int(cpustream_info.get("user", None))
        cpu["usage_nice"] = self._try_to_int(cpustream_info.get("nice", None))
        cpu["usage_system"] = self._try_to_int(cpustream_info.get("sys", None))
        cpu["usage_interrupt"] = self._try_to_int(cpustream_info.get("intr", None))
        cpu["usage_idle"] = self._try_to_int(cpustream_info.get("idle", None))
        _LOGGER.debug(f"[get_telemetry_cpu] cpu: {cpu}")
        return cpu

    @_log_errors
    async def _get_telemetry_filesystems(self) -> Mapping[str, Any]:
        filesystems_info: Mapping[str, Any] | list = await self._post(
            "/api/diagnostics/system/systemDisk"
        )
        if not isinstance(filesystems_info, Mapping):
            return {}
        _LOGGER.debug(
            f"[get_telemetry_filesystems] filesystems_info: {filesystems_info}"
        )
        filesystems = filesystems_info.get("devices", {})
        # To conform to the previous data being returned
        for filesystem in filesystems:
            filesystem["size"] = filesystem.pop("blocks", None)
            filesystem["capacity"] = f"{filesystem.pop('used_pct','')}%"
        _LOGGER.debug(f"[get_telemetry_filesystems] filesystems: {filesystems}")
        return filesystems

    @_log_errors
    async def _get_telemetry_openvpn(self) -> Mapping[str, Any]:
        openvpn_info: Mapping[str, Any] | list = await self._post(
            "/api/openvpn/export/providers"
        )
        _LOGGER.debug(f"[get_telemetry_openvpn] openvpn_info: {openvpn_info}")
        if not isinstance(openvpn_info, Mapping):
            return {}
        openvpn: Mapping[str, Any] = {}
        openvpn["servers"] = {}
        connection_info: Mapping[str, Any] = await self._post(
            "/api/openvpn/service/searchSessions"
        )
        _LOGGER.debug(f"[get_telemetry_openvpn] connection_info: {connection_info}")
        if connection_info is None or not isinstance(connection_info, Mapping):
            return {}
        for vpnid, vpn_info in openvpn_info.items():
            vpn: Mapping[str, Any] = {}
            vpn["vpnid"] = vpn_info.get("vpnid", "")
            vpn["name"] = vpn_info.get("name", "")
            total_bytes_recv = 0
            total_bytes_sent = 0
            for connect in connection_info.get("rows", {}):
                if connect.get("id", None) and connect.get("id", None) == vpn.get(
                    "vpnid", None
                ):
                    total_bytes_recv += self._try_to_int(
                        connect.get("bytes_received", 0), 0
                    )
                    total_bytes_sent += self._try_to_int(
                        connect.get("bytes_sent", 0), 0
                    )
            vpn["total_bytes_recv"] = total_bytes_recv
            vpn["total_bytes_sent"] = total_bytes_sent
            # Missing connected_client_count
            # vpn["connected_client_count"] =
            openvpn["servers"][vpnid] = vpn
        _LOGGER.debug(f"[get_telemetry_openvpn] openvpn: {openvpn}")
        return openvpn

    @_log_errors
    async def _get_telemetry_gateways(self) -> Mapping[str, Any]:
        gateways_info: Mapping[str, Any] | list = await self._post(
            "/api/routes/gateway/status"
        )
        _LOGGER.debug(f"[get_telemetry_gateways] gateways_info: {gateways_info}")
        if not isinstance(gateways_info, Mapping):
            return {}
        gateways: Mapping[str, Any] = {}
        for gw_info in gateways_info.get("items", []):
            if isinstance(gw_info, Mapping) and "name" in gw_info:
                gateways[gw_info["name"]] = gw_info
        for gateway in gateways.values():
            gateway["status"] = gateway.pop(
                "status_translated", gateway.get("status", "")
            ).lower()
        _LOGGER.debug(f"[get_telemetry_gateways] gateways: {gateways}")
        return gateways

    @_log_errors
    async def _get_telemetry_temps(self) -> Mapping[str, Any]:
        temps_info: Mapping[str, Any] | list = await self._post(
            "/api/diagnostics/system/systemTemperature"
        )
        _LOGGER.debug(f"[get_telemetry_temps] temps_info: {temps_info}")
        if not isinstance(temps_info, list) or not len(temps_info) > 0:
            return {}
        temps: Mapping[str, Any] = {}
        for i, temp_info in enumerate(temps_info):
            temp: Mapping[str, Any] = {}
            temp["temperature"] = self._try_to_float(temp_info.get("temperature", 0), 0)
            temp["name"] = (
                f"{temp_info.get('type_translated', 'Num')} {temp_info.get('device_seq', i)}"
            )
            temp["device_id"] = temp_info.get("device", str(i))
            temps[temp_info.get("device", str(i)).replace(".", "_")] = temp
        _LOGGER.debug(f"[get_telemetry_temps] temps: {temps}")
        return temps

    @_log_errors
    async def _get_telemetry_legacy(self) -> Mapping[str, Any]:
        script: str = r"""
require_once '/usr/local/www/widgets/api/plugins/system.inc';
include_once '/usr/local/www/widgets/api/plugins/interfaces.inc';
require_once '/usr/local/www/widgets/api/plugins/temperature.inc';
require_once '/usr/local/etc/inc/plugins.inc.d/openvpn.inc';

global $config;
global $g;

function stripalpha($s) {
  return preg_replace("/\D/", "", $s);
}

// OPNsense 24.1 removed /usr/local/www/widgets/api/plugins/interfaces.inc to replace with new api endpoint
if (!function_exists('interfaces_api')) {
    function interfaces_api() {
        global $config;
        $result = array();
        $oc = new OPNsense\Interfaces\Api\OverviewController();
        foreach (get_configured_interface_with_descr() as $ifdescr => $ifname) {
            $ifinfo = $oc->getInterfaceAction($config["interfaces"][$ifdescr]["if"])["message"];
            // if interfaces is disabled returns message => "failed"
            if (!is_array($ifinfo)) {
                continue;
            }
            $interfaceItem = array();
            $interfaceItem['inpkts'] = $ifinfo["packets received"]["value"];
            $interfaceItem['outpkts'] = $ifinfo["packets transmitted"]["value"];
            $interfaceItem['inbytes'] = $ifinfo["bytes received"]["value"];
            $interfaceItem['outbytes'] = $ifinfo["bytes transmitted"]["value"];
            $interfaceItem['inbytes_frmt'] = format_bytes($interfaceItem['inbytes']);
            $interfaceItem['outbytes_frmt'] = format_bytes($interfaceItem['outbytes']);
            $interfaceItem['inerrs'] = $ifinfo["input errors"]["value"];
            $interfaceItem['outerrs'] = $ifinfo["output errors"]["value"];
            $interfaceItem['collisions'] = $ifinfo["collisions"]["value"];
            $interfaceItem['descr'] = $ifdescr;
            $interfaceItem['name'] = $ifname;
            switch ($ifinfo["status"]["value"]) {
                case 'down':
                case 'no carrier':
                case 'up':
                    $interfaceItem['status'] = $ifinfo["status"]["value"];
                    break;
                case 'associated':
                    $interfaceItem['status'] = 'up';
                    break;
                default:
                    $interfaceItem['status'] = '';
                    break;
            }
            //$interfaceItem['ipaddr'] = empty($ifinfo['ipaddr']) ? "" : $ifinfo['ipaddr'];
            $interfaceItem['ipaddr'] = isset($ifinfo["ipv4"]["value"][0]["ipaddr"]) ? $ifinfo["ipv4"]["value"][0]["ipaddr"] : "";
            $interfaceItem['media'] = $ifinfo["media"]["value"];

            $result[] = $interfaceItem;
        }
        return $result;
    }
}

$interfaces_api_data = interfaces_api();
if (!is_iterable($interfaces_api_data)) {
    $interfaces_api_data = [];
}

$system_api_data = system_api();
$temperature_api_data = temperature_api();

// OPNsense 23.1.1: replaced single exec_command() with new shell_safe() wrapper
if (function_exists('exec_command')) {
    $boottime = exec_command("sysctl kern.boottime");
} else {
    $boottime = shell_safe("sysctl kern.boottime");
}

// kern.boottime: { sec = 1634047554, usec = 237429 } Tue Oct 12 08:05:54 2021
preg_match("/sec = [0-9]*/", $boottime, $matches);
$boottime = $matches[0];
$boottime = explode("=", $boottime)[1];
$boottime = (int) trim($boottime);

// Fix for 23.1.4 (https://forum.opnsense.org/index.php?topic=33144.0)
if (function_exists('openvpn_get_active_servers')) {
    $ovpn_servers = openvpn_get_active_servers();
} else {
    $ovpn_servers = [];
}

$toreturn = [
    "pfstate" => [
        "used" => (int) $system_api_data["kernel"]["pf"]["states"],
        "total" => (int) $system_api_data["kernel"]["pf"]["maxstates"],
        "used_percent" => round(floatval($system_api_data["kernel"]["pf"]["states"] / $system_api_data["kernel"]["pf"]["maxstates"]) * 100, 0),
    ],

    "mbuf" => [
        "used" => (int) $system_api_data["kernel"]["mbuf"]["total"],
        "total" => (int) $system_api_data["kernel"]["mbuf"]["max"],
        "used_percent" =>  round(floatval($system_api_data["kernel"]["mbuf"]["total"] / $system_api_data["kernel"]["mbuf"]["max"]) * 100, 0),
    ],

    "memory" => [
        "swap_used_percent" => ($system_api_data["disk"]["swap"][0]["total"] > 0) ? round(floatval($system_api_data["disk"]["swap"][0]["used"] / $system_api_data["disk"]["swap"][0]["total"]) * 100, 0) : 0,
        "used_percent" => round(floatval($system_api_data["kernel"]["memory"]["used"] / $system_api_data["kernel"]["memory"]["total"]) * 100, 0),
        "physmem" => (int) $system_api_data["kernel"]["memory"]["total"],
        "used" => (int) $system_api_data["kernel"]["memory"]["used"],
        "swap_total" => (int) $system_api_data["disk"]["swap"][0]["total"],
        "swap_reserved" => (int) $system_api_data["disk"]["swap"][0]["used"],
    ],

    "system" => [
        "boottime" => $boottime,
        "uptime" => (int) $system_api_data["uptime"],
        //"temp" => 0,
        "load_average" => [
            "one_minute" => floatval(trim($system_api_data["cpu"]["load"][0])),
            "five_minute" => floatval(trim($system_api_data["cpu"]["load"][1])),
            "fifteen_minute" => floatval(trim($system_api_data["cpu"]["load"][2])),
        ],
    ],

    "cpu" => [
        "frequency" => [
            "current" => (int) stripalpha($system_api_data["cpu"]["cur.freq"]),
            "max" => (int) stripalpha($system_api_data["cpu"]["max.freq"]),
        ],
        "count" => (int) $system_api_data["cpu"]["cur.freq"],
    ],

    "filesystems" => $system_api_data["disk"]["devices"],

    "interfaces" => [],

    "openvpn" => [],
    
    "gateways" => return_gateways_status(true),
];

if (!is_iterable($toreturn["gateways"])) {
    $toreturn["gateways"] = [];
}
foreach ($toreturn["gateways"] as $key => $gw) {
    $status = $gw["status"];
    if ($status == "none") {
        $status = "online";
    }
    $gw["status"] = $status;
    $toreturn["gateways"][$key] = $gw;
}

foreach ($interfaces_api_data as $if) {
    $if["inpkts"] = (int) $if["inpkts"];
    $if["outpkts"] = (int) $if["outpkts"];
    $if["inbytes"] = (int) $if["inbytes"];
    $if["outbytes"] = (int) $if["outbytes"];
    $if["inerrs"] = (int) $if["inerrs"];
    $if["outerrs"] = (int) $if["outerrs"];
    $if["collisions"] = (int) $if["collisions"];
    $toreturn["interfaces"][$if["descr"]] = $if;
}

foreach ($ovpn_servers as $server) {
    $vpnid = $server["vpnid"];
    $name = $server["name"];
    $conn_count = count($server["conns"]);
    $total_bytes_recv = 0;
    $total_bytes_sent = 0;
    foreach ($server["conns"] as $conn) {
        $total_bytes_recv += $conn["bytes_recv"];
        $total_bytes_sent += $conn["bytes_sent"];
    }
    
    $toreturn["openvpn"]["servers"][$vpnid]["name"] = $name;
    $toreturn["openvpn"]["servers"][$vpnid]["vpnid"] = $vpnid;
    $toreturn["openvpn"]["servers"][$vpnid]["connected_client_count"] = $conn_count;
    $toreturn["openvpn"]["servers"][$vpnid]["total_bytes_recv"] = $total_bytes_recv;
    $toreturn["openvpn"]["servers"][$vpnid]["total_bytes_sent"] = $total_bytes_sent;
}

"""
        telemetry: Mapping[str, Any] = await self._exec_php(script)
        if telemetry is None or not isinstance(telemetry, Mapping):
            _LOGGER.error("Invalid data returned from get_telemetry_legacy")
            return {}
        if isinstance(telemetry.get("gateways", []), list):
            telemetry["gateways"] = {}
        _LOGGER.debug(f"[get_telemetry_legacy] telemetry: {telemetry}")
        return telemetry

    @_log_errors
    async def get_notices(self) -> list:
        notices_info: Mapping[str, Any] | list = await self._get(
            "/api/core/system/status"
        )
        _LOGGER.debug(f"[get_notices] notices_info: {notices_info}")

        if not isinstance(notices_info, Mapping):
            return []
        pending_notices_present = False
        pending_notices: list = []
        for key, notice in notices_info.items():
            if isinstance(notices_info, Mapping) and notice.get("statusCode", 2) != 2:
                pending_notices_present = True
                real_notice: Mapping[str, Any] = {}
                real_notice["notice"] = notice.get("message", None)
                real_notice["id"] = key
                real_notice["created_at"] = notice.get("timestamp", None)
                pending_notices.append(real_notice)

        notices: Mapping[str, Any] = {}
        notices["pending_notices_present"] = pending_notices_present
        notices["pending_notices"] = pending_notices
        _LOGGER.debug(f"[get_notices] notices: {notices}")
        return notices

    @_log_errors
    async def close_notice(self, id) -> bool:
        """
        id = "all" to wipe everything
        """
        success = True
        if id.lower() == "all":
            notices: Mapping[str, Any] | list = await self._get(
                "/api/core/system/status"
            )
            _LOGGER.debug(f"[close_notice] notices: {notices}")

            if not isinstance(notices, Mapping):
                return False
            for key, notice in notices.items():
                if "statusCode" in notice:
                    dismiss: Mapping[str, Any] | list = await self._post(
                        "/api/core/system/dismissStatus", payload={"subject": key}
                    )
                    _LOGGER.debug(f"[close_notice] id: {key}, dismiss: {dismiss}")
                    if (
                        not isinstance(dismiss, Mapping)
                        or dismiss.get("status", "failed") != "ok"
                    ):
                        success = False
        else:
            dismiss: Mapping[str, Any] | list = await self._post(
                "/api/core/system/dismissStatus", payload={"subject": id}
            )
            _LOGGER.debug(f"[close_notice] id: {id}, dismiss: {dismiss}")
            if (
                not isinstance(dismiss, Mapping)
                or dismiss.get("status", "failed") != "ok"
            ):
                success = False
        _LOGGER.debug(f"[close_notice] success: {success}")
        return success
