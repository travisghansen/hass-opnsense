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
from xml.parsers.expat import ExpatError
import xmlrpc.client
import zoneinfo

from awesomeversion import AwesomeVersion
from dateutil.parser import parse
import requests
from requests.auth import HTTPBasicAuth

# value to set as the socket timeout
DEFAULT_TIMEOUT = 60

_LOGGER = logging.getLogger(__name__)

tzinfos = {}
for tname in zoneinfo.available_timezones():
    tzinfos[tname] = zoneinfo.ZoneInfo(tname)


def dict_get(data: dict, path: str, default=None):
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


class OPNSenseClient(object):
    """OPNsense Client"""

    def __init__(self, url, username, password, opts=None):
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
        self._scheme = parts.scheme

    # https://stackoverflow.com/questions/64983392/python-multiple-patch-gives-http-client-cannotsendrequest-request-sent
    def _get_proxy(self):
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

    def _apply_timeout(func):
        def inner(*args, **kwargs):
            response = None
            # timout applies to each recv() call, not the whole request
            default_timeout = socket.getdefaulttimeout()
            try:
                socket.setdefaulttimeout(DEFAULT_TIMEOUT)
                response = func(*args, **kwargs)
            finally:
                socket.setdefaulttimeout(default_timeout)
            return response

        return inner

    def _log_errors(func):
        def inner(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except BaseException as err:
                _LOGGER.error(f"Unexpected {func.__name__} error {err=}, {type(err)=}")
                raise err

        return inner

    @_apply_timeout
    def _get_config_section(self, section) -> Mapping[str, Any]:
        config: Mapping[str, Any] = self.get_config()
        if config is None or not isinstance(config, Mapping):
            _LOGGER.error("Invalid data returned from get_config_section")
            return {}
        return config.get(section, {})

    @_apply_timeout
    def _restore_config_section(self, section_name, data):
        params: Mapping[str, Any] = {section_name: data}
        response = self._get_proxy().opnsense.restore_config_section(params)
        return response

    @_apply_timeout
    def _exec_php(self, script, calling_method="") -> Mapping[str, Any]:
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
            response = self._get_proxy().opnsense.exec_php(script)
            response_json = json.loads(response["real"])
            return response_json
        except TypeError as e:
            _LOGGER.error(
                f"Invalid data returned from exec_php for {calling_method}. {e.__class__.__qualname__}: {e}. Ensure the OPNsense user connected to HA either has full Admin access or specifically has the 'XMLRPC Library' privilege."
            )
            return {}
        except xmlrpc.client.Fault as e:
            _LOGGER.error(
                f"Error running exec_php script for {calling_method}. {e.__class__.__qualname__}: {e}. Ensure the 'os-homeassistant-maxit' plugin has been installed on OPNsense ."
            )
            return {}

    @_apply_timeout
    @_log_errors
    def get_host_firmware_version(self) -> None | str:
        firmware_info: Mapping[str, Any] | list = self._get("/api/core/firmware/status")
        if not isinstance(firmware_info, Mapping):
            return None
        firmware: str | None = firmware_info.get("product_version", None)
        _LOGGER.debug(f"[get_host_firmware_version] firmware: {firmware}")
        return firmware

    @_apply_timeout
    @_log_errors
    def _list_services(self):
        response = self._get_proxy().opnsense.list_services()
        if response is None or not isinstance(response, Mapping):
            _LOGGER.error("Invalid data returned from list_services")
            return {}
        return response

    @_apply_timeout
    @_log_errors
    def _start_service(self, params):
        return self._get_proxy().opnsense.start_service(params)

    @_apply_timeout
    @_log_errors
    def _stop_service(self, params):
        return self._get_proxy().opnsense.stop_service(params)

    @_apply_timeout
    @_log_errors
    def _restart_service(self, params):
        return self._get_proxy().opnsense.restart_service(params)

    def _get_from_stream(self, path) -> Mapping[str, Any] | list:
        url: str = f"{self._url}{path}"
        _LOGGER.debug(f"[get_from_stream] url: {url}")
        requests.packages.urllib3.disable_warnings()

        response = requests.get(
            url,
            auth=HTTPBasicAuth(self._username, self._password),
            timeout=DEFAULT_TIMEOUT,
            verify=self._verify_ssl,
            stream=True,
        )
        _LOGGER.debug(
            f"[get_from_stream] Response {response.status_code}: {response.reason}"
        )

        if response.ok:
            buffer = ""
            message_count = 0
            for chunk in response.iter_content(chunk_size=1024, decode_unicode=True):
                buffer += chunk
                if "\n\n" in buffer:
                    message, buffer = buffer.split("\n\n", 1)
                    # Split by lines
                    lines = message.splitlines()
                    for line in lines:
                        if line.startswith("data:"):
                            message_count += 1
                            if message_count == 2:
                                response_str: str = line[len("data:") :].strip()
                                response_json: Mapping[str, Any] | list = json.loads(
                                    response_str
                                )
                                # _LOGGER.debug(f"[get_from_stream] response_json ({type(response_json).__name__}): {response_json}")
                                response.close()
                                return response_json  # Exit after processing the first line

        elif response.status_code == 403:
            _LOGGER.error(
                f"Permission Error in {inspect.currentframe().f_back.f_code.co_qualname}. Path: {path}. Ensure the OPNsense user connected to HA has full Admin access."
            )
        else:
            _LOGGER.error(
                f"Error in {inspect.currentframe().f_back.f_code.co_qualname}. Path: {path}. Response {response.status_code}: {response.reason}"
            )
        return {}

    def _get(self, path) -> Mapping[str, Any] | list:
        # /api/<module>/<controller>/<command>/[<param1>/[<param2>/...]]

        url: str = f"{self._url}{path}"
        _LOGGER.debug(f"[get] url: {url}")
        requests.packages.urllib3.disable_warnings()
        response: requests.Response = requests.get(
            url,
            auth=HTTPBasicAuth(self._username, self._password),
            timeout=DEFAULT_TIMEOUT,
            verify=self._verify_ssl,
            stream=False,
        )
        _LOGGER.debug(f"[get] Response {response.status_code}: {response.reason}")
        if response.ok:
            response_json: Mapping[str, Any] | list = response.json()
            # _LOGGER.debug(f"[get] response_json ({type(response_json).__name__}): {response_json}")
            return response_json
        elif response.status_code == 403:
            _LOGGER.error(
                f"Permission Error in {inspect.currentframe().f_back.f_code.co_qualname}. Path: {path}. Ensure the OPNsense user connected to HA has full Admin access."
            )
        else:
            _LOGGER.error(
                f"Error in {inspect.currentframe().f_back.f_code.co_qualname}. Path: {path}. Response {response.status_code}: {response.reason}"
            )
        return {}

    def _post(self, path, payload=None) -> Mapping[str, Any] | list:
        # /api/<module>/<controller>/<command>/[<param1>/[<param2>/...]]

        url: str = f"{self._url}{path}"
        _LOGGER.debug(f"[post] url: {url}")
        _LOGGER.debug(f"[post] payload: {payload}")
        requests.packages.urllib3.disable_warnings()
        response: requests.Response = requests.post(
            url,
            data=payload,
            auth=HTTPBasicAuth(self._username, self._password),
            timeout=DEFAULT_TIMEOUT,
            verify=self._verify_ssl,
        )
        _LOGGER.debug(f"[post] Response {response.status_code}: {response.reason}")
        if response.ok:
            response_json: Mapping[str, Any] | list = response.json()
            # _LOGGER.debug(f"[post] response_json ({type(response_json).__name__}): {response_json}")
            return response_json
        elif response.status_code == 403:
            _LOGGER.error(
                f"Permission Error in {inspect.currentframe().f_back.f_code.co_qualname}. Path: {path}. Ensure the OPNsense user connected to HA has full Admin access."
            )
        else:
            _LOGGER.error(
                f"Error in {inspect.currentframe().f_back.f_code.co_qualname}. Path: {path}. Response {response.status_code}: {response.reason}"
            )
        return {}

    @_log_errors
    def _is_subsystem_dirty(self, subsystem) -> bool:
        script = r"""
$data = json_decode('{}', true);
$subsystem = $data["subsystem"];
$dirty = is_subsystem_dirty($subsystem);
$toreturn = [
    "data" => $dirty,
];
""".format(
            json.dumps({"subsystem": subsystem})
        )

        response: Mapping[str, Any] = self._exec_php(script, "is_subsystem_dirty")
        if response is None or not isinstance(response, Mapping):
            _LOGGER.error("Invalid data returned from is_subsystem_dirty")
            return False
        return bool(response.get("data", False))

    @_log_errors
    def _mark_subsystem_dirty(self, subsystem) -> None:
        script = r"""
$data = json_decode('{}', true);
$subsystem = $data["subsystem"];
mark_subsystem_dirty($subsystem);
""".format(
            json.dumps({"subsystem": subsystem})
        )
        self._exec_php(script, "mark_subsystem_dirty")

    @_log_errors
    def _clear_subsystem_dirty(self, subsystem) -> None:
        script = r"""
$data = json_decode('{}', true);
$subsystem = $data["subsystem"];
clear_subsystem_dirty($subsystem);
""".format(
            json.dumps({"subsystem": subsystem})
        )
        self._exec_php(script, "clear_subsystem_dirty")

    @_log_errors
    def _filter_configure(self) -> None:
        script = r"""
filter_configure();
clear_subsystem_dirty('natconf');
clear_subsystem_dirty('filter');
"""
        self._exec_php(script, "filter_configure")

    @_log_errors
    def get_device_id(self) -> Mapping[str, Any]:
        script = r"""
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
        response: Mapping[str, Any] = self._exec_php(script, "get_device_id")
        if response is None or not isinstance(response, Mapping):
            _LOGGER.error("Invalid data returned from get_device_id")
            return {}
        return response.get("data", {})

    @_log_errors
    def get_system_info(self) -> Mapping[str, Any]:
        # TODO: add bios details here
        script = r"""
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
        response: Mapping[str, Any] = self._exec_php(script, "get_system_info")
        return response

    @_log_errors
    def get_firmware_update_info(self):
        current_time = time.time()
        refresh_triggered = False
        refresh_interval = 2 * 60 * 60  # 2 hours

        status = None
        upgradestatus = None

        # GET /api/core/firmware/status
        status = self._get("/api/core/firmware/status")
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
            self._post("/api/core/firmware/check")
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
                upgradestatus = self._get("/api/core/firmware/upgradestatus")
                # print(upgradestatus)
                if "status" in upgradestatus.keys():
                    # status = running (package refresh in progress OR upgrade in progress)
                    # status = done (refresh/upgrade done)
                    if upgradestatus["status"] == "done":
                        # tigger repo update
                        # should this be /api/core/firmware/upgrade
                        check = self._post("/api/core/firmware/check")
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
    def upgrade_firmware(self, type="update"):
        # minor updates of the same opnsense version
        if type == "update":
            # can watch the progress on the 'Updates' tab in the UI
            return self._post("/api/core/firmware/update")

        # major updates to a new opnsense version
        if type == "upgrade":
            # can watch the progress on the 'Updates' tab in the UI
            return self._post("/api/core/firmware/upgrade")

    @_log_errors
    def upgrade_status(self):
        return self._post("/api/core/firmware/upgradestatus")

    @_log_errors
    def firmware_changelog(self, version):
        return self._post("/api/core/firmware/changelog/" + version)

    @_log_errors
    def get_config(self) -> Mapping[str, Any]:
        script = r"""
global $config;

$toreturn = [
  "data" => $config,
];
"""
        response: Mapping[str, Any] = self._exec_php(script, "get_config")
        if response is None or not isinstance(response, Mapping):
            return {}
        return response.get("data", {})

    @_log_errors
    def get_interfaces(self) -> Mapping[str, Any]:
        return self._get_config_section("interfaces")

    @_log_errors
    def get_interface(self, interface) -> Mapping[str, Any]:
        interfaces: Mapping[str, Any] = self.get_interfaces()
        return interfaces.get(interface, {})

    @_log_errors
    def get_interface_by_description(self, interface):
        interfaces: Mapping[str, Any] = self.get_interfaces()
        for i, i_interface in enumerate(interfaces.keys()):
            if "descr" not in interfaces[i_interface]:
                continue

            if interfaces[i_interface]["descr"] is None:
                continue

            if interfaces[i_interface]["descr"] == interface:
                return interfaces[i_interface]

    @_log_errors
    def enable_filter_rule_by_created_time(self, created_time):
        config = self.get_config()
        for rule in config["filter"]["rule"]:
            if "created" not in rule.keys():
                continue
            if "time" not in rule["created"].keys():
                continue
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" in rule.keys():
                del rule["disabled"]
                self._restore_config_section("filter", config["filter"])
                self._filter_configure()

    @_log_errors
    def disable_filter_rule_by_created_time(self, created_time):
        config: Mapping[str, Any] = self.get_config()

        for rule in config.get("filter", {}).get("rule", []):
            if "created" not in rule.keys():
                continue
            if "time" not in rule["created"].keys():
                continue
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" not in rule.keys():
                rule["disabled"] = "1"
                self._restore_config_section("filter", config["filter"])
                self._filter_configure()

    # use created_time as a unique_id since none other exists
    @_log_errors
    def enable_nat_port_forward_rule_by_created_time(self, created_time):
        config: Mapping[str, Any] = self.get_config()
        for rule in config.get("nat", {}).get("rule", []):
            if "created" not in rule.keys():
                continue
            if "time" not in rule["created"].keys():
                continue
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" in rule.keys():
                del rule["disabled"]
                self._restore_config_section("nat", config["nat"])
                self._filter_configure()

    # use created_time as a unique_id since none other exists
    @_log_errors
    def disable_nat_port_forward_rule_by_created_time(self, created_time):
        config: Mapping[str, Any] = self.get_config()
        for rule in config.get("nat", {}).get("rule", []):
            if "created" not in rule.keys():
                continue
            if "time" not in rule["created"].keys():
                continue
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" not in rule.keys():
                rule["disabled"] = "1"
                self._restore_config_section("nat", config["nat"])
                self._filter_configure()

    # use created_time as a unique_id since none other exists
    @_log_errors
    def enable_nat_outbound_rule_by_created_time(self, created_time):
        config: Mapping[str, Any] = self.get_config()
        for rule in config.get("nat", {}).get("outbound", {}).get("rule", []):
            if "created" not in rule.keys():
                continue
            if "time" not in rule["created"].keys():
                continue
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" in rule.keys():
                del rule["disabled"]
                self._restore_config_section("nat", config["nat"])
                self._filter_configure()

    # use created_time as a unique_id since none other exists
    @_log_errors
    def disable_nat_outbound_rule_by_created_time(self, created_time):
        config: Mapping[str, Any] = self.get_config()
        for rule in config.get("nat", {}).get("outbound", {}).get("rule", []):
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" not in rule.keys():
                rule["disabled"] = "1"
                self._restore_config_section("nat", config["nat"])
                self._filter_configure()

    @_log_errors
    def get_configured_interface_descriptions(self) -> Mapping[str, Any]:
        script = r"""
$toreturn = [
  "data" => get_configured_interface_with_descr(),
];
"""
        response: Mapping[str, Any] = self._exec_php(
            script, "get_configured_interface_descriptions"
        )
        if response is None or not isinstance(response, Mapping):
            _LOGGER.error(
                "Invalid data returned from get_configured_interface_descriptions"
            )
            return {}
        return response.get("data", {})

    @_log_errors
    def get_gateways(self) -> Mapping[str, Any]:
        # {'GW_WAN': {'interface': '<if>', 'gateway': '<ip>', 'name': 'GW_WAN', 'weight': '1', 'ipprotocol': 'inet', 'interval': '', 'descr': 'Interface wan Gateway', 'monitor': '<ip>', 'friendlyiface': 'wan', 'friendlyifdescr': 'WAN', 'isdefaultgw': True, 'attribute': 0, 'tiername': 'Default (IPv4)'}}
        script = r"""
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
        response: Mapping[str, Any] = self._exec_php(script, "get_gateways")
        if response is None or not isinstance(response, Mapping):
            _LOGGER.error("Invalid data returned from get_gateways")
            return {}
        return response.get("data", {})

    @_log_errors
    def get_gateway(self, gateway):
        gateways = self.get_gateways()
        for g in gateways.keys():
            if g == gateway:
                return gateways[g]

    @_log_errors
    def get_gateways_status(self) -> Mapping[str, Any]:
        # {'GW_WAN': {'monitorip': '<ip>', 'srcip': '<ip>', 'name': 'GW_WAN', 'delay': '0.387ms', 'stddev': '0.097ms', 'loss': '0.0%', 'status': 'online', 'substatus': 'none'}}
        script = r"""
$toreturn = [
  // function return_gateways_status($byname = false, $gways = false)
  "data" => return_gateways_status(true),
];
"""
        response: Mapping[str, Any] = self._exec_php(script, "get_gateways_status")
        if response is None or not isinstance(response, Mapping):
            _LOGGER.error("Invalid data returned from get_gateways_status")
            return {}
        for gateway_name, gateway in response.get("data", {}).items():
            if gateway["status"] == "none":
                gateway["status"] = "online"
        return response.get("data", {})

    @_log_errors
    def get_gateway_status(self, gateway):
        gateways = self.get_gateways_status()
        for g in gateways.keys():
            if g == gateway:
                if gateways[g]["status"] == "none":
                    gateways[g]["status"] = "online"
                return gateways[g]

    @_log_errors
    def get_arp_table(self, resolve_hostnames=False) -> Mapping[str, Any]:
        # [{'hostname': '?', 'ip-address': '<ip>', 'mac-address': '<mac>', 'interface': 'em0', 'expires': 1199, 'type': 'ethernet'}, ...]
        script = r"""
$data = json_decode('{}', true);
$resolve_hostnames = $data["resolve_hostnames"];

function system_get_arp_table($resolve_hostnames = false) {{
        $params="-a";
        if (!$resolve_hostnames) {{
                $params .= "n";
        }}

        $arp_table = array();
        $_gb = exec("/usr/sbin/arp --libxo json {{$params}}", $rawdata, $rc);
        if ($rc == 0) {{
                $arp_table = json_decode(implode(" ", $rawdata),
                    JSON_OBJECT_AS_ARRAY);
                if ($rc == 0) {{
                        $arp_table = $arp_table['arp']['arp-cache'];
                }}
        }}

        return $arp_table;
}}

$toreturn = [
  "data" => system_get_arp_table($resolve_hostnames),
];
""".format(
            json.dumps(
                {
                    "resolve_hostnames": resolve_hostnames,
                }
            )
        )
        response: Mapping[str, Any] = self._exec_php(script, "get_arp_table")
        if response is None or not isinstance(response, Mapping):
            _LOGGER.error("Invalid data returned from get_arp_table")
            return {}
        return response.get("data", {})

    @_log_errors
    def get_services(self):
        response = self._list_services()
        services = []
        for key in response.keys():
            services.append(response[key])

        return services

    @_log_errors
    def get_service_is_running(self, service_name):
        services = self.get_services()
        for service in services:
            if service["name"] == service_name:
                return service["status"]

        return False

    @_log_errors
    def start_service(self, service_name):
        self._start_service({"service": service_name})

    @_log_errors
    def stop_service(self, service_name):
        self._stop_service({"service": service_name})

    @_log_errors
    def restart_service(self, service_name):
        self._restart_service({"service": service_name})

    @_log_errors
    def restart_service_if_running(self, service_name):
        if self.get_service_is_running(service_name):
            self.restart_service(service_name)

    @_log_errors
    def get_dhcp_leases(self):
        # function system_get_dhcpleases()
        # {'lease': [], 'failover': []}
        # {"lease":[{"ip":"<ip>","type":"static","mac":"<mac>","if":"lan","starts":"","ends":"","hostname":"<hostname>","descr":"","act":"static","online":"online","staticmap_array_index":48} ...
        script = r"""
require_once '/usr/local/etc/inc/plugins.inc.d/dhcpd.inc';

$toreturn = [
  "data" => dhcpd_leases(4),
];
"""
        response: Mapping[str, Any] = self._exec_php(script, "get_dhcp_leases")
        if (
            response is None
            or not isinstance(response, Mapping)
            or not isinstance(response.get("data", None), Mapping)
        ):
            _LOGGER.error("Invalid data returned from get_dhcp_leases")
            return []
        return response.get("data", {}).get("lease", [])

    @_log_errors
    def get_virtual_ips(self) -> Mapping[str, Any]:
        script = r"""
global $config;

$vips = [];
if ($config['virtualip'] && is_iterable($config['virtualip']['vip'])) {
  foreach ($config['virtualip']['vip'] as $vip) {
    $vips[] = $vip;
  }
}

$toreturn = [
  "data" => $vips,
];
"""
        response: Mapping[str, Any] = self._exec_php(script, "get_virtual_ips")
        if response is None or not isinstance(response, Mapping):
            _LOGGER.error("Invalid data returned from get_virtual_ips")
            return {}
        return response.get("data", {})

    @_log_errors
    def get_carp_status(self) -> Mapping[str, Any]:
        # carp enabled or not
        # readonly attribute, cannot be set directly
        # function get_carp_status()
        script = r"""
function get_carp_status() {
        /* grab the current status of carp */
        $status = get_single_sysctl('net.inet.carp.allow');
        return (intval($status) > 0);
}

$toreturn = [
  "data" => get_carp_status(),
];
"""
        response: Mapping[str, Any] = self._exec_php(script, "get_carp_status")
        if response is None or not isinstance(response, Mapping):
            _LOGGER.error("Invalid data returned from list_services")
            return {}
        return response.get("data", {})

    @_log_errors
    def get_carp_interfaces(self) -> Mapping[str, Any]:
        script = r"""
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
        response: Mapping[str, Any] = self._exec_php(script, "get_carp_interfaces")
        if response is None or not isinstance(response, Mapping):
            _LOGGER.error("Invalid data returned from get_carp_interfaces")
            return {}
        return response.get("data", {})

    @_log_errors
    def delete_arp_entry(self, ip) -> None:
        if len(ip) < 1:
            return
        script = r"""
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
        self._exec_php(script, "delete_arp_entry")

    @_log_errors
    def arp_get_mac_by_ip(self, ip, do_ping=True):
        """function arp_get_mac_by_ip($ip, $do_ping = true)"""
        script = r"""
$data = json_decode('{}', true);
$ip = $data["ip"];
$do_ping = $data["do_ping"];

function arp_get_mac_by_ip($ip, $do_ping = true) {{
        unset($macaddr);
        $retval = 1;
        switch (is_ipaddr($ip)) {{
                case 4:
                        if ($do_ping === true) {{
                                mwexec("/sbin/ping -c 1 -t 1 " . escapeshellarg($ip), true);
                        }}
                        $macaddr = exec("/usr/sbin/arp -n " . escapeshellarg($ip) . " | /usr/bin/awk '{{print $4}}'", $output, $retval);
                        break;
                case 6:
                        if ($do_ping === true) {{
                                mwexec("/sbin/ping6 -c 1 -X 1 " . escapeshellarg($ip), true);
                        }}
                        $macaddr = exec("/usr/sbin/ndp -n " . escapeshellarg($ip) . " | /usr/bin/awk '{{print $2}}'", $output, $retval);
                        break;
        }}
        if ($retval == 0 && is_macaddr($macaddr)) {{
                return $macaddr;
        }} else {{
                return false;
        }}
}}

$toreturn = [
  "data" => arp_get_mac_by_ip($ip, $do_ping),
];
""".format(
            json.dumps(
                {
                    "ip": ip,
                    "do_ping": do_ping,
                }
            )
        )
        response = self._exec_php(script, "arp_get_mac_by_ip").get("data", None)
        if not response:
            return None
        return response

    @_log_errors
    def system_reboot(self) -> None:
        script = r"""
// /usr/local/opnsense/mvc/app/library/OPNsense/Core/Backend.php
use OPNsense\Core\Backend;

$backend = new Backend();
$backend->configdRun('system reboot', true);

$toreturn = [
  "data" => true,
];
"""
        try:
            self._exec_php(script, "system_reboot")
        except ExpatError:
            # ignore response failures because the system is going down
            pass

    @_log_errors
    def system_halt(self) -> None:
        script = r"""
use OPNsense\Core\Backend;

$backend = new Backend();
$backend->configdRun('system halt', true);

$toreturn = [
  "data" => true,
];
"""
        try:
            self._exec_php(script, "system_halt")
        except ExpatError:
            # ignore response failures because the system is going down
            pass

    @_log_errors
    def send_wol(self, interface, mac) -> Mapping[str, Any]:
        """
        interface should be wan, lan, opt1, opt2 etc, not the description
        """

        script = r"""
$data = json_decode('{}', true);
$if = $data["interface"];
$mac = $data["mac"];

function send_wol($if, $mac) {{
    global $config;
    $ipaddr = get_interface_ip($if);
    if (!is_ipaddr($ipaddr) || !is_macaddr($mac)) {{
            return false;
    }}
    
    $bcip = gen_subnet_max($ipaddr, $config["interfaces"][$if]["subnet"]);
    return (bool) !mwexec("/usr/local/bin/wol -i {{$bcip}} {{$mac}}");
}}

$value = send_wol($if, $mac);
$toreturn = [
  "data" => $value,
];
""".format(
            json.dumps(
                {
                    "interface": interface,
                    "mac": mac,
                }
            )
        )

        response: Mapping[str, Any] = self._exec_php(script, "send_wol")
        return response

    @_log_errors
    def _try_to_int(self, input, retval=None) -> int | None:
        try:
            return int(input)
        except (ValueError, TypeError):
            return retval

    @_log_errors
    def _try_to_float(self, input, retval=None) -> int | None:
        try:
            return float(input)
        except (ValueError, TypeError):
            return retval

    @_log_errors
    def get_telemetry(self) -> Mapping[str, Any]:
        firmware: str | None = self.get_host_firmware_version()
        if firmware is None:
            firmware: str = "24.7"
        if AwesomeVersion(firmware) < AwesomeVersion("24.7"):
            _LOGGER.debug(
                f"[get_telemetry] Using legacy telemetry method for OPNsense < 24.7"
            )
            return self._get_telemetry_legacy()
        telemetry: Mapping[str, Any] = {}
        telemetry["interfaces"] = self._get_telemetry_interfaces()
        telemetry["mbuf"] = self._get_telemetry_mbuf()
        telemetry["pfstate"] = self._get_telemetry_pfstate()
        telemetry["memory"] = self._get_telemetry_memory()
        telemetry["system"] = self._get_telemetry_system()
        telemetry["cpu"] = self._get_telemetry_cpu()
        telemetry["filesystems"] = self._get_telemetry_filesystems()
        telemetry["openvpn"] = self._get_telemetry_openvpn()
        telemetry["gateways"] = self._get_telemetry_gateways()
        telemetry["temps"] = self._get_telemetry_temps()
        _LOGGER.debug(f"[get_telemetry] telemetry: {telemetry}")
        return telemetry

    @_log_errors
    def _get_telemetry_interfaces(self) -> Mapping[str, Any]:
        interface_info: Mapping[str, Any] | list = self._post(
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
    def _get_telemetry_mbuf(self) -> Mapping[str, Any]:
        mbuf_info: Mapping[str, Any] | list = self._post(
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
    def _get_telemetry_pfstate(self) -> Mapping[str, Any]:
        pfstate_info: Mapping[str, Any] | list = self._post(
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
    def _get_telemetry_memory(self) -> Mapping[str, Any]:
        memory_info: Mapping[str, Any] | list = self._post(
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
        swap_info: Mapping[str, Any] = self._post("/api/diagnostics/system/system_swap")
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
    def _get_telemetry_system(self) -> Mapping[str, Any]:
        time_info: Mapping[str, Any] | list = self._post(
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
    def _get_telemetry_cpu(self) -> Mapping[str, Any]:
        cputype_info: Mapping[str, Any] | list = self._post(
            "/api/diagnostics/cpu_usage/getCPUType"
        )
        _LOGGER.debug(f"[get_telemetry_cpu] cputype_info: {cputype_info}")
        if not isinstance(cputype_info, list) or not len(cputype_info) > 0:
            return {}
        cpu: Mapping[str, Any] = {}
        cores_match = re.search(r"\((\d+) cores", cputype_info[0])
        cpu["count"] = self._try_to_int(cores_match.group(1)) if cores_match else 0

        cpustream_info: Mapping[str, Any] | list = self._get_from_stream(
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
    def _get_telemetry_filesystems(self) -> Mapping[str, Any]:
        filesystems_info: Mapping[str, Any] | list = self._post(
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
    def _get_telemetry_openvpn(self) -> Mapping[str, Any]:
        openvpn_info: Mapping[str, Any] | list = self._post(
            "/api/openvpn/export/providers"
        )
        _LOGGER.debug(f"[get_telemetry_openvpn] openvpn_info: {openvpn_info}")
        if not isinstance(openvpn_info, Mapping):
            return {}
        openvpn: Mapping[str, Any] = {}
        openvpn["servers"] = {}
        connection_info: Mapping[str, Any] = self._post(
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
    def _get_telemetry_gateways(self) -> Mapping[str, Any]:
        gateways_info: Mapping[str, Any] | list = self._post(
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
    def _get_telemetry_temps(self) -> Mapping[str, Any]:
        temps_info: Mapping[str, Any] | list = self._post(
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
    def _get_telemetry_legacy(self) -> Mapping[str, Any]:
        script = r"""
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
        telemetry: Mapping[str, Any] = self._exec_php(script, "get_telemetry_legacy")
        if telemetry is None or not isinstance(telemetry, Mapping):
            _LOGGER.error("Invalid data returned from get_telemetry_legacy")
            return {}
        if isinstance(telemetry.get("gateways", []), list):
            telemetry["gateways"] = {}
        _LOGGER.debug(f"[get_telemetry_legacy] telemetry: {telemetry}")
        return telemetry

    @_log_errors
    def are_notices_pending(self) -> Mapping[str, Any]:
        script = r"""
if (file_exists('/usr/local/etc/inc/notices.inc')) {
    require_once '/usr/local/etc/inc/notices.inc';

    $toreturn = [
        "data" => are_notices_pending(),
    ];
} else {
    $status = new \OPNsense\System\SystemStatus();
    $pending = false;
    foreach ($status->getSystemStatus() as $key => $value) {
        if ($value["statusCode"] != 2) {
            $pending = true;
            break;
        }
    }
    $toreturn = [
        "data" => $pending,
    ];
}
"""
        response: Mapping[str, Any] = self._exec_php(script, "are_notices_pending")
        if response is None or not isinstance(response, Mapping):
            _LOGGER.error("Invalid data returned from are_notices_pending")
            return {}
        return response.get("data", {})

    @_log_errors
    def get_notices(self):
        script = r"""
if (file_exists('/usr/local/etc/inc/notices.inc')) {
    require_once '/usr/local/etc/inc/notices.inc';

    $toreturn = [
        "data" => get_notices(),
    ];
} else {
    $status = new \OPNsense\System\SystemStatus();
    $toreturn = [
        "data" => $status->getSystemStatus(),
    ];
}
"""
        response: Mapping[str, Any] = self._exec_php(script, "get_notices")
        if response is None or not isinstance(response, Mapping):
            _LOGGER.error("Invalid data returned from get_notices -> getSystemStatus")
            return []
        value: Mapping[str, Any] = response.get("data", [])

        if isinstance(value, list):
            return []

        notices: list = []
        for key in value.keys():
            notice: Mapping[str, Any] = value.get(key)
            # 22.7.2+
            if "statusCode" in notice.keys():
                if notice["statusCode"] != 2:
                    real_notice = {}
                    real_notice["notice"] = notice["message"]
                    real_notice["id"] = key
                    real_notice["created_at"] = notice["timestamp"]
                    notices.append(real_notice)
            else:
                notice["created_at"] = key
                notice["id"] = key
                notices.append(notice)

        return notices

    @_log_errors
    def file_notice(self, notice) -> None:
        script = r"""
$data = json_decode('{}', true);
$notice = $data["notice"];

if (file_exists('/usr/local/etc/inc/notices.inc')) {{
    require_once '/usr/local/etc/inc/notices.inc';
    $value = file_notice($notice);
    $toreturn = [
        "data" => $value,
    ];
}} else {{
    // not currently supported in 22.7.2+
    $toreturn = [
        "data" => false,
    ];
}}
""".format(
            json.dumps(
                {
                    "notice": notice,
                }
            )
        )

        self._exec_php(script, "file_notice")

    @_log_errors
    def close_notice(self, id) -> None:
        """
        id = "all" to wipe everything
        """
        script = r"""
$data = json_decode('{}', true);
$id = $data["id"];

if (file_exists('/usr/local/etc/inc/notices.inc')) {{
    require_once '/usr/local/etc/inc/notices.inc';
    close_notice($id);
    $toreturn = [
    "data" => true,
    ];
}} else {{
    $status = new \OPNsense\System\SystemStatus();
    if (strtolower($id) == "all") {{
        foreach ($status->getSystemStatus() as $key => $value) {{
            $status->dismissStatus($key);    
        }}
    }} else {{
        $status->dismissStatus($id);
    }}
    
    $toreturn = [
        "data" => true,
    ];
}}
""".format(
            json.dumps(
                {
                    "id": id,
                }
            )
        )

        self._exec_php(script, "close_notice")
