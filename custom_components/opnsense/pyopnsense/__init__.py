# import calendar
from collections.abc import Mapping
from datetime import datetime, timedelta
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

from dateutil.parser import parse
import requests

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


class Client(object):
    """OPNsense Client"""

    def __init__(self, url, username, password, opts=None):
        """OPNsense Client initializer."""

        if opts is None:
            opts = {}

        self._username = username
        self._password = password
        self._opts = opts
        parts = urlparse(url.rstrip("/"))
        self._url = "{scheme}://{username}:{password}@{host}".format(
            scheme=parts.scheme,
            username=quote_plus(username),
            password=quote_plus(password),
            host=parts.netloc,
        )
        self._url_parts = urlparse(self._url)

    # https://stackoverflow.com/questions/64983392/python-multiple-patch-gives-http-client-cannotsendrequest-request-sent
    def _get_proxy(self):
        # https://docs.python.org/3/library/xmlrpc.client.html#module-xmlrpc.client
        # https://stackoverflow.com/questions/30461969/disable-default-certificate-verification-in-python-2-7-9
        context = None
        verify_ssl = True
        if "verify_ssl" in self._opts.keys():
            verify_ssl = self._opts["verify_ssl"]

        if self._url_parts.scheme == "https" and not verify_ssl:
            context = ssl._create_unverified_context()

        # set to True if necessary during development
        verbose = False

        proxy = xmlrpc.client.ServerProxy(
            f"{self._url}/xmlrpc.php", context=context, verbose=verbose
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
    def _get_config_section(self, section):
        config = self.get_config()
        return config[section]

    @_apply_timeout
    def _restore_config_section(self, section_name, data):
        params = {section_name: data}
        response = self._get_proxy().opnsense.restore_config_section(params)
        return response

    @_apply_timeout
    def _exec_php(self, script):
        script = r"""
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
        response = self._get_proxy().opnsense.exec_php(script)
        response = json.loads(response["real"])
        return response

    @_apply_timeout
    @_log_errors
    def get_host_firmware_version(self):
        return self._get_proxy().opnsense.firmware_version()

    @_apply_timeout
    @_log_errors
    def _list_services(self):
        return self._get_proxy().opnsense.list_services()

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

    def _get(self, path):
        # /api/<module>/<controller>/<command>/[<param1>/[<param2>/...]]
        verify_ssl = True
        if "verify_ssl" in self._opts.keys():
            verify_ssl = self._opts["verify_ssl"]

        url = f"{self._url}{path}"
        response = requests.get(url, timeout=DEFAULT_TIMEOUT, verify=verify_ssl)
        return response.json()

    def _post(self, path, payload=None):
        # /api/<module>/<controller>/<command>/[<param1>/[<param2>/...]]
        verify_ssl = True
        if "verify_ssl" in self._opts.keys():
            verify_ssl = self._opts["verify_ssl"]

        url = f"{self._url}{path}"
        response = requests.post(
            url, data=payload, timeout=DEFAULT_TIMEOUT, verify=verify_ssl
        )
        return response.json()

    @_log_errors
    def _is_subsystem_dirty(self, subsystem):
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

        response = self._exec_php(script)
        return bool(response["data"])

    @_log_errors
    def _mark_subsystem_dirty(self, subsystem):
        script = r"""
$data = json_decode('{}', true);
$subsystem = $data["subsystem"];
mark_subsystem_dirty($subsystem);
""".format(
            json.dumps({"subsystem": subsystem})
        )
        self._exec_php(script)

    @_log_errors
    def _clear_subsystem_dirty(self, subsystem):
        script = r"""
$data = json_decode('{}', true);
$subsystem = $data["subsystem"];
clear_subsystem_dirty($subsystem);
""".format(
            json.dumps({"subsystem": subsystem})
        )
        self._exec_php(script)

    @_log_errors
    def _filter_configure(self):
        script = r"""
filter_configure();
clear_subsystem_dirty('natconf');
clear_subsystem_dirty('filter');
"""
        self._exec_php(script)

    @_log_errors
    def get_device_id(self):
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
        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def get_system_info(self):
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
        response = self._exec_php(script)
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
    def get_config(self):
        script = r"""
global $config;

$toreturn = [
  "data" => $config,
];
"""
        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def get_interfaces(self):
        return self._get_config_section("interfaces")

    @_log_errors
    def get_interface(self, interface):
        interfaces = self.get_interfaces()
        return interfaces[interface]

    @_log_errors
    def get_interface_by_description(self, interface):
        interfaces = self.get_interfaces()
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
        config = self.get_config()

        for rule in config["filter"]["rule"]:
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
        config = self.get_config()
        for rule in config["nat"]["rule"]:
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
        config = self.get_config()
        for rule in config["nat"]["rule"]:
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
        config = self.get_config()
        for rule in config["nat"]["outbound"]["rule"]:
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
        config = self.get_config()
        for rule in config["nat"]["outbound"]["rule"]:
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" not in rule.keys():
                rule["disabled"] = "1"
                self._restore_config_section("nat", config["nat"])
                self._filter_configure()

    @_log_errors
    def get_configured_interface_descriptions(self):
        script = r"""
$toreturn = [
  "data" => get_configured_interface_with_descr(),
];
"""
        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def get_gateways(self):
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
        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def get_gateway(self, gateway):
        gateways = self.get_gateways()
        for g in gateways.keys():
            if g == gateway:
                return gateways[g]

    @_log_errors
    def get_gateways_status(self):
        # {'GW_WAN': {'monitorip': '<ip>', 'srcip': '<ip>', 'name': 'GW_WAN', 'delay': '0.387ms', 'stddev': '0.097ms', 'loss': '0.0%', 'status': 'online', 'substatus': 'none'}}
        script = r"""
$toreturn = [
  // function return_gateways_status($byname = false, $gways = false)
  "data" => return_gateways_status(true),
];
"""
        response = self._exec_php(script)
        for gateway_name in response["data"].keys():
            gateway = response["data"][gateway_name]
            if gateway["status"] == "none":
                gateway["status"] = "online"
        return response["data"]

    @_log_errors
    def get_gateway_status(self, gateway):
        gateways = self.get_gateways_status()
        for g in gateways.keys():
            if g == gateway:
                if gateways[g]["status"] == "none":
                    gateways[g]["status"] = "online"
                return gateways[g]

    @_log_errors
    def get_arp_table(self, resolve_hostnames=False):
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
        response = self._exec_php(script)
        return response["data"]

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
        response = self._exec_php(script)
        return response["data"]["lease"]

    @_log_errors
    def get_virtual_ips(self):
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
        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def get_carp_status(self):
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
        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def get_carp_interfaces(self):
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
        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def delete_arp_entry(self, ip):
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
        self._exec_php(script)

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
        response = self._exec_php(script)["data"]
        if not response:
            return None
        return response

    @_log_errors
    def system_reboot(self):
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
            self._exec_php(script)
        except ExpatError:
            # ignore response failures because the system is going down
            pass

    @_log_errors
    def system_halt(self):
        script = r"""
use OPNsense\Core\Backend;

$backend = new Backend();
$backend->configdRun('system halt', true);

$toreturn = [
  "data" => true,
];
"""
        try:
            self._exec_php(script)
        except ExpatError:
            # ignore response failures because the system is going down
            pass

    @_log_errors
    def send_wol(self, interface, mac):
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

        response = self._exec_php(script)
        return response

    @_log_errors
    def _try_to_int(self, input, retval=None) -> int | None:
        try:
            return int(input)
        except (ValueError, TypeError):
            return retval

    @_log_errors
    def get_telemetry(self) -> dict:
        telemetry: dict[str, Any] = {}
        telemetry["interfaces"] = self._get_telemetry_interfaces()
        telemetry["mbuf"] = self._get_telemetry_mbuf()
        telemetry["pfstate"] = self._get_telemetry_pfstate()
        telemetry["memory"] = self._get_telemetry_memory()
        telemetry["system"] = self._get_telemetry_system()
        telemetry["cpu"] = self._get_telemetry_cpu()
        telemetry["filesystems"] = self._get_telemetry_filesystems()
        telemetry["openvpn"] = self._get_telemetry_openvpn()
        telemetry["gateways"] = self._get_telemetry_gateways()
        _LOGGER.debug(f"[get_telemetry] telemetry: {telemetry}")
        return telemetry

    @_log_errors
    def _get_telemetry_interfaces(self) -> dict:
        interface_info: dict[str, Any] = self._post("/api/interfaces/overview/export")
        _LOGGER.debug(f"[get_telemetry_interfaces] interface_info: {interface_info}")
        if interface_info is None or not isinstance(interface_info, list):
            return {}
        interfaces: dict[str, Any] = {}
        for ifinfo in interface_info:
            interface: dict[str, Any] = {}
            if ifinfo is None or not isinstance(ifinfo, Mapping):
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
            interface["descr"] = ifinfo.get("device", "")
            interface["name"] = ifinfo.get("description", "")
            interface["status"] = ""
            if ifinfo.get("status", "") in ("down", "no carrier", "up"):
                interface["status"] = ifinfo.get("status", "")
            elif ifinfo.get("status", "") in ("associated"):
                interface["status"] = "up"
            interface["ipaddr"] = ifinfo.get("addr4", "")
            interface["media"] = ifinfo.get("media", "")
            if (
                ifinfo.get("description", "").lower() == "unassigned interface"
                and "device" in ifinfo
            ):
                interfaces[ifinfo.get("device", "")] = interface
            else:
                interfaces[ifinfo.get("description", "")] = interface
        _LOGGER.debug(f"[get_telemetry_interfaces] interfaces: {interfaces}")
        return interfaces

    @_log_errors
    def _get_telemetry_mbuf(self) -> dict:
        mbuf_info: dict[str, Any] = self._post("/api/diagnostics/system/system_mbuf")
        _LOGGER.debug(f"[get_telemetry_mbuf] mbuf_info: {mbuf_info}")
        if mbuf_info is None or not isinstance(mbuf_info, Mapping):
            return {}
        mbuf: dict[str, Any] = {}
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
    def _get_telemetry_pfstate(self) -> dict:
        pfstate_info: dict[str, Any] = self._post("/api/diagnostics/firewall/pfstates")
        _LOGGER.debug(f"[get_telemetry_pfstate] pfstate_info: {pfstate_info}")
        if pfstate_info is None or not isinstance(pfstate_info, Mapping):
            return {}
        pfstate: dict[str, Any] = {}
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
    def _get_telemetry_memory(self) -> dict:
        memory_info: dict[str, Any] = self._post(
            "/api/diagnostics/system/systemResources"
        )
        _LOGGER.debug(f"[get_telemetry_memory] memory_info: {memory_info}")
        if memory_info is None or not isinstance(memory_info, Mapping):
            return memory
        memory: dict[str, Any] = {}
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
        swap_info: dict[str, Any] = self._post("/api/diagnostics/system/systemSwap")
        if (
            swap_info is None
            or not isinstance(swap_info, Mapping)
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
    def _get_telemetry_system(self) -> dict:
        time_info: dict[str, Any] = self._post("/api/diagnostics/system/systemTime")
        _LOGGER.debug(f"[get_telemetry_system] time_info: {time_info}")
        if time_info is None or not isinstance(time_info, Mapping):
            return {}
        system: dict[str, Any] = {}
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
    def _get_telemetry_cpu(self) -> dict:
        cputype_info: dict[str, Any] = self._post(
            "/api/diagnostics/cpu_usage/getCPUType"
        )
        _LOGGER.debug(f"[get_telemetry_cpu] cpu_info: {cputype_info}")
        if cputype_info is None or not isinstance(cputype_info, list):
            return {}
        cpu: dict[str, Any] = {}
        cores_match = re.search(r"\((\d+) cores", cputype_info[0])
        cpu["count"] = self._try_to_int(cores_match.group(1)) if cores_match else 0
        # Missing frequency current and max
        # cpu["frequency"] = {"current": 0, "max": 0}
        _LOGGER.debug(f"[get_telemetry_cpu] cpu: {cpu}")
        return cpu

    @_log_errors
    def _get_telemetry_filesystems(self) -> dict:
        filesystems: dict[str, Any] = {}
        filesystems_info: dict[str, Any] = self._post(
            "/api/diagnostics/system/systemDisk"
        )
        if filesystems_info is None or not isinstance(filesystems_info, Mapping):
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
    def _get_telemetry_openvpn(self) -> dict:
        openvpn_info: dict[str, Any] = self._post("/api/openvpn/export/providers")
        _LOGGER.debug(f"[get_telemetry_openvpn] openvpn_info: {openvpn_info}")
        if openvpn_info is None or not isinstance(openvpn_info, Mapping):
            return {}
        openvpn: dict[str, Any] = {}
        openvpn["servers"] = {}
        connection_info: dict[str, Any] = self._post(
            "/api/openvpn/service/searchSessions"
        )
        _LOGGER.debug(f"[get_telemetry_openvpn] connection_info: {connection_info}")
        if connection_info is None or not isinstance(connection_info, Mapping):
            return {}
        for vpnid, vpn_info in openvpn_info.items():
            vpn: dict[str, Any] = {}
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
    def _get_telemetry_gateways(self) -> dict:
        gateways_info: dict[str, Any] = self._post("/api/routes/gateway/status")
        _LOGGER.debug(f"[get_telemetry_gateways] gateways_info: {gateways_info}")
        if gateways_info is None or not isinstance(gateways_info, Mapping):
            return {}
        gateways: dict[str, Any] = {}
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
    def are_notices_pending(self):
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
        response = self._exec_php(script)
        return response["data"]

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
        response = self._exec_php(script)
        value = response["data"]
        if value is False:
            return []

        if isinstance(value, list):
            return []

        notices = []
        for key in value.keys():
            notice = value.get(key)
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
    def file_notice(self, notice):
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

        self._exec_php(script)

    @_log_errors
    def close_notice(self, id):
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

        self._exec_php(script)
