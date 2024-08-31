# import calendar
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
        verbose = True

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
        script = """
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
        script = """
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
        script = """
$data = json_decode('{}', true);
$subsystem = $data["subsystem"];
mark_subsystem_dirty($subsystem);
""".format(
            json.dumps({"subsystem": subsystem})
        )
        self._exec_php(script)

    @_log_errors
    def _clear_subsystem_dirty(self, subsystem):
        script = """
$data = json_decode('{}', true);
$subsystem = $data["subsystem"];
clear_subsystem_dirty($subsystem);
""".format(
            json.dumps({"subsystem": subsystem})
        )
        self._exec_php(script)

    @_log_errors
    def _filter_configure(self):
        script = """
filter_configure();
clear_subsystem_dirty('natconf');
clear_subsystem_dirty('filter');
"""
        self._exec_php(script)

    @_log_errors
    def get_device_id(self):
        script = """
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
        script = """
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
        script = """
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
        script = """
$toreturn = [
  "data" => get_configured_interface_with_descr(),
];
"""
        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def get_gateways(self):
        # {'GW_WAN': {'interface': '<if>', 'gateway': '<ip>', 'name': 'GW_WAN', 'weight': '1', 'ipprotocol': 'inet', 'interval': '', 'descr': 'Interface wan Gateway', 'monitor': '<ip>', 'friendlyiface': 'wan', 'friendlyifdescr': 'WAN', 'isdefaultgw': True, 'attribute': 0, 'tiername': 'Default (IPv4)'}}
        script = """
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
        script = """
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
        script = """
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
        script = """
require_once '/usr/local/etc/inc/plugins.inc.d/dhcpd.inc';

$toreturn = [
  "data" => dhcpd_leases(4),
];
"""
        response = self._exec_php(script)
        return response["data"]["lease"]

    @_log_errors
    def get_virtual_ips(self):
        script = """
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
        script = """
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
        script = """
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
        script = """
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
        script = """
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
        script = """
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
        script = """
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

        script = """
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
    def get_telemetry(self) -> dict:
        telemetry: dict[str, Any] = {}
        telemetry["interfaces"] = self._get_telemetry_interfaces()
        telemetry["mbuf"] = self._get_telemetry_mbuf()
        telemetry["pfstate"] = self._get_telemetry_pfstate()
        telemetry["memory"] = self._get_telemetry_memory()
        telemetry["system"] = self._get_telemetry_system()
        # telemetry["cpu"] = self._get_telemetry_cpu()
        telemetry["filesystems"] = self._get_telemetry_filesystems()
        # telemetry["openvpn"] = self._get_telemetry_openvpn()
        telemetry["gateways"] = self._get_telemetry_gateways()
        return telemetry

    @_log_errors
    def _get_telemetry_interfaces(self) -> dict:
        interface_info: dict[str, Any] = self._post("/api/interfaces/overview/export")
        _LOGGER.debug(f"[get_telemetry_interfaces] interface_info: {interface_info}")
        interfaces: dict[str, Any] = {}
        for ifinfo in interface_info:
            interface: dict[str, Any] = {}
            interface["inpkts"] = int(ifinfo["statistics"]["packets received"])
            interface["outpkts"] = int(ifinfo["statistics"]["packets transmitted"])
            interface["inbytes"] = int(ifinfo["statistics"]["bytes received"])
            interface["outbytes"] = int(ifinfo["statistics"]["bytes transmitted"])
            interface["inbytes_frmt"] = int(ifinfo["statistics"]["bytes received"])
            interface["outbytes_frmt"] = int(ifinfo["statistics"]["bytes transmitted"])
            interface["inerrs"] = int(ifinfo["statistics"]["input errors"])
            interface["outerrs"] = int(ifinfo["statistics"]["output errors"])
            interface["collisions"] = int(ifinfo["statistics"]["collisions"])
            interface["descr"] = ifinfo["description"]
            if ifinfo["description"] == "Unassigned Interface":
                interface["descr"] = f"{ifinfo['description']} ({ifinfo['device']})"
            interface["name"] = ifinfo["description"]
            interface["status"] = ""
            if ifinfo["status"] in ("down", "no carrier", "up"):
                interface["status"] = ifinfo["status"]
            elif ifinfo["status"] in ("associated"):
                interface["status"] = "up"
            interface["ipaddr"] = ""
            if "addr4" in ifinfo:
                interface["ipaddr"] = ifinfo["addr4"]
            interface["media"] = ""
            if "media" in ifinfo:
                interface["media"] = ifinfo["description"]
            interfaces[ifinfo["description"]] = interface
        _LOGGER.debug(f"[get_telemetry_interfaces] interfaces: {interfaces}")
        return interfaces

    @_log_errors
    def _get_telemetry_mbuf(self) -> dict:
        mbuf: dict[str, Any] = {}
        mbuf_info: dict[str, Any] = self._post("/api/diagnostics/system/system_mbuf")
        _LOGGER.debug(f"[get_telemetry_mbuf] mbuf_info: {mbuf_info}")
        mbuf["used"] = int(mbuf_info["mbuf-statistics"]["mbuf-current"])
        mbuf["total"] = int(mbuf_info["mbuf-statistics"]["mbuf-total"])
        mbuf["used_percent"] = round(mbuf["used"] / mbuf["total"] * 100)
        _LOGGER.debug(f"[get_telemetry_mbuf] mbuf: {mbuf}")
        return mbuf

    @_log_errors
    def _get_telemetry_pfstate(self) -> dict:
        pfstate: dict[str, Any] = {}
        pfstate_info: dict[str, Any] = self._post("/api/diagnostics/firewall/pfstates")
        _LOGGER.debug(f"[get_telemetry_pfstate] pfstate_info: {pfstate_info}")
        pfstate["used"] = int(pfstate_info["current"])
        pfstate["total"] = int(pfstate_info["limit"])
        pfstate["used_percent"] = round(pfstate["used"] / pfstate["total"] * 100)
        _LOGGER.debug(f"[get_telemetry_pfstate] pfstate: {pfstate}")
        return pfstate

    @_log_errors
    def _get_telemetry_memory(self) -> dict:
        memory: dict[str, Any] = {}
        memory_info: dict[str, Any] = self._post(
            "/api/diagnostics/system/systemResources"
        )
        swap_info: dict[str, Any] = self._post("/api/diagnostics/system/systemSwap")
        _LOGGER.debug(f"[get_telemetry_memory] memory_info: {memory_info}")
        _LOGGER.debug(f"[get_telemetry_memory] swap_info: {swap_info}")
        memory["physmem"] = int(memory_info["memory"]["total"])
        memory["used"] = int(memory_info["memory"]["used"])
        memory["swap_total"] = int(swap_info["swap"][0]["total"])
        memory["swap_reserved"] = int(swap_info["swap"][0]["used"])
        memory["swap_used_percent"] = (
            round(memory["swap_reserved"] / memory["swap_total"] * 100)
            if memory["swap_total"] > 0
            else 0
        )
        memory["used_percent"] = round(memory["used"] / memory["physmem"] * 100)
        _LOGGER.debug(f"[get_telemetry_memory] memory: {memory}")
        return memory

    @_log_errors
    def _get_telemetry_system(self) -> dict:
        system: dict[str, Any] = {}
        time_info: dict[str, Any] = self._post("/api/diagnostics/system/systemTime")
        _LOGGER.debug(f"[get_telemetry_system] time_info: {time_info}")
        uptime_str: str = time_info["uptime"]
        uptime_list: list[str] = uptime_str.split(":")
        system["uptime"] = (
            int(uptime_list[2])
            + (int(uptime_list[1]) * 60)
            + (int(uptime_list[0]) * 3600)
        )
        boottime: datetime = datetime.now() - timedelta(seconds=system["uptime"])
        system["boottime"] = boottime.timestamp()        
        load_str: str = time_info["loadavg"]
        load_list: list[str] = load_str.split(", ")
        system["load_average"] = {
            "one_minute": float(load_list[0]),
            "five_minute": float(load_list[1]),
            "fifteen_minute": float(load_list[2]),
        }
        _LOGGER.debug(f"[get_telemetry_system] system: {system}")
        return system

    @_log_errors
    def _get_telemetry_cpu(self) -> dict:
        cpu: dict[str, Any] = {}
        cpu_info: dict[str, Any] = self._post("/api/diagnostics/system/system_mbuf")
        _LOGGER.debug(f"[get_telemetry_cpu] cpu_info: {cpu_info}")

        _LOGGER.debug(f"[get_telemetry_cpu] cpu: {cpu}")
        return cpu

    @_log_errors
    def _get_telemetry_filesystems(self) -> dict:
        filesystems: dict[str, Any] = {}
        filesystems_info: dict[str, Any] = self._post(
            "/api/diagnostics/system/systemDisk"
        )
        _LOGGER.debug(f"[get_telemetry_filesystems] filesystems_info: {filesystems_info}")
        filesystems = filesystems_info["devices"]
        # To conform to the previous data being returned
        for filesystem in filesystems:
            filesystem["size"] = filesystem.pop("blocks", None)
            filesystem["capacity"] = f"{filesystem.pop("used_pct")}%"
        _LOGGER.debug(f"[get_telemetry_filesystems] filesystems: {filesystems}")
        return filesystems

    @_log_errors
    def _get_telemetry_openvpn(self) -> dict:
        openvpn: dict[str, Any] = {}
        openvpn_info: dict[str, Any] = self._post("/api/diagnostics/system/system_mbuf")
        _LOGGER.debug(f"[get_telemetry_openvpn] openvpn_info: {openvpn_info}")

        _LOGGER.debug(f"[get_telemetry_openvpn] openvpn: {openvpn}")
        return openvpn

    @_log_errors
    def _get_telemetry_gateways(self) -> dict:
        gateways: dict[str, Any] = {}
        gateways_info: dict[str, Any] = self._post(
            "/api/routes/gateway/status"
        )
        _LOGGER.debug(f"[get_telemetry_gateways] gateways_info: {gateways_info}")
        for gw_info in gateways_info["items"]:
            _LOGGER.debug(f"[get_telemetry_gateways] gw_info: {gw_info}")
            gateways[gw_info["name"]] = gw_info
        _LOGGER.debug(f"[get_telemetry_gateways] gateways pre: {gateways}")    
        for gateway in gateways.values():
            gateway["status"] = gateway.pop("status_translated", gateway["status"]).lower()
        _LOGGER.debug(f"[get_telemetry_gateways] gateways: {gateways}")
        return gateways

    #     @_log_errors
    #     def get_telemetry(self):
    #         script = """
    # require_once '/usr/local/www/widgets/api/plugins/system.inc';
    # include_once '/usr/local/www/widgets/api/plugins/interfaces.inc';
    # require_once '/usr/local/www/widgets/api/plugins/temperature.inc';
    # require_once '/usr/local/etc/inc/plugins.inc.d/openvpn.inc';

    # global $config;
    # global $g;

    # function stripalpha($s) {
    #   return preg_replace("/\D/", "", $s);
    # }

    # // OPNsense 24.1 removed /usr/local/www/widgets/api/plugins/interfaces.inc to replace with new api endpoint
    # if (!function_exists('interfaces_api')) {
    #     function interfaces_api() {
    #         global $config;
    #         $result = array();
    #         $oc = new OPNsense\Interfaces\Api\OverviewController();
    #         foreach (get_configured_interface_with_descr() as $ifdescr => $ifname) {
    #             $ifinfo = $oc->getInterfaceAction($config["interfaces"][$ifdescr]["if"])["message"];
    #             // if interfaces is disabled returns message => "failed"
    #             if (!is_array($ifinfo)) {
    #                 continue;
    #             }
    #             $interfaceItem = array();
    #             $interfaceItem['inpkts'] = $ifinfo["packets received"]["value"];
    #             $interfaceItem['outpkts'] = $ifinfo["packets transmitted"]["value"];
    #             $interfaceItem['inbytes'] = $ifinfo["bytes received"]["value"];
    #             $interfaceItem['outbytes'] = $ifinfo["bytes transmitted"]["value"];
    #             $interfaceItem['inbytes_frmt'] = format_bytes($interfaceItem['inbytes']);
    #             $interfaceItem['outbytes_frmt'] = format_bytes($interfaceItem['outbytes']);
    #             $interfaceItem['inerrs'] = $ifinfo["input errors"]["value"];
    #             $interfaceItem['outerrs'] = $ifinfo["output errors"]["value"];
    #             $interfaceItem['collisions'] = $ifinfo["collisions"]["value"];
    #             $interfaceItem['descr'] = $ifdescr;
    #             $interfaceItem['name'] = $ifname;
    #             switch ($ifinfo["status"]["value"]) {
    #                 case 'down':
    #                 case 'no carrier':
    #                 case 'up':
    #                     $interfaceItem['status'] = $ifinfo["status"]["value"];
    #                     break;
    #                 case 'associated':
    #                     $interfaceItem['status'] = 'up';
    #                     break;
    #                 default:
    #                     $interfaceItem['status'] = '';
    #                     break;
    #             }
    #             //$interfaceItem['ipaddr'] = empty($ifinfo['ipaddr']) ? "" : $ifinfo['ipaddr'];
    #             $interfaceItem['ipaddr'] = isset($ifinfo["ipv4"]["value"][0]["ipaddr"]) ? $ifinfo["ipv4"]["value"][0]["ipaddr"] : "";
    #             $interfaceItem['media'] = $ifinfo["media"]["value"];

    #             $result[] = $interfaceItem;
    #         }
    #         return $result;
    #     }
    # }

    # $interfaces_api_data = interfaces_api();
    # if (!is_iterable($interfaces_api_data)) {
    #     $interfaces_api_data = [];
    # }

    # $system_api_data = system_api();
    # $temperature_api_data = temperature_api();

    # // OPNsense 23.1.1: replaced single exec_command() with new shell_safe() wrapper
    # if (function_exists('exec_command')) {
    #     $boottime = exec_command("sysctl kern.boottime");
    # } else {
    #     $boottime = shell_safe("sysctl kern.boottime");
    # }

    # // kern.boottime: { sec = 1634047554, usec = 237429 } Tue Oct 12 08:05:54 2021
    # preg_match("/sec = [0-9]*/", $boottime, $matches);
    # $boottime = $matches[0];
    # $boottime = explode("=", $boottime)[1];
    # $boottime = (int) trim($boottime);

    # // Fix for 23.1.4 (https://forum.opnsense.org/index.php?topic=33144.0)
    # if (function_exists('openvpn_get_active_servers')) {
    #     $ovpn_servers = openvpn_get_active_servers();
    # } else {
    #     $ovpn_servers = [];
    # }

    # $toreturn = [
    #     "pfstate" => [
    #         "used" => (int) $system_api_data["kernel"]["pf"]["states"],
    #         "total" => (int) $system_api_data["kernel"]["pf"]["maxstates"],
    #         "used_percent" => round(floatval($system_api_data["kernel"]["pf"]["states"] / $system_api_data["kernel"]["pf"]["maxstates"]) * 100, 0),
    #     ],

    #     "mbuf" => [
    #         "used" => (int) $system_api_data["kernel"]["mbuf"]["total"],
    #         "total" => (int) $system_api_data["kernel"]["mbuf"]["max"],
    #         "used_percent" =>  round(floatval($system_api_data["kernel"]["mbuf"]["total"] / $system_api_data["kernel"]["mbuf"]["max"]) * 100, 0),
    #     ],

    #     "memory" => [
    #         "swap_used_percent" => ($system_api_data["disk"]["swap"][0]["total"] > 0) ? round(floatval($system_api_data["disk"]["swap"][0]["used"] / $system_api_data["disk"]["swap"][0]["total"]) * 100, 0) : 0,
    #         "used_percent" => round(floatval($system_api_data["kernel"]["memory"]["used"] / $system_api_data["kernel"]["memory"]["total"]) * 100, 0),
    #         "physmem" => (int) $system_api_data["kernel"]["memory"]["total"],
    #         "used" => (int) $system_api_data["kernel"]["memory"]["used"],
    #         "swap_total" => (int) $system_api_data["disk"]["swap"][0]["total"],
    #         "swap_reserved" => (int) $system_api_data["disk"]["swap"][0]["used"],
    #     ],

    #     "system" => [
    #         "boottime" => $boottime,
    #         "uptime" => (int) $system_api_data["uptime"],
    #         //"temp" => 0,
    #         "load_average" => [
    #             "one_minute" => floatval(trim($system_api_data["cpu"]["load"][0])),
    #             "five_minute" => floatval(trim($system_api_data["cpu"]["load"][1])),
    #             "fifteen_minute" => floatval(trim($system_api_data["cpu"]["load"][2])),
    #         ],
    #     ],

    #     "cpu" => [
    #         "frequency" => [
    #             "current" => (int) stripalpha($system_api_data["cpu"]["cur.freq"]),
    #             "max" => (int) stripalpha($system_api_data["cpu"]["max.freq"]),
    #         ],
    #         "count" => (int) $system_api_data["cpu"]["cur.freq"],
    #     ],

    #     "filesystems" => $system_api_data["disk"]["devices"],

    #     "interfaces" => [],

    #     "openvpn" => [],

    #     "gateways" => return_gateways_status(true),
    # ];

    # if (!is_iterable($toreturn["gateways"])) {
    #     $toreturn["gateways"] = [];
    # }
    # foreach ($toreturn["gateways"] as $key => $gw) {
    #     $status = $gw["status"];
    #     if ($status == "none") {
    #         $status = "online";
    #     }
    #     $gw["status"] = $status;
    #     $toreturn["gateways"][$key] = $gw;
    # }

    # foreach ($interfaces_api_data as $if) {
    #     $if["inpkts"] = (int) $if["inpkts"];
    #     $if["outpkts"] = (int) $if["outpkts"];
    #     $if["inbytes"] = (int) $if["inbytes"];
    #     $if["outbytes"] = (int) $if["outbytes"];
    #     $if["inerrs"] = (int) $if["inerrs"];
    #     $if["outerrs"] = (int) $if["outerrs"];
    #     $if["collisions"] = (int) $if["collisions"];
    #     $toreturn["interfaces"][$if["descr"]] = $if;
    # }

    # foreach ($ovpn_servers as $server) {
    #     $vpnid = $server["vpnid"];
    #     $name = $server["name"];
    #     $conn_count = count($server["conns"]);
    #     $total_bytes_recv = 0;
    #     $total_bytes_sent = 0;
    #     foreach ($server["conns"] as $conn) {
    #         $total_bytes_recv += $conn["bytes_recv"];
    #         $total_bytes_sent += $conn["bytes_sent"];
    #     }

    #     $toreturn["openvpn"]["servers"][$vpnid]["name"] = $name;
    #     $toreturn["openvpn"]["servers"][$vpnid]["vpnid"] = $vpnid;
    #     $toreturn["openvpn"]["servers"][$vpnid]["connected_client_count"] = $conn_count;
    #     $toreturn["openvpn"]["servers"][$vpnid]["total_bytes_recv"] = $total_bytes_recv;
    #     $toreturn["openvpn"]["servers"][$vpnid]["total_bytes_sent"] = $total_bytes_sent;
    # }

    # """
    #         data = self._exec_php(script)

    #         if isinstance(data["gateways"], list):
    #             data["gateways"] = {}

    #         return data

    @_log_errors
    def are_notices_pending(self):
        script = """
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
        script = """
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
        script = """
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
        script = """
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
