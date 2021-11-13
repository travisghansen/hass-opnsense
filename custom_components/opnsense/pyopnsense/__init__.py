import json
import socket
import ssl
from urllib.parse import quote_plus, unquote, urlparse
from xml.parsers.expat import ExpatError
import xmlrpc.client

# value to set as the socket timeout
DEFAULT_TIMEOUT = 10


class Client(object):
    """OPNsense Client"""

    def __init__(self, url, username, password, opts=None):
        """OPNsense Client initializer."""

        if opts is None:
            opts = {}

        self._username = username
        self._password = password
        self._opts = opts
        parts = urlparse(url.rstrip("/") + "/xmlrpc.php")
        self._url = "{scheme}://{username}:{password}@{host}/xmlrpc.php".format(
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

        proxy = xmlrpc.client.ServerProxy(self._url, context=context, verbose=verbose)
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
        return self._get_proxy().opnsense.exec_php(script)

    @_apply_timeout
    def get_host_firmware_version(self):
        return self._get_proxy().opnsense.firmware_version()

    @_apply_timeout
    def _list_services(self):
        return self._get_proxy().opnsense.list_services()

    @_apply_timeout
    def _start_service(self, params):
        return self._get_proxy().opnsense.start_service(params)

    @_apply_timeout
    def _stop_service(self, params):
        return self._get_proxy().opnsense.stop_service(params)

    @_apply_timeout
    def _restart_service(self, params):
        return self._get_proxy().opnsense.restart_service(params)

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

    def get_config(self):
        script = """
global $config;

$toreturn = [
  "data" => $config,
];
"""
        response = self._exec_php(script)
        return response["data"]

    def get_interfaces(self):
        return self._get_config_section("interfaces")

    def get_interface(self, interface):
        interfaces = self.get_interfaces()
        return interfaces[interface]

    def get_interface_by_description(self, interface):
        interfaces = self.get_interfaces()
        for i, i_interface in enumerate(interfaces.keys()):
            if "descr" not in interfaces[i_interface]:
                continue

            if interfaces[i_interface]["descr"] is None:
                continue

            if interfaces[i_interface]["descr"] == interface:
                return interfaces[i_interface]

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

    # use created_time as a unique_id since none other exists
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

    # use created_time as a unique_id since none other exists
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

    # use created_time as a unique_id since none other exists
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

    # use created_time as a unique_id since none other exists
    def disable_nat_outbound_rule_by_created_time(self, created_time):
        config = self.get_config()
        for rule in config["nat"]["outbound"]["rule"]:
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" not in rule.keys():
                rule["disabled"] = "1"
                self._restore_config_section("nat", config["nat"])

    def get_configured_interface_descriptions(self):
        script = """
$toreturn = [
  "data" => get_configured_interface_with_descr(),
];
"""
        response = self._exec_php(script)
        return response["data"]

    def get_gateways(self):
        # {'GW_WAN': {'interface': '<if>', 'gateway': '<ip>', 'name': 'GW_WAN', 'weight': '1', 'ipprotocol': 'inet', 'interval': '', 'descr': 'Interface wan Gateway', 'monitor': '<ip>', 'friendlyiface': 'wan', 'friendlyifdescr': 'WAN', 'isdefaultgw': True, 'attribute': 0, 'tiername': 'Default (IPv4)'}}
        script = """
$gateways = new \OPNsense\Routing\Gateways(legacy_interfaces_details());
//$default_gwv4 = $gateways->getDefaultGW(return_down_gateways(), "inet");
//$default_gwv6 = $gateways->getDefaultGW(return_down_gateways(), "inet6");
$a_gateways = array_values($gateways->gatewaysIndexedByName(true, false, true));

$result = [];
foreach ($a_gateways as $g) {
    $result[$g["name"]] = $g;
}

$toreturn = [
  "data" => $result,
];
"""
        response = self._exec_php(script)
        return response["data"]

    def get_gateway(self, gateway):
        gateways = self.get_gateways()
        for g in gateways.keys():
            if g == gateway:
                return gateways[g]

    def get_gateways_status(self):
        # {'GW_WAN': {'monitorip': '<ip>', 'srcip': '<ip>', 'name': 'GW_WAN', 'delay': '0.387ms', 'stddev': '0.097ms', 'loss': '0.0%', 'status': 'online', 'substatus': 'none'}}
        script = """
$toreturn = [
  // function return_gateways_status($byname = false, $gways = false)
  "data" => return_gateways_status(true),
];
"""
        response = self._exec_php(script)
        return response["data"]

    def get_gateway_status(self, gateway):
        gateways = self.get_gateways_status()
        for g in gateways.keys():
            if g == gateway:
                return gateways[g]

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

    def get_services(self):
        response = self._list_services()
        services = []
        for key in response.keys():
            services.append(response[key])

        return services

    def get_service_is_running(self, service_name):
        services = self.get_services()
        for service in services:
            if service["name"] == service_name:
                return service["status"]

        return False

    def start_service(self, service_name):
        self._start_service({"service": service_name})

    def stop_service(self, service_name):
        self._stop_service({"service": service_name})

    def restart_service(self, service_name):
        self._restart_service({"service": service_name})

    def restart_service_if_running(self, service_name):
        if self.get_service_is_running(service_name):
            self.restart_service(service_name)

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

    def get_virtual_ips(self):
        script = """
global $config;

$vips = [];
foreach ($config['virtualip']['vip'] as $vip) {
  $vips[] = $vip;
}

$toreturn = [
  "data" => $vips,
];
"""
        response = self._exec_php(script)
        return response["data"]

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

    def get_carp_interfaces(self):
        script = """
global $config;

$vips = [];
foreach ($config['virtualip']['vip'] as $vip) {
  if ($vip["mode"] != "carp") {
    continue;
  }
  $vips[] = $vip;
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

    def system_reboot(self):
        script = """
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

    def get_telemetry(self):
        script = """
require_once '/usr/local/www/widgets/api/plugins/system.inc';
require_once '/usr/local/www/widgets/api/plugins/interfaces.inc';
require_once '/usr/local/www/widgets/api/plugins/temperature.inc';

global $config;
global $g;

function stripalpha($s) {
  return preg_replace("/\D/", "", $s);
}

$system_api_data = system_api();
$temperature_api_data = temperature_api();
$interfaces_api_data = interfaces_api();

$boottime = exec_command("sysctl kern.boottime");
// kern.boottime: { sec = 1634047554, usec = 237429 } Tue Oct 12 08:05:54 2021
preg_match("/sec = [0-9]*/", $boottime, $matches);
$boottime = $matches[0];
$boottime = explode("=", $boottime)[1];
$boottime = (int) trim($boottime);


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
        "swap_used_percent" => round(floatval($system_api_data["disk"]["swap"][0]["used"] / $system_api_data["disk"]["swap"][0]["total"]) * 100, 0),
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
    ],

    "cpu" => [
        "frequency" => [
            "current" => (int) stripalpha($system_api_data["cpu"]["cur.freq"]),
            "max" => (int) stripalpha($system_api_data["cpu"]["max.freq"]),
        ],
        "count" => (int) $system_api_data["cpu"]["cur.freq"],
        "load_average" => [
            "one_minute" => floatval(trim($system_api_data["cpu"]["load"][0])),
            "five_minute" => floatval(trim($system_api_data["cpu"]["load"][1])),
            "fifteen_minute" => floatval(trim($system_api_data["cpu"]["load"][2])),
        ],
    ],

    "filesystems" => $system_api_data["disk"]["devices"],

    "interfaces" => [],
    
    "gateways" => return_gateways_status(true),

    //"system_foo" => $system_api_data,
    //"temperature_foo" => $temperature_api_data,
    //"interfaces_foo" => $interfaces_api_data,
];

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
"""
        data = self._exec_php(script)

        # for fs in data["filesystems"]:
        #    fs["percent_used"] = int(fs["percent_used"])

        # for i, i_key in enumerate(data["interfaces"].keys()):
        #    data["interfaces"][i_key] = json.loads(data["interfaces"][i_key])

        return data

    def are_notices_pending(self):
        script = """
$toreturn = [
  "data" => are_notices_pending(),
];
"""
        response = self._exec_php(script)
        return response["data"]

    def get_notices(self):
        script = """
$toreturn = [
  "data" => get_notices(),
];
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
            notice["created_at"] = key
            notice["id"] = key
            notices.append(notice)

        return notices

    def file_notice(self, notice):
        script = """
$data = json_decode('{}', true);
$notice = $data["notice"];
$value = file_notice($notice);
$toreturn = [
  "data" => $value,
];
""".format(
            json.dumps(
                {
                    "notice": notice,
                }
            )
        )

        self._exec_php(script)

    def close_notice(self, id):
        """
        id = "all" to wipe everything
        """
        script = """
$data = json_decode('{}', true);
$id = $data["id"];
close_notice($id);
$toreturn = [
  "data" => true,
];
""".format(
            json.dumps(
                {
                    "id": id,
                }
            )
        )

        self._exec_php(script)
