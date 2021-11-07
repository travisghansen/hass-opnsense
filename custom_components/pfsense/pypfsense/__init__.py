import json
import socket
import ssl
from urllib.parse import quote_plus, urlparse
from xml.parsers.expat import ExpatError
import xmlrpc.client

# value to set as the socket timeout
DEFAULT_TIMEOUT = 5


class Client(object):
    """pfSense Client"""

    def __init__(self, url, username, password, opts=None):
        """pfSense Client initializer."""

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
        response = self._get_proxy().pfsense.backup_config_section([section])
        return response[section]

    @_apply_timeout
    def _restore_config_section(self, section_name, data):
        params = {section_name: data}
        response = self._get_proxy().pfsense.restore_config_section(params, 60)
        return response

    @_apply_timeout
    def _exec_php(self, script):
        return self._get_proxy().pfsense.exec_php(script)

    @_apply_timeout
    def get_host_firmware_version(self):
        return self._get_proxy().pfsense.host_firmware_version(1, 60)

    def get_system_serial(self):
        script = """
$toreturn = [
  "data" => system_get_serial(),
];
"""
        response = self._exec_php(script)
        return response["data"]

    def get_netgate_device_id(self):
        script = """
$toreturn = [
  "data" => system_get_uniqueid(),
];
"""
        response = self._exec_php(script)
        return response["data"]

    def get_system_info(self):
        # TODO: add bios details here
        script = """
global $config;

$toreturn = [
  "hostname" => $config["system"]["hostname"],
  "domain" => $config["system"]["domain"],
  "serial" => system_get_serial(),
  "netgate_device_id" => system_get_uniqueid(),
  "platform" => system_identify_specific_platform(),
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
            if interfaces[i_interface]["descr"] == interface:
                return interfaces[i_interface]

    def enable_filter_rule_by_tracker(self, tracker):
        config = self.get_config()
        for rule in config["filter"]["rule"]:
            if "tracker" not in rule.keys():
                continue
            if rule["tracker"] != tracker:
                continue

            if "disabled" in rule.keys():
                del rule["disabled"]
                self._restore_config_section("filter", config["filter"])

    def disable_filter_rule_by_tracker(self, tracker):
        config = self.get_config()

        for rule in config["filter"]["rule"]:
            if "tracker" not in rule.keys():
                continue
            if rule["tracker"] != tracker:
                continue

            if "disabled" not in rule.keys():
                rule["disabled"] = ""
                self._restore_config_section("filter", config["filter"])

    # use created_time as a unique_id since none other exists
    def enable_nat_port_forward_rule_by_created_time(self, created_time):
        config = self.get_config()
        for rule in config["nat"]["rule"]:
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" in rule.keys():
                del rule["disabled"]
                self._restore_config_section("nat", config["nat"])

    # use created_time as a unique_id since none other exists
    def disable_nat_port_forward_rule_by_created_time(self, created_time):
        config = self.get_config()
        for rule in config["nat"]["rule"]:
            if rule["created"]["time"] != created_time:
                continue

            if "disabled" not in rule.keys():
                rule["disabled"] = ""
                self._restore_config_section("nat", config["nat"])

    # use created_time as a unique_id since none other exists
    def enable_nat_outbound_rule_by_created_time(self, created_time):
        config = self.get_config()
        for rule in config["nat"]["outbound"]["rule"]:
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
                rule["disabled"] = ""
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
$toreturn = [
  "data" => return_gateways_array(),
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
        # function get_services()
        # ["",{"name":"nut","rcfile":"nut.sh","executable":"upsmon","description":"UPS monitoring daemon"},{"name":"iperf","executable":"iperf3","description":"iperf Network Performance Testing Daemon/Client","stopcmd":"mwexec(\"/usr/bin/killall iperf3\");"},{"name":"telegraf","rcfile":"telegraf.sh","executable":"telegraf","description":"Telegraf daemon"},{"name":"vnstatd","rcfile":"vnstatd.sh","executable":"vnstatd","description":"Status Traffic Totals data collection daemon"},{"name":"wireguard","rcfile":"wireguardd","executable":"php_wg","description":"WireGuard"},{"name":"FRR zebra","rcfile":"frr.sh","executable":"zebra","description":"FRR core/abstraction daemon"},{"name":"FRR staticd","rcfile":"frr.sh","executable":"staticd","description":"FRR static route daemon"},{"name":"FRR bfdd","rcfile":"frr.sh","executable":"bfdd","description":"FRR BFD daemon"},{"name":"FRR bgpd","rcfile":"frr.sh","executable":"bgpd","description":"FRR BGP routing daemon"},{"name":"FRR ospfd","rcfile":"frr.sh","executable":"ospfd","description":"FRR OSPF routing daemon"},{"name":"FRR ospf6d","rcfile":"frr.sh","executable":"ospf6d","description":"FRR OSPF6 routing daemon"},{"name":"FRR watchfrr","rcfile":"frr.sh","executable":"watchfrr","description":"FRR watchfrr watchdog daemon"},{"name":"haproxy","rcfile":"haproxy.sh","executable":"haproxy","description":"TCP/HTTP(S) Load Balancer"},{"name":"unbound","description":"DNS Resolver","enabled":true,"status":true},{"name":"pcscd","description":"PC/SC Smart Card Daemon","enabled":true,"status":true},{"name":"ntpd","description":"NTP clock sync","enabled":true,"status":true},{"name":"syslogd","description":"System Logger Daemon","enabled":true,"status":true},{"name":"dhcpd","description":"DHCP Service","enabled":true,"status":true},{"name":"dpinger","description":"Gateway Monitoring Daemon","enabled":true,"status":true},{"name":"miniupnpd","description":"UPnP Service","enabled":true,"status":true},{"name":"ipsec","description":"IPsec VPN","enabled":true,"status":true},{"name":"sshd","description":"Secure Shell Daemon","enabled":true,"status":true},{"name":"openvpn","mode":"server","id":0,"vpnid":"1","description":"OpenVPN server: primary vpn","enabled":true,"status":true}]
        script = """
require_once '/etc/inc/service-utils.inc';
// only returns enabled services currently
$s = get_services();
$services = [];
foreach($s as $service) {
  if (!is_array($service)) {
      continue;
  }
  if (!empty($service)) {
    $services[] = $service;
  }
}

$toreturn = [
  // function get_services()
  "data" => $services,
];
"""
        response = self._exec_php(script)

        for service in response["data"]:
            if "status" not in service:
                service["status"] = self.get_service_is_running(service["name"])

        return response["data"]

    def get_service_is_enabled(self, service_name):
        # function is_service_enabled($service_name)
        script = """
require_once '/etc/inc/service-utils.inc';

$data = json_decode('{}', true);
$service_name = $data["service_name"];
$toreturn = [
  // always returns true, so mostly useless at this point
  "data" => is_service_enabled($service_name),
];
""".format(
            json.dumps(
                {
                    "service_name": service_name,
                }
            )
        )
        response = self._exec_php(script)
        return response["data"]

    def get_service_is_running(self, service_name):
        # function is_service_running($service, $ps = "")
        script = """
require_once '/etc/inc/service-utils.inc';

$data = json_decode('{}', true);
$service_name = $data["service_name"];
$toreturn = [
  "data" => (bool) is_service_running($service_name),
];
""".format(
            json.dumps(
                {
                    "service_name": service_name,
                }
            )
        )
        response = self._exec_php(script)
        return response["data"]

    def start_service(self, service_name):
        # function start_service($name, $after_sync = false)
        script = """
require_once '/etc/inc/service-utils.inc';

$data = json_decode('{}', true);
$service_name = $data["service_name"];
$is_running = is_service_running($service_name);
if (!$is_running) {{
  service_control_start($service_name, []);
}}
$toreturn = [
  // no return value
  "data" => true,
];
""".format(
            json.dumps(
                {
                    "service_name": service_name,
                }
            )
        )
        self._exec_php(script)

    def stop_service(self, service_name):
        # function stop_service($name)
        script = """
require_once '/etc/inc/service-utils.inc';

$data = json_decode('{}', true);
$service_name = $data["service_name"];
$is_running = is_service_running($service_name);
if ($is_running) {{
  service_control_stop($service_name, []);
}}
$toreturn = [
  // no return value
  "data" => true,
];
""".format(
            json.dumps(
                {
                    "service_name": service_name,
                }
            )
        )
        self._exec_php(script)

    def restart_service(self, service_name):
        # function restart_service($name) (if service is not currently running, it will be started)
        script = """
require_once '/etc/inc/service-utils.inc';

$data = json_decode('{}', true);
$service_name = $data["service_name"];
service_control_restart($service_name, []);
$toreturn = [
  // no return value
  "data" => true,
];
""".format(
            json.dumps(
                {
                    "service_name": service_name,
                }
            )
        )
        self._exec_php(script)

    def restart_service_if_running(self, service_name):
        # function restart_service_if_running($service)
        script = """
require_once '/etc/inc/service-utils.inc';

$data = json_decode('{}', true);
$service_name = $data["service_name"];
$is_running = is_service_running($service_name);
if ($is_running) {{
  service_control_restart($service_name, []);
}}
$toreturn = [
  // no return value
  "data" => true,
];
""".format(
            json.dumps(
                {
                    "service_name": service_name,
                }
            )
        )
        self._exec_php(script)

    def get_dhcp_leases(self):
        # function system_get_dhcpleases()
        # {'lease': [], 'failover': []}
        # {"lease":[{"ip":"<ip>","type":"static","mac":"<mac>","if":"lan","starts":"","ends":"","hostname":"<hostname>","descr":"","act":"static","online":"online","staticmap_array_index":48} ...
        script = """
$toreturn = [
  "data" => system_get_dhcpleases(),
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
$toreturn = [
  "data" => get_carp_status(),
];
"""
        response = self._exec_php(script)
        return response["data"]

    def get_carp_interface_status(self, uniqueid):
        # function get_carp_interface_status($carpid)
        script = """
$data = json_decode('{}', true);
$uniqueid = $data["uniqueid"];
$carp_if = "_vip{{$uniqueid}}";
$status = get_carp_interface_status($carp_if);
$toreturn = [
  "data" => $status,
];
""".format(
            json.dumps(
                {
                    "uniqueid": uniqueid,
                }
            )
        )
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

foreach ($vips as &$vip) {
  $status = get_carp_interface_status("_vip{$vip['uniqid']}");
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

    def system_reboot(self, type="normal"):
        """
        type = normal = simple reboot
        type = reroot = a reroot reboot
        type = fsck = perform an fsck on next boot
        """
        script = """
$data = json_decode('{}', true);
$type = $data["type"];
$type = strtolower($type);

switch ($type) {{
    case 'fsck':
        if (php_uname('m') != 'arm') {{
            mwexec('/sbin/nextboot -e "pfsense.fsck.force=5"');
        }}
        system_reboot();
        break;
    case 'reroot':
        system_reboot_sync(true);
        break;
    case 'normal':
        system_reboot();
        break;
    default:
        break;
}}

$toreturn = [
  "data" => true,
];
""".format(
            json.dumps(
                {
                    "type": type,
                }
            )
        )
        try:
            self._exec_php(script)
        except ExpatError:
            # ignore response failures because the system is going down
            pass

    def system_halt(self):
        script = """
system_halt();
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
        $ipaddr = get_interface_ip($if);
        if (!is_ipaddr($ipaddr) || !is_macaddr($mac)) {{
                return false;
        }}

        $bcip = gen_subnet_max($ipaddr, get_interface_subnet($if));
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
        return response["data"]

    # TODO: function find_service_by_name($name)
    # TODO: function get_service_status($service) # seems to be higher-level logic than is_service_running, passes in the full service object

    def get_telemetry(self):
        script = """
require_once '/usr/local/www/includes/functions.inc.php';
require_once '/etc/inc/config.inc';
require_once '/etc/inc/pfsense-utils.inc';
require_once '/etc/inc/system.inc';
require_once '/etc/inc/util.inc';
require_once 'interfaces.inc';

global $config;
global $g;

function stripalpha($s) {
  return preg_replace("/\D/", "", $s);
}

$mbuf = null;
$mbufpercent = null;
get_mbuf($mbuf, $mbufpercent);
$mbuf_parts = explode("/", $mbuf);

$filesystems = get_mounted_filesystems();
$ifdescrs = get_configured_interface_with_descr();

$boottime = exec_command("sysctl kern.boottime");
// kern.boottime: { sec = 1634047554, usec = 237429 } Tue Oct 12 08:05:54 2021
preg_match("/sec = [0-9]*/", $boottime, $matches);
$boottime = $matches[0];
$boottime = explode("=", $boottime)[1];
$boottime = (int) trim($boottime);

$pfstate = get_pfstate();
// <used>/<total>
$pfstate_parts = explode("/", $pfstate);

$cpu_usage = cpu_usage();
// 1112|111
$cpu_usage_parts = explode("|", $cpu_usage);

$cpu_load_average = get_load_average();
// 0.23, 0.22, 0.21
$cpu_load_average_parts = explode(",", $cpu_load_average);

$cpu_frequency = get_cpufreq();
// Current: 800 MHz, Max: 3700 MHz
$cpu_frequency_parts = explode(",", $cpu_frequency);

$memory_info = exec_command("sysctl hw.physmem hw.usermem hw.realmem vm.swap_total vm.swap_reserved");
$memory_parts = explode("\n", $memory_info);

$toreturn = [
  // true argument resolves hostnames
  //"arp_table" => json_encode(system_get_arp_table(true)),
  // true returns in percentage
  //"g" => json_encode($g),
  //"freebsd_version" => json_encode(get_freebsd_version()),
  //"version" => json_encode($version),
  //"system_uniqueid" => json_encode(system_get_uniqueid()),
  //"host_firmware_version" => json_encode(host_firmware_version()),
  "pfstate" => [
    "used" => (int) $pfstate_parts[0],
    "total" => (int) $pfstate_parts[1],
    "used_percent" => get_pfstate(true),
  ],
  "mbuf" => [
    "used" => (int) $mbuf_parts[0],
    "total" => (int) $mbuf_parts[1],
    "used_percent" => floatval($mbufpercent),
  ],
  "memory" => [
    "swap_used_percent" => floatval(swap_usage()),
    "used_percent" => floatval(mem_usage()),
    "physmem" => (int) trim(explode(":", $memory_parts[0])[1]),
    "usermem" => (int) trim(explode(":", $memory_parts[1])[1]),
    "realmem" => (int) trim(explode(":", $memory_parts[2])[1]),
    "swap_total" => (int) trim(explode(":", $memory_parts[3])[1]),
    "swap_reserved" => (int) trim(explode(":", $memory_parts[4])[1]),
  ],
  "system" => [
    "boottime" => $boottime,
    "uptime" => (int) get_uptime_sec(),
    "temp" => floatval(get_temp()),
  ],
  "cpu" => [
    "frequency" => [
        "current" => (int) stripalpha($cpu_frequency_parts[0]),
        "max" => (int) stripalpha($cpu_frequency_parts[1]),
    ],
    "speed" => (int) get_cpu_speed(),
    "count" => (int) get_cpu_count(),
    "ticks" => [
        "total" => (int) $cpu_usage_parts[0],
        "idle" => (int) $cpu_usage_parts[1],
    ],
    "load_average" => [
        "one_minute" => floatval(trim($cpu_load_average_parts[0])),
        "five_minute" => floatval(trim($cpu_load_average_parts[1])),
        "fifteen_minute" => floatval(trim($cpu_load_average_parts[2])),
    ],
  ],
  "filesystems" => $filesystems,
  "interfaces" => [],
  "gateways" => return_gateways_status(true),
];

foreach($filesystems as $fs) {
  $key = str_replace("/", "_slash_", $fs["mountpoint"]);
  $key = trim($key, "_");
  //$toreturn["disk_usage_percent_${key}"] = floatval(disk_usage($fs["mountpoint"]));
  //$toreturn["disk_usage_percent_${key}"] = floatval($fs["percent_used"]);
}

foreach ($ifdescrs as $ifdescr => $ifname) {
  $data = get_interface_info("${ifdescr}");
  // I know these look off, but they are indeed correct
  $data["descr"] = $ifname;
  $data["ifname"] = $ifdescr;
  $toreturn["interfaces"][${ifdescr}] = json_encode($data);
}
"""
        data = self._exec_php(script)

        for fs in data["filesystems"]:
            fs["percent_used"] = int(fs["percent_used"])

        for i, i_key in enumerate(data["interfaces"].keys()):
            data["interfaces"][i_key] = json.loads(data["interfaces"][i_key])

        if isinstance(data["gateways"], list):
            data["gateways"] = {}

        return data

    def are_notices_pending(self, category="all"):
        """
        are_notices_pending($category = "all")
        $category appears to be ignored currently
        """
        script = """
$data = json_decode('{}', true);
$category = $data["category"];
$toreturn = [
  "data" => are_notices_pending($category),
];
""".format(
            json.dumps(
                {
                    "category": category,
                }
            )
        )

        response = self._exec_php(script)
        return response["data"]

    def get_notices(self, category="all"):
        script = """
$data = json_decode('{}', true);
$category = $data["category"];
$value = get_notices($category);
if (!$value) {{
    $value = false;
}}
$toreturn = [
  "data" => $value,
];
""".format(
            json.dumps(
                {
                    "category": category,
                }
            )
        )

        response = self._exec_php(script)
        value = response["data"]
        if value is False:
            return []

        notices = []
        for key in value.keys():
            notice = value.get(key)
            notice["created_at"] = key
            notices.append(notice)

        return notices

    def file_notice(
        self, id, notice, category="General", url="", priority=1, local_only=False
    ):
        """
        /****f* notices/file_notice
        * NAME
        *   file_notice
        * INPUTS
        *       $id, $notice, $category, $url, $priority, $local_only
        * RESULT
        *   Files a notice and kicks off the various alerts, smtp, telegram, pushover, system log, LED's, etc.
        *   If $local_only is true then the notice is not sent to external places (smtp, telegram, pushover)
        ******/
        function file_notice($id, $notice, $category = "General", $url = "", $priority = 1, $local_only = false)
        """

        script = """
$data = json_decode('{}', true);
$id = $data["id"];
$notice = $data["notice"];
$category = $data["category"];
$url = $data["url"];
$priority = $data["priority"];
$local_only = $data["local_only"];

$value = file_notice($id, $notice, $category, $url, $priority, $local_only);
$toreturn = [
  "data" => $value,
];
""".format(
            json.dumps(
                {
                    "id": id,
                    "notice": notice,
                    "category": category,
                    "url": url,
                    "priority": priority,
                    "local_only": local_only,
                }
            )
        )

        response = self._exec_php(script)
        return response["data"]

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

        response = self._exec_php(script)
        return response["data"]
