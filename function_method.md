# XMLRPC Functions
**Granular Permission:** XMLRPC Library
| Function | Uses Plugin | Possible in REST API | Comments |
| ----- | ----- | ----- | ----- |
| Get Config | Yes | No as of 24.7 | Returns a __large__ dictionary of elements used for multiple functions. More details in the other functions. |
| Restore Config Section | No | No as of 24.7 | |
| Filter Configure | Yes | No as of 24.7 | Used by the Filter and NAT functions |
| Enable/Disable Filter Rule | N/A | No as of 24.7 | Uses Get Config, Filter Configure and Restore Config Section. |
| Enable/Disable NAT Port Forward Rule | N/A | No as of 24.7 | Uses Get Config, Filter Configure and Restore Config Section. |
| Enable/Disable NAT Outbound Rule | N/A | No as of 24.7 | Uses Get Config, Filter Configure and Restore Config Section. |

# REST API Functions

| Function | Endpoints | Min OPNsense Version | Granular Permission | Comments |
| ----- | ----- | ----- | ----- | ----- |
| Get Interfaces<br>Get Device Unique ID | /api/interfaces/overview/export | 24.1 | Status: Interfaces | |
| Get mbuf | /api/diagnostics/system/system_mbuf | 24.7 | Lobby: Dashboard | Part of Telemetry |
| Get pfstates | /api/diagnostics/firewall/pf_states | 24.7 | Lobby: Dashboard | Part of Telemetry |
| Get Memory | /api/diagnostics/system/systemResources<br>/api/diagnostics/system/system_swap | 24.7 | Lobby: Dashboard | Part of Telemetry |
| Get System Time | /api/diagnostics/system/systemTime | 24.7 | Lobby: Dashboard | Part of Telemetry |
| Get CPU | /api/diagnostics/cpu_usage/getCPUType<br>/api/diagnostics/cpu_usage/stream | 24.7 | Lobby: Dashboard | Part of Telemetry |
| Get Filesystem | /api/diagnostics/system/systemDisk | 24.7 | Lobby: Dashboard | Part of Telemetry |
| Get OpenVPN | /api/openvpn/export/providers<br>/api/openvpn/service/searchSessions<br>/api/openvpn/instances/search<br>/api/openvpn/instances/get | 20.1 | VPN: OpenVPN: Client Export Utility<br>Status: OpenVPN<br>VPN: OpenVPN: Instances | |
| Get Gateways | /api/routes/gateway/status | 2021 | System: Gateways | |
| Get Temperatures | /api/diagnostics/system/systemTemperature | 24.7 | Lobby: Dashboard | Part of Telemetry |
| Get Firmware Update Info<br>Get Firmware Version | /api/core/firmware/status | 2018 | System: Firmware | |
| Upgrade Firmware | /api/core/firmware/update<br>/api/core/firmware/upgrade | 2018 | System: Firmware | |
| Firmware Upgrade Status | /api/core/firmware/upgradestatus | 2018 | System: Firmware | |
| Firmware Changelog | /api/core/firmware/changelog/ | 2018 | System: Firmware | |
| System Reboot | /api/core/system/reboot | 20.1 | Diagnostics: Reboot System | |
| System Halt | /api/core/system/halt | 20.1 | Diagnostics: Halt system | |
| Send WOL | /api/wol/wol/set | 2018 | Services: Wake on LAN | |
| Get ARP Table | /api/diagnostics/interface/search_arp | 2022 | Diagnostics: ARP Table | |
| Get System Info | /api/diagnostics/system/systemInformation | 24.7 | Lobby: Dashboard | |
| Get Notices | /api/core/system/status | 2022 | System: Status | |
| Close Notice | /api/core/system/status<br>/api/core/system/dismissStatus | 2022 | System: Status | |
| Get Services | /api/core/service/search | 2023 | System: Status | |
| Start Service | /api/core/service/start | 2023 | Status: Services | |
| Stop Service | /api/core/service/stop | 2023 | Status: Services | |
| Restart Service | /api/core/service/restart | 2023 | Status: Services | |
| Get Carp Status | /api/diagnostics/interface/get_vip_status | 2022 | Interfaces: Virtual IPs: Status | |
| Get DHCP Leases | /api/kea/leases4/search<br>/api/kea/dhcpv4/searchReservation<br>/api/dhcpv4/leases/searchLease<br>/api/dhcpv6/leases/searchLease | 24.1 | Services: DHCP: Kea(v4)<br>Status: DHCP leases<br>Status: DHCPv6 leases | |
| Get Unbound Blocklist | /api/unbound/settings/get<br>/api/unbound/settings/set<br>/api/unbound/service/dnsbl<br>/api/unbound/service/restart | 21.7 | Services: Unbound (MVC) | |
| Get Wireguard | /api/wireguard/service/show<br>/api/wireguard/client/get<br>/api/wireguard/server/get | 24.1 | VPN: WireGuard | |
| Get Kea Interfaces | /api/kea/dhcpv4/get | 24.1 | Services: DHCP: Kea(v4) | |
| Toggle VPN Instance | /api/openvpn/instances/toggle<br>/api/openvpn/service/reconfigure<br>/api/wireguard/client/toggleClient<br>/api/wireguard/server/toggleServer<br>/api/wireguard/service/reconfigure | 24.1 | VPN: OpenVPN: Instances<br>Status: OpenVPN<br>VPN: WireGuard | |
| Get Carp Interfaces | /api/interfaces/vip_settings/get<br>/api/diagnostics/interface/get_vip_status | 2022 | Interfaces: Virtual IPs: Settings<br>Interfaces: Virtual IPs: Status | |
| Reload Interface | /api/interfaces/overview/reloadInterface/ | 24.1 | Status: Interfaces | |
| Get Certificates | /api/trust/cert/search | 24.7 | System: Certificate Manager | |
| Generate Vouchers | /api/captiveportal/voucher/listProviders<br>/api/captiveportal/voucher/generateVouchers/ | 20.1 | Services: Captive Portal | |
| Kill States | /api/diagnostics/firewall/kill_states/ | 21.7 | Diagnostics: Show States | |
| Toggle Alias | /api/firewall/alias/searchItem<br>/api/firewall/alias/toggleItem/<br>/api/firewall/alias/set<br>/api/firewall/alias/reconfigure| 20.1 | Firewall: Alias: Edit | |
