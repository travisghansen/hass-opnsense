# XMLRPC Functions

| Function | Uses Plugin | Possible in REST API | Comments |
| ----- | ----- | ----- | ----- |
| Get Config | Yes | No as of 24.7 | Returns a __large__ dictionary of elements used for multiple functions. Some can be replaced, others cannot. More details in the other functions. |
| Restore Config Section | No | No as of 24.7 | |
| Filter Configure | Yes | No as of 24.7 | Used by the Filter and NAT functions |
| Enable/Disable Filter Rule | N/A | No as of 24.7 | Uses Get Config, Filter Configure and Restore Config Section. |
| Enable/Disable NAT Port Forward Rule | N/A | No as of 24.7 | Uses Get Config, Filter Configure and Restore Config Section. |
| Enable/Disable NAT Outbound Rule | N/A | No as of 24.7 | Uses Get Config, Filter Configure and Restore Config Section. |
| Get Carp Interfaces | Yes | Yes | |

# REST API Functions

| Function | Endpoints | Min OPNsense Version | Comments |
| ----- | ----- | ----- | ----- |
| Get Interfaces<br>Get Device Unique ID | /api/interfaces/overview/export | 24.1 | Get Interfaces is part of Telemetry: Uses legacy function if <24.7 |
| Get mbuf | /api/diagnostics/system/system_mbuf | 24.7 | Part of Telemetry: Uses legacy function if <24.7 |
| Get pfstates | /api/diagnostics/firewall/pf_states | 24.7 | Part of Telemetry: Uses legacy function if <24.7 |
| Get Memory | /api/diagnostics/system/systemResources<br>/api/diagnostics/system/system_swap | 24.7 | Part of Telemetry: Uses legacy function if <24.7 |
| Get System Time | /api/diagnostics/system/systemTime | 24.7 | Part of Telemetry: Uses legacy function if <24.7 |
| Get CPU | /api/diagnostics/cpu_usage/getCPUType<br>/api/diagnostics/cpu_usage/stream | 24.7 | Part of Telemetry: Uses legacy function if <24.7 |
| Get Filesystem | /api/diagnostics/system/systemDisk | 24.7 | Part of Telemetry: Uses legacy function if <24.7 |
| Get OpenVPN | /api/openvpn/export/providers | 20.1 | Part of Telemetry: Uses legacy function if <24.7 |
| Get Gateways | /api/routes/gateway/status | 2021 | Part of Telemetry: Uses legacy function if <24.7 |
| Get Temperatures | /api/diagnostics/system/systemTemperature | 24.7 | Part of Telemetry |
| Get Firmware Update Info<br>Get Firmware Version | /api/core/firmware/status | 2018 | |
| Upgrade Firmware | /api/core/firmware/update<br>/api/core/firmware/upgrade | 2018 | |
| Firmware Upgrade Status | /api/core/firmware/upgradestatus | 2018 | |
| Firmware Changelog | /api/core/firmware/changelog/ | 2018 | |
| System Reboot | /api/core/system/reboot | 20.1 | |
| System Halt | /api/core/system/halt | 20.1 | |
| Send WOL | /api/wol/wol/set | 2018 | |
| Get ARP Table | /api/diagnostics/interface/search_arp | 2022 | |
| Get System Info | /api/diagnostics/system/systemInformation | 24.7 | Uses legacy function if <24.7 |
| Get Notices | /api/core/system/status | 2022 | |
| Close Notice | /api/core/system/status<br>/api/core/system/dismissStatus | 2022 | |
| Get Services | /api/core/service/search | 2023 | |
| Start Service | /api/core/service/start | 2023 | |
| Stop Service | /api/core/service/stop | 2023 | |
| Restart Service | /api/core/service/restart | 2023 | |
| Get Carp Status | /api/diagnostics/interface/get_vip_status | 2022 | |
| Get DHCP Leases | /api/kea/leases4/search<br>/api/kea/dhcpv4/searchReservation<br>/api/dhcpv4/leases/searchLease<br>/api/dhcpv6/leases/searchLease | 24.1 | |
| Get Unbound Blocklist | /api/unbound/settings/get<br>/api/unbound/settings/set<br>/api/unbound/service/dnsbl<br>/api/unbound/service/restart | 21.7 | |
