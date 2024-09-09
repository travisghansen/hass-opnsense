# XMLRPC Functions

| Function | Uses Plugin | Possible in REST API | Comments |
| ----- | ----- | ----- | ----- |
| Get Config | Yes | No | Returns a __large__ dictionary of elements used for multiple functions. Some can be replaced, others cannot. More details in the other functions. |
| Restore Config Section | No | | |
| Get Firmware Version | No | | |
| Get ARP Table | Yes | Yes | |
| Get/List Services | No | | |
| Start Service | No | | |
| Stop Service | No | | |
| Restart Service | No | | |
| Restart Service if Running | No | | |
| Is Subsystem Dirty | Yes | | |
| Mark Subsystem Dirty | Yes | | |
| Clear Subsystem Dirty | Yes | | |
| Filter Configure | Yes | | |
| Get Device ID | Yes | Maybe | Used as Unique ID for device. It is just a random 10 digit number generated the first time it is requested. May be able to transition to using the Config Entry ID or something else as a Unique ID. |
| Get System Info | Yes | Partial | Returns hostname and domain as well as Device ID. Hostname and Domain can be obtained in REST API. |
| Get Interfaces | Yes | Yes | Uses Get Config. Can use same function that is used for the Interface data for the Telemetry data. |
| Enable Filter Rule | Yes | No | Uses Get Config, Filter Configure and Restore Config Section. |
| Disable Filter Rule | Yes | No | Uses Get Config, Filter Configure and Restore Config Section. |
| Enable NAT Port Forward Rule | Yes | No | Uses Get Config, Filter Configure and Restore Config Section. |
| Disable NAT Port Forward Rule | Yes | No | Uses Get Config, Filter Configure and Restore Config Section. |
| Enable NAT Outbound Rule | Yes | No | Uses Get Config, Filter Configure and Restore Config Section. |
| Disable NAT Outbound Rule | Yes | No | Uses Get Config, Filter Configure and Restore Config Section. |
| Get Configured Interface Descriptions | Yes | | |
| Get Gateways | Yes | Yes | Can use same function that is used for the Gateway data for the Telemetry data. |
| Get Gateways Status | Yes | | |
| Get DHCP Leases | Yes | | |
| Get Virtual IPs | Yes | | |
| Get Carp Status | Yes | | |
| Get Carp Interfaces | Yes | | |
| Delete ARP Entry | Yes | | |
| Get MAC by IP | Yes | | |
| System Reboot | Yes | Yes | |
| System Halt | Yes | Yes | |
| Send WOL | Yes | | |
| Are Notices Pending | Yes | | |
| Get Notices | Yes | | |
| File Notice | Yes | | |
| Close Notice | Yes | | |

# REST API Functions

| Function | Endpoints | Min OPNsense Version | Comments |
| ----- | ----- | ----- | ----- |
| Get Interfaces | /api/interfaces/overview/export | 24.1 | |
| Get mbuf | /api/diagnostics/system/system_mbuf | 24.7 | |
| Get pfstates | /api/diagnostics/firewall/pf_states | 24.7 | |
| Get Memory | /api/diagnostics/system/systemResources <br>/api/diagnostics/system/system_swap | 24.7 | |
| Get System Time | /api/diagnostics/system/systemTime | 24.7 | |
| Get CPU | /api/diagnostics/cpu_usage/getCPUType<br>/api/diagnostics/cpu_usage/stream | 24.7 | |
| Get Filesystem | /api/diagnostics/system/systemDisk | 24.7 | |
| Get OpenVPN | /api/openvpn/export/providers | 20.1 | |
| Get Gateways | /api/routes/gateway/status | 2021 | |
| Get Temperatures | /api/diagnostics/system/systemTemperature | 24.7 | |
| Get Firmware Update Info | /api/core/firmware/status | 2018 | |
| Upgrade Firmware | /api/core/firmware/update<br>/api/core/firmware/upgrade | 2018 | |
| Firmware Upgrade Status | /api/core/firmware/upgradestatus | 2018 | |
| Firmware Changelog | /api/core/firmware/changelog/ | 2018 | |
