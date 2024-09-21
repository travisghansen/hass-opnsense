# XMLRPC Functions

| Function | Uses Plugin | Possible in REST API | Comments |
| ----- | ----- | ----- | ----- |
| Get Config | Yes | No as of 24.7 | Returns a __large__ dictionary of elements used for multiple functions. Some can be replaced, others cannot. More details in the other functions. |
| Restore Config Section | No | No as of 24.7 | |
| Filter Configure | Yes | No as of 24.7 | Used by the Filter and NAT functions |
| Enable Filter Rule | Yes | No as of 24.7 | Uses Get Config, Filter Configure and Restore Config Section. |
| Disable Filter Rule | Yes | No as of 24.7 | Uses Get Config, Filter Configure and Restore Config Section. |
| Enable NAT Port Forward Rule | Yes | No as of 24.7 | Uses Get Config, Filter Configure and Restore Config Section. |
| Disable NAT Port Forward Rule | Yes | No as of 24.7 | Uses Get Config, Filter Configure and Restore Config Section. |
| Enable NAT Outbound Rule | Yes | No as of 24.7 | Uses Get Config, Filter Configure and Restore Config Section. |
| Disable NAT Outbound Rule | Yes | No as of 24.7 | Uses Get Config, Filter Configure and Restore Config Section. |
| Get Configured Interface Descriptions | Yes | | Doesn't appear to be used anymore. Probably just remove altogether. |
| Get Gateways | Yes | Yes | Doesn't appear to be used anymore. Probably just remove altogether. |
| Get Gateways Status | Yes | | Doesn't appear to be used anymore. Probably just remove altogether. |
| Get DHCP Leases | Yes | Yes | Currently not in use, but desired feature. Will need to handle both the legacy DHCP and Kea endpoints. |
| Get Device ID | Yes | Maybe | Used as Unique ID for device. It is just a random 10 digit number generated the first time it is requested. May be able to transition to using the Config Entry ID or something else as a Unique ID. |
| Get Interfaces | Yes | Yes | Uses Get Config. Can use same function that is used for the Interface data for the Telemetry data. |
| Get/List Services | No | Yes | |
| Start Service | No | Yes | |
| Stop Service | No | Yes | |
| Restart Service | No | Yes | |
| Restart Service if Running | No | Yes | |
| Get Carp Status | Yes | Yes | |
| Get Carp Interfaces | Yes | Yes | |
| Delete ARP Entry | Yes | | |

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
| Get Firmware Update Info<br>Get Firmware Version | /api/core/firmware/status | 2018 | |
| Upgrade Firmware | /api/core/firmware/update<br>/api/core/firmware/upgrade | 2018 | |
| Firmware Upgrade Status | /api/core/firmware/upgradestatus | 2018 | |
| Firmware Changelog | /api/core/firmware/changelog/ | 2018 | |
| System Reboot | /api/core/system/reboot | 20.1 | |
| System Halt | /api/core/system/halt | 20.1 | |
| Send WOL | /api/wol/wol/set | 2018 | |
| Get ARP Table | /api/diagnostics/interface/search_arp | 2022 | |
| Get System Info | /api/diagnostics/system/systemInformation | 24.7 | Partial: Still using XMLRPC for Getting Device ID |
| Get Notices | /api/core/system/status | 2022 | |
| Close Notice | /api/core/system/status<br>/api/core/system/dismissStatus | 2022 | |
