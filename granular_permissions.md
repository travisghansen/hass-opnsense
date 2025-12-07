# Base Permissions <ins>required</ins> for the Integration

| OPNsense Permission | API Endpoints |
| ----- | ----- |
| Lobby: Dashboard | /api/diagnostics/system/system_information (or systemInformation) |
| Status: Interfaces | /api/interfaces/overview/export |
| System: Firmware | /api/core/firmware/status |

# Granular Sync Permissions

## Basic telemetry data

|  OPNsense Permission | API Endpoints |
| ----- | ----- |
| Lobby: Dashboard | /api/diagnostics/system/system_mbuf<br>/api/diagnostics/firewall/pf_states<br>/api/diagnostics/system/system_resources (or systemResources)<br>/api/diagnostics/system/system_swap<br>/api/diagnostics/system/system_time (or systemTime)<br>/api/diagnostics/cpu_usage/get_c_p_u_type (or getCPUType)<br>/api/diagnostics/cpu_usage/stream<br>/api/diagnostics/system/system_disk (or systemDisk)<br>/api/diagnostics/system/system_temperature (or systemTemperature) |

## Gateway information

| OPNsense Permission | API Endpoints |
| ----- | ----- |
| System: Gateways | /api/routes/gateway/status |

## Interface information

| OPNsense Permission | API Endpoints |
| ----- | ----- |
| Status: Interfaces | /api/interfaces/overview/export |

## DHCP leases

| OPNsense Permission | API Endpoints |
| ----- | ----- |
| Services: DHCP: Kea(v4) | /api/kea/leases4/search<br>/api/kea/dhcpv4/search_reservation (or searchReservation)<br>/api/kea/dhcpv4/get |
| Status: DHCP leases | /api/dhcpv4/leases/search_lease (or searchLease) |
| Status: DHCPv6 leases | /api/dhcpv6/leases/search_lease (or searchLease) |
| Services: Dnsmasq DNS/DHCP: Settings | /api/dnsmasq/leases/search |

## Notice information

|  OPNsense Permission | API Endpoints |
| ----- | ----- |
| System: Status | /api/core/system/status |

## Firmware updates

| OPNsense Permission | API Endpoints |
| ----- | ----- |
| System: Firmware | /api/core/firmware/changelog<br>/api/core/firmware/status<br>/api/core/firmware/update<br>/api/core/firmware/upgrade<br>/api/core/firmware/upgradestatus |

## CARP information

| OPNsense Permission | API Endpoints |
| ----- | ----- |
| Interfaces: Virtual IPs: Status | /api/diagnostics/interface/get_vip_status |
| Interfaces: Virtual IPs: Settings | /api/interfaces/vip_settings/get |

## Firewall filter and NAT switches
> **\*\*OPNsense plugin required\*\***

| OPNsense Permission | API Endpoints |
| ----- | ----- |
| XMLRPC Library | _N/A – Operations are executed using the XMLRPC interface and OPNsense plugin_ |

## Service switches

| OPNsense Permission | API Endpoints | 
| ----- | ----- |
| Status: Services | /api/core/service/search<br>/api/core/service/start<br>/api/core/service/stop |

## VPN information and switches

| OPNsense Permission | API Endpoints |
| ----- | ----- |
| Status: OpenVPN | /api/openvpn/service/reconfigure<br>/api/openvpn/service/search_sessions (or searchSessions) |
| VPN: OpenVPN: Instances | /api/openvpn/instances/get<br>/api/openvpn/instances/search<br>/api/openvpn/instances/toggle |
| VPN: OpenVPN: Client Export Utility | /api/openvpn/export/providers |
| VPN: WireGuard | /api/wireguard/client/get<br>/api/wireguard/client/toggle_client (or toggleClient)<br>/api/wireguard/server/get<br>/api/wireguard/service/reconfigure<br>/api/wireguard/service/show<br>/api/wireguard/server/toggle_server (or toggleServer) |

## Security certificate information

|  OPNsense Permission | API Endpoints |
| ----- | ----- |
| System: Certificate Manager | /api/trust/cert/search |

## Unbound blocklist switch

|  OPNsense Permission | API Endpoints |
| ----- | ----- |
| Services: Unbound (MVC) | **Firmware <25.7.8**<br>/api/unbound/service/dnsbl<br>/api/unbound/settings/get<br>/api/unbound/service/restart<br>/api/unbound/settings/set<br>**Firmware >=25.7.8**<br>/api/unbound/settings/search_dnsbl<br>/api/unbound/settings/toggle_dnsbl |

## Device Trackers

| OPNsense Permission | API Endpoints |
| ----- | ----- |
| Diagnostics: ARP Table | /api/diagnostics/interface/search_arp |

# Action (Service) Permissions

## Close Notice _(opnsense.close_notice)_

|  OPNsense Permission | API Endpoints |
| ----- | ----- |
| System: Status | /api/core/system/dismiss_status (or dismissStatus)<br>/api/core/system/status |

## Shutdown OPNsense _(opnsense.system_halt)_

|  OPNsense Permission | API Endpoints |
| ----- | ----- |
| Diagnostics: Halt system | /api/core/system/halt |

## Reboot OPNsense _(opnsense.system_reboot)_

|  OPNsense Permission | API Endpoints |
| ----- | ----- |
| Diagnostics: Reboot System | /api/core/system/reboot |

## Start Service _(opnsense.start_service)_

|  OPNsense Permission | API Endpoints |
| ----- | ----- |
| Status: Services | /api/core/service/start |

## Stop Service _(opnsense.stop_service)_

|  OPNsense Permission | API Endpoints |
| ----- | ----- |
| Status: Services | /api/core/service/stop |

## Restart Service _(opnsense.restart_service)_

|  OPNsense Permission | API Endpoints |
| ----- | ----- |
| Status: Services | /api/core/service/restart |

## Send Wake on LAN _(opnsense.send_wol)_

|  OPNsense Permission | API Endpoints |
| ----- | ----- |
| Services: Wake on LAN | /api/wol/wol/set |

## Reload Interface _(opnsense.reload_interface)_

|  OPNsense Permission | API Endpoints |
| ----- | ----- |
| Status: Interfaces | /api/interfaces/overview/reload_interface (or reloadInterface) |

## Kill States _(opnsense.kill_states)_

|  OPNsense Permission | API Endpoints |
| ----- | ----- |
| Diagnostics: Show States | /api/diagnostics/firewall/kill_states |

## Generate Captive Portal Vouchers _(opnsense.generate_vouchers)_

|  OPNsense Permission | API Endpoints |
| ----- | ----- |
| Services: Captive Portal | /api/captiveportal/voucher/generate_vouchers (or generateVouchers)<br>/api/captiveportal/voucher/list_providers (or listProviders) |

## Toggle Alias _(opnsense.toggle_alias)_

|  OPNsense Permission | API Endpoints |
| ----- | ----- |
| Firewall: Alias: Edit | /api/firewall/alias/reconfigure<br>/api/firewall/alias/search_item (or searchItem)<br>/api/firewall/alias/set<br>/api/firewall/alias/toggle_item (or toggleItem) |
