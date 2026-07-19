# OPNsense API Permissions

`All pages` grants access to every endpoint and is recommended, but the narrower permissions are below.

This page maps every OPNsense API endpoint used by the integration's `aiopnsense` client to the OPNsense permission that grants access to it. 

Endpoint parameters are shown in braces, for example `{uuid}`. OPNsense firmware before 25.7 uses the camelCase endpoint variant shown in parentheses for endpoints that were renamed to snake_case.

# Base Permissions Required for the Integration

These permissions are required during setup and normal operation, regardless of the selected granular sync options.

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Lobby: Dashboard | GET | `/api/diagnostics/system/system_information` (or `/api/diagnostics/system/systemInformation`) |
| Status: Interfaces | GET | `/api/interfaces/overview/export` |
| System: Firmware | GET | `/api/core/firmware/status` |

# Granular Sync Permissions

## Basic Telemetry Data

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Lobby: Dashboard | GET | `/api/diagnostics/system/system_mbuf`<br>`/api/diagnostics/firewall/pf_states`<br>`/api/diagnostics/system/system_resources` (or `/api/diagnostics/system/systemResources`)<br>`/api/diagnostics/system/system_swap`<br>`/api/diagnostics/system/system_time` (or `/api/diagnostics/system/systemTime`)<br>`/api/diagnostics/cpu_usage/get_c_p_u_type` (or `/api/diagnostics/cpu_usage/getCPUType`)<br>`/api/diagnostics/cpu_usage/stream`<br>`/api/diagnostics/system/system_disk` (or `/api/diagnostics/system/systemDisk`)<br>`/api/diagnostics/system/system_temperature` (or `/api/diagnostics/system/systemTemperature`) |

## Gateway Information

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| System: Gateways | GET | `/api/routes/gateway/status` |

## Interface Information

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Status: Interfaces | GET | `/api/interfaces/overview/export` |

## Live Traffic Metrics

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Reporting: Traffic | GET | `/api/diagnostics/traffic/interface`<br>`/api/diagnostics/traffic/stream/{interval}` |

This option depends on "Interface information". If disabled, interface traffic rates are calculated from coordinator polling instead of the live stream.

## DHCP Leases

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Services: DHCP: Kea(v4) | GET | `/api/kea/leases4/search`<br>`/api/kea/dhcpv4/search_reservation` (or `/api/kea/dhcpv4/searchReservation`)<br>`/api/kea/dhcpv4/get` |
| Services: DHCP: Kea(v6) | GET | `/api/kea/leases6/search` |
| Services: Dnsmasq DNS/DHCP: Settings | GET | `/api/dnsmasq/leases/search` |
| Status: DHCP leases (25.x)<br>Services: ISC DHCPv4: Leases (26.1+) | GET | `/api/dhcpv4/leases/search_lease` (or `/api/dhcpv4/leases/searchLease`) |
| Status: DHCPv6 leases (25.x)<br>Status: ISC DHCPv6: Leases (26.1+) | GET | `/api/dhcpv6/leases/search_lease` (or `/api/dhcpv6/leases/searchLease`) |
| All pages | GET | `/api/dhcpv4/service/status`<br>`/api/dhcpv6/service/status` |

OPNsense does not currently assign the ISC DHCP service-status endpoints to a narrower privilege. `All pages` is therefore required only when ISC DHCP lease discovery is needed; Kea and Dnsmasq lease collection use their own granular permissions.

## Notice Information

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| System: Status | GET | `/api/core/system/status` |

## Firmware Updates

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| System: Firmware | GET | `/api/core/firmware/status`<br>`/api/core/firmware/upgradestatus` |
| System: Firmware | POST | `/api/core/firmware/check`<br>`/api/core/firmware/update`<br>`/api/core/firmware/upgrade`<br>`/api/core/firmware/changelog/{version}` |

## CARP Information and Maintenance

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Interfaces: Virtual IPs: Status | GET | `/api/diagnostics/interface/get_vip_status` |
| Interfaces: Virtual IPs: Status | POST | `/api/diagnostics/interface/carp_status/maintenance` (26.1.11+) |
| Interfaces: Virtual IPs: Settings | GET | `/api/interfaces/vip_settings/get` |
| All pages | POST | `/api/diagnostics/interface/_carp_status/maintenance` (25.7 through 26.1.10)<br>`/api/diagnostics/interface/CarpStatus/maintenance` (before 25.7) |

The OPNsense `Interfaces: Virtual IPs: Status` ACL did not cover the parameterized CARP maintenance endpoint before firmware 26.1.11, so older supported firmware requires `All pages` for CARP maintenance changes.

## Firewall Rules and NAT Rule Switches

Available on OPNsense firmware 26.1.1 and newer.

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Firewall: Rules [new] | GET | `/api/firewall/filter/download_rules` |
| Firewall: Rules [new] | POST | `/api/firewall/filter/toggle_rule/{uuid}`<br>`/api/firewall/filter/toggle_rule/{uuid}/{state}`<br>`/api/firewall/filter/apply` |
| Firewall: NAT: Destination NAT | GET | `/api/firewall/d_nat/search_rule` |
| Firewall: NAT: Destination NAT | POST | `/api/firewall/d_nat/toggle_rule/{uuid}`<br>`/api/firewall/d_nat/toggle_rule/{uuid}/{state}`<br>`/api/firewall/d_nat/apply` |
| Firewall: NAT: 1:1 | GET | `/api/firewall/one_to_one/search_rule` |
| Firewall: NAT: 1:1 | POST | `/api/firewall/one_to_one/toggle_rule/{uuid}`<br>`/api/firewall/one_to_one/toggle_rule/{uuid}/{state}`<br>`/api/firewall/one_to_one/apply` |
| Firewall: NAT: Source NAT | GET | `/api/firewall/source_nat/search_rule` |
| Firewall: NAT: Source NAT | POST | `/api/firewall/source_nat/toggle_rule/{uuid}`<br>`/api/firewall/source_nat/toggle_rule/{uuid}/{state}`<br>`/api/firewall/source_nat/apply` |
| Firewall: NAT: NPTv6 | GET | `/api/firewall/npt/search_rule` |
| Firewall: NAT: NPTv6 | POST | `/api/firewall/npt/toggle_rule/{uuid}`<br>`/api/firewall/npt/toggle_rule/{uuid}/{state}`<br>`/api/firewall/npt/apply` |

Firewall and NAT rule switches are unavailable on older firmware; the deprecated OPNsense Home Assistant plugin is not used as a fallback.

## Service Switches

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Status: Services | GET | `/api/core/service/search` |
| Status: Services | POST | `/api/core/service/start/{service}`<br>`/api/core/service/stop/{service}`<br>`/api/core/service/restart/{service}` |

## VPN Information and Switches

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Status: OpenVPN | GET | `/api/openvpn/service/search_sessions` (or `/api/openvpn/service/searchSessions`)<br>`/api/openvpn/service/search_routes` (or `/api/openvpn/service/searchRoutes`) |
| Status: OpenVPN | POST | `/api/openvpn/service/reconfigure` |
| VPN: OpenVPN: Instances | GET | `/api/openvpn/instances/search`<br>`/api/openvpn/instances/get/{uuid}` |
| VPN: OpenVPN: Instances | POST | `/api/openvpn/instances/toggle/{uuid}` |
| VPN: OpenVPN: Client Export Utility | GET | `/api/openvpn/export/providers` |
| VPN: WireGuard (25.1)<br>VPN: WireGuard: Configuration (25.7+) | GET | `/api/wireguard/service/show`<br>`/api/wireguard/client/get`<br>`/api/wireguard/server/get` |
| VPN: WireGuard (25.1)<br>VPN: WireGuard: Configuration (25.7+) | POST | `/api/wireguard/client/toggle_client/{uuid}` (or `/api/wireguard/client/toggleClient/{uuid}`)<br>`/api/wireguard/server/toggle_server/{uuid}` (or `/api/wireguard/server/toggleServer/{uuid}`)<br>`/api/wireguard/service/reconfigure` |
| VPN: WireGuard: Status (25.7+, alternative for status-only access) | GET / POST | `/api/wireguard/service/show`<br>`/api/wireguard/service/reconfigure` |

## Security Certificate Information

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| System: Certificate Manager | GET | `/api/trust/cert/search` |

## Unbound Blocklist Switch

The permission is named `Services: Unbound (MVC)` on OPNsense 25.x and `Services: Unbound` on OPNsense 26.1 and newer.

| OPNsense Permission | Firmware | Method | API Endpoints |
| --- | --- | --- | --- |
| Services: Unbound (MVC)<br>Services: Unbound | Before 25.7.8 | GET / POST | `/api/unbound/service/dnsbl`<br>`/api/unbound/settings/get`<br>`/api/unbound/settings/set`<br>`/api/unbound/service/restart` |
| Services: Unbound (MVC)<br>Services: Unbound | 25.7.8+ | GET / POST | `/api/unbound/settings/search_dnsbl`<br>`/api/unbound/settings/toggle_dnsbl/{uuid}/{state}` |

## Device Trackers

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Diagnostics: ARP Table | GET | `/api/diagnostics/interface/search_arp` (availability probe)<br>`/api/diagnostics/interface/search_arp?resolve={yes-or-no}` |

## NUT UPS Information

Requires the OPNsense NUT plugin.

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Nut | GET | `/api/nut/diagnostics/upsstatus` |

## SMART Information

Requires the OPNsense SMART plugin.

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Services: SMART | POST | `/api/smart/service/list` (availability probe)<br>`/api/smart/service/list/1`<br>`/api/smart/service/info` |

## Speedtest Results

Requires a supported OPNsense Speedtest plugin. Both supported plugin variants use the same `Monitoring: Speedtest` permission.

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Monitoring: Speedtest | GET | `/api/speedtest/service/showlog`<br>`/api/speedtest/service/showstat` |

## vnStat Metrics

Requires the OPNsense vnStat plugin.

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Services: Vnstat | GET | `/api/vnstat/service/hourly`<br>`/api/vnstat/service/daily`<br>`/api/vnstat/service/monthly` |

# Action (Service) Permissions

## Close Notice (`opnsense.close_notice`)

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| System: Status | GET | `/api/core/system/status` |
| System: Status | POST | `/api/core/system/dismiss_status` (or `/api/core/system/dismissStatus`) |

## Shutdown OPNsense (`opnsense.system_halt`)

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Diagnostics: Halt system | POST | `/api/core/system/halt` |

## Reboot OPNsense (`opnsense.system_reboot`)

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Diagnostics: Reboot System | POST | `/api/core/system/reboot` |

## Start, Stop, or Restart Service

Applies to `opnsense.start_service`, `opnsense.stop_service`, and `opnsense.restart_service`.

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Status: Services | POST | `/api/core/service/start/{service}`<br>`/api/core/service/stop/{service}`<br>`/api/core/service/restart/{service}` |

## Send Wake on LAN (`opnsense.send_wol`)

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Services: Wake on LAN | POST | `/api/wol/wol/set` |

## Reload Interface (`opnsense.reload_interface`)

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Status: Interfaces | POST | `/api/interfaces/overview/reload_interface/{interface}` (or `/api/interfaces/overview/reloadInterface/{interface}`) |

## Kill States (`opnsense.kill_states`)

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Diagnostics: Show States | POST | `/api/diagnostics/firewall/kill_states/` |

## Generate Captive Portal Vouchers (`opnsense.generate_vouchers`)

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Services: Captive Portal | GET | `/api/captiveportal/voucher/list_providers` (or `/api/captiveportal/voucher/listProviders`) |
| Services: Captive Portal | POST | `/api/captiveportal/voucher/generate_vouchers/{server}/` (or `/api/captiveportal/voucher/generateVouchers/{server}/`) |

## Toggle Alias (`opnsense.toggle_alias`)

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Firewall: Alias: Edit | GET | `/api/firewall/alias/search_item` (or `/api/firewall/alias/searchItem`) |
| Firewall: Alias: Edit | POST | `/api/firewall/alias/toggle_item/{uuid}/{state}` (or `/api/firewall/alias/toggleItem/{uuid}/{state}`)<br>`/api/firewall/alias/set`<br>`/api/firewall/alias/reconfigure` |

## Run Speedtest (`opnsense.run_speedtest`)

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Monitoring: Speedtest | GET | `/api/speedtest/service/run` |

## Get vnStat Metrics (`opnsense.get_vnstat_metrics`)

| OPNsense Permission | Method | API Endpoints |
| --- | --- | --- |
| Services: Vnstat | GET | `/api/vnstat/service/hourly`<br>`/api/vnstat/service/daily`<br>`/api/vnstat/service/monthly`<br>`/api/vnstat/service/yearly` |
