<a id="v0.3.10"></a>
# [v0.3.10](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.3.10) - 2024-11-26

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🎉 Enhancements & New Features 🎉
* Add reconfigure by [@Snuffy2](https://github.com/Snuffy2) in [#325](https://github.com/travisghansen/hass-opnsense/pull/325)
* Alias Toggle Action/Service by [@Snuffy2](https://github.com/Snuffy2) in [#326](https://github.com/travisghansen/hass-opnsense/pull/326)
* Show repair and shutdown integration if new device id detected by [@Snuffy2](https://github.com/Snuffy2) in [#327](https://github.com/travisghansen/hass-opnsense/pull/327)
### 🕷️ Bug Fixes 🕷️
* Change firmware endpoint and handle non-SemVer firware by [@Snuffy2](https://github.com/Snuffy2) in [#324](https://github.com/travisghansen/hass-opnsense/pull/324)
### Other Changes
* Handle edge TypeError: argument of type 'NoneType' is not iterable errors by [@Snuffy2](https://github.com/Snuffy2) in [#314](https://github.com/travisghansen/hass-opnsense/pull/314)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.3.9...v0.3.10

[Changes][v0.3.10]


<a id="v0.3.9"></a>
# [v0.3.9](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.3.9) - 2024-11-01

<h3>OPNsense Minimum Firmware Required: 24.1</h3><h4>OPNsense Recommended Firmware: 24.7</h4><p><!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🕷️ Bug Fixes 🕷️
* Revert device class duration for Gateway sensors by [@Snuffy2](https://github.com/Snuffy2) in [#306](https://github.com/travisghansen/hass-opnsense/pull/306)
* Fix intermittent get_notices issue by [@Snuffy2](https://github.com/Snuffy2) in [#307](https://github.com/travisghansen/hass-opnsense/pull/307)
### Other Changes
* Minor sensor cleanup by [@Snuffy2](https://github.com/Snuffy2) in [#308](https://github.com/travisghansen/hass-opnsense/pull/308)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.3.8...v0.3.9<p><i>For firmware versions below the minimum version, the integration will not permit new installations and existing installations will no longer start. Firmware versions below the recommended version will likely work but may have limited features and/or show errors in the logs.</i>

[Changes][v0.3.9]


<a id="v0.3.8"></a>
# [v0.3.8](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.3.8) - 2024-10-27

<h3>OPNsense Minimum Firmware Required: 24.1</h3><h4>OPNsense Recommended Firmware: 24.7</h4><p><!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🎉 Enhancements & New Features 🎉
* Add additional details to Interfaces by [@Snuffy2](https://github.com/Snuffy2) in [#280](https://github.com/travisghansen/hass-opnsense/pull/280)
* Manually add MAC addresses as Device Trackers by [@Snuffy2](https://github.com/Snuffy2) in [#281](https://github.com/travisghansen/hass-opnsense/pull/281)
* Improve firmware check by [@Snuffy2](https://github.com/Snuffy2) in [#288](https://github.com/travisghansen/hass-opnsense/pull/288)
* VPN connected instance indicators and fixing OpenVPN server logic by [@Snuffy2](https://github.com/Snuffy2) in [#292](https://github.com/travisghansen/hass-opnsense/pull/292)
* Create Certificate Sensor by [@Snuffy2](https://github.com/Snuffy2) in [#294](https://github.com/travisghansen/hass-opnsense/pull/294)
* Further OpenVPN Server Refinements by [@Snuffy2](https://github.com/Snuffy2) in [#297](https://github.com/travisghansen/hass-opnsense/pull/297)
* Generate Captive Portal Vouchers Action by [@Snuffy2](https://github.com/Snuffy2) in [#302](https://github.com/travisghansen/hass-opnsense/pull/302)
* Further VPN Refinements by [@Snuffy2](https://github.com/Snuffy2) in [#300](https://github.com/travisghansen/hass-opnsense/pull/300)
* Kill States Action by [@Snuffy2](https://github.com/Snuffy2) in [#304](https://github.com/travisghansen/hass-opnsense/pull/304)
### 🕷️ Bug Fixes 🕷️
* Fix OpenVPN Client Error in v0.3.8-beta.1 by [@Snuffy2](https://github.com/Snuffy2) in [#293](https://github.com/travisghansen/hass-opnsense/pull/293)
* Change from tzinfo to utcoffset by [@Snuffy2](https://github.com/Snuffy2) in [#298](https://github.com/travisghansen/hass-opnsense/pull/298)
* Fix more timezone issues by [@Snuffy2](https://github.com/Snuffy2) in [#301](https://github.com/travisghansen/hass-opnsense/pull/301)
### Other Changes
* Create LICENSE by [@Snuffy2](https://github.com/Snuffy2) in [#286](https://github.com/travisghansen/hass-opnsense/pull/286)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.3.7...v0.3.8<p><i>For firmware versions below the minimum version, the integration will not permit new installations and existing installations will no longer start. Firmware versions below the recommended version will likely work but may have limited features and/or show errors in the logs.</i>

[Changes][v0.3.8]


<a id="v0.3.7"></a>
# [v0.3.7](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.3.7) - 2024-10-20

<h3>OPNsense Minimum Firmware Required: 24.1</h3><h4>OPNsense Recommended Firmware: 24.7</h4><p><!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🎉 Enhancements & New Features 🎉
* Add Wireguard. OpenVPN Sensor Enhancements. VPN Switches. by [@Snuffy2](https://github.com/Snuffy2) in [#271](https://github.com/travisghansen/hass-opnsense/pull/271)
* Move interfaces, gateways, and openvpn out of telemetry by [@Snuffy2](https://github.com/Snuffy2) in [#258](https://github.com/travisghansen/hass-opnsense/pull/258)
* Create Reload Interface Action by [@Snuffy2](https://github.com/Snuffy2) in [#276](https://github.com/travisghansen/hass-opnsense/pull/276)
* Sensor Device Class, Unit, and Icon Updates by [@Snuffy2](https://github.com/Snuffy2) in [#272](https://github.com/travisghansen/hass-opnsense/pull/272)
* Additional Sensor Default Tweaks by [@Snuffy2](https://github.com/Snuffy2) in [#273](https://github.com/travisghansen/hass-opnsense/pull/273)
* Migrate and rename filesystem sensors by [@Snuffy2](https://github.com/Snuffy2) in [#262](https://github.com/travisghansen/hass-opnsense/pull/262)
* Switch icon enhancements by [@Snuffy2](https://github.com/Snuffy2) in [#270](https://github.com/travisghansen/hass-opnsense/pull/270)
* Add all active Kea interfaces to DHCP Leases by [@Snuffy2](https://github.com/Snuffy2) in [#268](https://github.com/travisghansen/hass-opnsense/pull/268)
* Move Carp Interfaces to REST API by [@Snuffy2](https://github.com/Snuffy2) in [#275](https://github.com/travisghansen/hass-opnsense/pull/275)
* Remove OpenVPN connected_client_count Sensor by [@Snuffy2](https://github.com/Snuffy2) in [#278](https://github.com/travisghansen/hass-opnsense/pull/278)
### 🕷️ Bug Fixes 🕷️
* Fixed OpenVPN related sensors ([#264](https://github.com/travisghansen/hass-opnsense/issues/264)) by [@jesmak](https://github.com/jesmak) in [#265](https://github.com/travisghansen/hass-opnsense/pull/265)
* Fix device_tracker Presence by [@Snuffy2](https://github.com/Snuffy2) in [#266](https://github.com/travisghansen/hass-opnsense/pull/266)
* Fix making entities unavailable by [@Snuffy2](https://github.com/Snuffy2) in [#269](https://github.com/travisghansen/hass-opnsense/pull/269)

## New Contributors
* [@jesmak](https://github.com/jesmak) made their first contribution in [#265](https://github.com/travisghansen/hass-opnsense/pull/265)

**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.3.6...v0.3.7<p><i>For firmware versions below the minimum version, the integration will not permit new installations and existing installations will no longer start. Firmware versions below the recommended version will likely work but may have limited features and/or show errors in the logs.</i>

[Changes][v0.3.7]


<a id="v0.3.6"></a>
# [v0.3.6](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.3.6) - 2024-10-14

<h3>OPNsense Minimum Firmware Required: 24.1</h3><h4>OPNsense Recommended Firmware: 24.7</h4><p><!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🎉 Enhancements & New Features 🎉
* Improve some more Error Handling by [@Snuffy2](https://github.com/Snuffy2) in [#257](https://github.com/travisghansen/hass-opnsense/pull/257)
* Remove concurrency from coordinator by [@Snuffy2](https://github.com/Snuffy2) in [#256](https://github.com/travisghansen/hass-opnsense/pull/256)
### 🕷️ Bug Fixes 🕷️
* Fix TypeError in device_tracker by [@Snuffy2](https://github.com/Snuffy2) in [#255](https://github.com/travisghansen/hass-opnsense/pull/255)
* Handle migration errors by [@Snuffy2](https://github.com/Snuffy2) in [#260](https://github.com/travisghansen/hass-opnsense/pull/260)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.3.5...v0.3.6<p><i>For firmware versions below the minimum version, the integration will not permit new installations and existing installations will no longer start. Firmware versions below the recommended version will likely work but may have limited features and/or show errors in the logs.</i>

[Changes][v0.3.6]


<a id="v0.3.5"></a>
# [v0.3.5](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.3.5) - 2024-10-10

<h3>OPNsense Minimum Firmware Required: 24.1</h3><h4>OPNsense Recommended Firmware: 24.7</h4><p><!-- Release notes generated using configuration in .github/release.yml at main -->

## ATTENTION: We need debug logs from those with CARP Interfaces! [See this discussion for details.](https://github.com/travisghansen/hass-opnsense/discussions/250)

## What's Changed
### 🎉 Enhancements & New Features 🎉
* Change unique device ID to lowest MAC address by [@Snuffy2](https://github.com/Snuffy2) in [#227](https://github.com/travisghansen/hass-opnsense/pull/227)
* Move get_carp_status to REST API by [@Snuffy2](https://github.com/Snuffy2) in [#232](https://github.com/travisghansen/hass-opnsense/pull/232)
* DHCP Leases sensors by [@Snuffy2](https://github.com/Snuffy2) in [#236](https://github.com/travisghansen/hass-opnsense/pull/236)
### 🕷️ Bug Fixes 🕷️
* Fix update firmware by [@Snuffy2](https://github.com/Snuffy2) in [#230](https://github.com/travisghansen/hass-opnsense/pull/230)
* Refine Device ID Discrepancy Logging by [@Snuffy2](https://github.com/Snuffy2) in [#234](https://github.com/travisghansen/hass-opnsense/pull/234)
* Restart unbound on blocklist toggle by [@Snuffy2](https://github.com/Snuffy2) in [#241](https://github.com/travisghansen/hass-opnsense/pull/241)
* DHCP Lease Sensors fixes by [@Snuffy2](https://github.com/Snuffy2) in [#238](https://github.com/travisghansen/hass-opnsense/pull/238)
* More graceful error handling by [@Snuffy2](https://github.com/Snuffy2) in [#245](https://github.com/travisghansen/hass-opnsense/pull/245)
### Other Changes
* Add debug logging for Carp Interfaces by [@Snuffy2](https://github.com/Snuffy2) in [#231](https://github.com/travisghansen/hass-opnsense/pull/231)
* Logging refinements by [@Snuffy2](https://github.com/Snuffy2) in [#244](https://github.com/travisghansen/hass-opnsense/pull/244)
* Turn down more debug logging by [@Snuffy2](https://github.com/Snuffy2) in [#247](https://github.com/travisghansen/hass-opnsense/pull/247)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.3.4...v0.3.5<p><i>For firmware versions below the minimum version, the integration will not permit new installations and existing installations will no longer start. Firmware versions below the recommended version will likely work but may have limited features and/or show errors in the logs.</i>

[Changes][v0.3.5]


<a id="v0.3.4"></a>
# [v0.3.4](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.3.4) - 2024-10-01

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🎉 Enhancements & New Features 🎉
* Improve config_flow error handling by [@Snuffy2](https://github.com/Snuffy2) in [#225](https://github.com/travisghansen/hass-opnsense/pull/225)
### Other Changes
* Optimize entities final cleanup by [@Snuffy2](https://github.com/Snuffy2) in [#226](https://github.com/travisghansen/hass-opnsense/pull/226)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.3.3...v0.3.4

[Changes][v0.3.4]


<a id="v0.3.3"></a>
# [v0.3.3](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.3.3) - 2024-09-30

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🎉 Enhancements & New Features 🎉
* Optimize Binary Sensors by [@Snuffy2](https://github.com/Snuffy2) in [#221](https://github.com/travisghansen/hass-opnsense/pull/221)
* Optimize Sensors by [@Snuffy2](https://github.com/Snuffy2) in [#222](https://github.com/travisghansen/hass-opnsense/pull/222)
* Optimize Update by [@Snuffy2](https://github.com/Snuffy2) in [#223](https://github.com/travisghansen/hass-opnsense/pull/223)
* Optimize Device Trackers by [@Snuffy2](https://github.com/Snuffy2) in [#224](https://github.com/travisghansen/hass-opnsense/pull/224)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.3.2...v0.3.3

[Changes][v0.3.3]


<a id="v0.3.2"></a>
# [v0.3.2](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.3.2) - 2024-09-28

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 💥 Breaking Change 💥
* Move OPNsense services functions to REST API by [@Snuffy2](https://github.com/Snuffy2) in [#206](https://github.com/travisghansen/hass-opnsense/pull/206)
### 🎉 Enhancements & New Features 🎉
* Move HA services from entity level to platform level by [@Snuffy2](https://github.com/Snuffy2) in [#204](https://github.com/travisghansen/hass-opnsense/pull/204)
* Add Unbound Blocklist Switch by [@Snuffy2](https://github.com/Snuffy2) in [#210](https://github.com/travisghansen/hass-opnsense/pull/210)
* Sort Device Tracker Selector by [@Snuffy2](https://github.com/Snuffy2) in [#214](https://github.com/travisghansen/hass-opnsense/pull/214)
* Add concurrency to Coordinator by [@Snuffy2](https://github.com/Snuffy2) in [#218](https://github.com/travisghansen/hass-opnsense/pull/218)
* Optimize switches with concurrency and update logic by [@Snuffy2](https://github.com/Snuffy2) in [#219](https://github.com/travisghansen/hass-opnsense/pull/219)
### Other Changes
* Turn down Debug logging by [@Snuffy2](https://github.com/Snuffy2) in [#211](https://github.com/travisghansen/hass-opnsense/pull/211)
* Remove unused get_interfaces by [@Snuffy2](https://github.com/Snuffy2) in [#216](https://github.com/travisghansen/hass-opnsense/pull/216)

## New Contributors
* [@dependabot](https://github.com/dependabot) made their first contribution in [#213](https://github.com/travisghansen/hass-opnsense/pull/213)

**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.3.1...v0.3.2

[Changes][v0.3.2]


<a id="v0.3.1"></a>
# [v0.3.1](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.3.1) - 2024-09-22

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🎉 Enhancements & New Features 🎉
* Improve sensor error handling by [@Snuffy2](https://github.com/Snuffy2) in [#207](https://github.com/travisghansen/hass-opnsense/pull/207)
### 🕷️ Bug Fixes 🕷️
* Fix switches to use async by [@Snuffy2](https://github.com/Snuffy2) in [#208](https://github.com/travisghansen/hass-opnsense/pull/208)
### Other Changes
* Remove unused methods - take 2 by [@Snuffy2](https://github.com/Snuffy2) in [#209](https://github.com/travisghansen/hass-opnsense/pull/209)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.3.0...v0.3.1

[Changes][v0.3.1]


<a id="v0.3.0"></a>
# [v0.3.0](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.3.0) - 2024-09-20

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🎉 Enhancements & New Features 🎉
* Move get_system_info (except device_id) to REST API by [@Snuffy2](https://github.com/Snuffy2) in [#196](https://github.com/travisghansen/hass-opnsense/pull/196)
* Update config_flow exception handling by [@Snuffy2](https://github.com/Snuffy2) in [#197](https://github.com/travisghansen/hass-opnsense/pull/197)
* Change get_arp_table to REST API by [@Snuffy2](https://github.com/Snuffy2) in [#191](https://github.com/travisghansen/hass-opnsense/pull/191)
* Change send_wol to REST API by [@Snuffy2](https://github.com/Snuffy2) in [#192](https://github.com/travisghansen/hass-opnsense/pull/192)
* Change system_halt and system_reboot to REST API by [@Snuffy2](https://github.com/Snuffy2) in [#194](https://github.com/travisghansen/hass-opnsense/pull/194)
* Change notices functions to REST API by [@Snuffy2](https://github.com/Snuffy2) in [#203](https://github.com/travisghansen/hass-opnsense/pull/203)
### 🕷️ Bug Fixes 🕷️
* Handle potential AwesomeVersion errors by [@Snuffy2](https://github.com/Snuffy2) in [#189](https://github.com/travisghansen/hass-opnsense/pull/189)
### Other Changes
* Update README.md adding images by [@mkopnsrc](https://github.com/mkopnsrc) in [#185](https://github.com/travisghansen/hass-opnsense/pull/185)
* Pyopnsense and coordinator to async by [@Snuffy2](https://github.com/Snuffy2) in [#187](https://github.com/travisghansen/hass-opnsense/pull/187)
* Remove unused functions by [@Snuffy2](https://github.com/Snuffy2) in [#202](https://github.com/travisghansen/hass-opnsense/pull/202)
* Update all coordinator references by [@Snuffy2](https://github.com/Snuffy2) in [#201](https://github.com/travisghansen/hass-opnsense/pull/201)

## New Contributors
* [@mkopnsrc](https://github.com/mkopnsrc) made their first contribution in [#185](https://github.com/travisghansen/hass-opnsense/pull/185)

**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.2.1...v0.3.0

[Changes][v0.3.0]


<a id="v0.2.1"></a>
# [v0.2.1](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.2.1) - 2024-09-10

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🎉 Enhancements & New Features 🎉
* Feature: Add CPU Usage and remove CPU Frequency entities by [@Snuffy2](https://github.com/Snuffy2) in [#169](https://github.com/travisghansen/hass-opnsense/pull/169)
* Feature: Add Temperature Sensors by [@Snuffy2](https://github.com/Snuffy2) in [#168](https://github.com/travisghansen/hass-opnsense/pull/168)
### 🕷️ Bug Fixes 🕷️
* Add back support for OPNsense 24.1 by [@Snuffy2](https://github.com/Snuffy2) in [#173](https://github.com/travisghansen/hass-opnsense/pull/173)
### Other Changes
* Update get and post to handle response status by [@Snuffy2](https://github.com/Snuffy2) in [#164](https://github.com/travisghansen/hass-opnsense/pull/164)
* Create HA issue if OPNsense Firmware below min version by [@Snuffy2](https://github.com/Snuffy2) in [#178](https://github.com/travisghansen/hass-opnsense/pull/178)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.2.0...v0.2.1

[Changes][v0.2.1]


<a id="v0.2.0"></a>
# [v0.2.0 - Use the REST API for Telemetry](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.2.0) - 2024-09-07

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
# :boom: Breaking Change :boom:
* Use the REST API for Telemetry by [@Snuffy2](https://github.com/Snuffy2) in [#147](https://github.com/travisghansen/hass-opnsense/pull/147)
  * Requires that the OPNSense user has __admin__ permissions. See the Readme for details
  * OpenVPN Entities will be renamed and the old ones will need to be manually removed
  * `CPU Frequency Current` will always be _Unavailable_ for now and will likely be removed in a future version 
### :bug: Bug Fixes :bug:
* Fix pfstates access issues and readme update on permissions by [@Snuffy2](https://github.com/Snuffy2) in [#149](https://github.com/travisghansen/hass-opnsense/pull/149)
* Fix swap memory permission and gracefully handle permission errors by [@Snuffy2](https://github.com/Snuffy2) in [#150](https://github.com/travisghansen/hass-opnsense/pull/150)
* Revert instance entity naming by [@Snuffy2](https://github.com/Snuffy2) in [#151](https://github.com/travisghansen/hass-opnsense/pull/151)
* Don't show error if OpenVPN isn't used by [@Snuffy2](https://github.com/Snuffy2) in [#154](https://github.com/travisghansen/hass-opnsense/pull/154)
* Rename interfaces (take 2) by [@Snuffy2](https://github.com/Snuffy2) in [#155](https://github.com/travisghansen/hass-opnsense/pull/155)
### :wrench: Maintenance :wrench:
* Update GitHub Actions by [@Snuffy2](https://github.com/Snuffy2) in [#156](https://github.com/travisghansen/hass-opnsense/pull/156)
* Auto Label PRs and Update Changelog by [@Snuffy2](https://github.com/Snuffy2) in [#159](https://github.com/travisghansen/hass-opnsense/pull/159)

## New Contributors
* [@Snuffy2](https://github.com/Snuffy2) made their first contribution in [#147](https://github.com/travisghansen/hass-opnsense/pull/147)

**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.1.21...v0.2.0

[Changes][v0.2.0]


<a id="v0.1.22"></a>
# [v0.1.22](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.22) - 2024-09-04



[Changes][v0.1.22]


<a id="v0.1.21"></a>
# [v0.1.21](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.21) - 2024-03-18



[Changes][v0.1.21]


<a id="v0.1.20"></a>
# [v0.1.20](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.20) - 2024-02-17



[Changes][v0.1.20]


<a id="v0.1.19"></a>
# [v0.1.19](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.19) - 2024-02-17



[Changes][v0.1.19]


<a id="v0.1.18"></a>
# [v0.1.18](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.18) - 2024-02-16



[Changes][v0.1.18]


<a id="v0.1.17"></a>
# [v0.1.17](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.17) - 2024-02-12



[Changes][v0.1.17]


<a id="v0.1.16"></a>
# [v0.1.16](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.16) - 2023-04-30

# v0.1.16

Released 2023-04-30

- minor fixes
- support for hass 2023.5

[Changes][v0.1.16]


<a id="v0.1.15"></a>
# [v0.1.15](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.15) - 2023-03-21

Released 2023-03-21

- temporary workaround for removal of `openvpn_get_active_servers()` in `23.1.4`


[Changes][v0.1.15]


<a id="v0.1.14"></a>
# [v0.1.14](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.14) - 2023-02-19

Released 2023-02-19

- update deprecated syntax (`exec_command()` replaced by `shell_safe()` in `23.1.1`)

[Changes][v0.1.14]


<a id="v0.1.13"></a>
# [v0.1.13](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.13) - 2023-01-30



[Changes][v0.1.13]


<a id="v0.1.12"></a>
# [v0.1.12](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.12) - 2023-01-30



[Changes][v0.1.12]


<a id="v0.1.11"></a>
# [v0.1.11](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.11) - 2023-01-30



[Changes][v0.1.11]


<a id="v0.1.10"></a>
# [v0.1.10](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.10) - 2023-01-30



[Changes][v0.1.10]


<a id="v0.1.9"></a>
# [v0.1.9](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.9) - 2023-01-22



[Changes][v0.1.9]


<a id="v0.1.8"></a>
# [v0.1.8](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.8) - 2023-01-18



[Changes][v0.1.8]


<a id="v0.1.7"></a>
# [v0.1.7](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.7) - 2023-01-16



[Changes][v0.1.7]


<a id="v0.1.6"></a>
# [v0.1.6](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.6) - 2023-01-16



[Changes][v0.1.6]


<a id="v0.1.5"></a>
# [v0.1.5](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.5) - 2022-08-18



[Changes][v0.1.5]


<a id="v0.1.4"></a>
# [v0.1.4](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.4) - 2022-08-18



[Changes][v0.1.4]


<a id="v0.1.3"></a>
# [v0.1.3](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.3) - 2022-08-17



[Changes][v0.1.3]


<a id="v0.1.2"></a>
# [v0.1.2](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.2) - 2022-08-01



[Changes][v0.1.2]


<a id="v0.1.1"></a>
# [v0.1.1](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.1) - 2022-07-11



[Changes][v0.1.1]


<a id="v0.1.0"></a>
# [v0.1.0](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.0) - 2022-07-09



[Changes][v0.1.0]


[v0.3.10]: https://github.com/travisghansen/hass-opnsense/compare/v0.3.9...v0.3.10
[v0.3.9]: https://github.com/travisghansen/hass-opnsense/compare/v0.3.8...v0.3.9
[v0.3.8]: https://github.com/travisghansen/hass-opnsense/compare/v0.3.7...v0.3.8
[v0.3.7]: https://github.com/travisghansen/hass-opnsense/compare/v0.3.6...v0.3.7
[v0.3.6]: https://github.com/travisghansen/hass-opnsense/compare/v0.3.5...v0.3.6
[v0.3.5]: https://github.com/travisghansen/hass-opnsense/compare/v0.3.4...v0.3.5
[v0.3.4]: https://github.com/travisghansen/hass-opnsense/compare/v0.3.3...v0.3.4
[v0.3.3]: https://github.com/travisghansen/hass-opnsense/compare/v0.3.2...v0.3.3
[v0.3.2]: https://github.com/travisghansen/hass-opnsense/compare/v0.3.1...v0.3.2
[v0.3.1]: https://github.com/travisghansen/hass-opnsense/compare/v0.3.0...v0.3.1
[v0.3.0]: https://github.com/travisghansen/hass-opnsense/compare/v0.2.1...v0.3.0
[v0.2.1]: https://github.com/travisghansen/hass-opnsense/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.22...v0.2.0
[v0.1.22]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.21...v0.1.22
[v0.1.21]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.20...v0.1.21
[v0.1.20]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.19...v0.1.20
[v0.1.19]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.18...v0.1.19
[v0.1.18]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.17...v0.1.18
[v0.1.17]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.16...v0.1.17
[v0.1.16]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.15...v0.1.16
[v0.1.15]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.14...v0.1.15
[v0.1.14]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.13...v0.1.14
[v0.1.13]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.12...v0.1.13
[v0.1.12]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.11...v0.1.12
[v0.1.11]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.10...v0.1.11
[v0.1.10]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.9...v0.1.10
[v0.1.9]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.8...v0.1.9
[v0.1.8]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.7...v0.1.8
[v0.1.7]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.6...v0.1.7
[v0.1.6]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.5...v0.1.6
[v0.1.5]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.4...v0.1.5
[v0.1.4]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.3...v0.1.4
[v0.1.3]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.2...v0.1.3
[v0.1.2]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.1...v0.1.2
[v0.1.1]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.0...v0.1.1
[v0.1.0]: https://github.com/travisghansen/hass-opnsense/tree/v0.1.0

<!-- Generated by https://github.com/rhysd/changelog-from-release v3.8.0 -->
