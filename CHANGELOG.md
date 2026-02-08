<a id="v0.6.0"></a>
# [v0.6.0](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.6.0) - 2026-02-08


# Important Breaking Changes: Please Read

**If you are running OPNsense firmware < 26.1.1, existing Firewall and NAT switches will remain and the plugin will continue to work (if you were using it).**

With the addition of the Firewall and NAT Rules API in OPNsense 26.1.1 _**(note the extra .1)**_, the integration no longer needs to rely on the XMLRPC plugin for firewall and NAT rules and can now directly query the API. Additionally, with a future 26.1.x release, the plugin will [stop working altogether](https://github.com/opnsense/changelog/blob/5a6e7d3689da440e5eee6bcae9d5a2e679613917/community/26.1/26.1#L119).

When you update to hass-opnsense v0.6.0 and are running OPNsense 26.1.1+, the legacy NAT Outbound and NAT Port Forward rule switches will be removed. When the OPNsense plugin is removed, hass-opnsense will also remove the legacy Firewall Filter switches. **Before you remove the plugin, be sure to complete the [firewall migration](https://github.com/opnsense/changelog/blob/5a6e7d3689da440e5eee6bcae9d5a2e679613917/community/26.1/26.1#L123) in OPNsense.**

New, disabled switches will be added for new Firewall Rules, NAT Source Rules, NAT Destination Rules, NAT One to One Rules, and NAT NPTv6 Rules. *NAT Outbound Rule switches will no longer be supported in the integration until OPNsense adds them as an API.*

**Any Automations, Scripts, Dashboards, etc. using Firewall or NAT switches will need to be updated.**

## What's Changed
### 💥 Breaking Changes
* Implement new firewall api and deprecate plugin by [@Snuffy2](https://github.com/Snuffy2) in [#489](https://github.com/travisghansen/hass-opnsense/pull/489)
### 🚀 Enhancements
* Check for ISC DHCP plugin availability before querying for leases by [@Snuffy2](https://github.com/Snuffy2) in [#487](https://github.com/travisghansen/hass-opnsense/pull/487)
* Relax Unique ID logic by [@Snuffy2](https://github.com/Snuffy2) in [#493](https://github.com/travisghansen/hass-opnsense/pull/493)
### 🐛 Bug Fixes
* Show Floating for Firewall Rules and add Extra State Attr by [@Snuffy2](https://github.com/Snuffy2) in [#491](https://github.com/travisghansen/hass-opnsense/pull/491)
* Rename granular sync options by [@Snuffy2](https://github.com/Snuffy2) in [#492](https://github.com/travisghansen/hass-opnsense/pull/492)
* Handle when legacy firewall and nat rules are empty by [@Snuffy2](https://github.com/Snuffy2) in [#494](https://github.com/travisghansen/hass-opnsense/pull/494)
* Fix plugin check and plugin removal wording by [@Snuffy2](https://github.com/Snuffy2) in [#495](https://github.com/travisghansen/hass-opnsense/pull/495)
* Better handle naming Floating Firewall Rules by [@Snuffy2](https://github.com/Snuffy2) in [#496](https://github.com/travisghansen/hass-opnsense/pull/496)
* Shorten switch names by [@Snuffy2](https://github.com/Snuffy2) in [#497](https://github.com/travisghansen/hass-opnsense/pull/497)
### 📚 Documentation
* Update Documentation for Deprecating Plugin by [@Snuffy2](https://github.com/Snuffy2) in [#490](https://github.com/travisghansen/hass-opnsense/pull/490)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.5.0...v0.6.0



[Changes][v0.6.0]


<a id="v0.5.0"></a>
# [v0.5.0](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.5.0) - 2025-12-08

<h3>OPNsense Minimum Firmware Required: 24.7</h3><h4>OPNsense Recommended Firmware: 25.1</h4><p><!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 💥 Breaking Changes
* Support extended blocklists by [@Snuffy2](https://github.com/Snuffy2) in [#471](https://github.com/travisghansen/hass-opnsense/pull/471)
  * For firmware >= 25.7.8, the previous Unbound Blocklist Switch will be replaced (need to manually delete it) by a separate switch per Unbound blocklist row.
### 🐛 Bug Fixes
* Fix pytest errors by [@Snuffy2](https://github.com/Snuffy2) in [#470](https://github.com/travisghansen/hass-opnsense/pull/470)
* Increase Device Tracker Consider Home max from 600 to 3600 seconds by [@Snuffy2](https://github.com/Snuffy2) in [#472](https://github.com/travisghansen/hass-opnsense/pull/472)
* Fix VPN Connected Client count by [@Snuffy2](https://github.com/Snuffy2) in [#473](https://github.com/travisghansen/hass-opnsense/pull/473)
### 🎓 Code Quality
* Standardize from patch to monkeypatch by [@Snuffy2](https://github.com/Snuffy2) in [#446](https://github.com/travisghansen/hass-opnsense/pull/446)
* Refine pre-commit, labels and pytest github action by [@Snuffy2](https://github.com/Snuffy2) in [#449](https://github.com/travisghansen/hass-opnsense/pull/449)
### Other Changes
* Change from copilot-instructions to AGENTS by [@Snuffy2](https://github.com/Snuffy2) in [#469](https://github.com/travisghansen/hass-opnsense/pull/469)
* Move requirements to pyproject.toml by [@Snuffy2](https://github.com/Snuffy2) in [#474](https://github.com/travisghansen/hass-opnsense/pull/474)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.4.8...v0.5.0<p><i>For firmware versions below the minimum version, the integration will not permit new installations and existing installations will no longer start. Firmware versions below the recommended version will likely work but may have limited features and/or show errors in the logs.</i>

[Changes][v0.5.0]


<a id="v0.4.8"></a>
# [v0.4.8](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.4.8) - 2025-09-07

<h3>OPNsense Minimum Firmware Required: 24.7</h3><h4>OPNsense Recommended Firmware: 25.1</h4><p><!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🐛 Bug Fixes
* Fix plugin check in config_flow by [@Snuffy2](https://github.com/Snuffy2) in [#433](https://github.com/travisghansen/hass-opnsense/pull/433)
* Replace deprecated asyncio.get_event_loop() by [@Snuffy2](https://github.com/Snuffy2) in [#436](https://github.com/travisghansen/hass-opnsense/pull/436)
### 📚 Documentation
* Show coverage on Readme by [@Snuffy2](https://github.com/Snuffy2) in [#441](https://github.com/travisghansen/hass-opnsense/pull/441)
### 🎓 Code Quality
* Unit and integration tests by [@Snuffy2](https://github.com/Snuffy2) in [#432](https://github.com/travisghansen/hass-opnsense/pull/432)
* Update pre-commit by [@Snuffy2](https://github.com/Snuffy2) in [#442](https://github.com/travisghansen/hass-opnsense/pull/442)
### 🧰 Maintenance
* Update linting CI by [@Snuffy2](https://github.com/Snuffy2) in [#443](https://github.com/travisghansen/hass-opnsense/pull/443)
* Fix pytest CI by [@Snuffy2](https://github.com/Snuffy2) in [#434](https://github.com/travisghansen/hass-opnsense/pull/434)
* Update Python caching in GitHub Actions by [@Snuffy2](https://github.com/Snuffy2) in [#435](https://github.com/travisghansen/hass-opnsense/pull/435)
* Update pytest CI checkout by [@Snuffy2](https://github.com/Snuffy2) in [#437](https://github.com/travisghansen/hass-opnsense/pull/437)
* Refine pytest CI comment by [@Snuffy2](https://github.com/Snuffy2) in [#438](https://github.com/travisghansen/hass-opnsense/pull/438)
* Replace pytest CI Comment Action by [@Snuffy2](https://github.com/Snuffy2) in [#439](https://github.com/travisghansen/hass-opnsense/pull/439)
* Refine pytest CI again by [@Snuffy2](https://github.com/Snuffy2) in [#440](https://github.com/travisghansen/hass-opnsense/pull/440)
* Split Requirements and Update GitHub Actions by [@Snuffy2](https://github.com/Snuffy2) in [#445](https://github.com/travisghansen/hass-opnsense/pull/445)

**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.4.7...v0.4.8<p><i>For firmware versions below the minimum version, the integration will not permit new installations and existing installations will no longer start. Firmware versions below the recommended version will likely work but may have limited features and/or show errors in the logs.</i>

[Changes][v0.4.8]


<a id="v0.4.7"></a>
# [v0.4.7](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.4.7) - 2025-08-06

<h3>OPNsense Minimum Firmware Required: 24.7</h3><h4>OPNsense Recommended Firmware: 25.1</h4><p><!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🐛 Bug Fixes
* Handle AttributeError: 'NoneType' object has no attribute 'items' by [@Snuffy2](https://github.com/Snuffy2) in [#423](https://github.com/travisghansen/hass-opnsense/pull/423)
* Check for snake case from config_flow by [@Snuffy2](https://github.com/Snuffy2) in [#424](https://github.com/travisghansen/hass-opnsense/pull/424)
### 📚 Documentation
* Update README.md by [@Snuffy2](https://github.com/Snuffy2) in [#420](https://github.com/travisghansen/hass-opnsense/pull/420)
### 🧰 Maintenance
* Update GitHub Actions by [@Snuffy2](https://github.com/Snuffy2) in [#421](https://github.com/travisghansen/hass-opnsense/pull/421)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.4.6...v0.4.7<p><i>For firmware versions below the minimum version, the integration will not permit new installations and existing installations will no longer start. Firmware versions below the recommended version will likely work but may have limited features and/or show errors in the logs.</i>

[Changes][v0.4.7]


<a id="v0.4.6"></a>
# [v0.4.6](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.4.6) - 2025-08-02

<h3>OPNsense Minimum Firmware Required: 24.7</h3><h4>OPNsense Recommended Firmware: 25.1</h4><p><!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🐛 Bug Fixes
* Clarify permission issues on initial setup by [@Snuffy2](https://github.com/Snuffy2) in [#417](https://github.com/travisghansen/hass-opnsense/pull/417)
* Fix when a firmware check triggers by [@Snuffy2](https://github.com/Snuffy2) in [#419](https://github.com/travisghansen/hass-opnsense/pull/419)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.4.5...v0.4.6<p><i>For firmware versions below the minimum version, the integration will not permit new installations and existing installations will no longer start. Firmware versions below the recommended version will likely work but may have limited features and/or show errors in the logs.</i>

[Changes][v0.4.6]


<a id="v0.4.5"></a>
# [v0.4.5](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.4.5) - 2025-07-24

<h3>OPNsense Minimum Firmware Required: 24.7</h3><h4>OPNsense Recommended Firmware: 25.1</h4><p><!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🐛 Bug Fixes
* Don't check Dnsmasq leases if < 25.1.7 by [@Snuffy2](https://github.com/Snuffy2) in [#414](https://github.com/travisghansen/hass-opnsense/pull/414)
### 🎓 Code Quality
* Log what function an error came from by [@Snuffy2](https://github.com/Snuffy2) in [#412](https://github.com/travisghansen/hass-opnsense/pull/412)
### Other Changes
* Handle snake case if 25.7+ by [@Snuffy2](https://github.com/Snuffy2) in [#413](https://github.com/travisghansen/hass-opnsense/pull/413)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.4.4...v0.4.5<p><i>For firmware versions below the minimum version, the integration will not permit new installations and existing installations will no longer start. Firmware versions below the recommended version will likely work but may have limited features and/or show errors in the logs.</i>

[Changes][v0.4.5]


<a id="v0.4.4"></a>
# [v0.4.4](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.4.4) - 2025-07-17

<h3>OPNsense Minimum Firmware Required: 24.7</h3><h4>OPNsense Recommended Firmware: 25.1</h4><p><!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🚀 Enhancements
* Add Dnsmasq leases by [@Snuffy2](https://github.com/Snuffy2) in [#403](https://github.com/travisghansen/hass-opnsense/pull/403)
* Add granular sync options by [@Snuffy2](https://github.com/Snuffy2) in [#398](https://github.com/travisghansen/hass-opnsense/pull/398)
### 🐛 Bug Fixes
* Revert "Change API calls from camel to snake case ([#394](https://github.com/travisghansen/hass-opnsense/issues/394))" by [@Snuffy2](https://github.com/Snuffy2) in [#400](https://github.com/travisghansen/hass-opnsense/pull/400)
* Restrict Dnsmasq leases to 25.1+ by [@Snuffy2](https://github.com/Snuffy2) in [#404](https://github.com/travisghansen/hass-opnsense/pull/404)
### 🎓 Code Quality
* Refine pyproject and requirements by [@Snuffy2](https://github.com/Snuffy2) in [#401](https://github.com/travisghansen/hass-opnsense/pull/401)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.4.3...v0.4.4<p><i>For firmware versions below the minimum version, the integration will not permit new installations and existing installations will no longer start. Firmware versions below the recommended version will likely work but may have limited features and/or show errors in the logs.</i>

[Changes][v0.4.4]


<a id="v0.4.3"></a>
# [v0.4.3](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.4.3) - 2025-07-04

<h3>OPNsense Minimum Firmware Required: 24.7</h3><h4>OPNsense Recommended Firmware: 25.1</h4><p><!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🚀 Enhancements
* Implement queueing by [@Snuffy2](https://github.com/Snuffy2) in [#392](https://github.com/travisghansen/hass-opnsense/pull/392)
### 🐛 Bug Fixes
* Update logic for triggering a firmware check by [@Snuffy2](https://github.com/Snuffy2) in [#393](https://github.com/travisghansen/hass-opnsense/pull/393)
### 🎓 Code Quality
* Change API calls from camel to snake case by [@Snuffy2](https://github.com/Snuffy2) in [#394](https://github.com/travisghansen/hass-opnsense/pull/394)
* Change code for exception type name by [@Snuffy2](https://github.com/Snuffy2) in [#396](https://github.com/travisghansen/hass-opnsense/pull/396)
* Change from hass.data to runtime_data by [@Snuffy2](https://github.com/Snuffy2) in [#397](https://github.com/travisghansen/hass-opnsense/pull/397)
### 🧰 Maintenance
* Update when GitHub Actions run by [@Snuffy2](https://github.com/Snuffy2) in [#390](https://github.com/travisghansen/hass-opnsense/pull/390)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.4.2...v0.4.3<p><i>For firmware versions below the minimum version, the integration will not permit new installations and existing installations will no longer start. Firmware versions below the recommended version will likely work but may have limited features and/or show errors in the logs.</i>

[Changes][v0.4.3]


<a id="v0.4.2"></a>
# [v0.4.2](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.4.2) - 2025-06-29

<h3>OPNsense Minimum Firmware Required: 24.7</h3><h4>OPNsense Recommended Firmware: 25.1</h4><p><!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🐛 Bug Fixes
* Improve handling of opnsense datetime strings by [@Snuffy2](https://github.com/Snuffy2) in [#388](https://github.com/travisghansen/hass-opnsense/pull/388)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.4.1...v0.4.2<p><i>For firmware versions below the minimum version, the integration will not permit new installations and existing installations will no longer start. Firmware versions below the recommended version will likely work but may have limited features and/or show errors in the logs.</i>

[Changes][v0.4.2]


<a id="v0.4.1"></a>
# [v0.4.1](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.4.1) - 2025-06-20

<h3>OPNsense Minimum Firmware Required: 24.7</h3><h4>OPNsense Recommended Firmware: 25.1</h4><p><!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🧰 Maintenance
* Fix Github release action by [@Snuffy2](https://github.com/Snuffy2) in [#386](https://github.com/travisghansen/hass-opnsense/pull/386)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.4.0...v0.4.1<p><i>For firmware versions below the minimum version, the integration will not permit new installations and existing installations will no longer start. Firmware versions below the recommended version will likely work but may have limited features and/or show errors in the logs.</i>

[Changes][v0.4.1]


<a id="v0.4.0"></a>
# [v0.4.0](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.4.0) - 2025-06-19

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🚀 Enhancements
* Improve update firmware by [@Snuffy2](https://github.com/Snuffy2) in [#383](https://github.com/travisghansen/hass-opnsense/pull/383)
* Bump minimum firmware versions by [@Snuffy2](https://github.com/Snuffy2) in [#384](https://github.com/travisghansen/hass-opnsense/pull/384)
### 🐛 Bug Fixes
* Fix system boot time calculation by [@eopo](https://github.com/eopo) in [#379](https://github.com/travisghansen/hass-opnsense/pull/379)
### 🧰 Maintenance
* Create merge_conflict_labeler.yml by [@Snuffy2](https://github.com/Snuffy2) in [#373](https://github.com/travisghansen/hass-opnsense/pull/373)

## New Contributors
* [@eopo](https://github.com/eopo) made their first contribution in [#379](https://github.com/travisghansen/hass-opnsense/pull/379)

**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.3.16...v0.4.0

[Changes][v0.4.0]


<a id="v0.3.16"></a>
# [v0.3.16](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.3.16) - 2025-02-19

<h3>OPNsense Minimum Firmware Required: 24.1</h3><h4>OPNsense Recommended Firmware: 24.7</h4><p><!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🚀 Enhancements
* Re enable hassfest and move services text to translations by [@Snuffy2](https://github.com/Snuffy2) in [#370](https://github.com/travisghansen/hass-opnsense/pull/370)
### 🐛 Bug Fixes
* Handle changelog for plus releases by [@Snuffy2](https://github.com/Snuffy2) in [#367](https://github.com/travisghansen/hass-opnsense/pull/367)
### 🎓 Code Quality
* Increase get_from_stream debug logging by [@Snuffy2](https://github.com/Snuffy2) in [#371](https://github.com/travisghansen/hass-opnsense/pull/371)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.3.15...v0.3.16<p><i>For firmware versions below the minimum version, the integration will not permit new installations and existing installations will no longer start. Firmware versions below the recommended version will likely work but may have limited features and/or show errors in the logs.</i>

[Changes][v0.3.16]


<a id="v0.3.15"></a>
# [v0.3.15](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.3.15) - 2025-01-18

<h3>OPNsense Minimum Firmware Required: 24.1</h3><h4>OPNsense Recommended Firmware: 24.7</h4><p><!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🚀 Enhancements
* Use GitHub for Firmware Changelog link by [@Snuffy2](https://github.com/Snuffy2) in [#364](https://github.com/travisghansen/hass-opnsense/pull/364)
### 🎓 Code Quality
* Add additional typing by [@Snuffy2](https://github.com/Snuffy2) in [#363](https://github.com/travisghansen/hass-opnsense/pull/363)
### 🧰 Maintenance
* Update .pre-commit-config.yaml by [@Snuffy2](https://github.com/Snuffy2) in [#362](https://github.com/travisghansen/hass-opnsense/pull/362)
* Update labels and release notes by [@Snuffy2](https://github.com/Snuffy2) in [#365](https://github.com/travisghansen/hass-opnsense/pull/365)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.3.14...v0.3.15<p><i>For firmware versions below the minimum version, the integration will not permit new installations and existing installations will no longer start. Firmware versions below the recommended version will likely work but may have limited features and/or show errors in the logs.</i>

[Changes][v0.3.15]


<a id="v0.3.14"></a>
# [v0.3.14](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.3.14) - 2025-01-09

<h3>OPNsense Minimum Firmware Required: 24.1</h3><h4>OPNsense Recommended Firmware: 24.7</h4><p><!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🕷️ Bug Fixes 🕷️
* Fix single sequences being changed to strings by [@Snuffy2](https://github.com/Snuffy2) in [#359](https://github.com/travisghansen/hass-opnsense/pull/359)
### 🔧 Maintenance 🔧
* Incorporate the Commit that updates the version numbers into that release by [@Snuffy2](https://github.com/Snuffy2) in [#353](https://github.com/travisghansen/hass-opnsense/pull/353)
### Other Changes
* Enable McCabe complexity checking by [@Snuffy2](https://github.com/Snuffy2) in [#354](https://github.com/travisghansen/hass-opnsense/pull/354)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.3.13...v0.3.14<p><i>For firmware versions below the minimum version, the integration will not permit new installations and existing installations will no longer start. Firmware versions below the recommended version will likely work but may have limited features and/or show errors in the logs.</i>

[Changes][v0.3.14]


<a id="v0.3.13"></a>
# [v0.3.13](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.3.13) - 2024-12-28

<h3>OPNsense Minimum Firmware Required: 24.1</h3><h4>OPNsense Recommended Firmware: 24.7</h4><p><!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🎉 Enhancements & New Features 🎉
* List granular permissions by [@V4ler1an](https://github.com/V4ler1an) and [@Snuffy2](https://github.com/Snuffy2) in [#349](https://github.com/travisghansen/hass-opnsense/pull/349)
### 🕷️ Bug Fixes 🕷️
* Allow unsafe cookies for Private/Internal IPs by [@Snuffy2](https://github.com/Snuffy2) in [#348](https://github.com/travisghansen/hass-opnsense/pull/348)
* Improve Get Certificates function by [@Snuffy2](https://github.com/Snuffy2) in [#351](https://github.com/travisghansen/hass-opnsense/pull/351)
### Other Changes
* Implement pre-commit, pyproject, ruff, mypy by [@Snuffy2](https://github.com/Snuffy2) in [#341](https://github.com/travisghansen/hass-opnsense/pull/341)
* mypy and config_flow fix by [@Snuffy2](https://github.com/Snuffy2) in [#347](https://github.com/travisghansen/hass-opnsense/pull/347)
* Further linting/formatting fixes by [@Snuffy2](https://github.com/Snuffy2) in [#352](https://github.com/travisghansen/hass-opnsense/pull/352)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.3.12...v0.3.13<p><i>For firmware versions below the minimum version, the integration will not permit new installations and existing installations will no longer start. Firmware versions below the recommended version will likely work but may have limited features and/or show errors in the logs.</i>

[Changes][v0.3.13]


<a id="v0.3.12"></a>
# [v0.3.12](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.3.12) - 2024-12-06

<h3>OPNsense Minimum Firmware Required: 24.1</h3><h4>OPNsense Recommended Firmware: 24.7</h4><p><!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🎉 Enhancements & New Features 🎉
* Change user_input in Config Flow to use get by [@Snuffy2](https://github.com/Snuffy2) in [#334](https://github.com/travisghansen/hass-opnsense/pull/334)
* Add debug logging to config_flow by [@Snuffy2](https://github.com/Snuffy2) in [#336](https://github.com/travisghansen/hass-opnsense/pull/336)
### 🕷️ Bug Fixes 🕷️
* Throw ClientResponseError for HTTP Status Errors 4xx by [@Snuffy2](https://github.com/Snuffy2) in [#333](https://github.com/travisghansen/hass-opnsense/pull/333)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.3.11...v0.3.12<p><i>For firmware versions below the minimum version, the integration will not permit new installations and existing installations will no longer start. Firmware versions below the recommended version will likely work but may have limited features and/or show errors in the logs.</i>

[Changes][v0.3.12]


<a id="v0.3.11"></a>
# [v0.3.11](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.3.11) - 2024-11-28

<h3>OPNsense Minimum Firmware Required: 24.1</h3><h4>OPNsense Recommended Firmware: 24.7</h4><p><!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🕷️ Bug Fixes 🕷️
* Fix version update of const.py by [@Snuffy2](https://github.com/Snuffy2) in [#331](https://github.com/travisghansen/hass-opnsense/pull/331)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.3.10...v0.3.11<p><i>For firmware versions below the minimum version, the integration will not permit new installations and existing installations will no longer start. Firmware versions below the recommended version will likely work but may have limited features and/or show errors in the logs.</i>

[Changes][v0.3.11]


<a id="v0.3.10"></a>
# [v0.3.10](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.3.10) - 2024-11-26

<h3>OPNsense Minimum Firmware Required: 24.1</h3><h4>OPNsense Recommended Firmware: 24.7</h4><p><!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🎉 Enhancements & New Features 🎉
* Add reconfigure by [@Snuffy2](https://github.com/Snuffy2) in [#325](https://github.com/travisghansen/hass-opnsense/pull/325)
* Alias Toggle Action/Service by [@Snuffy2](https://github.com/Snuffy2) in [#326](https://github.com/travisghansen/hass-opnsense/pull/326)
* Show repair and shutdown integration if new device id detected by [@Snuffy2](https://github.com/Snuffy2) in [#327](https://github.com/travisghansen/hass-opnsense/pull/327)
### 🕷️ Bug Fixes 🕷️
* Change firmware endpoint and handle non-SemVer firware by [@Snuffy2](https://github.com/Snuffy2) in [#324](https://github.com/travisghansen/hass-opnsense/pull/324)
### Other Changes
* Handle edge TypeError: argument of type 'NoneType' is not iterable errors by [@Snuffy2](https://github.com/Snuffy2) in [#314](https://github.com/travisghansen/hass-opnsense/pull/314)


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.3.9...v0.3.10<p><i>For firmware versions below the minimum version, the integration will not permit new installations and existing installations will no longer start. Firmware versions below the recommended version will likely work but may have limited features and/or show errors in the logs.</i>

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


[v0.6.0]: https://github.com/travisghansen/hass-opnsense/compare/v0.5.0...v0.6.0
[v0.5.0]: https://github.com/travisghansen/hass-opnsense/compare/v0.4.8...v0.5.0
[v0.4.8]: https://github.com/travisghansen/hass-opnsense/compare/v0.4.7...v0.4.8
[v0.4.7]: https://github.com/travisghansen/hass-opnsense/compare/v0.4.6...v0.4.7
[v0.4.6]: https://github.com/travisghansen/hass-opnsense/compare/v0.4.5...v0.4.6
[v0.4.5]: https://github.com/travisghansen/hass-opnsense/compare/v0.4.4...v0.4.5
[v0.4.4]: https://github.com/travisghansen/hass-opnsense/compare/v0.4.3...v0.4.4
[v0.4.3]: https://github.com/travisghansen/hass-opnsense/compare/v0.4.2...v0.4.3
[v0.4.2]: https://github.com/travisghansen/hass-opnsense/compare/v0.4.1...v0.4.2
[v0.4.1]: https://github.com/travisghansen/hass-opnsense/compare/v0.4.0...v0.4.1
[v0.4.0]: https://github.com/travisghansen/hass-opnsense/compare/v0.3.16...v0.4.0
[v0.3.16]: https://github.com/travisghansen/hass-opnsense/compare/v0.3.15...v0.3.16
[v0.3.15]: https://github.com/travisghansen/hass-opnsense/compare/v0.3.14...v0.3.15
[v0.3.14]: https://github.com/travisghansen/hass-opnsense/compare/v0.3.13...v0.3.14
[v0.3.13]: https://github.com/travisghansen/hass-opnsense/compare/v0.3.12...v0.3.13
[v0.3.12]: https://github.com/travisghansen/hass-opnsense/compare/v0.3.11...v0.3.12
[v0.3.11]: https://github.com/travisghansen/hass-opnsense/compare/v0.3.10...v0.3.11
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

<!-- Generated by https://github.com/rhysd/changelog-from-release v3.9.1 -->
