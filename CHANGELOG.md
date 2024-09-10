<a name="v0.2.1"></a>
# [v0.2.1](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.2.1) - 10 Sep 2024

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🎉 Enhancements & New Features 🎉
* Feature: Add CPU Usage and remove CPU Frequency entities by [@Snuffy2](https://github.com/Snuffy2) in https://github.com/travisghansen/hass-opnsense/pull/169
* Feature: Add Temperature Sensors by [@Snuffy2](https://github.com/Snuffy2) in https://github.com/travisghansen/hass-opnsense/pull/168
### 🕷️ Bug Fixes 🕷️
* Add back support for OPNsense 24.1 by [@Snuffy2](https://github.com/Snuffy2) in https://github.com/travisghansen/hass-opnsense/pull/173
### Other Changes
* Update get and post to handle response status by [@Snuffy2](https://github.com/Snuffy2) in https://github.com/travisghansen/hass-opnsense/pull/164
* Create HA issue if OPNsense Firmware below min version by [@Snuffy2](https://github.com/Snuffy2) in https://github.com/travisghansen/hass-opnsense/pull/178


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.2.0...v0.2.1

[Changes][v0.2.1]


<a name="v0.2.1-beta.1"></a>
# [v0.2.1-beta.1](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.2.1-beta.1) - 09 Sep 2024

Please note that in OPNsense < 24.7, the following entities won't work (should be part of the final release notes):
* Temperature sensors
* CPU Usage
* _Possibly others_

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
### 🎉 Enhancements & New Features 🎉
* Feature: Add CPU Usage and remove CPU Frequency entities by [@Snuffy2](https://github.com/Snuffy2) in https://github.com/travisghansen/hass-opnsense/pull/169
* Feature: Add Temperature Sensors by [@Snuffy2](https://github.com/Snuffy2) in https://github.com/travisghansen/hass-opnsense/pull/168
### 🕷️ Bug Fixes 🕷️
* Add back support for OPNsense 24.1 by [@Snuffy2](https://github.com/Snuffy2) in https://github.com/travisghansen/hass-opnsense/pull/173
### Other Changes
* Update get and post to handle response status by [@Snuffy2](https://github.com/Snuffy2) in https://github.com/travisghansen/hass-opnsense/pull/164


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.2.0...v0.2.1-beta.1

[Changes][v0.2.1-beta.1]


<a name="v0.2.0"></a>
# [v0.2.0 - Use the REST API for Telemetry](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.2.0) - 07 Sep 2024

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
# :boom: Breaking Change :boom:
* Use the REST API for Telemetry by [@Snuffy2](https://github.com/Snuffy2) in https://github.com/travisghansen/hass-opnsense/pull/147
  * Requires that the OPNSense user has __admin__ permissions. See the Readme for details
  * OpenVPN Entities will be renamed and the old ones will need to be manually removed
  * `CPU Frequency Current` will always be _Unavailable_ for now and will likely be removed in a future version 
### :bug: Bug Fixes :bug:
* Fix pfstates access issues and readme update on permissions by [@Snuffy2](https://github.com/Snuffy2) in https://github.com/travisghansen/hass-opnsense/pull/149
* Fix swap memory permission and gracefully handle permission errors by [@Snuffy2](https://github.com/Snuffy2) in https://github.com/travisghansen/hass-opnsense/pull/150
* Revert instance entity naming by [@Snuffy2](https://github.com/Snuffy2) in https://github.com/travisghansen/hass-opnsense/pull/151
* Don't show error if OpenVPN isn't used by [@Snuffy2](https://github.com/Snuffy2) in https://github.com/travisghansen/hass-opnsense/pull/154
* Rename interfaces (take 2) by [@Snuffy2](https://github.com/Snuffy2) in https://github.com/travisghansen/hass-opnsense/pull/155
### :wrench: Maintenance :wrench:
* Update GitHub Actions by [@Snuffy2](https://github.com/Snuffy2) in https://github.com/travisghansen/hass-opnsense/pull/156
* Auto Label PRs and Update Changelog by [@Snuffy2](https://github.com/Snuffy2) in https://github.com/travisghansen/hass-opnsense/pull/159

## New Contributors
* [@Snuffy2](https://github.com/Snuffy2) made their first contribution in https://github.com/travisghansen/hass-opnsense/pull/147

**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.1.21...v0.2.0

[Changes][v0.2.0]


<a name="v0.2.0-beta.2"></a>
# [v0.2.0-beta.2](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.2.0-beta.2) - 06 Sep 2024

<!-- Release notes generated using configuration in .github/release.yml at main -->

## What's Changed
* Don't show error if OpenVPN isn't used by [@Snuffy2](https://github.com/Snuffy2) in https://github.com/travisghansen/hass-opnsense/pull/154
* Rename interfaces (take 2) by [@Snuffy2](https://github.com/Snuffy2) in https://github.com/travisghansen/hass-opnsense/pull/155
* Update GitHub Actions by [@Snuffy2](https://github.com/Snuffy2) in https://github.com/travisghansen/hass-opnsense/pull/156


**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.2.0-beta.1...v0.2.0-beta.2

[Changes][v0.2.0-beta.2]


<a name="v0.2.0-beta.1"></a>
# [v0.2.0-beta.1](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.2.0-beta.1) - 05 Sep 2024

**BREAKING CHANGE**: the official recommendation now is that the integration requires an admin role user.

## Other Changes:

* Use different swap memory endpoint that works with granular permissions
* Switch to `pf_states` endpoint so that it works with granular permissions
* Gracefully handle errors, especially permission errors and show this in the Error text
* Updated README with the revised user privileges required by the integration
* Added more type hints and annotations

This should resolve [#143](https://github.com/travisghansen/hass-opnsense/issues/143) [#148](https://github.com/travisghansen/hass-opnsense/issues/148) and similar issues.

Please give a feedback in the following Discussions section [thread](https://github.com/travisghansen/hass-opnsense/discussions/153)

**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.1.22...v0.2.0-beta.1

[Changes][v0.2.0-beta.1]


<a name="v0.1.23-beta.1"></a>
# [v0.1.23-beta.1](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.23-beta.1) - 04 Sep 2024

## What's Changed
* Fix pfstates access issues and readme update on permissions by [@Snuffy2](https://github.com/Snuffy2) in https://github.com/travisghansen/hass-opnsense/pull/149
* Fixes [#148](https://github.com/travisghansen/hass-opnsense/issues/148) 

**Full Changelog**: https://github.com/travisghansen/hass-opnsense/compare/v0.1.22...v0.1.23-beta.1

[Changes][v0.1.23-beta.1]


<a name="v0.1.22"></a>
# [v0.1.22](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.22) - 04 Sep 2024



[Changes][v0.1.22]


<a name="v0.1.21"></a>
# [v0.1.21](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.21) - 18 Mar 2024



[Changes][v0.1.21]


<a name="v0.1.20"></a>
# [v0.1.20](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.20) - 17 Feb 2024



[Changes][v0.1.20]


<a name="v0.1.19"></a>
# [v0.1.19](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.19) - 17 Feb 2024



[Changes][v0.1.19]


<a name="v0.1.18"></a>
# [v0.1.18](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.18) - 16 Feb 2024



[Changes][v0.1.18]


<a name="v0.1.17"></a>
# [v0.1.17](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.17) - 12 Feb 2024



[Changes][v0.1.17]


<a name="v0.1.16"></a>
# [v0.1.16](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.16) - 30 Apr 2023

# v0.1.16

Released 2023-04-30

- minor fixes
- support for hass 2023.5

[Changes][v0.1.16]


<a name="v0.1.15"></a>
# [v0.1.15](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.15) - 21 Mar 2023

Released 2023-03-21

- temporary workaround for removal of `openvpn_get_active_servers()` in `23.1.4`


[Changes][v0.1.15]


<a name="v0.1.14"></a>
# [v0.1.14](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.14) - 19 Feb 2023

Released 2023-02-19

- update deprecated syntax (`exec_command()` replaced by `shell_safe()` in `23.1.1`)

[Changes][v0.1.14]


<a name="v0.1.13"></a>
# [v0.1.13](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.13) - 30 Jan 2023



[Changes][v0.1.13]


<a name="v0.1.12"></a>
# [v0.1.12](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.12) - 30 Jan 2023



[Changes][v0.1.12]


<a name="v0.1.11"></a>
# [v0.1.11](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.11) - 30 Jan 2023



[Changes][v0.1.11]


<a name="v0.1.10"></a>
# [v0.1.10](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.10) - 30 Jan 2023



[Changes][v0.1.10]


<a name="v0.1.9"></a>
# [v0.1.9](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.9) - 22 Jan 2023



[Changes][v0.1.9]


<a name="v0.1.8"></a>
# [v0.1.8](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.8) - 18 Jan 2023



[Changes][v0.1.8]


<a name="v0.1.7"></a>
# [v0.1.7](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.7) - 16 Jan 2023



[Changes][v0.1.7]


<a name="v0.1.6"></a>
# [v0.1.6](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.6) - 16 Jan 2023



[Changes][v0.1.6]


<a name="v0.1.5"></a>
# [v0.1.5](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.5) - 18 Aug 2022



[Changes][v0.1.5]


<a name="v0.1.4"></a>
# [v0.1.4](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.4) - 18 Aug 2022



[Changes][v0.1.4]


<a name="v0.1.3"></a>
# [v0.1.3](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.3) - 17 Aug 2022



[Changes][v0.1.3]


<a name="v0.1.2"></a>
# [v0.1.2](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.2) - 01 Aug 2022



[Changes][v0.1.2]


<a name="v0.1.1"></a>
# [v0.1.1](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.1) - 11 Jul 2022



[Changes][v0.1.1]


<a name="v0.1.0"></a>
# [v0.1.0](https://github.com/travisghansen/hass-opnsense/releases/tag/v0.1.0) - 09 Jul 2022



[Changes][v0.1.0]


[v0.2.1]: https://github.com/travisghansen/hass-opnsense/compare/v0.2.1-beta.1...v0.2.1
[v0.2.1-beta.1]: https://github.com/travisghansen/hass-opnsense/compare/v0.2.0...v0.2.1-beta.1
[v0.2.0]: https://github.com/travisghansen/hass-opnsense/compare/v0.2.0-beta.2...v0.2.0
[v0.2.0-beta.2]: https://github.com/travisghansen/hass-opnsense/compare/v0.2.0-beta.1...v0.2.0-beta.2
[v0.2.0-beta.1]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.23-beta.1...v0.2.0-beta.1
[v0.1.23-beta.1]: https://github.com/travisghansen/hass-opnsense/compare/v0.1.22...v0.1.23-beta.1
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

<!-- Generated by https://github.com/rhysd/changelog-from-release v3.7.2 -->
