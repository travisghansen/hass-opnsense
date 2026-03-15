[![GitHub Downloads][downloads-shield]][releases]
[![GitHub Latest Downloads][downloads-latest-shield]][releases]
[![GitHub Release][releases-shield]][releases]
[![GitHub Release Date][release-date-shield]][releases]
[![GitHub Activity][commits-shield]][commits]
[![Coverage][coverage-shield]][coverage]
[![License][license-shield]](LICENSE)
[![hacs][hacsbadge]][hacs]
[![discord][discord-shield]][discord]

# hass-opnsense

Join `OPNsense` with `Home Assistant`!

`hass-opnsense` uses the OPNsense [REST API](https://docs.opnsense.org/development/api.html) to integrate OPNsense with Home Assistant. 

**With OPNsense Firmware 26.1.1+, a plugin is no longer needed on the OPNsense Router.**


A Discord server to discuss the integration is available, please click the Discord badge at the beginning of the page for the invite link.

## Table of Contents

* [Installation](#installation)
  * [OPNsense Plugin (deprecated)](#opnsense-plugin)
  * [Home Assistant Integration](#homeassistant-integration)
    * [HACS Installation](#hacs-installation)
    * [Manual Installation](#manual-installation)

* [Configuration](#configuration)
  * [OPNsense User](#opnsense-user)
    * [Granular Sync Options](#granular-sync-options)
  * [Basic Configuration](#basic-configuration)
  * [Options](#options)

* [Entities](#entities)
  * [Binary Sensor](#binary-sensor)
  * [Sensor](#sensor)
  * [Switch](#switch)
  * [Device Tracker](#device-tracker)

* [Actions](#actions-services)

* [Known Issues](#known-issues)
  * [Hardware Changes](#hardware-changes)

## Installation

This integration **replaces** the built-in OPNsense integration which only provides `device_tracker` functionality. Be sure to remove any associated configuration for the built-in integration **before** installing this replacement.

### OPNsense Plugin *(deprecated)*

With OPNsense Firmware 26.1.1+, a plugin is **no longer needed** on the OPNsense Router.

<details>
<summary><h4>OPNsense Firmware < 26.1.1</h4></summary>

In most cases, use of the integration requires an <ins>OPNsense</ins> plugin made available on mimugmail repository: `https://www.routerperformance.net/opnsense-repo/`. See [Granular Sync Options](#granular-sync-options) below for more details.

#### First, install the repository

* Open an SSH session on <ins>OPNsense</ins> and issue the following commands:

```
fetch -o /usr/local/etc/pkg/repos/mimugmail.conf https://www.routerperformance.net/mimugmail.conf
pkg update
```

#### Then, install the plugin

There are two ways to do it:

1. In <ins>OPNsense</ins> web UI, go to `System -> Firmware -> Plugins` and install plugin `os-homeassistant-maxit`

OR

2. In an <ins>OPNsense</ins> SSH session: `pkg install os-homeassistant-maxit`

</details>

### HomeAssistant Integration

In Home Assistant, add this repository to the HACS installation or clone the directory manually.

#### HACS Installation

In HACS, add this as a custom repository: 
`https://github.com/travisghansen/hass-opnsense`.
| STEP 1 | STEP 2 |
| ------ | ------ |
| ![image](https://github.com/user-attachments/assets/60c701dd-a8da-4205-85b8-81af2377e9a5) | ![image](https://github.com/user-attachments/assets/7e19a5e6-844f-4214-8704-ac6409756003) |

Then go to the HACS integrations page, search for `OPNsense integration for Home Assistant` and install it by clicking on 3 dots on the right side and select Download and click on Download on popup window. 

![image](https://github.com/user-attachments/assets/a3df3d73-6f0f-4045-9d29-25dd24202bb0)

![image](https://github.com/user-attachments/assets/42a747a5-f1dc-4cea-87ad-62ae1f7930da)

Once the integration is installed be sure to restart Home Assistant. Restart option available under Developer tools.

| Developer Tools Page | Restart Home Assistant Popup |
| ------ | ------ |
| ![image](https://github.com/user-attachments/assets/95c324e5-73cb-42f9-8cd2-c4acc35c9711) | ![image](https://github.com/user-attachments/assets/bbb0ac00-1709-4206-9d59-eb47ca40390b) |

<details>
<summary><h4>Manual Installation</h4></summary>

Copy the contents of the custom_components folder to the Home Assistant config/custom_components folder and restart Home Assistant.

</details>

## Configuration

Configuration is managed entirely from the Home Assistant UI. Simply go to `Configuration -> Integrations -> Add Integration` and search for <ins>OPNsense</ins> in the search box. If it isn't in the list (well-known HA issue), do a 'hard-refresh' of the browser (ctrl-F5) then open the list again.

### OPNsense User

The official and simplest recommendation is that the service user to be created has the admin role.

In <ins>OPNsense</ins>, create a new admin role user (or choose an existing admin user) and create an API key associated to the user. When creating the API key, <ins>OPNsense</ins> will download the file containing the API key and API secret to the computer. It will be in the download folder.

### Granular Sync Options

Either at the time of install or in the integration options, Granular Sync Options can be enabled. There, choose the categories to sync with HA as desired. If enabled, the <ins>OPNsense</ins> user can have more narrow permissions.

At minimum, the following permissions are required:

* Lobby: Dashboard
* Status: Interfaces
* System: Firmware

[The list of what other permissions are needed for the Granular Sync Options and for the Actions can be reviewed here.](docs/granular_permissions.md)

### Basic Configuration

| Option | Required | Default | Description |
| --- | :---: | --- | --- |
| URL | ✅ | | The full URL to the <ins>OPNsense</ins> UI (ie: `https://192.168.1.1`). Supported format is `<scheme>://<ip or host>[:<port>]` |
| Verify SSL Certificate | | True | If the SSL certificate should be verified or not *(if receiving an SSL error, try unchecking this)* |
| API Key | ✅ | | The API key of the OPNsense user created previously |
| API Secret | ✅ | | The API secret of the API key |
| Firewall Name | | Uses the `OPNsense hostname` | A custom name to be used for device and entity naming |
| Enable Granular Sync Options | | False | See [Granular Sync Options](#granular-sync-options) |

### Options

| Option | Default | Description |
| --- | --- | --- |
| Scan Interval (seconds) | 30 | Scan interval to use for state polling |
| Device Tracker Mode | Disabled | • Disabled<br>• Track all detected devices<br>• Track only selected devices |
| Device Tracker Scan Interval (seconds) | 60 | Scan interval to use for ARP updates |
| Device Tracker Consider Home (seconds) | 0 | Seconds to wait until marking a device as not home after not being seen:<br>• 0 : Disabled *(if device is not present during any given scan interval it is considered away)*<br>• > 0 : Should be a multiple of the Device Tracker Scan Interval |
| Enable Granular Sync Options | False | See Granular Sync Options |

## Entities

Many entities are created by `hass-opnsense` for statistics etc. Due to the volume of entities, **many are disabled by default**. If something is missing, be sure to review the disabled entities as it is probably there.

### Binary Sensor

* CARP Status (enabled/disabled)
* System Notices present *(the circle icon in the upper right of the UI)*
* Firmware updates available

### Sensor

* System details (name, version, temp, boottime, etc.)
* pfstate details
* CPU details (usage, load, cores)
* mbuf details
* Memory details
* Filesystem usage
* Interface details (status, stats, pps, kbs, etc.) *[speeds are based on the `Scan Interval (seconds)` config option]*
* Gateways details (status, delay, stddev, loss)
* CARP Interface status
* DHCP Leases
* OpenVPN and Wireguard server and client stats
* Certificates
* vnStat Metrics
* Speedtest last and average results (download, upload, latency)

### Switch

**All switches are disabled by default**

* Firewall Rules - enable/disable rules
* NAT Rules - enable/disable rules
* Services - start/stop services
* VPN Servers and Clients - enable/disable instances
* Unbound blocklists - enable/disable blocklists

### Device Tracker

Entities are created for selected devices to track whether they are connected to the network. This feature is disabled by default and can be enabled in the Options.

The options flow supports three modes:

* Disabled
* Track all detected devices
* Track only selected devices

The selectable device list is built from the current OPNsense ARP table, so only recently seen devices appear automatically. Devices that are not currently visible can still be added manually by MAC address.

See [Device Tracker Guide](docs/device_tracker.md) for setup details, ARP behavior, and troubleshooting.

## Actions *(Services)*

* **opnsense.close_notice:** Close any open notices
* **opnsense.system_halt:** Halt the OPNsense system
* **opnsense.system_reboot:** Reboot the OPNsense system
* **opnsense.start_service:** Start an OPNsense service
* **opnsense.stop_service:** Stop an OPNsense service
* **opnsense.restart_service:** Restart an OPNsense service
* **opnsense.send_wol:** Send a Wake-on-LAN magic packet
* **opnsense.reload_interface:** Reload an OPNsense interface
* **opnsense.kill_states:** Kill all states for an IP address
* **opnsense.run_speedtest:** Run a speed test and return action response data
* **opnsense.get_vnstat_metrics:** Get vnStat metrics and return action response data
* **opnsense.generate_vouchers:** Generate Captive Portal vouchers
* **opnsense.toggle_alias:** Toggle, enable, or disable an alias

[How to use <ins>action response data</ins> in an HA script or automation](https://www.home-assistant.io/docs/scripts/perform-actions/#use-templates-to-handle-response-data)

## Known Issues

### Hardware Changes

If you partially or fully change the <ins>OPNsense</ins> hardware, it will require a removal and reinstall of this integration. This is to ensure changed interfaces, services, gateways, etc. are accounted for and don't leave duplicate or non-functioning entities. 

[commits-shield]: https://img.shields.io/github/last-commit/travisghansen/hass-opnsense?style=for-the-badge
[commits]: https://github.com/travisghansen/hass-opnsense/commits/main
[hacs]: https://hacs.xyz
[hacsbadge]: https://img.shields.io/badge/HACS-Custom-orange.svg?style=for-the-badge
[license-shield]: https://img.shields.io/github/license/travisghansen/hass-opnsense.svg?style=for-the-badge
[downloads-latest-shield]: https://img.shields.io/github/downloads-pre/travisghansen/hass-opnsense/latest/total?style=for-the-badge
[downloads-shield]: https://img.shields.io/github/downloads/travisghansen/hass-opnsense/total?style=for-the-badge&label=total%20downloads
[release-date-shield]: https://img.shields.io/github/release-date/travisghansen/hass-opnsense?display_date=published_at&style=for-the-badge
[releases-shield]: https://img.shields.io/github/v/release/travisghansen/hass-opnsense?style=for-the-badge
[releases]: https://github.com/travisghansen/hass-opnsense/releases
[discord]: https://discord.gg/bfF47sBw6A
[discord-shield]: https://img.shields.io/discord/1283169313653526559?style=for-the-badge&label=Discord&logo=discord&&logoColor=lightcyan&logoSize=auto&color=white
[coverage]: https://htmlpreview.github.io/?https://github.com/travisghansen/hass-opnsense/blob/python-coverage-comment-action-data/htmlcov/index.html
[coverage-shield]: https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Ftravisghansen%2Fhass-opnsense%2Fpython-coverage-comment-action-data%2Fendpoint.json&style=for-the-badge
