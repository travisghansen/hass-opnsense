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

`hass-opnsense` uses [`aiopnsense`](https://pypi.org/project/aiopnsense/) as the backend client library to integrate OPNsense with Home Assistant.

Source and releases for `aiopnsense`:

* PyPI: <https://pypi.org/project/aiopnsense/>
* GitHub: <https://github.com/Snuffy2/aiopnsense>

A Discord server to discuss the integration is available. Click the Discord badge at the beginning of the page for the invite link.

## OPNsense Firmware Requirements

* Requires OPNsense Firmware 25.1+
* For OPNsense Firmware 25.1 through 26.1.0, the integration remains supported, but Firewall and NAT rule switches are not available.
* With OPNsense Firmware 26.1.1+, Firewall and NAT rule switches are available as well.

## Table of Contents

* [Installation](#installation)
* [Configuration](#configuration)
  * [OPNsense Device Entry](#opnsense-device-entry)
  * [CARP VIP Entry](#carp-vip-entry)
  * [Recommended CARP Topology](#recommended-carp-topology)
  * [OPNsense User](#opnsense-user)
  * [Granular Sync](#granular-sync)
  * [Basic Configuration](#basic-configuration)
  * [Options](#options)
* [Entities](#entities)
  * [Binary Sensor](#binary-sensor)
  * [Sensor](#sensor)
  * [Switch](#switch)
  * [Device Tracker](#device-tracker)
  * [CARP VIP Entities and Limitations](#carp-vip-entities-and-limitations)

* [Actions](#actions-services)
* [Replacing OPNsense Hardware](#replacing-opnsense-hardware)

## Installation

This integration **replaces** the built-in OPNsense integration which only provides `device_tracker` functionality. Be sure to remove any associated configuration for the built-in integration **before** installing this replacement.

The deprecated OPNsense Home Assistant plugin is no longer supported or used by hass-opnsense.

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
<summary><h3>Manual Installation</h3></summary>

Copy the contents of the custom_components folder to the Home Assistant config/custom_components folder and restart Home Assistant.

</details>

## Configuration

Configuration is managed entirely from the Home Assistant UI. Simply go to `Configuration -> Integrations -> Add Integration` and search for <ins>OPNsense</ins> in the search box.

### OPNsense Device Entry

Choose **OPNsense device entry** for each physical node's own non-VIP IP address or hostname. This is the full integration: telemetry, interfaces, services, gateways, firmware, optional CARP data, actions, and switches follow the selected sync options. Existing entries remain OPNsense device entries automatically and require no migration.

### CARP VIP Entry

Choose **CARP VIP entry** for the shared CARP VIP IP address or hostname when you want read-only CARP visibility. A CARP VIP entry follows the active responder and exposes only the CARP entities described in [CARP VIP Entities and Limitations](#carp-vip-entities-and-limitations). Configure each physical node separately with an OPNsense device entry; the VIP entry does not replace node entries.

### Recommended CARP Topology

Use one OPNsense device entry per physical node and add the optional CARP VIP entry for the shared endpoint:

```text
Node A non-VIP IP/hostname       -> full OPNsense device entry
Node B non-VIP IP/hostname       -> full OPNsense device entry
Shared CARP VIP IP/hostname      -> optional read-only CARP VIP entry
```

Node entries are required for complete monitoring because a VIP endpoint cannot prove the health of a standby node.

### OPNsense User

The official and simplest recommendation is that the service user to be created has the admin role.

In <ins>OPNsense</ins>, create a new admin role user (or choose an existing admin user) and create an API key associated to the user. When creating the API key, <ins>OPNsense</ins> will download the file containing the API key and API secret to the computer. It will be in the download folder.

### Granular Sync

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
| Enable Granular Sync Options | | False | See [Granular Sync Options](#granular-sync) |

### Options

| Option | Default | Description |
| --- | --- | --- |
| Scan Interval (seconds) | 30 | Scan interval to use for state polling |
| Device Tracker Mode | Disabled | • Disabled<br>• Track all detected devices<br>• Track only selected devices |
| Device Tracker Scan Interval (seconds) | 150 | Scan interval to use for ARP updates |
| Device Tracker Consider Home (seconds) | 0 | Seconds to wait until marking a device as not home after not being seen:<br>• 0 : Disabled *(if device is not present during any given scan interval it is considered away)*<br>• > 0 : Should be a multiple of the Device Tracker Scan Interval |
| Enable Granular Sync Options | False | See Granular Sync Options |

## Entities

Many entities are created by `hass-opnsense` for statistics etc. Due to the volume of entities, **many are disabled by default**. If something is missing, be sure to review the disabled entities as it is probably there.

### Binary Sensor

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
* Gateways details (status, delay, stddev, loss, address)
* CARP VIP status (aggregate)
* CARP Interface status
* DHCP Leases
* OpenVPN and Wireguard server and client stats
* Certificates
* vnStat Metrics
* Speedtest last and average results (download, upload, latency)

### Switch

**All switches are disabled by default**

* Firewall Rules - enable/disable rules *(requires OPNsense Firmware 26.1.1+)*
* NAT Rules - enable/disable rules *(requires OPNsense Firmware 26.1.1+)*
* Services - start/stop services
* VPN Servers and Clients - enable/disable instances
* Unbound blocklists - enable/disable blocklists

### Device Tracker

Entities are created for selected devices to track whether they are connected to the network. This feature is disabled by default and can be enabled in the Options once the integration is installed.

The options flow supports three modes:

* Disabled
* Track all detected devices
* Track only selected devices

The selectable device list is built from the current OPNsense ARP table, so only recently seen devices appear automatically. Devices that are not currently visible can still be added manually by MAC address.

See [Device Tracker Guide](docs/device_tracker.md) for setup details, ARP behavior, and troubleshooting.

### CARP VIP Entities and Limitations

A CARP VIP entry creates only these read-only entities:

* **active responder:** the name of the node currently answering through the VIP;
* **CARP VIP status:** aggregate CARP status reported by that active responder;
* **CARP VIP state:** one state sensor for each virtual IP keyed by VHID and subnet.

A CARP VIP entry does not expose node hardware telemetry, firmware/update entities, general interfaces, services, gateways, VPN, DHCP, firewall/NAT, SMART, disks, temperatures, device trackers, actions, or switches. The VIP cannot prove standby-node health; configure OPNsense device entries for each node when complete monitoring is required.

The persistent CARP maintenance switch remains on physical-node entries. Enabling maintenance through the VIP can move the VIP; a later disable request could then reach the other node. Use the physical node's OPNsense device entry when changing maintenance mode.

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

## Replacing OPNsense Hardware

Hardware replacement may change a number of OPNsense areas including interfaces, services, gateways, disks, and others.

When an OPNsense device entry reports a Device ID mismatch, Home Assistant offers a fixable repair. Confirm it once the replacement hardware is reachable and is the intended node. The repair selectively reconciles the registry with the replacement's entities: matching entities and devices retain their registry identity and customizations, entities absent from the replacement are removed, and new entities are created.

The repair preserves the URL, credentials, and options. A retry marker makes an interrupted repair resumable. Dashboards and automations remain intact for preserved entity IDs; review references to entities removed during reconciliation.

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
