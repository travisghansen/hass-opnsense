[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2Ftravisghansen%2Fhass-opnsense%2Fbadge%3Fref%3Dmain&style=for-the-badge)](https://actions-badge.atrox.dev/travisghansen/hass-opnsense/goto?ref=main)
[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg?style=for-the-badge)](https://github.com/hacs/integration)
[![][discord-shield]][discord]

[discord]: https://discord.gg/MXV7DgsaEQ
[discord-shield]: https://img.shields.io/discord/1283169313653526559?style=for-the-badge&label=Discord&logo=discord&&logoColor=lightcyan&logoSize=auto&color=white


# hass-opnsense

Join `OPNsense` with `Home Assistant`!

`hass-opnsense` uses the `OPNsense` [REST API](https://docs.opnsense.org/development/api.html)) built-in `xmlrpc` service to integrate OPNsense with Home Assistant. __A [plugin](#opnsense-plugin) is currently required to be installed in OPNsense for this to work properly.__

Initial development was done against `OPNsense` `21.7` and `Home Assistant` `2021.10`.

A Discord server to discuss the integration is available, please click the Discord badge at the beginning of the page for the invite link.

# Overview

- [Installation](#installation)
  - [OPNsense plugin](#opnsense-plugin)
  - [Home Assistant integration](#homeassistant-integration)
    - [HACS installation](#hacs-installation)
    - [Manual installation](#manual-installation)
- [Configuration](#configuration)
  - [OPNsense](#opnsense-plugin)
  - [HA Config](#config)
  - [Options](#options)
- [Entities](#entities)
  - [Binary Sensor](#binary-sensor)
  - [Device Tracker](#device-tracker)
  - [Sensor](#sensor)
  - [Switch](#switch)
  - [Services](#services)
- [Known Issues](#known-issues)
  - [AdGuardHome](#adguardhome)

# Installation

This integration currently **replaces** the built-in `OPNsense` integration which only provides `device_tracker` functionality, be sure to remove any associated configuration for the built-in integration before installing this replacement.

The installation requires a plugin on `OPNsense` and a custom integration in `Home Assistant`.

## OPNsense Plugin

To use the integration you need to install an `OPNsense` plugin made available on mimugmail repository: `https://www.routerperformance.net/opnsense-repo/`

First you need to install the repository:

- open an SSH session on `OPNsense` and issue the following commands:

```
fetch -o /usr/local/etc/pkg/repos/mimugmail.conf https://www.routerperformance.net/mimugmail.conf
pkg update
```

Now you need to install the plugin, you have two ways to do it:

- In `OPNsense` web UI, go to System:Firmware:Plugins and install plugin `os-homeassistant-maxit`
- From SSH shell: `pkg install os-homeassistant-maxit`

## HomeAssistant Integration

In `Home Assistant`, add this repository to your `HACS` installation or clone the directory manually.

### HACS Installation

In HACS, add this as a custom repository: 
```https://github.com/travisghansen/hass-opnsense```.
| STEP 1 | STEP 2 |
| ------ | ------ |
| ![image](https://github.com/user-attachments/assets/60c701dd-a8da-4205-85b8-81af2377e9a5) | ![image](https://github.com/user-attachments/assets/7e19a5e6-844f-4214-8704-ac6409756003) |

Then go to the HACS integrations page, search for `OPNsense integration for Home Assistant` and install it by clicking on 3 dots on the right side and select Download and click on Download on popup window. 

![image](https://github.com/user-attachments/assets/a3df3d73-6f0f-4045-9d29-25dd24202bb0)

![image](https://github.com/user-attachments/assets/42a747a5-f1dc-4cea-87ad-62ae1f7930da)

Once the integration is installed be sure to restart `Home Assistant`. Restart option available under Developer tools.

| Developer Tools Page | Restart Home Assistant Popup |
| ------ | ------ |
| ![image](https://github.com/user-attachments/assets/95c324e5-73cb-42f9-8cd2-c4acc35c9711) | ![image](https://github.com/user-attachments/assets/bbb0ac00-1709-4206-9d59-eb47ca40390b) |

<details>
<summary><h3>Manual Installation</h3></summary>

Copy the contents of the custom_components folder to your `Home Assistant` config/custom_components folder and restart `Home Assistant`.

</details>

# Configuration

Configuration is managed entirely from the UI using `config_flow` semantics. Simply go to `Configuration -> Integrations -> Add Integration` and search for `OPNsense` in the search box. If you can't find it in the list (well-known HA issue) you need to do a 'hard-refresh' of the browser (ctrl-F5) then open the list again, you'll find it there.

## OPNsense

The official recommendation is that the service user to be created has the admin role.

Create a new admin role user (or choose an existing admin user), and create an API key associated to the user. When creating the API key, `OPNsense` will push the API file containing the API key and API secret to your browser, you'll find it in the download folder.

<details>
<summary><h4>Unsupported Alternative</h4></summary>

If you don't want to user an `admin` user account, you can try assigning the following privileges, but this is not guaranteed to work and could lead to potential issues, so we still recommend using an admin user:
  - `Dashboard (all)`
  - `Lobby: Login / Logout / Dashboard`
  - `Status: Interfaces`
  - `Status: OpenVPN`
  - `System: Firmware`
  - `VPN: OpenVPN: Client Export Utility`
  - `XMLRPC Library` (note that this privilege effectively gives the user complete access to
    the system via the `xmlrpc` feature)

</details>

## Config

- `URL` - the full URL to your `OPNsense` UI (ie: `https://192.168.1.1`),
  supported format is `<scheme>://<ip or host>[:<port>]`
- `Verify SSL Certificate` - if the SSL certificate should be verified or not
  (if you get an SSL error try unchecking this)
- `API Key` - the API key created previously
- `API Secret` - the API secret of the API key
- `Firewall Name` - a custom name to be used for `entity` naming (default: use
  the `OPNsense` `hostname`)

## Options

- `Scan Interval (seconds)` - scan interval to use for state polling (default: `30`)
- `Enable Device Tracker` - turn on the device tracker integration using `OPNsense` arp table (default: `false`)
- `Device Tracker Scan Interval (seconds)` - scan interval to use for arp updates (default: `60`)
- `Device Tracker Consider Home (seconds)` - seconds to wait until marking a device as not home after not being seen. (default: `0`)
  - `0` - disabled (if device is not present during any given scan interval it is considered away)
  - `> 0` - generally should be a multiple of the configured scan interval

# Entities

Many `entities` are created by `hass-opnsense` for stats etc. Due to to volume of entities many are disabled by default. If something is missing be sure to review the disabled entities as what you're looking for is probably there.

## Binary Sensor

- carp status (enabled/disabled)
- system notices present (the circle icon in the upper right of the UI)
- firmware updates available

## Device Tracker

`ScannerEntity` entries are created for the `OPNsense` arp table. Disabled by default. Not only is the feature disabled by default but created entities are currently disabled by default as well. Search the disabled entity list for the relevant mac addresses and enable as desired.

Note that by default `FreeBSD`/`OPNsense` use a max age of 20 minutes for arp entries (sysctl `net.link.ether.inet.max_age`). You may lower that using `System -> Advanced -> System Tunables` if desired.

Also note that if you are running `AdGuardHome` DNS queries may get throttled causing issues with the tracker. See [below](#adguardhome) for details.

## Sensor

- System details (name, version, temp, boottime, etc)
- pfstate details
- CPU details (usage, load, cores)
- mbuf details
- Memory details
- Filesystem usage
- Interface details (status, stats, pps, kbs (time samples are based on the `Scan Interval (seconds)` config option))
- Gateways details (status, delay, stddev, loss)
- Carp Interface status
- DHCP Leases
- OpenVPN & Wireguard server and client stats
- Certificates

## Switch

All of the switches below are disabled by default.

- Filter Rules - enable/disable rules
- NAT Port Forward Rules - enable/disable rules
- NAT Outbound Rules - enable/disable rules
- Services - start/stop services (note that services must be enabled before they can be started)
- VPN Servers and Clients - enable/disable instances

# Services

```
service: opnsense.close_notice
data:
  # default is to clear all notices
  # id: <some id>

service: opnsense.system_halt

service: opnsense.system_reboot

service: opnsense.start_service
data:
  service_name: "dpinger"

service: opnsense.stop_service
data:
  service_name: "dpinger"

service: opnsense.restart_service
data:
  service_name: "dpinger"
  # only_if_running: false

service: opnsense.send_wol
data:
  interface: lan
  mac: "B9:7B:A6:46:B3:8B"

service: opnsense.reload_interface
data:
  interface: wan

```

# Known Issues

## AdGuardHome

As mentioned [here](https://github.com/travisghansen/hass-opnsense/issues/22) using AdGuardHome can lead to problems with the plugin. Setting the Ratelimit in AdGuardHome to 0 will resolve this problem.
