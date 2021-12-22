[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2Ftravisghansen%2Fhass-opnsense%2Fbadge%3Fref%3Dmain&style=for-the-badge)](https://actions-badge.atrox.dev/travisghansen/hass-opnsense/goto?ref=main)
[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg?style=for-the-badge)](https://github.com/custom-components/hacs)

# hass-opnsense

Join `OPNsense` with `home-assistant`!

`hass-opnsense` uses the built-in `xmlrpc` service of `OPNsense` for all
interactions. This project is currently a proof-of-concept and may fail to work
at any time.

Initial development was done againt `OPNsense` `21.7` and `home-assistant` `2021.10`.

# installation

This integration currenlty **replaces** the built-in `opnsense` integration
which only provides `device_tracker` functionality, be sure to remove any
associated configuration for the built-in integration before installing this
replacement.

To use the integration you need to install an OPNsense plugin mada available
on mimugmail repository: `https://www.routerperformance.net/opnsense-repo/`

First you need to install the repository:

- open an SSH session on OPNsense and issue the following commands:

```
fetch -o /usr/local/etc/pkg/repos/mimugmail.conf https://www.routerperformance.net/mimugmail.conf
pkg update
```

Now you need to install the plugin, you have two ways to do it:

- In OPNsense web UI, go to System:Firmware:Plugins and install plugin `os-homeassistant-maxit`
- From SSH shell: `pkg install os-homeassistant-maxit`

Now, on Home Assistant, add this repository to your `HACS` installation or clone the directory manually.
Once the integration is installed be sure to restart `hass` and hard-refresh the UI in
the browser (ctrl-F5) if it doesn't appear in the list.

# configuration

Configuration is managed entirely from the UI using `config_flow` semantics.
Simply go to `Configuration -> Integrations -> Add Integration` and search for
`OPNsense` in the search box.

## OPNsense

- If using a non `admin` user account ensure the user has the
  `System - HA node sync` privilege. Note that this privilege effectively gives
  the user complete access to the system via the `xmlrpc` feature.

## config

- `URL` - put the full URL to your `OPNsense` UI (ie: `https://192.168.1.1`),
  supported format is `<scheme>://<ip or host>[:<port>]`
- `Verify SSL Certificate` - if the SSL certificate should be verified or not
  (if you get an SSL error try unchecking this)
- `username` - the username to use for authentication (ie: `root`)
- `password` - the password to use for authentication
- `Firewall Name` - a custom name to be used for `entity` naming (default: use
  the `OPNsense` `hostname`)

## options

- `Scan Interval (seconds)` - scan interval to use for state polling (default:
  `30`)
- `Enable Device Tracker` - turn on the device tracker integration using
  `OPNsense` arp table (default: `false`)
- `Device Tracker Scan Interval (seconds)` - scan interval to use for arp
  updates (default: `60`)
- `Device Tracker Consider Home (seconds)` - seconds to wait until marking
  a device as not home after not being seen.
  (default: `0`)
  - `0` - disabled (if device is not present during any given scan interval it
    is considered away)
  - `> 0` - generally should be a multiple of the configured scan interval

# entities

Many `entities` are created by `hass-opnsense` for stats etc. Due to to volume
of entities many are disabled by default. If something is missing be sure to
review the disabled entities as what you're looking for is probably there.

## binary_sensor

- carp status (enabled/disabled)
- system notices present (the bell icon in the upper right of the UI)

## device_tracker

`ScannerEntity` entries are created for the `OPNsense` arp table. Disabled by
default. Not only is the feature disabled by default but created entities are
currently disabled by default as well. Search the disabled entity list for the
relevant mac addresses and enable as desired.

Note that by default `FreeBSD`/`OPNsense` use a max age of 20 minutes for arp
entries (sysctl `net.link.ether.inet.max_age`). You may lower that using
`System -> Advanced -> System Tunables` if desired.

## sensor

- system details (name, version, ~~temp~~, boottime, etc)
- pfstate details (used, max, etc)
- cpu details (average load, frequency, etc)
- mbuf details
- memory details
- filesystem usage
- interface details (status, stats, pps, kbs (time samples are based on the
  `Scan Interval (seconds)` config option))
- gateways details (status, delay, stddev, loss)
- carp interface status
- ~~dhcp stats (total, online, and offline clients)~~
- OpenVPN server stats (per-server basis - connected client count, bytes
  sent/received, kB/s sent/received)
  
## switch

All of the switches below are disabled by default.

- filter rules - enable/disable rules
- nat port forward rules - enable/disable rules
- nat outbound rules - enable/disable rules
- services - start/stop services (note that services must be enabled before they can be started)

# services

```
service: opnsense.close_notice
data:
  entity_id: binary_sensor.opnsense_localdomain_pending_notices_present
  # default is to clear all notices
  # id: <some id>

service: opnsense.file_notice
data:
  entity_id: binary_sensor.opnsense_localdomain_pending_notices_present
  notice: "hello world"

service: opnsense.system_halt
data:
  entity_id: binary_sensor.opnsense_localdomain_pending_notices_present

service: opnsense.system_reboot
data:
  entity_id: binary_sensor.opnsense_localdomain_pending_notices_present

service: opnsense.start_service
data:
  entity_id: binary_sensor.opnsense_localdomain_pending_notices_present
  service_name: "dpinger"

service: opnsense.stop_service
data:
  entity_id: binary_sensor.opnsense_localdomain_pending_notices_present
  service_name: "dpinger"

service: opnsense.restart_service
data:
  entity_id: binary_sensor.opnsense_localdomain_pending_notices_present
  service_name: "dpinger"
  # only_if_running: false

service: opnsense.send_wol
data:
  entity_id: binary_sensor.opnsense_localdomain_pending_notices_present
  interface: lan
  mac: "B9:7B:A6:46:B3:8B"
```
