# hass-pfsense

Join `pfSense` with `home-assistant`!

`hass-pfsense` uses the built-in `xmlrpc` service of `pfSense` for all
interactions. No special plugins or software needs to be installed to use the
integration.

Initial development was done againt `pfSense` `2.5.2` and `home-assistant`
`2021.10`.

# installation

Add the repo to your `hacs` installation or clone the directory manually. Once
the integration is installed be sure to restart `hass` and refresh the UI in
the browser.

# configuration

Configuration is managed entirely from the UI using `config_flow` semantics.
Simply go to `Configuration -> Integrations -> Add Integration` and search for
`pfSense` in the search box.

## pfSense

- `System -> Advanced -> Max Processes` - set it 5 or more.
- If using a non `admin` user account ensure the user has the
  `System - HA node sync` privilege. Note that this privilege effectively gives
  the user complete access to the system via the `xmlrpc` feature.

## config

- `URL` - put the full URL to your `pfSense` UI (ie: `https://192.168.1.1`),
  supported format is `<scheme>://<ip or host>[:<port>]`
- `Verify SSL Certificate` - if the SSL certificate should be verified or not
  (if you get an SSL error try unchecking this)
- `username` - the username to use for authentication (ie: `admin`)
- `password` - the password to use for authentication
- `Firewall Name` - a custom name to be used for `entity` naming (default: use
  the `pfSense` `hostname`)

## options

- `Scan Interval (seconds)` - scan interval to use for state polling (default:
  `30`)
- `Enable Device Tracker` - turn on the device tracker integration using
  `pfSense` arp table (default: `false`)
- `Device Tracker Scan Interval (seconds)` - scan interval to use for arp
  updates (default: `60`)

# entities

Many `entities` are created by `hass-pfsense` for stats etc. Due to to volume
of entities many are disabled by default. If something is missing be sure to
review the disabled entities as what you're looking for is probably there.

## binary_sensor

- carp status (enabled/disabled)
- system notices present (the bell icon in the upper right of the UI)

## device_tracker

`ScannerEntity` entries are created for the `pfSense` arp table. Disabled by
default. Not only is the feature disabled by default but created entities are
currently disabled by default as well. Search the disabled entity list for the
relevant mac addresses and enable as desired.

Note that by default `FreeBSD`/`pfSense` use a max age of 20 minutes for arp
entries (sysctl `net.link.ether.inet.max_age`). You may lower that using
`System -> Advanced -> System Tunables` if desired.

## sensor

- system details (name, version, temp, boottime, etc)
- pfstate details (used, max, etc)
- cpu details (average load, frequency, etc)
- mbuf details
- memory details
- filesystem usage
- interface details (status, stats, pps, kbs (time samples are based on the
  `Scan Interval (seconds)` config option))
- gateways details (status, delay, stddev, loss)
- carp interface status
- dhcp stats (total, online, and offline clients)

## switch

All of the switches below are disabled by default.

- filter rules - enable/disable rules
- nat port forward rules - enable/disable rules
- nat outbound rules - enable/disable rules
- services - start/stop services (note that services must be enabled before they can be started)

# services

```
service: pfsense.close_notice
data:
  entity_id: binary_sensor.pfsense_localdomain_pending_notices_present
  # default is to clear all notices
  # id: <some id>

service: pfsense.file_notice
data:
  entity_id: binary_sensor.pfsense_localdomain_pending_notices_present
  id: "hass"
  notice: "hello world"
  # category: "HASS"
  # url: ""
  # priority: 1
  # local_only: false

service: pfsense.system_halt
data:
  entity_id: binary_sensor.pfsense_localdomain_pending_notices_present

service: pfsense.system_reboot
data:
  entity_id: binary_sensor.pfsense_localdomain_pending_notices_present

service: pfsense.start_service
data:
  entity_id: binary_sensor.pfsense_localdomain_pending_notices_present
  service_name: "dpinger"

service: pfsense.stop_service
data:
  entity_id: binary_sensor.pfsense_localdomain_pending_notices_present
  service_name: "dpinger"

service: pfsense.restart_service
data:
  entity_id: binary_sensor.pfsense_localdomain_pending_notices_present
  service_name: "dpinger"
  # only_if_running: false

service: pfsense.send_wol
data:
  entity_id: binary_sensor.pfsense_localdomain_pending_notices_present
  interface: lan
  mac: "B9:7B:A6:46:B3:8B"
```