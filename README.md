# hass-pfsense

Join `pfSense` with `home-assistant`!

`hass-pfsense` uses the built-in `xmlrpc` service of `pfSense` for all
interactions. No special plugins or software needs to be installed to use the
integration.

Initial development was done againt `pfSense` `2.5.2` and `home-assistant`
`2021.10`.

# configuration

Configuration is managed entirely from the UI using `config_flow` semantics.

## config

- `URL` - put the full URL to your `pfSense` installation (ie:
  `http://pfSense.localdomain:8080`)
- `Allow Insecure TLS` - trust self-signed certs
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

Many `entities` are created by `hass-pfsense` for stats etc.

## device_tracker

`ScannerEntity` entries are created for the `pfSense` arp table. Disabled by
default.

## sensor

- system details (name, version, temp, boottime, etc)
- pfstate details (used, max, etc)
- cpu details (average load, frequency, etc)
- mbuf details
- memory details
- filesystem usage
- interface details (status, stats, pps, kbs (time samples are based on the
  `Scan Interval (seconds)` config option)), many are disabled by default so
  review disabled entities if you want more sensors
- gateways details (status, delay, stddev, loss)

## switch

All of the switches below are disabled by default.

- filter rules - enable/disable rules
- nat port forward rules - enable/disable rules
- nat outbound rules - enable/disable rules
- services - start/stop services
