# Device Tracker Guide

Use device tracking to show whether devices are currently on your network. This feature is disabled by default and can be enabled from the integration options.

## Configure device tracking

1. Open `Settings -> Devices & services`.
2. Select the OPNsense integration.
3. Open the integration menu and choose `Configure`.
4. Set `Device tracker mode` to one of the available options.
5. Save the options, or continue to device selection if prompted.

## Choose a tracking mode

The main options page provides three modes:

- `Disabled` (default): turns off device tracker updates.
- `Track all detected devices`: Home Assistant creates trackers for devices it finds automatically. *(All tracker entities will be disabled by default.)*
- `Track only selected devices`: opens the next step so you can choose specific devices and add manual MAC addresses.

Choose `Track all detected devices` for broad discovery with minimal setup.

Choose `Track only selected devices` to limit tracking to specific phones, tablets, laptops, or other important devices.

### Where the device list comes from

The selectable device list is built from the current OPNsense ARP table. That means:

- only devices seen recently by OPNsense appear automatically
- a device may be missing if it has been idle for too long
- a device may not appear until it talks on the network again

### When to use manual MAC addresses

Use the manual MAC field when:

- a device does not appear in the ARP-based list yet
- you want to preconfigure tracking before the device is online
- the device is quiet on the network and disappears from the ARP table too often

You can enter one or more MAC addresses separated by commas or new lines.

### ARP aging and `consider_home`

OPNsense and FreeBSD age out ARP entries over time. Because device tracking depends on recently seen network activity:

- devices can remain visible until their ARP entry expires
- devices may disappear earlier or later depending on network behavior and OPNsense tuning

`Device Tracker Consider Home (seconds)` adds extra time before Home Assistant marks a device as away after it stops appearing in scans.

By default, OPNsense/FreeBSD uses a max age of 20 minutes for ARP entries (sysctl `net.link.ether.inet.max_age`). This can be lowered in <ins>OPNsense</ins> from `System -> Settings -> Tunables` if desired.

## Troubleshooting

### A device is missing from the selector

- Make sure the device has recently been active on the network.
- Refresh the options flow again after the device appears in OPNsense.
- Add the MAC address manually if you already know it.

### A tracked entity exists but is disabled

If you use `Track all detected devices`, Home Assistant will create trackers that are disabled by default. Enable the ones you want to use from the entity settings.

### A device stays home longer than expected

Check both:

- OPNsense ARP aging behavior
- the configured `Device Tracker Consider Home (seconds)` value
