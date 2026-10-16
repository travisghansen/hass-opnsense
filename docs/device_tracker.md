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

The selectable device list combines OPNsense's ARP and NDP tables. Entries with the same MAC
address become one tracker, so a dual-stack device does not get separate IPv4 and IPv6 entities.
IPv6 neighbors include SLAAC, DHCPv6, and temporary addresses when OPNsense reports them. That
means:

- devices with ARP or NDP entries appear automatically
- neighbor entries may remain after a device disconnects; presence is evaluated separately from
  the address inventory
- a device may be missing after its neighbor entry expires
- a device may not appear until it talks on the network again
- an IPv6-only device needs the `Diagnostics: NDP Table` permission
- ARP and NDP permissions are independent; a missing permission for one table does not disable
  tracking from the other table

Each tracker exposes `ipv4_addresses` and `ipv6_addresses` state attributes. The entity's primary
IP address uses IPv4 when available and otherwise uses IPv6. MAC addresses remain the tracker
identity: a device can move between IPv4 and IPv6 without creating a new tracker.

### When to use manual MAC addresses

Use the manual MAC field when:

- a device does not appear in the ARP/NDP-based list yet
- you want to preconfigure tracking before the device is online
- the device is quiet on the network and disappears from the ARP or NDP table too often

You can enter one or more MAC addresses separated by commas or new lines.

### ARP aging and `consider_home`

OPNsense and FreeBSD age out ARP entries over time. Because device tracking depends on recently seen network activity:

- devices can remain visible until their ARP entry expires
- devices may disappear earlier or later depending on network behavior and OPNsense tuning

`Device Tracker Consider Home (seconds)` adds extra time before Home Assistant marks a device as
away after it stops appearing in successful scans. If one neighbor-table lookup fails, the last
known addresses are retained and that failed lookup does not count as a fresh sighting. The tracker
is reported as unavailable while the failed table is needed to confirm its last-known addresses.
Successful scans with no matching entry continue to use `consider_home` for departure aging.

By default, OPNsense/FreeBSD uses a max age of 20 minutes for ARP entries (sysctl
`net.link.ether.inet.max_age`). This can be lowered in <ins>OPNsense</ins> from
`System -> Settings -> Tunables` if desired. NDP entry lifetime is managed by OPNsense and can vary
with the address and neighbor state. Its API does not expose reachability, and stale NDP rows can
remain long after a device leaves.

Timestamped host-discovery evidence for IPv6 presence is available starting with OPNsense
Community 25.7.11. Enable automatic host discovery, select the interfaces it should monitor, and
grant the API user `Interfaces: Neighbors: Automatic discovery` access. The newest timestamped
observation for the same MAC from either IPv4 or IPv6 confirms a matching NDP row only while it is
fresh. The freshness window is 20 minutes or twice the configured device tracker scan interval,
whichever is longer, so long scan intervals do not outlive their evidence. `consider_home` then
adds its configured grace period.

The host-observation request is made only when the NDP table contains a row for a tracked MAC, so
scans without any relevant NDP row do not add an extra API call. If the request fails, the
integration logs one warning when the failure starts, then only debug messages until it recovers.

The `ipv6_addresses` attribute describes addresses in the NDP neighbor inventory; it does not
verify that each address is currently active. IPv6 addresses remain visible as metadata on older
firmware and when observations are unavailable. A matching NDP row by itself cannot confirm that
an IPv6-only device is home: without a usable timestamp for that MAC, the tracker is unavailable.
This also applies when host discovery is disabled, its API permission is missing, no monitored
interface observes the device, the client does not support the endpoint, or a lookup fails. A
fresh ARP entry can still confirm presence. A successful NDP scan with no matching row can still
confirm absence and use `consider_home` for departure aging.

The `ndp_presence_source` attribute describes only the NDP freshness evidence for that tracker, not
whether the tracker is available or home. It is `host_discovery` when a timestamped discovery
observation exists for the tracker MAC, and `no_evidence` when no usable timestamp exists. A
tracker confirmed by a fresh ARP entry can therefore be home while this attribute is
`no_evidence`. NDP-only devices on firmware older than 25.7.11 retain IPv6 metadata but remain
unavailable until another usable presence source confirms them.

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

For devices visible only in NDP, check whether `ndp_presence_source` is `no_evidence`. On OPNsense Community 25.7.11 or
newer, enable automatic host discovery, select the monitored interfaces, and grant its API
permission. An NDP address remains visible as inventory even when no timestamped observation can
confirm presence.
