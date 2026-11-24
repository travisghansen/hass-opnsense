# Device Tracker Guide

Use device tracking to show whether Tracked clients (machines on your network, identified by MAC address) are currently on your network. This feature is disabled by default and can be enabled from the integration options.

## Configure device tracking

1. Open `Settings -> Devices & services`.
2. Select the OPNsense integration.
3. Open the integration menu and choose `Configure`.
4. Set `Device tracker mode` to one of the available options.
5. Save the options, or continue to client selection if prompted.

## Choose a tracking mode

The main options page provides three modes:

- `Disabled` (default): turns off device tracker updates.
- `Track all detected clients`: Home Assistant creates trackers for clients it finds automatically. *(All tracker entities will be disabled by default.)*
- `Track only selected clients`: opens the next step so you can choose specific clients and add manual MAC addresses.

Choose `Track all detected clients` for broad discovery with minimal setup.

Choose `Track only selected clients` to limit tracking to specific phones, tablets, laptops, or other important clients.

### Where the client list comes from

The selectable client list combines the Firewall's ARP and NDP Neighbor entries. Entries with the
same MAC address become one tracker, so a dual-stack client does not get separate IPv4 and IPv6
entities. IPv6 neighbors include SLAAC, DHCPv6, and temporary addresses when OPNsense reports
them. That means:

- clients with ARP or NDP Neighbor entries appear automatically
- Neighbor entries may remain after a client disconnects; presence is evaluated separately from
  the address inventory
- a client may be missing after its Neighbor entry expires
- a client may not appear until it talks on the network again
- an IPv6-only client needs the `Diagnostics: NDP Table` permission
- ARP and NDP permissions are independent; a missing permission for one table does not disable
  tracking from the other table

Each tracker exposes `ipv4_addresses` and `ipv6_addresses` state attributes. The entity's primary
IP address uses IPv4 when available and otherwise uses IPv6. MAC addresses remain the tracker
identity: a client can move between IPv4 and IPv6 without creating a new tracker.

Each tracker provides device registry metadata for its client, including the MAC address,
hostname (or MAC address when unnamed), manufacturer when known, and parent Firewall.
This works with Home Assistant 2026.3+ and the scanner registration changes in 2026.11+.
The integration retains its existing enabled-default rules: selected clients are enabled by
default, while automatically discovered trackers stay disabled unless an enabled MAC-matched
device already exists. The config entry's preference to disable new entities still applies.

### When to use manual MAC addresses

Use the manual MAC field when:

- a client does not appear in the Neighbor entry-based list yet
- you want to preconfigure tracking before the client is online
- the client is quiet on the network and disappears from the ARP or NDP table too often

You can enter one or more MAC addresses separated by commas or new lines.

### ARP aging and `consider_home`

OPNsense and FreeBSD age out ARP Neighbor entries over time. Because device tracking depends on recently seen network activity:

- clients can remain visible until their ARP Neighbor entry expires
- clients may disappear earlier or later depending on network behavior and OPNsense tuning

`Device Tracker Consider Home (seconds)` adds extra time before Home Assistant marks a Tracked client
as Away after successful scans stop finding Presence evidence for it. If one neighbor-table
lookup fails, the last known addresses are retained and that failed lookup does not count as a
fresh sighting. The tracker is reported as Unavailable while the failed table is needed to confirm
its last-known addresses. Successful scans with no matching Neighbor entry continue to use
`consider_home` for departure aging.

By default, OPNsense/FreeBSD uses a max age of 20 minutes for ARP Neighbor entries (sysctl
`net.link.ether.inet.max_age`). This can be lowered in <ins>OPNsense</ins> from
`System -> Settings -> Tunables` if desired. NDP entry lifetime is managed by OPNsense and can vary
with the address and neighbor state. Its API does not expose reachability, and stale NDP rows can
remain long after a client leaves.

Timestamped host-discovery evidence for IPv6 presence is available starting with OPNsense
Community 25.7.11. Enable automatic host discovery, select the interfaces it should monitor, and
grant the API user `Interfaces: Neighbors: Automatic discovery` access. The newest timestamped
observation for the same MAC from either IPv4 or IPv6 confirms a matching NDP row only while it is
fresh. The freshness window is 20 minutes or twice the configured device tracker scan interval,
whichever is longer, so long scan intervals do not outlive their evidence. `consider_home` then
adds its configured grace period.

The host-observation request is made when the NDP table contains a row for a tracked MAC. When
you track all clients (no manually selected clients), any NDP row with a valid MAC qualifies, so
newly discovered clients get timestamp evidence on their first scan. Scans without any relevant NDP
row do not add an extra API call. If the request fails, the
integration logs one warning when the failure starts, then only debug messages until it recovers.

The `ipv6_addresses` attribute describes addresses in the NDP neighbor inventory; it does not
verify that each address is currently active. IPv6 addresses remain visible as metadata on older
firmware and when observations are unavailable. A matching NDP Neighbor entry by itself is not Presence evidence
and cannot confirm that an IPv6-only client is home: without a usable timestamp for that MAC, the
tracker is Unavailable.
This also applies when host discovery is disabled, its API permission is missing, no monitored
interface observes the client, the API client does not support the endpoint, or a lookup fails. A
current ARP Neighbor entry can still confirm presence. A successful NDP scan with no matching Neighbor entry can still
confirm absence and use `consider_home` for departure aging.

The `ndp_presence_source` attribute describes only the NDP freshness evidence for that tracker, not
whether the tracker is available or home. It is `host_discovery` when a timestamped discovery
observation exists for the tracker MAC, and `no_evidence` when no usable timestamp exists. A
tracker confirmed by a current ARP Neighbor entry can therefore be home while this attribute is
`no_evidence`. NDP-only clients on firmware older than 25.7.11 retain IPv6 metadata but remain
Unavailable until another usable presence source confirms them.

## Troubleshooting

### A client is missing from the selector

- Make sure the client has recently been active on the network.
- Refresh the options flow again after the client appears in OPNsense.
- Add the MAC address manually if you already know it.

### A tracked entity exists but is disabled

If you use `Track all detected clients`, Home Assistant will create trackers that are disabled by default. Enable the ones you want to use from the entity settings.

### A client stays home longer than expected

Check both:

- OPNsense ARP Neighbor entry aging behavior
- the configured `Device Tracker Consider Home (seconds)` value

For clients visible only in NDP, check whether `ndp_presence_source` is `no_evidence`. On OPNsense Community 25.7.11 or
newer, enable automatic host discovery, select the monitored interfaces, and grant its API
permission. An NDP address remains visible as inventory even when no timestamped observation can
confirm presence.
