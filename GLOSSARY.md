# hass-opnsense

Home Assistant integration that exposes OPNsense firewalls, and the LAN clients they see, as Home Assistant entities. Terms for the OPNsense API client it is built on, such as Host, DHCP Lease, VPN Instance, Toggle and Minimum Firmware, are defined in the [aiopnsense glossary](https://github.com/Snuffy2/aiopnsense/blob/main/GLOSSARY.md) and used here with the same meaning.

## Language

### Firewalls and entries

**Firewall**:
An OPNsense machine the integration monitors and controls. In a CARP cluster, each physical machine is a **Node**. **Router** is an equally acceptable name for it, as in aiopnsense.
_Avoid_: Device, box

**Node**:
One physical Firewall in a CARP cluster.
_Avoid_: Member, peer

**Firewall entry**:
The full-featured config entry for a single Firewall or Node; it exposes that machine's complete set of entities.
_Avoid_: Device entry, OPNsense device entry

**Hardware ID**:
The identifier a Firewall reports for its physical hardware, stored at setup and checked at runtime to detect that the machine was replaced.
_Avoid_: Device ID, device unique ID

**Hardware replacement**:
A Firewall's hardware changing while its Firewall entry stays in use, detected as a Hardware ID mismatch and resolved by the Replacement repair.
_Avoid_: Hardware swap, device replacement

**Replacement repair**:
The Home Assistant repair that rebuilds a Firewall entry for its replacement hardware while keeping the entry's connection settings and the identity of entities that still exist.
_Avoid_: Device ID repair

**Granular Sync**:
The option that limits which categories of a Firewall's data sync to Home Assistant, so the OPNsense API user can hold narrower permissions.
_Avoid_: Selective sync, partial sync

### Access

**Status Access**:
The level at which the Firewall lets the API user read the live status of a category, or of one VPN type, but not its configured inventory. Under Status Access, items the status does not show, such as disabled VPN Instances, are not visible, and nothing can be Toggled. The Firewall's answers decide the level, not a user setting.
_Avoid_: Read-only, status-only user

**Configuration Access**:
The level at which the API user can also read the configured inventory of a category, or of one VPN type, and Toggle its items.
_Avoid_: Read/write, full access

### CARP clusters

**CARP VIP entry**:
A read-only config entry for a cluster's shared CARP virtual IP; it follows the Active responder and never replaces the Firewall entries.
_Avoid_: VIP entry, cluster entry

**Active responder**:
The Node currently answering through the CARP VIP.
_Avoid_: Primary node, VIP owner

**Maintenance mode**:
The persistent CARP state that takes a Node out of service as Active responder; it is controlled only from that Node's own Firewall entry, never through the CARP VIP entry.
_Avoid_: CARP maintenance, standby switch

### LAN clients

**Tracked client**:
A Host (aiopnsense's term for a LAN endpoint), identified by MAC address, whose presence is reported through a Home Assistant device tracker entity.
_Avoid_: Tracked device, detected device

**Neighbor entry**:
One row in a Firewall's ARP or NDP table linking a MAC address to an IP address; it shows an address was seen, not that the client is present.
_Avoid_: ARP entry, ARP/NDP Entry, ARP/NDP row

**Presence evidence**:
Fresh proof that a Tracked client is on the network: a current ARP Neighbor entry, or a timestamped Host observation from the Firewall's host discovery. An NDP Neighbor entry alone is not Presence evidence.
_Avoid_: Reachability, liveness

**Away**:
The Tracked client state meaning a successful scan found no Presence evidence and the consider-home grace period has passed.
_Avoid_: Not home, offline

**Unavailable**:
The Tracked client state meaning presence cannot be determined, such as when a neighbor-table lookup failed or only an NDP Neighbor entry exists without timestamped evidence.
_Avoid_: Offline, unknown
