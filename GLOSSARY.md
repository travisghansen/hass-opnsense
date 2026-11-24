# hass-opnsense

Home Assistant integration that exposes OPNsense firewalls, and the LAN clients they see, as Home Assistant entities.

## Language

### Firewalls and entries

**Firewall**:
An OPNsense machine the integration monitors and controls. In a CARP cluster, each physical machine is a **Node**.
_Avoid_: Router, device, box

**Node**:
One physical Firewall in a CARP cluster.
_Avoid_: Member, peer

**Firewall entry**:
The full-featured config entry for a single Firewall or Node; it exposes that machine's complete set of entities.
_Avoid_: Device entry, OPNsense device entry

**CARP VIP entry**:
A read-only config entry for a cluster's shared CARP virtual IP; it follows whichever Node is answering and never replaces the Firewall entries.
_Avoid_: VIP entry, cluster entry

**Hardware ID**:
The identifier a Firewall reports for its physical hardware, stored at setup and checked at runtime to detect that the machine was replaced.
_Avoid_: Device ID, device unique ID

### LAN clients

**Tracked client**:
A machine on the network, identified by MAC address, whose presence is reported through a Home Assistant device tracker entity.
_Avoid_: Tracked device, detected device
