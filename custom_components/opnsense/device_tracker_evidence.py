"""Apply device-tracker policies to library-normalized ARP and NDP data."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Literal

from aiopnsense import OPNsenseClient

from .const import TRACKED_ARP_MACS, TRACKED_MACS, TRACKED_NDP_MACS
from .helpers import normalize_arp_mac, normalize_mac_address

ArpNdpFamily = Literal["arp", "ndp"]
PresenceStatus = Literal["present", "absent", "unknown"]


@dataclass(frozen=True, slots=True)
class ArpNdpTableEvidence:
    """Current and retained rows from one ARP/NDP table family."""

    successful: bool
    authoritative: bool
    has_payload: bool
    is_ndp: bool
    fetched_at: datetime | None
    current_entries: tuple[OPNsenseClient.ArpNdpEntry, ...] | None
    entries: tuple[OPNsenseClient.ArpNdpEntry, ...]

    @property
    def macs(self) -> tuple[str, ...]:
        """Return unique usable MAC identities represented by the effective rows."""
        return tuple(
            dict.fromkeys(
                mac
                for entry in self.entries
                if (mac := entry.valid_mac if self.is_ndp else entry.mac)
                and (not self.is_ndp or entry.ipv6_address is not None)
            )
        )


@dataclass(frozen=True, slots=True)
class TrackedDevice:
    """Normalized metadata for one tracker identity."""

    mac: str
    hostname: str | None = None
    manufacturer: str | None = None


@dataclass(frozen=True, slots=True)
class ArpNdpProvenance:
    """Immutable family membership inventories for automatically tracked devices."""

    arp_macs: tuple[str, ...]
    ndp_macs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DeviceTrackerPresenceEvidence:
    """Correlated current-presence evidence and address metadata for one tracker."""

    status: PresenceStatus
    ndp_presence_source: Literal["host_discovery", "no_evidence"]
    arp_failed: bool
    ndp_failed: bool
    observations_failed: bool
    ipv4_addresses: tuple[str, ...]
    ipv6_addresses: tuple[str, ...]
    arp_entry: OPNsenseClient.ArpNdpEntry | None
    ndp_entry: OPNsenseClient.ArpNdpEntry | None


@dataclass(frozen=True, slots=True)
class DeviceTrackerEvidenceSnapshot:
    """Normalized evidence from one device-tracker refresh."""

    arp: ArpNdpTableEvidence
    ndp: ArpNdpTableEvidence
    observation_times: Mapping[str, datetime] | None

    @classmethod
    def from_tables(
        cls,
        *,
        arp: OPNsenseClient.ArpNdpTable | None = None,
        ndp: OPNsenseClient.ArpNdpTable | None = None,
        arp_current: bool = False,
        ndp_current: bool = False,
        observations: OPNsenseClient.HostObservations | None = None,
    ) -> DeviceTrackerEvidenceSnapshot:
        """Build an immutable snapshot from the effective normalized tables.

        Args:
            arp (OPNsenseClient.ArpNdpTable | None): Effective ARP table, either fetched by the
                current refresh or retained from an earlier one.
            ndp (OPNsenseClient.ArpNdpTable | None): Effective NDP table, either fetched by the
                current refresh or retained from an earlier one.
            arp_current (bool): Whether ``arp`` was fetched by the current refresh.
            ndp_current (bool): Whether ``ndp`` was fetched by the current refresh.
            observations (OPNsenseClient.HostObservations | None): Typed host-observation response
                from the current refresh, if available.

        Returns:
            DeviceTrackerEvidenceSnapshot: Family evidence and timestamped observations. A
                retained table keeps its entries but is never current evidence.
        """
        return cls(
            arp=_arp_ndp_table_evidence(arp, current=arp_current, ndp=False),
            ndp=_arp_ndp_table_evidence(ndp, current=ndp_current, ndp=True),
            observation_times=_index_discovery_observations(observations),
        )

    def entries_for_mac(
        self,
        family: ArpNdpFamily,
        mac: str,
        *,
        require_valid_mac: bool = False,
        require_ipv6: bool = False,
    ) -> tuple[OPNsenseClient.ArpNdpEntry, ...]:
        """Return normalized rows matching one tracker MAC.

        Args:
            family (ArpNdpFamily): ARP/NDP table family to search.
            mac (str): Tracker MAC address.
            require_valid_mac (bool): Whether to reject permissively normalized MACs.
            require_ipv6 (bool): Whether NDP rows must contain a valid IPv6 address.

        Returns:
            tuple[OPNsenseClient.ArpNdpEntry, ...]: Matching normalized rows in table order.
        """
        normalized_mac = _normalize_tracked_mac(mac)
        if not normalized_mac:
            return ()
        table = self.arp if family == "arp" else self.ndp
        matching: list[OPNsenseClient.ArpNdpEntry] = []
        for entry in table.entries:
            entry_mac = entry.valid_mac if require_valid_mac else entry.mac
            if entry_mac != normalized_mac:
                continue
            if require_ipv6 and entry.ipv6_address is None:
                continue
            matching.append(entry)
        return tuple(matching)

    def needs_host_observations(self, tracked_macs: set[str] | None = None) -> bool:
        """Return whether the current NDP rows warrant a host-observation request.

        Args:
            tracked_macs (set[str] | None): Strict normalized MACs of selected devices. ``None``
                or an empty set means any valid MAC may be newly discovered.

        Returns:
            bool: Whether a current NDP row needs timestamp evidence.
        """
        entries = self.ndp.current_entries
        if entries is None:
            return False
        for entry in entries:
            if entry.valid_mac is not None and (
                not tracked_macs or entry.valid_mac in tracked_macs
            ):
                return True
        return False

    def with_observations(
        self, observations: OPNsenseClient.HostObservations | None
    ) -> DeviceTrackerEvidenceSnapshot:
        """Return the same normalized ARP/NDP snapshot with current observation timestamps.

        Args:
            observations (OPNsenseClient.HostObservations | None): Typed host-observation response
                from the current refresh, if available.

        Returns:
            DeviceTrackerEvidenceSnapshot: Snapshot reusing its family rows and replacing the
                timestamp index with an immutable index from ``observations``.
        """
        return replace(self, observation_times=_index_discovery_observations(observations))

    def addresses_for_mac(self, family: ArpNdpFamily, mac: str) -> tuple[str, ...]:
        """Return unique normalized IP addresses for a MAC in one family.

        Args:
            family (ArpNdpFamily): ARP/NDP table family to inspect.
            mac (str): Tracker MAC address.

        Returns:
            tuple[str, ...]: Canonical addresses in ARP/NDP table order.
        """
        address_key = "ipv4_address" if family == "arp" else "ipv6_address"
        return tuple(
            dict.fromkeys(
                address
                for entry in self.entries_for_mac(
                    family,
                    mac,
                    require_valid_mac=family == "ndp",
                    require_ipv6=family == "ndp",
                )
                if (address := getattr(entry, address_key)) is not None
            )
        )

    def presence_for_mac(
        self,
        mac: str,
        *,
        now: datetime,
        max_age: timedelta,
        previous_ipv4_addresses: Sequence[object] = (),
        previous_ipv6_addresses: Sequence[object] = (),
    ) -> DeviceTrackerPresenceEvidence:
        """Classify correlated ARP, NDP, and discovery evidence for one tracker.

        Args:
            mac (str): Tracker MAC address.
            now (datetime): Aware time sampled while processing this entity refresh.
            max_age (timedelta): Maximum accepted host-observation age.
            previous_ipv4_addresses (Sequence[object]): Last published IPv4 inventory, retained
                while its table is unavailable or incomplete.
            previous_ipv6_addresses (Sequence[object]): Last published IPv6 inventory, retained
                while its table is unavailable or incomplete.

        Returns:
            DeviceTrackerPresenceEvidence: Presence classification and effective metadata values.
        """
        arp_entries = self.entries_for_mac("arp", mac)
        ndp_entries = self.entries_for_mac("ndp", mac, require_valid_mac=True, require_ipv6=True)
        ndp_presence_entries = self.entries_for_mac("ndp", mac)
        arp_failed = not self.arp.successful
        ndp_failed = not self.ndp.successful
        observed_ipv4_addresses = self.addresses_for_mac("arp", mac)
        if self.arp.authoritative:
            ipv4_addresses = observed_ipv4_addresses
        elif arp_failed:
            ipv4_addresses = tuple(
                dict.fromkeys(
                    _saved_addresses(previous_ipv4_addresses) + list(observed_ipv4_addresses)
                )
            )
        else:
            ipv4_addresses = tuple(
                dict.fromkeys(
                    list(observed_ipv4_addresses) + _saved_addresses(previous_ipv4_addresses)
                )
            )
        observed_ipv6_addresses = self.addresses_for_mac("ndp", mac)
        if self.ndp.authoritative:
            ipv6_addresses = observed_ipv6_addresses
        elif ndp_failed:
            ipv6_addresses = tuple(
                dict.fromkeys(
                    _saved_addresses(previous_ipv6_addresses) + list(observed_ipv6_addresses)
                )
            )
        else:
            ipv6_addresses = tuple(
                dict.fromkeys(
                    list(observed_ipv6_addresses) + _saved_addresses(previous_ipv6_addresses)
                )
            )

        source = self.ndp_presence_source(mac)
        has_observation = source == "host_discovery"
        observations_failed = not ndp_failed and bool(ndp_presence_entries) and not has_observation
        fresh_arp_present = not arp_failed and any(not entry.expired for entry in arp_entries)
        fresh_ndp_present = (
            not ndp_failed
            and bool(ndp_presence_entries)
            and self.is_host_observation_fresh(mac, now=now, max_age=max_age)
        )
        if fresh_arp_present or fresh_ndp_present:
            status: PresenceStatus = "present"
        elif (
            observations_failed
            or (self.arp.successful and not self.arp.authoritative)
            or (self.ndp.successful and not self.ndp.authoritative)
            or (arp_failed and ndp_failed)
            or (arp_failed and bool(ipv4_addresses))
            or (ndp_failed and bool(ipv6_addresses))
        ):
            status = "unknown"
        else:
            status = "absent"

        return DeviceTrackerPresenceEvidence(
            status=status,
            ndp_presence_source=source,
            arp_failed=arp_failed,
            ndp_failed=ndp_failed,
            observations_failed=observations_failed,
            ipv4_addresses=ipv4_addresses,
            ipv6_addresses=ipv6_addresses,
            arp_entry=arp_entries[0] if arp_entries else None,
            ndp_entry=ndp_entries[0] if ndp_entries else None,
        )

    def devices(self, configured_macs: Sequence[str] | None = None) -> tuple[TrackedDevice, ...]:
        """Build tracker devices from effective rows or an explicit MAC selection.

        Args:
            configured_macs (Sequence[str] | None): Configured MACs, or ``None`` to discover
                every usable MAC represented in either table.

        Returns:
            tuple[TrackedDevice, ...]: Devices in stable table/configuration order.
        """
        if configured_macs is not None:
            normalized_macs = tuple(
                dict.fromkeys(
                    normalized
                    for mac in configured_macs
                    if (normalized := _normalize_tracked_mac(mac))
                )
            )
            return tuple(self._device_for_mac(mac) for mac in normalized_macs)

        devices: dict[str, TrackedDevice] = {}
        for family, entries in (("arp", self.arp.entries), ("ndp", self.ndp.entries)):
            for entry in entries:
                mac = entry.mac if family == "arp" else entry.valid_mac
                if mac is None or (family == "ndp" and entry.ipv6_address is None):
                    continue
                previous = devices.get(mac, TrackedDevice(mac))
                devices[mac] = TrackedDevice(
                    mac=mac,
                    hostname=previous.hostname or (entry.hostname if family == "arp" else None),
                    manufacturer=previous.manufacturer or entry.manufacturer,
                )
        return tuple(devices.values())

    def ndp_presence_source(self, mac: str) -> Literal["host_discovery", "no_evidence"]:
        """Describe whether a usable timestamped observation exists for a MAC.

        Args:
            mac (str): Tracker MAC address.

        Returns:
            Literal["host_discovery", "no_evidence"]: Presence-evidence source label.
        """
        normalized_mac = normalize_mac_address(mac)
        if (
            normalized_mac is not None
            and self.observation_times is not None
            and normalized_mac in self.observation_times
        ):
            return "host_discovery"
        return "no_evidence"

    def is_host_observation_fresh(
        self,
        mac: str,
        *,
        now: datetime,
        max_age: timedelta,
    ) -> bool:
        """Return whether a timestamped observation is fresh at the supplied instant.

        Args:
            mac (str): Tracker MAC address.
            now (datetime): Aware time sampled by the entity during its refresh.
            max_age (timedelta): Maximum accepted observation age.

        Returns:
            bool: Whether the same-MAC observation is younger than ``max_age``.
        """
        normalized_mac = normalize_mac_address(mac)
        if normalized_mac is None or self.observation_times is None:
            return False
        observed_at = self.observation_times.get(normalized_mac)
        if observed_at is None or now.tzinfo is None or now.utcoffset() is None:
            return False
        return now - observed_at < max_age

    def _device_for_mac(self, mac: str) -> TrackedDevice:
        """Build one configured tracker using ARP metadata and the NDP vendor fallback.

        Args:
            mac (str): Configured tracker MAC address.

        Returns:
            TrackedDevice: Normalized tracker identity and metadata.
        """
        arp_entries = self.entries_for_mac("arp", mac)
        ndp_entries = self.entries_for_mac("ndp", mac, require_valid_mac=True, require_ipv6=True)
        arp_entry = arp_entries[0] if arp_entries else None
        ndp_entry = ndp_entries[0] if ndp_entries else None
        return TrackedDevice(
            mac=mac,
            hostname=arp_entry.hostname if arp_entry is not None else None,
            manufacturer=(
                arp_entry.manufacturer
                if arp_entry is not None and arp_entry.manufacturer
                else ndp_entry.manufacturer
                if ndp_entry is not None
                else None
            ),
        )


def setup_arp_ndp_provenance(
    snapshot: DeviceTrackerEvidenceSnapshot,
    inventory: Mapping[str, object],
) -> ArpNdpProvenance:
    """Reconcile setup inventories, allowing authoritative families to replace membership.

    Args:
        snapshot (DeviceTrackerEvidenceSnapshot): Current normalized tracker snapshot.
        inventory (Mapping[str, object]): Config-entry data containing legacy or family-specific
            persisted MAC inventories.

    Returns:
        ArpNdpProvenance: Family inventories used by setup and stale-device cleanup.
    """
    previous_arp_inventory = inventory.get(TRACKED_ARP_MACS)
    if not isinstance(previous_arp_inventory, list):
        previous_arp_inventory = inventory.get(TRACKED_MACS, [])
    previous_arp = _normalize_inventory(previous_arp_inventory, ndp=False)
    previous_ndp = _normalize_inventory(inventory.get(TRACKED_NDP_MACS, []), ndp=True)
    arp_macs = list(snapshot.arp.macs)
    ndp_macs = list(snapshot.ndp.macs)
    if not snapshot.arp.authoritative:
        arp_macs = list(dict.fromkeys(arp_macs + previous_arp))
    if not snapshot.ndp.authoritative:
        ndp_macs = list(dict.fromkeys(ndp_macs + previous_ndp))
    return ArpNdpProvenance(tuple(arp_macs), tuple(ndp_macs))


def normalize_tracked_mac_inventory(value: object, *, ndp: bool = False) -> tuple[str, ...]:
    """Normalize one persisted tracker MAC inventory while preserving its order.

    Args:
        value (object): Persisted MAC inventory.
        ndp (bool): Whether entries require strict complete MAC formatting.

    Returns:
        tuple[str, ...]: Unique normalized MACs in stored order.
    """
    return tuple(_normalize_inventory(value, ndp=ndp))


def poll_arp_ndp_provenance(
    snapshot: DeviceTrackerEvidenceSnapshot,
    *,
    tracked_macs: object,
    previous_arp_macs: object,
    previous_ndp_macs: object,
) -> ArpNdpProvenance:
    """Update existing track-all membership while retaining provenance for absent devices.

    Args:
        snapshot (DeviceTrackerEvidenceSnapshot): Current normalized tracker snapshot.
        tracked_macs (object): Existing overall tracker inventory.
        previous_arp_macs (object): Last persisted ARP provenance.
        previous_ndp_macs (object): Last persisted NDP provenance.

    Returns:
        ArpNdpProvenance: Updated immutable inventories limited to existing tracked MACs.
    """
    tracked = _normalize_inventory(tracked_macs, ndp=False)
    prior_arp = set(_normalize_inventory(previous_arp_macs, ndp=False))
    prior_ndp = set(_normalize_inventory(previous_ndp_macs, ndp=True))
    current_arp = set(snapshot.arp.macs)
    current_ndp = set(snapshot.ndp.macs)
    arp_authoritative = snapshot.arp.authoritative
    ndp_authoritative = snapshot.ndp.authoritative
    updated_arp: list[str] = []
    updated_ndp: list[str] = []
    for mac in tracked:
        seen_in_arp = arp_authoritative and mac in current_arp
        seen_in_ndp = ndp_authoritative and mac in current_ndp
        if seen_in_arp or seen_in_ndp:
            in_arp = seen_in_arp if arp_authoritative else mac in prior_arp
            in_ndp = seen_in_ndp if ndp_authoritative else mac in prior_ndp
        else:
            in_arp = mac in prior_arp
            in_ndp = mac in prior_ndp
        if in_arp:
            updated_arp.append(mac)
        if in_ndp:
            updated_ndp.append(mac)
    return ArpNdpProvenance(tuple(updated_arp), tuple(updated_ndp))


def _arp_ndp_table_evidence(
    table: OPNsenseClient.ArpNdpTable | None, *, current: bool, ndp: bool
) -> ArpNdpTableEvidence:
    """Classify one effective table and its authority.

    Args:
        table (OPNsenseClient.ArpNdpTable | None): Current or retained normalized table.
        current (bool): Whether the table was fetched by the current refresh.
        ndp (bool): Whether the table belongs to the IPv6 NDP family.

    Returns:
        ArpNdpTableEvidence: Entries and their availability classification. Only a current table
            with no unparsed rows is authoritative, and every NDP entry must also carry a valid
            MAC and IPv6 address. ARP keeps its permissive identity policy.
    """
    entries = table.entries if table is not None else ()
    successful = current and table is not None
    rows_complete = table is not None and table.unparsed_row_count == 0
    if ndp:
        rows_complete = rows_complete and all(
            entry.valid_mac is not None and entry.ipv6_address is not None for entry in entries
        )
    return ArpNdpTableEvidence(
        successful=successful,
        authoritative=successful and rows_complete,
        has_payload=table is not None,
        is_ndp=ndp,
        fetched_at=table.fetched_at if table is not None else None,
        current_entries=entries if successful else None,
        entries=entries,
    )


def _index_discovery_observations(
    observations: OPNsenseClient.HostObservations | None,
) -> Mapping[str, datetime] | None:
    """Index newest discovery timestamps by library-normalized MAC.

    Args:
        observations (OPNsenseClient.HostObservations | None): Typed observations from the client.

    Returns:
        Mapping[str, datetime] | None: Latest timestamp per MAC for discovery observations, or
            ``None`` when the result is unavailable or came from ARP/NDP tables.
    """
    if observations is None or observations.source != "discovery":
        return None
    latest: dict[str, datetime] = {}
    for entry in observations.entries:
        previous = latest.get(entry.mac)
        if previous is None or entry.last_seen > previous:
            latest[entry.mac] = entry.last_seen
    return MappingProxyType(latest)


def _normalize_tracked_mac(mac: object) -> str:
    """Normalize a MAC using the tracker's permissive ARP-compatible fallback.

    Args:
        mac (object): MAC-like value from options or a table row.

    Returns:
        str: Canonical MAC when valid, otherwise permissively normalized ARP text.
    """
    normalized = normalize_mac_address(mac) if isinstance(mac, str) else None
    if normalized is not None:
        return normalized
    return normalize_arp_mac(mac)


def _normalize_inventory(value: object, *, ndp: bool) -> list[str]:
    """Normalize a persisted family inventory while preserving its order.

    Args:
        value (object): Persisted MAC inventory.
        ndp (bool): Whether entries require strict complete MAC formatting.

    Returns:
        list[str]: Unique normalized MACs in stored order.
    """
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        mac = normalize_mac_address(item) if ndp else _normalize_tracked_mac(item)
        if mac and mac not in result:
            result.append(mac)
    return result


def _saved_addresses(values: Sequence[object]) -> list[str]:
    """Return string values from a previously published address sequence.

    Args:
        values (Sequence[object]): Restored or previously published address values.

    Returns:
        list[str]: Address strings in their existing order.
    """
    return [value for value in values if isinstance(value, str)]
