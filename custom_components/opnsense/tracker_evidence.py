"""Apply device-tracker policies to library-normalized neighbor evidence."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Literal

from aiopnsense.arp_ndp import ArpNdpEntry, normalize_arp_ndp_entry

from .const import TRACKED_ARP_MACS, TRACKED_MACS, TRACKED_NDP_MACS
from .helpers import normalize_arp_mac, normalize_mac_address

TrackerFamily = Literal["arp", "ndp"]
PresenceStatus = Literal["present", "absent", "unknown"]


@dataclass(frozen=True, slots=True)
class NeighborTableEvidence:
    """Current and retained rows from one neighbor-table family."""

    successful: bool
    authoritative: bool
    has_payload: bool
    is_ndp: bool
    current_entries: tuple[ArpNdpEntry, ...] | None
    entries: tuple[ArpNdpEntry, ...]

    @property
    def macs(self) -> tuple[str, ...]:
        """Return unique usable MAC identities represented by the effective rows."""
        return tuple(
            dict.fromkeys(
                mac
                for entry in self.entries
                if entry.usable
                and (mac := entry.valid_mac if self.is_ndp else entry.mac)
                and (not self.is_ndp or entry.ipv6_address is not None)
            )
        )


@dataclass(frozen=True, slots=True)
class TrackerDevice:
    """Normalized metadata for one tracker identity."""

    mac: str
    hostname: str | None = None
    manufacturer: str | None = None


@dataclass(frozen=True, slots=True)
class FamilyProvenance:
    """Immutable family membership inventories for automatically tracked devices."""

    arp_macs: tuple[str, ...]
    ndp_macs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TrackerPresenceEvidence:
    """Correlated current-presence evidence and address metadata for one tracker."""

    status: PresenceStatus
    ndp_presence_source: Literal["host_discovery", "no_evidence"]
    arp_failed: bool
    ndp_failed: bool
    observations_failed: bool
    ipv4_addresses: tuple[str, ...]
    ipv6_addresses: tuple[str, ...]
    arp_entry: ArpNdpEntry | None
    ndp_entry: ArpNdpEntry | None


@dataclass(frozen=True, slots=True)
class TrackerEvidenceSnapshot:
    """Normalized evidence from one device-tracker refresh."""

    arp: NeighborTableEvidence
    ndp: NeighborTableEvidence
    observation_times: Mapping[str, datetime] | None

    @classmethod
    def from_state(
        cls,
        state: object,
        *,
        observations: object = None,
    ) -> TrackerEvidenceSnapshot:
        """Build an immutable snapshot from the coordinator's effective state.

        Args:
            state (object): Effective coordinator state, including retained rows and the
                ``unavailable_device_tracker_tables`` marker for failed lookups.
            observations (object): Raw host-observation response from the current refresh.

        Returns:
            TrackerEvidenceSnapshot: Normalized family rows and timestamped observations.
        """
        state_mapping = state if isinstance(state, Mapping) else {}
        unavailable = state_mapping.get("unavailable_device_tracker_tables", [])
        unavailable_tables = (
            [item for item in unavailable if isinstance(item, str)]
            if isinstance(unavailable, list)
            else []
        )
        return cls(
            arp=_table_evidence(
                state_mapping.get("arp_table"),
                failed="arp_table" in unavailable_tables,
                ndp=False,
            ),
            ndp=_table_evidence(
                state_mapping.get("ndp_table"),
                failed="ndp_table" in unavailable_tables,
                ndp=True,
            ),
            observation_times=_index_observations(observations),
        )

    def entries_for_mac(
        self,
        family: TrackerFamily,
        mac: str,
        *,
        require_valid_mac: bool = False,
        require_ipv6: bool = False,
    ) -> tuple[ArpNdpEntry, ...]:
        """Return normalized rows matching one tracker MAC.

        Args:
            family (TrackerFamily): Neighbor-table family to search.
            mac (str): Tracker MAC address.
            require_valid_mac (bool): Whether to reject permissively normalized MACs.
            require_ipv6 (bool): Whether NDP rows must contain a valid IPv6 address.

        Returns:
            tuple[ArpNdpEntry, ...]: Matching normalized rows in table order.
        """
        normalized_mac = _device_tracker_mac(mac)
        if not normalized_mac:
            return ()
        table = self.arp if family == "arp" else self.ndp
        matching: list[ArpNdpEntry] = []
        for entry in table.entries:
            if not entry.usable:
                continue
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

    def with_observations(self, observations: object) -> TrackerEvidenceSnapshot:
        """Return the same normalized neighbor snapshot with current observation timestamps.

        Args:
            observations (object): Raw host-observation response from the current refresh.

        Returns:
            TrackerEvidenceSnapshot: Snapshot reusing its family rows and replacing the
                timestamp index with an immutable index from ``observations``.
        """
        return replace(self, observation_times=_index_observations(observations))

    def addresses_for_mac(self, family: TrackerFamily, mac: str) -> tuple[str, ...]:
        """Return unique normalized IP addresses for a MAC in one family.

        Args:
            family (TrackerFamily): Neighbor-table family to inspect.
            mac (str): Tracker MAC address.

        Returns:
            tuple[str, ...]: Canonical addresses in neighbor-table order.
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
    ) -> TrackerPresenceEvidence:
        """Classify correlated ARP, NDP, and discovery evidence for one tracker.

        Args:
            mac (str): Tracker MAC address.
            now (datetime): Aware time sampled while processing this entity refresh.
            max_age (timedelta): Maximum accepted host-observation age.
            previous_ipv4_addresses (Sequence[object]): Last published IPv4 inventory, retained
                while its table is unavailable.
            previous_ipv6_addresses (Sequence[object]): Last published IPv6 inventory, retained
                while its table is unavailable.

        Returns:
            TrackerPresenceEvidence: Presence classification and effective metadata values.
        """
        arp_entries = self.entries_for_mac("arp", mac)
        ndp_entries = self.entries_for_mac("ndp", mac, require_valid_mac=True, require_ipv6=True)
        ndp_presence_entries = self.entries_for_mac("ndp", mac)
        arp_failed = not self.arp.successful
        ndp_failed = not self.ndp.successful
        ipv4_addresses = tuple(_saved_addresses(previous_ipv4_addresses) if arp_failed else ())
        if not arp_failed:
            ipv4_addresses = self.addresses_for_mac("arp", mac)
        observed_ipv6_addresses = self.addresses_for_mac("ndp", mac)
        if ndp_failed:
            ipv6_addresses = tuple(
                dict.fromkeys(
                    _saved_addresses(previous_ipv6_addresses) + list(observed_ipv6_addresses)
                )
            )
        else:
            ipv6_addresses = observed_ipv6_addresses

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
            or (arp_failed and ndp_failed)
            or (arp_failed and bool(ipv4_addresses))
            or (ndp_failed and bool(ipv6_addresses))
        ):
            status = "unknown"
        else:
            status = "absent"

        return TrackerPresenceEvidence(
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

    def devices(self, configured_macs: Sequence[str] | None = None) -> tuple[TrackerDevice, ...]:
        """Build tracker devices from effective rows or an explicit MAC selection.

        Args:
            configured_macs (Sequence[str] | None): Configured MACs, or ``None`` to discover
                every usable MAC represented in either table.

        Returns:
            tuple[TrackerDevice, ...]: Devices in stable table/configuration order.
        """
        if configured_macs is not None:
            normalized_macs = tuple(
                dict.fromkeys(
                    normalized
                    for mac in configured_macs
                    if (normalized := _device_tracker_mac(mac))
                )
            )
            return tuple(self._device_for_mac(mac) for mac in normalized_macs)

        devices: dict[str, TrackerDevice] = {}
        for family, entries in (("arp", self.arp.entries), ("ndp", self.ndp.entries)):
            for entry in entries:
                if not entry.usable:
                    continue
                mac = entry.mac if family == "arp" else entry.valid_mac
                if mac is None or (family == "ndp" and entry.ipv6_address is None):
                    continue
                previous = devices.get(mac, TrackerDevice(mac))
                devices[mac] = TrackerDevice(
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
        if observed_at is None or not _is_aware(now):
            return False
        return now - observed_at < max_age

    def _device_for_mac(self, mac: str) -> TrackerDevice:
        """Build one configured tracker using ARP metadata and the NDP vendor fallback.

        Args:
            mac (str): Configured tracker MAC address.

        Returns:
            TrackerDevice: Normalized tracker identity and metadata.
        """
        arp_entries = self.entries_for_mac("arp", mac)
        ndp_entries = self.entries_for_mac("ndp", mac, require_valid_mac=True, require_ipv6=True)
        arp_entry = arp_entries[0] if arp_entries else None
        ndp_entry = ndp_entries[0] if ndp_entries else None
        return TrackerDevice(
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


def setup_family_provenance(
    snapshot: TrackerEvidenceSnapshot,
    inventory: Mapping[str, object],
) -> FamilyProvenance:
    """Reconcile setup inventories, allowing authoritative families to replace membership.

    Args:
        snapshot (TrackerEvidenceSnapshot): Current normalized tracker snapshot.
        inventory (Mapping[str, object]): Config-entry data containing legacy or family-specific
            persisted MAC inventories.

    Returns:
        FamilyProvenance: Family inventories used by setup and stale-device cleanup.
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
    return FamilyProvenance(tuple(arp_macs), tuple(ndp_macs))


def normalize_family_inventory(value: object, *, ndp: bool = False) -> tuple[str, ...]:
    """Normalize one persisted tracker MAC inventory while preserving its order.

    Args:
        value (object): Persisted MAC inventory.
        ndp (bool): Whether entries require strict complete MAC formatting.

    Returns:
        tuple[str, ...]: Unique normalized MACs in stored order.
    """
    return tuple(_normalize_inventory(value, ndp=ndp))


def poll_family_provenance(
    snapshot: TrackerEvidenceSnapshot,
    *,
    tracked_macs: object,
    previous_arp_macs: object,
    previous_ndp_macs: object,
) -> FamilyProvenance:
    """Update existing track-all membership while retaining provenance for absent devices.

    Args:
        snapshot (TrackerEvidenceSnapshot): Current normalized tracker snapshot.
        tracked_macs (object): Existing overall tracker inventory.
        previous_arp_macs (object): Last persisted ARP provenance.
        previous_ndp_macs (object): Last persisted NDP provenance.

    Returns:
        FamilyProvenance: Updated immutable inventories limited to existing tracked MACs.
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
    return FamilyProvenance(tuple(updated_arp), tuple(updated_ndp))


def _table_evidence(value: object, *, failed: bool, ndp: bool) -> NeighborTableEvidence:
    """Normalize current or cached table rows and classify authority.

    Args:
        value (object): Effective state value for one neighbor table.
        failed (bool): Whether the current lookup failed despite retained rows.
        ndp (bool): Whether the rows belong to the IPv6 neighbor table.

    Returns:
        NeighborTableEvidence: Normalized rows and their availability classification.
    """
    rows = value if isinstance(value, list) else []
    entries = tuple(normalize_arp_ndp_entry(row) for row in rows if isinstance(row, Mapping))
    rows_complete = len(entries) == len(rows) and all(entry.usable for entry in entries)
    if ndp:
        rows_complete = rows_complete and all(
            entry.valid_mac is not None and entry.ipv6_address is not None for entry in entries
        )
    successful = not failed and isinstance(value, list)
    authoritative = successful and rows_complete
    return NeighborTableEvidence(
        successful=successful,
        authoritative=authoritative,
        has_payload=isinstance(value, list),
        is_ndp=ndp,
        current_entries=entries if successful else None,
        entries=entries,
    )


def _index_observations(observations: object) -> Mapping[str, datetime] | None:
    """Index newest valid discovery timestamps into an immutable mapping.

    Args:
        observations (object): Raw host-observation payload returned by the client.

    Returns:
        Mapping[str, datetime] | None: Latest aware timestamp per normalized MAC when the
            discovery source has a well-formed rows list, otherwise ``None``.
    """
    if (
        not isinstance(observations, Mapping)
        or observations.get("source") != "discovery"
        or not isinstance(observations.get("rows"), list)
    ):
        return None
    latest: dict[str, datetime] = {}
    for row in observations["rows"]:
        if not isinstance(row, Mapping):
            continue
        mac = row.get("mac")
        last_seen = row.get("last_seen")
        if (
            not isinstance(mac, str)
            or not isinstance(last_seen, datetime)
            or not _is_aware(last_seen)
        ):
            continue
        normalized_mac = normalize_mac_address(mac)
        if normalized_mac is None:
            continue
        previous = latest.get(normalized_mac)
        if previous is None or last_seen > previous:
            latest[normalized_mac] = last_seen
    return MappingProxyType(latest)


def _device_tracker_mac(mac: object) -> str:
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
        mac = normalize_mac_address(item) if ndp else _device_tracker_mac(item)
        if mac and mac not in result:
            result.append(mac)
    return result


def _is_aware(value: datetime) -> bool:
    """Return whether a timestamp has a usable UTC offset.

    Args:
        value (datetime): Timestamp to inspect.

    Returns:
        bool: Whether the timestamp is timezone-aware.
    """
    return value.tzinfo is not None and value.utcoffset() is not None


def _saved_addresses(values: Sequence[object]) -> list[str]:
    """Return string values from a previously published address sequence.

    Args:
        values (Sequence[object]): Restored or previously published address values.

    Returns:
        list[str]: Address strings in their existing order.
    """
    return [value for value in values if isinstance(value, str)]
