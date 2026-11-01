"""Behavioral contracts for reusable device-tracker evidence."""

from datetime import UTC, datetime, timedelta

from aiopnsense import OPNsenseClient
import pytest

from custom_components.opnsense.const import TRACKED_ARP_MACS, TRACKED_MACS, TRACKED_NDP_MACS
from custom_components.opnsense.device_tracker_evidence import (
    poll_arp_ndp_provenance,
    setup_arp_ndp_provenance,
)
from tests.utilities import arp_ndp_entry, arp_ndp_table, evidence_snapshot

MAC = "aa:bb:cc:dd:ee:01"


def test_one_snapshot_evaluates_freshness_at_each_consumer_time() -> None:
    """Reusing observations must not freeze their freshness at snapshot construction."""
    observed_at = datetime(2026, 10, 31, 12, tzinfo=UTC)
    snapshot = evidence_snapshot(
        arp=arp_ndp_table(),
        ndp=arp_ndp_table([arp_ndp_entry(MAC, ipv6_address="2001:db8::1")]),
        observations={"source": "discovery", "rows": [{"mac": MAC, "last_seen": observed_at}]},
    )
    max_age = timedelta(minutes=20)

    fresh = snapshot.presence_for_mac(
        MAC, now=observed_at + max_age - timedelta(seconds=1), max_age=max_age
    )
    expired = snapshot.presence_for_mac(MAC, now=observed_at + max_age, max_age=max_age)

    assert fresh.status == "present"
    assert expired.status == "absent"
    # An old observation still identifies the source, without confirming presence.
    assert expired.ndp_presence_source == "host_discovery"


def test_snapshot_isolates_consumers_from_later_source_mutation() -> None:
    """A published scan must keep its evidence when caller-owned inputs change."""
    observed_at = datetime(2026, 10, 31, 12, tzinfo=UTC)
    ndp_entries = [arp_ndp_entry(MAC, ipv6_address="2001:db8::1")]
    observations: dict[str, object] = {
        "source": "discovery",
        "rows": [{"mac": MAC, "last_seen": observed_at}],
    }
    snapshot = evidence_snapshot(
        arp=arp_ndp_table(),
        ndp=arp_ndp_table(ndp_entries),
        observations=observations,
    )

    ndp_entries.clear()
    observations.clear()

    assert snapshot.addresses_for_mac("ndp", MAC) == ("2001:db8::1",)
    assert snapshot.ndp.authoritative
    assert snapshot.is_host_observation_fresh(
        MAC, now=observed_at + timedelta(seconds=1), max_age=timedelta(minutes=20)
    )


def test_setup_and_poll_preserve_their_distinct_absence_policies() -> None:
    """A complete empty scan removes setup inventory but keeps polling provenance."""
    snapshot = evidence_snapshot(arp=arp_ndp_table(), ndp=arp_ndp_table())
    inventory = {TRACKED_MACS: [MAC], TRACKED_ARP_MACS: [MAC], TRACKED_NDP_MACS: []}

    setup = setup_arp_ndp_provenance(snapshot, inventory)
    poll = poll_arp_ndp_provenance(
        snapshot,
        tracked_macs=inventory[TRACKED_MACS],
        previous_arp_macs=inventory[TRACKED_ARP_MACS],
        previous_ndp_macs=inventory[TRACKED_NDP_MACS],
    )

    assert setup.arp_macs == ()
    assert setup.ndp_macs == ()
    assert poll.arp_macs == (MAC,)
    assert poll.ndp_macs == ()
    assert inventory == {TRACKED_MACS: [MAC], TRACKED_ARP_MACS: [MAC], TRACKED_NDP_MACS: []}


def test_cached_rows_preserve_inventory_without_becoming_current_evidence() -> None:
    """An unavailable family retains address metadata without a current sighting."""
    snapshot = evidence_snapshot(
        arp=arp_ndp_table([arp_ndp_entry(MAC, ipv4_address="192.0.2.1")]),
        ndp=arp_ndp_table(),
        arp_current=False,
    )

    assert snapshot.addresses_for_mac("arp", MAC) == ("192.0.2.1",)
    assert snapshot.arp.current_entries is None
    assert not snapshot.arp.successful
    assert not snapshot.arp.authoritative


@pytest.mark.parametrize(
    "row",
    [
        pytest.param(
            arp_ndp_entry("aa:bb", valid_mac=None, ipv6_address="2001:db8::1"),
            id="incomplete-mac",
        ),
        pytest.param(arp_ndp_entry(MAC, ipv4_address="192.0.2.1"), id="wrong-address-family"),
        pytest.param(arp_ndp_entry(MAC), id="missing-address"),
    ],
)
def test_incomplete_ndp_rows_do_not_discover_tracker_membership(
    row: OPNsenseClient.ArpNdpEntry,
) -> None:
    """Malformed NDP rows cannot introduce devices into the setup family inventory.

    Args:
        row (OPNsenseClient.ArpNdpEntry): Normalized neighbor row lacking a valid MAC or
            IPv6 address.
    """
    snapshot = evidence_snapshot(arp=arp_ndp_table(), ndp=arp_ndp_table([row]))

    provenance = setup_arp_ndp_provenance(snapshot, {})

    assert provenance.ndp_macs == ()
    assert snapshot.devices() == ()


def test_tuple_shaped_persisted_inventory_cannot_retain_membership() -> None:
    """Invalid persisted containers retain no provenance during a family outage."""
    snapshot = evidence_snapshot(arp=None, ndp=None)
    inventory = {TRACKED_MACS: (MAC,), TRACKED_NDP_MACS: (MAC,)}

    setup = setup_arp_ndp_provenance(snapshot, inventory)
    poll = poll_arp_ndp_provenance(
        snapshot,
        tracked_macs=[MAC],
        previous_arp_macs=(MAC,),
        previous_ndp_macs=(MAC,),
    )

    assert setup.arp_macs == setup.ndp_macs == ()
    assert poll.arp_macs == poll.ndp_macs == ()


@pytest.mark.parametrize(
    ("expired", "status"),
    [(False, "present"), (True, "absent")],
)
def test_arp_row_is_fresh_only_when_not_expired(expired: bool, status: str) -> None:
    """Only a non-expired ARP row establishes presence; an expired row does not.

    Args:
        expired (bool): Library-normalized expiration state of the only ARP row.
        status (str): Expected presence classification.
    """
    snapshot = evidence_snapshot(
        arp=arp_ndp_table([arp_ndp_entry(MAC, ipv4_address="192.0.2.1", expired=expired)]),
        ndp=arp_ndp_table(),
    )

    presence = snapshot.presence_for_mac(
        MAC, now=datetime(2026, 10, 31, 12, tzinfo=UTC), max_age=timedelta(minutes=20)
    )

    assert presence.status == status


def test_expired_row_yields_to_other_current_presence_evidence() -> None:
    """A non-expired row for the same MAC still establishes presence beside an expired one."""
    observed_at = datetime(2026, 10, 31, 12, tzinfo=UTC)
    snapshot = evidence_snapshot(
        arp=arp_ndp_table(
            [
                arp_ndp_entry(MAC, ipv4_address="192.0.2.1", expired=True),
                arp_ndp_entry(MAC, ipv4_address="192.0.2.2", expired=False),
            ]
        ),
        ndp=arp_ndp_table(),
    )
    ndp_snapshot = evidence_snapshot(
        arp=arp_ndp_table([arp_ndp_entry(MAC, ipv4_address="192.0.2.1", expired=True)]),
        ndp=arp_ndp_table([arp_ndp_entry(MAC, ipv6_address="2001:db8::1")]),
        observations={"source": "discovery", "rows": [{"mac": MAC, "last_seen": observed_at}]},
    )
    now = observed_at + timedelta(seconds=1)
    max_age = timedelta(minutes=20)

    assert snapshot.presence_for_mac(MAC, now=now, max_age=max_age).status == "present"
    assert ndp_snapshot.presence_for_mac(MAC, now=now, max_age=max_age).status == "present"


def test_partial_table_keeps_valid_entries_without_authoritative_absence() -> None:
    """Unparsed rows keep usable records but never turn a scan into a complete empty one."""
    other = "aa:bb:cc:dd:ee:02"
    partial = evidence_snapshot(
        arp=arp_ndp_table(
            [arp_ndp_entry(MAC, ipv4_address="192.0.2.1")],
            unparsed_row_count=1,
        ),
        ndp=arp_ndp_table(),
    )
    only_unparsed = evidence_snapshot(
        arp=arp_ndp_table(unparsed_row_count=1),
        ndp=arp_ndp_table(),
    )
    inventory = {TRACKED_MACS: [other], TRACKED_ARP_MACS: [other], TRACKED_NDP_MACS: []}

    assert partial.arp.successful
    assert not partial.arp.authoritative
    assert partial.addresses_for_mac("arp", MAC) == ("192.0.2.1",)
    assert (
        partial.presence_for_mac(
            MAC, now=datetime(2026, 10, 31, 12, tzinfo=UTC), max_age=timedelta(minutes=20)
        ).status
        == "present"
    )
    assert setup_arp_ndp_provenance(only_unparsed, inventory).arp_macs == (other,)
    assert (
        setup_arp_ndp_provenance(
            evidence_snapshot(arp=arp_ndp_table(), ndp=arp_ndp_table()), inventory
        ).arp_macs
        == ()
    )
