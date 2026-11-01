"""Behavioral contracts for reusable device-tracker evidence."""

from datetime import UTC, datetime, timedelta

from aiopnsense import OPNsenseClient
import pytest

from custom_components.opnsense.const import TRACKED_ARP_MACS, TRACKED_MACS, TRACKED_NDP_MACS
from custom_components.opnsense.device_tracker_evidence import (
    poll_arp_ndp_provenance,
    setup_arp_ndp_provenance,
)
from tests.utilities import (
    arp_ndp_entry,
    arp_ndp_table,
    evidence_snapshot,
    host_observation,
    host_observations,
)

MAC = "aa:bb:cc:dd:ee:01"


def test_one_snapshot_evaluates_freshness_at_each_consumer_time() -> None:
    """Reusing observations must not freeze their freshness at snapshot construction."""
    observed_at = datetime(2026, 10, 31, 12, tzinfo=UTC)
    snapshot = evidence_snapshot(
        arp=arp_ndp_table(),
        ndp=arp_ndp_table([arp_ndp_entry(MAC, ipv6_address="2001:db8::1")]),
        observations=host_observations(
            "discovery", [host_observation(MAC, "192.0.2.1", observed_at)]
        ),
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
    """Retained ARP rows preserve address metadata without confirming current presence."""
    snapshot = evidence_snapshot(
        arp=arp_ndp_table([arp_ndp_entry(MAC, ipv4_address="192.0.2.1")]),
        ndp=arp_ndp_table(),
        arp_current=False,
    )
    presence = snapshot.presence_for_mac(
        MAC,
        now=datetime(2026, 10, 31, 12, tzinfo=UTC),
        max_age=timedelta(minutes=20),
    )

    assert snapshot.addresses_for_mac("arp", MAC) == ("192.0.2.1",)
    assert snapshot.arp.current_entries is None
    assert not snapshot.arp.successful
    assert not snapshot.arp.authoritative
    assert presence.status == "unknown"
    assert presence.ipv4_addresses == ("192.0.2.1",)


def test_failed_arp_merges_saved_and_retained_addresses_once() -> None:
    """A failed ARP lookup keeps saved addresses and adds cached rows without duplicates."""
    snapshot = evidence_snapshot(
        arp=arp_ndp_table(
            [
                arp_ndp_entry(MAC, ipv4_address="192.0.2.2"),
                arp_ndp_entry(MAC, ipv4_address="192.0.2.3"),
            ]
        ),
        ndp=arp_ndp_table(),
        arp_current=False,
    )

    presence = snapshot.presence_for_mac(
        MAC,
        now=datetime(2026, 10, 31, 12, tzinfo=UTC),
        max_age=timedelta(minutes=20),
        previous_ipv4_addresses=["192.0.2.1", "192.0.2.2"],
    )

    assert presence.status == "unknown"
    assert presence.ipv4_addresses == ("192.0.2.1", "192.0.2.2", "192.0.2.3")


def test_complete_empty_arp_scan_clears_saved_ipv4_metadata() -> None:
    """An authoritative empty ARP scan still replaces old IPv4 metadata."""
    snapshot = evidence_snapshot(arp=arp_ndp_table(), ndp=arp_ndp_table())

    presence = snapshot.presence_for_mac(
        MAC,
        now=datetime(2026, 10, 31, 12, tzinfo=UTC),
        max_age=timedelta(minutes=20),
        previous_ipv4_addresses=["192.0.2.1"],
    )

    assert presence.status == "absent"
    assert presence.ipv4_addresses == ()


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
    ("expired", "permanent", "status"),
    [(False, False, "present"), (True, False, "absent"), (True, True, "absent")],
)
def test_arp_row_is_fresh_only_when_not_expired(
    expired: bool, permanent: bool, status: str
) -> None:
    """Only a non-expired ARP row establishes presence; an expired row does not.

    Args:
        expired (bool): Library-normalized expiration state of the only ARP row.
        permanent (bool): Whether the row is marked permanent for expiry display.
        status (str): Expected presence classification.
    """
    snapshot = evidence_snapshot(
        arp=arp_ndp_table(
            [
                arp_ndp_entry(
                    MAC,
                    ipv4_address="192.0.2.1",
                    expired=expired,
                    permanent=permanent,
                )
            ]
        ),
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
        observations=host_observations(
            "discovery", [host_observation(MAC, "2001:db8::1", observed_at)]
        ),
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


@pytest.mark.parametrize(
    ("partial_family", "other_current"),
    [
        pytest.param("arp", True, id="partial-arp-plus-empty-ndp"),
        pytest.param("ndp", True, id="partial-ndp-plus-empty-arp"),
        pytest.param("arp", False, id="partial-arp-plus-failed-ndp"),
        pytest.param("ndp", False, id="partial-ndp-plus-failed-arp"),
    ],
)
def test_incomplete_current_family_cannot_prove_absence_or_clear_addresses(
    partial_family: str,
    other_current: bool,
) -> None:
    """Partial family results leave omitted identities and their addresses uncertain.

    Args:
        partial_family (str): Family whose current table has an unparsed row.
        other_current (bool): Whether the other family returned a complete empty table.
    """
    partial_table = arp_ndp_table(unparsed_row_count=1)
    empty_table = arp_ndp_table()
    snapshot = evidence_snapshot(
        arp=partial_table if partial_family == "arp" else empty_table if other_current else None,
        ndp=partial_table if partial_family == "ndp" else empty_table if other_current else None,
        arp_current=partial_family == "arp" or other_current,
        ndp_current=partial_family == "ndp" or other_current,
    )

    presence = snapshot.presence_for_mac(
        MAC,
        now=datetime(2026, 10, 31, 12, tzinfo=UTC),
        max_age=timedelta(minutes=20),
        previous_ipv4_addresses=["192.0.2.10"],
        previous_ipv6_addresses=["2001:db8::10"],
    )

    assert presence.status == "unknown"
    assert presence.ipv4_addresses == (
        ("192.0.2.10",) if partial_family == "arp" or not other_current else ()
    )
    assert presence.ipv6_addresses == (
        ("2001:db8::10",) if partial_family == "ndp" or not other_current else ()
    )


def test_partial_ndp_positive_evidence_still_confirms_presence() -> None:
    """A validated NDP row and fresh discovery timestamp override table incompleteness."""
    observed_at = datetime(2026, 10, 31, 12, tzinfo=UTC)
    snapshot = evidence_snapshot(
        arp=arp_ndp_table(),
        ndp=arp_ndp_table(
            [arp_ndp_entry(MAC, ipv6_address="2001:db8::1")],
            unparsed_row_count=1,
        ),
        observations=host_observations(
            "discovery", [host_observation(MAC, "2001:db8::1", observed_at)]
        ),
    )

    presence = snapshot.presence_for_mac(
        MAC, now=observed_at + timedelta(seconds=1), max_age=timedelta(minutes=20)
    )

    assert presence.status == "present"
