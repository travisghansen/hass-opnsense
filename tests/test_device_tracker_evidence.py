"""Behavioral contracts for reusable device-tracker evidence."""

from datetime import UTC, datetime, timedelta

import pytest

from custom_components.opnsense.const import TRACKED_ARP_MACS, TRACKED_MACS, TRACKED_NDP_MACS
from custom_components.opnsense.device_tracker_evidence import (
    DeviceTrackerEvidenceSnapshot,
    poll_arp_ndp_provenance,
    setup_arp_ndp_provenance,
)

MAC = "aa:bb:cc:dd:ee:01"


def test_one_snapshot_evaluates_freshness_at_each_consumer_time() -> None:
    """Reusing observations must not freeze their freshness at snapshot construction."""
    observed_at = datetime(2026, 10, 31, 12, tzinfo=UTC)
    snapshot = DeviceTrackerEvidenceSnapshot.from_state(
        {"arp_table": [], "ndp_table": [{"mac": MAC, "ip": "2001:db8::1"}]},
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
    row = {"mac": MAC, "ip": "2001:db8::1"}
    ndp_rows = [row]
    failed_tables: list[str] = []
    observations: dict[str, object] = {
        "source": "discovery",
        "rows": [{"mac": MAC, "last_seen": observed_at}],
    }
    state: dict[str, object] = {
        "arp_table": [],
        "ndp_table": ndp_rows,
        "unavailable_device_tracker_tables": failed_tables,
    }
    snapshot = DeviceTrackerEvidenceSnapshot.from_state(state, observations=observations)

    row["ip"] = "2001:db8::99"
    ndp_rows.clear()
    failed_tables.append("ndp_table")
    observations.clear()

    assert snapshot.addresses_for_mac("ndp", MAC) == ("2001:db8::1",)
    assert snapshot.ndp.authoritative
    assert snapshot.is_host_observation_fresh(
        MAC, now=observed_at + timedelta(seconds=1), max_age=timedelta(minutes=20)
    )


def test_setup_and_poll_preserve_their_distinct_absence_policies() -> None:
    """A complete empty scan removes setup inventory but keeps polling provenance."""
    snapshot = DeviceTrackerEvidenceSnapshot.from_state({"arp_table": [], "ndp_table": []})
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
    snapshot = DeviceTrackerEvidenceSnapshot.from_state(
        {
            "arp_table": [{"mac": MAC, "ip": "192.0.2.1"}],
            "ndp_table": [],
            "unavailable_device_tracker_tables": ["arp_table"],
        }
    )

    assert snapshot.addresses_for_mac("arp", MAC) == ("192.0.2.1",)
    assert snapshot.arp.current_entries is None
    assert not snapshot.arp.successful
    assert not snapshot.arp.authoritative


@pytest.mark.parametrize(
    "row",
    [
        pytest.param({"mac": "aa:bb", "ip": "2001:db8::1"}, id="incomplete-mac"),
        pytest.param({"mac": MAC, "ip": "192.0.2.1"}, id="wrong-address-family"),
        pytest.param({"mac": MAC}, id="missing-address"),
    ],
)
def test_incomplete_ndp_rows_do_not_discover_tracker_membership(row: dict[str, str]) -> None:
    """Malformed NDP rows cannot introduce devices into the setup family inventory.

    Args:
        row (dict[str, str]): Neighbor row lacking a complete MAC or IPv6 address.
    """
    snapshot = DeviceTrackerEvidenceSnapshot.from_state({"arp_table": [], "ndp_table": [row]})

    provenance = setup_arp_ndp_provenance(snapshot, {})

    assert provenance.ndp_macs == ()
    assert snapshot.devices() == ()


def test_tuple_shaped_persisted_inventory_cannot_retain_membership() -> None:
    """Invalid persisted containers retain no provenance during a family outage."""
    snapshot = DeviceTrackerEvidenceSnapshot.from_state({"arp_table": None, "ndp_table": None})
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
