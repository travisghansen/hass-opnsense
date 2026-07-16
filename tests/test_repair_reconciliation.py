"""Tests for restart-safe device-ID repair reconciliation."""

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

from homeassistant.helpers.entity import Entity
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.opnsense import repair_reconciliation as rr
from custom_components.opnsense.const import DOMAIN


class _EntityRegistry:
    """Minimal mutable entity registry used by reconciliation tests."""

    def __init__(self, entries: list[Any]) -> None:
        self.entries = entries
        self.removed: list[str] = []

    def async_get(self, entity_id: str) -> Any | None:
        """Return an entry by entity ID."""
        return next((entry for entry in self.entries if entry.entity_id == entity_id), None)

    def async_get_entity_id(self, domain: str, platform: str, unique_id: str) -> str | None:
        """Return the entity ID matching a full registry identity."""
        entry = next(
            (
                item
                for item in self.entries
                if (item.domain, item.platform, item.unique_id) == (domain, platform, unique_id)
            ),
            None,
        )
        return entry.entity_id if entry else None

    def async_update_entity(self, entity_id: str, **changes: Any) -> Any:
        """Apply supported registry changes in place."""
        entry = self.async_get(entity_id)
        if entry is None:
            raise KeyError(entity_id)
        if "new_unique_id" in changes:
            entry.unique_id = changes["new_unique_id"]
        if "device_id" in changes:
            entry.device_id = changes["device_id"]
        return entry

    def async_remove(self, entity_id: str) -> None:
        """Remove an entity by ID."""
        self.removed.append(entity_id)
        self.entries[:] = [entry for entry in self.entries if entry.entity_id != entity_id]


class _DeviceRegistry:
    """Minimal mutable device registry used by reconciliation tests."""

    def __init__(self, devices: list[Any]) -> None:
        self.devices = devices
        self.updates: list[tuple[str, dict[str, Any]]] = []

    def async_get_device(self, *, identifiers: set[tuple[str, str]]) -> Any | None:
        """Return a device matching an identifier."""
        return next((device for device in self.devices if device.identifiers & identifiers), None)

    def async_update_device(self, device_id: str, **changes: Any) -> Any:
        """Apply identifiers or config-entry removal."""
        self.updates.append((device_id, changes))
        device = next(item for item in self.devices if item.id == device_id)
        if "new_identifiers" in changes:
            device.identifiers = changes["new_identifiers"]
        if "remove_config_entry_id" in changes:
            device.config_entries.discard(changes["remove_config_entry_id"])
        return device


def _entry(unique_id: str, *, entity_id: str, device_id: str | None = None, **attrs: Any) -> Any:
    """Create a registry-entry stand-in."""
    return SimpleNamespace(
        entity_id=entity_id,
        domain=entity_id.split(".", 1)[0],
        platform=DOMAIN,
        unique_id=unique_id,
        config_entry_id="entry-1",
        device_id=device_id,
        **attrs,
    )


def _device(
    device_id: str,
    identifier: str,
    *,
    config_entries: set[str] | None = None,
) -> Any:
    """Create a device-registry stand-in."""
    return SimpleNamespace(
        id=device_id,
        identifiers={(DOMAIN, identifier)},
        config_entries=set(config_entries or {"entry-1"}),
    )


def _subject(
    monkeypatch: pytest.MonkeyPatch,
    entities: list[Any],
    devices: list[Any],
) -> tuple[rr.RepairReconciliation, _EntityRegistry, _DeviceRegistry]:
    """Create reconciliation with patched mutable registries."""
    entity_registry = _EntityRegistry(entities)
    device_registry = _DeviceRegistry(devices)
    monkeypatch.setattr(rr.er, "async_get", lambda _hass: entity_registry)
    monkeypatch.setattr(
        rr.er,
        "async_entries_for_config_entry",
        lambda registry, entry_id: [
            item for item in registry.entries if item.config_entry_id == entry_id
        ],
    )
    monkeypatch.setattr(rr.dr, "async_get", lambda _hass: device_registry)
    monkeypatch.setattr(
        rr.dr,
        "async_entries_for_config_entry",
        lambda registry, entry_id: [
            item for item in registry.devices if entry_id in item.config_entries
        ],
    )
    entry = MockConfigEntry(domain=DOMAIN, data={}, unique_id="new_id")
    object.__setattr__(entry, "entry_id", "entry-1")
    reconciliation = rr.RepairReconciliation(
        MagicMock(), entry, rr.RepairMarker(1, "old_id", "new_id")
    )
    return reconciliation, entity_registry, device_registry


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        {"version": 2, "old_device_id": "old", "new_device_id": "new"},
        {"version": 1, "old_device_id": "", "new_device_id": "new"},
        {"version": 1, "old_device_id": "same", "new_device_id": "same"},
        {"version": 1, "old_device_id": 1, "new_device_id": "new"},
    ],
)
def test_parse_repair_marker_rejects_invalid_values(value: object) -> None:
    """Malformed markers must never start reconciliation."""
    entry = MockConfigEntry(domain=DOMAIN, data={rr.REPAIR_MARKER_KEY: value})

    assert rr.has_repair_marker(entry)
    assert rr.parse_repair_marker(entry) is None


def test_parse_repair_marker_accepts_current_marker() -> None:
    """A current complete marker is parsed exactly."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={rr.REPAIR_MARKER_KEY: rr.build_repair_marker("old", "new")},
    )

    assert rr.parse_repair_marker(entry) == rr.RepairMarker(1, "old", "new")


def test_prepare_migrates_exact_prefix_in_place_and_preserves_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only the exact slugged old prefix changes, preserving registry identity and metadata."""
    migrated = _entry(
        "old_id_interface_lan_with_under_scores",
        entity_id="sensor.kept",
        device_id="main",
        disabled_by="user",
        original_name="Original",
    )
    immune = _entry("old_identifier_other", entity_id="sensor.immune", device_id="main")
    reconciliation, registry, _ = _subject(
        monkeypatch, [migrated, immune], [_device("main", "old_id")]
    )

    reconciliation.prepare()

    assert migrated.entity_id == "sensor.kept"
    assert migrated.unique_id == "new_id_interface_lan_with_under_scores"
    assert migrated.disabled_by == "user"
    assert migrated.original_name == "Original"
    assert immune.unique_id == "old_identifier_other"
    assert registry.removed == []


def test_prepare_rejects_full_identity_collision(monkeypatch: pytest.MonkeyPatch) -> None:
    """A collision is determined by domain, platform, and unique ID."""
    candidate = _entry("old_id_status", entity_id="sensor.old")
    collision = _entry("new_id_status", entity_id="sensor.other")
    reconciliation, _, _ = _subject(monkeypatch, [candidate, collision], [])

    with pytest.raises(rr.RepairReconciliationError, match="entity target collision"):
        reconciliation.prepare()


def test_prepare_migrates_primary_device_or_rejects_foreign_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The primary device migrates in place, while a foreign target blocks repair."""
    old = _device("main", "old_id")
    reconciliation, _, _ = _subject(monkeypatch, [], [old])

    reconciliation.prepare()
    assert old.id == "main"
    assert old.identifiers == {(DOMAIN, "new_id")}

    retry, _, retry_registry = _subject(monkeypatch, [], [old])
    retry.prepare()
    assert retry_registry.updates == []

    foreign = _device("foreign", "new_id", config_entries={"entry-2"})
    reconciliation, _, _ = _subject(monkeypatch, [], [foreign])
    with pytest.raises(rr.RepairReconciliationError, match="primary device"):
        reconciliation.prepare()

    simultaneous = _device("target", "new_id")
    reconciliation, _, _ = _subject(monkeypatch, [], [_device("source", "old_id"), simultaneous])
    with pytest.raises(rr.RepairReconciliationError, match="primary device"):
        reconciliation.prepare()


def test_finalize_removes_only_stale_snapshot_and_preserves_device_associations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finalization removes stale pre-repair rows but never new rows or used devices."""
    surviving = _entry("old_id_keep", entity_id="sensor.keep", device_id="used")
    stale = _entry("old_id_stale", entity_id="sensor.stale", device_id="obsolete")
    reconciliation, registry, devices = _subject(
        monkeypatch,
        [surviving, stale],
        [
            _device("main", "old_id"),
            _device("used", "child-used"),
            _device("obsolete", "child-old", config_entries={"entry-1", "entry-2"}),
        ],
    )
    reconciliation.prepare()
    new_entity = _entry("new_id_new", entity_id="sensor.new", device_id="used")
    registry.entries.append(new_entity)
    reconciliation.desired_identities.add(("sensor", DOMAIN, surviving.unique_id))

    reconciliation.finalize()

    assert registry.removed == ["sensor.stale"]
    assert registry.async_get("sensor.new") is new_entity
    assert ("obsolete", {"remove_config_entry_id": "entry-1"}) in devices.updates
    assert (
        "entry-2" in next(item for item in devices.devices if item.id == "obsolete").config_entries
    )
    removals = [
        device_id for device_id, changes in devices.updates if "remove_config_entry_id" in changes
    ]
    assert all(device_id not in {"main", "used"} for device_id in removals)


def test_prepare_and_finalize_are_idempotent_after_partial_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retry safely handles already-migrated and still-old candidates."""
    first = _entry("old_id_first", entity_id="sensor.first")
    second = _entry("old_id_second", entity_id="sensor.second")
    reconciliation, registry, _ = _subject(monkeypatch, [first, second], [])
    reconciliation.prepare()
    second.unique_id = "old_id_second"

    retry, _, _ = _subject(monkeypatch, registry.entries, [])
    retry.prepare()
    retry.desired_identities.update(
        {("sensor", DOMAIN, "new_id_first"), ("sensor", DOMAIN, "new_id_second")}
    )
    retry.finalize()

    assert {item.unique_id for item in registry.entries} == {
        "new_id_first",
        "new_id_second",
    }
    assert registry.removed == []


def test_records_all_final_platform_lists_including_disabled_entities() -> None:
    """Every forwarded platform contributes its complete final identity list."""
    reconciliation = rr.RepairReconciliation(
        MagicMock(), MagicMock(), rr.RepairMarker(1, "old", "new")
    )
    for platform in ("binary_sensor", "sensor", "switch", "update", "device_tracker"):
        entity = Entity()
        entity._attr_unique_id = f"new_{platform}"
        reconciliation.record_desired_entities(platform, [entity])

    assert reconciliation.desired_identities == {
        (platform, DOMAIN, f"new_{platform}")
        for platform in ("binary_sensor", "sensor", "switch", "update", "device_tracker")
    }
    reconciliation.require_platforms_complete(
        ("binary_sensor", "sensor", "switch", "update", "device_tracker")
    )


def test_incomplete_platform_lists_block_finalization() -> None:
    """Missing a forwarded platform completion is a hard reconciliation failure."""
    reconciliation = rr.RepairReconciliation(
        MagicMock(), MagicMock(), rr.RepairMarker(1, "old", "new")
    )
    reconciliation.record_desired_entities("sensor", [])

    with pytest.raises(rr.RepairReconciliationError, match="binary_sensor"):
        reconciliation.require_platforms_complete(("sensor", "binary_sensor"))
