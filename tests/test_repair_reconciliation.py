"""Tests for restart-safe Device ID repair reconciliation."""

from collections.abc import Callable
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.entity import Entity
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.opnsense import repair_reconciliation as rr
from custom_components.opnsense.const import CONF_DEVICE_UNIQUE_ID, DOMAIN
from custom_components.opnsense.repair_reconciliation import (
    REPAIR_MARKER_KEY,
    RepairMarker,
    RepairReconciliation,
    RepairReconciliationError,
    build_repair_marker,
    has_repair_marker,
    is_reconciliation_active,
    parse_repair_marker,
    record_desired_entities,
)


class _EntityRegistry:
    """Minimal mutable entity registry used by reconciliation tests."""

    def __init__(self, entries: list[Any]) -> None:
        """Initialize the test entity registry.

        Args:
            entries (list[Any]): Initial entity-registry entries.
        """
        self.entries = entries
        self.removed: list[str] = []

    def async_get(self, entity_id: str) -> Any | None:
        """Return an entry by entity ID.

        Returns:
            Any | None: Simulated result used by the get scenario.

        Args:
            entity_id (str): Entity identifier looked up in the mocked registry.
        """
        return next((entry for entry in self.entries if entry.entity_id == entity_id), None)

    def async_get_entity_id(self, domain: str, platform: str, unique_id: str) -> str | None:
        """Return the entity ID matching a full registry identity.

        Returns:
            str | None: Simulated result used by the get entity id scenario.

        Args:
            domain (str): Registry filter used by the simulated lookup.
            platform (str): Registry filter used by the simulated lookup.
            unique_id (str): Entity or config-entry unique identifier for the scenario.
        """
        entry = next(
            (
                item
                for item in self.entries
                if (item.domain, item.platform, item.unique_id) == (domain, platform, unique_id)
            ),
            None,
        )
        return entry.entity_id if entry else None

    def async_update_entity(self, entity_id: str, **_changes: Any) -> Any:
        """Apply supported registry changes in place.

        Returns:
            Any: Simulated result used by the update entity scenario.

        Args:
            entity_id (str): Entity identifier looked up in the mocked registry.
            _changes (Any): Registry changes applied by the test double.

        Raises:
            KeyError: The requested entity is not present in the fake registry.
        """
        entry = self.async_get(entity_id)
        if entry is None:
            raise KeyError(entity_id)
        if "new_unique_id" in _changes:
            entry.unique_id = _changes["new_unique_id"]
        if "device_id" in _changes:
            entry.device_id = _changes["device_id"]
        return entry

    def async_remove(self, entity_id: str) -> None:
        """Remove an entity by ID.

        Args:
            entity_id (str): Entity identifier looked up in the mocked registry.
        """
        self.removed.append(entity_id)
        self.entries[:] = [entry for entry in self.entries if entry.entity_id != entity_id]


class _DeviceRegistry:
    """Minimal mutable device registry used by reconciliation tests."""

    def __init__(self, devices: list[Any]) -> None:
        """Initialize the test device registry.

        Args:
            devices (list[Any]): Initial device-registry devices.
        """
        self.devices = devices
        self.updates: list[tuple[str, dict[str, Any]]] = []

    def async_get_device(self, *, identifiers: set[tuple[str, str]]) -> Any | None:
        """Return a device matching an identifier.

        Returns:
            Any | None: Simulated result used by the get device scenario.

        Args:
            identifiers (set[tuple[str, str]]): Parameterized identifiers used by the get device scenario.
        """
        return next((device for device in self.devices if device.identifiers & identifiers), None)

    def async_update_device(self, device_id: str, **_changes: Any) -> Any:
        """Apply identifiers or config-entry removal.

        Returns:
            Any: Simulated result used by the update device scenario.

        Args:
            device_id (str): Home Assistant device registry identifier to validate.
            _changes (Any): Registry changes applied by the test double.
        """
        self.updates.append((device_id, _changes))
        device = next(item for item in self.devices if item.id == device_id)
        if "new_identifiers" in _changes:
            device.identifiers = _changes["new_identifiers"]
        if "remove_config_entry_id" in _changes:
            device.config_entries.discard(_changes["remove_config_entry_id"])
        if "via_device_id" in _changes:
            device.via_device_id = _changes["via_device_id"]
        return device


class _ConfigEntries:
    """Minimal config-entry registry used for shared-router lookup."""

    def __init__(self, entries: dict[str, object]) -> None:
        """Initialize the test config-entry registry.

        Args:
            entries (dict[str, object]): Config entries keyed by their IDs.
        """
        self._entries = entries

    def async_get_entry(self, entry_id: str) -> object | None:
        """Return a stored config entry.

        Returns:
            object | None: Simulated result used by the get entry scenario.

        Args:
            entry_id (str): Config entry identifier used by the repair scenario.
        """
        return self._entries.get(entry_id)


class _DesiredTrackerEntity(Entity):
    """Minimal desired tracker entity carrying a MAC connection identity."""

    def __init__(self, unique_id: str, mac_address: str) -> None:
        """Initialize the desired tracker identity.

        Args:
            unique_id (str): Entity or config-entry unique identifier for the scenario.
            mac_address (str): Parameterized mac address used by the init scenario.
        """
        self._attr_unique_id = unique_id
        self._mac_address = mac_address

    @property
    def mac_address(self) -> str:
        """Return the tracker MAC address.

        Returns:
            str: Simulated result used by the mac address scenario.
        """
        return self._mac_address


def _other_config_entry(entry_id: str, unique_id: str) -> MockConfigEntry:
    """Create a config entry carrying OPNsense device unique identifier.

    Returns:
        MockConfigEntry: Simulated result used by the other config entry scenario.

    Args:
        entry_id (str): Config entry identifier used by the repair scenario.
        unique_id (str): Entity or config-entry unique identifier for the scenario.
    """
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_DEVICE_UNIQUE_ID: unique_id},
        unique_id=unique_id,
    )
    object.__setattr__(entry, "entry_id", entry_id)
    return entry


def _entry(unique_id: str, *, entity_id: str, device_id: str | None = None, **_attrs: Any) -> Any:
    """Create a registry-entry stand-in.

    Returns:
        Any: Simulated result used by the entry scenario.

    Args:
        unique_id (str): Entity or config-entry unique identifier for the scenario.
        entity_id (str): Entity identifier looked up in the mocked registry.
        device_id (str | None): Home Assistant device registry identifier to validate.
        _attrs (Any): Additional registry-entry attributes.
    """
    return SimpleNamespace(
        entity_id=entity_id,
        domain=entity_id.split(".", 1)[0],
        platform=DOMAIN,
        unique_id=unique_id,
        config_entry_id="entry-1",
        device_id=device_id,
        **_attrs,
    )


def _config_entry_with_runtime_data(runtime_data: Any) -> MockConfigEntry:
    """Create an entry carrying explicit runtime reconciliation wiring.

    Returns:
        MockConfigEntry: Simulated result used by the config entry with runtime data scenario.

    Args:
        runtime_data (Any): Simulated runtime object exposed to diagnostics.
    """
    entry = _other_config_entry("entry-1", "new")
    object.__setattr__(entry, "runtime_data", runtime_data)
    return entry


def _device(
    device_id: str,
    identifier: str,
    *,
    config_entries: set[str] | None = None,
    via_device_id: str | None = None,
    connections: set[tuple[str, str]] | None = None,
) -> Any:
    """Create a device-registry stand-in.

    Returns:
        Any: Simulated result used by the device scenario.

    Args:
        device_id (str): Home Assistant device registry identifier to validate.
        identifier (str): Parameterized identifier used by the device scenario.
        config_entries (set[str] | None): Parameterized config entries used by the device scenario.
        via_device_id (str | None): Parameterized via device id used by the device scenario.
        connections (set[tuple[str, str]] | None): Parameterized connections used by the device scenario.
    """
    return SimpleNamespace(
        id=device_id,
        identifiers={(DOMAIN, identifier)},
        config_entries=set(config_entries or {"entry-1"}),
        via_device_id=via_device_id,
        connections=set(connections or set()),
    )


def _subject(
    monkeypatch: pytest.MonkeyPatch,
    entities: list[Any],
    devices: list[Any],
    extra_config_entries: dict[str, MockConfigEntry] | None = None,
) -> tuple[RepairReconciliation, _EntityRegistry, _DeviceRegistry]:
    """Create reconciliation with patched mutable registries.

    Returns:
        tuple[RepairReconciliation, _EntityRegistry, _DeviceRegistry]: Simulated collection used by the subject scenario.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest fixture used to isolate the simulated behavior.
        entities (list[Any]): Registry records exposed to the repair helper.
        devices (list[Any]): Registry records exposed to the repair helper.
        extra_config_entries (dict[str, MockConfigEntry] | None): Parameterized extra config entries used by the subject scenario.
    """
    entity_registry = _EntityRegistry(entities)
    device_registry = _DeviceRegistry(devices)
    monkeypatch.setattr(er, "async_get", lambda _hass: entity_registry)
    monkeypatch.setattr(
        er,
        "async_entries_for_config_entry",
        lambda registry, entry_id: [
            item for item in registry.entries if item.config_entry_id == entry_id
        ],
    )
    monkeypatch.setattr(dr, "async_get", lambda _hass: device_registry)
    monkeypatch.setattr(
        dr,
        "async_entries_for_config_entry",
        lambda registry, entry_id: [
            item for item in registry.devices if entry_id in item.config_entries
        ],
    )
    entry = MockConfigEntry(domain=DOMAIN, data={}, unique_id="new_id")
    object.__setattr__(entry, "entry_id", "entry-1")
    config_entry_map: dict[str, MockConfigEntry] = {"entry-1": entry}
    if extra_config_entries:
        config_entry_map.update(extra_config_entries)
    hass = MagicMock()
    hass.config_entries = _ConfigEntries(config_entry_map)
    reconciliation = RepairReconciliation(hass, entry, RepairMarker(1, "old_id", "new_id"))
    return reconciliation, entity_registry, device_registry


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        {"version": 2, "old_device_id": "old", "new_device_id": "new"},
        {"version": True, "old_device_id": "old", "new_device_id": "new"},
        {"version": 1.0, "old_device_id": "old", "new_device_id": "new"},
        {"version": 1, "old_device_id": "", "new_device_id": "new"},
        {"version": 1, "old_device_id": "same", "new_device_id": "same"},
        {"version": 1, "old_device_id": 1, "new_device_id": "new"},
    ],
)
def test_parse_repair_marker_rejects_invalid_values(value: object) -> None:
    """Malformed markers must never start reconciliation.

    Args:
        value (object): Diagnostic value being inspected or transformed.
    """
    entry = MockConfigEntry(domain=DOMAIN, data={REPAIR_MARKER_KEY: value})

    assert has_repair_marker(entry)
    assert parse_repair_marker(entry) is None


def test_parse_repair_marker_accepts_current_marker() -> None:
    """A current complete marker is parsed exactly."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={REPAIR_MARKER_KEY: build_repair_marker("old", "new")},
    )

    assert parse_repair_marker(entry) == RepairMarker(1, "old", "new")


def test_prepare_migrates_exact_prefix_in_place_and_preserves_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only the exact slugged old prefix changes, preserving registry identity and metadata.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest fixture used to isolate the simulated behavior.
    """
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
    """A collision is determined by domain, platform, and unique ID.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest fixture used to isolate the simulated behavior.
    """
    candidate = _entry("old_id_status", entity_id="sensor.old")
    collision = _entry("new_id_status", entity_id="sensor.other")
    reconciliation, _, _ = _subject(monkeypatch, [candidate, collision], [])

    with pytest.raises(RepairReconciliationError, match="entity target collision"):
        reconciliation.prepare()


def test_prepare_migrates_primary_device_or_rejects_foreign_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The primary device migrates in place, while a foreign target blocks repair.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest fixture used to isolate the simulated behavior.
    """
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
    with pytest.raises(RepairReconciliationError, match="primary device"):
        reconciliation.prepare()

    simultaneous = _device("target", "new_id")
    reconciliation, _, _ = _subject(monkeypatch, [], [_device("source", "old_id"), simultaneous])
    with pytest.raises(RepairReconciliationError, match="primary device"):
        reconciliation.prepare()


def test_prepare_keeps_all_identifiers_except_old_domain_on_main_device(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preserve unrelated identifiers when the target already has both old and new IDs.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest fixture used to isolate the simulated behavior.
    """
    main_device = _device(
        "main",
        "old_id",
        config_entries={"entry-1"},
    )
    main_device.identifiers.add((DOMAIN, "new_id"))
    main_device.identifiers.add((DOMAIN, "other-domain-id"))
    main_device.identifiers.add(("other", "unrelated"))
    reconciliation, _, devices = _subject(monkeypatch, [], [main_device])

    reconciliation.prepare()

    assert main_device.identifiers == {
        (DOMAIN, "new_id"),
        (DOMAIN, "other-domain-id"),
        ("other", "unrelated"),
    }
    assert devices.updates == [
        (
            "main",
            {
                "new_identifiers": {
                    (DOMAIN, "new_id"),
                    (DOMAIN, "other-domain-id"),
                    ("other", "unrelated"),
                }
            },
        )
    ]


def test_finalize_removes_only_stale_snapshot_and_preserves_device_associations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finalization removes stale pre-repair rows but never new rows or used devices.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest fixture used to isolate the simulated behavior.
    """
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


def test_finalize_preserves_desired_disabled_tracker_device_by_mac(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A desired disabled tracker keeps its MAC device without an entity device ID.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest fixture used to isolate the simulated behavior.
    """
    tracker = _entry(
        "old_id_mac_aa_bb_cc_dd_ee_ff",
        entity_id="device_tracker.disabled_tracker",
        device_id=None,
    )
    main = _device("main", "old_id")
    tracked_device = _device(
        "tracked-device",
        "tracked-client",
        via_device_id=main.id,
        connections={("mac", "aa:bb:cc:dd:ee:ff")},
    )
    reconciliation, _, devices = _subject(
        monkeypatch,
        [tracker],
        [main, tracked_device],
    )
    reconciliation.prepare()
    desired_tracker = _DesiredTrackerEntity(
        "new_id_mac_aa_bb_cc_dd_ee_ff",
        "aa:bb:cc:dd:ee:ff",
    )
    reconciliation.record_desired_entities("device_tracker", [desired_tracker])

    reconciliation.finalize()

    assert all(
        not (device_id == tracked_device.id and changes.get("remove_config_entry_id") == "entry-1")
        for device_id, changes in devices.updates
    )


def test_prepare_and_finalize_are_idempotent_after_partial_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retry safely handles already-migrated and still-old candidates.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest fixture used to isolate the simulated behavior.
    """
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


@pytest.mark.parametrize(
    "failure_factory",
    [
        (lambda: HomeAssistantError("migrating entity"), HomeAssistantError),
        (lambda: KeyError("migrating entity"), KeyError),
        (lambda: ValueError("migrating entity"), ValueError),
        (
            lambda: dr.DeviceIdentifierCollisionError(
                {("domain", "identifier")}, MagicMock(spec=dr.DeviceEntry)
            ),
            dr.DeviceIdentifierCollisionError,
        ),
    ],
)
def test_prepare_wraps_registry_identifier_migration_failure(
    monkeypatch: pytest.MonkeyPatch,
    failure_factory: tuple[Callable[[], Exception], type[Exception]],
) -> None:
    """Update errors during identifier migration are wrapped as repair errors.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest fixture used to isolate the simulated behavior.
        failure_factory (tuple[Callable[[], Exception], type[Exception]]): Factory and expected
            exception type for the parameterized registry failure.
    """
    candidate = _entry("old_id_sensor", entity_id="sensor.old")
    reconciliation, entity_registry, _ = _subject(monkeypatch, [candidate], [])
    failure, expected = failure_factory
    monkeypatch.setattr(
        entity_registry,
        "async_update_entity",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(failure()),
    )

    with pytest.raises(
        RepairReconciliationError, match="registry identifier migration failed"
    ) as err:
        reconciliation.prepare()
    assert isinstance(err.value.__cause__, expected)


def test_finalize_wraps_detach_failure_as_registry_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finalization surfaces detach failures as a repair reconciliation error.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest fixture used to isolate the simulated behavior.
    """
    stale = _entry("old_id_stale", entity_id="sensor.stale")
    reconciliation, _, device_registry = _subject(
        monkeypatch,
        [stale],
        [
            _device("main", "new_id"),
            _device("obsolete", "old", config_entries={"entry-1"}),
        ],
    )
    reconciliation.prepare()
    monkeypatch.setattr(
        rr,
        "detach_shared_router_parent",
        lambda *args, **kwargs: (_ for _ in ()).throw(KeyError("detach shared tracker")),
    )

    with pytest.raises(RepairReconciliationError, match="registry finalization failed") as err:
        reconciliation.finalize()
    assert isinstance(err.value.__cause__, KeyError)
    assert device_registry.updates == []


def test_mark_complete_deactivates() -> None:
    """Finishing reconciliation disables active state."""
    reconciliation = RepairReconciliation(
        MagicMock(),
        _other_config_entry("entry-1", "old"),
        RepairMarker(1, "old", "new"),
    )
    assert reconciliation.active is True

    reconciliation.mark_complete()

    assert reconciliation.active is False


def test_finalize_reassigns_shared_tracker_parent_to_remaining_router(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Shared tracker devices are reparented when another router still owns shared trackers.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest fixture used to isolate the simulated behavior.
    """
    stale = _entry("old_id_stale", entity_id="sensor.stale", device_id="shared-device")
    surviving_entry = _other_config_entry("entry-2", "survivor_router")
    current_router = _device("current_router", "new_id")
    surviving_router = _device("survivor_router_id", "survivor_router", config_entries={"entry-2"})
    shared_tracker = _device(
        "shared-device",
        "shared-tracker",
        config_entries={"entry-1", "entry-2"},
    )
    shared_tracker.via_device_id = current_router.id

    reconciliation, _, devices = _subject(
        monkeypatch,
        [stale],
        [current_router, surviving_router, shared_tracker],
        extra_config_entries={"entry-2": surviving_entry},
    )
    reconciliation.prepare()

    reconciliation.finalize()

    assert (
        "shared-device",
        {"remove_config_entry_id": "entry-1", "via_device_id": "survivor_router_id"},
    ) in devices.updates


def test_finalize_clears_parent_from_shared_tracker_when_no_replacement_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Shared tracker parent reference is cleared when no surviving router can be resolved.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest fixture used to isolate the simulated behavior.
    """
    stale = _entry("old_id_stale", entity_id="sensor.stale", device_id="shared-device")
    current_router = _device("current_router", "new_id")
    shared_tracker = _device("shared-device", "shared-tracker", config_entries={"entry-1"})
    shared_tracker.via_device_id = current_router.id

    reconciliation, _, devices = _subject(monkeypatch, [stale], [current_router, shared_tracker])
    reconciliation.prepare()

    reconciliation.finalize()

    assert (
        "shared-device",
        {"remove_config_entry_id": "entry-1", "via_device_id": None},
    ) in devices.updates


def test_records_all_final_platform_lists_including_disabled_entities() -> None:
    """Every forwarded platform contributes its complete final identity list."""
    reconciliation = RepairReconciliation(MagicMock(), MagicMock(), RepairMarker(1, "old", "new"))
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
    reconciliation = RepairReconciliation(MagicMock(), MagicMock(), RepairMarker(1, "old", "new"))
    reconciliation.record_desired_entities("sensor", [])

    with pytest.raises(RepairReconciliationError, match="binary_sensor"):
        reconciliation.require_platforms_complete(("sensor", "binary_sensor"))


def test_none_authenticates_as_incomplete_platform_discovery() -> None:
    """Missing or malformed payloads keep a platform from being marked complete."""
    reconciliation = RepairReconciliation(MagicMock(), MagicMock(), RepairMarker(1, "old", "new"))
    reconciliation.record_desired_entities("sensor", None)

    with pytest.raises(RepairReconciliationError, match="sensor"):
        reconciliation.require_platforms_complete(("sensor",))


def test_record_desired_entities_and_is_reconciliation_active_handle_none_marker() -> None:
    """None marker should be treated as inactive without raising."""
    entry = _config_entry_with_runtime_data(SimpleNamespace(repair_reconciliation=None))
    entity = Entity()
    entity._attr_unique_id = "new_sensor"

    record_desired_entities(entry, "sensor", [entity])
    assert is_reconciliation_active(entry) is False


def test_record_desired_entities_requires_runtime_marker_attribute() -> None:
    """Missing repair_reconciliation on runtime_data should now raise."""
    entry = _config_entry_with_runtime_data(SimpleNamespace())
    entity = Entity()
    entity._attr_unique_id = "new_sensor"

    with pytest.raises(AttributeError):
        record_desired_entities(entry, "sensor", [entity])


def test_record_desired_entities_uses_active_reconciliation_state() -> None:
    """Active reconciliation keeps desired identities and returns active state."""
    entry = _config_entry_with_runtime_data(SimpleNamespace())
    entry.runtime_data.repair_reconciliation = RepairReconciliation(
        MagicMock(), entry, RepairMarker(1, "old", "new")
    )
    entity = Entity()
    entity._attr_unique_id = "new_sensor"

    record_desired_entities(entry, "sensor", [entity])
    assert is_reconciliation_active(entry) is True
    assert "new_sensor" in {
        identity[2] for identity in entry.runtime_data.repair_reconciliation.desired_identities
    }
