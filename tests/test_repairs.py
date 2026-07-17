"""Tests for the OPNsense Device ID replacement repair flow."""

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, call

from aiopnsense.exceptions import (
    OPNsenseBelowMinFirmware,
    OPNsenseConnectionError,
    OPNsenseError,
    OPNsenseTimeoutError,
    OPNsenseUnknownFirmware,
)
from homeassistant.components.repairs import ConfirmRepairFlow
from homeassistant.config_entries import ConfigEntryState
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.exceptions import HomeAssistantError
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.opnsense import repair_reconciliation, repairs
from custom_components.opnsense.const import CONF_DEVICE_UNIQUE_ID, DOMAIN, TRACKED_MACS
from custom_components.opnsense.repair_reconciliation import REPAIR_MARKER_KEY, build_repair_marker


def _make_entry(
    *,
    entry_id: str = "entry-1",
    device_id: str = "dev1",
    unique_id: str | None = "dev1",
    state: ConfigEntryState = ConfigEntryState.NOT_LOADED,
    options: dict[str, Any] | None = None,
) -> MockConfigEntry:
    """Build a config entry with connection data used by the repair tests."""
    data: dict[str, Any] = {
        "url": "https://router.example",
        "username": "api-user",
        "password": "api-password",
        CONF_DEVICE_UNIQUE_ID: device_id,
    }
    entry = MockConfigEntry(domain=DOMAIN, data=data, title="OPNsense Test")
    object.__setattr__(entry, "entry_id", entry_id)
    object.__setattr__(entry, "unique_id", unique_id)
    object.__setattr__(entry, "state", state)
    object.__setattr__(entry, "options", options or {"scan_interval": 30})
    return entry


def _make_flow(
    hass: Any,
    entry: MockConfigEntry,
    *,
    old_device_id: str | None = None,
    new_device_id: str = "other",
) -> repairs.DeviceIDMismatchRepairFlow:
    """Create a configured repair flow for direct step testing."""
    if old_device_id is None:
        old_device_id = entry.data[CONF_DEVICE_UNIQUE_ID]
    flow = repairs.DeviceIDMismatchRepairFlow(
        entry_id=entry.entry_id,
        old_device_id=old_device_id,
        new_device_id=new_device_id,
    )
    flow.hass = hass
    flow.handler = DOMAIN
    flow.issue_id = f"{entry.entry_id}_device_id_mismatched"
    flow.flow_id = "flow-1"
    return flow


def _configure_hass(hass: Any, entry: MockConfigEntry) -> None:
    """Configure the config-entry manager methods shared by flow tests."""
    hass.config_entries = MagicMock()
    hass.config_entries.async_get_entry.return_value = entry
    hass.config_entries.async_entries.return_value = [entry]
    hass.config_entries.async_unload = AsyncMock(return_value=True)
    hass.config_entries.async_update_entry = MagicMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock(return_value=True)
    hass.config_entries.async_schedule_reload = MagicMock()


def _patch_registries(
    monkeypatch: pytest.MonkeyPatch,
    entities: list[Any] | None = None,
    devices: list[Any] | None = None,
) -> tuple[MagicMock, MagicMock]:
    """Return registry spies proving the confirmation flow does not mutate registries."""
    entries = list(entities or [])
    devices = list(devices or [])
    entity_registry = MagicMock()
    device_registry = MagicMock()

    def _get_entry(entity_id: str) -> Any:
        """Return a matching entity from the provided entity fixture list."""
        for entry in entries:
            if getattr(entry, "entity_id", None) == entity_id:
                return entry
        return None

    def _get_entity_id(domain: str, platform: str, unique_id: str) -> str | None:
        """Return the stored entity_id matching domain, platform, and unique_id."""
        for entity in entries:
            if (
                getattr(entity, "domain", None) == domain
                and getattr(entity, "platform", None) == platform
                and getattr(entity, "unique_id", None) == unique_id
            ):
                return getattr(entity, "entity_id", None)
        return None

    def _get_device(identifiers: set[tuple[str, str]] | frozenset[tuple[str, str]]) -> Any:
        """Return a matching device fixture whose identifiers cover the query."""
        for device in devices:
            if getattr(device, "identifiers", frozenset()).issuperset(identifiers):
                return device
        return None

    def _entities_for_config_entry(_registry: Any, _config_entry_id: Any) -> list[Any]:
        """Return configured entities for a config-entry-based lookup."""
        return entries

    def _devices_for_config_entry(_registry: Any, _config_entry_id: Any) -> list[Any]:
        """Return configured devices for a config-entry-based lookup."""
        return devices

    entity_registry.async_get = MagicMock(side_effect=_get_entry)
    entity_registry.async_get_entity_id = MagicMock(side_effect=_get_entity_id)
    entity_registry.async_update_entity = MagicMock()
    entity_registry.async_remove = MagicMock()
    device_registry.async_get_device = MagicMock(side_effect=_get_device)
    device_registry.async_update_device = MagicMock()

    # Install the registries behind module-level helper accessors used during
    # repair reconciliation to ensure production call sites consume these
    # in-memory registries directly.
    monkeypatch.setattr(repair_reconciliation.er, "async_get", lambda _hass: entity_registry)
    monkeypatch.setattr(
        repair_reconciliation.er, "async_entries_for_config_entry", _entities_for_config_entry
    )
    monkeypatch.setattr(repair_reconciliation.dr, "async_get", lambda _hass: device_registry)
    monkeypatch.setattr(
        repair_reconciliation.dr, "async_entries_for_config_entry", _devices_for_config_entry
    )

    return entity_registry, device_registry


def _patch_issue_registry(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Patch issue lookups used to render confirmation placeholders."""
    issue_registry = MagicMock()
    issue_registry.async_get_issue.return_value = SimpleNamespace(
        translation_placeholders={
            "entry_title": "OPNsense Test",
            "old_device_id": "dev1",
            "new_device_id": "other",
        }
    )
    monkeypatch.setattr(repairs.ir, "async_get", lambda hass: issue_registry)
    return issue_registry


def _patch_probe_client(
    monkeypatch: pytest.MonkeyPatch,
    *,
    observed_device_id: Any = "other",
    probe_error: BaseException | None = None,
    events: list[str] | None = None,
) -> MagicMock:
    """Patch strict client construction and return the client mock."""
    client = MagicMock()

    async def _probe() -> Any:
        """Return the configured replacement identifier."""
        if events is not None:
            events.append("probe")
        return observed_device_id

    async def _validate() -> None:
        """Record strict client validation."""
        if events is not None:
            events.append("validate")

    async def _close() -> None:
        """Record strict probe client closure."""
        if events is not None:
            events.append("close")

    client.get_device_unique_id = AsyncMock(
        side_effect=probe_error if probe_error is not None else _probe
    )
    client.validate = AsyncMock(side_effect=_validate)
    client.async_close = AsyncMock(side_effect=_close)
    factory = MagicMock(return_value=client)
    client.factory = factory
    monkeypatch.setattr(repairs, "create_opnsense_client_from_config_entry", factory)
    return client


@pytest.mark.asyncio
async def test_initial_flow_renders_replacement_ids_and_confirmation_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Initial step should show old/new IDs and a destructive-rebuild confirmation."""
    hass = MagicMock()
    entry = _make_entry()
    _patch_issue_registry(monkeypatch)
    flow = _make_flow(hass, entry)

    result = await flow.async_step_init()

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "confirm"
    assert result["description_placeholders"] == {
        "entry_title": entry.title,
        "old_device_id": "dev1",
        "new_device_id": "other",
    }
    data_schema = result["data_schema"]
    assert data_schema is not None
    assert data_schema({}) == {}


@pytest.mark.asyncio
async def test_confirmation_reprobes_with_strict_client_and_closes_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Confirmation should re-probe the current ID with throw_errors enabled."""
    hass = MagicMock()
    entry = _make_entry()
    _configure_hass(hass, entry)
    _patch_registries(monkeypatch)
    client = _patch_probe_client(monkeypatch)
    monkeypatch.setattr(repairs.ir, "async_delete_issue", MagicMock())
    flow = _make_flow(hass, entry)

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert client.factory.call_count == 2
    client.factory.assert_has_calls(
        [
            call(hass=hass, config_entry=entry, throw_errors=True),
            call(hass=hass, config_entry=entry, throw_errors=True),
        ],
        any_order=False,
    )
    assert client.validate.await_count == 2
    assert client.get_device_unique_id.await_count == 2
    assert client.async_close.await_count == 2


@pytest.mark.asyncio
async def test_stale_observed_device_id_aborts_without_mutations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stale issue with matching observed ID should abort without destructive work."""
    hass = MagicMock()
    entry = _make_entry(state=ConfigEntryState.LOADED)
    _configure_hass(hass, entry)
    entity_registry, device_registry = _patch_registries(
        monkeypatch,
        entities=[SimpleNamespace(entity_id="sensor.old")],
        devices=[SimpleNamespace(id="device")],
    )
    client = _patch_probe_client(monkeypatch, observed_device_id="dev1")
    flow = _make_flow(hass, entry)

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "entry_changed"
    client.async_close.assert_awaited_once_with()
    hass.config_entries.async_unload.assert_not_awaited()
    entity_registry.async_remove.assert_not_called()
    device_registry.async_update_device.assert_not_called()
    hass.config_entries.async_update_entry.assert_not_called()
    hass.config_entries.async_schedule_reload.assert_not_called()


@pytest.mark.asyncio
async def test_observed_device_id_mismatch_with_issue_expected_id_aborts_before_unload_or_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Observed IDs that do not match issue expectation must abort without mutation."""
    hass = MagicMock()
    entry = _make_entry(state=ConfigEntryState.LOADED)
    _configure_hass(hass, entry)
    entity_registry, device_registry = _patch_registries(
        monkeypatch,
        entities=[SimpleNamespace(entity_id="sensor.old")],
        devices=[SimpleNamespace(id="device")],
    )
    _patch_probe_client(monkeypatch, observed_device_id="third")
    flow = _make_flow(hass, entry)

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "entry_changed"
    hass.config_entries.async_unload.assert_not_awaited()
    entity_registry.async_remove.assert_not_called()
    device_registry.async_update_device.assert_not_called()
    hass.config_entries.async_update_entry.assert_not_called()
    hass.config_entries.async_schedule_reload.assert_not_called()


@pytest.mark.asyncio
async def test_old_device_id_mismatch_aborts_without_mutations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stale issue with mismatched old_device_id should abort without mutation."""
    hass = MagicMock()
    entry = _make_entry(state=ConfigEntryState.LOADED)
    _configure_hass(hass, entry)
    entity_registry, device_registry = _patch_registries(
        monkeypatch,
        entities=[SimpleNamespace(entity_id="sensor.old")],
        devices=[SimpleNamespace(id="device")],
    )
    client = _patch_probe_client(monkeypatch)
    flow = _make_flow(
        hass,
        entry,
        old_device_id="stale-old-device-id",
        new_device_id="other",
    )

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "entry_changed"
    client.factory.assert_not_called()
    hass.config_entries.async_unload.assert_not_awaited()
    client.validate.assert_not_awaited()
    client.get_device_unique_id.assert_not_awaited()
    entity_registry.async_remove.assert_not_called()
    device_registry.async_update_device.assert_not_called()
    hass.config_entries.async_update_entry.assert_not_called()
    hass.config_entries.async_schedule_reload.assert_not_called()


@pytest.mark.asyncio
async def test_duplicate_entry_aborts_before_unload_or_registry_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Duplicates created during unload must abort before config or registry mutation."""
    hass = MagicMock()
    entry = _make_entry(state=ConfigEntryState.LOADED)
    duplicate = _make_entry(entry_id="entry-2", device_id="other", unique_id="other")
    _configure_hass(hass, entry)
    entries = [entry]
    hass.config_entries.async_entries.side_effect = lambda domain: entries

    def _unload(entry_id: str) -> bool:
        """Create a competing entry after the initial duplicate check."""
        del entry_id
        entries.append(duplicate)
        return True

    hass.config_entries.async_unload.side_effect = _unload
    entity_registry, device_registry = _patch_registries(
        monkeypatch,
        entities=[SimpleNamespace(entity_id="sensor.old")],
        devices=[SimpleNamespace(id="device")],
    )
    _patch_probe_client(monkeypatch)
    issue_delete = MagicMock()
    monkeypatch.setattr(repairs.ir, "async_delete_issue", issue_delete)
    flow = _make_flow(hass, entry)

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"
    hass.config_entries.async_unload.assert_awaited_once_with(entry.entry_id)
    entity_registry.async_remove.assert_not_called()
    device_registry.async_update_device.assert_not_called()
    hass.config_entries.async_update_entry.assert_not_called()
    hass.config_entries.async_schedule_reload.assert_called_once_with(entry.entry_id)
    issue_delete.assert_not_called()
    assert entry.data[CONF_DEVICE_UNIQUE_ID] == "dev1"
    assert entry.unique_id == "dev1"


@pytest.mark.asyncio
async def test_loaded_entry_duplicate_after_unload_schedules_changed_entry_reload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A duplicate that appears after unload should schedule a guarded reload."""
    hass = MagicMock()
    entry = _make_entry(state=ConfigEntryState.LOADED)
    duplicate = _make_entry(entry_id="entry-2", device_id="other", unique_id="other")
    _configure_hass(hass, entry)
    entries_calls: list[str] = []

    def _entries(domain: str) -> list[Any]:
        """Return a duplicate config entry only after unload and snapshot checks."""
        del domain
        entries_calls.append("entries")
        if len(entries_calls) == 1:
            return [entry]
        return [entry, duplicate]

    hass.config_entries.async_entries.side_effect = _entries
    entity_registry, device_registry = _patch_registries(
        monkeypatch,
        entities=[SimpleNamespace(entity_id="sensor.old")],
        devices=[SimpleNamespace(id="device")],
    )
    _patch_probe_client(monkeypatch, observed_device_id="other")
    flow = _make_flow(hass, entry)

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"
    hass.config_entries.async_schedule_reload.assert_called_once_with(entry.entry_id)
    hass.config_entries.async_unload.assert_awaited_once_with(entry.entry_id)
    entity_registry.async_remove.assert_not_called()
    device_registry.async_update_device.assert_not_called()
    hass.config_entries.async_update_entry.assert_not_called()


@pytest.mark.asyncio
async def test_observed_duplicate_id_aborts_before_unload_or_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An existing entry with the observed ID should abort before unload."""
    hass = MagicMock()
    entry = _make_entry()
    duplicate = _make_entry(entry_id="entry-2", device_id="other", unique_id="other")
    _configure_hass(hass, entry)
    hass.config_entries.async_entries.return_value = [entry, duplicate]
    entity_registry, device_registry = _patch_registries(
        monkeypatch,
        entities=[SimpleNamespace(entity_id="sensor.old")],
        devices=[SimpleNamespace(id="device")],
    )
    _patch_probe_client(monkeypatch, observed_device_id="other")
    flow = _make_flow(hass, entry)

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"
    entity_registry.async_remove.assert_not_called()
    device_registry.async_update_device.assert_not_called()
    hass.config_entries.async_unload.assert_not_awaited()
    hass.config_entries.async_update_entry.assert_not_called()
    hass.config_entries.async_schedule_reload.assert_not_called()


@pytest.mark.asyncio
async def test_loaded_entry_unloads_before_marker_update_and_reload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A loaded entry unloads before marker persistence and reload."""
    hass = MagicMock()
    entry = _make_entry(state=ConfigEntryState.LOADED)
    events: list[str] = []
    _configure_hass(hass, entry)

    def _unload(entry_id: str) -> bool:
        """Record unload before returning success."""
        events.append("unload")
        return True

    class _OtherEntry:
        """Duplicate-scan candidate whose ID access is observable."""

        entry_id = "entry-2"

        @property
        def unique_id(self) -> str:
            """Record the duplicate candidate comparison."""
            events.append("duplicate_check")
            return "different"

    def _entries(domain: str) -> list[Any]:
        """Record the duplicate scan and return only non-conflicting entries."""
        events.append("duplicate_scan")
        return [entry, _OtherEntry()]

    hass.config_entries.async_entries.side_effect = _entries
    hass.config_entries.async_unload.side_effect = _unload
    entity = SimpleNamespace(entity_id="sensor.old", disabled_by=None)
    device = SimpleNamespace(id="device")
    entity_registry, device_registry = _patch_registries(
        monkeypatch, entities=[entity], devices=[device]
    )
    entity_registry.async_remove.side_effect = lambda entity_id: events.append("entity")
    device_registry.async_update_device.side_effect = lambda device_id, **kwargs: events.append(
        "device"
    )

    def _update_entry(*args: Any, **kwargs: Any) -> bool:
        """Record the config update and report that it changed the entry."""
        del args, kwargs
        events.append("config_update")
        return True

    hass.config_entries.async_update_entry.side_effect = _update_entry

    async def _reload(entry_id: str) -> bool:
        """Record reload scheduling and signal success."""
        del entry_id
        events.append("reload")
        return True

    hass.config_entries.async_reload.side_effect = _reload
    _patch_probe_client(monkeypatch, events=events)
    monkeypatch.setattr(repairs.ir, "async_delete_issue", lambda *args: events.append("delete"))
    flow = _make_flow(hass, entry)

    def _create_entry(**_: Any) -> dict[str, str]:
        """Record creation after the reload was scheduled."""
        events.append("create")
        return {"type": "create_entry"}

    object.__setattr__(
        flow,
        "async_create_entry",
        _create_entry,
    )

    await flow.async_step_confirm({})

    assert events == [
        "validate",
        "probe",
        "close",
        "duplicate_scan",
        "duplicate_check",
        "unload",
        "validate",
        "probe",
        "close",
        "duplicate_scan",
        "duplicate_check",
        "config_update",
        "reload",
        "create",
    ]
    entity_registry.async_remove.assert_not_called()
    device_registry.async_update_device.assert_not_called()


@pytest.mark.asyncio
async def test_loaded_entry_reprobe_after_unload_rejects_router_swap_without_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A router change after unload must be re-probed and must not persist stale IDs."""
    hass = MagicMock()
    entry = _make_entry(state=ConfigEntryState.LOADED)
    _configure_hass(hass, entry)
    entity_registry, device_registry = _patch_registries(
        monkeypatch,
        entities=[SimpleNamespace(entity_id="sensor.old")],
        devices=[SimpleNamespace(id="device")],
    )
    client = _patch_probe_client(monkeypatch)
    probe_calls: list[int] = []

    async def _probe_then_swap() -> str:
        """Return a stale ID before unload and a swapped ID after unload."""
        probe_calls.append(1)
        if len(probe_calls) == 1:
            return "other"
        return "swapped"

    client.get_device_unique_id.side_effect = _probe_then_swap
    flow = _make_flow(hass, entry)

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "entry_changed"
    assert client.get_device_unique_id.await_count == 2
    assert client.async_close.await_count == 2
    assert len(probe_calls) == 2
    entity_registry.async_remove.assert_not_called()
    device_registry.async_update_device.assert_not_called()
    hass.config_entries.async_update_entry.assert_not_called()
    hass.config_entries.async_unload.assert_awaited_once_with(entry.entry_id)
    hass.config_entries.async_schedule_reload.assert_called_once_with(entry.entry_id)
    hass.config_entries.async_reload.assert_not_awaited()


@pytest.mark.asyncio
async def test_loaded_entry_reprobe_after_unload_rejects_probe_failure_without_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A strict re-probe failure after unload must abort and recover without mutation."""
    hass = MagicMock()
    entry = _make_entry(state=ConfigEntryState.LOADED)
    _configure_hass(hass, entry)
    entity_registry, device_registry = _patch_registries(
        monkeypatch,
        entities=[SimpleNamespace(entity_id="sensor.old")],
        devices=[SimpleNamespace(id="device")],
    )
    client = _patch_probe_client(monkeypatch)
    probe_calls: list[int] = []

    async def _probe_then_fail() -> str:
        """Return a stale ID before unload and fail on the re-probe."""
        probe_calls.append(1)
        if len(probe_calls) == 1:
            return "other"
        raise OPNsenseConnectionError("offline")

    client.get_device_unique_id.side_effect = _probe_then_fail
    flow = _make_flow(hass, entry)

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "cannot_connect"
    assert client.get_device_unique_id.await_count == 2
    assert client.async_close.await_count == 2
    assert len(probe_calls) == 2
    entity_registry.async_remove.assert_not_called()
    device_registry.async_update_device.assert_not_called()
    hass.config_entries.async_update_entry.assert_not_called()
    hass.config_entries.async_unload.assert_awaited_once_with(entry.entry_id)
    hass.config_entries.async_schedule_reload.assert_called_once_with(entry.entry_id)
    hass.config_entries.async_reload.assert_not_awaited()


@pytest.mark.asyncio
async def test_entry_swap_reprobe_snapshot_stability_checks_after_unload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An entry that mutates while reprobing must abort before persistence."""
    hass = MagicMock()
    entry = _make_entry(state=ConfigEntryState.LOADED)
    _configure_hass(hass, entry)
    _patch_registries(
        monkeypatch,
        entities=[SimpleNamespace(entity_id="sensor.old")],
        devices=[SimpleNamespace(id="device")],
    )
    client = _patch_probe_client(monkeypatch)
    probe_calls: list[int] = []

    async def _probe_then_mutate_entry() -> str:
        """Mutate entry persistence during the second probe cycle."""
        probe_calls.append(1)
        if len(probe_calls) == 2:
            object.__setattr__(
                entry,
                "data",
                {**entry.data, "url": "https://changed.example"},
            )
        return "other"

    client.get_device_unique_id.side_effect = _probe_then_mutate_entry
    flow = _make_flow(hass, entry)

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "entry_changed"
    assert client.get_device_unique_id.await_count == 2
    assert client.async_close.await_count == 2
    assert len(probe_calls) == 2
    hass.config_entries.async_update_entry.assert_not_called()
    hass.config_entries.async_unload.assert_awaited_once_with(entry.entry_id)
    hass.config_entries.async_schedule_reload.assert_called_once_with(entry.entry_id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("probe_error", "observed_device_id"),
    [
        pytest.param(OPNsenseConnectionError("transport"), None, id="connection-error"),
        pytest.param(OPNsenseTimeoutError("timeout"), None, id="timeout-error"),
        pytest.param(None, None, id="missing-device-id"),
        pytest.param(None, "", id="blank-device-id"),
        pytest.param(None, "   ", id="whitespace-device-id"),
        pytest.param(None, 123, id="non-string-device-id"),
    ],
)
async def test_invalid_probe_result_aborts_without_mutations(
    monkeypatch: pytest.MonkeyPatch,
    probe_error: BaseException | None,
    observed_device_id: Any,
) -> None:
    """Invalid strict-probe results should abort and close the client."""
    hass = MagicMock()
    entry = _make_entry()
    _configure_hass(hass, entry)
    entity_registry, device_registry = _patch_registries(
        monkeypatch,
        entities=[SimpleNamespace(entity_id="sensor.old")],
        devices=[SimpleNamespace(id="device")],
    )
    client = _patch_probe_client(
        monkeypatch,
        observed_device_id=observed_device_id,
        probe_error=probe_error,
    )
    flow = _make_flow(hass, entry)

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "cannot_connect"
    client.async_close.assert_awaited_once_with()
    entity_registry.async_remove.assert_not_called()
    device_registry.async_update_device.assert_not_called()
    hass.config_entries.async_unload.assert_not_awaited()
    hass.config_entries.async_update_entry.assert_not_called()
    hass.config_entries.async_schedule_reload.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "validation_error",
    [
        pytest.param(OPNsenseBelowMinFirmware("unsupported"), id="below-minimum"),
        pytest.param(OPNsenseUnknownFirmware("unknown"), id="unknown-firmware"),
    ],
)
async def test_firmware_validation_failure_aborts_before_mutations(
    monkeypatch: pytest.MonkeyPatch,
    validation_error: BaseException,
) -> None:
    """Firmware validation failures must stop the repair before any mutation."""
    hass = MagicMock()
    entry = _make_entry(state=ConfigEntryState.LOADED)
    _configure_hass(hass, entry)
    entity_registry, device_registry = _patch_registries(
        monkeypatch,
        entities=[SimpleNamespace(entity_id="sensor.old")],
        devices=[SimpleNamespace(id="device")],
    )
    client = _patch_probe_client(monkeypatch)
    client.validate.side_effect = validation_error
    flow = _make_flow(hass, entry)

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "cannot_connect"
    client.validate.assert_awaited_once_with()
    client.get_device_unique_id.assert_not_awaited()
    client.async_close.assert_awaited_once_with()
    hass.config_entries.async_unload.assert_not_awaited()
    entity_registry.async_remove.assert_not_called()
    device_registry.async_update_device.assert_not_called()
    hass.config_entries.async_update_entry.assert_not_called()
    hass.config_entries.async_schedule_reload.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "unload_result",
    [
        pytest.param(False, id="unload-false"),
        pytest.param(HomeAssistantError("transport"), id="homeassistant-error"),
        pytest.param(KeyError("entry key"), id="key-error"),
    ],
)
async def test_unload_failure_aborts_before_registry_mutation(
    monkeypatch: pytest.MonkeyPatch,
    unload_result: bool | BaseException,
) -> None:
    """Unloading failures must abort before mutating registries or reload state."""
    hass = MagicMock()
    entry = _make_entry(state=ConfigEntryState.LOADED)
    _configure_hass(hass, entry)
    if isinstance(unload_result, BaseException):
        hass.config_entries.async_unload.side_effect = unload_result
    else:
        hass.config_entries.async_unload.return_value = unload_result
    entity_registry, device_registry = _patch_registries(
        monkeypatch,
        entities=[SimpleNamespace(entity_id="sensor.old")],
        devices=[SimpleNamespace(id="device")],
    )
    client = _patch_probe_client(monkeypatch)
    flow = _make_flow(hass, entry)

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "cannot_unload"
    client.async_close.assert_awaited_once_with()
    hass.config_entries.async_unload.assert_awaited_once_with(entry.entry_id)
    entity_registry.async_remove.assert_not_called()
    device_registry.async_update_device.assert_not_called()
    hass.config_entries.async_update_entry.assert_not_called()
    hass.config_entries.async_schedule_reload.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state",
    [
        ConfigEntryState.FAILED_UNLOAD,
        ConfigEntryState.SETUP_IN_PROGRESS,
        ConfigEntryState.UNLOAD_IN_PROGRESS,
    ],
)
async def test_nonrecoverable_entry_state_aborts_before_unload_or_mutation(
    monkeypatch: pytest.MonkeyPatch,
    state: ConfigEntryState,
) -> None:
    """Non-recoverable entry states must not reach unload or repair mutation."""
    hass = MagicMock()
    entry = _make_entry(state=state)
    _configure_hass(hass, entry)
    entity_registry, device_registry = _patch_registries(
        monkeypatch,
        entities=[SimpleNamespace(entity_id="sensor.old")],
        devices=[SimpleNamespace(id="device")],
    )
    client = _patch_probe_client(monkeypatch)
    flow = _make_flow(hass, entry)

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "cannot_unload"
    client.async_close.assert_awaited_once_with()
    hass.config_entries.async_unload.assert_not_awaited()
    entity_registry.async_remove.assert_not_called()
    device_registry.async_update_device.assert_not_called()
    hass.config_entries.async_update_entry.assert_not_called()
    hass.config_entries.async_schedule_reload.assert_not_called()


@pytest.mark.asyncio
async def test_entry_removed_during_unload_aborts_before_registry_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A removed entry after unload must not allow stale registry mutations."""
    hass = MagicMock()
    entry = _make_entry(state=ConfigEntryState.LOADED)
    _configure_hass(hass, entry)
    hass.config_entries.async_get_entry.side_effect = [entry, entry, None]
    entity_registry, device_registry = _patch_registries(
        monkeypatch,
        entities=[SimpleNamespace(entity_id="sensor.old")],
        devices=[SimpleNamespace(id="device")],
    )
    _patch_probe_client(monkeypatch)
    flow = _make_flow(hass, entry)

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "entry_changed"
    entity_registry.async_remove.assert_not_called()
    device_registry.async_update_device.assert_not_called()
    hass.config_entries.async_update_entry.assert_not_called()
    hass.config_entries.async_unload.assert_awaited_once_with(entry.entry_id)
    hass.config_entries.async_reload.assert_not_awaited()
    hass.config_entries.async_schedule_reload.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation_stage", ["probe", "unload"])
@pytest.mark.parametrize("field", ["url", "username", "password", "options", "unique_id"])
async def test_entry_changed_during_probe_or_unload_aborts_without_mutation(
    monkeypatch: pytest.MonkeyPatch,
    mutation_stage: str,
    field: str,
) -> None:
    """Config-entry changes during awaited work must stop the destructive repair."""
    hass = MagicMock()
    entry = _make_entry(
        state=ConfigEntryState.LOADED if mutation_stage == "unload" else ConfigEntryState.NOT_LOADED
    )
    _configure_hass(hass, entry)
    entity_registry, device_registry = _patch_registries(
        monkeypatch,
        entities=[SimpleNamespace(entity_id="sensor.old")],
        devices=[SimpleNamespace(id="device")],
    )
    client = _patch_probe_client(monkeypatch)

    def _mutate_entry() -> None:
        """Apply one persisted-entry mutation while the repair is awaiting."""
        if field in {"url", "username", "password"}:
            object.__setattr__(entry, "data", {**entry.data, field: f"changed-{field}"})
        elif field == "options":
            entry.options["scan_interval"] = 99
        else:
            object.__setattr__(entry, "unique_id", "changed-unique-id")

    if mutation_stage == "probe":

        async def _probe_and_mutate() -> str:
            """Mutate the entry before the probe completes."""
            _mutate_entry()
            return "other"

        client.get_device_unique_id.side_effect = _probe_and_mutate
    else:

        def _unload_and_mutate(entry_id: str) -> bool:
            """Mutate the entry while unloading it."""
            _mutate_entry()
            return True

        hass.config_entries.async_unload.side_effect = _unload_and_mutate

    flow = _make_flow(hass, entry)

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "entry_changed"
    entity_registry.async_remove.assert_not_called()
    device_registry.async_update_device.assert_not_called()
    hass.config_entries.async_update_entry.assert_not_called()
    if mutation_stage == "probe":
        hass.config_entries.async_schedule_reload.assert_not_called()
        hass.config_entries.async_unload.assert_not_awaited()
    else:
        hass.config_entries.async_schedule_reload.assert_called_once_with(entry.entry_id)
        hass.config_entries.async_unload.assert_awaited_once_with(entry.entry_id)


@pytest.mark.asyncio
async def test_nested_mutable_options_mutation_during_probe_aborts_without_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutating a nested options list in-place during probe must still abort safely."""
    hass = MagicMock()
    nested_devices = ["aa:bb:cc:dd:ee:01"]
    entry = _make_entry(
        state=ConfigEntryState.NOT_LOADED,
        options={"scan_interval": 30, "devices": nested_devices},
    )
    _configure_hass(hass, entry)
    entity_registry, device_registry = _patch_registries(
        monkeypatch,
        entities=[SimpleNamespace(entity_id="sensor.old")],
        devices=[SimpleNamespace(id="device")],
    )
    client = _patch_probe_client(monkeypatch)

    async def _probe_and_mutate() -> str:
        nested_devices.append("aa:bb:cc:dd:ee:02")
        return "other"

    client.get_device_unique_id.side_effect = _probe_and_mutate
    flow = _make_flow(hass, entry)

    result = await flow.async_step_confirm({})

    assert nested_devices == ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "entry_changed"
    entity_registry.async_remove.assert_not_called()
    device_registry.async_update_device.assert_not_called()
    hass.config_entries.async_update_entry.assert_not_called()
    hass.config_entries.async_reload.assert_not_awaited()
    hass.config_entries.async_schedule_reload.assert_not_called()
    client.async_close.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_update_preserves_connection_and_options_while_replacing_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Entry update should replace only the device ID and unique ID."""
    hass = MagicMock()
    entry = _make_entry(options={"scan_interval": 45})
    _configure_hass(hass, entry)
    _patch_registries(monkeypatch)
    _patch_probe_client(monkeypatch)
    monkeypatch.setattr(repairs.ir, "async_delete_issue", MagicMock())
    flow = _make_flow(hass, entry)

    await flow.async_step_confirm({})

    hass.config_entries.async_update_entry.assert_called_once_with(
        entry,
        data={
            **entry.data,
            CONF_DEVICE_UNIQUE_ID: "other",
            REPAIR_MARKER_KEY: build_repair_marker("dev1", "other"),
        },
        unique_id="other",
    )
    assert entry.data["url"] == "https://router.example"
    assert entry.data["username"] == "api-user"
    assert entry.data["password"] == "api-password"
    assert entry.options == {"scan_interval": 45}


@pytest.mark.asyncio
async def test_success_deletes_issue_and_reloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Successful rebuild should async-reload and let the manager delete the issue."""
    hass = MagicMock()
    entry = _make_entry()
    _configure_hass(hass, entry)
    _patch_registries(monkeypatch)
    _patch_probe_client(monkeypatch)
    issue_delete = MagicMock()
    monkeypatch.setattr(repairs.ir, "async_delete_issue", issue_delete)
    flow = _make_flow(hass, entry)

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.CREATE_ENTRY
    issue_delete.assert_not_called()
    hass.config_entries.async_reload.assert_awaited_once_with(entry.entry_id)
    hass.config_entries.async_schedule_reload.assert_not_called()


@pytest.mark.asyncio
async def test_entry_update_failure_aborts_without_registry_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Entry-update failure must abort before any registry mutation."""
    hass = MagicMock()
    entry = _make_entry()
    _configure_hass(hass, entry)
    entity_registry, device_registry = _patch_registries(
        monkeypatch,
        entities=[SimpleNamespace(entity_id="sensor.old")],
        devices=[SimpleNamespace(id="device")],
    )
    client = _patch_probe_client(monkeypatch)
    hass.config_entries.async_update_entry.side_effect = HomeAssistantError("entry update")
    issue_delete = MagicMock()
    monkeypatch.setattr(repairs.ir, "async_delete_issue", issue_delete)
    flow = _make_flow(hass, entry)

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "repair_failed"
    entity_registry.async_remove.assert_not_called()
    device_registry.async_update_device.assert_not_called()
    hass.config_entries.async_update_entry.assert_called_once_with(
        entry,
        data={
            **entry.data,
            CONF_DEVICE_UNIQUE_ID: "other",
            REPAIR_MARKER_KEY: build_repair_marker("dev1", "other"),
        },
        unique_id="other",
    )
    issue_delete.assert_not_called()
    hass.config_entries.async_schedule_reload.assert_not_called()
    assert client.async_close.await_count == 2


@pytest.mark.asyncio
async def test_entry_update_false_aborts_before_registry_mutation_and_recovers_loaded_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A no-op entry update must leave registries untouched and reload a prior loaded entry."""
    hass = MagicMock()
    entry = _make_entry(state=ConfigEntryState.LOADED)
    _configure_hass(hass, entry)
    entity_registry, device_registry = _patch_registries(
        monkeypatch,
        entities=[SimpleNamespace(entity_id="sensor.old")],
        devices=[SimpleNamespace(id="device")],
    )
    _patch_probe_client(monkeypatch)
    hass.config_entries.async_update_entry.return_value = False
    flow = _make_flow(hass, entry)

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "repair_failed"
    entity_registry.async_remove.assert_not_called()
    device_registry.async_update_device.assert_not_called()
    hass.config_entries.async_update_entry.assert_called_once_with(
        entry,
        data={
            **entry.data,
            CONF_DEVICE_UNIQUE_ID: "other",
            REPAIR_MARKER_KEY: build_repair_marker("dev1", "other"),
        },
        unique_id="other",
    )
    hass.config_entries.async_schedule_reload.assert_called_once_with(entry.entry_id)


@pytest.mark.asyncio
async def test_loaded_entry_update_exception_recovers_without_registry_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An update exception after unload should schedule guarded recovery."""
    hass = MagicMock()
    entry = _make_entry(state=ConfigEntryState.LOADED)
    _configure_hass(hass, entry)
    entity_registry, device_registry = _patch_registries(
        monkeypatch,
        entities=[SimpleNamespace(entity_id="sensor.old")],
        devices=[SimpleNamespace(id="device")],
    )
    _patch_probe_client(monkeypatch)
    hass.config_entries.async_update_entry.side_effect = HomeAssistantError("entry update")
    flow = _make_flow(hass, entry)

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "repair_failed"
    entity_registry.async_remove.assert_not_called()
    device_registry.async_update_device.assert_not_called()
    hass.config_entries.async_schedule_reload.assert_called_once_with(entry.entry_id)


@pytest.mark.asyncio
async def test_expected_id_retry_rechecks_snapshot_after_unload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retry must not clean registries after its entry changes during unload."""
    hass = MagicMock()
    entry = _make_entry(state=ConfigEntryState.LOADED, device_id="other", unique_id="other")
    object.__setattr__(
        entry,
        "data",
        {**entry.data, REPAIR_MARKER_KEY: build_repair_marker("dev1", "other")},
    )
    _configure_hass(hass, entry)
    entity_registry, device_registry = _patch_registries(
        monkeypatch,
        entities=[SimpleNamespace(entity_id="sensor.old")],
        devices=[SimpleNamespace(id="device")],
    )

    def _unload_and_mutate(entry_id: str) -> bool:
        """Mutate persisted data while the retry is awaiting unload."""
        del entry_id
        object.__setattr__(entry, "data", {**entry.data, "url": "https://changed.example"})
        return True

    hass.config_entries.async_unload.side_effect = _unload_and_mutate
    _patch_probe_client(monkeypatch)
    flow = _make_flow(hass, entry, old_device_id="dev1", new_device_id="other")

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "entry_changed"
    entity_registry.async_remove.assert_not_called()
    device_registry.async_update_device.assert_not_called()
    hass.config_entries.async_update_entry.assert_not_called()
    hass.config_entries.async_reload.assert_not_awaited()
    hass.config_entries.async_schedule_reload.assert_called_once_with(entry.entry_id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reload_result",
    [
        pytest.param(False, id="false-result"),
        pytest.param(HomeAssistantError("entry removed"), id="homeassistant-error"),
        pytest.param(KeyError("entry key"), id="key-error"),
    ],
)
async def test_reload_failure_keeps_entry_update_and_keeps_issue(
    monkeypatch: pytest.MonkeyPatch,
    reload_result: bool | Exception,
) -> None:
    """Reload failures should keep the new ID and schedule a follow-up reload."""
    hass = MagicMock()
    entry = _make_entry()
    _configure_hass(hass, entry)
    entity_registry, device_registry = _patch_registries(
        monkeypatch,
        entities=[SimpleNamespace(entity_id="sensor.old")],
        devices=[SimpleNamespace(id="device")],
    )
    observed_device_id = "other"
    _patch_probe_client(monkeypatch, observed_device_id=observed_device_id)
    issue_delete = MagicMock()
    monkeypatch.setattr(repairs.ir, "async_delete_issue", issue_delete)

    old_data = dict(entry.data)

    def _update_entry(
        config_entry: MockConfigEntry,
        *,
        data: dict[str, Any],
        unique_id: str,
    ) -> bool:
        """Apply the requested entry mutation to the in-memory test object."""
        del config_entry
        object.__setattr__(entry, "data", dict(data))
        object.__setattr__(entry, "unique_id", unique_id)
        return True

    hass.config_entries.async_update_entry.side_effect = _update_entry
    if isinstance(reload_result, bool):
        hass.config_entries.async_reload.return_value = reload_result
    else:
        hass.config_entries.async_reload.side_effect = reload_result
    flow = _make_flow(hass, entry)

    result = await flow.async_step_confirm({})

    expected_updated_data = {
        **old_data,
        CONF_DEVICE_UNIQUE_ID: observed_device_id,
        REPAIR_MARKER_KEY: build_repair_marker("dev1", observed_device_id),
    }
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "repair_failed"
    entity_registry.async_remove.assert_not_called()
    device_registry.async_update_device.assert_not_called()
    assert hass.config_entries.async_update_entry.call_args_list[0].kwargs == {
        "data": expected_updated_data,
        "unique_id": observed_device_id,
    }
    assert entry.data == expected_updated_data
    assert entry.unique_id == observed_device_id
    assert len(hass.config_entries.async_update_entry.call_args_list) == 1
    issue_delete.assert_not_called()
    hass.config_entries.async_reload.assert_awaited_once_with(entry.entry_id)
    hass.config_entries.async_schedule_reload.assert_called_once_with(entry.entry_id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reload_result",
    [False, HomeAssistantError("reload failed"), KeyError("entry key")],
)
async def test_retry_keeps_issue_when_recovery_reload_fails(
    monkeypatch: pytest.MonkeyPatch,
    reload_result: bool | Exception,
) -> None:
    """Keep the repair available when reloading an already-updated entry fails."""
    hass = MagicMock()
    entry = _make_entry(device_id="other", unique_id="other")
    _configure_hass(hass, entry)
    entity_registry, device_registry = _patch_registries(monkeypatch)
    client = _patch_probe_client(monkeypatch)
    if isinstance(reload_result, bool):
        hass.config_entries.async_reload.return_value = reload_result
    else:
        hass.config_entries.async_reload.side_effect = reload_result
    flow = _make_flow(hass, entry, old_device_id="dev1")

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "repair_failed"
    hass.config_entries.async_update_entry.assert_not_called()
    entity_registry.async_remove.assert_not_called()
    device_registry.async_update_device.assert_not_called()
    client.factory.assert_not_called()
    hass.config_entries.async_reload.assert_awaited_once_with(entry.entry_id)
    hass.config_entries.async_schedule_reload.assert_called_once_with(entry.entry_id)


@pytest.mark.asyncio
async def test_removed_entry_aborts_without_mutations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A deleted config entry should abort before creating a strict client."""
    hass = MagicMock()
    entry = _make_entry()
    _configure_hass(hass, entry)
    hass.config_entries.async_get_entry.return_value = None
    client_factory = MagicMock()
    monkeypatch.setattr(repairs, "create_opnsense_client_from_config_entry", client_factory)
    flow = _make_flow(hass, entry)

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "entry_not_found"
    client_factory.assert_not_called()
    hass.config_entries.async_unload.assert_not_awaited()
    hass.config_entries.async_update_entry.assert_not_called()
    hass.config_entries.async_schedule_reload.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("data", "expects_replacement_flow"),
    [
        (
            {
                "entry_id": "entry-1",
                "old_device_id": "dev1",
                "new_device_id": "other",
            },
            True,
        ),
        (
            {
                "entry_id": "entry-1",
                "old_device_id": "dev1",
                "new_device_id": "   ",
            },
            False,
        ),
        (
            {
                "entry_id": "entry-1",
                "old_device_id": "   ",
                "new_device_id": "other",
            },
            False,
        ),
    ],
)
async def test_fix_flow_factory_validates_issue_suffix_and_payload(
    data: dict[str, str | int | float | None],
    expects_replacement_flow: bool,
) -> None:
    """Only well-formed Device ID issues should construct the destructive flow."""
    hass = MagicMock()
    flow = await repairs.async_create_fix_flow(hass, "entry-1_device_id_mismatched", data)
    if expects_replacement_flow:
        assert isinstance(flow, repairs.DeviceIDMismatchRepairFlow)
    else:
        assert isinstance(flow, ConfirmRepairFlow)
    unknown_flow = await repairs.async_create_fix_flow(hass, "unrelated", None)
    assert isinstance(unknown_flow, ConfirmRepairFlow)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("entry_device_id", "observed_device_id", "expect_issue"),
    [
        ("dev1", "other", True),
        ("   ", "other", False),
        ("dev1", "   ", False),
    ],
)
async def test_async_create_device_id_mismatch_issue_ignores_invalid_ids(
    monkeypatch: pytest.MonkeyPatch,
    entry_device_id: str,
    observed_device_id: str,
    expect_issue: bool,
) -> None:
    """Do not create mismatches when configured or observed IDs are malformed."""
    entry = _make_entry(device_id=entry_device_id)
    called: dict[str, int] = {"count": 0}

    def _capture_issue(**kwargs: Any) -> None:
        del kwargs
        called["count"] += 1

    monkeypatch.setattr(repairs.ir, "async_create_issue", _capture_issue)

    issue_created = repairs.async_create_device_id_mismatch_issue(
        MagicMock(), entry, observed_device_id
    )

    if expect_issue:
        assert called["count"] == 1
        assert issue_created is True
    else:
        assert called["count"] == 0
        assert issue_created is False


@pytest.mark.asyncio
async def test_stored_expected_id_unloaded_entry_retries_recovery_reload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unloaded expected-ID retry should still keep recovery reload on failure."""
    hass = MagicMock()
    entry = _make_entry(
        state=ConfigEntryState.NOT_LOADED,
        device_id="dev1",
        unique_id="dev1",
    )
    _configure_hass(hass, entry)
    hass.config_entries.async_reload.return_value = False
    _patch_registries(monkeypatch)
    _patch_probe_client(monkeypatch, observed_device_id="dev1")
    flow = _make_flow(hass, entry, new_device_id="dev1")

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "repair_failed"
    hass.config_entries.async_unload.assert_not_awaited()
    hass.config_entries.async_reload.assert_awaited_once_with(entry.entry_id)
    hass.config_entries.async_schedule_reload.assert_called_once_with(entry.entry_id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "schedule_error",
    [
        pytest.param(HomeAssistantError("reload schedule failed"), id="homeassistant-error"),
        pytest.param(KeyError("entry_id"), id="key-error"),
    ],
)
async def test_schedule_changed_entry_reload_handles_schedule_errors(
    schedule_error: Exception,
) -> None:
    """Recovery scheduling for changed entries should tolerate schedule failures."""
    hass = MagicMock()
    entry = _make_entry()
    hass.config_entries = MagicMock()
    hass.config_entries.async_get_entry.return_value = entry
    hass.config_entries.async_schedule_reload.side_effect = schedule_error
    flow = _make_flow(hass, entry)

    flow._schedule_changed_entry_reload(entry_id=entry.entry_id, entry_title=entry.title)

    hass.config_entries.async_schedule_reload.assert_called_once_with(entry.entry_id)


@pytest.mark.asyncio
async def test_schedule_recovery_reload_skips_when_snapshot_changes() -> None:
    """Recovery scheduling should be skipped when entry snapshot checks fail."""
    hass = MagicMock()
    entry = _make_entry()
    entry_data_snapshot = dict(entry.data)
    entry_options_snapshot = dict(entry.options)
    current_entry = _make_entry()
    object.__setattr__(
        current_entry,
        "data",
        {**current_entry.data, "url": "https://changed.example"},
    )
    hass.config_entries = MagicMock()
    hass.config_entries.async_get_entry.return_value = current_entry
    hass.config_entries.async_schedule_reload = MagicMock()
    flow = _make_flow(hass, entry)

    flow._schedule_recovery_reload(
        data_snapshot=entry_data_snapshot,
        options_snapshot=entry_options_snapshot,
        unique_id_snapshot=entry.unique_id,
        entry_id=entry.entry_id,
        entry_title=entry.title,
    )

    hass.config_entries.async_schedule_reload.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "schedule_error",
    [
        pytest.param(HomeAssistantError("schedule failed"), id="homeassistant-error"),
        pytest.param(KeyError("entry-id"), id="key-error"),
    ],
)
async def test_schedule_recovery_reload_ignores_schedule_errors(
    schedule_error: HomeAssistantError | KeyError,
) -> None:
    """Failure to schedule recovery should not crash the flow."""
    hass = MagicMock()
    entry = _make_entry()
    hass.config_entries = MagicMock()
    hass.config_entries.async_get_entry.return_value = entry
    hass.config_entries.async_schedule_reload.side_effect = schedule_error
    flow = _make_flow(hass, entry)

    flow._schedule_recovery_reload(
        data_snapshot=dict(entry.data),
        options_snapshot=dict(entry.options),
        unique_id_snapshot=entry.unique_id,
        entry_id=entry.entry_id,
        entry_title=entry.title,
    )

    hass.config_entries.async_schedule_reload.assert_called_once_with(entry.entry_id)


@pytest.mark.asyncio
async def test_repair_persists_marker_without_registry_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The repair flow persists intent and leaves registry work to setup reconciliation."""
    hass = MagicMock()
    entry = _make_entry()
    _configure_hass(hass, entry)
    entity_registry, device_registry = _patch_registries(monkeypatch)
    _patch_probe_client(monkeypatch)
    flow = _make_flow(hass, entry)

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.CREATE_ENTRY
    hass.config_entries.async_update_entry.assert_called_once_with(
        entry,
        data={
            **entry.data,
            CONF_DEVICE_UNIQUE_ID: "other",
            REPAIR_MARKER_KEY: build_repair_marker("dev1", "other"),
        },
        unique_id="other",
    )
    entity_registry.async_remove.assert_not_called()
    device_registry.async_update_device.assert_not_called()


@pytest.mark.asyncio
async def test_valid_marker_retry_reprobes_and_reloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A matching persisted marker resumes only after a fresh strict probe."""
    hass = MagicMock()
    entry = _make_entry(device_id="other", unique_id="other")
    object.__setattr__(
        entry,
        "data",
        {**entry.data, REPAIR_MARKER_KEY: build_repair_marker("dev1", "other")},
    )
    _configure_hass(hass, entry)
    client = _patch_probe_client(monkeypatch, observed_device_id="other")
    flow = _make_flow(hass, entry, old_device_id="dev1", new_device_id="other")

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.CREATE_ENTRY
    client.validate.assert_awaited_once_with()
    client.get_device_unique_id.assert_awaited_once_with()
    hass.config_entries.async_reload.assert_awaited_once_with(entry.entry_id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("probe_error", "observed_device_id", "expected_reason"),
    [
        (OPNsenseConnectionError("transport"), None, "cannot_connect"),
        (OPNsenseTimeoutError("timeout"), None, "cannot_connect"),
        (None, "", "cannot_connect"),
        (None, "dev1", "entry_changed"),
    ],
)
async def test_marker_retry_reprobe_error_and_id_checks_abort_without_mutation(
    monkeypatch: pytest.MonkeyPatch,
    probe_error: OPNsenseError | None,
    observed_device_id: Any | None,
    expected_reason: str,
) -> None:
    """Marker retries should abort safely for probe failures and ID mismatches."""
    hass = MagicMock()
    entry = _make_entry(device_id="other", unique_id="other")
    object.__setattr__(
        entry,
        "data",
        {**entry.data, REPAIR_MARKER_KEY: build_repair_marker("dev1", "other")},
    )
    _configure_hass(hass, entry)
    _patch_probe_client(
        monkeypatch,
        observed_device_id=observed_device_id,
        probe_error=probe_error,
    )
    _patch_registries(monkeypatch)
    flow = _make_flow(hass, entry, old_device_id="dev1", new_device_id="other")

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == expected_reason
    hass.config_entries.async_unload.assert_not_awaited()
    hass.config_entries.async_update_entry.assert_not_called()


@pytest.mark.asyncio
async def test_marker_retry_reprobe_match_but_cannot_unload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When a marker retry reprobe matches, unload failures must yield cannot_unload."""
    hass = MagicMock()
    entry = _make_entry(
        device_id="other",
        unique_id="other",
        state=ConfigEntryState.LOADED,
    )
    object.__setattr__(
        entry,
        "data",
        {**entry.data, REPAIR_MARKER_KEY: build_repair_marker("dev1", "other")},
    )
    _configure_hass(hass, entry)
    hass.config_entries.async_unload.return_value = False
    _patch_probe_client(monkeypatch, observed_device_id="other")
    _patch_registries(monkeypatch)
    flow = _make_flow(hass, entry, old_device_id="dev1", new_device_id="other")

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "cannot_unload"
    hass.config_entries.async_unload.assert_awaited_once_with(entry.entry_id)
    hass.config_entries.async_update_entry.assert_not_called()


@pytest.mark.asyncio
async def test_completed_retry_without_marker_reloads_without_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An already-completed repair retries reload without reopening the hardware boundary."""
    hass = MagicMock()
    entry = _make_entry(device_id="other", unique_id="other")
    _configure_hass(hass, entry)
    client = _patch_probe_client(monkeypatch)
    flow = _make_flow(hass, entry, old_device_id="dev1", new_device_id="other")

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.CREATE_ENTRY
    client.factory.assert_not_called()
    hass.config_entries.async_reload.assert_awaited_once_with(entry.entry_id)


@pytest.mark.asyncio
async def test_retry_rejects_invalid_or_mismatched_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A malformed or stale marker cannot resume a repair flow."""
    hass = MagicMock()
    entry = _make_entry(device_id="other", unique_id="other")
    object.__setattr__(entry, "data", {**entry.data, REPAIR_MARKER_KEY: {"version": 1}})
    _configure_hass(hass, entry)
    client = _patch_probe_client(monkeypatch)
    flow = _make_flow(hass, entry, old_device_id="dev1", new_device_id="other")

    result = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "entry_changed"
    client.factory.assert_not_called()


@pytest.mark.parametrize(
    ("scenario", "allow_tracked_macs_mutation"),
    [
        pytest.param("tracked-macs-reject", False, id="tracked-macs-reject"),
        pytest.param("tracked-macs-allow", True, id="tracked-macs-allow"),
        pytest.param("non-tracked-reject", True, id="non-tracked-reject"),
    ],
)
def test_entry_matches_snapshot_invariants(
    scenario: str,
    allow_tracked_macs_mutation: bool,
) -> None:
    """Snapshot matching is strict by default, lenient only for tracked-MAC recovery checks."""
    entry = _make_entry()
    entry_options_snapshot = dict(entry.options)

    if scenario == "non-tracked-reject":
        baseline = dict(entry.data)
        baseline["some_other_key"] = "original"
        object.__setattr__(entry, "data", baseline)

        assert repairs._entry_matches_snapshot(
            entry=entry,
            entry_id=entry.entry_id,
            data_snapshot=baseline,
            options_snapshot=entry_options_snapshot,
            unique_id_snapshot=entry.unique_id,
            allow_tracked_macs_mutation=allow_tracked_macs_mutation,
        )

        mutated = dict(baseline)
        mutated["some_other_key"] = "mutated"
        object.__setattr__(entry, "data", mutated)

        assert not repairs._entry_matches_snapshot(
            entry=entry,
            entry_id=entry.entry_id,
            data_snapshot=baseline,
            options_snapshot=entry_options_snapshot,
            unique_id_snapshot=entry.unique_id,
            allow_tracked_macs_mutation=allow_tracked_macs_mutation,
        )
        return

    baseline = dict(entry.data)
    snapshot = {**baseline, TRACKED_MACS: ["AA:BB:CC:DD"]}
    current = {**baseline, TRACKED_MACS: ["11:22:33:44"]}
    object.__setattr__(entry, "data", current)

    expected_match = scenario == "tracked-macs-allow"
    assert (
        repairs._entry_matches_snapshot(
            entry=entry,
            entry_id=entry.entry_id,
            data_snapshot=snapshot,
            options_snapshot=entry_options_snapshot,
            unique_id_snapshot=entry.unique_id,
            allow_tracked_macs_mutation=allow_tracked_macs_mutation,
        )
        == expected_match
    )
