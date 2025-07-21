"""Unit tests for custom_components.opnsense.entity."""

from unittest.mock import MagicMock

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.opnsense.const import CONF_DEVICE_UNIQUE_ID
from custom_components.opnsense.entity import OPNsenseBaseEntity, OPNsenseEntity


class DummyCoordinator(MagicMock):
    """Lightweight coordinator mock used by the entities.

    Use a MagicMock so that callbacks registered synchronously do not create
    AsyncMock coroutines that are never awaited. Tests can set async attributes
    individually to AsyncMock when they need awaitable behavior.
    """


def _make_entry(title: str | None = "TestDevice", data: dict | None = None):
    data = data or {CONF_DEVICE_UNIQUE_ID: "dev-123", "url": "http://x"}
    entry = MockConfigEntry(domain="opnsense", data=data, title=title or "")
    entry.runtime_data = MagicMock()
    return entry


def test_init_sets_unique_and_name_suffixes():
    entry = _make_entry(title="MyBox")
    coord = DummyCoordinator()
    ent = OPNsenseBaseEntity(
        config_entry=entry, coordinator=coord, unique_id_suffix="suf", name_suffix="Name"
    )

    assert hasattr(ent, "_attr_unique_id")
    # slugify may normalize characters (e.g. '-' -> '_'), assert suffix and device id present
    assert ent._attr_unique_id.endswith("_suf")
    assert "dev" in ent._attr_unique_id
    assert hasattr(ent, "_attr_name")
    assert ent._attr_name == "MyBox Name"


def test_available_property_toggle():
    entry = _make_entry()
    coord = DummyCoordinator()
    ent = OPNsenseBaseEntity(config_entry=entry, coordinator=coord)
    assert ent.available is False
    ent._available = True
    assert ent.available is True


def test_opnsense_device_name_prefers_title_and_fallback_to_state():
    # when title present
    entry = _make_entry(title="BoxTitle")
    coord = DummyCoordinator()
    ent = OPNsenseBaseEntity(config_entry=entry, coordinator=coord)
    assert ent.opnsense_device_name == "BoxTitle"

    # when title empty -> falls back to coordinator.data system_info.name
    entry2 = _make_entry(title="")
    coord2 = DummyCoordinator()
    coord2.data = {"system_info": {"name": "FromState"}}
    ent2 = OPNsenseBaseEntity(config_entry=entry2, coordinator=coord2)
    assert ent2.opnsense_device_name == "FromState"


def test_get_opnsense_state_value_nested_lookup():
    entry = _make_entry()
    coord = DummyCoordinator()
    coord.data = {"a": {"b": {"c": 5}}}
    ent = OPNsenseBaseEntity(config_entry=entry, coordinator=coord)
    assert ent._get_opnsense_state_value("a.b.c") == 5
    assert ent._get_opnsense_state_value("non.existent.path") is None


@pytest.mark.asyncio
async def test_async_added_to_hass_sets_client_and_calls_update(monkeypatch):
    entry = _make_entry()
    coord = DummyCoordinator()
    # provide a runtime client
    client = object()
    entry.runtime_data.opnsense_client = client

    ent = OPNsenseBaseEntity(config_entry=entry, coordinator=coord)

    # stub the entity update handler to observe it being called
    called = {"count": 0}

    def fake_handle():
        called["count"] += 1

    ent._handle_coordinator_update = fake_handle

    # should not raise because runtime_data contains OPNSENSE_CLIENT
    await ent.async_added_to_hass()
    assert ent._client is client
    assert called["count"] == 1


@pytest.mark.asyncio
async def test_async_added_to_hass_missing_client_raises(monkeypatch):
    entry = _make_entry()
    coord = DummyCoordinator()
    # runtime_data has opnsense_client attribute but it's None -> triggers assertion
    entry.runtime_data = MagicMock()
    entry.runtime_data.opnsense_client = None

    ent = OPNsenseBaseEntity(config_entry=entry, coordinator=coord)

    # avoid writing HA state (which requires hass) by stubbing the handler
    ent._handle_coordinator_update = lambda: None
    with pytest.raises(AssertionError):
        await ent.async_added_to_hass()


def test_device_info_variants():
    entry = _make_entry()
    coord = DummyCoordinator()
    # when coordinator.data is None
    coord.data = None
    ent = OPNsenseEntity(config_entry=entry, coordinator=coord)
    info = ent.device_info
    assert info["identifiers"] == {("opnsense", "dev-123")}
    assert info["sw_version"] is None

    # when firmware present
    coord2 = DummyCoordinator()
    coord2.data = {"host_firmware_version": "1.2.3"}
    ent2 = OPNsenseEntity(config_entry=entry, coordinator=coord2)
    info2 = ent2.device_info
    assert info2["sw_version"] == "1.2.3"
