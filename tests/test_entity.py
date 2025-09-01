"""Unit tests for custom_components.opnsense.entity."""

from unittest.mock import MagicMock

import pytest

from custom_components.opnsense.entity import OPNsenseBaseEntity, OPNsenseEntity
from homeassistant.util import slugify


def test_init_sets_unique_and_name_suffixes(make_config_entry, dummy_coordinator):
    entry = make_config_entry({"device_unique_id": "dev-123", "url": "http://x"}, title="MyBox")
    coord = dummy_coordinator
    ent = OPNsenseBaseEntity(
        config_entry=entry, coordinator=coord, unique_id_suffix="suf", name_suffix="Name"
    )

    assert hasattr(ent, "_attr_unique_id")
    # deterministically compute expected slug from device_unique_id and assert
    device_unique = entry.data.get("device_unique_id")
    expected_prefix = slugify(device_unique)
    # entity unique id is slugified(device_unique_id) + '_' + suffix
    assert ent._attr_unique_id.startswith(f"{expected_prefix}_")
    assert ent._attr_unique_id.endswith("_suf")
    assert hasattr(ent, "_attr_name")
    assert ent._attr_name == "MyBox Name"


def test_available_property_toggle(make_config_entry, dummy_coordinator):
    entry = make_config_entry()
    coord = dummy_coordinator
    ent = OPNsenseBaseEntity(config_entry=entry, coordinator=coord)
    assert ent.available is False
    ent._available = True
    assert ent.available is True


def test_opnsense_device_name_prefers_title_and_fallback_to_state(
    make_config_entry, dummy_coordinator
):
    # when title present
    entry = make_config_entry({"device_unique_id": "dev-123", "url": "http://x"}, title="BoxTitle")
    coord = dummy_coordinator
    ent = OPNsenseBaseEntity(config_entry=entry, coordinator=coord)
    assert ent.opnsense_device_name == "BoxTitle"

    # when title empty -> falls back to coordinator.data system_info.name
    entry2 = make_config_entry({"device_unique_id": "dev-123", "url": "http://x"}, title="")
    coord2 = type(dummy_coordinator)()
    coord2.data = {"system_info": {"name": "FromState"}}
    ent2 = OPNsenseBaseEntity(config_entry=entry2, coordinator=coord2)
    assert ent2.opnsense_device_name == "FromState"


def test_get_opnsense_state_value_nested_lookup(make_config_entry, dummy_coordinator):
    entry = make_config_entry()
    coord = dummy_coordinator
    coord.data = {"a": {"b": {"c": 5}}}
    ent = OPNsenseBaseEntity(config_entry=entry, coordinator=coord)
    assert ent._get_opnsense_state_value("a.b.c") == 5
    assert ent._get_opnsense_state_value("non.existent.path") is None


@pytest.mark.asyncio
async def test_async_added_to_hass_sets_client_and_calls_update(
    make_config_entry, dummy_coordinator
):
    entry = make_config_entry()
    coord = dummy_coordinator
    # provide a runtime client
    client = object()
    # make_config_entry provides a dict for runtime_data; tests expect attribute access
    entry.runtime_data = MagicMock()
    entry.runtime_data.opnsense_client = client

    ent = OPNsenseBaseEntity(config_entry=entry, coordinator=coord)

    # stub the entity update handler to observe it being called
    called = {"count": 0}

    def fake_handle():
        called["count"] += 1

    ent._handle_coordinator_update = fake_handle

    # provide a minimal hass stub so lifecycle behaves more like real HA
    ent.hass = MagicMock()
    # should not raise because runtime_data contains OPNSENSE_CLIENT
    await ent.async_added_to_hass()
    assert ent._client is client
    assert called["count"] == 1


@pytest.mark.asyncio
async def test_async_added_to_hass_missing_client_raises(make_config_entry, dummy_coordinator):
    entry = make_config_entry()
    coord = dummy_coordinator
    # runtime_data has opnsense_client attribute but it's None -> triggers assertion
    entry.runtime_data = MagicMock()
    entry.runtime_data.opnsense_client = None

    ent = OPNsenseBaseEntity(config_entry=entry, coordinator=coord)

    # avoid writing HA state (which requires hass) by stubbing the handler
    ent._handle_coordinator_update = lambda: None
    with pytest.raises(AssertionError):
        await ent.async_added_to_hass()


def test_device_info_variants(make_config_entry, dummy_coordinator):
    entry = make_config_entry({"device_unique_id": "dev-123"})
    coord = dummy_coordinator
    # when coordinator.data is None
    coord.data = None
    ent = OPNsenseEntity(config_entry=entry, coordinator=coord)
    info = ent.device_info
    assert info["identifiers"] == {("opnsense", "dev-123")}
    assert info["sw_version"] is None

    # when firmware present
    coord2 = type(dummy_coordinator)()
    coord2.data = {"host_firmware_version": "1.2.3"}
    ent2 = OPNsenseEntity(config_entry=entry, coordinator=coord2)
    info2 = ent2.device_info
    assert info2["sw_version"] == "1.2.3"
