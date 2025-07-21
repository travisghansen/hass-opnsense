"""Unit tests for custom_components.opnsense.binary_sensor.

These tests validate async_setup_entry and the update handlers for the
binary sensor entities.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.opnsense.binary_sensor import (
    OPNsenseCarpStatusBinarySensor,
    OPNsensePendingNoticesPresentBinarySensor,
    async_setup_entry,
)
from custom_components.opnsense.const import (
    CONF_DEVICE_UNIQUE_ID,
    CONF_SYNC_CARP,
    CONF_SYNC_NOTICES,
    COORDINATOR,
)
from homeassistant.components.binary_sensor import BinarySensorEntityDescription


def _make_config_entry(data: dict | None = None) -> MockConfigEntry:
    data = data or {CONF_DEVICE_UNIQUE_ID: "test-device-123"}
    entry = MockConfigEntry(domain="opnsense", data=data, title="OPNsense Test")
    entry.runtime_data = {}
    return entry


@pytest.mark.asyncio
async def test_async_setup_entry_creates_entities_when_enabled():
    # enable both sync options
    entry = _make_config_entry(
        {CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_CARP: True, CONF_SYNC_NOTICES: True}
    )
    coord = SimpleNamespace(data={})
    entry.runtime_data = SimpleNamespace(**{COORDINATOR: coord})

    created: list = []

    def add_entities(ents):
        created.extend(ents)

    await async_setup_entry(MagicMock(), entry, add_entities)
    # expect two entities created
    assert any(isinstance(e, OPNsenseCarpStatusBinarySensor) for e in created)
    assert any(isinstance(e, OPNsensePendingNoticesPresentBinarySensor) for e in created)


@pytest.mark.asyncio
async def test_async_setup_entry_skips_when_disabled():
    # explicitly disable both
    entry = _make_config_entry(
        {CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_CARP: False, CONF_SYNC_NOTICES: False}
    )
    coord = SimpleNamespace(data={})
    entry.runtime_data = SimpleNamespace(**{COORDINATOR: coord})

    created: list = []

    def add_entities(ents):
        created.extend(ents)

    await async_setup_entry(MagicMock(), entry, add_entities)
    assert created == []


def test_carp_sensor_update_paths():
    entry = _make_config_entry()

    desc = BinarySensorEntityDescription(key="carp.status", name="CARP Status")

    # non-mapping state -> unavailable
    coord = SimpleNamespace(data=None)
    s = OPNsenseCarpStatusBinarySensor(
        config_entry=entry, coordinator=coord, entity_description=desc
    )
    called = False

    def write():
        nonlocal called
        called = True

    s.hass = MagicMock()
    s.entity_id = "binary_sensor.carp"
    s.async_write_ha_state = write
    s._handle_coordinator_update()
    assert called is True
    assert s.available is False

    # mapping with carp_status True
    coord2 = SimpleNamespace(data={"carp_status": True})
    s2 = OPNsenseCarpStatusBinarySensor(
        config_entry=entry, coordinator=coord2, entity_description=desc
    )
    s2.hass = MagicMock()
    s2.entity_id = "binary_sensor.carp2"
    s2.async_write_ha_state = lambda: None
    s2._handle_coordinator_update()
    assert s2.available is True
    assert s2.is_on is True
    assert isinstance(s2.extra_state_attributes, dict)

    # mapping missing key -> unavailable
    coord3 = SimpleNamespace(data={"other": 1})
    s3 = OPNsenseCarpStatusBinarySensor(
        config_entry=entry, coordinator=coord3, entity_description=desc
    )
    s3.hass = MagicMock()
    s3.entity_id = "binary_sensor.carp3"
    s3.async_write_ha_state = lambda: None
    s3._handle_coordinator_update()
    assert s3.available is False


def test_pending_notices_sensor_update_paths():
    entry = _make_config_entry()
    desc = BinarySensorEntityDescription(
        key="notices.pending_notices_present", name="Pending Notices"
    )

    # non-mapping state -> unavailable
    coord = SimpleNamespace(data=None)
    s = OPNsensePendingNoticesPresentBinarySensor(
        config_entry=entry, coordinator=coord, entity_description=desc
    )
    s.hass = MagicMock()
    s.entity_id = "binary_sensor.notices"
    called = False

    def write():
        nonlocal called
        called = True

    s.async_write_ha_state = write
    s._handle_coordinator_update()
    assert called is True
    assert s.available is False

    # mapping with pending notices present and list
    coord2 = SimpleNamespace(
        data={"notices": {"pending_notices_present": True, "pending_notices": [{"id": 1}]}}
    )
    s2 = OPNsensePendingNoticesPresentBinarySensor(
        config_entry=entry, coordinator=coord2, entity_description=desc
    )
    s2.hass = MagicMock()
    s2.entity_id = "binary_sensor.notices2"
    s2.async_write_ha_state = lambda: None
    s2._handle_coordinator_update()
    assert s2.available is True
    assert s2.is_on is True
    assert s2.extra_state_attributes.get("pending_notices") == [{"id": 1}]

    # mapping with missing pending_notices -> should get default []
    coord3 = SimpleNamespace(data={"notices": {"pending_notices_present": False}})
    s3 = OPNsensePendingNoticesPresentBinarySensor(
        config_entry=entry, coordinator=coord3, entity_description=desc
    )
    s3.hass = MagicMock()
    s3.entity_id = "binary_sensor.notices3"
    s3.async_write_ha_state = lambda: None
    s3._handle_coordinator_update()
    assert s3.available is True
    assert s3.is_on is False
    assert s3.extra_state_attributes.get("pending_notices") == []
