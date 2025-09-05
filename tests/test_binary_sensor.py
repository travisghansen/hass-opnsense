"""Unit tests for custom_components.opnsense.binary_sensor.

These tests validate async_setup_entry and the update handlers for the
binary sensor entities.
"""

from unittest.mock import MagicMock

import pytest

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
from custom_components.opnsense.coordinator import OPNsenseDataUpdateCoordinator
from homeassistant.components.binary_sensor import BinarySensorEntityDescription


@pytest.mark.asyncio
async def test_async_setup_entry_creates_entities_when_enabled(make_config_entry):
    """Create entities when sync options are enabled."""
    # enable both sync options
    entry = make_config_entry(
        {CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_CARP: True, CONF_SYNC_NOTICES: True}
    )
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {}
    setattr(entry.runtime_data, COORDINATOR, coord)

    created: list = []

    def add_entities(ents):
        created.extend(ents)

    await async_setup_entry(MagicMock(), entry, add_entities)
    # expect two entities created
    assert len(created) == 2
    assert any(isinstance(e, OPNsenseCarpStatusBinarySensor) for e in created)
    assert any(isinstance(e, OPNsensePendingNoticesPresentBinarySensor) for e in created)


@pytest.mark.asyncio
async def test_async_setup_entry_skips_when_disabled(make_config_entry):
    """Skip creating entities when sync options are disabled."""
    # explicitly disable both
    entry = make_config_entry(
        {CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_CARP: False, CONF_SYNC_NOTICES: False}
    )
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {}
    setattr(entry.runtime_data, COORDINATOR, coord)

    created: list = []

    def add_entities(ents):
        created.extend(ents)

    await async_setup_entry(MagicMock(), entry, add_entities)
    assert created == []


@pytest.mark.asyncio
async def test_async_setup_entry_creates_only_carp_when_carp_enabled(make_config_entry):
    """Create only CARP entity when CARP sync is enabled."""
    # enable only CARP
    entry = make_config_entry(
        {CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_CARP: True, CONF_SYNC_NOTICES: False}
    )
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {}
    setattr(entry.runtime_data, COORDINATOR, coord)

    created: list = []

    def add_entities(ents):
        created.extend(ents)

    await async_setup_entry(MagicMock(), entry, add_entities)
    # expect one CARP entity created
    assert len(created) == 1
    assert isinstance(created[0], OPNsenseCarpStatusBinarySensor)


@pytest.mark.asyncio
async def test_async_setup_entry_creates_only_notices_when_notices_enabled(make_config_entry):
    """Create only Notices entity when notices sync is enabled."""
    # enable only Notices
    entry = make_config_entry(
        {CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_CARP: False, CONF_SYNC_NOTICES: True}
    )
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {}
    setattr(entry.runtime_data, COORDINATOR, coord)

    created: list = []

    def add_entities(ents):
        created.extend(ents)

    await async_setup_entry(MagicMock(), entry, add_entities)
    # expect one Notices entity created
    assert len(created) == 1
    assert isinstance(created[0], OPNsensePendingNoticesPresentBinarySensor)


@pytest.mark.parametrize(
    "coord_data,expect_write_called,expect_available,expect_is_on,expect_extra",
    [
        (None, True, False, None, None),
        ({"carp_status": True}, True, True, True, dict),
        ({"carp_status": False}, True, True, False, dict),
        ({"other": 1}, True, False, None, None),
        # non-boolean carp value should trigger a write and mark sensor available; extras are dict
        ({"carp_status": "up"}, True, True, None, dict),
    ],
)
def test_carp_sensor_update_paths_param(
    coord_data, expect_write_called, expect_available, expect_is_on, expect_extra, make_config_entry
):
    """Parameterized tests for CARP status sensor update paths.

    Covers: non-mapping (None), present True, and missing-key cases.
    """
    entry = make_config_entry()
    desc = BinarySensorEntityDescription(key="carp_status", name="CARP Status")

    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = coord_data
    s = OPNsenseCarpStatusBinarySensor(
        config_entry=entry, coordinator=coord, entity_description=desc
    )

    write_called = {"val": False}

    def write():
        write_called["val"] = True

    s.hass = MagicMock()
    s.entity_id = "binary_sensor.carp"
    # only replace writer when we expect to observe a call, else set a no-op
    s.async_write_ha_state = write if expect_write_called else lambda: None

    s._handle_coordinator_update()
    assert write_called["val"] is expect_write_called
    assert s.available is expect_available
    if expect_is_on is not None:
        assert s.is_on is expect_is_on
    if expect_extra is not None:
        assert isinstance(s.extra_state_attributes, expect_extra)
        if coord_data and "carp_status" in (coord_data or {}):
            assert s.extra_state_attributes == {}


@pytest.mark.parametrize(
    "coord_data,expect_write_called,expect_available,expect_is_on,expect_pending",
    [
        (None, True, False, None, None),
        (
            {"notices": {"pending_notices_present": True, "pending_notices": [{"id": 1}]}},
            True,
            True,
            True,
            [{"id": 1}],
        ),
        (
            {"notices": {"pending_notices_present": True}},
            True,
            True,
            True,
            [],
        ),
        ({"notices": {"pending_notices_present": False}}, True, True, False, []),
    ],
)
def test_pending_notices_sensor_update_paths_param(
    coord_data,
    expect_write_called,
    expect_available,
    expect_is_on,
    expect_pending,
    make_config_entry,
):
    """Parameterized tests for pending notices sensor update paths.

    Covers: non-mapping (None), present with list, and present but missing list.
    """
    entry = make_config_entry()
    desc = BinarySensorEntityDescription(
        key="notices.pending_notices_present", name="Pending Notices"
    )

    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = coord_data
    s = OPNsensePendingNoticesPresentBinarySensor(
        config_entry=entry, coordinator=coord, entity_description=desc
    )
    s.hass = MagicMock()
    s.entity_id = "binary_sensor.notices"

    write_called = {"val": False}

    def write():
        write_called["val"] = True

    s.async_write_ha_state = write if expect_write_called else lambda: None

    s._handle_coordinator_update()
    assert write_called["val"] is expect_write_called
    assert s.available is expect_available
    if expect_is_on is not None:
        assert s.is_on is expect_is_on
    if expect_pending is not None:
        assert s.extra_state_attributes.get("pending_notices") == expect_pending
