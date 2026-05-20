"""Unit tests for custom_components.opnsense.binary_sensor.

These tests validate async_setup_entry and the update handlers for the
binary sensor entities.
"""

from unittest.mock import MagicMock

import pytest

from custom_components.opnsense.binary_sensor import (
    OPNsenseInterfaceEnabledBinarySensor,
    OPNsensePendingNoticesPresentBinarySensor,
    async_setup_entry,
)
from custom_components.opnsense.const import (
    CONF_DEVICE_UNIQUE_ID,
    CONF_SYNC_INTERFACES,
    CONF_SYNC_NOTICES,
    COORDINATOR,
)
from custom_components.opnsense.coordinator import OPNsenseDataUpdateCoordinator
from homeassistant.components.binary_sensor import BinarySensorEntityDescription


@pytest.mark.asyncio
async def test_async_setup_entry_creates_entities_when_enabled(make_config_entry):
    """Create notices binary sensor when notices sync is enabled."""
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_NOTICES: True})
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {}
    setattr(entry.runtime_data, COORDINATOR, coord)

    created: list = []

    def add_entities(ents):
        """Add entities.

        Args:
            ents: Ents provided by pytest or the test case.
        """
        created.extend(ents)

    await async_setup_entry(MagicMock(), entry, add_entities)
    assert len(created) == 1
    assert isinstance(created[0], OPNsensePendingNoticesPresentBinarySensor)


@pytest.mark.asyncio
async def test_async_setup_entry_skips_when_disabled(make_config_entry):
    """Skip creating entities when sync options are disabled."""
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_NOTICES: False})
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {}
    setattr(entry.runtime_data, COORDINATOR, coord)

    created: list = []

    def add_entities(ents):
        """Add entities.

        Args:
            ents: Ents provided by pytest or the test case.
        """
        created.extend(ents)

    await async_setup_entry(MagicMock(), entry, add_entities)
    assert created == []


@pytest.mark.asyncio
async def test_async_setup_entry_creates_only_notices_when_notices_enabled(make_config_entry):
    """Create only Notices entity when notices sync is enabled."""
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_NOTICES: True})
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {}
    setattr(entry.runtime_data, COORDINATOR, coord)

    created: list = []

    def add_entities(ents):
        """Add entities.

        Args:
            ents: Ents provided by pytest or the test case.
        """
        created.extend(ents)

    await async_setup_entry(MagicMock(), entry, add_entities)
    # expect one Notices entity created
    assert len(created) == 1
    assert isinstance(created[0], OPNsensePendingNoticesPresentBinarySensor)


@pytest.mark.asyncio
async def test_async_setup_entry_creates_disabled_interface_enabled_sensors(make_config_entry):
    """Create disabled-by-default enabled-state binary sensors for interfaces."""
    entry = make_config_entry(
        {
            CONF_DEVICE_UNIQUE_ID: "id",
            CONF_SYNC_INTERFACES: True,
            CONF_SYNC_NOTICES: False,
        }
    )
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {
        "interfaces": {
            "wan": {"name": "WAN", "enabled": False},
            "lan": {"name": "LAN", "enabled": True},
        }
    }
    setattr(entry.runtime_data, COORDINATOR, coord)

    created: list = []

    def add_entities(ents):
        """Add entities.

        Args:
            ents: Ents provided by pytest or the test case.
        """
        created.extend(ents)

    await async_setup_entry(MagicMock(), entry, add_entities)

    assert len(created) == 2
    assert all(isinstance(entity, OPNsenseInterfaceEnabledBinarySensor) for entity in created)
    assert {entity.entity_description.key for entity in created} == {
        "interface.wan.enabled",
        "interface.lan.enabled",
    }
    assert all(
        entity.entity_description.entity_registry_enabled_default is False for entity in created
    )


def test_interface_enabled_binary_sensor_state(make_config_entry):
    """Interface enabled binary sensor should expose the interface enabled state."""
    entry = make_config_entry()
    desc = BinarySensorEntityDescription(key="interface.wan.enabled", name="Interface WAN Enabled")

    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {"interfaces": {"wan": {"name": "WAN", "enabled": False}}}
    sensor = OPNsenseInterfaceEnabledBinarySensor(
        config_entry=entry, coordinator=coord, entity_description=desc
    )
    sensor.hass = MagicMock()
    sensor.entity_id = "binary_sensor.wan_enabled"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)

    sensor._handle_coordinator_update()

    assert sensor.available is True
    assert sensor.is_on is False


def test_interface_enabled_binary_sensor_unavailable_when_enabled_unknown(make_config_entry):
    """Interface enabled binary sensor should be unavailable when enabled state is unknown."""
    entry = make_config_entry()
    desc = BinarySensorEntityDescription(key="interface.wan.enabled", name="Interface WAN Enabled")

    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {"interfaces": {"wan": {"name": "WAN", "enabled": None}}}
    sensor = OPNsenseInterfaceEnabledBinarySensor(
        config_entry=entry, coordinator=coord, entity_description=desc
    )
    sensor.hass = MagicMock()
    sensor.entity_id = "binary_sensor.wan_enabled"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)

    sensor._handle_coordinator_update()

    assert sensor.available is False


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
    """Parameterized tests for pending notices sensor update paths. Covers: non-mapping (None), present with list, and present but missing list."""
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
        """Write."""
        write_called["val"] = True

    s.async_write_ha_state = write if expect_write_called else lambda: None

    s._handle_coordinator_update()
    assert write_called["val"] is expect_write_called
    assert s.available is expect_available
    if expect_is_on is not None:
        assert s.is_on is expect_is_on
    if expect_pending is not None:
        assert s.extra_state_attributes.get("pending_notices") == expect_pending
