"""Unit tests for custom_components.opnsense.binary_sensor.

These tests validate async_setup_entry and the update handlers for the
binary sensor entities.
"""

from collections.abc import Callable, Iterable
from typing import Any, cast
from unittest.mock import MagicMock

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntityDescription,
)
from homeassistant.helpers.entity_platform import AddEntitiesCallback
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.opnsense.binary_sensor import (
    OPNsenseInterfaceEnabledBinarySensor,
    OPNsensePendingNoticesPresentBinarySensor,
    OPNsenseSmartStatusBinarySensor,
    _compile_interface_enabled_binary_sensors,
    _compile_smart_status_binary_sensors,
    async_setup_entry,
)
from custom_components.opnsense.const import (
    CONF_DEVICE_UNIQUE_ID,
    CONF_SYNC_INTERFACES,
    CONF_SYNC_NOTICES,
    CONF_SYNC_SMART,
    COORDINATOR,
)
from custom_components.opnsense.coordinator import OPNsenseDataUpdateCoordinator
from tests.utilities import stub_async_write_ha_state


@pytest.mark.asyncio
async def test_async_setup_entry_creates_entities_when_enabled(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Create notices binary sensor when notices sync is enabled."""
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_NOTICES: True})
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {}
    setattr(entry.runtime_data, COORDINATOR, coord)

    created: list = []

    def add_entities(ents: Iterable[Any], _update_before_add: bool = False) -> None:
        """Add entities.

        Args:
            ents: Ents provided by pytest or the test case.
        """
        created.extend(ents)

    await async_setup_entry(MagicMock(), entry, cast("AddEntitiesCallback", add_entities))
    assert len(created) == 1
    assert isinstance(created[0], OPNsensePendingNoticesPresentBinarySensor)


@pytest.mark.asyncio
async def test_async_setup_entry_skips_when_disabled(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Skip creating entities when sync options are disabled."""
    entry = make_config_entry(
        {CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_NOTICES: False, CONF_SYNC_SMART: False}
    )
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {}
    setattr(entry.runtime_data, COORDINATOR, coord)

    created: list = []

    def add_entities(ents: Iterable[Any], _update_before_add: bool = False) -> None:
        """Add entities.

        Args:
            ents: Ents provided by pytest or the test case.
        """
        created.extend(ents)

    await async_setup_entry(MagicMock(), entry, cast("AddEntitiesCallback", add_entities))
    assert created == []


@pytest.mark.asyncio
async def test_async_setup_entry_creates_only_notices_when_notices_enabled(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Create only Notices entity when notices sync is enabled."""
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_NOTICES: True})
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {}
    setattr(entry.runtime_data, COORDINATOR, coord)

    created: list = []

    def add_entities(ents: Iterable[Any], _update_before_add: bool = False) -> None:
        """Add entities.

        Args:
            ents: Ents provided by pytest or the test case.
        """
        created.extend(ents)

    await async_setup_entry(MagicMock(), entry, cast("AddEntitiesCallback", add_entities))
    # expect one Notices entity created
    assert len(created) == 1
    assert isinstance(created[0], OPNsensePendingNoticesPresentBinarySensor)


@pytest.mark.asyncio
async def test_async_setup_entry_creates_disabled_interface_enabled_sensors(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
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

    def add_entities(ents: Iterable[Any], _update_before_add: bool = False) -> None:
        """Add entities.

        Args:
            ents: Ents provided by pytest or the test case.
        """
        created.extend(ents)

    await async_setup_entry(MagicMock(), entry, cast("AddEntitiesCallback", add_entities))

    assert len(created) == 2
    assert all(isinstance(entity, OPNsenseInterfaceEnabledBinarySensor) for entity in created)
    assert {entity.entity_description.key for entity in created} == {
        "interface.wan.enabled",
        "interface.lan.enabled",
    }
    assert all(
        entity.entity_description.entity_registry_enabled_default is False for entity in created
    )


@pytest.mark.asyncio
async def test_async_setup_entry_creates_smart_status_problem_binary_sensors(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Create SMART status binary sensors with health-log attributes."""
    entry = make_config_entry(
        {
            CONF_DEVICE_UNIQUE_ID: "id",
            CONF_SYNC_INTERFACES: False,
            CONF_SYNC_NOTICES: False,
            CONF_SYNC_SMART: True,
        }
    )
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {
        "smart": [
            {
                "device": "nvme0",
                "ident": "SERIAL",
                "state": {"smart_status": {"passed": True}},
            },
            {"device": "ada0", "state": {"smart_status": {"passed": False}}},
        ],
        "smart_info": {
            "nvme0": {
                "nvme_smart_health_information_log": {
                    "critical_warning": 0,
                    "media_errors": 0,
                    "temperature": 71,
                }
            },
            "ada0": {
                "nvme_smart_health_information_log": {"critical_warning": 1, "media_errors": 2}
            },
        },
    }
    setattr(entry.runtime_data, COORDINATOR, coord)
    created: list[Any] = []

    def add_entities(ents: Iterable[Any], _update_before_add: bool = False) -> None:
        """Add entities.

        Args:
            ents: Ents provided by pytest or the test case.
        """
        created.extend(ents)

    await async_setup_entry(MagicMock(), entry, cast("AddEntitiesCallback", add_entities))

    smart_entities = [
        entity for entity in created if isinstance(entity, OPNsenseSmartStatusBinarySensor)
    ]
    assert {entity.entity_description.key for entity in smart_entities} == {
        "smart.nvme0.status",
        "smart.ada0.status",
    }
    assert all(
        entity.entity_description.device_class is BinarySensorDeviceClass.PROBLEM
        for entity in smart_entities
    )

    entities_by_key = {entity.entity_description.key: entity for entity in smart_entities}
    nvme_status = entities_by_key["smart.nvme0.status"]
    nvme_status.hass = MagicMock()
    nvme_status.entity_id = "binary_sensor.smart_nvme0_status"
    stub_async_write_ha_state(nvme_status)
    nvme_status._handle_coordinator_update()

    assert nvme_status.available is True
    assert nvme_status.is_on is False
    assert nvme_status.extra_state_attributes == {
        "device": "nvme0",
        "ident": "SERIAL",
        "critical_warning": 0,
        "media_errors": 0,
        "temperature": 71,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("coord_data", [None, {"smart": {}}])
async def test_compile_smart_status_binary_sensors_skips_invalid_state(
    coord_data: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Skip SMART status binary sensors from invalid coordinator state."""
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id"})
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = coord_data

    assert await _compile_smart_status_binary_sensors(entry, coord) == []


@pytest.mark.asyncio
async def test_compile_smart_status_binary_sensors_skips_malformed_devices(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Skip malformed SMART rows while compiling valid status binary sensors."""
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id"})
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {
        "smart": [
            "ignored",
            {"device": ""},
            {"device": "nvme0", "state": {"smart_status": {"passed": True}}},
        ]
    }

    entities = await _compile_smart_status_binary_sensors(entry, coord)

    assert len(entities) == 1
    assert entities[0].entity_description.key == "smart.nvme0.status"


def _build_smart_status_binary_sensor(
    make_config_entry: Callable[..., MockConfigEntry],
    state: Any,
    key: str = "smart.nvme0.status",
) -> OPNsenseSmartStatusBinarySensor:
    """Build a SMART status binary sensor for direct update tests.

    Args:
        make_config_entry: Config-entry factory fixture.
        state: Coordinator data to bind to the sensor.
        key: Entity description key to test.

    Returns:
        OPNsenseSmartStatusBinarySensor: Prepared sensor instance.
    """
    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = state
    sensor = OPNsenseSmartStatusBinarySensor(
        config_entry=entry,
        coordinator=coord,
        entity_description=BinarySensorEntityDescription(key=key, name="SMART nvme0 Status"),
    )
    sensor.hass = MagicMock()
    sensor.entity_id = "binary_sensor.smart_nvme0_status"
    stub_async_write_ha_state(sensor)
    return sensor


@pytest.mark.parametrize(
    ("state", "key"),
    [
        (None, "smart.nvme0.status"),
        ({"smart": []}, "smart.nvme0.status.extra"),
        ({"smart": {}}, "smart.nvme0.status"),
        ({"smart": ["ignored", {"device": ""}]}, "smart.nvme0.status"),
        (
            {"smart": [{"device": "nvme0", "state": {"smart_status": {}}}]},
            "smart.nvme0.status",
        ),
        (
            {"smart": [{"device": "nvme0", "state": {"smart_status": ""}}]},
            "smart.nvme0.status",
        ),
    ],
)
def test_smart_status_binary_sensor_unavailable_for_invalid_payloads(
    state: Any,
    key: str,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART status binary sensors should reject invalid state and status payloads."""
    sensor = _build_smart_status_binary_sensor(make_config_entry, state, key)

    sensor._handle_coordinator_update()

    assert sensor.available is False


@pytest.mark.parametrize(
    ("smart_state", "smart_info", "expected_is_on"),
    [
        ({"smart_status": {"status": "FAILED"}}, {}, True),
        (None, {"nvme0": {"smart_status": True}}, False),
        ({}, {"nvme0": {"smart_status": "PASSED"}}, False),
    ],
)
def test_smart_status_binary_sensor_parses_supported_status_shapes(
    smart_state: dict[str, Any] | None,
    smart_info: dict[str, Any],
    expected_is_on: bool,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART status binary sensors should parse supported status shapes."""
    smart_device: dict[str, Any] = {"device": "nvme0"}
    if smart_state is not None:
        smart_device["state"] = smart_state
    sensor = _build_smart_status_binary_sensor(
        make_config_entry,
        {
            "smart": [
                {"device": "ada0", "state": {"smart_status": {"passed": True}}},
                smart_device,
            ],
            "smart_info": smart_info,
        },
    )

    sensor._handle_coordinator_update()

    assert sensor.available is True
    assert sensor.is_on is expected_is_on
    assert sensor.extra_state_attributes == {"device": "nvme0"}


def test_smart_status_binary_sensor_strips_device_name_before_smart_info_lookup(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART status binary sensors should normalize padded device names before lookup."""
    sensor = _build_smart_status_binary_sensor(
        make_config_entry,
        {
            "smart": [{"device": " nvme0 "}],
            "smart_info": {"nvme0": {"smart_status": {"passed": False}}},
        },
    )

    sensor._handle_coordinator_update()

    assert sensor.available is True
    assert sensor.is_on is True


@pytest.mark.asyncio
async def test_async_setup_entry_skips_interfaces_when_interface_sync_disabled(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Skip interface enabled binary sensors when interface sync is disabled."""
    entry = make_config_entry(
        {
            CONF_DEVICE_UNIQUE_ID: "id",
            CONF_SYNC_INTERFACES: False,
            CONF_SYNC_NOTICES: True,
        }
    )
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {"interfaces": {"wan": {"name": "WAN", "enabled": True}}}
    setattr(entry.runtime_data, COORDINATOR, coord)

    created: list = []

    def add_entities(ents: Iterable[Any], _update_before_add: bool = False) -> None:
        """Add entities.

        Args:
            ents: Ents provided by pytest or the test case.
        """
        created.extend(ents)

    await async_setup_entry(MagicMock(), entry, cast("AddEntitiesCallback", add_entities))

    assert len(created) == 1
    assert isinstance(created[0], OPNsensePendingNoticesPresentBinarySensor)


@pytest.mark.asyncio
@pytest.mark.parametrize("coord_data", [None, {"interfaces": []}])
async def test_compile_interface_enabled_binary_sensors_skips_invalid_state(
    coord_data: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Skip compiling interface enabled sensors from invalid coordinator state."""
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id"})
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = coord_data

    assert await _compile_interface_enabled_binary_sensors(entry, coord) == []


@pytest.mark.asyncio
async def test_compile_interface_enabled_binary_sensors_skips_malformed_interfaces(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Skip malformed interfaces while compiling valid interface enabled sensors."""
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id"})
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {
        "interfaces": {
            1: {"name": "bad"},
            "missing": [],
            "wan": {"name": "WAN", "enabled": True},
        }
    }

    entities = await _compile_interface_enabled_binary_sensors(entry, coord)

    assert len(entities) == 1
    assert entities[0].entity_description.key == "interface.wan.enabled"


@pytest.mark.parametrize(
    ("desc_key", "coord_data", "expected_available", "expected_is_on"),
    [
        pytest.param(
            "interface.wan.enabled",
            {"interfaces": {"wan": {"name": "WAN", "enabled": False}}},
            True,
            False,
            id="disabled",
        ),
        pytest.param(
            "interface.wan.enabled",
            {"interfaces": {"wan": {"name": "WAN", "enabled": None}}},
            False,
            None,
            id="unknown",
        ),
        pytest.param(
            "bad.key",
            {"interfaces": {"wan": {"enabled": True}}},
            False,
            None,
            id="bad-key",
        ),
        pytest.param("interface.wan.enabled", None, False, None, id="missing-state"),
        pytest.param(
            "interface.wan.enabled",
            {"interfaces": {"wan": {}}},
            False,
            None,
            id="missing-enabled",
        ),
        pytest.param(
            "interface.wan.enabled",
            {"interfaces": {"wan": []}},
            False,
            None,
            id="malformed-interface",
        ),
    ],
)
def test_interface_enabled_binary_sensor_state_handling(
    desc_key: Any,
    coord_data: Any,
    expected_available: bool,
    expected_is_on: bool | None,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Interface enabled binary sensor should expose or reject enabled state payloads."""
    entry = make_config_entry()
    desc = BinarySensorEntityDescription(key=desc_key, name="Interface WAN Enabled")

    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = coord_data
    sensor = OPNsenseInterfaceEnabledBinarySensor(
        config_entry=entry, coordinator=coord, entity_description=desc
    )
    sensor.hass = MagicMock()
    sensor.entity_id = "binary_sensor.wan_enabled"
    stub_async_write_ha_state(sensor)

    sensor._handle_coordinator_update()

    assert sensor.available is expected_available
    if expected_is_on is not None:
        assert sensor.is_on is expected_is_on


def test_interface_enabled_binary_sensor_extra_attributes(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Interface enabled binary sensor should expose useful interface attributes."""
    entry = make_config_entry()
    desc = BinarySensorEntityDescription(key="interface.wan.enabled", name="Interface WAN Enabled")

    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {
        "interfaces": {
            "wan": {
                "enabled": True,
                "interface": "wan",
                "device": "igc0",
                "ipv4": "192.0.2.1",
                "ipv6": "",
                "mac": "00:11:22:33:44:55",
            }
        }
    }
    sensor = OPNsenseInterfaceEnabledBinarySensor(
        config_entry=entry, coordinator=coord, entity_description=desc
    )
    sensor.hass = MagicMock()
    sensor.entity_id = "binary_sensor.wan_enabled"
    stub_async_write_ha_state(sensor)

    sensor._handle_coordinator_update()

    assert sensor.available is True
    assert sensor.is_on is True
    assert sensor.extra_state_attributes == {
        "interface": "wan",
        "device": "igc0",
        "ipv4": "192.0.2.1",
        "mac": "00:11:22:33:44:55",
    }


@pytest.mark.parametrize(
    ("coord_data", "expect_write_called", "expect_available", "expect_is_on", "expect_pending"),
    [
        (None, True, False, None, None),
        ({"notices": {}}, True, False, None, None),
        ({"notices": None}, True, False, None, None),
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
    coord_data: Any,
    expect_write_called: Any,
    expect_available: Any,
    expect_is_on: Any,
    expect_pending: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
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
    write_state = MagicMock()
    object.__setattr__(s, "async_write_ha_state", write_state)

    s._handle_coordinator_update()
    assert write_state.called is expect_write_called
    assert s.available is expect_available
    if expect_is_on is not None:
        assert s.is_on is expect_is_on
    if expect_pending is not None:
        attrs = s.extra_state_attributes
        assert attrs is not None
        assert attrs.get("pending_notices") == expect_pending
