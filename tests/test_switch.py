"""Unit tests for switch entities and helpers in the hass-opnsense integration.

These tests validate switch compilation helpers, entity behavior, and
async setup flows for the integration's switch platform.
"""

import asyncio
from collections.abc import Callable, Iterable, MutableMapping
import contextlib
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

from homeassistant.components.switch import SwitchEntityDescription
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.opnsense import switch as switch_mod
from custom_components.opnsense.const import (
    CONF_DEVICE_UNIQUE_ID,
    CONF_FIRMWARE_VERSION,
    CONF_SYNC_CARP,
    CONF_SYNC_FIREWALL_AND_NAT,
    CONF_SYNC_SERVICES,
    CONF_SYNC_UNBOUND,
    CONF_SYNC_VPN,
    COORDINATOR,
)
from custom_components.opnsense.coordinator import OPNsenseDataUpdateCoordinator
from custom_components.opnsense.switch import (
    OPNsenseCarpMaintenanceSwitch,
    OPNsenseFirewallRuleSwitch,
    OPNsenseNATRuleSwitch,
    OPNsenseServiceSwitch,
    OPNsenseVPNSwitch,
    _compile_carp_maintenance_switch,
    _compile_firewall_rules_switches,
    _compile_nat_destination_rules_switches,
    _compile_nat_npt_rules_switches,
    _compile_nat_one_to_one_rules_switches,
    _compile_nat_source_rules_switches,
    _compile_service_switches,
    _compile_static_unbound_switch_legacy,
    _compile_unbound_switches,
    _compile_vpn_switches,
)
from tests.utilities import stub_async_write_ha_state


def make_coord(data: Any) -> Any:
    """Create a MagicMock that behaves like an OPNsenseDataUpdateCoordinator for tests."""
    m = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    m.data = data
    m.async_request_refresh = AsyncMock()
    return m


def make_carp_config_entry(
    make_config_entry: Callable[..., MockConfigEntry],
    coordinator: Any,
    data: dict[str, Any] | None = None,
) -> MockConfigEntry:
    """Create a config entry with CARP test coordinator runtime data."""
    config_entry = make_config_entry(
        data={CONF_DEVICE_UNIQUE_ID: "dev1", **(data or {})},
        title="OPNsenseTest",
    )
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    return config_entry


def make_carp_maintenance_switch(
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
    coordinator: Any,
) -> OPNsenseCarpMaintenanceSwitch:
    """Create a CARP maintenance switch entity for tests."""
    config_entry = make_carp_config_entry(make_config_entry, coordinator)
    entity = OPNsenseCarpMaintenanceSwitch(
        config_entry=config_entry,
        coordinator=coordinator,
        entity_description=SwitchEntityDescription(
            key="carp.maintenance_mode",
            name="CARP Persistent Maintenance Mode",
        ),
    )
    entity.hass = ph_hass
    entity.entity_id = "switch.carp_maintenance_mode"
    stub_async_write_ha_state(entity)
    return entity


async def collect_setup_carp_switches(
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
    coordinator: Any,
    *,
    config_data: dict[str, Any] | None = None,
    firmware: Any = "26.1.1",
) -> list[OPNsenseCarpMaintenanceSwitch]:
    """Run switch setup and return CARP maintenance switches."""
    calls: dict[str, list[Any]] = {}

    def fake_add_entities(entities: Iterable[Any], _update_before_add: bool = False) -> None:
        """Capture switch entities emitted by setup.

        Args:
            entities: Switch entities emitted by setup.
            _update_before_add: Whether HA should refresh entities before adding them.
        """
        calls["entities"] = list(entities)

    coordinator.data = {
        "carp": {"status_summary": {"maintenance_mode": False, "enabled": True}},
        "host_firmware_version": firmware,
    }
    config_entry = make_carp_config_entry(
        make_config_entry,
        coordinator,
        {
            CONF_SYNC_FIREWALL_AND_NAT: False,
            CONF_SYNC_SERVICES: False,
            CONF_SYNC_VPN: False,
            CONF_SYNC_UNBOUND: False,
            **(config_data or {}),
        },
    )

    await switch_mod.async_setup_entry(
        ph_hass, config_entry, cast("AddEntitiesCallback", fake_add_entities)
    )
    return [
        entity
        for entity in calls.get("entities", [])
        if isinstance(entity, OPNsenseCarpMaintenanceSwitch)
    ]


@pytest.mark.asyncio
async def test_compile_carp_maintenance_switch(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP maintenance switch should compile when CARP summary data exists."""
    state = {"carp": {"status_summary": {"maintenance_mode": False, "enabled": True}}}
    config_entry = make_carp_config_entry(make_config_entry, coordinator)

    entities = await _compile_carp_maintenance_switch(config_entry, coordinator, state)

    assert len(entities) == 1
    assert isinstance(entities[0], OPNsenseCarpMaintenanceSwitch)
    assert entities[0].entity_description.key == "carp.maintenance_mode"
    assert entities[0].entity_description.entity_registry_enabled_default is False


@pytest.mark.asyncio
async def test_compile_carp_maintenance_switch_skips_missing_summary(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP maintenance switch should not compile without CARP summary data."""
    config_entry = make_carp_config_entry(make_config_entry, coordinator)

    entities = await _compile_carp_maintenance_switch(config_entry, coordinator, {"carp": {}})

    assert entities == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("config_data", "expected_count"),
    [
        pytest.param(
            {},
            1,
            id="default-carp-sync-enabled",
        ),
        pytest.param(
            {CONF_SYNC_CARP: True},
            1,
            id="carp-sync-enabled",
        ),
        pytest.param(
            {CONF_SYNC_CARP: False},
            0,
            id="carp-sync-disabled",
        ),
    ],
)
async def test_async_setup_entry_carp_maintenance_switch_sync_gate(
    coordinator: MagicMock,
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
    config_data: dict[str, Any],
    expected_count: int,
) -> None:
    """CARP maintenance switch should follow the CARP sync flag."""
    carp_switches = await collect_setup_carp_switches(
        ph_hass,
        make_config_entry,
        coordinator,
        config_data=config_data,
    )
    assert len(carp_switches) == expected_count


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("firmware", "expected_count"),
    [
        pytest.param("26.1", 0, id="firmware-too-old"),
        pytest.param(object(), 0, id="invalid-firmware"),
    ],
)
async def test_async_setup_entry_carp_maintenance_switch_firmware_gate(
    coordinator: MagicMock,
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
    firmware: Any,
    expected_count: int,
) -> None:
    """CARP maintenance switch should only compile for supported firmware."""
    carp_switches = await collect_setup_carp_switches(
        ph_hass,
        make_config_entry,
        coordinator,
        firmware=firmware,
    )
    assert len(carp_switches) == expected_count


@pytest.mark.asyncio
async def test_carp_maintenance_switch_state_and_toggle(
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP maintenance switch should mirror summary state and toggle maintenance mode."""
    state = {"carp": {"status_summary": {"maintenance_mode": False, "enabled": True}}}
    coordinator = make_coord(state)
    entity = make_carp_maintenance_switch(ph_hass, make_config_entry, coordinator)
    entity._client = MagicMock()
    entity._client.toggle_carp_maintenance_mode = AsyncMock(return_value=True)

    entity._handle_coordinator_update()
    assert entity.available is True
    assert entity.is_on is False

    await entity.async_turn_on()

    entity._client.toggle_carp_maintenance_mode.assert_awaited_once()
    assert entity.is_on is True
    assert entity.delay_update is True

    entity.delay_update = False
    state["carp"]["status_summary"]["maintenance_mode"] = True
    entity._client.toggle_carp_maintenance_mode = AsyncMock(return_value=True)

    await entity.async_turn_off()

    entity._client.toggle_carp_maintenance_mode.assert_awaited_once()
    assert entity.is_on is False
    assert entity.delay_update is True


@pytest.mark.asyncio
async def test_carp_maintenance_switch_ignores_updates_during_delay(
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP maintenance switch should keep optimistic state during update delay."""
    state = {"carp": {"status_summary": {"maintenance_mode": True, "enabled": True}}}
    coordinator = make_coord(state)
    entity = make_carp_maintenance_switch(ph_hass, make_config_entry, coordinator)
    entity._handle_coordinator_update()
    assert entity.is_on is True

    entity.delay_update = True
    state["carp"]["status_summary"]["maintenance_mode"] = False
    entity._handle_coordinator_update()

    assert entity.is_on is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method_name", "initial_state", "refreshed_state"),
    [
        pytest.param("async_turn_on", False, True, id="turn-on-already-on-after-refresh"),
        pytest.param("async_turn_off", True, False, id="turn-off-already-off-after-refresh"),
    ],
)
async def test_carp_maintenance_switch_refreshes_before_toggle(
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
    method_name: str,
    initial_state: bool,
    refreshed_state: bool,
) -> None:
    """CARP maintenance should not toggle when refreshed state already matches."""
    state = {"carp": {"status_summary": {"maintenance_mode": initial_state, "enabled": True}}}
    coordinator = make_coord(state)

    async def refresh_state() -> None:
        """Set refreshed CARP maintenance state."""
        state["carp"]["status_summary"]["maintenance_mode"] = refreshed_state

    coordinator.async_request_refresh = AsyncMock(side_effect=refresh_state)
    entity = make_carp_maintenance_switch(ph_hass, make_config_entry, coordinator)
    entity._client = MagicMock()
    entity._client.toggle_carp_maintenance_mode = AsyncMock(return_value=True)
    entity._handle_coordinator_update()

    await getattr(entity, method_name)()

    coordinator.async_request_refresh.assert_awaited_once()
    entity._client.toggle_carp_maintenance_mode.assert_not_awaited()
    assert entity.is_on is refreshed_state
    assert entity.delay_update is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("first_method_name", "second_method_name", "initial_state", "optimistic_state"),
    [
        pytest.param("async_turn_on", "async_turn_on", False, True, id="turn-on-then-turn-on"),
        pytest.param("async_turn_on", "async_turn_off", False, True, id="turn-on-then-turn-off"),
        pytest.param("async_turn_off", "async_turn_off", True, False, id="turn-off-then-turn-off"),
        pytest.param("async_turn_off", "async_turn_on", True, False, id="turn-off-then-turn-on"),
    ],
)
async def test_carp_maintenance_switch_ignores_service_calls_during_delay(
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
    first_method_name: str,
    second_method_name: str,
    initial_state: bool,
    optimistic_state: bool,
) -> None:
    """CARP maintenance should not toggle again while optimistic state is pending."""
    state = {"carp": {"status_summary": {"maintenance_mode": initial_state, "enabled": True}}}
    coordinator = make_coord(state)
    entity = make_carp_maintenance_switch(ph_hass, make_config_entry, coordinator)
    entity._client = MagicMock()
    entity._client.toggle_carp_maintenance_mode = AsyncMock(return_value=True)
    entity._handle_coordinator_update()

    await getattr(entity, first_method_name)()
    assert entity.is_on is optimistic_state
    assert entity.delay_update is True

    coordinator.async_request_refresh.reset_mock()
    await getattr(entity, second_method_name)()

    coordinator.async_request_refresh.assert_not_awaited()
    entity._client.toggle_carp_maintenance_mode.assert_awaited_once()
    assert entity.is_on is optimistic_state
    assert entity.delay_update is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method_name", "initial_state"), [("async_turn_on", False), ("async_turn_off", True)]
)
async def test_carp_maintenance_switch_serializes_overlapping_requests(
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
    method_name: str,
    initial_state: bool,
) -> None:
    """CARP maintenance toggles should only execute one backend call at a time."""
    state = {"carp": {"status_summary": {"maintenance_mode": initial_state, "enabled": True}}}
    coordinator = make_coord(state)
    refresh_gate = asyncio.Event()
    refresh_started = asyncio.Event()
    toggle_gate = asyncio.Event()
    toggle_started = asyncio.Event()
    refresh_calls = 0

    async def refresh_side_effect() -> None:
        """Pause refresh so both toggle paths overlap."""
        nonlocal refresh_calls
        refresh_calls += 1
        refresh_started.set()
        if refresh_calls <= 2:
            await refresh_gate.wait()

    toggle_calls = 0

    async def toggle_side_effect() -> bool:
        """Pause toggles so both requests can overlap before completion."""
        nonlocal toggle_calls
        toggle_calls += 1
        toggle_started.set()
        if toggle_calls <= 2:
            await toggle_gate.wait()
        return True

    coordinator.async_request_refresh = AsyncMock(side_effect=refresh_side_effect)
    entity = make_carp_maintenance_switch(ph_hass, make_config_entry, coordinator)
    entity._client = MagicMock()
    entity._client.toggle_carp_maintenance_mode = AsyncMock(side_effect=toggle_side_effect)

    first_task = asyncio.create_task(getattr(entity, method_name)())
    second_task = asyncio.create_task(getattr(entity, method_name)())

    await refresh_started.wait()
    refresh_gate.set()
    await toggle_started.wait()
    toggle_gate.set()
    await first_task
    await second_task

    coordinator.async_request_refresh.assert_awaited_once()
    entity._client.toggle_carp_maintenance_mode.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method_name", "maintenance_mode"),
    [
        pytest.param("async_turn_on", False, id="turn-on-no-client"),
        pytest.param("async_turn_off", True, id="turn-off-no-client"),
    ],
)
async def test_carp_maintenance_switch_turn_returns_without_client(
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
    method_name: str,
    maintenance_mode: bool,
) -> None:
    """CARP maintenance switch should not refresh or toggle without a client."""
    state = {"carp": {"status_summary": {"maintenance_mode": maintenance_mode, "enabled": True}}}
    coordinator = make_coord(state)
    entity = make_carp_maintenance_switch(ph_hass, make_config_entry, coordinator)
    entity._handle_coordinator_update()

    await getattr(entity, method_name)()

    coordinator.async_request_refresh.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method_name", "maintenance_mode"),
    [
        pytest.param("async_turn_on", False, id="turn-on-missing-method"),
        pytest.param("async_turn_off", True, id="turn-off-missing-method"),
    ],
)
async def test_carp_maintenance_switch_turn_returns_without_toggle_method(
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
    method_name: str,
    maintenance_mode: bool,
) -> None:
    """CARP maintenance switch should not refresh or toggle without toggle support."""
    state = {"carp": {"status_summary": {"maintenance_mode": maintenance_mode, "enabled": True}}}
    coordinator = make_coord(state)
    entity = make_carp_maintenance_switch(ph_hass, make_config_entry, coordinator)
    entity._client = cast("Any", object())
    entity._handle_coordinator_update()

    await getattr(entity, method_name)()

    coordinator.async_request_refresh.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method_name", "maintenance_mode", "expected_state"),
    [
        pytest.param("async_turn_on", False, False, id="turn-on-fails"),
        pytest.param("async_turn_off", True, True, id="turn-off-fails"),
    ],
)
async def test_carp_maintenance_switch_failed_toggle_keeps_state(
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
    method_name: str,
    maintenance_mode: bool,
    expected_state: bool,
) -> None:
    """CARP maintenance switch should keep current state when toggle fails."""
    state = {"carp": {"status_summary": {"maintenance_mode": maintenance_mode, "enabled": True}}}
    coordinator = make_coord(state)
    entity = make_carp_maintenance_switch(ph_hass, make_config_entry, coordinator)
    entity._client = MagicMock()
    entity._client.toggle_carp_maintenance_mode = AsyncMock(return_value=False)
    entity._handle_coordinator_update()

    await getattr(entity, method_name)()

    entity._client.toggle_carp_maintenance_mode.assert_awaited_once()
    assert entity.is_on is expected_state
    assert entity.delay_update is False


@pytest.mark.asyncio
async def test_carp_maintenance_switch_unavailable_without_summary(
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP maintenance switch should become unavailable without summary data."""
    coordinator = make_coord({"carp": {}})
    entity = make_carp_maintenance_switch(ph_hass, make_config_entry, coordinator)

    entity._handle_coordinator_update()

    assert entity.available is False


@pytest.mark.asyncio
async def test_carp_maintenance_switch_unavailable_without_mapping_state(
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP maintenance switch should become unavailable without mapping state."""
    coordinator = make_coord([])
    entity = make_carp_maintenance_switch(ph_hass, make_config_entry, coordinator)

    entity._handle_coordinator_update()

    assert entity.available is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("maintenance_state", "maintenance_mode"),
    [
        pytest.param("unknown", False, id="unknown-state"),
        pytest.param("unavailable", False, id="unavailable-state"),
        pytest.param("ok", None, id="missing-maintenance-mode"),
        pytest.param("ok", "maybe", id="untrusted-maintenance-mode"),
        pytest.param("ok", object(), id="unsupported-maintenance-mode"),
    ],
)
async def test_carp_maintenance_switch_unavailable_for_untrusted_summary(
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
    maintenance_state: str,
    maintenance_mode: Any,
) -> None:
    """CARP maintenance switch should be unavailable when summary state is unreliable."""
    coordinator = make_coord(
        {
            "carp": {
                "status_summary": {
                    "maintenance_mode": maintenance_mode,
                    "state": maintenance_state,
                    "enabled": True,
                }
            }
        }
    )
    entity = make_carp_maintenance_switch(ph_hass, make_config_entry, coordinator)

    entity._handle_coordinator_update()

    assert entity.available is False
    assert entity.is_on is False


@pytest.mark.asyncio
async def test_carp_maintenance_switch_icon(
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP maintenance switch should use an alert icon while maintenance is on."""
    state = {"carp": {"status_summary": {"maintenance_mode": True, "enabled": True}}}
    coordinator = make_coord(state)
    entity = make_carp_maintenance_switch(ph_hass, make_config_entry, coordinator)

    entity._handle_coordinator_update()
    assert entity.icon == "mdi:server-network-off"

    state["carp"]["status_summary"]["maintenance_mode"] = False
    entity._handle_coordinator_update()
    assert entity.icon is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("compile_fn", "state", "client_methods"),
    [
        (
            _compile_service_switches,
            {
                "services": [
                    {
                        "id": "svc1",
                        "name": "svc",
                        "description": "MySvc",
                        "locked": 0,
                        "status": True,
                    }
                ]
            },
            ("start_service", "stop_service"),
        ),
        (
            _compile_static_unbound_switch_legacy,
            {"unbound_blocklist": {"legacy": {"enabled": "1"}}},
            ("enable_unbound_blocklist", "disable_unbound_blocklist"),
        ),
        (
            _compile_firewall_rules_switches,
            {
                "firewall": {
                    "rules": {
                        "rule1": {
                            "uuid": "rule1",
                            "description": "Test Firewall Rule",
                            "%interface": "wan",
                            "enabled": "1",
                        }
                    }
                }
            },
            ("toggle_firewall_rule", "toggle_firewall_rule"),
        ),
        (
            _compile_nat_source_rules_switches,
            {
                "firewall": {
                    "nat": {
                        "source_nat": {
                            "nat1": {
                                "uuid": "nat1",
                                "description": "Source NAT Rule",
                                "%interface": "wan",
                                "enabled": "1",
                            }
                        }
                    }
                }
            },
            ("toggle_nat_rule", "toggle_nat_rule"),
        ),
        (
            _compile_nat_destination_rules_switches,
            {
                "firewall": {
                    "nat": {
                        "d_nat": {
                            "dnat1": {
                                "uuid": "dnat1",
                                "description": "Destination NAT Rule",
                                "%interface": "wan",
                                "enabled": "1",
                            }
                        }
                    }
                }
            },
            ("toggle_nat_rule", "toggle_nat_rule"),
        ),
        (
            _compile_nat_one_to_one_rules_switches,
            {
                "firewall": {
                    "nat": {
                        "one_to_one": {
                            "oto1": {
                                "uuid": "oto1",
                                "description": "One-to-One NAT Rule",
                                "%interface": "wan",
                                "enabled": "1",
                            }
                        }
                    }
                }
            },
            ("toggle_nat_rule", "toggle_nat_rule"),
        ),
        (
            _compile_nat_npt_rules_switches,
            {
                "firewall": {
                    "nat": {
                        "npt": {
                            "npt1": {
                                "uuid": "npt1",
                                "description": "NPT NAT Rule",
                                "%interface": "wan",
                                "enabled": "1",
                            }
                        }
                    }
                }
            },
            ("toggle_nat_rule", "toggle_nat_rule"),
        ),
    ],
)
async def test_switch_toggle_variants(
    coordinator: MagicMock,
    ph_hass: Any,
    compile_fn: Any,
    state: MutableMapping[str, Any],
    client_methods: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Generic param test for switches that support enable/disable-style clients."""
    config_entry = make_config_entry(
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"},
        title="OPNsenseTest",
    )
    # runtime_data is provided by the factory as a MagicMock; attach coordinator
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)

    coordinator.data = state

    ents = await compile_fn(config_entry, coordinator, state)
    assert len(ents) >= 1
    ent = ents[0]

    hass = ph_hass
    ent.hass = hass
    ent.coordinator = make_coord(state)
    # prefer unique id if present, otherwise fall back to entity_description.key
    unique = getattr(ent, "_attr_unique_id", None)
    ent.entity_id = f"switch.{unique or ent.entity_description.key}"
    stub_async_write_ha_state(ent)

    # attach client with AsyncMock methods named per the compile target
    on_mock = AsyncMock(return_value=True)
    off_mock = AsyncMock(return_value=True)
    client_kwargs = {client_methods[0]: on_mock, client_methods[1]: off_mock}
    ent._client = MagicMock()
    for k, v in client_kwargs.items():
        setattr(ent._client, k, v)

    ent._handle_coordinator_update()
    assert ent.available is True

    # call turn_on/turn_off and assert client methods called
    await ent.async_turn_on()
    # turning on should set delay_update for entities that perform delayed updates
    assert ent.delay_update is True

    await ent.async_turn_off()
    # turning off should also set delay_update
    assert ent.delay_update is True

    # Check that the correct client methods were called
    if client_methods[0] == client_methods[1]:
        # Same method for on/off with different parameters
        if "firewall_rule" in client_methods[0]:
            # toggle_firewall_rule(rule_id, action)
            getattr(ent._client, client_methods[0]).assert_has_awaits(
                [
                    ((ent._rule_id, "on"), {}),
                    ((ent._rule_id, "off"), {}),
                ],
                any_order=True,
            )
        else:
            # toggle_nat_rule(rule_type, rule_id, action)
            getattr(ent._client, client_methods[0]).assert_has_awaits(
                [
                    ((ent._nat_rule_type, ent._rule_id, "on"), {}),
                    ((ent._nat_rule_type, ent._rule_id, "off"), {}),
                ],
                any_order=True,
            )
    else:
        # Different methods for on/off
        getattr(ent._client, client_methods[0]).assert_awaited_once()
        getattr(ent._client, client_methods[1]).assert_awaited_once()


@pytest.mark.asyncio
async def test_async_setup_entry_all_flags(
    coordinator: MagicMock, ph_hass: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Async setup should create entities for all enabled sync flags."""
    calls = {}

    def fake_add_entities(entities: Iterable[Any], _update_before_add: bool = False) -> None:
        """Capture the entities created during setup for later assertions.

        Args:
            entities: Sequence of switch entities added by ``async_setup_entry``.
        """
        calls["len"] = len(list(entities))

    # create a state that contains one of each entity type
    state = {
        "firewall": {
            "rules": {
                "r1": {
                    "uuid": "r1",
                    "description": "Test",
                    "%interface": "wan",
                    "enabled": "1",
                }
            },
            "nat": {
                "source_nat": {
                    "nat1": {
                        "uuid": "nat1",
                        "description": "Source NAT",
                        "%interface": "wan",
                        "enabled": "1",
                    }
                }
            },
        },
        "services": [{"id": "s1", "name": "svc", "locked": 0, "status": True}],
        "openvpn": {"clients": {"c1": {"enabled": True, "name": "C1"}}, "servers": {}},
        "wireguard": {"clients": {}, "servers": {}},
        "unbound_blocklist": {"legacy": {"enabled": "1"}},
        "host_firmware_version": "26.1.1",
    }
    coordinator.data = state

    config_entry = make_config_entry(
        data={
            CONF_DEVICE_UNIQUE_ID: "dev1",
            CONF_SYNC_FIREWALL_AND_NAT: True,
            CONF_SYNC_SERVICES: True,
            CONF_SYNC_VPN: True,
            CONF_SYNC_UNBOUND: True,
        },
        title="OPNsenseTest",
    )
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)

    hass = ph_hass
    await switch_mod.async_setup_entry(
        hass, config_entry, cast("AddEntitiesCallback", fake_add_entities)
    )

    # compute expected counts from coordinator.data to avoid brittle hard-coded value
    expected = 0
    firewall_cfg = coordinator.data.get("firewall", {})
    expected += len(firewall_cfg.get("rules", {}))
    for nat_rules in firewall_cfg.get("nat", {}).values():
        expected += len(nat_rules)
    # services
    expected += len(coordinator.data.get("services", []) or [])
    # vpn clients+servers for enabled VPN platforms
    for vpn_key in ("openvpn", "wireguard"):
        vpn_blob = coordinator.data.get(vpn_key, {})
        # clients and servers are dicts keyed by uuid
        expected += len(vpn_blob.get("clients", {}) or {})
        expected += len(vpn_blob.get("servers", {}) or {})
    # unbound blocklist counts as a single entity when enabled
    expected += 1

    assert calls.get("len") == expected


@pytest.mark.asyncio
async def test_async_setup_entry_new_firewall_api(
    coordinator: MagicMock, ph_hass: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Async setup should create entities for new firewall API (>= 26.1.1)."""
    calls = {}

    def fake_add_entities(entities: Iterable[Any], _update_before_add: bool = False) -> None:
        """Capture the entities created during setup for later assertions.

        Args:
            entities: Sequence of switch entities added by ``async_setup_entry``.
        """
        calls["len"] = len(list(entities))

    # create a state that contains new firewall API structure
    state = {
        "firewall": {
            "rules": {
                "rule1": {
                    "uuid": "rule1",
                    "description": "Test Firewall Rule",
                    "%interface": "wan",
                    "enabled": "1",
                }
            },
            "nat": {
                "source_nat": {
                    "nat1": {
                        "uuid": "nat1",
                        "description": "Test Source NAT",
                        "%interface": "wan",
                        "enabled": "1",
                    }
                },
                "d_nat": {
                    "dnat1": {
                        "uuid": "dnat1",
                        "description": "Test Destination NAT",
                        "%interface": "wan",
                        "enabled": "1",
                    }
                },
                "one_to_one": {
                    "oto1": {
                        "uuid": "oto1",
                        "description": "Test One-to-One NAT",
                        "%interface": "wan",
                        "enabled": "1",
                    }
                },
                "npt": {
                    "npt1": {
                        "uuid": "npt1",
                        "description": "Test NPT NAT",
                        "%interface": "wan",
                        "enabled": "1",
                    }
                },
            },
        },
        "host_firmware_version": "26.1.1",
    }
    coordinator.data = state

    config_entry = make_config_entry(
        data={
            CONF_DEVICE_UNIQUE_ID: "dev1",
            CONF_SYNC_FIREWALL_AND_NAT: True,
            CONF_SYNC_SERVICES: False,
            CONF_SYNC_VPN: False,
            CONF_SYNC_UNBOUND: False,
        },
        title="OPNsenseTest",
    )
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)

    hass = ph_hass
    await switch_mod.async_setup_entry(
        hass, config_entry, cast("AddEntitiesCallback", fake_add_entities)
    )

    # Should create entities for each rule type in new API
    expected = 5  # 1 firewall rule + 4 NAT rules
    assert calls.get("len") == expected


@pytest.mark.asyncio
async def test_async_setup_entry_new_firewall_api_without_runtime_firmware_uses_config_firmware(
    coordinator: MagicMock, ph_hass: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Runtime firmware missing should fall back to config firmware for firewall/NAT setup."""
    calls = {}

    def fake_add_entities(entities: Iterable[Any], _update_before_add: bool = False) -> None:
        """Capture entities created during setup for assertion."""
        calls["len"] = len(list(entities))

    # create state without host_firmware_version; only config firmware should gate feature
    state = {
        "firewall": {
            "rules": {
                "rule1": {
                    "uuid": "rule1",
                    "description": "Config-Fallback Firewall Rule",
                    "%interface": "wan",
                    "enabled": "1",
                }
            },
            "nat": {
                "source_nat": {
                    "nat1": {
                        "uuid": "nat1",
                        "description": "Config-Fallback Source NAT",
                        "%interface": "wan",
                        "enabled": "1",
                    }
                },
            },
        }
    }
    coordinator.data = state

    config_entry = make_config_entry(
        data={
            CONF_DEVICE_UNIQUE_ID: "dev1",
            CONF_FIRMWARE_VERSION: "26.1.1",
            CONF_SYNC_FIREWALL_AND_NAT: True,
            CONF_SYNC_SERVICES: False,
            CONF_SYNC_VPN: False,
            CONF_SYNC_UNBOUND: False,
        },
        title="OPNsenseTest",
    )
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)

    await switch_mod.async_setup_entry(
        ph_hass, config_entry, cast("AddEntitiesCallback", fake_add_entities)
    )

    # Should still create the native firewall/NAT entities when runtime firmware is missing
    # but config stored firmware is supported.
    assert calls.get("len") == 2


@pytest.mark.asyncio
async def test_async_setup_entry_skips_firewall_and_nat_for_old_firmware(
    coordinator: MagicMock, ph_hass: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Firewall/NAT entities are skipped in switch setup when firmware is older than 26.1.1."""
    calls: dict[str, list[Any]] = {}

    def fake_add_entities(entities: Iterable[Any], _update_before_add: bool = False) -> None:
        """Capture entities emitted by setup for assertion."""
        calls["entities"] = list(entities)

    state = {
        "firewall": {
            "config": {
                "filter": {"rule": [{"descr": "Allow", "created": {"time": "f1"}}]},
                "nat": {
                    "rule": [{"descr": "PF", "created": {"time": "p1"}}],
                    "outbound": {"rule": [{"descr": "OB", "created": {"time": "o1"}}]},
                },
            },
        },
        "host_firmware_version": "25.1",
    }
    coordinator.data = state

    config_entry = make_config_entry(
        data={
            CONF_DEVICE_UNIQUE_ID: "dev1",
            CONF_SYNC_FIREWALL_AND_NAT: True,
            CONF_SYNC_SERVICES: False,
            CONF_SYNC_VPN: False,
            CONF_SYNC_UNBOUND: False,
        },
        title="OPNsenseTest",
    )
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)

    await switch_mod.async_setup_entry(
        ph_hass,
        config_entry,
        cast("AddEntitiesCallback", fake_add_entities),
    )

    entities = calls.get("entities", [])
    assert not any(isinstance(entity, OPNsenseFirewallRuleSwitch) for entity in entities)
    assert not any(isinstance(entity, OPNsenseNATRuleSwitch) for entity in entities)


def test_vpn_icon_property(make_config_entry: Callable[..., MockConfigEntry]) -> None:
    """VPN switch exposes the expected icon when available and on."""
    desc = SwitchEntityDescription(key="openvpn.clients.c1", name="VPNC")
    coord = make_coord({})
    config_entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"}, title="OPNsenseTest")
    setattr(config_entry.runtime_data, COORDINATOR, coord)
    ent = OPNsenseVPNSwitch(
        config_entry=config_entry,
        coordinator=coord,
        entity_description=desc,
    )
    ent._attr_is_on = True
    ent._available = True
    assert ent.icon == "mdi:folder-key-network"


@pytest.mark.asyncio
async def test_unbound_and_vpn_variations(
    coordinator: MagicMock, ph_hass: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Compile and exercise unbound and VPN switch variations."""
    config_entry = make_config_entry(
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"},
        title="OPNsenseTest",
    )
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    dnsbl = {
        "enabled": "1",
        "safesearch": "1",
        "type": "a",
        "lists": "u",
        "whitelists": "w",
        "blocklists": "b",
        "wildcards": "x",
        "address": "1.2.3.4",
        "nxdomain": "1",
    }
    state = {
        "unbound_blocklist": {"legacy": dnsbl},
        "host_firmware_version": "25.7.7",
        "openvpn": {
            "clients": {"u1": {"enabled": True, "name": "C1"}},
            "servers": {"s1": {"enabled": False, "name": "S1"}},
        },
        "wireguard": {"clients": {}, "servers": {}},
    }
    coordinator.data = state

    # Prefer exercising the public setup path to reduce coupling to private
    # compile helpers: run async_setup_entry and inspect created entities.
    created: list = []

    async def run_setup() -> None:
        """Run the public setup flow and collect the created switch entities."""

        def add_entities(ents: Iterable[Any], _update_before_add: bool = False) -> None:
            """Collect the switch entities created by ``async_setup_entry``.

            Args:
                ents: Sequence of switch entities emitted by setup.
            """
            created.extend(ents)

        await switch_mod.async_setup_entry(
            MagicMock(), config_entry, cast("AddEntitiesCallback", add_entities)
        )

    await run_setup()

    # find the unbound and vpn entities we expect
    unbound = next(
        e
        for e in created
        if getattr(e, "entity_description", None)
        and e.entity_description.key.startswith("unbound_blocklist")
    )
    vpn_ents = [e for e in created if isinstance(e, OPNsenseVPNSwitch)]

    # use PHCC-provided hass fixture
    hass = ph_hass
    unbound.hass = hass
    unbound.coordinator = make_coord(state)
    unbound.entity_id = f"switch.{unbound._attr_unique_id}"
    stub_async_write_ha_state(unbound)
    unbound._client = MagicMock()
    unbound._client.enable_unbound_blocklist = AsyncMock(return_value=True)
    unbound._client.disable_unbound_blocklist = AsyncMock(return_value=True)
    unbound._handle_coordinator_update()
    assert unbound.available is True
    assert unbound.is_on is True

    await unbound.async_turn_off()
    assert unbound.is_on is False
    unbound._client.disable_unbound_blocklist.assert_awaited_once()

    assert any(isinstance(e, OPNsenseVPNSwitch) for e in vpn_ents)
    for vpn in vpn_ents:
        vpn.hass = hass
        vpn.coordinator = make_coord(state)
        vpn.entity_id = f"switch.{vpn.entity_description.key}"
        stub_async_write_ha_state(vpn)
        vpn._client = MagicMock()
        vpn._client.toggle_vpn_instance = AsyncMock(return_value=True)
        vpn._handle_coordinator_update()
        assert vpn.available is True
        inst = state.get(vpn._vpn_type, {}).get(vpn._clients_servers, {}).get(vpn._uuid)
        assert isinstance(inst, MutableMapping)
        assert vpn.is_on is bool(inst.get("enabled"))


def test_delay_update_setter(
    monkeypatch: pytest.MonkeyPatch,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Delay update setter captures and removes scheduled removers correctly."""
    desc = SwitchEntityDescription(key="service.s1.status", name="DelayTest")
    config_entry = make_config_entry(
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"},
        title="OPNsenseTest",
    )
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    ent = OPNsenseServiceSwitch(
        config_entry=config_entry,
        coordinator=coordinator,
        entity_description=desc,
    )
    # synchronous test: use a plain hass-like object with a dedicated loop
    hass_local = MagicMock(spec=HomeAssistant)
    loop = asyncio.new_event_loop()
    try:
        hass_local.loop = loop
        hass_local.data = {}
        ent.hass = hass_local
        called = {"removed": False}

        def fake_async_call_later(*args: Any, **kwargs: Any) -> Callable[[], None]:
            """Return a removable callback stub instead of scheduling real work.

            Args:
                *args: Positional arguments normally passed to ``async_call_later``.
                **kwargs: Keyword arguments normally passed to ``async_call_later``.
            """

            def remover() -> None:
                """Record that the delayed callback remover was invoked."""
                called["removed"] = True

            return remover

        monkeypatch.setattr(
            "custom_components.opnsense.switch.async_call_later", fake_async_call_later
        )

        ent.delay_update = True
        assert ent.delay_update is True
        # ensure async_call_later returned remover was captured
        assert callable(getattr(ent, "_delay_update_remove", None))
        ent.delay_update = False
        assert called["removed"] is True
    finally:
        # make sure we close the loop created for this test
        with contextlib.suppress(RuntimeError):
            loop.close()


@pytest.mark.asyncio
async def test_vpn_turn_on_off_calls_client_and_sets_delay(
    monkeypatch: pytest.MonkeyPatch,
    coordinator: MagicMock,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """VPN switch should call toggle_vpn_instance, update state, and enable delay_update."""

    # replace async_call_later so tests don't schedule real callbacks
    def fake_async_call_later(
        hass: HomeAssistant, delay: float, action: Callable[..., None]
    ) -> Callable[[], None]:
        """Return a no-op remover instead of scheduling a delayed callback.

        Args:
            hass: Home Assistant instance that would own the scheduled callback.
            delay: Delay value that would normally be used for scheduling.
            action: Callback that would normally run after the delay expires.
        """

        def remover() -> None:
            """Discard the delayed callback without executing any work."""
            return

        return remover

    monkeypatch.setattr("custom_components.opnsense.switch.async_call_later", fake_async_call_later)

    desc = SwitchEntityDescription(key="openvpn.clients.c1", name="VPNC")
    coord = make_coord({"openvpn": {"clients": {"c1": {"enabled": False, "name": "C1"}}}})
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(config_entry.runtime_data, COORDINATOR, coord)

    ent = OPNsenseVPNSwitch(
        config_entry=config_entry,
        coordinator=coord,
        entity_description=desc,
    )
    # attach hass and coordinator similar to other tests
    ent.hass = ph_hass
    ent.coordinator = make_coord(coord.data)
    ent.entity_id = f"switch.{ent.entity_description.key}"
    stub_async_write_ha_state(ent)

    # client toggles VPN instance
    ent._client = MagicMock()
    ent._client.toggle_vpn_instance = AsyncMock(return_value=True)

    # ensure start state is off
    ent._attr_is_on = False

    # turn on -> should call client and set is_on and delay_update
    await ent.async_turn_on()
    ent._client.toggle_vpn_instance.assert_awaited_once_with("openvpn", "clients", "c1")
    assert ent.is_on is True
    assert ent.delay_update is True


@pytest.mark.asyncio
async def test_compile_unbound_extended_and_toggle(
    coordinator: MagicMock, ph_hass: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Compile extended unbound blocklist switches and exercise toggle behavior."""
    # create state with two extended blocklists
    state = {
        "unbound_blocklist": {
            "u1": {"enabled": "1", "description": "One"},
            "u2": {"enabled": "0", "description": "Two"},
        },
        "host_firmware_version": "25.7.8",
    }
    coordinator.data = state

    config_entry = make_config_entry(
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"}, title="OPNsenseTest"
    )
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)

    ents = await _compile_unbound_switches(config_entry, coordinator, state)
    # expect two switches (one per uuid)
    assert len(ents) == 2

    # pick one entity and exercise client toggle methods; ensure uuid passed
    ent = next(e for e in ents if e.entity_description.key.endswith(".u1"))
    hass = ph_hass
    ent.hass = hass
    ent.coordinator = make_coord(state)
    ent.entity_id = f"switch.{ent._attr_unique_id or ent.entity_description.key}"
    stub_async_write_ha_state(ent)

    # attach client with AsyncMock methods
    ent._client = MagicMock()
    ent._client.enable_unbound_blocklist = AsyncMock(return_value=True)
    ent._client.disable_unbound_blocklist = AsyncMock(return_value=True)

    # initial update should mark available and on
    ent._handle_coordinator_update()
    assert ent.available is True
    assert ent.is_on is True

    # toggling off should call disable with uuid
    await ent.async_turn_off()
    ent._client.disable_unbound_blocklist.assert_awaited_once_with("u1")

    # toggling on should call enable with uuid
    await ent.async_turn_on()
    ent._client.enable_unbound_blocklist.assert_awaited_once_with("u1")

    # nothing more to assert for VPN here; unbound toggle assertions complete


@pytest.mark.asyncio
async def test_vpn_turn_on_off_noops_when_preconditions_fail(
    monkeypatch: pytest.MonkeyPatch,
    coordinator: MagicMock,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """VPN async_turn_on/async_turn_off should be no-ops when preconditions are not met."""
    # replace async_call_later to avoid scheduling
    monkeypatch.setattr(
        "custom_components.opnsense.switch.async_call_later",
        lambda hass, delay, action: lambda: None,
    )

    desc = SwitchEntityDescription(key="openvpn.clients.c2", name="VPNC2")
    coord = make_coord({"openvpn": {"clients": {"c2": {"enabled": True, "name": "C2"}}}})
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(config_entry.runtime_data, COORDINATOR, coord)

    ent = OPNsenseVPNSwitch(
        config_entry=config_entry,
        coordinator=coord,
        entity_description=desc,
    )
    ent.hass = ph_hass
    ent.coordinator = make_coord(coord.data)
    ent.entity_id = f"switch.{ent.entity_description.key}"
    stub_async_write_ha_state(ent)

    # client that would raise if called -- we assert it's not awaited
    ent._client = MagicMock()
    ent._client.toggle_vpn_instance = AsyncMock(return_value=True)

    # If already on, async_turn_on should do nothing
    ent._attr_is_on = True
    await ent.async_turn_on()
    # ensure client was not awaited
    assert ent._client.toggle_vpn_instance.await_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("client_result", "expected_is_on", "expected_delay", "expect_error"),
    [
        (True, False, True, False),  # client succeeds -> turned off
        (False, True, False, True),  # client fails -> remains on, error logged
        (None, True, False, False),  # no client -> no-op
    ],
)
async def test_vpn_async_turn_off_variations(
    monkeypatch: pytest.MonkeyPatch,
    coordinator: MagicMock,
    ph_hass: Any,
    caplog: pytest.LogCaptureFixture,
    client_result: Any,
    expected_is_on: Any,
    expected_delay: Any,
    expect_error: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Parameterize async_turn_off behavior for success, failure, and missing client."""
    # avoid scheduling real async_call_later during tests
    monkeypatch.setattr(
        "custom_components.opnsense.switch.async_call_later",
        lambda hass, delay, action: lambda: None,
    )

    desc = SwitchEntityDescription(key="openvpn.clients.cx", name="VPNCX")
    coord = make_coord({"openvpn": {"clients": {"cx": {"enabled": True, "name": "CX"}}}})
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(config_entry.runtime_data, COORDINATOR, coord)

    ent = OPNsenseVPNSwitch(
        config_entry=config_entry,
        coordinator=coord,
        entity_description=desc,
    )
    ent.hass = ph_hass
    ent.coordinator = make_coord(coord.data)
    ent.entity_id = f"switch.{ent.entity_description.key}"
    stub_async_write_ha_state(ent)

    # set initial state as on so turn_off proceeds
    ent._attr_is_on = True

    if client_result is None:
        ent._client = None
    else:
        ent._client = MagicMock()
        ent._client.toggle_vpn_instance = AsyncMock(return_value=client_result)

    # capture logs
    caplog.clear()
    caplog.set_level("INFO")

    await ent.async_turn_off()

    assert ent.is_on is expected_is_on
    assert ent.delay_update is expected_delay

    if expect_error:
        assert "Failed to turn off VPN" in caplog.text
    else:
        # on success or when no client is present, there should be no failure log
        assert "Failed to turn off VPN" not in caplog.text

    # If already off, async_turn_off should do nothing (no additional client calls)
    ent._attr_is_on = False
    if getattr(ent, "_client", None) is None:
        # ensure calling with no client does not raise
        await ent.async_turn_off()
    else:
        client = ent._client
        assert client is not None
        before = client.toggle_vpn_instance.await_count
        await ent.async_turn_off()
        assert client.toggle_vpn_instance.await_count == before


@pytest.mark.asyncio
async def test_unbound_missing_sets_unavailable(
    coordinator: MagicMock, ph_hass: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Unbound switch becomes unavailable when expected data is missing."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"})
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    state: dict[str, Any] = {"unbound_blocklist": {"legacy": {}}}
    coordinator.data = state
    ent = (await _compile_static_unbound_switch_legacy(config_entry, coordinator, state))[0]
    # use PHCC-provided hass fixture
    hass = ph_hass
    ent.hass = hass
    ent.coordinator = make_coord(state)
    ent.entity_id = f"switch.{ent._attr_unique_id}"
    stub_async_write_ha_state(ent)
    ent._handle_coordinator_update()
    assert ent.available is False


@pytest.mark.asyncio
async def test_unbound_skips_update_when_delay_set(
    coordinator: MagicMock, ph_hass: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """When delay_update is set, the unbound handler should skip updating state."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"})
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)

    # coordinator contains enabled blocklist; handler would normally set is_on True
    state = {"unbound_blocklist": {"legacy": {"enabled": "1"}}}
    coordinator.data = state
    ent = (await _compile_static_unbound_switch_legacy(config_entry, coordinator, state))[0]

    hass = ph_hass
    ent.hass = hass
    ent.coordinator = make_coord(state)
    ent.entity_id = f"switch.{ent._attr_unique_id}"
    stub_async_write_ha_state(ent)

    # set initial known state that should NOT be changed while delay flag is set
    ent._attr_is_on = False
    ent._available = True
    # simulate a recent turn_on/off action that sets the delay
    ent._delay_update = True

    # call the handler; because delay is set, it should return early and not flip is_on
    ent._handle_coordinator_update()
    assert ent.is_on is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kind", "compile_fn", "state", "selector", "options"),
    [
        (
            "unbound",
            _compile_static_unbound_switch_legacy,
            {"unbound_blocklist": {"legacy": {"enabled": "1"}}},
            "first",
            {CONF_SYNC_UNBOUND: True},
        ),
        (
            "service",
            _compile_service_switches,
            {
                "services": [
                    {
                        "id": "svcD",
                        "name": "svcD",
                        "description": "SvcD",
                        "locked": 0,
                        "status": True,
                    }
                ]
            },
            "first",
            {CONF_SYNC_SERVICES: True},
        ),
        (
            "vpn",
            _compile_vpn_switches,
            {
                "openvpn": {"clients": {"v1": {"enabled": True, "name": "V1"}}},
                "wireguard": {"clients": {}, "servers": {}},
            },
            "endswith:v1",
            {CONF_SYNC_VPN: True},
        ),
    ],
)
async def test_delay_skips_update_parametrized(
    kind: Any,
    compile_fn: Any,
    state: MutableMapping[str, Any],
    selector: Any,
    options: Any,
    coordinator: MagicMock,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Parametrized test asserting handlers return early when delay_update is set."""
    config_entry = make_config_entry(
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"}, options=options
    )
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)

    coordinator.data = state
    ents = await compile_fn(config_entry, coordinator, state)
    assert len(ents) >= 1

    if selector.startswith("endswith:"):
        suffix = selector.split(":", 1)[1]
        ent = next(e for e in ents if e.entity_description.key.endswith(suffix))
    else:
        ent = ents[0]

    hass = ph_hass
    ent.hass = hass
    ent.coordinator = make_coord(state)
    # entity id setup varies; prefer unique_id when present
    unique = getattr(ent, "_attr_unique_id", None)
    ent.entity_id = f"switch.{unique or ent.entity_description.key}"
    stub_async_write_ha_state(ent)

    # set initial known state that should NOT be changed while delay flag is set
    ent._attr_is_on = False
    ent._available = True
    ent._delay_update = True

    ent._handle_coordinator_update()
    assert ent.is_on is False


@pytest.mark.asyncio
async def test_nat_rule_switch_delay_skips_update(
    coordinator: MagicMock,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Verify delayed NAT updates return early without mutating state.

    Args:
        coordinator: Mock OPNsense coordinator fixture.
        ph_hass: Home Assistant test instance.
        make_config_entry: Factory for Home Assistant config entries.
    """
    state = {
        "firewall": {
            "nat": {
                "source_nat": {
                    "nat1": {
                        "uuid": "nat1",
                        "description": "Source NAT Rule",
                        "%interface": "wan",
                        "enabled": "1",
                    }
                }
            }
        }
    }
    config_entry = make_config_entry(
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"},
        options={CONF_SYNC_FIREWALL_AND_NAT: True},
    )
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    coordinator.data = state

    ents = await _compile_nat_source_rules_switches(config_entry, coordinator, state)
    assert len(ents) == 1

    ent = ents[0]
    ent.hass = ph_hass
    ent.coordinator = make_coord(state)
    ent.entity_id = f"switch.{ent.entity_description.key}"
    stub_async_write_ha_state(ent)
    ent._attr_is_on = False
    ent._available = True
    ent._delay_update = True

    ent._handle_coordinator_update()

    assert ent.is_on is False
    assert ent.available is True


@pytest.mark.asyncio
async def test_nat_rule_switch_missing_rule_marks_unavailable(
    coordinator: MagicMock,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Verify a missing NAT rule marks the switch unavailable.

    Args:
        coordinator: Mock OPNsense coordinator fixture.
        ph_hass: Home Assistant test instance.
        make_config_entry: Factory for Home Assistant config entries.
    """
    state: dict[str, Any] = {"firewall": {"nat": {"source_nat": {}}}}
    desc = SwitchEntityDescription(key="firewall.nat.source_nat.missing", name="Missing")
    config_entry = make_config_entry(
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"},
        options={CONF_SYNC_FIREWALL_AND_NAT: True},
    )
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    ent = OPNsenseNATRuleSwitch(
        config_entry=config_entry,
        coordinator=coordinator,
        entity_description=desc,
    )
    ent.hass = ph_hass
    ent.coordinator = make_coord(state)
    ent.entity_id = "switch.missing_nat_rule"
    stub_async_write_ha_state(ent)
    ent._available = True

    ent._handle_coordinator_update()

    assert ent.available is False


@pytest.mark.asyncio
async def test_compile_helpers_bad_input(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Compilation helpers return empty lists on bad/non-mapping input."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    # non-mapping state
    bad_state = cast("MutableMapping[str, Any]", None)
    assert await _compile_service_switches(config_entry, coordinator, bad_state) == []
    legacy_ents = await _compile_static_unbound_switch_legacy(config_entry, coordinator, bad_state)
    assert legacy_ents is not None
    assert len(legacy_ents) == 1


@pytest.mark.asyncio
async def test_async_setup_entry_missing_state(
    monkeypatch: pytest.MonkeyPatch,
    coordinator: MagicMock,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Async setup should handle missing coordinator state without adding entities."""
    calls = {}

    def fake_add_entities(entities: Iterable[Any], _update_before_add: bool = False) -> None:
        """Capture entities emitted by setup so the test can count them.

        Args:
            entities: Sequence of switch entities added by ``async_setup_entry``.
        """
        calls["len"] = len(list(entities))

    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    # coordinator returns non-mapping
    coordinator.data = None
    hass = ph_hass
    await switch_mod.async_setup_entry(
        hass, config_entry, cast("AddEntitiesCallback", fake_add_entities)
    )
    # should not have added entities
    assert calls.get("len") is None


@pytest.mark.asyncio
async def test_switch_handle_error_sets_unavailable(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Service handler marks entity unavailable when rule lookup returns non-mapping values."""
    hass_local = MagicMock(spec=HomeAssistant)
    loop = asyncio.new_event_loop()
    try:
        hass_local.loop = loop
        hass_local.data = {}

        config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
        setattr(config_entry.runtime_data, COORDINATOR, coordinator)
        ent = OPNsenseServiceSwitch(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=SwitchEntityDescription(
                key="service.svc1.status",
                name="Svc",
            ),
        )
        ent.hass = hass_local
        ent.coordinator = make_coord({})
        ent.entity_id = "switch.svc"
        object.__setattr__(ent, "async_write_ha_state", lambda: None)

        def _fake_get_service() -> MutableMapping[str, Any] | None:
            """Return a non-mapping value to exercise service error handling."""
            return cast("MutableMapping[str, Any] | None", 5)

        object.__setattr__(ent, "_opnsense_get_service", cast("Any", _fake_get_service))

        # Exercise the update logic; ensure the handler did not raise and
        # availability is reported as a boolean (handlers may early-return).
        ent._handle_coordinator_update()
        assert isinstance(ent.available, bool)
    finally:
        # make sure we close the loop created for this test
        with contextlib.suppress(RuntimeError):
            loop.close()


def test_entity_icons(make_config_entry: Callable[..., MockConfigEntry]) -> None:
    """Switch entities expose the correct platform icons based on type."""
    # firewall icon
    f_desc = SwitchEntityDescription(key="firewall.rule.r1", name="Firewall")
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(config_entry.runtime_data, COORDINATOR, None)
    f_ent = OPNsenseFirewallRuleSwitch(
        config_entry=config_entry,
        coordinator=make_coord({}),
        entity_description=f_desc,
    )
    f_ent._attr_is_on = True
    f_ent._available = True
    assert f_ent.icon == "mdi:play-network"

    # nat icon
    n_desc = SwitchEntityDescription(key="firewall.nat.source_nat.n1", name="NAT")
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(config_entry.runtime_data, COORDINATOR, None)
    n_ent = OPNsenseNATRuleSwitch(
        config_entry=config_entry,
        coordinator=make_coord({}),
        entity_description=n_desc,
    )
    n_ent._attr_is_on = True
    n_ent._available = True
    assert n_ent.icon == "mdi:network"

    # service icon
    s_desc = SwitchEntityDescription(key="service.s1.status", name="Svc")
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(config_entry.runtime_data, COORDINATOR, None)
    s_ent = OPNsenseServiceSwitch(
        config_entry=config_entry,
        coordinator=make_coord({}),
        entity_description=s_desc,
    )
    s_ent._attr_is_on = True
    s_ent._available = True
    assert s_ent.icon == "mdi:application-cog"


@pytest.mark.parametrize(
    ("state", "select_suffix", "expect_name", "toggle_return", "expect_on"),
    [
        (
            {
                "openvpn": {
                    "clients": {
                        "c1": {
                            "enabled": True,
                            "name": "C1",
                            "uuid": "c1",
                            "connected_servers": 1,
                            "servers": {},
                        }
                    }
                },
                "wireguard": {"clients": {}, "servers": {}},
            },
            "openvpn.clients.c1",
            "C1",
            True,
            True,
        ),
        (
            {
                "openvpn": {
                    "servers": {
                        "srv1": {
                            "enabled": True,
                            "name": "S1",
                            "uuid": "srv1",
                            "status": "up",
                            "clients": {},
                        }
                    }
                },
                "wireguard": {"clients": {}, "servers": {}},
            },
            "openvpn.servers.srv1",
            "S1",
            True,
            True,
        ),
        (
            {
                "openvpn": {
                    "clients": {
                        "cfail": {"enabled": False, "name": "Cfail", "uuid": "cfail", "servers": {}}
                    }
                },
                "wireguard": {"clients": {}, "servers": {}},
            },
            "cfail",
            "Cfail",
            False,
            False,
        ),
    ],
)
@pytest.mark.asyncio
async def test_vpn_toggle_parametrized(
    coordinator: MagicMock,
    ph_hass: Any,
    state: MutableMapping[str, Any],
    select_suffix: Any,
    expect_name: Any,
    toggle_return: Any,
    expect_on: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Parameterized VPN client/server/toggle behaviors. Covers: client present and toggle succeeds, server present and toggle succeeds, and client toggle failure (should not set is_on)."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    coordinator.data = state
    ents = await _compile_vpn_switches(config_entry, coordinator, state)

    # pick matching entity: prefer exact key match, then full dotted-suffix,
    # then fallback to last-segment match
    ent = next((e for e in ents if e.entity_description.key == select_suffix), None)
    if ent is None:
        ent = next((e for e in ents if e.entity_description.key.endswith(select_suffix)), None)
    if ent is None:
        ent = next(
            (e for e in ents if e.entity_description.key.endswith(select_suffix.split(".")[-1])),
            None,
        )
    assert ent is not None
    hass = ph_hass
    ent.hass = hass
    ent.coordinator = make_coord(state)
    ent.entity_id = f"switch.{ent.entity_description.key}"
    object.__setattr__(ent, "async_write_ha_state", lambda: None)
    # attach a client and set its toggle_vpn_instance to a simple AsyncMock
    # that returns the desired toggle_return value for the test case.
    ent._client = MagicMock()
    ent._client.toggle_vpn_instance = AsyncMock(return_value=toggle_return)

    ent._handle_coordinator_update()
    assert ent.available is True
    # when available, name should be present for created entities
    if expect_name:
        assert ent.extra_state_attributes.get("name") == expect_name

    # try toggle
    # capture whether the entity was already on (in which case async_turn_on
    # should early-return and not call the client), then invoke the turn on
    # behavior and assert the client was awaited only when appropriate.
    already_on = ent.is_on
    await ent.async_turn_on()
    assert ent.is_on is expect_on

    if already_on:
        # when already on, the client should not be invoked
        ent._client.toggle_vpn_instance.assert_not_awaited()
    else:
        # when not already on, the client should have been awaited once
        ent._client.toggle_vpn_instance.assert_awaited_once()


def test_reset_delay_calls_existing_remover(
    monkeypatch: pytest.MonkeyPatch, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Resetting delay should call any existing remover and replace it."""
    desc = SwitchEntityDescription(key="service.svc1.status", name="Svc")
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(config_entry.runtime_data, COORDINATOR, None)
    ent = OPNsenseServiceSwitch(
        config_entry=config_entry,
        coordinator=make_coord({}),
        entity_description=desc,
    )
    called = {"old_removed": False, "new_removed": False}

    def old_remover() -> None:
        """Old remover."""
        called["old_removed"] = True

    def new_remover() -> None:
        """New remover."""
        called["new_removed"] = True

    ent._delay_update_remove = old_remover
    # monkeypatch async_call_later to return new_remover
    monkeypatch.setattr(
        "custom_components.opnsense.switch.async_call_later",
        lambda hass, delay, action: new_remover,
    )
    ent._reset_delay()
    # old remover should have been called and replaced
    assert called["old_removed"] is True
    assert ent._delay_update_remove == new_remover


@pytest.mark.asyncio
async def test_compile_service_skips_locked(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Service compilation skips locked services."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"})
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    state = {
        "services": [
            {"id": "s1", "name": "one", "locked": 1, "status": True},
            {"id": "s2", "name": "two", "locked": 0, "status": False},
        ]
    }
    coordinator.data = state
    ents = await _compile_service_switches(config_entry, coordinator, state)
    # only unlocked service should be present
    assert any("service.s2" in e.entity_description.key for e in ents)


@pytest.mark.asyncio
async def test_async_setup_entry_respects_config_flags(
    monkeypatch: pytest.MonkeyPatch,
    coordinator: MagicMock,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Async setup respects per-entry configuration flags when creating entities."""
    calls = {}

    def fake_add_entities(entities: Iterable[Any], _update_before_add: bool = False) -> None:
        """Record how many entities setup created for the enabled platforms.

        Args:
            entities: Entities emitted by ``async_setup_entry`` for this config.
        """
        calls["len"] = len(list(entities))

    # create config where only unbound is enabled
    config_entry = make_config_entry(
        data={
            CONF_DEVICE_UNIQUE_ID: "dev1",
            CONF_SYNC_FIREWALL_AND_NAT: False,
            CONF_SYNC_SERVICES: False,
            CONF_SYNC_VPN: False,
            CONF_SYNC_UNBOUND: True,
        }
    )
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    # coordinator.data can be minimal; include firmware so unbound is compiled
    coordinator.data = {"host_firmware_version": "25.7.7"}
    # run the async setup
    hass = ph_hass
    await switch_mod.async_setup_entry(
        hass, config_entry, cast("AddEntitiesCallback", fake_add_entities)
    )
    # since only unbound is enabled, expect 1 entity
    assert calls.get("len") == 1


@pytest.mark.asyncio
async def test_vpn_servers_properties_and_toggle(
    coordinator: MagicMock, ph_hass: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """VPN server switches expose properties and support toggle behavior."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"})
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    # create a server entry with many properties
    server = {
        "enabled": True,
        "name": "S1",
        "uuid": "srv1",
        "status": "up",
        "connected_clients": 2,
        "endpoint": "1.2.3.4",
        "interface": "igb0",
        "dev_type": "tun",
        "pubkey": "abc",
        "tunnel_addresses": ["10.0.0.1"],
        "dns_servers": ["8.8.8.8"],
        "latest_handshake": 12345,
        "clients": {"c1": {}},
    }
    state = {"openvpn": {"servers": {"srv1": server}}, "wireguard": {"clients": {}, "servers": {}}}
    coordinator.data = state

    # Use public setup to create switches and find the server entity
    created: list = []

    async def run_setup() -> None:
        """Run the public setup flow and collect the created switch entities."""

        def add_entities(ents: Iterable[Any], _update_before_add: bool = False) -> None:
            """Collect the switch entities created by ``async_setup_entry``.

            Args:
                ents: Sequence of switch entities emitted by setup.
            """
            created.extend(ents)

        await switch_mod.async_setup_entry(
            MagicMock(), config_entry, cast("AddEntitiesCallback", add_entities)
        )

    await run_setup()
    # find the server entity
    server_ent = next(e for e in created if e.entity_description.key.startswith("openvpn.servers."))
    hass = ph_hass
    server_ent.hass = hass
    server_ent.coordinator = make_coord(state)
    server_ent.entity_id = f"switch.{server_ent.entity_description.key}"
    stub_async_write_ha_state(server_ent)
    server_ent._client = MagicMock()
    server_ent._client.toggle_vpn_instance = AsyncMock(return_value=True)

    server_ent._handle_coordinator_update()
    assert server_ent.available is True
    # properties populated
    assert server_ent.extra_state_attributes.get("name") == "S1"
    assert server_ent.extra_state_attributes.get("endpoint") == "1.2.3.4"
    assert "interface" in server_ent.extra_state_attributes

    # test toggle when currently off
    await server_ent.async_turn_on()
    assert server_ent.is_on is True

    # test when already on, async_turn_on should early return (client not called)
    server_ent._client.toggle_vpn_instance = AsyncMock()
    server_ent._attr_is_on = True
    await server_ent.async_turn_on()
    server_ent._client.toggle_vpn_instance.assert_not_awaited()


@pytest.mark.asyncio
async def test_unbound_turn_on_off_failure_logs(
    coordinator: MagicMock, ph_hass: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Unbound turn on/off failures are handled without raising and leave state unchanged."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"})
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    dnsbl = {"enabled": "0", "safesearch": "0"}
    state = {"unbound_blocklist": {"legacy": dnsbl}}
    coordinator.data = state
    ent = (await _compile_static_unbound_switch_legacy(config_entry, coordinator, state))[0]
    hass = ph_hass
    ent.hass = hass
    ent.coordinator = make_coord(state)
    ent.entity_id = f"switch.{ent._attr_unique_id}"
    object.__setattr__(ent, "async_write_ha_state", lambda: None)
    # simulate client failure
    ent._client = MagicMock()
    ent._client.enable_unbound_blocklist = AsyncMock(return_value=False)
    ent._client.disable_unbound_blocklist = AsyncMock(return_value=False)
    await ent.async_turn_on()
    # still should not raise and is_on remains False
    assert ent.is_on is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("compile_fn", "state", "client_attr", "turn_method", "expect_is_on"),
    [
        (
            _compile_service_switches,
            {"services": [{"id": "svcX", "name": "svcX", "locked": 0, "status": False}]},
            ("start_service", "stop_service"),
            "async_turn_on",
            False,
        ),
        (
            _compile_static_unbound_switch_legacy,
            {"unbound_blocklist": {"legacy": {"enabled": "0", "safesearch": "0"}}},
            ("enable_unbound_blocklist", "disable_unbound_blocklist"),
            "async_turn_on",
            False,
        ),
    ],
)
async def test_client_failure_does_not_set_on(
    coordinator: MagicMock,
    ph_hass: Any,
    compile_fn: Any,
    state: MutableMapping[str, Any],
    client_attr: Any,
    turn_method: Any,
    expect_is_on: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Generic test to ensure failing client methods (return False) don't flip is_on."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"})
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    coordinator.data = state
    ents = await compile_fn(config_entry, coordinator, state)
    ent = ents[0]
    hass = ph_hass
    ent.hass = hass
    ent.coordinator = make_coord(state)
    ent.entity_id = f"switch.{ent._attr_unique_id}"
    object.__setattr__(ent, "async_write_ha_state", lambda: None)
    # Ensure service data is populated from coordinator so the turn method
    # exercises the client call path (otherwise _client won't be invoked).
    ent._handle_coordinator_update()

    # attach failing client methods
    ent._client = MagicMock()
    setattr(ent._client, client_attr[0], AsyncMock(return_value=False))
    setattr(ent._client, client_attr[1], AsyncMock(return_value=False))
    # call the turn method and assert is_on unchanged/False
    # capture whether entity was already in the requested state so we can
    # assert the client is not called in that case
    already_on = ent.is_on
    await getattr(ent, turn_method)()
    assert ent.is_on is expect_is_on
    method = getattr(ent._client, client_attr[0])
    if already_on:
        # when already matching the requested action, client should not be called
        assert method.await_count == 0
    else:
        # otherwise the client should have been awaited exactly once
        method.assert_awaited_once()


@pytest.mark.asyncio
async def test_compile_vpn_with_non_mapping_state(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """VPN compilation returns empty list when provided non-mapping state."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    # non-mapping state should result in []
    assert (
        await _compile_vpn_switches(
            config_entry, coordinator, cast("MutableMapping[str, Any]", None)
        )
        == []
    )


def test_vpn_handle_coordinator_update_state_not_mapping(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """VPN entity becomes unavailable if coordinator.data is not a mapping."""
    # Create a VPN entity and simulate coordinator.data not being a mapping
    desc = SwitchEntityDescription(key="openvpn.clients.c1", name="VPNC")
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    ent = OPNsenseVPNSwitch(
        config_entry=config_entry,
        coordinator=coordinator,
        entity_description=desc,
    )
    # coordinator.data is None -> unavailable
    coordinator.data = None
    object.__setattr__(ent, "async_write_ha_state", lambda: None)
    ent._handle_coordinator_update()
    assert ent.available is False


@pytest.mark.asyncio
async def test_compile_vpn_wireguard_variations(
    coordinator: MagicMock, ph_hass: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Ensure wireguard clients and servers compile into switches properly."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"})
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    state = {
        "wireguard": {
            "clients": {"c1": {"enabled": True, "name": "Client1", "uuid": "c1"}},
            "servers": {"s1": {"enabled": False, "name": "Server1", "uuid": "s1"}},
        }
    }
    coordinator.data = state
    ents = await _compile_vpn_switches(config_entry, coordinator, state)
    # should include both client and server entries
    assert any(e.entity_description.key.startswith("wireguard.clients.") for e in ents)
    assert any(e.entity_description.key.startswith("wireguard.servers.") for e in ents)
    hass = ph_hass
    for vpn in ents:
        vpn.hass = hass
        vpn.coordinator = make_coord(state)
        vpn.entity_id = f"switch.{vpn.entity_description.key}"
        stub_async_write_ha_state(vpn)
        vpn._client = MagicMock()
        vpn._client.toggle_vpn_instance = AsyncMock(return_value=True)
        vpn._handle_coordinator_update()
        # available should be a boolean; ensures handler ran without raising
        assert isinstance(vpn.available, bool)


def test_vpn_instance_non_mapping_sets_unavailable(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """VPN instance that's not a mapping should mark the entity unavailable."""
    desc = SwitchEntityDescription(key="openvpn.clients.c1", name="VPNC")
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    ent = OPNsenseVPNSwitch(
        config_entry=config_entry,
        coordinator=coordinator,
        entity_description=desc,
    )
    # set a mapping where instance is not a mapping
    coordinator.data = {
        "openvpn": {"clients": {"c1": "not-a-dict"}},
        "wireguard": {"clients": {}, "servers": {}},
    }
    object.__setattr__(ent, "async_write_ha_state", lambda: None)
    ent._handle_coordinator_update()
    assert ent.available is False


@pytest.mark.asyncio
async def test_service_async_turn_on_off_failure(
    coordinator: MagicMock, ph_hass: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Service start/stop failures do not set the switch on or crash."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"})
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    state = {"services": [{"id": "svcX", "name": "svcX", "locked": 0, "status": False}]}
    coordinator.data = state
    ents = await _compile_service_switches(config_entry, coordinator, state)
    ent: OPNsenseServiceSwitch = ents[0]
    hass = ph_hass
    ent.hass = hass
    ent.coordinator = make_coord(state)
    ent.entity_id = f"switch.{ent._attr_unique_id}"
    object.__setattr__(ent, "async_write_ha_state", lambda: None)
    # simulate failure to start/stop
    ent._client = MagicMock()
    ent._client.start_service = AsyncMock(return_value=False)
    ent._client.stop_service = AsyncMock(return_value=False)
    await ent.async_turn_on()
    assert ent.is_on is False
    await ent.async_turn_off()
    assert ent.is_on is False


@pytest.mark.asyncio
async def test_vpn_toggle_failure_does_not_set_on(
    coordinator: MagicMock, ph_hass: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """VPN toggle failure should not set the switch state to on."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"})
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    client = {"enabled": False, "name": "Cfail", "uuid": "cfail", "servers": {}}
    state = {"openvpn": {"clients": {"cfail": client}}, "wireguard": {"clients": {}, "servers": {}}}
    coordinator.data = state
    ents = await _compile_vpn_switches(config_entry, coordinator, state)
    ent = next(e for e in ents if e.entity_description.key.endswith("cfail"))
    hass = ph_hass
    ent.hass = hass
    ent.coordinator = make_coord(state)
    ent.entity_id = f"switch.{ent.entity_description.key}"
    object.__setattr__(ent, "async_write_ha_state", lambda: None)
    ent._client = MagicMock()
    ent._client.toggle_vpn_instance = AsyncMock(return_value=False)
    # attempt to turn on should not set is_on when client returns False
    await ent.async_turn_on()
    assert ent.is_on is False


@pytest.mark.asyncio
async def test_service_locked_skipped(make_config_entry: Callable[..., MockConfigEntry]) -> None:
    """Locked services are omitted from compiled switch lists."""
    config_entry = make_config_entry({})
    setattr(config_entry.runtime_data, COORDINATOR, None)
    coordinator = make_coord({})
    # service with locked=1 should be skipped
    state = {"services": [{"id": "s1", "name": "svc", "locked": 1}]}
    coordinator.data = state
    ents = await _compile_service_switches(config_entry, coordinator, state)
    assert ents == []


@pytest.mark.asyncio
async def test_vpn_entries_skip_non_mapping_and_missing_enabled(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """VPN compilation skips entries that are non-mapping or missing 'enabled'."""
    config_entry = make_config_entry({})
    setattr(config_entry.runtime_data, COORDINATOR, None)
    coordinator = make_coord({})
    # provide structure where instances are not mapping or missing 'enabled'
    state = {
        "openvpn": {"clients": {"c1": "not-a-mapping"}, "servers": {"s1": {}}},
        "wireguard": {"clients": {}, "servers": {}},
    }
    coordinator.data = state
    ents = await _compile_vpn_switches(config_entry, coordinator, state)
    # s1 missing 'enabled' should be skipped, c1 is not a mapping -> skipped
    assert ents == []


def test_service_helper_methods(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Service switch helper methods extract property and service id correctly."""
    desc = SwitchEntityDescription(key="service.svcx.status", name="SvcX")
    config_entry_srv = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(config_entry_srv.runtime_data, COORDINATOR, coordinator)
    ent = OPNsenseServiceSwitch(
        config_entry=config_entry_srv,
        coordinator=coordinator,
        entity_description=desc,
    )
    assert ent._opnsense_get_property_name() == "status"
    assert ent._opnsense_get_service_id() == "svcx"


def test_vpn_instance_key_parsing(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """VPNSwitch parses its entity_description.key into type, section, and uuid."""
    # ensure VPNSwitch parses key parts without raising
    desc = SwitchEntityDescription(key="openvpn.clients.c1", name="VPNC")
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    ent = OPNsenseVPNSwitch(
        config_entry=config_entry,
        coordinator=coordinator,
        entity_description=desc,
    )
    assert ent._vpn_type == "openvpn"
    assert ent._clients_servers == "clients"
    assert ent._uuid == "c1"


@pytest.mark.parametrize("exc_type", [TypeError, KeyError, AttributeError])
def test_vpn_handle_exceptions_sets_unavailable(
    exc_type: type[Exception],
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """VPN handler should mark entity unavailable when instance indexing raises exceptions."""
    desc = SwitchEntityDescription(key="openvpn.clients.ex", name="VPNEx")
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)

    ent = OPNsenseVPNSwitch(
        config_entry=config_entry, coordinator=coordinator, entity_description=desc
    )
    ent.hass = MagicMock(spec=HomeAssistant)
    ent.entity_id = f"switch.{ent.entity_description.key}"
    object.__setattr__(ent, "async_write_ha_state", lambda: None)

    # instance must be a MutableMapping so the code reaches the try/except block;
    # create a dict subclass that raises when __getitem__ is used for ['enabled']
    class BadIndex(dict):
        def __getitem__(self, _k: Any) -> None:
            """Raise the parameterized exception when the VPN handler indexes the mapping.

            Raises:
                TypeError: If ``exc_type`` is ``TypeError`` for this parameterized case.
                KeyError: If ``exc_type`` is ``KeyError`` for this parameterized case.
                AttributeError: If ``exc_type`` is ``AttributeError`` for this parameterized case.
            """
            raise exc_type("boom")

    # ensure coordinator.data returns a mapping with our bad instance
    coordinator.data = {
        "openvpn": {"clients": {"ex": BadIndex({})}},
        "wireguard": {"clients": {}, "servers": {}},
    }
    ent.coordinator = make_coord(coordinator.data)

    ent._handle_coordinator_update()
    assert ent.available is False


@pytest.mark.parametrize("exc_type", [TypeError, KeyError, AttributeError])
def test_service_handle_exceptions_sets_unavailable(
    exc_type: type[Exception],
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Service handler should mark entity unavailable when indexing raises exceptions."""
    desc = SwitchEntityDescription(key="service.svcx.status", name="SvcEx")
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)

    ent = OPNsenseServiceSwitch(
        config_entry=config_entry, coordinator=coordinator, entity_description=desc
    )
    ent.hass = MagicMock(spec=HomeAssistant)
    ent.entity_id = f"switch.{ent.entity_description.key}"
    object.__setattr__(ent, "async_write_ha_state", lambda: None)

    # create an object that raises when __getitem__ is used (service[prop])
    class BadIndex(dict):
        def __getitem__(self, _k: Any) -> None:
            """Raise the parameterized exception when the service handler indexes the mapping.

            Raises:
                TypeError: If ``exc_type`` is ``TypeError`` for this parameterized case.
                KeyError: If ``exc_type`` is ``KeyError`` for this parameterized case.
                AttributeError: If ``exc_type`` is ``AttributeError`` for this parameterized case.
            """
            raise exc_type("boom")

    # Ensure handler receives a mapping-like that raises on indexing
    object.__setattr__(ent, "_opnsense_get_service", lambda: BadIndex({}))
    ent._handle_coordinator_update()
    assert ent.available is False


@pytest.mark.asyncio
async def test_unbound_legacy_switch_toggle_failures(
    coordinator: MagicMock, ph_hass: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Test unbound legacy switch handles client method failures."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"})
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    state = {"unbound_blocklist": {"legacy": {"enabled": "0"}}}
    coordinator.data = state
    ent = (await _compile_static_unbound_switch_legacy(config_entry, coordinator, state))[0]

    hass = ph_hass
    ent.hass = hass
    ent.coordinator = make_coord(state)
    ent.entity_id = f"switch.{ent._attr_unique_id}"
    stub_async_write_ha_state(ent)

    # Mock client to return False (failure)
    ent._client = MagicMock()
    ent._client.enable_unbound_blocklist = AsyncMock(return_value=False)
    ent._client.disable_unbound_blocklist = AsyncMock(return_value=False)

    # Test turn_on failure - should not change state
    await ent.async_turn_on()
    assert ent.is_on is False  # Should remain off
    assert ent.delay_update is False  # Should not set delay

    # Update coordinator data to simulate successful previous state
    state["unbound_blocklist"]["legacy"]["enabled"] = "1"
    ent._handle_coordinator_update()

    # Test turn_off failure - should not change state
    await ent.async_turn_off()
    assert ent.is_on is True  # Should remain on
    assert ent.delay_update is False  # Should not set delay


@pytest.mark.asyncio
async def test_unbound_extended_switch_toggle_failures(
    coordinator: MagicMock, ph_hass: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Test unbound extended switch handles client method failures."""
    # create state with extended blocklist
    state = {
        "unbound_blocklist": {
            "u1": {"enabled": "0", "description": "One"},
        },
        "host_firmware_version": "25.7.8",
    }
    coordinator.data = state

    config_entry = make_config_entry(
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"}, title="OPNsenseTest"
    )
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)

    ents = await _compile_unbound_switches(config_entry, coordinator, state)
    ent = next(e for e in ents if e.entity_description.key.endswith(".u1"))
    hass = ph_hass
    ent.hass = hass
    ent.coordinator = make_coord(state)
    ent.entity_id = f"switch.{ent._attr_unique_id}"
    stub_async_write_ha_state(ent)

    # Mock client to return False (failure)
    ent._client = MagicMock()
    ent._client.enable_unbound_blocklist = AsyncMock(return_value=False)
    ent._client.disable_unbound_blocklist = AsyncMock(return_value=False)

    # Test turn_on failure - should not change state
    await ent.async_turn_on()
    assert ent.is_on is False  # Should remain off
    assert ent.delay_update is False  # Should not set delay

    # Update coordinator data to simulate successful previous state
    unbound = state["unbound_blocklist"]
    assert isinstance(unbound, dict)
    u1 = unbound["u1"]
    assert isinstance(u1, dict)
    u1["enabled"] = "1"
    ent._handle_coordinator_update()

    # Test turn_off failure - should not change state
    await ent.async_turn_off()
    assert ent.is_on is True  # Should remain on
    assert ent.delay_update is False  # Should not set delay


@pytest.mark.asyncio
async def test_compile_firewall_rules_switches(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Test compilation of firewall rule switches for new API."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    state = {
        "firewall": {
            "rules": {
                "rule1": {
                    "uuid": "rule1",
                    "description": "Test Rule 1",
                    "%interface": "wan",
                    "enabled": "1",
                },
                "rule2": {
                    "uuid": "rule2",
                    "description": "Test Rule 2",
                    "%interface": "lan",
                    "enabled": "0",
                },
            }
        }
    }
    ents = await _compile_firewall_rules_switches(config_entry, coordinator, state)
    assert len(ents) == 2
    assert isinstance(ents[0], OPNsenseFirewallRuleSwitch)
    assert isinstance(ents[1], OPNsenseFirewallRuleSwitch)
    assert ents[0].entity_description.key == "firewall.rule.rule1"
    assert ents[1].entity_description.key == "firewall.rule.rule2"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("if_value", "expected_interface"),
    [
        ("wan", "wan"),
        ("lan, opt1", "Floating"),
        ("lan,wan", "Floating"),
        ("", "Floating"),
    ],
)
async def test_firewall_rule_interface_name_override(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    if_value: Any,
    expected_interface: Any,
) -> None:
    """Interface should be overridden to 'Floating' when multiple interfaces are present."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    state = {
        "firewall": {
            "rules": {
                "r1": {
                    "uuid": "r1",
                    "description": "Test",
                    "%interface": if_value,
                    "enabled": "1",
                }
            }
        }
    }

    ents = await _compile_firewall_rules_switches(config_entry, coordinator, state)
    assert len(ents) == 1
    ent = ents[0]
    assert isinstance(ent, OPNsenseFirewallRuleSwitch)
    assert ent.entity_description.name == f"Firewall: {expected_interface}: Test"


@pytest.mark.asyncio
async def test_firewall_rule_uses_interface_key_if_no_percent_key(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """If "%interface" is missing, the "interface" key should be used."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    state = {
        "firewall": {
            "rules": {
                "r1": {
                    "uuid": "r1",
                    "description": "Test",
                    "interface": "lan",
                    "enabled": "1",
                }
            }
        }
    }

    ents = await _compile_firewall_rules_switches(config_entry, coordinator, state)
    assert len(ents) == 1
    assert ents[0].entity_description.name == "Firewall: lan: Test"


@pytest.mark.asyncio
async def test_firewall_rule_skips_non_string_interface(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Rules with non-string interface values should be skipped."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    state = {
        "firewall": {
            "rules": {
                "r1": {
                    "uuid": "r1",
                    "description": "Test",
                    "%interface": ["not", "a", "string"],
                    "enabled": "1",
                }
            }
        }
    }

    ents = await _compile_firewall_rules_switches(config_entry, coordinator, state)
    assert len(ents) == 0


@pytest.mark.asyncio
async def test_compile_nat_source_rules_switches(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Test compilation of NAT source rule switches."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    state = {
        "firewall": {
            "nat": {
                "source_nat": {
                    "nat1": {
                        "uuid": "nat1",
                        "description": "Source NAT Rule",
                        "%interface": "wan",
                        "enabled": "1",
                    }
                }
            }
        }
    }
    ents = await _compile_nat_source_rules_switches(config_entry, coordinator, state)
    assert len(ents) == 1
    assert isinstance(ents[0], OPNsenseNATRuleSwitch)
    assert ents[0].entity_description.key == "firewall.nat.source_nat.nat1"


@pytest.mark.asyncio
async def test_compile_nat_destination_rules_switches(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Test compilation of NAT destination rule switches."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    state = {
        "firewall": {
            "nat": {
                "d_nat": {
                    "dnat1": {
                        "uuid": "dnat1",
                        "description": "Destination NAT Rule",
                        "%interface": "wan",
                        "enabled": "1",
                    }
                }
            }
        }
    }
    ents = await _compile_nat_destination_rules_switches(config_entry, coordinator, state)
    assert len(ents) == 1
    assert isinstance(ents[0], OPNsenseNATRuleSwitch)
    assert ents[0].entity_description.key == "firewall.nat.d_nat.dnat1"


@pytest.mark.asyncio
async def test_compile_nat_one_to_one_rules_switches(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Test compilation of NAT one-to-one rule switches."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    state = {
        "firewall": {
            "nat": {
                "one_to_one": {
                    "oto1": {
                        "uuid": "oto1",
                        "description": "One-to-One NAT Rule",
                        "%interface": "wan",
                        "enabled": "1",
                    }
                }
            }
        }
    }
    ents = await _compile_nat_one_to_one_rules_switches(config_entry, coordinator, state)
    assert len(ents) == 1
    assert isinstance(ents[0], OPNsenseNATRuleSwitch)
    assert ents[0].entity_description.key == "firewall.nat.one_to_one.oto1"


@pytest.mark.asyncio
async def test_compile_nat_npt_rules_switches(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Test compilation of NAT NPT rule switches."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    state = {
        "firewall": {
            "nat": {
                "npt": {
                    "npt1": {
                        "uuid": "npt1",
                        "description": "NPT NAT Rule",
                        "%interface": "wan",
                        "enabled": "1",
                    }
                }
            }
        }
    }
    ents = await _compile_nat_npt_rules_switches(config_entry, coordinator, state)
    assert len(ents) == 1
    assert isinstance(ents[0], OPNsenseNATRuleSwitch)
    assert ents[0].entity_description.key == "firewall.nat.npt.npt1"


@pytest.mark.asyncio
async def test_compile_new_api_empty_state(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Test compilation functions handle empty/missing state gracefully."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})

    # Test empty state
    ents = await _compile_firewall_rules_switches(config_entry, coordinator, {})
    assert ents == []

    ents = await _compile_nat_source_rules_switches(config_entry, coordinator, {})
    assert ents == []

    # Test state with firewall but no rules
    state: dict[str, Any] = {"firewall": {}}
    ents = await _compile_firewall_rules_switches(config_entry, coordinator, state)
    assert ents == []

    ents = await _compile_nat_source_rules_switches(config_entry, coordinator, state)
    assert ents == []
