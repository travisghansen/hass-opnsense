"""Unit tests for switch entities and helpers in the hass-opnsense integration.

These tests validate switch compilation helpers, entity behavior, and
async setup flows for the integration's switch platform.
"""

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.opnsense import switch as switch_mod
from custom_components.opnsense.const import (
    ATTR_NAT_OUTBOUND,
    ATTR_NAT_PORT_FORWARD,
    CONF_DEVICE_UNIQUE_ID,
    CONF_SYNC_FILTERS_AND_NAT,
    CONF_SYNC_SERVICES,
    CONF_SYNC_UNBOUND,
    CONF_SYNC_VPN,
    COORDINATOR,
)
from custom_components.opnsense.coordinator import OPNsenseDataUpdateCoordinator
from custom_components.opnsense.switch import (
    OPNsenseFilterSwitch,
    OPNsenseNatSwitch,
    OPNsenseServiceSwitch,
    OPNsenseVPNSwitch,
    _compile_filter_switches,
    _compile_nat_outbound_switches,
    _compile_port_forward_switches,
    _compile_service_switches,
    _compile_static_unbound_switches,
    _compile_vpn_switches,
)
from homeassistant.components.switch import SwitchEntityDescription
from homeassistant.core import HomeAssistant


def make_coord(data):
    """Create a MagicMock that behaves like an OPNsenseDataUpdateCoordinator for tests."""
    m = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    m.data = data
    return m


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "compile_fn,state,client_methods,on_name,off_name",
    [
        (
            _compile_filter_switches,
            {"config": {"filter": {"rule": [{"descr": "Allow LAN", "created": {"time": "t1"}}]}}},
            ("enable_filter_rule_by_created_time", "disable_filter_rule_by_created_time"),
            "enable_filter_rule_by_created_time",
            "disable_filter_rule_by_created_time",
        ),
        (
            _compile_port_forward_switches,
            {"config": {"nat": {"rule": [{"descr": "PF", "created": {"time": "p1"}}]}}},
            (
                "enable_nat_port_forward_rule_by_created_time",
                "disable_nat_port_forward_rule_by_created_time",
            ),
            "enable_nat_port_forward_rule_by_created_time",
            "disable_nat_port_forward_rule_by_created_time",
        ),
        (
            _compile_nat_outbound_switches,
            {
                "config": {
                    "nat": {"outbound": {"rule": [{"descr": "OB", "created": {"time": "o1"}}]}}
                }
            },
            (
                "enable_nat_outbound_rule_by_created_time",
                "disable_nat_outbound_rule_by_created_time",
            ),
            "enable_nat_outbound_rule_by_created_time",
            "disable_nat_outbound_rule_by_created_time",
        ),
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
            "start_service",
            "stop_service",
        ),
        (
            _compile_static_unbound_switches,
            {"unbound_blocklist": {"enabled": "1"}},
            ("enable_unbound_blocklist", "disable_unbound_blocklist"),
            "enable_unbound_blocklist",
            "disable_unbound_blocklist",
        ),
    ],
)
async def test_switch_toggle_variants(
    coordinator, ph_hass, compile_fn, state, client_methods, on_name, off_name
):
    """Generic param test for switches that support enable/disable-style clients."""
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"}
    config_entry.title = "OPNsenseTest"
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
    ent.async_write_ha_state = lambda: None

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
    assert getattr(ent._client, on_name).called
    await ent.async_turn_off()
    assert getattr(ent._client, off_name).called


@pytest.mark.asyncio
async def test_compile_port_forward_skips_non_dict(coordinator):
    """Port forward compilation should skip non-dict rule entries."""
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"}
    config_entry.title = "OPNsenseTest"
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    # include a non-dict in nat.rule which should be skipped
    state = {
        "config": {"nat": {"rule": ["not-a-dict", {"descr": "PF", "created": {"time": "p2"}}]}}
    }
    coordinator.data = state
    ents = await _compile_port_forward_switches(config_entry, coordinator, state)
    assert len(ents) == 1
    assert ents[0].entity_description.key.endswith(".p2")


@pytest.mark.asyncio
async def test_async_setup_entry_all_flags(coordinator, ph_hass):
    """Async setup should create entities for all enabled sync flags."""
    calls = {}

    def fake_add_entities(entities):
        calls["len"] = len(entities)

    # create a state that contains one of each entity type
    state = {
        "config": {
            "filter": {"rule": [{"descr": "Allow", "created": {"time": "f1"}}]},
            "nat": {
                "rule": [{"descr": "PF", "created": {"time": "p1"}}],
                "outbound": {"rule": [{"descr": "OB", "created": {"time": "o1"}}]},
            },
        },
        "services": [{"id": "s1", "name": "svc", "locked": 0, "status": True}],
        "openvpn": {"clients": {"c1": {"enabled": True, "name": "C1"}}, "servers": {}},
        "wireguard": {"clients": {}, "servers": {}},
        "unbound_blocklist": {"enabled": "1"},
    }
    coordinator.data = state

    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {
        CONF_DEVICE_UNIQUE_ID: "dev1",
        CONF_SYNC_FILTERS_AND_NAT: True,
        CONF_SYNC_SERVICES: True,
        CONF_SYNC_VPN: True,
        CONF_SYNC_UNBOUND: True,
    }
    config_entry.title = "OPNsenseTest"
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)

    hass = ph_hass
    await switch_mod.async_setup_entry(hass, config_entry, fake_add_entities)

    # expecting: filter(1) + pf(1) + nat outbound(1) + service(1) + vpn client(1) + unbound(1) = 6
    assert calls.get("len") == 6


def test_vpn_icon_property():
    """VPN switch exposes the expected icon when available and on."""
    desc = SwitchEntityDescription(key="openvpn.clients.c1", name="VPNC")
    coord = make_coord({})
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1"}
    config_entry.title = "OPNsenseTest"
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
async def test_unbound_and_vpn_variations(coordinator, ph_hass):
    """Compile and exercise unbound and VPN switch variations."""
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"}
    config_entry.title = "OPNsenseTest"
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
        "unbound_blocklist": dnsbl,
        "openvpn": {
            "clients": {"u1": {"enabled": True, "name": "C1"}},
            "servers": {"s1": {"enabled": False, "name": "S1"}},
        },
        "wireguard": {"clients": {}, "servers": {}},
    }
    coordinator.data = state

    unbound = (await _compile_static_unbound_switches(config_entry, coordinator, state))[0]
    vpn_ents = await _compile_vpn_switches(config_entry, coordinator, state)

    # use PHCC-provided hass fixture
    hass = ph_hass
    unbound.hass = hass
    unbound.coordinator = make_coord(state)
    unbound.entity_id = f"switch.{unbound._attr_unique_id}"
    unbound.async_write_ha_state = lambda: None
    unbound._client = MagicMock()
    unbound._client.enable_unbound_blocklist = AsyncMock(return_value=True)
    unbound._client.disable_unbound_blocklist = AsyncMock(return_value=True)
    unbound._handle_coordinator_update()
    assert unbound.available is True
    assert unbound.is_on is True

    await unbound.async_turn_off()
    assert unbound.is_on is False

    assert any(isinstance(e, OPNsenseVPNSwitch) for e in vpn_ents)
    for vpn in vpn_ents:
        vpn.hass = hass
        vpn.coordinator = make_coord(state)
        vpn.entity_id = f"switch.{vpn.entity_description.key}"
        vpn.async_write_ha_state = lambda: None
        vpn._client = MagicMock()
        vpn._client.toggle_vpn_instance = AsyncMock(return_value=True)
        vpn._handle_coordinator_update()
        assert vpn.available is True
        inst = state.get(vpn._vpn_type, {}).get(vpn._clients_servers, {}).get(vpn._uuid)
        assert isinstance(inst, dict)
        assert vpn.is_on is bool(inst.get("enabled"))


def test_delay_update_setter(monkeypatch, coordinator):
    """Delay update setter captures and removes scheduled removers correctly."""
    desc = SwitchEntityDescription(key="x", name="DelayTest")
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"}
    config_entry.title = "OPNsenseTest"
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    ent = OPNsenseFilterSwitch(
        config_entry=config_entry, coordinator=coordinator, entity_description=desc
    )
    # synchronous test: use a plain hass-like object
    hass_local = MagicMock(spec=HomeAssistant)
    hass_local.loop = asyncio.get_event_loop()
    hass_local.data = {}
    ent.hass = hass_local
    called = {"removed": False}

    def fake_async_call_later(*args, **kwargs):
        def remover():
            called["removed"] = True

        return remover

    monkeypatch.setattr("custom_components.opnsense.switch.async_call_later", fake_async_call_later)

    ent.delay_update = True
    assert ent.delay_update is True
    # ensure async_call_later returned remover was captured
    assert callable(getattr(ent, "_delay_update_remove", None))
    ent.delay_update = False
    assert called["removed"] is True


@pytest.mark.asyncio
async def test_filter_disabled_and_missing(coordinator, ph_hass):
    """Filter compilation handles missing and disabled rules correctly."""
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"}
    config_entry.title = "OPNsenseTest"
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    # missing rules -> compile returns []
    state = {"config": {"filter": {"rule": []}}}
    coordinator.data = state
    entities = await _compile_filter_switches(config_entry, coordinator, state)
    assert entities == []

    # disabled rule -> is_on False
    state = {
        "config": {"filter": {"rule": [{"descr": "x", "created": {"time": "t2"}, "disabled": "1"}]}}
    }
    coordinator.data = state
    entities = await _compile_filter_switches(config_entry, coordinator, state)
    ent = entities[0]
    # use PHCC-provided hass fixture
    hass = ph_hass
    ent.hass = hass
    ent.coordinator = make_coord(state)
    ent.entity_id = f"switch.{ent._attr_unique_id}"
    ent.async_write_ha_state = lambda: None
    ent._handle_coordinator_update()
    assert ent.is_on is False


@pytest.mark.asyncio
async def test_unbound_missing_sets_unavailable(coordinator, ph_hass):
    """Unbound switch becomes unavailable when expected data is missing."""
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"}
    config_entry.title = "OPNsenseTest"
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    state = {"unbound_blocklist": {}}
    coordinator.data = state
    ent = (await _compile_static_unbound_switches(config_entry, coordinator, state))[0]
    # use PHCC-provided hass fixture
    hass = ph_hass
    ent.hass = hass
    ent.coordinator = make_coord(state)
    ent.entity_id = f"switch.{ent._attr_unique_id}"
    ent.async_write_ha_state = lambda: None
    ent._handle_coordinator_update()
    assert ent.available is False


@pytest.mark.asyncio
async def test_compile_helpers_bad_input(coordinator):
    """Compilation helpers return empty lists on bad/non-mapping input."""
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1"}
    config_entry.title = "OPNsenseTest"
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    # non-mapping state
    assert await _compile_filter_switches(config_entry, coordinator, None) == []
    assert await _compile_port_forward_switches(config_entry, coordinator, None) == []


@pytest.mark.asyncio
async def test_async_setup_entry_missing_state(monkeypatch, coordinator, ph_hass):
    """Async setup should handle missing coordinator state without adding entities."""
    calls = {}

    def fake_add_entities(entities):
        calls["len"] = len(entities)

    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1"}
    config_entry.title = "OPNsenseTest"
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    # coordinator returns non-mapping
    coordinator.data = None
    hass = ph_hass
    await switch_mod.async_setup_entry(hass, config_entry, fake_add_entities)
    # should not have added entities
    assert calls.get("len") is None


@pytest.mark.parametrize("kind", ["filter", "nat", "service"])
@pytest.mark.asyncio
async def test_switch_handle_error_sets_unavailable(kind: str, coordinator) -> None:
    """When underlying rule/service lookups return non-mapping values, switch becomes unavailable."""
    hass_local = MagicMock(spec=HomeAssistant)
    hass_local.loop = asyncio.get_event_loop()
    hass_local.data = {}

    if kind == "filter":
        # compile one valid filter entity then monkeypatch to produce error
        config_entry = MagicMock()
        config_entry.runtime_data = MagicMock()
        config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1"}
        config_entry.title = "OPNsenseTest"
        setattr(config_entry.runtime_data, COORDINATOR, coordinator)
        state = {"config": {"filter": {"rule": [{"descr": "Good", "created": {"time": "t1"}}]}}}
        coordinator.data = state
        ent = (await _compile_filter_switches(config_entry, coordinator, state))[0]
        ent.hass = hass_local
        ent.coordinator = make_coord(state)
        ent.entity_id = f"switch.{ent._attr_unique_id}"
        ent.async_write_ha_state = lambda: None

        def _fake_get_rule_filter() -> Any:
            return 5

        ent._opnsense_get_rule = _fake_get_rule_filter
    elif kind == "nat":
        desc = SwitchEntityDescription(key="nat_port_forward.abc", name="NAT")
        config_entry = MagicMock()
        config_entry.runtime_data = MagicMock()
        config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1"}
        config_entry.title = "OPNsenseTest"
        setattr(config_entry.runtime_data, COORDINATOR, coordinator)
        ent = OPNsenseNatSwitch(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=desc,
        )
        ent.hass = hass_local
        ent.coordinator = make_coord({})
        ent.entity_id = "switch.nat"
        ent.async_write_ha_state = lambda: None

        def _fake_get_rule_nat() -> Any:
            return 123

        ent._opnsense_get_rule = _fake_get_rule_nat
    else:  # service
        desc = SwitchEntityDescription(key="service.svc1.status", name="Svc")
        config_entry = MagicMock()
        config_entry.runtime_data = MagicMock()
        config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1"}
        config_entry.title = "OPNsenseTest"
        setattr(config_entry.runtime_data, COORDINATOR, coordinator)
        ent = OPNsenseServiceSwitch(
            config_entry=config_entry,
            coordinator=coordinator,
            entity_description=desc,
        )
        ent.hass = hass_local
        ent.coordinator = make_coord({})
        ent.entity_id = "switch.svc"
        ent.async_write_ha_state = lambda: None

        def _fake_get_service() -> Any:
            return 5

        ent._opnsense_get_service = _fake_get_service

    # Exercise the update logic and ensure entity is marked unavailable.
    ent._handle_coordinator_update()
    assert ent.available is False


def test_entity_icons():
    """Switch entities expose the correct platform icons based on type."""
    # filter icon
    f_desc = SwitchEntityDescription(key="filter.t1", name="Filter")
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1"}
    config_entry.title = "OPNsenseTest"
    setattr(config_entry.runtime_data, COORDINATOR, None)
    f_ent = OPNsenseFilterSwitch(
        config_entry=config_entry,
        coordinator=make_coord({}),
        entity_description=f_desc,
    )
    f_ent._attr_is_on = True
    f_ent._available = True
    assert f_ent.icon == "mdi:play-network"

    # nat icon
    n_desc = SwitchEntityDescription(key="nat_port_forward.t1", name="NAT")
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1"}
    config_entry.title = "OPNsenseTest"
    setattr(config_entry.runtime_data, COORDINATOR, None)
    n_ent = OPNsenseNatSwitch(
        config_entry=config_entry,
        coordinator=make_coord({}),
        entity_description=n_desc,
    )
    n_ent._attr_is_on = True
    n_ent._available = True
    assert n_ent.icon == "mdi:network"

    # service icon
    s_desc = SwitchEntityDescription(key="service.s1.status", name="Svc")
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1"}
    config_entry.title = "OPNsenseTest"
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
    "state,select_suffix,expect_name,toggle_return,expect_on",
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
    coordinator,
    ph_hass,
    state,
    select_suffix,
    expect_name,
    toggle_return,
    expect_on,
    make_config_entry,
):
    """Parameterized VPN client/server/toggle behaviors.

    Covers: client present and toggle succeeds, server present and toggle succeeds,
    and client toggle failure (should not set is_on).
    """
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    config_entry.runtime_data = MagicMock()
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
    ent.async_write_ha_state = lambda: None
    ent._client = MagicMock()
    ent._client.toggle_vpn_instance = AsyncMock(return_value=toggle_return)

    ent._handle_coordinator_update()
    assert ent.available is True
    # when available, name should be present for created entities
    if expect_name:
        assert ent.extra_state_attributes.get("name") == expect_name

    # try toggle
    await ent.async_turn_on()
    assert ent.is_on is expect_on


def test_reset_delay_calls_existing_remover(monkeypatch):
    """Resetting delay should call any existing remover and replace it."""
    desc = SwitchEntityDescription(key="filter.t1", name="Filter")
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1"}
    config_entry.title = "OPNsenseTest"
    setattr(config_entry.runtime_data, COORDINATOR, None)
    ent = OPNsenseFilterSwitch(
        config_entry=config_entry,
        coordinator=make_coord({}),
        entity_description=desc,
    )
    called = {"old_removed": False, "new_removed": False}

    def old_remover():
        called["old_removed"] = True

    def new_remover():
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
async def test_compile_filter_skip_and_invalid_rules(coordinator):
    """Filter compilation skips invalid and non-dict rule entries."""
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"}
    config_entry.title = "OPNsenseTest"
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    # include various rules that should be skipped
    state = {
        "config": {
            "filter": {
                "rule": [
                    {"descr": "Anti-Lockout Rule", "created": {"time": "a1"}},
                    {"associated-rule-id": "x", "created": {"time": "a2"}},
                    {"descr": "No tracker"},
                    ["not", "a", "dict"],
                    {"descr": "Good", "created": {"time": "g1"}},
                ]
            }
        }
    }
    coordinator.data = state
    entities = await _compile_filter_switches(config_entry, coordinator, state)
    # only the valid rule should be compiled
    assert len(entities) == 1


@pytest.mark.asyncio
async def test_compile_nat_outbound_skips_auto_created(coordinator):
    """Outbound NAT compilation ignores auto-created rules."""
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"}
    config_entry.title = "OPNsenseTest"
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    state = {
        "config": {
            "nat": {
                "outbound": {
                    "rule": [
                        {"descr": "Auto created rule", "created": {"time": "x1"}},
                        {"descr": "Manual", "created": {"time": "x2"}},
                    ]
                }
            }
        }
    }
    coordinator.data = state
    ents = await _compile_nat_outbound_switches(config_entry, coordinator, state)
    assert len(ents) == 1


@pytest.mark.asyncio
async def test_compile_service_skips_locked(coordinator):
    """Service compilation skips locked services."""
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"}
    config_entry.title = "OPNsenseTest"
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
async def test_async_setup_entry_respects_config_flags(monkeypatch, coordinator, ph_hass):
    """Async setup respects per-entry configuration flags when creating entities."""
    calls = {}

    def fake_add_entities(entities):
        calls["len"] = len(entities)

    # create config where only unbound is enabled
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {
        CONF_DEVICE_UNIQUE_ID: "dev1",
        CONF_SYNC_FILTERS_AND_NAT: False,
        CONF_SYNC_SERVICES: False,
        CONF_SYNC_VPN: False,
        CONF_SYNC_UNBOUND: True,
    }
    config_entry.title = "OPNsenseTest"
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    # coordinator.data can be minimal
    coordinator.data = {}
    # run the async setup
    hass = ph_hass
    await switch_mod.async_setup_entry(hass, config_entry, fake_add_entities)
    # since only unbound is enabled, expect 1 entity
    assert calls.get("len") == 1


@pytest.mark.asyncio
async def test_vpn_servers_properties_and_toggle(coordinator, ph_hass, make_config_entry):
    """VPN server switches expose properties and support toggle behavior."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"})
    config_entry.runtime_data = MagicMock()
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

    ents = await _compile_vpn_switches(config_entry, coordinator, state)
    # find the server ent
    server_ent = next(e for e in ents if e.entity_description.key.startswith("openvpn.servers."))
    hass = ph_hass
    server_ent.hass = hass
    server_ent.coordinator = make_coord(state)
    server_ent.entity_id = f"switch.{server_ent.entity_description.key}"
    server_ent.async_write_ha_state = lambda: None
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
    assert not server_ent._client.toggle_vpn_instance.called


@pytest.mark.asyncio
async def test_nat_handle_missing_rule_returns_none(coordinator, ph_hass):
    """NAT switch handles missing rules gracefully without exceptions."""
    # create a nat switch with rule type that doesn't exist in state
    desc = SwitchEntityDescription(key="nat_outbound.missing", name="Missing")
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1"}
    config_entry.title = "OPNsenseTest"
    ent = OPNsenseNatSwitch(
        config_entry=config_entry,
        coordinator=coordinator,
        entity_description=desc,
    )
    setattr(ent.config_entry.runtime_data, COORDINATOR, coordinator)
    # ensure missing NAT rule is handled gracefully (no exception, no state change)
    hass = ph_hass
    ent.hass = hass
    ent.coordinator = make_coord({})
    ent.entity_id = "switch.missing"
    ent.async_write_ha_state = lambda: None
    # calling _handle_coordinator_update should not raise
    ent._handle_coordinator_update()
    assert ent.available is False


@pytest.mark.asyncio
async def test_unbound_turn_on_off_failure_logs(coordinator, ph_hass):
    """Unbound turn on/off failures are handled without raising and leave state unchanged."""
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"}
    config_entry.title = "OPNsenseTest"
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    dnsbl = {"enabled": "0", "safesearch": "0"}
    state = {"unbound_blocklist": dnsbl}
    coordinator.data = state
    ent = (await _compile_static_unbound_switches(config_entry, coordinator, state))[0]
    hass = ph_hass
    ent.hass = hass
    ent.coordinator = make_coord(state)
    ent.entity_id = f"switch.{ent._attr_unique_id}"
    ent.async_write_ha_state = lambda: None
    # simulate client failure
    ent._client = MagicMock()
    ent._client.enable_unbound_blocklist = AsyncMock(return_value=False)
    ent._client.disable_unbound_blocklist = AsyncMock(return_value=False)
    await ent.async_turn_on()
    # still should not raise and is_on remains False
    assert ent.is_on is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "compile_fn,state,client_attr,turn_method,expect_is_on",
    [
        (
            _compile_service_switches,
            {"services": [{"id": "svcX", "name": "svcX", "locked": 0, "status": False}]},
            ("start_service", "stop_service"),
            "async_turn_on",
            False,
        ),
        (
            _compile_static_unbound_switches,
            {"unbound_blocklist": {"enabled": "0", "safesearch": "0"}},
            ("enable_unbound_blocklist", "disable_unbound_blocklist"),
            "async_turn_on",
            False,
        ),
    ],
)
async def test_client_failure_does_not_set_on(
    coordinator, ph_hass, compile_fn, state, client_attr, turn_method, expect_is_on
):
    """Generic test to ensure failing client methods (return False) don't flip is_on."""
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"}
    config_entry.title = "OPNsenseTest"
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    coordinator.data = state
    ents = await compile_fn(config_entry, coordinator, state)
    ent = ents[0]
    hass = ph_hass
    ent.hass = hass
    ent.coordinator = make_coord(state)
    ent.entity_id = f"switch.{ent._attr_unique_id}"
    ent.async_write_ha_state = lambda: None
    # Ensure service data is populated from coordinator so the turn method
    # exercises the client call path (otherwise _client won't be invoked).
    ent._handle_coordinator_update()

    # attach failing client methods
    ent._client = MagicMock()
    setattr(ent._client, client_attr[0], AsyncMock(return_value=False))
    setattr(ent._client, client_attr[1], AsyncMock(return_value=False))
    # call the turn method and assert is_on unchanged/False
    await getattr(ent, turn_method)()
    assert ent.is_on is expect_is_on
    method = getattr(ent._client, client_attr[0])
    method.assert_awaited()


@pytest.mark.asyncio
async def test_compile_vpn_with_non_mapping_state(coordinator, make_config_entry):
    """VPN compilation returns empty list when provided non-mapping state."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1"})
    config_entry.runtime_data = MagicMock()
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    # non-mapping state should result in []
    assert await _compile_vpn_switches(config_entry, coordinator, None) == []


def test_vpn_handle_coordinator_update_state_not_mapping(coordinator):
    """VPN entity becomes unavailable if coordinator.data is not a mapping."""
    # Create a VPN entity and simulate coordinator.data not being a mapping
    desc = SwitchEntityDescription(key="openvpn.clients.c1", name="VPNC")
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1"}
    config_entry.title = "OPNsenseTest"
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    ent = OPNsenseVPNSwitch(
        config_entry=config_entry,
        coordinator=coordinator,
        entity_description=desc,
    )
    # coordinator.data is None -> unavailable
    coordinator.data = None
    ent.async_write_ha_state = lambda: None
    ent._handle_coordinator_update()
    assert ent.available is False


@pytest.mark.asyncio
async def test_compile_vpn_wireguard_variations(coordinator, ph_hass, make_config_entry):
    """Ensure wireguard clients and servers compile into switches properly."""
    config_entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"})
    config_entry.runtime_data = MagicMock()
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
        vpn.async_write_ha_state = lambda: None
        vpn._client = MagicMock()
        vpn._client.toggle_vpn_instance = AsyncMock(return_value=True)
        vpn._handle_coordinator_update()
        # available may be True/False depending on enabled flag but handler should not raise
        assert vpn.available in (True, False)


def test_vpn_instance_non_mapping_sets_unavailable(coordinator):
    """VPN instance that's not a mapping should mark the entity unavailable."""
    desc = SwitchEntityDescription(key="openvpn.clients.c1", name="VPNC")
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1"}
    config_entry.title = "OPNsenseTest"
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
    ent.async_write_ha_state = lambda: None
    ent._handle_coordinator_update()
    assert ent.available is False


@pytest.mark.asyncio
async def test_service_async_turn_on_off_failure(coordinator, ph_hass):
    """Service start/stop failures do not set the switch on or crash."""
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"}
    config_entry.title = "OPNsenseTest"
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    state = {"services": [{"id": "svcX", "name": "svcX", "locked": 0, "status": False}]}
    coordinator.data = state
    ents = await _compile_service_switches(config_entry, coordinator, state)
    ent: OPNsenseServiceSwitch = ents[0]
    hass = ph_hass
    ent.hass = hass
    ent.coordinator = make_coord(state)
    ent.entity_id = f"switch.{ent._attr_unique_id}"
    ent.async_write_ha_state = lambda: None
    # simulate failure to start/stop
    ent._client = MagicMock()
    ent._client.start_service = AsyncMock(return_value=False)
    ent._client.stop_service = AsyncMock(return_value=False)
    await ent.async_turn_on()
    assert ent.is_on is False
    await ent.async_turn_off()
    assert ent.is_on is False


@pytest.mark.asyncio
async def test_vpn_toggle_failure_does_not_set_on(coordinator, ph_hass):
    """VPN toggle failure should not set the switch state to on."""
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"}
    config_entry.title = "OPNsenseTest"
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
    ent.async_write_ha_state = lambda: None
    ent._client = MagicMock()
    ent._client.toggle_vpn_instance = AsyncMock(return_value=False)
    # attempt to turn on should not set is_on when client returns False
    await ent.async_turn_on()
    assert ent.is_on is False


@pytest.mark.asyncio
async def test_service_locked_skipped():
    """Locked services are omitted from compiled switch lists."""
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {}
    config_entry.title = "t"
    setattr(config_entry.runtime_data, COORDINATOR, None)
    coordinator = make_coord({})
    # service with locked=1 should be skipped
    state = {"services": [{"id": "s1", "name": "svc", "locked": 1}]}
    coordinator.data = state
    ents = await _compile_service_switches(config_entry, coordinator, state)
    assert ents == []


@pytest.mark.asyncio
async def test_vpn_entries_skip_non_mapping_and_missing_enabled():
    """VPN compilation skips entries that are non-mapping or missing 'enabled'."""
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {}
    config_entry.title = "t"
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


def test_nat_rule_type_and_tracker_methods(coordinator):
    """NAT switch helper methods return correct types and trackers."""
    desc_pf = SwitchEntityDescription(key=f"{ATTR_NAT_PORT_FORWARD}.tpf", name="PF")
    desc_ob = SwitchEntityDescription(key=f"{ATTR_NAT_OUTBOUND}.tob", name="OB")

    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1"}
    config_entry.title = "OPNsenseTest"
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    pf = OPNsenseNatSwitch(
        config_entry=config_entry,
        coordinator=coordinator,
        entity_description=desc_pf,
    )
    # create a separate config_entry for the outbound test
    config_entry_ob = MagicMock()
    config_entry_ob.runtime_data = MagicMock()
    config_entry_ob.data = {CONF_DEVICE_UNIQUE_ID: "dev1"}
    config_entry_ob.title = "OPNsenseTest"
    setattr(config_entry_ob.runtime_data, COORDINATOR, coordinator)
    ob = OPNsenseNatSwitch(
        config_entry=config_entry_ob,
        coordinator=coordinator,
        entity_description=desc_ob,
    )

    assert pf._opnsense_get_rule_type() == ATTR_NAT_PORT_FORWARD
    assert ob._opnsense_get_rule_type() == ATTR_NAT_OUTBOUND
    assert pf._opnsense_get_tracker() == "tpf"
    assert ob._opnsense_get_tracker() == "tob"


def test_service_helper_methods(coordinator):
    """Service switch helper methods extract property and service id correctly."""
    desc = SwitchEntityDescription(key="service.svcx.status", name="SvcX")
    config_entry_srv = MagicMock()
    config_entry_srv.runtime_data = MagicMock()
    config_entry_srv.data = {CONF_DEVICE_UNIQUE_ID: "dev1"}
    config_entry_srv.title = "OPNsenseTest"
    setattr(config_entry_srv.runtime_data, COORDINATOR, coordinator)
    ent = OPNsenseServiceSwitch(
        config_entry=config_entry_srv,
        coordinator=coordinator,
        entity_description=desc,
    )
    assert ent._opnsense_get_property_name() == "status"
    assert ent._opnsense_get_service_id() == "svcx"


@pytest.mark.asyncio
async def test_compile_port_forward_with_missing_rules(coordinator):
    """Port-forward compilation returns empty list when rules are missing."""
    # port forward compile should return [] when nat not present or rules missing
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1"}
    config_entry.title = "t"
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    coordinator.data = {"config": {}}
    res = await _compile_port_forward_switches(config_entry, coordinator, coordinator.data)
    assert res == []


def test_vpn_instance_key_parsing(coordinator):
    """VPNSwitch parses its entity_description.key into type, section, and uuid."""
    # ensure VPNSwitch parses key parts without raising
    desc = SwitchEntityDescription(key="openvpn.clients.c1", name="VPNC")
    config_entry = MagicMock()
    config_entry.runtime_data = MagicMock()
    config_entry.data = {CONF_DEVICE_UNIQUE_ID: "dev1"}
    config_entry.title = "t"
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)
    ent = OPNsenseVPNSwitch(
        config_entry=config_entry,
        coordinator=coordinator,
        entity_description=desc,
    )
    assert ent._vpn_type == "openvpn"
    assert ent._clients_servers == "clients"
    assert ent._uuid == "c1"
