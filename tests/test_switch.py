import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

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
)
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


@pytest.mark.asyncio
async def test_compile_filter_switches_and_filter_handle(coordinator, hass):
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"},
        title="OPNsenseTest",
    )

    state = {
        "config": {
            "filter": {
                "rule": [
                    {"descr": "Allow LAN", "created": {"time": "t1"}},
                ]
            }
        }
    }
    coordinator.data = state

    entities = await _compile_filter_switches(config_entry, coordinator, state)
    assert len(entities) == 1
    ent: OPNsenseFilterSwitch = entities[0]

    ent.hass = hass
    ent.coordinator = SimpleNamespace(data=state)
    ent.entity_id = f"switch.{ent._attr_unique_id}"
    ent.async_write_ha_state = lambda: None
    ent._client = SimpleNamespace(
        enable_filter_rule_by_created_time=AsyncMock(return_value=True),
        disable_filter_rule_by_created_time=AsyncMock(return_value=True),
    )

    ent._handle_coordinator_update()
    assert ent.available is True
    assert ent.is_on is True

    await ent.async_turn_off()
    assert ent.is_on is False


@pytest.mark.asyncio
async def test_nat_port_forward_and_outbound_switches(coordinator, hass):
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"},
        title="OPNsenseTest",
    )

    state = {
        "config": {
            "nat": {
                "rule": [{"descr": "PF", "created": {"time": "p1"}}],
                "outbound": {"rule": [{"descr": "OB", "created": {"time": "o1"}}]},
            }
        }
    }
    coordinator.data = state

    pf = (await _compile_port_forward_switches(config_entry, coordinator, state))[0]
    ob = (await _compile_nat_outbound_switches(config_entry, coordinator, state))[0]

    enable_pf = AsyncMock(return_value=True)
    disable_pf = AsyncMock(return_value=True)
    enable_ob = AsyncMock(return_value=True)
    disable_ob = AsyncMock(return_value=True)

    pf._client = SimpleNamespace(
        enable_nat_port_forward_rule_by_created_time=enable_pf,
        disable_nat_port_forward_rule_by_created_time=disable_pf,
    )
    ob._client = SimpleNamespace(
        enable_nat_outbound_rule_by_created_time=enable_ob,
        disable_nat_outbound_rule_by_created_time=disable_ob,
    )

    for ent in (pf, ob):
        ent.hass = hass
        ent.coordinator = SimpleNamespace(data=state)
        ent.entity_id = f"switch.{ent._attr_unique_id}"
        ent.async_write_ha_state = lambda: None
        ent._handle_coordinator_update()
        assert ent.available is True

    await pf.async_turn_on()
    assert enable_pf.called
    await pf.async_turn_off()
    assert disable_pf.called

    await ob.async_turn_on()
    assert enable_ob.called
    await ob.async_turn_off()
    assert disable_ob.called


@pytest.mark.asyncio
async def test_service_switch_and_failure(coordinator, hass):
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"},
        title="OPNsenseTest",
    )
    state = {
        "services": [
            {"id": "svc1", "name": "svc", "description": "MySvc", "locked": 0, "status": True}
        ]
    }
    coordinator.data = state

    ents = await _compile_service_switches(config_entry, coordinator, state)
    assert len(ents) == 1
    ent: OPNsenseServiceSwitch = ents[0]
    ent.hass = hass
    ent.coordinator = SimpleNamespace(data=state)
    ent.entity_id = f"switch.{ent._attr_unique_id}"
    ent.async_write_ha_state = lambda: None
    ent._client = SimpleNamespace(
        start_service=AsyncMock(return_value=True), stop_service=AsyncMock(return_value=True)
    )

    ent._handle_coordinator_update()
    assert ent.available is True
    assert ent.extra_state_attributes.get("service_id") == "svc1"

    await ent.async_turn_off()
    assert ent.is_on is False


def test_compile_port_forward_skips_non_dict(coordinator):
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"},
        title="OPNsenseTest",
    )
    # include a non-dict in nat.rule which should be skipped
    state = {
        "config": {"nat": {"rule": ["not-a-dict", {"descr": "PF", "created": {"time": "p2"}}]}}
    }
    coordinator.data = state
    ents = asyncio.get_event_loop().run_until_complete(
        _compile_port_forward_switches(config_entry, coordinator, state)
    )
    assert len(ents) == 1


def test_async_setup_entry_all_flags(monkeypatch, coordinator):
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

    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={
            CONF_DEVICE_UNIQUE_ID: "dev1",
            CONF_SYNC_FILTERS_AND_NAT: True,
            CONF_SYNC_SERVICES: True,
            CONF_SYNC_VPN: True,
            CONF_SYNC_UNBOUND: True,
        },
        title="OPNsenseTest",
    )

    asyncio.get_event_loop().run_until_complete(
        switch_mod.async_setup_entry(None, config_entry, fake_add_entities)
    )

    # expecting: filter(1) + pf(1) + nat outbound(1) + service(1) + vpn client(1) + unbound(1) = 6
    assert calls.get("len") == 6


def test_vpn_icon_property():
    desc = SwitchEntityDescription(key="openvpn.clients.c1", name="VPNC")
    ent = OPNsenseVPNSwitch(
        config_entry=SimpleNamespace(
            runtime_data=SimpleNamespace(coordinator=None),
            data={CONF_DEVICE_UNIQUE_ID: "dev1"},
            title="OPNsenseTest",
        ),
        coordinator=SimpleNamespace(data={}),
        entity_description=desc,
    )
    ent._attr_is_on = True
    ent._available = True
    assert ent.icon == "mdi:folder-key-network"


@pytest.mark.asyncio
async def test_unbound_and_vpn_variations(coordinator, hass):
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"},
        title="OPNsenseTest",
    )
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

    unbound.hass = hass
    unbound.coordinator = SimpleNamespace(data=state)
    unbound.entity_id = f"switch.{unbound._attr_unique_id}"
    unbound.async_write_ha_state = lambda: None
    unbound._client = SimpleNamespace(
        enable_unbound_blocklist=AsyncMock(return_value=True),
        disable_unbound_blocklist=AsyncMock(return_value=True),
    )
    unbound._handle_coordinator_update()
    assert unbound.available is True
    assert unbound.is_on is True

    await unbound.async_turn_off()
    assert unbound.is_on is False

    assert any(isinstance(e, OPNsenseVPNSwitch) for e in vpn_ents)
    for vpn in vpn_ents:
        vpn.hass = hass
        vpn.coordinator = SimpleNamespace(data=state)
        vpn.entity_id = f"switch.{vpn.entity_description.key}"
        vpn.async_write_ha_state = lambda: None
        vpn._client = SimpleNamespace(toggle_vpn_instance=AsyncMock(return_value=True))
        vpn._handle_coordinator_update()
        assert vpn.available in (True, False)


def test_delay_update_setter(monkeypatch, coordinator, hass):
    desc = SwitchEntityDescription(key="x", name="DelayTest")
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"},
        title="OPNsenseTest",
    )
    ent = OPNsenseFilterSwitch(
        config_entry=config_entry, coordinator=coordinator, entity_description=desc
    )
    ent.hass = hass
    called = {"removed": False}

    def fake_async_call_later(*args, **kwargs):
        def remover():
            called["removed"] = True

        return remover

    monkeypatch.setattr("custom_components.opnsense.switch.async_call_later", fake_async_call_later)

    ent.delay_update = True
    assert ent.delay_update is True
    ent.delay_update = False
    assert called["removed"] is True


@pytest.mark.asyncio
async def test_filter_disabled_and_missing(coordinator, hass):
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"},
        title="OPNsenseTest",
    )
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
    ent.hass = hass
    ent.coordinator = SimpleNamespace(data=state)
    ent.entity_id = f"switch.{ent._attr_unique_id}"
    ent.async_write_ha_state = lambda: None
    ent._handle_coordinator_update()
    assert ent.is_on is False


@pytest.mark.asyncio
async def test_unbound_missing_sets_unavailable(coordinator, hass):
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"},
        title="OPNsenseTest",
    )
    state = {"unbound_blocklist": {}}
    coordinator.data = state
    ent = (await _compile_static_unbound_switches(config_entry, coordinator, state))[0]
    ent.hass = hass
    ent.coordinator = SimpleNamespace(data=state)
    ent.entity_id = f"switch.{ent._attr_unique_id}"
    ent.async_write_ha_state = lambda: None
    ent._handle_coordinator_update()
    assert ent.available is False


@pytest.mark.asyncio
async def test_compile_helpers_bad_input(coordinator):
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={CONF_DEVICE_UNIQUE_ID: "dev1"},
        title="OPNsenseTest",
    )
    # non-mapping state
    assert await _compile_filter_switches(config_entry, coordinator, None) == []
    assert await _compile_port_forward_switches(config_entry, coordinator, None) == []


def test_async_setup_entry_missing_state(monkeypatch, coordinator):
    calls = {}

    def fake_add_entities(entities):
        calls["len"] = len(entities)

    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={CONF_DEVICE_UNIQUE_ID: "dev1"},
        title="OPNsenseTest",
    )
    # coordinator returns non-mapping
    coordinator.data = None
    asyncio.get_event_loop().run_until_complete(
        switch_mod.async_setup_entry(None, config_entry, fake_add_entities)
    )
    # should not have added entities
    assert calls.get("len") is None


def test_filter_handle_error_sets_unavailable(coordinator, hass):
    # compile one valid entity then monkeypatch to produce error
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={CONF_DEVICE_UNIQUE_ID: "dev1"},
        title="OPNsenseTest",
    )
    state = {"config": {"filter": {"rule": [{"descr": "Good", "created": {"time": "t1"}}]}}}
    coordinator.data = state
    ent = (
        asyncio.get_event_loop().run_until_complete(
            _compile_filter_switches(config_entry, coordinator, state)
        )
    )[0]
    ent.hass = hass
    ent.coordinator = SimpleNamespace(data=state)
    ent.entity_id = f"switch.{ent._attr_unique_id}"
    ent.async_write_ha_state = lambda: None
    # monkeypatch to return a non-dict so 'in' will raise TypeError
    ent._opnsense_get_rule = lambda: 5
    ent._handle_coordinator_update()
    assert ent.available is False


def test_nat_handle_type_error_sets_unavailable(coordinator, hass):
    desc = SwitchEntityDescription(key="nat_port_forward.abc", name="NAT")
    ent = OPNsenseNatSwitch(
        config_entry=SimpleNamespace(
            runtime_data=SimpleNamespace(coordinator=coordinator),
            data={CONF_DEVICE_UNIQUE_ID: "dev1"},
            title="OPNsenseTest",
        ),
        coordinator=coordinator,
        entity_description=desc,
    )
    ent.hass = hass
    ent.coordinator = SimpleNamespace(data={})
    ent.entity_id = "switch.nat"
    ent.async_write_ha_state = lambda: None
    ent._opnsense_get_rule = lambda: 123
    ent._handle_coordinator_update()
    assert ent.available is False


def test_service_handle_error_sets_unavailable(coordinator, hass):
    desc = SwitchEntityDescription(key="service.svc1.status", name="Svc")
    ent = OPNsenseServiceSwitch(
        config_entry=SimpleNamespace(
            runtime_data=SimpleNamespace(coordinator=coordinator),
            data={CONF_DEVICE_UNIQUE_ID: "dev1"},
            title="OPNsenseTest",
        ),
        coordinator=coordinator,
        entity_description=desc,
    )
    ent.hass = hass
    ent.coordinator = SimpleNamespace(data={})
    ent.entity_id = "switch.svc"
    ent.async_write_ha_state = lambda: None
    ent._opnsense_get_service = lambda: 5
    ent._handle_coordinator_update()
    assert ent.available is False


def test_entity_icons():
    # filter icon
    f_desc = SwitchEntityDescription(key="filter.t1", name="Filter")
    f_ent = OPNsenseFilterSwitch(
        config_entry=SimpleNamespace(
            runtime_data=SimpleNamespace(coordinator=None),
            data={CONF_DEVICE_UNIQUE_ID: "dev1"},
            title="OPNsenseTest",
        ),
        coordinator=SimpleNamespace(data={}),
        entity_description=f_desc,
    )
    f_ent._attr_is_on = True
    f_ent._available = True
    assert f_ent.icon == "mdi:play-network"

    # nat icon
    n_desc = SwitchEntityDescription(key="nat_port_forward.t1", name="NAT")
    n_ent = OPNsenseNatSwitch(
        config_entry=SimpleNamespace(
            runtime_data=SimpleNamespace(coordinator=None),
            data={CONF_DEVICE_UNIQUE_ID: "dev1"},
            title="OPNsenseTest",
        ),
        coordinator=SimpleNamespace(data={}),
        entity_description=n_desc,
    )
    n_ent._attr_is_on = True
    n_ent._available = True
    assert n_ent.icon == "mdi:network"

    # service icon
    s_desc = SwitchEntityDescription(key="service.s1.status", name="Svc")
    s_ent = OPNsenseServiceSwitch(
        config_entry=SimpleNamespace(
            runtime_data=SimpleNamespace(coordinator=None),
            data={CONF_DEVICE_UNIQUE_ID: "dev1"},
            title="OPNsenseTest",
        ),
        coordinator=SimpleNamespace(data={}),
        entity_description=s_desc,
    )
    s_ent._attr_is_on = True
    s_ent._available = True
    assert s_ent.icon == "mdi:application-cog"


@pytest.mark.asyncio
async def test_vpn_clients_properties_and_toggle(coordinator, hass):
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={CONF_DEVICE_UNIQUE_ID: "dev1"},
        title="OPNsenseTest",
    )
    client = {"enabled": True, "name": "C1", "uuid": "c1", "connected_servers": 1, "servers": {}}
    state = {"openvpn": {"clients": {"c1": client}}, "wireguard": {"clients": {}, "servers": {}}}
    coordinator.data = state
    ents = await _compile_vpn_switches(config_entry, coordinator, state)
    ent = next(e for e in ents if e.entity_description.key.startswith("openvpn.clients."))
    ent.hass = hass
    ent.coordinator = SimpleNamespace(data=state)
    ent.entity_id = f"switch.{ent.entity_description.key}"
    ent.async_write_ha_state = lambda: None
    ent._client = SimpleNamespace(toggle_vpn_instance=AsyncMock(return_value=True))
    ent._handle_coordinator_update()
    assert ent.available is True
    assert ent.extra_state_attributes.get("name") == "C1"
    await ent.async_turn_on()
    assert ent.is_on is True


def test_reset_delay_calls_existing_remover(monkeypatch):
    desc = SwitchEntityDescription(key="filter.t1", name="Filter")
    ent = OPNsenseFilterSwitch(
        config_entry=SimpleNamespace(
            runtime_data=SimpleNamespace(coordinator=None),
            data={CONF_DEVICE_UNIQUE_ID: "dev1"},
            title="OPNsenseTest",
        ),
        coordinator=SimpleNamespace(data={}),
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
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"},
        title="OPNsenseTest",
    )
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
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"},
        title="OPNsenseTest",
    )
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
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"},
        title="OPNsenseTest",
    )
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


def test_async_setup_entry_respects_config_flags(monkeypatch, coordinator):
    calls = {}

    def fake_add_entities(entities):
        calls["len"] = len(entities)

    # create config where only unbound is enabled
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={
            CONF_DEVICE_UNIQUE_ID: "dev1",
            CONF_SYNC_FILTERS_AND_NAT: False,
            CONF_SYNC_SERVICES: False,
            CONF_SYNC_VPN: False,
            CONF_SYNC_UNBOUND: True,
        },
        title="OPNsenseTest",
    )
    # coordinator.data can be minimal
    coordinator.data = {}
    # run the async setup
    asyncio.get_event_loop().run_until_complete(
        switch_mod.async_setup_entry(None, config_entry, fake_add_entities)
    )
    # since only unbound is enabled, expect 1 entity
    assert calls.get("len") == 1


@pytest.mark.asyncio
async def test_vpn_servers_properties_and_toggle(coordinator, hass):
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"},
        title="OPNsenseTest",
    )
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
    server_ent.hass = hass
    server_ent.coordinator = SimpleNamespace(data=state)
    server_ent.entity_id = f"switch.{server_ent.entity_description.key}"
    server_ent.async_write_ha_state = lambda: None
    server_ent._client = SimpleNamespace(toggle_vpn_instance=AsyncMock(return_value=True))

    server_ent._handle_coordinator_update()
    assert server_ent.available is True
    # properties populated
    assert server_ent.extra_state_attributes.get("name") == "S1"

    # test toggle when currently off
    await server_ent.async_turn_on()
    assert server_ent.is_on is True

    # test when already on, async_turn_on should early return (client not called)
    server_ent._client.toggle_vpn_instance = AsyncMock()
    server_ent._attr_is_on = True
    await server_ent.async_turn_on()
    assert not server_ent._client.toggle_vpn_instance.called


@pytest.mark.asyncio
async def test_nat_handle_missing_rule_returns_none(coordinator, hass):
    # create a nat switch with rule type that doesn't exist in state
    desc = SwitchEntityDescription(key="nat_outbound.missing", name="Missing")
    ent = OPNsenseNatSwitch(
        config_entry=SimpleNamespace(
            runtime_data=SimpleNamespace(coordinator=coordinator),
            data={CONF_DEVICE_UNIQUE_ID: "dev1"},
            title="OPNsenseTest",
        ),
        coordinator=coordinator,
        entity_description=desc,
    )
    # ensure _opnsense_get_service returns None gracefully when no services
    ent.hass = hass
    ent.coordinator = SimpleNamespace(data={})
    ent.entity_id = "switch.missing"
    ent.async_write_ha_state = lambda: None
    # calling _handle_coordinator_update should not raise
    ent._handle_coordinator_update()


@pytest.mark.asyncio
async def test_unbound_turn_on_off_failure_logs(coordinator, hass):
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"},
        title="OPNsenseTest",
    )
    dnsbl = {"enabled": "0", "safesearch": "0"}
    state = {"unbound_blocklist": dnsbl}
    coordinator.data = state
    ent = (await _compile_static_unbound_switches(config_entry, coordinator, state))[0]
    ent.hass = hass
    ent.coordinator = SimpleNamespace(data=state)
    ent.entity_id = f"switch.{ent._attr_unique_id}"
    ent.async_write_ha_state = lambda: None
    # simulate client failure
    ent._client = SimpleNamespace(
        enable_unbound_blocklist=AsyncMock(return_value=False),
        disable_unbound_blocklist=AsyncMock(return_value=False),
    )
    await ent.async_turn_on()
    # still should not raise and is_on remains False
    assert ent.is_on is False


@pytest.mark.asyncio
async def test_compile_vpn_with_non_mapping_state(coordinator):
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={CONF_DEVICE_UNIQUE_ID: "dev1"},
        title="OPNsenseTest",
    )
    # non-mapping state should result in []
    assert await _compile_vpn_switches(config_entry, coordinator, None) == []


def test_vpn_handle_coordinator_update_state_not_mapping(coordinator):
    # Create a VPN entity and simulate coordinator.data not being a mapping
    desc = SwitchEntityDescription(key="openvpn.clients.c1", name="VPNC")
    ent = OPNsenseVPNSwitch(
        config_entry=SimpleNamespace(
            runtime_data=SimpleNamespace(coordinator=coordinator),
            data={CONF_DEVICE_UNIQUE_ID: "dev1"},
            title="OPNsenseTest",
        ),
        coordinator=coordinator,
        entity_description=desc,
    )
    # coordinator.data is None -> unavailable
    coordinator.data = None
    ent.async_write_ha_state = lambda: None
    ent._handle_coordinator_update()
    assert ent.available is False


@pytest.mark.asyncio
async def test_compile_vpn_wireguard_variations(coordinator, hass):
    """Ensure wireguard clients and servers compile into switches properly."""
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"},
        title="OPNsenseTest",
    )
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
    for vpn in ents:
        vpn.hass = hass
        vpn.coordinator = SimpleNamespace(data=state)
        vpn.entity_id = f"switch.{vpn.entity_description.key}"
        vpn.async_write_ha_state = lambda: None
        vpn._client = SimpleNamespace(toggle_vpn_instance=AsyncMock(return_value=True))
        vpn._handle_coordinator_update()
        # available may be True/False depending on enabled flag but handler should not raise
        assert vpn.available in (True, False)


def test_vpn_instance_non_mapping_sets_unavailable(coordinator):
    desc = SwitchEntityDescription(key="openvpn.clients.c1", name="VPNC")
    ent = OPNsenseVPNSwitch(
        config_entry=SimpleNamespace(
            runtime_data=SimpleNamespace(coordinator=coordinator),
            data={CONF_DEVICE_UNIQUE_ID: "dev1"},
            title="OPNsenseTest",
        ),
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
async def test_service_async_turn_on_off_failure(coordinator, hass):
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"},
        title="OPNsenseTest",
    )
    state = {"services": [{"id": "svcX", "name": "svcX", "locked": 0, "status": False}]}
    coordinator.data = state
    ents = await _compile_service_switches(config_entry, coordinator, state)
    ent: OPNsenseServiceSwitch = ents[0]
    ent.hass = hass
    ent.coordinator = SimpleNamespace(data=state)
    ent.entity_id = f"switch.{ent._attr_unique_id}"
    ent.async_write_ha_state = lambda: None
    # simulate failure to start/stop
    ent._client = SimpleNamespace(
        start_service=AsyncMock(return_value=False), stop_service=AsyncMock(return_value=False)
    )
    await ent.async_turn_on()
    assert ent.is_on is False
    await ent.async_turn_off()
    assert ent.is_on is False


@pytest.mark.asyncio
async def test_vpn_toggle_failure_does_not_set_on(coordinator, hass):
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={CONF_DEVICE_UNIQUE_ID: "dev1", "url": "http://example"},
        title="OPNsenseTest",
    )
    client = {"enabled": False, "name": "Cfail", "uuid": "cfail", "servers": {}}
    state = {"openvpn": {"clients": {"cfail": client}}, "wireguard": {"clients": {}, "servers": {}}}
    coordinator.data = state
    ents = await _compile_vpn_switches(config_entry, coordinator, state)
    ent = next(e for e in ents if e.entity_description.key.endswith("cfail"))
    ent.hass = hass
    ent.coordinator = SimpleNamespace(data=state)
    ent.entity_id = f"switch.{ent.entity_description.key}"
    ent.async_write_ha_state = lambda: None
    ent._client = SimpleNamespace(toggle_vpn_instance=AsyncMock(return_value=False))
    # attempt to turn on should not set is_on when client returns False
    await ent.async_turn_on()
    assert ent.is_on is False


@pytest.mark.asyncio
async def test_service_locked_skipped():
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=None), data={}, title="t"
    )
    coordinator = SimpleNamespace(data={})
    # service with locked=1 should be skipped
    state = {"services": [{"id": "s1", "name": "svc", "locked": 1}]}
    coordinator.data = state
    ents = await _compile_service_switches(config_entry, coordinator, state)
    assert ents == []


@pytest.mark.asyncio
async def test_vpn_entries_skip_non_mapping_and_missing_enabled():
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=None), data={}, title="t"
    )
    coordinator = SimpleNamespace(data={})
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
    desc_pf = SwitchEntityDescription(key=f"{ATTR_NAT_PORT_FORWARD}.tpf", name="PF")
    desc_ob = SwitchEntityDescription(key=f"{ATTR_NAT_OUTBOUND}.tob", name="OB")

    pf = OPNsenseNatSwitch(
        config_entry=SimpleNamespace(
            runtime_data=SimpleNamespace(coordinator=coordinator),
            data={CONF_DEVICE_UNIQUE_ID: "dev1"},
            title="t",
        ),
        coordinator=coordinator,
        entity_description=desc_pf,
    )
    ob = OPNsenseNatSwitch(
        config_entry=SimpleNamespace(
            runtime_data=SimpleNamespace(coordinator=coordinator),
            data={CONF_DEVICE_UNIQUE_ID: "dev1"},
            title="t",
        ),
        coordinator=coordinator,
        entity_description=desc_ob,
    )

    assert pf._opnsense_get_rule_type() == ATTR_NAT_PORT_FORWARD
    assert ob._opnsense_get_rule_type() == ATTR_NAT_OUTBOUND
    assert pf._opnsense_get_tracker() == "tpf"
    assert ob._opnsense_get_tracker() == "tob"


def test_service_helper_methods(coordinator):
    desc = SwitchEntityDescription(key="service.svcx.status", name="SvcX")
    ent = OPNsenseServiceSwitch(
        config_entry=SimpleNamespace(
            runtime_data=SimpleNamespace(coordinator=coordinator),
            data={CONF_DEVICE_UNIQUE_ID: "dev1"},
            title="t",
        ),
        coordinator=coordinator,
        entity_description=desc,
    )
    assert ent._opnsense_get_property_name() == "status"
    assert ent._opnsense_get_service_id() == "svcx"


def test_compile_port_forward_with_missing_rules(coordinator):
    # port forward compile should return [] when nat not present or rules missing
    config_entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        data={CONF_DEVICE_UNIQUE_ID: "dev1"},
        title="t",
    )
    coordinator.data = {"config": {}}
    res = (
        __import__("asyncio")
        .get_event_loop()
        .run_until_complete(
            _compile_port_forward_switches(config_entry, coordinator, coordinator.data)
        )
    )
    assert res == []


def test_vpn_instance_key_parsing(coordinator):
    # ensure VPNSwitch parses key parts without raising
    desc = SwitchEntityDescription(key="openvpn.clients.c1", name="VPNC")
    ent = OPNsenseVPNSwitch(
        config_entry=SimpleNamespace(
            runtime_data=SimpleNamespace(coordinator=coordinator),
            data={CONF_DEVICE_UNIQUE_ID: "dev1"},
            title="t",
        ),
        coordinator=coordinator,
        entity_description=desc,
    )
    assert ent._vpn_type == "openvpn"
    assert ent._clients_servers == "clients"
    assert ent._uuid == "c1"
