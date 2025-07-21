"""Unit tests for custom_components.opnsense.coordinator.

These tests exercise the coordinator logic paths: initialization errors,
category building, state fetching, device ID mismatch handling, speed
calculations, and update flow.
"""

from datetime import timedelta
import time
from unittest.mock import MagicMock

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.opnsense import coordinator as coordinator_module
from custom_components.opnsense.const import (
    CONF_DEVICE_UNIQUE_ID,
    CONF_SYNC_INTERFACES,
    CONF_SYNC_VPN,
)
from custom_components.opnsense.coordinator import OPNsenseDataUpdateCoordinator


class FakeClient:
    def __init__(self, data_map=None):
        self._data_map = data_map or {}

    async def set_use_snake_case(self):
        return True

    async def reset_query_counts(self):
        return None

    async def get_query_counts(self):
        return 1, 1

    # generic getters used by _get_states
    async def get_telemetry(self):
        return {"telemetry": True}

    async def get_interfaces(self):
        return {"eth0": {"inbytes": 200, "outbytes": 100}}

    async def get_openvpn(self):
        return {"servers": {}}

    async def get_wireguard(self):
        return {"servers": {}}


@pytest.mark.asyncio
async def test_init_requires_config_entry():
    with pytest.raises(ValueError):
        OPNsenseDataUpdateCoordinator(
            hass=MagicMock(),
            client=FakeClient(),
            name="test",
            update_interval=timedelta(seconds=1),
            device_unique_id="id",
            config_entry=None,
        )


def _make_entry(data=None):
    data = data or {CONF_DEVICE_UNIQUE_ID: "id"}
    entry = MockConfigEntry(domain="opnsense", data=data, title="t")
    entry.runtime_data = {}
    return entry


@pytest.mark.asyncio
async def test_build_categories_respects_flags():
    entry = _make_entry(
        {CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_INTERFACES: True, CONF_SYNC_VPN: True}
    )
    client = FakeClient()
    coord = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry,
    )
    # categories built on init
    keys = [c["state_key"] for c in coord._categories]
    assert "interfaces" in keys
    assert "openvpn" in keys or "wireguard" in keys


@pytest.mark.asyncio
async def test_get_states_handles_missing_method_and_calls():
    client = FakeClient()
    coord = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=_make_entry(),
    )
    categories = [
        {"function": "get_telemetry", "state_key": "telemetry"},
        {"function": "nonexistent_method", "state_key": "bad"},
    ]
    state = await coord._get_states(categories)
    assert "telemetry" in state
    assert "bad" not in state


@pytest.mark.asyncio
async def test_check_device_unique_id_mismatch_triggers_issue(monkeypatch):
    entry = _make_entry({CONF_DEVICE_UNIQUE_ID: "expected"})
    client = FakeClient()
    coord = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="expected",
        config_entry=entry,
    )

    # state missing device_unique_id -> returns False and resets count
    coord._state = {}
    res = await coord._check_device_unique_id()
    assert res is False
    assert coord._mismatched_count == 0

    # state present but mismatched -> increments and eventually triggers issue
    coord._state = {"device_unique_id": "other"}
    # patch issue registry and async_shutdown to avoid side effects
    called = {"issue": 0, "shutdown": 0}

    async def fake_shutdown():
        called["shutdown"] += 1

    def fake_async_create_issue(**kwargs):
        called["issue"] += 1

    monkeypatch.setattr(coordinator_module.ir, "async_create_issue", fake_async_create_issue)
    coord.async_shutdown = fake_shutdown

    # call 3 times -> should call issue once and shutdown once
    await coord._check_device_unique_id()
    await coord._check_device_unique_id()
    await coord._check_device_unique_id()
    assert coord._mismatched_count == 3
    assert called["issue"] == 1
    assert called["shutdown"] == 1


@pytest.mark.asyncio
async def test_calculate_speed_normal_and_exception():
    # normal pkts
    new_prop, value = await OPNsenseDataUpdateCoordinator._calculate_speed(
        prop_name="inpkts",
        elapsed_time=2.0,
        current_parent_value=200,
        previous_parent_value=100,
    )
    assert new_prop.endswith("packets_per_second")
    assert isinstance(value, int)

    # zero elapsed_time -> exception handled -> rate 0
    new_prop2, value2 = await OPNsenseDataUpdateCoordinator._calculate_speed(
        prop_name="inpkts",
        elapsed_time=0,
        current_parent_value=10,
        previous_parent_value=5,
    )
    assert value2 == 0


@pytest.mark.asyncio
async def test_calculate_entity_speeds_applies_calculations():
    entry = _make_entry(
        {CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_INTERFACES: True, CONF_SYNC_VPN: True}
    )
    client = FakeClient()
    coord = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry,
    )

    # set up state and previous_state with times
    now = time.time()
    coord._state = {
        "update_time": now,
        "interfaces": {"eth0": {"inbytes": 200, "outbytes": 100, "inpkts": 300, "outpkts": 150}},
        "openvpn": {"servers": {"s1": {"total_bytes_recv": 1000, "total_bytes_sent": 2000}}},
        "previous_state": {
            "update_time": now - 2,
            "interfaces": {"eth0": {"inbytes": 100, "outbytes": 50, "inpkts": 100, "outpkts": 50}},
            "openvpn": {"servers": {"s1": {"total_bytes_recv": 500, "total_bytes_sent": 1000}}},
        },
    }

    # Should not raise
    await coord._calculate_entity_speeds()


@pytest.mark.asyncio
async def test_async_update_data_reentrancy_and_full_flow(monkeypatch):
    entry = _make_entry({CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_INTERFACES: True})
    client = FakeClient()
    coord = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry,
    )

    # reentrancy: set updating True
    coord._updating = True
    res = await coord._async_update_data()
    assert res == coord._state
    coord._updating = False

    # full flow: monkeypatch _check_device_unique_id to True and ensure functions called
    async def true_check():
        return True

    monkeypatch.setattr(coord, "_check_device_unique_id", true_check)

    # ensure calculate_entity_speeds is callable
    async def fake_calc():
        return None

    monkeypatch.setattr(coord, "_calculate_entity_speeds", fake_calc)
    # run update; should return a dict
    out = await coord._async_update_data()
    assert isinstance(out, dict)


@pytest.mark.asyncio
async def test_async_setup_calls_client_set_use_snake_case(monkeypatch):
    called = {"count": 0}

    async def fake_set_use_snake_case():
        called["count"] += 1

    entry = _make_entry()
    client = FakeClient()
    client.set_use_snake_case = fake_set_use_snake_case
    coord = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry,
    )

    # call the async setup which should call the client's set_use_snake_case
    await coord._async_setup()
    assert called["count"] == 1


@pytest.mark.asyncio
async def test_calculate_speed_bytes_case():
    # bytes branch should return kilobytes_per_second label
    new_prop, value = await OPNsenseDataUpdateCoordinator._calculate_speed(
        prop_name="inbytes",
        elapsed_time=2.0,
        current_parent_value=2000,
        previous_parent_value=1000,
    )
    assert "kilobytes_per_second" in new_prop
    assert isinstance(value, int)


def test_build_categories_returns_empty_when_no_config():
    entry = _make_entry()
    client = FakeClient()
    coord = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry,
    )
    # simulate missing config_entry
    coord.config_entry = None
    cats = coord._build_categories()
    assert cats == []
