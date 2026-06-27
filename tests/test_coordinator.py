"""Unit tests for custom_components.opnsense.coordinator.

These tests exercise the coordinator logic paths: initialization errors,
category building, state fetching, device ID mismatch handling, speed
calculations, and update flow.
"""

from collections.abc import Callable, MutableMapping
from datetime import timedelta
import logging
import time
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock, call

from homeassistant.config_entries import ConfigEntry
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.opnsense import coordinator as coordinator_module
from custom_components.opnsense.const import (
    ATTR_UNBOUND_BLOCKLIST,
    CONF_DEVICE_UNIQUE_ID,
    CONF_FIRMWARE_VERSION,
    CONF_SYNC_CARP,
    CONF_SYNC_CERTIFICATES,
    CONF_SYNC_DHCP_LEASES,
    CONF_SYNC_FIREWALL_AND_NAT,
    CONF_SYNC_FIRMWARE_UPDATES,
    CONF_SYNC_GATEWAYS,
    CONF_SYNC_INTERFACES,
    CONF_SYNC_NOTICES,
    CONF_SYNC_SERVICES,
    CONF_SYNC_SMART,
    CONF_SYNC_SPEEDTEST,
    CONF_SYNC_TELEMETRY,
    CONF_SYNC_UNBOUND,
    CONF_SYNC_VNSTAT,
    CONF_SYNC_VPN,
)
from custom_components.opnsense.coordinator import OPNsenseDataUpdateCoordinator


@pytest.mark.asyncio
async def test_init_requires_config_entry(fake_client: Any) -> None:
    """Ensure coordinator initialization requires a config entry."""
    with pytest.raises(ValueError):
        OPNsenseDataUpdateCoordinator(
            hass=MagicMock(),
            client=fake_client()(),
            name="test",
            update_interval=timedelta(seconds=1),
            device_unique_id="id",
            config_entry=cast("ConfigEntry[Any]", None),
        )


@pytest.mark.asyncio
async def test_build_categories_respects_flags(
    make_config_entry: Callable[..., MockConfigEntry], fake_client: Any
) -> None:
    """Categories builder respects configuration sync flags."""
    entry = make_config_entry(
        {CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_INTERFACES: True, CONF_SYNC_VPN: True}
    )
    client = fake_client()()
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
    assert "openvpn" in keys
    assert "wireguard" in keys
    assert "smart" in keys


@pytest.mark.asyncio
async def test_build_categories_includes_smart_by_default(
    make_config_entry: Callable[..., MockConfigEntry], fake_client: Any
) -> None:
    """SMART uses the shared granular sync default."""
    client = fake_client()()

    entry_default = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id"})
    coord_default = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry_default,
    )
    assert "smart" in [category["state_key"] for category in coord_default._categories]
    assert "smart_info" in [category["state_key"] for category in coord_default._categories]

    entry_disabled = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_SMART: False})
    coord_disabled = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry_disabled,
    )
    assert "smart" not in [category["state_key"] for category in coord_disabled._categories]


@pytest.mark.asyncio
async def test_get_states_fetches_smart_info_for_each_smart_device(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART attribute data should be fetched per discovered SMART device."""
    client = MagicMock()
    client.get_smart = AsyncMock(
        return_value=[
            {"device": "nvme0", "state": {"smart_status": {"passed": True}}},
            {"device": "ada0", "state": {"smart_status": {"passed": False}}},
            {"device": ""},
            "ignored",
        ]
    )
    client.get_smart_info = AsyncMock(
        side_effect=[
            {"temperature": {"current": 71}},
            {"temperature": {"current": 42}},
        ]
    )
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_SMART: True})
    coordinator = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry,
    )

    state = await coordinator._get_states(
        [
            {"function": "get_smart", "state_key": "smart"},
            {"function": "get_smart_info", "state_key": "smart_info"},
        ]
    )

    assert state["smart_info"] == {
        "nvme0": {"temperature": {"current": 71}},
        "ada0": {"temperature": {"current": 42}},
    }
    assert client.get_smart_info.await_args_list == [
        call(device="nvme0", info_type="A"),
        call(device="ada0", info_type="A"),
    ]


@pytest.mark.asyncio
async def test_get_states_continues_when_one_smart_device_lookup_fails(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART attribute data should keep processing after one per-device lookup fails."""
    client = MagicMock()
    client.get_smart = AsyncMock(
        return_value=[
            {"device": "nvme0", "state": {"smart_status": {"passed": True}}},
            {"device": "ada0", "state": {"smart_status": {"passed": False}}},
        ]
    )
    client.get_smart_info = AsyncMock(
        side_effect=[
            TimeoutError("nvme0 timed out"),
            {"temperature": {"current": 42}},
        ]
    )
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_SMART: True})
    coordinator = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry,
    )

    state = await coordinator._get_states(
        [
            {"function": "get_smart", "state_key": "smart"},
            {"function": "get_smart_info", "state_key": "smart_info"},
        ]
    )

    assert state["smart_info"] == {"ada0": {"temperature": {"current": 42}}}
    assert client.get_smart_info.await_args_list == [
        call(device="nvme0", info_type="A"),
        call(device="ada0", info_type="A"),
    ]


@pytest.mark.asyncio
async def test_get_states_skips_smart_info_when_smart_devices_missing(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART attribute data should stay empty without discovered SMART devices."""
    client = MagicMock()
    client.get_smart = AsyncMock(return_value={})
    client.get_smart_info = AsyncMock()
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_SMART: True})
    coordinator = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry,
    )

    state = await coordinator._get_states(
        [
            {"function": "get_smart", "state_key": "smart"},
            {"function": "get_smart_info", "state_key": "smart_info"},
        ]
    )

    assert state["smart_info"] == {}
    client.get_smart_info.assert_not_awaited()


@pytest.mark.asyncio
async def test_build_categories_includes_smart_without_smart_info_when_client_lacks_method(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART sync should still collect status when attribute data is unsupported."""

    class ClientWithoutSmartInfo:
        """Client that supports SMART status but not SMART attributes."""

        async def get_smart(self) -> list[Any]:
            """Return empty SMART status rows."""
            return []

    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_SMART: True})
    coordinator = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=cast("Any", ClientWithoutSmartInfo()),
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry,
    )

    state_keys = [category["state_key"] for category in coordinator._categories]
    assert "smart" in state_keys
    assert "smart_info" not in state_keys


@pytest.mark.asyncio
async def test_build_categories_skips_smart_when_client_lacks_support(
    make_config_entry: Callable[..., MockConfigEntry],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """SMART sync should not call unsupported runtime clients."""
    caplog.set_level(logging.DEBUG, logger=coordinator_module.__name__)
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_SMART: True})
    client = MagicMock()
    del client.get_smart

    coord = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry,
    )

    assert "smart" not in [category["state_key"] for category in coord._categories]
    assert "does not support it" in caplog.text


@pytest.mark.asyncio
async def test_get_states_handles_missing_method_and_calls(
    make_config_entry: Callable[..., MockConfigEntry], fake_client: Any
) -> None:
    """_get_states should skip missing client methods and return available states."""
    client = fake_client()()
    coord = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=make_config_entry(),
    )
    categories = [
        {"function": "get_telemetry", "state_key": "telemetry"},
        {"function": "nonexistent_method", "state_key": "bad"},
    ]
    state = await coord._get_states(categories)
    assert "telemetry" in state
    assert "bad" not in state


@pytest.mark.asyncio
async def test_get_states_uses_single_carp_call(
    make_config_entry: Callable[..., MockConfigEntry], fake_client: Any
) -> None:
    """Coordinator should fetch CARP once and populate unified CARP state key."""
    client = fake_client()()
    client.get_carp = AsyncMock(
        return_value={
            "interfaces": [{"interface": "wan", "subnet": "1.2.3.4", "status": "MASTER"}],
            "status_summary": {"state": "healthy", "vip_count": 1},
        }
    )

    coord = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=make_config_entry(),
    )
    categories = [
        {"function": "get_carp", "state_key": "carp"},
    ]

    state = await coord._get_states(categories)

    client.get_carp.assert_awaited_once()
    assert state["carp"]["interfaces"][0]["status"] == "MASTER"
    assert state["carp"]["status_summary"]["state"] == "healthy"


@pytest.mark.asyncio
async def test_check_device_unique_id_mismatch_triggers_issue(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_client: Any,
) -> None:
    """Mismatched device_unique_id should create an issue and shutdown after threshold."""
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "expected"})
    client = fake_client()()
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
    called: dict[str, Any] = {"issue": 0, "shutdown": 0, "issue_kwargs": None}

    async def fake_shutdown() -> None:
        """Record that the coordinator requested shutdown after repeated mismatches."""
        called["shutdown"] += 1

    def fake_async_create_issue(**kwargs: Any) -> None:
        # record the kwargs so tests can validate domain and issue_id
        """Capture the issue payload emitted for a device-ID mismatch.

        Args:
            **kwargs: Issue fields passed to ``issue_registry.async_create_issue``.
        """
        called["issue"] += 1
        called["issue_kwargs"] = kwargs

    monkeypatch.setattr(coordinator_module.ir, "async_create_issue", fake_async_create_issue)
    object.__setattr__(coord, "async_shutdown", fake_shutdown)

    # call 3 times -> should call issue once and shutdown once
    await coord._check_device_unique_id()
    await coord._check_device_unique_id()
    await coord._check_device_unique_id()
    assert coord._mismatched_count == 3
    assert called["issue"] == 1
    assert called["shutdown"] == 1
    # validate the issue was created for the integration domain and expected id
    assert isinstance(called["issue_kwargs"], MutableMapping)
    assert called["issue_kwargs"].get("domain") == coordinator_module.DOMAIN
    assert (
        called["issue_kwargs"].get("issue_id") == f"{coord._device_unique_id}_device_id_mismatched"
    )


@pytest.mark.asyncio
async def test_calculate_speed_normal_and_exception() -> None:
    """Calculate speed handles normal and exceptional (zero elapsed) cases."""
    # normal pkts
    new_prop, value = await OPNsenseDataUpdateCoordinator._calculate_speed(
        prop_name="inpkts",
        elapsed_time=2.0,
        current_parent_value=200,
        previous_parent_value=100,
    )
    assert new_prop == "inpkts_packets_per_second"
    assert isinstance(value, int)
    assert value == 50

    # zero elapsed_time -> exception handled -> rate 0
    _new_prop2, value2 = await OPNsenseDataUpdateCoordinator._calculate_speed(
        prop_name="inpkts",
        elapsed_time=0,
        current_parent_value=10,
        previous_parent_value=5,
    )
    assert value2 == 0


@pytest.mark.asyncio
async def test_calculate_entity_speeds_applies_calculations(
    make_config_entry: Callable[..., MockConfigEntry], fake_client: Any
) -> None:
    """Entity speed calculations should add correct rate keys to state."""
    entry = make_config_entry(
        {CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_INTERFACES: True, CONF_SYNC_VPN: True}
    )
    client = fake_client()()
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

    # calculate speeds and assert expected rate fields exist with correct values
    await coord._calculate_entity_speeds()

    # delta_time between now and previous_state is 2 seconds
    # coordinator stores byte rates as kilobytes_per_second (rounded) and
    # packet rates as packets_per_second (rounded). Assert those keys/values.
    assert "interfaces" in coord._state
    eth0 = coord._state["interfaces"]["eth0"]
    # byte rates -> kilobytes_per_second (rounded)
    assert "inbytes_kilobytes_per_second" in eth0
    assert "outbytes_kilobytes_per_second" in eth0
    # packet rates -> packets_per_second
    assert "inpkts_packets_per_second" in eth0
    assert "outpkts_packets_per_second" in eth0

    # Compute expected rounded values
    # inbytes: change = 100 B/s -> 100 / 2 = 50 B/s -> 50 / 1000 = 0.05 KB/s -> round = 0
    # outbytes: change = 50 B/s -> 25 B/s -> 0.025 KB/s -> round = 0
    assert eth0["inbytes_kilobytes_per_second"] == pytest.approx(0.5, abs=0.5)
    assert eth0["outbytes_kilobytes_per_second"] == pytest.approx(0.5, abs=0.5)
    assert eth0["inpkts_packets_per_second"] == pytest.approx(100, abs=0.5)
    assert eth0["outpkts_packets_per_second"] == pytest.approx(50, abs=0.5)

    # openvpn server s1 expected rates (kilobytes_per_second, rounded)
    assert "openvpn" in coord._state
    assert "servers" in coord._state["openvpn"]
    s1 = coord._state["openvpn"]["servers"]["s1"]
    assert "total_bytes_recv_kilobytes_per_second" in s1
    assert "total_bytes_sent_kilobytes_per_second" in s1
    # total_bytes_recv: (1000-500)/2 = 250 B/s -> 0.25 KB/s -> round = 0
    # total_bytes_sent: (2000-1000)/2 = 500 B/s -> 0.5 KB/s -> round = 0
    assert s1["total_bytes_recv_kilobytes_per_second"] == pytest.approx(0.5, abs=0.5)
    assert s1["total_bytes_sent_kilobytes_per_second"] == pytest.approx(0.5, abs=0.5)


@pytest.mark.asyncio
async def test_calculate_entity_speeds_treats_counter_decrease_as_reset(
    make_config_entry: Callable[..., MockConfigEntry], fake_client: Any
) -> None:
    """Counter resets should not be reported as traffic spikes."""
    entry = make_config_entry(
        {CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_INTERFACES: True, CONF_SYNC_VPN: True}
    )
    client = fake_client()()
    coord = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry,
    )

    # Now simulate a rollback: previous counters larger than current
    now = time.time()
    coord._state = {
        "update_time": now,
        "interfaces": {"eth0": {"inbytes": 100, "outbytes": 50, "inpkts": 10, "outpkts": 5}},
        "openvpn": {"servers": {"s1": {"total_bytes_recv": 100, "total_bytes_sent": 200}}},
        "previous_state": {
            "update_time": now - 2,
            "interfaces": {
                "eth0": {"inbytes": 1000, "outbytes": 500, "inpkts": 1000, "outpkts": 500}
            },
            "openvpn": {"servers": {"s1": {"total_bytes_recv": 1000, "total_bytes_sent": 2000}}},
        },
    }

    await coord._calculate_entity_speeds()

    eth0 = coord._state["interfaces"]["eth0"]
    assert eth0["inbytes_kilobytes_per_second"] == 0
    assert eth0["outbytes_kilobytes_per_second"] == 0
    assert eth0["inpkts_packets_per_second"] == 0
    assert eth0["outpkts_packets_per_second"] == 0

    s1 = coord._state["openvpn"]["servers"]["s1"]
    assert s1["total_bytes_recv_kilobytes_per_second"] == 0
    assert s1["total_bytes_sent_kilobytes_per_second"] == 0


@pytest.mark.asyncio
async def test_calculate_entity_speeds_skips_missing_counter_values(
    make_config_entry: Callable[..., MockConfigEntry], fake_client: Any
) -> None:
    """Missing counter values should not abort a coordinator refresh."""
    entry = make_config_entry(
        {CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_INTERFACES: True, CONF_SYNC_VPN: True}
    )
    client = fake_client()()
    coord = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry,
    )

    now = time.time()
    coord._state = {
        "update_time": now,
        "interfaces": {"eth0": {"inbytes": 200, "inpkts": 300}},
        "openvpn": {"servers": {"s1": {"total_bytes_recv": 1000}}},
        "wireguard": {"clients": {"c1": {"total_bytes_sent": 2000}}},
        "previous_state": {
            "update_time": now - 2,
            "interfaces": {"eth0": {"inbytes": 100}},
            "openvpn": {"servers": {"s1": {}}},
            "wireguard": {"clients": {"c1": {"total_bytes_sent": 1000}}},
        },
    }

    await coord._calculate_entity_speeds()

    eth0 = coord._state["interfaces"]["eth0"]
    assert eth0["inbytes_kilobytes_per_second"] == 0
    assert "outbytes_kilobytes_per_second" not in eth0
    assert "inpkts_packets_per_second" not in eth0
    assert "outpkts_packets_per_second" not in eth0
    assert "total_bytes_recv_kilobytes_per_second" not in coord._state["openvpn"]["servers"]["s1"]
    assert coord._state["wireguard"]["clients"]["c1"]["total_bytes_sent_kilobytes_per_second"] == 0


@pytest.mark.asyncio
async def test_async_update_data_reentrancy_and_full_flow(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_client: Any,
) -> None:
    """End-to-end coordinator update flow and reentrancy behavior."""
    entry = make_config_entry({CONF_DEVICE_UNIQUE_ID: "id", CONF_SYNC_INTERFACES: True})
    client = fake_client()()
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
    async def true_check() -> bool:
        """Force the device-ID validation step to succeed."""
        return True

    monkeypatch.setattr(coord, "_check_device_unique_id", true_check)

    # ensure calculate_entity_speeds is callable
    async def fake_calc() -> None:
        """Skip entity-speed calculation while still satisfying the update flow."""
        return

    monkeypatch.setattr(coord, "_calculate_entity_speeds", fake_calc)
    # Spy on client's reset_query_counts before running the update so we can
    # assert the public method was awaited during the update flow.
    object.__setattr__(
        client, "reset_query_counts", AsyncMock(wraps=getattr(client, "reset_query_counts", None))
    )
    object.__setattr__(client, "get_query_counts", AsyncMock(return_value=11))

    # run update; should return a dict
    out = await coord._async_update_data()
    assert isinstance(out, MutableMapping)
    # Verify returned dict is the coordinator's state and bookkeeping completed
    assert out == coord._state
    assert coord._updating is False
    # Ensure a last-update marker exists via DataUpdateCoordinator API
    assert isinstance(coord.last_update_success, bool)
    # And the client.reset_query_counts public method was awaited exactly once
    client.reset_query_counts.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_update_data_enables_firewall_polling_when_runtime_firmware_updates(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_client: Any,
) -> None:
    """Firewall polling should run when sync is enabled, regardless of stored firmware."""
    entry = make_config_entry(
        {
            CONF_DEVICE_UNIQUE_ID: "id",
            CONF_FIRMWARE_VERSION: "25.1",
            CONF_SYNC_FIREWALL_AND_NAT: True,
            CONF_SYNC_INTERFACES: False,
            CONF_SYNC_TELEMETRY: False,
            CONF_SYNC_VNSTAT: False,
            CONF_SYNC_SPEEDTEST: False,
            CONF_SYNC_SMART: False,
            CONF_SYNC_VPN: False,
            CONF_SYNC_FIRMWARE_UPDATES: False,
            CONF_SYNC_CARP: False,
            CONF_SYNC_DHCP_LEASES: False,
            CONF_SYNC_GATEWAYS: False,
            CONF_SYNC_SERVICES: False,
            CONF_SYNC_NOTICES: False,
            CONF_SYNC_UNBOUND: False,
            CONF_SYNC_CERTIFICATES: False,
        }
    )
    client = fake_client()()
    object.__setattr__(
        client,
        "get_host_firmware_version",
        AsyncMock(side_effect=["26.1.1", "26.1.1"]),
    )
    object.__setattr__(
        client,
        "get_firewall",
        AsyncMock(return_value={"config": {"filter": {"rule": []}}}),
    )
    object.__setattr__(
        client,
        "get_system_info",
        AsyncMock(return_value={"name": "test-router"}),
    )
    object.__setattr__(
        client,
        "reset_query_counts",
        AsyncMock(
            wraps=getattr(client, "reset_query_counts", None),
        ),
    )
    object.__setattr__(client, "get_query_counts", AsyncMock(return_value=11))

    coord = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry,
    )

    async def true_check() -> bool:
        """Force the device-id validation step to succeed."""
        return True

    monkeypatch.setattr(coord, "_check_device_unique_id", true_check)

    async def fake_calc() -> None:
        """Skip speed calculations for this path under test."""
        return

    monkeypatch.setattr(coord, "_calculate_entity_speeds", fake_calc)

    first_update = await coord._async_update_data()
    assert first_update == coord._state
    assert coord._state.get("host_firmware_version") == "26.1.1"
    assert client.get_firewall.await_count == 1
    assert coord._state.get("firewall") == {"config": {"filter": {"rule": []}}}

    second_update = await coord._async_update_data()
    assert second_update == coord._state
    assert coord._state.get("firewall") == {"config": {"filter": {"rule": []}}}
    assert client.get_firewall.await_count == 2


@pytest.mark.asyncio
async def test_build_categories_and_refresh_queue_firewall_for_legacy_firmware(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_client: Any,
) -> None:
    """Legacy firmware should rely on aiopnsense empty firewall responses."""
    entry = make_config_entry(
        {
            CONF_DEVICE_UNIQUE_ID: "id",
            CONF_FIRMWARE_VERSION: "26.1.1",
            CONF_SYNC_FIREWALL_AND_NAT: True,
            CONF_SYNC_INTERFACES: False,
            CONF_SYNC_TELEMETRY: False,
            CONF_SYNC_VNSTAT: False,
            CONF_SYNC_SPEEDTEST: False,
            CONF_SYNC_SMART: False,
            CONF_SYNC_VPN: False,
            CONF_SYNC_FIRMWARE_UPDATES: False,
            CONF_SYNC_CARP: False,
            CONF_SYNC_DHCP_LEASES: False,
            CONF_SYNC_GATEWAYS: False,
            CONF_SYNC_SERVICES: False,
            CONF_SYNC_NOTICES: False,
            CONF_SYNC_UNBOUND: False,
            CONF_SYNC_CERTIFICATES: False,
        }
    )
    client = fake_client(device_id="id", firmware_version="26.1.1")()
    object.__setattr__(client, "get_host_firmware_version", AsyncMock(return_value="25.1"))
    object.__setattr__(
        client,
        "get_firewall",
        AsyncMock(return_value={"rules": {}, "nat": {}}),
    )
    object.__setattr__(
        client,
        "get_system_info",
        AsyncMock(return_value={"name": "test-router"}),
    )
    object.__setattr__(
        client,
        "reset_query_counts",
        AsyncMock(wraps=getattr(client, "reset_query_counts", None)),
    )
    object.__setattr__(client, "get_query_counts", AsyncMock(return_value=11))

    coord = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry,
    )

    assert "firewall" in [category["state_key"] for category in coord._categories]

    async def true_check() -> bool:
        """Force the device-id validation step to succeed."""
        return True

    monkeypatch.setattr(coord, "_check_device_unique_id", true_check)

    async def fake_calc() -> None:
        """Skip speed calculations for this path under test."""
        return

    monkeypatch.setattr(coord, "_calculate_entity_speeds", fake_calc)

    first_update = await coord._async_update_data()
    assert first_update == coord._state
    assert coord._state.get("host_firmware_version") == "25.1"
    assert coord._state.get("firewall") == {"rules": {}, "nat": {}}
    assert client.get_firewall.await_count == 1


@pytest.mark.asyncio
async def test_async_update_data_continues_firewall_polling_after_runtime_downgrade(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_client: Any,
) -> None:
    """Downgraded runtime firmware should still poll firewall state through aiopnsense."""
    entry = make_config_entry(
        {
            CONF_DEVICE_UNIQUE_ID: "id",
            CONF_SYNC_FIREWALL_AND_NAT: True,
            CONF_SYNC_INTERFACES: False,
            CONF_SYNC_TELEMETRY: False,
            CONF_SYNC_VNSTAT: False,
            CONF_SYNC_SPEEDTEST: False,
            CONF_SYNC_SMART: False,
            CONF_SYNC_VPN: False,
            CONF_SYNC_FIRMWARE_UPDATES: False,
            CONF_SYNC_CARP: False,
            CONF_SYNC_DHCP_LEASES: False,
            CONF_SYNC_GATEWAYS: False,
            CONF_SYNC_SERVICES: False,
            CONF_SYNC_NOTICES: False,
            CONF_SYNC_UNBOUND: False,
            CONF_SYNC_CERTIFICATES: False,
        }
    )
    client = fake_client(device_id="id", firmware_version="26.1.1")()
    object.__setattr__(
        client, "get_host_firmware_version", AsyncMock(side_effect=["26.1.1", "25.1"])
    )
    object.__setattr__(
        client,
        "get_firewall",
        AsyncMock(
            side_effect=[
                {"rules": {"r1": {"uuid": "r1", "description": "Modern"}}},
                {"rules": {}, "nat": {}},
            ]
        ),
    )
    object.__setattr__(
        client,
        "get_system_info",
        AsyncMock(return_value={"name": "test-router"}),
    )
    object.__setattr__(
        client,
        "reset_query_counts",
        AsyncMock(wraps=getattr(client, "reset_query_counts", None)),
    )
    object.__setattr__(client, "get_query_counts", AsyncMock(return_value=11))

    coord = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry,
    )

    async def true_check() -> bool:
        """Force the device-id validation step to succeed."""
        return True

    monkeypatch.setattr(coord, "_check_device_unique_id", true_check)

    async def fake_calc() -> None:
        """Skip speed calculations for this path under test."""
        return

    monkeypatch.setattr(coord, "_calculate_entity_speeds", fake_calc)

    first_update = await coord._async_update_data()
    assert first_update == coord._state
    assert coord._state.get("host_firmware_version") == "26.1.1"
    assert coord._state.get("firewall") == {
        "rules": {"r1": {"uuid": "r1", "description": "Modern"}}
    }
    assert client.get_firewall.await_count == 1

    second_update = await coord._async_update_data()
    assert second_update == coord._state
    assert coord._state.get("host_firmware_version") == "25.1"
    assert coord._state.get("firewall") == {"rules": {}, "nat": {}}
    assert client.get_firewall.await_count == 2


@pytest.mark.asyncio
async def test_async_update_data_fetches_firewall_on_first_refresh_if_firmware_is_learned_and_not_stored(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_client: Any,
) -> None:
    """When stored firmware is missing, first refresh should fetch firewall after learning version."""
    entry = make_config_entry(
        {
            CONF_DEVICE_UNIQUE_ID: "id",
            CONF_SYNC_FIREWALL_AND_NAT: True,
            CONF_SYNC_INTERFACES: False,
            CONF_SYNC_TELEMETRY: False,
            CONF_SYNC_VNSTAT: False,
            CONF_SYNC_SPEEDTEST: False,
            CONF_SYNC_SMART: False,
            CONF_SYNC_VPN: False,
            CONF_SYNC_FIRMWARE_UPDATES: False,
            CONF_SYNC_CARP: False,
            CONF_SYNC_DHCP_LEASES: False,
            CONF_SYNC_GATEWAYS: False,
            CONF_SYNC_SERVICES: False,
            CONF_SYNC_NOTICES: False,
            CONF_SYNC_UNBOUND: False,
            CONF_SYNC_CERTIFICATES: False,
        }
    )
    client = fake_client(device_id="id", firmware_version="25.1")()
    object.__setattr__(
        client,
        "get_host_firmware_version",
        AsyncMock(side_effect=["26.1.1"]),
    )
    object.__setattr__(
        client,
        "get_firewall",
        AsyncMock(return_value={"rules": {"r1": {"uuid": "r1", "description": "Bootstrapped"}}}),
    )
    object.__setattr__(
        client,
        "get_system_info",
        AsyncMock(return_value={"name": "test-router"}),
    )
    object.__setattr__(
        client,
        "reset_query_counts",
        AsyncMock(wraps=getattr(client, "reset_query_counts", None)),
    )
    object.__setattr__(client, "get_query_counts", AsyncMock(return_value=11))

    coord = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry,
    )

    async def true_check() -> bool:
        """Force the device-id validation step to succeed."""
        return True

    monkeypatch.setattr(coord, "_check_device_unique_id", true_check)

    async def fake_calc() -> None:
        """Skip speed calculations for this path under test."""
        return

    monkeypatch.setattr(coord, "_calculate_entity_speeds", fake_calc)

    first_update = await coord._async_update_data()
    assert first_update == coord._state
    assert coord._state.get("host_firmware_version") == "26.1.1"
    assert coord._state.get("firewall") == {
        "rules": {"r1": {"uuid": "r1", "description": "Bootstrapped"}}
    }
    assert client.get_firewall.await_count == 1


@pytest.mark.asyncio
async def test_calculate_speed_bytes_case() -> None:
    """Calculate byte-rate conversion yields kilobytes_per_second."""
    # bytes branch should return kilobytes_per_second label
    new_prop, value = await OPNsenseDataUpdateCoordinator._calculate_speed(
        prop_name="inbytes",
        elapsed_time=2.0,
        current_parent_value=2000,
        previous_parent_value=1000,
    )
    assert new_prop == "inbytes_kilobytes_per_second"
    assert isinstance(value, int)
    assert value == pytest.approx(0.5, abs=0.5)  # 500 B/s -> 0.5 KB/s, allow ±0.5 tolerance


def test_build_categories_returns_empty_when_no_config(
    make_config_entry: Callable[..., MockConfigEntry], fake_client: Any
) -> None:
    """Categories builder returns empty list when config_entry is missing."""
    entry = make_config_entry()
    client = fake_client()()
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("flag", "expected_keys"),
    [
        (CONF_SYNC_TELEMETRY, ["telemetry"]),
        (CONF_SYNC_VNSTAT, ["vnstat"]),
        (CONF_SYNC_SPEEDTEST, ["speedtest"]),
        (CONF_SYNC_SMART, ["smart", "smart_info"]),
        (CONF_SYNC_VPN, ["openvpn", "wireguard"]),
        (CONF_SYNC_FIRMWARE_UPDATES, ["firmware_update_info"]),
        (CONF_SYNC_CARP, ["carp"]),
        (CONF_SYNC_DHCP_LEASES, ["dhcp_leases"]),
        (CONF_SYNC_GATEWAYS, ["gateways"]),
        (CONF_SYNC_SERVICES, ["services"]),
        (CONF_SYNC_NOTICES, ["notices"]),
        (CONF_SYNC_UNBOUND, [ATTR_UNBOUND_BLOCKLIST]),
        (CONF_SYNC_INTERFACES, ["interfaces"]),
        (CONF_SYNC_CERTIFICATES, ["certificates"]),
    ],
)
async def test_build_categories_flag_true_and_false(
    make_config_entry: Callable[..., MockConfigEntry],
    fake_client: Any,
    flag: Any,
    expected_keys: Any,
) -> None:
    """Verify categories include keys when flag True and exclude when False."""
    # When flag is True -> expected keys present
    entry_true = make_config_entry(
        {
            "device_unique_id": "id",
            CONF_FIRMWARE_VERSION: "26.1.1",
            flag: True,
        }
    )
    client = fake_client()()
    coord_true = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry_true,
    )
    keys_true = [c["state_key"] for c in coord_true._categories]
    for ek in expected_keys:
        assert ek in keys_true

    # When flag is False -> expected keys absent
    entry_false = make_config_entry(
        {
            "device_unique_id": "id",
            CONF_FIRMWARE_VERSION: "26.1.1",
            flag: False,
        }
    )
    coord_false = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry_false,
    )
    keys_false = [c["state_key"] for c in coord_false._categories]
    for ek in expected_keys:
        assert ek not in keys_false


@pytest.mark.asyncio
async def test_build_categories_includes_firewall_when_sync_is_enabled(
    make_config_entry: Callable[..., MockConfigEntry],
    fake_client: Any,
) -> None:
    """Firewall category should be queued whenever firewall sync is enabled."""
    entry = make_config_entry(
        {
            "device_unique_id": "id",
            CONF_SYNC_FIREWALL_AND_NAT: True,
            CONF_FIRMWARE_VERSION: "25.1",
        }
    )
    client = fake_client()()
    coord = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry,
    )
    keys_true = [c["state_key"] for c in coord._build_categories()]
    assert "firewall" in keys_true


@pytest.mark.asyncio
async def test_build_categories_keeps_firewall_polling_for_legacy_firmware(
    make_config_entry: Callable[..., MockConfigEntry],
    fake_client: Any,
) -> None:
    """Legacy firmware should keep native firewall polling and skip removed backends."""
    entry = make_config_entry(
        {
            CONF_DEVICE_UNIQUE_ID: "id",
            CONF_SYNC_FIREWALL_AND_NAT: True,
            CONF_FIRMWARE_VERSION: "26.1.1",
        }
    )
    client = fake_client()()
    coord = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry,
    )

    # Force the runtime state to legacy firmware and rebuild categories.
    coord._state["host_firmware_version"] = "25.1"
    keys = [cat["state_key"] for cat in coord._build_categories()]
    functions = [cat["function"] for cat in coord._build_categories()]

    assert "firewall" in keys
    assert "get_firewall" in functions
    assert "is_plugin_installed" not in functions
    assert "is_plugin_deprecated" not in functions


@pytest.mark.asyncio
async def test_async_update_data_preserves_only_counter_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_client: Any,
) -> None:
    """Previous state should keep only fields needed for counter rates."""
    entry = make_config_entry({"device_unique_id": "id", CONF_SYNC_INTERFACES: True})
    client = fake_client()()
    coord = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry,
    )

    now = time.time()
    coord._state = {
        "update_time": now,
        "previous_state": {"inner": 1},
        "device_unique_id": "id",
        "interfaces": {"eth0": {"inbytes": 100}},
        "openvpn": {"servers": {"s1": {"total_bytes_recv": 1000}}},
        "firewall": {"rules": {"r1": {"description": "large payload"}}},
        "extra": "keep",
    }

    async def true_check() -> bool:
        """Force device-ID validation to pass for previous-state assertions."""
        return True

    async def noop_calc() -> None:
        """Skip speed calculation so the test can focus on state copying."""
        return

    monkeypatch.setattr(coord, "_check_device_unique_id", true_check)
    monkeypatch.setattr(coord, "_calculate_entity_speeds", noop_calc)

    object.__setattr__(
        client, "reset_query_counts", AsyncMock(wraps=getattr(client, "reset_query_counts", None))
    )

    out = await coord._async_update_data()

    assert isinstance(out, MutableMapping)
    assert "previous_state" in out
    assert "previous_state" not in out["previous_state"]
    assert out["previous_state"] == {
        "update_time": now,
        "interfaces": {"eth0": {"inbytes": 100}},
        "openvpn": {"servers": {"s1": {"total_bytes_recv": 1000}}},
    }


@pytest.mark.asyncio
async def test_async_update_data_device_tracker_branch(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_client: Any,
) -> None:
    """When coordinator is a device tracker coordinator, _async_update_data should return _async_update_dt_data result."""
    entry = make_config_entry({"device_unique_id": "id"})
    client = fake_client()()
    # create coordinator as device tracker coordinator
    coord = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry,
        device_tracker_coordinator=True,
    )

    # patch the device tracker update to return a specific dict and record calls
    called = {"dt_called": 0}

    async def fake_dt_update() -> dict[str, Any]:
        """Return a canned device-tracker payload and record the call count."""
        called["dt_called"] += 1
        return {"dt": True}

    monkeypatch.setattr(coord, "_async_update_dt_data", fake_dt_update)

    # spy on client's reset_query_counts
    object.__setattr__(
        client, "reset_query_counts", AsyncMock(wraps=getattr(client, "reset_query_counts", None))
    )

    res = await coord._async_update_data()
    assert res == {"dt": True}
    assert called["dt_called"] == 1
    client.reset_query_counts.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_update_data_returns_empty_when_device_id_check_fails(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_client: Any,
) -> None:
    """When device unique id check fails, _async_update_data should return an empty dict."""
    entry = make_config_entry({"device_unique_id": "id", CONF_SYNC_INTERFACES: True})
    client = fake_client()()
    coord = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry,
    )

    async def false_check() -> bool:
        """Force device-ID validation to fail for the early-return branch."""
        return False

    # make the device id check return False
    monkeypatch.setattr(coord, "_check_device_unique_id", false_check)

    # spy on reset_query_counts
    object.__setattr__(
        client, "reset_query_counts", AsyncMock(wraps=getattr(client, "reset_query_counts", None))
    )

    res = await coord._async_update_data()

    assert res == {}
    client.reset_query_counts.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["no_previous", "no_config"])
async def test_calculate_entity_speeds_returns_early_when_missing(
    case: Any,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_client: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_calculate_entity_speeds should return early when previous_update_time is falsy or config_entry is falsy."""
    entry = make_config_entry(
        {"device_unique_id": "id", CONF_SYNC_INTERFACES: True, CONF_SYNC_VPN: True}
    )
    client = fake_client()()
    coord = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry,
    )

    now = time.time()
    if case == "no_previous":
        # update_time present but previous_state.update_time missing -> early return
        coord._state = {"update_time": now, "previous_state": {}}
    else:
        # previous_update_time present but config_entry falsy -> early return
        coord._state = {"update_time": now, "previous_state": {"update_time": now - 2}}
        object.__setattr__(coord, "config_entry", None)

    # Ensure the deeper calculation functions are not called when guard triggers
    object.__setattr__(
        coord,
        "_calculate_interface_speeds",
        AsyncMock(side_effect=AssertionError("_calculate_interface_speeds should not be called")),
    )
    object.__setattr__(
        coord,
        "_calculate_vpn_speeds",
        AsyncMock(side_effect=AssertionError("_calculate_vpn_speeds should not be called")),
    )

    # Call the method; it should return None and not call the mocked methods
    await coord._calculate_entity_speeds()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("returned_device_id", "should_call_counts"),
    [
        (None, False),
        ("other", False),
        ("id", True),
    ],
)
async def test_async_update_dt_data_device_id_branches(
    returned_device_id: Any,
    should_call_counts: Any,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_client: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify _async_update_dt_data returns early for missing/mismatched IDs and calls query counts when OK."""
    entry = make_config_entry({"device_unique_id": "id"})
    client = fake_client()()
    coord = OPNsenseDataUpdateCoordinator(
        hass=MagicMock(),
        client=client,
        name="n",
        update_interval=timedelta(seconds=1),
        device_unique_id="id",
        config_entry=entry,
    )

    # stub _get_states to return controlled values
    fake_state = {
        "device_unique_id": returned_device_id,
        "host_firmware_version": "fv",
        "system_info": {"name": "opn"},
        "arp_table": {"a": 1},
    }

    async def fake_get_states(categories: list[dict[str, str]]) -> dict[str, Any]:
        """Return the canned state payload used by the device-tracker branch test.

        Args:
            categories: Categories requested by the coordinator and ignored by this fake.
        """
        return fake_state

    monkeypatch.setattr(coord, "_get_states", fake_get_states)

    # spy on client's get_query_counts
    object.__setattr__(client, "get_query_counts", AsyncMock(return_value=3))

    res = await coord._async_update_dt_data()

    if should_call_counts:
        # Should return the state and call get_query_counts
        assert isinstance(res, MutableMapping)
        assert res.get("device_unique_id") == "id"
        client.get_query_counts.assert_awaited_once()
    else:
        # Should return empty dict and not call get_query_counts
        assert res == {}
        assert client.get_query_counts.await_count == 0
