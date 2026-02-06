"""End-to-end style integration tests for the hass-opnsense integration.

These tests intentionally exercise multiple layers together (config flow +
entry setup + options flow) to provide confidence that the main user
journeys succeed when stitched end-to-end. They still rely on extensive
monkeypatching of network / OPNsense client calls so they remain fast and
deterministic while validating control flow, data propagation and side
effects.

NOTE: A lightweight MagicMock-based Home Assistant stand‑in is used instead
of the full pytest-homeassistant-custom-component hass fixture so that we do
not interfere with existing unit tests which purposely employ a simplified
mock hass. If desired in the future these tests could be migrated to use the
real hass fixture for deeper integration, but that would require adapting
the project-wide conftest which currently overrides the hass fixture.
"""

from __future__ import annotations

import asyncio
from collections.abc import MutableMapping
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

import custom_components.opnsense as init_mod
from custom_components.opnsense import config_flow as cf_mod
from custom_components.opnsense.const import (
    CONF_DEVICE_TRACKER_ENABLED,
    CONF_DEVICE_UNIQUE_ID,
    CONF_DEVICES,
    CONF_GRANULAR_SYNC_OPTIONS,
    CONF_MANUAL_DEVICES,
)
from homeassistant.const import CONF_NAME, CONF_PASSWORD, CONF_URL, CONF_USERNAME, CONF_VERIFY_SSL

homeassistant = pytest.importorskip("homeassistant")


class _FakeFlowClient:
    """Fake client used during config & options flows.

    It implements only the async methods the flows invoke.
    """

    def __init__(self, device_id: str = "dev-flow", firmware: str = "25.1") -> None:
        self._device_id = device_id
        self._firmware = firmware

    async def get_host_firmware_version(self) -> str:
        return self._firmware

    async def set_use_snake_case(self, initial: bool = False) -> None:
        """No-op used by config flow validation path."""
        return

    async def is_plugin_installed(self) -> bool:  # for SYNC_ITEMS_REQUIRING_PLUGIN path
        return True

    async def get_system_info(self) -> MutableMapping[str, Any]:
        return {"name": "OPNsenseTest"}

    async def get_device_unique_id(self) -> str:
        return self._device_id

    async def get_arp_table(self, resolve_hostnames: bool = False) -> list[dict[str, Any]]:
        # Used by options flow device tracker step
        return [
            {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "host1", "ip": "192.168.1.10"},
            {"mac": "11:22:33:44:55:66", "hostname": "", "ip": "192.168.1.11"},
        ]


class _FakeRuntimeClient:
    """Fake client used during async_setup_entry (main integration path)."""

    def __init__(self, device_id: str = "dev-runtime", firmware: str = "25.1") -> None:
        self._device_id = device_id
        self._firmware = firmware
        self._closed = False

    async def get_device_unique_id(self) -> str:  # used by setup & coordinator
        return self._device_id

    async def get_host_firmware_version(self) -> str:  # used by setup & coordinator
        return self._firmware

    async def async_close(self) -> bool:
        self._closed = True
        return True

    async def set_use_snake_case(
        self, initial: bool = False
    ) -> None:  # called during coordinator _async_setup
        # Accept the optional `initial` flag like the production client. No-op for tests.
        return None

    async def reset_query_counts(self) -> None:
        return None

    async def get_query_counts(self) -> tuple[int, int]:
        return (0, 0)

    async def get_system_info(self):  # first refresh path
        return {"name": "sys"}


class _FakeCoordinator:
    """Minimal coordinator stand‑in used for async_setup_entry tests."""

    def __init__(self, **kwargs: Any) -> None:  # pragma: no cover - simple init
        # capture flags we care about for assertions if needed
        self._device_tracker = kwargs.get("device_tracker_coordinator", False)
        self._refreshed = False

    async def async_config_entry_first_refresh(self) -> bool:
        self._refreshed = True
        return True

    async def async_shutdown(self) -> bool:  # pragma: no cover - not used in happy path
        return True


def _make_basic_user_input() -> dict[str, Any]:
    return {
        CONF_URL: "https://router.example",
        CONF_USERNAME: "user",
        CONF_PASSWORD: "pass",
        CONF_VERIFY_SSL: True,
        CONF_NAME: "MyRouter",
        CONF_GRANULAR_SYNC_OPTIONS: False,
    }


def _build_mock_hass() -> Any:
    """Construct a lightweight hass stand‑in with required attributes."""
    hass = MagicMock()
    hass.data = {}

    # config_entries API surface used inside tests
    class _Cfg:
        def __init__(self) -> None:
            self._entries: dict[str, Any] = {}

        def async_update_entry(
            self,
            entry,
            data=None,
            options=None,
            version=None,
            unique_id=None,
            **kwargs,
        ):
            # Bypass ConfigEntry attribute protections using object.__setattr__
            if data is not None:
                object.__setattr__(entry, "data", data)
            if options is not None:
                object.__setattr__(entry, "options", options)
            if unique_id is not None:
                object.__setattr__(entry, "unique_id", unique_id)
            if version is not None:
                object.__setattr__(entry, "version", version)
            return True

        async def async_forward_entry_setups(self, entry, platforms):  # pragma: no cover
            return True

        async def async_unload_platforms(self, entry, platforms):  # pragma: no cover
            return True

        async def async_reload(self, entry_id):  # pragma: no cover - reload path not asserted
            return None

    hass.config_entries = _Cfg()
    hass.async_create_task = MagicMock(side_effect=asyncio.create_task)
    return hass


@pytest.mark.asyncio
async def test_e2e_basic_config_flow_and_setup(monkeypatch, make_config_entry):
    """E2E: basic config flow (single step) followed by entry setup."""

    # Patch client for config flow
    monkeypatch.setattr(
        cf_mod, "OPNsenseClient", lambda **k: _FakeFlowClient(device_id="dev-basic")
    )
    monkeypatch.setattr(
        cf_mod, "async_create_clientsession", lambda **k: MagicMock(), raising=False
    )

    flow = cf_mod.OPNsenseConfigFlow()
    hass = _build_mock_hass()
    flow.hass = hass

    # Bypass HA flow unique-id internals (we don't implement hass.config_entries.flow)
    async def _noop_unique_id(*a, **k):
        return None

    flow.async_set_unique_id = _noop_unique_id
    flow._abort_if_unique_id_configured = lambda: None

    user_input = _make_basic_user_input()
    # Run user step -> should create entry directly (no granular sync)
    result = await flow.async_step_user(user_input=user_input)
    assert result["type"] == "create_entry"
    data = result["data"]
    assert data[CONF_DEVICE_UNIQUE_ID] == "dev-basic"
    assert data[CONF_NAME] == "MyRouter"

    # Now patch runtime client & coordinator and call async_setup_entry
    monkeypatch.setattr(
        init_mod, "OPNsenseClient", lambda **k: _FakeRuntimeClient(device_id="dev-basic")
    )
    monkeypatch.setattr(init_mod, "OPNsenseDataUpdateCoordinator", _FakeCoordinator)

    # Build ConfigEntry using MockConfigEntry for better parity
    entry = make_config_entry(
        data={**data},
        title=data[CONF_NAME],
        unique_id=data[CONF_DEVICE_UNIQUE_ID],
        entry_id="entry_basic",
        options={},
    )
    # Provide stubs expected by integration (update listener registration returns unsubscribe)
    entry.add_update_listener = lambda f: lambda: None
    entry.async_on_unload = lambda x: None
    hass.data = {}

    ok = await init_mod.async_setup_entry(hass, entry)
    assert ok is True
    # hass.data should contain stored client under domain/entry_id
    assert init_mod.DOMAIN in hass.data
    assert entry.entry_id in hass.data[init_mod.DOMAIN]
    # Runtime data should be populated
    assert hasattr(entry, "runtime_data")
    assert getattr(entry.runtime_data, "coordinator", None) is not None


@pytest.mark.asyncio
async def test_e2e_granular_sync_and_options_device_tracker(
    monkeypatch, make_config_entry, coordinator_capture
):
    """E2E: multi-step config flow (granular sync) + options enabling device tracker list.

    Validates:
    - user step with granular option -> granular step -> entry created
    - options flow: enable granular sync again + enable device tracker -> granular sync step
      -> device tracker step -> final options (devices merged with manual list)
    - subsequent async_setup_entry honors device tracker enabled (coordinator instantiated twice)
    """

    # Patch flow client
    monkeypatch.setattr(cf_mod, "OPNsenseClient", lambda **k: _FakeFlowClient(device_id="dev-gran"))
    monkeypatch.setattr(
        cf_mod, "async_create_clientsession", lambda **k: MagicMock(), raising=False
    )

    flow = cf_mod.OPNsenseConfigFlow()
    hass = _build_mock_hass()
    flow.hass = hass

    async def _noop_unique_id(*a, **k):  # redefined for this test context
        return None

    flow.async_set_unique_id = _noop_unique_id
    flow._abort_if_unique_id_configured = lambda: None

    # Step 1: user chooses granular sync
    user_input = _make_basic_user_input()
    user_input[CONF_GRANULAR_SYNC_OPTIONS] = True
    res1 = await flow.async_step_user(user_input=user_input)
    assert res1["type"] == "form" and res1["step_id"] == "granular_sync"

    # Step 2: granular sync submission (empty -> defaults True)
    res2 = await flow.async_step_granular_sync(user_input={})
    assert res2["type"] == "create_entry"
    entry_data = res2["data"]
    assert entry_data[CONF_DEVICE_UNIQUE_ID] == "dev-gran"

    # Prepare config entry via MockConfigEntry
    entry = make_config_entry(
        data={**entry_data},
        title=entry_data[CONF_NAME],
        unique_id=entry_data[CONF_DEVICE_UNIQUE_ID],
        entry_id="entry_gran",
        options={},
    )
    entry.add_update_listener = lambda f: lambda: None
    entry.async_on_unload = lambda x: None

    # Add to fake hass store so options flow update calls can mutate it
    hass.data.setdefault(init_mod.DOMAIN, {})
    # Provide async_get_known_entry for options flow compatibility
    if not hasattr(hass.config_entries, "async_get_known_entry"):
        hass.config_entries.async_get_known_entry = lambda entry_id: entry

    # Options flow path
    opt_flow = cf_mod.OPNsenseConfigFlow.async_get_options_flow(
        entry
    )  # returns OPNsenseOptionsFlow
    opt_flow.hass = hass
    # Avoid Home Assistant usage reporting side-effects in this lightweight
    # test harness (the real HA runtime sets up frame helpers). Stub the
    # usage reporter so assigning the config_entry property on the flow
    # doesn't fail during tests. Use raising=False to allow older HA versions
    # that don't expose report_usage.
    monkeypatch.setattr(
        homeassistant.config_entries, "report_usage", lambda *a, **k: None, raising=False
    )
    # Provide the config entry to the options flow in this test environment
    # so it can access entry.data/options without relying on HA internals.
    opt_flow.config_entry = entry
    # initial options step: enable device tracker & granular sync
    opt_init = await opt_flow.async_step_init(
        user_input={CONF_DEVICE_TRACKER_ENABLED: True, CONF_GRANULAR_SYNC_OPTIONS: True}
    )
    assert opt_init["type"] == "form" and opt_init["step_id"] == "granular_sync"

    # granular sync step in options: keep defaults
    opt_gran = await opt_flow.async_step_granular_sync(user_input={})
    # device tracker list form expected next
    assert opt_gran["type"] == "form" and opt_gran["step_id"] == "device_tracker"

    # device tracker selection (one existing + manual list)
    opt_final = await opt_flow.async_step_device_tracker(
        user_input={
            CONF_DEVICES: ["aa:bb:cc:dd:ee:ff"],
            CONF_MANUAL_DEVICES: "11:22:33:44:55:66, 77:88:99:aa:bb:cc",  # valid MACs
        }
    )
    assert opt_final["type"] == "create_entry"
    # Options merged list should contain unique MACs (order not strictly enforced)
    devices_set = set(entry.options.get(CONF_DEVICES, []))
    assert {"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", "77:88:99:aa:bb:cc"}.issubset(devices_set)
    assert entry.options.get(CONF_DEVICE_TRACKER_ENABLED) is True

    # Patch runtime setup components (client + coordinator) to count device tracker coordinator instantiation
    monkeypatch.setattr(
        init_mod, "OPNsenseClient", lambda **k: _FakeRuntimeClient(device_id="dev-gran")
    )
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(_FakeCoordinator)
    )

    ok = await init_mod.async_setup_entry(hass, entry)
    assert ok is True
    # Expect two coordinators: main + device tracker
    assert len(coordinator_capture.instances) == 2
    assert any(c._device_tracker for c in coordinator_capture.instances)


@pytest.mark.asyncio
async def test_e2e_reload_and_unload(monkeypatch, make_config_entry):
    """E2E: validate update-listener triggered reload and full unload cleanup.

    Steps:
    1. Perform basic config flow / setup.
    2. Trigger update listener (SHOULD_RELOAD True) and assert reload scheduled.
    3. Unload entry; confirm client closed and data removed.
    """

    # Patch config flow client
    monkeypatch.setattr(cf_mod, "OPNsenseClient", lambda **k: _FakeFlowClient(device_id="dev-rel"))
    monkeypatch.setattr(
        cf_mod, "async_create_clientsession", lambda **k: MagicMock(), raising=False
    )

    flow = cf_mod.OPNsenseConfigFlow()
    hass = _build_mock_hass()
    flow.hass = hass

    async def _noop_unique_id(*a, **k):
        return None

    flow.async_set_unique_id = _noop_unique_id
    flow._abort_if_unique_id_configured = lambda: None

    result = await flow.async_step_user(user_input=_make_basic_user_input())
    data = result["data"]

    # Runtime path patches
    runtime_client = _FakeRuntimeClient(device_id="dev-rel")
    monkeypatch.setattr(init_mod, "OPNsenseClient", lambda **k: runtime_client)
    monkeypatch.setattr(init_mod, "OPNsenseDataUpdateCoordinator", _FakeCoordinator)

    # Provide unload platforms async method
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()

    # Entry object using MockConfigEntry
    entry = make_config_entry(
        data={**data},
        title=data[CONF_NAME],
        unique_id=data[CONF_DEVICE_UNIQUE_ID],
        entry_id="entry_rel",
        options={},
    )
    entry.add_update_listener = lambda f: lambda: None
    entry.async_on_unload = lambda x: None

    # Setup
    ok = await init_mod.async_setup_entry(hass, entry)
    assert ok is True
    assert entry.entry_id in hass.data[init_mod.DOMAIN]

    # Patch registries for update listener (return no entities/devices)
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: MagicMock())
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: []
    )
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: MagicMock())
    monkeypatch.setattr(
        init_mod.dr, "async_entries_for_config_entry", lambda registry, config_entry_id: []
    )

    # Trigger update listener -> should schedule reload
    setattr(entry.runtime_data, init_mod.SHOULD_RELOAD, True)
    await init_mod._async_update_listener(hass, entry)
    assert hass.config_entries.async_reload.call_count == 1

    # Unload
    res_unload = await init_mod.async_unload_entry(hass, entry)
    assert res_unload is True
    assert entry.entry_id not in hass.data[init_mod.DOMAIN]
    assert runtime_client._closed is True
    hass.config_entries.async_unload_platforms.assert_awaited_once()


@pytest.mark.asyncio
async def test_e2e_full_migration_chain(monkeypatch, make_config_entry):
    """E2E: exercise async_migrate_entry path from version 1 -> 4.

    Verifies:
    - v1->2 removes tls_insecure and adds verify_ssl (inverse of tls_insecure)
    - v2->3 updates device unique id across entry + entities + devices
    - v3->4 transforms telemetry-related sensor unique ids and removes *_connected_client_count
    """

    # Build hass mock with update_entry bypass logic
    hass = _build_mock_hass()

    # Fake device & entity registry implementations
    class FakeDevice:
        def __init__(self, id_: str, identifiers: set[tuple[str, str]]):
            self.id = id_
            self.identifiers = identifiers

    class FakeDeviceRegistry:
        def __init__(self):
            self._devices: list[FakeDevice] = [
                FakeDevice("dev-main", {("opnsense", "oldmacid"), ("other", "x")}),
                FakeDevice("dev-other", {("misc", "abc")}),
            ]
            self.updated: list[FakeDevice] = []

        def async_update_device(self, device_id: str, new_identifiers: set[tuple[str, str]]):
            for d in self._devices:
                if d.id == device_id:
                    d.identifiers = new_identifiers
                    self.updated.append(d)
                    return d
            raise ValueError("device not found")

    class FakeEntity:
        def __init__(self, entity_id: str, unique_id: str, device_id: str):
            self.entity_id = entity_id
            self.unique_id = unique_id
            self.device_id = device_id

    class FakeEntityRegistry:
        def __init__(self):
            self._entities: dict[str, FakeEntity] = {}
            # initial telemetry / non-telemetry examples
            ents = [
                FakeEntity(
                    "sensor.router_interface_eth0", "oldmacid_telemetry_interface_eth0", "dev-main"
                ),
                FakeEntity(
                    "sensor.router_gateway_wan", "oldmacid_telemetry_gateway_wan", "dev-main"
                ),
                FakeEntity(
                    "sensor.router_vpn_clients", "oldmacid_connected_client_count", "dev-main"
                ),
                FakeEntity(
                    "sensor.router_openvpn_status0",
                    "oldmacid_telemetry_openvpn_status0",
                    "dev-main",
                ),
            ]
            for e in ents:
                self._entities[e.entity_id] = e
            self.updated: list[FakeEntity] = []
            self.removed: list[str] = []

        def async_update_entity(self, entity_id: str, new_unique_id: str, **kwargs):
            # Accept HA's keyword-based calls (e.g. new_unique_id=...) while
            # preserving existing positional behavior. Prefer kwarg when present.
            new_unique_id = kwargs.get("new_unique_id", new_unique_id)
            ent = self._entities[entity_id]
            ent.unique_id = new_unique_id
            self.updated.append(ent)
            return ent

        def async_remove(self, entity_id: str):
            self.removed.append(entity_id)
            self._entities.pop(entity_id, None)

    fake_device_reg = FakeDeviceRegistry()
    fake_entity_reg = FakeEntityRegistry()

    # Monkeypatch registry access/functions used in migration helpers
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: fake_device_reg)
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: fake_entity_reg)
    monkeypatch.setattr(
        init_mod.dr,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: list(fake_device_reg._devices),
    )
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: list(fake_entity_reg._entities.values()),
    )

    # Patch client used during migrations (v2->3 get_device_unique_id, v3->4 get_telemetry)
    class _MigClient:
        async def get_device_unique_id(self) -> str:
            return "newmacid"

        async def get_host_firmware_version(self):  # not used in migration chain here
            return "25.1"

        async def get_telemetry(self) -> dict[str, Any]:
            return {"filesystems": []}  # keep simple to avoid extra branches

    monkeypatch.setattr(init_mod, "OPNsenseClient", lambda **k: _MigClient())
    monkeypatch.setattr(
        init_mod, "async_create_clientsession", lambda **k: MagicMock(), raising=False
    )

    # Build legacy v1 entry (tls_insecure True, missing verify_ssl)
    entry = make_config_entry(
        data={
            CONF_URL: "https://router.example",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "oldmacid",
            init_mod.CONF_TLS_INSECURE: True,
        },
        title="Router",
        unique_id="oldmacid",
        version=1,
        entry_id="entry_migrate",
        options={},
    )

    # Run full migration
    ok = await init_mod.async_migrate_entry(hass, entry)
    assert ok is True
    assert entry.version == 4
    # v1->2: tls_insecure removed, verify_ssl added (inverse of True -> False)
    assert init_mod.CONF_TLS_INSECURE not in entry.data
    assert entry.data.get(CONF_VERIFY_SSL) is False
    # v2->3: unique id updated
    assert entry.data[init_mod.CONF_DEVICE_UNIQUE_ID] == "newmacid"
    assert entry.unique_id == "newmacid"
    # Device identifiers updated
    main_dev = next(d for d in fake_device_reg._devices if d.id == "dev-main")
    assert any(i == ("opnsense", "newmacid") for i in main_dev.identifiers)
    # Entities updated: telemetry prefixes removed for interface/gateway/openvpn; connected client removed
    ent_ids = {e.entity_id: e for e in fake_entity_reg._entities.values()}
    # connected_client_count entity should be removed during v3->4 migration
    assert "sensor.router_vpn_clients" in fake_entity_reg.removed
    assert "sensor.router_vpn_clients" not in fake_entity_reg._entities
    # Remaining entities use new prefix and no _telemetry_ substring
    for ent in ent_ids.values():
        assert ent.unique_id.startswith("newmacid_")
        assert "_telemetry_" not in ent.unique_id
