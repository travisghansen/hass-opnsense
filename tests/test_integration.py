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
    CONF_DEVICE_UNIQUE_ID,
    CONF_DEVICES,
    CONF_GRANULAR_SYNC_OPTIONS,
    CONF_MANUAL_DEVICES,
)
from homeassistant.const import CONF_NAME, CONF_PASSWORD, CONF_URL, CONF_USERNAME, CONF_VERIFY_SSL
from tests.utilities import patch_client_factory

homeassistant = pytest.importorskip("homeassistant")


class _FakeFlowClient:
    """Fake client used during config & options flows.

    It implements only the async methods the flows invoke.
    """

    def __init__(self, device_id: str = "dev-flow", firmware: str = "25.1") -> None:
        """Store the device identity and firmware used by flow tests.

        Args:
            device_id: Device identifier returned by the fake client during
                flow validation.
            firmware: Firmware version returned during config-flow checks.
        """
        self._device_id = device_id
        self._firmware = firmware

    async def get_host_firmware_version(self) -> str:
        """Return the firmware version configured for this fake flow client."""
        return self._firmware

    async def set_use_snake_case(self, initial: bool = False) -> None:
        """Accept the snake-case toggle call used by flow validation without side effects."""
        return

    async def is_plugin_installed(self) -> bool:  # for SYNC_ITEMS_REQUIRING_PLUGIN path
        """Report plugin availability for config-flow validation checks.

        Returns:
            bool: Always returns ``True`` so plugin-gated flow branches remain enabled.
        """
        return True

    async def get_system_info(self) -> MutableMapping[str, Any]:
        """Return a minimal system info payload used by flow validation."""
        return {"name": "OPNsenseTest"}

    async def get_device_unique_id(self, expected_id: str | None = None) -> str:
        """Return the fake router identifier used by the flow tests.

        Args:
            expected_id: Expected device identifier supplied by the caller and
                ignored by this fake implementation.
        """
        return self._device_id

    async def get_arp_table(self, resolve_hostnames: bool = False) -> list[dict[str, Any]]:
        # Used by options flow device tracker step
        """Return two static ARP entries for device-tracker options tests."""
        return [
            {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "host1", "ip": "192.168.1.10"},
            {"mac": "11:22:33:44:55:66", "hostname": "", "ip": "192.168.1.11"},
        ]

    async def async_close(self) -> None:
        return None


class _FakeRuntimeClient:
    """Fake client used during async_setup_entry (main integration path)."""

    def __init__(self, device_id: str = "dev-runtime", firmware: str = "25.1") -> None:
        """Store fake runtime client state used during integration setup tests.

        Args:
            device_id: Device identifier returned during setup-time probes.
            firmware: Firmware version returned during setup-time probes.
        """
        self._device_id = device_id
        self._firmware = firmware
        self._closed = False

    async def get_device_unique_id(
        self, expected_id: str | None = None
    ) -> str:  # used by setup & coordinator
        """Return the fake runtime device identifier for setup and refresh calls.

        Args:
            expected_id: Expected device identifier supplied by the caller and
                ignored by this fake implementation.
        """
        return self._device_id

    async def get_host_firmware_version(self) -> str:  # used by setup & coordinator
        """Return the fake firmware version used by setup and coordinator refreshes."""
        return self._firmware

    async def async_close(self) -> bool:
        """Record that the fake runtime client was closed.

        Returns:
            bool: Always returns ``True`` after setting the closed flag.
        """
        self._closed = True
        return True

    async def set_use_snake_case(
        self, initial: bool = False
    ) -> None:  # called during coordinator _async_setup
        # Accept the optional `initial` flag like the production client. No-op for tests.
        """Accept the snake-case toggle call used during coordinator setup."""
        return

    async def reset_query_counts(self) -> None:
        """Accept query-count reset calls without changing test state."""
        return

    async def get_query_counts(self) -> tuple[int, int]:
        """Return a fixed pair of query counters for coordinator assertions."""
        return (0, 0)

    async def get_system_info(self):  # first refresh path
        """Return minimal system information for the initial refresh path."""
        return {"name": "sys"}


class _FakeCoordinator:
    """Minimal coordinator stand‑in used for async_setup_entry tests."""

    def __init__(self, **kwargs: Any) -> None:  # pragma: no cover - simple init
        # capture flags we care about for assertions if needed
        """Capture the flags needed by async setup tests.

        Args:
            **kwargs: Coordinator construction arguments, including the optional
                device-tracker flag.
        """
        self._device_tracker = kwargs.get("device_tracker_coordinator", False)
        self._refreshed = False

    async def async_config_entry_first_refresh(self) -> bool:
        """Record that the fake coordinator performed its initial refresh.

        Returns:
            bool: Always returns ``True`` after marking the coordinator refreshed.
        """
        self._refreshed = True
        return True

    async def async_shutdown(self) -> bool:  # pragma: no cover - not used in happy path
        """Return a successful shutdown result for setup failure branches.

        Returns:
            bool: Always returns ``True`` in this fake coordinator.
        """
        return True


def _make_basic_user_input() -> dict[str, Any]:
    """Create basic user input."""
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
            """Initialize _Cfg."""
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
            """Async update entry.

            Args:
                entry: Config entry being set up, unloaded, migrated, or reloaded.
                data: Data provided by pytest or the test case.
                options: Options mapping that stores the integration settings being updated.
                version: Version provided by pytest or the test case.
                unique_id: Identifier for unique.
                **kwargs: Additional keyword arguments forwarded by the function.
            """
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
            """Async forward entry setups.

            Args:
                entry: Config entry being set up, unloaded, migrated, or reloaded.
                platforms: Platforms provided by pytest or the test case.
            """
            return True

        async def async_unload_platforms(self, entry, platforms):  # pragma: no cover
            """Async unload platforms.

            Args:
                entry: Config entry being set up, unloaded, migrated, or reloaded.
                platforms: Platforms provided by pytest or the test case.
            """
            return True

        async def async_reload(self, entry_id):  # pragma: no cover - reload path not asserted
            """Async reload.

            Args:
                entry_id: Config entry identifier for the integration instance being referenced.
            """
            return

    hass.config_entries = _Cfg()
    hass.async_create_task = MagicMock(side_effect=asyncio.create_task)
    return hass


@pytest.mark.asyncio
async def test_e2e_basic_config_flow_and_setup(monkeypatch, make_config_entry):
    """E2E: basic config flow (single step) followed by entry setup."""

    # Patch client for config flow
    patch_client_factory(monkeypatch, cf_mod, lambda **k: _FakeFlowClient(device_id="dev-basic"))
    monkeypatch.setattr(
        cf_mod, "async_create_clientsession", lambda **k: MagicMock(), raising=False
    )

    flow = cf_mod.OPNsenseConfigFlow()
    hass = _build_mock_hass()
    flow.hass = hass

    # Bypass HA flow unique-id internals (we don't implement hass.config_entries.flow)
    async def _noop_unique_id(*a, **k):
        """Bypass Home Assistant unique-ID bookkeeping for this flow test.

        Args:
            *a: Additional positional arguments forwarded by the function.
            **k: Additional keyword arguments forwarded by the function.
        """
        return

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
    patch_client_factory(
        monkeypatch, init_mod, lambda **k: _FakeRuntimeClient(device_id="dev-basic")
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
    """Exercise granular sync config flow and device tracker options flow end to end.

    Validates:
        - User step with granular option leads to granular sync and entry creation.
        - Options flow re-enables granular sync and device tracker, then advances
          through granular sync and device tracker steps to final merged options.
        - Subsequent ``async_setup_entry`` honors device tracker enabled and
          instantiates two coordinators.
    """

    # Patch flow client
    patch_client_factory(monkeypatch, cf_mod, lambda **k: _FakeFlowClient(device_id="dev-gran"))
    monkeypatch.setattr(
        cf_mod, "async_create_clientsession", lambda **k: MagicMock(), raising=False
    )

    flow = cf_mod.OPNsenseConfigFlow()
    hass = _build_mock_hass()
    flow.hass = hass

    async def _noop_unique_id(*a, **k):  # redefined for this test context
        """Bypass Home Assistant unique-ID bookkeeping for this flow test.

        Args:
            *a: Additional positional arguments forwarded by the function.
            **k: Additional keyword arguments forwarded by the function.
        """
        return

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
        user_input={
            cf_mod.CONF_DEVICE_TRACKING_MODE: cf_mod.DEVICE_TRACKING_MODE_SELECTED,
            CONF_GRANULAR_SYNC_OPTIONS: True,
        }
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
            CONF_MANUAL_DEVICES: "11:22:33:44:55:66\n77:88:99:aa:bb:cc",  # valid MACs
        }
    )
    assert opt_final["type"] == "create_entry"
    # Options merged list should contain unique MACs (order not strictly enforced)
    devices_set = set(entry.options.get(CONF_DEVICES, []))
    assert {"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", "77:88:99:aa:bb:cc"}.issubset(devices_set)
    assert entry.options.get(cf_mod.CONF_DEVICE_TRACKER_ENABLED) is True

    # Patch runtime setup components (client + coordinator) to count device tracker coordinator instantiation
    patch_client_factory(
        monkeypatch, init_mod, lambda **k: _FakeRuntimeClient(device_id="dev-gran")
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
    """Validate update-listener reload handling and full unload cleanup end to end.

    Steps:
        - Perform the basic config flow and integration setup.
        - Trigger the update listener with ``SHOULD_RELOAD`` set and assert a
          reload is scheduled.
        - Unload the entry and confirm the client is closed and stored data is
          removed.
    """

    # Patch config flow client
    patch_client_factory(monkeypatch, cf_mod, lambda **k: _FakeFlowClient(device_id="dev-rel"))
    monkeypatch.setattr(
        cf_mod, "async_create_clientsession", lambda **k: MagicMock(), raising=False
    )

    flow = cf_mod.OPNsenseConfigFlow()
    hass = _build_mock_hass()
    flow.hass = hass

    async def _noop_unique_id(*a, **k):
        """Bypass Home Assistant unique-ID bookkeeping for this flow test.

        Args:
            *a: Additional positional arguments forwarded by the function.
            **k: Additional keyword arguments forwarded by the function.
        """
        return

    flow.async_set_unique_id = _noop_unique_id
    flow._abort_if_unique_id_configured = lambda: None

    result = await flow.async_step_user(user_input=_make_basic_user_input())
    data = result["data"]

    # Runtime path patches
    runtime_client = _FakeRuntimeClient(device_id="dev-rel")
    patch_client_factory(monkeypatch, init_mod, lambda **k: runtime_client)
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
    """Exercise the full ``async_migrate_entry`` path from version 1 to 4.

    Verifies:
        - v1 to v2 removes ``tls_insecure`` and adds ``verify_ssl`` as its inverse.
        - v2 to v3 updates the device unique ID across the entry, entities, and devices.
        - v3 to v4 transforms telemetry-related sensor unique IDs and removes
          ``*_connected_client_count`` entities.
    """

    # Build hass mock with update_entry bypass logic
    hass = _build_mock_hass()

    # Fake device & entity registry implementations
    class FakeDevice:
        def __init__(self, id_: str, identifiers: set[tuple[str, str]]):
            """Initialize FakeDevice."""
            self.id = id_
            self.identifiers = identifiers

    class FakeDeviceRegistry:
        def __init__(self):
            """Initialize FakeDeviceRegistry."""
            self._devices: list[FakeDevice] = [
                FakeDevice("dev-main", {("opnsense", "oldmacid"), ("other", "x")}),
                FakeDevice("dev-other", {("misc", "abc")}),
            ]
            self.updated: list[FakeDevice] = []

        def async_update_device(self, device_id: str, new_identifiers: set[tuple[str, str]]):
            """Async update device.

            Args:
                device_id: Device identifier used to target the correct OPNsense device or config entry.

            Raises:
                ValueError: If an input value cannot be parsed or normalized.
            """
            for d in self._devices:
                if d.id == device_id:
                    d.identifiers = new_identifiers
                    self.updated.append(d)
                    return d
            raise ValueError("device not found")

    class FakeEntity:
        def __init__(self, entity_id: str, unique_id: str, device_id: str):
            """Initialize FakeEntity.

            Args:
                entity_id: Entity identifier used to resolve the matching OPNsense entity.
                unique_id: Identifier for unique.
                device_id: Device identifier used to target the correct OPNsense device or config entry.
            """
            self.entity_id = entity_id
            self.unique_id = unique_id
            self.device_id = device_id

    class FakeEntityRegistry:
        def __init__(self):
            """Initialize FakeEntityRegistry."""
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
            """Async update entity.

            Args:
                entity_id: Entity identifier used to resolve the matching OPNsense entity.
                new_unique_id: Identifier for new unique.
                **kwargs: Additional keyword arguments forwarded by the function.
            """
            new_unique_id = kwargs.get("new_unique_id", new_unique_id)
            ent = self._entities[entity_id]
            ent.unique_id = new_unique_id
            self.updated.append(ent)
            return ent

        def async_remove(self, entity_id: str):
            """Async remove.

            Args:
                entity_id: Entity identifier used to resolve the matching OPNsense entity.
            """
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
            """Return the migrated device identifier used by the migration test."""
            return "newmacid"

        async def async_close(self) -> None:
            return None

        async def get_host_firmware_version(self):  # not used in migration chain here
            """Return a placeholder firmware version for migration compatibility."""
            return "25.1"

        async def get_telemetry(self) -> dict[str, Any]:
            """Return minimal telemetry so migration code can inspect filesystems."""
            return {"filesystems": []}  # keep simple to avoid extra branches

    patch_client_factory(monkeypatch, init_mod, lambda **k: _MigClient())
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
