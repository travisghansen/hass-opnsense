"""Unit tests for the integration package initialization and lifecycle helpers.

These tests exercise async_setup_entry, migration helpers, update listeners,
and removal/unload behaviors for the hass-opnsense integration.
"""

from collections.abc import Callable
import importlib
import logging
from typing import Any, Never, Self
from unittest.mock import ANY, AsyncMock, MagicMock, call

from homeassistant.core import HomeAssistant
import homeassistant.helpers.aiohttp_client as _hc
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from tests.utilities import patch_opnsense_client

# import the package module object so we can access its functions/attrs
init_mod = importlib.import_module("custom_components.opnsense")
helpers_mod = importlib.import_module("custom_components.opnsense.helpers")


@pytest.fixture(autouse=True)
def _patch_hass_async_create_clientsession(monkeypatch: pytest.MonkeyPatch) -> None:
    """Autouse fixture to stub Home Assistant's async_create_clientsession. Some tests use a minimal `hass` object (SimpleNamespace) which does not provide the full helper; patch the helper to return a lightweight session-like object to avoid opening real network resources."""

    class _FakeSession:
        async def __aenter__(self) -> Self:
            """Yield the fake client session to the async context manager."""
            return self

        async def __aexit__(
            self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: object
        ) -> bool:
            """Close the fake session and return False so exceptions propagate."""
            await self.close()
            return False

        async def close(self) -> None:
            """Simulate closing the fake session."""
            return

    def _fake_create_clientsession(*args: object, **kwargs: object) -> _FakeSession:
        """Return a lightweight fake client session for Home Assistant tests.

        Args:
            *args: Positional arguments forwarded from the patched helper and ignored.
            **kwargs: Keyword arguments forwarded from the patched helper and ignored.
        """
        return _FakeSession()

    # Patch both the imported module object and the import-path string so
    # tests are resilient in different environments. Use raising=False so
    # missing targets don't cause the fixture to fail.
    monkeypatch.setattr(
        _hc, "async_create_clientsession", _fake_create_clientsession, raising=False
    )
    monkeypatch.setattr(
        "homeassistant.helpers.aiohttp_client.async_create_clientsession",
        _fake_create_clientsession,
        raising=False,
    )

    # Also patch the integration helper's local import so shared client construction
    # does not create a real session.
    monkeypatch.setattr(
        helpers_mod, "async_create_clientsession", _fake_create_clientsession, raising=False
    )
    # Stub CookieJar used by migrations so aiohttp isn't required in the test env
    monkeypatch.setattr(
        "custom_components.opnsense.helpers.aiohttp.CookieJar",
        lambda *a, **k: object(),
        raising=False,
    )


def test_align_aiopnsense_log_level_mirrors_opnsense_when_unset() -> None:
    """Aiopnsense should inherit the integration debug level when not configured."""
    opnsense_logger = logging.getLogger("custom_components.opnsense")
    aiopnsense_logger = logging.getLogger("aiopnsense")
    aiopnsense_helper_logger = logging.getLogger("aiopnsense.helpers")
    original_opnsense_level = opnsense_logger.level
    original_aiopnsense_level = aiopnsense_logger.level
    original_aiopnsense_helper_level = aiopnsense_helper_logger.level

    try:
        opnsense_logger.setLevel(logging.DEBUG)
        aiopnsense_logger.setLevel(logging.NOTSET)
        aiopnsense_helper_logger.setLevel(logging.NOTSET)

        init_mod._align_aiopnsense_log_level()

        assert aiopnsense_logger.level == logging.DEBUG
        assert aiopnsense_helper_logger.getEffectiveLevel() == logging.DEBUG
    finally:
        opnsense_logger.setLevel(original_opnsense_level)
        aiopnsense_logger.setLevel(original_aiopnsense_level)
        aiopnsense_helper_logger.setLevel(original_aiopnsense_helper_level)


def test_align_aiopnsense_log_level_keeps_explicit_aiopnsense_level() -> None:
    """aiopnsense-specific logger configuration should remain authoritative."""
    opnsense_logger = logging.getLogger("custom_components.opnsense")
    aiopnsense_logger = logging.getLogger("aiopnsense")
    original_opnsense_level = opnsense_logger.level
    original_aiopnsense_level = aiopnsense_logger.level

    try:
        opnsense_logger.setLevel(logging.DEBUG)
        aiopnsense_logger.setLevel(logging.WARNING)

        init_mod._align_aiopnsense_log_level()

        assert aiopnsense_logger.level == logging.WARNING
    finally:
        opnsense_logger.setLevel(original_opnsense_level)
        aiopnsense_logger.setLevel(original_aiopnsense_level)


def test_align_aiopnsense_log_level_leaves_both_loggers_unset() -> None:
    """Unset loggers should continue to inherit the root logger level."""
    opnsense_logger = logging.getLogger("custom_components.opnsense")
    aiopnsense_logger = logging.getLogger("aiopnsense")
    original_opnsense_level = opnsense_logger.level
    original_aiopnsense_level = aiopnsense_logger.level

    try:
        opnsense_logger.setLevel(logging.NOTSET)
        aiopnsense_logger.setLevel(logging.NOTSET)

        init_mod._align_aiopnsense_log_level()

        assert aiopnsense_logger.level == logging.NOTSET
    finally:
        opnsense_logger.setLevel(original_opnsense_level)
        aiopnsense_logger.setLevel(original_aiopnsense_level)


@pytest.mark.asyncio
async def test_async_setup_entry_success(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_client: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry should succeed with valid client and coordinator."""
    patch_opnsense_client(monkeypatch, init_mod, fake_client())
    # use shared coordinator capture fixture
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    # create a minimal config entry using the shared helper so all fields
    # (data, options, title, entry_id, unique_id, listeners) are set
    entry = make_config_entry(
        data={
            init_mod.CONF_URL: "http://1.2.3.4",
            init_mod.CONF_USERNAME: "u",
            init_mod.CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={},
    )

    # use migration fixture which may wrap the real hass or provide a MagicMock
    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()

    # ensure hass.data is a real dict for the integration to populate
    hass.data = {}

    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True
    assert init_mod.DOMAIN in hass.data and entry.entry_id in hass.data[init_mod.DOMAIN]


@pytest.mark.asyncio
async def test_async_setup_entry_validates_client_before_probes(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry should validate the client before device/firmware probes."""
    probe_calls: list[str] = []
    client = MagicMock()
    client.name = "test-router"
    client.validate = AsyncMock(side_effect=lambda: probe_calls.append("validate"))

    async def _get_device_unique_id(expected_id: str | None = None) -> str:
        """Return test router device id after recording probe ordering."""
        probe_calls.append("get_device_unique_id")
        return "dev1"

    async def _get_host_firmware_version() -> str:
        """Return test firmware after recording probe ordering."""
        probe_calls.append("get_host_firmware_version")
        return "99.0"

    client.get_device_unique_id = _get_device_unique_id
    client.get_host_firmware_version = _get_host_firmware_version
    client.async_close = AsyncMock(return_value=True)

    def _create_client(**kwargs: Any) -> Any:
        """Return the probe-tracking client used by this setup-entry test."""
        return client

    monkeypatch.setattr(init_mod, "create_opnsense_client", _create_client)
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    entry = make_config_entry(
        data={
            init_mod.CONF_URL: "http://1.2.3.4",
            init_mod.CONF_USERNAME: "u",
            init_mod.CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={},
    )

    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True
    assert probe_calls == [
        "validate",
        "get_device_unique_id",
        "get_host_firmware_version",
    ]


@pytest.mark.asyncio
async def test_async_setup_entry_closes_client_when_validation_fails(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry should close a constructed client when validation fails."""
    client = MagicMock()
    client.validate = AsyncMock(side_effect=init_mod.OPNsenseError("boom"))
    client.async_close = AsyncMock(return_value=True)

    def _create_client(**kwargs: Any) -> Any:
        """Return the validation-failing client for this setup-entry test."""
        return client

    monkeypatch.setattr(init_mod, "create_opnsense_client", _create_client)

    entry = make_config_entry(
        data={
            init_mod.CONF_URL: "http://1.2.3.4",
            init_mod.CONF_USERNAME: "u",
            init_mod.CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={},
    )

    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    with pytest.raises(init_mod.OPNsenseError):
        await init_mod.async_setup_entry(hass, entry)

    client.async_close.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_setup_entry_closes_client_when_validation_times_out(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry should close and re-raise when validation times out."""
    client = MagicMock()
    client.validate = AsyncMock(side_effect=TimeoutError)
    client.async_close = AsyncMock(return_value=True)

    def _create_client(**kwargs: Any) -> Any:
        """Return the timeout-raising client for this setup-entry test."""
        return client

    monkeypatch.setattr(init_mod, "create_opnsense_client", _create_client)

    entry = make_config_entry(
        data={
            init_mod.CONF_URL: "http://1.2.3.4",
            init_mod.CONF_USERNAME: "u",
            init_mod.CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={},
    )

    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    with pytest.raises(TimeoutError):
        await init_mod.async_setup_entry(hass, entry)

    client.async_close.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_setup_entry_reraises_client_creation_error(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry should re-raise client creation errors before close handling."""

    def _create_client(**kwargs: Any) -> Any:
        """Raise a backend error before a client instance exists."""
        raise init_mod.OPNsenseError("boom")

    monkeypatch.setattr(init_mod, "create_opnsense_client", _create_client)
    entry = make_config_entry(
        data={
            init_mod.CONF_URL: "http://1.2.3.4",
            init_mod.CONF_USERNAME: "u",
            init_mod.CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={},
    )

    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    with pytest.raises(init_mod.OPNsenseError):
        await init_mod.async_setup_entry(hass, entry)


@pytest.mark.asyncio
async def test_async_setup_entry_continues_after_firmware_validation_error(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry should keep probing after firmware validation exceptions."""
    probe_calls: list[str] = []
    client = MagicMock()
    client.name = "test-router"
    client.validate = AsyncMock(side_effect=init_mod.OPNsenseBelowMinFirmware("boom"))
    client.async_close = AsyncMock(return_value=True)

    async def _get_device_unique_id(expected_id: str | None = None) -> str:
        """Return test router device id after recording probe ordering."""
        probe_calls.append("get_device_unique_id")
        return "dev1"

    async def _get_host_firmware_version() -> str:
        """Return test firmware after recording probe ordering."""
        probe_calls.append("get_host_firmware_version")
        return "99.0"

    client.get_device_unique_id = _get_device_unique_id
    client.get_host_firmware_version = _get_host_firmware_version

    def _create_client(**kwargs: Any) -> Any:
        """Return the firmware-failing client for this setup-entry test."""
        return client

    monkeypatch.setattr(init_mod, "create_opnsense_client", _create_client)
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    entry = make_config_entry(
        data={
            init_mod.CONF_URL: "http://1.2.3.4",
            init_mod.CONF_USERNAME: "u",
            init_mod.CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={},
    )

    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True
    assert probe_calls == [
        "get_device_unique_id",
        "get_host_firmware_version",
    ]
    client.async_close.assert_not_awaited()


@pytest.mark.asyncio
async def test_async_setup_entry_device_id_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_client: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry should fail when client reports mismatched device id."""
    patch_opnsense_client(monkeypatch, init_mod, fake_client(device_id="other"))
    # use shared coordinator capture fixture
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    # use the shared helper to construct the entry for consistency
    entry = make_config_entry(
        data={
            init_mod.CONF_URL: "http://1.2.3.4",
            init_mod.CONF_USERNAME: "u",
            init_mod.CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={},
    )

    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()

    # should return False because router id mismatches and coordinator.shutdown called
    res = await init_mod.async_setup_entry(hass, entry)
    assert res is False

    # ensure coordinator shutdown was invoked
    assert any(getattr(inst, "shut", False) for inst in coordinator_capture.instances)


@pytest.mark.asyncio
async def test_async_update_listener_not_reload(
    monkeypatch: pytest.MonkeyPatch, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """_async_update_listener should set SHOULD_RELOAD True and not call reload when flag False."""
    entry = make_config_entry(entry_id="e", unique_id="u")
    # ensure runtime_data exists and set SHOULD_RELOAD to False
    setattr(entry.runtime_data, init_mod.SHOULD_RELOAD, False)

    # hass with config_entries.async_reload not called
    hass = MagicMock(spec=HomeAssistant)
    hass.config_entries = MagicMock()
    hass.config_entries.async_reload = AsyncMock()

    # should set SHOULD_RELOAD back to True and not call reload
    await init_mod._async_update_listener(hass, entry)
    assert getattr(entry.runtime_data, init_mod.SHOULD_RELOAD) is True
    hass.config_entries.async_reload.assert_not_called()


@pytest.mark.asyncio
async def test_async_remove_config_entry_device_branches(
    monkeypatch: pytest.MonkeyPatch, hass: HomeAssistant
) -> None:
    """Verify removal logic for config entry device registry branches."""
    device = MagicMock()
    device.via_device_id = True
    device.id = "d1"
    res = await init_mod.async_remove_config_entry_device(hass, None, device)
    assert res is False

    # device_entry with linked entity -> False
    device = MagicMock()
    device.via_device_id = False
    device.id = "d2"

    class EntityRegistry:
        pass

    # fake registry that returns one entity with matching device_id
    ent = MagicMock()
    ent.device_id = "d2"
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: EntityRegistry())
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: [ent]
    )
    res = await init_mod.async_remove_config_entry_device(hass, MagicMock(entry_id="x"), device)
    assert res is False


@pytest.mark.asyncio
async def test_async_remove_config_entry_device_no_linked_entities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When no linked entities exist for a device, removal should succeed (return True)."""
    # device not linked via via_device_id and has an id
    device = MagicMock()
    device.via_device_id = False
    device.id = "d3"

    # fake entity registry returns no entities for the config entry
    er_reg = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: er_reg)
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: []
    )

    # call the removal helper with a dummy config entry
    res = await init_mod.async_remove_config_entry_device(None, MagicMock(entry_id="x"), device)
    assert res is True


@pytest.mark.asyncio
async def test_async_unload_entry_and_pop(
    ph_hass: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """async_unload_entry removes entry from hass.data and closes the client."""
    entry = make_config_entry(entry_id="e_unload")
    entry.as_dict = lambda: {"id": "x"}
    # use the constant names used by the integration
    setattr(entry.runtime_data, init_mod.LOADED_PLATFORMS, ["p1"])
    fake_client = MagicMock()
    fake_client.async_close = AsyncMock()
    setattr(entry.runtime_data, init_mod.OPNSENSE_CLIENT, fake_client)

    hass = ph_hass
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=True)
    hass.data = {init_mod.DOMAIN: {entry.entry_id: fake_client}}
    res = await init_mod.async_unload_entry(hass, entry)
    assert res is True
    assert entry.entry_id not in hass.data[init_mod.DOMAIN]
    fake_client.async_close.assert_awaited_once()


@pytest.mark.asyncio
async def test_migrate_1_to_2_updates_entry(ph_hass: Any) -> None:
    """_migrate_1_to_2 migrates tls_insecure to verify_ssl and updates version."""
    cfg = MagicMock()
    cfg.data = {init_mod.CONF_TLS_INSECURE: True}
    # ensure verify_ssl missing
    cfg.version = 1
    # mock async_update_entry
    hass = ph_hass
    hass.config_entries.async_update_entry = MagicMock(return_value=True)
    res = await init_mod._migrate_1_to_2(hass, cfg)
    assert res is True
    # verify async_update_entry was called with the migrated data: tls_insecure removed
    # and verify_ssl derived as not tls_insecure, and version set to 2
    expected_data = {init_mod.CONF_VERIFY_SSL: False}
    hass.config_entries.async_update_entry.assert_called_once_with(
        cfg, data=expected_data, version=2
    )

    # Also test tls_insecure == False -> verify_ssl True
    cfg2 = MagicMock()
    cfg2.data = {init_mod.CONF_TLS_INSECURE: False}
    cfg2.version = 1
    # reset mock
    hass.config_entries.async_update_entry = MagicMock(return_value=True)
    res2 = await init_mod._migrate_1_to_2(hass, cfg2)
    assert res2 is True
    expected_data2 = {init_mod.CONF_VERIFY_SSL: True}
    hass.config_entries.async_update_entry.assert_called_once_with(
        cfg2, data=expected_data2, version=2
    )


@pytest.mark.asyncio
async def test_async_migrate_entry_version_gt5(ph_hass: Any) -> None:
    """async_migrate_entry returns False for versions greater than supported."""
    cfg = MagicMock()
    cfg.version = 6
    # should return False
    res = await init_mod.async_migrate_entry(ph_hass, cfg)
    assert res is False


@pytest.mark.asyncio
@pytest.mark.parametrize("version", [0])
async def test_async_migrate_entry_does_not_call_migrate_3_to_4_when_version_not_3(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any, version: Any
) -> None:
    """When entry.version is not 3, _migrate_3_to_4 must not be called."""
    mock_m3 = AsyncMock(return_value=True)
    monkeypatch.setattr(init_mod, "_migrate_3_to_4", mock_m3)

    cfg = MagicMock()
    cfg.version = version

    res = await init_mod.async_migrate_entry(ph_hass, cfg)

    # for versions not 3, migration should complete (except versions >5, which are handled earlier)
    assert res is True
    mock_m3.assert_not_called()


@pytest.mark.asyncio
async def test_migrate_4_to_5_removes_legacy_rule_switch_entities(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any
) -> None:
    """_migrate_4_to_5 removes legacy switch entities and updates config entry version."""
    ph_hass.config_entries.async_update_entry = MagicMock(return_value=True)
    entry = MockConfigEntry(
        domain=init_mod.DOMAIN,
        data={init_mod.CONF_DEVICE_UNIQUE_ID: "device-id"},
        version=4,
    )
    entry.add_to_hass(ph_hass)

    class Ent:
        def __init__(self, entity_id: str, unique_id: str) -> None:
            self.entity_id = entity_id
            self.unique_id = unique_id

    legacy_filter = Ent("switch.filter", "device-id_filter_123")
    legacy_nat_pf = Ent("switch.nat_pf", "device-id_nat_port_forward_123")
    legacy_nat_out = Ent("switch.nat_out", "device-id_nat_outbound_123")
    service_entity = Ent("switch.service", "device-id_service_unbound_status")
    telemetry_entity = Ent("sensor.telemetry", "device-id_telemetry_cpu")

    entity_registry = MagicMock()
    entity_registry.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [
            legacy_filter,
            legacy_nat_pf,
            legacy_nat_out,
            service_entity,
            telemetry_entity,
        ],
    )

    res = await init_mod.async_migrate_entry(ph_hass, entry)
    assert res is True
    entity_registry.async_remove.assert_has_calls(
        [
            call(legacy_filter.entity_id),
            call(legacy_nat_pf.entity_id),
            call(legacy_nat_out.entity_id),
        ],
        any_order=True,
    )
    assert entity_registry.async_remove.call_count == 3
    ph_hass.config_entries.async_update_entry.assert_called_once_with(entry, version=5)


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", [KeyError("legacy"), ValueError("legacy")])
async def test_migrate_4_to_5_legacy_entity_remove_failure_continues_migration(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any, exc: BaseException
) -> None:
    """_migrate_4_to_5 logs removal failures and still attempts version bump."""
    ph_hass.config_entries.async_update_entry = MagicMock(return_value=True)
    entry = MockConfigEntry(
        domain=init_mod.DOMAIN,
        data={init_mod.CONF_DEVICE_UNIQUE_ID: "device-id"},
        version=4,
    )
    entry.add_to_hass(ph_hass)

    class Ent:
        def __init__(self, entity_id: str, unique_id: str) -> None:
            self.entity_id = entity_id
            self.unique_id = unique_id

    broken_ent = Ent("switch.filter", "device-id_filter_123")
    ok_ent = Ent("switch.nat_pf", "device-id_nat_port_forward_123")

    entity_registry = MagicMock()
    entity_registry.async_remove = MagicMock(side_effect=[exc, None])
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [broken_ent, ok_ent],
    )

    res = await init_mod.async_migrate_entry(ph_hass, entry)
    assert res is True
    assert entity_registry.async_remove.call_count == 2
    entity_registry.async_remove.assert_has_calls(
        [call(broken_ent.entity_id), call(ok_ent.entity_id)],
        any_order=False,
    )
    ph_hass.config_entries.async_update_entry.assert_called_once_with(entry, version=5)


@pytest.mark.asyncio
async def test_migrate_4_to_5_version_bump_failure_aborts_migration(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any
) -> None:
    """_migrate_4_to_5 returns False when async_update_entry fails."""
    ph_hass.config_entries.async_update_entry = MagicMock(return_value=False)
    entry = MockConfigEntry(
        domain=init_mod.DOMAIN,
        data={init_mod.CONF_DEVICE_UNIQUE_ID: "device-id"},
        version=4,
    )
    entry.add_to_hass(ph_hass)

    class Ent:
        def __init__(self, entity_id: str, unique_id: str) -> None:
            self.entity_id = entity_id
            self.unique_id = unique_id

    legacy_filter = Ent("switch.filter", "device-id_filter_123")

    entity_registry = MagicMock()
    entity_registry.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [legacy_filter],
    )

    res = await init_mod.async_migrate_entry(ph_hass, entry)
    assert res is False
    ph_hass.config_entries.async_update_entry.assert_called_once_with(entry, version=5)


@pytest.mark.asyncio
@pytest.mark.parametrize("should_raise", [False, True])
async def test_async_setup_calls_services_and_handles_exceptions(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any, should_raise: Any
) -> None:
    """Verify ``async_setup`` invokes the service hook and propagates errors.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        ph_hass: Home Assistant test instance.
        should_raise: Whether the service hook should raise an error.
    """
    mock_align = MagicMock()
    if should_raise:
        mock_services = AsyncMock(side_effect=RuntimeError("fail"))
    else:
        mock_services = AsyncMock(return_value=None)

    monkeypatch.setattr(init_mod, "_align_aiopnsense_log_level", mock_align)
    monkeypatch.setattr(init_mod, "async_setup_services", mock_services)

    if should_raise:
        with pytest.raises(RuntimeError):
            await init_mod.async_setup(ph_hass, {})
        mock_services.assert_awaited_once()
        mock_align.assert_called_once_with()
    else:
        res = await init_mod.async_setup(ph_hass, {})
        assert res is True
        mock_services.assert_awaited_once()
        mock_align.assert_called_once_with()


@pytest.mark.asyncio
async def test_async_update_listener_reload_and_remove(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """When SHOULD_RELOAD True and sync disabled, update listener schedules reload and removes entities."""
    # Prepare entry with SHOULD_RELOAD True and granular sync option disabled to force removal_prefixes
    entry = make_config_entry(
        data={
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
            "sync_telemetry": False,
        },
        unique_id="u123",
    )
    setattr(entry.runtime_data, init_mod.SHOULD_RELOAD, True)
    # config entries and hass async reload stub
    # use migration fixture which provides config_entries and async helpers
    hass = ph_hass
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    # construct an entity that should be removed by unique_id prefix
    class Ent:
        def __init__(self, entity_id: Any, unique_id: Any) -> None:
            """Store the entity and unique IDs used by the update-listener test."""
            self.entity_id = entity_id
            self.unique_id = unique_id

    # explicitly use the 'sync_telemetry' prefix so the test targets the intended sync item
    prefix = list(init_mod.GRANULAR_SYNC_PREFIX["sync_telemetry"])
    pre = prefix[0]
    ent = Ent("sensor.x", f"{entry.unique_id}_{pre}_suffix")

    # monkeypatch entity registry functions
    er_reg = MagicMock()
    er_reg.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: er_reg)
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: [ent]
    )
    # patch device registry to return no devices and provide async_remove_device
    dr_reg = MagicMock()
    dr_reg.async_remove_device = MagicMock()
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: dr_reg)
    monkeypatch.setattr(
        init_mod.dr, "async_entries_for_config_entry", lambda registry, config_entry_id: []
    )

    # config option already provided via factory; no mutation needed

    await init_mod._async_update_listener(hass, entry)

    # async_create_task should have been used to schedule reload
    assert hass.async_create_task.called

    # entity matched by prefix should be removed; no devices to remove
    er_reg.async_remove.assert_called_once_with(ent.entity_id)
    dr_reg.async_remove_device.assert_not_called()


@pytest.mark.asyncio
async def test_async_update_listener_removes_native_firewall_entities(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Update listener should remove native firewall entities when sync is disabled."""
    entry = make_config_entry(
        data={
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
            "sync_firewall_and_nat": False,
        },
        unique_id="u123",
    )
    setattr(entry.runtime_data, init_mod.SHOULD_RELOAD, True)

    hass = ph_hass
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    class Ent:
        """Simple entity record for registry cleanup assertions."""

        def __init__(self, entity_id: str, unique_id: str) -> None:
            """Store entity and unique IDs for the test."""
            self.entity_id = entity_id
            self.unique_id = unique_id

    ent = Ent("switch.native_firewall", f"{entry.unique_id}_firewall_rule_rule1")

    entity_registry = MagicMock()
    entity_registry.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [ent],
    )

    device_registry = MagicMock()
    device_registry.async_remove_device = MagicMock()
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: device_registry)
    monkeypatch.setattr(
        init_mod.dr,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [],
    )

    await init_mod._async_update_listener(hass, entry)

    entity_registry.async_remove.assert_called_once_with(ent.entity_id)


@pytest.mark.asyncio
async def test_async_update_listener_uses_shared_default_for_smart_entity_pruning(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Missing SMART sync config should preserve registered SMART entities."""
    entry = make_config_entry(
        data={init_mod.CONF_DEVICE_UNIQUE_ID: "dev1"},
        unique_id="u123",
    )
    setattr(entry.runtime_data, init_mod.SHOULD_RELOAD, True)
    hass = ph_hass
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    smart_entity = MagicMock()
    smart_entity.entity_id = "binary_sensor.opnsense_smart_nvme0_status"
    smart_entity.unique_id = f"{entry.unique_id}_smart_nvme0_status"
    telemetry_entity = MagicMock()
    telemetry_entity.entity_id = "sensor.opnsense_cpu"
    telemetry_entity.unique_id = f"{entry.unique_id}_telemetry_cpu"

    entity_registry = MagicMock()
    entity_registry.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [smart_entity, telemetry_entity],
    )

    device_registry = MagicMock()
    device_registry.async_remove_device = MagicMock()
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: device_registry)
    monkeypatch.setattr(
        init_mod.dr,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [],
    )

    await init_mod._async_update_listener(hass, entry)

    entity_registry.async_remove.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("dt_enabled", "via_device_id", "expect_removed"),
    [
        (False, True, True),
        (False, False, False),
        (True, True, False),
    ],
)
async def test_async_update_listener_device_removal_param(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
    dt_enabled: Any,
    via_device_id: Any,
    expect_removed: Any,
) -> None:
    """Parameterized: ensure devices are removed only when device tracker disabled and via_device_id is True."""
    # create an entry with the device tracker option set per parameter
    entry = make_config_entry(
        data={init_mod.CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={init_mod.CONF_DEVICE_TRACKER_ENABLED: dt_enabled},
    )
    setattr(entry.runtime_data, init_mod.SHOULD_RELOAD, True)

    hass = ph_hass
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    # prepare a single device entry returned by the device registry
    device = MagicMock()
    device.via_device_id = via_device_id
    device.id = "d_device"
    device.name = "devname"

    dr_reg = MagicMock()
    dr_reg.async_remove_device = MagicMock()
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: dr_reg)
    monkeypatch.setattr(
        init_mod.dr,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [device],
    )

    # ensure no entity registry removals interfere
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: MagicMock())
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [],
    )

    await init_mod._async_update_listener(hass, entry)

    if expect_removed:
        dr_reg.async_remove_device.assert_called_once_with(device.id)
    else:
        dr_reg.async_remove_device.assert_not_called()


@pytest.mark.asyncio
async def test_async_setup_entry_firmware_below_min(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_client: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry returns False for devices with firmware below minimum supported."""
    # fake client where device id matches but firmware is below min
    patch_opnsense_client(monkeypatch, init_mod, fake_client(firmware_version="1.0"))
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    entry = make_config_entry(
        data={
            init_mod.CONF_URL: "http://1.2.3.4",
            init_mod.CONF_USERNAME: "u",
            init_mod.CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        }
    )
    # use hass fixture for aiohttp helpers
    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data.setdefault("aiohttp_connector", {})

    res = await init_mod.async_setup_entry(hass, entry)
    assert res is False


@pytest.mark.asyncio
async def test_async_setup_entry_firmware_between_min_and_ltd(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_client: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry logs a warning issue for firmware between min and LTD but continues."""
    patch_opnsense_client(monkeypatch, init_mod, fake_client(firmware_version="25.1"))
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )
    # capture calls to the issue registry to assert a warning issue is created
    create_issue_mock = MagicMock()
    monkeypatch.setattr(init_mod.ir, "async_create_issue", create_issue_mock)

    entry = make_config_entry(
        data={
            init_mod.CONF_URL: "http://1.2.3.4",
            init_mod.CONF_USERNAME: "u",
            init_mod.CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        }
    )
    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data.setdefault("aiohttp_connector", {})

    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True
    # verify the LTD deprecation/warning issue was created
    assert create_issue_mock.called, (
        "async_create_issue should have been called for firmware between min and LTD"
    )
    call_args = create_issue_mock.call_args
    # args: (hass, domain, issue_id, ...)
    assert call_args[0][1] == init_mod.DOMAIN
    expected_issue_id = f"{entry.data[init_mod.CONF_DEVICE_UNIQUE_ID]}_opnsense_below_ltd_firmware_{init_mod.OPNSENSE_LTD_FIRMWARE}"
    assert call_args[0][2] == expected_issue_id
    assert call_args[1].get("severity") == init_mod.ir.IssueSeverity.WARNING


@pytest.mark.asyncio
async def test_migrate_2_to_3_missing_device_id(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """_migrate_2_to_3 returns False when the client provides no device id."""
    client = fake_client(device_id=None)()
    cfg = MagicMock()
    cfg.data = {
        init_mod.CONF_URL: "http://1.2.3.4",
        init_mod.CONF_USERNAME: "u",
        init_mod.CONF_PASSWORD: "p",
    }
    cfg.version = 2
    # set up hass fixture-like object for registry access
    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    # avoid touching real entity/device registry and aiohttp helpers
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: MagicMock())
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: MagicMock())
    res = await init_mod._migrate_2_to_3(hass, cfg, client)
    assert res is False


@pytest.mark.asyncio
async def test_migrate_2_to_3_success(monkeypatch: pytest.MonkeyPatch, fake_client: Any) -> None:
    """_migrate_2_to_3 updates device and entity identifiers when client reports new device id."""
    client = fake_client(device_id="newdev")()

    # fake device entries and entity entries
    dev = MagicMock()
    dev.id = "d1"
    dev.identifiers = {("opnsense", "old")}

    ent = MagicMock()
    ent.entity_id = "sensor.x"
    ent.unique_id = "old"
    ent.device_id = "d1"

    er_reg = MagicMock()
    er_reg.async_update_entity = MagicMock(
        return_value=MagicMock(entity_id=ent.entity_id, unique_id="new")
    )
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: er_reg)
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: [ent]
    )

    dr_reg = MagicMock()
    dr_reg.async_update_device = MagicMock(
        return_value=MagicMock(id=dev.id, identifiers={("opnsense", "newdev")})
    )
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: dr_reg)
    monkeypatch.setattr(
        init_mod.dr, "async_entries_for_config_entry", lambda registry, config_entry_id: [dev]
    )

    cfg = MagicMock()
    cfg.data = {
        init_mod.CONF_URL: "http://1.2.3.4",
        init_mod.CONF_USERNAME: "u",
        init_mod.CONF_PASSWORD: "p",
    }
    cfg.version = 2
    cfg.entry_id = "e"
    cfg.unique_id = "old_unique"

    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)
    res = await init_mod._migrate_2_to_3(hass, cfg, client)
    assert res is True
    assert dr_reg.async_update_device.called, "device identifiers should be updated"
    assert er_reg.async_update_entity.called, "entity unique_ids should be updated"
    assert hass.config_entries.async_update_entry.called
    kwargs = hass.config_entries.async_update_entry.call_args.kwargs
    assert kwargs["version"] == 3
    assert kwargs["unique_id"] == "newdev"
    assert kwargs["data"][init_mod.CONF_DEVICE_UNIQUE_ID] == "newdev"


@pytest.mark.asyncio
async def test_migrate_2_to_3_returns_false_when_update_entry_fails(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """_migrate_2_to_3 should fail when config entry update returns False."""
    client = fake_client(device_id="newdev")()

    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: MagicMock())
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: []
    )
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: MagicMock())
    monkeypatch.setattr(
        init_mod.dr, "async_entries_for_config_entry", lambda registry, config_entry_id: []
    )

    cfg = MagicMock()
    cfg.data = {
        init_mod.CONF_URL: "http://1.2.3.4",
        init_mod.CONF_USERNAME: "u",
        init_mod.CONF_PASSWORD: "p",
    }
    cfg.version = 2
    cfg.entry_id = "e"
    cfg.unique_id = "old_unique"

    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=False)

    res = await init_mod._migrate_2_to_3(hass, cfg, client)
    assert res is False


@pytest.mark.asyncio
async def test_async_setup_entry_awesomeversion_exception(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_client: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry should continue when AwesomeVersion comparison raises an exception."""

    # fake client where device id matches but awesomeversion comparison raises
    # monkeypatch AwesomeVersion to a class that raises on comparison
    class DummyAV:
        def __init__(self, v: Any) -> None:
            """Store the version string used by the comparison stub."""
            self.v = v

        def __lt__(self, other: Any) -> None:
            """Raise a compare exception so setup falls back to the safe path."""
            raise init_mod.awesomeversion.exceptions.AwesomeVersionCompareException

    patch_opnsense_client(monkeypatch, init_mod, fake_client())
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )
    monkeypatch.setattr(init_mod.awesomeversion, "AwesomeVersion", DummyAV)
    entry = make_config_entry(
        data={
            init_mod.CONF_URL: "http://1.2.3.4",
            init_mod.CONF_USERNAME: "u",
            init_mod.CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        }
    )
    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()

    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True


@pytest.mark.asyncio
async def test_async_unload_entry_unload_fails(
    ph_hass: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """async_unload_entry returns False and keeps runtime resources when unload fails."""
    entry = make_config_entry(entry_id="e_unload_fail")
    entry.as_dict = lambda: {"id": "x"}
    setattr(entry.runtime_data, init_mod.LOADED_PLATFORMS, ["p1"])
    fake_client = MagicMock()
    fake_client.async_close = AsyncMock()
    setattr(entry.runtime_data, init_mod.OPNSENSE_CLIENT, fake_client)

    hass = ph_hass
    # unload_platforms returns False
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=False)
    hass.data = {init_mod.DOMAIN: {entry.entry_id: fake_client}}
    res = await init_mod.async_unload_entry(hass, entry)
    assert res is False
    # hass.data should still have the entry
    assert entry.entry_id in hass.data[init_mod.DOMAIN]
    fake_client.async_close.assert_not_awaited()


@pytest.mark.asyncio
async def test_migrate_3_to_4_filesystem_and_remove(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """_migrate_3_to_4 handles filesystem telemetry renames and removes connected_client_count entities."""
    client = fake_client(telemetry={"filesystems": [{"device": "/dev/sda1", "mountpoint": "/"}]})()

    # entities: one that maps telemetry_filesystems, one that is connected_client_count
    # make e1's unique_id include the processed device name so the migration will match
    e1 = MagicMock()
    e1.entity_id = "sensor.fs"
    e1.unique_id = "abc_telemetry_filesystems_slash_dev_slash_sda1"
    e2 = MagicMock()
    e2.entity_id = "sensor.clients"
    e2.unique_id = "something_connected_client_count"

    er_reg = MagicMock()
    er_reg.async_update_entity = MagicMock(
        return_value=MagicMock(entity_id=e1.entity_id, unique_id="updated")
    )
    er_reg.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: er_reg)
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: [e1, e2]
    )

    cfg = MagicMock()
    cfg.data = {
        init_mod.CONF_URL: "http://1.2.3.4",
        init_mod.CONF_USERNAME: "u",
        init_mod.CONF_PASSWORD: "p",
    }
    cfg.version = 3
    cfg.entry_id = "e3"

    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)
    # avoid aiohttp connector creation
    res = await init_mod._migrate_3_to_4(hass, cfg, client)
    assert res is True
    # Ensure the connected_client_count entity was removed (called with entity_id)
    er_reg.async_remove.assert_called_once_with(e2.entity_id)
    # Ensure telemetry-mapped entity was updated with the expected new unique_id
    expected_new_unique_id = "abc_telemetry_filesystems_root"
    er_reg.async_update_entity.assert_called_once_with(
        e1.entity_id, new_unique_id=expected_new_unique_id
    )


@pytest.mark.asyncio
async def test_migrate_3_to_4_filesystem_preserves_unique_id_prefix(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """Filesystem remap should only replace the suffix after telemetry_filesystems_."""
    client = fake_client(telemetry={"filesystems": [{"device": "/dev/sda1", "mountpoint": "/"}]})()

    e1 = MagicMock()
    e1.entity_id = "sensor.fs"
    e1.unique_id = "slash_dev_slash_sda1_telemetry_filesystems_slash_dev_slash_sda1"

    er_reg = MagicMock()
    er_reg.async_update_entity = MagicMock(
        return_value=MagicMock(entity_id=e1.entity_id, unique_id="updated")
    )
    er_reg.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: er_reg)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [e1],
    )

    cfg = MagicMock()
    cfg.data = {
        init_mod.CONF_URL: "http://1.2.3.4",
        init_mod.CONF_USERNAME: "u",
        init_mod.CONF_PASSWORD: "p",
    }
    cfg.version = 3
    cfg.entry_id = "e3"

    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    res = await init_mod._migrate_3_to_4(hass, cfg, client)
    assert res is True
    er_reg.async_update_entity.assert_called_once_with(
        e1.entity_id,
        new_unique_id="slash_dev_slash_sda1_telemetry_filesystems_root",
    )


@pytest.mark.asyncio
async def test_migrate_3_to_4_filesystem_skips_and_non_root_mountpoint(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """_migrate_3_to_4 skips unmapped entities and maps non-root filesystem mountpoints."""
    client = fake_client(
        telemetry={
            "filesystems": [
                {"device": "/dev/other", "mountpoint": "/unused"},
                {"device": "/dev/sdb1", "mountpoint": "/mnt/data"},
                {"device": "data", "mountpoint": "/data"},
            ]
        }
    )()

    matched = MagicMock()
    matched.entity_id = "sensor.fs_data"
    matched.unique_id = "abc_telemetry_filesystems_slash_dev_slash_sdb1"
    unmatched_filesystem = MagicMock()
    unmatched_filesystem.entity_id = "sensor.fs_missing"
    unmatched_filesystem.unique_id = "abc_telemetry_filesystems_slash_dev_slash_missing"
    unchanged_filesystem = MagicMock()
    unchanged_filesystem.entity_id = "sensor.fs_unchanged"
    unchanged_filesystem.unique_id = "abc_telemetry_filesystems_data"
    unknown_sensor = MagicMock()
    unknown_sensor.entity_id = "sensor.unmapped"
    unknown_sensor.unique_id = "abc_unmapped"

    er_reg = MagicMock()
    er_reg.async_update_entity = MagicMock(
        return_value=MagicMock(entity_id=matched.entity_id, unique_id="updated")
    )
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: er_reg)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [
            matched,
            unmatched_filesystem,
            unchanged_filesystem,
            unknown_sensor,
        ],
    )

    cfg = MagicMock()
    cfg.data = {
        init_mod.CONF_URL: "http://1.2.3.4",
        init_mod.CONF_USERNAME: "u",
        init_mod.CONF_PASSWORD: "p",
    }
    cfg.version = 3
    cfg.entry_id = "e3"

    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    res = await init_mod._migrate_3_to_4(hass, cfg, client)

    assert res is True
    er_reg.async_update_entity.assert_called_once_with(
        matched.entity_id, new_unique_id="abc_telemetry_filesystems_mnt_data"
    )


@pytest.mark.asyncio
async def test_migrate_3_to_4_skips_filesystems_when_telemetry_is_not_mapping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_migrate_3_to_4 should defer filesystem remaps when telemetry is invalid."""

    class Client:
        async def get_telemetry(self) -> None:
            """Return an invalid telemetry payload for migration hardening."""
            return

    client = Client()

    interface_entity = MagicMock()
    interface_entity.entity_id = "sensor.interface"
    interface_entity.unique_id = "abc_telemetry_interface_lan"
    filesystem_entity = MagicMock()
    filesystem_entity.entity_id = "sensor.fs"
    filesystem_entity.unique_id = "abc_telemetry_filesystems_slash_dev_slash_sda1"

    entity_registry = MagicMock()
    entity_registry.async_update_entity = MagicMock(
        return_value=MagicMock(entity_id=interface_entity.entity_id, unique_id="updated")
    )
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [interface_entity, filesystem_entity],
    )

    config_entry = MagicMock()
    config_entry.version = 3
    config_entry.entry_id = "e3"

    hass = MagicMock(spec=HomeAssistant)
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    result = await init_mod._migrate_3_to_4(hass, config_entry, client)

    assert result is False
    entity_registry.async_update_entity.assert_called_once_with(
        interface_entity.entity_id,
        new_unique_id="abc_interface_lan",
    )
    hass.config_entries.async_update_entry.assert_not_called()


@pytest.mark.asyncio
async def test_migrate_3_to_4_skips_filesystems_when_filesystems_payload_is_invalid(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """_migrate_3_to_4 should defer filesystem remaps when filesystems is invalid."""
    client = fake_client(telemetry={"filesystems": None})()

    filesystem_entity = MagicMock()
    filesystem_entity.entity_id = "sensor.fs"
    filesystem_entity.unique_id = "abc_telemetry_filesystems_slash_dev_slash_sda1"

    entity_registry = MagicMock()
    entity_registry.async_update_entity = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [filesystem_entity],
    )

    config_entry = MagicMock()
    config_entry.version = 3
    config_entry.entry_id = "e3"

    hass = MagicMock(spec=HomeAssistant)
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    result = await init_mod._migrate_3_to_4(hass, config_entry, client)

    assert result is False
    entity_registry.async_update_entity.assert_not_called()
    hass.config_entries.async_update_entry.assert_not_called()


@pytest.mark.asyncio
async def test_migrate_3_to_4_defers_filesystems_when_filesystems_contains_non_mapping_item(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """_migrate_3_to_4 should defer when filesystems contains untrusted non-mapping entries."""
    client = fake_client(telemetry={"filesystems": [None]})()

    filesystem_entity = MagicMock()
    filesystem_entity.entity_id = "sensor.fs"
    filesystem_entity.unique_id = "abc_telemetry_filesystems_slash_dev_slash_sda1"

    entity_registry = MagicMock()
    entity_registry.async_update_entity = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [filesystem_entity],
    )

    config_entry = MagicMock()
    config_entry.version = 3
    config_entry.entry_id = "e3"

    hass = MagicMock(spec=HomeAssistant)
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    result = await init_mod._migrate_3_to_4(hass, config_entry, client)

    assert result is False
    entity_registry.async_update_entity.assert_not_called()
    hass.config_entries.async_update_entry.assert_not_called()


@pytest.mark.asyncio
async def test_migrate_3_to_4_defers_filesystem_migration_when_mountpoint_invalid(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """A matched filesystem with an invalid mountpoint should defer the migration."""
    client = fake_client(
        telemetry={
            "filesystems": [
                {"device": None, "mountpoint": "/"},
                {"device": "/dev/sda1", "mountpoint": None},
                {"device": "/dev/sdb1", "mountpoint": "/mnt/data"},
            ]
        }
    )()

    filesystem_entity = MagicMock()
    filesystem_entity.entity_id = "sensor.fs"
    filesystem_entity.unique_id = "abc_telemetry_filesystems_slash_dev_slash_sda1"

    entity_registry = MagicMock()
    entity_registry.async_update_entity = MagicMock(
        return_value=MagicMock(entity_id=filesystem_entity.entity_id, unique_id="updated")
    )
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [filesystem_entity],
    )

    config_entry = MagicMock()
    config_entry.version = 3
    config_entry.entry_id = "e3"

    hass = MagicMock(spec=HomeAssistant)
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    result = await init_mod._migrate_3_to_4(hass, config_entry, client)

    assert result is False
    entity_registry.async_update_entity.assert_not_called()
    hass.config_entries.async_update_entry.assert_not_called()


@pytest.mark.asyncio
async def test_migrate_3_to_4_skips_filesystems_when_filesystems_key_is_missing(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """_migrate_3_to_4 should defer when telemetry lacks filesystems metadata."""
    client = fake_client(telemetry={})()

    filesystem_entity = MagicMock()
    filesystem_entity.entity_id = "sensor.fs"
    filesystem_entity.unique_id = "abc_telemetry_filesystems_slash_dev_slash_sda1"

    entity_registry = MagicMock()
    entity_registry.async_update_entity = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [filesystem_entity],
    )

    config_entry = MagicMock()
    config_entry.version = 3
    config_entry.entry_id = "e3"

    hass = MagicMock(spec=HomeAssistant)
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    result = await init_mod._migrate_3_to_4(hass, config_entry, client)

    assert result is False
    entity_registry.async_update_entity.assert_not_called()
    hass.config_entries.async_update_entry.assert_not_called()


@pytest.mark.asyncio
async def test_migrate_3_to_4_returns_false_when_update_entry_fails(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """_migrate_3_to_4 should fail when config entry update returns False."""
    client = fake_client(telemetry={})()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: MagicMock())
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: []
    )

    cfg = MagicMock()
    cfg.data = {
        init_mod.CONF_URL: "http://1.2.3.4",
        init_mod.CONF_USERNAME: "u",
        init_mod.CONF_PASSWORD: "p",
    }
    cfg.version = 3
    cfg.entry_id = "e3"

    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=False)

    res = await init_mod._migrate_3_to_4(hass, cfg, client)

    assert res is False


@pytest.mark.asyncio
async def test_migrate_2_to_3_handles_entity_update_value_error(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """When entity_registry.async_update_entity raises ValueError, migration continues."""
    client = fake_client(device_id="newdev")()

    # single entity that will cause async_update_entity to raise
    ent = MagicMock()
    ent.entity_id = "sensor.x"
    ent.unique_id = "old"

    er_reg = MagicMock()
    er_reg.async_update_entity = MagicMock(side_effect=ValueError("bad entity"))
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: er_reg)
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: [ent]
    )

    # no devices to update
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: MagicMock())
    monkeypatch.setattr(
        init_mod.dr, "async_entries_for_config_entry", lambda registry, config_entry_id: []
    )

    cfg = MagicMock()
    cfg.data = {
        init_mod.CONF_URL: "http://1.2.3.4",
        init_mod.CONF_USERNAME: "u",
        init_mod.CONF_PASSWORD: "p",
    }
    cfg.version = 2
    cfg.entry_id = "e"
    cfg.unique_id = "old_unique"

    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    res = await init_mod._migrate_2_to_3(hass, cfg, client)
    assert res is True
    # ensure we attempted to update the entity (which raised) and migration completed
    er_reg.async_update_entity.assert_called_once_with(ent.entity_id, new_unique_id=ANY)
    assert hass.config_entries.async_update_entry.called


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", [KeyError("k"), ValueError("v")])
async def test_migrate_3_to_4_handles_remove_exceptions(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any, exc: BaseException | None
) -> None:
    """If entity_registry.async_remove raises KeyError/ValueError, migration continues."""
    client = fake_client(telemetry={})()

    e = MagicMock()
    e.entity_id = "sensor.clients"
    e.unique_id = "something_connected_client_count"

    er_reg = MagicMock()
    er_reg.async_remove = MagicMock(side_effect=exc)
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: er_reg)
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: [e]
    )

    cfg = MagicMock()
    cfg.data = {
        init_mod.CONF_URL: "http://1.2.3.4",
        init_mod.CONF_USERNAME: "u",
        init_mod.CONF_PASSWORD: "p",
    }
    cfg.version = 3
    cfg.entry_id = "e3"

    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    res = await init_mod._migrate_3_to_4(hass, cfg, client)
    assert res is True
    er_reg.async_remove.assert_called_once_with(e.entity_id)


@pytest.mark.asyncio
async def test_migrate_3_to_4_handles_update_value_error(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """If entity_registry.async_update_entity raises ValueError, migration continues."""
    client = fake_client(telemetry={})()

    e = MagicMock()
    e.entity_id = "sensor.if"
    e.unique_id = "abc_telemetry_interface_eth0"

    er_reg = MagicMock()
    er_reg.async_update_entity = MagicMock(side_effect=ValueError("bad update"))
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: er_reg)
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: [e]
    )

    cfg = MagicMock()
    cfg.data = {
        init_mod.CONF_URL: "http://1.2.3.4",
        init_mod.CONF_USERNAME: "u",
        init_mod.CONF_PASSWORD: "p",
    }
    cfg.version = 3
    cfg.entry_id = "e3"

    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    res = await init_mod._migrate_3_to_4(hass, cfg, client)
    assert res is True
    er_reg.async_update_entity.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("version", "failing_fn"),
    [
        (1, "_migrate_1_to_2"),
        (2, "_migrate_2_to_3"),
        (3, "_migrate_3_to_4"),
    ],
)
async def test_async_migrate_entry_returns_false_when_submigration_fails(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any, version: Any, failing_fn: Any
) -> None:
    """async_migrate_entry should return False when a sub-migration returns False."""
    # make the targeted sub-migration return False
    monkeypatch.setattr(init_mod, failing_fn, AsyncMock(return_value=False))
    client = MagicMock()
    client.async_close = AsyncMock()
    monkeypatch.setattr(init_mod, "create_opnsense_client", lambda **_kwargs: client)

    cfg = MagicMock()
    cfg.version = version
    cfg.data = {
        init_mod.CONF_URL: "http://1.2.3.4",
        init_mod.CONF_USERNAME: "u",
        init_mod.CONF_PASSWORD: "p",
    }

    # call with a real hass fixture
    res = await init_mod.async_migrate_entry(ph_hass, cfg)
    assert res is False


@pytest.mark.asyncio
@pytest.mark.parametrize("version", [2, 3])
async def test_async_migrate_entry_returns_false_when_migration_client_missing(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any, version: int
) -> None:
    """async_migrate_entry should fail version 2/3 migrations without a client."""
    monkeypatch.setattr(init_mod, "create_opnsense_client", lambda **_kwargs: None)

    cfg = MagicMock()
    cfg.version = version
    cfg.data = {
        init_mod.CONF_URL: "http://1.2.3.4",
        init_mod.CONF_USERNAME: "u",
        init_mod.CONF_PASSWORD: "p",
    }
    cfg.title = "router"

    res = await init_mod.async_migrate_entry(ph_hass, cfg)

    assert res is False


@pytest.mark.asyncio
async def test_async_setup_entry_firmware_above_ltd_calls_delete(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_client: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry deletes previous issues when firmware is at or above LTD."""
    patch_opnsense_client(
        monkeypatch, init_mod, fake_client(firmware_version=init_mod.OPNSENSE_LTD_FIRMWARE)
    )
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )
    called = []
    monkeypatch.setattr(init_mod.ir, "async_delete_issue", lambda *a, **k: called.append(True))

    entry = make_config_entry(
        data={
            init_mod.CONF_URL: "http://1.2.3.4",
            init_mod.CONF_USERNAME: "u",
            init_mod.CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        }
    )
    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = MagicMock()
    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True
    assert called, "async_delete_issue should have been called for firmware >= LTD"


@pytest.mark.asyncio
async def test_async_setup_entry_firmware_at_or_above_ltd_deletes_previous_issues(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_client: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry cleans up previous firmware-related issues for LTD and min thresholds."""
    patch_opnsense_client(
        monkeypatch, init_mod, fake_client(firmware_version=init_mod.OPNSENSE_LTD_FIRMWARE)
    )
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    # capture delete_issue calls
    delete_issue_mock = MagicMock()
    monkeypatch.setattr(init_mod.ir, "async_delete_issue", delete_issue_mock)

    entry = make_config_entry(
        data={
            init_mod.CONF_URL: "http://1.2.3.4",
            init_mod.CONF_USERNAME: "u",
            init_mod.CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        }
    )
    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = MagicMock()
    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True

    # Expect delete_issue to be called for the previous below-min and below-ltd issue ids
    assert delete_issue_mock.called, "async_delete_issue should have been called"
    called_issue_ids = [call[0][2] for call in delete_issue_mock.call_args_list if len(call[0]) > 2]
    expected_min = f"{entry.data[init_mod.CONF_DEVICE_UNIQUE_ID]}_opnsense_below_min_firmware_{init_mod.OPNSENSE_MIN_FIRMWARE}"
    expected_ltd = f"{entry.data[init_mod.CONF_DEVICE_UNIQUE_ID]}_opnsense_below_ltd_firmware_{init_mod.OPNSENSE_LTD_FIRMWARE}"
    assert expected_min in called_issue_ids
    assert expected_ltd in called_issue_ids


@pytest.mark.asyncio
async def test_async_setup_entry_delete_uses_actual_firmware_string(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_client: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry uses the client's firmware string when deleting previous issues."""
    firmware_str = "99.9"
    patch_opnsense_client(monkeypatch, init_mod, fake_client(firmware_version=firmware_str))
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    calls = MagicMock()
    monkeypatch.setattr(init_mod.ir, "async_delete_issue", calls)

    entry = make_config_entry(
        data={
            init_mod.CONF_URL: "http://1.2.3.4",
            init_mod.CONF_USERNAME: "u",
            init_mod.CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        }
    )
    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = MagicMock()
    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True

    # Confirm delete_issue was called for the expected issue ids
    expected_min = f"{entry.data[init_mod.CONF_DEVICE_UNIQUE_ID]}_opnsense_below_min_firmware_{init_mod.OPNSENSE_MIN_FIRMWARE}"
    expected_ltd = f"{entry.data[init_mod.CONF_DEVICE_UNIQUE_ID]}_opnsense_below_ltd_firmware_{init_mod.OPNSENSE_LTD_FIRMWARE}"
    assert calls.called, "async_delete_issue should have been called"
    issue_ids = [call[0][2] for call in calls.call_args_list if len(call[0]) > 2]
    assert expected_min in issue_ids
    assert expected_ltd in issue_ids


@pytest.mark.asyncio
async def test_async_setup_entry_delete_not_called_for_between_min_and_ltd(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_client: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry should not call delete_issue for firmware between min and LTD."""
    patch_opnsense_client(monkeypatch, init_mod, fake_client(firmware_version="25.1"))
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    delete_issue_mock = MagicMock()
    monkeypatch.setattr(init_mod.ir, "async_delete_issue", delete_issue_mock)

    entry = make_config_entry(
        data={
            init_mod.CONF_URL: "http://1.2.3.4",
            init_mod.CONF_USERNAME: "u",
            init_mod.CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        }
    )
    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data.setdefault("aiohttp_connector", {})

    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True
    # delete should not be called for firmware between min and LTD
    assert not delete_issue_mock.called


@pytest.mark.asyncio
async def test_async_setup_entry_with_device_tracker_enabled(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_client: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Device tracker option creates a device-tracker coordinator and triggers initial refresh."""
    patch_opnsense_client(monkeypatch, init_mod, fake_client())
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    entry = make_config_entry(
        data={
            init_mod.CONF_URL: "http://1.2.3.4",
            init_mod.CONF_USERNAME: "u",
            init_mod.CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={init_mod.CONF_DEVICE_TRACKER_ENABLED: True},
    )

    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = MagicMock()
    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True
    # ensure a device-tracker coordinator was created and its initial refresh ran
    assert any(getattr(inst, "_is_device_tracker", False) for inst in coordinator_capture.instances)
    assert any(getattr(inst, "refreshed", False) for inst in coordinator_capture.instances)


@pytest.mark.asyncio
async def test_async_setup_entry_cleans_up_when_device_tracker_refresh_fails(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry should clean up when device-tracker setup fails."""
    client = MagicMock()
    client.validate = AsyncMock(return_value=True)
    client.get_device_unique_id = AsyncMock(return_value="dev1")
    client.get_host_firmware_version = AsyncMock(return_value="99.0")
    client.async_close = AsyncMock(return_value=True)
    monkeypatch.setattr(init_mod, "create_opnsense_client", lambda **_kwargs: client)

    main_coordinator = MagicMock()
    main_coordinator.async_config_entry_first_refresh = AsyncMock(return_value=True)
    main_coordinator.async_shutdown = AsyncMock(return_value=True)
    device_tracker_coordinator = MagicMock()
    device_tracker_coordinator.async_config_entry_first_refresh = AsyncMock(
        side_effect=RuntimeError("device tracker refresh failed")
    )
    device_tracker_coordinator.async_shutdown = AsyncMock(return_value=True)

    coordinators = [main_coordinator, device_tracker_coordinator]

    def _coordinator_factory(**_kwargs: Any) -> Any:
        """Return setup coordinators in creation order."""
        return coordinators.pop(0)

    monkeypatch.setattr(init_mod, "OPNsenseDataUpdateCoordinator", _coordinator_factory)

    entry = make_config_entry(
        data={
            init_mod.CONF_URL: "http://1.2.3.4",
            init_mod.CONF_USERNAME: "u",
            init_mod.CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={init_mod.CONF_DEVICE_TRACKER_ENABLED: True},
    )

    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = MagicMock()
    hass.data = {}

    with pytest.raises(RuntimeError, match="device tracker refresh failed"):
        await init_mod.async_setup_entry(hass, entry)

    main_coordinator.async_shutdown.assert_awaited_once()
    device_tracker_coordinator.async_shutdown.assert_awaited_once()
    client.async_close.assert_awaited_once()
    assert entry.entry_id not in hass.data.get(init_mod.DOMAIN, {})


@pytest.mark.asyncio
async def test_async_setup_entry_cleans_up_when_platform_forwarding_fails(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry should clean up when platform forwarding fails."""
    client = MagicMock()
    client.validate = AsyncMock(return_value=True)
    client.get_device_unique_id = AsyncMock(return_value="dev1")
    client.get_host_firmware_version = AsyncMock(return_value="99.0")
    client.async_close = AsyncMock(return_value=True)
    monkeypatch.setattr(init_mod, "create_opnsense_client", lambda **_kwargs: client)

    coordinator = MagicMock()
    coordinator.async_config_entry_first_refresh = AsyncMock(return_value=True)
    coordinator.async_shutdown = AsyncMock(return_value=True)
    monkeypatch.setattr(init_mod, "OPNsenseDataUpdateCoordinator", lambda **_kwargs: coordinator)

    entry = make_config_entry(
        data={
            init_mod.CONF_URL: "http://1.2.3.4",
            init_mod.CONF_USERNAME: "u",
            init_mod.CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={init_mod.CONF_DEVICE_TRACKER_ENABLED: False},
    )
    remove_listener = MagicMock()
    entry.add_update_listener = MagicMock(return_value=remove_listener)
    entry.async_on_unload = MagicMock(return_value=None)

    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(
        side_effect=RuntimeError("platform forwarding failed")
    )
    hass.config_entries.async_reload = MagicMock()
    hass.data = {}

    with pytest.raises(RuntimeError, match="platform forwarding failed"):
        await init_mod.async_setup_entry(hass, entry)

    coordinator.async_shutdown.assert_awaited_once()
    client.async_close.assert_awaited_once()
    entry.add_update_listener.assert_called_once()
    entry.async_on_unload.assert_called_once_with(remove_listener)
    remove_listener.assert_not_called()
    assert entry.entry_id not in hass.data.get(init_mod.DOMAIN, {})


@pytest.mark.asyncio
async def test_async_setup_entry_registers_update_listener_before_forwarding(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Update listener registration should happen before platform forwarding."""
    call_order: list[str] = []

    client = MagicMock()
    client.validate = AsyncMock(return_value=True)
    client.get_device_unique_id = AsyncMock(return_value="dev1")
    client.get_host_firmware_version = AsyncMock(return_value="99.0")
    client.async_close = AsyncMock(return_value=True)
    monkeypatch.setattr(init_mod, "create_opnsense_client", lambda **_kwargs: client)

    coordinator = MagicMock()
    coordinator.async_config_entry_first_refresh = AsyncMock(return_value=True)
    coordinator.async_shutdown = AsyncMock(return_value=True)
    monkeypatch.setattr(init_mod, "OPNsenseDataUpdateCoordinator", lambda **_kwargs: coordinator)

    entry = make_config_entry(
        data={
            init_mod.CONF_URL: "http://1.2.3.4",
            init_mod.CONF_USERNAME: "u",
            init_mod.CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={init_mod.CONF_DEVICE_TRACKER_ENABLED: False},
    )
    remove_listener = MagicMock()

    def _add_update_listener(listener: Any) -> MagicMock:
        call_order.append("add_listener")
        return remove_listener

    def _async_on_unload(unregister: MagicMock) -> None:
        call_order.append("async_on_unload")

    entry.add_update_listener = MagicMock(side_effect=_add_update_listener)
    entry.async_on_unload = MagicMock(side_effect=_async_on_unload)

    async def _forward_entry_setups(*_args: Any, **_kwargs: Any) -> bool:
        call_order.append("forward")
        return True

    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(side_effect=_forward_entry_setups)
    hass.config_entries.async_reload = MagicMock()
    hass.data = {}

    res = await init_mod.async_setup_entry(hass, entry)

    assert res is True
    assert call_order.index("add_listener") < call_order.index("forward")
    entry.add_update_listener.assert_called_once_with(init_mod._async_update_listener)
    entry.async_on_unload.assert_called_once_with(remove_listener)
    remove_listener.assert_not_called()


@pytest.mark.asyncio
async def test_migrate_2_to_3_handles_identifier_collision(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """_migrate_2_to_3 continues when DeviceIdentifierCollisionError occurs while updating devices."""
    # migration should continue if DeviceIdentifierCollisionError raised when updating device
    client = fake_client(device_id="newdev")()

    # fake device that will cause collision when updating
    dev = MagicMock()
    dev.id = "d1"
    dev.identifiers = {("opnsense", "old")}

    class DeviceRegistry:
        def __init__(self) -> None:
            """Provide a fake device registry object for the collision test."""

        def async_update_device(self, *a, **k) -> Never:
            # DeviceIdentifierCollisionError requires an existing_device argument
            """Raise the collision error expected by the registry migration test."""
            raise init_mod.dr.DeviceIdentifierCollisionError("collision", MagicMock(id="other"))

    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: DeviceRegistry())
    monkeypatch.setattr(
        init_mod.dr, "async_entries_for_config_entry", lambda registry, config_entry_id: [dev]
    )
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: MagicMock())
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: []
    )
    cfg = MagicMock()
    cfg.data = {
        init_mod.CONF_URL: "http://1.2.3.4",
        init_mod.CONF_USERNAME: "u",
        init_mod.CONF_PASSWORD: "p",
    }
    cfg.version = 2
    cfg.entry_id = "e"
    cfg.unique_id = "old_unique"

    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    res = await init_mod._migrate_2_to_3(hass, cfg, client)
    assert res is True


@pytest.mark.asyncio
async def test_migrate_3_to_4_defers_when_filesystem_device_is_not_string(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any
) -> None:
    """_migrate_3_to_4 should defer when filesystem device values are malformed."""
    client = MagicMock()
    client.get_telemetry = AsyncMock(return_value={"filesystems": [{"device": 7}]})

    migration_entry = MagicMock()
    migration_entry.entry_id = "entry"
    migration_entry.version = 3

    hass = ph_hass
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    class EntityRegistry:
        def async_entries_for_config_entry(
            self, registry: Any, config_entry_id: str
        ) -> list[MagicMock]:
            """Expose one stale filesystem telemetry entity for migration."""
            return [
                MagicMock(
                    entity_id="sensor.router_telemetry_filesystems_root",
                    unique_id="router_telemetry_filesystems_root",
                )
            ]

        def async_update_entity(self, entity_id: str, new_unique_id: str) -> Any:
            """Surface unsupported update attempts as a test failure."""
            raise AssertionError(
                "Entity updates should not occur when filesystem migration is deferred"
            )

    entity_registry = EntityRegistry()
    monkeypatch.setattr(init_mod.er, "async_get", lambda _hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        entity_registry.async_entries_for_config_entry,
    )

    res = await init_mod._migrate_3_to_4(hass, migration_entry, client)

    assert res is False
    hass.config_entries.async_update_entry.assert_not_called()


@pytest.mark.asyncio
async def test_migrate_3_to_4_defers_without_updating_entities_when_later_filesystem_invalid(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any
) -> None:
    """A valid filesystem before a malformed filesystem should not partially migrate or bump version."""
    client = MagicMock()
    client.get_telemetry = AsyncMock(
        return_value={
            "filesystems": [
                {"device": "/dev/sda1", "mountpoint": "/"},
                {"device": 7, "mountpoint": "/data"},
            ]
        }
    )

    migration_entry = MagicMock()
    migration_entry.entry_id = "entry"
    migration_entry.version = 3

    first_filesystem_entity = MagicMock(
        entity_id="sensor.router_telemetry_filesystems_slash_dev_slash_sda1",
        unique_id="router_telemetry_filesystems_slash_dev_slash_sda1",
    )
    second_filesystem_entity = MagicMock(
        entity_id="sensor.router_telemetry_filesystems_slash_dev_slash_sdb1",
        unique_id="router_telemetry_filesystems_slash_dev_slash_sdb1",
    )

    hass = ph_hass
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    entity_registry = MagicMock()
    entity_registry.async_entries_for_config_entry = lambda registry, config_entry_id: [
        first_filesystem_entity,
        second_filesystem_entity,
    ]
    entity_registry.async_update_entity = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda _hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        entity_registry.async_entries_for_config_entry,
    )

    res = await init_mod._migrate_3_to_4(hass, migration_entry, client)

    assert res is False
    entity_registry.async_update_entity.assert_not_called()
    hass.config_entries.async_update_entry.assert_not_called()
