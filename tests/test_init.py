"""Unit tests for the integration package initialization and lifecycle helpers.

These tests exercise async_setup_entry, migration helpers, update listeners,
and removal/unload behaviors for the hass-opnsense integration.
"""

import importlib
from unittest.mock import ANY, AsyncMock, MagicMock

import pytest

from homeassistant.core import HomeAssistant
import homeassistant.helpers.aiohttp_client as _hc

# import the package module object so we can access its functions/attrs
init_mod = importlib.import_module("custom_components.opnsense")


@pytest.fixture(autouse=True)
def _patch_hass_async_create_clientsession(monkeypatch):
    """Autouse fixture to stub Home Assistant's async_create_clientsession.

    Some tests use a minimal `hass` object (SimpleNamespace) which does not
    provide the full helper; patch the helper to return a lightweight
    session-like object to avoid opening real network resources.
    """

    def _fake_create_clientsession(*args, **kwargs):
        class _FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                await self.close()
                return False

            async def close(self):
                return True

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

    # Also patch the integration's local import of the helper so the
    # integration doesn't create a real session when tests import the
    # symbol into its own namespace (e.g., `from ...aiohttp_client import async_create_clientsession`).
    # Use raising=False and a fallback import path to be resilient.
    monkeypatch.setattr(
        init_mod, "async_create_clientsession", _fake_create_clientsession, raising=False
    )
    # Stub CookieJar used by migrations so aiohttp isn't required in the test env
    monkeypatch.setattr(
        "custom_components.opnsense.aiohttp.CookieJar",
        lambda *a, **k: object(),
        raising=False,
    )


@pytest.mark.asyncio
async def test_async_setup_entry_success(
    monkeypatch, ph_hass, coordinator_capture, fake_client, fake_coordinator, make_config_entry
):
    """async_setup_entry should succeed with valid client and coordinator."""
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client())
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
async def test_async_setup_entry_device_id_mismatch(
    monkeypatch, ph_hass, coordinator_capture, fake_client, fake_coordinator, make_config_entry
):
    """async_setup_entry should fail when client reports mismatched device id."""
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client(device_id="other"))
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
async def test_async_update_listener_not_reload(monkeypatch, make_config_entry):
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
async def test_async_remove_config_entry_device_branches(monkeypatch, hass):
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

    class ER:
        pass

    # fake registry that returns one entity with matching device_id
    ent = MagicMock()
    ent.device_id = "d2"
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: ER())
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: [ent]
    )
    res = await init_mod.async_remove_config_entry_device(hass, MagicMock(entry_id="x"), device)
    assert res is False


@pytest.mark.asyncio
async def test_async_remove_config_entry_device_no_linked_entities(monkeypatch):
    """When no linked entities exist for a device, removal should succeed (return True)."""
    # device not linked via via_device_id and has an id
    device = MagicMock()
    device.via_device_id = False
    device.id = "d3"

    # fake entity registry returns no entities for the config entry
    ER = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: ER)
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: []
    )

    # call the removal helper with a dummy config entry
    res = await init_mod.async_remove_config_entry_device(None, MagicMock(entry_id="x"), device)
    assert res is True


@pytest.mark.asyncio
async def test_async_unload_entry_and_pop(ph_hass, make_config_entry):
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
async def test_migrate_1_to_2_updates_entry(ph_hass):
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
async def test_async_migrate_entry_version_gt4(ph_hass):
    """async_migrate_entry returns False for versions greater than supported."""
    cfg = MagicMock()
    cfg.version = 5
    # should return False
    res = await init_mod.async_migrate_entry(ph_hass, cfg)
    assert res is False


@pytest.mark.asyncio
@pytest.mark.parametrize("version", [0, 4])
async def test_async_migrate_entry_does_not_call_migrate_3_to_4_when_version_not_3(
    monkeypatch, ph_hass, version
):
    """When entry.version is not 3, _migrate_3_to_4 must not be called."""
    mock_m3 = AsyncMock(return_value=True)
    monkeypatch.setattr(init_mod, "_migrate_3_to_4", mock_m3)

    cfg = MagicMock()
    cfg.version = version

    res = await init_mod.async_migrate_entry(ph_hass, cfg)

    # for versions not 3, migration should complete (unless version > 4 which we don't test)
    assert res is True
    mock_m3.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("should_raise", [False, True])
async def test_async_setup_calls_services_and_handles_exceptions(
    monkeypatch, ph_hass, should_raise
):
    """async_setup should call async_setup_services; exceptions should propagate."""
    if should_raise:
        mock_services = AsyncMock(side_effect=RuntimeError("fail"))
    else:
        mock_services = AsyncMock(return_value=None)

    monkeypatch.setattr(init_mod, "async_setup_services", mock_services)

    if should_raise:
        with pytest.raises(RuntimeError):
            await init_mod.async_setup(ph_hass, {})
        mock_services.assert_awaited_once()
    else:
        res = await init_mod.async_setup(ph_hass, {})
        assert res is True
        mock_services.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_update_listener_reload_and_remove(monkeypatch, ph_hass, make_config_entry):
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
        def __init__(self, entity_id, unique_id):
            self.entity_id = entity_id
            self.unique_id = unique_id

    # explicitly use the 'sync_telemetry' prefix so the test targets the intended sync item
    prefix = list(init_mod.GRANULAR_SYNC_PREFIX["sync_telemetry"])
    pre = prefix[0]
    ent = Ent("sensor.x", f"{entry.unique_id}_{pre}_suffix")

    # monkeypatch entity registry functions
    ER = MagicMock()
    ER.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: ER)
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: [ent]
    )
    # patch device registry to return no devices and provide async_remove_device
    DR = MagicMock()
    DR.async_remove_device = MagicMock()
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: DR)
    monkeypatch.setattr(
        init_mod.dr, "async_entries_for_config_entry", lambda registry, config_entry_id: []
    )

    # config option already provided via factory; no mutation needed

    # Ensure hass.async_create_task exists (ph_hass MagicMock fallback may not
    # provide it). Tests expect this to exist so they can assert it was called.
    if not hasattr(hass, "async_create_task"):
        hass.async_create_task = MagicMock()

    await init_mod._async_update_listener(hass, entry)

    # async_create_task should have been used to schedule reload
    assert hass.async_create_task.called

    # entity matched by prefix should be removed; no devices to remove
    ER.async_remove.assert_called_once_with(ent.entity_id)
    DR.async_remove_device.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "dt_enabled, via_device_id, expect_removed",
    [
        (False, True, True),
        (False, False, False),
        (True, True, False),
    ],
)
async def test_async_update_listener_device_removal_param(
    monkeypatch, ph_hass, make_config_entry, dt_enabled, via_device_id, expect_removed
):
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

    # ensure hass.async_create_task exists for scheduling reload
    if not hasattr(hass, "async_create_task"):
        hass.async_create_task = MagicMock()

    # prepare a single device entry returned by the device registry
    device = MagicMock()
    device.via_device_id = via_device_id
    device.id = "d_device"
    device.name = "devname"

    DR = MagicMock()
    DR.async_remove_device = MagicMock()
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: DR)
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
        DR.async_remove_device.assert_called_once_with(device.id)
    else:
        DR.async_remove_device.assert_not_called()


@pytest.mark.asyncio
async def test_async_setup_entry_firmware_below_min(
    monkeypatch, ph_hass, coordinator_capture, fake_client, fake_coordinator, make_config_entry
):
    """async_setup_entry returns False for devices with firmware below minimum supported."""
    # fake client where device id matches but firmware is below min
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client(firmware_version="1.0"))
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
    monkeypatch, ph_hass, coordinator_capture, fake_client, fake_coordinator, make_config_entry
):
    """async_setup_entry logs a warning issue for firmware between min and LTD but continues."""
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client(firmware_version="25.0"))
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
    expected_issue_id = f"opnsense_25.0_below_ltd_firmware_{init_mod.OPNSENSE_LTD_FIRMWARE}"
    assert call_args[0][2] == expected_issue_id
    assert call_args[1].get("severity") == init_mod.ir.IssueSeverity.WARNING


@pytest.mark.asyncio
async def test_async_setup_entry_firmware_triggers_plugin_cleanup(
    monkeypatch, ph_hass, coordinator_capture, fake_client, fake_coordinator, make_config_entry
):
    """async_setup_entry calls _deprecated_plugin_cleanup_26_1_1 for firmware >25.10 and <26.7."""
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client(firmware_version="26.2"))
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )
    # Mock the cleanup function to track if it's called
    cleanup_mock = AsyncMock(return_value=True)
    monkeypatch.setattr(init_mod, "_deprecated_plugin_cleanup_26_1_1", cleanup_mock)

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
    # Verify cleanup was called with correct args and awaited
    cleanup_mock.assert_awaited_once_with(hass=hass, client=ANY, entry_id=entry.entry_id)


@pytest.mark.asyncio
async def test_deprecated_plugin_cleanup_26_1_1_plugin_not_installed(monkeypatch):
    """_deprecated_plugin_cleanup_26_1_1 removes filter entities when plugin not installed."""
    hass = MagicMock(spec=HomeAssistant)
    client = MagicMock()
    client.is_plugin_installed = AsyncMock(return_value=False)
    entry_id = "test_entry_id"

    # Mock entity registry
    entity_registry = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)

    # Mock entities: one filter entity, one normal switch
    filter_entity = MagicMock()
    filter_entity.entity_id = "switch.opnsense_filter_rule"
    filter_entity.unique_id = "dev1_filter_rule1"
    normal_entity = MagicMock()
    normal_entity.entity_id = "switch.opnsense_normal_rule"
    normal_entity.unique_id = "dev1_normal_rule1"
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        MagicMock(return_value=[filter_entity, normal_entity]),
    )

    # Mock issue registry
    create_issue_mock = MagicMock()
    monkeypatch.setattr(init_mod.ir, "async_create_issue", create_issue_mock)

    await init_mod._deprecated_plugin_cleanup_26_1_1(hass, client, entry_id)

    # Verify filter entity was removed, normal was not
    entity_registry.async_remove.assert_called_once_with("switch.opnsense_filter_rule")
    # Verify issue created for cleanup done
    create_issue_mock.assert_called_once()
    call_args = create_issue_mock.call_args
    assert call_args[0][2] == "plugin_cleanup_done"


@pytest.mark.asyncio
async def test_deprecated_plugin_cleanup_26_1_1_plugin_installed(monkeypatch):
    """_deprecated_plugin_cleanup_26_1_1 removes NAT entities when plugin is installed."""
    hass = MagicMock(spec=HomeAssistant)
    client = MagicMock()
    client.is_plugin_installed = AsyncMock(return_value=True)
    entry_id = "test_entry_id"

    # Mock entity registry
    entity_registry = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)

    # Mock entities: NAT port forward, NAT outbound, normal switch
    nat_pf_entity = MagicMock()
    nat_pf_entity.entity_id = "switch.opnsense_nat_port_forward_rule"
    nat_pf_entity.unique_id = "dev1_nat_port_forward_rule1"
    nat_out_entity = MagicMock()
    nat_out_entity.entity_id = "switch.opnsense_nat_outbound_rule"
    nat_out_entity.unique_id = "dev1_nat_outbound_rule1"
    normal_entity = MagicMock()
    normal_entity.entity_id = "switch.opnsense_normal_rule"
    normal_entity.unique_id = "dev1_normal_rule1"
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        MagicMock(return_value=[nat_pf_entity, nat_out_entity, normal_entity]),
    )

    # Mock issue registry
    create_issue_mock = MagicMock()
    monkeypatch.setattr(init_mod.ir, "async_create_issue", create_issue_mock)

    await init_mod._deprecated_plugin_cleanup_26_1_1(hass, client, entry_id)

    # Verify NAT entities were removed, normal was not
    assert entity_registry.async_remove.call_count == 2
    entity_registry.async_remove.assert_any_call("switch.opnsense_nat_port_forward_rule")
    entity_registry.async_remove.assert_any_call("switch.opnsense_nat_outbound_rule")
    # Verify issue created for partial cleanup
    create_issue_mock.assert_called_once()
    call_args = create_issue_mock.call_args
    assert call_args[0][2] == "plugin_cleanup_partial"


@pytest.mark.asyncio
async def test_migrate_2_to_3_missing_device_id(monkeypatch, fake_client):
    """_migrate_2_to_3 returns False when the client provides no device id."""
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client(device_id=None))
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
    res = await init_mod._migrate_2_to_3(hass, cfg)
    assert res is False


@pytest.mark.asyncio
async def test_migrate_2_to_3_success(monkeypatch, fake_client):
    """_migrate_2_to_3 updates device and entity identifiers when client reports new device id."""
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client(device_id="newdev"))

    # fake device entries and entity entries
    dev = MagicMock()
    dev.id = "d1"
    dev.identifiers = {("opnsense", "old")}

    ent = MagicMock()
    ent.entity_id = "sensor.x"
    ent.unique_id = "old"
    ent.device_id = "d1"

    ER = MagicMock()
    ER.async_update_entity = MagicMock(
        return_value=MagicMock(entity_id=ent.entity_id, unique_id="new")
    )
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: ER)
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: [ent]
    )

    DR = MagicMock()
    DR.async_update_device = MagicMock(
        return_value=MagicMock(id=dev.id, identifiers={("opnsense", "newdev")})
    )
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: DR)
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
    res = await init_mod._migrate_2_to_3(hass, cfg)
    assert res is True
    assert DR.async_update_device.called, "device identifiers should be updated"
    assert ER.async_update_entity.called, "entity unique_ids should be updated"
    assert hass.config_entries.async_update_entry.called
    kwargs = hass.config_entries.async_update_entry.call_args.kwargs
    assert kwargs["version"] == 3
    assert kwargs["unique_id"] == "newdev"
    assert kwargs["data"][init_mod.CONF_DEVICE_UNIQUE_ID] == "newdev"


@pytest.mark.asyncio
async def test_async_setup_entry_awesomeversion_exception(
    monkeypatch, ph_hass, coordinator_capture, fake_client, fake_coordinator, make_config_entry
):
    """async_setup_entry should continue when AwesomeVersion comparison raises an exception."""

    # fake client where device id matches but awesomeversion comparison raises
    # monkeypatch AwesomeVersion to a class that raises on comparison
    class DummyAV:
        def __init__(self, v):
            self.v = v

        def __lt__(self, other):
            raise init_mod.awesomeversion.exceptions.AwesomeVersionCompareException

    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client())
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
async def test_async_unload_entry_unload_fails(ph_hass, make_config_entry):
    """async_unload_entry returns False and retains hass.data when platform unload fails."""
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
    fake_client.async_close.assert_awaited_once()


@pytest.mark.asyncio
async def test_migrate_3_to_4_filesystem_and_remove(monkeypatch, fake_client):
    """_migrate_3_to_4 handles filesystem telemetry renames and removes connected_client_count entities."""
    monkeypatch.setattr(
        init_mod,
        "OPNsenseClient",
        fake_client(telemetry={"filesystems": [{"device": "/dev/sda1", "mountpoint": "/"}]}),
    )

    # entities: one that maps telemetry_filesystems, one that is connected_client_count
    # make e1's unique_id include the processed device name so the migration will match
    e1 = MagicMock()
    e1.entity_id = "sensor.fs"
    e1.unique_id = "abc_telemetry_filesystems_slash_dev_slash_sda1"
    e2 = MagicMock()
    e2.entity_id = "sensor.clients"
    e2.unique_id = "something_connected_client_count"

    ER = MagicMock()
    ER.async_update_entity = MagicMock(
        return_value=MagicMock(entity_id=e1.entity_id, unique_id="updated")
    )
    ER.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: ER)
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
    res = await init_mod._migrate_3_to_4(hass, cfg)
    assert res is True
    # Ensure the connected_client_count entity was removed (called with entity_id)
    ER.async_remove.assert_called_once_with(e2.entity_id)
    # Ensure telemetry-mapped entity was updated with the expected new unique_id
    expected_new_unique_id = "abc_telemetry_filesystems_root"
    ER.async_update_entity.assert_called_once_with(
        e1.entity_id, new_unique_id=expected_new_unique_id
    )


@pytest.mark.asyncio
async def test_migrate_2_to_3_handles_entity_update_value_error(monkeypatch, fake_client):
    """When entity_registry.async_update_entity raises ValueError, migration continues."""
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client(device_id="newdev"))

    # single entity that will cause async_update_entity to raise
    ent = MagicMock()
    ent.entity_id = "sensor.x"
    ent.unique_id = "old"

    ER = MagicMock()
    ER.async_update_entity = MagicMock(side_effect=ValueError("bad entity"))
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: ER)
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

    res = await init_mod._migrate_2_to_3(hass, cfg)
    assert res is True
    # ensure we attempted to update the entity (which raised) and migration completed
    ER.async_update_entity.assert_called_once_with(ent.entity_id, new_unique_id=ANY)
    assert hass.config_entries.async_update_entry.called


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", [KeyError("k"), ValueError("v")])
async def test_migrate_3_to_4_handles_remove_exceptions(monkeypatch, fake_client, exc):
    """If entity_registry.async_remove raises KeyError/ValueError, migration continues."""
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client(telemetry={}))

    e = MagicMock()
    e.entity_id = "sensor.clients"
    e.unique_id = "something_connected_client_count"

    ER = MagicMock()
    ER.async_remove = MagicMock(side_effect=exc)
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: ER)
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

    res = await init_mod._migrate_3_to_4(hass, cfg)
    assert res is True
    ER.async_remove.assert_called_once_with(e.entity_id)


@pytest.mark.asyncio
async def test_migrate_3_to_4_handles_update_value_error(monkeypatch, fake_client):
    """If entity_registry.async_update_entity raises ValueError, migration continues."""
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client(telemetry={}))

    e = MagicMock()
    e.entity_id = "sensor.if"
    e.unique_id = "abc_telemetry_interface_eth0"

    ER = MagicMock()
    ER.async_update_entity = MagicMock(side_effect=ValueError("bad update"))
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: ER)
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

    res = await init_mod._migrate_3_to_4(hass, cfg)
    assert res is True
    ER.async_update_entity.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "version, failing_fn",
    [
        (1, "_migrate_1_to_2"),
        (2, "_migrate_2_to_3"),
        (3, "_migrate_3_to_4"),
    ],
)
async def test_async_migrate_entry_returns_false_when_submigration_fails(
    monkeypatch, ph_hass, version, failing_fn
):
    """async_migrate_entry should return False when a sub-migration returns False."""
    # make the targeted sub-migration return False
    monkeypatch.setattr(init_mod, failing_fn, AsyncMock(return_value=False))

    cfg = MagicMock()
    cfg.version = version

    # call with a real hass fixture
    res = await init_mod.async_migrate_entry(ph_hass, cfg)
    assert res is False


@pytest.mark.asyncio
async def test_async_setup_entry_firmware_above_ltd_calls_delete(
    monkeypatch, ph_hass, coordinator_capture, fake_client, fake_coordinator, make_config_entry
):
    """async_setup_entry deletes previous issues when firmware is at or above LTD."""
    monkeypatch.setattr(
        init_mod, "OPNsenseClient", fake_client(firmware_version=init_mod.OPNSENSE_LTD_FIRMWARE)
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
    monkeypatch, ph_hass, coordinator_capture, fake_client, fake_coordinator, make_config_entry
):
    """async_setup_entry cleans up previous firmware-related issues for LTD and min thresholds."""
    monkeypatch.setattr(
        init_mod, "OPNsenseClient", fake_client(firmware_version=init_mod.OPNSENSE_LTD_FIRMWARE)
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
    expected_min = f"opnsense_{init_mod.OPNSENSE_LTD_FIRMWARE}_below_min_firmware_{init_mod.OPNSENSE_MIN_FIRMWARE}"
    expected_ltd = f"opnsense_{init_mod.OPNSENSE_LTD_FIRMWARE}_below_ltd_firmware_{init_mod.OPNSENSE_LTD_FIRMWARE}"
    assert expected_min in called_issue_ids
    assert expected_ltd in called_issue_ids


@pytest.mark.asyncio
async def test_async_setup_entry_delete_uses_actual_firmware_string(
    monkeypatch, ph_hass, coordinator_capture, fake_client, fake_coordinator, make_config_entry
):
    """async_setup_entry uses the client's firmware string when deleting previous issues."""
    firmware_str = "99.9"
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client(firmware_version=firmware_str))
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

    # Confirm delete_issue was called with the firmware returned by the client
    expected_min = f"opnsense_{firmware_str}_below_min_firmware_{init_mod.OPNSENSE_MIN_FIRMWARE}"
    expected_ltd = f"opnsense_{firmware_str}_below_ltd_firmware_{init_mod.OPNSENSE_LTD_FIRMWARE}"
    assert calls.called, "async_delete_issue should have been called"
    issue_ids = [call[0][2] for call in calls.call_args_list if len(call[0]) > 2]
    assert expected_min in issue_ids
    assert expected_ltd in issue_ids


@pytest.mark.asyncio
async def test_async_setup_entry_delete_not_called_for_between_min_and_ltd(
    monkeypatch, ph_hass, coordinator_capture, fake_client, fake_coordinator, make_config_entry
):
    """async_setup_entry should not call delete_issue for firmware between min and LTD."""
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client(firmware_version="25.0"))
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
    monkeypatch, ph_hass, coordinator_capture, fake_client, fake_coordinator, make_config_entry
):
    """Device tracker option creates a device-tracker coordinator and triggers initial refresh."""
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client())
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
async def test_migrate_2_to_3_handles_identifier_collision(monkeypatch, fake_client):
    """_migrate_2_to_3 continues when DeviceIdentifierCollisionError occurs while updating devices."""
    # migration should continue if DeviceIdentifierCollisionError raised when updating device
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client(device_id="newdev"))

    # fake device that will cause collision when updating
    dev = MagicMock()
    dev.id = "d1"
    dev.identifiers = {("opnsense", "old")}

    class DR:
        def __init__(self):
            pass

        def async_update_device(self, *a, **k):
            # DeviceIdentifierCollisionError requires an existing_device argument
            raise init_mod.dr.DeviceIdentifierCollisionError("collision", MagicMock(id="other"))

    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: DR())
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

    res = await init_mod._migrate_2_to_3(hass, cfg)
    assert res is True
