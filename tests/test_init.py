import importlib
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

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

    # Prefer setting via the real module object when available; fall back to
    # setting by import path string to be resilient in different test envs.
    # Patch the helper in the imported module; if it's missing (ImportError) use
    # monkeypatch.setattr with the import path string.
    try:
        monkeypatch.setattr(
            _hc, "async_create_clientsession", _fake_create_clientsession, raising=False
        )
    except ImportError:
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


@pytest.mark.asyncio
async def test_async_setup_entry_success(
    monkeypatch, ph_hass, coordinator_capture, fake_client, fake_coordinator
):
    # Use shared fake client and coordinator fixtures
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client())
    # use shared coordinator capture fixture
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    # create a minimal config entry
    entry = SimpleNamespace()
    entry.data = {
        init_mod.CONF_URL: "http://1.2.3.4",
        init_mod.CONF_USERNAME: "u",
        init_mod.CONF_PASSWORD: "p",
        init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
    }
    entry.options = {}
    entry.title = "Test"
    entry.entry_id = "entry1"
    entry.unique_id = "uid"
    # add_update_listener returns a remover
    entry.add_update_listener = lambda f: (lambda: None)
    entry.async_on_unload = lambda x: None

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
    monkeypatch, ph_hass, coordinator_capture, fake_client, fake_coordinator
):
    # use shared fake client that reports a different device id
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client(device_id="other"))
    # use shared coordinator capture fixture
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    entry = SimpleNamespace()
    entry.data = {
        init_mod.CONF_URL: "http://1.2.3.4",
        init_mod.CONF_USERNAME: "u",
        init_mod.CONF_PASSWORD: "p",
        init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
    }
    entry.options = {}
    entry.title = "Test"
    entry.entry_id = "entry2"
    entry.unique_id = "uid2"
    entry.add_update_listener = lambda f: (lambda: None)
    entry.async_on_unload = lambda x: None

    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()

    # should return False because router id mismatches and coordinator.shutdown called
    res = await init_mod.async_setup_entry(hass, entry)
    assert res is False

    # ensure coordinator shutdown was invoked
    assert any(getattr(inst, "shut", False) for inst in coordinator_capture.instances)


@pytest.mark.asyncio
async def test_async_update_listener_not_reload(monkeypatch):
    # set up entry with runtime_data SHOULD_RELOAD False
    entry = SimpleNamespace()
    entry.runtime_data = SimpleNamespace()
    setattr(entry.runtime_data, init_mod.SHOULD_RELOAD, False)
    entry.entry_id = "e"
    entry.unique_id = "u"

    # hass with config_entries.async_reload not called
    hass = SimpleNamespace()
    hass.config_entries = SimpleNamespace()
    hass.config_entries.async_reload = AsyncMock()

    # should set SHOULD_RELOAD back to True and not call reload
    await init_mod._async_update_listener(hass, entry)
    assert getattr(entry.runtime_data, init_mod.SHOULD_RELOAD) is True


@pytest.mark.asyncio
async def test_async_remove_config_entry_device_branches(monkeypatch):
    # device_entry.via_device_id True -> False
    device = SimpleNamespace(via_device_id=True, id="d1")
    res = await init_mod.async_remove_config_entry_device(None, None, device)
    assert res is False

    # device_entry with linked entity -> False
    device = SimpleNamespace(via_device_id=False, id="d2")

    class ER:
        pass

    # fake registry that returns one entity with matching device_id
    ent = SimpleNamespace(device_id="d2")
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: ER())
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: [ent]
    )
    res = await init_mod.async_remove_config_entry_device(
        None, SimpleNamespace(entry_id="x"), device
    )
    assert res is False


@pytest.mark.asyncio
async def test_async_unload_entry_and_pop(ph_hass):
    entry = SimpleNamespace()
    entry.as_dict = lambda: {"id": "x"}
    entry.runtime_data = SimpleNamespace()
    # use the constant names used by the integration
    setattr(entry.runtime_data, init_mod.LOADED_PLATFORMS, ["p1"])
    fake_client = SimpleNamespace(async_close=AsyncMock())
    setattr(entry.runtime_data, init_mod.OPNSENSE_CLIENT, fake_client)
    entry.entry_id = "e_unload"

    hass = ph_hass
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=True)
    hass.data = {init_mod.DOMAIN: {entry.entry_id: fake_client}}
    res = await init_mod.async_unload_entry(hass, entry)
    assert res is True
    assert entry.entry_id not in hass.data[init_mod.DOMAIN]
    fake_client.async_close.assert_awaited_once()


@pytest.mark.asyncio
async def test_migrate_1_to_2_updates_entry(ph_hass):
    cfg = SimpleNamespace()
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
    cfg2 = SimpleNamespace()
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
async def test_async_migrate_entry_version_gt4():
    cfg = SimpleNamespace()
    cfg.version = 5
    # should return False
    res = await init_mod.async_migrate_entry(None, cfg)
    assert res is False


def make_entry(data=None, options=None):
    e = SimpleNamespace()
    e.data = data or {
        init_mod.CONF_URL: "http://1.2.3.4",
        init_mod.CONF_USERNAME: "u",
        init_mod.CONF_PASSWORD: "p",
        init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
    }
    e.options = options or {}
    e.entry_id = "e1"
    e.unique_id = "uid"
    e.title = "Test"
    e.add_update_listener = lambda f: (lambda: None)
    e.async_on_unload = lambda x: None
    e.runtime_data = SimpleNamespace()
    return e


@pytest.mark.asyncio
async def test_async_update_listener_reload_and_remove(monkeypatch, ph_hass):
    # Prepare entry with SHOULD_RELOAD True and granular sync option disabled to force removal_prefixes
    entry = make_entry()
    setattr(entry.runtime_data, init_mod.SHOULD_RELOAD, True)
    entry.unique_id = "u123"
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
    ER = SimpleNamespace()
    ER.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: ER)
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: [ent]
    )
    # patch device registry to return no devices and provide async_remove_device
    DR = SimpleNamespace()
    DR.async_remove_device = MagicMock()
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: DR)
    monkeypatch.setattr(
        init_mod.dr, "async_entries_for_config_entry", lambda registry, config_entry_id: []
    )

    # set config option to disable the sync item so removal_prefixes includes prefix
    # the const name is 'sync_telemetry'
    entry.data["sync_telemetry"] = False

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
async def test_async_setup_entry_firmware_below_min(
    monkeypatch, ph_hass, coordinator_capture, fake_client, fake_coordinator
):
    # fake client where device id matches but firmware is below min
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client(firmware_version="1.0"))
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    entry = make_entry()
    # use hass fixture for aiohttp helpers
    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data.setdefault("aiohttp_connector", {})

    res = await init_mod.async_setup_entry(hass, entry)
    assert res is False


@pytest.mark.asyncio
async def test_async_setup_entry_firmware_between_min_and_ltd(
    monkeypatch, ph_hass, coordinator_capture, fake_client, fake_coordinator
):
    # fake client where firmware between min and ltd triggers a warning issue but continues
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client(firmware_version="25.0"))
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )
    # capture calls to the issue registry to assert a warning issue is created
    create_issue_mock = MagicMock()
    monkeypatch.setattr(init_mod.ir, "async_create_issue", create_issue_mock)

    entry = make_entry()
    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data.setdefault("aiohttp_connector", {})

    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True
    # verify the LTD deprecation/warning issue was created
    assert (
        create_issue_mock.called
    ), "async_create_issue should have been called for firmware between min and LTD"
    call_args = create_issue_mock.call_args
    # args: (hass, domain, issue_id, ...)
    assert call_args[0][1] == init_mod.DOMAIN
    expected_issue_id = f"opnsense_25.0_below_ltd_firmware_{init_mod.OPNSENSE_LTD_FIRMWARE}"
    assert call_args[0][2] == expected_issue_id
    assert call_args[1].get("severity") == init_mod.ir.IssueSeverity.WARNING


@pytest.mark.asyncio
async def test_migrate_2_to_3_missing_device_id(monkeypatch, fake_client):
    # migration should fail when client returns no device id
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client(device_id=None))
    cfg = SimpleNamespace()
    cfg.data = {
        init_mod.CONF_URL: "http://1.2.3.4",
        init_mod.CONF_USERNAME: "u",
        init_mod.CONF_PASSWORD: "p",
    }
    cfg.version = 2
    # set up hass fixture-like object for registry access
    hass = SimpleNamespace()
    hass.data = {}
    # avoid touching real entity/device registry and aiohttp helpers
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: SimpleNamespace())
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: SimpleNamespace())
    res = await init_mod._migrate_2_to_3(hass, cfg)
    assert res is False


@pytest.mark.asyncio
async def test_migrate_2_to_3_success(monkeypatch, fake_client):
    # migration updates entries when client reports a new device id
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client(device_id="newdev"))

    # fake device entries and entity entries
    dev = SimpleNamespace(id="d1", identifiers={("opnsense", "old")})
    ent = SimpleNamespace(entity_id="sensor.x", unique_id="old", device_id="d1")

    ER = SimpleNamespace()
    ER.async_update_entity = MagicMock(
        return_value=SimpleNamespace(entity_id=ent.entity_id, unique_id="new")
    )
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: ER)
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: [ent]
    )

    DR = SimpleNamespace()
    DR.async_update_device = MagicMock(
        return_value=SimpleNamespace(id=dev.id, identifiers={("opnsense", "newdev")})
    )
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: DR)
    monkeypatch.setattr(
        init_mod.dr, "async_entries_for_config_entry", lambda registry, config_entry_id: [dev]
    )

    cfg = SimpleNamespace()
    cfg.data = {
        init_mod.CONF_URL: "http://1.2.3.4",
        init_mod.CONF_USERNAME: "u",
        init_mod.CONF_PASSWORD: "p",
    }
    cfg.version = 2
    cfg.entry_id = "e"
    cfg.unique_id = "old_unique"

    hass = SimpleNamespace()
    hass.data = {}
    hass.config_entries = SimpleNamespace()
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
    monkeypatch, ph_hass, coordinator_capture, fake_client, fake_coordinator
):
    # fake client where device id matches but awesomeversion comparison raises
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
    entry = make_entry()
    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()

    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True


@pytest.mark.asyncio
async def test_async_unload_entry_unload_fails(ph_hass):
    entry = SimpleNamespace()
    entry.as_dict = lambda: {"id": "x"}
    entry.runtime_data = SimpleNamespace()
    setattr(entry.runtime_data, init_mod.LOADED_PLATFORMS, ["p1"])
    fake_client = SimpleNamespace(async_close=AsyncMock())
    setattr(entry.runtime_data, init_mod.OPNSENSE_CLIENT, fake_client)
    entry.entry_id = "e_unload_fail"

    hass = ph_hass
    # unload_platforms returns False
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=False)
    hass.data = {init_mod.DOMAIN: {entry.entry_id: fake_client}}
    res = await init_mod.async_unload_entry(hass, entry)
    assert res is False
    # hass.data should still have the entry
    assert entry.entry_id in hass.data[init_mod.DOMAIN]


@pytest.mark.asyncio
async def test_migrate_3_to_4_filesystem_and_remove(monkeypatch, fake_client):
    # migration 3->4 handles telemetry filesystems and connected_client_count removals
    monkeypatch.setattr(
        init_mod,
        "OPNsenseClient",
        fake_client(telemetry={"filesystems": [{"device": "/dev/sda1", "mountpoint": "/"}]}),
    )

    # entities: one that maps telemetry_filesystems, one that is connected_client_count
    # make e1's unique_id include the processed device name so the migration will match
    e1 = SimpleNamespace(
        entity_id="sensor.fs",
        unique_id="abc_telemetry_filesystems_slash_dev_slash_sda1",
    )
    e2 = SimpleNamespace(entity_id="sensor.clients", unique_id="something_connected_client_count")

    ER = SimpleNamespace()
    ER.async_update_entity = MagicMock(
        return_value=SimpleNamespace(entity_id=e1.entity_id, unique_id="updated")
    )
    ER.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: ER)
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: [e1, e2]
    )

    cfg = SimpleNamespace()
    cfg.data = {
        init_mod.CONF_URL: "http://1.2.3.4",
        init_mod.CONF_USERNAME: "u",
        init_mod.CONF_PASSWORD: "p",
    }
    cfg.version = 3
    cfg.entry_id = "e3"

    hass = SimpleNamespace()
    hass.data = {}
    hass.config_entries = SimpleNamespace()
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
async def test_async_setup_entry_firmware_above_ltd_calls_delete(
    monkeypatch, ph_hass, coordinator_capture, fake_client, fake_coordinator
):
    # fake client where device id matches and firmware is >= LTD
    monkeypatch.setattr(
        init_mod, "OPNsenseClient", fake_client(firmware_version=init_mod.OPNSENSE_LTD_FIRMWARE)
    )
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )
    called = []
    monkeypatch.setattr(init_mod.ir, "async_delete_issue", lambda *a, **k: called.append(True))

    entry = make_entry()
    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = MagicMock()
    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True
    assert called, "async_delete_issue should have been called for firmware >= LTD"


@pytest.mark.asyncio
async def test_async_setup_entry_firmware_at_or_above_ltd_deletes_previous_issues(
    monkeypatch, ph_hass, coordinator_capture, fake_client, fake_coordinator
):
    # fake client where device id matches and firmware is >= LTD
    monkeypatch.setattr(
        init_mod, "OPNsenseClient", fake_client(firmware_version=init_mod.OPNSENSE_LTD_FIRMWARE)
    )
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    # capture delete_issue calls
    delete_issue_mock = MagicMock()
    monkeypatch.setattr(init_mod.ir, "async_delete_issue", delete_issue_mock)

    entry = make_entry()
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
    monkeypatch, ph_hass, coordinator_capture, fake_client, fake_coordinator
):
    # Use a firmware string that differs from the LTD constant to ensure
    # the delete path uses the returned firmware in the issue id.
    firmware_str = "99.9"
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client(firmware_version=firmware_str))
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    calls = MagicMock()
    monkeypatch.setattr(init_mod.ir, "async_delete_issue", calls)

    entry = make_entry()
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
    monkeypatch, ph_hass, coordinator_capture, fake_client, fake_coordinator
):
    # firmware between min and ltd should create a warning issue but not call delete
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client(firmware_version="25.0"))
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    delete_issue_mock = MagicMock()
    monkeypatch.setattr(init_mod.ir, "async_delete_issue", delete_issue_mock)

    entry = make_entry()
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
    monkeypatch, ph_hass, coordinator_capture, fake_client, fake_coordinator
):
    # ensure device tracker coordinator is created and initial refresh is called
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client())
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    entry = make_entry()
    # enable device tracker option
    entry.options = {init_mod.CONF_DEVICE_TRACKER_ENABLED: True}

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
    # migration should continue if DeviceIdentifierCollisionError raised when updating device
    monkeypatch.setattr(init_mod, "OPNsenseClient", fake_client(device_id="newdev"))

    # fake device that will cause collision when updating
    dev = SimpleNamespace(id="d1", identifiers={("opnsense", "old")})

    class DR:
        def __init__(self):
            pass

        def async_update_device(self, *a, **k):
            # DeviceIdentifierCollisionError requires an existing_device argument
            raise init_mod.dr.DeviceIdentifierCollisionError(
                "collision", SimpleNamespace(id="other")
            )

    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: DR())
    monkeypatch.setattr(
        init_mod.dr, "async_entries_for_config_entry", lambda registry, config_entry_id: [dev]
    )
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: SimpleNamespace())
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: []
    )
    cfg = SimpleNamespace()
    cfg.data = {
        init_mod.CONF_URL: "http://1.2.3.4",
        init_mod.CONF_USERNAME: "u",
        init_mod.CONF_PASSWORD: "p",
    }
    cfg.version = 2
    cfg.entry_id = "e"
    cfg.unique_id = "old_unique"

    hass = SimpleNamespace()
    hass.data = {}
    hass.config_entries = SimpleNamespace()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    res = await init_mod._migrate_2_to_3(hass, cfg)
    assert res is True
