import importlib
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

# import the package module object so we can access its functions/attrs
init_mod = importlib.import_module("custom_components.opnsense")


@pytest.mark.asyncio
async def test_async_setup_entry_success(monkeypatch, hass):
    # Fake client with required async methods
    class FakeClient:
        def __init__(self, **kwargs):
            self.name = kwargs.get("name", "fake")

        async def get_device_unique_id(self):
            return "dev1"

        async def get_host_firmware_version(self):
            return "99.0"

        async def async_close(self):
            return True

    # Fake coordinator class
    class FakeCoordinator:
        def __init__(self, **kwargs):
            pass

        async def async_config_entry_first_refresh(self):
            return True

        async def async_shutdown(self):
            return True

    monkeypatch.setattr(init_mod, "OPNsenseClient", FakeClient)
    monkeypatch.setattr(init_mod, "OPNsenseDataUpdateCoordinator", FakeCoordinator)

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

    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()

    # ensure hass.data is a real dict for the integration to populate
    hass.data = {}

    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True
    assert init_mod.DOMAIN in hass.data and entry.entry_id in hass.data[init_mod.DOMAIN]


@pytest.mark.asyncio
async def test_async_setup_entry_device_id_mismatch(monkeypatch, hass):
    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def get_device_unique_id(self):
            return "other"

        async def get_host_firmware_version(self):
            return "99.0"

        async def async_close(self):
            return True

    class FakeCoordinator:
        def __init__(self, **kwargs):
            pass

        async def async_config_entry_first_refresh(self):
            return True

        async def async_shutdown(self):
            self.shut = True
            return True

    monkeypatch.setattr(init_mod, "OPNsenseClient", FakeClient)
    monkeypatch.setattr(init_mod, "OPNsenseDataUpdateCoordinator", FakeCoordinator)

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

    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()

    # should return False because router id mismatches and coordinator.shutdown called
    res = await init_mod.async_setup_entry(hass, entry)
    assert res is False


def test_async_update_listener_not_reload(monkeypatch):
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
    asyncio_run = pytest.importorskip("asyncio").get_event_loop().run_until_complete
    asyncio_run(init_mod._async_update_listener(hass, entry))
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
async def test_async_unload_entry_and_pop(hass):
    entry = SimpleNamespace()
    entry.as_dict = lambda: {"id": "x"}
    entry.runtime_data = SimpleNamespace()
    # use the constant names used by the integration
    setattr(entry.runtime_data, init_mod.LOADED_PLATFORMS, ["p1"])
    fake_client = SimpleNamespace(async_close=AsyncMock())
    setattr(entry.runtime_data, init_mod.OPNSENSE_CLIENT, fake_client)
    entry.entry_id = "e_unload"

    hass.config_entries.async_unload_platforms = AsyncMock(return_value=True)
    hass.data = {init_mod.DOMAIN: {entry.entry_id: fake_client}}
    res = await init_mod.async_unload_entry(hass, entry)
    assert res is True
    assert entry.entry_id not in hass.data[init_mod.DOMAIN]


@pytest.mark.asyncio
async def test_migrate_1_to_2_updates_entry(hass):
    cfg = SimpleNamespace()
    cfg.data = {init_mod.CONF_TLS_INSECURE: True}
    # ensure verify_ssl missing
    cfg.version = 1
    # mock async_update_entry
    hass.config_entries.async_update_entry = MagicMock(return_value=True)
    res = await init_mod._migrate_1_to_2(hass, cfg)
    assert res is True


def test_async_migrate_entry_version_gt4():
    cfg = SimpleNamespace()
    cfg.version = 5
    # should return False
    res = (
        pytest.importorskip("asyncio")
        .get_event_loop()
        .run_until_complete(init_mod.async_migrate_entry(None, cfg))
    )
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


def test_async_update_listener_reload_and_remove(monkeypatch, hass):
    # Prepare entry with SHOULD_RELOAD True and granular sync option disabled to force removal_prefixes
    entry = make_entry()
    setattr(entry.runtime_data, init_mod.SHOULD_RELOAD, True)
    entry.unique_id = "u123"
    # config entries and hass async reload stub
    # use hass fixture which provides config_entries and async helpers
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    # construct an entity that should be removed by unique_id prefix
    class Ent:
        def __init__(self, entity_id, unique_id):
            self.entity_id = entity_id
            self.unique_id = unique_id

    # pick a prefix from GRANULAR_SYNC_PREFIX values
    any_prefix = list(next(iter(init_mod.GRANULAR_SYNC_PREFIX.values())))
    pre = any_prefix[0]
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

    # run the listener
    asyncio_run = pytest.importorskip("asyncio").get_event_loop().run_until_complete
    asyncio_run(init_mod._async_update_listener(hass, entry))

    # async_create_task should have been used to schedule reload
    assert hass.async_create_task.called


@pytest.mark.asyncio
async def test_async_setup_entry_firmware_below_min(monkeypatch, hass):
    # fake client where device id matches but firmware is below min
    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def get_device_unique_id(self):
            return "dev1"

        async def get_host_firmware_version(self):
            return "1.0"

        async def async_close(self):
            return True

    class FakeCoordinator:
        def __init__(self, **kwargs):
            pass

        async def async_config_entry_first_refresh(self):
            return True

        async def async_shutdown(self):
            return True

    monkeypatch.setattr(init_mod, "OPNsenseClient", lambda **kwargs: FakeClient())
    monkeypatch.setattr(init_mod, "OPNsenseDataUpdateCoordinator", FakeCoordinator)

    entry = make_entry()
    # use hass fixture for aiohttp helpers
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data.setdefault("aiohttp_connector", {})

    # avoid creating real aiohttp connectors; provide dummy session
    monkeypatch.setattr(init_mod, "async_create_clientsession", lambda **kwargs: object())
    res = await init_mod.async_setup_entry(hass, entry)
    assert res is False


@pytest.mark.asyncio
async def test_async_setup_entry_firmware_between_min_and_ltd(monkeypatch, hass):
    # fake client where firmware between min and ltd triggers a warning issue but continues
    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def get_device_unique_id(self):
            return "dev1"

        async def get_host_firmware_version(self):
            # choose version between OPNSENSE_MIN_FIRMWARE and OPNSENSE_LTD_FIRMWARE
            return "25.0"

        async def async_close(self):
            return True

    class FakeCoordinator:
        def __init__(self, **kwargs):
            pass

        async def async_config_entry_first_refresh(self):
            return True

        async def async_shutdown(self):
            return True

    monkeypatch.setattr(init_mod, "OPNsenseClient", lambda **kwargs: FakeClient())
    monkeypatch.setattr(init_mod, "OPNsenseDataUpdateCoordinator", FakeCoordinator)

    entry = make_entry()
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data.setdefault("aiohttp_connector", {})

    monkeypatch.setattr(init_mod, "async_create_clientsession", lambda **kwargs: object())
    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True


@pytest.mark.asyncio
async def test_migrate_2_to_3_missing_device_id(monkeypatch):
    # migration should fail when client returns no device id
    class FakeClient:
        async def get_device_unique_id(self):
            return None

    monkeypatch.setattr(init_mod, "OPNsenseClient", lambda **kwargs: FakeClient())
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
    monkeypatch.setattr(init_mod, "async_create_clientsession", lambda **kwargs: object())
    res = await init_mod._migrate_2_to_3(hass, cfg)
    assert res is False


@pytest.mark.asyncio
async def test_migrate_2_to_3_success(monkeypatch):
    # migration updates entries when device id present
    class FakeClient:
        async def get_device_unique_id(self):
            return "newdev"

    monkeypatch.setattr(init_mod, "OPNsenseClient", lambda **kwargs: FakeClient())

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
    # avoid creating aiohttp connectors during migration
    monkeypatch.setattr(init_mod, "async_create_clientsession", lambda **kwargs: object())

    res = await init_mod._migrate_2_to_3(hass, cfg)
    assert res is True


@pytest.mark.asyncio
async def test_async_setup_entry_awesomeversion_exception(monkeypatch, hass):
    # fake client where device id matches but awesomeversion comparison raises
    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def get_device_unique_id(self):
            return "dev1"

        async def get_host_firmware_version(self):
            return "weird"

        async def async_close(self):
            return True

    class FakeCoordinator:
        def __init__(self, **kwargs):
            pass

        async def async_config_entry_first_refresh(self):
            return True

        async def async_shutdown(self):
            return True

    # monkeypatch AwesomeVersion to a class that raises on comparison
    class DummyAV:
        def __init__(self, v):
            self.v = v

        def __lt__(self, other):
            raise init_mod.awesomeversion.exceptions.AwesomeVersionCompareException

    monkeypatch.setattr(init_mod, "OPNsenseClient", lambda **kwargs: FakeClient())
    monkeypatch.setattr(init_mod, "OPNsenseDataUpdateCoordinator", FakeCoordinator)
    monkeypatch.setattr(init_mod.awesomeversion, "AwesomeVersion", DummyAV)
    monkeypatch.setattr(init_mod, "async_create_clientsession", lambda **kwargs: object())

    entry = make_entry()
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()

    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True


@pytest.mark.asyncio
async def test_async_unload_entry_unload_fails(hass):
    entry = SimpleNamespace()
    entry.as_dict = lambda: {"id": "x"}
    entry.runtime_data = SimpleNamespace()
    setattr(entry.runtime_data, init_mod.LOADED_PLATFORMS, ["p1"])
    fake_client = SimpleNamespace(async_close=AsyncMock())
    setattr(entry.runtime_data, init_mod.OPNSENSE_CLIENT, fake_client)
    entry.entry_id = "e_unload_fail"

    # unload_platforms returns False
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=False)
    hass.data = {init_mod.DOMAIN: {entry.entry_id: fake_client}}
    res = await init_mod.async_unload_entry(hass, entry)
    assert res is False
    # hass.data should still have the entry
    assert entry.entry_id in hass.data[init_mod.DOMAIN]


@pytest.mark.asyncio
async def test_migrate_3_to_4_filesystem_and_remove(monkeypatch):
    # migration 3->4 handles telemetry filesystems and connected_client_count removals
    class FakeClient:
        async def get_telemetry(self):
            return {"filesystems": [{"device": "/dev/sda1", "mountpoint": "/"}]}

    monkeypatch.setattr(init_mod, "OPNsenseClient", lambda **kwargs: FakeClient())

    # entities: one that maps telemetry_filesystems, one that is connected_client_count
    e1 = SimpleNamespace(entity_id="sensor.fs", unique_id="abc_telemetry_filesystems_sda1")
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
    monkeypatch.setattr(init_mod, "async_create_clientsession", lambda **kwargs: object())

    res = await init_mod._migrate_3_to_4(hass, cfg)
    assert res is True


@pytest.mark.asyncio
async def test_async_setup_entry_firmware_above_ltd_calls_delete(monkeypatch, hass):
    # fake client where device id matches and firmware is >= LTD
    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def get_device_unique_id(self):
            return "dev1"

        async def get_host_firmware_version(self):
            return init_mod.OPNSENSE_LTD_FIRMWARE

        async def async_close(self):
            return True

    class FakeCoordinator:
        def __init__(self, **kwargs):
            pass

        async def async_config_entry_first_refresh(self):
            return True

        async def async_shutdown(self):
            return True

    # track delete_issue calls
    monkeypatch.setattr(init_mod, "OPNsenseClient", lambda **kwargs: FakeClient())
    monkeypatch.setattr(init_mod, "OPNsenseDataUpdateCoordinator", FakeCoordinator)
    called = []
    monkeypatch.setattr(init_mod.ir, "async_delete_issue", lambda *a, **k: called.append(True))

    entry = make_entry()
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = MagicMock()
    monkeypatch.setattr(init_mod, "async_create_clientsession", lambda **kwargs: object())

    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True
    assert called, "async_delete_issue should have been called for firmware >= LTD"


@pytest.mark.asyncio
async def test_async_setup_entry_with_device_tracker_enabled(monkeypatch, hass):
    # ensure device tracker coordinator is created and initial refresh is called
    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def get_device_unique_id(self):
            return "dev1"

        async def get_host_firmware_version(self):
            return "99.0"

        async def async_close(self):
            return True

    class FakeCoordinator:
        def __init__(self, **kwargs):
            # expose whether this was instantiated for device_tracker
            self._is_device_tracker = kwargs.get("device_tracker_coordinator", False)

        async def async_config_entry_first_refresh(self):
            # mark that initial refresh happened
            self.refreshed = True
            return True

        async def async_shutdown(self):
            return True

    monkeypatch.setattr(init_mod, "OPNsenseClient", lambda **kwargs: FakeClient())
    monkeypatch.setattr(init_mod, "OPNsenseDataUpdateCoordinator", FakeCoordinator)

    entry = make_entry()
    # enable device tracker option
    entry.options = {init_mod.CONF_DEVICE_TRACKER_ENABLED: True}

    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = MagicMock()
    monkeypatch.setattr(init_mod, "async_create_clientsession", lambda **kwargs: object())

    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True


@pytest.mark.asyncio
async def test_migrate_2_to_3_handles_identifier_collision(monkeypatch):
    # migration should continue if DeviceIdentifierCollisionError raised when updating device
    class FakeClient:
        async def get_device_unique_id(self):
            return "newdev"

    monkeypatch.setattr(init_mod, "OPNsenseClient", lambda **kwargs: FakeClient())

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
    monkeypatch.setattr(init_mod, "async_create_clientsession", lambda **kwargs: object())

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
