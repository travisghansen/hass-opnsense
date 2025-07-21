from datetime import datetime
import importlib
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

# import the module under test and package constants
dt_mod = importlib.import_module("custom_components.opnsense.device_tracker")
pkg = importlib.import_module("custom_components.opnsense")


def make_config_entry(mac_list=None, tracked_macs=None, options=None):
    entry = SimpleNamespace()
    entry.data = {dt_mod.TRACKED_MACS: tracked_macs or [], pkg.CONF_DEVICE_UNIQUE_ID: "dev1"}
    entry.options = options or {}
    entry.runtime_data = SimpleNamespace()
    entry.title = "OPNsense"
    return entry


@pytest.mark.asyncio
async def test_async_setup_entry_configured_devices(monkeypatch, hass, coordinator):
    # prepare a coordinator with arp_table containing a matching mac
    coordinator.data = {
        "arp_table": [{"mac": "aa:bb:cc", "ip": "1.2.3.4", "hostname": "dev", "manufacturer": "m"}]
    }

    entry = make_config_entry(
        tracked_macs=[],
        options={dt_mod.CONF_DEVICES: ["aa:bb:cc"], dt_mod.CONF_DEVICE_TRACKER_ENABLED: True},
    )
    # attach coordinator into runtime_data under the expected attribute name
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)
    entry.entry_id = "eid"
    entry.add_update_listener = lambda f: (lambda: None)
    entry.async_on_unload = lambda x: None
    hass.config_entries.async_update_entry = MagicMock()
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    # fake device registry so removal code can be exercised safely
    class FakeReg:
        def async_get_device(self, *args, **kwargs):
            return None

        def async_remove_device(self, *args, **kwargs):
            return None

    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda hass: FakeReg())

    added = []

    def async_add_entities(ents):
        added.extend(ents)

    await dt_mod.async_setup_entry(hass, entry, async_add_entities)

    assert len(added) == 1
    # tracked macs should have been updated on the config entry
    assert hass.config_entries.async_update_entry.called


def test_handle_coordinator_update_unavailable(monkeypatch, coordinator):
    # coordinator with invalid data should mark entity unavailable
    coordinator.data = None
    entry = make_config_entry()
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )
    ent._attr_extra_state_attributes = {}
    ent.async_write_ha_state = MagicMock()

    ent._handle_coordinator_update()
    assert ent.available is False
    assert ent.async_write_ha_state.called


def test_handle_coordinator_update_entry_present(monkeypatch, coordinator):
    # coordinator has an arp entry that should populate attributes
    coordinator.data = {
        "arp_table": [
            {
                "mac": "aa:bb:cc",
                "ip": "1.2.3.4",
                "hostname": "host?",
                "manufacturer": "m",
                "intf_description": "lan0",
                "expires": -1,
                "type": "arp",
            }
        ],
        "update_time": float(int(datetime.now().timestamp())),
    }

    entry = make_config_entry()
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor="m",
        hostname="host?",
    )
    ent._attr_extra_state_attributes = {}
    ent.async_write_ha_state = MagicMock()

    ent._handle_coordinator_update()

    assert ent.ip_address == "1.2.3.4"
    # hostname should have stripped the trailing '?'
    assert ent.hostname == "host"
    assert ent.is_connected is True
    assert ent._attr_extra_state_attributes.get("expires") == "Never"
    assert ent._attr_extra_state_attributes.get("interface") == "lan0"
    assert ent._attr_extra_state_attributes.get("type") == "arp"
    assert ent._attr_icon == "mdi:lan-connect"


def test_handle_coordinator_update_missing_entry_consider_home(coordinator):
    # missing arp entry but recent last_known_connected_time and consider_home > 0
    coordinator.data = {"arp_table": []}
    entry = make_config_entry(options={dt_mod.CONF_DEVICE_TRACKER_CONSIDER_HOME: 3600})
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )
    ent._attr_extra_state_attributes = {}
    # set a recent last known connected time
    ent._last_known_connected_time = datetime.now().astimezone()
    ent.async_write_ha_state = MagicMock()

    ent._handle_coordinator_update()
    # elapsed < consider_home so device considered connected
    assert ent.is_connected is True


@pytest.mark.asyncio
async def test_restore_last_state_and_device_info(monkeypatch, coordinator):
    coordinator.data = {"arp_table": []}
    entry = make_config_entry()
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor="mfg",
        hostname="dev",
    )
    ent._attr_extra_state_attributes = {}

    # fake last state with attributes including isoformat time
    last_state = SimpleNamespace()
    last_state.attributes = {
        "last_known_hostname": "oldhost",
        "last_known_ip": "9.9.9.9",
        "interface": "lan0",
        "expires": 10,
        "type": "arp",
        "last_known_connected_time": datetime.now().isoformat(),
    }
    ent.async_get_last_state = AsyncMock(return_value=last_state)

    await ent._restore_last_state()
    # restored attributes should be present
    assert ent._last_known_hostname == "oldhost"
    assert ent._last_known_ip == "9.9.9.9"
    assert ent._attr_extra_state_attributes.get("interface") == "lan0"
    assert "last_known_connected_time" in ent._attr_extra_state_attributes

    # device_info should include the mac connection and via_device tuple
    devinfo = ent.device_info
    # support both DeviceInfo object and dict-shaped DeviceInfo used in tests
    if isinstance(devinfo, dict):
        connections = devinfo.get("connections", [])
        via = devinfo.get("via_device")
    else:
        connections = getattr(devinfo, "connections", [])
        via = getattr(devinfo, "via_device", None)

    assert any(t[1] == "aa:bb:cc" for t in connections)
    assert via[0] == dt_mod.DOMAIN


@pytest.mark.asyncio
async def test_async_added_to_hass_calls_restore(monkeypatch, coordinator):
    coordinator.data = {"arp_table": []}
    entry = make_config_entry()
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )

    # patch the restore method and the parent async_added_to_hass to avoid side effects
    ent._restore_last_state = AsyncMock()
    # patch the base class async_added_to_hass (no-op)
    base_mod = importlib.import_module("custom_components.opnsense.entity")
    monkeypatch.setattr(base_mod.OPNsenseBaseEntity, "async_added_to_hass", AsyncMock())

    await ent.async_added_to_hass()
    assert ent._restore_last_state.called


@pytest.mark.asyncio
async def test_async_setup_entry_state_not_mapping(hass, coordinator):
    # coordinator.data is not a mapping -> async_setup_entry should return early and not add entities
    coordinator.data = "not-a-mapping"
    entry = make_config_entry()
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)
    added = []

    hass.data = {}
    hass.config_entries.async_update_entry = MagicMock()

    await dt_mod.async_setup_entry(hass, entry, lambda x: added.extend(x))
    assert len(added) == 0
    assert not hass.config_entries.async_update_entry.called


@pytest.mark.asyncio
async def test_async_setup_entry_removes_previous_mac(monkeypatch, hass, coordinator):
    # previous tracked macs include an old mac that should be removed via device registry
    coordinator.data = {"arp_table": []}
    entry = make_config_entry(tracked_macs=["old:mac:1"])
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)
    entry.entry_id = "e_rm"
    hass.data = {}

    class FakeReg:
        def __init__(self):
            self.removed = False

        def async_get_device(self, *args, **kwargs):
            return SimpleNamespace(id="dev_to_remove")

        def async_remove_device(self, _id):
            self.removed = True

    fake = FakeReg()
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda hass: fake)

    hass.config_entries.async_update_entry = MagicMock()

    await dt_mod.async_setup_entry(hass, entry, lambda x: None)
    assert fake.removed is True
    assert hass.config_entries.async_update_entry.called


def test_handle_coordinator_update_expires_positive(coordinator):
    coordinator.data = {
        "arp_table": [
            {
                "mac": "aa:bb:cc",
                "ip": "1.2.3.4",
                "hostname": "hn",
                "intf_description": "lan",
                "expires": 30,
            }
        ],
        "update_time": float(int(datetime.now().timestamp())),
    }

    entry = make_config_entry()
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )
    ent._attr_extra_state_attributes = {}
    ent.async_write_ha_state = MagicMock()

    ent._handle_coordinator_update()
    assert isinstance(ent._attr_extra_state_attributes.get("expires"), datetime)


def test_handle_coordinator_update_ip_typeerror(coordinator):
    # entry ip is None which causes TypeError in len() -> should be handled
    coordinator.data = {"arp_table": [{"mac": "aa:bb:cc", "ip": None}]}

    entry = make_config_entry()
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )
    ent._attr_extra_state_attributes = {}
    ent.async_write_ha_state = MagicMock()

    ent._handle_coordinator_update()
    # no exception and ip_address is None
    assert ent.ip_address is None


def test_handle_coordinator_update_expired_preserve_last_known_ip(coordinator):
    # expired entry should set is_connected False and preserve last_known_ip
    # no ip in entry triggers branch where last_known_ip is preserved
    coordinator.data = {"arp_table": [{"mac": "aa:bb:cc", "expired": True}]}

    entry = make_config_entry()
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )
    ent._attr_extra_state_attributes = {}
    ent._last_known_ip = "1.2.3.4"
    ent.async_write_ha_state = MagicMock()

    ent._handle_coordinator_update()
    assert ent.is_connected is False
    assert ent._attr_extra_state_attributes.get("last_known_ip") == "1.2.3.4"


@pytest.mark.asyncio
async def test_async_setup_entry_from_arp_entries(monkeypatch, hass, coordinator):
    # when CONF_DEVICES not set but device tracker enabled, create entity per arp entry
    coordinator.data = {"arp_table": [{"mac": "m1"}, {"mac": "m2", "hostname": "h2"}]}
    entry = make_config_entry(options={dt_mod.CONF_DEVICE_TRACKER_ENABLED: True})
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)
    entry.entry_id = "eid2"
    hass.data = {}
    hass.config_entries.async_update_entry = MagicMock()

    added = []

    await dt_mod.async_setup_entry(hass, entry, lambda ents: added.extend(ents))
    assert len(added) == 2
