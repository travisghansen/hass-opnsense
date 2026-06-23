"""Unit tests for the device_tracker component of the hass-opnsense integration.

These tests cover setup, coordinator update handling, restore state behavior,
and device info formatting for the integration's device tracker entities.
"""

from collections.abc import Callable, Iterable, MutableMapping
from datetime import UTC, datetime
import importlib
from types import MappingProxyType
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

# import the module under test and package constants
dt_mod = importlib.import_module("custom_components.opnsense.device_tracker")
pkg = importlib.import_module("custom_components.opnsense")


def test_device_from_arp_entry_skips_malformed_and_nonmatching_entries() -> None:
    """Device lookup should ignore malformed and nonmatching ARP entries."""
    device = dt_mod._device_from_arp_entry(
        "aa:bb:cc",
        [
            object(),
            {"mac": "dd:ee:ff", "hostname": "other"},
            {"mac": "aa:bb:cc", "hostname": "tracked", "manufacturer": "maker"},
        ],
    )

    assert device == {"mac": "aa:bb:cc", "hostname": "tracked", "manufacturer": "maker"}


def test_device_from_arp_entry_returns_mac_fallback_without_entries() -> None:
    """Device lookup should return a MAC-only fallback when no ARP entries exist."""
    assert dt_mod._device_from_arp_entry("aa:bb:cc", []) == {"mac": "aa:bb:cc"}


def test_devices_from_arp_entries_skips_malformed_invalid_and_duplicate_macs() -> None:
    """ARP conversion should only return devices for unique valid MAC strings."""
    devices, mac_addresses = dt_mod._devices_from_arp_entries(
        [
            object(),
            {"mac": None},
            {"mac": ""},
            {"mac": "aa:bb:cc", "hostname": "tracked"},
            {"mac": "aa:bb:cc", "hostname": "duplicate"},
        ],
    )

    assert mac_addresses == ["aa:bb:cc"]
    assert devices == [{"mac": "aa:bb:cc", "hostname": "tracked"}]


@pytest.mark.asyncio
async def test_async_setup_entry_configured_devices(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """Setup creates device tracker entities for configured MACs."""
    coordinator.data = {
        "arp_table": [{"mac": "aa:bb:cc", "ip": "1.2.3.4", "hostname": "dev", "manufacturer": "m"}]
    }

    entry = make_config_entry(
        data={dt_mod.TRACKED_MACS: [], pkg.CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={dt_mod.CONF_DEVICES: ["aa:bb:cc"], dt_mod.CONF_DEVICE_TRACKER_ENABLED: True},
        entry_id="eid",
    )
    # attach coordinator into runtime_data under the expected attribute name
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)
    entry.add_update_listener = lambda f: lambda: None
    entry.async_on_unload = lambda x: None
    hass = ph_hass
    hass.config_entries.async_update_entry = MagicMock()
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    # use shared fake registry fixture: device does not exist
    fake = fake_reg_factory(device_exists=False)
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda hass: fake, raising=False)

    added: list[Any] = []

    def async_add_entities(ents: Iterable[Any], _update_before_add: bool = False) -> None:
        """Async add entities.

        Args:
            ents: Ents provided by pytest or the test case.
        """
        added.extend(ents)

    await dt_mod.async_setup_entry(hass, entry, async_add_entities)

    assert len(added) == 1
    # the created entity should be the integration's device tracker entity and have a unique_id
    created = added[0]
    assert isinstance(created, dt_mod.OPNsenseScannerEntity)
    # make_config_entry sets the device unique id to a suffix like "mac_<normalized_mac>".
    # slugify should normalize ':' to '_' -> unique_id should end with 'mac_aa_bb_cc'
    uid = getattr(created, "unique_id", None)
    assert uid is not None
    assert uid.startswith("dev1_")
    assert uid.endswith("mac_aa_bb_cc")
    # ensure the normalized MAC components are present in the unique_id
    assert "aa_bb_cc" in uid
    # ensure the MAC is available on the entity (or included in unique_id) and was normalized
    assert created.mac_address == "aa:bb:cc"
    # tracked macs should have been updated on the config entry
    assert hass.config_entries.async_update_entry.called
    # Inspect the update payload to ensure tracked MACs were persisted
    call = hass.config_entries.async_update_entry.call_args
    args = call.args
    kwargs = call.kwargs
    # HA calls async_update_entry(positionally): (entry, data)
    target_entry = args[0]
    updated_data = kwargs.get("data", args[1] if len(args) > 1 else None)

    assert target_entry is entry
    assert updated_data.get(dt_mod.TRACKED_MACS) == ["aa:bb:cc"]


@pytest.mark.asyncio
async def test_async_setup_entry_removes_nonmatching_tracked_macs(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """Ensure previously-tracked MACs not present in current devices are removed."""
    # coordinator reports only one arp entry
    coordinator.data = {
        "arp_table": [{"mac": "aa:bb:cc", "ip": "1.2.3.4", "hostname": "dev", "manufacturer": "m"}]
    }

    # entry previously tracked an extra MAC that is no longer present
    entry = make_config_entry(
        data={dt_mod.TRACKED_MACS: ["aa:bb:cc", "ff:ee:dd"], pkg.CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={dt_mod.CONF_DEVICES: ["aa:bb:cc"], dt_mod.CONF_DEVICE_TRACKER_ENABLED: True},
        entry_id="eid_remove",
    )
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)
    entry.add_update_listener = lambda f: lambda: None
    entry.async_on_unload = lambda x: None

    hass = ph_hass
    hass.config_entries.async_update_entry = MagicMock()
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    fake = fake_reg_factory(device_exists=True, device_id="removed-device-id")
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda hass: fake, raising=False)

    added: list[Any] = []

    def async_add_entities(ents: Iterable[Any], _update_before_add: bool = False) -> None:
        """Async add entities.

        Args:
            ents: Ents provided by pytest or the test case.
        """
        added.extend(ents)

    await dt_mod.async_setup_entry(hass, entry, async_add_entities)

    # ensure an update was persisted and the stale MAC was removed
    assert hass.config_entries.async_update_entry.called
    call = hass.config_entries.async_update_entry.call_args
    args = call.args
    kwargs = call.kwargs
    updated_data = kwargs.get("data", args[1] if len(args) > 1 else None)

    assert updated_data is not None
    # The stale MAC should no longer be present
    assert "ff:ee:dd" not in updated_data.get(dt_mod.TRACKED_MACS, [])
    # The expected remaining MAC should still be present
    assert "aa:bb:cc" in updated_data.get(dt_mod.TRACKED_MACS, [])


def test_handle_coordinator_update_unavailable(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Coordinator with invalid data should mark entity unavailable."""
    coordinator.data = None
    entry = make_config_entry(data={pkg.CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )
    object.__setattr__(ent, "async_write_ha_state", MagicMock())

    ent._handle_coordinator_update()
    assert ent.available is False
    assert ent.async_write_ha_state.called


def test_handle_coordinator_update_entry_present(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Coordinator arp entry populates entity attributes correctly."""
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
        "update_time": float(int(datetime.now(UTC).timestamp())),
    }

    entry = make_config_entry(data={pkg.CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor="m",
        hostname="host?",
    )
    object.__setattr__(ent, "async_write_ha_state", MagicMock())

    ent._handle_coordinator_update()

    assert ent.ip_address == "1.2.3.4"
    # hostname should have stripped the trailing '?'
    assert ent.hostname == "host"
    assert ent.is_connected is True
    assert ent.extra_state_attributes.get("expires") == "Never"
    assert ent.extra_state_attributes.get("interface") == "lan0"
    assert ent.extra_state_attributes.get("type") == "arp"
    assert ent.icon == "mdi:lan-connect"


def test_handle_coordinator_update_skips_malformed_arp_entries(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Malformed ARP entries should be skipped while searching for the tracked MAC."""
    coordinator.data = {"arp_table": [object()]}
    entry = make_config_entry(data={pkg.CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )
    object.__setattr__(ent, "async_write_ha_state", MagicMock())

    ent._handle_coordinator_update()

    assert ent.is_connected is False
    assert ent.available is True


def test_handle_coordinator_update_missing_entry_consider_home(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """If missing entry and within consider_home, entity remains connected."""
    coordinator.data = {"arp_table": []}
    entry = make_config_entry(
        data={pkg.CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={dt_mod.CONF_DEVICE_TRACKER_CONSIDER_HOME: 3600},
    )
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )
    # set a recent last known connected time
    ent._last_known_connected_time = datetime.now(UTC).astimezone()
    object.__setattr__(ent, "async_write_ha_state", MagicMock())

    ent._handle_coordinator_update()
    # elapsed < consider_home so device considered connected
    assert ent.is_connected is True


@pytest.mark.asyncio
async def test_restore_last_state_and_device_info(
    monkeypatch: pytest.MonkeyPatch,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Restoring last state merges saved attributes into the entity."""
    coordinator.data = {"arp_table": []}
    entry = make_config_entry(data={pkg.CONF_DEVICE_UNIQUE_ID: "dev1"})
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
    last_known_connected_time = datetime.now(UTC)

    # fake last state with attributes including isoformat time
    last_state = MagicMock()
    last_state.attributes = MappingProxyType(
        {
            "last_known_hostname": "oldhost",
            "last_known_ip": "9.9.9.9",
            "interface": "lan0",
            "expires": 10,
            "type": "arp",
            "last_known_connected_time": last_known_connected_time.isoformat(),
        },
    )
    ent.async_get_last_state = AsyncMock(return_value=last_state)

    await ent._restore_last_state()
    # restored attributes should be present
    assert ent._last_known_hostname == "oldhost"
    assert ent._last_known_ip == "9.9.9.9"
    assert ent._last_known_connected_time == last_known_connected_time
    assert ent.extra_state_attributes.get("interface") == "lan0"
    assert "last_known_connected_time" in ent.extra_state_attributes

    # device_info should include the mac connection and via_device tuple
    devinfo = ent.device_info
    # support both DeviceInfo object and dict-shaped DeviceInfo used in tests
    if isinstance(devinfo, MutableMapping):
        connections = devinfo.get("connections", [])
        via = devinfo.get("via_device")
    else:
        connections = getattr(devinfo, "connections", [])
        via = getattr(devinfo, "via_device", None)

    assert any(t[1] == "aa:bb:cc" for t in connections)
    assert via is not None
    assert via[0] == dt_mod.DOMAIN
    assert via[1] == entry.data[pkg.CONF_DEVICE_UNIQUE_ID]


@pytest.mark.asyncio
async def test_restore_last_state_uses_datetime_and_skips_empty_attributes(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Restoring state should preserve datetime values and ignore empty saved attributes."""
    coordinator.data = {"arp_table": []}
    entry = make_config_entry(data={pkg.CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)
    last_known_connected_time = datetime.now(UTC)

    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )
    last_state = MagicMock()
    last_state.attributes = {
        "last_known_hostname": None,
        "last_known_ip": None,
        "interface": "",
        "expires": None,
        "type": "",
        "last_known_connected_time": last_known_connected_time,
    }
    ent.async_get_last_state = AsyncMock(return_value=last_state)

    await ent._restore_last_state()

    assert ent._last_known_connected_time == last_known_connected_time
    assert ent.extra_state_attributes == {"last_known_connected_time": last_known_connected_time}


@pytest.mark.asyncio
async def test_restore_last_state_ignores_unparseable_connected_time(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Restoring state should ignore invalid saved connection timestamps."""
    coordinator.data = {"arp_table": []}
    entry = make_config_entry(data={pkg.CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )
    last_state = MagicMock()
    last_state.attributes = {"last_known_connected_time": "not-a-date"}
    ent.async_get_last_state = AsyncMock(return_value=last_state)

    await ent._restore_last_state()

    assert ent._last_known_connected_time is None
    assert "last_known_connected_time" not in ent.extra_state_attributes


@pytest.mark.asyncio
async def test_restore_last_state_ignores_non_mapping_attributes(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Restoring state should ignore snapshots with malformed attributes."""
    coordinator.data = {"arp_table": []}
    entry = make_config_entry(data={pkg.CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )
    last_state = MagicMock()
    last_state.attributes = ["not", "a", "mapping"]
    ent.async_get_last_state = AsyncMock(return_value=last_state)

    await ent._restore_last_state()

    assert ent.extra_state_attributes == {}


@pytest.mark.asyncio
async def test_async_added_to_hass_calls_restore(
    monkeypatch: pytest.MonkeyPatch,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Entity.async_added_to_hass should call state restoration."""
    coordinator.data = {"arp_table": []}
    entry = make_config_entry(data={pkg.CONF_DEVICE_UNIQUE_ID: "dev1"})
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
async def test_async_setup_entry_state_not_mapping(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """Setup exits early when coordinator state is not a mapping."""
    # coordinator.data is not a mapping -> async_setup_entry should return early and not add entities
    coordinator.data = "not-a-mapping"
    entry = make_config_entry(data={pkg.CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)
    added: list[Any] = []

    hass = ph_hass
    hass.data = {}
    hass.config_entries.async_update_entry = MagicMock()
    fake = fake_reg_factory(device_exists=False)
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda hass: fake, raising=False)

    await dt_mod.async_setup_entry(hass, entry, added.extend)
    assert len(added) == 0
    assert not hass.config_entries.async_update_entry.called


@pytest.mark.asyncio
async def test_async_setup_entry_removes_previous_mac(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """Setup removes previously tracked MAC addresses when reconfiguring."""
    # previous tracked macs include an old mac that should be removed via device registry
    coordinator.data = {"arp_table": []}
    entry = make_config_entry(
        data={dt_mod.TRACKED_MACS: ["old:mac:1"], pkg.CONF_DEVICE_UNIQUE_ID: "dev1"},
        entry_id="e_rm",
    )
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)
    hass = ph_hass
    hass.data = {}

    # use shared fake registry fixture: simulate device present and removal
    fake = fake_reg_factory(device_exists=True, device_id="dev_to_remove")
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda hass: fake, raising=False)

    hass.config_entries.async_update_entry = MagicMock()

    await dt_mod.async_setup_entry(hass, entry, lambda x: None)
    assert fake.removed is True
    assert hass.config_entries.async_update_entry.called


def test_handle_coordinator_update_expires_positive(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Expired ARP entries set entity to disconnected and update attributes."""
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
        "update_time": float(int(datetime.now(UTC).timestamp())),
    }

    entry = make_config_entry(data={pkg.CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )
    object.__setattr__(ent, "async_write_ha_state", MagicMock())

    ent._handle_coordinator_update()
    assert isinstance(ent.extra_state_attributes.get("expires"), datetime)


def test_handle_coordinator_update_skips_malformed_expires(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Malformed ARP expiry data should not hide other valid ARP attributes."""
    coordinator.data = {
        "arp_table": [
            {
                "mac": "aa:bb:cc",
                "ip": "1.2.3.4",
                "intf_description": "lan",
                "expires": "soon",
                "type": "arp",
            }
        ],
        "update_time": float(int(datetime.now(UTC).timestamp())),
    }

    entry = make_config_entry(data={pkg.CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )
    object.__setattr__(ent, "async_write_ha_state", MagicMock())

    ent._handle_coordinator_update()

    assert ent.extra_state_attributes.get("interface") == "lan"
    assert "expires" not in ent.extra_state_attributes
    assert ent.extra_state_attributes.get("type") == "arp"


def test_handle_coordinator_update_ip_typeerror(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Handle TypeError when entry IP is None and avoid crashing."""
    coordinator.data = {"arp_table": [{"mac": "aa:bb:cc", "ip": None}]}

    entry = make_config_entry(data={pkg.CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )
    object.__setattr__(ent, "async_write_ha_state", MagicMock())

    ent._handle_coordinator_update()
    # no exception and ip_address is None
    assert ent.ip_address is None


def test_handle_coordinator_update_expired_preserve_last_known_ip(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Expired entries preserve last_known_ip when no IP present."""
    # expired entry should set is_connected False and preserve last_known_ip
    # no ip in entry triggers branch where last_known_ip is preserved
    coordinator.data = {"arp_table": [{"mac": "aa:bb:cc", "expired": True}]}

    entry = make_config_entry(data={pkg.CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )
    ent._last_known_ip = "1.2.3.4"
    object.__setattr__(ent, "async_write_ha_state", MagicMock())

    ent._handle_coordinator_update()
    assert ent.is_connected is False
    assert ent.extra_state_attributes.get("last_known_ip") == "1.2.3.4"
    assert ent.icon == "mdi:lan-disconnect"


@pytest.mark.asyncio
async def test_async_setup_entry_from_arp_entries(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """Setup from ARP entries creates device trackers for present ARP rows."""
    # when CONF_DEVICES not set but device tracker enabled, create entity per arp entry
    coordinator.data = {"arp_table": [{"mac": "m1"}, {"mac": "m2", "hostname": "h2"}]}
    entry = make_config_entry(
        data={pkg.CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={dt_mod.CONF_DEVICE_TRACKER_ENABLED: True},
        entry_id="eid2",
    )
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)
    hass = ph_hass
    hass.data = {}
    hass.config_entries.async_update_entry = MagicMock()
    fake = fake_reg_factory(device_exists=False)
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda hass: fake, raising=False)

    added: list[Any] = []

    await dt_mod.async_setup_entry(hass, entry, added.extend)
    assert len(added) == 2
    assert all(isinstance(e, dt_mod.OPNsenseScannerEntity) for e in added)
    assert {e.unique_id for e in added} == {"dev1_mac_m1", "dev1_mac_m2"}
