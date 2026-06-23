"""Unit tests for the device_tracker component of the hass-opnsense integration.

These tests cover setup, coordinator update handling, restore state behavior,
and device info formatting for the integration's device tracker entities.
"""

from collections.abc import Callable, Iterable, MutableMapping
from datetime import UTC, datetime, timedelta
import importlib
from types import MappingProxyType
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.opnsense.device_tracker import OPNsenseScannerEntity

dt_mod = importlib.import_module("custom_components.opnsense.device_tracker")
pkg = importlib.import_module("custom_components.opnsense")


def _make_scanner_entity(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    *,
    coordinator_data: object | None = None,
) -> OPNsenseScannerEntity:
    """Create a scanner entity with coordinator runtime data wired in.

    Args:
        coordinator: Device tracker coordinator used by the entity.
        make_config_entry: Fixture that creates a mock config entry.
        coordinator_data: Optional coordinator data to install before creating the entity.

    Returns:
        A scanner entity for the standard tracked MAC used in these tests.
    """
    coordinator.data = {"arp_table": []} if coordinator_data is None else coordinator_data
    entry = make_config_entry(data={pkg.CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)
    return dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )


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
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)
    entry.add_update_listener = lambda f: lambda: None
    entry.async_on_unload = lambda x: None
    hass = ph_hass
    hass.config_entries.async_update_entry = MagicMock()
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

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
    created = added[0]
    assert isinstance(created, dt_mod.OPNsenseScannerEntity)
    uid = getattr(created, "unique_id", None)
    assert uid is not None
    assert uid.startswith("dev1_")
    assert uid.endswith("mac_aa_bb_cc")
    assert "aa_bb_cc" in uid
    assert created.mac_address == "aa:bb:cc"
    assert hass.config_entries.async_update_entry.called
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
    coordinator.data = {
        "arp_table": [{"mac": "aa:bb:cc", "ip": "1.2.3.4", "hostname": "dev", "manufacturer": "m"}]
    }

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

    assert hass.config_entries.async_update_entry.called
    call = hass.config_entries.async_update_entry.call_args
    args = call.args
    kwargs = call.kwargs
    updated_data = kwargs.get("data", args[1] if len(args) > 1 else None)

    assert updated_data is not None
    assert "ff:ee:dd" not in updated_data.get(dt_mod.TRACKED_MACS, [])
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
    assert ent.hostname == "host"
    assert ent.is_connected is True
    assert ent.extra_state_attributes.get("expires") == "Never"
    assert ent.extra_state_attributes.get("interface") == "lan0"
    assert ent.extra_state_attributes.get("type") == "arp"
    assert ent.icon == "mdi:lan-connect"
    assert ent.source_type == dt_mod.SourceType.ROUTER


def test_device_data_from_arp_entry_normalizes_hostname_and_filters_manufacturer() -> None:
    """ARP setup data should normalize hostnames and ignore non-string manufacturer."""
    device = dt_mod._device_data_from_arp_entry(
        "aa:bb:cc", {"hostname": "host?", "manufacturer": ""}
    )
    assert device == {"mac": "aa:bb:cc", "hostname": "host"}

    device = dt_mod._device_data_from_arp_entry(
        "dd:ee:ff", {"hostname": "host", "manufacturer": None}
    )
    assert device == {"mac": "dd:ee:ff", "hostname": "host"}


def test_device_from_arp_entry_matches_mac_case_insensitively_and_rejects_non_string_macs() -> None:
    """Device lookup should match MAC addresses case-insensitively and skip bad MAC types."""
    device = dt_mod._device_from_arp_entry(
        "aa:bb:cc",
        [{"mac": 12345}, {"mac": "AA:BB:CC", "hostname": "TrackedHost", "manufacturer": "m"}],
    )

    assert device == {"mac": "aa:bb:cc", "hostname": "TrackedHost", "manufacturer": "m"}


def test_handle_coordinator_update_skips_malformed_arp_entries(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Malformed ARP entries should be skipped while searching for the tracked MAC."""
    ent = _make_scanner_entity(
        coordinator=coordinator,
        make_config_entry=make_config_entry,
        coordinator_data={"arp_table": [object()]},
    )
    object.__setattr__(ent, "async_write_ha_state", MagicMock())

    ent._handle_coordinator_update()

    assert ent.is_connected is False
    assert ent.available is True


def test_handle_coordinator_update_skips_nonmatching_mapping_arp_entries(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Nonmatching ARP mapping entries should be skipped while searching."""
    ent = _make_scanner_entity(
        coordinator=coordinator,
        make_config_entry=make_config_entry,
        coordinator_data={"arp_table": [{"mac": "dd:ee:ff"}]},
    )
    object.__setattr__(ent, "async_write_ha_state", MagicMock())

    ent._handle_coordinator_update()

    assert ent.is_connected is False
    assert ent.available is True


def test_handle_coordinator_update_matches_mac_case_insensitively(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Coordinator matching should include uppercase/lowercase MAC variations."""
    coordinator.data = {
        "arp_table": [{"mac": "AA:BB:CC", "ip": "1.2.3.4", "intf_description": "lan"}],
        "update_time": 0,
    }
    ent = _make_scanner_entity(
        coordinator=coordinator,
        make_config_entry=make_config_entry,
        coordinator_data=coordinator.data,
    )
    object.__setattr__(ent, "async_write_ha_state", MagicMock())

    ent._handle_coordinator_update()

    assert ent.ip_address == "1.2.3.4"
    attrs = ent.extra_state_attributes
    assert attrs is not None
    assert attrs.get("interface") == "lan"
    assert ent.available is True


def test_update_arp_extra_state_attributes_clears_stale_values() -> None:
    """Stale ARP extra state attributes are removed when absent in current entry."""
    attributes: dict[str, Any] = {
        "interface": "old",
        "expires": "Never",
        "type": "old",
        "last_known_ip": "9.9.9.9",
    }

    dt_mod._update_arp_extra_state_attributes(attributes, {})

    assert "interface" not in attributes
    assert "expires" not in attributes
    assert "type" not in attributes
    assert attributes == {"last_known_ip": "9.9.9.9"}


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
    ent._last_known_connected_time = datetime.now(UTC).astimezone()
    object.__setattr__(ent, "async_write_ha_state", MagicMock())

    ent._handle_coordinator_update()
    assert ent.is_connected is True


def test_handle_coordinator_update_expired_entry_outside_consider_home(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Expired ARP entries outside consider_home should stay disconnected."""
    entry = make_config_entry(
        data={pkg.CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={dt_mod.CONF_DEVICE_TRACKER_CONSIDER_HOME: 1},
    )
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)
    coordinator.data = {"arp_table": [{"mac": "aa:bb:cc", "expired": True}]}
    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )
    ent._last_known_connected_time = datetime.now(UTC).astimezone() - timedelta(seconds=5)
    object.__setattr__(ent, "async_write_ha_state", MagicMock())

    ent._handle_coordinator_update()

    assert ent.is_connected is False


@pytest.mark.asyncio
async def test_restore_last_state_returns_when_no_snapshot(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Restoring state should return when Home Assistant has no saved snapshot."""
    ent = _make_scanner_entity(coordinator, make_config_entry)
    object.__setattr__(ent, "async_get_last_state", AsyncMock(return_value=None))

    await ent._restore_last_state()

    assert ent.extra_state_attributes == {}


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
    object.__setattr__(ent, "async_get_last_state", AsyncMock(return_value=last_state))

    await ent._restore_last_state()
    assert ent._last_known_hostname == "oldhost"
    assert ent._last_known_ip == "9.9.9.9"
    assert ent._last_known_connected_time == last_known_connected_time
    assert ent.extra_state_attributes.get("interface") == "lan0"
    assert "last_known_connected_time" in ent.extra_state_attributes

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
    last_known_connected_time = datetime.now(UTC)
    ent = _make_scanner_entity(coordinator, make_config_entry)
    last_state = MagicMock()
    last_state.attributes = {
        "last_known_hostname": None,
        "last_known_ip": None,
        "interface": "",
        "expires": None,
        "type": "",
        "last_known_connected_time": last_known_connected_time,
    }
    object.__setattr__(ent, "async_get_last_state", AsyncMock(return_value=last_state))

    await ent._restore_last_state()

    assert ent._last_known_connected_time == last_known_connected_time
    assert ent.extra_state_attributes == {"last_known_connected_time": last_known_connected_time}


@pytest.mark.asyncio
async def test_restore_last_state_ignores_unparseable_connected_time(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Restoring state should ignore invalid saved connection timestamps."""
    ent = _make_scanner_entity(coordinator, make_config_entry)
    last_state = MagicMock()
    last_state.attributes = {"last_known_connected_time": "not-a-date"}
    object.__setattr__(ent, "async_get_last_state", AsyncMock(return_value=last_state))

    await ent._restore_last_state()

    assert ent._last_known_connected_time is None
    attrs = ent.extra_state_attributes
    assert attrs is not None
    assert "last_known_connected_time" not in attrs


@pytest.mark.asyncio
async def test_restore_last_state_ignores_non_datetime_connected_time(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Restoring state should ignore non-string and non-datetime timestamps."""
    ent = _make_scanner_entity(coordinator, make_config_entry)
    last_state = MagicMock()
    last_state.attributes = {"last_known_connected_time": 1}
    object.__setattr__(ent, "async_get_last_state", AsyncMock(return_value=last_state))

    await ent._restore_last_state()

    assert ent._last_known_connected_time is None
    attrs = ent.extra_state_attributes
    assert attrs is not None
    assert "last_known_connected_time" not in attrs


@pytest.mark.asyncio
async def test_restore_last_state_ignores_non_mapping_attributes(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Restoring state should ignore snapshots with malformed attributes."""
    ent = _make_scanner_entity(coordinator, make_config_entry)
    last_state = MagicMock()
    last_state.attributes = ["not", "a", "mapping"]
    object.__setattr__(ent, "async_get_last_state", AsyncMock(return_value=last_state))

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

    ent._restore_last_state = AsyncMock()
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
    coordinator.data = {"arp_table": []}
    entry = make_config_entry(
        data={dt_mod.TRACKED_MACS: ["old:mac:1"], pkg.CONF_DEVICE_UNIQUE_ID: "dev1"},
        entry_id="e_rm",
    )
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)
    hass = ph_hass
    hass.data = {}

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
    assert ent.ip_address is None


def test_handle_coordinator_update_expired_preserve_last_known_ip(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Expired entries preserve last_known_ip when no IP present."""
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
