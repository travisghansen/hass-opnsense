"""Unit tests for the device_tracker component of the hass-opnsense integration.

These tests cover setup, coordinator update handling, restore state behavior,
and device info formatting for the integration's device tracker entities.
"""

from collections.abc import Callable, Iterable, MutableMapping
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.entity_platform import AddEntitiesCallback
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

import custom_components.opnsense as opnsense_pkg
import custom_components.opnsense.device_tracker as device_tracker_mod
from custom_components.opnsense.device_tracker import OPNsenseScannerEntity
import custom_components.opnsense.entity as entity_mod

base_entity_mod = entity_mod
dt_mod = device_tracker_mod
pkg = opnsense_pkg


def _make_scanner_entity(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    *,
    coordinator_data: object | None = None,
    enabled_default: bool = False,
    mac: str | None = "aa:bb:cc",
) -> OPNsenseScannerEntity:
    """Create a scanner entity with coordinator runtime data wired in.

    Args:
        coordinator: Device tracker coordinator used by the entity.
        make_config_entry: Fixture that creates a mock config entry.
        coordinator_data: Optional coordinator data to install before creating the entity.
        enabled_default: Whether the entity should be enabled by default.
        mac: MAC address tracked by the entity.

    Returns:
        A scanner entity for the requested MAC address.
    """
    coordinator.data = {"arp_table": []} if coordinator_data is None else coordinator_data
    entry = make_config_entry(data={pkg.CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)
    return dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=enabled_default,
        mac=mac,
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
            {"mac": "AA:BB:CC:DD:EE:FF", "hostname": "tracked"},
            {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "duplicate"},
            {"mac": "AA-BB-CC-DD-EE-FF", "hostname": "dash-case"},
            {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "lower"},
            {"mac": "11:22:33:44:55:66", "hostname": "first"},
        ],
    )

    assert mac_addresses == ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]
    assert devices == [
        {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "tracked"},
        {"mac": "11:22:33:44:55:66", "hostname": "first"},
    ]


def test_compile_tracked_devices_normalizes_and_deduplicates_configured_macs(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Configured MACs should be normalized and deduplicated before entity creation."""
    config_entry = make_config_entry(
        options={
            dt_mod.CONF_DEVICE_TRACKER_ENABLED: True,
            dt_mod.CONF_DEVICES: [
                "AA-BB-CC-DD-EE-FF",
                "aa:bb:cc:dd:ee:ff",
                "11:22:33:44:55:66",
                "11-22-33-44-55-66",
            ],
        }
    )
    devices, mac_addresses, enabled_default = dt_mod._compile_tracked_devices(
        config_entry,
        [
            {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "canonical"},
            {"mac": "11:22:33:44:55:66", "hostname": "canonical2"},
        ],
    )

    assert enabled_default is True
    assert mac_addresses == ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]
    assert devices == [
        {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "canonical"},
        {"mac": "11:22:33:44:55:66", "hostname": "canonical2"},
    ]


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
        "arp_table": [
            "not-an-arp-row",
            {"mac": "aa:bb:cc", "ip": "1.2.3.4", "hostname": "dev", "manufacturer": "m"},
        ]
    }

    entry = make_config_entry(
        data={dt_mod.TRACKED_MACS: [], pkg.CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={dt_mod.CONF_DEVICES: ["aa:bb:cc"], dt_mod.CONF_DEVICE_TRACKER_ENABLED: True},
        entry_id="eid",
    )
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)
    entry.add_update_listener = lambda _listener: lambda: None
    entry.async_on_unload = lambda _unload: None
    hass = ph_hass
    hass.config_entries.async_update_entry = MagicMock()
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    fake = fake_reg_factory(device_exists=False)
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: fake, raising=False)

    added: list[Any] = []

    def async_add_entities(ents: Iterable[Any], _update_before_add: bool = False) -> None:
        """Async add entities.

        Args:
            ents: Ents provided by pytest or the test case.
        """
        added.extend(ents)

    await dt_mod.async_setup_entry(hass, entry, cast("AddEntitiesCallback", async_add_entities))

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
async def test_async_setup_entry_skips_malformed_arp_rows(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """Malformed ARP rows should not prevent valid device trackers from being created."""
    coordinator.data = {
        "arp_table": [
            "not-an-arp-row",
            {"mac": "aa:bb:cc", "ip": "1.2.3.4", "hostname": "dev", "manufacturer": "m"},
        ]
    }
    entry = make_config_entry(
        data={dt_mod.TRACKED_MACS: [], pkg.CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={dt_mod.CONF_DEVICE_TRACKER_ENABLED: True},
        entry_id="eid",
    )
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)
    hass = ph_hass
    hass.config_entries.async_update_entry = MagicMock()
    fake = fake_reg_factory(device_exists=False)
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda hass: fake, raising=False)
    added: list[Any] = []

    await dt_mod.async_setup_entry(hass, entry, cast("AddEntitiesCallback", added.extend))

    assert len(added) == 1
    assert added[0].mac_address == "aa:bb:cc"


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
    entry.add_update_listener = lambda _listener: lambda: None
    entry.async_on_unload = lambda _unload: None

    hass = ph_hass
    hass.config_entries.async_update_entry = MagicMock()
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    fake = fake_reg_factory(device_exists=True, device_id="removed-device-id")
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: fake, raising=False)

    added: list[Any] = []

    def async_add_entities(ents: Iterable[Any], _update_before_add: bool = False) -> None:
        """Async add entities.

        Args:
            ents: Ents provided by pytest or the test case.
        """
        added.extend(ents)

    await dt_mod.async_setup_entry(hass, entry, cast("AddEntitiesCallback", async_add_entities))

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
    async_write_ha_state = MagicMock()
    object.__setattr__(ent, "async_write_ha_state", async_write_ha_state)

    ent._handle_coordinator_update()
    assert ent.available is False
    assert async_write_ha_state.called


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
    attributes = ent.extra_state_attributes
    assert attributes is not None
    assert attributes.get("expires") == "Never"
    assert attributes.get("interface") == "lan0"
    assert attributes.get("type") == "arp"
    assert ent.icon == "mdi:lan-connect"
    assert ent.source_type == dt_mod.SourceType.ROUTER


def test_scanner_entity_uses_attr_backed_home_assistant_properties() -> None:
    """Scanner entity should rely on Home Assistant attr-backed properties."""
    locally_defined_properties = {
        name
        for name, value in vars(dt_mod.OPNsenseScannerEntity).items()
        if isinstance(value, property)
    }

    assert "unique_id" in locally_defined_properties
    assert "device_info" in locally_defined_properties
    assert "entity_registry_enabled_default" in locally_defined_properties
    assert "is_connected" in locally_defined_properties
    assert {
        "hostname",
        "ip_address",
        "mac_address",
        "source_type",
    }.isdisjoint(locally_defined_properties)


def test_entity_registry_enabled_default_uses_existing_mac_device(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """Auto-discovered trackers should be enabled when HA can link a MAC device."""
    ent = _make_scanner_entity(
        coordinator=coordinator,
        make_config_entry=make_config_entry,
        coordinator_data={"arp_table": []},
    )
    ent.hass = ph_hass
    device_reg = fake_reg_factory(device_exists=True, device_id="existing-device")
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: device_reg)

    assert ent.entity_registry_enabled_default is True
    assert ent.device_info is None


def test_suggested_object_id_prefers_hostname_when_matching_enabled_mac_device(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """Hostnames should drive suggested_object_id for existing enabled MAC matches."""
    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=make_config_entry(data={pkg.CONF_DEVICE_UNIQUE_ID: "dev1"}),
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname="MyDevice",
    )
    ent.hass = ph_hass
    device_reg = fake_reg_factory(device_exists=True, device_id="existing-device")
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: device_reg)

    assert ent.device_info is None
    assert ent.suggested_object_id == "MyDevice"


def test_suggested_object_id_falls_back_to_mac_for_existing_enabled_mac_match(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """Use MAC as suggested_object_id when hostname is unavailable."""
    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=make_config_entry(data={pkg.CONF_DEVICE_UNIQUE_ID: "dev1"}),
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )
    ent.hass = ph_hass
    device_reg = fake_reg_factory(device_exists=True, device_id="existing-device")
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: device_reg)

    assert ent.device_info is None
    assert ent.suggested_object_id == "aa:bb:cc"


def test_entity_registry_enabled_default_respects_configured_enabled_default(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Configured trackers should keep their requested enabled-by-default state."""
    ent = _make_scanner_entity(
        coordinator=coordinator,
        make_config_entry=make_config_entry,
        coordinator_data={"arp_table": []},
        enabled_default=True,
    )

    assert ent.entity_registry_enabled_default is True


def test_entity_registry_enabled_default_without_mac_stays_disabled(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Trackers without a MAC cannot link to an enabled MAC device."""
    ent = _make_scanner_entity(
        coordinator=coordinator,
        make_config_entry=make_config_entry,
        coordinator_data={"arp_table": []},
        mac=None,
    )

    assert ent.entity_registry_enabled_default is False
    device_info = ent.device_info
    assert device_info is not None
    if isinstance(device_info, MutableMapping):
        connections = device_info.get("connections", [])
    else:
        connections = getattr(device_info, "connections", [])
    assert all(connection[1] != "" for connection in connections)


def test_entity_registry_enabled_default_pref_disable_new_entities_keeps_device_link(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """Existing MAC matches should still link while the new-entity preference is enabled."""
    ent = _make_scanner_entity(
        coordinator=coordinator,
        make_config_entry=make_config_entry,
        coordinator_data={"arp_table": []},
    )
    ent.hass = ph_hass
    object.__setattr__(ent.config_entry, "pref_disable_new_entities", True)
    device_reg = fake_reg_factory(device_exists=True, device_id="existing-device")
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: device_reg)

    assert ent.entity_registry_enabled_default is True
    device_info = ent.device_info
    assert device_info is not None

    if isinstance(device_info, MutableMapping):
        connections = device_info.get("connections", [])
    else:
        connections = getattr(device_info, "connections", [])
    assert any(conn[1] == "aa:bb:cc" for conn in connections)


def test_entity_registry_enabled_default_fallback_when_no_matching_device(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Auto-discovered trackers should stay disabled when no matching device exists."""
    ent = _make_scanner_entity(
        coordinator=coordinator,
        make_config_entry=make_config_entry,
        coordinator_data={"arp_table": []},
    )
    ent.hass = ph_hass
    matched_state = {"has_device": False}

    class _FallbackDevice:
        """Simple stand-in for a registry entry."""

        id = "fallback-device-id"
        disabled_by = None

    class _TrackingRegistry:
        """Mock device registry that can emulate fallback device appearance."""

        def __init__(self) -> None:
            """Initialize the tracking registry."""
            self._device = _FallbackDevice()

        def async_get_device(self, *_args: Any, **_kwargs: Any) -> Any:
            """Return the fallback device only after it is marked as present."""
            return self._device if matched_state["has_device"] else None

    registry = _TrackingRegistry()
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: registry)

    fallback_device_info = ent.device_info
    assert fallback_device_info is not None
    matched_state["has_device"] = True
    assert ent.entity_registry_enabled_default is False


def test_entity_registry_enabled_default_falls_back_for_disabled_mac_device(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """Disabled matching MAC devices should keep fallback device_info-based linking."""
    ent = _make_scanner_entity(
        coordinator=coordinator,
        make_config_entry=make_config_entry,
        coordinator_data={"arp_table": []},
    )
    ent.hass = ph_hass

    device_reg = fake_reg_factory(
        device_exists=True,
        device_id="existing-disabled-device",
        disabled_by="user",
    )
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: device_reg)
    assert ent.entity_registry_enabled_default is False

    device_info = ent.device_info
    assert device_info is not None
    assert isinstance(device_info, MutableMapping)
    connections = device_info.get("connections", [])
    assert any(conn[1] == "aa:bb:cc" for conn in connections)


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


def test_handle_coordinator_update_skips_malformed_arp_rows(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Malformed rows in arp_table should be skipped and valid rows still apply."""
    coordinator.data = {
        "arp_table": [
            "not-an-arp-row",
            {"mac": "dd:ee:ff", "ip": "5.6.7.8"},
            {
                "mac": "aa:bb:cc",
                "ip": "1.2.3.4",
                "hostname": "host?",
                "manufacturer": "m",
                "expires": "not-a-duration",
            },
        ]
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

    assert ent.ip_address == "1.2.3.4"
    assert ent.hostname == "host"
    attributes = ent.extra_state_attributes
    assert attributes is not None
    assert "expires" not in attributes


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
    assert ent.name is None
    assert ent.unique_id == "dev1_mac_aa_bb_cc"
    assert ent.has_entity_name is True
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
    attributes = ent.extra_state_attributes
    assert attributes is not None
    assert attributes.get("interface") == "lan0"
    assert "last_known_connected_time" in attributes

    devinfo = ent.device_info
    # support both DeviceInfo object and dict-shaped DeviceInfo used in tests
    if isinstance(devinfo, MutableMapping):
        connections = devinfo.get("connections", [])
        via = devinfo.get("via_device")
        default_name = devinfo.get("default_name")
    else:
        connections = getattr(devinfo, "connections", [])
        via = getattr(devinfo, "via_device", None)
        default_name = getattr(devinfo, "default_name", None)

    assert any(t[1] == "aa:bb:cc" for t in connections)
    assert default_name == "dev"
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
@pytest.mark.parametrize(
    "connected_time",
    [
        datetime(2026, 6, 22, 12, 30, 5, tzinfo=UTC),
        datetime(2026, 6, 22, 12, 30, 5, tzinfo=UTC).isoformat(),
    ],
)
async def test_restore_last_state_restores_tz_aware_connected_time(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    connected_time: datetime | str,
) -> None:
    """Aware datetime values should restore into tracker state."""
    ent = _make_scanner_entity(coordinator, make_config_entry)
    last_state = MagicMock()
    last_state.attributes = {"last_known_connected_time": connected_time}
    object.__setattr__(ent, "async_get_last_state", AsyncMock(return_value=last_state))

    await ent._restore_last_state()

    assert ent._last_known_connected_time == datetime(2026, 6, 22, 12, 30, 5, tzinfo=UTC)
    attrs = ent.extra_state_attributes
    assert attrs is not None
    assert "last_known_connected_time" in attrs


@pytest.mark.asyncio
async def test_restore_last_state_ignores_naive_iso_connected_time(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Naive ISO timestamps should be ignored during state restore."""
    ent = _make_scanner_entity(coordinator, make_config_entry)
    last_state = MagicMock()
    last_state.attributes = {"last_known_connected_time": "2026-06-22T12:30:05"}
    object.__setattr__(ent, "async_get_last_state", AsyncMock(return_value=last_state))

    await ent._restore_last_state()

    assert ent._last_known_connected_time is None
    attrs = ent.extra_state_attributes
    assert attrs is not None
    assert "last_known_connected_time" not in attrs


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

    restore_last_state = AsyncMock()
    object.__setattr__(ent, "_restore_last_state", restore_last_state)
    monkeypatch.setattr(base_entity_mod.OPNsenseBaseEntity, "async_added_to_hass", AsyncMock())

    await ent.async_added_to_hass()
    assert restore_last_state.called


@pytest.mark.asyncio
async def test_async_internal_added_to_hass_links_existing_mac_device(
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Scanner entity should link to an existing registry device with the same MAC."""
    coordinator.data = {"arp_table": []}
    entry = make_config_entry(data={pkg.CONF_DEVICE_UNIQUE_ID: "dev1"}, entry_id="entry-1")
    entry.add_to_hass(ph_hass)
    existing_entry = make_config_entry(
        data={pkg.CONF_DEVICE_UNIQUE_ID: "other"}, entry_id="existing-entry"
    )
    existing_entry.add_to_hass(ph_hass)
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)
    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )
    ent.hass = ph_hass
    ent.platform = MagicMock(config_entry=entry, platform_name=dt_mod.DOMAIN)

    device_reg = dr.async_get(ph_hass)
    existing_device = device_reg.async_get_or_create(
        config_entry_id="existing-entry",
        connections={(dr.CONNECTION_NETWORK_MAC, "aa:bb:cc")},
    )
    entity_reg = er.async_get(ph_hass)
    unique_id = ent.unique_id
    assert unique_id is not None
    ent.registry_entry = entity_reg.async_get_or_create(
        "device_tracker",
        dt_mod.DOMAIN,
        unique_id,
        config_entry=entry,
    )
    ent.entity_id = ent.registry_entry.entity_id

    await ent.async_internal_added_to_hass()

    assert ent.registry_entry.device_id == existing_device.id
    updated_device = device_reg.async_get(existing_device.id)
    assert updated_device is not None
    assert entry.entry_id in updated_device.config_entries


@pytest.mark.asyncio
async def test_async_internal_added_to_hass_keeps_fallback_device_info_without_match(
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Scanner entity should keep its fallback device info when no MAC device exists."""
    coordinator.data = {"arp_table": []}
    entry = make_config_entry(data={pkg.CONF_DEVICE_UNIQUE_ID: "dev1"}, entry_id="entry-1")
    entry.add_to_hass(ph_hass)
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)
    ent = dt_mod.OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )
    ent.hass = ph_hass
    ent.platform = MagicMock(config_entry=entry, platform_name=dt_mod.DOMAIN)
    entity_reg = er.async_get(ph_hass)
    unique_id = ent.unique_id
    assert unique_id is not None
    ent.registry_entry = entity_reg.async_get_or_create(
        "device_tracker",
        dt_mod.DOMAIN,
        unique_id,
        config_entry=entry,
    )
    ent.entity_id = ent.registry_entry.entity_id

    await ent.async_internal_added_to_hass()

    assert ent.registry_entry.device_id is None
    assert ent.device_info is not None


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
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: fake, raising=False)

    await dt_mod.async_setup_entry(hass, entry, cast("AddEntitiesCallback", added.extend))
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
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: fake, raising=False)

    hass.config_entries.async_update_entry = MagicMock()

    await dt_mod.async_setup_entry(hass, entry, cast("AddEntitiesCallback", lambda _x: None))
    assert fake.removed is False
    assert fake.updated_devices == [
        ("dev_to_remove", {"remove_config_entry_id": entry.entry_id})
    ]
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
    attributes = ent.extra_state_attributes
    assert attributes is not None
    assert isinstance(attributes.get("expires"), datetime)


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

    attributes = ent.extra_state_attributes
    assert attributes is not None
    assert attributes.get("interface") == "lan"
    assert "expires" not in attributes
    assert attributes.get("type") == "arp"


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
    attributes = ent.extra_state_attributes
    assert attributes is not None
    assert attributes.get("last_known_ip") == "1.2.3.4"
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
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: fake, raising=False)

    added: list[Any] = []

    await dt_mod.async_setup_entry(hass, entry, cast("AddEntitiesCallback", added.extend))
    assert len(added) == 2
    assert all(isinstance(e, dt_mod.OPNsenseScannerEntity) for e in added)
    assert {e.unique_id for e in added} == {"dev1_mac_m1", "dev1_mac_m2"}


@pytest.mark.asyncio
async def test_async_setup_entry_removes_stale_tracker_entities_before_detach(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Stale MAC removal should clear via-links and remove matching tracker entities."""
    coordinator.data = {"arp_table": [{"mac": "keep:mac"}]}
    stale_router_mac = "stale:mac:router"
    stale_other_mac = "stale:mac:other"
    entry = make_config_entry(
        data={
            dt_mod.TRACKED_MACS: [stale_router_mac, stale_other_mac, "keep:mac"],
            pkg.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={dt_mod.CONF_DEVICE_TRACKER_ENABLED: True},
        entry_id="entity-rm",
    )
    setattr(entry.runtime_data, dt_mod.DEVICE_TRACKER_COORDINATOR, coordinator)

    stale_router_ent = MagicMock()
    stale_router_ent.entity_id = "device_tracker.device_stale_router"
    stale_router_ent.unique_id = "dev1_mac_stale_mac_router"
    stale_router_ent.domain = "device_tracker"

    stale_other_ent = MagicMock()
    stale_other_ent.entity_id = "device_tracker.device_stale_other"
    stale_other_ent.unique_id = "dev1_mac_stale_mac_other"
    stale_other_ent.domain = "device_tracker"

    other_ent = MagicMock()
    other_ent.entity_id = "sensor.other"
    other_ent.unique_id = "dev1_sensor_other"
    other_ent.domain = "sensor"

    class _FakeEntityReg:
        def __init__(self) -> None:
            """Track removed entity IDs."""
            self.removed: list[str] = []
            self.updated: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
            self._router_device = MagicMock()
            self._router_device.id = "router-device-id"
            self._router_device.identifiers = {(dt_mod.DOMAIN, "dev1")}
            self._mac_devices: dict[frozenset[Any], MagicMock] = {
                frozenset({(dt_mod.CONNECTION_NETWORK_MAC, stale_router_mac)}): MagicMock(
                    id="stale-router-device", via_device_id="router-device-id"
                ),
                frozenset({(dt_mod.CONNECTION_NETWORK_MAC, stale_other_mac)}): MagicMock(
                    id="stale-other-device", via_device_id="other-device-id"
                ),
            }

        def async_entries_for_config_entry(self, registry: Any, config_entry_id: str) -> list[Any]:
            """Return registry entries for this config entry."""
            return [stale_router_ent, stale_other_ent, other_ent]

        def async_remove(self, entity_id: str) -> None:
            """Record removed entity identifiers."""
            self.removed.append(entity_id)

        def async_get_device(self, *args: Any, **kwargs: Any) -> Any:
            """Return configured stale router or stale tracker devices by lookup.

            Returns the router device by identifiers and stale devices by connection.
            """
            if "identifiers" in kwargs:
                identifiers = kwargs["identifiers"]
                if identifiers == self._router_device.identifiers:
                    return self._router_device
                return None
            if "connections" in kwargs:
                return self._mac_devices.get(frozenset(kwargs["connections"]))
            return None

        def async_update_device(self, *args: Any, **kwargs: Any) -> None:
            """Record a cleanup update to the device registry."""
            self.updated.append((args, kwargs))

    entity_registry = _FakeEntityReg()
    monkeypatch.setattr(dt_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        dt_mod.er,
        "async_entries_for_config_entry",
        entity_registry.async_entries_for_config_entry,
    )

    hass = ph_hass
    hass.config_entries.async_update_entry = MagicMock()

    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda hass: entity_registry)

    await dt_mod.async_setup_entry(hass, entry, lambda x: None)
    assert set(entity_registry.removed) == {
        "device_tracker.device_stale_router",
        "device_tracker.device_stale_other",
    }
    assert (
        ("stale-router-device",),
        {"remove_config_entry_id": entry.entry_id, "via_device_id": None},
    ) in entity_registry.updated
    assert (
        ("stale-other-device",),
        {"remove_config_entry_id": entry.entry_id},
    ) in entity_registry.updated
