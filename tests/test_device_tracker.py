"""Unit tests for the device_tracker component of the hass-opnsense integration.

These tests cover setup, coordinator update handling, restore state behavior,
and device info formatting for the integration's device tracker entities.
"""

from collections.abc import Callable, Iterable, MutableMapping
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock, call

from homeassistant.components.device_tracker import SourceType
from homeassistant.const import Platform
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.entity_platform import AddEntitiesCallback
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.opnsense.const import (
    CONF_DEVICE_TRACKER_CONSIDER_HOME,
    CONF_DEVICE_TRACKER_ENABLED,
    CONF_DEVICE_UNIQUE_ID,
    CONF_DEVICES,
    DEVICE_TRACKER_COORDINATOR,
    DOMAIN,
    TRACKED_MACS,
)
import custom_components.opnsense.device_tracker as dt_mod
from custom_components.opnsense.device_tracker import OPNsenseScannerEntity
from custom_components.opnsense.entity import OPNsenseBaseEntity


def _make_scanner_entity(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    *,
    coordinator_data: object | None = None,
    enabled_default: bool = False,
    mac: str = "aa:bb:cc",
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
    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    return OPNsenseScannerEntity(
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
            CONF_DEVICE_TRACKER_ENABLED: True,
            CONF_DEVICES: [
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


def test_device_from_arp_entry_uses_raw_arp_keys() -> None:
    """Raw aiopnsense ARP keys should be discovered alongside normalized keys."""
    device = dt_mod._device_from_arp_entry(
        "aa:bb:cc",
        [{"mac-address": "AA-BB-CC"}, {"mac": "11:22:33"}],
    )

    assert device == {"mac": "aa:bb:cc"}


def test_devices_from_arp_entries_reads_raw_mac_ip_keys() -> None:
    """Raw ARP key names should be consumed when scanning configured devices."""
    devices, mac_addresses = dt_mod._devices_from_arp_entries(
        [{"mac-address": "AA-BB-CC", "ip-address": "10.0.0.2", "hostname": "raw"}],
    )

    assert mac_addresses == ["aa:bb:cc"]
    assert devices == [{"mac": "aa:bb:cc", "hostname": "raw"}]


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
        data={TRACKED_MACS: [], CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={CONF_DEVICES: ["aa:bb:cc"], CONF_DEVICE_TRACKER_ENABLED: True},
        entry_id="eid",
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
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
    assert isinstance(created, OPNsenseScannerEntity)
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
    assert updated_data.get(TRACKED_MACS) == ["aa:bb:cc"]


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
        data={TRACKED_MACS: [], CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={CONF_DEVICE_TRACKER_ENABLED: True},
        entry_id="eid",
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
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
        data={TRACKED_MACS: ["aa:bb:cc", "ff:ee:dd"], CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={CONF_DEVICES: ["aa:bb:cc"], CONF_DEVICE_TRACKER_ENABLED: True},
        entry_id="eid_remove",
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
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
    assert "ff:ee:dd" not in updated_data.get(TRACKED_MACS, [])
    assert "aa:bb:cc" in updated_data.get(TRACKED_MACS, [])


def test_handle_coordinator_update_unavailable(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Coordinator with invalid data should mark entity unavailable."""
    coordinator.data = None
    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = OPNsenseScannerEntity(
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

    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = OPNsenseScannerEntity(
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
    assert ent.source_type == SourceType.ROUTER


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


@pytest.mark.parametrize(
    ("hostname", "expected_object_id"),
    [
        pytest.param("MyDevice", "MyDevice", id="hostname"),
        pytest.param(None, "aa:bb:cc", id="mac-fallback"),
    ],
)
def test_suggested_object_id_for_matching_enabled_mac_device(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
    hostname: str | None,
    expected_object_id: str,
) -> None:
    """Suggested object IDs should prefer hostnames and otherwise use the MAC."""
    ent = OPNsenseScannerEntity(
        config_entry=make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"}),
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=hostname,
    )
    ent.hass = ph_hass
    device_reg = fake_reg_factory(device_exists=True, device_id="existing-device")
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: device_reg)

    assert ent.device_info is None
    assert ent.suggested_object_id == expected_object_id


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
    )

    object.__setattr__(ent, "_attr_mac_address", None)

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


def test_handle_coordinator_update_reads_raw_arp_ip_key(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Tracker update should still read `ip-address` when `ip` is absent."""
    coordinator.data = {
        "arp_table": [
            {"mac-address": "AA:BB:CC", "ip-address": "10.0.0.12", "intf_description": "lan"}
        ],
        "update_time": 0,
    }
    ent = _make_scanner_entity(
        coordinator=coordinator,
        make_config_entry=make_config_entry,
        coordinator_data=coordinator.data,
    )
    object.__setattr__(ent, "async_write_ha_state", MagicMock())

    ent._handle_coordinator_update()

    assert ent.ip_address == "10.0.0.12"


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
    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = OPNsenseScannerEntity(
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
        data={CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={CONF_DEVICE_TRACKER_CONSIDER_HOME: 3600},
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = OPNsenseScannerEntity(
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
        data={CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={CONF_DEVICE_TRACKER_CONSIDER_HOME: 1},
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    coordinator.data = {"arp_table": [{"mac": "aa:bb:cc", "expired": True}]}
    ent = OPNsenseScannerEntity(
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
    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = OPNsenseScannerEntity(
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
    assert via[0] == DOMAIN
    assert via[1] == entry.data[CONF_DEVICE_UNIQUE_ID]


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
@pytest.mark.parametrize(
    "connected_time",
    [
        pytest.param("2026-06-22T12:30:05", id="naive-iso"),
        pytest.param("not-a-date", id="unparsable"),
        pytest.param(1, id="non-datetime"),
    ],
)
async def test_restore_last_state_ignores_invalid_connected_time(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    connected_time: str | int,
) -> None:
    """Restoring state should ignore invalid saved connection timestamps."""
    ent = _make_scanner_entity(coordinator, make_config_entry)
    last_state = MagicMock()
    last_state.attributes = {"last_known_connected_time": connected_time}
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
    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )

    restore_last_state = AsyncMock()
    object.__setattr__(ent, "_restore_last_state", restore_last_state)
    monkeypatch.setattr(OPNsenseBaseEntity, "async_added_to_hass", AsyncMock())

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
    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"}, entry_id="entry-1")
    entry.add_to_hass(ph_hass)
    existing_entry = make_config_entry(
        data={CONF_DEVICE_UNIQUE_ID: "other"}, entry_id="existing-entry"
    )
    existing_entry.add_to_hass(ph_hass)
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    ent = OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )
    ent.hass = ph_hass
    ent.platform = MagicMock(config_entry=entry, platform_name=DOMAIN)

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
        DOMAIN,
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
    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"}, entry_id="entry-1")
    entry.add_to_hass(ph_hass)
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    ent = OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc",
        mac_vendor=None,
        hostname=None,
    )
    ent.hass = ph_hass
    ent.platform = MagicMock(config_entry=entry, platform_name=DOMAIN)
    entity_reg = er.async_get(ph_hass)
    unique_id = ent.unique_id
    assert unique_id is not None
    ent.registry_entry = entity_reg.async_get_or_create(
        "device_tracker",
        DOMAIN,
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
    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
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
async def test_async_setup_entry_records_none_for_missing_arp_inventory(
    monkeypatch: pytest.MonkeyPatch,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Missing ARP payload should keep device tracker reconciliation incomplete."""
    coordinator.data = {}
    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)

    recorded: dict[str, Any] = {}

    def capture(_entry: MockConfigEntry, _platform: str, entities: Any | None = None) -> None:
        """Capture the desired-entity payload sent to reconciliation."""
        recorded["entities"] = entities

    monkeypatch.setattr(dt_mod, "record_desired_entities", capture)

    await dt_mod.async_setup_entry(
        MagicMock(),
        entry,
        cast("AddEntitiesCallback", lambda _entities: None),
    )

    assert "entities" in recorded
    assert recorded["entities"] is None


@pytest.mark.asyncio
async def test_async_setup_entry_records_empty_authoritative_arp_inventory(
    monkeypatch: pytest.MonkeyPatch,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """An explicit empty ARP table is still authoritative for tracker reconciliation."""
    coordinator.data = {"arp_table": []}
    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)

    recorded: dict[str, Any] = {}

    def capture(_entry: MockConfigEntry, _platform: str, entities: Any | None = None) -> None:
        """Capture the desired-entity payload sent to reconciliation."""
        recorded["entities"] = entities

    monkeypatch.setattr(dt_mod, "record_desired_entities", capture)

    await dt_mod.async_setup_entry(
        MagicMock(),
        entry,
        cast("AddEntitiesCallback", lambda _entities: None),
    )

    assert "entities" in recorded
    assert recorded["entities"] == []


@pytest.mark.asyncio
async def test_async_setup_entry_records_none_for_malformed_arp_rows_in_track_all(
    monkeypatch: pytest.MonkeyPatch,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Track-all mode should fail reconciliation if any ARP row cannot compile."""
    coordinator.data = {
        "arp_table": [
            "not-an-arp-row",
            {},
            {"mac": "", "hostname": "malformed"},
            {"mac": "AA-BB-CC-DD-EE-FF", "hostname": "good"},
        ]
    }
    entry = make_config_entry(
        data={CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={CONF_DEVICE_TRACKER_ENABLED: True},
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    recorded: dict[str, Any] = {}
    added: list[Any] = []

    def capture(_entry: MockConfigEntry, _platform: str, entities: Any | None = None) -> None:
        """Capture the desired-entity payload sent to reconciliation."""
        recorded["entities"] = entities

    monkeypatch.setattr(dt_mod, "record_desired_entities", capture)

    await dt_mod.async_setup_entry(
        MagicMock(),
        entry,
        cast("AddEntitiesCallback", lambda entities, _=False: added.extend(entities)),
    )

    assert "entities" in recorded
    assert recorded["entities"] is None
    assert len(added) == 1
    assert added[0].mac_address == "aa:bb:cc:dd:ee:ff"


@pytest.mark.asyncio
async def test_async_setup_entry_records_entities_for_duplicate_macs_in_track_all(
    monkeypatch: pytest.MonkeyPatch,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Track-all mode should treat duplicate normalized MAC rows as authoritative."""
    coordinator.data = {
        "arp_table": [
            {"mac": "AA-BB-CC-DD-EE-FF", "hostname": "first"},
            {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "duplicate"},
            {"mac": "11:22:33:44:55:66", "hostname": "good"},
        ]
    }
    entry = make_config_entry(
        data={CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={CONF_DEVICE_TRACKER_ENABLED: True},
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    recorded: dict[str, Any] = {}
    added: list[Any] = []

    def capture(_entry: MockConfigEntry, _platform: str, entities: Any | None = None) -> None:
        """Capture the desired-entity payload sent to reconciliation."""
        recorded["entities"] = entities

    monkeypatch.setattr(dt_mod, "record_desired_entities", capture)

    await dt_mod.async_setup_entry(
        MagicMock(),
        entry,
        cast("AddEntitiesCallback", lambda entities, _=False: added.extend(entities)),
    )

    assert "entities" in recorded
    assert isinstance(recorded["entities"], list)
    assert [entity.mac_address for entity in recorded["entities"]] == [
        "aa:bb:cc:dd:ee:ff",
        "11:22:33:44:55:66",
    ]
    assert len(added) == 2
    assert added[0].mac_address == "aa:bb:cc:dd:ee:ff"
    assert added[1].mac_address == "11:22:33:44:55:66"


@pytest.mark.asyncio
async def test_async_setup_entry_track_all_completeness_ignored_in_explicit_mac_mode(
    monkeypatch: pytest.MonkeyPatch,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Explicit configured-MAC mode should ignore track-all completeness failures."""
    coordinator.data = {
        "arp_table": [
            "not-an-arp-row",
            {"mac": "", "hostname": "malformed"},
            {"mac": "AA-BB-CC-DD-EE-FF", "hostname": "good"},
        ]
    }
    entry = make_config_entry(
        data={CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={
            CONF_DEVICE_TRACKER_ENABLED: True,
            CONF_DEVICES: ["aa:bb:cc:dd:ee:ff"],
        },
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    recorded: dict[str, Any] = {}
    added: list[Any] = []

    def capture(_entry: MockConfigEntry, _platform: str, entities: Any | None = None) -> None:
        """Capture the desired-entity payload sent to reconciliation."""
        recorded["entities"] = entities

    monkeypatch.setattr(dt_mod, "record_desired_entities", capture)

    await dt_mod.async_setup_entry(
        MagicMock(),
        entry,
        cast("AddEntitiesCallback", lambda entities, _=False: added.extend(entities)),
    )

    assert "entities" in recorded
    assert isinstance(recorded["entities"], list)
    assert len(added) == 1
    assert added[0].mac_address == "aa:bb:cc:dd:ee:ff"


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
        data={TRACKED_MACS: ["old:mac:1"], CONF_DEVICE_UNIQUE_ID: "dev1"},
        entry_id="e_rm",
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    hass = ph_hass
    hass.data = {}

    fake = fake_reg_factory(device_exists=True, device_id="dev_to_remove")
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: fake, raising=False)

    hass.config_entries.async_update_entry = MagicMock()

    await dt_mod.async_setup_entry(hass, entry, cast("AddEntitiesCallback", lambda _x: None))
    fake.async_remove_device.assert_not_called()
    fake.async_update_device.assert_called_once_with(
        "dev_to_remove", remove_config_entry_id=entry.entry_id
    )
    assert hass.config_entries.async_update_entry.called


@pytest.mark.asyncio
async def test_async_setup_entry_preserves_previous_device_during_reconciliation(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """Active reconciliation owns stale deletion, including tracker devices."""
    coordinator.data = {"arp_table": []}
    entry = make_config_entry(
        data={TRACKED_MACS: ["old:mac:1"], CONF_DEVICE_UNIQUE_ID: "dev1"},
        entry_id="e_reconcile",
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    fake = fake_reg_factory(device_exists=True, device_id="dev_to_preserve")
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: fake, raising=False)
    monkeypatch.setattr(dt_mod, "is_reconciliation_active", lambda _entry: True)
    cleanup = MagicMock()
    monkeypatch.setattr(dt_mod, "_cleanup_stale_tracked_devices", cleanup)
    record = MagicMock()
    monkeypatch.setattr(dt_mod, "record_desired_entities", record)
    ph_hass.config_entries.async_update_entry = MagicMock()

    await dt_mod.async_setup_entry(
        ph_hass, entry, cast("AddEntitiesCallback", lambda _entities: None)
    )

    cleanup.assert_not_called()
    record.assert_called_once_with(entry, "device_tracker", [])


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

    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = OPNsenseScannerEntity(
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

    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = OPNsenseScannerEntity(
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

    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = OPNsenseScannerEntity(
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

    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)

    ent = OPNsenseScannerEntity(
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
        data={CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={CONF_DEVICE_TRACKER_ENABLED: True},
        entry_id="eid2",
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    hass = ph_hass
    hass.data = {}
    hass.config_entries.async_update_entry = MagicMock()
    fake = fake_reg_factory(device_exists=False)
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: fake, raising=False)

    added: list[Any] = []

    await dt_mod.async_setup_entry(hass, entry, cast("AddEntitiesCallback", added.extend))
    assert len(added) == 2
    assert all(isinstance(e, OPNsenseScannerEntity) for e in added)
    assert {e.unique_id for e in added} == {"dev1_mac_m1", "dev1_mac_m2"}


@pytest.mark.asyncio
async def test_async_setup_entry_removes_stale_tracker_entities_and_reparents_shared_router(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Stale MAC cleanup reassigns shared parents to surviving OPNsense routers."""
    coordinator.data = {"arp_table": [{"mac": "keep:mac"}]}
    stale_router_mac = "stale:mac:router"
    stale_other_mac = "stale:mac:other"
    stale_non_opnsense_mac = "stale:mac:nonopnsense"
    entry = make_config_entry(
        data={
            TRACKED_MACS: [
                stale_router_mac,
                stale_other_mac,
                stale_non_opnsense_mac,
                "keep:mac",
            ],
            CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={CONF_DEVICE_TRACKER_ENABLED: True},
        entry_id="entity-rm",
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)

    entity_registry = MagicMock()
    entity_ids = {
        "dev1_mac_stale_mac_router": "device_tracker.device_stale_router",
        "dev1_mac_stale_mac_other": "device_tracker.device_stale_other",
        "dev1_mac_stale_mac_nonopnsense": "device_tracker.device_stale_nonopnsense_router",
    }

    def get_entity_id(domain: str, platform: str, unique_id: str) -> str | None:
        """Return the registered tracker entity for a stale unique ID."""
        return entity_ids.get(unique_id)

    entity_registry.async_get_entity_id.side_effect = get_entity_id
    monkeypatch.setattr(dt_mod.er, "async_get", MagicMock(return_value=entity_registry))

    router_device = MagicMock(
        id="router-device-id",
        identifiers={(DOMAIN, entry.data[CONF_DEVICE_UNIQUE_ID])},
    )
    surviving_entry_a = MagicMock(
        entry_id="survive-entry-b",
        domain=DOMAIN,
        data={CONF_DEVICE_UNIQUE_ID: "survive-b"},
    )
    surviving_entry_b = MagicMock(
        entry_id="survive-entry-a",
        domain=DOMAIN,
        data={CONF_DEVICE_UNIQUE_ID: "survive-a"},
    )
    non_opnsense_entry = MagicMock(
        entry_id="non-opnsense-entry",
        domain="other",
        data={CONF_DEVICE_UNIQUE_ID: "non-opnsense"},
    )
    async_get_entry_map = {
        entry.entry_id: entry,
        surviving_entry_a.entry_id: surviving_entry_a,
        surviving_entry_b.entry_id: surviving_entry_b,
        non_opnsense_entry.entry_id: non_opnsense_entry,
    }
    ph_hass.config_entries.async_get_entry = MagicMock(side_effect=async_get_entry_map.get)
    surviving_router_a = MagicMock(id="survivor-a-router")
    surviving_router_b = MagicMock(id="survivor-b-router")
    identifier_router_map = {
        (DOMAIN, entry.data[CONF_DEVICE_UNIQUE_ID]): router_device,
        (DOMAIN, "survive-b"): surviving_router_b,
        (DOMAIN, "survive-a"): surviving_router_a,
    }
    devices = {
        stale_router_mac: MagicMock(
            id="stale-router-device",
            via_device_id="router-device-id",
            config_entries={
                entry.entry_id,
                surviving_entry_a.entry_id,
                surviving_entry_b.entry_id,
                non_opnsense_entry.entry_id,
            },
        ),
        stale_other_mac: MagicMock(
            id="stale-other-device",
            via_device_id="other-device-id",
            config_entries={entry.entry_id, non_opnsense_entry.entry_id},
        ),
        stale_non_opnsense_mac: MagicMock(
            id="stale-nonopnsense-device",
            via_device_id="router-device-id",
            config_entries={entry.entry_id, non_opnsense_entry.entry_id},
        ),
    }

    def get_device(
        *,
        identifiers: set[tuple[str, str]] | None = None,
        connections: set[tuple[str, str]] | None = None,
    ) -> Any:
        """Return the fake router or stale device for the requested lookup."""
        if identifiers is not None:
            key = next(iter(identifiers))
            return identifier_router_map.get(key)
        if connections is not None:
            return devices[next(iter(connections))[1]]
        return None

    device_registry = MagicMock()
    device_registry.async_get_device.side_effect = get_device
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", MagicMock(return_value=device_registry))

    ph_hass.config_entries.async_update_entry = MagicMock()
    await dt_mod.async_setup_entry(ph_hass, entry, MagicMock())

    entity_registry.async_get_entity_id.assert_has_calls(
        [
            call(Platform.DEVICE_TRACKER, DOMAIN, "dev1_mac_stale_mac_router"),
            call(Platform.DEVICE_TRACKER, DOMAIN, "dev1_mac_stale_mac_other"),
            call(
                Platform.DEVICE_TRACKER,
                DOMAIN,
                "dev1_mac_stale_mac_nonopnsense",
            ),
        ],
        any_order=True,
    )
    assert entity_registry.async_get_entity_id.call_count == 3
    removed_ids = {item.args[0] for item in entity_registry.async_remove.call_args_list}
    assert removed_ids == {
        "device_tracker.device_stale_router",
        "device_tracker.device_stale_other",
        "device_tracker.device_stale_nonopnsense_router",
    }
    device_registry.async_update_device.assert_has_calls(
        [
            call(
                "stale-router-device",
                remove_config_entry_id=entry.entry_id,
                via_device_id="survivor-a-router",
            ),
            call(
                "stale-nonopnsense-device",
                remove_config_entry_id=entry.entry_id,
                via_device_id=None,
            ),
            call("stale-other-device", remove_config_entry_id=entry.entry_id),
        ],
        any_order=True,
    )
    assert call(
        "stale-other-device", remove_config_entry_id=entry.entry_id, via_device_id=None
    ) not in (device_registry.async_update_device.call_args_list)


@pytest.mark.asyncio
async def test_async_setup_entry_removes_stale_tracker_entities_clears_missing_parent(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Clear stale tracker parent assignment when router lookup is no longer available."""
    coordinator.data = {"arp_table": [{"mac": "keep:mac"}]}
    stale_router_mac = "stale:mac:router"
    entry = make_config_entry(
        data={
            TRACKED_MACS: [stale_router_mac, "keep:mac"],
            CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={CONF_DEVICE_TRACKER_ENABLED: True},
        entry_id="entity-rm-missing-parent",
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)

    entity_registry = MagicMock()
    entity_registry.async_get_entity_id = MagicMock(return_value=None)
    monkeypatch.setattr(dt_mod.er, "async_get", MagicMock(return_value=entity_registry))

    missing_parent_id = "missing-router-device-id"
    stale_device = MagicMock(
        id="stale-router-device",
        via_device_id=missing_parent_id,
        config_entries={entry.entry_id},
    )
    devices = {
        stale_router_mac: stale_device,
    }

    def get_device(
        *,
        identifiers: set[tuple[str, str]] | None = None,
        connections: set[tuple[str, str]] | None = None,
    ) -> Any:
        """Return fake stale tracker devices and missing router lookup results."""
        if identifiers is not None:
            return None
        if connections is not None:
            return devices[next(iter(connections))[1]]
        return None

    device_registry = MagicMock()
    device_registry.async_get_device = MagicMock(side_effect=get_device)
    device_registry.async_get = MagicMock(return_value=None)
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", MagicMock(return_value=device_registry))

    ph_hass.config_entries.async_update_entry = MagicMock()
    await dt_mod.async_setup_entry(ph_hass, entry, MagicMock())

    device_registry.async_get.assert_called_once_with(missing_parent_id)
    device_registry.async_update_device.assert_called_once_with(
        stale_device.id,
        remove_config_entry_id=entry.entry_id,
        via_device_id=None,
    )
