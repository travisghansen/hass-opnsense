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
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.entity_platform import AddEntitiesCallback
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

import custom_components.opnsense as init_mod
from custom_components.opnsense.const import (
    CONF_DEVICE_TRACKER_CONSIDER_HOME,
    CONF_DEVICE_TRACKER_ENABLED,
    CONF_DEVICE_UNIQUE_ID,
    CONF_DEVICES,
    DEVICE_TRACKER_COORDINATOR,
    DOMAIN,
    SHOULD_RELOAD,
    TRACKED_ARP_MACS,
    TRACKED_MACS,
    TRACKED_NDP_MACS,
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
        coordinator (MagicMock): Device tracker coordinator used by the entity.
        make_config_entry (Callable[..., MockConfigEntry]): Fixture that creates a mock config
            entry.
        coordinator_data (object | None): Optional coordinator data to install before creating the
            entity.
        enabled_default (bool): Whether the entity should be enabled by default.
        mac (str): MAC address tracked by the entity.

    Returns:
        OPNsenseScannerEntity: A scanner entity for the requested MAC address.
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
    """Configured MACs should be normalized and deduplicated before entity creation.

    Args:
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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


def test_devices_from_tracker_entries_merges_dual_stack_and_skips_invalid_ndp_rows() -> None:
    """Valid NDP rows should merge with ARP metadata by canonical MAC."""
    devices, mac_addresses = dt_mod._devices_from_tracker_entries(
        [
            {
                "mac": "AA-BB-CC-DD-EE-01",
                "ip": "192.0.2.10",
                "hostname": "client?",
            }
        ],
        [
            {
                "mac": "aa:bb:cc:dd:ee:01",
                "ip": "2001:0db8::10",
                "manufacturer": "Example Vendor",
            },
            {"mac": "aa:bb:cc", "ip": "2001:db8::11"},
            {"mac": "00:11:22:33:44:55", "ip": "not-an-ip"},
        ],
    )

    assert mac_addresses == ["aa:bb:cc:dd:ee:01"]
    assert devices == [
        {
            "mac": "aa:bb:cc:dd:ee:01",
            "hostname": "client",
            "manufacturer": "Example Vendor",
        }
    ]


@pytest.mark.asyncio
async def test_async_setup_entry_configured_devices(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """Setup creates device tracker entities for configured MACs.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        fake_reg_factory (Any): Factory for the in-memory entity registry test double.
    """
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
            ents (Iterable[Any]): Ents provided by pytest or the test case.
            _update_before_add (bool): Whether Home Assistant requested an update before adding the entities.
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
    assert created._router_device_id == "router-device-id"
    device_info = created.device_info
    assert device_info is not None
    assert device_info["via_device_id"] == "router-device-id"
    assert "via_device" not in device_info
    fake.async_get_or_create.assert_called_once_with(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, "dev1")},
    )
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
    """Malformed ARP rows should not prevent valid device trackers from being created.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        fake_reg_factory (Any): Factory for the in-memory entity registry test double.
    """
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
async def test_async_setup_entry_discovers_ipv6_only_tracker(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """Track-all setup should create one tracker for a valid NDP-only MAC.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate registry access.
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        fake_reg_factory (Any): Factory for the in-memory device registry test double.
    """
    coordinator.data = {
        "arp_table": [],
        "ndp_table": [
            {
                "mac": "AA-BB-CC-DD-EE-01",
                "ip": "2001:db8::1",
                "manufacturer": "Example Vendor",
            }
        ],
    }
    entry = make_config_entry(
        data={TRACKED_MACS: [], CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={CONF_DEVICE_TRACKER_ENABLED: True},
        entry_id="e_ndp_only",
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    ph_hass.config_entries.async_update_entry = MagicMock()
    fake = fake_reg_factory(device_exists=False)
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: fake, raising=False)
    added: list[Any] = []

    await dt_mod.async_setup_entry(ph_hass, entry, cast("AddEntitiesCallback", added.extend))

    assert len(added) == 1
    assert added[0].mac_address == "aa:bb:cc:dd:ee:01"
    assert added[0]._mac_vendor == "Example Vendor"
    updated_data = ph_hass.config_entries.async_update_entry.call_args.kwargs["data"]
    assert updated_data[TRACKED_MACS] == ["aa:bb:cc:dd:ee:01"]
    assert updated_data[TRACKED_ARP_MACS] == []
    assert updated_data[TRACKED_NDP_MACS] == ["aa:bb:cc:dd:ee:01"]


@pytest.mark.asyncio
async def test_async_setup_entry_removes_nonmatching_tracked_macs(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """Ensure previously-tracked MACs not present in current devices are removed.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        fake_reg_factory (Any): Factory for the in-memory entity registry test double.
    """
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
            ents (Iterable[Any]): Ents provided by pytest or the test case.
            _update_before_add (bool): Whether Home Assistant requested an update before adding the entities.
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
    """Coordinator with invalid data should mark entity unavailable.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
    """Coordinator arp entry populates entity attributes correctly.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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


def test_handle_coordinator_update_empty_data_keeps_connected_tracker_unavailable(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Empty coordinator data must not turn a connected tracker into an away observation.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake config entry.
    """
    entry = make_config_entry(
        data={CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={CONF_DEVICE_TRACKER_CONSIDER_HOME: 0},
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    coordinator.data = {"arp_table": [{"mac": "aa:bb:cc", "ip": "192.0.2.1"}]}
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

    assert ent.available is True
    assert ent.is_connected is True

    coordinator.data = {}
    ent._handle_coordinator_update()

    assert ent.available is False
    assert ent.is_connected is True


@pytest.mark.parametrize(
    ("missing_table", "successful_table", "successful_entry", "expected_ipv4", "expected_ipv6"),
    [
        pytest.param(
            "arp_table",
            "ndp_table",
            {"mac": "aa:bb:cc:dd:ee:01", "ip": "2001:db8::2"},
            ["192.0.2.1"],
            ["2001:db8::2"],
            id="missing-arp-with-ndp-sighting",
        ),
        pytest.param(
            "ndp_table",
            "arp_table",
            {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.0.2.2"},
            ["192.0.2.2"],
            ["2001:db8::1"],
            id="missing-ndp-with-arp-sighting",
        ),
    ],
)
def test_handle_coordinator_update_missing_table_preserves_cached_family(
    missing_table: str,
    successful_table: str,
    successful_entry: dict[str, str],
    expected_ipv4: list[str],
    expected_ipv6: list[str],
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """A missing family is failed while a valid sighting from the other family still applies.

    Args:
        missing_table (str): Neighbor table omitted from the latest coordinator data.
        successful_table (str): Neighbor table containing a fresh matching sighting.
        successful_entry (dict[str, str]): Fresh row in the successful neighbor table.
        expected_ipv4 (list[str]): Preserved and current IPv4 addresses.
        expected_ipv6 (list[str]): Preserved and current IPv6 addresses.
        coordinator (MagicMock): Mock coordinator supplying entity data.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake config entry.
    """
    coordinator_data = {
        "arp_table": [{"mac": "aa:bb:cc:dd:ee:01", "ip": "192.0.2.1"}],
        "ndp_table": [{"mac": "aa:bb:cc:dd:ee:01", "ip": "2001:db8::1"}],
    }
    ent = _make_scanner_entity(
        coordinator=coordinator,
        make_config_entry=make_config_entry,
        coordinator_data=coordinator_data,
        mac="aa:bb:cc:dd:ee:01",
    )
    object.__setattr__(ent, "async_write_ha_state", MagicMock())
    ent._handle_coordinator_update()

    coordinator.data = {
        successful_table: [successful_entry],
        "update_time": 1_800_000_500.0,
    }
    ent._handle_coordinator_update()

    assert ent.available is True
    assert ent.is_connected is True
    attributes = ent.extra_state_attributes
    assert attributes is not None
    assert attributes["ipv4_addresses"] == expected_ipv4
    assert attributes["ipv6_addresses"] == expected_ipv6
    assert missing_table not in coordinator.data


def test_entity_registry_enabled_default_uses_existing_mac_device(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """Auto-discovered trackers should be enabled when HA can link a MAC device.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        fake_reg_factory (Any): Factory for the in-memory entity registry test double.
    """
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
    """Suggested object IDs should prefer hostnames and otherwise use the MAC.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        fake_reg_factory (Any): Factory for the in-memory entity registry test double.
        hostname (str | None): Hostname used to derive the tracker object ID.
        expected_object_id (str): Expected object ID derived from the tracker identity.
    """
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
    """Configured trackers should keep their requested enabled-by-default state.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
    """Trackers without a MAC cannot link to an enabled MAC device.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
    """Existing MAC matches should still link while the new-entity preference is enabled.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        fake_reg_factory (Any): Factory for the in-memory entity registry test double.
    """
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
    """Auto-discovered trackers should stay disabled when no matching device exists.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
            """Return the fallback device only after it is marked as present.

            Args:
                _args (Any): Additional positional arguments accepted by the test double.
                _kwargs (Any): Additional keyword arguments accepted by the test double.

            Returns:
                Any: Matching fake registry object, or ``None`` when absent.
            """
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
    """Disabled matching MAC devices should keep fallback device_info-based linking.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        fake_reg_factory (Any): Factory for the in-memory entity registry test double.
    """
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
    """Malformed ARP entries should be skipped while searching for the tracked MAC.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
    """Nonmatching ARP mapping entries should be skipped while searching.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
    """Coordinator matching should include uppercase/lowercase MAC variations.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
    """Tracker update should still read `ip-address` when `ip` is absent.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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


def test_handle_coordinator_update_merges_ipv4_and_ipv6_addresses_and_ages_failed_ndp(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Dual-stack rows should share one tracker and cached NDP data must not refresh presence.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
    mac_address = "aa:bb:cc:dd:ee:01"
    ndp_row = {"mac": mac_address, "ip": "2001:0db8::10", "intf_description": "lan"}
    ndp_rows = [
        ndp_row,
        {"mac": "AA-BB-CC-DD-EE-01", "ip": "2001:db8::10"},
        {"mac": mac_address, "ip": "2001:db8::11"},
        {"mac": mac_address, "ip": "fe80::1%em0", "intf": "em0"},
    ]
    coordinator.data = {
        "arp_table": [{"mac": mac_address, "ip": "192.0.2.10", "hostname": "client"}],
        "ndp_table": ndp_rows,
        "update_time": 1_800_000_000.0,
    }
    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    entity = OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac=mac_address,
        mac_vendor=None,
        hostname=None,
    )
    write_state = MagicMock()
    object.__setattr__(entity, "async_write_ha_state", write_state)

    entity._handle_coordinator_update()

    first_observation_time = entity._last_known_connected_time
    attributes = entity.extra_state_attributes
    assert attributes is not None
    assert entity.is_connected is True
    assert entity.ip_address == "192.0.2.10"
    assert attributes["ipv4_addresses"] == ["192.0.2.10"]
    assert attributes["ipv6_addresses"] == [
        "2001:db8::10",
        "2001:db8::11",
        "fe80::1%em0",
    ]

    coordinator.data = {
        "arp_table": [],
        "ndp_table": [ndp_row],
        "unavailable_device_tracker_tables": ["ndp_table"],
        "update_time": 1_800_000_500.0,
    }
    entity._handle_coordinator_update()

    assert entity.available is False
    assert entity.is_connected is True
    assert entity._last_known_connected_time == first_observation_time
    attributes = entity.extra_state_attributes
    assert attributes is not None
    assert attributes["ipv6_addresses"] == [
        "2001:db8::10",
        "2001:db8::11",
        "fe80::1%em0",
    ]


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
    """Malformed rows in arp_table should be skipped and valid rows still apply.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
    """If missing entry and within consider_home, entity remains connected.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
    """Expired ARP entries outside consider_home should stay disconnected.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
    """Restoring state should return when Home Assistant has no saved snapshot.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
    """Restoring last state merges saved attributes into the entity.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
        router_device_id="router-device-id",
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
    assert devinfo is not None
    assert any(t[1] == "aa:bb:cc" for t in devinfo["connections"])
    assert devinfo["name"] == "dev"
    assert devinfo["manufacturer"] == "mfg"
    assert devinfo["via_device_id"] == "router-device-id"
    assert "default_name" not in devinfo
    assert "default_manufacturer" not in devinfo
    assert "via_device" not in devinfo


@pytest.mark.asyncio
async def test_restored_ipv6_tracker_stays_unavailable_when_ndp_lookup_is_denied(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """A denied NDP lookup must not turn restored IPv6 presence into an away observation.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
    coordinator.data = {
        "arp_table": [],
        "ndp_table": None,
        "unavailable_device_tracker_tables": ["ndp_table"],
    }
    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    entity = OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc:dd:ee:01",
        mac_vendor=None,
        hostname=None,
    )
    last_state = MagicMock()
    last_state.attributes = {
        "ipv6_addresses": ["2001:db8::1"],
        "last_known_ip": "2001:db8::1",
        "last_known_connected_time": datetime.now(UTC).isoformat(),
    }
    object.__setattr__(entity, "async_get_last_state", AsyncMock(return_value=last_state))
    object.__setattr__(entity, "async_write_ha_state", MagicMock())

    await entity._restore_last_state()
    entity._handle_coordinator_update()

    assert entity.available is False
    attributes = entity.extra_state_attributes
    assert attributes is not None
    assert attributes["ipv6_addresses"] == ["2001:db8::1"]


@pytest.mark.parametrize(
    ("legacy_ip", "failed_table", "ipv4_addresses", "ipv6_addresses"),
    [
        ("192.0.2.8", "arp_table", ["192.0.2.8"], []),
        ("2001:db8::8", "ndp_table", [], ["2001:db8::8"]),
    ],
    ids=["legacy-ipv4-arp-failure", "legacy-ipv6-ndp-failure"],
)
@pytest.mark.asyncio
async def test_restored_legacy_ip_preserves_family_during_table_failure(
    legacy_ip: str,
    failed_table: str,
    ipv4_addresses: list[str],
    ipv6_addresses: list[str],
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Legacy scalar IP state should preserve family presence during a lookup failure.

    Args:
        legacy_ip (str): Scalar IP address in the legacy saved-state format.
        failed_table (str): Neighbor table whose lookup failed.
        ipv4_addresses (list[str]): Expected restored IPv4 address list.
        ipv6_addresses (list[str]): Expected restored IPv6 address list.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
    coordinator.data = {
        "arp_table": None if failed_table == "arp_table" else [],
        "ndp_table": None if failed_table == "ndp_table" else [],
        "unavailable_device_tracker_tables": [failed_table],
    }
    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    entity = OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc:dd:ee:08",
        mac_vendor=None,
        hostname=None,
    )
    last_known_connected_time = datetime.now(UTC) - timedelta(minutes=5)
    last_state = MagicMock()
    last_state.attributes = {
        "last_known_ip": legacy_ip,
        "last_known_connected_time": last_known_connected_time.isoformat(),
    }
    object.__setattr__(entity, "async_get_last_state", AsyncMock(return_value=last_state))
    object.__setattr__(entity, "async_write_ha_state", MagicMock())

    await entity._restore_last_state()
    entity._handle_coordinator_update()

    assert entity.available is False
    assert entity._last_known_connected_time == last_known_connected_time
    attributes = entity.extra_state_attributes
    assert attributes is not None
    assert attributes["ipv4_addresses"] == ipv4_addresses
    assert attributes["ipv6_addresses"] == ipv6_addresses


@pytest.mark.parametrize("previously_observed", [False, True])
def test_valid_ndp_sighting_survives_unrelated_malformed_row(
    previously_observed: bool,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Usable IPv6 sightings refresh presence even when another neighbor row is incomplete.

    Args:
        previously_observed (bool): Whether the tracker already has a saved IPv6 observation.
        coordinator (MagicMock): Coordinator supplying neighbor observations.
        make_config_entry (Callable[..., MockConfigEntry]): Configuration entry factory.
    """
    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    entity = OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc:dd:ee:01",
        mac_vendor=None,
        hostname=None,
    )
    object.__setattr__(entity, "async_write_ha_state", MagicMock())
    if previously_observed:
        coordinator.data = {
            "arp_table": [],
            "ndp_table": [{"mac": "aa:bb:cc:dd:ee:01", "ip": "2001:db8::1"}],
            "update_time": 1_800_000_000.0,
        }
        entity._handle_coordinator_update()
    coordinator.data = {
        "arp_table": [],
        "ndp_table": [
            {"mac": "aa:bb:cc:dd:ee:01", "ip": "2001:db8::2"},
            {"ip": "2001:db8::3"},
        ],
        "update_time": 1_900_000_000.0,
    }

    entity._handle_coordinator_update()

    assert entity.available is True
    assert entity.is_connected is True
    assert entity._last_known_connected_time is not None
    assert entity._last_known_connected_time.timestamp() == 1_900_000_000.0
    attributes = entity.extra_state_attributes
    assert attributes is not None
    assert attributes["ipv6_addresses"] == (
        ["2001:db8::1", "2001:db8::2"] if previously_observed else ["2001:db8::2"]
    )


def test_malformed_ndp_inventory_does_not_age_ipv6_tracker(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Malformed NDP rows preserve prior IPv6 presence without refreshing its sighting time.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    entity = OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc:dd:ee:02",
        mac_vendor=None,
        hostname=None,
    )
    object.__setattr__(entity, "async_write_ha_state", MagicMock())
    coordinator.data = {
        "arp_table": [],
        "ndp_table": [{"mac": "aa:bb:cc:dd:ee:02", "ip": "2001:db8::2", "intf": "em0"}],
        "update_time": 1_800_000_000.0,
    }

    entity._handle_coordinator_update()
    first_observation_time = entity._last_known_connected_time

    coordinator.data = {
        "arp_table": [],
        "ndp_table": [{"ip": "2001:db8::3"}],
        "update_time": 1_900_000_000.0,
    }
    entity._handle_coordinator_update()

    assert entity.available is False
    assert entity.is_connected is True
    assert entity._last_known_connected_time == first_observation_time
    attributes = entity.extra_state_attributes
    assert attributes is not None
    assert attributes["ipv6_addresses"] == ["2001:db8::2"]


def test_device_info_uses_legacy_parent_identifier(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Retain identifier-based parent linking for Home Assistant 2026.3-2026.7.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
    entity = _make_scanner_entity(coordinator, make_config_entry)

    device_info = entity.device_info

    assert device_info is not None
    assert dict(device_info)["via_device"] == (DOMAIN, "dev1")
    assert "via_device_id" not in device_info
    assert "default_name" not in device_info
    assert "default_manufacturer" not in device_info


@pytest.mark.asyncio
async def test_restore_last_state_uses_datetime_and_skips_empty_attributes(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Restoring state should preserve datetime values and ignore empty saved attributes.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
    """Aware datetime values should restore into tracker state.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        connected_time (datetime | str): Connection timestamp value supplied for tracker normalization.
    """
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
    """Restoring state should ignore invalid saved connection timestamps.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        connected_time (str | int): Connection timestamp value supplied for tracker normalization.
    """
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
    """Restoring state should ignore snapshots with malformed attributes.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
    """Entity.async_added_to_hass should call state restoration.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
async def test_async_internal_added_to_hass_creates_integration_device_for_existing_mac(
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Scanner entity should create its integration device for an existing MAC.

    Args:
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
    coordinator.data = {"arp_table": []}
    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"}, entry_id="entry-1")
    entry.add_to_hass(ph_hass)
    existing_entry = make_config_entry(
        data={CONF_DEVICE_UNIQUE_ID: "other"}, entry_id="existing-entry"
    )
    existing_entry.add_to_hass(ph_hass)
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    mac_address = "aa:bb:cc:dd:ee:ff"
    ent = OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac=mac_address,
        mac_vendor=None,
        hostname=None,
    )
    ent.hass = ph_hass
    ent.platform = MagicMock(config_entry=entry, platform_name=DOMAIN)

    device_reg = dr.async_get(ph_hass)
    existing_device = device_reg.async_get_or_create(
        config_entry_id="existing-entry",
        connections={(dr.CONNECTION_NETWORK_MAC, mac_address)},
    )
    assert (
        device_reg.async_get_device_by_connection(
            (dr.CONNECTION_NETWORK_MAC, mac_address), existing_entry.entry_id
        )
        == existing_device
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

    device_id = ent.registry_entry.device_id
    assert device_id is not None
    linked_device = device_reg.async_get(device_id)
    assert isinstance(linked_device, dr.DeviceEntry)
    assert linked_device.id != existing_device.id
    assert (dr.CONNECTION_NETWORK_MAC, mac_address) in linked_device.connections
    assert entry.entry_id in linked_device.config_entries


@pytest.mark.asyncio
async def test_async_internal_added_to_hass_keeps_fallback_device_info_without_match(
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Scanner entity should keep its fallback device info when no MAC device exists.

    Args:
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
    """Setup exits early when coordinator state is not a mapping.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        fake_reg_factory (Any): Factory for the in-memory entity registry test double.
    """
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
    """Missing ARP payload should keep device tracker reconciliation incomplete.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
    coordinator.data = {}
    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)

    recorded: dict[str, Any] = {}

    def capture(_entry: MockConfigEntry, _platform: str, entities: Any | None = None) -> None:
        """Capture the desired-entity payload sent to reconciliation.

        Args:
            _entry (MockConfigEntry): Config entry passed through the mocked platform loader.
            _platform (str): Platform name passed through the mocked loader.
            entities (Any | None): Entities captured by the platform add callback.
        """
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
    """An explicit empty ARP table is still authoritative for tracker reconciliation.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
    coordinator.data = {"arp_table": []}
    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)

    recorded: dict[str, Any] = {}

    def capture(_entry: MockConfigEntry, _platform: str, entities: Any | None = None) -> None:
        """Capture the desired-entity payload sent to reconciliation.

        Args:
            _entry (MockConfigEntry): Config entry passed through the mocked platform loader.
            _platform (str): Platform name passed through the mocked loader.
            entities (Any | None): Entities captured by the platform add callback.
        """
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
    """Track-all mode should fail reconciliation if any ARP row cannot compile.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
        """Capture the desired-entity payload sent to reconciliation.

        Args:
            _entry (MockConfigEntry): Config entry passed through the mocked platform loader.
            _platform (str): Platform name passed through the mocked loader.
            entities (Any | None): Entities captured by the platform add callback.
        """
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
async def test_async_setup_entry_records_entities_for_invalid_mapping_rows_in_track_all(
    monkeypatch: pytest.MonkeyPatch,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Track-all should ignore non-entity mapping rows with unusable MAC values.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
    coordinator.data = {
        "arp_table": [
            {"mac": None},
            {"mac": ""},
            {"mac": 1234},
            {"hostname": "invalid"},
            {"mac": "AA-BB-CC-DD-EE-FF", "hostname": "good"},
        ]
    }
    entry = make_config_entry(
        data={CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={CONF_DEVICES: [], CONF_DEVICE_TRACKER_ENABLED: True},
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    recorded: dict[str, Any] = {}
    added: list[Any] = []

    def capture(_entry: MockConfigEntry, _platform: str, entities: Any | None = None) -> None:
        """Capture the desired-entity payload sent to reconciliation.

        Args:
            _entry (MockConfigEntry): Config entry passed through the mocked platform loader.
            _platform (str): Platform name passed through the mocked loader.
            entities (Any | None): Entities captured by the platform add callback.
        """
        recorded["entities"] = entities

    monkeypatch.setattr(dt_mod, "record_desired_entities", capture)

    await dt_mod.async_setup_entry(
        MagicMock(),
        entry,
        cast("AddEntitiesCallback", lambda entities, _=False: added.extend(entities)),
    )

    assert "entities" in recorded
    assert isinstance(recorded["entities"], list)
    assert [entity.mac_address for entity in recorded["entities"]] == ["aa:bb:cc:dd:ee:ff"]
    assert len(added) == 1
    assert added[0].mac_address == "aa:bb:cc:dd:ee:ff"


@pytest.mark.asyncio
async def test_async_setup_entry_records_entities_for_duplicate_macs_in_track_all(
    monkeypatch: pytest.MonkeyPatch,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Track-all mode should treat duplicate normalized MAC rows as authoritative.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
        """Capture the desired-entity payload sent to reconciliation.

        Args:
            _entry (MockConfigEntry): Config entry passed through the mocked platform loader.
            _platform (str): Platform name passed through the mocked loader.
            entities (Any | None): Entities captured by the platform add callback.
        """
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
    """Explicit configured-MAC mode should ignore track-all completeness failures.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
        """Capture the desired-entity payload sent to reconciliation.

        Args:
            _entry (MockConfigEntry): Config entry passed through the mocked platform loader.
            _platform (str): Platform name passed through the mocked loader.
            entities (Any | None): Entities captured by the platform add callback.
        """
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
    """Setup removes previously tracked MAC addresses when reconfiguring.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        fake_reg_factory (Any): Factory for the in-memory entity registry test double.
    """
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
    """Active reconciliation owns stale deletion, including tracker devices.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        fake_reg_factory (Any): Factory for the in-memory entity registry test double.
    """
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
    """Expired ARP entries set entity to disconnected and update attributes.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
    """Malformed ARP expiry data should not hide other valid ARP attributes.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
    """Handle TypeError when entry IP is None and avoid crashing.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
    """Expired entries preserve last_known_ip when no IP present.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
    """Setup from ARP entries creates device trackers for present ARP rows.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        fake_reg_factory (Any): Factory for the in-memory entity registry test double.
    """
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
    """Stale MAC cleanup reassigns shared parents to surviving OPNsense routers.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
        """Return the registered tracker entity for a stale unique ID.

        Returns:
            str | None: Registered entity ID for the stale unique ID, if present.

        Args:
            domain (str): Entity domain used for the fake registry lookup.
            platform (str): Integration platform used for the fake registry lookup.
            unique_id (str): Stale tracker unique ID resolved by the fake registry.
        """
        return entity_ids.get(unique_id)

    entity_registry.async_get_entity_id.side_effect = get_entity_id
    monkeypatch.setattr(er, "async_get", MagicMock(return_value=entity_registry))

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
        """Return the fake router or stale device for the requested lookup.

        Returns:
            Any: Matching fake registry object, or ``None`` when absent.

        Args:
            identifiers (set[tuple[str, str]] | None): Device identifiers used for the fake registry lookup.
            connections (set[tuple[str, str]] | None): Device connections used for the fake registry lookup.
        """
        if identifiers is not None:
            key = next(iter(identifiers))
            return identifier_router_map.get(key)
        if connections is not None:
            return devices[next(iter(connections))[1]]
        return None

    device_registry = MagicMock()
    device_registry.async_get_device.side_effect = get_device
    device_registry.async_get_device_by_identifier.side_effect = (
        lambda identifier, _config_entry_id: get_device(identifiers={identifier})
    )
    device_registry.async_get_device_by_connection.side_effect = (
        lambda connection, _config_entry_id: get_device(connections={connection})
    )
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
    """Clear stale tracker parent assignment when router lookup is no longer available.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
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
    monkeypatch.setattr(er, "async_get", MagicMock(return_value=entity_registry))

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
        """Return fake stale tracker devices and missing router lookup results.

        Returns:
            Any: Matching fake registry object, or ``None`` when absent.

        Args:
            identifiers (set[tuple[str, str]] | None): Device identifiers used for the fake registry lookup.
            connections (set[tuple[str, str]] | None): Device connections used for the fake registry lookup.
        """
        if identifiers is not None:
            return None
        if connections is not None:
            return devices[next(iter(connections))[1]]
        return None

    device_registry = MagicMock()
    device_registry.async_get_device = MagicMock(side_effect=get_device)
    device_registry.async_get_device_by_identifier.side_effect = (
        lambda identifier, _config_entry_id: get_device(identifiers={identifier})
    )
    device_registry.async_get_device_by_connection.side_effect = (
        lambda connection, _config_entry_id: get_device(connections={connection})
    )
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failed_state",
    [{}, {"arp_table": None}],
    ids=["refresh_returned_no_state", "arp_table_missing"],
)
async def test_async_setup_entry_keeps_trackers_when_first_refresh_fails(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
    failed_state: dict[str, Any],
) -> None:
    """A failed first refresh must not remove trackers that already exist.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        fake_reg_factory (Any): Factory for the in-memory entity registry test double.
        failed_state (dict[str, Any]): Coordinator payload left behind by a failed refresh.
    """
    coordinator.data = failed_state
    entry = make_config_entry(
        data={
            TRACKED_MACS: ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"],
            CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={CONF_DEVICE_TRACKER_ENABLED: True},
        entry_id="e_failed_refresh",
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    fake = fake_reg_factory(device_exists=True, device_id="router-device")
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: fake, raising=False)
    monkeypatch.setattr(dt_mod, "is_reconciliation_active", lambda _entry: False)
    cleanup = MagicMock()
    monkeypatch.setattr(dt_mod, "_cleanup_stale_tracked_devices", cleanup)
    record = MagicMock()
    monkeypatch.setattr(dt_mod, "record_desired_entities", record)
    ph_hass.config_entries.async_update_entry = MagicMock()
    added: list[Any] = []

    await dt_mod.async_setup_entry(ph_hass, entry, cast("AddEntitiesCallback", added.extend))

    assert sorted(entity.mac_address for entity in added) == [
        "aa:bb:cc:dd:ee:01",
        "aa:bb:cc:dd:ee:02",
    ]
    cleanup.assert_not_called()
    ph_hass.config_entries.async_update_entry.assert_not_called()
    record.assert_called_once_with(entry, "device_tracker", None)


@pytest.mark.asyncio
async def test_async_setup_entry_empty_arp_table_still_removes_stale_trackers(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """An empty ARP table stays authoritative, unlike a missing one, so stale trackers are removed.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        fake_reg_factory (Any): Factory for the in-memory entity registry test double.
    """
    coordinator.data = {"arp_table": []}
    entry = make_config_entry(
        data={TRACKED_MACS: ["aa:bb:cc:dd:ee:01"], CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={CONF_DEVICE_TRACKER_ENABLED: True},
        entry_id="e_empty_arp",
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    fake = fake_reg_factory(device_exists=True, device_id="router-device")
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: fake, raising=False)
    monkeypatch.setattr(dt_mod, "is_reconciliation_active", lambda _entry: False)
    cleanup = MagicMock()
    monkeypatch.setattr(dt_mod, "_cleanup_stale_tracked_devices", cleanup)
    monkeypatch.setattr(dt_mod, "record_desired_entities", MagicMock())
    ph_hass.config_entries.async_update_entry = MagicMock()

    await dt_mod.async_setup_entry(
        ph_hass, entry, cast("AddEntitiesCallback", lambda _entities: None)
    )

    cleanup.assert_called_once()
    assert cleanup.call_args.kwargs["current_mac_addresses"] == []


@pytest.mark.asyncio
async def test_async_setup_entry_retains_only_failed_family_inventory(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """An NDP failure should retain IPv6-only trackers and reconcile successful ARP rows.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate registry access.
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        fake_reg_factory (Any): Factory for the in-memory device registry test double.
    """
    arp_mac = "aa:bb:cc:dd:ee:01"
    ndp_mac = "aa:bb:cc:dd:ee:02"
    coordinator.data = {
        "arp_table": [],
        "ndp_table": None,
        "unavailable_device_tracker_tables": ["ndp_table"],
    }
    entry = make_config_entry(
        data={
            TRACKED_MACS: [arp_mac, ndp_mac],
            TRACKED_ARP_MACS: [arp_mac],
            TRACKED_NDP_MACS: [ndp_mac],
            CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={CONF_DEVICE_TRACKER_ENABLED: True},
        entry_id="e_partial_neighbor_failure",
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    fake = fake_reg_factory(device_exists=True, device_id="router-device")
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: fake, raising=False)
    monkeypatch.setattr(dt_mod, "is_reconciliation_active", lambda _entry: False)
    cleanup = MagicMock()
    monkeypatch.setattr(dt_mod, "_cleanup_stale_tracked_devices", cleanup)
    record = MagicMock()
    monkeypatch.setattr(dt_mod, "record_desired_entities", record)
    ph_hass.config_entries.async_update_entry = MagicMock()
    added: list[Any] = []

    await dt_mod.async_setup_entry(ph_hass, entry, cast("AddEntitiesCallback", added.extend))

    assert [entity.mac_address for entity in added] == [ndp_mac]
    cleanup.assert_called_once()
    assert cleanup.call_args.kwargs["current_mac_addresses"] == [ndp_mac]
    updated_data = ph_hass.config_entries.async_update_entry.call_args.kwargs["data"]
    assert updated_data[TRACKED_MACS] == [ndp_mac]
    assert updated_data[TRACKED_ARP_MACS] == []
    assert updated_data[TRACKED_NDP_MACS] == [ndp_mac]


@pytest.mark.asyncio
async def test_setup_inventory_write_preserves_next_options_reload(
    monkeypatch: pytest.MonkeyPatch,
    hass: HomeAssistant,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """An upgrade inventory write must not suppress the next real options update.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture isolating registry and reload operations.
        hass (HomeAssistant): Home Assistant instance delivering entry update notifications.
        coordinator (MagicMock): Coordinator exposing a successful neighbor inventory.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for configuration entries.
        fake_reg_factory (Any): Factory for the device registry test double.
    """
    mac_address = "aa:bb:cc:dd:ee:01"
    entry = make_config_entry(
        data={TRACKED_MACS: [mac_address], CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={CONF_DEVICE_TRACKER_ENABLED: True},
    )
    entry.add_to_hass(hass)
    setattr(entry.runtime_data, SHOULD_RELOAD, True)
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    coordinator.data = {
        "arp_table": [{"mac": mac_address, "ip": "192.0.2.10"}],
        "ndp_table": [],
    }
    registry = fake_reg_factory(device_exists=False)
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: registry)
    reload_entry = AsyncMock(return_value=True)
    monkeypatch.setattr(hass.config_entries, "async_reload", reload_entry)

    await dt_mod.async_setup_entry(hass, entry, MagicMock())
    assert entry.data[TRACKED_ARP_MACS] == [mac_address]

    # Main setup registers this listener only after platform forwarding finishes.
    entry.async_on_unload(entry.add_update_listener(init_mod._async_update_listener))
    hass.config_entries.async_update_entry(
        entry,
        options={CONF_DEVICE_TRACKER_ENABLED: True, CONF_DEVICE_TRACKER_CONSIDER_HOME: 30},
    )
    await hass.async_block_till_done()

    reload_entry.assert_awaited_once_with(entry.entry_id)


@pytest.mark.asyncio
async def test_poll_inventory_write_does_not_suppress_next_options_reload(
    monkeypatch: pytest.MonkeyPatch,
    hass: HomeAssistant,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """A poll-driven family update consumes its marker before a later options reload.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture isolating registry and reload operations.
        hass (HomeAssistant): Home Assistant instance delivering entry update notifications.
        coordinator (MagicMock): Coordinator exposing neighbor inventory and listeners.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for configuration entries.
        fake_reg_factory (Any): Factory for the device registry test double.
    """
    mac_address = "aa:bb:cc:dd:ee:01"
    entry = make_config_entry(
        data={
            TRACKED_MACS: [mac_address],
            TRACKED_ARP_MACS: [mac_address],
            TRACKED_NDP_MACS: [],
            CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={CONF_DEVICE_TRACKER_ENABLED: True},
    )
    entry.add_to_hass(hass)
    setattr(entry.runtime_data, SHOULD_RELOAD, True)
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    coordinator.data = {
        "arp_table": [{"mac": mac_address, "ip": "192.0.2.10"}],
        "ndp_table": [],
    }
    coordinator_listeners: list[Callable[[], None]] = []

    def capture_listener(listener: Callable[[], None]) -> Callable[[], None]:
        """Capture a coordinator callback and return its unload function.

        Args:
            listener (Callable[[], None]): Callback registered for coordinator updates.

        Returns:
            Callable[[], None]: No-op listener cleanup function.
        """
        coordinator_listeners.append(listener)
        return lambda: None

    coordinator.async_add_listener.side_effect = capture_listener
    registry = fake_reg_factory(device_exists=False)
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: registry)
    reload_entry = AsyncMock(return_value=True)
    monkeypatch.setattr(hass.config_entries, "async_reload", reload_entry)

    await dt_mod.async_setup_entry(hass, entry, MagicMock())
    assert len(coordinator_listeners) == 1
    entry.async_on_unload(entry.add_update_listener(init_mod._async_update_listener))

    coordinator.data = {
        "arp_table": [],
        "ndp_table": [{"mac": mac_address, "ip": "2001:db8::10"}],
    }
    coordinator_listeners[0]()
    await hass.async_block_till_done()

    assert entry.data[TRACKED_ARP_MACS] == []
    assert entry.data[TRACKED_NDP_MACS] == [mac_address]
    reload_entry.assert_not_awaited()
    assert getattr(entry.runtime_data, SHOULD_RELOAD) is True

    hass.config_entries.async_update_entry(
        entry,
        options={CONF_DEVICE_TRACKER_ENABLED: True, CONF_DEVICE_TRACKER_CONSIDER_HOME: 30},
    )
    await hass.async_block_till_done()

    reload_entry.assert_awaited_once_with(entry.entry_id)


@pytest.mark.asyncio
async def test_track_all_family_transition_is_persisted_once_and_survives_reload(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """Existing trackers record family transitions once and survive a later table outage.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate registry access.
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        fake_reg_factory (Any): Factory for the in-memory device registry test double.
    """
    mac_addresses = ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]
    coordinator.data = {
        "arp_table": [
            {"mac": mac_address, "ip": f"192.0.2.{index + 10}"}
            for index, mac_address in enumerate(mac_addresses)
        ],
        "ndp_table": [],
    }
    entry = make_config_entry(
        data={
            TRACKED_MACS: mac_addresses.copy(),
            TRACKED_ARP_MACS: mac_addresses.copy(),
            TRACKED_NDP_MACS: [],
            CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={CONF_DEVICE_TRACKER_ENABLED: True},
        entry_id="e_family_transition",
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    entry.async_on_unload = MagicMock()
    remove_listener = MagicMock()
    coordinator.async_add_listener = MagicMock(return_value=remove_listener)
    device_registry = fake_reg_factory(device_exists=False)
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: device_registry)
    monkeypatch.setattr(dt_mod, "record_desired_entities", MagicMock())
    update_entry = MagicMock(
        side_effect=lambda updated_entry, *, data: object.__setattr__(updated_entry, "data", data)
    )
    ph_hass.config_entries.async_update_entry = update_entry

    initially_added: list[Any] = []
    await dt_mod.async_setup_entry(
        ph_hass, entry, cast("AddEntitiesCallback", initially_added.extend)
    )

    assert [entity.mac_address for entity in initially_added] == mac_addresses
    assert all(not entity._attr_entity_registry_enabled_default for entity in initially_added)
    assert entry.async_on_unload.call_count == 1
    source_inventory_listener = coordinator.async_add_listener.call_args.args[0]

    coordinator.data = {
        "arp_table": [],
        "ndp_table": [
            {"mac": mac_address, "ip": f"2001:db8::{index + 1}"}
            for index, mac_address in enumerate(mac_addresses)
        ],
    }
    source_inventory_listener()
    source_inventory_listener()

    assert entry.data[TRACKED_ARP_MACS] == []
    assert entry.data[TRACKED_NDP_MACS] == mac_addresses
    assert update_entry.call_count == 1
    assert getattr(entry.runtime_data, SHOULD_RELOAD) is False

    coordinator.data = {
        "arp_table": [],
        "ndp_table": None,
        "unavailable_device_tracker_tables": ["ndp_table"],
    }
    after_reload: list[Any] = []
    await dt_mod.async_setup_entry(ph_hass, entry, cast("AddEntitiesCallback", after_reload.extend))

    assert [entity.mac_address for entity in after_reload] == mac_addresses
    assert entry.data[TRACKED_NDP_MACS] == mac_addresses
    assert update_entry.call_count == 1
    assert entry.async_on_unload.call_count == 2


@pytest.mark.parametrize(
    "ndp_row",
    [
        {"ip": "2001:db8::2"},
        {"mac": "", "ip": "2001:db8::2"},
        {"mac": "not-a-mac", "ip": "2001:db8::2"},
        {"mac": "aa:bb:cc:dd:ee:02", "ip": "not-an-ip"},
    ],
    ids=["missing-mac", "blank-mac", "invalid-mac", "invalid-ip"],
)
@pytest.mark.asyncio
async def test_async_setup_entry_preserves_ndp_tracker_for_unusable_rows(
    ndp_row: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """Unusable NDP rows must not reconcile away a previously discovered device.

    Args:
        ndp_row (dict[str, str]): Invalid NDP response row under test.
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate registry access.
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        fake_reg_factory (Any): Factory for the in-memory device registry test double.
    """
    ndp_mac = "aa:bb:cc:dd:ee:02"
    coordinator.data = {"arp_table": [], "ndp_table": [ndp_row]}
    entry = make_config_entry(
        data={
            TRACKED_MACS: [ndp_mac],
            TRACKED_ARP_MACS: [],
            TRACKED_NDP_MACS: [ndp_mac],
            CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={CONF_DEVICE_TRACKER_ENABLED: True},
        entry_id="e_invalid_ndp_row",
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    device_registry = fake_reg_factory(device_exists=False)
    entity_registry = MagicMock()
    entity_registry.async_get_entity_id.return_value = "device_tracker.device_ipv6"
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: device_registry)
    monkeypatch.setattr(er, "async_get", MagicMock(return_value=entity_registry))
    monkeypatch.setattr(dt_mod, "record_desired_entities", MagicMock())
    ph_hass.config_entries.async_update_entry = MagicMock()
    added: list[Any] = []

    await dt_mod.async_setup_entry(ph_hass, entry, cast("AddEntitiesCallback", added.extend))

    assert [entity.mac_address for entity in added] == [ndp_mac]
    assert entry.data[TRACKED_MACS] == [ndp_mac]
    assert entry.data[TRACKED_NDP_MACS] == [ndp_mac]
    entity_registry.async_get_entity_id.assert_not_called()
    entity_registry.async_remove.assert_not_called()


def test_devices_from_mac_addresses_skips_malformed_and_duplicate_macs() -> None:
    """Persisted MACs should be normalized and de-duplicated, dropping unusable values."""
    devices, mac_addresses = dt_mod._devices_from_mac_addresses(
        ["AA-BB-CC-DD-EE-01", None, "aa:bb:cc:dd:ee:01", "", "aa:bb:cc:dd:ee:02"]
    )

    assert mac_addresses == ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]
    assert devices == [{"mac": "aa:bb:cc:dd:ee:01"}, {"mac": "aa:bb:cc:dd:ee:02"}]
