"""Unit tests for the device_tracker component of the hass-opnsense integration.

These tests cover setup, coordinator update handling, restore state behavior,
and device info formatting for the integration's device tracker entities.
"""

from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
import logging
from types import MappingProxyType
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock, call, patch

from aiopnsense.exceptions import OPNsenseTimeoutError
from homeassistant.components.device_tracker import SourceType
from homeassistant.components.device_tracker.entity import BaseScannerEntity, ScannerEntity
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, State
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.entity_platform import AddEntitiesCallback, EntityPlatform
from homeassistant.util import slugify
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

import custom_components.opnsense as init_mod
from custom_components.opnsense.const import (
    CONF_DEVICE_TRACKER_CONSIDER_HOME,
    CONF_DEVICE_TRACKER_ENABLED,
    CONF_DEVICE_TRACKER_SCAN_INTERVAL,
    CONF_DEVICE_UNIQUE_ID,
    CONF_DEVICES,
    DEVICE_TRACKER_COORDINATOR,
    DOMAIN,
    SHOULD_RELOAD,
    TRACKED_ARP_MACS,
    TRACKED_MACS,
    TRACKED_NDP_MACS,
)
from custom_components.opnsense.coordinator import OPNsenseDataUpdateCoordinator
import custom_components.opnsense.device_tracker as dt_mod
from custom_components.opnsense.device_tracker import OPNsenseScannerEntity
from custom_components.opnsense.entity import OPNsenseBaseEntity
from custom_components.opnsense.helpers import device_belongs_to_config_entry


async def _restore_state(entity: OPNsenseScannerEntity) -> None:
    """Add the entity to Home Assistant so it restores its saved state.

    Args:
        entity (OPNsenseScannerEntity): Entity whose ``async_get_last_state`` is already stubbed.
    """
    with patch.object(OPNsenseBaseEntity, "async_added_to_hass", AsyncMock()):
        await entity.async_added_to_hass()


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
    coordinator.host_observation_times = None
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


@pytest.mark.parametrize(
    ("mac", "arp_entries", "ndp_entries", "expected"),
    [
        pytest.param(
            "aa:bb:cc",
            [
                object(),
                {"mac": "dd:ee:ff", "hostname": "other"},
                {"mac": "aa:bb:cc", "hostname": "tracked", "manufacturer": "maker"},
            ],
            [],
            {"mac": "aa:bb:cc", "hostname": "tracked", "manufacturer": "maker"},
            id="skips-malformed-and-nonmatching-arp",
        ),
        pytest.param("aa:bb:cc", [], [], {"mac": "aa:bb:cc"}, id="mac-only-fallback"),
        pytest.param(
            "aa:bb:cc",
            [{"mac-address": "AA-BB-CC"}, {"mac": "11:22:33"}],
            [],
            {"mac": "aa:bb:cc"},
            id="raw-arp-mac-key",
        ),
        pytest.param(
            "aa:bb:cc",
            [{"mac": 12345}, {"mac": "AA:BB:CC", "hostname": "TrackedHost", "manufacturer": "m"}],
            [],
            {"mac": "aa:bb:cc", "hostname": "TrackedHost", "manufacturer": "m"},
            id="case-insensitive-match-skips-bad-mac-types",
        ),
        pytest.param(
            "aa:bb:cc:dd:ee:01",
            [],
            [
                None,
                {"mac": "aa:bb:cc:dd:ee:01", "ip": "2001:db8::1", "manufacturer": "Example Vendor"},
            ],
            {"mac": "aa:bb:cc:dd:ee:01", "manufacturer": "Example Vendor"},
            id="skips-non-mapping-ndp-rows",
        ),
        pytest.param(
            "aa:bb:cc:dd:ee:01",
            [{"mac": "aa:bb:cc:dd:ee:01"}],
            [{"mac": "aa:bb:cc:dd:ee:01", "ip": "2001:db8::1", "manufacturer": "NDP Vendor"}],
            {"mac": "aa:bb:cc:dd:ee:01", "manufacturer": "NDP Vendor"},
            id="ndp-supplies-missing-manufacturer",
        ),
        pytest.param(
            "aa:bb:cc:dd:ee:01",
            [{"mac": "aa:bb:cc:dd:ee:01", "manufacturer": "ARP Vendor"}],
            [{"mac": "aa:bb:cc:dd:ee:01", "ip": "2001:db8::1", "manufacturer": "NDP Vendor"}],
            {"mac": "aa:bb:cc:dd:ee:01", "manufacturer": "ARP Vendor"},
            id="arp-manufacturer-wins",
        ),
        pytest.param(
            "aa:bb:cc:dd:ee:01",
            [{"mac": "aa:bb:cc:dd:ee:01"}],
            [{"mac": "aa:bb:cc:dd:ee:01", "ip": "2001:db8::1"}],
            {"mac": "aa:bb:cc:dd:ee:01"},
            id="ndp-without-manufacturer-adds-nothing",
        ),
    ],
)
def test_device_from_tracker_entries(
    mac: str,
    arp_entries: list[Any],
    ndp_entries: list[Any],
    expected: dict[str, Any],
) -> None:
    """Configured-device metadata comes from the matching ARP row, with NDP as a fallback.

    Args:
        mac (str): Configured MAC address being resolved.
        arp_entries (list[Any]): Raw ARP rows from the coordinator.
        ndp_entries (list[Any]): Raw NDP rows from the coordinator.
        expected (dict[str, Any]): Expected device metadata.
    """
    assert dt_mod._device_from_tracker_entries(mac, arp_entries, ndp_entries) == expected


@pytest.mark.parametrize(
    ("arp_entries", "ndp_entries", "expected_macs", "expected_devices"),
    [
        pytest.param(
            [
                object(),
                {"mac": None},
                {"mac": ""},
                {"mac": "AA:BB:CC:DD:EE:FF", "hostname": "tracked"},
                {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "duplicate"},
                {"mac": "AA-BB-CC-DD-EE-FF", "hostname": "dash-case"},
                {"mac": "11:22:33:44:55:66", "hostname": "first"},
            ],
            [],
            ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"],
            [
                {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "tracked"},
                {"mac": "11:22:33:44:55:66", "hostname": "first"},
            ],
            id="skips-malformed-invalid-and-duplicate-arp-macs",
        ),
        pytest.param(
            [{"mac-address": "AA-BB-CC", "hostname": "raw"}],
            [],
            ["aa:bb:cc"],
            [{"mac": "aa:bb:cc", "hostname": "raw"}],
            id="reads-raw-mac-key",
        ),
        pytest.param(
            [{"mac": "AA-BB-CC-DD-EE-01", "ip": "192.0.2.10", "hostname": "client?"}],
            [
                {
                    "mac": "aa:bb:cc:dd:ee:01",
                    "ip": "2001:0db8::10",
                    "manufacturer": "Example Vendor",
                },
                {"mac": "aa:bb:cc", "ip": "2001:db8::11"},
                {"mac": "00:11:22:33:44:55", "ip": "not-an-ip"},
            ],
            ["aa:bb:cc:dd:ee:01"],
            [{"mac": "aa:bb:cc:dd:ee:01", "hostname": "client", "manufacturer": "Example Vendor"}],
            id="merges-dual-stack-and-skips-invalid-ndp-rows",
        ),
    ],
)
def test_devices_from_tracker_entries(
    arp_entries: list[Any],
    ndp_entries: list[Any],
    expected_macs: list[str],
    expected_devices: list[dict[str, Any]],
) -> None:
    """Tracker discovery returns one device per unique valid MAC, merging ARP and NDP metadata.

    Args:
        arp_entries (list[Any]): Raw ARP rows from the coordinator.
        ndp_entries (list[Any]): Raw NDP rows from the coordinator.
        expected_macs (list[str]): Expected canonical MAC addresses in discovery order.
        expected_devices (list[dict[str, Any]]): Expected device metadata.
    """
    devices, mac_addresses = dt_mod._devices_from_tracker_entries(arp_entries, ndp_entries)

    assert mac_addresses == expected_macs
    assert devices == expected_devices


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
    device_info = added[0].device_info
    assert device_info is not None
    assert device_info["manufacturer"] == "Example Vendor"
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


@pytest.mark.parametrize("unusable_data", [{}, None], ids=["empty", "none"])
def test_handle_coordinator_update_unusable_data_keeps_connected_tracker_unavailable(
    unusable_data: dict[str, Any] | None,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Unusable coordinator data must not turn a connected tracker into an away observation.

    Args:
        unusable_data (dict[str, Any] | None): Coordinator payload without any neighbor table.
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

    coordinator.data = unusable_data
    ent._handle_coordinator_update()

    assert ent.available is False
    assert ent.is_connected is True


@pytest.mark.parametrize(
    ("successful_table", "successful_entry", "expected_ipv4", "expected_ipv6"),
    [
        pytest.param(
            "ndp_table",
            {"mac": "aa:bb:cc:dd:ee:01", "ip": "2001:db8::2"},
            ["192.0.2.1"],
            ["2001:db8::2"],
            id="missing-arp-with-ndp-sighting",
        ),
        pytest.param(
            "arp_table",
            {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.0.2.2"},
            ["192.0.2.2"],
            ["2001:db8::1"],
            id="missing-ndp-with-arp-sighting",
        ),
    ],
)
def test_handle_coordinator_update_missing_table_preserves_cached_family(
    successful_table: str,
    successful_entry: dict[str, str],
    expected_ipv4: list[str],
    expected_ipv6: list[str],
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """A missing family is failed while a valid sighting from the other family still applies.

    Args:
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
    if successful_table == "ndp_table":
        last_seen = datetime.now(UTC)
        coordinator.host_observation_times = {"aa:bb:cc:dd:ee:01": last_seen}
    ent._handle_coordinator_update()

    assert ent.available is True
    assert ent.is_connected is True
    attributes = ent.extra_state_attributes
    assert attributes is not None
    assert attributes["ipv4_addresses"] == expected_ipv4
    assert attributes["ipv6_addresses"] == expected_ipv6


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
    assert dict(ent.device_info)["connections"] == {(dr.CONNECTION_NETWORK_MAC, "aa:bb:cc")}
    assert ent.entity_registry_enabled_default is True


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

    assert ent.device_info is not None
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
    connections = device_info["connections"]
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

    connections = device_info["connections"]
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
    connections = device_info["connections"]
    assert any(conn[1] == "aa:bb:cc" for conn in connections)


@pytest.mark.parametrize(
    "arp_table",
    [[object()], [{"mac": "dd:ee:ff"}]],
    ids=["malformed_row", "nonmatching_mapping_row"],
)
def test_handle_coordinator_update_skips_unusable_arp_entries(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry], arp_table: list[Any]
) -> None:
    """Malformed or nonmatching ARP rows should be skipped while searching for the tracked MAC.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        arp_table (list[Any]): ARP rows that do not match the tracked MAC.
    """
    ent = _make_scanner_entity(
        coordinator=coordinator,
        make_config_entry=make_config_entry,
        coordinator_data={"arp_table": arp_table},
    )
    object.__setattr__(ent, "async_write_ha_state", MagicMock())

    ent._handle_coordinator_update()

    assert ent.is_connected is False
    assert ent.available is True


@pytest.mark.parametrize(
    "arp_row",
    [
        pytest.param(
            {"mac": "AA:BB:CC", "ip": "1.2.3.4", "intf_description": "lan"}, id="uppercase-mac"
        ),
        pytest.param(
            {"mac-address": "AA:BB:CC", "ip-address": "1.2.3.4", "intf_description": "lan"},
            id="raw-aiopnsense-keys",
        ),
    ],
)
def test_handle_coordinator_update_matches_arp_row_variants(
    arp_row: dict[str, str],
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """ARP rows match the tracked MAC regardless of case or aiopnsense key naming.

    Args:
        arp_row (dict[str, str]): ARP row using a different MAC case or the raw key names.
        coordinator (MagicMock): Mock coordinator supplying entity data.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake config entry.
    """
    ent = _make_scanner_entity(
        coordinator=coordinator,
        make_config_entry=make_config_entry,
        coordinator_data={"arp_table": [arp_row], "update_time": 0},
    )
    object.__setattr__(ent, "async_write_ha_state", MagicMock())

    ent._handle_coordinator_update()

    assert ent.ip_address == "1.2.3.4"
    attributes = ent.extra_state_attributes
    assert attributes is not None
    assert attributes.get("interface") == "lan"
    assert ent.available is True


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

    attributes = entity.extra_state_attributes
    assert attributes is not None
    first_observation_time = attributes["last_known_connected_time"]
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
    attributes = entity.extra_state_attributes
    assert attributes is not None
    assert attributes["last_known_connected_time"] == first_observation_time
    assert attributes["ipv6_addresses"] == [
        "2001:db8::10",
        "2001:db8::11",
        "fe80::1%em0",
    ]


def test_handle_coordinator_update_clears_arp_attributes_missing_from_latest_row(
    coordinator: MagicMock, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """ARP-derived attributes disappear when the latest row no longer carries them.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake config entry.
    """
    ent = _make_scanner_entity(
        coordinator,
        make_config_entry,
        coordinator_data={
            "arp_table": [
                {
                    "mac": "aa:bb:cc",
                    "ip": "1.2.3.4",
                    "intf_description": "lan",
                    "expires": -1,
                    "type": "arp",
                }
            ]
        },
    )
    object.__setattr__(ent, "async_write_ha_state", MagicMock())
    ent._handle_coordinator_update()
    attributes = ent.extra_state_attributes
    assert attributes is not None
    assert {"interface", "expires", "type"} <= attributes.keys()

    coordinator.data = {"arp_table": [{"mac": "aa:bb:cc", "ip": "1.2.3.4"}]}
    ent._handle_coordinator_update()

    assert not {"interface", "expires", "type"} & attributes.keys()


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


@pytest.mark.parametrize(
    ("arp_table", "consider_home", "last_seen_secs_ago", "expected_connected"),
    [
        pytest.param([], 3600, 0, True, id="missing-row-within-consider-home"),
        pytest.param([], 1, 5, False, id="missing-row-outside-consider-home"),
        pytest.param(
            [{"mac": "aa:bb:cc", "expired": True}],
            1,
            5,
            False,
            id="expired-row-outside-consider-home",
        ),
        pytest.param(
            [{"mac": "aa:bb:cc", "expired": True}],
            3600,
            5,
            True,
            id="expired-row-within-consider-home",
        ),
    ],
)
def test_handle_coordinator_update_applies_consider_home_to_absent_or_expired_rows(
    arp_table: list[dict[str, Any]],
    consider_home: int,
    last_seen_secs_ago: int,
    expected_connected: bool,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """A missing or expired ARP row stays home only inside the consider-home window.

    Args:
        arp_table (list[dict[str, Any]]): ARP rows supplied by the coordinator.
        consider_home (int): Configured consider-home grace period in seconds.
        last_seen_secs_ago (int): Age of the tracker's last known connection.
        expected_connected (bool): Whether the tracker should still be home.
        coordinator (MagicMock): Mock coordinator supplying entity data.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake config entry.
    """
    coordinator.data = {"arp_table": arp_table}
    entry = make_config_entry(
        data={CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={CONF_DEVICE_TRACKER_CONSIDER_HOME: consider_home},
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
    ent._last_known_connected_time = datetime.now(UTC).astimezone() - timedelta(
        seconds=last_seen_secs_ago
    )
    object.__setattr__(ent, "async_write_ha_state", MagicMock())

    ent._handle_coordinator_update()

    assert ent.is_connected is expected_connected


@pytest.mark.parametrize(
    "last_state_attributes",
    [pytest.param(None, id="no-snapshot"), pytest.param(["not", "a", "mapping"], id="non-mapping")],
)
@pytest.mark.asyncio
async def test_restore_last_state_ignores_missing_or_malformed_snapshot(
    last_state_attributes: list[str] | None,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Restoring state leaves the entity untouched without a usable saved snapshot.

    Args:
        last_state_attributes (list[str] | None): Saved attributes, or ``None`` for no snapshot.
        coordinator (MagicMock): Mock coordinator supplying entity data.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake config entry.
    """
    ent = _make_scanner_entity(coordinator, make_config_entry)
    last_state = None
    if last_state_attributes is not None:
        last_state = MagicMock()
        last_state.attributes = last_state_attributes
    object.__setattr__(ent, "async_get_last_state", AsyncMock(return_value=last_state))

    await _restore_state(ent)

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

    await _restore_state(ent)
    attributes = ent.extra_state_attributes
    assert attributes is not None
    assert attributes.get("interface") == "lan0"
    assert attributes.get("last_known_connected_time") == last_known_connected_time

    devinfo = ent.device_info
    assert devinfo is not None
    assert any(t[1] == "aa:bb:cc" for t in devinfo["connections"])
    assert devinfo["name"] == "dev"
    assert devinfo["manufacturer"] == "mfg"
    assert devinfo["via_device_id"] == "router-device-id"
    assert "default_name" not in devinfo
    assert "default_manufacturer" not in devinfo
    assert "via_device" not in devinfo

    # Restored hostname and IP surface only once a poll finds the device without live values.
    object.__setattr__(ent, "async_write_ha_state", MagicMock())
    ent._handle_coordinator_update()
    attributes = ent.extra_state_attributes
    assert attributes is not None
    assert attributes.get("last_known_hostname") == "oldhost"
    assert attributes.get("last_known_ip") == "9.9.9.9"


@pytest.mark.parametrize(
    ("snapshot_attributes", "failed_table", "ipv4_addresses", "ipv6_addresses"),
    [
        pytest.param(
            {"last_known_ip": "192.0.2.8"},
            "arp_table",
            ["192.0.2.8"],
            [],
            id="legacy-ipv4-arp-failure",
        ),
        pytest.param(
            {"last_known_ip": "2001:db8::8"},
            "ndp_table",
            [],
            ["2001:db8::8"],
            id="legacy-ipv6-ndp-failure",
        ),
        pytest.param(
            {"ip": "192.0.2.10"}, "arp_table", ["192.0.2.10"], [], id="home-ip-arp-failure"
        ),
        pytest.param(
            {"ipv6_addresses": ["2001:db8::1"], "last_known_ip": "2001:db8::1"},
            "ndp_table",
            [],
            ["2001:db8::1"],
            id="address-list-ndp-failure",
        ),
    ],
)
@pytest.mark.asyncio
async def test_restored_address_family_is_preserved_during_table_failure(
    snapshot_attributes: dict[str, Any],
    failed_table: str,
    ipv4_addresses: list[str],
    ipv6_addresses: list[str],
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """A failed lookup keeps the restored family's addresses and never reports the tracker away.

    Args:
        snapshot_attributes (dict[str, Any]): Saved address attributes in legacy or list format.
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
        **snapshot_attributes,
        "last_known_connected_time": last_known_connected_time.isoformat(),
    }
    object.__setattr__(entity, "async_get_last_state", AsyncMock(return_value=last_state))
    object.__setattr__(entity, "async_write_ha_state", MagicMock())

    await _restore_state(entity)
    entity._handle_coordinator_update()

    assert entity.available is False
    attributes = entity.extra_state_attributes
    assert attributes is not None
    assert attributes["last_known_connected_time"] == last_known_connected_time
    assert attributes["ipv4_addresses"] == ipv4_addresses
    assert attributes["ipv6_addresses"] == ipv6_addresses


@pytest.mark.parametrize("previously_observed", [False, True])
def test_valid_ndp_sighting_survives_unrelated_malformed_row(
    previously_observed: bool,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Usable rotating IPv6 sightings refresh presence and prune old addresses.

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
    observation: dict[str, str | datetime] = {
        "mac": "aa:bb:cc:dd:ee:01",
        "ip": "192.0.2.1",
        "last_seen": datetime.now(UTC),
    }
    if previously_observed:
        coordinator.data = {
            "arp_table": [],
            "ndp_table": [{"mac": "aa:bb:cc:dd:ee:01", "ip": "2001:db8::1"}],
            "update_time": 1_800_000_000.0,
        }
        coordinator.host_observation_times = {"aa:bb:cc:dd:ee:01": observation["last_seen"]}
        entity._handle_coordinator_update()
    observation["last_seen"] = datetime.now(UTC)
    coordinator.data = {
        "arp_table": [],
        "ndp_table": [
            {"mac": "aa:bb:cc:dd:ee:01", "ip": "2001:db8::2"},
            {"ip": "2001:db8::3"},
        ],
        "update_time": 1_900_000_000.0,
    }
    coordinator.host_observation_times = {"aa:bb:cc:dd:ee:01": observation["last_seen"]}

    entity._handle_coordinator_update()

    assert entity.available is True
    assert entity.is_connected is True
    attributes = entity.extra_state_attributes
    assert attributes is not None
    assert attributes["last_known_connected_time"].timestamp() == 1_900_000_000.0
    assert attributes["ipv6_addresses"] == ["2001:db8::2"]

    coordinator.data = {
        "arp_table": [],
        "ndp_table": [
            {"mac": "aa:bb:cc:dd:ee:01", "ip": "2001:db8::3"},
            {"ip": "2001:db8::4"},
        ],
        "update_time": 2_000_000_000.0,
    }
    observation["last_seen"] = datetime.now(UTC)
    coordinator.host_observation_times = {"aa:bb:cc:dd:ee:01": observation["last_seen"]}
    entity._handle_coordinator_update()

    assert entity.is_connected is True
    attributes = entity.extra_state_attributes
    assert attributes is not None
    assert attributes["ipv6_addresses"] == ["2001:db8::3"]


@pytest.mark.parametrize("consider_home", [0, 30])
def test_successful_ndp_inventory_ages_ipv6_tracker_when_mac_is_missing(
    consider_home: int,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """An incomplete unrelated row does not prevent a successful departure observation.

    Args:
        consider_home (int): Presence grace period applied to the previous sighting.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
    entry = make_config_entry(
        data={CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={CONF_DEVICE_TRACKER_CONSIDER_HOME: consider_home},
    )
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
    last_sighting = datetime.now(UTC).timestamp() - consider_home - 1
    coordinator.data = {
        "arp_table": [],
        "ndp_table": [{"mac": "aa:bb:cc:dd:ee:02", "ip": "2001:db8::2", "intf": "em0"}],
        "update_time": last_sighting,
    }
    observed_at = datetime.fromtimestamp(last_sighting, UTC)
    coordinator.host_observation_times = {"aa:bb:cc:dd:ee:02": observed_at}

    entity._handle_coordinator_update()
    attributes = entity.extra_state_attributes
    assert attributes is not None
    first_observation_time = attributes["last_known_connected_time"]

    coordinator.data = {
        "arp_table": [],
        "ndp_table": [{"ip": "2001:db8::3"}],
    }
    entity._handle_coordinator_update()

    assert entity.available is True
    assert entity.is_connected is False
    assert entity.ip_address is None
    attributes = entity.extra_state_attributes
    assert attributes is not None
    assert attributes["last_known_connected_time"] == first_observation_time
    assert attributes["ipv6_addresses"] == []
    assert attributes["last_known_ip"] == "2001:db8::2"


def test_both_lookups_failing_after_empty_scan_keeps_tracker_unavailable(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """A full lookup outage must not age a tracker to away even with no cached addresses.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
    entry = make_config_entry(
        data={CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={CONF_DEVICE_TRACKER_CONSIDER_HOME: 30},
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    entity = OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=False,
        mac="aa:bb:cc:dd:ee:03",
        mac_vendor=None,
        hostname=None,
    )
    object.__setattr__(entity, "async_write_ha_state", MagicMock())

    coordinator.data = {
        "arp_table": [{"mac": "aa:bb:cc:dd:ee:03", "ip": "192.0.2.3", "intf": "em0"}],
        "ndp_table": [],
        "update_time": datetime.now(UTC).timestamp() - 10,
    }
    entity._handle_coordinator_update()
    assert entity.is_connected is True

    # A successful scan with no rows clears addresses but stays home within consider_home.
    coordinator.data = {"arp_table": [], "ndp_table": []}
    entity._handle_coordinator_update()
    assert entity.available is True
    assert entity.is_connected is True
    attributes = entity.extra_state_attributes
    assert attributes is not None
    assert attributes["ipv4_addresses"] == []
    assert attributes["ipv6_addresses"] == []

    # The grace period expires while both lookups are failing.
    entity._last_known_connected_time = datetime.now(UTC).astimezone() - timedelta(seconds=60)
    coordinator.data = {
        "arp_table": [],
        "ndp_table": [],
        "unavailable_device_tracker_tables": ["arp_table", "ndp_table"],
    }
    entity._handle_coordinator_update()

    assert entity.available is False


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
@pytest.mark.parametrize(
    ("connected_time", "expected_connected_time"),
    [
        pytest.param(
            datetime(2026, 6, 22, 12, 30, 5, tzinfo=UTC),
            datetime(2026, 6, 22, 12, 30, 5, tzinfo=UTC),
            id="aware-datetime",
        ),
        pytest.param(
            "2026-06-22T12:30:05+00:00",
            datetime(2026, 6, 22, 12, 30, 5, tzinfo=UTC),
            id="aware-iso",
        ),
        pytest.param("2026-06-22T12:30:05", None, id="naive-iso"),
        pytest.param("not-a-date", None, id="malformed-string"),
        pytest.param(1, None, id="integer"),
    ],
)
async def test_restore_last_state_normalizes_connected_time_and_skips_empty_attributes(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    connected_time: datetime | str | int,
    expected_connected_time: datetime | None,
) -> None:
    """Restore only aware connection times and omit empty saved attributes.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        connected_time (datetime | str | int): Saved timestamp value to restore.
        expected_connected_time (datetime | None): Timestamp expected in the exposed state attributes.
    """
    ent = _make_scanner_entity(coordinator, make_config_entry)
    last_state = MagicMock()
    last_state.attributes = {
        "last_known_hostname": None,
        "last_known_ip": None,
        "interface": "",
        "expires": None,
        "type": "",
        "last_known_connected_time": connected_time,
    }
    object.__setattr__(ent, "async_get_last_state", AsyncMock(return_value=last_state))

    await _restore_state(ent)

    attributes = ent.extra_state_attributes
    assert attributes is not None
    for empty_attribute in (
        "last_known_hostname",
        "last_known_ip",
        "interface",
        "expires",
        "type",
    ):
        assert empty_attribute not in attributes

    if expected_connected_time is None:
        assert "last_known_connected_time" not in attributes
    else:
        assert attributes.get("last_known_connected_time") == expected_connected_time


@pytest.mark.asyncio
@pytest.mark.parametrize("legacy_mac_linking", [True, False], ids=["pre-2026.11", "2026.11+"])
@pytest.mark.parametrize(
    ("existing_device", "enabled_default", "disable_new", "expected_disabler"),
    [
        pytest.param(True, False, False, None, id="existing-enabled-mac"),
        pytest.param(False, False, False, er.RegistryEntryDisabler.INTEGRATION, id="discovered"),
        pytest.param(False, True, False, None, id="selected"),
        pytest.param(True, False, True, er.RegistryEntryDisabler.INTEGRATION, id="preference"),
    ],
)
async def test_tracker_platform_registers_client_device(
    hass: HomeAssistant,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    monkeypatch: pytest.MonkeyPatch,
    legacy_mac_linking: bool,
    existing_device: bool,
    enabled_default: bool,
    disable_new: bool,
    expected_disabler: er.RegistryEntryDisabler | None,
) -> None:
    """Register client metadata and retain enabled defaults without legacy MAC linking.

    Args:
        hass (HomeAssistant): Home Assistant test instance.
        coordinator (MagicMock): Coordinator supplying tracker state.
        make_config_entry (Callable[..., MockConfigEntry]): Config entry factory.
        monkeypatch (pytest.MonkeyPatch): Fixture replacing the removed Core hook.
        legacy_mac_linking (bool): Whether to retain Core's pre-2026.11 linking hook.
        existing_device (bool): Whether another integration already knows the MAC.
        enabled_default (bool): Whether this tracker was explicitly selected.
        disable_new (bool): Whether the config entry disables new entities.
        expected_disabler (er.RegistryEntryDisabler | None): Expected registry disable reason.
    """
    coordinator.data = {"arp_table": []}
    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(entry, pref_disable_new_entities=disable_new)
    device_reg = dr.async_get(hass)
    router = device_reg.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, "dev1")},
        name="Router",
    )
    mac_address = "aa:bb:cc:dd:ee:ff"
    if existing_device:
        other_entry = MockConfigEntry(domain="other")
        other_entry.add_to_hass(hass)
        device_reg.async_get_or_create(
            config_entry_id=other_entry.entry_id,
            connections={(dr.CONNECTION_NETWORK_MAC, mac_address)},
        )
    entity = OPNsenseScannerEntity(
        config_entry=entry,
        coordinator=coordinator,
        enabled_default=enabled_default,
        mac=mac_address,
        mac_vendor="Client Vendor",
        hostname="Client",
        router_device_id=router.id,
    )
    if not legacy_mac_linking:
        # HA 2026.11 removes ScannerEntity's special post-registration MAC linking.
        monkeypatch.setattr(
            ScannerEntity,
            "async_internal_added_to_hass",
            BaseScannerEntity.async_internal_added_to_hass,
        )
    platform = EntityPlatform(
        hass=hass,
        logger=logging.getLogger(__name__),
        domain="device_tracker",
        platform_name=DOMAIN,
        platform=None,
        scan_interval=timedelta(seconds=30),
        entity_namespace=None,
    )
    platform.config_entry = entry
    with patch.object(OPNsenseBaseEntity, "async_added_to_hass", AsyncMock()):
        await platform.async_add_entities([entity])

    unique_id = entity.unique_id
    assert unique_id is not None
    registry_entry = er.async_get(hass).async_get_entity_id("device_tracker", DOMAIN, unique_id)
    assert registry_entry is not None
    registered = er.async_get(hass).async_get(registry_entry)
    assert registered is not None
    assert registered.disabled_by == expected_disabler
    assert registered.device_id is not None
    client_device = device_reg.async_get(registered.device_id)
    assert isinstance(client_device, dr.DeviceEntry)
    assert (dr.CONNECTION_NETWORK_MAC, mac_address) in client_device.connections
    assert device_belongs_to_config_entry(client_device, entry.entry_id)
    assert client_device.name == "Client"
    assert client_device.manufacturer == "Client Vendor"
    assert client_device.via_device_id == router.id
    await platform.async_reset()


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
@pytest.mark.parametrize(
    ("arp_table", "options", "expected_recorded", "expected_added"),
    [
        pytest.param(None, None, None, [], id="missing-arp-inventory-is-incomplete"),
        pytest.param([], None, [], [], id="empty-arp-inventory-is-authoritative"),
        pytest.param(
            [{"mac": "m1"}, {"mac": "m2", "hostname": "h2"}],
            {CONF_DEVICE_TRACKER_ENABLED: True},
            ["m1", "m2"],
            ["m1", "m2"],
            id="track-all-creates-tracker-per-arp-row",
        ),
        pytest.param(
            ["not-an-arp-row", {}, {"mac": "", "hostname": "bad"}, {"mac": "AA-BB-CC-DD-EE-FF"}],
            {CONF_DEVICE_TRACKER_ENABLED: True},
            None,
            ["aa:bb:cc:dd:ee:ff"],
            id="track-all-malformed-row-fails-reconciliation",
        ),
        pytest.param(
            [
                {"mac": None},
                {"mac": ""},
                {"mac": 1234},
                {"hostname": "x"},
                {"mac": "AA-BB-CC-DD-EE-FF"},
            ],
            {CONF_DEVICE_TRACKER_ENABLED: True, CONF_DEVICES: []},
            ["aa:bb:cc:dd:ee:ff"],
            ["aa:bb:cc:dd:ee:ff"],
            id="track-all-ignores-mapping-rows-without-usable-mac",
        ),
        pytest.param(
            [
                {"mac": "AA-BB-CC-DD-EE-FF", "hostname": "first"},
                {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "duplicate"},
                {"mac": "11:22:33:44:55:66"},
            ],
            {CONF_DEVICE_TRACKER_ENABLED: True},
            ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"],
            ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"],
            id="track-all-duplicate-macs-are-authoritative",
        ),
        pytest.param(
            ["not-an-arp-row", {"mac": ""}, {"mac": "AA-BB-CC-DD-EE-FF"}],
            {CONF_DEVICE_TRACKER_ENABLED: True, CONF_DEVICES: ["aa:bb:cc:dd:ee:ff"]},
            ["aa:bb:cc:dd:ee:ff"],
            ["aa:bb:cc:dd:ee:ff"],
            id="configured-macs-ignore-malformed-rows",
        ),
        pytest.param(
            [{"mac": "aa:bb:cc:dd:ee:ff"}],
            {
                CONF_DEVICE_TRACKER_ENABLED: True,
                CONF_DEVICES: [
                    "AA-BB-CC-DD-EE-FF",
                    "aa:bb:cc:dd:ee:ff",
                    "11:22:33:44:55:66",
                    "11-22-33-44-55-66",
                ],
            },
            ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"],
            ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"],
            id="configured-macs-are-normalized-and-deduplicated",
        ),
    ],
)
async def test_async_setup_entry_reconciles_desired_trackers_from_arp_table(
    monkeypatch: pytest.MonkeyPatch,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    arp_table: list[Any] | None,
    options: dict[str, Any] | None,
    expected_recorded: list[str] | None,
    expected_added: list[str],
) -> None:
    """Setup creates trackers from usable ARP rows and only reports authoritative inventories.

    A ``None`` desired-entity payload keeps stale-entity reconciliation from removing trackers
    when the inventory could not be trusted.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake config entry.
        arp_table (list[Any] | None): ARP rows supplied by the coordinator, or ``None`` if absent.
        options (dict[str, Any] | None): Config entry options selecting track-all or configured MACs.
        expected_recorded (list[str] | None): MACs reported as desired, or ``None`` if incomplete.
        expected_added (list[str]): MACs of the entities added to Home Assistant.
    """
    coordinator.data = {} if arp_table is None else {"arp_table": arp_table}
    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"}, options=options)
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    record = MagicMock()
    monkeypatch.setattr(dt_mod, "record_desired_entities", record)
    added: list[Any] = []

    await dt_mod.async_setup_entry(
        MagicMock(),
        entry,
        cast("AddEntitiesCallback", lambda entities, _=False: added.extend(entities)),
    )

    desired = record.call_args.args[2]
    assert (
        desired if desired is None else [entity.mac_address for entity in desired]
    ) == expected_recorded
    assert [entity.mac_address for entity in added] == expected_added


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "options",
    [
        pytest.param(None, id="default-options"),
        pytest.param({CONF_DEVICE_TRACKER_ENABLED: True}, id="track-all-with-empty-arp-table"),
    ],
)
async def test_async_setup_entry_removes_previous_mac(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
    options: dict[str, Any] | None,
) -> None:
    """Setup removes stale tracked MACs, including when an empty ARP table is authoritative.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        fake_reg_factory (Any): Factory for the in-memory entity registry test double.
        options (dict[str, Any] | None): Config entry options selecting the tracking mode.
    """
    coordinator.data = {"arp_table": []}
    entry = make_config_entry(
        data={TRACKED_MACS: ["old:mac:1"], CONF_DEVICE_UNIQUE_ID: "dev1"},
        options=options,
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
    record = MagicMock()
    monkeypatch.setattr(dt_mod, "record_desired_entities", record)
    ph_hass.config_entries.async_update_entry = MagicMock()

    await dt_mod.async_setup_entry(
        ph_hass, entry, cast("AddEntitiesCallback", lambda _entities: None)
    )

    fake.async_remove_device.assert_not_called()
    fake.async_update_device.assert_not_called()
    record.assert_called_once_with(entry, "device_tracker", [])


@pytest.mark.parametrize(
    ("expires", "expected_expires_kind"),
    [
        pytest.param(30, "datetime", id="positive-seconds"),
        pytest.param("soon", "absent", id="malformed"),
    ],
)
def test_handle_coordinator_update_exposes_arp_expiry_only_when_valid(
    expires: object,
    expected_expires_kind: str,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """A valid ARP expiry is exposed, while malformed expiry data never hides other attributes.

    Args:
        expires (object): Raw ARP ``expires`` value.
        expected_expires_kind (str): Whether the ``expires`` attribute should be a datetime or absent.
        coordinator (MagicMock): Mock coordinator supplying entity data.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake config entry.
    """
    ent = _make_scanner_entity(
        coordinator,
        make_config_entry,
        coordinator_data={
            "arp_table": [
                {
                    "mac": "aa:bb:cc",
                    "ip": "1.2.3.4",
                    "intf_description": "lan",
                    "expires": expires,
                    "type": "arp",
                }
            ],
            "update_time": float(int(datetime.now(UTC).timestamp())),
        },
    )
    object.__setattr__(ent, "async_write_ha_state", MagicMock())

    ent._handle_coordinator_update()

    attributes = ent.extra_state_attributes
    assert attributes is not None
    assert attributes.get("interface") == "lan"
    assert attributes.get("type") == "arp"
    if expected_expires_kind == "datetime":
        assert isinstance(attributes.get("expires"), datetime)
    else:
        assert "expires" not in attributes


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
async def test_async_setup_entry_removes_stale_tracker_entities_and_detaches_their_devices(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Stale MAC cleanup removes tracker entities and detaches their devices from this router.

    Reparenting of shared devices is covered directly by the ``detach_shared_router_parent``
    helper tests, so this test only checks the stale-MAC wiring: a router-linked device is
    handed to a surviving OPNsense router while an unrelated device is simply detached.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate integration boundaries.
        ph_hass (Any): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
    coordinator.data = {"arp_table": [{"mac": "keep:mac"}]}
    stale_router_mac = "stale:mac:router"
    stale_other_mac = "stale:mac:other"
    entry = make_config_entry(
        data={
            TRACKED_MACS: [stale_router_mac, stale_other_mac, "keep:mac"],
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
    }
    entity_registry.async_get_entity_id.side_effect = lambda _domain, _platform, unique_id: (
        entity_ids.get(unique_id)
    )
    monkeypatch.setattr(er, "async_get", MagicMock(return_value=entity_registry))

    router_device = MagicMock(
        id="router-device-id",
        identifiers={(DOMAIN, entry.data[CONF_DEVICE_UNIQUE_ID])},
    )
    surviving_entry = MagicMock(
        entry_id="survive-entry-a",
        domain=DOMAIN,
        data={CONF_DEVICE_UNIQUE_ID: "survive-a"},
    )
    ph_hass.config_entries.async_get_entry = MagicMock(
        side_effect={entry.entry_id: entry, surviving_entry.entry_id: surviving_entry}.get
    )
    identifier_router_map = {
        (DOMAIN, entry.data[CONF_DEVICE_UNIQUE_ID]): router_device,
        (DOMAIN, "survive-a"): MagicMock(id="survivor-a-router"),
    }
    devices = {
        stale_router_mac: MagicMock(
            id="stale-router-device",
            via_device_id="router-device-id",
            config_entries={entry.entry_id, surviving_entry.entry_id},
        ),
        stale_other_mac: MagicMock(
            id="stale-other-device",
            via_device_id="other-device-id",
            config_entries={entry.entry_id},
        ),
    }
    device_registry = MagicMock()
    device_registry.async_get_device_by_identifier.side_effect = (
        lambda identifier, _config_entry_id: identifier_router_map.get(identifier)
    )
    device_registry.async_get_device_by_connection.side_effect = (
        lambda connection, _config_entry_id: devices[connection[1]]
    )
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", MagicMock(return_value=device_registry))

    ph_hass.config_entries.async_update_entry = MagicMock()
    await dt_mod.async_setup_entry(ph_hass, entry, MagicMock())

    removed_ids = {item.args[0] for item in entity_registry.async_remove.call_args_list}
    assert removed_ids == {
        "device_tracker.device_stale_router",
        "device_tracker.device_stale_other",
    }
    assert sorted(device_registry.async_update_device.call_args_list, key=str) == sorted(
        [
            call(
                "stale-router-device",
                remove_config_entry_id=entry.entry_id,
                via_device_id="survivor-a-router",
            ),
            call("stale-other-device", remove_config_entry_id=entry.entry_id),
        ],
        key=str,
    )


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
    record = MagicMock()
    monkeypatch.setattr(dt_mod, "record_desired_entities", record)
    ph_hass.config_entries.async_update_entry = MagicMock()
    added: list[Any] = []

    await dt_mod.async_setup_entry(ph_hass, entry, cast("AddEntitiesCallback", added.extend))

    assert sorted(entity.mac_address for entity in added) == [
        "aa:bb:cc:dd:ee:01",
        "aa:bb:cc:dd:ee:02",
    ]
    fake.async_remove_device.assert_not_called()
    fake.async_update_device.assert_not_called()
    ph_hass.config_entries.async_update_entry.assert_not_called()
    record.assert_called_once_with(entry, "device_tracker", None)


@pytest.mark.asyncio
async def test_async_setup_entry_retains_only_failed_family_inventory(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: HomeAssistant,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """An NDP failure should retain IPv6-only trackers and reconcile successful ARP rows.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate registry access.
        ph_hass (HomeAssistant): Home Assistant test instance used to register and inspect entities.
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
    entry.add_to_hass(ph_hass)
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    entity_registry = er.async_get(ph_hass)
    stale_arp_entity = entity_registry.async_get_or_create(
        Platform.DEVICE_TRACKER,
        DOMAIN,
        slugify(f"dev1_mac_{arp_mac}"),
        config_entry=entry,
    )
    retained_ndp_entity = entity_registry.async_get_or_create(
        Platform.DEVICE_TRACKER,
        DOMAIN,
        slugify(f"dev1_mac_{ndp_mac}"),
        config_entry=entry,
    )
    fake = fake_reg_factory(device_exists=False)
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: fake, raising=False)
    monkeypatch.setattr(dt_mod, "is_reconciliation_active", lambda _entry: False)
    record = MagicMock()
    monkeypatch.setattr(dt_mod, "record_desired_entities", record)
    added: list[Any] = []

    await dt_mod.async_setup_entry(ph_hass, entry, cast("AddEntitiesCallback", added.extend))

    assert [entity.mac_address for entity in added] == [ndp_mac]
    assert entity_registry.async_get(stale_arp_entity.entity_id) is None
    assert entity_registry.async_get(retained_ndp_entity.entity_id) == retained_ndp_entity
    assert entry.data[TRACKED_MACS] == [ndp_mac]
    assert entry.data[TRACKED_ARP_MACS] == []
    assert entry.data[TRACKED_NDP_MACS] == [ndp_mac]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("reload_state"),
    [
        pytest.param(
            {
                "arp_table": None,
                "ndp_table": [],
                "unavailable_device_tracker_tables": ["arp_table"],
            },
            id="arp_outage_ndp_empty",
        ),
        pytest.param(
            {
                "arp_table": None,
                "ndp_table": None,
                "unavailable_device_tracker_tables": ["arp_table", "ndp_table"],
            },
            id="both_tables_unavailable",
        ),
    ],
)
async def test_track_all_absent_device_keeps_last_family_across_arp_outage_reload(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: HomeAssistant,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
    reload_state: dict[str, Any],
) -> None:
    """A tracker absent from a successful scan keeps its last family across a later outage.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate registry access.
        ph_hass (HomeAssistant): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        fake_reg_factory (Any): Factory for the in-memory device registry test double.
        reload_state (dict[str, Any]): Coordinator state present when the entry reloads.
    """
    mac = "aa:bb:cc:dd:ee:01"
    entry = make_config_entry(
        data={
            TRACKED_MACS: [mac],
            TRACKED_ARP_MACS: [mac],
            TRACKED_NDP_MACS: [],
            CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={CONF_DEVICE_TRACKER_ENABLED: True},
        entry_id="e_absent_device_outage",
    )
    entry.add_to_hass(ph_hass)
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)

    dt_mod._update_track_all_source_inventory(ph_hass, entry, {"arp_table": [], "ndp_table": []})
    assert entry.data[TRACKED_ARP_MACS] == [mac]
    assert entry.data[TRACKED_NDP_MACS] == []

    entity_registry = er.async_get(ph_hass)
    registered = entity_registry.async_get_or_create(
        Platform.DEVICE_TRACKER,
        DOMAIN,
        slugify(f"dev1_mac_{mac}"),
        config_entry=entry,
    )
    fake = fake_reg_factory(device_exists=False)
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: fake, raising=False)
    monkeypatch.setattr(dt_mod, "is_reconciliation_active", lambda _entry: False)
    monkeypatch.setattr(dt_mod, "record_desired_entities", MagicMock())
    coordinator.data = reload_state
    added: list[Any] = []

    await dt_mod.async_setup_entry(ph_hass, entry, cast("AddEntitiesCallback", added.extend))

    assert [entity.mac_address for entity in added] == [mac]
    assert entity_registry.async_get(registered.entity_id) == registered
    assert entry.data[TRACKED_MACS] == [mac]


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


@pytest.mark.parametrize(
    "update_order",
    [
        "inventory_then_options",
        "options_then_inventory",
        "inventory_then_drained_options",
    ],
)
@pytest.mark.asyncio
async def test_poll_inventory_write_does_not_suppress_next_options_reload(
    update_order: str,
    monkeypatch: pytest.MonkeyPatch,
    hass: HomeAssistant,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """Concurrent poll and options updates result in exactly one integration reload.

    Args:
        update_order (str): Order and task-drain behavior for poll and options updates.
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
    assert coordinator_listeners
    entry.async_on_unload(entry.add_update_listener(init_mod._async_update_listener))

    def update_inventory() -> None:
        """Apply one coordinator poll that moves the tracker from ARP to NDP."""
        coordinator.data = {
            "arp_table": [],
            "ndp_table": [{"mac": mac_address, "ip": "2001:db8::10"}],
        }
        for listener in coordinator_listeners:
            listener()

    def update_options() -> None:
        """Apply a real options update to the config entry."""
        hass.config_entries.async_update_entry(
            entry,
            options={CONF_DEVICE_TRACKER_ENABLED: True, CONF_DEVICE_TRACKER_CONSIDER_HOME: 30},
        )

    if update_order == "inventory_then_options":
        update_inventory()
        update_options()
    elif update_order == "options_then_inventory":
        update_options()
        update_inventory()
    else:
        update_inventory()
        await hass.async_block_till_done()
        assert entry.data[TRACKED_ARP_MACS] == []
        assert entry.data[TRACKED_NDP_MACS] == [mac_address]
        reload_entry.assert_not_awaited()
        update_options()

    # Let both real async_update_entry notifications run only after both updates.
    await hass.async_block_till_done()

    assert entry.data[TRACKED_ARP_MACS] == []
    assert entry.data[TRACKED_NDP_MACS] == [mac_address]
    reload_entry.assert_awaited_once_with(entry.entry_id)


@pytest.mark.asyncio
async def test_track_all_family_transition_is_persisted_once_and_survives_reload(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: HomeAssistant,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """Existing trackers record family transitions once and survive a later table outage.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate registry access.
        ph_hass (HomeAssistant): Home Assistant test instance used to register and inspect entities.
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
    listener_registrations: list[tuple[Callable[[], None], MagicMock]] = []

    def capture_listener(listener: Callable[[], None]) -> MagicMock:
        """Capture each registered listener with its own unsubscribe callback.

        Args:
            listener (Callable[[], None]): Coordinator callback to register.

        Returns:
            MagicMock: Unique unload callback returned by coordinator registration.
        """
        remove_listener = MagicMock()
        listener_registrations.append((listener, remove_listener))
        return remove_listener

    coordinator.async_add_listener = MagicMock(side_effect=capture_listener)
    device_registry = fake_reg_factory(device_exists=False)
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: device_registry)
    monkeypatch.setattr(dt_mod, "record_desired_entities", MagicMock())
    update_entry = MagicMock(
        side_effect=lambda updated_entry, *, data: object.__setattr__(updated_entry, "data", data)
    )
    monkeypatch.setattr(ph_hass.config_entries, "async_update_entry", update_entry)

    initially_added: list[Any] = []
    await dt_mod.async_setup_entry(
        ph_hass, entry, cast("AddEntitiesCallback", initially_added.extend)
    )

    assert [entity.mac_address for entity in initially_added] == mac_addresses
    assert all(not entity.entity_registry_enabled_default for entity in initially_added)
    first_setup_listener_count = len(listener_registrations)
    first_setup_listeners = listener_registrations.copy()
    assert first_setup_listeners
    for _, remove_listener in first_setup_listeners:
        entry.async_on_unload.assert_any_call(remove_listener)

    coordinator.data = {
        "arp_table": [],
        "ndp_table": [
            {"mac": mac_address, "ip": f"2001:db8::{index + 1}"}
            for index, mac_address in enumerate(mac_addresses)
        ],
    }
    for _ in range(2):
        for listener, _ in first_setup_listeners:
            listener()

    assert entry.data[TRACKED_ARP_MACS] == []
    assert entry.data[TRACKED_NDP_MACS] == mac_addresses
    assert update_entry.call_count == 1

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
    reload_listeners = listener_registrations[first_setup_listener_count:]
    assert reload_listeners
    for _, remove_listener in reload_listeners:
        entry.async_on_unload.assert_any_call(remove_listener)


@pytest.mark.parametrize(
    "ndp_row",
    [
        {"ip": "2001:db8::2"},
        {"mac": "not-a-mac", "ip": "2001:db8::2"},
        {"mac": "aa:bb:cc:dd:ee:02", "ip": "not-an-ip"},
    ],
    ids=["missing-mac", "invalid-mac", "invalid-ip"],
)
@pytest.mark.asyncio
async def test_async_setup_entry_preserves_ndp_tracker_for_unusable_rows(
    ndp_row: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: HomeAssistant,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
) -> None:
    """Unusable NDP rows must not reconcile away a previously discovered device.

    Args:
        ndp_row (dict[str, str]): Invalid NDP response row under test.
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate registry access.
        ph_hass (HomeAssistant): Home Assistant instance used to inspect entity-registry cleanup.
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
    entry.add_to_hass(ph_hass)
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    entity_registry = er.async_get(ph_hass)
    retained_entity = entity_registry.async_get_or_create(
        Platform.DEVICE_TRACKER,
        DOMAIN,
        slugify(f"dev1_mac_{ndp_mac}"),
        config_entry=entry,
    )
    device_registry = fake_reg_factory(device_exists=False)
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: device_registry)
    monkeypatch.setattr(dt_mod, "record_desired_entities", MagicMock())
    added: list[Any] = []

    await dt_mod.async_setup_entry(ph_hass, entry, cast("AddEntitiesCallback", added.extend))

    assert [entity.mac_address for entity in added] == [ndp_mac]
    assert entry.data[TRACKED_MACS] == [ndp_mac]
    assert entry.data[TRACKED_NDP_MACS] == [ndp_mac]
    assert entity_registry.async_get(retained_entity.entity_id) == retained_entity


_COVERAGE_MAC = "aa:bb:cc:dd:ee:01"


@pytest.mark.parametrize(
    ("ndp_rows", "expected_connected", "expected_ipv6"),
    [
        pytest.param(
            [
                {"mac": _COVERAGE_MAC, "ip": "not-an-ip"},
                {"mac": _COVERAGE_MAC, "ip": "2001:db8::5"},
            ],
            True,
            ["2001:db8::5"],
            id="invalid_ipv6_row_skipped_before_valid_row",
        ),
        pytest.param(
            [
                {"mac": _COVERAGE_MAC, "ip": "not-an-ip"},
                {"mac": _COVERAGE_MAC, "ip": "192.0.2.10"},
            ],
            False,
            [],
            id="only_invalid_ipv6_rows_do_not_confirm_presence",
        ),
    ],
)
def test_handle_coordinator_update_ignores_ndp_rows_without_valid_ipv6(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    ndp_rows: list[dict[str, Any]],
    expected_connected: bool,
    expected_ipv6: list[str],
) -> None:
    """NDP rows without a usable IPv6 address should not confirm tracker presence.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        ndp_rows (list[dict[str, Any]]): NDP rows supplied by the coordinator.
        expected_connected (bool): Expected connection state after the update.
        expected_ipv6 (list[str]): Expected IPv6 addresses exposed by the entity.
    """
    ent = _make_scanner_entity(
        coordinator=coordinator,
        make_config_entry=make_config_entry,
        coordinator_data={"arp_table": [], "ndp_table": ndp_rows},
        mac=_COVERAGE_MAC,
    )
    object.__setattr__(ent, "async_write_ha_state", MagicMock())
    if expected_connected:
        last_seen = datetime.now(UTC)
        coordinator.host_observation_times = {_COVERAGE_MAC: last_seen}

    ent._handle_coordinator_update()

    assert ent.is_connected is expected_connected
    attributes = ent.extra_state_attributes
    assert attributes is not None
    assert attributes["ipv6_addresses"] == expected_ipv6


_NDP_AUTHORITATIVE_STATE_WITH_COVERAGE_MAC: dict[str, Any] = {
    "arp_table": [],
    "ndp_table": [{"mac": _COVERAGE_MAC, "ip": "2001:db8::1"}],
}
_NO_AUTHORITATIVE_STATE: dict[str, Any] = {
    "arp_table": None,
    "ndp_table": None,
    "unavailable_device_tracker_tables": ["arp_table"],
}


@pytest.mark.parametrize(
    ("options", "tracked_data", "state"),
    [
        pytest.param(
            {CONF_DEVICE_TRACKER_ENABLED: True},
            None,
            None,
            id="non_mapping_state",
        ),
        pytest.param(
            {CONF_DEVICE_TRACKER_ENABLED: False},
            None,
            _NDP_AUTHORITATIVE_STATE_WITH_COVERAGE_MAC,
            id="tracker_disabled",
        ),
        pytest.param(
            {CONF_DEVICE_TRACKER_ENABLED: True, CONF_DEVICES: ["11:22:33:44:55:66"]},
            None,
            _NDP_AUTHORITATIVE_STATE_WITH_COVERAGE_MAC,
            id="explicit_macs_configured",
        ),
        pytest.param(
            {CONF_DEVICE_TRACKER_ENABLED: True},
            {TRACKED_MACS: []},
            _NDP_AUTHORITATIVE_STATE_WITH_COVERAGE_MAC,
            id="no_tracked_macs",
        ),
        pytest.param(
            {CONF_DEVICE_TRACKER_ENABLED: True},
            None,
            _NO_AUTHORITATIVE_STATE,
            id="no_authoritative_family",
        ),
    ],
)
def test_update_track_all_source_inventory_leaves_inventory_unchanged_when_inapplicable(
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
    options: dict[str, Any],
    tracked_data: dict[str, Any] | None,
    state: object,
) -> None:
    """Provenance refresh applies only to enabled track-all trackers with tracked MACs.

    The disabled and explicit-MAC cases would otherwise move the tracked MAC from ARP to NDP.
    The remaining cases verify that malformed state, no tracked MACs, and unavailable tables
    leave the stored inventory unchanged.

    Args:
        ph_hass (HomeAssistant): Home Assistant test instance used to persist config-entry data.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        options (dict[str, Any]): Config-entry options that select the tracker mode.
        tracked_data (dict[str, Any] | None): Optional data overrides for the tracked inventory.
        state (object): Coordinator state passed to the provenance update.
    """
    data: dict[str, Any] = {
        TRACKED_MACS: [_COVERAGE_MAC],
        TRACKED_ARP_MACS: [_COVERAGE_MAC],
        TRACKED_NDP_MACS: [],
        CONF_DEVICE_UNIQUE_ID: "dev1",
    }
    data.update(tracked_data or {})
    entry = make_config_entry(data=data, options=options, entry_id="e_inapplicable_inventory")
    entry.add_to_hass(ph_hass)
    before = dict(entry.data)

    dt_mod._update_track_all_source_inventory(ph_hass, entry, state)

    assert dict(entry.data) == before


def test_update_track_all_source_inventory_treats_non_list_arp_inventory_as_empty(
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """A corrupt stored ARP inventory should not block recording a fresh ARP sighting.

    Args:
        ph_hass (HomeAssistant): Home Assistant test instance used to persist config-entry data.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
    entry = make_config_entry(
        data={
            TRACKED_MACS: [_COVERAGE_MAC],
            TRACKED_ARP_MACS: "corrupt-inventory",
            TRACKED_NDP_MACS: [],
            CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={CONF_DEVICE_TRACKER_ENABLED: True},
        entry_id="e_non_list_arp_inventory",
    )
    entry.add_to_hass(ph_hass)

    dt_mod._update_track_all_source_inventory(
        ph_hass,
        entry,
        {"arp_table": [{"mac": _COVERAGE_MAC}], "ndp_table": []},
    )

    assert entry.data[TRACKED_ARP_MACS] == [_COVERAGE_MAC]
    assert entry.data[TRACKED_NDP_MACS] == []


def test_update_track_all_source_inventory_skips_non_string_inventory_entries(
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Non-string stored inventory entries should be dropped while valid MACs are kept.

    The ARP table is unavailable, so the valid stored MAC is retained from last known
    membership and the junk entries must not survive into the rewritten inventory.

    Args:
        ph_hass (HomeAssistant): Home Assistant test instance used to persist config-entry data.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
    """
    entry = make_config_entry(
        data={
            TRACKED_MACS: [_COVERAGE_MAC],
            TRACKED_ARP_MACS: [None, 7, _COVERAGE_MAC],
            TRACKED_NDP_MACS: [],
            CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={CONF_DEVICE_TRACKER_ENABLED: True},
        entry_id="e_non_string_inventory",
    )
    entry.add_to_hass(ph_hass)

    dt_mod._update_track_all_source_inventory(
        ph_hass,
        entry,
        {
            "arp_table": None,
            "ndp_table": [],
            "unavailable_device_tracker_tables": ["arp_table"],
        },
    )

    assert entry.data[TRACKED_ARP_MACS] == [_COVERAGE_MAC]
    assert entry.data[TRACKED_NDP_MACS] == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stored_arp_macs",
    [
        pytest.param("not-a-list", id="string"),
        pytest.param(None, id="none"),
    ],
)
async def test_async_setup_entry_falls_back_to_tracked_macs_for_non_list_arp_inventory(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: HomeAssistant,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    fake_reg_factory: Any,
    stored_arp_macs: object,
) -> None:
    """A malformed persisted ARP inventory should fall back to the legacy tracked-MAC union.

    The ARP table is unavailable, so the fallback is the only reason the tracked MAC survives.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patch fixture used to isolate registry access.
        ph_hass (HomeAssistant): Home Assistant test instance used to register and inspect entities.
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        fake_reg_factory (Any): Factory for the in-memory device registry test double.
        stored_arp_macs (object): Malformed stored ARP inventory value.
    """
    coordinator.data = {
        "arp_table": None,
        "ndp_table": [],
        "unavailable_device_tracker_tables": ["arp_table"],
    }
    entry = make_config_entry(
        data={
            TRACKED_MACS: [_COVERAGE_MAC],
            TRACKED_ARP_MACS: stored_arp_macs,
            TRACKED_NDP_MACS: [],
            CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={CONF_DEVICE_TRACKER_ENABLED: True},
        entry_id="e_legacy_arp_inventory",
    )
    entry.add_to_hass(ph_hass)
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    fake = fake_reg_factory(device_exists=False)
    monkeypatch.setattr(dt_mod, "async_get_dev_reg", lambda _hass: fake, raising=False)
    monkeypatch.setattr(dt_mod, "is_reconciliation_active", lambda _entry: False)
    monkeypatch.setattr(dt_mod, "record_desired_entities", MagicMock())
    added: list[Any] = []

    await dt_mod.async_setup_entry(ph_hass, entry, cast("AddEntitiesCallback", added.extend))

    assert [entity.mac_address for entity in added] == [_COVERAGE_MAC]
    assert entry.data[TRACKED_ARP_MACS] == [_COVERAGE_MAC]


@pytest.mark.parametrize(
    ("hostname_in_arp", "expected_last_known"),
    [
        pytest.param(None, "oldhost", id="live_hostname_missing_keeps_last_known"),
        pytest.param("livehost", None, id="live_hostname_present_clears_last_known"),
    ],
)
@pytest.mark.asyncio
async def test_handle_coordinator_update_exposes_last_known_hostname_only_while_missing(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
    hostname_in_arp: str | None,
    expected_last_known: str | None,
) -> None:
    """A restored hostname is exposed only while the live neighbor row lacks one.

    Args:
        coordinator (MagicMock): Mock coordinator supplying entity data and client behavior.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake integration config entry.
        hostname_in_arp (str | None): Hostname on the live ARP row, or ``None`` when absent.
        expected_last_known (str | None): Expected ``last_known_hostname`` attribute.
    """
    arp_row: dict[str, Any] = {"mac": _COVERAGE_MAC, "ip": "10.0.0.5"}
    if hostname_in_arp is not None:
        arp_row["hostname"] = hostname_in_arp
    ent = _make_scanner_entity(
        coordinator=coordinator,
        make_config_entry=make_config_entry,
        coordinator_data={"arp_table": [arp_row]},
        mac=_COVERAGE_MAC,
    )
    object.__setattr__(ent, "async_write_ha_state", MagicMock())
    last_state = MagicMock()
    last_state.attributes = MappingProxyType({"last_known_hostname": "oldhost"})
    object.__setattr__(ent, "async_get_last_state", AsyncMock(return_value=last_state))
    await _restore_state(ent)

    ent._handle_coordinator_update()

    assert ent.is_connected is True
    attributes = ent.extra_state_attributes
    assert attributes is not None
    assert attributes.get("last_known_hostname") == expected_last_known


@pytest.mark.parametrize("consider_home", [0, 30])
def test_timestamped_ndp_presence_ages_away_and_returns(
    consider_home: int,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Retained neighbors must age away, and a fresh observation confirms the MAC again.

    Args:
        consider_home (int): Additional departure grace period.
        coordinator (MagicMock): Coordinator supplying API boundary payloads.
        make_config_entry (Callable[..., MockConfigEntry]): Config entry factory.
    """
    mac = "aa:bb:cc:dd:ee:01"
    entry = make_config_entry(
        data={CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={CONF_DEVICE_TRACKER_CONSIDER_HOME: consider_home},
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    entity = OPNsenseScannerEntity(entry, coordinator, True, mac, None, None)
    object.__setattr__(entity, "async_write_ha_state", MagicMock())
    last_seen = datetime.now(UTC)
    coordinator.data = {
        "arp_table": [{"mac": mac, "ip": "192.0.2.1"}],
        "ndp_table": [{"mac": mac, "ip": "2001:db8::1"}],
        "update_time": datetime.now(UTC).timestamp() - consider_home - 1,
    }
    coordinator.host_observation_times = {mac: last_seen}
    entity._handle_coordinator_update()
    identity = entity.unique_id
    assert entity.is_connected is True
    attributes = entity.extra_state_attributes
    assert attributes is not None
    last_sighting = attributes["last_known_connected_time"]

    coordinator.data["arp_table"] = []
    coordinator.data["update_time"] = datetime.now(UTC).timestamp()
    coordinator.host_observation_times = {mac: datetime.now(UTC) - timedelta(hours=1)}
    for _ in range(2):
        entity._handle_coordinator_update()
        assert entity.available is True
        assert entity.is_connected is False
        assert attributes["last_known_connected_time"] == last_sighting
        assert attributes["ipv6_addresses"] == ["2001:db8::1"]

    # Other recently observed MACs do not confirm this device's presence.
    coordinator.host_observation_times = {"aa:bb:cc:dd:ee:02": datetime.now(UTC)}
    entity._handle_coordinator_update()
    assert entity.available is False
    assert entity.is_connected is False
    assert attributes["ndp_presence_source"] == "no_evidence"

    # The same tracker can return through IPv6 after previously being observed through ARP.
    coordinator.host_observation_times = {mac: datetime.now(UTC)}
    entity._handle_coordinator_update()
    assert entity.is_connected is True
    assert entity.unique_id == identity
    assert entity.mac_address == mac
    assert attributes["ndp_presence_source"] == "host_discovery"


@pytest.mark.asyncio
async def test_coordinator_observation_index_confirms_restored_ndp_tracker(
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """A fresh coordinator observation should confirm an established NDP source.

    Args:
        ph_hass (HomeAssistant): Home Assistant instance used for coordinator refreshes.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake config entry.
    """
    mac = "aa:bb:cc:dd:ee:01"
    client = MagicMock()
    client.get_device_unique_id = AsyncMock(return_value="dev1")
    client.get_host_firmware_version = AsyncMock(return_value="26.1")
    client.get_system_info = AsyncMock(return_value={})
    client.get_arp_table = AsyncMock(return_value=[])
    client.get_ndp_table = AsyncMock(return_value=[{"mac": mac, "ip": "2001:db8::1"}])
    client.get_host_observations = AsyncMock(
        return_value={
            "source": "discovery",
            "rows": [{"mac": mac, "ip": "192.0.2.1", "last_seen": datetime.now(UTC)}],
        }
    )
    client.get_query_counts = AsyncMock(return_value=0)
    client.reset_query_counts = AsyncMock(
        side_effect=[None, OPNsenseTimeoutError("Query-count reset failed")]
    )
    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    coordinator = OPNsenseDataUpdateCoordinator(
        hass=ph_hass,
        client=client,
        name="device tracker",
        update_interval=timedelta(seconds=1),
        device_unique_id="dev1",
        config_entry=entry,
        device_tracker_coordinator=True,
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    await coordinator.async_refresh()

    entity = OPNsenseScannerEntity(entry, coordinator, True, mac, None, None)
    saved_state = State(
        "device_tracker.phone", "unavailable", {"ndp_presence_source": "host_discovery"}
    )
    object.__setattr__(entity, "async_get_last_state", AsyncMock(return_value=saved_state))
    object.__setattr__(entity, "async_write_ha_state", MagicMock())
    await _restore_state(entity)
    entity._handle_coordinator_update()

    assert entity.available is True
    assert entity.is_connected is True

    await coordinator.async_refresh()
    assert coordinator.last_update_success is False
    assert coordinator.host_observation_times is None

    entity._handle_coordinator_update()
    assert entity.available is False
    assert entity.is_connected is True


@pytest.mark.parametrize("saved_state_kind", ["brand_new", "legacy_home"])
@pytest.mark.parametrize(
    "observation_case",
    ["unavailable_index", "empty_index", "unobserved_mac", "invalid_index"],
)
@pytest.mark.asyncio
async def test_first_ndp_sighting_requires_current_same_mac_observation(
    saved_state_kind: str,
    observation_case: str,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """A matching NDP row cannot establish home without a usable same-MAC timestamp.

    Args:
        saved_state_kind (str): Whether the tracker is new or restores legacy home state.
        observation_case (str): Unavailable, empty, malformed, or nonmatching observation index.
        coordinator (MagicMock): Coordinator supplying API boundary state.
        make_config_entry (Callable[..., MockConfigEntry]): Config entry factory.
    """
    mac = "aa:bb:cc:dd:ee:01"
    observation_times_by_case: dict[str, object] = {
        "unavailable_index": None,
        "empty_index": {},
        "unobserved_mac": {"aa:bb:cc:dd:ee:02": datetime.now(UTC)},
        "invalid_index": {mac: "not-a-timestamp"},
    }
    observation_times = observation_times_by_case[observation_case]
    coordinator.data = {
        "arp_table": [],
        "ndp_table": [{"mac": mac, "ip": "2001:db8::1"}],
    }
    coordinator.host_observation_times = observation_times
    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    entity = OPNsenseScannerEntity(entry, coordinator, True, mac, None, None)
    object.__setattr__(entity, "async_write_ha_state", MagicMock())
    if saved_state_kind == "legacy_home":
        saved_state = State(
            "device_tracker.phone",
            "home",
            {
                "ndp_presence_source": "neighbor_table",
                "ipv6_addresses": ["2001:db8::1"],
                "last_known_connected_time": datetime.now(UTC).isoformat(),
            },
        )
        object.__setattr__(entity, "async_get_last_state", AsyncMock(return_value=saved_state))
        await _restore_state(entity)

    entity._handle_coordinator_update()

    assert entity.available is False
    assert entity.is_connected is False
    attributes = entity.extra_state_attributes
    assert attributes is not None
    assert attributes["ipv6_addresses"] == ["2001:db8::1"]
    assert attributes["ndp_presence_source"] == "no_evidence"

    coordinator.data["arp_table"] = [{"mac": mac, "ip": "192.0.2.1"}]
    coordinator.data["update_time"] = datetime.now(UTC).timestamp()
    entity._handle_coordinator_update()

    assert entity.available is True
    assert entity.is_connected is True


@pytest.mark.parametrize(
    ("firmware_version", "supports_host_observations"),
    [("25.1", False), ("25.7.10", True)],
    ids=["old-client-without-method", "unsupported-endpoint-returns-none"],
)
@pytest.mark.asyncio
async def test_old_firmware_ndp_metadata_does_not_confirm_presence_without_observations(
    firmware_version: str,
    supports_host_observations: bool,
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Older firmware or unavailable discovery keeps NDP metadata without confirming home.

    Args:
        firmware_version (str): OPNsense firmware reported by the real coordinator.
        supports_host_observations (bool): Whether the simulated client exposes the optional method.
        ph_hass (HomeAssistant): Home Assistant instance used for coordinator refreshes.
        make_config_entry (Callable[..., MockConfigEntry]): Factory for the fake config entry.
    """
    mac = "aa:bb:cc:dd:ee:01"
    methods = [
        "get_device_unique_id",
        "get_host_firmware_version",
        "get_system_info",
        "get_arp_table",
        "get_ndp_table",
        "get_query_counts",
        "reset_query_counts",
    ]
    if supports_host_observations:
        methods.append("get_host_observations")
    client = MagicMock(spec=methods)
    client.get_device_unique_id = AsyncMock(return_value="dev1")
    client.get_host_firmware_version = AsyncMock(return_value=firmware_version)
    client.get_system_info = AsyncMock(return_value={})
    client.get_arp_table = AsyncMock(return_value=[])
    client.get_ndp_table = AsyncMock(return_value=[{"mac": mac, "ip": "2001:db8::1"}])
    if supports_host_observations:
        client.get_host_observations = AsyncMock(return_value=None)
    client.get_query_counts = AsyncMock(return_value=0)
    client.reset_query_counts = AsyncMock()
    entry = make_config_entry(data={CONF_DEVICE_UNIQUE_ID: "dev1"})
    coordinator = OPNsenseDataUpdateCoordinator(
        hass=ph_hass,
        client=client,
        name="device tracker",
        update_interval=timedelta(seconds=1),
        device_unique_id="dev1",
        config_entry=entry,
        device_tracker_coordinator=True,
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    entity = OPNsenseScannerEntity(entry, coordinator, True, mac, None, None)
    object.__setattr__(entity, "async_write_ha_state", MagicMock())

    await coordinator.async_refresh()
    entity._handle_coordinator_update()

    assert coordinator.last_update_success is True
    assert coordinator.data["ndp_table"] == [{"mac": mac, "ip": "2001:db8::1"}]
    assert entity.available is False
    assert entity.is_connected is False
    attributes = entity.extra_state_attributes
    assert attributes is not None
    assert attributes["ipv6_addresses"] == ["2001:db8::1"]
    assert attributes["ndp_presence_source"] == "no_evidence"

    client.get_arp_table.return_value = [{"mac": mac, "ip": "192.0.2.1"}]
    await coordinator.async_refresh()
    entity._handle_coordinator_update()

    assert coordinator.last_update_success is True
    assert entity.available is True
    assert entity.is_connected is True


@pytest.mark.parametrize("failed_index", [None, {}])
@pytest.mark.asyncio
async def test_restored_home_needs_current_ndp_evidence(
    failed_index: dict[str, datetime] | None,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """A restored home state cannot revive NDP presence without a current observation.

    Args:
        failed_index (dict[str, datetime] | None): Unavailable or empty observation index.
        coordinator (MagicMock): Coordinator supplying API boundary payloads.
        make_config_entry (Callable[..., MockConfigEntry]): Config entry factory.
    """
    mac = "aa:bb:cc:dd:ee:01"
    coordinator.host_observation_times = failed_index
    entity = _make_scanner_entity(
        coordinator,
        make_config_entry,
        mac=mac,
        coordinator_data={
            "arp_table": [],
            "ndp_table": [{"mac": mac, "ip": "2001:db8::1"}],
        },
    )
    saved = State(
        "device_tracker.phone",
        "home",
        {
            "ndp_presence_source": "host_discovery",
            "ipv6_addresses": ["2001:db8::1"],
            "last_known_connected_time": datetime.now(UTC).isoformat(),
        },
    )
    object.__setattr__(entity, "async_get_last_state", AsyncMock(return_value=saved))
    object.__setattr__(entity, "async_write_ha_state", MagicMock())
    await _restore_state(entity)
    healthy_tables = coordinator.data.copy()
    coordinator.data["arp_table"] = None
    coordinator.data["ndp_table"] = None
    entity._handle_coordinator_update()
    assert entity.available is False

    # Restoring the just-published unavailable state must not let the same NDP row revive home.
    published = entity.extra_state_attributes
    assert published is not None
    saved = State("device_tracker.phone", "unavailable", published)
    entity = _make_scanner_entity(
        coordinator,
        make_config_entry,
        mac=mac,
        coordinator_data=healthy_tables,
    )
    object.__setattr__(entity, "async_get_last_state", AsyncMock(return_value=saved))
    object.__setattr__(entity, "async_write_ha_state", MagicMock())
    await _restore_state(entity)
    entity._handle_coordinator_update()
    assert entity.available is False

    coordinator.data["arp_table"] = [{"mac": mac, "ip": "192.0.2.1"}]
    entity._handle_coordinator_update()
    assert entity.available is True
    assert entity.is_connected is True

    # A successful empty NDP scan still proves absence even if observations are unavailable.
    coordinator.data["arp_table"] = []
    coordinator.data["ndp_table"] = []
    entity._handle_coordinator_update()
    assert entity.available is True
    assert entity.is_connected is False


@pytest.mark.parametrize(
    ("scan_interval", "age_secs", "expected_connected"),
    [
        (150, 19 * 60, True),
        (150, 21 * 60, False),
        (900, 29 * 60, True),
        (900, 31 * 60, False),
        ("invalid", 19 * 60, True),
        ("invalid", 21 * 60, False),
        (True, 19 * 60, True),
    ],
)
def test_ndp_freshness_window_scales_with_scan_interval(
    scan_interval: object,
    age_secs: int,
    expected_connected: bool,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """The NDP window is the larger of the 20 minute floor and twice the scan interval.

    Args:
        scan_interval (object): Configured scan interval in seconds; non-numeric values fall back to
            the default.
        age_secs (int): Age of the discovery observation in seconds.
        expected_connected (bool): Whether the observation is still fresh.
        coordinator (MagicMock): Coordinator supplying API boundary state.
        make_config_entry (Callable[..., MockConfigEntry]): Config entry factory.
    """
    mac = "aa:bb:cc:dd:ee:01"
    entry = make_config_entry(
        data={CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={CONF_DEVICE_TRACKER_SCAN_INTERVAL: scan_interval},
    )
    setattr(entry.runtime_data, DEVICE_TRACKER_COORDINATOR, coordinator)
    entity = OPNsenseScannerEntity(entry, coordinator, True, mac, None, None)
    object.__setattr__(entity, "async_write_ha_state", MagicMock())
    coordinator.data = {
        "arp_table": [],
        "ndp_table": [{"mac": mac, "ip": "2001:db8::1"}],
        "update_time": datetime.now(UTC).timestamp(),
    }
    coordinator.host_observation_times = {mac: datetime.now(UTC) - timedelta(seconds=age_secs)}

    entity._handle_coordinator_update()

    assert entity.is_connected is expected_connected


@pytest.mark.parametrize(
    ("observation_age_secs", "indexed", "expected_available", "expected_connected", "source"),
    [
        pytest.param(None, "no_index", False, False, "no_evidence", id="index-none"),
        pytest.param(None, "other_mac", False, False, "no_evidence", id="index-without-mac"),
        pytest.param(3 * 3600, "tracker_mac", True, False, "host_discovery", id="stale-away"),
        pytest.param(60, "tracker_mac", True, True, "host_discovery", id="fresh-home"),
    ],
)
def test_expired_arp_with_ndp_row_requires_timestamp_evidence(
    observation_age_secs: int | None,
    indexed: str,
    expected_available: bool,
    expected_connected: bool,
    source: str,
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """An expired ARP entry plus an NDP row is unknown without a timestamp, away if stale.

    Args:
        observation_age_secs (int | None): Age of the discovery timestamp, if one is indexed.
        indexed (str): Whether the index is absent, lacks the tracker MAC, or has it.
        expected_available (bool): Whether the tracker should report a known state.
        expected_connected (bool): Whether the tracker should be home.
        source (str): Expected ``ndp_presence_source`` attribute.
        coordinator (MagicMock): Coordinator supplying API boundary state.
        make_config_entry (Callable[..., MockConfigEntry]): Config entry factory.
    """
    mac = "aa:bb:cc:dd:ee:01"
    entity = _make_scanner_entity(
        coordinator,
        make_config_entry,
        mac=mac,
        coordinator_data={
            "arp_table": [{"mac": mac, "ip": "192.0.2.1", "expired": True}],
            "ndp_table": [{"mac": mac, "ip": "2001:db8::1"}],
            "update_time": datetime.now(UTC).timestamp(),
        },
    )
    object.__setattr__(entity, "async_write_ha_state", MagicMock())
    if indexed == "other_mac":
        coordinator.host_observation_times = {"aa:bb:cc:dd:ee:02": datetime.now(UTC)}
    elif indexed == "tracker_mac" and observation_age_secs is not None:
        coordinator.host_observation_times = {
            mac: datetime.now(UTC) - timedelta(seconds=observation_age_secs)
        }

    entity._handle_coordinator_update()

    assert entity.available is expected_available
    assert entity.is_connected is expected_connected
    assert entity.extra_state_attributes is not None
    assert entity.extra_state_attributes["ndp_presence_source"] == source


def test_no_evidence_attribute_describes_ndp_evidence_only(
    coordinator: MagicMock,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """ARP can confirm presence while the NDP evidence attribute reports no_evidence.

    Args:
        coordinator (MagicMock): Coordinator supplying API boundary state.
        make_config_entry (Callable[..., MockConfigEntry]): Config entry factory.
    """
    mac = "aa:bb:cc:dd:ee:01"
    coordinator.host_observation_times = None
    entity = _make_scanner_entity(
        coordinator,
        make_config_entry,
        mac=mac,
        coordinator_data={
            "arp_table": [{"mac": mac, "ip": "192.0.2.1"}],
            "ndp_table": [],
        },
    )
    object.__setattr__(entity, "async_write_ha_state", MagicMock())

    entity._handle_coordinator_update()

    assert entity.available is True
    assert entity.is_connected is True
    assert entity.extra_state_attributes is not None
    assert entity.extra_state_attributes["ndp_presence_source"] == "no_evidence"
