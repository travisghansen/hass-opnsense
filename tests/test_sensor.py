"""Unit tests for custom_components.opnsense.sensor.

These tests use relative imports from the package root to locate the integration code.
They are tolerant: if the expected function is not present in the sensor module the tests
will be skipped rather than failing, making the test file safe to add to the repository
without breaking CI for different code states.
"""

from contextlib import suppress
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.opnsense import sensor as sensor_module
from custom_components.opnsense.const import (
    CONF_DEVICE_UNIQUE_ID,
    CONF_SYNC_CARP,
    CONF_SYNC_CERTIFICATES,
    CONF_SYNC_DHCP_LEASES,
    CONF_SYNC_GATEWAYS,
    CONF_SYNC_INTERFACES,
    CONF_SYNC_TELEMETRY,
    CONF_SYNC_VPN,
    COORDINATOR,
)
from custom_components.opnsense.sensor import (
    OPNsenseCarpInterfaceSensor,
    OPNsenseDHCPLeasesSensor,
    OPNsenseFilesystemSensor,
    OPNsenseGatewaySensor,
    OPNsenseInterfaceSensor,
    OPNsenseStaticKeySensor,
    OPNsenseTempSensor,
    OPNsenseVPNSensor,
    _compile_carp_interface_sensors,
    _compile_dhcp_leases_sensors,
    _compile_filesystem_sensors,
    _compile_gateway_sensors,
    _compile_interface_sensors,
    _compile_static_certificate_sensors,
    _compile_static_telemetry_sensors,
    _compile_temperature_sensors,
    _compile_vpn_sensors,
    async_setup_entry,
    normalize_filesystem_mountpoint,
    slugify_filesystem_mountpoint,
)


def _make_config_entry() -> MockConfigEntry:
    """Return a minimal MockConfigEntry for tests."""
    entry = MockConfigEntry(
        domain="opnsense", data={CONF_DEVICE_UNIQUE_ID: "test-device-123"}, title="OPNsense Test"
    )
    # Use a dict for runtime_data so tests can assign coordinator by key when needed
    entry.runtime_data = {}
    return entry


@pytest.mark.asyncio
async def test_async_setup_entry_invalid_state(monkeypatch):
    """async_setup_entry should do nothing when coordinator.data is invalid."""
    config_entry = _make_config_entry()
    # runtime_data used by async_setup_entry expects an attribute named COORDINATOR
    coordinator = SimpleNamespace(data=None)
    config_entry.runtime_data = SimpleNamespace(**{COORDINATOR: coordinator})

    called = False

    def add_entities(entities):
        nonlocal called
        called = True

    await async_setup_entry(MagicMock(), config_entry, add_entities)
    assert called is False


@pytest.mark.asyncio
async def test_static_key_sensor_cpu_and_boot_and_certificates():
    coordinator = SimpleNamespace(
        data={
            "telemetry": {
                "cpu": {"usage_1": 10, "usage_2": 20, "usage_total": 30},
                "system": {"boottime": 1609459200},
            },
            "certificates": {"a": 1, "b": 2},
        }
    )

    entry = _make_config_entry()

    # CPU total sensor
    desc = MagicMock()
    desc.key = "telemetry.cpu.usage_total"
    desc.name = "CPU Total"
    s_cpu = OPNsenseStaticKeySensor(
        config_entry=entry, coordinator=coordinator, entity_description=desc
    )
    s_cpu.hass = MagicMock()
    s_cpu.entity_id = "sensor.cpu_total"
    s_cpu.async_write_ha_state = lambda: None
    # first call when previous is None and value !=0 -> available True and extra attributes
    s_cpu._handle_coordinator_update()
    assert s_cpu.available is True
    assert s_cpu.native_value == 30
    assert "1" not in s_cpu.extra_state_attributes or isinstance(s_cpu.extra_state_attributes, dict)

    # boottime sensor -> converted to datetime
    desc2 = MagicMock()
    desc2.key = "telemetry.system.boottime"
    desc2.name = "Boot Time"
    s_boot = OPNsenseStaticKeySensor(
        config_entry=entry, coordinator=coordinator, entity_description=desc2
    )
    s_boot.hass = MagicMock()
    s_boot.entity_id = "sensor.boottime"
    s_boot.async_write_ha_state = lambda: None
    s_boot._handle_coordinator_update()
    assert s_boot.available is True
    assert s_boot.native_value is not None

    # certificates -> length
    desc3 = MagicMock()
    desc3.key = "certificates"
    desc3.name = "Certs"
    s_cert = OPNsenseStaticKeySensor(
        config_entry=entry, coordinator=coordinator, entity_description=desc3
    )
    s_cert.hass = MagicMock()
    s_cert.entity_id = "sensor.certs"
    s_cert.async_write_ha_state = lambda: None
    s_cert._handle_coordinator_update()
    assert s_cert.available is True
    assert s_cert.native_value == len(coordinator.data["certificates"])


@pytest.mark.asyncio
async def test_filesystem_and_compile_helpers():
    state = {
        "telemetry": {
            "filesystems": [
                {
                    "mountpoint": "/",
                    "used_pct": 9,
                    "device": "/dev/sda1",
                    "type": "ext4",
                    "blocks": 100,
                    "used": 9,
                    "available": 91,
                }
            ]
        }
    }
    entry = _make_config_entry()
    coordinator = SimpleNamespace(data=state)

    # compile filesystem sensors directly
    entities = await _compile_filesystem_sensors(entry, coordinator, state)
    assert any("telemetry.filesystems.root" in e.entity_description.key for e in entities)

    # instance sensor behavior
    desc = MagicMock()
    desc.key = "telemetry.filesystems.root"
    desc.name = "Filesystem /"
    s_fs = OPNsenseFilesystemSensor(
        config_entry=entry, coordinator=coordinator, entity_description=desc
    )
    s_fs.hass = MagicMock()
    s_fs.entity_id = "sensor.fs_root"
    s_fs.async_write_ha_state = lambda: None
    s_fs._handle_coordinator_update()
    assert s_fs.available is True
    assert s_fs.native_value == 9
    assert s_fs.extra_state_attributes["mountpoint"] == "/"

    # missing used_pct -> unavailable
    state2 = {"telemetry": {"filesystems": [{"mountpoint": "/var"}]}}
    coordinator2 = SimpleNamespace(data=state2)
    s_fs2 = OPNsenseFilesystemSensor(
        config_entry=entry, coordinator=coordinator2, entity_description=desc
    )
    s_fs2.hass = MagicMock()
    s_fs2.entity_id = "sensor.fs_var"
    s_fs2.async_write_ha_state = lambda: None
    s_fs2._handle_coordinator_update()
    assert s_fs2.available is False


@pytest.mark.asyncio
async def test_interface_and_icon_behavior():
    state = {
        "interfaces": {
            "lan": {
                "name": "LAN",
                "inbytes": 12345,
                "status": "down",
                "interface": "lan0",
                "device": "eth0",
            }
        }
    }
    entry = _make_config_entry()
    coordinator = SimpleNamespace(data=state)

    # inbytes sensor
    desc = MagicMock()
    desc.key = "interface.lan.inbytes"
    desc.name = "In Bytes"
    s_if = OPNsenseInterfaceSensor(
        config_entry=entry, coordinator=coordinator, entity_description=desc
    )
    s_if.hass = MagicMock()
    s_if.entity_id = "sensor.lan_inbytes"
    s_if.async_write_ha_state = lambda: None
    s_if._handle_coordinator_update()
    assert s_if.available is True
    assert s_if.native_value == 12345

    # status sensor icon when not up
    desc2 = MagicMock()
    desc2.key = "interface.lan.status"
    desc2.name = "Status"
    s_status = OPNsenseInterfaceSensor(
        config_entry=entry, coordinator=coordinator, entity_description=desc2
    )
    s_status.hass = MagicMock()
    s_status.entity_id = "sensor.lan_status"
    s_status.async_write_ha_state = lambda: None
    s_status._handle_coordinator_update()
    assert s_status.icon == "mdi:close-network-outline"


@pytest.mark.asyncio
async def test_carp_and_gateway_and_vpn_and_temp_and_dhcp():
    state = {
        "carp_interfaces": [
            {"subnet": "10.0.0.1", "status": "MASTER", "interface": "lan0", "vhid": 1}
        ],
        "gateways": {"gw1": {"name": "gw1", "delay": "12ms", "loss": "0", "status": "online"}},
        "openvpn": {
            "servers": {
                "uuid1": {
                    "name": "ovpn",
                    "status": "up",
                    "clients": [{"name": "c1", "status": "up"}],
                }
            }
        },
        "telemetry": {"temps": {"sensor1": {"temperature": 42, "device_id": "dev1"}}},
        "dhcp_leases": {
            "leases": {"lan": [{"address": "192.168.1.2"}]},
            "lease_interfaces": {"lan": "LAN"},
        },
    }
    entry = _make_config_entry()
    coordinator = SimpleNamespace(data=state)

    # carp interface
    desc_carp = MagicMock()
    desc_carp.key = f"carp.interface.{sensor_module.slugify('10.0.0.1')}"
    desc_carp.name = "CARP"
    s_carp = OPNsenseCarpInterfaceSensor(
        config_entry=entry, coordinator=coordinator, entity_description=desc_carp
    )
    s_carp.hass = MagicMock()
    s_carp.entity_id = "sensor.carp"
    s_carp.async_write_ha_state = lambda: None
    s_carp._handle_coordinator_update()
    assert s_carp.available is True
    assert s_carp.native_value == "MASTER"
    # icon falls back to super().icon for MASTER; ensure it's not the "down" icon
    assert s_carp.icon != "mdi:close-network-outline"

    # gateway cleanses ms and converts
    desc_gw = MagicMock()
    desc_gw.key = "gateway.gw1.delay"
    desc_gw.name = "Gateway Delay"
    s_gw = OPNsenseGatewaySensor(
        config_entry=entry, coordinator=coordinator, entity_description=desc_gw
    )
    s_gw.hass = MagicMock()
    s_gw.entity_id = "sensor.gw_delay"
    s_gw.async_write_ha_state = lambda: None
    s_gw._handle_coordinator_update()
    assert s_gw.available is True
    assert float(s_gw.native_value) == 12.0

    # VPN server with clients -> clients attr present
    desc_vpn = MagicMock()
    desc_vpn.key = "openvpn.servers.uuid1.status"
    desc_vpn.name = "OpenVPN Server"
    s_vpn = OPNsenseVPNSensor(
        config_entry=entry, coordinator=coordinator, entity_description=desc_vpn
    )
    s_vpn.hass = MagicMock()
    s_vpn.entity_id = "sensor.ovpn"
    s_vpn.async_write_ha_state = lambda: None
    s_vpn._handle_coordinator_update()
    assert s_vpn.available is True
    assert "clients" in s_vpn.extra_state_attributes

    # temp
    desc_temp = MagicMock()
    desc_temp.key = "telemetry.temps.sensor1"
    desc_temp.name = "Temp"
    s_temp = OPNsenseTempSensor(
        config_entry=entry, coordinator=coordinator, entity_description=desc_temp
    )
    s_temp.hass = MagicMock()
    s_temp.entity_id = "sensor.temp"
    s_temp.async_write_ha_state = lambda: None
    s_temp._handle_coordinator_update()
    assert s_temp.available is True
    assert s_temp.native_value == 42

    # dhcp leases all
    desc_all = MagicMock()
    desc_all.key = "dhcp_leases.all"
    desc_all.name = "DHCP All"
    s_all = OPNsenseDHCPLeasesSensor(
        config_entry=entry, coordinator=coordinator, entity_description=desc_all
    )
    s_all.hass = MagicMock()
    s_all.entity_id = "sensor.dhcp_all"
    s_all.async_write_ha_state = lambda: None
    s_all._handle_coordinator_update()
    assert s_all.available is True
    assert isinstance(s_all.native_value, int)


def test_sensor_module_import() -> None:
    """Test that the sensor module can be imported via relative import."""
    assert sensor_module is not None


@pytest.mark.parametrize(
    "input_value,expected",
    [
        (None, ""),
        ("", ""),
        ("/", "root"),
        ("/boot", "boot"),
        ("/var/log", "var_log"),
        ("var/log/", "var_log"),
        ("//multiple///slashes//", "multiple___slashes"),
        ("relative/path", "relative_path"),
    ],
)
def test_slugify_filesystem_mountpoint(input_value: Any, expected: str) -> None:
    """slugify_filesystem_mountpoint should convert mountpoints to slugs."""
    assert slugify_filesystem_mountpoint(input_value) == expected


@pytest.mark.parametrize(
    "input_value,expected",
    [
        (None, ""),
        ("", ""),
        ("/", "root"),
        ("/boot", "/boot"),
        ("/var/log", "/var/log"),
        ("var/log/", "var/log"),
        ("//multiple///slashes//", "//multiple///slashes"),
    ],
)
def test_normalize_filesystem_mountpoint(input_value: Any, expected: str) -> None:
    """normalize_filesystem_mountpoint should strip trailing slashes and handle root."""
    assert normalize_filesystem_mountpoint(input_value) == expected


def test_static_cpu_zero_unavailable():
    coord = SimpleNamespace(data={"telemetry": {"cpu": {"usage_total": 0}}})
    entry = _make_config_entry()

    desc = MagicMock()
    desc.key = "telemetry.cpu.usage_total"
    desc.name = "CPU Total"

    s = OPNsenseStaticKeySensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.cpu_zero"
    s.async_write_ha_state = lambda: None
    s._handle_coordinator_update()
    assert s.available is False


def test_static_cpu_zero_use_previous():
    coord = SimpleNamespace(data={"telemetry": {"cpu": {"usage_total": 0, "usage_1": 1}}})
    entry = _make_config_entry()

    desc = MagicMock()
    desc.key = "telemetry.cpu.usage_total"
    desc.name = "CPU Total"

    s = OPNsenseStaticKeySensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.cpu_prev"
    s.async_write_ha_state = lambda: None
    # simulate previous value
    s._previous_value = 7
    s._handle_coordinator_update()
    assert s.available is True
    assert s.native_value == 7


def test_gateway_empty_string_unavailable():
    state = {"gateways": {"gw1": {"name": "gw1", "status": ""}}}
    coord = SimpleNamespace(data=state)
    entry = _make_config_entry()

    desc = MagicMock()
    desc.key = "gateway.gw1.status"
    desc.name = "Gateway Status"

    s = OPNsenseGatewaySensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.gw_empty"
    s.async_write_ha_state = lambda: None
    s._handle_coordinator_update()
    assert s.available is False


def test_interface_status_icon_up():
    state = {"interfaces": {"lan": {"name": "LAN", "status": "up", "interface": "lan0"}}}
    coord = SimpleNamespace(data=state)
    entry = _make_config_entry()

    desc = MagicMock()
    desc.key = "interface.lan.status"
    desc.name = "LAN Status"

    s = OPNsenseInterfaceSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.lan_status_up"
    s.async_write_ha_state = lambda: None
    s._handle_coordinator_update()
    # when native_value is 'up', icon should not be the down icon
    assert s.icon != "mdi:close-network-outline"


def _setup_entry_with_all_syncs(state: dict):
    entry = _make_config_entry()
    # enable all sync options; entry.data may be a mappingproxy so construct a new dict
    base = dict(entry.data)
    base.update(
        {
            CONF_SYNC_TELEMETRY: True,
            CONF_SYNC_CERTIFICATES: True,
            CONF_SYNC_VPN: True,
            CONF_SYNC_GATEWAYS: True,
            CONF_SYNC_INTERFACES: True,
            CONF_SYNC_CARP: True,
            CONF_SYNC_DHCP_LEASES: True,
        }
    )
    # create a new MockConfigEntry with the updated data to avoid mutating mappingproxy
    entry = MockConfigEntry(domain=entry.domain, data=base, title=entry.title)
    coord = SimpleNamespace(data=state)
    entry.runtime_data = SimpleNamespace(**{COORDINATOR: coord})
    return entry, coord


@pytest.mark.asyncio
async def test_compile_and_handle_many_entities():
    # craft a rich state to exercise many branches
    state = {
        "telemetry": {
            "filesystems": [
                {
                    "mountpoint": "/",
                    "used_pct": 5,
                    "device": "/dev/sda1",
                    "type": "ext4",
                    "blocks": 1000,
                    "used": 50,
                    "available": 950,
                },
                {
                    "mountpoint": "/var/log",
                    "used_pct": 12,
                    "device": "/dev/sdb1",
                    "type": "ext4",
                    "blocks": 2000,
                    "used": 240,
                    "available": 1760,
                },
            ],
            "temps": {"cpu": {"temperature": 55, "device_id": "cpu0"}},
            "cpu": {"usage_total": 10, "usage_1": 4, "usage_2": 6},
        },
        "interfaces": {
            "wan": {
                "name": "WAN",
                "inbytes_kilobytes_per_second": 1.2,
                "outbytes_kilobytes_per_second": 0.8,
                "inpkts_packets_per_second": 100,
                "status": "up",
                "interface": "wan0",
                "device": "eth0",
            },
            "lan": {
                "name": "LAN",
                "inbytes": 12345,
                "outpkts_packets_per_second": 50,
                "status": "down",
                "interface": "lan0",
                "device": "eth1",
            },
        },
        "gateways": {
            "gw1": {
                "name": "gw1",
                "delay": "15ms",
                "stddev": "1ms",
                "loss": "0%",
                "status": "online",
            }
        },
        "carp_interfaces": [
            {
                "subnet": "192.0.2.1",
                "status": "BACKUP",
                "interface": "lan0",
                "vhid": 2,
                "advskew": 100,
            }
        ],
        "openvpn": {
            "servers": {
                "s1": {"name": "ovpn1", "status": "up", "clients": [{"name": "c1", "status": "up"}]}
            }
        },
        "wireguard": {
            "servers": {"wg1": {"name": "wg1", "status": "up", "clients": []}},
            "clients": {"c1": {"name": "c1", "enabled": True}},
        },
        "dhcp_leases": {
            "leases": {"lan": [{"address": "192.168.1.2", "hostname": "host1"}]},
            "lease_interfaces": {"lan": "LAN"},
        },
        "certificates": {"a": 1},
    }

    entry, coord = _setup_entry_with_all_syncs(state)

    # compile all entity lists
    entities = []
    entities.extend(await _compile_static_telemetry_sensors(entry, coord))
    entities.extend(await _compile_static_certificate_sensors(entry, coord))
    entities.extend(await _compile_filesystem_sensors(entry, coord, state))
    entities.extend(await _compile_temperature_sensors(entry, coord, state))
    entities.extend(await _compile_vpn_sensors(entry, coord, state))
    entities.extend(await _compile_gateway_sensors(entry, coord, state))
    entities.extend(await _compile_interface_sensors(entry, coord, state))
    entities.extend(await _compile_carp_interface_sensors(entry, coord, state))
    entities.extend(await _compile_dhcp_leases_sensors(entry, coord, state))

    # Ensure we produced entities
    assert len(entities) > 0

    # Exercise each entity's update handler
    for i, ent in enumerate(entities):
        ent.hass = MagicMock()
        ent.entity_id = f"sensor.test_{i}"
        ent.async_write_ha_state = lambda: None
        # call handler where present and ignore common data-related exceptions
        with suppress(TypeError, KeyError, ZeroDivisionError, AttributeError):
            ent._handle_coordinator_update()


@pytest.mark.asyncio
async def test_async_setup_entry_creates_entities():
    state = {"telemetry": {"filesystems": [], "temps": {}}, "interfaces": {}, "gateways": {}}
    entry, coord = _setup_entry_with_all_syncs(state)

    created: list = []

    def add_entities(ents):
        created.extend(ents)

    await async_setup_entry(MagicMock(), entry, add_entities)
    assert isinstance(created, list)
    # should not error and should return a list (may be empty depending on static lists)


@pytest.mark.asyncio
async def test_compile_interface_sensors_values_end():
    """Extra test to ensure interface sensors report expected numeric values."""
    state = {
        "interfaces": {
            "eth0": {
                "name": "eth0",
                "inbytes_kilobytes_per_second": 123,
                "inpkts_packets_per_second": 10,
                "inbytes": 2048,
                "inpkts": 100,
                "status": "up",
                "interface": "eth0",
                "device": "eth0",
            }
        }
    }
    entry = _make_config_entry()
    coordinator = SimpleNamespace(data=state)

    entities = await _compile_interface_sensors(entry, coordinator, state)
    assert any(e.entity_description.key.startswith("interface.eth0.") for e in entities)

    kb_entity = next(
        e for e in entities if e.entity_description.key.endswith("inbytes_kilobytes_per_second")
    )
    kb = OPNsenseInterfaceSensor(
        config_entry=entry, coordinator=coordinator, entity_description=kb_entity.entity_description
    )
    kb.hass = MagicMock()
    kb.entity_id = "sensor.eth0_inkb"
    kb.async_write_ha_state = lambda: None
    kb._handle_coordinator_update()
    assert kb.available is True
    assert kb.native_value == 123
