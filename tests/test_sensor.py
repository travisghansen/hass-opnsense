"""These tests import the integration code via relative imports and assert behavior across sensor variants using a synthesized coordinator state."""

from collections.abc import Callable, Iterable
from typing import Any, Never, cast
from unittest.mock import MagicMock

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.helpers.entity_platform import AddEntitiesCallback
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.opnsense import const as const_module, sensor as sensor_module
from custom_components.opnsense.const import (
    CONF_SYNC_CARP,
    CONF_SYNC_CERTIFICATES,
    CONF_SYNC_DHCP_LEASES,
    CONF_SYNC_GATEWAYS,
    CONF_SYNC_INTERFACES,
    CONF_SYNC_SMART,
    CONF_SYNC_SPEEDTEST,
    CONF_SYNC_TELEMETRY,
    CONF_SYNC_VNSTAT,
    CONF_SYNC_VPN,
    COORDINATOR,
)
from custom_components.opnsense.coordinator import OPNsenseDataUpdateCoordinator
from custom_components.opnsense.sensor import (
    OPNsenseCarpActiveResponderSensor,
    OPNsenseCarpInterfaceSensor,
    OPNsenseCarpStatusSensor,
    OPNsenseCarpVipSensor,
    OPNsenseDHCPLeasesSensor,
    OPNsenseFilesystemSensor,
    OPNsenseGatewaySensor,
    OPNsenseInterfaceSensor,
    OPNsenseSmartSensor,
    OPNsenseSpeedtestSensor,
    OPNsenseStaticKeySensor,
    OPNsenseTempSensor,
    OPNsenseVnstatSensor,
    OPNsenseVPNSensor,
    async_setup_entry,
    normalize_filesystem_mountpoint,
    slugify_filesystem_mountpoint,
)


def test_static_sensor_descriptions_live_in_sensor_module() -> None:
    """Static sensor descriptions should be owned by the sensor platform."""
    telemetry_keys = {description.key for description in sensor_module.STATIC_TELEMETRY_SENSORS}
    certificate_keys = {description.key for description in sensor_module.STATIC_CERTIFICATE_SENSORS}

    assert not hasattr(const_module, "STATIC_TELEMETRY_SENSORS")
    assert not hasattr(const_module, "STATIC_CERTIFICATE_SENSORS")
    assert "telemetry.cpu.usage_total" in telemetry_keys
    assert "certificates" in certificate_keys


@pytest.mark.asyncio
async def test_async_setup_entry_invalid_state(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry should do nothing when coordinator.data is invalid."""
    config_entry = make_config_entry()
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = None
    setattr(config_entry.runtime_data, COORDINATOR, coordinator)

    called = False

    def add_entities(entities: Iterable[Any], _update_before_add: bool = False) -> None:
        """Add entities.

        Args:
            entities: Entities provided by pytest or the test case.
        """
        nonlocal called
        called = True

    await async_setup_entry(MagicMock(), config_entry, cast("AddEntitiesCallback", add_entities))
    assert called is False


@pytest.mark.asyncio
async def test_carp_entry_setup_has_exact_read_only_vip_inventory(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP entries should expose only the responder, summary, and VIP sensors."""
    entry = make_config_entry(
        data={"entry_type": "carp"},
        entry_id="carp-entry",
        title="CARP VIP",
    )
    state: dict[str, Any] = {
        "system_info": {"name": "node-a"},
        "carp": {
            "interfaces": [
                {"vhid": 1, "subnet": "192.0.2.1", "interface": "igc0", "status": "BACKUP"},
                {
                    "vhid": "2",
                    "subnet": "198.51.100.1",
                    "interface": "igc1",
                    "status": "MASTER",
                },
            ],
            "status_summary": {"state": "healthy"},
        },
    }
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = state
    setattr(entry.runtime_data, COORDINATOR, coordinator)
    created: list[Any] = []

    def add_entities(entities: Iterable[Any], _update_before_add: bool = False) -> None:
        """Collect entities created by the sensor platform."""
        created.extend(entities)

    await async_setup_entry(MagicMock(), entry, cast("AddEntitiesCallback", add_entities))

    keys = {entity.entity_description.key for entity in created}
    expected_keys = {
        "carp.active_responder",
        "carp.status_summary",
        sensor_module._build_carp_vip_sensor_key("1", "192.0.2.1"),
        sensor_module._build_carp_vip_sensor_key("2", "198.51.100.1"),
    }
    expected_unique_ids = {
        sensor_module.slugify(f"{entry.entry_id}_{key}") for key in expected_keys
    }
    assert keys == expected_keys
    assert {entity.unique_id for entity in created} == expected_unique_ids
    descriptions = {entity.entity_description.key: entity.entity_description for entity in created}
    assert descriptions["carp.active_responder"].translation_key == "carp_active_responder"
    assert descriptions["carp.status_summary"].translation_key == "carp_status_summary"
    vip_descriptions = [
        description for key, description in descriptions.items() if key.startswith("carp.vip.")
    ]
    assert {description.translation_key for description in vip_descriptions} == {"carp_vip"}
    assert all(
        set(description.translation_placeholders or {}) == {"subnet", "vhid"}
        for description in vip_descriptions
    )
    assert all(
        entity.entity_description.entity_registry_enabled_default is False
        for entity in created
        if entity.entity_description.key.startswith("carp.vip.")
    )
    assert isinstance(
        next(
            entity for entity in created if entity.entity_description.key == "carp.active_responder"
        ),
        OPNsenseCarpActiveResponderSensor,
    )
    assert all(
        isinstance(entity, OPNsenseCarpVipSensor)
        for entity in created
        if entity.entity_description.key.startswith("carp.vip.")
    )
    assert all(entity.entity_description.key.startswith("carp.") for entity in created)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("entry_data", "expected_translation_key"),
    [
        ({}, None),
        ({"entry_type": "carp"}, "carp_status_summary"),
    ],
)
async def test_carp_status_description_preserves_entry_mode_naming(
    entry_data: dict[str, Any],
    expected_translation_key: str | None,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP status should keep legacy device naming and translated CARP naming."""
    entry = make_config_entry(data=entry_data)
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = {"carp": {"status_summary": {"state": "healthy"}}}

    entities = await sensor_module._compile_carp_status_sensor(entry, coordinator, coordinator.data)

    assert len(entities) == 1
    sensor = entities[0]
    assert sensor.entity_description.translation_key == expected_translation_key
    if expected_translation_key is None:
        assert sensor.name == "CARP Status"


@pytest.mark.asyncio
async def test_carp_entry_failover_keeps_vip_identity_and_updates_responder(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP failover should update the responder while retaining each VIP entity."""
    entry = make_config_entry(
        data={"entry_type": "carp"},
        entry_id="carp-entry",
        title="CARP VIP",
    )
    state: dict[str, Any] = {
        "system_info": {"name": "node-a"},
        "carp": {
            "interfaces": [
                {
                    "vhid": 1,
                    "subnet": "192.0.2.1",
                    "interface": "igc0",
                    "status": "BACKUP",
                    "advskew": 100,
                    "advbase": 1,
                    "subnet_bits": 24,
                    "descr": "Primary VIP",
                    "mode": "carp",
                }
            ],
            "status_summary": {"state": "healthy"},
        },
    }
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = state
    setattr(entry.runtime_data, COORDINATOR, coordinator)
    created: list[Any] = []

    def add_entities(entities: Iterable[Any], _update_before_add: bool = False) -> None:
        """Collect entities created by the sensor platform."""
        created.extend(entities)

    await async_setup_entry(MagicMock(), entry, cast("AddEntitiesCallback", add_entities))
    responder = next(
        entity for entity in created if entity.entity_description.key == "carp.active_responder"
    )
    vip = next(
        entity for entity in created if entity.entity_description.key.startswith("carp.vip.")
    )
    initial_unique_id = vip.unique_id
    for entity in (responder, vip):
        entity.hass = MagicMock()
        object.__setattr__(entity, "async_write_ha_state", lambda: None)
        entity._handle_coordinator_update()

    assert responder.native_value == "node-a"
    assert responder.extra_state_attributes == {}
    assert vip.available is True
    assert vip.native_value == "BACKUP"
    assert vip.icon == "mdi:backup-restore"

    state["system_info"]["name"] = "node-b"
    state["carp"]["interfaces"][0]["interface"] = "ix0"
    state["carp"]["interfaces"][0]["status"] = "MASTER"
    responder._handle_coordinator_update()
    vip._handle_coordinator_update()

    assert responder.native_value == "node-b"
    assert vip.available is True
    assert vip.native_value == "MASTER"
    assert vip.icon == "mdi:check-network"
    assert vip.unique_id == initial_unique_id
    assert vip.extra_state_attributes is not None
    assert vip.extra_state_attributes == {
        "interface": "ix0",
        "vhid": 1,
        "advskew": 100,
        "advbase": 1,
        "subnet_bits": 24,
        "subnet": "192.0.2.1",
        "descr": "Primary VIP",
        "mode": "carp",
    }


@pytest.mark.parametrize(
    "unavailable_scenario",
    ["malformed_key", "disappeared_vip", "missing_status"],
)
def test_carp_vip_sensor_clears_attributes_when_becoming_unavailable(
    unavailable_scenario: str,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """A CARP VIP should not retain attributes after its payload becomes unusable."""
    entry = make_config_entry(data={"entry_type": "carp"}, entry_id="carp-entry")
    interface = {
        "vhid": 1,
        "subnet": "192.0.2.1",
        "interface": "igc0",
        "status": "MASTER",
    }
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = {"carp": {"interfaces": [interface]}}
    description = MagicMock(spec=SensorEntityDescription)
    description.key = sensor_module._build_carp_vip_sensor_key("1", "192.0.2.1")
    description.name = "CARP VIP 192.0.2.1 (VHID 1)"
    description.translation_key = "carp_vip"
    sensor = OPNsenseCarpVipSensor(
        config_entry=entry,
        coordinator=coordinator,
        entity_description=description,
    )
    sensor.hass = MagicMock()
    sensor.entity_id = "sensor.carp_vip"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)

    sensor._handle_coordinator_update()
    assert sensor.available is True
    assert sensor.extra_state_attributes == {
        "interface": "igc0",
        "vhid": 1,
        "subnet": "192.0.2.1",
    }

    if unavailable_scenario == "malformed_key":
        description.key = "carp.vip.invalid"
    elif unavailable_scenario == "disappeared_vip":
        coordinator.data["carp"]["interfaces"] = []
    else:
        interface.pop("status")

    sensor._handle_coordinator_update()

    assert sensor.available is False
    assert sensor.extra_state_attributes == {}


@pytest.mark.parametrize("system_info", [{}, {"name": None}, {"name": ""}, {"name": "  "}])
def test_carp_active_responder_unavailable_without_name(
    system_info: dict[str, Any],
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """The active responder sensor should fail closed for missing or blank names."""
    entry = make_config_entry(data={"entry_type": "carp"}, entry_id="carp-entry")
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = {"system_info": system_info}
    sensor = OPNsenseCarpActiveResponderSensor(
        config_entry=entry,
        coordinator=coordinator,
        entity_description=SensorEntityDescription(
            key="carp.active_responder",
            name="Active CARP Responder",
            translation_key="carp_active_responder",
        ),
    )
    sensor.hass = MagicMock()
    sensor.entity_id = "sensor.carp_active_responder_unavailable"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)

    sensor._handle_coordinator_update()

    assert sensor.available is False
    assert sensor.extra_state_attributes == {}


def test_carp_active_responder_unavailable_without_system_info(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """The active responder should fail closed when system information is absent."""
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = {}
    sensor = OPNsenseCarpActiveResponderSensor(
        config_entry=make_config_entry(data={"entry_type": "carp"}),
        coordinator=coordinator,
        entity_description=SensorEntityDescription(key="carp.active_responder"),
    )
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)

    sensor._handle_coordinator_update()

    assert sensor.available is False
    assert sensor.extra_state_attributes == {}


def test_carp_value_normalization_handles_empty_and_conversion_errors() -> None:
    """CARP normalization should return blanks for absent or unconvertible values."""

    class UnconvertibleValue:
        """Value whose string conversion fails."""

        def __str__(self) -> str:
            """Raise a representative conversion error."""
            raise ValueError

    assert sensor_module._normalize_carp_value(None) == ""
    assert sensor_module._normalize_carp_value(UnconvertibleValue()) == ""


@pytest.mark.parametrize(
    ("subnet", "expected"),
    [("  ", ""), ("not an ip", "not_an_ip")],
)
def test_carp_vip_subnet_normalization_fallbacks(subnet: str, expected: str) -> None:
    """CARP subnet normalization should handle blanks and non-IP identifiers."""
    assert sensor_module._normalize_carp_vip_subnet(subnet) == expected


@pytest.mark.parametrize("key", ["carp.vip..192_0_2_1", "carp.vip.1."])
def test_parse_carp_vip_sensor_key_rejects_blank_components(key: str) -> None:
    """CARP VIP keys with blank identity components should be rejected."""
    assert sensor_module._parse_carp_vip_sensor_key(key) is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state",
    [[], {"carp": {"interfaces": "invalid"}}],
)
async def test_compile_carp_vip_sensors_rejects_malformed_containers(
    state: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP VIP compilation should reject malformed state and interface containers."""
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = state

    assert (
        await sensor_module._compile_carp_vip_sensors(make_config_entry(), coordinator, state) == []
    )


@pytest.mark.asyncio
async def test_compile_carp_vip_sensors_skips_bad_rows_and_duplicates(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP VIP compilation should skip malformed, incomplete, and duplicate rows."""
    valid = {"vhid": "1", "subnet": "192.0.2.1", "status": "MASTER"}
    state = {
        "carp": {"interfaces": ["invalid", {"vhid": ""}, {"subnet": "192.0.2.1"}, valid, valid]}
    }
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = state

    entities = await sensor_module._compile_carp_vip_sensors(
        make_config_entry(), coordinator, state
    )

    assert len(entities) == 1


def test_carp_vip_sensor_skips_malformed_and_nonmatching_rows(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP VIP updates should ignore unusable rows and fail closed without a match."""
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = {
        "carp": {
            "interfaces": [
                "invalid",
                {"vhid": "", "subnet": "192.0.2.1"},
                {"vhid": "2", "subnet": "192.0.2.2", "status": "MASTER"},
            ]
        }
    }
    sensor = OPNsenseCarpVipSensor(
        config_entry=make_config_entry(data={"entry_type": "carp"}),
        coordinator=coordinator,
        entity_description=SensorEntityDescription(key="carp.vip.1.192_0_2_1"),
    )
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)

    sensor._handle_coordinator_update()

    assert sensor.available is False


def test_carp_vip_sensor_non_string_status_uses_failure_icon(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP VIP sensors should use the failure icon for non-string states."""
    sensor = OPNsenseCarpVipSensor(
        config_entry=make_config_entry(data={"entry_type": "carp"}),
        coordinator=MagicMock(spec=OPNsenseDataUpdateCoordinator),
        entity_description=SensorEntityDescription(key="carp.vip.1.192_0_2_1"),
    )
    sensor._attr_native_value = 1

    assert sensor.icon == "mdi:close-network-outline"


@pytest.mark.asyncio
async def test_static_key_sensor_cpu_and_boot_and_certificates(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Static key sensors should expose CPU, boot time, and certificate counts."""
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = {
        "telemetry": {
            "cpu": {"usage_1": 10, "usage_2": 20, "usage_total": 30},
            "system": {"boottime": 1609459200},
        },
        "certificates": {"a": 1, "b": 2},
    }

    entry = make_config_entry()

    desc = MagicMock()
    desc.key = "telemetry.cpu.usage_total"
    desc.name = "CPU Total"
    s_cpu = OPNsenseStaticKeySensor(
        config_entry=entry, coordinator=coordinator, entity_description=desc
    )
    s_cpu.hass = MagicMock()
    s_cpu.entity_id = "sensor.cpu_total"
    object.__setattr__(s_cpu, "async_write_ha_state", lambda: None)
    s_cpu._handle_coordinator_update()
    assert s_cpu.available is True
    assert s_cpu.native_value == 30
    attrs = s_cpu.extra_state_attributes
    assert attrs is not None
    assert attrs.get("1") == "10%"
    assert attrs.get("2") == "20%"


@pytest.mark.asyncio
async def test_compile_gateway_sensors_creates_disabled_address_sensor(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Gateway address sensors should be created and disabled by default."""
    entry = make_config_entry()
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = {
        "gateways": {
            "wan": {
                "name": "WAN Gateway",
                "address": "203.0.113.1",
                "delay": "15ms",
                "stddev": "1ms",
                "loss": "0%",
                "status": "online",
            }
        }
    }

    entities = await sensor_module._compile_gateway_sensors(entry, coordinator, coordinator.data)
    address_sensor = next(
        entity for entity in entities if entity.entity_description.key == "gateway.wan.address"
    )

    assert isinstance(address_sensor, OPNsenseGatewaySensor)
    assert address_sensor.entity_description.name == "Gateway WAN Gateway address"
    assert address_sensor.entity_description.icon == "mdi:ip-network"
    assert address_sensor.entity_description.state_class is None
    assert address_sensor.entity_description.entity_registry_enabled_default is False


async def test_compile_gateway_sensors_keeps_gateway_id_in_entity_key(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Gateway display name should not be used as the entity key."""
    entry = make_config_entry({"device_unique_id": "router-id"})
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = {
        "gateways": {
            "wan": {
                "name": "WAN_GW",
                "address": "203.0.113.1",
                "delay": "15ms",
                "stddev": "1ms",
                "loss": "0%",
                "status": "online",
            }
        }
    }

    entities = await sensor_module._compile_gateway_sensors(entry, coordinator, coordinator.data)
    address_entity = next(
        entity for entity in entities if entity.entity_description.key == "gateway.wan.address"
    )
    status_entity = next(
        entity for entity in entities if entity.entity_description.key == "gateway.wan.status"
    )
    assert address_entity.entity_description.name == "Gateway WAN_GW address"
    assert address_entity._attr_unique_id == sensor_module.slugify(
        f"{entry.data['device_unique_id']}_gateway.WAN_GW.address"
    )
    assert status_entity._attr_unique_id == sensor_module.slugify(
        f"{entry.data['device_unique_id']}_gateway.WAN_GW.status"
    )


@pytest.mark.parametrize(
    ("coord_data", "desc_subnet"),
    [
        (None, "some"),
        ({"carp": {"interfaces": [{"subnet": "10.0.0.5", "status": "MASTER"}]}}, "192.168.1.10"),
        ({"carp": {"interfaces": [{"subnet": "1.2.3.4", "interface": "lan0"}]}}, "1.2.3.4"),
    ],
)
def test_carp_sensor_unavailable_variants(
    coord_data: Any, desc_subnet: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Parameterised unavailable variants for CARP sensor."""
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = coord_data
    entry = make_config_entry()

    desc = MagicMock()
    desc.key = f"carp.interface.lan0.{sensor_module.slugify(desc_subnet)}"
    desc.name = "CARP"

    s = OPNsenseCarpInterfaceSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.carp_unavailable"
    object.__setattr__(s, "async_write_ha_state", lambda: None)
    s._handle_coordinator_update()
    assert s.available is False


def test_carp_sensor_state_wrong_type(make_config_entry: Callable[..., MockConfigEntry]) -> None:
    """CARP sensor should be unavailable when coordinator.data is not a mapping (e.g., list)."""
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = []
    entry = make_config_entry()

    desc = MagicMock()
    desc.key = f"carp.interface.wan.{sensor_module.slugify('10.10.10.10')}"
    desc.name = "CARP WrongType"

    s = OPNsenseCarpInterfaceSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.carp_wrongtype"
    object.__setattr__(s, "async_write_ha_state", lambda: None)
    s._handle_coordinator_update()
    assert s.available is False


@pytest.mark.parametrize(
    ("desc_key", "cls"),
    [
        ("carp.interface.some.some", OPNsenseCarpInterfaceSensor),
        ("carp.status_summary", OPNsenseCarpStatusSensor),
        ("gateway.gw1.status", OPNsenseGatewaySensor),
        ("interface.lan.status", OPNsenseInterfaceSensor),
        ("telemetry.temps.sensor1", OPNsenseTempSensor),
        ("openvpn.servers.uuid1.status", OPNsenseVPNSensor),
        ("dhcp_leases.all", OPNsenseDHCPLeasesSensor),
    ],
)
def test_sensors_unavailable_on_non_mapping_state(
    desc_key: Any, cls: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Sensors should mark themselves unavailable when coordinator.data is not a mapping."""
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = []
    entry = make_config_entry()

    desc = MagicMock()
    desc.key = desc_key
    desc.name = "NonMappingState"

    s = cls(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.unavailable"
    object.__setattr__(s, "async_write_ha_state", lambda: None)
    s._handle_coordinator_update()
    assert s.available is False


@pytest.mark.parametrize(
    ("coord_data", "desc_key"),
    [
        ([], "vnstat.igc0.vnstat_today"),
        ({"vnstat": {"interfaces": {"igc0": {"metrics": {}}}}}, "vnstat.igc0"),
        (
            {"vnstat": {"interfaces": {"igc0": {"metrics": {"vnstat_today": []}}}}},
            "vnstat.igc0.vnstat_today",
        ),
        (
            {
                "vnstat": {
                    "interfaces": {"igc0": {"metrics": {"vnstat_today": {"total_bytes": "100"}}}}
                }
            },
            "vnstat.igc0.vnstat_today",
        ),
    ],
    ids=["state-not-mapping", "invalid-key", "metric-not-mapping", "total-not-int"],
)
def test_vnstat_sensor_fails_closed_for_malformed_payloads(
    coord_data: Any,
    desc_key: str,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Vnstat sensors should become unavailable for malformed payload shapes."""
    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = coord_data

    desc = MagicMock()
    desc.key = desc_key
    desc.name = "Vnstat Malformed"

    sensor = OPNsenseVnstatSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    sensor.hass = MagicMock()
    sensor.entity_id = "sensor.vnstat_malformed"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)

    sensor._handle_coordinator_update()

    assert sensor.available is False


@pytest.mark.parametrize(
    ("prop_name", "input_value", "expected_available", "expected_value", "expect_down_icon"),
    [
        ("status", "online", True, "online", False),
        ("status", "", False, None, True),
        ("delay", "15ms", True, 15.0, False),
        ("stddev", "1ms", True, 1.0, False),
        ("loss", "0%", True, 0.0, False),
        ("delay", "not_a_float", False, None, True),
        ("loss", "oops", False, None, True),
        ("stddev", "12.34.56", False, None, True),
        ("loss", "", False, None, True),
        ("delay", 12, True, 12, False),
        ("address", "203.0.113.1", True, "203.0.113.1", False),
    ],
)
def test_gateway_sensor_value_parsing(
    prop_name: Any,
    input_value: Any,
    expected_available: bool,
    expected_value: Any,
    expect_down_icon: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Parameterized checks for gateway value parsing and availability."""
    entry = make_config_entry()
    gw = {"name": "gw1", prop_name: input_value}
    state = {"gateways": {"gw1": gw}}

    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = state

    desc = MagicMock()
    desc.key = f"gateway.gw1.{prop_name}"
    desc.name = "Gateway Test"

    s = OPNsenseGatewaySensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.gw_test"
    object.__setattr__(s, "async_write_ha_state", lambda: None)
    s._handle_coordinator_update()

    assert s.available is expected_available
    if expected_available:
        if isinstance(expected_value, float):
            assert isinstance(s.native_value, str | int | float)
            assert float(s.native_value) == pytest.approx(expected_value)
        else:
            assert s.native_value == expected_value
    else:
        assert s.native_value == expected_value
        if prop_name == "status":
            if expect_down_icon:
                assert s.icon == "mdi:close-network-outline"
            else:
                assert s.icon != "mdi:close-network-outline"


def test_gateway_sensor_resolves_display_name_when_mapping_key_differs(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Gateway sensor should resolve payload when description key uses display name."""
    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {
        "gateways": {
            "wan_primary": {"name": "WAN Gateway", "status": "online"},
        }
    }

    desc = MagicMock()
    desc.key = "gateway.WAN Gateway.status"
    desc.name = "Gateway WAN Gateway status"

    s = OPNsenseGatewaySensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.wan_gateway_status"
    object.__setattr__(s, "async_write_ha_state", lambda: None)
    s._handle_coordinator_update()

    assert s.available is True
    assert s.native_value == "online"
    assert s.icon != "mdi:close-network-outline"


@pytest.mark.parametrize(
    ("gateway_key", "gateway_name", "expected_display_name"),
    [
        ("gw1", " WAN Gateway ", "WAN Gateway"),
        ("gw2", 42, "42"),
    ],
    ids=["whitespace-padded-name", "scalar-name"],
)
@pytest.mark.asyncio
async def test_gateway_compile_and_lookup_normalizes_display_name(
    make_config_entry: Callable[..., MockConfigEntry],
    gateway_key: str,
    gateway_name: Any,
    expected_display_name: str,
) -> None:
    """Compile and lookup should agree on normalized gateway display names."""
    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {
        "gateways": {
            gateway_key: {"name": gateway_name, "status": "online"},
        }
    }

    entities = await sensor_module._compile_gateway_sensors(entry, coord, coord.data)
    expected_key = f"gateway.{gateway_key}.status"
    s = next(entity for entity in entities if entity.entity_description.key == expected_key)

    assert isinstance(s, OPNsenseGatewaySensor)
    assert s.entity_description.name == f"Gateway {expected_display_name} status"
    assert s._opnsense_get_gateway_entry(expected_display_name) == {
        "name": gateway_name,
        "status": "online",
    }

    s.hass = MagicMock()
    s.entity_id = "sensor.gateway_status"
    object.__setattr__(s, "async_write_ha_state", lambda: None)
    s._handle_coordinator_update()

    assert s.available is True
    assert s.native_value == "online"


@pytest.mark.parametrize(
    "instance",
    [
        {"enabled": True},
        {"enabled": True, "name": ""},
        {"enabled": True, "name": None},
        {"enabled": True, "name": 7},
    ],
    ids=["missing-name", "blank-name", "non-string-none", "non-string-number"],
)
@pytest.mark.asyncio
async def test_compile_vpn_sensors_falls_back_to_uuid_when_name_is_unusable(
    make_config_entry: Callable[..., MockConfigEntry],
    instance: dict[str, Any],
) -> None:
    """VPN sensor compilation should use uuid for display name when `name` is unusable."""
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = {
        "wireguard": {
            "clients": {},
            "servers": {"wg-uuid": instance},
        }
    }
    entry = make_config_entry()

    entities = await sensor_module._compile_vpn_sensors(entry, coordinator, coordinator.data)
    status_sensor = next(
        entity
        for entity in entities
        if entity.entity_description.key == "wireguard.servers.wg-uuid.status"
    )

    assert isinstance(status_sensor, OPNsenseVPNSensor)
    assert status_sensor.entity_description.name == "Wireguard Server wg-uuid status"


def test_vpn_sensor_key_malformed_key_marked_unavailable(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Malformed VPN sensor keys should fail closed to unavailable instead of raising."""
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {"openvpn": {"servers": {"uuid1": {"name": "ovpn", "status": "up"}}}}
    entry = make_config_entry()

    desc = MagicMock()
    desc.key = "openvpn.servers.uuid1"
    desc.name = "Malformed VPN Key"
    desc.icon = "mdi:custom-icon"

    sensor = OPNsenseVPNSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    sensor.hass = MagicMock()
    sensor.entity_id = "sensor.vpn_malformed_key"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)
    sensor._handle_coordinator_update()

    assert sensor.available is False
    assert sensor.icon == "mdi:custom-icon"


def test_gateway_sensor_missing_and_missing_prop(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Gateway sensor should be unavailable when gateway missing or property missing."""
    entry = make_config_entry()

    coord1 = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord1.data = {"gateways": {}}
    desc1 = MagicMock()
    desc1.key = "gateway.missing.status"
    desc1.name = "GW Missing"
    s1 = OPNsenseGatewaySensor(config_entry=entry, coordinator=coord1, entity_description=desc1)
    s1.hass = MagicMock()
    s1.entity_id = "sensor.gw_missing"
    object.__setattr__(s1, "async_write_ha_state", lambda: None)
    s1._handle_coordinator_update()
    assert s1.available is False

    coord2 = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord2.data = {"gateways": {"gw1": {"name": "gw1"}}}
    desc2 = MagicMock()
    desc2.key = "gateway.gw1.delay"
    desc2.name = "GW NoProp"
    s2 = OPNsenseGatewaySensor(config_entry=entry, coordinator=coord2, entity_description=desc2)
    s2.hass = MagicMock()
    s2.entity_id = "sensor.gw_noprop"
    object.__setattr__(s2, "async_write_ha_state", lambda: None)
    s2._handle_coordinator_update()
    assert s2.available is False


def test_gateway_lookup_handles_invalid_payloads_and_casefold_match(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Gateway lookup should skip invalid payloads and fall back to case-insensitive names."""
    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {"gateways": []}
    desc = MagicMock()
    desc.key = "gateway.wan gateway.status"
    desc.name = "Gateway Status"
    sensor = OPNsenseGatewaySensor(config_entry=entry, coordinator=coord, entity_description=desc)

    assert sensor._opnsense_get_gateway_entry("wan gateway") == {}

    coord.data = {
        "gateways": {
            "bad": [],
            "other": {"name": "LAN Gateway", "status": "online"},
            "wan": {"name": "WAN Gateway", "status": "online"},
        }
    }
    assert sensor._opnsense_get_gateway_entry("wan gateway") == {
        "name": "WAN Gateway",
        "status": "online",
    }


@pytest.mark.parametrize("description_key", ["gateway", "gateway.wan"])
def test_gateway_sensor_invalid_description_key_unavailable(
    description_key: str,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Gateway sensor should be unavailable when its description key cannot be parsed."""
    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {"gateways": {"wan": {"name": "WAN", "status": "online"}}}
    desc = MagicMock()
    desc.key = description_key
    desc.name = "Gateway Invalid"

    sensor = OPNsenseGatewaySensor(config_entry=entry, coordinator=coord, entity_description=desc)
    sensor.hass = MagicMock()
    sensor.entity_id = "sensor.gateway_invalid"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)
    sensor._handle_coordinator_update()

    assert sensor.available is False


def test_gateway_sensor_invalid_icon_key_uses_description_icon(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Gateway sensor icon should fall back when its description key cannot be parsed."""
    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {"gateways": {"wan": {"name": "WAN", "status": "online"}}}
    desc = MagicMock()
    desc.key = "gateway"
    desc.name = "Gateway Invalid"
    desc.icon = "mdi:gauge"

    sensor = OPNsenseGatewaySensor(config_entry=entry, coordinator=coord, entity_description=desc)

    assert sensor.icon == "mdi:gauge"


@pytest.mark.parametrize(
    ("carp_entry", "expected_value", "expected_icon", "expect_keys"),
    [
        (
            {
                "subnet": "192.168.1.20",
                "status": "BACKUP",
                "interface": "lan0",
                "vhid": 7,
                "advskew": 100,
                "advbase": 0,
                "subnet_bits": 24,
                "descr": "test carp",
                "mode": "carp",
            },
            "BACKUP",
            "mdi:backup-restore",
            ("interface", "vhid", "advskew", "advbase", "subnet_bits", "subnet", "descr", "mode"),
        ),
        (
            {"subnet": "10.0.0.1", "status": "MASTER"},
            "MASTER",
            "mdi:check-network",
            (),
        ),
        (
            {"subnet": "10.0.0.3", "status": "INIT"},
            "INIT",
            "mdi:close-network-outline",
            (),
        ),
    ],
)
def test_carp_sensor_attributes_and_icon(
    carp_entry: Any,
    expected_value: Any,
    expected_icon: Any,
    expect_keys: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Parameterized attribute and icon checks for CARP sensor."""
    entry = make_config_entry()

    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {"carp": {"interfaces": [carp_entry]}}

    desc = MagicMock()
    desc.key = (
        f"carp.interface."
        f"{sensor_module.slugify(carp_entry.get('interface', 'unknown'))}."
        f"{sensor_module.slugify(carp_entry['subnet'])}"
    )
    desc.name = "CARP Test"

    s = OPNsenseCarpInterfaceSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.carp_param"
    object.__setattr__(s, "async_write_ha_state", lambda: None)
    s._handle_coordinator_update()

    assert s.available is True
    assert s.native_value == expected_value
    assert s.icon == expected_icon
    attrs = s.extra_state_attributes
    assert attrs is not None
    for key in expect_keys:
        assert key in attrs


@pytest.mark.parametrize(
    ("summary", "expected_value", "expected_icon"),
    [
        (
            {
                "state": "healthy",
                "enabled": True,
                "maintenance_mode": False,
                "demotion": 0,
                "status_message": "",
                "vip_count": 2,
                "master_count": 1,
                "backup_count": 1,
                "other_count": 0,
                "interfaces": ["lan", "wan"],
                "vips": [{"interface": "wan", "subnet": "1.2.3.4", "status": "MASTER"}],
            },
            "Healthy",
            "mdi:check-network",
        ),
        (
            {
                "state": "maintenance",
                "enabled": True,
                "maintenance_mode": True,
                "demotion": 0,
                "status_message": "",
                "vip_count": 1,
                "master_count": 1,
                "backup_count": 0,
                "other_count": 0,
                "interfaces": ["wan"],
                "vips": [],
            },
            "Maintenance",
            "mdi:backup-restore",
        ),
        (
            {
                "state": "degraded",
                "enabled": True,
                "maintenance_mode": False,
                "demotion": 3,
                "status_message": "demoted",
                "vip_count": 1,
                "master_count": 0,
                "backup_count": 0,
                "other_count": 1,
                "interfaces": ["wan"],
                "vips": [],
            },
            "Degraded",
            "mdi:close-network-outline",
        ),
        (
            {
                "state": "disabled",
                "enabled": False,
                "maintenance_mode": False,
                "demotion": 0,
                "status_message": "",
                "vip_count": 1,
                "master_count": 0,
                "backup_count": 0,
                "other_count": 1,
                "interfaces": ["wan"],
                "vips": [{"interface": "wan", "subnet": "1.2.3.5", "status": "INIT"}],
            },
            "Disabled",
            "mdi:close-network-outline",
        ),
        (
            {
                "state": "not_configured",
                "enabled": True,
                "maintenance_mode": False,
                "demotion": 0,
                "status_message": "",
                "vip_count": 0,
                "master_count": 0,
                "backup_count": 0,
                "other_count": 0,
                "interfaces": [],
                "vips": [],
            },
            "Not Configured",
            "mdi:backup-restore",
        ),
        (
            {
                "state": "unavailable",
                "enabled": False,
                "maintenance_mode": False,
                "demotion": 0,
                "status_message": "",
                "vip_count": 0,
                "master_count": 0,
                "backup_count": 0,
                "other_count": 0,
                "interfaces": [],
                "vips": [],
            },
            "unavailable",
            "mdi:gauge",
        ),
        (
            {
                "state": "unknown",
                "enabled": False,
                "maintenance_mode": False,
                "demotion": 0,
                "status_message": "",
                "vip_count": 0,
                "master_count": 0,
                "backup_count": 0,
                "other_count": 0,
                "interfaces": [],
                "vips": [],
            },
            "unknown",
            "mdi:gauge",
        ),
    ],
)
def test_carp_status_sensor_states_and_attributes(
    summary: dict[str, Any],
    expected_value: str,
    expected_icon: str,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Validate aggregate CARP status sensor state, icon, and attributes."""
    entry = make_config_entry()
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = {"carp": {"status_summary": summary}}

    desc = MagicMock()
    desc.key = "carp.status_summary"
    desc.name = "CARP Status"
    desc.icon = "mdi:gauge"

    sensor = OPNsenseCarpStatusSensor(
        config_entry=entry,
        coordinator=coordinator,
        entity_description=desc,
    )
    sensor.hass = MagicMock()
    sensor.entity_id = "sensor.carp_status"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)
    sensor._handle_coordinator_update()

    assert sensor.available is True
    assert sensor.native_value == expected_value
    assert sensor.icon == expected_icon
    attrs = sensor.extra_state_attributes
    assert attrs is not None
    assert attrs.get("vip_count") == summary.get("vip_count")
    assert attrs.get("interfaces") == summary.get("interfaces")


def test_carp_status_sensor_normalizes_state_spacing_and_icon(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP status sensor should normalize spacing/underscores for non-special values."""
    entry = make_config_entry()
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = {
        "carp": {
            "status_summary": {
                "state": " not_configured ",
                "enabled": True,
                "maintenance_mode": False,
                "demotion": 0,
                "status_message": "",
                "vip_count": 0,
                "master_count": 0,
                "backup_count": 0,
                "other_count": 0,
                "interfaces": [],
                "vips": [],
            }
        }
    }

    desc = MagicMock()
    desc.key = "carp.status_summary"
    desc.name = "CARP Status"
    desc.icon = "mdi:gauge"

    sensor = OPNsenseCarpStatusSensor(
        config_entry=entry,
        coordinator=coordinator,
        entity_description=desc,
    )
    sensor.hass = MagicMock()
    sensor.entity_id = "sensor.carp_status_normalized"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)
    sensor._handle_coordinator_update()

    assert sensor.available is True
    assert sensor.native_value == "Not Configured"
    assert sensor.icon == "mdi:backup-restore"


@pytest.mark.parametrize("summary_state", [None, ""])
def test_carp_status_sensor_fails_closed_for_missing_state(
    summary_state: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP status sensor should be unavailable when summary state is missing."""
    entry = make_config_entry()
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = {"carp": {"status_summary": {"state": summary_state}}}

    desc = MagicMock()
    desc.key = "carp.status_summary"
    desc.name = "CARP Status"

    sensor = OPNsenseCarpStatusSensor(
        config_entry=entry,
        coordinator=coordinator,
        entity_description=desc,
    )
    sensor.hass = MagicMock()
    sensor.entity_id = "sensor.carp_status_missing"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)

    sensor._handle_coordinator_update()

    assert sensor.available is False


@pytest.mark.parametrize(
    ("interface_name", "subnet", "expected_key"),
    [
        ("wan", "203.0.113.10", "carp.interface.wan.203_0_113_10"),
        (None, "10.0.0.5", "carp.interface.unknown.10_0_0_5"),
        ("!!!", "10.0.0.6", "carp.interface.unknown.10_0_0_6"),
        ("  lan0  ", " 10.0.0.7 ", "carp.interface.lan0.10_0_0_7"),
    ],
)
def test_build_carp_interface_sensor_key(
    interface_name: str | None,
    subnet: str,
    expected_key: str,
) -> None:
    """Build helper should produce stable CARP interface keys for edge cases."""
    assert sensor_module._build_carp_interface_sensor_key(interface_name, subnet) == expected_key


@pytest.mark.parametrize(
    ("subnet", "equivalent_subnet"),
    [
        ("192.0.2.1/32", "192.0.2.1"),
        (
            "2001:db8::1/128",
            "2001:0db8:0000:0000:0000:0000:0000:0001",
        ),
    ],
)
def test_build_carp_vip_sensor_key_normalizes_equivalent_subnet_text(
    subnet: str,
    equivalent_subnet: str,
) -> None:
    """Equivalent subnet text forms should map to the same CARP VIP key."""
    assert sensor_module._build_carp_vip_sensor_key(
        "7", subnet
    ) == sensor_module._build_carp_vip_sensor_key("7", equivalent_subnet)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("initial_subnet", "updated_subnet"),
    [
        ("192.0.2.1/32", "192.0.2.1"),
        (
            "2001:DB8::0001",
            "2001:db8::1",
        ),
    ],
)
async def test_carp_vip_sensor_matches_canonicalized_subnet_identity_on_updates(
    make_config_entry: Callable[..., MockConfigEntry],
    initial_subnet: str,
    updated_subnet: str,
) -> None:
    """CARP VIP updates should match across textual subnet variants."""
    entry = make_config_entry(
        data={"entry_type": "carp"},
        entry_id="carp-entry",
        title="CARP VIP",
    )
    state: dict[str, Any] = {
        "carp": {
            "interfaces": [
                {
                    "vhid": "1",
                    "subnet": initial_subnet,
                    "status": "BACKUP",
                    "interface": "igc0",
                }
            ],
            "status_summary": {"state": "healthy"},
        }
    }
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = state
    setattr(entry.runtime_data, COORDINATOR, coordinator)
    created: list[Any] = []

    def add_entities(entities: Iterable[Any], _update_before_add: bool = False) -> None:
        """Collect entities created by async_setup_entry."""
        created.extend(entities)

    await async_setup_entry(MagicMock(), entry, cast("AddEntitiesCallback", add_entities))
    vip = next(
        entity for entity in created if entity.entity_description.key.startswith("carp.vip.")
    )
    initial_unique_id = vip.unique_id
    object.__setattr__(vip, "hass", MagicMock())
    object.__setattr__(vip, "async_write_ha_state", lambda: None)

    vip._handle_coordinator_update()
    assert vip.native_value == "BACKUP"
    assert vip.extra_state_attributes is not None
    assert vip.extra_state_attributes["subnet"] == initial_subnet

    state["carp"]["interfaces"][0]["subnet"] = updated_subnet
    state["carp"]["interfaces"][0]["status"] = "MASTER"
    vip._handle_coordinator_update()

    assert vip.unique_id == initial_unique_id
    assert vip.native_value == "MASTER"
    assert vip.extra_state_attributes is not None
    assert vip.extra_state_attributes["subnet"] == updated_subnet
    assert vip.entity_description.key == sensor_module._build_carp_vip_sensor_key(
        "1", updated_subnet
    )


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        ("carp.interface.wan.203_0_113_10", ("wan", "203_0_113_10")),
        ("carp.interface..10_0_0_1", ("unknown", "10_0_0_1")),
        ("carp.interface.wan", None),
        ("carp.status_summary", None),
        ("carp.interface.wan.", None),
    ],
)
def test_parse_carp_interface_sensor_key(
    key: str,
    expected: tuple[str, str] | None,
) -> None:
    """Parse helper should extract valid slugs and reject malformed keys."""
    assert sensor_module._parse_carp_interface_sensor_key(key) == expected


@pytest.mark.asyncio
async def test_compile_carp_interface_sensor_name_includes_interface(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Compiled CARP interface sensor names should include interface and VIP address."""
    entry = make_config_entry()
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    state = {
        "interfaces": {"wan": {"name": "WAN", "interface": "wan", "device": "igc0"}},
        "carp": {
            "interfaces": [
                {
                    "subnet": "203.0.113.10",
                    "interface": "wan",
                    "status": "MASTER",
                    "descr": "Primary WAN VIP",
                }
            ]
        },
    }
    coordinator.data = state

    entities = await sensor_module._compile_carp_interface_sensors(entry, coordinator, state)
    assert len(entities) == 1
    assert entities[0].entity_description.name == "CARP Interface: WAN: 203.0.113.10"
    assert entities[0].entity_description.key == "carp.interface.wan.203_0_113_10"


@pytest.mark.asyncio
async def test_compile_carp_interface_sensor_fallbacks_to_unknown_interface(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Compiled CARP interface sensor key should use unknown for unslugifiable interface names."""
    entry = make_config_entry()
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    state = {
        "interfaces": {},
        "carp": {
            "interfaces": [
                {
                    "subnet": "198.51.100.10",
                    "interface": "!!!",
                    "status": "MASTER",
                }
            ]
        },
    }
    coordinator.data = state

    entities = await sensor_module._compile_carp_interface_sensors(entry, coordinator, state)
    assert len(entities) == 1
    assert entities[0].entity_description.name == "CARP Interface: !!!: 198.51.100.10"
    assert entities[0].entity_description.key == "carp.interface.unknown.198_51_100_10"


def test_carp_interface_sensor_unavailable_for_malformed_key(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP interface sensor should be unavailable when description key is malformed."""
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = {
        "carp": {"interfaces": [{"subnet": "10.0.0.1", "interface": "lan0", "status": "MASTER"}]}
    }
    entry = make_config_entry()

    desc = MagicMock()
    desc.key = "carp.interface.invalid"
    desc.name = "Malformed CARP Key"

    sensor = OPNsenseCarpInterfaceSensor(
        config_entry=entry,
        coordinator=coordinator,
        entity_description=desc,
    )
    sensor.hass = MagicMock()
    sensor.entity_id = "sensor.carp_malformed_key"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)
    sensor._handle_coordinator_update()

    assert sensor.available is False


def test_carp_interface_sensor_disambiguates_same_subnet_by_interface(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP interface sensor should match both subnet and interface slug."""
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = {
        "carp": {
            "interfaces": [
                {"subnet": "10.0.0.1", "interface": "wan", "status": "BACKUP"},
                {"subnet": "10.0.0.1", "interface": "lan0", "status": "MASTER"},
            ]
        }
    }
    entry = make_config_entry()

    desc = MagicMock()
    desc.key = "carp.interface.lan0.10_0_0_1"
    desc.name = "CARP Disambiguated"

    sensor = OPNsenseCarpInterfaceSensor(
        config_entry=entry,
        coordinator=coordinator,
        entity_description=desc,
    )
    sensor.hass = MagicMock()
    sensor.entity_id = "sensor.carp_disambiguated"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)
    sensor._handle_coordinator_update()

    assert sensor.available is True
    assert sensor.native_value == "MASTER"


@pytest.mark.parametrize(
    ("desc_key", "cls", "main_check", "extra_check"),
    [
        (
            f"carp.interface.{sensor_module.slugify('lan0')}.{sensor_module.slugify('10.0.0.1')}",
            OPNsenseCarpInterfaceSensor,
            lambda s: s.native_value == "MASTER",
            lambda s: s.icon == "mdi:check-network",
        ),
        (
            "carp.status_summary",
            OPNsenseCarpStatusSensor,
            lambda s: s.native_value == "Healthy",
            lambda s: s.icon == "mdi:check-network",
        ),
        (
            "gateway.gw1.delay",
            OPNsenseGatewaySensor,
            lambda s: float(s.native_value) == pytest.approx(12.0),
            None,
        ),
        (
            "openvpn.servers.uuid1.status",
            OPNsenseVPNSensor,
            lambda s: "clients" in s.extra_state_attributes,
            None,
        ),
        ("telemetry.temps.sensor1", OPNsenseTempSensor, lambda s: s.native_value == 42, None),
        (
            "dhcp_leases.all",
            OPNsenseDHCPLeasesSensor,
            lambda s: isinstance(s.native_value, int),
            None,
        ),
    ],
)
def test_compiled_sensor_variants(
    desc_key: Any,
    cls: Any,
    main_check: Any,
    extra_check: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Table-driven checks for several sensor types using a common sample state."""
    state = {
        "carp": {
            "interfaces": [
                {"subnet": "10.0.0.1", "status": "MASTER", "interface": "lan0", "vhid": 1}
            ],
            "status_summary": {
                "state": "healthy",
                "enabled": True,
                "maintenance_mode": False,
                "demotion": 0,
                "status_message": "",
                "vip_count": 1,
                "master_count": 1,
                "backup_count": 0,
                "other_count": 0,
                "interfaces": ["lan0"],
                "vips": [{"interface": "lan0", "subnet": "10.0.0.1", "status": "MASTER"}],
            },
        },
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

    entry = make_config_entry()
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = state

    desc = MagicMock()
    desc.key = desc_key
    desc.name = "Test"

    s = cls(config_entry=entry, coordinator=coordinator, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.test"
    object.__setattr__(s, "async_write_ha_state", lambda: None)
    s._handle_coordinator_update()

    assert s.available is True
    assert main_check(s)
    if extra_check:
        assert extra_check(s)


@pytest.mark.parametrize(
    (
        "state",
        "desc_key",
        "expected_available",
        "expected_value",
        "expect_clients",
        "expect_extra_keys",
    ),
    [
        (
            {"openvpn": {"servers": {}}},
            "openvpn.servers.uuid_missing.status",
            False,
            None,
            False,
            (),
        ),
        (
            {"openvpn": {"servers": {"uuid1": {"name": "ovpn1", "enabled": False}}}},
            "openvpn.servers.uuid1.connected_clients",
            False,
            None,
            False,
            (),
        ),
        (
            {
                "openvpn": {
                    "servers": {"uuid1": {"uuid": "uuid1", "name": "ovpn1", "enabled": False}}
                }
            },
            "openvpn.servers.uuid1.status",
            True,
            "disabled",
            False,
            ("uuid", "name", "enabled"),
        ),
        (
            {
                "openvpn": {
                    "servers": {
                        "uuid1": {
                            "uuid": "uuid1",
                            "name": "ovpn1",
                            "status": "up",
                            "enabled": True,
                            "connected_clients": 1,
                            "clients": [{"name": "c1", "status": "up", "bytes_sent": 10}],
                        }
                    }
                }
            },
            "openvpn.servers.uuid1.status",
            True,
            "up",
            True,
            ("uuid", "name", "enabled", "connected_clients"),
        ),
    ],
)
def test_vpn_sensor_variants(
    state: dict[str, Any],
    desc_key: Any,
    expected_available: bool,
    expected_value: Any,
    expect_clients: Any,
    expect_extra_keys: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Parameterised tests for OPNsenseVPNSensor to hit key branches in the update handler."""
    entry = make_config_entry()

    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = state

    desc = MagicMock()
    desc.key = desc_key
    desc.name = "VPN Test"

    s = OPNsenseVPNSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.vpn_test"
    object.__setattr__(s, "async_write_ha_state", lambda: None)
    s._handle_coordinator_update()

    assert s.available is expected_available
    if expected_available:
        assert s.native_value == expected_value
        attrs = s.extra_state_attributes
        assert attrs is not None
        if expect_clients:
            assert "clients" in attrs
            assert isinstance(attrs["clients"], list)
            assert attrs["clients"][0]["name"] == "c1"
        for key in expect_extra_keys:
            assert key in attrs


def test_vpn_sensor_unavailable_when_instance_container_is_not_mapping(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Malformed VPN instance container should mark VPNSensor unavailable."""
    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {
        "openvpn": {
            "servers": "bad-servers",
        }
    }

    desc = MagicMock()
    desc.key = "openvpn.servers.uuid1.status"
    desc.name = "VPN Test"

    s = OPNsenseVPNSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.vpn_test"
    object.__setattr__(s, "async_write_ha_state", lambda: None)
    s._handle_coordinator_update()

    assert s.available is False


def test_vpn_sensor_skips_malformed_client_rows(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Malformed nested VPN client rows should be skipped and valid clients still parsed."""
    state = {
        "openvpn": {
            "servers": {
                "uuid1": {
                    "name": "ovpn1",
                    "status": "up",
                    "clients": [
                        "bad-client-row",
                        {"name": "good", "status": "up", "bytes_recv": 5},
                    ],
                }
            }
        }
    }
    entry = make_config_entry()

    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = state

    desc = MagicMock()
    desc.key = "openvpn.servers.uuid1.status"
    desc.name = "VPN Test"

    s = OPNsenseVPNSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.vpn_malformed_client"
    object.__setattr__(s, "async_write_ha_state", lambda: None)
    s._handle_coordinator_update()

    assert s.available is True
    attrs = s.extra_state_attributes
    assert attrs is not None
    assert attrs.get("clients", []) == [{"name": "good", "status": "up", "bytes_recv": 5}]


@pytest.mark.parametrize("exc_type", [TypeError, KeyError, ZeroDivisionError])
def test_vpn_sensor_handles_exceptions_from_instance_get(
    exc_type: type[Exception], make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """VPNSensor marks itself unavailable when instance access raises.

    The test injects a broken instance object whose ``get`` method raises the
    requested exception so the handler exercises its defensive exception path.
    """

    class BrokenInstance(dict):
        """Mapping that raises from ``get`` for sensor error-path testing."""

        def __init__(self, exc: type[Exception]) -> None:
            """Initialize BrokenInstance.

            Args:
                exc: Exc provided by pytest or the test case.
            """
            super().__init__({"enabled": True})
            self._exc = exc

        def get(self, *args, **kwargs) -> Never:
            """Raise the configured exception when the sensor reads the mapping.

            Args:
                *args: Additional positional arguments forwarded by the function.
                **kwargs: Additional keyword arguments forwarded by the function.

            Raises:
                Exception: Raised using ``self._exc`` to exercise sensor exception handling.
            """
            raise self._exc("simulated")

    entry = make_config_entry()
    broken = BrokenInstance(exc_type)

    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {"openvpn": {"servers": {"uuid1": broken}}}

    desc = MagicMock()
    desc.key = "openvpn.servers.uuid1.status"
    desc.name = "VPN Broken"

    s = OPNsenseVPNSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.vpn_broken"
    object.__setattr__(s, "async_write_ha_state", lambda: None)
    s._handle_coordinator_update()

    assert s.available is False


def test_vpn_sensor_fails_closed_for_malformed_instance_collection(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """VPN sensor should mark unavailable when the instance collection is malformed."""
    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {"openvpn": {"servers": "not-a-mapping"}}
    desc = MagicMock()
    desc.key = "openvpn.servers.uuid1.status"
    desc.name = "VPN Malformed"

    s = OPNsenseVPNSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.vpn_malformed"
    object.__setattr__(s, "async_write_ha_state", lambda: None)

    s._handle_coordinator_update()

    assert s.available is False


@pytest.mark.parametrize(
    ("coord_data", "key"),
    [
        ({"openvpn": {"servers": {"uuid1": "not-a-mapping"}}}, "openvpn.servers.uuid1.status"),
        (
            {"openvpn": {"servers": {"uuid1": {"clients": "not-a-list", "status": "up"}}}},
            "openvpn.servers.uuid1.status",
        ),
        (
            {"openvpn": {"servers": {"uuid1": {"clients": ["not-a-mapping"], "status": "up"}}}},
            "openvpn.servers.uuid1.status",
        ),
    ],
)
def test_vpn_sensor_fails_closed_for_malformed_instance_members(
    coord_data: dict[str, Any],
    key: str,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """VPN sensor should mark unavailable when matched instance members are malformed."""
    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = coord_data
    desc = MagicMock()
    desc.key = key
    desc.name = "VPN Malformed Member"

    s = OPNsenseVPNSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.vpn_malformed_member"
    object.__setattr__(s, "async_write_ha_state", lambda: None)

    s._handle_coordinator_update()

    assert s.available is False


@pytest.mark.parametrize(
    ("coord_data", "expected_available", "expected_value", "expect_device"),
    [
        ([], False, None, False),
        ({"telemetry": {}}, False, None, False),
        ({"telemetry": {"temps": {"other": {"temperature": 55}}}}, False, None, False),
        (
            {"telemetry": {"temps": {"sensor1": {"temperature": 55, "device_id": "dev0"}}}},
            True,
            55,
            True,
        ),
    ],
)
def test_temp_sensor_basic_variants(
    coord_data: Any,
    expected_available: bool,
    expected_value: Any,
    expect_device: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Temp sensor should handle non-mapping/missing and successful value extraction."""
    entry = make_config_entry()

    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = coord_data

    desc = MagicMock()
    desc.key = "telemetry.temps.sensor1"
    desc.name = "Temp Test"

    s = OPNsenseTempSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.temp_test"
    object.__setattr__(s, "async_write_ha_state", lambda: None)
    s._handle_coordinator_update()

    assert s.available is expected_available
    if expected_available:
        assert s.native_value == expected_value
        if expect_device:
            attrs = s.extra_state_attributes
            assert attrs is not None
            assert attrs.get("device_id") == "dev0"


@pytest.mark.parametrize(
    "description_key",
    [
        pytest.param("telemetry.temps", id="missing-sensor-key"),
        pytest.param("foo.bar.sensor1", id="wrong-prefix"),
    ],
)
def test_temp_sensor_invalid_description_key_marked_unavailable(
    description_key: str,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Invalid temp sensor keys should fail closed to unavailable instead of raising."""
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {"telemetry": {"temps": {"sensor1": {"temperature": 55, "device_id": "dev0"}}}}
    entry = make_config_entry()

    desc = MagicMock()
    desc.key = description_key
    desc.name = "Invalid Temp Key"

    s = OPNsenseTempSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.temp_invalid_key"
    object.__setattr__(s, "async_write_ha_state", lambda: None)
    s._handle_coordinator_update()

    assert s.available is False


def test_temp_sensor_malformed_temps_container_on_update(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Temp sensor should become unavailable when a later update has malformed temps."""
    entry = make_config_entry()

    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {
        "telemetry": {"temps": {"sensor1": {"temperature": 55, "device_id": "dev0"}}},
    }

    desc = MagicMock()
    desc.key = "telemetry.temps.sensor1"
    desc.name = "Temp Test"

    s = OPNsenseTempSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.temp_test"
    object.__setattr__(s, "async_write_ha_state", lambda: None)
    s._handle_coordinator_update()
    assert s.available is True
    assert s.native_value == 55

    coord.data = {"telemetry": {"temps": "bad"}}
    s._handle_coordinator_update()
    assert s.available is False


@pytest.mark.parametrize("exc_type", [TypeError, KeyError, ZeroDivisionError])
def test_temp_sensor_handles_index_exceptions(
    exc_type: type[Exception], make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Temp sensor should mark itself unavailable when indexing temp raises exceptions."""

    class BrokenTemp:
        """Value object that raises when indexed by the temperature sensor."""

        def __init__(self, exc: type[Exception]) -> None:
            """Initialize BrokenTemp.

            Args:
                exc: Exc provided by pytest or the test case.
            """
            self._exc = exc

        def __bool__(self) -> bool:
            """Bool."""
            return True

        def __getitem__(self, key: str) -> None:
            """Raise the configured exception when the sensor indexes the temperature mapping.

            Args:
                key: Key provided by pytest or the test case.

            Raises:
                Exception: Raised using ``self._exc`` to exercise temperature sensor handling.
            """
            raise self._exc("simulated")

    entry = make_config_entry()
    broken = BrokenTemp(exc_type)

    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {"telemetry": {"temps": {"sensor1": broken}}}

    desc = MagicMock()
    desc.key = "telemetry.temps.sensor1"
    desc.name = "Temp Broken"

    s = OPNsenseTempSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.temp_broken"
    object.__setattr__(s, "async_write_ha_state", lambda: None)
    s._handle_coordinator_update()

    assert s.available is False


def test_temp_sensor_fails_closed_for_malformed_telemetry_payload(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Temp sensor should mark unavailable when telemetry is not a mapping."""
    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {"telemetry": "not-a-mapping"}
    desc = MagicMock()
    desc.key = "telemetry.temps.sensor1"
    desc.name = "Temp Malformed"

    s = OPNsenseTempSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.temp_malformed"
    object.__setattr__(s, "async_write_ha_state", lambda: None)

    s._handle_coordinator_update()

    assert s.available is False


def test_filesystem_sensor_fails_closed_for_malformed_telemetry_payload(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Filesystem sensor should mark unavailable when telemetry is not a mapping."""
    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {"telemetry": "not-a-mapping"}
    desc = MagicMock()
    desc.key = "telemetry.filesystems.root"
    desc.name = "Filesystem Malformed"

    s = OPNsenseFilesystemSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.filesystem_malformed"
    object.__setattr__(s, "async_write_ha_state", lambda: None)

    s._handle_coordinator_update()

    assert s.available is False


@pytest.mark.parametrize(
    "coord_data",
    [
        [],
        {"telemetry": {"filesystems": "not-a-list"}},
        {"telemetry": {"filesystems": ["not-a-mapping"]}},
        {"telemetry": {"filesystems": [{"mountpoint": "/var", "used_pct": 5}]}},
        {"telemetry": {"filesystems": [{"mountpoint": "/", "device": "/dev/gpt/rootfs"}]}},
    ],
    ids=[
        "state-not-mapping",
        "filesystems-not-list",
        "entry-not-mapping",
        "filesystem-not-found",
        "missing-used-pct",
    ],
)
def test_filesystem_sensor_fails_closed_for_malformed_filesystems(
    coord_data: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Filesystem sensor should become unavailable for malformed filesystem payloads."""
    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = coord_data
    desc = MagicMock()
    desc.key = "telemetry.filesystems.root"
    desc.name = "Filesystem Root"

    sensor = OPNsenseFilesystemSensor(
        config_entry=entry,
        coordinator=coord,
        entity_description=desc,
    )
    sensor.hass = MagicMock()
    sensor.entity_id = "sensor.filesystem_root"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)

    sensor._handle_coordinator_update()

    assert sensor.available is False


@pytest.mark.parametrize(
    ("desc_key", "state", "expect_close_icon"),
    [
        (
            "openvpn.servers.uuid1.status",
            {"openvpn": {"servers": {"uuid1": {"name": "ovpn", "status": "up"}}}},
            False,
        ),
        (
            "openvpn.servers.uuid1.status",
            {"openvpn": {"servers": {"uuid1": {"name": "ovpn", "status": "down"}}}},
            True,
        ),
        (
            "openvpn.servers.uuid1.connected_clients",
            {"openvpn": {"servers": {"uuid1": {"name": "ovpn", "connected_clients": 1}}}},
            False,
        ),
    ],
)
def test_vpn_sensor_icon_variants(
    desc_key: Any,
    state: dict[str, Any],
    expect_close_icon: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Verify VPNSensor.icon for status up/down and fallback to description icon for non-status."""
    entry = make_config_entry()

    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = state

    desc = MagicMock()
    desc.key = desc_key
    desc.name = "VPN Icon Test"
    desc.icon = "mdi:custom-icon"

    s = OPNsenseVPNSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.vpn_icon"
    object.__setattr__(s, "async_write_ha_state", lambda: None)
    s._handle_coordinator_update()

    if expect_close_icon:
        assert s.icon == "mdi:close-network-outline"
    else:
        assert s.icon != "mdi:close-network-outline"


def test_build_vpn_sensor_description_uses_gauge_icon_for_generic_properties() -> None:
    """VPN sensor descriptions should use the gauge icon for unclassified properties."""
    description = sensor_module._build_vpn_sensor_description(
        "wireguard",
        "servers",
        "uuid1",
        "wg0",
        "uptime",
    )

    assert description.icon == "mdi:gauge"


def test_sensor_module_import() -> None:
    """Test that the sensor module can be imported via relative import."""
    assert sensor_module is not None


@pytest.mark.parametrize(
    ("input_value", "expected"),
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
    ("input_value", "expected"),
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


@pytest.mark.parametrize(
    ("cpu_map", "previous", "expected_available", "expected_value"),
    [
        ({"usage_total": 0}, None, False, None),
        ({"usage_total": 0}, 0, False, None),
        ({"usage_total": 0, "usage_1": 1}, 7, True, 7),
    ],
)
def test_static_cpu_zero_variants(
    cpu_map: dict,
    previous: int | None,
    expected_available: bool,
    expected_value: int | None,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Zero CPU totals make the sensor unavailable unless a previous value exists.

    This parameterized test covers both the unavailable path and the branch
    that reuses the previous sensor value.
    """
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {"telemetry": {"cpu": cpu_map}}
    entry = make_config_entry()

    desc = MagicMock()
    desc.key = "telemetry.cpu.usage_total"
    desc.name = "CPU Total"

    sensor = OPNsenseStaticKeySensor(config_entry=entry, coordinator=coord, entity_description=desc)
    sensor.hass = MagicMock()
    sensor.entity_id = "sensor.cpu_total"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)
    if previous is not None:
        sensor._previous_value = previous

    sensor._handle_coordinator_update()
    assert sensor.available is expected_available
    if expected_value is not None:
        assert sensor.native_value == expected_value


def test_gateway_empty_string_unavailable(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Gateway sensor should be unavailable for empty status strings."""
    state = {"gateways": {"gw1": {"name": "gw1", "status": ""}}}
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = state
    entry = make_config_entry()

    desc = MagicMock()
    desc.key = "gateway.gw1.status"
    desc.name = "Gateway Status"

    s = OPNsenseGatewaySensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.gw_empty"
    object.__setattr__(s, "async_write_ha_state", lambda: None)
    s._handle_coordinator_update()
    assert s.available is False


def test_interface_status_icon_up(make_config_entry: Callable[..., MockConfigEntry]) -> None:
    """Interface status sensor shows an 'up' icon when status is up."""
    state = {"interfaces": {"lan": {"name": "LAN", "status": "up", "interface": "lan0"}}}
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = state
    entry = make_config_entry()

    desc = MagicMock()
    desc.key = "interface.lan.status"
    desc.name = "LAN Status"

    s = OPNsenseInterfaceSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.lan_status_up"
    object.__setattr__(s, "async_write_ha_state", lambda: None)
    s._handle_coordinator_update()
    assert s.icon != "mdi:close-network-outline"


def test_interface_sensor_with_dotted_key_parses_interface_name(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Interface sensor should parse dotted interface keys."""
    state = {
        "interfaces": {
            "wan.vlan.100": {
                "name": "WAN VLAN 100",
                "inbytes": 321,
                "status": "up",
                "interface": "igc0",
            }
        }
    }
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = state
    entry = make_config_entry()

    desc = MagicMock()
    desc.key = "interface.wan.vlan.100.inbytes"
    desc.name = "WAN VLAN 100 inbytes"

    sensor = OPNsenseInterfaceSensor(
        config_entry=entry,
        coordinator=coord,
        entity_description=desc,
    )
    sensor.hass = MagicMock()
    sensor.entity_id = "sensor.wan_vlan_100_inbytes"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)
    sensor._handle_coordinator_update()

    assert sensor.available is True
    assert sensor.native_value == 321


@pytest.mark.asyncio
async def test_interface_rate_sensor_unavailable_when_counter_disappears_mid_refresh(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Interface rate sensors should become unavailable when a derived counter disappears."""
    state = {
        "interfaces": {
            "eth0": {
                "name": "eth0",
                "inbytes_kilobytes_per_second": 123,
                "inbytes": 2048,
                "status": "up",
                "interface": "eth0",
                "device": "eth0",
            }
        }
    }
    entry = make_config_entry()
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = state

    entities = await sensor_module._compile_interface_sensors(entry, coordinator, state)
    rate_sensor = next(
        entity
        for entity in entities
        if entity.entity_description.key == "interface.eth0.inbytes_kilobytes_per_second"
    )
    rate_sensor.hass = MagicMock()
    rate_sensor.entity_id = "sensor.eth0_inbytes_kilobytes_per_second"
    object.__setattr__(rate_sensor, "async_write_ha_state", lambda: None)

    rate_sensor._handle_coordinator_update()
    assert rate_sensor.available is True
    assert rate_sensor.native_value == 123

    coordinator.data = {
        "interfaces": {
            "eth0": {
                "name": "eth0",
                "inbytes": 4096,
                "status": "up",
                "interface": "eth0",
                "device": "eth0",
            }
        }
    }

    rate_sensor._handle_coordinator_update()
    assert rate_sensor.available is False


@pytest.mark.parametrize("description_key", ["interface", "interface.lan"])
def test_interface_sensor_invalid_description_key_unavailable(
    description_key: str,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Interface sensor should be unavailable when its description key cannot be parsed."""
    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {"interfaces": {"lan": {"name": "LAN", "status": "up"}}}
    desc = MagicMock()
    desc.key = description_key
    desc.name = "Interface Invalid"

    sensor = OPNsenseInterfaceSensor(
        config_entry=entry,
        coordinator=coord,
        entity_description=desc,
    )
    sensor.hass = MagicMock()
    sensor.entity_id = "sensor.interface_invalid"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)
    sensor._handle_coordinator_update()

    assert sensor.available is False


def test_interface_sensor_invalid_icon_key_uses_description_icon(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Interface sensor icon should fall back when its description key cannot be parsed."""
    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {"interfaces": {"lan": {"name": "LAN", "status": "up"}}}
    desc = MagicMock()
    desc.key = "interface"
    desc.name = "Interface Invalid"
    desc.icon = "mdi:gauge"

    sensor = OPNsenseInterfaceSensor(
        config_entry=entry,
        coordinator=coord,
        entity_description=desc,
    )

    assert sensor.icon == "mdi:gauge"


def test_gateway_sensor_with_dotted_key_parses_gateway_name_and_icon(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Gateway sensor should parse dotted gateway names and status icon logic."""
    state = {
        "gateways": {
            "wan-gw": {
                "name": "WAN.Gateway",
                "status": "offline",
                "address": "198.51.100.1",
            }
        }
    }
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = state
    entry = make_config_entry()

    desc = MagicMock()
    desc.key = "gateway.WAN.Gateway.status"
    desc.name = "WAN.Gateway Status"

    sensor = OPNsenseGatewaySensor(
        config_entry=entry,
        coordinator=coord,
        entity_description=desc,
    )
    sensor.hass = MagicMock()
    sensor.entity_id = "sensor.wan_gateway_status"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)
    sensor._handle_coordinator_update()

    assert sensor.available is True
    assert sensor.native_value == "offline"
    assert sensor.icon == "mdi:close-network-outline"


@pytest.mark.parametrize(
    (
        "description_key",
        "description_name",
        "interface_values",
        "expected_available",
        "expected_native_value",
        "expected_enabled_attribute",
    ),
    [
        pytest.param(
            "interface.wan.status",
            "WAN Status",
            {"status": "up", "enabled": False},
            False,
            None,
            False,
            id="status-disabled-preserves-enabled-attribute",
        ),
        pytest.param(
            "interface.wan.inbytes",
            "WAN In Bytes",
            {"status": "up", "enabled": False, "inbytes": 2048},
            False,
            None,
            None,
            id="metric-disabled",
        ),
        pytest.param(
            "interface.wan.status",
            "WAN Status",
            {"status": "up", "enabled": None},
            True,
            "up",
            None,
            id="status-enabled-unknown",
        ),
    ],
)
def test_interface_sensor_enabled_state_handling(
    description_key: str,
    description_name: str,
    interface_values: dict[str, Any],
    expected_available: bool,
    expected_native_value: Any,
    expected_enabled_attribute: bool | None,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Interface sensors should handle false and unknown enabled states."""
    state = {
        "interfaces": {
            "wan": {
                "name": "WAN",
                "interface": "wan",
                **interface_values,
            }
        }
    }
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = state
    entry = make_config_entry()

    desc = MagicMock()
    desc.key = description_key
    desc.name = description_name

    sensor = OPNsenseInterfaceSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    sensor.hass = MagicMock()
    sensor.entity_id = f"sensor.{description_key.replace('.', '_')}"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)

    sensor._handle_coordinator_update()

    assert sensor.available is expected_available
    if expected_native_value is None:
        assert sensor.native_value is None
    else:
        assert sensor.native_value == expected_native_value

    attrs = sensor.extra_state_attributes
    if expected_enabled_attribute is None:
        assert attrs is None or "enabled" not in attrs
    else:
        assert attrs is not None
        assert attrs["enabled"] is expected_enabled_attribute


@pytest.mark.parametrize(
    "coord_data",
    [
        {"interfaces": "not-a-mapping"},
        {"interfaces": {"lan": {"name": "LAN", "status": "up"}}},
    ],
    ids=["interfaces-not-mapping", "interface-not-found"],
)
def test_interface_sensor_fails_closed_for_missing_interface_payloads(
    coord_data: dict[str, Any],
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Interface sensor should be unavailable when interface state cannot be found."""
    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = coord_data
    desc = MagicMock()
    desc.key = "interface.wan.status"
    desc.name = "WAN Status"

    sensor = OPNsenseInterfaceSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    sensor.hass = MagicMock()
    sensor.entity_id = "sensor.wan_status"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)

    sensor._handle_coordinator_update()

    assert sensor.available is False


@pytest.mark.parametrize(
    ("leases_val", "lease_interfaces_val"),
    [
        ([], {"lan": "LAN"}),
        ({"lan": [{"address": "192.168.1.2"}]}, []),
        (None, {"lan": "LAN"}),
    ],
)
def test_dhcp_leases_all_non_mapping(
    leases_val: Any,
    lease_interfaces_val: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """DHCP Leases 'all' sensor should be unavailable when leases or lease_interfaces are not mappings."""
    entry = make_config_entry()

    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {"dhcp_leases": {"leases": leases_val, "lease_interfaces": lease_interfaces_val}}

    desc = MagicMock()
    desc.key = "dhcp_leases.all"
    desc.name = "DHCP All"

    s = OPNsenseDHCPLeasesSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.dhcp_all"
    object.__setattr__(s, "async_write_ha_state", lambda: None)
    s._handle_coordinator_update()
    assert s.available is False


@pytest.mark.parametrize("key", ["dhcp_leases.all", "dhcp_leases.lan"])
def test_dhcp_leases_sensor_handles_none_payload(
    key: str, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """DHCP leases sensors should be unavailable when coordinator data contains a null DHCP payload."""
    entry = make_config_entry()

    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {"dhcp_leases": None}

    desc = MagicMock()
    desc.key = key
    desc.name = "DHCP Leases"

    s = OPNsenseDHCPLeasesSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.dhcp_leases"

    writes: list[bool] = []

    def collector() -> None:
        """Collect availability when the entity state is written."""
        writes.append(bool(getattr(s, "_available", None)))

    object.__setattr__(s, "async_write_ha_state", collector)
    s._handle_coordinator_update()

    assert s.available is False
    assert writes == [False]


@pytest.mark.parametrize("leases", [None, []])
def test_dhcp_leases_interface_sensor_handles_non_mapping_leases(
    leases: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """DHCP interface leases sensor should be unavailable when leases are not a mapping."""
    entry = make_config_entry()

    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {"dhcp_leases": {"leases": leases}}

    desc = MagicMock()
    desc.key = "dhcp_leases.lan"
    desc.name = "DHCP LAN"

    s = OPNsenseDHCPLeasesSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.dhcp_lan"

    writes: list[bool] = []

    def collector() -> None:
        """Collect availability when the entity state is written."""
        writes.append(bool(getattr(s, "_available", None)))

    object.__setattr__(s, "async_write_ha_state", collector)
    s._handle_coordinator_update()

    assert s.available is False
    assert writes == [False]


def test_dhcp_leases_interface_sensor_handles_non_list_interface(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """DHCP interface lease sensor should be unavailable when interface leases are not a list."""
    entry = make_config_entry()

    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {"dhcp_leases": {"leases": {"lan": "not-a-list"}}}

    desc = MagicMock()
    desc.key = "dhcp_leases.lan"
    desc.name = "DHCP LAN"

    sensor = OPNsenseDHCPLeasesSensor(
        config_entry=entry,
        coordinator=coord,
        entity_description=desc,
    )
    sensor.hass = MagicMock()
    sensor.entity_id = "sensor.dhcp_lan"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)

    sensor._handle_coordinator_update()

    assert sensor.available is False


@pytest.mark.parametrize(
    ("key", "coord_data"),
    [
        (
            "dhcp_leases.all",
            {
                "dhcp_leases": {
                    "leases": {"lan": ["not-a-mapping"]},
                    "lease_interfaces": {"lan": "LAN"},
                }
            },
        ),
        (
            "dhcp_leases.lan",
            {"dhcp_leases": {"leases": {"lan": ["not-a-mapping"]}}},
        ),
    ],
)
def test_dhcp_leases_sensor_fails_closed_for_scalar_lease_rows(
    key: str,
    coord_data: dict[str, Any],
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """DHCP leases sensors should mark unavailable when a lease row is malformed."""
    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = coord_data

    desc = MagicMock()
    desc.key = key
    desc.name = "DHCP Scalar Lease"

    s = OPNsenseDHCPLeasesSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.dhcp_scalar_lease"

    writes: list[bool] = []

    def collector() -> None:
        """Collect availability when the entity state is written."""
        writes.append(bool(getattr(s, "_available", None)))

    object.__setattr__(s, "async_write_ha_state", collector)
    s._available = True

    s._handle_coordinator_update()

    assert s.available is False
    assert writes == [False]


@pytest.mark.parametrize("exc_type", [TypeError, KeyError, AttributeError, ZeroDivisionError])
def test_dhcp_leases_handles_exceptions(
    exc_type: type[Exception], make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """DHCP lease aggregation marks the sensor unavailable on lease errors.

    The test injects a broken lease object whose ``get`` method raises the
    requested exception so the aggregation loop exercises its exception path.
    """

    class BrokenLease:
        """Lease mapping that raises from ``get`` for error-path testing."""

        def __init__(self, exc: type[Exception]) -> None:
            """Initialize BrokenLease.

            Args:
                exc: Exc provided by pytest or the test case.
            """
            self._exc = exc

        def get(self, *args, **kwargs) -> Never:
            """Raise the configured exception when the DHCP lease mapping is read.

            Args:
                *args: Additional positional arguments forwarded by the function.
                **kwargs: Additional keyword arguments forwarded by the function.

            Raises:
                Exception: Raised using ``self._exc`` to exercise lease sensor handling.
            """
            raise self._exc("simulated")

    entry = make_config_entry()

    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {
        "dhcp_leases": {
            "leases": {"lan": [BrokenLease(exc_type)]},
            "lease_interfaces": {"lan": "LAN"},
        }
    }

    desc = MagicMock()
    desc.key = "dhcp_leases.all"
    desc.name = "DHCP Broken Iteration"

    s = OPNsenseDHCPLeasesSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.dhcp_broken"
    object.__setattr__(s, "async_write_ha_state", lambda: None)
    s._handle_coordinator_update()
    assert s.available is False


@pytest.mark.parametrize("exc_type", [TypeError, KeyError, AttributeError, ZeroDivisionError])
def test_dhcp_lease_interfaces_items_raises(
    exc_type: type[Exception], make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Ensure exceptions raised by lease_interfaces.items() are caught and sensor becomes unavailable."""

    class BrokenLeaseInterfaces(dict):
        """Lease-interface mapping that raises while iterating items."""

        def items(self) -> Never:
            """Raise the parametrized exception when lease interfaces are iterated.

            Raises:
                Exception: Raised using ``exc_type`` to test interface iteration failures.
            """
            raise exc_type("simulated")

    entry = make_config_entry()

    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {
        "dhcp_leases": {
            "leases": {"lan": [{"address": "192.168.1.2"}]},
            "lease_interfaces": BrokenLeaseInterfaces({"lan": "LAN"}),
        }
    }

    desc = MagicMock()
    desc.key = "dhcp_leases.all"
    desc.name = "DHCP Broken LeaseInterfaces"

    s = OPNsenseDHCPLeasesSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.dhcp_broken_items"
    object.__setattr__(s, "async_write_ha_state", lambda: None)
    s._handle_coordinator_update()
    assert s.available is False


@pytest.mark.parametrize("exc_type", [TypeError, KeyError, AttributeError, ZeroDivisionError])
def test_dhcp_leases_iterable_raises_on_iter(
    exc_type: type[Exception], make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Ensure exceptions raised while iterating the leases list are caught and sensor becomes unavailable."""

    class BrokenLeaseList(list):
        """Lease list that raises when the sensor begins iteration."""

        def __iter__(self) -> Never:
            """Raise the parametrized exception when the lease list is iterated.

            Raises:
                Exception: Raised using ``exc_type`` to test iterable failure handling.
            """
            raise exc_type("simulated")

    entry = make_config_entry()

    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {
        "dhcp_leases": {
            "leases": {"lan": BrokenLeaseList([{"address": "192.168.1.2"}])},
            "lease_interfaces": {"lan": "LAN"},
        }
    }

    desc = MagicMock()
    desc.key = "dhcp_leases.all"
    desc.name = "DHCP Broken Iterable"

    s = OPNsenseDHCPLeasesSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.dhcp_broken_iter"
    object.__setattr__(s, "async_write_ha_state", lambda: None)
    s._handle_coordinator_update()
    assert s.available is False


def test_dhcp_leases_inner_except_writes_unavailable(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Inner DHCP lease errors write an unavailable state to Home Assistant.

    The test records ``self._available`` at each write so a captured ``False``
    proves the inner exception branch executed before the state update.
    """

    class BrokenLease:
        """Lease mapping that raises during the inner aggregation loop."""

        def get(self, *args, **kwargs) -> Never:
            """Raise ``KeyError`` when the sensor reads the lease mapping.

            Args:
                *args: Additional positional arguments forwarded by the function.
                **kwargs: Additional keyword arguments forwarded by the function.

            Raises:
                TypeError: If a supplied argument has an unsupported type.
            """
            raise TypeError("simulated")

    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {
        "dhcp_leases": {
            "leases": {"lan": [BrokenLease()]},
            "lease_interfaces": {"lan": "LAN"},
        }
    }

    desc = MagicMock()
    desc.key = "dhcp_leases.all"
    desc.name = "DHCP Inner Except Collector"

    s = OPNsenseDHCPLeasesSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.dhcp_inner_collector"

    writes: list[bool] = []

    def collector() -> None:
        """Collector."""
        writes.append(bool(getattr(s, "_available", None)))

    object.__setattr__(s, "async_write_ha_state", collector)
    s._handle_coordinator_update()

    assert writes, "async_write_ha_state was not called"
    assert any(w is False for w in writes), f"expected a False write captured, got {writes}"


def test_dhcp_leases_items_except_writes_unavailable(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Verify exceptions from lease_interfaces.items() cause unavailable state and write."""

    class BrokenLeaseInterfaces(dict):
        """Lease-interface mapping that raises during item iteration."""

        def items(self) -> Never:
            """Raise ``KeyError`` when interface items are requested.

            Raises:
                KeyError: Always raised to exercise item-iteration fallback handling.
            """
            raise KeyError("simulated")

    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {
        "dhcp_leases": {
            "leases": {"lan": [{"address": "192.168.1.2"}]},
            "lease_interfaces": BrokenLeaseInterfaces({"lan": "LAN"}),
        }
    }

    desc = MagicMock()
    desc.key = "dhcp_leases.all"
    desc.name = "DHCP Items Except Collector"

    s = OPNsenseDHCPLeasesSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.dhcp_items_collector"

    writes: list[bool] = []

    def collector() -> None:
        """Collector."""
        writes.append(bool(getattr(s, "_available", None)))

    object.__setattr__(s, "async_write_ha_state", collector)
    s._handle_coordinator_update()

    assert writes, "async_write_ha_state was not called"
    assert any(w is False for w in writes), f"expected a False write captured, got {writes}"


@pytest.mark.parametrize("exc_type", [TypeError, KeyError, AttributeError, ZeroDivisionError])
def test_dhcp_leases_per_interface_handles_exceptions(
    exc_type: type[Exception], make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Per-interface DHCP lease errors mark the sensor unavailable and write state.

    This exercises the branch that sums leases for one interface while a broken
    lease object raises inside the surrounding exception handler.
    """

    class BrokenLease(dict):
        """Lease mapping that raises while reading per-interface data."""

        def __init__(self, exc: type[Exception]) -> None:
            """Initialize BrokenLease.

            Args:
                exc: Exc provided by pytest or the test case.
            """
            super().__init__({"address": "192.168.1.2"})
            self._exc = exc

        def get(self, *args, **kwargs) -> Never:
            """Raise the configured exception when per-interface lease data is read.

            Args:
                *args: Additional positional arguments forwarded by the function.
                **kwargs: Additional keyword arguments forwarded by the function.

            Raises:
                Exception: Raised using ``self._exc`` to test per-interface error handling.
            """
            raise self._exc("simulated")

    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = {"dhcp_leases": {"leases": {"lan": [BrokenLease(exc_type)]}}}

    desc = MagicMock()
    desc.key = "dhcp_leases.lan"
    desc.name = "DHCP Per-Interface Broken"

    s = OPNsenseDHCPLeasesSensor(config_entry=entry, coordinator=coord, entity_description=desc)
    s.hass = MagicMock()
    s.entity_id = "sensor.dhcp_per_if_broken"

    writes: list[bool] = []

    def collector() -> None:
        """Collector."""
        writes.append(bool(getattr(s, "_available", None)))

    object.__setattr__(s, "async_write_ha_state", collector)
    s._handle_coordinator_update()

    assert writes, "async_write_ha_state was not called"
    assert any(w is False for w in writes), f"expected a False write captured, got {writes}"


def _setup_entry_with_all_syncs(
    state: dict, make_config_entry: Callable[..., MockConfigEntry]
) -> Any:
    """Setup entry with all syncs.

    Args:
        state: Dictionary containing the initial coordinator state for the entry.
        make_config_entry: Fixture that builds config entries tailored for the test scenario.
    """
    entry = make_config_entry()
    base = dict(entry.data)
    base.update(
        {
            CONF_SYNC_TELEMETRY: True,
            CONF_SYNC_VNSTAT: True,
            CONF_SYNC_SPEEDTEST: True,
            CONF_SYNC_SMART: True,
            CONF_SYNC_CERTIFICATES: True,
            CONF_SYNC_VPN: True,
            CONF_SYNC_GATEWAYS: True,
            CONF_SYNC_INTERFACES: True,
            CONF_SYNC_CARP: True,
            CONF_SYNC_DHCP_LEASES: True,
        }
    )
    entry = make_config_entry(base)
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = state
    setattr(entry.runtime_data, COORDINATOR, coord)
    return entry, coord


@pytest.mark.parametrize(
    ("state", "expected_key", "expected_name", "absent_classes"),
    [
        (
            {
                "telemetry": {"filesystems": [], "temps": {}},
                "interfaces": {},
                "gateways": {},
                "openvpn": {
                    "servers": {"server-uuid": {"description": "Remote Access", "status": "up"}}
                },
            },
            "openvpn.servers.server-uuid.status",
            "OpenVPN Server Remote Access status",
            (),
        ),
        (
            {
                "telemetry": {"filesystems": [], "temps": {}},
                "interfaces": {},
                "gateways": {"wan": {"status": "online", "delay": "12ms", "loss": "0%"}},
                "openvpn": {"servers": {}},
            },
            "gateway.wan.status",
            "Gateway wan status",
            (),
        ),
        (
            {
                "telemetry": {
                    "filesystems": ["not-a-filesystem"],
                    "temps": {"cpu": "not-a-temp"},
                },
                "interfaces": {"wan": "not-an-interface"},
                "gateways": {"wan": "not-a-gateway"},
                "openvpn": {"servers": {}},
            },
            None,
            None,
            (
                OPNsenseFilesystemSensor,
                OPNsenseTempSensor,
                OPNsenseInterfaceSensor,
                OPNsenseGatewaySensor,
            ),
        ),
    ],
)
@pytest.mark.asyncio
async def test_async_setup_entry_handles_partial_or_malformed_dynamic_sensor_payloads(
    make_config_entry: Callable[..., MockConfigEntry],
    state: dict[str, Any],
    expected_key: str | None,
    expected_name: str | None,
    absent_classes: tuple[type[object], ...],
) -> None:
    """Partial or malformed dynamic sensor payloads should not block setup."""
    entry, _coord = _setup_entry_with_all_syncs(state, make_config_entry)
    created: list[Any] = []

    def add_entities(entities: Iterable[Any], _update_before_add: bool = False) -> None:
        """Add entities.

        Args:
            entities: Entities provided by pytest or the test case.
        """
        created.extend(entities)

    await async_setup_entry(MagicMock(), entry, cast("AddEntitiesCallback", add_entities))

    assert any(isinstance(entity, OPNsenseStaticKeySensor) for entity in created)
    if expected_key is not None:
        matched = next(
            entity for entity in created if entity.entity_description.key == expected_key
        )
        assert matched.entity_description.name == expected_name
    for entity_class in absent_classes:
        assert not any(isinstance(entity, entity_class) for entity in created)


@pytest.mark.parametrize(
    ("compile_helper", "state"),
    [
        (sensor_module._compile_filesystem_sensors, []),
        (sensor_module._compile_filesystem_sensors, {"telemetry": {"filesystems": "bad"}}),
        (sensor_module._compile_interface_sensors, []),
        (sensor_module._compile_interface_sensors, {"interfaces": "bad"}),
        (sensor_module._compile_gateway_sensors, []),
        (sensor_module._compile_gateway_sensors, {"gateways": "bad"}),
        (sensor_module._compile_temperature_sensors, []),
        (sensor_module._compile_temperature_sensors, {"telemetry": {"temps": "bad"}}),
        (sensor_module._compile_dhcp_leases_sensors, []),
    ],
)
async def test_dynamic_sensor_compile_helpers_skip_malformed_containers(
    make_config_entry: Callable[..., MockConfigEntry],
    compile_helper: Callable[
        [MockConfigEntry, OPNsenseDataUpdateCoordinator, Any],
        Any,
    ],
    state: Any,
) -> None:
    """Malformed dynamic sensor containers should compile to no entities."""
    entry = make_config_entry()
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = state

    assert await compile_helper(entry, coordinator, state) == []


@pytest.mark.asyncio
async def test_compile_vpn_sensors_skips_malformed_containers(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Malformed VPN setup containers should not produce any VPN sensors."""
    state: dict[str, Any] = {
        "openvpn": {"servers": {"empty-server": {}}},
        "wireguard": {
            "clients": "bad-clients",
            "servers": {"bad-server": "bad-server"},
        },
    }
    entry = make_config_entry()
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = state

    entities = await sensor_module._compile_vpn_sensors(entry, coordinator, state)

    assert entities == []


async def test_dhcp_leases_compile_helper_uses_all_sensor_for_malformed_interfaces(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Malformed DHCP lease interface containers should still create aggregate sensor."""
    state: dict[str, Any] = {"dhcp_leases": {"lease_interfaces": "bad"}}
    entry = make_config_entry()
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = state

    entities = await sensor_module._compile_dhcp_leases_sensors(entry, coordinator, state)

    assert [entity.entity_description.key for entity in entities] == ["dhcp_leases.all"]


class _BadDHCPLeaseInterfaces(dict):
    """Mapping that raises when items() is queried."""

    def items(self) -> Never:  # type: ignore[override]
        """Raise when the compiler queries interface items."""
        raise RuntimeError("items failure for test")


async def test_dhcp_leases_compile_helper_skips_on_items_failure(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """items() failures should be ignored but still produce the aggregate DHCP sensor."""
    state: dict[str, Any] = {
        "dhcp_leases": {
            "lease_interfaces": _BadDHCPLeaseInterfaces({"lan": "LAN", "wan": "WAN"}),
            "leases": {"lan": [{"address": "192.168.1.2"}], "wan": []},
        }
    }
    entry = make_config_entry()
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = state

    entities = await sensor_module._compile_dhcp_leases_sensors(entry, coordinator, state)

    assert [entity.entity_description.key for entity in entities] == ["dhcp_leases.all"]


async def test_filesystem_compile_helper_skips_rows_without_mountpoint(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Filesystem rows without a usable mountpoint should not create entities."""
    state: dict[str, Any] = {
        "telemetry": {
            "filesystems": [
                {"used_pct": 42},
                {"mountpoint": "", "used_pct": 12},
            ]
        }
    }
    entry = make_config_entry()
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = state

    assert await sensor_module._compile_filesystem_sensors(entry, coordinator, state) == []


def test_filesystem_sensor_skips_malformed_rows(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Malformed filesystem rows should be skipped while reading a valid filesystem."""
    state = {
        "telemetry": {
            "filesystems": [
                "bad-row",
                {
                    "mountpoint": "/",
                    "used_pct": 42,
                    "device": "/dev/sda1",
                    "type": "ext4",
                    "blocks": 1000,
                    "used": 420,
                    "available": 580,
                },
            ],
            "temps": {},
        },
        "interfaces": {},
    }
    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = state
    desc = MagicMock()
    desc.key = f"telemetry.filesystems.{slugify_filesystem_mountpoint('/')}"
    desc.name = "Filesystem Test"

    sensor = OPNsenseFilesystemSensor(
        config_entry=entry,
        coordinator=coord,
        entity_description=desc,
    )
    sensor.hass = MagicMock()
    sensor.entity_id = "sensor.fs_root"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)
    sensor._handle_coordinator_update()

    assert sensor.available is True
    assert sensor.native_value == 42
    attrs = sensor.extra_state_attributes
    assert attrs is not None
    assert attrs.get("mountpoint") == "/"


def test_filesystem_sensor_handles_partial_matching_row(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Partial matching filesystem rows should not raise while updating state."""
    state = {
        "telemetry": {
            "filesystems": [
                {
                    "mountpoint": "/",
                    "used_pct": 42,
                },
            ],
            "temps": {},
        },
    }
    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = state
    desc = MagicMock()
    desc.key = f"telemetry.filesystems.{slugify_filesystem_mountpoint('/')}"
    desc.name = "Filesystem Test"

    sensor = OPNsenseFilesystemSensor(
        config_entry=entry,
        coordinator=coord,
        entity_description=desc,
    )
    sensor.hass = MagicMock()
    sensor.entity_id = "sensor.fs_root"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)
    sensor._handle_coordinator_update()

    assert sensor.available is True
    assert sensor.native_value == 42
    assert sensor.extra_state_attributes == {"mountpoint": "/"}


@pytest.mark.parametrize(
    "state",
    [
        [],
        {"telemetry": {"filesystems": "bad-filesystems"}},
        {"telemetry": {"filesystems": [{"mountpoint": "/var", "used_pct": 12}]}},
        {"telemetry": "bad-telemetry"},
    ],
)
def test_filesystem_sensor_unavailable_with_malformed_containers(
    make_config_entry: Callable[..., MockConfigEntry],
    state: Any,
) -> None:
    """Missing or malformed filesystem state should mark the sensor unavailable."""
    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = state
    desc = MagicMock()
    desc.key = f"telemetry.filesystems.{slugify_filesystem_mountpoint('/')}"
    desc.name = "Filesystem Test"

    sensor = OPNsenseFilesystemSensor(
        config_entry=entry,
        coordinator=coord,
        entity_description=desc,
    )
    sensor.hass = MagicMock()
    sensor.entity_id = "sensor.fs_root"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)
    sensor._handle_coordinator_update()

    assert sensor.available is False


@pytest.mark.asyncio
async def test_compile_and_handle_many_entities(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Compile a complex state and verify many sensor branches are handled."""
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
        "carp": {
            "interfaces": [
                {
                    "subnet": "192.0.2.1",
                    "status": "BACKUP",
                    "interface": "lan0",
                    "vhid": 2,
                    "advskew": 100,
                }
            ]
        },
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

    entry, _coord = _setup_entry_with_all_syncs(state, make_config_entry)

    created: list = []

    async def run_setup() -> None:
        """Run setup."""

        def add_entities(entities: Iterable[Any], _update_before_add: bool = False) -> None:
            """Add entities.

            Args:
                entities: Entities provided by pytest or the test case.
            """
            created.extend(entities)

        await sensor_module.async_setup_entry(
            MagicMock(), entry, cast("AddEntitiesCallback", add_entities)
        )

    await run_setup()

    assert len(created) > 0

    failures: list[str] = []
    for i, ent in enumerate(created):
        ent.hass = MagicMock()
        ent.entity_id = f"sensor.test_{i}"
        object.__setattr__(ent, "async_write_ha_state", lambda: None)
        try:
            ent._handle_coordinator_update()
        except (
            TypeError,
            KeyError,
            ZeroDivisionError,
            AttributeError,
        ) as e:
            failures.append(
                f"entity={getattr(ent, 'entity_id', i)} type={type(e).__name__} msg={e!r}"
            )

    if failures:
        pytest.fail("Exceptions raised by entity handlers:\n" + "\n".join(failures))


@pytest.mark.asyncio
async def test_async_setup_entry_creates_entities(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry should create sensor entities for available telemetry and interfaces."""
    state: dict[str, Any] = {
        "telemetry": {"filesystems": [], "temps": {}},
        "interfaces": {},
        "gateways": {},
    }
    entry, _coord = _setup_entry_with_all_syncs(state, make_config_entry)

    created: list = []

    def add_entities(ents: Iterable[Any], _update_before_add: bool = False) -> None:
        """Add entities.

        Args:
            ents: Ents provided by pytest or the test case.
        """
        created.extend(ents)

    await async_setup_entry(MagicMock(), entry, cast("AddEntitiesCallback", add_entities))
    assert created, "no entities created"
    assert any(isinstance(e, OPNsenseStaticKeySensor) for e in created)


@pytest.mark.asyncio
async def test_compile_vpn_sensors_skips_empty_instances(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Empty VPN instances should be skipped during VPN sensor setup."""
    state: dict[str, Any] = {
        "openvpn": {"servers": {"server-uuid": {}}},
        "wireguard": {"clients": {}, "servers": {}},
    }
    entry = make_config_entry()
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = state

    entities = await sensor_module._compile_vpn_sensors(entry, coordinator, state)

    assert entities == []


def test_filesystem_sensor_handles_partial_telemetry_row(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Filesystem sensor should tolerate partial telemetry rows and keep available state."""
    state = {
        "telemetry": {
            "filesystems": [
                {"mountpoint": "/", "used_pct": 12, "type": "ext4"},
            ],
            "temps": {},
        },
        "interfaces": {},
    }
    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = state
    desc = MagicMock()
    desc.key = f"telemetry.filesystems.{slugify_filesystem_mountpoint('/')}"
    desc.name = "Filesystem Test"

    sensor = OPNsenseFilesystemSensor(
        config_entry=entry,
        coordinator=coord,
        entity_description=desc,
    )
    sensor.hass = MagicMock()
    sensor.entity_id = "sensor.fs_root"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)
    sensor._handle_coordinator_update()

    assert sensor.available is True
    assert sensor.native_value == 12
    attrs = sensor.extra_state_attributes
    assert attrs is not None
    assert attrs.get("mountpoint") == "/"
    assert attrs.get("type") == "ext4"
    assert "device" not in attrs


def test_filesystem_sensor_unavailable_when_used_percent_missing(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Filesystem sensor should become unavailable when the matched row lacks usage."""
    state = {
        "telemetry": {
            "filesystems": [
                {"mountpoint": "/", "type": "ext4"},
            ],
            "temps": {},
        },
        "interfaces": {},
    }
    entry = make_config_entry()
    coord = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coord.data = state
    desc = MagicMock()
    desc.key = f"telemetry.filesystems.{slugify_filesystem_mountpoint('/')}"
    desc.name = "Filesystem Test"

    sensor = OPNsenseFilesystemSensor(
        config_entry=entry,
        coordinator=coord,
        entity_description=desc,
    )
    sensor.hass = MagicMock()
    sensor.entity_id = "sensor.fs_root"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)
    sensor._handle_coordinator_update()

    assert sensor.available is False


@pytest.mark.asyncio
async def test_async_setup_entry_creates_vnstat_sensors(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """VnStat sensors should be created with expected state classes and values."""
    state = {
        "telemetry": {"filesystems": [], "temps": {}},
        "interfaces": {
            "wan": {
                "name": "WAN",
                "device": "igc0",
                "interface": "wan",
            }
        },
        "vnstat": {
            "interfaces": {
                "igc0": {
                    "metrics": {
                        "vnstat_today": {"total_bytes": 1000, "rx_bytes": 700, "tx_bytes": 300},
                        "vnstat_this_month": {
                            "total_bytes": 2000,
                            "rx_bytes": 1200,
                            "tx_bytes": 800,
                        },
                        "vnstat_yesterday": {
                            "total_bytes": 900,
                            "rx_bytes": 600,
                            "tx_bytes": 300,
                        },
                        "vnstat_last_month": {
                            "total_bytes": 1500,
                            "rx_bytes": 800,
                            "tx_bytes": 700,
                        },
                        "vnstat_last_hour": {
                            "total_bytes": 50,
                            "rx_bytes": 30,
                            "tx_bytes": 20,
                        },
                    }
                }
            }
        },
    }
    entry, _coord = _setup_entry_with_all_syncs(state, make_config_entry)

    created: list = []

    def add_entities(ents: Iterable[Any], _update_before_add: bool = False) -> None:
        """Add entities.

        Args:
            ents: Ents provided by pytest or the test case.
        """
        created.extend(ents)

    await async_setup_entry(MagicMock(), entry, cast("AddEntitiesCallback", add_entities))
    key_to_entity = {
        e.entity_description.key: e for e in created if isinstance(e, OPNsenseVnstatSensor)
    }

    assert key_to_entity["vnstat.igc0.vnstat_today"].entity_description.state_class is (
        SensorStateClass.TOTAL_INCREASING
    )
    assert key_to_entity["vnstat.igc0.vnstat_this_month"].entity_description.state_class is (
        SensorStateClass.TOTAL_INCREASING
    )
    assert key_to_entity["vnstat.igc0.vnstat_yesterday"].entity_description.state_class is (
        SensorStateClass.MEASUREMENT
    )
    assert key_to_entity["vnstat.igc0.vnstat_last_month"].entity_description.state_class is (
        SensorStateClass.MEASUREMENT
    )
    assert key_to_entity["vnstat.igc0.vnstat_last_hour"].entity_description.state_class is (
        SensorStateClass.MEASUREMENT
    )
    assert key_to_entity["vnstat.igc0.vnstat_today"].entity_description.name == "vnStat: WAN: Today"
    assert (
        key_to_entity["vnstat.igc0.vnstat_last_month"].entity_description.name
        == "vnStat: WAN: Last Month"
    )

    for key in (
        "vnstat.igc0.vnstat_today",
        "vnstat.igc0.vnstat_this_month",
        "vnstat.igc0.vnstat_yesterday",
        "vnstat.igc0.vnstat_last_month",
        "vnstat.igc0.vnstat_last_hour",
    ):
        entity = key_to_entity[key]
        entity.hass = MagicMock()
        entity.entity_id = f"sensor.{entity.entity_description.key.replace('.', '_')}"
        object.__setattr__(entity, "async_write_ha_state", lambda: None)
        entity._handle_coordinator_update()
        assert entity.available is True

    today_entity = key_to_entity["vnstat.igc0.vnstat_today"]
    assert today_entity.native_value == 1000
    attrs = today_entity.extra_state_attributes
    assert attrs is not None
    assert attrs.get("rx_bytes") == 700
    assert attrs.get("tx_bytes") == 300
    assert key_to_entity["vnstat.igc0.vnstat_this_month"].native_value == 2000
    assert key_to_entity["vnstat.igc0.vnstat_yesterday"].native_value == 900
    assert key_to_entity["vnstat.igc0.vnstat_last_month"].native_value == 1500
    assert key_to_entity["vnstat.igc0.vnstat_last_hour"].native_value == 50


@pytest.mark.asyncio
async def test_async_setup_entry_skips_vnstat_sensors_when_no_interfaces(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """No vnStat entities should be created when vnStat interface payload is empty."""
    state = {
        "telemetry": {"filesystems": [], "temps": {}},
        "interfaces": {"wan": {"name": "WAN", "device": "igc0", "interface": "wan"}},
        "vnstat": {"interfaces": {}},
    }
    entry, _coord = _setup_entry_with_all_syncs(state, make_config_entry)

    created: list = []

    def add_entities(ents: Iterable[Any], _update_before_add: bool = False) -> None:
        """Add entities.

        Args:
            ents: Ents provided by pytest or the test case.
        """
        created.extend(ents)

    await async_setup_entry(MagicMock(), entry, cast("AddEntitiesCallback", add_entities))
    assert not any(isinstance(e, OPNsenseVnstatSensor) for e in created)


@pytest.mark.asyncio
async def test_async_setup_entry_creates_speedtest_sensors(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Speedtest sensors should be created when speedtest data is available."""
    state = {
        "speedtest": {
            "available": True,
            "last": {
                "download": {
                    "value": 836.05,
                    "date": "2026-03-14T03:09:45",
                    "server_id": "72800",
                    "server": "RippleFiber, Newark, NJ",
                    "url": "https://www.speedtest.net/result/c/abc",
                },
                "upload": {
                    "value": 832.97,
                    "date": "2026-03-14T03:09:45",
                    "server_id": "72800",
                    "server": "RippleFiber, Newark, NJ",
                    "url": "https://www.speedtest.net/result/c/abc",
                },
                "latency": {
                    "value": 4.0,
                    "date": "2026-03-14T03:09:45",
                    "server_id": "72800",
                    "server": "RippleFiber, Newark, NJ",
                    "url": "https://www.speedtest.net/result/c/abc",
                },
            },
            "average": {
                "download": {
                    "value": 723.83,
                    "min": 4.18,
                    "max": 942.02,
                    "oldest": "2023-01-22 00:29:00",
                    "youngest": "2026-03-14 03:09:45",
                    "samples": 10717,
                },
                "upload": {
                    "value": 706.7,
                    "min": 1.54,
                    "max": 890.32,
                    "oldest": "2023-01-22 00:29:00",
                    "youngest": "2026-03-14 03:09:45",
                    "samples": 10717,
                },
                "latency": {
                    "value": 13.42,
                    "min": 2.35,
                    "max": 1266.74,
                    "oldest": "2023-01-22 00:29:00",
                    "youngest": "2026-03-14 03:09:45",
                    "samples": 10717,
                },
            },
        }
    }

    entry = make_config_entry(
        {
            "device_unique_id": "id",
            CONF_SYNC_TELEMETRY: False,
            CONF_SYNC_VNSTAT: False,
            CONF_SYNC_CERTIFICATES: False,
            CONF_SYNC_VPN: False,
            CONF_SYNC_GATEWAYS: False,
            CONF_SYNC_INTERFACES: False,
            CONF_SYNC_CARP: False,
            CONF_SYNC_DHCP_LEASES: False,
            CONF_SYNC_SPEEDTEST: True,
        }
    )
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = state
    setattr(entry.runtime_data, COORDINATOR, coordinator)

    created: list = []

    def add_entities(entities: Iterable[Any], _update_before_add: bool = False) -> None:
        """Add entities.

        Args:
            entities: Entities provided by pytest or the test case.
        """
        created.extend(entities)

    await async_setup_entry(MagicMock(), entry, cast("AddEntitiesCallback", add_entities))
    speedtest_entities = [e for e in created if isinstance(e, OPNsenseSpeedtestSensor)]
    assert len(speedtest_entities) == 6
    assert all(not e.entity_description.entity_registry_enabled_default for e in speedtest_entities)

    entities_by_key = {e.entity_description.key: e for e in speedtest_entities}
    for entity in speedtest_entities:
        entity.hass = MagicMock()
        entity.entity_id = f"sensor.{entity.entity_description.key.replace('.', '_')}"
        object.__setattr__(entity, "async_write_ha_state", lambda: None)
        entity._handle_coordinator_update()
        assert entity.available is True

    assert entities_by_key["speedtest.last.download"].native_value == 836.05
    download_attrs = entities_by_key["speedtest.last.download"].extra_state_attributes
    assert download_attrs is not None
    assert download_attrs["server_id"] == "72800"
    assert entities_by_key["speedtest.average.latency"].native_value == 13.42
    latency_attrs = entities_by_key["speedtest.average.latency"].extra_state_attributes
    assert latency_attrs is not None
    assert latency_attrs["samples"] == 10717


@pytest.mark.asyncio
async def test_generated_sensor_entity_contract(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Representative generated sensors should keep their entity-description contract."""

    def assert_entity_description_fields(
        key: str,
        expected: dict[str, Any],
    ) -> None:
        """Assert a representative generated entity description contract."""
        description = entities_by_key[key].entity_description
        for field_name, expected_value in expected.items():
            assert getattr(description, field_name) == expected_value

    state = {
        "telemetry": {
            "filesystems": [{"mountpoint": "/", "used_pct": 5}],
            "temps": {"cpu": {"name": "CPU", "temperature": 55}},
        },
        "interfaces": {
            "wan": {"name": "WAN", "device": "igc0", "interface": "wan", "status": "up"},
        },
        "vnstat": {
            "interfaces": {
                "igc0": {
                    "metrics": {
                        "vnstat_today": {"total_bytes": 1000, "rx_bytes": 700, "tx_bytes": 300},
                        "vnstat_this_month": {
                            "total_bytes": 2000,
                            "rx_bytes": 1200,
                            "tx_bytes": 800,
                        },
                        "vnstat_yesterday": {"total_bytes": 900, "rx_bytes": 600, "tx_bytes": 300},
                        "vnstat_last_month": {
                            "total_bytes": 1500,
                            "rx_bytes": 800,
                            "tx_bytes": 700,
                        },
                        "vnstat_last_hour": {"total_bytes": 50, "rx_bytes": 30, "tx_bytes": 20},
                    }
                }
            }
        },
        "speedtest": {
            "available": True,
            "last": {
                "download": {"value": 836.05},
                "upload": {"value": 832.97},
                "latency": {"value": 4.0},
            },
            "average": {
                "download": {"value": 723.83},
                "upload": {"value": 706.7},
                "latency": {"value": 13.42},
            },
        },
        "smart": [{"device": "nvme0"}],
        "smart_info": {"nvme0": {"temperature": {"current": 37}}},
        "gateways": {"gw1": {"name": "WAN Gateway", "status": "online", "address": "203.0.113.1"}},
        "openvpn": {"servers": {"s1": {"name": "ovpn1", "status": "up", "connected_clients": 2}}},
        "wireguard": {
            "clients": {"c1": {"name": "wg-client-1", "connected_servers": 1}},
            "servers": {"wg1": {"name": "wg-server-1", "status": "up", "connected_clients": 1}},
        },
        "dhcp_leases": {"leases": {"lan": []}, "lease_interfaces": {"lan": "LAN"}},
        "certificates": {"cert1": 1},
        "carp": {"interfaces": []},
    }
    entry, _coord = _setup_entry_with_all_syncs(state, make_config_entry)
    created: list[Any] = []

    def add_entities(entities: Iterable[Any], _update_before_add: bool = False) -> None:
        """Collect entities created during setup."""
        created.extend(entities)

    await async_setup_entry(MagicMock(), entry, cast("AddEntitiesCallback", add_entities))
    entities_by_key: dict[str, Any] = {}
    for entity in created:
        key = entity.entity_description.key
        if key in entities_by_key:
            pytest.fail(f"duplicate entity key generated during setup: {key}")
        entities_by_key[key] = entity
    expected_contracts: dict[str, dict[str, Any]] = {
        "telemetry.filesystems.root": {
            "name": "Filesystem Used Percentage root",
            "native_unit_of_measurement": sensor_module.PERCENTAGE,
            "device_class": None,
            "state_class": SensorStateClass.MEASUREMENT,
            "entity_registry_enabled_default": True,
        },
        "vnstat.igc0.vnstat_today": {
            "name": "vnStat: WAN: Today",
            "device_class": SensorDeviceClass.DATA_SIZE,
            "state_class": SensorStateClass.TOTAL_INCREASING,
            "suggested_unit_of_measurement": sensor_module.UnitOfInformation.GIBIBYTES,
            "suggested_display_precision": 1,
            "entity_registry_enabled_default": False,
        },
        "speedtest.last.download": {
            "name": "Speedtest Last Download",
            "native_unit_of_measurement": sensor_module.UnitOfDataRate.MEGABITS_PER_SECOND,
            "device_class": SensorDeviceClass.DATA_RATE,
            "state_class": SensorStateClass.MEASUREMENT,
            "entity_registry_enabled_default": False,
        },
        "smart.nvme0.temperature": {
            "name": "SMART nvme0 Temperature",
            "native_unit_of_measurement": sensor_module.UnitOfTemperature.CELSIUS,
            "device_class": SensorDeviceClass.TEMPERATURE,
            "state_class": SensorStateClass.MEASUREMENT,
            "suggested_unit_of_measurement": sensor_module.UnitOfTemperature.CELSIUS,
            "suggested_display_precision": 1,
            "entity_registry_enabled_default": False,
        },
        "interface.wan.inbytes": {
            "name": "Interface WAN inbytes",
            "native_unit_of_measurement": sensor_module.UnitOfInformation.BYTES,
            "device_class": SensorDeviceClass.DATA_SIZE,
            "state_class": SensorStateClass.TOTAL_INCREASING,
            "suggested_unit_of_measurement": sensor_module.UnitOfInformation.GIGABYTES,
            "suggested_display_precision": 1,
            "entity_registry_enabled_default": False,
        },
        "gateway.gw1.address": {
            "name": "Gateway WAN Gateway address",
            "native_unit_of_measurement": None,
            "device_class": None,
            "state_class": None,
            "entity_registry_enabled_default": False,
        },
        "openvpn.servers.s1.status": {
            "name": "OpenVPN Server ovpn1 status",
            "native_unit_of_measurement": None,
            "device_class": None,
            "state_class": None,
            "entity_registry_enabled_default": True,
        },
        "wireguard.clients.c1.connected_servers": {
            "name": "Wireguard Client wg-client-1 connected_servers",
            "native_unit_of_measurement": None,
            "device_class": None,
            "state_class": SensorStateClass.MEASUREMENT,
            "entity_registry_enabled_default": False,
        },
        "dhcp_leases.all": {
            "name": "DHCP Leases All",
            "native_unit_of_measurement": "leases",
            "device_class": None,
            "state_class": SensorStateClass.MEASUREMENT,
            "entity_registry_enabled_default": True,
        },
    }

    for key, expected in expected_contracts.items():
        assert_entity_description_fields(key, expected)

    interface_keys = {key for key in entities_by_key if key.startswith("interface.wan.")}
    assert interface_keys == {
        "interface.wan.status",
        "interface.wan.inerrs",
        "interface.wan.outerrs",
        "interface.wan.collisions",
        "interface.wan.inbytes",
        "interface.wan.inbytes_kilobytes_per_second",
        "interface.wan.outbytes",
        "interface.wan.outbytes_kilobytes_per_second",
        "interface.wan.inpkts",
        "interface.wan.inpkts_packets_per_second",
        "interface.wan.outpkts",
        "interface.wan.outpkts_packets_per_second",
    }

    gateway_keys = {key for key in entities_by_key if key.startswith("gateway.gw1.")}
    assert gateway_keys == {
        "gateway.gw1.status",
        "gateway.gw1.delay",
        "gateway.gw1.stddev",
        "gateway.gw1.loss",
        "gateway.gw1.address",
    }

    openvpn_server_keys = {key for key in entities_by_key if key.startswith("openvpn.servers.s1.")}
    assert openvpn_server_keys == {
        "openvpn.servers.s1.total_bytes_recv",
        "openvpn.servers.s1.total_bytes_sent",
        "openvpn.servers.s1.total_bytes_recv_kilobytes_per_second",
        "openvpn.servers.s1.total_bytes_sent_kilobytes_per_second",
        "openvpn.servers.s1.status",
        "openvpn.servers.s1.connected_clients",
    }

    wireguard_server_keys = {
        key for key in entities_by_key if key.startswith("wireguard.servers.wg1.")
    }
    assert wireguard_server_keys == {
        "wireguard.servers.wg1.total_bytes_recv",
        "wireguard.servers.wg1.total_bytes_sent",
        "wireguard.servers.wg1.total_bytes_recv_kilobytes_per_second",
        "wireguard.servers.wg1.total_bytes_sent_kilobytes_per_second",
        "wireguard.servers.wg1.status",
        "wireguard.servers.wg1.connected_clients",
    }

    wireguard_client_keys = {
        key for key in entities_by_key if key.startswith("wireguard.clients.c1.")
    }
    assert wireguard_client_keys == {
        "wireguard.clients.c1.total_bytes_recv",
        "wireguard.clients.c1.total_bytes_sent",
        "wireguard.clients.c1.total_bytes_recv_kilobytes_per_second",
        "wireguard.clients.c1.total_bytes_sent_kilobytes_per_second",
        "wireguard.clients.c1.connected_servers",
    }


def _prepare_smart_sensor(entity: OPNsenseSmartSensor, entity_id: str | None = None) -> None:
    """Prepare a SMART sensor for direct coordinator update handling.

    Args:
        entity: SMART sensor under test.
        entity_id: Optional entity ID override.
    """
    entity.hass = MagicMock()
    entity.entity_id = entity_id or f"sensor.{entity.entity_description.key.replace('.', '_')}"
    object.__setattr__(entity, "async_write_ha_state", lambda: None)


def _build_smart_sensor(
    make_config_entry: Callable[..., MockConfigEntry],
    state: Any,
    key: str,
    name: str = "SMART nvme0",
) -> OPNsenseSmartSensor:
    """Build a SMART sensor with coordinator data for direct update tests.

    Args:
        make_config_entry: Test fixture factory for config entries.
        state: Coordinator data payload.
        key: SMART entity description key.
        name: SMART entity description name.

    Returns:
        OPNsenseSmartSensor: Sensor prepared with coordinator data.
    """
    entry = make_config_entry()
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = state
    desc = MagicMock()
    desc.key = key
    desc.name = name
    return OPNsenseSmartSensor(
        config_entry=entry,
        coordinator=coordinator,
        entity_description=desc,
    )


async def _async_setup_smart_entities(
    make_config_entry: Callable[..., MockConfigEntry],
    config: dict[str, Any],
    state: dict[str, Any],
) -> list[OPNsenseSmartSensor]:
    """Set up a config entry and return created SMART sensors.

    Args:
        make_config_entry: Test fixture factory for config entries.
        config: Config entry data.
        state: Coordinator data payload.

    Returns:
        list[OPNsenseSmartSensor]: Created SMART sensors.
    """
    entry = make_config_entry({"device_unique_id": "id", **config})
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = state
    setattr(entry.runtime_data, COORDINATOR, coordinator)
    created: list[Any] = []

    def add_entities(entities: Iterable[Any], _update_before_add: bool = False) -> None:
        """Add entities.

        Args:
            entities: Entities provided by pytest or the test case.
        """
        created.extend(entities)

    await async_setup_entry(MagicMock(), entry, cast("AddEntitiesCallback", add_entities))
    return [entity for entity in created if isinstance(entity, OPNsenseSmartSensor)]


@pytest.mark.asyncio
async def test_async_setup_entry_creates_disabled_smart_disk_sensors(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART temperature sensors should be created per device and disabled by default."""
    state = {
        "smart": [
            {
                "device": "nvme0",
                "model": "Samsung SSD",
                "serial_number": "S123",
            },
            {
                "device": "ada0",
            },
            {"device": "da0"},
            "ignored",
            {"device": ""},
        ],
        "smart_info": {
            "nvme0": {"temperature": {"current": 37}},
            "ada0": {"temperature": {"current": 41}},
            "da0": {"temperature": {"current": 42.5}},
        },
    }
    smart_entities = await _async_setup_smart_entities(
        make_config_entry,
        {
            CONF_SYNC_TELEMETRY: False,
            CONF_SYNC_VNSTAT: False,
            CONF_SYNC_CERTIFICATES: False,
            CONF_SYNC_VPN: False,
            CONF_SYNC_GATEWAYS: False,
            CONF_SYNC_INTERFACES: False,
            CONF_SYNC_CARP: False,
            CONF_SYNC_DHCP_LEASES: False,
            CONF_SYNC_SPEEDTEST: False,
            CONF_SYNC_SMART: True,
        },
        state,
    )

    assert {entity.entity_description.key for entity in smart_entities} == {
        "smart.nvme0.temperature",
        "smart.ada0.temperature",
        "smart.da0.temperature",
    }
    assert all(
        entity.entity_description.entity_registry_enabled_default is False
        for entity in smart_entities
    )

    key_to_entity = {entity.entity_description.key: entity for entity in smart_entities}
    nvme_temperature_entity = key_to_entity["smart.nvme0.temperature"]
    temperature_entity = key_to_entity["smart.ada0.temperature"]
    fallback_name_entity = key_to_entity["smart.da0.temperature"]
    for entity in (nvme_temperature_entity, temperature_entity):
        _prepare_smart_sensor(entity)
        entity._handle_coordinator_update()

    assert nvme_temperature_entity.available is True
    assert nvme_temperature_entity.native_value == 37
    assert nvme_temperature_entity.extra_state_attributes == {
        "device": "nvme0",
        "model": "Samsung SSD",
        "serial_number": "S123",
    }
    assert temperature_entity.available is True
    assert temperature_entity.native_value == 41
    _prepare_smart_sensor(fallback_name_entity, "sensor.smart_da0_temperature")
    fallback_name_entity._handle_coordinator_update()
    assert fallback_name_entity.available is True
    assert fallback_name_entity.native_value == 42.5
    assert fallback_name_entity.extra_state_attributes == {"device": "da0"}


@pytest.mark.asyncio
async def test_async_setup_entry_creates_smart_disk_sensors_by_default(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART disk sensors should use the shared granular sync default."""
    smart_entities = await _async_setup_smart_entities(
        make_config_entry,
        {
            CONF_SYNC_TELEMETRY: False,
            CONF_SYNC_VNSTAT: False,
            CONF_SYNC_CERTIFICATES: False,
            CONF_SYNC_VPN: False,
            CONF_SYNC_GATEWAYS: False,
            CONF_SYNC_INTERFACES: False,
            CONF_SYNC_CARP: False,
            CONF_SYNC_DHCP_LEASES: False,
            CONF_SYNC_SPEEDTEST: False,
        },
        {
            "smart": [
                {
                    "device": "nvme0",
                }
            ],
            "smart_info": {"nvme0": {"temperature": {"current": 37}}},
        },
    )

    assert {entity.entity_description.key for entity in smart_entities} == {
        "smart.nvme0.temperature",
    }


@pytest.mark.asyncio
async def test_async_setup_entry_creates_smart_disk_sensors_from_ident_only_rows(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART temperature sensors should be compiled when rows provide `ident` only."""
    smart_entities = await _async_setup_smart_entities(
        make_config_entry,
        {
            CONF_SYNC_TELEMETRY: False,
            CONF_SYNC_VNSTAT: False,
            CONF_SYNC_CERTIFICATES: False,
            CONF_SYNC_VPN: False,
            CONF_SYNC_GATEWAYS: False,
            CONF_SYNC_INTERFACES: False,
            CONF_SYNC_CARP: False,
            CONF_SYNC_DHCP_LEASES: False,
            CONF_SYNC_SPEEDTEST: False,
            CONF_SYNC_SMART: True,
        },
        {
            "smart": [{"ident": "SERIAL-ONLY"}],
            "smart_info": {"SERIAL-ONLY": {"temperature": {"current": 58}}},
        },
    )

    assert {entity.entity_description.key for entity in smart_entities} == {
        "smart.serial_only.temperature",
    }
    entity = smart_entities[0]
    _prepare_smart_sensor(entity)
    entity._handle_coordinator_update()

    assert entity.available is True
    assert entity.native_value == 58
    assert entity.extra_state_attributes == {"ident": "SERIAL-ONLY"}


@pytest.mark.asyncio
async def test_async_setup_entry_creates_smart_temperature_sensors_from_smart_info(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART temperature sensors should use get_smart_info attribute data."""
    smart_entities = await _async_setup_smart_entities(
        make_config_entry,
        {
            CONF_SYNC_TELEMETRY: False,
            CONF_SYNC_VNSTAT: False,
            CONF_SYNC_CERTIFICATES: False,
            CONF_SYNC_VPN: False,
            CONF_SYNC_GATEWAYS: False,
            CONF_SYNC_INTERFACES: False,
            CONF_SYNC_CARP: False,
            CONF_SYNC_DHCP_LEASES: False,
            CONF_SYNC_SPEEDTEST: False,
            CONF_SYNC_SMART: True,
        },
        {
            "smart": [
                {"device": "nvme0", "ident": "22384S808411"},
                {"device": "ada0", "ident": "SERIAL2"},
            ],
            "smart_info": {
                "nvme0": {"temperature": {"current": 71}},
                "ada0": {"temperature": {"current": 42}},
            },
        },
    )

    assert {entity.entity_description.key for entity in smart_entities} == {
        "smart.nvme0.temperature",
        "smart.ada0.temperature",
    }

    temperature_entity = {entity.entity_description.key: entity for entity in smart_entities}[
        "smart.nvme0.temperature"
    ]
    _prepare_smart_sensor(temperature_entity, "sensor.smart_nvme0_temperature")
    temperature_entity._handle_coordinator_update()

    assert temperature_entity.available is True
    assert temperature_entity.native_value == 71
    assert temperature_entity.extra_state_attributes == {
        "device": "nvme0",
        "ident": "22384S808411",
    }


@pytest.mark.asyncio
async def test_async_setup_entry_keeps_smart_entities_when_smart_info_present_but_empty(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART entities should be created when `smart_info` exists and update to available."""
    smart_entities = await _async_setup_smart_entities(
        make_config_entry,
        {CONF_SYNC_SMART: True},
        {
            "smart": [
                {"device": "nvme0"},
                {"device": "ada0"},
            ],
            "smart_info": {},
        },
    )

    assert {entity.entity_description.key for entity in smart_entities} == {
        "smart.nvme0.temperature",
        "smart.ada0.temperature",
    }

    for entity in smart_entities:
        _prepare_smart_sensor(entity)
        entity._handle_coordinator_update()
        assert entity.available is False

    for entity in smart_entities:
        entity.coordinator.data = {
            "smart": [
                {"device": "nvme0"},
                {"device": "ada0"},
            ],
            "smart_info": {
                "nvme0": {"temperature": {"current": 71}},
                "ada0": {"temperature": {"current": 42}},
            },
        }
        entity._handle_coordinator_update()

    assert {entity.available for entity in smart_entities} == {True}
    assert {entity.native_value for entity in smart_entities} == {71, 42}


@pytest.mark.asyncio
async def test_async_setup_entry_keeps_smart_entities_when_initial_smart_info_missing(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART temperature entities should still be created before attribute data arrives."""
    smart_entities = await _async_setup_smart_entities(
        make_config_entry,
        {CONF_SYNC_SMART: True},
        {
            "smart": [
                {"device": "nvme0"},
                {"device": "ada0"},
            ],
            "smart_info": {
                "ada0": {"temperature": {"current": 42}},
            },
        },
    )

    assert {entity.entity_description.key for entity in smart_entities} == {
        "smart.nvme0.temperature",
        "smart.ada0.temperature",
    }


@pytest.mark.asyncio
async def test_async_setup_entry_skips_malformed_smart_values(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART temperature sensors should still be created for discovered devices."""
    smart_entities = await _async_setup_smart_entities(
        make_config_entry,
        {CONF_SYNC_SMART: True},
        {
            "smart": [
                {"device": "nvme0"},
                {"device": "ada0"},
                {"device": "da0"},
            ],
            "smart_info": {
                "nvme0": {"temperature": []},
                "ada0": {"temperature": {}},
                "da0": {"temperature": {"current": 42}},
            },
        },
    )

    assert {entity.entity_description.key for entity in smart_entities} == {
        "smart.nvme0.temperature",
        "smart.ada0.temperature",
        "smart.da0.temperature",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("state", [[], {}, {"smart": {}}, {"smart": None}])
async def test_compile_smart_sensors_skips_invalid_state_shapes(
    state: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART sensor compilation should ignore invalid coordinator state shapes."""
    entry = make_config_entry({"device_unique_id": "id", CONF_SYNC_SMART: True})
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)

    entities = await sensor_module._compile_smart_sensors(entry, coordinator, state)

    assert entities == []


@pytest.mark.asyncio
async def test_compile_smart_sensors_creates_entities_when_smart_info_present(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART sensor compilation should create entities when `smart_info` exists."""
    entry = make_config_entry({"device_unique_id": "id", CONF_SYNC_SMART: True})
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)

    entities = await sensor_module._compile_smart_sensors(
        entry,
        coordinator,
        {"smart": [{"device": "nvme0"}], "smart_info": {}},
    )

    assert [entity.entity_description.key for entity in entities] == ["smart.nvme0.temperature"]


@pytest.mark.asyncio
async def test_compile_smart_sensors_skips_when_smart_info_key_missing(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART sensor compilation should not run when `smart_info` state is absent."""
    entry = make_config_entry({"device_unique_id": "id", CONF_SYNC_SMART: True})
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)

    entities = await sensor_module._compile_smart_sensors(
        entry,
        coordinator,
        {"smart": [{"device": "nvme0"}]},
    )

    assert entities == []


@pytest.mark.asyncio
async def test_compile_smart_sensors_keeps_entities_when_device_info_malformed(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART sensor compilation should keep entities even before attribute data is usable."""
    entry = make_config_entry({"device_unique_id": "id", CONF_SYNC_SMART: True})
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)

    entities = await sensor_module._compile_smart_sensors(
        entry,
        coordinator,
        {
            "smart": [{"device": "nvme0"}, {"device": "ada0"}],
            "smart_info": {"nvme0": [], "ada0": {"temperature": {"current": 42}}},
        },
    )

    assert [entity.entity_description.key for entity in entities] == [
        "smart.nvme0.temperature",
        "smart.ada0.temperature",
    ]


def test_smart_sensor_unavailable_when_device_or_property_missing(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART disk sensors should be unavailable when their row or field is absent."""
    sensor = _build_smart_sensor(
        make_config_entry,
        {
            "smart": [{"device": "nvme0"}],
            "smart_info": {"nvme0": {"temperature": {"current": 37}}},
        },
        "smart.ada0.temperature",
        "SMART ada0 Temperature",
    )
    _prepare_smart_sensor(sensor, "sensor.smart_ada0_temperature")
    sensor._handle_coordinator_update()
    assert sensor.available is False

    sensor = _build_smart_sensor(
        make_config_entry,
        {
            "smart": [{"device": "nvme0"}],
            "smart_info": {"nvme0": []},
        },
        "smart.nvme0.temperature",
    )
    _prepare_smart_sensor(sensor, "sensor.smart_nvme0_temperature")
    sensor._handle_coordinator_update()
    assert sensor.available is False

    sensor = _build_smart_sensor(
        make_config_entry,
        {
            "smart": [{"device": "nvme0"}],
            "smart_info": {"nvme0": {}},
        },
        "smart.nvme0.temperature",
    )
    _prepare_smart_sensor(sensor, "sensor.smart_nvme0_temperature")
    sensor._handle_coordinator_update()
    assert sensor.available is False


def test_smart_sensor_strips_device_name_before_smart_info_lookup(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART disk sensors should normalize padded device names before lookup."""
    sensor = _build_smart_sensor(
        make_config_entry,
        {
            "smart": [{"device": " nvme0 "}],
            "smart_info": {"nvme0": {"temperature": {"current": 37}}},
        },
        "smart.nvme0.temperature",
    )
    _prepare_smart_sensor(sensor, "sensor.smart_nvme0_temperature")
    sensor._handle_coordinator_update()

    assert sensor.available is True
    assert sensor.native_value == 37


def test_smart_sensor_uses_ident_when_device_missing(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART sensors should identify rows using `ident` when `device` is absent."""
    sensor = _build_smart_sensor(
        make_config_entry,
        {
            "smart": [{"ident": "SERIAL-ONLY"}],
            "smart_info": {"SERIAL-ONLY": {"temperature": {"current": 58}}},
        },
        "smart.serial_only.temperature",
    )
    _prepare_smart_sensor(sensor, "sensor.smart_serial_only_temperature")
    sensor._handle_coordinator_update()

    assert sensor.available is True
    assert sensor.native_value == 58
    assert sensor.extra_state_attributes == {"ident": "SERIAL-ONLY"}


@pytest.mark.parametrize(
    ("state", "key"),
    [
        ([], "smart.nvme0.temperature"),
        ({"smart": {}}, "smart.nvme0.temperature"),
        ({"smart": []}, "smart.nvme0.temperature"),
        ({"smart": []}, "smart.nvme0.temperature.extra"),
        (
            {"smart": [{"device": "nvme0"}], "smart_info": {"nvme0": {"unknown": "value"}}},
            "smart.nvme0.unknown",
        ),
    ],
)
def test_smart_sensor_unavailable_when_state_or_key_invalid(
    state: dict[str, Any] | list[Any],
    key: str,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART disk sensors should be unavailable for invalid state and entity keys."""
    sensor = _build_smart_sensor(make_config_entry, state, key)
    _prepare_smart_sensor(sensor, "sensor.smart_nvme0")
    sensor._handle_coordinator_update()

    assert sensor.available is False


def test_smart_sensor_finds_device_after_ignored_rows(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART disk sensors should skip invalid rows while searching for a device."""
    sensor = _build_smart_sensor(
        make_config_entry,
        {
            "smart": [
                "ignored",
                {"device": ""},
                {"device": "nvme0"},
            ],
            "smart_info": {"nvme0": {"temperature": {"current": 37}}},
        },
        "smart.nvme0.temperature",
    )
    _prepare_smart_sensor(sensor, "sensor.smart_nvme0")
    sensor._handle_coordinator_update()

    assert sensor.available is True
    assert sensor.native_value == 37


@pytest.mark.parametrize(
    "value",
    [
        [],
        {},
        False,
        {"current": False},
        {"current": "unknown"},
    ],
)
def test_smart_sensor_unavailable_when_property_malformed(
    value: object,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """SMART disk sensors should be unavailable for malformed values."""
    sensor = _build_smart_sensor(
        make_config_entry,
        {
            "smart": [{"device": "nvme0"}],
            "smart_info": {"nvme0": {"temperature": value}},
        },
        "smart.nvme0.temperature",
    )
    _prepare_smart_sensor(sensor, "sensor.smart_nvme0")
    sensor._handle_coordinator_update()

    assert sensor.available is False


@pytest.mark.parametrize(
    ("state", "key"),
    [
        ([], "speedtest.last.download"),
        ({"speedtest": {"last": {"download": {"value": 100}}}}, "speedtest.last"),
        ({"speedtest": {"last": {"download": 100}}}, "speedtest.last.download"),
        ({"speedtest": {"last": {"download": {"value": "bad"}}}}, "speedtest.last.download"),
    ],
)
def test_speedtest_sensor_unavailable_variants(
    state: dict[str, Any] | list[Any], key: str, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Speedtest sensors should be unavailable for malformed key/state/value variants."""
    entry = make_config_entry()
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = state

    description = MagicMock()
    description.key = key
    description.name = "Speedtest Sensor"

    sensor = OPNsenseSpeedtestSensor(
        config_entry=entry,
        coordinator=coordinator,
        entity_description=description,
    )
    sensor.hass = MagicMock()
    sensor.entity_id = f"sensor.{key.replace('.', '_')}"
    object.__setattr__(sensor, "async_write_ha_state", lambda: None)

    sensor._handle_coordinator_update()
    assert sensor.available is False


def test_speedtest_sensor_attribute_filtering(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Speedtest sensors should only include non-None attributes."""
    state = {
        "speedtest": {
            "last": {
                "download": {
                    "value": 850.5,
                    "date": None,
                    "server_id": "10001",
                    "server": None,
                    "url": "https://example.test/result/1",
                }
            },
            "average": {
                "download": {
                    "value": 750.2,
                    "min": None,
                    "max": 901.3,
                    "oldest": None,
                    "youngest": "2026-03-14 03:09:45",
                    "samples": 0,
                }
            },
        }
    }

    entry = make_config_entry()
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = state

    last_description = MagicMock()
    last_description.key = "speedtest.last.download"
    last_description.name = "Speedtest Last Download"
    last_sensor = OPNsenseSpeedtestSensor(
        config_entry=entry,
        coordinator=coordinator,
        entity_description=last_description,
    )
    last_sensor.hass = MagicMock()
    last_sensor.entity_id = "sensor.speedtest_last_download"
    object.__setattr__(last_sensor, "async_write_ha_state", lambda: None)
    last_sensor._handle_coordinator_update()
    assert last_sensor.available is True
    assert last_sensor.extra_state_attributes == {
        "server_id": "10001",
        "url": "https://example.test/result/1",
    }

    average_description = MagicMock()
    average_description.key = "speedtest.average.download"
    average_description.name = "Speedtest Average Download"
    average_sensor = OPNsenseSpeedtestSensor(
        config_entry=entry,
        coordinator=coordinator,
        entity_description=average_description,
    )
    average_sensor.hass = MagicMock()
    average_sensor.entity_id = "sensor.speedtest_average_download"
    object.__setattr__(average_sensor, "async_write_ha_state", lambda: None)
    average_sensor._handle_coordinator_update()
    assert average_sensor.available is True
    assert average_sensor.extra_state_attributes == {
        "max": 901.3,
        "youngest": "2026-03-14 03:09:45",
        "samples": 0,
    }


@pytest.mark.asyncio
async def test_async_setup_entry_skips_speedtest_sensors_when_unavailable(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Speedtest sensors should not be created when speedtest is unavailable."""
    state = {"speedtest": {"available": False}}
    entry = make_config_entry(
        {
            "device_unique_id": "id",
            CONF_SYNC_TELEMETRY: False,
            CONF_SYNC_VNSTAT: False,
            CONF_SYNC_CERTIFICATES: False,
            CONF_SYNC_VPN: False,
            CONF_SYNC_GATEWAYS: False,
            CONF_SYNC_INTERFACES: False,
            CONF_SYNC_CARP: False,
            CONF_SYNC_DHCP_LEASES: False,
            CONF_SYNC_SPEEDTEST: True,
        }
    )
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = state
    setattr(entry.runtime_data, COORDINATOR, coordinator)

    created: list = []

    def add_entities(entities: Iterable[Any], _update_before_add: bool = False) -> None:
        """Add entities.

        Args:
            entities: Entities provided by pytest or the test case.
        """
        created.extend(entities)

    await async_setup_entry(MagicMock(), entry, cast("AddEntitiesCallback", add_entities))
    assert not any(isinstance(e, OPNsenseSpeedtestSensor) for e in created)


@pytest.mark.asyncio
async def test_compile_interface_sensors_values_end(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
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
    entry = make_config_entry()
    coordinator = MagicMock(spec=OPNsenseDataUpdateCoordinator)
    coordinator.data = state

    entities = await sensor_module._compile_interface_sensors(entry, coordinator, state)
    assert any(e.entity_description.key.startswith("interface.eth0.") for e in entities)

    kb_entity = next(
        e for e in entities if e.entity_description.key.endswith("inbytes_kilobytes_per_second")
    )
    kb = OPNsenseInterfaceSensor(
        config_entry=entry, coordinator=coordinator, entity_description=kb_entity.entity_description
    )
    kb.hass = MagicMock()
    kb.entity_id = "sensor.eth0_inkb"
    object.__setattr__(kb, "async_write_ha_state", lambda: None)
    kb._handle_coordinator_update()
    assert kb.available is True
    assert kb.native_value == 123
