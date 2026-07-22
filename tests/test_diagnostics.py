"""Tests for OPNsense diagnostics."""

import copy
from datetime import UTC, date, datetime, time
from enum import Enum, IntEnum
import json
import math
from types import SimpleNamespace
from typing import Any, Self

from homeassistant.components.diagnostics import REDACTED
from homeassistant.core import HomeAssistant

from custom_components.opnsense.const import CONF_DEVICE_UNIQUE_ID, CONF_ENTRY_TYPE, ENTRY_TYPE_CARP
from custom_components.opnsense.diagnostics import async_get_config_entry_diagnostics


class _DiagnosticMode(Enum):
    """Representative enum included in a diagnostics payload."""

    ACTIVE = "active"


class _NumericDiagnosticId(IntEnum):
    """Representative numeric enum used as an identifier."""

    PRIMARY = 7


class _OpaqueDiagnosticValue:
    """Representative unsupported object included in a diagnostics payload."""

    def __deepcopy__(self, memo: dict[int, Any]) -> Self:
        """Preserve identity when snapshotting the immutable test value."""
        return self

    def __repr__(self) -> str:
        """Fail if diagnostics attempts to render the private object."""
        raise AssertionError("opaque diagnostics values must not be rendered")


def _coordinator(
    data: dict[str, Any], *, success: bool = True, exception: Exception | None = None
) -> SimpleNamespace:
    """Create a coordinator-shaped object for diagnostics tests."""
    return SimpleNamespace(
        data=data,
        last_update_success=success,
        last_exception=exception,
    )


async def test_config_entry_diagnostics_pseudonymizes_full_runtime(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should retain operational state without exposing identifiers."""
    router_mac = "aa:bb:cc:dd:ee:ff"
    router_ip = "192.0.2.10"
    router_uuid = "123e4567-e89b-42d3-a456-426614174000"
    workstation = "private-workstation"
    entry = make_config_entry(
        data={
            "url": f"https://{router_ip}",
            "username": "diagnostics-user",
            "password": "diagnostics-password",
            "name": "Office Firewall",
            CONF_DEVICE_UNIQUE_ID: router_mac,
            "firmware_version": "26.7.1",
        },
        title="Office Firewall",
        unique_id=router_mac,
        entry_id="private-entry-id",
        options={"devices": [router_mac], "scan_interval": 30},
    )
    main_data = {
        "system_info": {"name": "Office Firewall"},
        "host_firmware_version": "26.7.1",
        "telemetry": {
            "pfstate": {"used": 42},
            "status": "ok",
            "temps": {"private-cpu-device": {"temperature": 42.5}},
        },
        "interfaces": {
            "wan": {
                "interface": "wan",
                "name": "Fiber WAN",
                "mac": router_mac,
                "ipv4": router_ip,
                "status": "up",
            }
        },
        "certificates": {
            "Home Certificate": {
                "uuid": router_uuid,
                "issuer": "Home Certificate Authority",
                "valid_to": "2030-01-01",
            }
        },
        "wireguard": {
            "clients": {
                router_uuid: {
                    "uuid": router_uuid,
                    "pubkey": "private-wireguard-public-key",
                    "endpoint": "vpn.private.example:51820",
                    "tunnel_addresses": ["2001:db8::10/64"],
                }
            }
        },
        "nut_ups_status": {
            "response": "device.serial: private-ups-serial\nups.status: OL",
            "status": {
                "device.serial": "private-ups-serial",
                "ups.status": "OL",
            },
        },
        "notices": [
            {
                "subject": (
                    f"Contact admin@example.com for {router_mac} at https://{router_ip}/status"
                ),
                "status": "pending",
            }
        ],
        "connection_summary": "peer [2001:db8::10]:51820 is active",
        "detail": "Connected through the private office uplink",
        "leases": {workstation: {"hostname": workstation, "active": True}},
        "json_scalars": {
            "datetime": datetime(2026, 7, 21, 12, 30, tzinfo=UTC),
            "date": date(2026, 7, 21),
            "time": time(12, 30),
            "enum": _DiagnosticMode.ACTIVE,
            "bytes": b"private bytes",
            "opaque": _OpaqueDiagnosticValue(),
        },
    }
    tracker_data = {
        "arp_table": [{"mac": router_mac, "ip": router_ip, "hostname": "private-workstation"}]
    }
    live_data = {
        "interfaces": {
            "wan": {
                "interface": "wan",
                "mac": router_mac,
                "ipv4": router_ip,
                "status": "up",
                "inbytes_kilobytes_per_second": 12.5,
            }
        }
    }
    original_entry_data = copy.deepcopy(dict(entry.data))
    original_main_data = copy.deepcopy(main_data)
    original_tracker_data = copy.deepcopy(tracker_data)
    original_live_data = copy.deepcopy(live_data)
    entry.runtime_data = SimpleNamespace(
        coordinator=_coordinator(main_data),
        device_tracker_coordinator=_coordinator(
            tracker_data,
            success=False,
            exception=RuntimeError(f"Could not reach https://{router_ip} as diagnostics-user"),
        ),
        live_traffic_coordinator=_coordinator(live_data),
    )

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    config_data = diagnostics["config_entry"]["data"]
    coordinators = diagnostics["coordinators"]
    sanitized_main = coordinators["main"]["data"]
    sanitized_tracker = coordinators["device_tracker"]["data"]
    sanitized_live = coordinators["live_traffic"]["data"]

    assert config_data["username"] == REDACTED
    assert config_data["password"] == REDACTED
    assert config_data["url"].startswith("**REDACTED_URL_")
    assert config_data["firmware_version"] == "26.7.1"
    assert sanitized_main["host_firmware_version"] == "26.7.1"
    assert sanitized_main["telemetry"]["pfstate"] == {"used": 42}
    assert sanitized_main["telemetry"]["status"] == "ok"
    redacted_temp_key = next(iter(sanitized_main["telemetry"]["temps"]))
    assert redacted_temp_key.startswith("**REDACTED_KEY_")
    assert sanitized_main["telemetry"]["temps"][redacted_temp_key] == {"temperature": 42.5}

    redacted_mac = config_data[CONF_DEVICE_UNIQUE_ID]
    redacted_ip = sanitized_tracker["arp_table"][0]["ip"]
    redacted_interface = sanitized_main["interfaces"][next(iter(sanitized_main["interfaces"]))]
    assert redacted_mac.startswith("**REDACTED_MAC_")
    assert sanitized_tracker["arp_table"][0]["mac"] == redacted_mac
    assert (
        sanitized_live["interfaces"][next(iter(sanitized_live["interfaces"]))]["mac"]
        == redacted_mac
    )
    assert redacted_ip.startswith("**REDACTED_IP_")
    assert redacted_interface["ipv4"] == redacted_ip
    assert redacted_interface["status"] == "up"
    assert (
        sanitized_live["interfaces"][next(iter(sanitized_live["interfaces"]))][
            "inbytes_kilobytes_per_second"
        ]
        == 12.5
    )

    redacted_wan_key = next(iter(sanitized_main["interfaces"]))
    assert redacted_wan_key.startswith("**REDACTED_KEY_")
    assert redacted_interface["interface"] == redacted_wan_key
    redacted_certificate_key = next(iter(sanitized_main["certificates"]))
    assert redacted_certificate_key.startswith("**REDACTED_KEY_")
    assert sanitized_main["certificates"][redacted_certificate_key]["uuid"].startswith(
        "**REDACTED_ID_"
    )
    redacted_vpn_key = next(iter(sanitized_main["wireguard"]["clients"]))
    sanitized_vpn = sanitized_main["wireguard"]["clients"][redacted_vpn_key]
    assert sanitized_vpn["uuid"] == redacted_vpn_key
    assert sanitized_vpn["pubkey"].startswith("**REDACTED_ID_")
    assert sanitized_vpn["endpoint"].startswith("**REDACTED_VALUE_")
    assert sanitized_vpn["tunnel_addresses"][0].startswith("**REDACTED_IP_")
    assert sanitized_main["nut_ups_status"]["response"].startswith("**REDACTED_VALUE_")
    assert sanitized_main["nut_ups_status"]["status"]["device.serial"].startswith("**REDACTED_ID_")
    assert sanitized_main["nut_ups_status"]["status"]["ups.status"] == "OL"

    redacted_lease_key = next(iter(sanitized_main["leases"]))
    assert redacted_lease_key.startswith("**REDACTED_KEY_")
    assert sanitized_main["leases"][redacted_lease_key]["hostname"] == redacted_lease_key
    json_scalars = sanitized_main["json_scalars"]
    assert json_scalars["datetime"] == "2026-07-21T12:30:00+00:00"
    assert json_scalars["date"] == "2026-07-21"
    assert json_scalars["time"] == "12:30:00"
    assert json_scalars["enum"].startswith("**REDACTED_VALUE_")
    assert json_scalars["bytes"] == REDACTED
    assert json_scalars["opaque"] == REDACTED

    subject = sanitized_main["notices"][0]["subject"]
    assert subject.startswith("**REDACTED_ID_")
    assert router_mac not in subject
    assert router_ip not in subject
    assert "admin@example.com" not in subject
    assert coordinators["device_tracker"]["last_update_success"] is False
    assert coordinators["device_tracker"]["last_exception"] == "RuntimeError"
    assert "diagnostics-user" not in json.dumps(diagnostics)
    assert "diagnostics-password" not in json.dumps(diagnostics)
    assert router_mac not in json.dumps(diagnostics)
    assert router_ip not in json.dumps(diagnostics)
    assert "private-ups-serial" not in json.dumps(diagnostics)
    assert "private-wireguard-public-key" not in json.dumps(diagnostics)
    assert "vpn.private.example" not in json.dumps(diagnostics)
    assert "private office uplink" not in json.dumps(diagnostics)
    assert "connection_summary" not in json.dumps(diagnostics)
    assert "detail" not in json.dumps(diagnostics)
    assert "2001:db8::10" not in json.dumps(diagnostics)
    json.dumps(diagnostics)

    assert dict(entry.data) == original_entry_data
    assert main_data == original_main_data
    assert tracker_data == original_tracker_data
    assert live_data == original_live_data


async def test_config_entry_diagnostics_supports_optional_coordinators(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should use a stable shape when optional coordinators are absent."""
    entry = make_config_entry(
        data={CONF_ENTRY_TYPE: ENTRY_TYPE_CARP, "url": "https://carp.example.test"},
        title="Private CARP VIP",
    )
    entry.runtime_data = SimpleNamespace(
        coordinator=_coordinator(
            {
                "carp": {"interfaces": []},
                "host_firmware_version": "26.7.1",
            }
        ),
        device_tracker_coordinator=None,
        live_traffic_coordinator=None,
    )

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    assert diagnostics["coordinators"]["device_tracker"] is None
    assert diagnostics["coordinators"]["live_traffic"] is None
    assert diagnostics["coordinators"]["main"] == {
        "last_update_success": True,
        "last_exception": None,
        "data": {
            "carp": {"interfaces": []},
            "host_firmware_version": "26.7.1",
        },
    }
    assert diagnostics["config_entry"]["data"]["url"].startswith("**REDACTED_URL_")
    json.dumps(diagnostics)


async def test_config_entry_diagnostics_redacts_keys_and_sensitive_containers(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should redact secret keys and recursively pseudonymize private containers."""
    entry = make_config_entry(
        data={"url": "https://router.example.test"},
        title="Private Router",
    )
    entry.runtime_data = SimpleNamespace(
        coordinator=_coordinator(
            {
                "preshared_key": "private-preshared-key",
                "client_key": "private-client-key",
                "public_key": "correlatable-public-key",
                "lease_interfaces": {
                    "lan_custom": "Private LAN",
                    "nested_group": {
                        "labels": ["Private Guest", 7, True, None],
                    },
                },
            }
        ),
        device_tracker_coordinator=None,
        live_traffic_coordinator=None,
    )

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    data = diagnostics["coordinators"]["main"]["data"]
    assert data["preshared_key"] == REDACTED
    assert data["client_key"] == REDACTED
    assert data["public_key"].startswith("**REDACTED_ID_")
    interfaces = data["lease_interfaces"]
    interface_key = next(key for key, value in interfaces.items() if isinstance(value, str))
    assert interface_key.startswith("**REDACTED_KEY_")
    assert interfaces[interface_key].startswith("**REDACTED_VALUE_")
    nested = next(value for value in interfaces.values() if isinstance(value, dict))
    nested_key = next(iter(nested))
    assert nested_key.startswith("**REDACTED_KEY_")
    assert nested[nested_key][0].startswith("**REDACTED_VALUE_")
    assert nested[nested_key][1].startswith("**REDACTED_VALUE_")
    assert nested[nested_key][2:] == [True, None]
    serialized = json.dumps(diagnostics)
    assert "private-preshared-key" not in serialized
    assert "private-client-key" not in serialized
    assert "lan_custom" not in serialized
    assert "Private LAN" not in serialized


async def test_config_entry_diagnostics_numeric_ids_and_high_cardinality(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should alias numeric IDs without changing metrics at high cardinality."""
    leases = {
        f"private-lease-{index}": {
            "ip": f"10.0.{index // 250}.{index % 250 + 1}",
            "status": "active",
        }
        for index in range(500)
    }
    entry = make_config_entry(
        data={"url": "https://router.example.test"},
        title="Private Router",
    )
    entry.runtime_data = SimpleNamespace(
        coordinator=_coordinator(
            {
                "firmware_version": "26.7.1",
                "status": "online",
                "clients": {
                    101: {"id": 101, "packets": 101},
                    202: {"id": 202, "packets": 202},
                },
                "leases": leases,
            }
        ),
        device_tracker_coordinator=None,
        live_traffic_coordinator=None,
    )

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    data = diagnostics["coordinators"]["main"]["data"]
    assert data["firmware_version"] == "26.7.1"
    assert data["status"] == "online"
    clients = data["clients"]
    assert len(clients) == 2
    for client_key, client in clients.items():
        assert client_key.startswith("**REDACTED_KEY_")
        assert client["id"] == client_key
    assert {client["packets"] for client in clients.values()} == {101, 202}
    assert len(data["leases"]) == 500
    serialized = json.dumps(diagnostics)
    assert "private-lease-0" not in serialized
    assert "10.0.0.1" not in serialized


async def test_config_entry_diagnostics_defaults_dynamic_keys_and_text_private(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should hide dynamic keys and validate operational string values."""
    entry = make_config_entry(data={"url": "https://router.example.test"}, title="Router")
    entry.runtime_data = SimpleNamespace(
        coordinator=_coordinator(
            {
                "users_by_name": {"Alice Smith": {"count": 1}},
                "Alice_id": {"count": 2},
                "Alice_ids": {"count": 3},
                "Alice_status": {"count": 4},
                "Alice_state": {"count": 5},
                "Alice_version": {"count": 6},
                "status": "Connected for Alice Smith",
                "firmware_version": "26.7.1",
                "new_version": "26.1-OfficeFirewall",
            }
        ),
        device_tracker_coordinator=None,
        live_traffic_coordinator=None,
    )

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    data = diagnostics["coordinators"]["main"]["data"]
    assert data["status"].startswith("**REDACTED_VALUE_")
    assert data["firmware_version"] == "26.7.1"
    assert data["new_version"].startswith("**REDACTED_VALUE_")
    users = next(value for key, value in data.items() if key.startswith("**REDACTED_KEY_"))
    user = next(iter(users.values()))
    assert user == {"count": 1}
    serialized = json.dumps(diagnostics)
    assert "users_by_name" not in serialized
    assert "Alice Smith" not in serialized
    assert "Connected for Alice Smith" not in serialized
    for private_key in (
        "Alice_id",
        "Alice_ids",
        "Alice_status",
        "Alice_state",
        "Alice_version",
    ):
        assert private_key not in serialized
    assert "26.1-OfficeFirewall" not in serialized


async def test_config_entry_diagnostics_plural_numeric_ids_and_distinct_dynamic_keys(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should alias nested numeric IDs and avoid dynamic-key collisions."""
    opaque_key = _OpaqueDiagnosticValue()
    entry = make_config_entry(data={"url": "https://router.example.test"}, title="Router")
    entry.runtime_data = SimpleNamespace(
        coordinator=_coordinator(
            {
                "rule_ids": [_NumericDiagnosticId.PRIMARY, 7, 2],
                "client_ids": (1, 3),
                "nested_ids": {"private_group": [1, 4]},
                "packets": 7,
                "dynamic_keys": {None: 1, False: 2, "": 3, opaque_key: 4},
            }
        ),
        device_tracker_coordinator=None,
        live_traffic_coordinator=None,
    )

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    data = diagnostics["coordinators"]["main"]["data"]
    assert all(value.startswith("**REDACTED_VALUE_") for value in data["rule_ids"])
    assert data["rule_ids"][0] == data["rule_ids"][1]
    assert data["client_ids"][0] != data["rule_ids"][0]
    assert data["client_ids"][1] != data["rule_ids"][2]
    nested_ids = data["nested_ids"]
    nested_values = next(iter(nested_ids.values()))
    assert nested_values[0] == data["client_ids"][0]
    assert nested_values[1].startswith("**REDACTED_VALUE_")
    assert data["packets"] == 7
    dynamic = next(
        value
        for key, value in data.items()
        if key.startswith("**REDACTED_KEY_")
        and isinstance(value, dict)
        and set(value.values()) == {1, 2, 3, 4}
    )
    assert len(dynamic) == 4
    assert len(set(dynamic)) == 4
    assert all(key.startswith("**REDACTED_KEY_") for key in dynamic)
    json.dumps(diagnostics)


async def test_config_entry_diagnostics_preserves_real_payload_shapes(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should retain known coordinator schemas while hiding dynamic identifiers."""
    entry = make_config_entry(data={"url": "https://router.example.test"}, title="Router")
    entry.runtime_data = SimpleNamespace(
        coordinator=_coordinator(
            {
                "vnstat": {"interfaces": {"igc0": {"used": 10}}},
                "speedtest": {"download": 100.5, "upload": 20.5, "latency": 8.1},
                "smart": {"smart_info": {"nvme0": {"temperature": 41}}},
                "openvpn": {"clients": {"private-client": {"status": "up"}}},
                "firmware_update_info": {
                    "new_version": "26.7.1_2",
                    "new_packages": 3,
                },
                "dhcp_leases": [{"interface": "lan", "hostname": "private-host", "active": True}],
                "gateways": {"private-gateway": {"status": "online", "delay": 3.2}},
                "services": [
                    {"service_name": "private-service", "status": state}
                    for state in (
                        "MASTER",
                        "BACKUP",
                        "INIT",
                        "healthy",
                        "maintenance",
                        "degraded",
                        "not_configured",
                    )
                ],
                "firewall": {"rules": {"private-rule": {"enabled": True}}},
                "carp": {
                    "interfaces": [
                        {
                            "interface": "igc0",
                            "subnet": "192.0.2.10",
                            "status": "MASTER",
                            "unexpected_owner": "Alice Smith",
                        }
                    ],
                    "status_summary": {"state": "healthy"},
                },
            }
        ),
        device_tracker_coordinator=None,
        live_traffic_coordinator=None,
    )

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    data = diagnostics["coordinators"]["main"]["data"]
    assert data["speedtest"] == {"download": 100.5, "upload": 20.5, "latency": 8.1}
    assert data["firmware_update_info"]["new_version"] == "26.7.1_2"
    assert [service["status"] for service in data["services"]] == [
        "MASTER",
        "BACKUP",
        "INIT",
        "healthy",
        "maintenance",
        "degraded",
        "not_configured",
    ]
    carp_row = data["carp"]["interfaces"][0]
    assert {"interface", "subnet", "status"} <= carp_row.keys()
    assert carp_row["status"] == "MASTER"
    assert "unexpected_owner" not in carp_row
    serialized = json.dumps(diagnostics)
    for private_value in (
        "igc0",
        "nvme0",
        "private-client",
        "private-host",
        "private-gateway",
        "private-service",
        "private-rule",
        "Alice Smith",
    ):
        assert private_value not in serialized


async def test_config_entry_diagnostics_typed_identifier_keys_are_order_independent(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should type aliases consistently whether keys or fields occur first."""
    key_first_ip = "192.0.2.10"
    field_first_ip = "192.0.2.20"
    key_first_mac = "aa:bb:cc:dd:ee:01"
    field_first_mac = "aa:bb:cc:dd:ee:02"
    payload = {
        "ipv4": field_first_ip,
        "mac": field_first_mac,
        "leases": {
            key_first_ip: {"ip": key_first_ip},
            field_first_ip: {"ip": field_first_ip},
        },
        "clients": {
            key_first_mac: {"mac": key_first_mac},
            field_first_mac: {"mac": field_first_mac},
        },
    }
    original_payload = copy.deepcopy(payload)
    entry = make_config_entry(data={"url": "https://router.example.test"}, title="Router")
    entry.runtime_data = SimpleNamespace(
        coordinator=_coordinator(payload),
        device_tracker_coordinator=None,
        live_traffic_coordinator=None,
    )

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    data = diagnostics["coordinators"]["main"]["data"]
    lease_keys = list(data["leases"])
    assert all(key.startswith("**REDACTED_IP_") for key in lease_keys)
    assert [lease["ip"] for lease in data["leases"].values()] == lease_keys
    client_keys = list(data["clients"])
    assert all(key.startswith("**REDACTED_MAC_") for key in client_keys)
    assert [client["mac"] for client in data["clients"].values()] == client_keys
    assert data["ipv4"] == lease_keys[1]
    assert data["mac"] == client_keys[1]
    serialized = json.dumps(diagnostics)
    for identifier in (key_first_ip, field_first_ip, key_first_mac, field_first_mac):
        assert identifier not in serialized
    assert payload == original_payload


async def test_config_entry_diagnostics_uses_per_download_alias_namespace(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should prevent aliases from linking separate downloads."""
    private_mac = "aa:bb:cc:dd:ee:ff"
    payload = {
        "clients": {private_mac: {"mac": private_mac}},
        "interfaces": {"wan": {"mac": private_mac, "status": "up"}},
    }
    original_payload = copy.deepcopy(payload)
    entry = make_config_entry(
        data={CONF_DEVICE_UNIQUE_ID: private_mac, "url": "https://router.example.test"},
        title="Router",
    )
    entry.runtime_data = SimpleNamespace(
        coordinator=_coordinator(payload),
        device_tracker_coordinator=None,
        live_traffic_coordinator=None,
    )

    first = await async_get_config_entry_diagnostics(hass, entry)
    second = await async_get_config_entry_diagnostics(hass, entry)

    first_mac = first["config_entry"]["data"][CONF_DEVICE_UNIQUE_ID]
    second_mac = second["config_entry"]["data"][CONF_DEVICE_UNIQUE_ID]
    assert first_mac.startswith("**REDACTED_MAC_")
    assert second_mac.startswith("**REDACTED_MAC_")
    assert first_mac != second_mac
    first_data = first["coordinators"]["main"]["data"]
    second_data = second["coordinators"]["main"]["data"]
    assert next(iter(first_data["clients"])) == first_mac
    assert next(iter(first_data["clients"].values()))["mac"] == first_mac
    assert next(iter(first_data["interfaces"].values()))["mac"] == first_mac
    assert next(iter(second_data["clients"])) == second_mac
    assert next(iter(second_data["clients"].values()))["mac"] == second_mac
    assert next(iter(second_data["interfaces"].values()))["mac"] == second_mac
    json.dumps(first)
    json.dumps(second)
    assert payload == original_payload


async def test_config_entry_diagnostics_preserves_post_refresh_counters(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should preserve current coordinator counter and rate schema keys."""
    current_time = 1_721_572_200.5
    interface_sample = {
        "inbytes": 200,
        "outbytes": 100,
        "inpkts": 300,
        "outpkts": 150,
        "inbytes_kilobytes_per_second": 10,
        "outbytes_kilobytes_per_second": 5,
        "inpkts_packets_per_second": 100,
        "outpkts_packets_per_second": 50,
    }
    vpn_sample = {
        "total_bytes_recv": 1000,
        "total_bytes_sent": 2000,
        "total_bytes_recv_kilobytes_per_second": 25,
        "total_bytes_sent_kilobytes_per_second": 50,
        "connected_clients": 2,
    }
    payload = {
        "update_time": current_time,
        "interfaces": {"private-wan": interface_sample},
        "openvpn": {"servers": {"private-openvpn": vpn_sample}},
        "wireguard": {
            "clients": {
                "private-wireguard-client": {
                    "total_bytes_recv": 3000,
                    "total_bytes_sent": 4000,
                    "total_bytes_recv_kilobytes_per_second": 75,
                    "total_bytes_sent_kilobytes_per_second": 100,
                    "connected_servers": 1,
                }
            }
        },
        "previous_state": {
            "update_time": current_time - 2,
            "interfaces": {
                "private-wan": {
                    "inbytes": 100,
                    "outbytes": 50,
                    "inpkts": 100,
                    "outpkts": 50,
                }
            },
            "openvpn": {
                "servers": {
                    "private-openvpn": {
                        "total_bytes_recv": 500,
                        "total_bytes_sent": 1000,
                    }
                }
            },
        },
    }
    original_payload = copy.deepcopy(payload)
    entry = make_config_entry(data={"url": "https://router.example.test"}, title="Router")
    entry.runtime_data = SimpleNamespace(
        coordinator=_coordinator(payload),
        device_tracker_coordinator=None,
        live_traffic_coordinator=None,
    )

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    data = diagnostics["coordinators"]["main"]["data"]
    assert data["update_time"] == current_time
    assert data["previous_state"]["update_time"] == current_time - 2
    current_interface = next(iter(data["interfaces"].values()))
    assert current_interface == interface_sample
    previous_interface = next(iter(data["previous_state"]["interfaces"].values()))
    assert previous_interface == {
        "inbytes": 100,
        "outbytes": 50,
        "inpkts": 100,
        "outpkts": 50,
    }
    openvpn_server = next(iter(data["openvpn"]["servers"].values()))
    assert openvpn_server == vpn_sample
    wireguard_client = next(iter(data["wireguard"]["clients"].values()))
    assert wireguard_client["total_bytes_recv"] == 3000
    assert wireguard_client["total_bytes_sent_kilobytes_per_second"] == 100
    assert wireguard_client["connected_servers"] == 1
    serialized = json.dumps(diagnostics)
    for identifier in ("private-wan", "private-openvpn", "private-wireguard-client"):
        assert identifier not in serialized
    assert payload == original_payload


async def test_config_entry_diagnostics_temporal_privacy_and_strict_json(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should hide unknown temporal data and normalize non-finite floats."""
    private_datetime = datetime(1990, 5, 4, 3, 2, 1, tzinfo=UTC)
    private_date = date(1990, 5, 4)
    private_time = time(3, 2, 1)
    payload = {
        "customer_birth_date": "1990-05-04",
        "private_event": private_datetime,
        "repeated_private_event": private_datetime,
        "private_day": private_date,
        "private_clock": private_time,
        "date": date(2026, 7, 21),
        "timestamp": "2026-07-21T12:30:00+00:00",
        "update_time": 1_721_572_200.5,
        "used": float("nan"),
        "temperature": float("inf"),
        "packets": float("-inf"),
        "count": 42.5,
    }
    entry = make_config_entry(data={"url": "https://router.example.test"}, title="Router")
    entry.runtime_data = SimpleNamespace(
        coordinator=_coordinator(payload),
        device_tracker_coordinator=None,
        live_traffic_coordinator=None,
    )

    first = await async_get_config_entry_diagnostics(hass, entry)
    second = await async_get_config_entry_diagnostics(hass, entry)

    first_data = first["coordinators"]["main"]["data"]
    second_data = second["coordinators"]["main"]["data"]
    assert first_data["date"] == "2026-07-21"
    assert first_data["timestamp"] == "2026-07-21T12:30:00+00:00"
    assert first_data["update_time"] == 1_721_572_200.5
    assert first_data["used"] is None
    assert first_data["temperature"] is None
    assert first_data["packets"] is None
    assert first_data["count"] == 42.5
    first_private_values = [
        value for key, value in first_data.items() if key.startswith("**REDACTED_KEY_")
    ]
    second_private_values = [
        value for key, value in second_data.items() if key.startswith("**REDACTED_KEY_")
    ]
    assert first_private_values[1] == first_private_values[2]
    assert first_private_values != second_private_values
    assert all(
        isinstance(value, str) and value.startswith("**REDACTED_VALUE_")
        for value in first_private_values
    )
    serialized = json.dumps(first, allow_nan=False)
    for private_value in (
        "customer_birth_date",
        "1990-05-04",
        "private_event",
        "03:02:01",
    ):
        assert private_value not in serialized
    source_used = payload["used"]
    source_temperature = payload["temperature"]
    source_packets = payload["packets"]
    assert isinstance(source_used, float) and math.isnan(source_used)
    assert isinstance(source_temperature, float) and math.isinf(source_temperature)
    assert isinstance(source_packets, float) and math.isinf(source_packets)
