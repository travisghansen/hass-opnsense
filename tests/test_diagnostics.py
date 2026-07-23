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
import pytest

from custom_components.opnsense.const import CONF_DEVICE_UNIQUE_ID, CONF_ENTRY_TYPE, ENTRY_TYPE_CARP
from custom_components.opnsense.diagnostics import (
    _Pseudonymizer,
    _validated_ipv6_candidate,
    async_get_config_entry_diagnostics,
)


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


_MISSING_RUNTIME_DATA = object()


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
    router_ip = "192.168.1.10"
    router_uuid = "123e4567-e89b-42d3-a456-426614174000"
    device_unique_id = "private-device-id"
    unique_id = "private-unique-id"
    workstation = "private-workstation"
    entry = make_config_entry(
        data={
            "url": f"https://{router_ip}",
            "username": "diagnostics-user",
            "password": "diagnostics-password",
            "name": "Office Firewall",
            CONF_DEVICE_UNIQUE_ID: device_unique_id,
            "firmware_version": "26.7.1",
        },
        title="Office Firewall",
        unique_id=unique_id,
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
    assert sanitized_main["telemetry"]["temps"]["private-cpu-device"] == {"temperature": 42.5}

    assert config_data[CONF_DEVICE_UNIQUE_ID] == device_unique_id
    assert diagnostics["config_entry"]["entry_id"] == "private-entry-id"
    assert diagnostics["config_entry"]["unique_id"] == unique_id
    assert sanitized_tracker["arp_table"][0]["mac"] == router_mac
    assert sanitized_live["interfaces"]["wan"]["mac"] == router_mac
    assert sanitized_tracker["arp_table"][0]["ip"] == router_ip
    redacted_interface = sanitized_main["interfaces"]["wan"]
    assert redacted_interface["ipv4"] == router_ip
    assert redacted_interface["status"] == "up"
    assert sanitized_live["interfaces"]["wan"]["inbytes_kilobytes_per_second"] == 12.5

    assert redacted_interface["interface"] == "wan"
    certificate = sanitized_main["certificates"]["Home Certificate"]
    assert certificate["uuid"] == router_uuid
    sanitized_vpn = sanitized_main["wireguard"]["clients"][router_uuid]
    assert sanitized_vpn["uuid"] == router_uuid
    assert sanitized_vpn["pubkey"].startswith("**REDACTED_ID_")
    assert sanitized_vpn["endpoint"] == "vpn.private.example:51820"
    assert sanitized_vpn["tunnel_addresses"][0].startswith("**REDACTED_IPV6_")
    assert sanitized_main["nut_ups_status"]["response"].startswith("**REDACTED_VALUE_")
    assert sanitized_main["nut_ups_status"]["status"]["device.serial"].startswith("**REDACTED_ID_")
    assert sanitized_main["nut_ups_status"]["status"]["ups.status"] == "OL"

    assert sanitized_main["leases"][workstation]["hostname"] == workstation
    json_scalars = sanitized_main["json_scalars"]
    assert json_scalars["datetime"] == "2026-07-21T12:30:00+00:00"
    assert json_scalars["date"] == "2026-07-21"
    assert json_scalars["time"] == "12:30:00"
    assert json_scalars["enum"] == "active"
    assert json_scalars["bytes"] == REDACTED
    assert json_scalars["opaque"] == REDACTED

    subject = sanitized_main["notices"][0]["subject"]
    assert router_mac in subject
    assert "admin@example.com" not in subject
    assert coordinators["device_tracker"]["last_update_success"] is False
    assert coordinators["device_tracker"]["last_exception"] == "RuntimeError"
    assert "diagnostics-user" not in json.dumps(diagnostics)
    assert "diagnostics-password" not in json.dumps(diagnostics)
    assert router_mac in json.dumps(diagnostics)
    assert router_ip in json.dumps(diagnostics)
    assert "private-ups-serial" not in json.dumps(diagnostics)
    assert "private-wireguard-public-key" not in json.dumps(diagnostics)
    assert "vpn.private.example" in json.dumps(diagnostics)
    assert "private office uplink" in json.dumps(diagnostics)
    assert "connection_summary" in json.dumps(diagnostics)
    assert "detail" in json.dumps(diagnostics)
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


@pytest.mark.parametrize("runtime_data", [_MISSING_RUNTIME_DATA, None, SimpleNamespace()])
async def test_config_entry_diagnostics_supports_missing_runtime_data(
    hass: HomeAssistant, make_config_entry: Any, runtime_data: object
) -> None:
    """Diagnostics should retain a stable shape before runtime setup completes."""
    entry = make_config_entry(
        data={
            "url": "https://router.example.test",
            "username": "diagnostics-user",
            "password": "diagnostics-password",
        },
        title="Router",
    )
    if runtime_data is _MISSING_RUNTIME_DATA:
        del entry.runtime_data
    else:
        entry.runtime_data = runtime_data

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    assert diagnostics["coordinators"] == {
        "main": None,
        "device_tracker": None,
        "live_traffic": None,
    }
    assert diagnostics["config_entry"]["data"]["username"] == REDACTED
    assert diagnostics["config_entry"]["data"]["password"] == REDACTED
    assert diagnostics["config_entry"]["data"]["url"].startswith("**REDACTED_URL_")


async def test_config_entry_diagnostics_redacts_credentials_embedded_in_text(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should replace config credentials repeated in coordinator text."""
    username = "diagnostics-user"
    password = "diagnostics-password"
    api_key = "diagnostics-api-key"
    entry = make_config_entry(
        data={
            "url": "https://router.example.test",
            "username": username,
            "password": password,
            "api_key": api_key,
        },
        title="Router",
    )
    entry.runtime_data = SimpleNamespace(
        coordinator=_coordinator(
            {
                "detail": f"Authentication for {username} failed with {password}.",
                "nested": [
                    f"Rejected API key {api_key}",
                    f"Repeated user {username}",
                    f"Request https://{username}:{password}@router.example.test/status failed",
                ],
            }
        ),
        device_tracker_coordinator=None,
        live_traffic_coordinator=None,
    )

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    config_data = diagnostics["config_entry"]["data"]
    assert config_data["username"] == REDACTED
    assert config_data["password"] == REDACTED
    assert config_data["api_key"] == REDACTED
    main_data = diagnostics["coordinators"]["main"]["data"]
    assert "**REDACTED_SECRET_" in main_data["detail"]
    assert "**REDACTED_SECRET_" in main_data["nested"][0]
    username_alias = main_data["nested"][1].removeprefix("Repeated user ")
    assert username_alias.startswith("**REDACTED_SECRET_")
    assert f"Authentication for {username_alias} failed" in main_data["detail"]
    assert main_data["nested"][2].startswith("Request **REDACTED_URL_")
    assert "router.example.test" not in main_data["nested"][2]
    serialized = json.dumps(diagnostics)
    for credential in (username, password, api_key):
        assert credential not in serialized


async def test_config_entry_diagnostics_replaces_identifier_literals_in_free_text(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should correlate identifier fields with bounded text replacements."""
    serial = "SN-1234"
    user = "private-user"
    common_name = "Private Common Name"
    entry = make_config_entry(data={"url": "https://router.example.test"}, title="Router")
    entry.runtime_data = SimpleNamespace(
        coordinator=_coordinator(
            {
                "serial_number": serial,
                "user": user,
                "common_name": common_name,
                "detail": (
                    f"device {serial} reported twice: {serial}; "
                    f"user {user}; certificate {common_name}"
                ),
                "larger_word": f"prefix{serial}suffix remains operational text",
            }
        ),
        device_tracker_coordinator=None,
        live_traffic_coordinator=None,
    )

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    data = diagnostics["coordinators"]["main"]["data"]
    serial_alias = data["serial_number"]
    user_alias = data["user"]
    common_name_alias = data["common_name"]
    assert serial_alias == "**REDACTED_ID_1**"
    assert user_alias == "**REDACTED_USER_1**"
    assert common_name_alias == "**REDACTED_VALUE_1**"
    assert data["detail"] == (
        f"device {serial_alias} reported twice: {serial_alias}; "
        f"user {user_alias}; certificate {common_name_alias}"
    )
    assert data["larger_word"] == f"prefix{serial}suffix remains operational text"


async def test_config_entry_diagnostics_collects_runtime_secrets_before_redaction(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should remove runtime and nested secrets repeated in free text."""
    preshared_key = "runtime-secret"
    client_key = "nested-client-secret"
    entry = make_config_entry(data={"url": "https://router.example.test"}, title="Router")
    entry.runtime_data = SimpleNamespace(
        coordinator=_coordinator(
            {
                "detail": f"failed with {preshared_key} and {client_key}",
                "preshared_key": preshared_key,
                "nested": [{"credentials": {"client_key": client_key}}],
                "credential_url": (f"https://user:{preshared_key}@router.example.test/status"),
            }
        ),
        device_tracker_coordinator=None,
        live_traffic_coordinator=None,
    )

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    data = diagnostics["coordinators"]["main"]["data"]
    assert data["preshared_key"] == REDACTED
    assert data["nested"][0]["credentials"]["client_key"] == REDACTED
    assert preshared_key not in data["detail"]
    assert client_key not in data["detail"]
    assert data["detail"].count("**REDACTED_SECRET_") == 2
    assert data["credential_url"].startswith("**REDACTED_URL_")
    assert "router.example.test" not in data["credential_url"]


async def test_config_entry_diagnostics_ipv6_sentence_punctuation(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should redact public IPv6 before preserving sentence punctuation."""
    public_ipv6 = "2001:db8::10"
    safe_addresses = ("fe80::1", "fd12:3456:789a::1", "::1")
    entry = make_config_entry(data={"url": "https://router.example.test"}, title="Router")
    entry.runtime_data = SimpleNamespace(
        coordinator=_coordinator(
            {
                "detail": f"peer {public_ipv6}.",
                "safe_detail": "; ".join(f"peer {address}." for address in safe_addresses),
            }
        ),
        device_tracker_coordinator=None,
        live_traffic_coordinator=None,
    )

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    data = diagnostics["coordinators"]["main"]["data"]
    assert data["detail"].startswith("peer **REDACTED_IPV6_")
    assert data["detail"].endswith("**.")
    assert public_ipv6 not in data["detail"]
    assert data["safe_detail"] == "; ".join(f"peer {address}." for address in safe_addresses)


@pytest.mark.parametrize("candidate", ["2001:db8::invalid.", "192.0.2.1"])
def test_validated_ipv6_candidate_rejects_invalid_and_ipv4_candidates(candidate: str) -> None:
    """IPv6 candidate validation should reject malformed and IPv4 input."""
    assert _validated_ipv6_candidate(candidate) is None


def test_pseudonymizer_ignores_unsupported_config_secret_values() -> None:
    """Config secret collection should ignore absent, non-string, and redacted values."""
    pseudonymizer = _Pseudonymizer()

    pseudonymizer.collect_secret_literals(None)
    pseudonymizer.collect_secret_literals(
        {
            "password": 123,
            "username": "",
            "nested": {"token": REDACTED},
            "auth": {"primary": "nested-secret", "fallbacks": ["backup-secret", None]},
        }
    )

    assert set(pseudonymizer.embedded_secret_aliases) == {
        "nested-secret",
        "backup-secret",
    }


async def test_config_entry_diagnostics_redacts_keys_and_sensitive_containers(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should redact secrets while retaining useful interface labels."""
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
    assert interfaces == {
        "lan_custom": "Private LAN",
        "nested_group": {"labels": ["Private Guest", 7, True, None]},
    }
    serialized = json.dumps(diagnostics)
    assert "private-preshared-key" not in serialized
    assert "private-client-key" not in serialized
    assert "lan_custom" in serialized
    assert "Private LAN" in serialized


async def test_config_entry_diagnostics_preserves_alias_metadata(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should preserve every alias metadata key and value."""
    alias_metadata = [
        {
            "summary": "<strong>Public endpoint</strong><br/>203.0.113.10",
            "description": "Public endpoint",
            "value": "public_endpoint_alias",
            "%value": "public_endpoint_alias",
            "isAlias": True,
        }
    ]
    entry = make_config_entry(
        data={"url": "https://router.example.test"},
        title="Private Router",
    )
    entry.runtime_data = SimpleNamespace(
        coordinator=_coordinator({"alias_meta_target": alias_metadata}),
        device_tracker_coordinator=None,
        live_traffic_coordinator=None,
    )

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    assert diagnostics["coordinators"]["main"]["data"]["alias_meta_target"] == alias_metadata


async def test_config_entry_diagnostics_numeric_ids_and_high_cardinality(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should preserve local IDs and labels at high cardinality."""
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
    assert clients == {
        101: {"id": 101, "packets": 101},
        202: {"id": 202, "packets": 202},
    }
    assert {client["packets"] for client in clients.values()} == {101, 202}
    assert len(data["leases"]) == 500
    serialized = json.dumps(diagnostics)
    assert "private-lease-0" in serialized
    assert "10.0.0.1" in serialized


async def test_config_entry_diagnostics_preserves_dynamic_keys_and_operational_text(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should preserve evolving keys and operational string values."""
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
    assert data["status"] == "Connected for Alice Smith"
    assert data["firmware_version"] == "26.7.1"
    assert data["new_version"] == "26.1-OfficeFirewall"
    assert data["users_by_name"]["Alice Smith"] == {"count": 1}
    serialized = json.dumps(diagnostics)
    assert "users_by_name" in serialized
    assert "Alice Smith" in serialized
    assert "Connected for Alice Smith" in serialized
    for private_key in (
        "Alice_id",
        "Alice_ids",
        "Alice_status",
        "Alice_state",
        "Alice_version",
    ):
        assert private_key in serialized
    assert "26.1-OfficeFirewall" in serialized


async def test_config_entry_diagnostics_plural_numeric_ids_and_distinct_dynamic_keys(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should preserve numeric IDs and safely encode unsupported keys."""
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
    assert data["rule_ids"] == [7, 7, 2]
    assert data["client_ids"] == [1, 3]
    assert data["nested_ids"] == {"private_group": [1, 4]}
    assert data["packets"] == 7
    dynamic = data["dynamic_keys"]
    assert len(dynamic) == 4
    assert dynamic[None] == 1
    assert dynamic[False] == 2
    assert dynamic[""] == 3
    opaque_alias = next(key for key in dynamic if isinstance(key, str) and key)
    assert opaque_alias.startswith("**REDACTED_KEY_")
    assert dynamic[opaque_alias] == 4
    json.dumps(diagnostics)


async def test_config_entry_diagnostics_preserves_real_payload_shapes(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should retain coordinator schemas and local operational labels."""
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
    assert carp_row["unexpected_owner"] == "Alice Smith"
    assert carp_row["subnet"].startswith("**REDACTED_IPV4_")
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
        assert private_value in serialized


async def test_config_entry_diagnostics_typed_identifier_keys_are_order_independent(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should redact public IPs while preserving local MAC identifiers."""
    key_first_ip = "192.0.2.10"
    field_first_ip = "192.0.2.20"
    public_ipv6 = "2001:db8::20"
    loopback_ipv4 = "127.0.0.1"
    link_local_ipv6 = "fe80::1%igc0"
    ula_ipv6 = "fd12:3456:789a::1/64"
    loopback_ipv6 = "::1"
    key_first_mac = "aa:bb:cc:dd:ee:01"
    field_first_mac = "aa:bb:cc:dd:ee:02"
    payload = {
        "ipv4": field_first_ip,
        "ipv6": public_ipv6,
        "loopback_ip": loopback_ipv4,
        "loopback_detail": f"API bound to {loopback_ipv4}",
        "link_local_ipv6": link_local_ipv6,
        "link_local_detail": f"Neighbor {link_local_ipv6} is reachable",
        "ula_ipv6": ula_ipv6,
        "ula_detail": f"Local tunnel {ula_ipv6} is active",
        "loopback_ipv6": loopback_ipv6,
        "loopback_ipv6_detail": f"API bound to [{loopback_ipv6}]",
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
    assert all(key.startswith("**REDACTED_IPV4_") for key in lease_keys)
    assert [lease["ip"] for lease in data["leases"].values()] == lease_keys
    client_keys = list(data["clients"])
    assert client_keys == [key_first_mac, field_first_mac]
    assert [client["mac"] for client in data["clients"].values()] == client_keys
    assert data["ipv4"] == lease_keys[1]
    assert data["ipv6"].startswith("**REDACTED_IPV6_")
    assert data["loopback_ip"] == loopback_ipv4
    assert data["loopback_detail"] == f"API bound to {loopback_ipv4}"
    assert data["link_local_ipv6"] == link_local_ipv6
    assert data["link_local_detail"] == f"Neighbor {link_local_ipv6} is reachable"
    assert data["ula_ipv6"] == ula_ipv6
    assert data["ula_detail"] == f"Local tunnel {ula_ipv6} is active"
    assert data["loopback_ipv6"] == loopback_ipv6
    assert data["loopback_ipv6_detail"] == f"API bound to [{loopback_ipv6}]"
    assert data["mac"] == field_first_mac
    serialized = json.dumps(diagnostics)
    for identifier in (key_first_ip, field_first_ip, public_ipv6):
        assert identifier not in serialized
    for identifier in (key_first_mac, field_first_mac):
        assert identifier in serialized
    assert payload == original_payload


async def test_config_entry_diagnostics_uses_simple_correlated_aliases(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should use simple aliases correlated within each download."""
    private_serial = "private-appliance-serial"
    payload = {
        "devices": [{"serial": private_serial}, {"serial_number": private_serial}],
    }
    original_payload = copy.deepcopy(payload)
    entry = make_config_entry(
        data={CONF_DEVICE_UNIQUE_ID: "local-device-id", "url": "https://router.example.test"},
        title="Router",
    )
    entry.runtime_data = SimpleNamespace(
        coordinator=_coordinator(payload),
        device_tracker_coordinator=None,
        live_traffic_coordinator=None,
    )

    first = await async_get_config_entry_diagnostics(hass, entry)
    second = await async_get_config_entry_diagnostics(hass, entry)

    first_data = first["coordinators"]["main"]["data"]
    second_data = second["coordinators"]["main"]["data"]
    first_serial = first_data["devices"][0]["serial"]
    second_serial = second_data["devices"][0]["serial"]
    assert first_serial == "**REDACTED_ID_1**"
    assert second_serial == "**REDACTED_ID_1**"
    assert [
        device["serial"] if "serial" in device else device["serial_number"]
        for device in first_data["devices"]
    ] == [first_serial, first_serial]
    assert [
        device["serial"] if "serial" in device else device["serial_number"]
        for device in second_data["devices"]
    ] == [second_serial, second_serial]
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
        assert identifier in serialized
    assert payload == original_payload


async def test_config_entry_diagnostics_preserves_evolving_operational_schema(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should keep unclassified API schema while hiding private values."""
    main_payload = {
        "telemetry": {"mbuf": {"used": 12, "total": 24, "status": "ok"}},
        "firmware_update_info": {
            "product_version": "26.7.1",
            "upgrade_needs_reboot": False,
        },
        "firewall": {
            "rules": {
                "private-rule-id": {
                    "uuid": "private-rule-id",
                    "sequence": 10,
                    "action": "pass",
                    "ipprotocol": "inet",
                    "protocol": "TCP",
                    "source_net": "Private VLAN",
                    "destination_net": "any",
                    "description": "Private firewall rule",
                }
            }
        },
    }
    tracker_payload = {
        "arp_table": [
            {
                "expires": 1200,
                "permanent": False,
                "type": "ethernet",
                "ip": "192.168.1.10",
                "mac": "aa:bb:cc:dd:ee:ff",
                "hostname": "private-host",
            }
        ]
    }
    entry = make_config_entry(data={"url": "https://router.example.test"}, title="Router")
    entry.runtime_data = SimpleNamespace(
        coordinator=_coordinator(main_payload),
        device_tracker_coordinator=_coordinator(tracker_payload),
        live_traffic_coordinator=None,
    )

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    main = diagnostics["coordinators"]["main"]["data"]
    assert main["telemetry"]["mbuf"] == {"used": 12, "total": 24, "status": "ok"}
    assert main["firmware_update_info"] == {
        "product_version": "26.7.1",
        "upgrade_needs_reboot": False,
    }
    rule = next(iter(main["firewall"]["rules"].values()))
    assert {
        "uuid",
        "sequence",
        "action",
        "ipprotocol",
        "protocol",
        "source_net",
        "destination_net",
        "description",
    } == set(rule)
    assert rule["sequence"] == 10
    assert rule["action"] == "pass"
    assert rule["ipprotocol"] == "inet"
    assert rule["protocol"] == "TCP"
    assert rule["uuid"] == "private-rule-id"
    assert rule["source_net"] == "Private VLAN"
    assert rule["destination_net"] == "any"
    assert rule["description"] == "Private firewall rule"

    arp_row = diagnostics["coordinators"]["device_tracker"]["data"]["arp_table"][0]
    assert {"expires", "permanent", "type", "ip", "mac", "hostname"} == set(arp_row)
    assert arp_row["expires"] == 1200
    assert arp_row["permanent"] is False
    assert arp_row["type"] == "ethernet"
    assert arp_row["ip"] == "192.168.1.10"
    assert arp_row["mac"] == "aa:bb:cc:dd:ee:ff"
    assert arp_row["hostname"] == "private-host"


async def test_config_entry_diagnostics_temporal_privacy_and_strict_json(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should preserve temporal data and normalize non-finite floats."""
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
    assert first_data["customer_birth_date"] == "1990-05-04"
    assert first_data["private_event"] == "1990-05-04T03:02:01+00:00"
    assert first_data["repeated_private_event"] == "1990-05-04T03:02:01+00:00"
    assert first_data["private_day"] == "1990-05-04"
    assert first_data["private_clock"] == "03:02:01"
    assert first_data == second_data
    serialized = json.dumps(first, allow_nan=False)
    for operational_value in (
        "customer_birth_date",
        "1990-05-04",
        "private_event",
        "03:02:01",
    ):
        assert operational_value in serialized
    source_used = payload["used"]
    source_temperature = payload["temperature"]
    source_packets = payload["packets"]
    assert isinstance(source_used, float) and math.isnan(source_used)
    assert isinstance(source_temperature, float) and math.isinf(source_temperature)
    assert isinstance(source_packets, float) and math.isinf(source_packets)


async def test_config_entry_diagnostics_preserves_temporal_and_unit_metadata(
    hass: HomeAssistant, make_config_entry: Any
) -> None:
    """Diagnostics should retain unfamiliar temporal and unit metadata."""
    payload = {
        "date": "not-a-date",
        "time": "not-a-time",
        "timestamp": "not-a-datetime",
        "unit": "ms",
        "units": "private-unit",
    }
    entry = make_config_entry(data={"url": "https://router.example.test"}, title="Router")
    entry.runtime_data = SimpleNamespace(
        coordinator=_coordinator(payload),
        device_tracker_coordinator=None,
        live_traffic_coordinator=None,
    )

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    data = diagnostics["coordinators"]["main"]["data"]
    assert data == payload
    json.dumps(diagnostics)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_pseudonymizer_ignores_non_finite_alias_values(value: float) -> None:
    """Non-finite floats should never be registered or resolved as aliases."""
    pseudonymizer = _Pseudonymizer()

    pseudonymizer.register("value", value)

    assert pseudonymizer.aliases == {}
    assert pseudonymizer.alias_for(value) is None


@pytest.mark.parametrize("value", ["", REDACTED])
def test_pseudonymizer_ignores_empty_and_redacted_alias_values(value: str) -> None:
    """Empty and already-redacted values should not consume alias counters."""
    pseudonymizer = _Pseudonymizer()

    pseudonymizer.register("value", value)

    assert pseudonymizer.aliases == {}
    assert pseudonymizer.counters == {}


def test_pseudonymizer_distinguishes_non_finite_mapping_keys() -> None:
    """Non-finite mapping keys should receive stable, distinct aliases."""
    pseudonymizer = _Pseudonymizer()
    values = (float("nan"), float("inf"), float("-inf"))

    for value in values:
        pseudonymizer.register_key(value)
    pseudonymizer.register_key(values[0])

    aliases = [pseudonymizer.key_alias_for(value) for value in values]
    assert len(set(aliases)) == 3
    assert all(alias.startswith("**REDACTED_KEY_") for alias in aliases)
    assert pseudonymizer.key_alias_for(float("nan")) == aliases[0]


def test_pseudonymizer_preserves_safe_identifiers_and_scalar_types() -> None:
    """Local identifiers and ordinary scalar types should remain useful."""
    pseudonymizer = _Pseudonymizer()
    uuid = "123e4567-e89b-42d3-a456-426614174000"
    public_ip = "192.0.2.10"
    mac = "aa:bb:cc:dd:ee:ff"

    pseudonymizer.register("ipv4", public_ip)
    pseudonymizer.register("value", True)
    pseudonymizer.register("value", object())

    assert pseudonymizer._kind_for_field("entry_id", uuid) is None
    assert pseudonymizer._kind_for_field("unique_id", mac) is None
    assert pseudonymizer._key_token("label") == (str, "label")
    assert pseudonymizer.sanitize(True, force_sensitive=True) is True
    assert pseudonymizer._replace_scalar(public_ip) == pseudonymizer.alias_for(public_ip)


def test_pseudonymizer_skips_regex_shaped_invalid_ipv4_candidates() -> None:
    """Regex-shaped text should not register an alias unless it is a valid IPv4 address."""
    pseudonymizer = _Pseudonymizer()
    candidate = "999.999.999.999"

    pseudonymizer._collect_detected_values(f"peer {candidate} unavailable")

    assert pseudonymizer.alias_for(candidate) is None
    assert pseudonymizer._replace_embedded(candidate) == candidate


@pytest.mark.parametrize("field_name", ["email", "user"])
def test_pseudonymizer_classifies_email_and_user_fields(field_name: str) -> None:
    """Email and user fields should use the user alias classification."""
    pseudonymizer = _Pseudonymizer()

    assert pseudonymizer._kind_for_field(field_name, "private-user") == "user"


def test_pseudonymizer_replaces_embedded_ip_with_registered_alias() -> None:
    """Embedded valid IP addresses should reuse their previously registered alias."""
    pseudonymizer = _Pseudonymizer()
    private_ip = "192.0.2.10"
    pseudonymizer.register("ipv4", private_ip)
    alias = pseudonymizer.alias_for(private_ip)

    assert alias is not None
    assert pseudonymizer._replace_embedded(f"peer {private_ip} unavailable") == (
        f"peer {alias} unavailable"
    )
