"""Tests for OPNsense diagnostics."""

import copy
from datetime import UTC, date, datetime, time
from enum import Enum
import json
from types import SimpleNamespace
from typing import Any, Self

from homeassistant.components.diagnostics import REDACTED
from homeassistant.core import HomeAssistant

from custom_components.opnsense.const import CONF_DEVICE_UNIQUE_ID, CONF_ENTRY_TYPE, ENTRY_TYPE_CARP
from custom_components.opnsense.diagnostics import async_get_config_entry_diagnostics


class _DiagnosticMode(Enum):
    """Representative enum included in a diagnostics payload."""

    ACTIVE = "active"


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

    assert "2001:db8::10" not in sanitized_main["connection_summary"]
    assert "**REDACTED_IP_" in sanitized_main["connection_summary"]
    redacted_lease_key = next(iter(sanitized_main["leases"]))
    assert redacted_lease_key.startswith("**REDACTED_KEY_")
    assert sanitized_main["leases"][redacted_lease_key]["hostname"] == redacted_lease_key
    assert sanitized_main["json_scalars"] == {
        "datetime": "2026-07-21T12:30:00+00:00",
        "date": "2026-07-21",
        "time": "12:30:00",
        "enum": "active",
        "bytes": REDACTED,
        "opaque": REDACTED,
    }

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
