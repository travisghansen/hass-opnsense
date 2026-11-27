"""Tests for OPNsense config-entry migration during Home Assistant setup."""

from unittest.mock import MagicMock

from aiopnsense import Access, AccessDict, OPNsenseClient
from aiopnsense.exceptions import OPNsenseConnectionError, OPNsensePrivilegeMissing
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import CONF_PASSWORD, CONF_URL, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
import pytest
from pytest_homeassistant.common import MockConfigEntry

from custom_components.opnsense import helpers
from custom_components.opnsense.const import (
    CONF_DEVICE_TRACKER_ENABLED,
    CONF_DEVICE_UNIQUE_ID,
    CONF_SYNC_VPN,
    DOMAIN,
    GRANULAR_SYNC_ITEMS,
)
from custom_components.opnsense.repair_reconciliation import REPAIR_MARKER_KEY, build_repair_marker


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        "configuration",
        "status",
        "unavailable",
        "error",
        "collision",
        "no-legacy",
        "pending-repair",
    ],
)
async def test_wireguard_sensor_migration_during_setup(
    hass: HomeAssistant,
    entity_registry: er.EntityRegistry,
    monkeypatch: pytest.MonkeyPatch,
    response: str,
) -> None:
    """Re-key available WireGuard sensors without disrupting entry setup.

    Args:
        hass (HomeAssistant): Home Assistant instance loading the Firewall entry.
        entity_registry (er.EntityRegistry): Registry containing the legacy WireGuard entities.
        monkeypatch (pytest.MonkeyPatch): Fixture used to replace the OPNsense client.
        response (str): WireGuard response available during migration.
    """
    pending_repair = response == "pending-repair"
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id="AA:BB",
        data={
            CONF_URL: "https://firewall.example",
            CONF_USERNAME: "user",
            CONF_PASSWORD: "password",
            CONF_DEVICE_UNIQUE_ID: "AA:BB",
            **{option: option == CONF_SYNC_VPN for option in GRANULAR_SYNC_ITEMS},
            **({REPAIR_MARKER_KEY: build_repair_marker("old", "AA:BB")} if pending_repair else {}),
        },
        options={CONF_DEVICE_TRACKER_ENABLED: False},
        version=5,
    )
    entry.add_to_hass(hass)
    legacy_ids = {
        # Shares the office server's public key; the interface tells them apart.
        "disabled_server": "aa_bb_wireguard_servers_ddeeff00_1234_4321_9876_abcdef012345_status",
        "office_server": "aa_bb_wireguard_servers_aabbccdd_1234_4321_9876_abcdef012345_status",
        "office_client": "aa_bb_wireguard_clients_bbccddee_1234_4321_9876_abcdef012345_connected_servers",
        # Shares the office client's public key, so each keeps its own sensor.
        "branch_client": "aa_bb_wireguard_clients_ccbbaa99_1234_4321_9876_abcdef012345_connected_servers",
        "missing_server": "aa_bb_wireguard_servers_ccddeeff_1234_4321_9876_abcdef012345_status",
    }
    target_ids = {
        **legacy_ids,
        "disabled_server": "aa_bb_wireguard_servers_0123456789abcdef_wg1_status",
        "office_server": "aa_bb_wireguard_servers_0123456789abcdef_wg0_status",
        "office_client": (
            "aa_bb_wireguard_clients_123456789abcdef0_"
            "bbccddee_1234_4321_9876_abcdef012345_connected_servers"
        ),
        "branch_client": (
            "aa_bb_wireguard_clients_123456789abcdef0_"
            "ccbbaa99_1234_4321_9876_abcdef012345_connected_servers"
        ),
    }
    if response == "no-legacy":
        legacy_ids = {"office_server": target_ids["office_server"]}
    elif pending_repair:
        legacy_ids = {
            name: unique_id.replace("aa_bb_", "old_", 1)
            for name, unique_id in legacy_ids.items()
            if name != "missing_server"
        }
    entities = {
        name: entity_registry.async_get_or_create(
            "sensor", DOMAIN, unique_id, config_entry=entry, suggested_object_id=name
        ).entity_id
        for name, unique_id in legacy_ids.items()
    }
    if response == "collision":
        occupied = entity_registry.async_get_or_create(
            "sensor", DOMAIN, target_ids["office_server"], config_entry=entry
        )
        target_ids["office_server"] = legacy_ids["office_server"]
    switch = entity_registry.async_get_or_create(
        "switch",
        DOMAIN,
        "aa_bb_wireguard_servers_aabbccdd_1234_4321_9876_abcdef012345",
        config_entry=entry,
    )

    migration_client = MagicMock(spec=OPNsenseClient)
    if response in {"configuration", "collision", "pending-repair"}:
        migration_client.get_wireguard.return_value = AccessDict(
            {
                "servers": {
                    "ddeeff00-1234-4321-9876-abcdef012345": {
                        "enabled": False,
                        "key_hash": "0123456789abcdef",
                        "interface": "wg1",
                    },
                    "aabbccdd-1234-4321-9876-abcdef012345": {
                        "enabled": True,
                        "key_hash": "0123456789abcdef",
                        "interface": "wg0",
                    },
                },
                "clients": {
                    "bbccddee-1234-4321-9876-abcdef012345": {
                        "enabled": True,
                        "key_hash": "123456789abcdef0",
                    },
                    "ccbbaa99-1234-4321-9876-abcdef012345": {
                        "enabled": True,
                        "key_hash": "123456789abcdef0",
                    },
                },
            },
            access=Access.CONFIGURATION,
        )
    elif response == "status":
        # The migration client raises on errors, so Status Access arrives as a denial.
        migration_client.get_wireguard.side_effect = OPNsensePrivilegeMissing("forbidden")
    elif response == "error":
        migration_client.get_wireguard.side_effect = OPNsenseConnectionError("offline")
    else:
        migration_client.get_wireguard.return_value = None

    runtime_client = MagicMock(spec=OPNsenseClient)
    runtime_client.get_device_unique_id.return_value = "AA:BB"
    runtime_client.get_host_firmware_version.return_value = "26.1.1"
    runtime_client.get_system_info.return_value = {"name": "Firewall"}
    runtime_client.get_wireguard.return_value = {"servers": {}, "clients": {}}
    if pending_repair:
        runtime_client.get_wireguard.return_value = migration_client.get_wireguard.return_value
    runtime_client.get_openvpn.return_value = {"servers": {}, "clients": {}}
    runtime_client.get_ipsec.return_value = {"connections": {}, "children": {}}
    monkeypatch.setattr(
        helpers,
        "OPNsenseClient",
        MagicMock(
            side_effect=lambda **kwargs: (
                migration_client if kwargs["throw_errors"] else runtime_client
            )
        ),
    )

    assert await hass.config_entries.async_setup(entry.entry_id)
    assert entry.version == 6
    assert entry.state is ConfigEntryState.LOADED
    if response == "no-legacy":
        migration_client.get_wireguard.assert_not_awaited()
    else:
        migration_client.async_close.assert_awaited_once()
    if response == "collision":
        assert entity_registry.async_get(occupied.entity_id) == occupied
    expected_ids = (
        target_ids if response in {"configuration", "collision", "pending-repair"} else legacy_ids
    )
    for name, entity_id in entities.items():
        assert (
            entity_registry.async_get_entity_id("sensor", DOMAIN, expected_ids[name]) == entity_id
        )
    assert (
        entity_registry.async_get_entity_id("switch", DOMAIN, switch.unique_id) == switch.entity_id
    )
