"""Unit tests for custom_components.opnsense.update."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.opnsense import update as update_module
from custom_components.opnsense.update import OPNsenseFirmwareUpdatesAvailableUpdate
from homeassistant.components.update import UpdateEntityDescription


def _make_entry(data=None):
    data = data or {"device_unique_id": "d1", "url": "http://x"}
    entry = MockConfigEntry(domain="opnsense", data=data, title="t")
    entry.runtime_data = MagicMock()
    return entry


class DummyCoordinator(MagicMock):
    pass


def test_is_update_available_false_when_missing():
    entry = _make_entry()
    coord = DummyCoordinator()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=coord,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )
    ent.async_write_ha_state = lambda: None

    # state missing or malformed
    coord.data = None
    ent.coordinator = coord
    ent._handle_coordinator_update()
    assert ent.available is False


def test_get_versions_update_with_packages_and_series_upgrade():
    entry = _make_entry()
    coord = DummyCoordinator()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=coord,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )
    ent.async_write_ha_state = lambda: None

    # prepare a state where status is 'update' and packages list contains opnsense with new_version
    state = {
        "firmware_update_info": {
            "product": {
                "product_version": "1.0.0",
                "product_latest": "1_0_0",
                "product_series": "1.0",
                "product_check": {
                    "upgrade_packages": [
                        {"name": "opnsense", "new_version": "1_0_1"},
                    ]
                },
            },
            "status": "update",
        }
    }

    pv, pl, ps = ent._get_versions(state)
    assert pv == "1.0.0"
    assert pl == "1_0_1"
    assert ps == "1.0"


def test_get_versions_product_latest_plus_when_no_package_list():
    entry = _make_entry()
    coord = DummyCoordinator()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=coord,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )
    ent.async_write_ha_state = lambda: None

    state = {
        "firmware_update_info": {
            "product": {
                # match formats so product_version == product_latest triggers '+' handling
                "product_version": "1_0_0",
                "product_latest": "1_0_0",
                "product_series": "1.0",
                "product_check": {"upgrade_packages": None},
            },
            "status": "update",
        }
    }

    pv, pl, ps = ent._get_versions(state)
    assert pl.endswith("+")


def test_get_product_class_and_series_parsing():
    entry = _make_entry()
    coord = DummyCoordinator()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=coord,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )
    # series minor mapping
    assert ent._get_product_class("25.1") == "community"
    assert ent._get_product_class("1.1") == "community"
    assert ent._get_product_class("2.4") == "business"
    assert ent._get_product_class("3.4") == "business"


def test_handle_coordinator_update_sets_attributes():
    entry = _make_entry()
    coord = DummyCoordinator()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=coord,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )
    # prepare state with many firmware fields
    state = {
        "firmware_update_info": {
            "status": "update",
            "status_msg": "ok",
            "product": {
                "product_version": "1_0_0",
                "product_latest": "1_0_2",
                "product_series": "2.1",
                "product_name": "OPN",
                "product_nickname": "OPN",
                "product_check": {"upgrade_packages": []},
            },
            "os_version": "os",
            "product_id": "pid",
            "product_target": "pt",
            "upgrade_needs_reboot": "0",
            "needs_reboot": "0",
            "download_size": 123,
            "last_check": 1,
        }
    }
    ent.coordinator.data = state
    ent.async_write_ha_state = lambda: None
    ent._handle_coordinator_update()
    assert ent.available is True
    assert ent._attr_installed_version == "1_0_0"
    assert ent._attr_latest_version == "1.0.2"
    # extra state attributes are created from firmware_update_info keys (top-level ones)
    assert "opnsense_download_size" in ent._attr_extra_state_attributes
    assert ent._attr_extra_state_attributes.get("opnsense_download_size") == 123
    assert ent._attr_extra_state_attributes.get("opnsense_last_check") == 1


def test_handle_coordinator_update_upgrade_sets_release_url():
    entry = _make_entry()
    coord = DummyCoordinator()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=coord,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )
    state = {
        "firmware_update_info": {
            "status": "upgrade",
            "product": {
                "product_version": "2.0.0",
                "product_latest": "2_0_1",
                "product_series": "2.1",
            },
            "upgrade_major_version": "2.1.3",
        }
    }
    ent.coordinator.data = state
    ent.async_write_ha_state = lambda: None
    ent._handle_coordinator_update()
    # product_series '2.1' => series_minor '1' => product_class community -> use github URL
    assert ent._attr_release_url is not None
    assert "community/2.1" in ent._attr_release_url


def test_get_release_notes_update_and_upgrade_and_default():
    entry = _make_entry()
    coord = DummyCoordinator()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=coord,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )
    ent.async_write_ha_state = lambda: None

    state_update = {
        "firmware_update_info": {
            "status": "update",
            "product": {"product_name": "OPN", "product_nickname": "OPN"},
            "status_msg": "msg",
            "needs_reboot": "1",
            "all_packages": {"a": 1},
            "new_packages": [1, 2],
            "reinstall_packages": [],
            "remove_packages": [],
            "upgrade_packages": [1],
        }
    }

    notes = ent._get_release_notes(state_update, "1_0_1", "1.0")
    assert "OPN" in notes

    state_upgrade = {
        "firmware_update_info": {
            "status": "upgrade",
            "product": {"product_name": "OPN"},
            "status_msg": "up",
            "upgrade_needs_reboot": "1",
        }
    }
    notes2 = ent._get_release_notes(state_upgrade, "1_2_0", "1.2")
    assert "version" in notes2

    # default fallback
    state_default = {"firmware_update_info": {"status": "none", "status_msg": "nothing"}}
    assert ent._get_release_notes(state_default, None, None) == "nothing"


@pytest.mark.asyncio
async def test_async_install_reboots_when_needed(monkeypatch):
    entry = _make_entry()
    coord = DummyCoordinator()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=coord,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )
    ent.async_write_ha_state = lambda: None

    class FakeClient:
        def __init__(self):
            self._status_calls = [
                {"status": "running"},
                {"status": "done"},
            ]
            self.rebooted = False

        async def upgrade_firmware(self, upgrade_type):
            return {"started": True}

        async def upgrade_status(self):
            return self._status_calls.pop(0)

        async def get_firmware_update_info(self):
            return {"needs_reboot": "1", "upgrade_needs_reboot": None}

        async def system_reboot(self):
            self.rebooted = True

    fake = FakeClient()
    ent._client = fake

    # provide coordinator state with firmware info and upgrade in progress
    ent.coordinator.data = {"firmware_update_info": {"status": "update"}}

    # speed up sleep
    monkeypatch.setattr(asyncio, "sleep", AsyncMock(return_value=None))

    await ent.async_install()
    assert fake.rebooted is True


@pytest.mark.asyncio
async def test_async_install_early_returns_and_no_client(monkeypatch):
    entry = _make_entry()
    coord = DummyCoordinator()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=coord,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )
    ent.async_write_ha_state = lambda: None

    # state not mapping
    ent.coordinator.data = None
    await ent.async_install()

    # state present but no client
    ent.coordinator.data = {"firmware_update_info": {"status": "update"}}
    ent._client = None
    await ent.async_install()


def test_get_versions_handles_missing_values():
    entry = _make_entry()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=DummyCoordinator(),
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )

    # missing product_latest should yield (product_version, None, product_series)
    state = {
        "firmware_update_info": {
            "product": {"product_version": "v1", "product_latest": None, "product_series": "s1"},
            "status": "update",
        }
    }
    pv, pl, ps = ent._get_versions(state)
    assert pv == "v1"
    assert pl is None


def test_get_versions_exception_path(monkeypatch):
    # force dict_get to raise so we hit the exception return

    entry = _make_entry()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=DummyCoordinator(),
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )

    def raise_type(*args, **kwargs):
        raise TypeError("boom")

    monkeypatch.setattr(update_module, "dict_get", raise_type)
    try:
        pv, pl, ps = ent._get_versions({})
        assert pv is None and pl is None and ps is None
    finally:
        # restore by reloading module if needed in other tests (tests isolated so not required)
        pass


def test_get_release_notes_exception_path(monkeypatch):
    entry = _make_entry()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=DummyCoordinator(),
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )

    def raise_key(*args, **kwargs):
        raise KeyError("nope")

    monkeypatch.setattr(update_module, "dict_get", raise_key)
    res = ent._get_release_notes({}, None, None)
    assert "Release notes unavailable" in res


@pytest.mark.asyncio
async def test_async_install_exceptions_loop(monkeypatch):
    entry = _make_entry()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=DummyCoordinator(),
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )

    class BadClient:
        def __init__(self):
            self.rebooted = False

        async def upgrade_firmware(self, upgrade_type):
            return {"started": True}

        async def upgrade_status(self):
            raise RuntimeError("fail")

        async def get_firmware_update_info(self):
            return {"needs_reboot": None, "upgrade_needs_reboot": None}

        async def system_reboot(self):
            self.rebooted = True

    bad = BadClient()
    ent._client = bad
    ent.coordinator.data = {"firmware_update_info": {"status": "update"}}
    monkeypatch.setattr(asyncio, "sleep", AsyncMock(return_value=None))

    await ent.async_install()
    assert bad.rebooted is False


def test_get_installed_version_none_on_error():
    entry = _make_entry()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=DummyCoordinator(),
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )
    assert ent._get_installed_version({}) is None


@pytest.mark.asyncio
async def test_async_release_notes_returns_value():
    entry = _make_entry()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=DummyCoordinator(),
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )
    ent._release_notes = "nn"
    val = await ent.async_release_notes()
    assert val == "nn"
