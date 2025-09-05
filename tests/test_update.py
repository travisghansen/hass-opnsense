"""Unit tests for custom_components.opnsense.update."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.opnsense import update as update_module
from custom_components.opnsense.const import CONF_DEVICE_UNIQUE_ID
from custom_components.opnsense.update import OPNsenseFirmwareUpdatesAvailableUpdate
from homeassistant.components.update import UpdateEntityDescription


def test_is_update_available_false_when_missing(make_config_entry, dummy_coordinator):
    """Update entity should be unavailable when coordinator data is missing."""
    entry = make_config_entry()
    coord = dummy_coordinator
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
    ent._handle_coordinator_update()
    assert ent.available is False


def test_is_update_available_false_when_error(make_config_entry, dummy_coordinator):
    """Update entity should be unavailable when coordinator reports an error status."""
    entry = make_config_entry()
    coord = dummy_coordinator
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=coord,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )
    ent.async_write_ha_state = lambda: None
    coord.data = {"firmware_update_info": {"status": "error"}}
    ent._handle_coordinator_update()
    assert ent.available is False


@pytest.mark.parametrize(
    "state_builder,expect_latest,expect_series,expect_latest_condition",
    [
        # product_version == product_latest and packages is list without opnsense -> append '+'
        (
            lambda: {
                "firmware_update_info": {
                    "product": {
                        "product_version": "1_0_0",
                        "product_latest": "1_0_0",
                        "product_series": "1.0",
                        "product_check": {"upgrade_packages": [{"name": "not-opnsense"}]},
                    },
                    "status": "update",
                }
            },
            None,
            "1.0",
            lambda latest: latest == "1_0_0+",
        ),
        (
            lambda: {
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
            },
            "1_0_1",
            "1.0",
            lambda latest: latest == "1_0_1",
        ),
        (
            lambda: {
                "firmware_update_info": {
                    "product": {
                        "product_version": "1_0_0",
                        "product_latest": "1_0_0",
                        "product_series": "1.0",
                        "product_check": {"upgrade_packages": None},
                    },
                    "status": "update",
                }
            },
            None,  # expect_latest unknown until post-processing; condition will check exact string
            "1.0",
            lambda latest, pv="1_0_0": latest == pv + "+",
        ),
        (
            lambda: {
                "firmware_update_info": {
                    "product": {
                        "product_version": "v1",
                        "product_latest": None,
                        "product_series": "s1",
                    },
                    "status": "update",
                }
            },
            None,
            "s1",
            lambda latest: latest is None,
        ),
        # exercise the 'upgrade' branch: upgrade_major_version should become product_latest
        (
            lambda: {
                "firmware_update_info": {
                    "status": "upgrade",
                    "product": {
                        "product_version": "2_0_0",
                        "product_latest": "2_0_0",
                        "product_series": "2.0",
                    },
                    "upgrade_major_version": "2.1.3",
                }
            },
            "2.1.3",
            "2.1",
            lambda latest: latest == "2.1.3",
        ),
    ],
)
def test_get_versions_scenarios(
    state_builder,
    expect_latest,
    expect_series,
    expect_latest_condition,
    make_config_entry,
    dummy_coordinator,
):
    """Parameterize _get_versions behaviors across upgrade package presence and missing fields."""
    # Use the shared fixture for a config entry
    entry = make_config_entry()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=dummy_coordinator,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )
    state = state_builder()
    pv, pl, ps = ent._get_versions(state)
    assert ps == expect_series
    if expect_latest is not None:
        assert pl == expect_latest
    assert expect_latest_condition(pl)


@pytest.mark.parametrize(
    "series,expected",
    [
        ("25.1", "community"),
        ("1.1", "community"),
        ("2.4", "business"),
        ("3.4", "business"),
        ("25.7", "community"),
        ("1.10", "business"),
    ],
)
def test_get_product_class_and_series_parsing(
    series, expected, make_config_entry, dummy_coordinator
):
    """Parameterize product class mapping by series minor version."""
    entry = make_config_entry()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=dummy_coordinator,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )
    assert ent._get_product_class(series) == expected


def test_handle_coordinator_update_sets_attributes(make_config_entry, dummy_coordinator):
    """_handle_coordinator_update should populate versions and extra attributes."""
    entry = make_config_entry()
    coord = dummy_coordinator
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
    assert ent.installed_version == "1_0_0"
    assert ent.latest_version == "1.0.2"
    # extra state attributes are created from firmware_update_info keys (top-level ones)
    assert "opnsense_download_size" in ent.extra_state_attributes
    assert ent.extra_state_attributes.get("opnsense_download_size") == 123
    assert ent.extra_state_attributes.get("opnsense_last_check") == 1


@pytest.mark.asyncio
async def test_handle_coordinator_update_upgrade_sets_release_url(
    make_config_entry, dummy_coordinator
):
    """Upgrade state should compute a release URL and provide release notes.

    This also asserts normalization of product_latest and correct derivation of
    the series_minor (from product_series) which affects the release URL.
    """
    entry = make_config_entry()
    coord = dummy_coordinator
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

    # For upgrade status, latest_version should reflect the upgrade_major_version
    assert ent.latest_version == "2.1.3"

    # product_series '2.1' => series_minor '1' => product_class community -> use github URL
    assert ent.release_url is not None
    assert "community/2.1" in ent.release_url

    # Ensure the upgrade_major_version appears in release_url
    assert "2.1.3" in ent.release_url


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "product_latest_input, expected_latest_normalized",
    [("2_0_1", "2.0.1"), ("2.0.1", "2.0.1")],
)
async def test_handle_coordinator_update_update_normalizes_product_latest(
    product_latest_input, expected_latest_normalized, make_config_entry, dummy_coordinator
):
    """When status is 'update', product_latest should be normalized (underscores -> dots)."""
    entry = make_config_entry()
    coord = dummy_coordinator
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=coord,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )
    state = {
        "firmware_update_info": {
            "status": "update",
            "product": {
                "product_version": "2.0.0",
                "product_latest": product_latest_input,
                "product_series": "2.1",
                "product_check": {"upgrade_packages": []},
            },
        }
    }
    ent.coordinator.data = state
    ent.async_write_ha_state = lambda: None
    ent._handle_coordinator_update()

    # product_latest should be normalized into latest_version
    assert ent.latest_version == expected_latest_normalized

    # release notes are currently generated from the raw product_latest value
    # (the entity stores a normalized latest_version separately), so verify
    # the original input appears in the notes and the normalized value is
    # available on the entity
    notes = await ent.async_release_notes()
    assert product_latest_input in notes


def test_handle_coordinator_update_release_url_fallback_when_product_class_none(
    monkeypatch, make_config_entry, dummy_coordinator
):
    """When _get_product_class returns None, release_url should fall back to the OPNsense UI changelog."""
    # ensure config entry has a base url for the fallback and a device id
    entry = make_config_entry(
        {
            CONF_DEVICE_UNIQUE_ID: "test-device-123",
            "url": "https://opnsense.example",
        }
    )
    coord = dummy_coordinator
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=coord,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )

    # arrange state where product_series and product_latest exist but product class will be None
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

    # Patch the instance method to return None to force the fallback branch
    monkeypatch.setattr(ent, "_get_product_class", lambda series: None)

    ent._handle_coordinator_update()

    expected = entry.data.get("url") + "/ui/core/firmware#changelog"
    assert ent.release_url == expected


def test_handle_coordinator_update_upgrade_sets_business_release_url(
    make_config_entry, dummy_coordinator
):
    """Business product series should generate business release URL."""
    entry = make_config_entry()
    coord = dummy_coordinator
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
                "product_version": "3.0.0",
                "product_latest": "3_0_1",
                "product_series": "2.4",
            },
            "upgrade_major_version": "2.4.1",
        }
    }
    ent.coordinator.data = state
    ent.async_write_ha_state = lambda: None
    ent._handle_coordinator_update()
    assert ent.release_url and "business/2.4" in ent.release_url
    assert "2.4.1" in ent.release_url


@pytest.mark.parametrize(
    "state,latest,product_version,expect_exact,expected",
    [
        (
            {
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
            },
            "1_0_1",
            None,
            False,
            "OPN",
        ),
        (
            {
                "firmware_update_info": {
                    "status": "upgrade",
                    "product": {"product_name": "OPN"},
                    "status_msg": "up",
                    "upgrade_needs_reboot": "1",
                }
            },
            "1_2_0",
            "1.2.0",
            False,
            "1.2.0",
        ),
        (
            {"firmware_update_info": {"status": "none", "status_msg": "nothing"}},
            None,
            None,
            True,
            "nothing",
        ),
    ],
)
def test_get_release_notes_variants(
    state, latest, product_version, expect_exact, expected, make_config_entry, dummy_coordinator
):
    """Parameterize release-notes generation for update/upgrade/default paths."""
    entry = make_config_entry()
    coord = dummy_coordinator
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=coord,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )
    ent.async_write_ha_state = lambda: None

    notes = ent._get_release_notes(
        state=state, product_latest=latest, product_version=product_version
    )
    if expect_exact:
        assert notes == expected
    else:
        assert expected in notes


@pytest.mark.asyncio
async def test_async_install_reboots_when_needed(monkeypatch, make_config_entry, dummy_coordinator):
    """async_install should trigger a reboot when the update requires it."""
    entry = make_config_entry()
    coord = dummy_coordinator
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
            # planned sequence: first 'running', then 'done'
            self._status_calls = [
                {"status": "running"},
                {"status": "done"},
            ]
            self.rebooted = False

        async def upgrade_firmware(self, upgrade_type):
            return {"started": True}

        async def upgrade_status(self):
            # placeholder; will be replaced by AsyncMock in test below
            return self._status_calls.pop(0)

        async def get_firmware_update_info(self):
            return {"needs_reboot": "1", "upgrade_needs_reboot": None}

        async def system_reboot(self):
            self.rebooted = True

    fake = FakeClient()
    # replace upgrade_status with an AsyncMock to track await calls and sequence
    fake.upgrade_status = AsyncMock(side_effect=fake._status_calls.copy())
    # wrap upgrade_firmware to assert it was awaited exactly once
    fake.upgrade_firmware = AsyncMock(wraps=fake.upgrade_firmware)
    ent._client = fake

    # provide coordinator state with firmware info and upgrade in progress
    ent.coordinator.data = {"firmware_update_info": {"status": "update"}}

    # speed up sleep and capture await count
    sleep_spy = AsyncMock(return_value=None)
    monkeypatch.setattr(asyncio, "sleep", sleep_spy)

    await ent.async_install()
    assert fake.rebooted is True
    # ensure polling occurred: upgrade_status should have been awaited twice (running -> done)
    assert fake.upgrade_status.await_count == 2
    fake.upgrade_firmware.assert_awaited_once_with("update")
    assert sleep_spy.await_count >= 1


@pytest.mark.asyncio
async def test_async_install_does_nothing_on_non_update_status(
    make_config_entry, dummy_coordinator
):
    """async_install should early-return and not call upgrade_firmware when status is not update/upgrade."""
    entry = make_config_entry()
    coord = dummy_coordinator
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=coord,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )
    ent.async_write_ha_state = lambda: None

    # non-update status
    ent.coordinator.data = {"firmware_update_info": {"status": "none"}}

    # attach a mock client and ensure upgrade_firmware is not called
    client = MagicMock()
    client.upgrade_firmware = AsyncMock()
    ent._client = client

    await ent.async_install()

    client.upgrade_firmware.assert_not_awaited()


@pytest.mark.asyncio
async def test_async_install_early_returns_and_no_client(
    monkeypatch, make_config_entry, dummy_coordinator
):
    """async_install should return early when there's no client available."""
    entry = make_config_entry()
    coord = dummy_coordinator
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


def test_get_versions_exception_path(monkeypatch, make_config_entry, dummy_coordinator):
    """_get_versions returns None tuple when underlying dict_get raises."""

    # force dict_get to raise so we hit the exception return

    entry = make_config_entry()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=dummy_coordinator,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )

    def raise_type(*args, **kwargs):
        raise TypeError("boom")

    monkeypatch.setattr(update_module, "dict_get", raise_type)
    pv, pl, ps = ent._get_versions({})
    assert pv is None and pl is None and ps is None


def test_get_release_notes_exception_path(monkeypatch, make_config_entry, dummy_coordinator):
    """_get_release_notes returns an unavailable message when dict_get raises."""

    entry = make_config_entry()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=dummy_coordinator,
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
async def test_async_install_exceptions_loop(monkeypatch, make_config_entry, dummy_coordinator):
    """async_install should handle exceptions and exit the install loop gracefully."""
    entry = make_config_entry()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=dummy_coordinator,
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


def test_get_installed_version_none_on_error(make_config_entry, dummy_coordinator):
    """_get_installed_version returns None on malformed or missing state."""

    entry = make_config_entry()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=dummy_coordinator,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )
    assert ent._get_installed_version({}) is None


@pytest.mark.asyncio
async def test_async_release_notes_returns_value(make_config_entry, dummy_coordinator):
    """async_release_notes returns generated release notes when state present."""

    entry = make_config_entry()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=dummy_coordinator,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )
    # Provide coordinator state that would generate release notes via the
    # entity's normal update handling instead of setting the private attr.
    state = {
        "firmware_update_info": {
            "status": "update",
            "product": {
                "product_version": "1_0_0",
                "product_latest": "1_0_1",
                "product_series": "2.1",
                "product_name": "OPN",
                "product_nickname": "OPN",
                "product_check": {"upgrade_packages": []},
            },
            "status_msg": "ok",
            "needs_reboot": "0",
            "all_packages": {},
            "new_packages": [],
            "reinstall_packages": [],
            "remove_packages": [],
            "upgrade_packages": [],
        }
    }
    ent.coordinator.data = state
    ent.async_write_ha_state = lambda: None
    # Populate internal fields as Home Assistant would via coordinator update
    ent._handle_coordinator_update()

    val = await ent.async_release_notes()
    assert val is not None
    assert "OPN" in val
