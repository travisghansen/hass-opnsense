"""Unit tests for custom_components.opnsense.update."""

import asyncio
from collections.abc import Callable, MutableMapping
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

from homeassistant.components.update import UpdateDeviceClass, UpdateEntityDescription
from homeassistant.components.update.const import UpdateEntityFeature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.opnsense import update as update_module
from custom_components.opnsense.const import CONF_DEVICE_UNIQUE_ID, CONF_SYNC_FIRMWARE_UPDATES
from custom_components.opnsense.update import OPNsenseFirmwareUpdatesAvailableUpdate


@pytest.mark.asyncio
async def test_async_setup_entry_adds_firmware_update_entity_contract(
    hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
    dummy_coordinator: MagicMock,
) -> None:
    """async_setup_entry creates the firmware update entity with its public contract."""
    entry = make_config_entry(
        {
            CONF_DEVICE_UNIQUE_ID: "test-device-123",
            CONF_SYNC_FIRMWARE_UPDATES: True,
        }
    )
    setattr(entry.runtime_data, update_module.COORDINATOR, dummy_coordinator)
    added_entities: list[OPNsenseFirmwareUpdatesAvailableUpdate] = []

    def async_add_entities(
        entities: list[OPNsenseFirmwareUpdatesAvailableUpdate],
        _update_before_add: bool = False,
    ) -> None:
        """Capture entities added by the platform setup callback."""
        added_entities.extend(entities)

    await update_module.async_setup_entry(
        hass, entry, cast("AddEntitiesCallback", async_add_entities)
    )

    assert len(added_entities) == 1
    entity = added_entities[0]
    assert isinstance(entity, OPNsenseFirmwareUpdatesAvailableUpdate)
    assert entity.entity_description.key == "firmware.update_available"
    assert entity.entity_description.name == "Firmware Updates Available"
    assert entity.entity_description.entity_category is EntityCategory.DIAGNOSTIC
    assert entity.entity_description.device_class is UpdateDeviceClass.FIRMWARE
    assert entity.entity_description.entity_registry_enabled_default is True
    assert entity.supported_features == (
        UpdateEntityFeature.INSTALL | UpdateEntityFeature.RELEASE_NOTES
    )


@pytest.mark.asyncio
async def test_async_setup_entry_skips_disabled_firmware_update_sync(
    hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
    dummy_coordinator: MagicMock,
) -> None:
    """async_setup_entry should not add firmware entities when sync is disabled."""
    entry = make_config_entry(
        {
            CONF_DEVICE_UNIQUE_ID: "test-device-123",
            CONF_SYNC_FIRMWARE_UPDATES: False,
        }
    )
    setattr(entry.runtime_data, update_module.COORDINATOR, dummy_coordinator)
    added_entities: list[OPNsenseFirmwareUpdatesAvailableUpdate] = []

    def async_add_entities(
        entities: list[OPNsenseFirmwareUpdatesAvailableUpdate],
        _update_before_add: bool = False,
    ) -> None:
        """Capture entities added by the platform setup callback."""
        added_entities.extend(entities)

    await update_module.async_setup_entry(
        hass, entry, cast("AddEntitiesCallback", async_add_entities)
    )

    assert added_entities == []


@pytest.mark.parametrize(
    "coordinator_data",
    [
        pytest.param(None, id="missing"),
        pytest.param({"firmware_update_info": []}, id="non-mapping-info"),
        pytest.param({"firmware_update_info": {"status": "error"}}, id="error-status"),
        pytest.param({"firmware_update_info": {}}, id="missing-status"),
        pytest.param({"firmware_update_info": {"status": 1}}, id="non-string-status"),
        pytest.param({"firmware_update_info": {"status": ""}}, id="empty-status"),
    ],
)
def test_is_update_available_false_for_missing_or_error_state(
    coordinator_data: dict[str, Any] | None,
    make_config_entry: Callable[..., MockConfigEntry],
    dummy_coordinator: MagicMock,
) -> None:
    """Update entity should be unavailable when firmware update state is unusable."""
    entry = make_config_entry(
        {
            "url": "https://opnsense.example",
            CONF_DEVICE_UNIQUE_ID: "test-device-123",
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
    object.__setattr__(ent, "async_write_ha_state", lambda: None)

    coord.data = coordinator_data
    ent._handle_coordinator_update()
    assert ent.available is False


@pytest.mark.parametrize(
    "status",
    ["none", "update", "upgrade"],
)
def test_is_update_available_true_for_valid_status(
    status: str,
    make_config_entry: Callable[..., MockConfigEntry],
    dummy_coordinator: MagicMock,
) -> None:
    """Valid firmware statuses should keep the update entity available."""
    entry = make_config_entry(
        {
            "url": "https://opnsense.example",
            CONF_DEVICE_UNIQUE_ID: "test-device-123",
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
    object.__setattr__(ent, "async_write_ha_state", lambda: None)

    coord.data = {"firmware_update_info": {"status": status}}
    ent._handle_coordinator_update()
    assert ent.available is True


def test_affected_package_count_counts_lists() -> None:
    """Affected package count should count list-shaped package collections."""
    assert update_module._affected_package_count(["base", "kernel"]) == 2


@pytest.mark.parametrize(
    ("state_builder", "expect_latest", "expect_series", "expect_latest_condition"),
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
                        "product_version": "1.0.0",
                        "product_latest": "1.0.0",
                        "product_series": "1.0",
                        "product_check": {
                            "upgrade_packages": [
                                object(),
                                {"name": "opnsense", "new_version": "1.0.1"},
                            ]
                        },
                    },
                    "status": "update",
                }
            },
            "1.0.1",
            "1.0",
            lambda latest: latest == "1.0.1",
        ),
        (
            lambda: {
                "firmware_update_info": {
                    "product": {
                        "product_version": "1.0.0",
                        "product_latest": "1.0.1",
                        "product_series": "1.0",
                        "product_check": {
                            "upgrade_packages": [
                                object(),
                                {"name": "kernel", "new_version": "1.0.2"},
                                {"name": "opnsense", "new_version": "1.0.2"},
                            ]
                        },
                    },
                    "status": "update",
                }
            },
            "1.0.2",
            "1.0",
            lambda latest: latest == "1.0.2",
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
        (
            lambda: {
                "firmware_update_info": {
                    "status": "upgrade",
                    "product": {
                        "product_version": "2.0.0",
                        "product_latest": "2.0.0",
                        "product_series": "2.0",
                    },
                    "upgrade_major_version": "",
                }
            },
            "2.0.0",
            "2.0",
            lambda latest: latest == "2.0.0",
        ),
    ],
)
def test_get_versions_scenarios(
    state_builder: Any,
    expect_latest: Any,
    expect_series: Any,
    expect_latest_condition: Any,
    make_config_entry: Callable[..., MockConfigEntry],
    dummy_coordinator: MagicMock,
) -> None:
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
    _pv, pl, ps = ent._get_versions(state)
    assert ps == expect_series
    if expect_latest is not None:
        assert pl == expect_latest
    assert expect_latest_condition(pl)


@pytest.mark.parametrize(
    ("series", "expected"),
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
    series: str | None,
    expected: Any,
    make_config_entry: Callable[..., MockConfigEntry],
    dummy_coordinator: MagicMock,
) -> None:
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


def test_handle_coordinator_update_sets_attributes(
    make_config_entry: Callable[..., MockConfigEntry], dummy_coordinator: MagicMock
) -> None:
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
    object.__setattr__(ent, "async_write_ha_state", lambda: None)
    ent._handle_coordinator_update()
    assert ent.available is True
    assert ent.installed_version == "1_0_0"
    assert ent.latest_version == "1.0.2"
    assert ent.release_summary == "ok"
    # extra state attributes are created from firmware_update_info keys (top-level ones)
    attrs = ent.extra_state_attributes
    assert attrs is not None
    assert "opnsense_download_size" in attrs
    assert attrs.get("opnsense_download_size") == 123
    assert attrs.get("opnsense_last_check") == 1


@pytest.mark.parametrize(
    (
        "product_version",
        "product_latest",
        "product_series",
        "upgrade_major_version",
        "expected_url_path",
    ),
    [
        pytest.param("2.0.0", "2_0_1", "2.1", "2.1.3", "community/2.1", id="community"),
        pytest.param("3.0.0", "3_0_1", "2.4", "2.4.1", "business/2.4", id="business"),
    ],
)
def test_handle_coordinator_update_upgrade_sets_release_url(
    product_version: str,
    product_latest: str,
    product_series: str,
    upgrade_major_version: str,
    expected_url_path: str,
    make_config_entry: Callable[..., MockConfigEntry],
    dummy_coordinator: MagicMock,
) -> None:
    """Upgrade state should compute a release URL and provide release notes.

    This also asserts correct product class derivation from ``product_series``,
    which affects the generated release URL.
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
                "product_version": product_version,
                "product_latest": product_latest,
                "product_series": product_series,
            },
            "upgrade_major_version": upgrade_major_version,
        }
    }
    ent.coordinator.data = state
    object.__setattr__(ent, "async_write_ha_state", lambda: None)
    ent._handle_coordinator_update()

    assert ent.latest_version == upgrade_major_version

    assert ent.release_url is not None
    assert expected_url_path in ent.release_url
    assert upgrade_major_version in ent.release_url


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("product_latest_input", "expected_latest_normalized"),
    [("2_0_1", "2.0.1"), ("2.0.1", "2.0.1")],
)
async def test_handle_coordinator_update_update_normalizes_product_latest(
    product_latest_input: str,
    expected_latest_normalized: str,
    make_config_entry: Callable[..., MockConfigEntry],
    dummy_coordinator: MagicMock,
) -> None:
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
    object.__setattr__(ent, "async_write_ha_state", lambda: None)
    ent._handle_coordinator_update()

    # product_latest should be normalized into latest_version
    assert ent.latest_version == expected_latest_normalized

    # release notes are currently generated from the raw product_latest value
    # (the entity stores a normalized latest_version separately), so verify
    # the original input appears in the notes and the normalized value is
    # available on the entity
    notes = await ent.async_release_notes()
    assert notes is not None
    assert product_latest_input in notes
    # series '2.1' -> community mapping reflected in path
    assert ent.release_url is not None
    assert "community/2.1" in ent.release_url


def test_handle_coordinator_update_release_url_fallback_when_product_class_none(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
    dummy_coordinator: MagicMock,
) -> None:
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
    object.__setattr__(ent, "async_write_ha_state", lambda: None)

    # Patch the instance method to return None to force the fallback branch
    monkeypatch.setattr(ent, "_get_product_class", lambda series: None)

    ent._handle_coordinator_update()

    expected = entry.data.get("url") + "/ui/core/firmware#changelog"
    assert ent.release_url == expected


@pytest.mark.parametrize(
    ("state", "latest", "product_version", "expect_exact", "expected"),
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
    state: MutableMapping[str, Any],
    latest: str | None,
    product_version: str | None,
    expect_exact: bool,
    expected: Any,
    make_config_entry: Callable[..., MockConfigEntry],
    dummy_coordinator: MagicMock,
) -> None:
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
    object.__setattr__(ent, "async_write_ha_state", lambda: None)

    notes = ent._get_release_notes(
        state=state, product_latest=latest, product_version=product_version
    )
    if expect_exact:
        assert notes == expected
    else:
        assert notes is not None
        assert expected in notes


@pytest.mark.asyncio
async def test_async_install_reboots_when_needed(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
    dummy_coordinator: MagicMock,
) -> None:
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
    object.__setattr__(ent, "async_write_ha_state", lambda: None)

    class FakeClient:
        """Fake firmware client for a successful install flow."""

        def __init__(self) -> None:
            # planned sequence: first 'running', then 'done'
            """Initialize a fake client that simulates a successful update flow."""
            self._status_calls = [
                {"status": "running"},
                {"status": "done"},
            ]
            self.rebooted = False

        async def upgrade_firmware(self, _upgrade_type: Any) -> dict[str, Any]:
            """Simulate starting a firmware upgrade request.

            Args:
                _upgrade_type: Upgrade mode requested by the entity and ignored by this fake client.

            Returns:
                dict[str, Any]: Payload indicating that the upgrade request started.
            """
            return {"started": True}

        async def upgrade_status(self) -> dict[str, str]:
            """Return the next queued upgrade status payload.

            Returns:
                dict[str, str]: The next queued upgrade status response.
            """
            return self._status_calls.pop(0)

        async def get_firmware_update_info(self) -> dict[str, Any]:
            """Return update metadata indicating that a reboot is required.

            Returns:
                dict[str, Any]: Firmware update metadata that requires a reboot.
            """
            return {"needs_reboot": "1", "upgrade_needs_reboot": None}

        async def system_reboot(self) -> None:
            """Record that the update entity requested a system reboot."""
            self.rebooted = True

    fake: Any = FakeClient()
    # replace upgrade_status with an AsyncMock to track await calls and sequence
    object.__setattr__(fake, "upgrade_status", AsyncMock(side_effect=fake._status_calls.copy()))
    # wrap upgrade_firmware to assert it was awaited exactly once
    object.__setattr__(fake, "upgrade_firmware", AsyncMock(wraps=fake.upgrade_firmware))
    object.__setattr__(ent, "_client", fake)

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
    assert 1 <= sleep_spy.await_count <= 5


@pytest.mark.asyncio
async def test_async_install_does_nothing_on_non_update_status(
    make_config_entry: Callable[..., MockConfigEntry], dummy_coordinator: MagicMock
) -> None:
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
    object.__setattr__(ent, "async_write_ha_state", lambda: None)

    # non-update status
    ent.coordinator.data = {"firmware_update_info": {"status": "none"}}

    # attach a mock client and ensure upgrade_firmware is not called
    client = MagicMock()
    object.__setattr__(client, "upgrade_firmware", AsyncMock())
    ent._client = client

    await ent.async_install()

    client.upgrade_firmware.assert_not_awaited()


@pytest.mark.asyncio
async def test_async_install_early_returns_and_no_client(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
    dummy_coordinator: MagicMock,
) -> None:
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
    object.__setattr__(ent, "async_write_ha_state", lambda: None)

    # state not mapping
    ent.coordinator.data = cast("dict[str, Any]", None)
    await ent.async_install()

    # state present but no client
    ent.coordinator.data = {"firmware_update_info": {"status": "update"}}
    object.__setattr__(ent, "_client", None)
    await ent.async_install()


def test_get_versions_malformed_state_returns_empty_versions(
    make_config_entry: Callable[..., MockConfigEntry],
    dummy_coordinator: MagicMock,
) -> None:
    """_get_versions returns empty version data for malformed firmware state."""
    entry = make_config_entry()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=dummy_coordinator,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )

    pv, pl, ps = ent._get_versions({"firmware_update_info": []})
    assert pv is None and pl is None and ps is None


def test_get_release_notes_malformed_state_returns_none(
    make_config_entry: Callable[..., MockConfigEntry],
    dummy_coordinator: MagicMock,
) -> None:
    """_get_release_notes returns None for malformed firmware state."""
    entry = make_config_entry()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=dummy_coordinator,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )

    assert ent._get_release_notes({"firmware_update_info": []}, None, None) is None


@pytest.mark.asyncio
async def test_async_install_exceptions_loop(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
    dummy_coordinator: MagicMock,
) -> None:
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
        """Fake firmware client that raises retryable polling errors."""

        def __init__(self) -> None:
            """Initialize a fake client that fails during upgrade polling."""
            self.rebooted = False

        async def upgrade_firmware(self, _upgrade_type: Any) -> dict[str, Any]:
            """Simulate accepting an upgrade request before polling fails.

            Args:
                _upgrade_type: Upgrade mode requested by the entity and ignored by this fake client.

            Returns:
                dict[str, Any]: Payload indicating that the upgrade request started.
            """
            return {"started": True}

        async def upgrade_status(self) -> dict[str, Any]:
            """Raise a timeout error while the entity polls upgrade status.

            Raises:
                TimeoutError: Always raised to exercise the entity's exception
                    handling path.

            Returns:
                dict[str, Any]: This method never returns normally.
            """
            raise TimeoutError("fail")

        async def get_firmware_update_info(self) -> dict[str, Any]:
            """Return update metadata showing that no reboot is required.

            Returns:
                dict[str, Any]: Firmware update metadata that does not require a reboot.
            """
            return {"needs_reboot": None, "upgrade_needs_reboot": None}

        async def system_reboot(self) -> None:
            """Record whether a reboot was incorrectly requested after failure."""
            self.rebooted = True

    bad: Any = BadClient()
    object.__setattr__(ent, "_client", bad)
    ent.coordinator.data = {"firmware_update_info": {"status": "update"}}
    monkeypatch.setattr(asyncio, "sleep", AsyncMock(return_value=None))

    await ent.async_install()
    assert bad.rebooted is False


@pytest.mark.asyncio
async def test_async_install_unexpected_polling_error_raises(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
    dummy_coordinator: MagicMock,
) -> None:
    """async_install should not hide unexpected polling errors."""
    entry = make_config_entry()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=dummy_coordinator,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )

    class BadClient:
        """Fake firmware client that raises an unexpected polling error."""

        async def upgrade_firmware(self, _upgrade_type: Any) -> dict[str, Any]:
            """Simulate accepting an upgrade request before polling fails.

            Args:
                _upgrade_type: Upgrade mode requested by the entity and ignored by this fake client.

            Returns:
                dict[str, Any]: Payload indicating that the upgrade request started.
            """
            return {"started": True}

        async def upgrade_status(self) -> dict[str, Any]:
            """Raise an unexpected polling error.

            Raises:
                RuntimeError: Always raised to verify unexpected errors are not
                    handled as retryable polling errors.

            Returns:
                dict[str, Any]: This method never returns normally.
            """
            raise RuntimeError("unexpected")

    bad: Any = BadClient()
    object.__setattr__(ent, "_client", bad)
    ent.coordinator.data = {"firmware_update_info": {"status": "update"}}
    monkeypatch.setattr(asyncio, "sleep", AsyncMock(return_value=None))

    with pytest.raises(RuntimeError, match="unexpected"):
        await ent.async_install()


def test_get_installed_version_none_on_error(
    make_config_entry: Callable[..., MockConfigEntry], dummy_coordinator: MagicMock
) -> None:
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
async def test_async_release_notes_returns_value(
    make_config_entry: Callable[..., MockConfigEntry], dummy_coordinator: MagicMock
) -> None:
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
    object.__setattr__(ent, "async_write_ha_state", lambda: None)
    # Populate internal fields as Home Assistant would via coordinator update
    ent._handle_coordinator_update()

    val = await ent.async_release_notes()
    assert val is not None
    assert "OPN" in val
