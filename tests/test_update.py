"""Unit tests for custom_components.opnsense.update."""

import asyncio
from collections.abc import Callable, MutableMapping
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

from aiopnsense.exceptions import OPNsenseError, OPNsenseTimeoutError
from homeassistant.components.update import UpdateDeviceClass, UpdateEntityDescription
from homeassistant.components.update.const import UpdateEntityFeature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.opnsense.const import (
    CONF_DEVICE_UNIQUE_ID,
    CONF_SYNC_FIRMWARE_UPDATES,
    COORDINATOR,
)
from custom_components.opnsense.update import (
    OPNsenseFirmwareUpdatesAvailableUpdate,
    async_setup_entry,
)


def _firmware_update_state(
    *,
    product_version: Any,
    product_latest: Any,
    product_series: Any,
    status: str = "update",
    upgrade_packages: Any = None,
    upgrade_major_version: Any = None,
) -> dict[str, Any]:
    """Build firmware update state for version parsing tests.

    Args:
        product_version: Installed product version value.
        product_latest: Latest product version value.
        product_series: Product series value.
        status: Firmware status value.
        upgrade_packages: Optional package check payload.
        upgrade_major_version: Optional major upgrade version.

    Returns:
        Firmware update state with the requested product and status payload.
    """
    firmware_update_info: dict[str, Any] = {
        "product": {
            "product_version": product_version,
            "product_latest": product_latest,
            "product_series": product_series,
        },
        "status": status,
    }
    if upgrade_packages is not None:
        firmware_update_info["product"]["product_check"] = {"upgrade_packages": upgrade_packages}
    if upgrade_major_version is not None:
        firmware_update_info["upgrade_major_version"] = upgrade_major_version
    return {"firmware_update_info": firmware_update_info}


class _FirmwareInstallClient:
    """Fake firmware client for update install flow tests."""

    def __init__(
        self,
        *,
        status_responses: list[Any] | None = None,
        status_response: Any = None,
        status_error: BaseException | None = None,
        firmware_info: dict[str, Any] | None = None,
    ) -> None:
        """Initialize a fake firmware install client.

        Args:
            status_responses: Queued responses returned by ``upgrade_status``.
            status_response: Repeated response returned by ``upgrade_status``.
            status_error: Error raised by ``upgrade_status``.
            firmware_info: Payload returned by ``get_firmware_update_info``.
        """
        self.status_responses = list(status_responses or [])
        self.status_response = status_response
        self.status_error = status_error
        self.firmware_info = firmware_info or {
            "needs_reboot": None,
            "upgrade_needs_reboot": None,
        }
        self.rebooted = False

    async def upgrade_firmware(self, _upgrade_type: Any) -> dict[str, Any]:
        """Simulate accepting an upgrade request before polling.

        Args:
            _upgrade_type: Upgrade mode requested by the entity and ignored by
                this fake client.

        Returns:
            Payload indicating that the upgrade request started.
        """
        return {"started": True}

    async def upgrade_status(self) -> Any:
        """Return or raise the configured polling result.

        Raises:
            BaseException: The configured ``status_error``, when provided.

        Returns:
            The next queued status response, or the configured repeated response.
        """
        if self.status_error is not None:
            raise self.status_error
        if self.status_responses:
            return self.status_responses.pop(0)
        return self.status_response

    async def get_firmware_update_info(self) -> dict[str, Any]:
        """Return configured firmware metadata.

        Returns:
            Firmware update metadata.
        """
        return self.firmware_info

    async def system_reboot(self) -> None:
        """Record that the update entity requested a system reboot."""
        self.rebooted = True


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
    setattr(entry.runtime_data, COORDINATOR, dummy_coordinator)
    added_entities: list[OPNsenseFirmwareUpdatesAvailableUpdate] = []

    def async_add_entities(
        entities: list[OPNsenseFirmwareUpdatesAvailableUpdate],
        _update_before_add: bool = False,
    ) -> None:
        """Capture entities added by the platform setup callback."""
        added_entities.extend(entities)

    await async_setup_entry(hass, entry, cast("AddEntitiesCallback", async_add_entities))

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
    setattr(entry.runtime_data, COORDINATOR, dummy_coordinator)
    added_entities: list[OPNsenseFirmwareUpdatesAvailableUpdate] = []

    def async_add_entities(
        entities: list[OPNsenseFirmwareUpdatesAvailableUpdate],
        _update_before_add: bool = False,
    ) -> None:
        """Capture entities added by the platform setup callback."""
        added_entities.extend(entities)

    await async_setup_entry(hass, entry, cast("AddEntitiesCallback", async_add_entities))

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


@pytest.mark.parametrize(
    ("state", "expected_latest"),
    [
        (
            _firmware_update_state(
                product_version="1_0_0",
                product_latest="1_0_0",
                product_series="1.0",
                upgrade_packages=[{"name": "not-opnsense"}],
            ),
            "1_0_0+",
        ),
        (
            _firmware_update_state(
                product_version="1.0.0",
                product_latest="1_0_0",
                product_series="1.0",
                upgrade_packages=[{"name": "opnsense", "new_version": "1_0_1"}],
            ),
            "1_0_1",
        ),
        (
            _firmware_update_state(
                product_version="1_0_0",
                product_latest="1_0_0",
                product_series="1.0",
                upgrade_packages=[{"name": "opnsense", "new_version": ""}],
            ),
            "1_0_0+",
        ),
        (
            _firmware_update_state(
                product_version="1.0.0",
                product_latest="1.0.0",
                product_series="1.0",
                upgrade_packages=[
                    object(),
                    {"name": "opnsense", "new_version": "1.0.1"},
                ],
            ),
            "1.0.1",
        ),
        (
            _firmware_update_state(
                product_version="1.0.0",
                product_latest="1.0.1",
                product_series="1.0",
                upgrade_packages=[
                    object(),
                    {"name": "kernel", "new_version": "1.0.2"},
                    {"name": "opnsense", "new_version": "1.0.2"},
                ],
            ),
            "1.0.2",
        ),
        (
            _firmware_update_state(
                product_version="1_0_0",
                product_latest="1_0_0",
                product_series="1.0",
            ),
            "1_0_0+",
        ),
        (
            _firmware_update_state(
                product_version="v1",
                product_latest=None,
                product_series="s1",
            ),
            None,
        ),
        (
            _firmware_update_state(
                product_version="2_0_0",
                product_latest="2_0_0",
                product_series="2.0",
                status="upgrade",
                upgrade_major_version="2.1.3",
            ),
            "2.1.3",
        ),
        (
            _firmware_update_state(
                product_version="2.0.0",
                product_latest="2.0.0",
                product_series="2.0",
                status="upgrade",
                upgrade_major_version="",
            ),
            "2.0.0",
        ),
    ],
)
def test_handle_coordinator_update_publishes_latest_version(
    state: dict[str, Any],
    expected_latest: str | None,
    make_config_entry: Callable[..., MockConfigEntry],
    dummy_coordinator: MagicMock,
) -> None:
    """Publish the expected latest version across representative firmware payloads."""
    entry = make_config_entry({"url": "https://opnsense.example"})
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=dummy_coordinator,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )
    ent.coordinator.data = state
    object.__setattr__(ent, "async_write_ha_state", lambda: None)
    ent._handle_coordinator_update()
    expected_published = expected_latest.replace("_", ".") if expected_latest else None
    assert ent.latest_version == expected_published


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
        pytest.param("1.9.0", "1_9_1", "1.9", "1.10.3", "business/1.10", id="business-1.10"),
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

    assert ent.latest_version == expected_latest_normalized

    notes = await ent.async_release_notes()
    assert notes is not None
    assert product_latest_input in notes
    assert ent.release_url is not None
    assert "community/2.1" in ent.release_url


def test_handle_coordinator_update_release_url_fallback_when_product_class_none(
    make_config_entry: Callable[..., MockConfigEntry],
    dummy_coordinator: MagicMock,
) -> None:
    """An unmapped firmware series should use the OPNsense UI changelog."""
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

    state = {
        "firmware_update_info": {
            "status": "update",
            "product": {
                "product_version": "2.0.0",
                "product_latest": "2_0_1",
                "product_series": "25.13",
            },
        }
    }
    ent.coordinator.data = state
    object.__setattr__(ent, "async_write_ha_state", lambda: None)

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
            "1_2_0",
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


def test_get_release_notes_upgrade_uses_target_version_in_header(
    make_config_entry: Callable[..., MockConfigEntry], dummy_coordinator: MagicMock
) -> None:
    """Upgrade release notes should use product_latest as the target version."""
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
        state={
            "firmware_update_info": {
                "status": "upgrade",
                "product": {"product_name": "OPN"},
                "status_msg": "up",
                "upgrade_needs_reboot": "1",
            }
        },
        product_latest="2_1_0",
        product_version="2.0.0",
    )
    assert notes is not None
    assert "## OPN version 2_1_0" in notes
    assert "2.0.0" not in notes


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

    status_responses = [{"status": "running"}, {"status": "done"}]
    fake: Any = _FirmwareInstallClient(
        status_responses=status_responses,
        firmware_info={"needs_reboot": "1", "upgrade_needs_reboot": None},
    )
    object.__setattr__(fake, "upgrade_status", AsyncMock(side_effect=status_responses))
    object.__setattr__(fake, "upgrade_firmware", AsyncMock(wraps=fake.upgrade_firmware))
    object.__setattr__(ent, "_client", fake)

    ent.coordinator.data = {"firmware_update_info": {"status": "update"}}

    sleep_spy = AsyncMock(return_value=None)
    monkeypatch.setattr(asyncio, "sleep", sleep_spy)

    await ent.async_install()
    assert fake.rebooted is True
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

    ent.coordinator.data = {"firmware_update_info": {"status": "none"}}

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

    ent.coordinator.data = cast("dict[str, Any]", None)
    await ent.async_install()

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
    assert pv is None
    assert pl is None
    assert ps is None


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
@pytest.mark.parametrize(
    "upgrade_status_response",
    [
        pytest.param(None, id="none-response"),
        pytest.param({}, id="missing-status"),
    ],
)
async def test_async_install_handles_masked_polling_response(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
    dummy_coordinator: MagicMock,
    upgrade_status_response: Any,
) -> None:
    """async_install should handle masked aiopnsense polling failures."""
    entry = make_config_entry()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=dummy_coordinator,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )

    bad: Any = _FirmwareInstallClient(status_response=upgrade_status_response)
    object.__setattr__(ent, "_client", bad)
    ent.coordinator.data = {"firmware_update_info": {"status": "update"}}
    monkeypatch.setattr(asyncio, "sleep", AsyncMock(return_value=None))

    await ent.async_install()
    assert bad.rebooted is False


@pytest.mark.asyncio
async def test_async_install_terminates_after_invalid_polling_responses(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
    dummy_coordinator: MagicMock,
) -> None:
    """Malformed polling responses should terminate without fetching info or rebooting."""
    entry = make_config_entry()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=dummy_coordinator,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )

    bad: Any = _FirmwareInstallClient(
        status_responses=[None, None, None, None],
        firmware_info={"needs_reboot": "1", "upgrade_needs_reboot": None},
    )
    object.__setattr__(bad, "upgrade_status", AsyncMock(side_effect=[None, None, None, None]))
    object.__setattr__(bad, "upgrade_firmware", AsyncMock(wraps=bad.upgrade_firmware))
    object.__setattr__(
        bad,
        "get_firmware_update_info",
        AsyncMock(wraps=bad.get_firmware_update_info),
    )
    object.__setattr__(ent, "_client", bad)
    ent.coordinator.data = {"firmware_update_info": {"status": "upgrade"}}
    monkeypatch.setattr(asyncio, "sleep", AsyncMock(return_value=None))

    await ent.async_install()

    bad.upgrade_status.assert_awaited()
    bad.upgrade_firmware.assert_awaited_once()
    bad.get_firmware_update_info.assert_not_awaited()
    assert bad.rebooted is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error_type", "message"),
    [
        pytest.param(OPNsenseTimeoutError, "fail", id="timeout"),
        pytest.param(OPNsenseError, "unexpected", id="generic"),
    ],
)
async def test_async_install_polling_error_raises(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
    dummy_coordinator: MagicMock,
    error_type: type[OPNsenseError],
    message: str,
) -> None:
    """async_install should not hide errors raised by aiopnsense while polling."""
    entry = make_config_entry()
    ent = OPNsenseFirmwareUpdatesAvailableUpdate(
        config_entry=entry,
        coordinator=dummy_coordinator,
        entity_description=UpdateEntityDescription(
            key="firmware.update_available", name="Firmware"
        ),
    )

    bad: Any = _FirmwareInstallClient(status_error=error_type(message))
    object.__setattr__(ent, "_client", bad)
    ent.coordinator.data = {"firmware_update_info": {"status": "update"}}
    monkeypatch.setattr(asyncio, "sleep", AsyncMock(return_value=None))

    with pytest.raises(error_type, match=message):
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
            "all_packages": ["base", "kernel"],
            "new_packages": [],
            "reinstall_packages": [],
            "remove_packages": [],
            "upgrade_packages": [],
        }
    }
    ent.coordinator.data = state
    object.__setattr__(ent, "async_write_ha_state", lambda: None)
    ent._handle_coordinator_update()

    val = await ent.async_release_notes()
    assert val is not None
    assert "OPN" in val
    assert "- total affected packages: 2" in val
