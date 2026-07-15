"""Unit tests for the integration package initialization and lifecycle helpers.

These tests exercise async_setup_entry, migration helpers, update listeners,
and removal/unload behaviors for the hass-opnsense integration.
"""

from collections.abc import Callable
from dataclasses import dataclass
import logging
from typing import Any, Never, cast
from unittest.mock import ANY, AsyncMock, MagicMock, call

from aiopnsense.exceptions import (
    OPNsenseBelowMinFirmware,
    OPNsenseConnectionError,
    OPNsenseInvalidAuth,
    OPNsenseInvalidURL,
    OPNsensePrivilegeMissing,
    OPNsenseSSLError,
    OPNsenseTimeoutError,
    OPNsenseUnknownFirmware,
)
from homeassistant.const import CONF_PASSWORD, CONF_URL, CONF_USERNAME, CONF_VERIFY_SSL, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.util import slugify
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

import custom_components.opnsense as opnsense_mod
from custom_components.opnsense.const import (
    CONF_ENTRY_TYPE,
    CONF_GRANULAR_SYNC_OPTIONS,
    CONF_SYNC_FIREWALL_AND_NAT,
    CONF_TLS_INSECURE,
    ENTRY_TYPE_CARP,
)
from tests.utilities import patch_opnsense_client

init_mod: Any = opnsense_mod


@dataclass(slots=True)
class _RegistryEntity:
    """Minimal entity-registry record for migration and listener tests."""

    entity_id: str
    unique_id: str


def _make_valid_setup_client() -> MagicMock:
    """Create a valid OPNsense client mock for setup-entry lifecycle tests."""
    client = MagicMock()
    client.validate = AsyncMock(return_value=True)
    client.get_device_unique_id = AsyncMock(return_value="dev1")
    client.get_host_firmware_version = AsyncMock(return_value="99.0")
    client.async_close = AsyncMock(return_value=True)
    return client


def _make_setup_coordinator() -> MagicMock:
    """Create a coordinator mock that succeeds initial setup and supports shutdown."""
    coordinator = MagicMock()
    coordinator.async_config_entry_first_refresh = AsyncMock(return_value=True)
    coordinator.async_shutdown = AsyncMock(return_value=True)
    return coordinator


def test_align_aiopnsense_log_level_mirrors_opnsense_when_unset() -> None:
    """Aiopnsense should inherit the integration debug level when not configured."""
    opnsense_logger = logging.getLogger("custom_components.opnsense")
    aiopnsense_logger = logging.getLogger("aiopnsense")
    aiopnsense_helper_logger = logging.getLogger("aiopnsense.helpers")
    original_opnsense_level = opnsense_logger.level
    original_aiopnsense_level = aiopnsense_logger.level
    original_aiopnsense_helper_level = aiopnsense_helper_logger.level

    try:
        opnsense_logger.setLevel(logging.DEBUG)
        aiopnsense_logger.setLevel(logging.NOTSET)
        aiopnsense_helper_logger.setLevel(logging.NOTSET)

        init_mod._align_aiopnsense_log_level()

        assert aiopnsense_logger.level == logging.DEBUG
        assert aiopnsense_helper_logger.getEffectiveLevel() == logging.DEBUG
    finally:
        opnsense_logger.setLevel(original_opnsense_level)
        aiopnsense_logger.setLevel(original_aiopnsense_level)
        aiopnsense_helper_logger.setLevel(original_aiopnsense_helper_level)


@pytest.mark.parametrize(
    ("opnsense_level", "aiopnsense_level", "expected_level"),
    [
        pytest.param(logging.DEBUG, logging.WARNING, logging.WARNING, id="explicit-aiopnsense"),
        pytest.param(logging.NOTSET, logging.NOTSET, logging.NOTSET, id="both-unset"),
    ],
)
def test_align_aiopnsense_log_level_preserves_setting(
    opnsense_level: int,
    aiopnsense_level: int,
    expected_level: int,
) -> None:
    """Aiopnsense logger settings should remain authoritative when already set."""
    opnsense_logger = logging.getLogger("custom_components.opnsense")
    aiopnsense_logger = logging.getLogger("aiopnsense")
    original_opnsense_level = opnsense_logger.level
    original_aiopnsense_level = aiopnsense_logger.level

    try:
        opnsense_logger.setLevel(opnsense_level)
        aiopnsense_logger.setLevel(aiopnsense_level)

        init_mod._align_aiopnsense_log_level()

        assert aiopnsense_logger.level == expected_level
    finally:
        opnsense_logger.setLevel(original_opnsense_level)
        aiopnsense_logger.setLevel(original_aiopnsense_level)


@pytest.mark.asyncio
async def test_async_setup_entry_success(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_client: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry should succeed with valid client and coordinator."""
    patch_opnsense_client(monkeypatch, init_mod, fake_client())
    # use shared coordinator capture fixture
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    # create a minimal config entry using the shared helper so all fields
    # (data, options, title, entry_id, unique_id, listeners) are set
    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={},
    )

    # use migration fixture which may wrap the real hass or provide a MagicMock
    hass = cast("MagicMock", ph_hass)
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)  # type: ignore[method-assign]
    hass.config_entries.async_reload = AsyncMock()  # type: ignore[method-assign]

    # ensure hass.data is a real dict for the integration to populate
    hass.data = {}

    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True
    assert init_mod.DOMAIN in hass.data and entry.entry_id in hass.data[init_mod.DOMAIN]


@pytest.mark.asyncio
async def test_async_setup_entry_validates_client_before_probes(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry should validate the client before device/firmware probes."""
    probe_calls: list[str] = []
    client = MagicMock()
    client.name = "test-router"
    client.validate = AsyncMock(side_effect=lambda: probe_calls.append("validate"))

    async def _get_device_unique_id(expected_id: str | None = None) -> str:
        """Return test router device id after recording probe ordering."""
        probe_calls.append("get_device_unique_id")
        return "dev1"

    async def _get_host_firmware_version() -> str:
        """Return test firmware after recording probe ordering."""
        probe_calls.append("get_host_firmware_version")
        return "99.0"

    client.get_device_unique_id = _get_device_unique_id
    client.get_host_firmware_version = _get_host_firmware_version
    client.async_close = AsyncMock(return_value=True)

    def _create_client(**kwargs: Any) -> Any:
        """Return the probe-tracking client used by this setup-entry test."""
        return client

    monkeypatch.setattr(init_mod, "create_opnsense_client_from_config_entry", _create_client)
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={},
    )

    hass = cast("MagicMock", ph_hass)
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True
    assert probe_calls == [
        "validate",
        "get_device_unique_id",
        "get_host_firmware_version",
    ]
    assert entry.runtime_data.device_unique_id == "dev1"
    expected_platforms = [Platform.SENSOR, Platform.SWITCH, Platform.BINARY_SENSOR, Platform.UPDATE]
    assert entry.runtime_data.loaded_platforms == expected_platforms


@pytest.mark.asyncio
async def test_async_setup_entry_carp_entry_uses_identity_less_runtime(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP entries use identity-less coordinator state and Sensor-only platform setup."""
    validate_calls: list[dict[str, Any]] = []
    create_calls: dict[str, Any] = {}
    client = MagicMock()
    client.get_host_firmware_version = AsyncMock(return_value="99.0")

    async def _validate(**kwargs: Any) -> bool:
        """Record setup validation kwargs and return successful validation."""
        validate_calls.append(kwargs)
        return True

    client.validate = _validate
    client.get_device_unique_id = AsyncMock(return_value="ignore-me")
    client.async_close = AsyncMock(return_value=True)

    def _create_client(**kwargs: Any) -> Any:
        """Record how the client factory is called and return the fake client."""
        create_calls.update(kwargs)
        return client

    monkeypatch.setattr(init_mod, "create_opnsense_client_from_config_entry", _create_client)

    captured = {}

    class _CarpCoordinator:
        """Fake coordinator used to exercise CARP setup without polling."""

        def __init__(self, **kwargs: Any) -> None:
            """Capture coordinator construction kwargs for CARP assertions."""
            captured.update(kwargs)
            self.data = {"carp": {"interfaces": [{"vhid": 1, "subnet": "192.0.2.1"}]}}

        async def async_config_entry_first_refresh(self) -> bool:
            """Complete the coordinator's initial refresh protocol."""
            return True

        async def async_shutdown(self) -> bool:
            """Complete the coordinator's shutdown protocol."""
            return True

    monkeypatch.setattr(init_mod, "OPNsenseDataUpdateCoordinator", _CarpCoordinator)

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            CONF_ENTRY_TYPE: ENTRY_TYPE_CARP,
        },
        options={},
    )

    hass = cast("MagicMock", ph_hass)
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)  # type: ignore[method-assign]
    hass.config_entries.async_reload = MagicMock()  # type: ignore[method-assign]
    hass.data = {}

    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True
    assert create_calls.get("hass") is hass
    assert create_calls.get("config_entry") is entry
    assert create_calls.get("throw_errors", False) is False
    assert captured["device_unique_id"] is None
    assert captured["config_entry"] is entry
    assert validate_calls == [{"require_device_id": False}]
    client.get_device_unique_id.assert_not_awaited()
    client.get_host_firmware_version.assert_not_awaited()

    assert entry.runtime_data.device_unique_id is None
    assert entry.runtime_data.loaded_platforms == init_mod.CARP_PLATFORMS
    assert entry.runtime_data.device_tracker_coordinator is None
    assert hass.config_entries.async_forward_entry_setups.await_count == 1  # type: ignore[union-attr]
    hass.config_entries.async_forward_entry_setups.assert_awaited_with(entry, [Platform.SENSOR])  # type: ignore[union-attr]


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", [OPNsenseBelowMinFirmware, OPNsenseUnknownFirmware])
async def test_async_setup_entry_carp_validation_firmware_errors_fail_setup(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
    exc: type[Exception],
) -> None:
    """CARP setup must fail fast on firmware validation exceptions."""
    coordinator = AsyncMock()
    coordinator.async_config_entry_first_refresh = AsyncMock(return_value=True)
    coordinator.async_shutdown = AsyncMock(return_value=True)
    coordinator.data = {"carp": {"interfaces": [{"vhid": 1, "subnet": "192.0.2.1"}]}}
    coordinator_factory = MagicMock(return_value=coordinator)
    client = MagicMock()
    client.validate = AsyncMock(side_effect=exc("firmware"))
    client.async_close = AsyncMock(return_value=True)
    monkeypatch.setattr(
        init_mod, "create_opnsense_client_from_config_entry", lambda **_kwargs: client
    )
    monkeypatch.setattr(init_mod, "OPNsenseDataUpdateCoordinator", coordinator_factory)

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            CONF_ENTRY_TYPE: ENTRY_TYPE_CARP,
        },
        options={},
    )

    hass = ph_hass
    hass.data = {}
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)

    with pytest.raises(exc):
        await init_mod.async_setup_entry(hass, entry)

    coordinator_factory.assert_not_called()
    hass.config_entries.async_forward_entry_setups.assert_not_awaited()
    client.async_close.assert_awaited_once()


@pytest.mark.parametrize(
    "exc",
    [OPNsenseTimeoutError, OPNsenseConnectionError],
    ids=["timeout", "connection"],
)
@pytest.mark.asyncio
async def test_async_setup_entry_carp_entry_retries_on_transient_validation_failures(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
    exc: type[BaseException],
) -> None:
    """CARP setup should retry on transient validation transport failures."""
    client = MagicMock()
    client.validate = AsyncMock(side_effect=exc("transient"))
    client.async_close = AsyncMock(return_value=True)

    create_client = MagicMock(return_value=client)
    coordinator_factory = MagicMock()
    monkeypatch.setattr(init_mod, "create_opnsense_client_from_config_entry", create_client)
    monkeypatch.setattr(init_mod, "OPNsenseDataUpdateCoordinator", coordinator_factory)

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            CONF_ENTRY_TYPE: ENTRY_TYPE_CARP,
        },
        options={},
    )

    hass = cast("MagicMock", ph_hass)
    hass.data = {}

    with pytest.raises(ConfigEntryNotReady):
        await init_mod.async_setup_entry(hass, entry)

    coordinator_factory.assert_not_called()
    create_client.assert_called_once()
    client.async_close.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_setup_entry_carp_reraises_connection_error_subclass(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP setup must preserve specialized connection failures."""

    class SpecializedConnectionError(OPNsenseConnectionError):
        """Connection failure carrying more specific client semantics."""

    client = MagicMock()
    client.validate = AsyncMock(side_effect=SpecializedConnectionError("specialized"))
    client.async_close = AsyncMock(return_value=True)
    monkeypatch.setattr(
        init_mod, "create_opnsense_client_from_config_entry", MagicMock(return_value=client)
    )

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            CONF_ENTRY_TYPE: ENTRY_TYPE_CARP,
        },
        options={},
    )
    hass = cast("MagicMock", ph_hass)
    hass.data = {}

    with pytest.raises(SpecializedConnectionError, match="specialized"):
        await init_mod.async_setup_entry(hass, entry)

    client.async_close.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "initial_data",
    [
        {},
        {"carp": {}},
        {"carp": {"interfaces": []}},
        {"carp": {"interfaces": [{}]}},
    ],
)
async def test_async_setup_entry_carp_requires_usable_initial_vip_inventory(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
    initial_data: dict[str, Any],
) -> None:
    """CARP setup should retry when the first refresh has no usable VIP inventory."""
    client = _make_valid_setup_client()
    monkeypatch.setattr(
        init_mod, "create_opnsense_client_from_config_entry", lambda **_kwargs: client
    )
    coordinator = _make_setup_coordinator()
    coordinator.data = initial_data
    monkeypatch.setattr(init_mod, "OPNsenseDataUpdateCoordinator", lambda **_kwargs: coordinator)

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            CONF_ENTRY_TYPE: ENTRY_TYPE_CARP,
        },
        options={},
    )
    hass = ph_hass
    hass.data = {init_mod.DOMAIN: {entry.entry_id: client}}
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)

    with pytest.raises(ConfigEntryNotReady, match="usable CARP VIP"):
        await init_mod.async_setup_entry(hass, entry)

    coordinator.async_shutdown.assert_awaited_once()
    client.async_close.assert_awaited_once()
    assert entry.entry_id not in hass.data.get(init_mod.DOMAIN, {})
    hass.config_entries.async_forward_entry_setups.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "interface",
    [
        {"vhid": 1, "subnet": "192.0.2.1"},
        {"vhid": " 2 ", "subnet": " 192.0.2.2 "},
    ],
)
async def test_async_setup_entry_carp_accepts_usable_initial_vip_inventory(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
    interface: dict[str, Any],
) -> None:
    """CARP setup should forward platforms when the first inventory has a usable VIP."""
    client = _make_valid_setup_client()
    monkeypatch.setattr(
        init_mod, "create_opnsense_client_from_config_entry", lambda **_kwargs: client
    )
    coordinator = _make_setup_coordinator()
    coordinator.data = {"carp": {"interfaces": [interface]}}
    monkeypatch.setattr(init_mod, "OPNsenseDataUpdateCoordinator", lambda **_kwargs: coordinator)

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            CONF_ENTRY_TYPE: ENTRY_TYPE_CARP,
        },
        options={},
    )
    hass = ph_hass
    hass.data = {}
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)

    assert await init_mod.async_setup_entry(hass, entry) is True

    coordinator.async_shutdown.assert_not_awaited()
    client.async_close.assert_not_awaited()
    hass.config_entries.async_forward_entry_setups.assert_awaited_once_with(
        entry, [Platform.SENSOR]
    )


@pytest.mark.asyncio
async def test_async_setup_entry_carp_first_refresh_failure_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP setup should stop its coordinator, close the client, and remove hass data."""
    client = _make_valid_setup_client()
    monkeypatch.setattr(
        init_mod, "create_opnsense_client_from_config_entry", lambda **_kwargs: client
    )
    coordinator = _make_setup_coordinator()
    coordinator.async_config_entry_first_refresh.side_effect = RuntimeError("refresh failed")
    coordinator.data = {"carp": {"interfaces": [{"vhid": 1, "subnet": "192.0.2.1"}]}}
    monkeypatch.setattr(init_mod, "OPNsenseDataUpdateCoordinator", lambda **_kwargs: coordinator)

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            CONF_ENTRY_TYPE: ENTRY_TYPE_CARP,
        },
        options={},
    )
    hass = ph_hass
    hass.data = {init_mod.DOMAIN: {entry.entry_id: client}}
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)

    with pytest.raises(RuntimeError, match="refresh failed"):
        await init_mod.async_setup_entry(hass, entry)

    coordinator.async_shutdown.assert_awaited_once()
    client.async_close.assert_awaited_once()
    assert entry.entry_id not in hass.data.get(init_mod.DOMAIN, {})
    hass.config_entries.async_forward_entry_setups.assert_not_awaited()


@pytest.mark.asyncio
async def test_async_setup_entry_carp_platform_forward_failure_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP platform-forward failures should clean up runtime state and the client."""
    client = _make_valid_setup_client()
    monkeypatch.setattr(
        init_mod, "create_opnsense_client_from_config_entry", lambda **_kwargs: client
    )
    coordinator = _make_setup_coordinator()
    coordinator.data = {"carp": {"interfaces": [{"vhid": 1, "subnet": "192.0.2.1"}]}}
    monkeypatch.setattr(init_mod, "OPNsenseDataUpdateCoordinator", lambda **_kwargs: coordinator)

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            CONF_ENTRY_TYPE: ENTRY_TYPE_CARP,
        },
        options={},
    )
    remove_listener = MagicMock()
    entry.add_update_listener = MagicMock(return_value=remove_listener)
    entry.async_on_unload = MagicMock(return_value=None)
    hass = ph_hass
    hass.data = {}
    hass.config_entries.async_forward_entry_setups = AsyncMock(
        side_effect=RuntimeError("CARP platform forwarding failed")
    )

    with pytest.raises(RuntimeError, match="CARP platform forwarding failed"):
        await init_mod.async_setup_entry(hass, entry)

    coordinator.async_shutdown.assert_awaited_once()
    client.async_close.assert_awaited_once()
    entry.add_update_listener.assert_not_called()
    entry.async_on_unload.assert_not_called()
    remove_listener.assert_not_called()
    assert entry.entry_id not in hass.data.get(init_mod.DOMAIN, {})
    assert entry.runtime_data is None


@pytest.mark.asyncio
async def test_async_setup_entry_carp_registers_update_listener_after_forwarding(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP update-listener registration should follow platform forwarding."""
    call_order: list[str] = []
    client = _make_valid_setup_client()
    monkeypatch.setattr(
        init_mod, "create_opnsense_client_from_config_entry", lambda **_kwargs: client
    )
    coordinator = _make_setup_coordinator()
    coordinator.data = {"carp": {"interfaces": [{"vhid": 1, "subnet": "192.0.2.1"}]}}
    monkeypatch.setattr(init_mod, "OPNsenseDataUpdateCoordinator", lambda **_kwargs: coordinator)

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            CONF_ENTRY_TYPE: ENTRY_TYPE_CARP,
        },
        options={},
    )
    remove_listener = MagicMock()

    def _add_update_listener(listener: Any) -> MagicMock:
        """Record listener registration and return its removal callback."""
        call_order.append("add_listener")
        return remove_listener

    def _async_on_unload(unregister: MagicMock) -> None:
        """Record unload-callback registration."""
        call_order.append("async_on_unload")

    entry.add_update_listener = MagicMock(side_effect=_add_update_listener)
    entry.async_on_unload = MagicMock(side_effect=_async_on_unload)

    async def _forward_entry_setups(*_args: Any, **_kwargs: Any) -> bool:
        """Record CARP platform forwarding and report success."""
        call_order.append("forward")
        return True

    hass = ph_hass
    hass.data = {}
    hass.config_entries.async_forward_entry_setups = AsyncMock(side_effect=_forward_entry_setups)

    assert await init_mod.async_setup_entry(hass, entry) is True

    assert call_order == ["forward", "add_listener", "async_on_unload"]
    entry.add_update_listener.assert_called_once_with(init_mod._async_update_listener)
    entry.async_on_unload.assert_called_once_with(remove_listener)
    remove_listener.assert_not_called()


@pytest.mark.asyncio
async def test_async_setup_entry_closes_client_when_validation_fails(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry should close a constructed client when validation fails."""
    error = init_mod.OPNsenseError("boom")
    client = MagicMock()
    client.validate = AsyncMock(side_effect=error)
    client.async_close = AsyncMock(return_value=True)

    def _create_client(**kwargs: Any) -> Any:
        """Return the validation-failing client for this setup-entry test."""
        return client

    monkeypatch.setattr(init_mod, "create_opnsense_client_from_config_entry", _create_client)

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={},
    )

    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    with pytest.raises(type(error), match=str(error)):
        await init_mod.async_setup_entry(hass, entry)

    client.async_close.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_setup_entry_does_not_catch_raw_validation_timeout(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Setup should close the client and re-raise a raw validation timeout."""
    client = MagicMock()
    client.validate = AsyncMock(side_effect=TimeoutError)
    client.async_close = AsyncMock(return_value=True)

    def _create_client(**kwargs: Any) -> Any:
        """Return the timeout-raising client for this setup-entry test."""
        return client

    monkeypatch.setattr(init_mod, "create_opnsense_client_from_config_entry", _create_client)

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={},
    )

    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    with pytest.raises(TimeoutError):
        await init_mod.async_setup_entry(hass, entry)

    client.async_close.assert_awaited_once()


@pytest.mark.parametrize(
    "exc", [OPNsenseTimeoutError, OPNsenseConnectionError], ids=["timeout", "connection"]
)
@pytest.mark.asyncio
async def test_async_setup_entry_retries_on_transient_validation_failures(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
    exc: type[BaseException],
) -> None:
    """Transient validation connection failures should trigger ConfigEntryNotReady."""
    client = MagicMock()
    client.validate = AsyncMock(side_effect=exc("timed out"))
    client.async_close = AsyncMock(return_value=True)

    def _create_client(**kwargs: Any) -> Any:
        """Return the timeout-raising client for this setup-entry test."""
        return client

    monkeypatch.setattr(init_mod, "create_opnsense_client_from_config_entry", _create_client)

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={},
    )

    hass = ph_hass
    monkeypatch.setattr(
        hass.config_entries, "async_forward_entry_setups", AsyncMock(return_value=True)
    )
    monkeypatch.setattr(hass.config_entries, "async_reload", AsyncMock())
    hass.data.clear()

    with pytest.raises(ConfigEntryNotReady):
        await init_mod.async_setup_entry(hass, entry)

    client.async_close.assert_awaited_once()


@pytest.mark.parametrize(
    "exc",
    [
        OPNsenseInvalidAuth,
        OPNsensePrivilegeMissing,
        OPNsenseSSLError,
        OPNsenseInvalidURL,
    ],
    ids=[
        "invalid_auth",
        "privilege_missing",
        "ssl_error",
        "invalid_url",
    ],
)
@pytest.mark.asyncio
async def test_async_setup_entry_does_not_retry_non_transient_validation_failures(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: HomeAssistant,
    make_config_entry: Callable[..., MockConfigEntry],
    exc: type[BaseException],
) -> None:
    """Non-transient validation failures should bubble as hard errors."""
    client = MagicMock()
    client.validate = AsyncMock(side_effect=exc("invalid"))
    client.async_close = AsyncMock(return_value=True)

    def _create_client(**kwargs: Any) -> Any:
        """Return the auth-failing client for this setup-entry test."""
        return client

    monkeypatch.setattr(init_mod, "create_opnsense_client_from_config_entry", _create_client)

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={},
    )

    hass = ph_hass
    monkeypatch.setattr(
        hass.config_entries, "async_forward_entry_setups", AsyncMock(return_value=True)
    )
    monkeypatch.setattr(hass.config_entries, "async_reload", AsyncMock())
    hass.data.clear()

    with pytest.raises(exc):
        await init_mod.async_setup_entry(hass, entry)

    client.async_close.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_setup_entry_reraises_client_creation_error(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry should re-raise client creation errors before close handling."""

    def _create_client(**kwargs: Any) -> Any:
        """Raise a backend error before a client instance exists."""
        raise init_mod.OPNsenseError("boom")

    monkeypatch.setattr(init_mod, "create_opnsense_client_from_config_entry", _create_client)
    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={},
    )

    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    with pytest.raises(init_mod.OPNsenseError):
        await init_mod.async_setup_entry(hass, entry)


@pytest.mark.asyncio
async def test_async_setup_entry_continues_after_firmware_validation_error(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry should keep probing after firmware validation exceptions."""
    probe_calls: list[str] = []
    client = MagicMock()
    client.name = "test-router"
    client.validate = AsyncMock(side_effect=init_mod.OPNsenseBelowMinFirmware("boom"))
    client.async_close = AsyncMock(return_value=True)

    async def _get_device_unique_id(expected_id: str | None = None) -> str:
        """Return test router device id after recording probe ordering."""
        probe_calls.append("get_device_unique_id")
        return "dev1"

    async def _get_host_firmware_version() -> str:
        """Return test firmware after recording probe ordering."""
        probe_calls.append("get_host_firmware_version")
        return "99.0"

    client.get_device_unique_id = _get_device_unique_id
    client.get_host_firmware_version = _get_host_firmware_version

    def _create_client(**kwargs: Any) -> Any:
        """Return the firmware-failing client for this setup-entry test."""
        return client

    monkeypatch.setattr(init_mod, "create_opnsense_client_from_config_entry", _create_client)
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={},
    )

    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True
    assert probe_calls == [
        "get_device_unique_id",
        "get_host_firmware_version",
    ]
    client.async_close.assert_not_awaited()


@pytest.mark.asyncio
async def test_async_setup_entry_continues_after_missing_device_unique_id_validation(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry should continue when unique-id validation is unavailable."""
    probe_calls: list[str] = []
    client = MagicMock()
    client.name = "test-router"
    client.validate = AsyncMock(
        side_effect=init_mod.OPNsenseMissingDeviceUniqueID("unable to determine device id")
    )
    client.async_close = AsyncMock(return_value=True)

    async def _get_device_unique_id(expected_id: str | None = None) -> str:
        """Return test router device id after recording probe ordering."""
        probe_calls.append("get_device_unique_id")
        return "dev1"

    async def _get_host_firmware_version() -> str:
        """Return test firmware after recording probe ordering."""
        probe_calls.append("get_host_firmware_version")
        return "99.0"

    client.get_device_unique_id = _get_device_unique_id
    client.get_host_firmware_version = _get_host_firmware_version

    def _create_client(**kwargs: Any) -> Any:
        """Return the unique-id-missing client for this setup-entry test."""
        return client

    monkeypatch.setattr(init_mod, "create_opnsense_client_from_config_entry", _create_client)
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={},
    )

    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True
    assert probe_calls == [
        "get_device_unique_id",
        "get_host_firmware_version",
    ]
    client.async_close.assert_not_awaited()


@pytest.mark.asyncio
async def test_async_setup_entry_device_id_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_client: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """async_setup_entry should fail when client reports mismatched device id."""
    caplog.set_level(logging.ERROR, logger=init_mod.__name__)
    patch_opnsense_client(monkeypatch, init_mod, fake_client(device_id="other"))
    # use shared coordinator capture fixture
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    # use the shared helper to construct the entry for consistency
    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={},
    )

    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()

    issue_kwargs: dict[str, Any] = {}

    def _capture_issue(**kwargs: Any) -> None:
        """Capture the startup device-ID repair issue payload."""
        issue_kwargs.update(kwargs)

    monkeypatch.setattr(init_mod.ir, "async_create_issue", _capture_issue)

    # should return False because router id mismatches and coordinator.shutdown called
    res = await init_mod.async_setup_entry(hass, entry)
    assert res is False

    # ensure coordinator shutdown was invoked
    assert any(getattr(inst, "shut", False) for inst in coordinator_capture.instances)
    assert hass.config_entries.async_forward_entry_setups.await_count == 0
    assert issue_kwargs["is_fixable"] is True
    assert issue_kwargs["issue_id"] == f"{entry.entry_id}_device_id_mismatched"
    assert issue_kwargs["data"] == {
        "entry_id": entry.entry_id,
        "old_device_id": "dev1",
        "new_device_id": "other",
    }
    assert issue_kwargs["translation_placeholders"] == {
        "entry_title": entry.title,
        "old_device_id": "dev1",
        "new_device_id": "other",
    }
    assert "fixable repair issue" in caplog.text
    assert "rebuild entities" in caplog.text


@pytest.mark.asyncio
async def test_async_update_listener_not_reload(
    monkeypatch: pytest.MonkeyPatch, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """_async_update_listener should set SHOULD_RELOAD True and not call reload when flag False."""
    entry = make_config_entry(entry_id="e", unique_id="u")
    # ensure runtime_data exists and set SHOULD_RELOAD to False
    setattr(entry.runtime_data, init_mod.SHOULD_RELOAD, False)

    # hass with config_entries.async_reload not called
    hass = MagicMock(spec=HomeAssistant)
    hass.config_entries = MagicMock()
    hass.config_entries.async_reload = AsyncMock()

    # should set SHOULD_RELOAD back to True and not call reload
    await init_mod._async_update_listener(hass, entry)
    assert getattr(entry.runtime_data, init_mod.SHOULD_RELOAD) is True
    hass.config_entries.async_reload.assert_not_called()


@pytest.mark.asyncio
async def test_async_remove_config_entry_device_branches(
    monkeypatch: pytest.MonkeyPatch, hass: HomeAssistant
) -> None:
    """Verify removal logic for config entry device registry branches."""
    device = MagicMock()
    device.via_device_id = True
    device.id = "d1"
    res = await init_mod.async_remove_config_entry_device(hass, None, device)
    assert res is False

    # device_entry with linked entity -> False
    device = MagicMock()
    device.via_device_id = False
    device.id = "d2"

    # fake registry that returns one entity with matching device_id
    ent = MagicMock()
    ent.device_id = "d2"
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: object())
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: [ent]
    )
    res = await init_mod.async_remove_config_entry_device(hass, MagicMock(entry_id="x"), device)
    assert res is False


@pytest.mark.asyncio
async def test_async_remove_config_entry_device_no_linked_entities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When no linked entities exist for a device, removal should succeed (return True)."""
    # device not linked via via_device_id and has an id
    device = MagicMock()
    device.via_device_id = False
    device.id = "d3"

    # fake entity registry returns no entities for the config entry
    er_reg = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: er_reg)
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: []
    )

    # call the removal helper with a dummy config entry
    res = await init_mod.async_remove_config_entry_device(None, MagicMock(entry_id="x"), device)
    assert res is True


@pytest.mark.asyncio
async def test_async_unload_entry_and_pop(
    ph_hass: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """async_unload_entry removes entry from hass.data and closes the client."""
    entry = make_config_entry(entry_id="e_unload")
    entry.as_dict = lambda: {"id": "x"}
    # use the constant names used by the integration
    setattr(entry.runtime_data, init_mod.LOADED_PLATFORMS, ["p1"])
    fake_client = MagicMock()
    fake_client.async_close = AsyncMock()
    setattr(entry.runtime_data, init_mod.OPNSENSE_CLIENT, fake_client)

    hass = ph_hass
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=True)
    hass.data = {init_mod.DOMAIN: {entry.entry_id: fake_client}}
    res = await init_mod.async_unload_entry(hass, entry)
    assert res is True
    assert entry.entry_id not in hass.data[init_mod.DOMAIN]
    fake_client.async_close.assert_awaited_once()


@pytest.mark.asyncio
async def test_migrate_1_to_2_updates_entry(ph_hass: Any) -> None:
    """_migrate_1_to_2 migrates tls_insecure to verify_ssl and updates version."""
    cfg = MagicMock()
    cfg.data = {CONF_TLS_INSECURE: True}
    # ensure verify_ssl missing
    cfg.version = 1
    # mock async_update_entry
    hass = ph_hass
    hass.config_entries.async_update_entry = MagicMock(return_value=True)
    res = await init_mod._migrate_1_to_2(hass, cfg)
    assert res is True
    # verify async_update_entry was called with the migrated data: tls_insecure removed
    # and verify_ssl derived as not tls_insecure, and version set to 2
    expected_data = {CONF_VERIFY_SSL: False}
    hass.config_entries.async_update_entry.assert_called_once_with(
        cfg, data=expected_data, version=2
    )

    # Also test tls_insecure == False -> verify_ssl True
    cfg2 = MagicMock()
    cfg2.data = {CONF_TLS_INSECURE: False}
    cfg2.version = 1
    # reset mock
    hass.config_entries.async_update_entry = MagicMock(return_value=True)
    res2 = await init_mod._migrate_1_to_2(hass, cfg2)
    assert res2 is True
    expected_data2 = {CONF_VERIFY_SSL: True}
    hass.config_entries.async_update_entry.assert_called_once_with(
        cfg2, data=expected_data2, version=2
    )


@pytest.mark.asyncio
async def test_async_migrate_entry_version_gt5(ph_hass: Any) -> None:
    """async_migrate_entry returns False for versions greater than supported."""
    cfg = MagicMock()
    cfg.version = 6
    # should return False
    res = await init_mod.async_migrate_entry(ph_hass, cfg)
    assert res is False


@pytest.mark.asyncio
@pytest.mark.parametrize("version", [0])
async def test_async_migrate_entry_does_not_call_migrate_3_to_4_when_version_not_3(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any, version: Any
) -> None:
    """When entry.version is not 3, _migrate_3_to_4 must not be called."""
    mock_m3 = AsyncMock(return_value=True)
    monkeypatch.setattr(init_mod, "_migrate_3_to_4", mock_m3)

    cfg = MagicMock()
    cfg.version = version

    res = await init_mod.async_migrate_entry(ph_hass, cfg)

    # for versions not 3, migration should complete (except versions >5, which are handled earlier)
    assert res is True
    mock_m3.assert_not_called()


@pytest.mark.asyncio
async def test_async_migrate_entry_uses_throw_errors_for_migration_client(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any
) -> None:
    """Migration should create the OPNsense client with throw_errors enabled."""
    ph_hass.config_entries.async_update_entry = MagicMock(return_value=True)
    entry = MockConfigEntry(
        domain=init_mod.DOMAIN,
        data={
            init_mod.CONF_DEVICE_UNIQUE_ID: "device-id",
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
        },
        version=3,
    )
    entry.add_to_hass(ph_hass)

    client = MagicMock()
    client.get_firewall = AsyncMock(return_value={})
    client.get_telemetry = AsyncMock(return_value={"filesystems": []})
    client.async_close = AsyncMock()
    create_client = MagicMock(return_value=client)
    monkeypatch.setattr(init_mod, "create_opnsense_client_from_config_entry", create_client)
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: MagicMock())
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [],
    )

    res = await init_mod.async_migrate_entry(ph_hass, entry)
    assert res is True
    create_client.assert_called_once_with(
        hass=ph_hass,
        config_entry=entry,
        throw_errors=True,
    )


@pytest.mark.asyncio
async def test_migrate_4_to_5_removes_rule_switch_entities(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any
) -> None:
    """_migrate_4_to_5 removes stale rule switch entities and updates config entry version."""
    slugified_prefix: str = slugify("router unit")
    ph_hass.config_entries.async_update_entry = MagicMock(return_value=True)
    entry = MockConfigEntry(
        domain=init_mod.DOMAIN,
        data={
            init_mod.CONF_DEVICE_UNIQUE_ID: "router unit",
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
        },
        unique_id="router unit",
        version=4,
    )
    entry.add_to_hass(ph_hass)
    client = MagicMock()
    client.get_firewall = AsyncMock(return_value={"rules": {"row-key": {"uuid": "current"}}})
    client.async_close = AsyncMock()
    monkeypatch.setattr(
        init_mod, "create_opnsense_client_from_config_entry", MagicMock(return_value=client)
    )

    legacy_filter = _RegistryEntity("switch.filter", f"{slugified_prefix}_filter_123")
    legacy_nat_pf = _RegistryEntity("switch.nat_pf", f"{slugified_prefix}_nat_port_forward_123")
    legacy_nat_out = _RegistryEntity("switch.nat_out", f"{slugified_prefix}_nat_outbound_123")
    stale_native_firewall = _RegistryEntity(
        "switch.firewall_rule_stale", f"{slugified_prefix}_firewall_rule_stale"
    )
    current_native_firewall = _RegistryEntity(
        "switch.firewall_rule_current", f"{slugified_prefix}_firewall_rule_current"
    )
    native_nat = _RegistryEntity("switch.firewall_nat", f"{slugified_prefix}_firewall_nat_123")
    unrelated_entry = _RegistryEntity("switch.unrelated_filter", "unrelated_filter_123")
    service_entity = _RegistryEntity("switch.service", f"{slugified_prefix}_service_unbound_status")
    telemetry_entity = _RegistryEntity("sensor.telemetry", f"{slugified_prefix}_telemetry_cpu")

    entity_registry = MagicMock()
    entity_registry.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [
            legacy_filter,
            legacy_nat_pf,
            legacy_nat_out,
            stale_native_firewall,
            current_native_firewall,
            native_nat,
            unrelated_entry,
            service_entity,
            telemetry_entity,
        ],
    )

    res = await init_mod.async_migrate_entry(ph_hass, entry)
    assert res is True
    entity_registry.async_remove.assert_has_calls(
        [
            call(legacy_filter.entity_id),
            call(legacy_nat_pf.entity_id),
            call(legacy_nat_out.entity_id),
            call(stale_native_firewall.entity_id),
        ],
        any_order=True,
    )
    assert entity_registry.async_remove.call_count == 4
    assert all(
        remove_call.args[0] != unrelated_entry.entity_id
        for remove_call in entity_registry.async_remove.call_args_list
    )
    ph_hass.config_entries.async_update_entry.assert_called_once_with(entry, version=5)


@pytest.mark.asyncio
async def test_migrate_4_to_5_uses_rule_key_when_uuid_is_missing(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any
) -> None:
    """_migrate_4_to_5 should keep non-uuid rules by mapping key."""
    ph_hass.config_entries.async_update_entry = MagicMock(return_value=True)
    entry = MockConfigEntry(
        domain=init_mod.DOMAIN,
        data={
            init_mod.CONF_DEVICE_UNIQUE_ID: "deviceid",
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
        },
        version=4,
    )
    entry.add_to_hass(ph_hass)
    client = MagicMock()
    client.get_firewall = AsyncMock(return_value={"rules": {"r1": {"description": "current"}}})
    client.async_close = AsyncMock()
    monkeypatch.setattr(
        init_mod, "create_opnsense_client_from_config_entry", MagicMock(return_value=client)
    )

    legacy_filter = _RegistryEntity("switch.filter", "deviceid_filter_123")
    stale_native_firewall = _RegistryEntity(
        "switch.firewall_rule_stale", "deviceid_firewall_rule_stale"
    )
    current_native_firewall = _RegistryEntity(
        "switch.firewall_rule_current", "deviceid_firewall_rule_r1"
    )

    entity_registry = MagicMock()
    entity_registry.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [
            legacy_filter,
            stale_native_firewall,
            current_native_firewall,
        ],
    )

    res = await init_mod.async_migrate_entry(ph_hass, entry)

    assert res is True
    assert entity_registry.async_remove.call_count == 2
    entity_registry.async_remove.assert_has_calls(
        [call(legacy_filter.entity_id), call(stale_native_firewall.entity_id)],
        any_order=True,
    )
    removed_entity_ids = {
        remove_call.args[0] for remove_call in entity_registry.async_remove.call_args_list
    }
    assert current_native_firewall.entity_id not in removed_entity_ids
    ph_hass.config_entries.async_update_entry.assert_called_once_with(entry, version=5)


@pytest.mark.asyncio
async def test_migrate_4_to_5_sync_disabled_skips_firewall_fetch_removes_native_firewall_and_nat_rules(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
) -> None:
    """_migrate_4_to_5 should remove native firewall and NAT rules when sync is disabled."""
    ph_hass.config_entries.async_update_entry = MagicMock(return_value=True)
    data: dict[str, Any] = {
        init_mod.CONF_DEVICE_UNIQUE_ID: "deviceid",
        CONF_URL: "http://1.2.3.4",
        CONF_USERNAME: "u",
        CONF_PASSWORD: "p",
    }
    data[CONF_SYNC_FIREWALL_AND_NAT] = False
    entry = MockConfigEntry(
        domain=init_mod.DOMAIN,
        data=data,
        version=4,
    )
    entry.add_to_hass(ph_hass)
    client = MagicMock()
    client.get_firewall = AsyncMock(return_value={"rules": {}})
    client.async_close = AsyncMock()
    create_client = MagicMock(return_value=client)
    monkeypatch.setattr(init_mod, "create_opnsense_client_from_config_entry", create_client)

    legacy_filter = _RegistryEntity("switch.filter", "deviceid_filter_123")
    stale_native_firewall = _RegistryEntity(
        "switch.firewall_rule_stale", "deviceid_firewall_rule_stale"
    )
    current_native_firewall = _RegistryEntity(
        "switch.firewall_rule_current", "deviceid_firewall_rule_current"
    )
    native_nat = _RegistryEntity("switch.firewall_nat", "deviceid_firewall_nat_123")

    entity_registry = MagicMock()
    entity_registry.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [
            legacy_filter,
            stale_native_firewall,
            current_native_firewall,
            native_nat,
        ],
    )

    res = await init_mod.async_migrate_entry(ph_hass, entry)

    assert res is True
    client.get_firewall.assert_not_called()
    entity_registry.async_remove.assert_has_calls(
        [
            call(legacy_filter.entity_id),
            call(stale_native_firewall.entity_id),
            call(current_native_firewall.entity_id),
            call(native_nat.entity_id),
        ],
        any_order=True,
    )
    assert entity_registry.async_remove.call_count == 4
    removed_entity_ids = {
        remove_call.args[0] for remove_call in entity_registry.async_remove.call_args_list
    }
    assert stale_native_firewall.entity_id in removed_entity_ids
    assert current_native_firewall.entity_id in removed_entity_ids
    assert native_nat.entity_id in removed_entity_ids
    ph_hass.config_entries.async_update_entry.assert_called_once_with(entry, version=5)
    create_client.assert_not_called()


@pytest.mark.asyncio
async def test_migrate_4_to_5_granular_entry_defaults_missing_category_key_to_enabled(
    monkeypatch: pytest.MonkeyPatch, ph_hass: HomeAssistant
) -> None:
    """Granular migration preserves firewall sync for entries missing the category key."""
    update_entry = MagicMock(return_value=True)
    monkeypatch.setattr(ph_hass.config_entries, "async_update_entry", update_entry)
    entry = MockConfigEntry(
        domain=init_mod.DOMAIN,
        data={
            init_mod.CONF_DEVICE_UNIQUE_ID: "deviceid",
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            CONF_GRANULAR_SYNC_OPTIONS: True,
        },
        version=4,
    )
    entry.add_to_hass(ph_hass)
    assert CONF_SYNC_FIREWALL_AND_NAT not in entry.data

    client = MagicMock()
    client.get_firewall = AsyncMock(return_value={"rules": {"row-key": {"uuid": "current"}}})
    client.async_close = AsyncMock()
    create_client = MagicMock(return_value=client)
    monkeypatch.setattr(init_mod, "create_opnsense_client_from_config_entry", create_client)

    stale_native_firewall = _RegistryEntity(
        "switch.firewall_rule_stale",
        "deviceid_firewall_rule_stale",
    )

    entity_registry = MagicMock()
    entity_registry.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [stale_native_firewall],
    )

    res = await init_mod.async_migrate_entry(ph_hass, entry)

    assert res is True
    create_client.assert_called_once()
    client.get_firewall.assert_awaited_once()
    entity_registry.async_remove.assert_called_once_with(stale_native_firewall.entity_id)
    update_entry.assert_called_once_with(entry, version=5)


@pytest.mark.asyncio
async def test_migrate_4_to_5_non_granular_entry_missing_category_key_preserves_sync(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: HomeAssistant,
) -> None:
    """A non-granular entry without a category key should preserve current rule entities."""
    update_entry = MagicMock(return_value=True)
    monkeypatch.setattr(ph_hass.config_entries, "async_update_entry", update_entry)
    entry = MockConfigEntry(
        domain=init_mod.DOMAIN,
        data={
            init_mod.CONF_DEVICE_UNIQUE_ID: "deviceid",
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            CONF_GRANULAR_SYNC_OPTIONS: False,
        },
        version=4,
    )
    entry.add_to_hass(ph_hass)
    client = MagicMock()
    client.get_firewall = AsyncMock(
        return_value={
            "rules": {"keep": {"uuid": "current"}},
            "nat": {
                "source_nat": {"source-keep": {"uuid": "current"}},
            },
        }
    )
    client.async_close = AsyncMock()
    create_client = MagicMock(return_value=client)
    monkeypatch.setattr(init_mod, "create_opnsense_client_from_config_entry", create_client)

    legacy_filter = _RegistryEntity("switch.filter", "deviceid_filter_123")
    stale_native_firewall = _RegistryEntity(
        "switch.firewall_rule_stale", "deviceid_firewall_rule_stale"
    )
    stale_nat = _RegistryEntity(
        "switch.firewall_nat",
        slugify("deviceid.firewall.nat.source_nat.removed_source"),
    )
    current_native_firewall = _RegistryEntity(
        "switch.firewall_rule_current", "deviceid_firewall_rule_current"
    )
    current_nat = _RegistryEntity(
        "switch.firewall_nat_current",
        slugify("deviceid.firewall.nat.source_nat.current"),
    )

    entity_registry = MagicMock()
    entity_registry.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [
            legacy_filter,
            stale_native_firewall,
            stale_nat,
            current_native_firewall,
            current_nat,
        ],
    )

    res = await init_mod.async_migrate_entry(ph_hass, entry)

    assert res is True
    create_client.assert_called_once()
    client.get_firewall.assert_awaited_once()
    removed_entity_ids = {
        remove_call.args[0] for remove_call in entity_registry.async_remove.call_args_list
    }
    assert legacy_filter.entity_id in removed_entity_ids
    assert stale_native_firewall.entity_id in removed_entity_ids
    assert stale_nat.entity_id in removed_entity_ids
    assert current_native_firewall.entity_id not in removed_entity_ids
    assert current_nat.entity_id not in removed_entity_ids
    assert entity_registry.async_remove.call_count == 3
    update_entry.assert_called_once_with(entry, version=5)


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        pytest.param({}, True, id="legacy-default"),
        pytest.param({CONF_GRANULAR_SYNC_OPTIONS: False}, True, id="non-granular-default"),
        pytest.param(
            {
                CONF_GRANULAR_SYNC_OPTIONS: False,
                CONF_SYNC_FIREWALL_AND_NAT: True,
            },
            True,
            id="explicit-category-enabled",
        ),
        pytest.param(
            {
                CONF_GRANULAR_SYNC_OPTIONS: True,
                CONF_SYNC_FIREWALL_AND_NAT: False,
            },
            False,
            id="explicit-category-disabled",
        ),
    ],
)
def test_is_firewall_sync_enabled_uses_category_then_default(
    data: dict[str, Any], expected: bool
) -> None:
    """Migration sync state should preserve explicit and runtime defaults."""
    entry = MagicMock()
    entry.data = data

    assert init_mod._is_firewall_sync_enabled(entry) is expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("sync_firewall_and_nat", "device_unique_id"),
    [
        pytest.param(True, None, id="enabled-missing"),
        pytest.param(False, None, id="disabled-missing"),
        pytest.param(True, "", id="enabled-empty"),
        pytest.param(False, "", id="disabled-empty"),
        pytest.param(True, "   ", id="enabled-whitespace"),
        pytest.param(False, "   ", id="disabled-whitespace"),
    ],
)
async def test_migrate_4_to_5_defers_when_device_unique_id_is_missing(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: HomeAssistant,
    sync_firewall_and_nat: bool,
    device_unique_id: str | None,
) -> None:
    """_migrate_4_to_5 should defer when migration lacks a device unique ID."""
    update_entry = MagicMock(return_value=True)
    monkeypatch.setattr(ph_hass.config_entries, "async_update_entry", update_entry)
    entry_data: dict[str, Any] = {
        CONF_URL: "http://1.2.3.4",
        CONF_USERNAME: "u",
        CONF_PASSWORD: "p",
    }
    if not sync_firewall_and_nat:
        entry_data[CONF_SYNC_FIREWALL_AND_NAT] = False
    if device_unique_id is not None:
        entry_data[init_mod.CONF_DEVICE_UNIQUE_ID] = device_unique_id
    entry_prefix = slugify("device-id")
    entry = MockConfigEntry(
        domain=init_mod.DOMAIN,
        data=entry_data,
        version=4,
    )
    entry.add_to_hass(ph_hass)
    client = MagicMock()
    client.get_firewall = AsyncMock(return_value={"rules": {"r1": {"uuid": "keep"}}})
    client.async_close = AsyncMock()
    create_client = MagicMock(return_value=client)
    monkeypatch.setattr(init_mod, "create_opnsense_client_from_config_entry", create_client)

    legacy_filter = _RegistryEntity("switch.filter", f"{entry_prefix}_filter_123")
    entity_registry = MagicMock()
    entity_registry.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [legacy_filter],
    )

    res = await init_mod.async_migrate_entry(ph_hass, entry)
    assert res is False
    entity_registry.async_remove.assert_not_called()
    update_entry.assert_not_called()
    if sync_firewall_and_nat:
        create_client.assert_called_once_with(
            hass=ph_hass,
            config_entry=entry,
            throw_errors=True,
        )
    else:
        create_client.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "firewall_result",
    [
        pytest.param(init_mod.OPNsenseError("unavailable"), id="fetch-error"),
    ],
)
async def test_migrate_4_to_5_defers_when_firewall_rules_unavailable(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any, firewall_result: Any
) -> None:
    """_migrate_4_to_5 should not version-bump when firewall rules cannot be fetched."""
    ph_hass.config_entries.async_update_entry = MagicMock(return_value=True)
    entry = MockConfigEntry(
        domain=init_mod.DOMAIN,
        data={
            init_mod.CONF_DEVICE_UNIQUE_ID: "device-id",
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
        },
        version=4,
    )
    entry.add_to_hass(ph_hass)
    client = MagicMock()
    if isinstance(firewall_result, init_mod.OPNsenseError):
        client.get_firewall = AsyncMock(side_effect=firewall_result)
    else:
        client.get_firewall = AsyncMock(return_value=firewall_result)
    client.async_close = AsyncMock()
    monkeypatch.setattr(
        init_mod, "create_opnsense_client_from_config_entry", MagicMock(return_value=client)
    )

    entry_prefix = slugify("device-id")
    legacy_filter = _RegistryEntity("switch.filter", f"{entry_prefix}_filter_123")

    entity_registry = MagicMock()
    entity_registry.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [legacy_filter],
    )

    res = await init_mod.async_migrate_entry(ph_hass, entry)

    assert res is False
    entity_registry.async_remove.assert_not_called()
    ph_hass.config_entries.async_update_entry.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "firewall_payload",
    [
        pytest.param({}, id="missing-rules"),
        pytest.param({"rules": []}, id="invalid-rules"),
    ],
)
async def test_migrate_4_to_5_skips_native_pruning_when_rules_payload_unavailable(
    monkeypatch: pytest.MonkeyPatch, ph_hass: HomeAssistant, firewall_payload: dict[str, object]
) -> None:
    """_migrate_4_to_5 should complete migration with legacy cleanup only when rules are unavailable."""
    update_entry = MagicMock(return_value=True)
    monkeypatch.setattr(ph_hass.config_entries, "async_update_entry", update_entry)
    entry = MockConfigEntry(
        domain=init_mod.DOMAIN,
        data={
            init_mod.CONF_DEVICE_UNIQUE_ID: "device-id",
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
        },
        version=4,
    )
    entry.add_to_hass(ph_hass)
    client = MagicMock()
    client.get_firewall = AsyncMock(return_value=firewall_payload)
    client.async_close = AsyncMock()
    monkeypatch.setattr(
        init_mod, "create_opnsense_client_from_config_entry", MagicMock(return_value=client)
    )

    entry_prefix = slugify("device-id")
    legacy_filter = _RegistryEntity("switch.filter", f"{entry_prefix}_filter_123")
    stale_native_firewall = _RegistryEntity(
        "switch.firewall_rule", f"{entry_prefix}_firewall_rule_stale"
    )
    stale_native_nat = _RegistryEntity(
        "switch.firewall_nat", slugify("deviceid.firewall.nat.source_nat.stale_source")
    )

    entity_registry = MagicMock()
    entity_registry.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [legacy_filter, stale_native_firewall, stale_native_nat],
    )

    res = await init_mod.async_migrate_entry(ph_hass, entry)

    assert res is True
    entity_registry.async_remove.assert_has_calls(
        [call(legacy_filter.entity_id)],
        any_order=True,
    )
    assert entity_registry.async_remove.call_count == 1
    update_entry.assert_called_once_with(entry, version=5)


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", [KeyError("legacy"), ValueError("legacy")])
async def test_migrate_4_to_5_legacy_entity_remove_failure_aborts_migration(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any, exc: BaseException
) -> None:
    """_migrate_4_to_5 returns False when entity removal raises handled exceptions."""
    ph_hass.config_entries.async_update_entry = MagicMock(return_value=True)
    entry = MockConfigEntry(
        domain=init_mod.DOMAIN,
        data={
            init_mod.CONF_DEVICE_UNIQUE_ID: "device-id",
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
        },
        version=4,
    )
    entry.add_to_hass(ph_hass)
    client = MagicMock()
    client.get_firewall = AsyncMock(return_value={"rules": {}})
    client.async_close = AsyncMock()
    monkeypatch.setattr(
        init_mod, "create_opnsense_client_from_config_entry", MagicMock(return_value=client)
    )

    entry_prefix = slugify("device-id")
    broken_ent = _RegistryEntity("switch.filter", f"{entry_prefix}_filter_123")
    ok_ent = _RegistryEntity("switch.nat_pf", f"{entry_prefix}_nat_port_forward_123")

    entity_registry = MagicMock()
    entity_registry.async_remove = MagicMock(side_effect=[exc, None])
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [broken_ent, ok_ent],
    )

    res = await init_mod.async_migrate_entry(ph_hass, entry)
    assert res is False
    assert entity_registry.async_remove.call_count == 1
    entity_registry.async_remove.assert_has_calls([call(broken_ent.entity_id)])
    ph_hass.config_entries.async_update_entry.assert_not_called()


@pytest.mark.asyncio
async def test_migrate_4_to_5_sync_enabled_prunes_stale_native_nat_rule_entities(
    monkeypatch: pytest.MonkeyPatch, ph_hass: HomeAssistant
) -> None:
    """_migrate_4_to_5 should prune stale native NAT IDs for explicit empty NAT sections."""
    update_entry = MagicMock(return_value=True)
    monkeypatch.setattr(ph_hass.config_entries, "async_update_entry", update_entry)
    entry = MockConfigEntry(
        domain=init_mod.DOMAIN,
        data={
            init_mod.CONF_DEVICE_UNIQUE_ID: "deviceid",
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
        },
        version=4,
    )
    entry.add_to_hass(ph_hass)
    client = MagicMock()
    client.get_firewall = AsyncMock(
        return_value={
            "rules": {"r1": {"uuid": "keep"}},
            "nat": {
                "source_nat": {
                    "source-current": {"uuid": "current_source"},
                    "source-kept": {"uuid": "kept_source"},
                },
                "d_nat": {
                    "dnat-current": {"uuid": "current_dnat"},
                    "dnat-kept": {"uuid": "kept_dnat"},
                },
                "npt": {"npt-current": {"uuid": "current_npt"}},
            },
        }
    )
    client.async_close = AsyncMock()
    monkeypatch.setattr(
        init_mod, "create_opnsense_client_from_config_entry", MagicMock(return_value=client)
    )

    stale_native_firewall = _RegistryEntity(
        "switch.firewall_rule_stale", "deviceid_firewall_rule_stale"
    )
    current_native_firewall = _RegistryEntity(
        "switch.firewall_rule_keep", "deviceid_firewall_rule_keep"
    )
    stale_nat_source = _RegistryEntity(
        "switch.firewall_nat_source",
        slugify("deviceid.firewall.nat.source_nat.removed_source"),
    )
    current_nat_source = _RegistryEntity(
        "switch.firewall_nat_source_current",
        slugify("deviceid.firewall.nat.source_nat.current_source"),
    )
    stale_nat_dnat = _RegistryEntity(
        "switch.firewall_nat_dnat",
        slugify("deviceid.firewall.nat.d_nat.removed_dnat"),
    )
    current_nat_dnat = _RegistryEntity(
        "switch.firewall_nat_dnat_current",
        slugify("deviceid.firewall.nat.d_nat.current_dnat"),
    )
    stale_nat_npt = _RegistryEntity(
        "switch.firewall_nat_npt",
        slugify("deviceid.firewall.nat.npt.stale_npt"),
    )
    stale_nat_one_to_one = _RegistryEntity(
        "switch.firewall_nat_one_to_one",
        slugify("deviceid.firewall.nat.one_to_one.stale_one_to_one"),
    )

    entity_registry = MagicMock()
    entity_registry.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [
            stale_native_firewall,
            current_native_firewall,
            stale_nat_source,
            current_nat_source,
            stale_nat_dnat,
            current_nat_dnat,
            stale_nat_npt,
            stale_nat_one_to_one,
        ],
    )

    res = await init_mod.async_migrate_entry(ph_hass, entry)
    assert res is True
    entity_registry.async_remove.assert_has_calls(
        [
            call(stale_native_firewall.entity_id),
            call(stale_nat_source.entity_id),
            call(stale_nat_dnat.entity_id),
            call(stale_nat_npt.entity_id),
            call(stale_nat_one_to_one.entity_id),
        ],
        any_order=True,
    )
    removed_entity_ids = {
        remove_call.args[0] for remove_call in entity_registry.async_remove.call_args_list
    }
    assert current_native_firewall.entity_id not in removed_entity_ids
    assert current_nat_source.entity_id not in removed_entity_ids
    assert current_nat_dnat.entity_id not in removed_entity_ids
    assert stale_nat_one_to_one.entity_id in removed_entity_ids
    assert entity_registry.async_remove.call_count == 5
    update_entry.assert_called_once_with(entry, version=5)


@pytest.mark.asyncio
async def test_migrate_4_to_5_version_bump_failure_aborts_migration(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any
) -> None:
    """_migrate_4_to_5 returns False when async_update_entry fails."""
    ph_hass.config_entries.async_update_entry = MagicMock(return_value=False)
    entry = MockConfigEntry(
        domain=init_mod.DOMAIN,
        data={
            init_mod.CONF_DEVICE_UNIQUE_ID: "device-id",
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
        },
        version=4,
    )
    entry.add_to_hass(ph_hass)
    client = MagicMock()
    client.get_firewall = AsyncMock(return_value={"rules": {}})
    client.async_close = AsyncMock()
    monkeypatch.setattr(
        init_mod, "create_opnsense_client_from_config_entry", MagicMock(return_value=client)
    )

    legacy_filter = _RegistryEntity("switch.filter", f"{slugify('device-id')}_filter_123")

    entity_registry = MagicMock()
    entity_registry.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [legacy_filter],
    )

    res = await init_mod.async_migrate_entry(ph_hass, entry)
    assert res is False
    ph_hass.config_entries.async_update_entry.assert_called_once_with(entry, version=5)


@pytest.mark.asyncio
@pytest.mark.parametrize("should_raise", [False, True])
async def test_async_setup_calls_services_and_handles_exceptions(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any, should_raise: Any
) -> None:
    """Verify ``async_setup`` invokes the service hook and propagates errors.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        ph_hass: Home Assistant test instance.
        should_raise: Whether the service hook should raise an error.
    """
    mock_align = MagicMock()
    if should_raise:
        mock_services = AsyncMock(side_effect=RuntimeError("fail"))
    else:
        mock_services = AsyncMock(return_value=None)

    monkeypatch.setattr(init_mod, "_align_aiopnsense_log_level", mock_align)
    monkeypatch.setattr(init_mod, "async_setup_services", mock_services)

    if should_raise:
        with pytest.raises(RuntimeError):
            await init_mod.async_setup(ph_hass, {})
        mock_services.assert_awaited_once()
        mock_align.assert_called_once_with()
    else:
        res = await init_mod.async_setup(ph_hass, {})
        assert res is True
        mock_services.assert_awaited_once()
        mock_align.assert_called_once_with()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("entry_id", "entry_data", "entry_unique_id", "entity_unique_id_prefix"),
    [
        (
            "device-entry",
            {init_mod.CONF_DEVICE_UNIQUE_ID: "dev1", "sync_telemetry": False},
            "stale-device-id",
            "dev1",
        ),
        (
            "carp-entry",
            {CONF_ENTRY_TYPE: ENTRY_TYPE_CARP, "sync_telemetry": False},
            None,
            "carp_entry",
        ),
    ],
)
async def test_async_update_listener_reload_and_remove(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
    entry_id: str,
    entry_data: dict[str, Any],
    entry_unique_id: str | None,
    entity_unique_id_prefix: str,
) -> None:
    """Remove disabled entities using the same identity prefix as entity creation."""
    # Prepare entry with SHOULD_RELOAD True and granular sync option disabled to force removal_prefixes
    entry = make_config_entry(
        entry_id=entry_id,
        data=entry_data,
        unique_id=entry_unique_id,
    )
    setattr(entry.runtime_data, init_mod.SHOULD_RELOAD, True)
    # config entries and hass async reload stub
    # use migration fixture which provides config_entries and async helpers
    hass = ph_hass
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    # construct an entity that should be removed by unique_id prefix
    class Ent:
        """Minimal entity registry entry used by listener cleanup tests."""

        def __init__(self, entity_id: Any, unique_id: Any) -> None:
            """Store the entity and unique IDs used by the update-listener test."""
            self.entity_id = entity_id
            self.unique_id = unique_id
            self.domain = init_mod.Platform.SENSOR

    # explicitly use the 'sync_telemetry' prefix so the test targets the intended sync item
    prefix = list(init_mod.GRANULAR_SYNC_PREFIX["sync_telemetry"])
    pre = prefix[0]
    ent = Ent("sensor.x", f"{entity_unique_id_prefix}_{pre}_suffix")

    # monkeypatch entity registry functions
    er_reg = MagicMock()
    er_reg.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: er_reg)
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: [ent]
    )
    # patch device registry to return no devices and provide async_remove_device
    dr_reg = MagicMock()
    dr_reg.async_remove_device = MagicMock()
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: dr_reg)
    monkeypatch.setattr(
        init_mod.dr, "async_entries_for_config_entry", lambda registry, config_entry_id: []
    )

    # config option already provided via factory; no mutation needed

    await init_mod._async_update_listener(hass, entry)

    # async_create_task should have been used to schedule reload
    assert hass.async_create_task.called

    # entity matched by prefix should be removed; no devices to remove
    er_reg.async_remove.assert_called_once_with(ent.entity_id)
    dr_reg.async_remove_device.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(("sync_enabled", "expect_removed"), [(False, True), (True, False)])
async def test_async_update_listener_handles_native_firewall_entities_by_sync_state(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
    sync_enabled: bool,
    expect_removed: bool,
) -> None:
    """Remove native firewall entities only when Firewall/NAT sync is disabled."""
    entry = make_config_entry(
        data={
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
            CONF_SYNC_FIREWALL_AND_NAT: sync_enabled,
        },
        unique_id="unit two",
    )
    setattr(entry.runtime_data, init_mod.SHOULD_RELOAD, True)

    hass = ph_hass
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    class Ent:
        """Simple entity record for registry cleanup assertions."""

        def __init__(self, entity_id: str, unique_id: str) -> None:
            """Store entity and unique IDs for the test."""
            self.entity_id = entity_id
            self.unique_id = unique_id

    ent = Ent(
        "switch.native_firewall",
        f"{slugify(entry.data[init_mod.CONF_DEVICE_UNIQUE_ID])}_firewall_rule_rule1",
    )

    entity_registry = MagicMock()
    entity_registry.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [ent],
    )

    device_registry = MagicMock()
    device_registry.async_remove_device = MagicMock()
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: device_registry)
    monkeypatch.setattr(
        init_mod.dr,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [],
    )

    await init_mod._async_update_listener(hass, entry)

    if expect_removed:
        entity_registry.async_remove.assert_called_once_with(ent.entity_id)
    else:
        entity_registry.async_remove.assert_not_called()


@pytest.mark.asyncio
async def test_async_update_listener_skips_native_firewall_entities_when_firewall_sync_is_enabled(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Native entities should remain when sync is enabled for this entry."""
    entry = make_config_entry(
        data={
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
            CONF_SYNC_FIREWALL_AND_NAT: True,
        },
        unique_id="unit two",
    )
    setattr(entry.runtime_data, init_mod.SHOULD_RELOAD, True)

    hass = ph_hass
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    class Ent:
        """Simple entity record for registry cleanup assertions."""

        def __init__(self, entity_id: str, unique_id: str) -> None:
            """Store entity and unique IDs for the test."""
            self.entity_id = entity_id
            self.unique_id = unique_id

    ent = Ent(
        "switch.native_firewall",
        f"{slugify(entry.data[init_mod.CONF_DEVICE_UNIQUE_ID])}_firewall_rule_rule1",
    )

    entity_registry = MagicMock()
    entity_registry.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [ent],
    )

    device_registry = MagicMock()
    device_registry.async_remove_device = MagicMock()
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: device_registry)
    monkeypatch.setattr(
        init_mod.dr,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [],
    )

    await init_mod._async_update_listener(hass, entry)

    entity_registry.async_remove.assert_not_called()


@pytest.mark.asyncio
async def test_async_update_listener_uses_shared_default_for_smart_entity_pruning(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Missing SMART sync config should preserve registered SMART entities."""
    entry = make_config_entry(
        data={init_mod.CONF_DEVICE_UNIQUE_ID: "dev1"},
        unique_id="u123",
    )
    setattr(entry.runtime_data, init_mod.SHOULD_RELOAD, True)
    hass = ph_hass
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    smart_entity = MagicMock()
    smart_entity.entity_id = "binary_sensor.opnsense_smart_nvme0_status"
    smart_entity.unique_id = f"{entry.data[init_mod.CONF_DEVICE_UNIQUE_ID]}_smart_nvme0_status"
    telemetry_entity = MagicMock()
    telemetry_entity.entity_id = "sensor.opnsense_cpu"
    telemetry_entity.unique_id = f"{entry.data[init_mod.CONF_DEVICE_UNIQUE_ID]}_telemetry_cpu"

    entity_registry = MagicMock()
    entity_registry.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [smart_entity, telemetry_entity],
    )

    device_registry = MagicMock()
    device_registry.async_remove_device = MagicMock()
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: device_registry)
    monkeypatch.setattr(
        init_mod.dr,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [],
    )

    await init_mod._async_update_listener(hass, entry)

    entity_registry.async_remove.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("dt_enabled", "via_device_id", "tracker_device_id", "expect_updated"),
    [
        (False, True, "tracked-device", True),
        (False, False, "tracked-device", True),
        (True, True, "tracked-device", False),
        (False, True, None, False),
    ],
)
async def test_async_update_listener_device_removal_param(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
    dt_enabled: Any,
    via_device_id: Any,
    tracker_device_id: Any,
    expect_updated: Any,
) -> None:
    """Remove only this config entry from tracked devices when tracking is disabled."""
    # create an entry with the device tracker option set per parameter
    entry = make_config_entry(
        data={init_mod.CONF_DEVICE_UNIQUE_ID: "dev1"},
        options={init_mod.CONF_DEVICE_TRACKER_ENABLED: dt_enabled},
    )
    setattr(entry.runtime_data, init_mod.SHOULD_RELOAD, True)

    hass = ph_hass
    hass.config_entries.async_reload = AsyncMock()
    hass.data = {}

    # ensure hass.async_create_task exists for scheduling reload
    if not hasattr(hass, "async_create_task"):
        hass.async_create_task = MagicMock()

    dt_ent = None
    if tracker_device_id is not None:
        dt_ent = MagicMock(
            entity_id=f"device_tracker.{tracker_device_id}",
            domain=init_mod.Platform.DEVICE_TRACKER,
            unique_id=f"{entry.unique_id}_{tracker_device_id}",
            device_id=tracker_device_id,
        )

    # prepare a single device entry returned by the device registry
    device = MagicMock()
    device.via_device_id = via_device_id
    device.id = tracker_device_id or "d_device"
    device.name = "devname"

    dr_reg = MagicMock()
    dr_reg.async_remove_device = MagicMock()
    dr_reg.async_update_device = MagicMock()
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: dr_reg)
    monkeypatch.setattr(
        init_mod.dr,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [device],
    )

    # ensure no entity registry removals interfere
    er_reg = MagicMock()
    er_reg.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: er_reg)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [dt_ent] if dt_ent is not None else [],
    )

    await init_mod._async_update_listener(hass, entry)

    dr_reg.async_remove_device.assert_not_called()
    if tracker_device_id is None:
        er_reg.async_remove.assert_not_called()
    if expect_updated:
        dr_reg.async_update_device.assert_called_once_with(
            device.id, remove_config_entry_id=entry.entry_id
        )
    else:
        dr_reg.async_update_device.assert_not_called()


@pytest.mark.asyncio
async def test_async_update_listener_detaches_no_parent_tracker_device(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Trackers with no parent remain detached from removed config entry."""
    entry = make_config_entry(
        data={init_mod.CONF_DEVICE_UNIQUE_ID: "router-mac"},
        options={init_mod.CONF_DEVICE_TRACKER_ENABLED: False},
    )
    setattr(entry.runtime_data, init_mod.SHOULD_RELOAD, True)

    ph_hass.config_entries.async_reload = AsyncMock()
    ph_hass.data = {}
    if not hasattr(ph_hass, "async_create_task"):
        ph_hass.async_create_task = MagicMock()

    dt_ent = MagicMock(
        entity_id="device_tracker.tracked_device",
        domain=init_mod.Platform.DEVICE_TRACKER,
        unique_id=f"{entry.unique_id}_mac_aabbccddeeff",
        device_id="tracker-device-no-parent",
    )
    sensor_ent = MagicMock(
        entity_id="sensor.system_uptime",
        domain=init_mod.Platform.SENSOR,
        unique_id=f"{entry.unique_id}_system_uptime",
    )
    er_reg = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", MagicMock(return_value=er_reg))
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        MagicMock(return_value=[dt_ent, sensor_ent]),
    )

    tracker_without_parent = MagicMock(id="tracker-device-no-parent", via_device_id=None)
    non_tracker_no_parent = MagicMock(id="nontracker-no-parent-device", via_device_id=None)
    dr_reg = MagicMock()
    dr_reg.async_update_device = MagicMock()
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: dr_reg)
    monkeypatch.setattr(
        init_mod.dr,
        "async_entries_for_config_entry",
        MagicMock(return_value=[tracker_without_parent, non_tracker_no_parent]),
    )

    await init_mod._async_update_listener(ph_hass, entry)

    er_reg.async_remove.assert_called_once_with(dt_ent.entity_id)
    assert (
        call(tracker_without_parent.id, remove_config_entry_id=entry.entry_id)
        in dr_reg.async_update_device.mock_calls
    )
    assert (
        call(
            non_tracker_no_parent.id,
            remove_config_entry_id=entry.entry_id,
        )
        not in dr_reg.async_update_device.mock_calls
    )
    assert (
        call(non_tracker_no_parent.id, remove_config_entry_id=entry.entry_id, via_device_id=None)
        not in dr_reg.async_update_device.mock_calls
    )
    assert dr_reg.async_update_device.call_count == 1


@pytest.mark.asyncio
async def test_async_update_listener_detaches_tracker_device_without_entity(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Detach a router-linked tracker device after its entity was already removed."""
    entry = make_config_entry(
        data={init_mod.CONF_DEVICE_UNIQUE_ID: "router-mac"},
        options={init_mod.CONF_DEVICE_TRACKER_ENABLED: False},
    )
    setattr(entry.runtime_data, init_mod.SHOULD_RELOAD, True)

    ph_hass.config_entries.async_reload = AsyncMock()
    ph_hass.data = {}

    er_reg = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", MagicMock(return_value=er_reg))
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        MagicMock(return_value=[]),
    )

    router_device = MagicMock(
        id="router-device-id",
        identifiers={(init_mod.DOMAIN, "router-mac")},
        via_device_id=None,
    )
    tracker_without_entity = MagicMock(
        id="tracker-without-entity",
        identifiers=set(),
        via_device_id=router_device.id,
        config_entries={entry.entry_id},
    )
    unrelated_device = MagicMock(
        id="unrelated-device",
        identifiers=set(),
        via_device_id="other-router-id",
        config_entries={entry.entry_id},
    )
    dr_reg = MagicMock()
    monkeypatch.setattr(init_mod.dr, "async_get", MagicMock(return_value=dr_reg))
    monkeypatch.setattr(
        init_mod.dr,
        "async_entries_for_config_entry",
        MagicMock(return_value=[router_device, tracker_without_entity, unrelated_device]),
    )

    await init_mod._async_update_listener(ph_hass, entry)

    dr_reg.async_update_device.assert_called_once_with(
        tracker_without_entity.id,
        remove_config_entry_id=entry.entry_id,
        via_device_id=None,
    )


@pytest.mark.asyncio
async def test_async_update_listener_detaches_tracker_when_router_and_entity_are_missing(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Detach a MAC tracker whose removed router remains as a stale parent."""
    entry = make_config_entry(
        data={init_mod.CONF_DEVICE_UNIQUE_ID: "router-mac"},
        options={init_mod.CONF_DEVICE_TRACKER_ENABLED: False},
    )
    setattr(entry.runtime_data, init_mod.SHOULD_RELOAD, True)

    ph_hass.config_entries.async_reload = AsyncMock()
    ph_hass.data = {}

    er_reg = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", MagicMock(return_value=er_reg))
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        MagicMock(return_value=[]),
    )

    tracker_without_router_or_entity = MagicMock(
        id="tracker-without-router-or-entity",
        identifiers=set(),
        connections={(init_mod.dr.CONNECTION_NETWORK_MAC, "aa:bb:cc:dd:ee:ff")},
        via_device_id="removed-router-device-id",
        config_entries={entry.entry_id},
    )
    unrelated_device = MagicMock(
        id="unrelated-device",
        identifiers=set(),
        connections=set(),
        via_device_id="unrelated-parent-id",
        config_entries={entry.entry_id},
    )
    dr_reg = MagicMock()
    dr_reg.async_get = MagicMock(return_value=None)
    monkeypatch.setattr(init_mod.dr, "async_get", MagicMock(return_value=dr_reg))
    monkeypatch.setattr(
        init_mod.dr,
        "async_entries_for_config_entry",
        MagicMock(return_value=[tracker_without_router_or_entity, unrelated_device]),
    )

    await init_mod._async_update_listener(ph_hass, entry)

    dr_reg.async_update_device.assert_called_once_with(
        tracker_without_router_or_entity.id,
        remove_config_entry_id=entry.entry_id,
        via_device_id=None,
    )


@pytest.mark.asyncio
async def test_async_update_listener_preserves_existing_tracker_parent_when_parent_device_exists(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Keep a shared tracker parent when disabling tracking if that parent still exists."""
    entry = make_config_entry(
        data={init_mod.CONF_DEVICE_UNIQUE_ID: "router-mac"},
        options={init_mod.CONF_DEVICE_TRACKER_ENABLED: False},
    )
    setattr(entry.runtime_data, init_mod.SHOULD_RELOAD, True)

    ph_hass.config_entries.async_reload = AsyncMock()
    ph_hass.data = {}
    if not hasattr(ph_hass, "async_create_task"):
        ph_hass.async_create_task = MagicMock()

    dt_ent = MagicMock(
        entity_id="device_tracker.shared_tracker",
        domain=init_mod.Platform.DEVICE_TRACKER,
        unique_id=f"{entry.unique_id}_mac_aabbccddeeff",
        device_id="shared-device",
    )
    er_reg = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", MagicMock(return_value=er_reg))
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        MagicMock(return_value=[dt_ent]),
    )

    shared_parent = MagicMock(id="shared-router-device-id")
    shared_tracker = MagicMock(
        id="shared-device",
        identifiers=set(),
        via_device_id=shared_parent.id,
        config_entries={entry.entry_id},
    )
    dr_reg = MagicMock()
    dr_reg.async_update_device = MagicMock()
    dr_reg.async_get = MagicMock(return_value=shared_parent)
    monkeypatch.setattr(init_mod.dr, "async_get", MagicMock(return_value=dr_reg))
    monkeypatch.setattr(
        init_mod.dr,
        "async_entries_for_config_entry",
        MagicMock(return_value=[shared_tracker]),
    )

    await init_mod._async_update_listener(ph_hass, entry)

    er_reg.async_remove.assert_called_once_with(dt_ent.entity_id)
    dr_reg.async_get.assert_called_once_with(shared_parent.id)
    dr_reg.async_update_device.assert_called_once_with(
        shared_tracker.id, remove_config_entry_id=entry.entry_id
    )
    assert (
        call(shared_tracker.id, remove_config_entry_id=entry.entry_id, via_device_id=None)
        not in dr_reg.async_update_device.mock_calls
    )


@pytest.mark.asyncio
async def test_async_update_listener_reparents_tracker_link_to_remaining_opnsense_router(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Disabling tracking reassigns shared tracker parent to surviving OPNsense router."""
    entry = make_config_entry(
        data={init_mod.CONF_DEVICE_UNIQUE_ID: "router-mac"},
        options={init_mod.CONF_DEVICE_TRACKER_ENABLED: False},
    )
    setattr(entry.runtime_data, init_mod.SHOULD_RELOAD, True)

    ph_hass.config_entries.async_reload = AsyncMock()
    ph_hass.data = {}
    if not hasattr(ph_hass, "async_create_task"):
        ph_hass.async_create_task = MagicMock()

    dt_ent = MagicMock(
        entity_id="device_tracker.living_room_device",
        domain=init_mod.Platform.DEVICE_TRACKER,
        unique_id=f"{entry.unique_id}_mac_aabbccddeeff",
        device_id="shared-device",
    )
    dt_ent_non_router = MagicMock(
        entity_id="device_tracker.kitchen_device",
        domain=init_mod.Platform.DEVICE_TRACKER,
        unique_id=f"{entry.unique_id}_mac_cdddeeff0011",
        device_id="nonopnsense-device",
    )
    sensor_ent = MagicMock(
        entity_id="sensor.system_uptime",
        domain=init_mod.Platform.SENSOR,
        unique_id=f"{entry.unique_id}_system_uptime",
    )
    er_reg = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", MagicMock(return_value=er_reg))
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        MagicMock(return_value=[dt_ent, dt_ent_non_router, sensor_ent]),
    )

    router_device = MagicMock(
        id="router-device-id",
        identifiers={(init_mod.DOMAIN, "router-mac")},
        via_device_id=None,
    )
    surviving_opnsense_a = MagicMock(
        entry_id="survive-entry-b",
        domain=init_mod.DOMAIN,
        data={init_mod.CONF_DEVICE_UNIQUE_ID: "survive-b"},
    )
    surviving_opnsense_b = MagicMock(
        entry_id="survive-entry-a",
        domain=init_mod.DOMAIN,
        data={init_mod.CONF_DEVICE_UNIQUE_ID: "survive-a"},
    )
    non_opnsense_entry = MagicMock(
        entry_id="non-opnsense-entry",
        domain="other",
        data={init_mod.CONF_DEVICE_UNIQUE_ID: "non-opnsense"},
    )
    shared_router_b = MagicMock(id="survivor-b-router")
    shared_router_a = MagicMock(id="survivor-a-router")
    linked_to_router = MagicMock(
        id="shared-device",
        via_device_id=router_device.id,
        config_entries={
            entry.entry_id,
            surviving_opnsense_a.entry_id,
            surviving_opnsense_b.entry_id,
            non_opnsense_entry.entry_id,
        },
    )
    linked_to_router_non_opnsense_only = MagicMock(
        id="nonopnsense-device",
        via_device_id=router_device.id,
        config_entries={entry.entry_id, non_opnsense_entry.entry_id},
    )
    linked_to_other_router = MagicMock(id="other-device", via_device_id="other-device-id")
    no_parent = MagicMock(id="noparent-device", via_device_id=None)
    async_get_entry_map = {
        entry.entry_id: entry,
        surviving_opnsense_a.entry_id: surviving_opnsense_a,
        surviving_opnsense_b.entry_id: surviving_opnsense_b,
        non_opnsense_entry.entry_id: non_opnsense_entry,
    }
    ph_hass.config_entries.async_get_entry = MagicMock(side_effect=async_get_entry_map.get)
    identifier_router_map = {
        (init_mod.DOMAIN, "router-mac"): router_device,
        (init_mod.DOMAIN, "survive-b"): shared_router_b,
        (init_mod.DOMAIN, "survive-a"): shared_router_a,
    }
    dr_reg = MagicMock()

    def get_device(
        *,
        identifiers: set[tuple[str, str]] | None = None,
        **kwargs: Any,
    ) -> Any:
        if identifiers is None:
            return None
        key = next(iter(identifiers))
        return identifier_router_map.get(key)

    dr_reg.async_get_device = MagicMock(side_effect=get_device)
    monkeypatch.setattr(init_mod.dr, "async_get", MagicMock(return_value=dr_reg))
    monkeypatch.setattr(
        init_mod.dr,
        "async_entries_for_config_entry",
        MagicMock(
            return_value=[
                router_device,
                linked_to_router,
                linked_to_router_non_opnsense_only,
                linked_to_other_router,
                no_parent,
            ]
        ),
    )

    await init_mod._async_update_listener(ph_hass, entry)

    er_reg.async_remove.assert_has_calls(
        [call(dt_ent.entity_id), call(dt_ent_non_router.entity_id)],
        any_order=True,
    )
    assert call(sensor_ent.entity_id) not in er_reg.async_remove.mock_calls
    dr_reg.async_update_device.assert_has_calls(
        [
            call(
                linked_to_router.id,
                remove_config_entry_id=entry.entry_id,
                via_device_id="survivor-a-router",
            ),
            call(
                linked_to_router_non_opnsense_only.id,
                remove_config_entry_id=entry.entry_id,
                via_device_id=None,
            ),
        ],
        any_order=True,
    )
    assert (
        call(
            linked_to_other_router.id,
            via_device_id=None,
        )
        not in dr_reg.async_update_device.mock_calls
    )
    assert (
        call(no_parent.id, remove_config_entry_id=entry.entry_id)
        not in dr_reg.async_update_device.mock_calls
    )
    assert (
        call(no_parent.id, remove_config_entry_id=entry.entry_id, via_device_id=None)
        not in dr_reg.async_update_device.mock_calls
    )
    assert dr_reg.async_update_device.call_count == 2


@pytest.mark.asyncio
async def test_async_setup_entry_firmware_below_min(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_client: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry returns False for devices with firmware below minimum supported."""
    # fake client where device id matches but firmware is below min
    patch_opnsense_client(monkeypatch, init_mod, fake_client(firmware_version="1.0"))
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        }
    )
    # use hass fixture for aiohttp helpers
    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data.setdefault("aiohttp_connector", {})

    res = await init_mod.async_setup_entry(hass, entry)
    assert res is False


@pytest.mark.asyncio
async def test_async_setup_entry_firmware_between_min_and_ltd(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_client: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry logs a warning issue for firmware between min and LTD but continues."""
    patch_opnsense_client(monkeypatch, init_mod, fake_client(firmware_version="25.1"))
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )
    # capture calls to the issue registry to assert a warning issue is created
    create_issue_mock = MagicMock()
    monkeypatch.setattr(init_mod.ir, "async_create_issue", create_issue_mock)

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        }
    )
    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data.setdefault("aiohttp_connector", {})

    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True
    # verify the LTD deprecation/warning issue was created
    assert create_issue_mock.called, (
        "async_create_issue should have been called for firmware between min and LTD"
    )
    call_args = create_issue_mock.call_args
    # args: (hass, domain, issue_id, ...)
    assert call_args[0][1] == init_mod.DOMAIN
    expected_issue_id = f"{entry.data[init_mod.CONF_DEVICE_UNIQUE_ID]}_opnsense_below_ltd_firmware_{init_mod.OPNSENSE_LTD_FIRMWARE}"
    assert call_args[0][2] == expected_issue_id
    assert call_args[1].get("severity") == init_mod.ir.IssueSeverity.WARNING


@pytest.mark.asyncio
async def test_migrate_2_to_3_missing_device_id(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """_migrate_2_to_3 returns False when the client provides no device id."""
    client = fake_client(device_id=None)()
    cfg = MagicMock()
    cfg.data = {
        CONF_URL: "http://1.2.3.4",
        CONF_USERNAME: "u",
        CONF_PASSWORD: "p",
    }
    cfg.version = 2
    # set up hass fixture-like object for registry access
    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    # avoid touching real entity/device registry and aiohttp helpers
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: MagicMock())
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: MagicMock())
    res = await init_mod._migrate_2_to_3(hass, cfg, client)
    assert res is False


@pytest.mark.asyncio
async def test_migrate_2_to_3_success(monkeypatch: pytest.MonkeyPatch, fake_client: Any) -> None:
    """_migrate_2_to_3 updates device and entity identifiers when client reports new device id."""
    client = fake_client(device_id="newdev")()

    # fake device entries and entity entries
    dev = MagicMock()
    dev.id = "d1"
    dev.identifiers = {("opnsense", "old")}

    ent = MagicMock()
    ent.entity_id = "sensor.x"
    ent.unique_id = "old"
    ent.device_id = "d1"

    er_reg = MagicMock()
    er_reg.async_update_entity = MagicMock(
        return_value=MagicMock(entity_id=ent.entity_id, unique_id="new")
    )
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: er_reg)
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: [ent]
    )

    dr_reg = MagicMock()
    dr_reg.async_update_device = MagicMock(
        return_value=MagicMock(id=dev.id, identifiers={("opnsense", "newdev")})
    )
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: dr_reg)
    monkeypatch.setattr(
        init_mod.dr, "async_entries_for_config_entry", lambda registry, config_entry_id: [dev]
    )

    cfg = MagicMock()
    cfg.data = {
        CONF_URL: "http://1.2.3.4",
        CONF_USERNAME: "u",
        CONF_PASSWORD: "p",
    }
    cfg.version = 2
    cfg.entry_id = "e"
    cfg.unique_id = "old_unique"

    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)
    res = await init_mod._migrate_2_to_3(hass, cfg, client)
    assert res is True
    assert dr_reg.async_update_device.called, "device identifiers should be updated"
    assert er_reg.async_update_entity.called, "entity unique_ids should be updated"
    assert hass.config_entries.async_update_entry.called
    kwargs = hass.config_entries.async_update_entry.call_args.kwargs
    assert kwargs["version"] == 3
    assert kwargs["unique_id"] == "newdev"
    assert kwargs["data"][init_mod.CONF_DEVICE_UNIQUE_ID] == "newdev"


@pytest.mark.asyncio
async def test_migrate_2_to_3_normalizes_legacy_entity_unique_ids_with_slugify(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """_migrate_2_to_3 should slugify legacy unique IDs with colons and case."""
    client = fake_client(device_id="newdev")()

    ent = MagicMock()
    ent.entity_id = "sensor.x"
    ent.unique_id = "AA:BB:CC"
    er_reg = MagicMock()
    er_reg.async_update_entity = MagicMock(
        return_value=MagicMock(entity_id=ent.entity_id, unique_id="updated")
    )
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: er_reg)
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: [ent]
    )

    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: MagicMock())
    monkeypatch.setattr(
        init_mod.dr, "async_entries_for_config_entry", lambda registry, config_entry_id: []
    )

    cfg = MagicMock()
    cfg.data = {
        CONF_URL: "http://1.2.3.4",
        CONF_USERNAME: "u",
        CONF_PASSWORD: "p",
    }
    cfg.version = 2
    cfg.entry_id = "e"
    cfg.unique_id = "old_unique"

    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    await init_mod._migrate_2_to_3(hass, cfg, client)
    expected_unique_id = slugify("newdev_mac_AA:BB:CC")
    er_reg.async_update_entity.assert_called_once_with(
        ent.entity_id, new_unique_id=expected_unique_id
    )


@pytest.mark.asyncio
async def test_migrate_2_to_3_returns_false_when_update_entry_fails(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """_migrate_2_to_3 should fail when config entry update returns False."""
    client = fake_client(device_id="newdev")()

    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: MagicMock())
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: []
    )
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: MagicMock())
    monkeypatch.setattr(
        init_mod.dr, "async_entries_for_config_entry", lambda registry, config_entry_id: []
    )

    cfg = MagicMock()
    cfg.data = {
        CONF_URL: "http://1.2.3.4",
        CONF_USERNAME: "u",
        CONF_PASSWORD: "p",
    }
    cfg.version = 2
    cfg.entry_id = "e"
    cfg.unique_id = "old_unique"

    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=False)

    res = await init_mod._migrate_2_to_3(hass, cfg, client)
    assert res is False


@pytest.mark.asyncio
async def test_async_setup_entry_awesomeversion_exception(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_client: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry should continue when AwesomeVersion comparison raises an exception."""

    # fake client where device id matches but awesomeversion comparison raises
    # monkeypatch AwesomeVersion to a class that raises on comparison
    class DummyAV:
        """AwesomeVersion replacement that raises on comparisons."""

        def __init__(self, v: Any) -> None:
            """Store the version string used by the comparison stub."""
            self.v = v

        def __lt__(self, other: Any) -> None:
            """Raise a compare exception so setup falls back to the safe path."""
            raise init_mod.awesomeversion.exceptions.AwesomeVersionCompareException

    patch_opnsense_client(monkeypatch, init_mod, fake_client())
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )
    monkeypatch.setattr(init_mod.awesomeversion, "AwesomeVersion", DummyAV)
    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        }
    )
    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()

    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True


@pytest.mark.asyncio
async def test_async_unload_entry_unload_fails(
    ph_hass: Any, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """async_unload_entry returns False and keeps runtime resources when unload fails."""
    entry = make_config_entry(entry_id="e_unload_fail")
    entry.as_dict = lambda: {"id": "x"}
    setattr(entry.runtime_data, init_mod.LOADED_PLATFORMS, ["p1"])
    fake_client = MagicMock()
    fake_client.async_close = AsyncMock()
    setattr(entry.runtime_data, init_mod.OPNSENSE_CLIENT, fake_client)

    hass = ph_hass
    # unload_platforms returns False
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=False)
    hass.data = {init_mod.DOMAIN: {entry.entry_id: fake_client}}
    res = await init_mod.async_unload_entry(hass, entry)
    assert res is False
    # hass.data should still have the entry
    assert entry.entry_id in hass.data[init_mod.DOMAIN]
    fake_client.async_close.assert_not_awaited()


@pytest.mark.asyncio
async def test_migrate_3_to_4_filesystem_and_remove(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """_migrate_3_to_4 handles filesystem telemetry renames and removes connected_client_count entities."""
    client = fake_client(telemetry={"filesystems": [{"device": "/dev/sda1", "mountpoint": "/"}]})()

    # entities: one that maps telemetry_filesystems, one that is connected_client_count
    # make e1's unique_id include the processed device name so the migration will match
    e1 = MagicMock()
    e1.entity_id = "sensor.fs"
    e1.unique_id = "abc_telemetry_filesystems_slash_dev_slash_sda1"
    e2 = MagicMock()
    e2.entity_id = "sensor.clients"
    e2.unique_id = "something_connected_client_count"

    er_reg = MagicMock()
    er_reg.async_update_entity = MagicMock(
        return_value=MagicMock(entity_id=e1.entity_id, unique_id="updated")
    )
    er_reg.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: er_reg)
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: [e1, e2]
    )

    cfg = MagicMock()
    cfg.data = {
        CONF_URL: "http://1.2.3.4",
        CONF_USERNAME: "u",
        CONF_PASSWORD: "p",
    }
    cfg.version = 3
    cfg.entry_id = "e3"

    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)
    # avoid aiohttp connector creation
    res = await init_mod._migrate_3_to_4(hass, cfg, client)
    assert res is True
    # Ensure the connected_client_count entity was removed (called with entity_id)
    er_reg.async_remove.assert_called_once_with(e2.entity_id)
    # Ensure telemetry-mapped entity was updated with the expected new unique_id
    expected_new_unique_id = "abc_telemetry_filesystems_root"
    er_reg.async_update_entity.assert_called_once_with(
        e1.entity_id, new_unique_id=expected_new_unique_id
    )


@pytest.mark.asyncio
async def test_migrate_3_to_4_preserves_mixed_marker_precedence(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """Mixed legacy markers follow the original migration branch precedence."""
    client = fake_client(telemetry={"filesystems": []})()

    gateway_entity = MagicMock(
        entity_id="sensor.gateway",
        unique_id="abc_telemetry_gateway_lan_connected_client_count",
    )
    connected_entity = MagicMock(
        entity_id="sensor.clients",
        unique_id="abc_connected_client_count_telemetry_openvpn_vpn",
    )
    openvpn_entity = MagicMock(
        entity_id="sensor.openvpn",
        unique_id="abc_telemetry_openvpn_vpn",
    )

    entity_registry = MagicMock()
    entity_registry.async_update_entity = MagicMock(
        return_value=MagicMock(entity_id=gateway_entity.entity_id, unique_id="updated")
    )
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [gateway_entity, connected_entity, openvpn_entity],
    )

    config_entry = MagicMock(version=3, entry_id="e3")
    hass = MagicMock(spec=HomeAssistant)
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    result = await init_mod._migrate_3_to_4(hass, config_entry, client)

    assert result is True
    assert entity_registry.async_update_entity.call_args_list == [
        call(
            gateway_entity.entity_id,
            new_unique_id="abc_gateway_lan_connected_client_count",
        ),
        call(openvpn_entity.entity_id, new_unique_id="abc_openvpn_vpn"),
    ]
    entity_registry.async_remove.assert_called_once_with(connected_entity.entity_id)


@pytest.mark.asyncio
async def test_migrate_3_to_4_filesystem_preserves_unique_id_prefix(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """Filesystem remap should only replace the suffix after telemetry_filesystems_."""
    client = fake_client(telemetry={"filesystems": [{"device": "/dev/sda1", "mountpoint": "/"}]})()

    e1 = MagicMock()
    e1.entity_id = "sensor.fs"
    e1.unique_id = "slash_dev_slash_sda1_telemetry_filesystems_slash_dev_slash_sda1"

    er_reg = MagicMock()
    er_reg.async_update_entity = MagicMock(
        return_value=MagicMock(entity_id=e1.entity_id, unique_id="updated")
    )
    er_reg.async_remove = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: er_reg)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [e1],
    )

    cfg = MagicMock()
    cfg.data = {
        CONF_URL: "http://1.2.3.4",
        CONF_USERNAME: "u",
        CONF_PASSWORD: "p",
    }
    cfg.version = 3
    cfg.entry_id = "e3"

    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    res = await init_mod._migrate_3_to_4(hass, cfg, client)
    assert res is True
    er_reg.async_update_entity.assert_called_once_with(
        e1.entity_id,
        new_unique_id="slash_dev_slash_sda1_telemetry_filesystems_root",
    )


@pytest.mark.asyncio
async def test_migrate_3_to_4_filesystem_skips_and_non_root_mountpoint(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """_migrate_3_to_4 skips unmapped entities and maps non-root filesystem mountpoints."""
    client = fake_client(
        telemetry={
            "filesystems": [
                {"device": "/dev/other", "mountpoint": "/unused"},
                {"device": "/dev/sdb1", "mountpoint": "/mnt/data"},
                {"device": "data", "mountpoint": "/data"},
            ]
        }
    )()

    matched = MagicMock()
    matched.entity_id = "sensor.fs_data"
    matched.unique_id = "abc_telemetry_filesystems_slash_dev_slash_sdb1"
    unmatched_filesystem = MagicMock()
    unmatched_filesystem.entity_id = "sensor.fs_missing"
    unmatched_filesystem.unique_id = "abc_telemetry_filesystems_slash_dev_slash_missing"
    unchanged_filesystem = MagicMock()
    unchanged_filesystem.entity_id = "sensor.fs_unchanged"
    unchanged_filesystem.unique_id = "abc_telemetry_filesystems_data"
    unknown_sensor = MagicMock()
    unknown_sensor.entity_id = "sensor.unmapped"
    unknown_sensor.unique_id = "abc_unmapped"

    er_reg = MagicMock()
    er_reg.async_update_entity = MagicMock(
        return_value=MagicMock(entity_id=matched.entity_id, unique_id="updated")
    )
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: er_reg)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [
            matched,
            unmatched_filesystem,
            unchanged_filesystem,
            unknown_sensor,
        ],
    )

    cfg = MagicMock()
    cfg.data = {
        CONF_URL: "http://1.2.3.4",
        CONF_USERNAME: "u",
        CONF_PASSWORD: "p",
    }
    cfg.version = 3
    cfg.entry_id = "e3"

    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    res = await init_mod._migrate_3_to_4(hass, cfg, client)

    assert res is True
    er_reg.async_update_entity.assert_called_once_with(
        matched.entity_id, new_unique_id="abc_telemetry_filesystems_mnt_data"
    )


@pytest.mark.asyncio
async def test_migrate_3_to_4_skips_filesystems_when_telemetry_is_not_mapping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_migrate_3_to_4 should defer filesystem remaps when telemetry is invalid."""

    class Client:
        """Fake client returning invalid telemetry during migration."""

        async def get_telemetry(self) -> None:
            """Return an invalid telemetry payload for migration hardening."""
            return

    client = Client()

    interface_entity = MagicMock()
    interface_entity.entity_id = "sensor.interface"
    interface_entity.unique_id = "abc_telemetry_interface_lan"
    filesystem_entity = MagicMock()
    filesystem_entity.entity_id = "sensor.fs"
    filesystem_entity.unique_id = "abc_telemetry_filesystems_slash_dev_slash_sda1"

    entity_registry = MagicMock()
    entity_registry.async_update_entity = MagicMock(
        return_value=MagicMock(entity_id=interface_entity.entity_id, unique_id="updated")
    )
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [interface_entity, filesystem_entity],
    )

    config_entry = MagicMock()
    config_entry.version = 3
    config_entry.entry_id = "e3"

    hass = MagicMock(spec=HomeAssistant)
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    result = await init_mod._migrate_3_to_4(hass, config_entry, client)

    assert result is False
    entity_registry.async_update_entity.assert_called_once_with(
        interface_entity.entity_id,
        new_unique_id="abc_interface_lan",
    )
    hass.config_entries.async_update_entry.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "telemetry",
    [
        {"filesystems": None},
        {"filesystems": [None]},
        {
            "filesystems": [
                {"device": None, "mountpoint": "/"},
                {"device": "/dev/sda1", "mountpoint": None},
            ]
        },
        {"filesystems": [{"mountpoint": "/"}]},
        {"filesystems": [{"device": "/dev/sda1"}]},
        {"filesystems": [{"device": 7, "mountpoint": "/"}]},
        {},
    ],
)
async def test_migrate_3_to_4_defers_filesystems_when_payload_is_invalid(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any, telemetry: dict[str, Any]
) -> None:
    """_migrate_3_to_4 should defer filesystem remaps when telemetry is invalid."""
    client = fake_client(telemetry=telemetry)()

    filesystem_entity = MagicMock()
    filesystem_entity.entity_id = "sensor.fs"
    filesystem_entity.unique_id = "abc_telemetry_filesystems_slash_dev_slash_sda1"

    entity_registry = MagicMock()
    entity_registry.async_update_entity = MagicMock(
        return_value=MagicMock(entity_id=filesystem_entity.entity_id, unique_id="updated")
    )
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        lambda registry, config_entry_id: [filesystem_entity],
    )

    config_entry = MagicMock()
    config_entry.version = 3
    config_entry.entry_id = "e3"

    hass = MagicMock(spec=HomeAssistant)
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    result = await init_mod._migrate_3_to_4(hass, config_entry, client)

    assert result is False
    entity_registry.async_update_entity.assert_not_called()
    hass.config_entries.async_update_entry.assert_not_called()


@pytest.mark.asyncio
async def test_migrate_3_to_4_returns_false_when_update_entry_fails(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """_migrate_3_to_4 should fail when config entry update returns False."""
    client = fake_client(telemetry={})()
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: MagicMock())
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: []
    )

    cfg = MagicMock()
    cfg.data = {
        CONF_URL: "http://1.2.3.4",
        CONF_USERNAME: "u",
        CONF_PASSWORD: "p",
    }
    cfg.version = 3
    cfg.entry_id = "e3"

    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=False)

    res = await init_mod._migrate_3_to_4(hass, cfg, client)

    assert res is False


@pytest.mark.asyncio
async def test_migrate_2_to_3_handles_entity_update_value_error(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """When entity_registry.async_update_entity raises ValueError, migration continues."""
    client = fake_client(device_id="newdev")()

    # single entity that will cause async_update_entity to raise
    ent = MagicMock()
    ent.entity_id = "sensor.x"
    ent.unique_id = "old"

    er_reg = MagicMock()
    er_reg.async_update_entity = MagicMock(side_effect=ValueError("bad entity"))
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: er_reg)
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: [ent]
    )

    # no devices to update
    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: MagicMock())
    monkeypatch.setattr(
        init_mod.dr, "async_entries_for_config_entry", lambda registry, config_entry_id: []
    )

    cfg = MagicMock()
    cfg.data = {
        CONF_URL: "http://1.2.3.4",
        CONF_USERNAME: "u",
        CONF_PASSWORD: "p",
    }
    cfg.version = 2
    cfg.entry_id = "e"
    cfg.unique_id = "old_unique"

    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    res = await init_mod._migrate_2_to_3(hass, cfg, client)
    assert res is True
    # ensure we attempted to update the entity (which raised) and migration completed
    er_reg.async_update_entity.assert_called_once_with(ent.entity_id, new_unique_id=ANY)
    assert hass.config_entries.async_update_entry.called


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", [KeyError("k"), ValueError("v")])
async def test_migrate_3_to_4_handles_remove_exceptions(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any, exc: BaseException | None
) -> None:
    """If entity_registry.async_remove raises KeyError/ValueError, migration fails."""
    client = fake_client(telemetry={})()

    e = MagicMock()
    e.entity_id = "sensor.clients"
    e.unique_id = "something_connected_client_count"

    er_reg = MagicMock()
    er_reg.async_remove = MagicMock(side_effect=exc)
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: er_reg)
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: [e]
    )

    cfg = MagicMock()
    cfg.data = {
        CONF_URL: "http://1.2.3.4",
        CONF_USERNAME: "u",
        CONF_PASSWORD: "p",
    }
    cfg.version = 3
    cfg.entry_id = "e3"

    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    res = await init_mod._migrate_3_to_4(hass, cfg, client)
    assert res is False
    er_reg.async_remove.assert_called_once_with(e.entity_id)
    hass.config_entries.async_update_entry.assert_not_called()


@pytest.mark.asyncio
async def test_migrate_3_to_4_handles_update_value_error(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """If entity_registry.async_update_entity raises ValueError, migration fails."""
    client = fake_client(telemetry={})()

    e = MagicMock()
    e.entity_id = "sensor.if"
    e.unique_id = "abc_telemetry_interface_eth0"

    er_reg = MagicMock()
    er_reg.async_update_entity = MagicMock(side_effect=ValueError("bad update"))
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: er_reg)
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: [e]
    )

    cfg = MagicMock()
    cfg.data = {
        CONF_URL: "http://1.2.3.4",
        CONF_USERNAME: "u",
        CONF_PASSWORD: "p",
    }
    cfg.version = 3
    cfg.entry_id = "e3"

    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    res = await init_mod._migrate_3_to_4(hass, cfg, client)
    assert res is False
    er_reg.async_update_entity.assert_called_once()
    hass.config_entries.async_update_entry.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("version", "failing_fn"),
    [
        (1, "_migrate_1_to_2"),
        (2, "_migrate_2_to_3"),
        (3, "_migrate_3_to_4"),
        (4, "_migrate_4_to_5"),
    ],
)
async def test_async_migrate_entry_returns_false_when_submigration_fails(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any, version: Any, failing_fn: Any
) -> None:
    """async_migrate_entry should return False when a sub-migration returns False."""
    # make the targeted sub-migration return False
    monkeypatch.setattr(init_mod, failing_fn, AsyncMock(return_value=False))
    client = MagicMock()
    client.async_close = AsyncMock()
    create_client = MagicMock(return_value=client)
    monkeypatch.setattr(init_mod, "create_opnsense_client_from_config_entry", create_client)

    cfg = MagicMock()
    cfg.version = version
    cfg.data = {
        CONF_URL: "http://1.2.3.4",
        CONF_USERNAME: "u",
        CONF_PASSWORD: "p",
    }

    # call with a real hass fixture
    res = await init_mod.async_migrate_entry(ph_hass, cfg)
    assert res is False
    if version == 1:
        create_client.assert_not_called()
        client.async_close.assert_not_awaited()
    else:
        create_client.assert_called_once()
        client.async_close.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exc", [OPNsenseTimeoutError, OPNsenseConnectionError, init_mod.OPNsenseError]
)
async def test_async_migrate_entry_defers_when_migration_client_raises_opnsense_error(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any, exc: type[BaseException]
) -> None:
    """async_migrate_entry should return False when migration-client creation fails."""
    migration_exc = exc("temporary failure")
    create_client = MagicMock(side_effect=migration_exc)
    monkeypatch.setattr(init_mod, "create_opnsense_client_from_config_entry", create_client)

    cfg = MagicMock()
    cfg.version = 2
    cfg.data = {
        CONF_URL: "http://1.2.3.4",
        CONF_USERNAME: "u",
        CONF_PASSWORD: "p",
    }

    res = await init_mod.async_migrate_entry(ph_hass, cfg)
    assert res is False
    create_client.assert_called_once_with(
        hass=ph_hass,
        config_entry=cfg,
        throw_errors=True,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exc", [OPNsenseTimeoutError, OPNsenseConnectionError, init_mod.OPNsenseError]
)
async def test_async_migrate_entry_defers_when_v2_to_3_fails_with_opnsense_error(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any, exc: type[BaseException]
) -> None:
    """async_migrate_entry should return False when v2->v3 raises OPNsense errors."""
    client = MagicMock()
    client.async_close = AsyncMock()
    monkeypatch.setattr(
        init_mod,
        "create_opnsense_client_from_config_entry",
        MagicMock(return_value=client),
    )
    monkeypatch.setattr(
        init_mod, "_migrate_2_to_3", AsyncMock(side_effect=exc("temporary failure"))
    )

    cfg = MagicMock()
    cfg.version = 2
    cfg.data = {
        CONF_URL: "http://1.2.3.4",
        CONF_USERNAME: "u",
        CONF_PASSWORD: "p",
    }

    res = await init_mod.async_migrate_entry(ph_hass, cfg)
    assert res is False
    client.async_close.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exc", [OPNsenseTimeoutError, OPNsenseConnectionError, init_mod.OPNsenseError]
)
async def test_async_migrate_entry_defers_when_v3_to_4_fails_with_opnsense_error(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any, exc: type[BaseException]
) -> None:
    """async_migrate_entry should return False when v3->v4 raises OPNsense errors."""
    client = MagicMock()
    client.async_close = AsyncMock()
    monkeypatch.setattr(
        init_mod,
        "create_opnsense_client_from_config_entry",
        MagicMock(return_value=client),
    )
    monkeypatch.setattr(
        init_mod, "_migrate_3_to_4", AsyncMock(side_effect=exc("temporary failure"))
    )

    cfg = MagicMock()
    cfg.version = 3
    cfg.data = {
        CONF_URL: "http://1.2.3.4",
        CONF_USERNAME: "u",
        CONF_PASSWORD: "p",
    }

    res = await init_mod.async_migrate_entry(ph_hass, cfg)
    assert res is False
    client.async_close.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("version", [2, 3, 4])
async def test_async_migrate_entry_returns_false_when_migration_client_missing(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any, version: int
) -> None:
    """async_migrate_entry should fail client-backed migrations without a client."""
    monkeypatch.setattr(
        init_mod, "create_opnsense_client_from_config_entry", lambda **_kwargs: None
    )

    cfg = MagicMock()
    cfg.version = version
    cfg.data = {
        CONF_URL: "http://1.2.3.4",
        CONF_USERNAME: "u",
        CONF_PASSWORD: "p",
    }
    cfg.title = "router"

    res = await init_mod.async_migrate_entry(ph_hass, cfg)

    assert res is False


@pytest.mark.asyncio
async def test_async_setup_entry_firmware_above_ltd_calls_delete(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_client: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry deletes previous issues when firmware is at or above LTD."""
    patch_opnsense_client(
        monkeypatch, init_mod, fake_client(firmware_version=init_mod.OPNSENSE_LTD_FIRMWARE)
    )
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )
    called = []
    monkeypatch.setattr(init_mod.ir, "async_delete_issue", lambda *a, **k: called.append(True))

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        }
    )
    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = MagicMock()
    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True
    assert called, "async_delete_issue should have been called for firmware >= LTD"


@pytest.mark.asyncio
async def test_async_setup_entry_firmware_at_or_above_ltd_deletes_previous_issues(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_client: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry cleans up previous firmware-related issues for LTD and min thresholds."""
    patch_opnsense_client(
        monkeypatch, init_mod, fake_client(firmware_version=init_mod.OPNSENSE_LTD_FIRMWARE)
    )
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    # capture delete_issue calls
    delete_issue_mock = MagicMock()
    monkeypatch.setattr(init_mod.ir, "async_delete_issue", delete_issue_mock)

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        }
    )
    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = MagicMock()
    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True

    # Expect delete_issue to be called for the previous below-min and below-ltd issue ids
    assert delete_issue_mock.called, "async_delete_issue should have been called"
    called_issue_ids = [call[0][2] for call in delete_issue_mock.call_args_list if len(call[0]) > 2]
    expected_min = f"{entry.data[init_mod.CONF_DEVICE_UNIQUE_ID]}_opnsense_below_min_firmware_{init_mod.OPNSENSE_MIN_FIRMWARE}"
    expected_ltd = f"{entry.data[init_mod.CONF_DEVICE_UNIQUE_ID]}_opnsense_below_ltd_firmware_{init_mod.OPNSENSE_LTD_FIRMWARE}"
    assert expected_min in called_issue_ids
    assert expected_ltd in called_issue_ids


@pytest.mark.asyncio
async def test_async_setup_entry_delete_uses_actual_firmware_string(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_client: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry uses the client's firmware string when deleting previous issues."""
    firmware_str = "99.9"
    patch_opnsense_client(monkeypatch, init_mod, fake_client(firmware_version=firmware_str))
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    calls = MagicMock()
    monkeypatch.setattr(init_mod.ir, "async_delete_issue", calls)

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        }
    )
    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = MagicMock()
    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True

    # Confirm delete_issue was called for the expected issue ids
    expected_min = f"{entry.data[init_mod.CONF_DEVICE_UNIQUE_ID]}_opnsense_below_min_firmware_{init_mod.OPNSENSE_MIN_FIRMWARE}"
    expected_ltd = f"{entry.data[init_mod.CONF_DEVICE_UNIQUE_ID]}_opnsense_below_ltd_firmware_{init_mod.OPNSENSE_LTD_FIRMWARE}"
    assert calls.called, "async_delete_issue should have been called"
    issue_ids = [call[0][2] for call in calls.call_args_list if len(call[0]) > 2]
    assert expected_min in issue_ids
    assert expected_ltd in issue_ids


@pytest.mark.asyncio
async def test_async_setup_entry_delete_not_called_for_between_min_and_ltd(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_client: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry should not call delete_issue for firmware between min and LTD."""
    patch_opnsense_client(monkeypatch, init_mod, fake_client(firmware_version="25.1"))
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    delete_issue_mock = MagicMock()
    monkeypatch.setattr(init_mod.ir, "async_delete_issue", delete_issue_mock)

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        }
    )
    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()
    hass.data.setdefault("aiohttp_connector", {})

    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True
    # delete should not be called for firmware between min and LTD
    assert not delete_issue_mock.called


@pytest.mark.asyncio
async def test_async_setup_entry_with_device_tracker_enabled(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    coordinator_capture: Any,
    fake_client: Any,
    fake_coordinator: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Device tracker option creates a device-tracker coordinator and triggers initial refresh."""
    patch_opnsense_client(monkeypatch, init_mod, fake_client())
    monkeypatch.setattr(
        init_mod, "OPNsenseDataUpdateCoordinator", coordinator_capture.factory(fake_coordinator)
    )

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={init_mod.CONF_DEVICE_TRACKER_ENABLED: True},
    )

    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = MagicMock()
    res = await init_mod.async_setup_entry(hass, entry)
    assert res is True
    # ensure a device-tracker coordinator was created and its initial refresh ran
    assert any(getattr(inst, "_is_device_tracker", False) for inst in coordinator_capture.instances)
    assert any(getattr(inst, "refreshed", False) for inst in coordinator_capture.instances)


@pytest.mark.asyncio
async def test_async_setup_entry_cleans_up_when_device_tracker_refresh_fails(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry should clean up when device-tracker setup fails."""
    client = _make_valid_setup_client()
    monkeypatch.setattr(
        init_mod, "create_opnsense_client_from_config_entry", lambda **_kwargs: client
    )

    main_coordinator = _make_setup_coordinator()
    device_tracker_coordinator = _make_setup_coordinator()
    device_tracker_coordinator.async_config_entry_first_refresh = AsyncMock(
        side_effect=RuntimeError("device tracker refresh failed")
    )

    coordinators = [main_coordinator, device_tracker_coordinator]

    def _coordinator_factory(**_kwargs: Any) -> Any:
        """Return setup coordinators in creation order."""
        return coordinators.pop(0)

    monkeypatch.setattr(init_mod, "OPNsenseDataUpdateCoordinator", _coordinator_factory)

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={init_mod.CONF_DEVICE_TRACKER_ENABLED: True},
    )

    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    hass.config_entries.async_reload = MagicMock()
    hass.data = {}

    with pytest.raises(RuntimeError, match="device tracker refresh failed"):
        await init_mod.async_setup_entry(hass, entry)

    main_coordinator.async_shutdown.assert_awaited_once()
    device_tracker_coordinator.async_shutdown.assert_awaited_once()
    client.async_close.assert_awaited_once()
    assert entry.entry_id not in hass.data.get(init_mod.DOMAIN, {})


@pytest.mark.asyncio
async def test_async_setup_entry_cleans_up_when_platform_forwarding_fails(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """async_setup_entry should clean up when platform forwarding fails."""
    client = _make_valid_setup_client()
    monkeypatch.setattr(
        init_mod, "create_opnsense_client_from_config_entry", lambda **_kwargs: client
    )

    coordinator = _make_setup_coordinator()
    monkeypatch.setattr(init_mod, "OPNsenseDataUpdateCoordinator", lambda **_kwargs: coordinator)

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={init_mod.CONF_DEVICE_TRACKER_ENABLED: False},
    )
    remove_listener = MagicMock()
    entry.add_update_listener = MagicMock(return_value=remove_listener)
    entry.async_on_unload = MagicMock(return_value=None)

    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(
        side_effect=RuntimeError("platform forwarding failed")
    )
    hass.config_entries.async_reload = MagicMock()
    hass.data = {}

    with pytest.raises(RuntimeError, match="platform forwarding failed"):
        await init_mod.async_setup_entry(hass, entry)

    coordinator.async_shutdown.assert_awaited_once()
    client.async_close.assert_awaited_once()
    entry.add_update_listener.assert_not_called()
    entry.async_on_unload.assert_not_called()
    remove_listener.assert_not_called()
    assert entry.runtime_data is None
    assert entry.entry_id not in hass.data.get(init_mod.DOMAIN, {})


@pytest.mark.asyncio
async def test_async_setup_entry_registers_update_listener_after_forwarding(
    monkeypatch: pytest.MonkeyPatch,
    ph_hass: Any,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Update listener registration should happen after platform forwarding."""
    call_order: list[str] = []

    client = _make_valid_setup_client()
    monkeypatch.setattr(
        init_mod, "create_opnsense_client_from_config_entry", lambda **_kwargs: client
    )

    coordinator = _make_setup_coordinator()
    monkeypatch.setattr(init_mod, "OPNsenseDataUpdateCoordinator", lambda **_kwargs: coordinator)

    entry = make_config_entry(
        data={
            CONF_URL: "http://1.2.3.4",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            init_mod.CONF_DEVICE_UNIQUE_ID: "dev1",
        },
        options={init_mod.CONF_DEVICE_TRACKER_ENABLED: False},
    )
    remove_listener = MagicMock()

    def _add_update_listener(listener: Any) -> MagicMock:
        """Record listener registration and return the removal callback.

        Args:
            listener: Update listener registered on the config entry.

        Returns:
            MagicMock: Callback used to unregister the listener.
        """
        call_order.append("add_listener")
        return remove_listener

    def _async_on_unload(unregister: MagicMock) -> None:
        """Record when Home Assistant registers the unload callback.

        Args:
            unregister: Unload callback passed by the config entry.
        """
        call_order.append("async_on_unload")

    entry.add_update_listener = MagicMock(side_effect=_add_update_listener)
    entry.async_on_unload = MagicMock(side_effect=_async_on_unload)

    async def _forward_entry_setups(*_args: Any, **_kwargs: Any) -> bool:
        """Record platform forwarding and report success.

        Args:
            *_args: Positional setup arguments ignored by the stub.
            **_kwargs: Keyword setup arguments ignored by the stub.

        Returns:
            bool: Always ``True`` for the test setup path.
        """
        call_order.append("forward")
        return True

    hass = ph_hass
    hass.config_entries.async_forward_entry_setups = AsyncMock(side_effect=_forward_entry_setups)
    hass.config_entries.async_reload = MagicMock()
    hass.data = {}

    res = await init_mod.async_setup_entry(hass, entry)

    assert res is True
    assert call_order.index("forward") < call_order.index("add_listener")
    entry.add_update_listener.assert_called_once_with(init_mod._async_update_listener)
    entry.async_on_unload.assert_called_once_with(remove_listener)
    remove_listener.assert_not_called()


@pytest.mark.asyncio
async def test_migrate_2_to_3_handles_identifier_collision(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """_migrate_2_to_3 continues when DeviceIdentifierCollisionError occurs while updating devices."""
    # migration should continue if DeviceIdentifierCollisionError raised when updating device
    client = fake_client(device_id="newdev")()

    # fake device that will cause collision when updating
    dev = MagicMock()
    dev.id = "d1"
    dev.identifiers = {("opnsense", "old")}

    class DeviceRegistry:
        """Fake device registry that raises identifier collisions."""

        def __init__(self) -> None:
            """Provide a fake device registry object for the collision test."""

        def async_update_device(self, *a, **k) -> Never:
            # DeviceIdentifierCollisionError requires an existing_device argument
            """Raise the collision error expected by the registry migration test."""
            raise init_mod.dr.DeviceIdentifierCollisionError("collision", MagicMock(id="other"))

    monkeypatch.setattr(init_mod.dr, "async_get", lambda hass: DeviceRegistry())
    monkeypatch.setattr(
        init_mod.dr, "async_entries_for_config_entry", lambda registry, config_entry_id: [dev]
    )
    monkeypatch.setattr(init_mod.er, "async_get", lambda hass: MagicMock())
    monkeypatch.setattr(
        init_mod.er, "async_entries_for_config_entry", lambda registry, config_entry_id: []
    )
    cfg = MagicMock()
    cfg.data = {
        CONF_URL: "http://1.2.3.4",
        CONF_USERNAME: "u",
        CONF_PASSWORD: "p",
    }
    cfg.version = 2
    cfg.entry_id = "e"
    cfg.unique_id = "old_unique"

    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    res = await init_mod._migrate_2_to_3(hass, cfg, client)
    assert res is True


@pytest.mark.asyncio
async def test_migrate_3_to_4_defers_without_updating_entities_when_later_filesystem_invalid(
    monkeypatch: pytest.MonkeyPatch, ph_hass: Any
) -> None:
    """A valid filesystem before a malformed filesystem should not partially migrate or bump version."""
    client = MagicMock()
    client.get_telemetry = AsyncMock(
        return_value={
            "filesystems": [
                {"device": "/dev/sda1", "mountpoint": "/"},
                {"device": 7, "mountpoint": "/data"},
            ]
        }
    )

    migration_entry = MagicMock()
    migration_entry.entry_id = "entry"
    migration_entry.version = 3

    first_filesystem_entity = MagicMock(
        entity_id="sensor.router_telemetry_filesystems_slash_dev_slash_sda1",
        unique_id="router_telemetry_filesystems_slash_dev_slash_sda1",
    )
    second_filesystem_entity = MagicMock(
        entity_id="sensor.router_telemetry_filesystems_slash_dev_slash_sdb1",
        unique_id="router_telemetry_filesystems_slash_dev_slash_sdb1",
    )

    hass = ph_hass
    hass.config_entries = MagicMock()
    hass.config_entries.async_update_entry = MagicMock(return_value=True)

    entity_registry = MagicMock()
    entity_registry.async_entries_for_config_entry = lambda _registry, _config_entry_id: [
        first_filesystem_entity,
        second_filesystem_entity,
    ]
    entity_registry.async_update_entity = MagicMock()
    monkeypatch.setattr(init_mod.er, "async_get", lambda _hass: entity_registry)
    monkeypatch.setattr(
        init_mod.er,
        "async_entries_for_config_entry",
        entity_registry.async_entries_for_config_entry,
    )

    res = await init_mod._migrate_3_to_4(hass, migration_entry, client)

    assert res is False
    entity_registry.async_update_entity.assert_not_called()
    hass.config_entries.async_update_entry.assert_not_called()
