"""Unit tests for the config flow and options flow of the hass-opnsense integration.

Tests include URL parsing/validation, exception mapping for user input,
and options flow behaviors such as device tracker handling.
"""

from collections.abc import Callable
from typing import Any, Never
from unittest.mock import AsyncMock, MagicMock

from aiohttp import ClientError, ClientResponseError, ClientSSLError, ServerTimeoutError
from aiopnsense import exceptions as aiopnsense_exceptions
from homeassistant.core import HomeAssistant
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
import voluptuous as vol

import custom_components.opnsense.config_flow as config_flow_mod
from custom_components.opnsense.const import (
    CONF_ENTRY_TYPE,
    CONF_SYNC_FIREWALL_AND_NAT,
    CONF_SYNC_SMART,
    CONF_SYNC_TELEMETRY,
    ENTRY_TYPE_CARP,
    ENTRY_TYPE_DEVICE,
)
from tests.utilities import patch_opnsense_client

cf_mod: Any = config_flow_mod


def _make_options_flow(config_entry: Any) -> Any:
    """Create an options flow using Home Assistant's built-in config entry lookup."""
    if not isinstance(getattr(config_entry, "entry_id", None), str):
        config_entry.entry_id = "test-entry"
    flow = cf_mod.OPNsenseOptionsFlow()
    flow.hass = MagicMock()
    flow.hass.config_entries = MagicMock()
    flow.hass.config_entries.async_update_entry = MagicMock()
    flow.hass.config_entries.async_get_known_entry = MagicMock(return_value=config_entry)
    flow.handler = config_entry.entry_id
    return flow


class _CarpFlowClient:
    """Fake client for CARP config-flow validation and setup tests."""

    def __init__(
        self,
        *,
        firmware_version: str = "26.1.11",
        system_name: str = "fw-a.example",
        carp_interfaces: list[dict[str, str]] | None = None,
        validate_error: BaseException | None = None,
    ) -> None:
        """Initialize fake client responses for config-flow tests.

        Args:
            firmware_version: Firmware version returned by the fake client.
            system_name: System name returned by the fake client.
            carp_interfaces: CARP interface rows returned by the fake client.
            validate_error: Optional validation exception raised by the fake client.
        """
        self.firmware_version = firmware_version
        self.system_name = system_name
        self.carp_interfaces = (
            carp_interfaces
            if carp_interfaces is not None
            else [
                {
                    "interface": "lan",
                    "subnet": "192.0.2.1",
                    "vhid": "1",
                    "status": "MASTER",
                }
            ]
        )
        self.validate = AsyncMock()
        if validate_error is not None:
            self.validate.side_effect = validate_error
        self.async_close = AsyncMock()
        self.get_device_unique_id = AsyncMock(return_value="dev-id")

    async def get_host_firmware_version(self) -> str:
        """Return fake firmware version."""
        return self.firmware_version

    async def get_system_info(self) -> dict[str, str]:
        """Return fake responder metadata."""
        return {"name": self.system_name}

    async def get_carp(self) -> dict[str, Any]:
        """Return CARP endpoint payload."""
        return {"interfaces": self.carp_interfaces}


def _make_basic_device_input() -> dict[str, Any]:
    """Build a minimal device-flow input payload."""
    return {
        "url": "https://router.example",
        "username": "user",
        "password": "pass",
        "verify_ssl": True,
        "granular_sync_options": False,
    }


def _make_basic_carp_input() -> dict[str, Any]:
    """Build a minimal CARP-flow input payload."""
    return {
        "url": "https://router.example",
        "username": "user",
        "password": "pass",
        "verify_ssl": True,
    }


def test_mac_and_ip_and_cleanse() -> None:
    """Validate MAC/IP helpers and cleanse sensitive data."""
    assert cf_mod.normalize_mac_address("aa:bb:cc:dd:ee:ff") == "aa:bb:cc:dd:ee:ff"
    assert cf_mod.normalize_mac_address("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert cf_mod.normalize_mac_address("not-a-mac") is None

    # IP validation
    assert cf_mod.is_ip_address("192.168.1.1")
    assert not cf_mod.is_ip_address("not-an-ip")

    # cleanse sensitive data
    msg = "user=admin&pass=secret"
    out = cf_mod.cleanse_sensitive_data(msg, ["secret"])
    assert "[redacted]" in out
    assert "secret" not in out


def test_device_tracking_mode_helper() -> None:
    """Map stored devices to the expected UI tracking mode."""
    assert (
        cf_mod._get_device_tracking_mode(False, ["aa:bb:cc:dd:ee:ff"])
        == cf_mod.DEVICE_TRACKING_MODE_DISABLED
    )
    assert cf_mod._get_device_tracking_mode(True, []) == cf_mod.DEVICE_TRACKING_MODE_ALL
    assert cf_mod._get_device_tracking_mode(True, None) == cf_mod.DEVICE_TRACKING_MODE_ALL
    assert cf_mod._get_device_tracking_mode(True, ["aa:bb:cc:dd:ee:ff"]) == (
        cf_mod.DEVICE_TRACKING_MODE_SELECTED
    )


def test_parse_and_merge_manual_devices() -> None:
    """Parse mixed separators and deduplicate MAC addresses in order."""
    parsed = cf_mod._parse_manual_devices(
        "AA-BB-CC-DD-EE-FF,\n11:22:33:44:55:66\ninvalid\naa:bb:cc:dd:ee:ff"
    )
    assert parsed == [
        "aa:bb:cc:dd:ee:ff",
        "11:22:33:44:55:66",
        "aa:bb:cc:dd:ee:ff",
    ]
    assert cf_mod._merge_selected_devices(
        ["11:22:33:44:55:66", "aa-bb-cc-dd-ee-ff"],
        parsed,
    ) == [
        "11:22:33:44:55:66",
        "aa:bb:cc:dd:ee:ff",
    ]


def test_device_entry_sort_key_numeric_ip_sorting() -> None:
    """Sort key should use numeric IP ordering when an IP is available."""
    ip_by_mac = {
        "aa:bb:cc:dd:ee:ff": "10.0.0.5",
        "11:22:33:44:55:66": "",
        "22:33:44:55:66:77": "192.168.1.2",
        "33:44:55:66:77:88": "192.168.1.10",
    }
    ip_key = cf_mod._device_entry_sort_key(
        "aa:bb:cc:dd:ee:ff",
        "host-a [10.0.0.5 | aa:bb:cc:dd:ee:ff]",
        ip_by_mac,
    )
    label_key = cf_mod._device_entry_sort_key(
        "11:22:33:44:55:66",
        "host-b [11:22:33:44:55:66]",
        ip_by_mac,
    )
    subnet_key_2 = cf_mod._device_entry_sort_key(
        "22:33:44:55:66:77",
        "host-c [192.168.1.2 | 22:33:44:55:66:77]",
        ip_by_mac,
    )
    subnet_key_10 = cf_mod._device_entry_sort_key(
        "33:44:55:66:77:88",
        "host-d [192.168.1.10 | 33:44:55:66:77:88]",
        ip_by_mac,
    )
    assert ip_key == (1, (4, int(cf_mod.ipaddress.ip_address("10.0.0.5"))))
    assert label_key == (2, "host-b [11:22:33:44:55:66]")
    assert subnet_key_2 < subnet_key_10


@pytest.mark.asyncio
async def test_clean_and_parse_url_success_and_failure() -> None:
    """Clean and parse URL, fix missing scheme and handle invalid URL."""
    ui = {cf_mod.CONF_URL: "router.example"}
    await cf_mod._clean_and_parse_url(ui)
    assert ui[cf_mod.CONF_URL] == "https://router.example"

    auth_ui = {cf_mod.CONF_URL: "https://user:pass@router.example:8443"}
    await cf_mod._clean_and_parse_url(auth_ui)
    assert auth_ui[cf_mod.CONF_URL] == "https://router.example:8443"

    ipv6_ui = {cf_mod.CONF_URL: "https://user:pass@[2001:db8::1]:8443"}
    await cf_mod._clean_and_parse_url(ipv6_ui)
    assert ipv6_ui[cf_mod.CONF_URL] == "https://[2001:db8::1]:8443"

    invalid_port_ui = {cf_mod.CONF_URL: "https://router.example:abc"}
    with pytest.raises(cf_mod.OPNsenseInvalidURL):
        await cf_mod._clean_and_parse_url(invalid_port_ui)

    # invalid netloc -> raise OPNsenseInvalidURL
    with pytest.raises(cf_mod.OPNsenseInvalidURL):
        await cf_mod._clean_and_parse_url({cf_mod.CONF_URL: ""})

    missing_host_ui = {cf_mod.CONF_URL: "https://:8443"}
    with pytest.raises(cf_mod.OPNsenseInvalidURL):
        await cf_mod._clean_and_parse_url(missing_host_ui)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("input_url", "expected_url"),
    [
        ("https://router.example:443", "https://router.example"),
        ("http://router.example:80", "http://router.example"),
        ("https://router.example:8443", "https://router.example:8443"),
        ("http://router.example:8080", "http://router.example:8080"),
    ],
)
async def test_clean_and_parse_url_canonicalizes_default_ports(
    input_url: str, expected_url: str
) -> None:
    """Normalize default HTTP ports while preserving non-default ports."""
    user_input = {cf_mod.CONF_URL: input_url}

    await cf_mod._clean_and_parse_url(user_input)

    assert user_input[cf_mod.CONF_URL] == expected_url


@pytest.mark.parametrize(
    ("stored_url", "normalized_url"),
    [
        ("https://router.example:443", "https://router.example"),
        ("http://router.example:80", "http://router.example"),
    ],
)
def test_url_conflict_matches_persisted_default_ports(
    make_config_entry: Callable[..., MockConfigEntry], stored_url: str, normalized_url: str
) -> None:
    """Opposite-kind URL conflicts should match legacy explicit default ports."""
    existing_entry = make_config_entry(
        data={
            cf_mod.CONF_URL: stored_url,
            cf_mod.CONF_USERNAME: "carp-user",
            cf_mod.CONF_PASSWORD: "carp-pass",
            cf_mod.CONF_ENTRY_TYPE: ENTRY_TYPE_CARP,
        },
        options={},
    )
    flow = cf_mod.OPNsenseConfigFlow()
    flow.hass = MagicMock()
    flow.hass.config_entries = MagicMock()
    flow.hass.config_entries.async_entries = MagicMock(return_value=[existing_entry])

    result = flow._async_abort_if_url_conflict(url=normalized_url, carp=False)

    assert result["type"] == "abort"
    assert result["reason"] == "carp_device_url_conflict"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("exc_key", "expected"),
    [
        ("below_min", "below_min_firmware"),
        ("unknown_fw", "unknown_firmware"),
        ("missing_id", "missing_device_unique_id"),
        ("invalid_url", "invalid_url_format"),
        ("ssl", "cannot_connect_ssl"),
        ("invalid_auth", "invalid_auth"),
        ("privilege_missing", "privilege_missing"),
        ("timeout", "connect_timeout"),
        ("connection", "cannot_connect"),
        ("aiohttp_client_error", "cannot_connect"),
    ],
)
async def test_validate_input_exception_mapping(
    monkeypatch: pytest.MonkeyPatch, exc_key: Any, expected: Any
) -> None:
    """Ensure validate_input maps various exceptions to the expected error code."""
    # Build exception object lazily to avoid constructor issues at collection time
    exc: BaseException
    if exc_key == "below_min":
        exc = aiopnsense_exceptions.OPNsenseBelowMinFirmware()
    elif exc_key == "unknown_fw":
        exc = aiopnsense_exceptions.OPNsenseUnknownFirmware()
    elif exc_key == "missing_id":
        exc = aiopnsense_exceptions.OPNsenseMissingDeviceUniqueID("x")
    elif exc_key == "invalid_url":
        exc = cf_mod.OPNsenseInvalidURL("u")
    elif exc_key == "ssl":
        exc = aiopnsense_exceptions.OPNsenseSSLError("ssl error")
    elif exc_key == "invalid_auth":
        exc = aiopnsense_exceptions.OPNsenseInvalidAuth("auth error")
    elif exc_key == "privilege_missing":
        exc = aiopnsense_exceptions.OPNsensePrivilegeMissing("privilege error")
    elif exc_key == "timeout":
        exc = aiopnsense_exceptions.OPNsenseTimeoutError("t")
    elif exc_key == "connection":
        exc = aiopnsense_exceptions.OPNsenseConnectionError("boom")
    elif exc_key == "aiohttp_client_error":
        exc = ClientError("boom")
    else:
        exc = OSError("unknown")

    async def _raiser(*args, **kwargs) -> Never:
        """Raise the prepared exception so input error mapping can be validated.

        Args:
            *args: Additional positional arguments forwarded by the function.
            **kwargs: Additional keyword arguments forwarded by the function.

        Raises:
            OSError: Raised with the prepared message for the current parametrized case.
        """
        raise exc

    monkeypatch.setattr(cf_mod, "_validate_client_details", _raiser)
    errors: dict[str, str] = {}
    res = await cf_mod.validate_input(hass=MagicMock(), user_input={}, errors=errors)
    assert res.get("base") == expected


@pytest.mark.asyncio
async def test_validate_input_maps_raw_aiohttp_client_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Aiohttp ClientError should map to cannot_connect without aborting the flow."""

    async def _raise(*args: object, **kwargs: object) -> Never:
        """Raise a raw aiohttp ClientError to exercise transport mapping."""
        raise ClientError("client request failed")

    monkeypatch.setattr(cf_mod, "_validate_client_details", _raise)
    errors: dict[str, str] = {}
    res = await cf_mod.validate_input(hass=MagicMock(), user_input={}, errors=errors)

    assert res["base"] == "cannot_connect"


@pytest.mark.asyncio
async def test_validate_input_maps_raw_aiohttp_forbidden_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Aiohttp 403 responses should map to privilege_missing."""

    async def _raise(*args: object, **kwargs: object) -> Never:
        """Raise a fake 403 response error to exercise privilege mapping."""
        error = ClientResponseError(
            request_info=MagicMock(real_url="https://x"),
            history=(),
            status=403,
            message="forbidden",
            headers=MagicMock(),
        )
        raise error

    monkeypatch.setattr(cf_mod, "_validate_client_details", _raise)
    errors: dict[str, str] = {}
    res = await cf_mod.validate_input(hass=MagicMock(), user_input={}, errors=errors)

    assert res["base"] == "privilege_missing"


@pytest.mark.asyncio
async def test_validate_input_maps_raw_aiohttp_ssl_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Aiohttp SSL errors should map to cannot_connect_ssl."""

    async def _raise(*args: object, **kwargs: object) -> Never:
        """Raise a raw aiohttp SSL error to exercise ssl mapping."""
        error = ClientSSLError(MagicMock(host="x", port=443, ssl=True), OSError("ssl"))
        raise error

    monkeypatch.setattr(cf_mod, "_validate_client_details", _raise)
    errors: dict[str, str] = {}
    res = await cf_mod.validate_input(hass=MagicMock(), user_input={}, errors=errors)

    assert res["base"] == "cannot_connect_ssl"

@pytest.mark.parametrize(
    (
        "failing_attribute",
        "carp",
    ),
    [
        ("get_system_info", False),
        ("get_device_unique_id", False),
        ("get_carp", True),
    ],
)
async def test_validate_input_maps_aiohttp_client_error_from_enrichment_calls(
    monkeypatch: pytest.MonkeyPatch,
    failing_attribute: str,
    carp: bool,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Raw aiohttp errors from enrichment calls should map to cannot_connect."""
    username = "admin"
    password = "supersecret"
    client = _CarpFlowClient()
    setattr(
        client,
        failing_attribute,
        AsyncMock(side_effect=ClientError(f"timeout user={username} pass={password}")),
    )
    patch_opnsense_client(monkeypatch, cf_mod, lambda **_kwargs: client)

    user_input = _make_basic_carp_input() if carp else _make_basic_device_input()
    user_input.update(
        {
            cf_mod.CONF_USERNAME: username,
            cf_mod.CONF_PASSWORD: password,
        }
    )

    with caplog.at_level("ERROR"):
        result = await cf_mod.validate_input(
            hass=MagicMock(),
            user_input=user_input,
            errors={},
            carp=carp,
        )

    assert result["base"] == "cannot_connect"
    assert "[redacted]" in caplog.text
    assert username not in caplog.text
    assert password not in caplog.text


@pytest.mark.asyncio
async def test_validate_input_reraises_unmapped_opnsense_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """validate_input should re-raise OPNsense errors without form mappings."""
    exc = cf_mod.OPNsenseError("unmapped")

    async def _raiser(*args: object, **kwargs: object) -> Never:
        """Raise an unmapped OPNsense error.

        Args:
            *args: Positional validation arguments ignored by this stub.
            **kwargs: Keyword validation arguments ignored by this stub.

        Raises:
            OPNsenseError: Always raised to exercise the re-raise path.
        """
        raise exc

    monkeypatch.setattr(cf_mod, "_validate_client_details", _raiser)

    with pytest.raises(cf_mod.OPNsenseError) as err:
        await cf_mod.validate_input(hass=MagicMock(), user_input={}, errors={})

    assert err.value is exc


@pytest.mark.asyncio
async def test_validate_input_timeout_uses_connect_timeout_error(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """OPNsense timeout should map to connect_timeout and redact credentials in logs."""
    username = "admin"
    password = "supersecret"

    async def _raiser(*args: object, **kwargs: object) -> Never:
        """Raise an OPNsense timeout that includes secrets in the message."""
        raise aiopnsense_exceptions.OPNsenseTimeoutError(
            f"timed out for user={username} pass={password}"
        )

    monkeypatch.setattr(cf_mod, "_validate_client_details", _raiser)
    with caplog.at_level("ERROR"):
        result = await cf_mod.validate_input(
            hass=MagicMock(),
            user_input={cf_mod.CONF_USERNAME: username, cf_mod.CONF_PASSWORD: password},
            errors={},
        )

    assert result.get("base") == "connect_timeout"
    assert "[redacted]" in caplog.text
    assert username not in caplog.text
    assert password not in caplog.text


@pytest.mark.asyncio
async def test_validate_input_timeout_subclass_of_client_error_still_maps_connect_timeout(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Timeout subclasses that also appear as ClientError map to connect_timeout."""
    username = "admin"
    password = "supersecret"

    async def _raiser(*args: object, **kwargs: object) -> Never:
        """Raise an exception that is both TimeoutError and ClientError."""
        raise ServerTimeoutError(f"timeout user={username} pass={password}")

    monkeypatch.setattr(cf_mod, "_validate_client_details", _raiser)
    with caplog.at_level("ERROR"):
        result = await cf_mod.validate_input(
            hass=MagicMock(),
            user_input={cf_mod.CONF_USERNAME: username, cf_mod.CONF_PASSWORD: password},
            errors={},
        )

    assert result.get("base") == "connect_timeout"
    assert "[redacted]" in caplog.text
    assert username not in caplog.text
    assert password not in caplog.text


@pytest.mark.asyncio
async def test_async_step_user_shows_menu() -> None:
    """Initial config flow step should present a menu with two entry types."""
    flow = cf_mod.OPNsenseConfigFlow()
    flow.hass = MagicMock()

    result = await flow.async_step_user()

    assert result["type"] == "menu"
    assert result["step_id"] == "user"
    assert result["menu_options"] == ["device", "carp"]


@pytest.mark.asyncio
async def test_async_step_device_creates_entry_and_sets_entry_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Device flow should continue to set a hardware-backed entry type."""
    client = _CarpFlowClient()
    patch_opnsense_client(monkeypatch, cf_mod, lambda **_kwargs: client)

    flow = cf_mod.OPNsenseConfigFlow()
    flow.hass = MagicMock()
    object.__setattr__(
        flow,
        "async_set_unique_id",
        AsyncMock(),
    )
    object.__setattr__(flow, "_abort_if_unique_id_configured", lambda: None)
    flow.hass.config_entries = MagicMock()
    flow.hass.config_entries.async_entries = MagicMock(return_value=[])

    result = await flow.async_step_device(user_input=_make_basic_device_input())

    assert result["type"] == "create_entry"
    assert result["data"][CONF_ENTRY_TYPE] == ENTRY_TYPE_DEVICE
    assert result["data"][cf_mod.CONF_DEVICE_UNIQUE_ID] == "dev-id"
    assert not result["data"][cf_mod.CONF_GRANULAR_SYNC_OPTIONS]


@pytest.mark.asyncio
async def test_async_step_device_routes_to_granular_sync(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Device flow must still forward granular-sync-enabled submissions."""
    client = _CarpFlowClient()
    patch_opnsense_client(monkeypatch, cf_mod, lambda **_kwargs: client)

    flow = cf_mod.OPNsenseConfigFlow()
    flow.hass = MagicMock()
    object.__setattr__(
        flow,
        "async_set_unique_id",
        AsyncMock(),
    )
    object.__setattr__(flow, "_abort_if_unique_id_configured", lambda: None)
    flow.hass.config_entries = MagicMock()
    flow.hass.config_entries.async_entries = MagicMock(return_value=[])

    ui = _make_basic_device_input()
    ui[cf_mod.CONF_GRANULAR_SYNC_OPTIONS] = True
    result = await flow.async_step_device(user_input=ui)

    assert result["type"] == "form"
    assert result["step_id"] == "granular_sync"


@pytest.mark.asyncio
async def test_async_step_device_aborts_on_duplicate_carp_url(
    monkeypatch: pytest.MonkeyPatch, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Device flow should reject a normalized URL already used by a CARP entry."""
    client = _CarpFlowClient()
    patch_opnsense_client(monkeypatch, cf_mod, lambda **_kwargs: client)

    existing_entry = make_config_entry(
        data={
            cf_mod.CONF_URL: "https://router.example",
            cf_mod.CONF_ENTRY_TYPE: ENTRY_TYPE_CARP,
            cf_mod.CONF_USERNAME: "carp-user",
            cf_mod.CONF_PASSWORD: "carp-pass",
        },
        options={},
    )
    assert existing_entry.data[cf_mod.CONF_ENTRY_TYPE] == ENTRY_TYPE_CARP

    flow = cf_mod.OPNsenseConfigFlow()
    flow.hass = MagicMock()
    flow.hass.config_entries = MagicMock()
    flow.hass.config_entries.async_entries = MagicMock(return_value=[existing_entry])
    set_unique_id = AsyncMock()
    abort_if_configured = MagicMock()
    object.__setattr__(flow, "async_set_unique_id", set_unique_id)
    object.__setattr__(flow, "_abort_if_unique_id_configured", abort_if_configured)

    user_input = _make_basic_device_input()
    user_input[cf_mod.CONF_URL] = "https://router.example/"
    result = await flow.async_step_device(user_input=user_input)

    assert result["type"] == "abort"
    assert result["reason"] == "carp_device_url_conflict"
    flow.hass.config_entries.async_entries.assert_called_once_with(cf_mod.DOMAIN)
    set_unique_id.assert_not_awaited()
    abort_if_configured.assert_not_called()


@pytest.mark.asyncio
async def test_async_step_carp_aborts_on_device_url_conflict(
    monkeypatch: pytest.MonkeyPatch, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """CARP flow should reject a URL already used by a device entry."""
    client = _CarpFlowClient()
    patch_opnsense_client(monkeypatch, cf_mod, lambda **_kwargs: client)

    existing_entry = make_config_entry(
        data={
            cf_mod.CONF_URL: "https://router.example",
            cf_mod.CONF_USERNAME: "device-user",
            cf_mod.CONF_PASSWORD: "device-pass",
        },
        options={},
    )

    flow = cf_mod.OPNsenseConfigFlow()
    flow.hass = MagicMock()
    flow.hass.config_entries = MagicMock()
    flow.hass.config_entries.async_entries = MagicMock(return_value=[existing_entry])
    abort_match = MagicMock(return_value={"type": "abort", "reason": "already_configured"})
    object.__setattr__(flow, "_async_abort_entries_match", abort_match)

    user_input = _make_basic_carp_input()
    user_input[cf_mod.CONF_URL] = "https://router.example/"
    result = await flow.async_step_carp(user_input=user_input)

    assert result["type"] == "abort"
    assert result["reason"] == "carp_device_url_conflict"
    flow.hass.config_entries.async_entries.assert_called_once_with(cf_mod.DOMAIN)
    abort_match.assert_not_called()


@pytest.mark.asyncio
async def test_async_step_device_allows_same_url_for_non_carp_entry(
    monkeypatch: pytest.MonkeyPatch, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Device flow should not block URL duplicates when matching entry is not CARP."""
    client = _CarpFlowClient()
    patch_opnsense_client(monkeypatch, cf_mod, lambda **_kwargs: client)

    existing_entry = make_config_entry(
        data={
            cf_mod.CONF_URL: "https://router.example",
            cf_mod.CONF_USERNAME: "device-user",
            cf_mod.CONF_PASSWORD: "device-pass",
        },
        options={},
    )
    assert existing_entry.data.get(cf_mod.CONF_ENTRY_TYPE, ENTRY_TYPE_DEVICE) == ENTRY_TYPE_DEVICE

    flow = cf_mod.OPNsenseConfigFlow()
    flow.hass = MagicMock()
    flow.hass.config_entries = MagicMock()
    flow.hass.config_entries.async_entries = MagicMock(return_value=[existing_entry])
    set_unique_id = AsyncMock()
    abort_if_configured = MagicMock()

    object.__setattr__(
        flow,
        "async_set_unique_id",
        set_unique_id,
    )
    object.__setattr__(flow, "_abort_if_unique_id_configured", abort_if_configured)

    user_input = _make_basic_device_input()
    user_input[cf_mod.CONF_URL] = "https://router.example/"
    result = await flow.async_step_device(user_input=user_input)

    assert result["type"] == "create_entry"
    assert result["data"][CONF_ENTRY_TYPE] == ENTRY_TYPE_DEVICE
    assert result["data"][cf_mod.CONF_URL] == "https://router.example"
    set_unique_id.assert_awaited_once_with("dev-id")
    abort_if_configured.assert_called_once_with()


@pytest.mark.asyncio
async def test_async_step_carp_validates_without_device_id_and_sets_entry_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CARP flow should validate with device-id disabled and skip granular sync fields."""
    client = _CarpFlowClient()
    patch_opnsense_client(monkeypatch, cf_mod, lambda **_kwargs: client)

    flow = cf_mod.OPNsenseConfigFlow()
    flow.hass = MagicMock()

    result = await flow.async_step_carp(user_input=_make_basic_carp_input())

    assert result["type"] == "create_entry"
    assert result["data"][CONF_ENTRY_TYPE] == ENTRY_TYPE_CARP
    assert result["data"][cf_mod.CONF_FIRMWARE_VERSION] == client.firmware_version
    assert result["data"][cf_mod.CONF_NAME] == f"{client.system_name} CARP VIP"
    assert result["data"].get(cf_mod.CONF_DEVICE_UNIQUE_ID) is None
    assert result["data"].get(cf_mod.CONF_GRANULAR_SYNC_OPTIONS) is None
    client.validate.assert_awaited_once_with(require_device_id=False)
    client.get_device_unique_id.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "interfaces",
    [
        None,
        (),
        "not-a-list",
        [],
        [{}],
        ["not-a-mapping"],
        [{"vhid": "", "subnet": "192.0.2.1"}],
        [{"vhid": "1", "subnet": ""}],
        [{"vhid": "  ", "subnet": "  "}],
    ],
)
async def test_async_step_carp_rejects_malformed_or_blank_vip_rows(
    monkeypatch: pytest.MonkeyPatch,
    interfaces: Any,
) -> None:
    """CARP validation should require a mapping row with usable VHID and subnet."""
    client = _CarpFlowClient()
    object.__setattr__(client, "get_carp", AsyncMock(return_value={"interfaces": interfaces}))
    patch_opnsense_client(monkeypatch, cf_mod, lambda **_kwargs: client)

    flow = cf_mod.OPNsenseConfigFlow()
    flow.hass = MagicMock()

    result = await flow.async_step_carp(user_input=_make_basic_carp_input())

    assert result["type"] == "form"
    assert result["errors"]["base"] == "carp_not_configured"
    client.get_device_unique_id.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "interface",
    [
        {"vhid": 1, "subnet": "192.0.2.1"},
        {"vhid": " 2 ", "subnet": " 192.0.2.2 "},
    ],
)
async def test_async_step_carp_accepts_vip_identity_without_physical_interface(
    monkeypatch: pytest.MonkeyPatch,
    interface: dict[str, Any],
) -> None:
    """CARP validation should accept integer/string VHIDs without interface names."""
    client = _CarpFlowClient()
    object.__setattr__(client, "get_carp", AsyncMock(return_value={"interfaces": [interface]}))
    patch_opnsense_client(monkeypatch, cf_mod, lambda **_kwargs: client)

    flow = cf_mod.OPNsenseConfigFlow()
    flow.hass = MagicMock()

    result = await flow.async_step_carp(user_input=_make_basic_carp_input())

    assert result["type"] == "create_entry"
    assert result["data"][cf_mod.CONF_ENTRY_TYPE] == ENTRY_TYPE_CARP


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "system_info",
    [None, {}, {"name": None}, {"name": ""}, {"name": "  "}, {"name": 123}, []],
)
async def test_async_step_carp_rejects_missing_or_blank_responder_name(
    monkeypatch: pytest.MonkeyPatch,
    system_info: Any,
) -> None:
    """CARP validation should require a usable responder name from system info."""
    client = _CarpFlowClient()
    object.__setattr__(client, "get_system_info", AsyncMock(return_value=system_info))
    patch_opnsense_client(monkeypatch, cf_mod, lambda **_kwargs: client)

    flow = cf_mod.OPNsenseConfigFlow()
    flow.hass = MagicMock()

    result = await flow.async_step_carp(user_input=_make_basic_carp_input())

    assert result["type"] == "form"
    assert result["errors"]["base"] == "carp_responder_unavailable"


@pytest.mark.asyncio
async def test_async_step_carp_custom_name_does_not_waive_responder_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A custom entry name should not bypass required responder metadata."""
    client = _CarpFlowClient()
    object.__setattr__(client, "get_system_info", AsyncMock(return_value={"name": "  "}))
    patch_opnsense_client(monkeypatch, cf_mod, lambda **_kwargs: client)

    flow = cf_mod.OPNsenseConfigFlow()
    flow.hass = MagicMock()
    user_input = _make_basic_carp_input()
    user_input[cf_mod.CONF_NAME] = "Custom CARP"

    result = await flow.async_step_carp(user_input=user_input)

    assert result["type"] == "form"
    assert result["errors"]["base"] == "carp_responder_unavailable"


def test_validation_error_details_maps_carp_responder_unavailable() -> None:
    """Responder validation errors should use their dedicated form error key."""
    result = cf_mod._get_validation_error_details(
        cf_mod.OPNsenseCarpResponderUnavailableError("missing responder"),
        _make_basic_carp_input(),
    )

    assert result is not None
    assert result[0] == "carp_responder_unavailable"
    assert result[1] == "Unable to determine the active CARP responder"


@pytest.mark.asyncio
async def test_async_step_carp_rejects_below_min_firmware(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Below-minimum firmware in CARP mode should map to below_min_firmware."""
    client = _CarpFlowClient(
        firmware_version="0.1.0",
        validate_error=aiopnsense_exceptions.OPNsenseBelowMinFirmware("too old"),
    )
    patch_opnsense_client(monkeypatch, cf_mod, lambda **_kwargs: client)

    flow = cf_mod.OPNsenseConfigFlow()
    flow.hass = MagicMock()
    result = await flow.async_step_carp(user_input=_make_basic_carp_input())

    assert result["type"] == "form"
    assert result["errors"]["base"] == "below_min_firmware"


@pytest.mark.asyncio
async def test_async_step_carp_aborts_on_duplicate_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CARP flow should use abort-by-URL dedupe for existing entries."""
    client = _CarpFlowClient()
    patch_opnsense_client(monkeypatch, cf_mod, lambda **_kwargs: client)

    flow = cf_mod.OPNsenseConfigFlow()
    flow.hass = MagicMock()
    object.__setattr__(
        flow,
        "_async_abort_entries_match",
        lambda _match: {"type": "abort", "reason": "already_configured"},
    )

    result = await flow.async_step_carp(user_input=_make_basic_carp_input())

    assert result == {"type": "abort", "reason": "already_configured"}


@pytest.mark.asyncio
async def test_validate_input_can_map_carp_not_configured_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """validate_input should map CARP payload errors to base key carp_not_configured."""

    async def _raise(*_args: object, **_kwargs: object) -> Never:
        """Raise the CARP validation error requested by the test."""
        raise cf_mod.OPNsenseCarpNotConfiguredError("No CARP VIPs were returned")

    monkeypatch.setattr(cf_mod, "_validate_carp_client_details", _raise)
    errors: dict[str, str] = {}
    result = await cf_mod.validate_input(
        hass=MagicMock(),
        user_input=_make_basic_carp_input(),
        errors=errors,
        carp=True,
    )
    assert result["base"] == "carp_not_configured"


def test_record_validation_error_sets_base(caplog: pytest.LogCaptureFixture) -> None:
    """_record_validation_error should log the message and set errors['base']."""
    errors: dict[str, str] = {}
    cf_mod._record_validation_error(errors=errors, key="test_key", message="an msg")
    assert errors.get("base") == "test_key"
    assert "an msg" in caplog.text


def test_build_carp_input_schema_defaults_and_rejects_unknown_fields() -> None:
    """CARP schema should apply defaults and ignore unrelated field keys."""
    schema = cf_mod._build_carp_input_schema(
        user_input=None,
        stored_values={
            cf_mod.CONF_URL: "https://stored.example",
            cf_mod.CONF_VERIFY_SSL: False,
            cf_mod.CONF_USERNAME: "stored-user",
            cf_mod.CONF_PASSWORD: "stored-pass",
            cf_mod.CONF_NAME: "Stored Router",
        },
    )
    values = schema({})
    assert values[cf_mod.CONF_URL] == "https://stored.example"
    assert values[cf_mod.CONF_VERIFY_SSL] is False
    assert values[cf_mod.CONF_USERNAME] == "stored-user"
    assert values[cf_mod.CONF_PASSWORD] == "stored-pass"
    assert values[cf_mod.CONF_NAME] == "Stored Router"
    with pytest.raises(vol.Invalid):
        schema({cf_mod.CONF_GRANULAR_SYNC_OPTIONS: True})


def test_build_carp_options_schema_exposes_scan_interval_only() -> None:
    """CARP options schema should only contain scan interval."""
    schema = cf_mod._build_carp_options_schema(user_input=None, stored_options=None)
    values = schema({})
    assert values == {cf_mod.CONF_SCAN_INTERVAL: cf_mod.DEFAULT_SCAN_INTERVAL}

    with pytest.raises(vol.Invalid):
        schema({cf_mod.CONF_DEVICE_TRACKING_MODE: cf_mod.DEVICE_TRACKING_MODE_ALL})


@pytest.mark.asyncio
async def test_get_dt_entries_sorts_and_includes_selected(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """Ensure _get_dt_entries returns selected devices first and ARP entries sorted by IP."""
    # Create a client class via fixture and attach a get_arp_table implementation
    client_cls = fake_client()

    async def _get_arp_table(self: Any, resolve_hostnames: bool = True) -> Any:
        """Return arp table.

        Args:
            self: Fake client instance.
            resolve_hostnames: Resolve hostnames provided by pytest or the test case.
        """
        return [
            {"mac": "aa:bb:cc:00:00:01", "hostname": "hostb", "ip": "192.168.1.20"},
            {"mac": "aa:bb:cc:00:00:03", "hostname": "hostc", "ip": "192.168.1.100"},
            {"mac": "11:22:33:44:55:66", "hostname": "", "ip": "10.0.0.5"},
            {"mac": "bb:cc:dd:00:00:02", "hostname": "hosta", "ip": "192.168.1.10"},
        ]

    client_cls.get_arp_table = _get_arp_table
    patch_opnsense_client(monkeypatch, cf_mod, client_cls)

    hass = MagicMock()
    config = {cf_mod.CONF_URL: "https://x", cf_mod.CONF_USERNAME: "u", cf_mod.CONF_PASSWORD: "p"}
    selected = ["aa:bb:cc:00:00:01"]
    res = await cf_mod._get_dt_entries(hass=hass, config=config, selected_devices=selected)

    # ensure selected device is present and IP-based entries are present
    keys = list(res.keys())
    assert "aa:bb:cc:00:00:01" in keys
    assert "11:22:33:44:55:66" in keys
    # Detected entries are sorted numerically by IP (10.0.0.5 before 192.168.1.10 < 192.168.1.20)
    vals = list(res.values())
    assert vals.index("10.0.0.5 [11:22:33:44:55:66]") < vals.index(
        "hosta [192.168.1.10 | bb:cc:dd:00:00:02]"
    )
    assert vals.index("hosta [192.168.1.10 | bb:cc:dd:00:00:02]") < vals.index(
        "hostb [192.168.1.20 | aa:bb:cc:00:00:01]"
    )
    assert vals.index("hostb [192.168.1.20 | aa:bb:cc:00:00:01]") < vals.index(
        "hostc [192.168.1.100 | aa:bb:cc:00:00:03]"
    )


@pytest.mark.asyncio
async def test_get_dt_entries_passes_throw_errors_to_client(
    monkeypatch: pytest.MonkeyPatch,
    fake_client: Any,
) -> None:
    """_get_dt_entries should request throw-errors behavior from the API client."""
    create_calls: dict[str, Any] = {}

    client_cls = fake_client()

    async def _get_arp_table(self: Any, resolve_hostnames: bool = True) -> list[dict[str, str]]:
        """Return no ARP rows for deterministic entry-point assertions."""
        return []

    client_cls.get_arp_table = _get_arp_table

    def _init_client(**kwargs: Any) -> Any:
        """Capture the create_opnsense_client call and return the fake client."""
        create_calls.update(kwargs)
        return client_cls(**kwargs)

    monkeypatch.setattr(cf_mod, "create_opnsense_client", _init_client)

    await cf_mod._get_dt_entries(
        hass=MagicMock(),
        config={cf_mod.CONF_URL: "https://x", cf_mod.CONF_USERNAME: "u", cf_mod.CONF_PASSWORD: "p"},
        selected_devices=[],
    )

    assert create_calls["throw_errors"] is True


@pytest.mark.asyncio
async def test_get_dt_entries_preserves_missing_selected_devices(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """Selected MACs missing from ARP stay available with a fallback label."""
    client_cls = fake_client()

    async def _get_arp_table(self: Any, resolve_hostnames: bool = True) -> Any:
        """Return arp table.

        Args:
            self: Fake client instance.
            resolve_hostnames: Resolve hostnames provided by pytest or the test case.
        """
        return [{"mac": "11:22:33:44:55:66", "hostname": "", "ip": "10.0.0.5"}]

    client_cls.get_arp_table = _get_arp_table
    patch_opnsense_client(monkeypatch, cf_mod, client_cls)

    res = await cf_mod._get_dt_entries(
        hass=MagicMock(),
        config={cf_mod.CONF_URL: "https://x", cf_mod.CONF_USERNAME: "u", cf_mod.CONF_PASSWORD: "p"},
        selected_devices=["AA-BB-CC-DD-EE-FF"],
    )
    assert res["aa:bb:cc:dd:ee:ff"] == "Not currently detected [aa:bb:cc:dd:ee:ff]"


@pytest.mark.asyncio
async def test_get_dt_entries_supports_raw_arp_keys(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any
) -> None:
    """_get_dt_entries should parse raw aiopnsense 1.1.1 ARP keys."""
    client_cls = fake_client()

    async def _get_arp_table(self: Any, resolve_hostnames: bool = True) -> Any:
        return [{"mac-address": "AA-BB-CC-00-00-01", "ip-address": "10.0.0.10"}]

    client_cls.get_arp_table = _get_arp_table
    patch_opnsense_client(monkeypatch, cf_mod, client_cls)

    res = await cf_mod._get_dt_entries(
        hass=MagicMock(),
        config={cf_mod.CONF_URL: "https://x", cf_mod.CONF_USERNAME: "u", cf_mod.CONF_PASSWORD: "p"},
        selected_devices=[],
    )

    assert res == {"aa:bb:cc:00:00:01": "10.0.0.10 [aa:bb:cc:00:00:01]"}


@pytest.mark.asyncio
async def test_get_dt_entries_closes_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """_get_dt_entries should close the client and request propagated errors."""

    class _Client:
        """Fake client that records closure for device-tracker entry tests."""

        last_instance = None

        def __init__(self, *args, **kwargs) -> None:
            """Capture last created client instance for close assertions.

            Args:
                *args: Unused positional constructor args from factory helper.
                **kwargs: Unused keyword constructor args from factory helper.
            """
            type(self).last_instance = self
            self.throw_errors = kwargs.get("throw_errors")
            self.async_close = AsyncMock()

        async def get_arp_table(self, resolve_hostnames: bool = True) -> Any:
            """Return an empty ARP table for close-path testing.

            Args:
                resolve_hostnames: Hostname-resolution flag passed by caller and ignored.

            Returns:
                list: Empty ARP-table payload.
            """
            return []

    patch_opnsense_client(monkeypatch, cf_mod, _Client)

    await cf_mod._get_dt_entries(
        hass=MagicMock(),
        config={cf_mod.CONF_URL: "https://x", cf_mod.CONF_USERNAME: "u", cf_mod.CONF_PASSWORD: "p"},
        selected_devices=[],
    )
    assert _Client.last_instance is not None
    assert _Client.last_instance.throw_errors is True
    _Client.last_instance.async_close.assert_awaited_once()


@pytest.mark.asyncio
async def test_validate_client_details_closes_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """_validate_client_details should always close the temporary client."""

    class _Client:
        """Fake client that records closure for validation cleanup tests."""

        last_instance = None

        def __init__(self, *args, **kwargs) -> None:
            """Capture last created client instance for close assertions.

            Args:
                *args: Unused positional constructor args from factory helper.
                **kwargs: Unused keyword constructor args from factory helper.
            """
            type(self).last_instance = self
            self.validate = AsyncMock()
            self.async_close = AsyncMock()

        async def get_host_firmware_version(self) -> str:
            """Return firmware that passes minimum-version validation.

            Returns:
                str: Firmware version used by the test.
            """
            return "26.1.1"

        async def get_system_info(self) -> Any:
            """Return minimal system metadata for name derivation.

            Returns:
                dict[str, str]: Mapping containing router display name.
            """
            return {"name": "OPNsense"}

        async def get_device_unique_id(
            self, _expected_id: str | None = None, **_kwargs: Any
        ) -> str:
            """Return deterministic device identifier for validation.

            Args:
                _expected_id: Expected device ID from caller and ignored in this stub.

            Returns:
                str: Fake device identifier.
            """
            return "dev123"

    patch_opnsense_client(monkeypatch, cf_mod, _Client)

    user_input = {
        cf_mod.CONF_URL: "https://router.example",
        cf_mod.CONF_USERNAME: "u",
        cf_mod.CONF_PASSWORD: "p",
        cf_mod.CONF_GRANULAR_SYNC_OPTIONS: False,
    }
    await cf_mod._validate_client_details(
        hass=MagicMock(),
        user_input=user_input,
    )
    assert _Client.last_instance is not None
    _Client.last_instance.validate.assert_awaited_once()
    _Client.last_instance.async_close.assert_awaited_once()


@pytest.mark.asyncio
async def test_validate_client_details_raises_when_device_id_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_validate_client_details should reject clients that return no device id."""

    class _Client:
        """Fake client that returns no device ID for validation tests."""

        last_instance = None

        def __init__(self, *args: object, **kwargs: object) -> None:
            """Capture the created client instance.

            Args:
                *args: Positional constructor arguments ignored by this stub.
                **kwargs: Keyword constructor arguments ignored by this stub.
            """
            type(self).last_instance = self
            self.validate = AsyncMock()
            self.async_close = AsyncMock()

        async def get_host_firmware_version(self) -> str:
            """Return firmware that passes minimum-version validation."""
            return "26.1.1"

        async def get_system_info(self) -> dict[str, str]:
            """Return minimal system metadata for validation."""
            return {"name": "OPNsense"}

        async def get_device_unique_id(self, expected_id: str | None = None) -> str:
            """Return an empty device identifier.

            Args:
                expected_id: Expected device ID supplied by validation and ignored.
            """
            return ""

    patch_opnsense_client(monkeypatch, cf_mod, _Client)

    user_input = {
        cf_mod.CONF_URL: "https://router.example",
        cf_mod.CONF_USERNAME: "u",
        cf_mod.CONF_PASSWORD: "p",
    }
    with pytest.raises(cf_mod.OPNsenseMissingDeviceUniqueID):
        await cf_mod._validate_client_details(hass=MagicMock(), user_input=user_input)

    assert _Client.last_instance is not None
    _Client.last_instance.async_close.assert_awaited_once()


def test_build_user_input_and_granular_and_options_schemas_defaults() -> None:
    """Verify the schema builders accept empty input and return defaults where applicable."""
    uis = None
    # user input schema should provide keys and defaults
    schema = cf_mod._build_user_input_schema(user_input=uis)
    validated = schema({})
    assert cf_mod.CONF_URL in validated

    # granular sync schema
    gschema = cf_mod._build_granular_sync_schema(user_input=None)
    gvalidated = gschema({})
    # every granular item should be present (defaults applied)
    for item in cf_mod.GRANULAR_SYNC_ITEMS:
        assert item in gvalidated
    assert gvalidated[CONF_SYNC_SMART] is True
    assert gvalidated[CONF_SYNC_TELEMETRY] is True
    gvalidated = gschema({CONF_SYNC_SMART: False})
    assert gvalidated[CONF_SYNC_SMART] is False

    # options init schema: test clamping/coercion for scan interval
    oschema = cf_mod._build_options_init_schema(user_input=None)
    out = oschema({})
    assert cf_mod.CONF_SCAN_INTERVAL in out
    assert cf_mod.CONF_DEVICE_TRACKING_MODE in out


def test_schema_builders_preserve_submitted_values_before_stored_values() -> None:
    """Schema defaults should prefer submitted values, then stored values, then constants."""
    user_schema = cf_mod._build_user_input_schema(
        user_input={
            cf_mod.CONF_URL: "https://submitted.example",
            cf_mod.CONF_GRANULAR_SYNC_OPTIONS: False,
        },
        stored_values={
            cf_mod.CONF_URL: "https://stored.example",
            cf_mod.CONF_GRANULAR_SYNC_OPTIONS: True,
        },
    )
    user_values = user_schema({})
    assert user_values[cf_mod.CONF_URL] == "https://submitted.example"
    assert user_values[cf_mod.CONF_GRANULAR_SYNC_OPTIONS] is False

    granular_schema = cf_mod._build_granular_sync_schema(
        user_input={CONF_SYNC_SMART: False},
        stored_values={CONF_SYNC_SMART: True, CONF_SYNC_TELEMETRY: False},
    )
    granular_values = granular_schema({})
    assert granular_values[CONF_SYNC_SMART] is False
    assert granular_values[CONF_SYNC_TELEMETRY] is False

    options_schema = cf_mod._build_options_init_schema(
        user_input={
            cf_mod.CONF_SCAN_INTERVAL: 45,
            cf_mod.CONF_DEVICE_TRACKING_MODE: cf_mod.DEVICE_TRACKING_MODE_SELECTED,
        },
        stored_config={cf_mod.CONF_GRANULAR_SYNC_OPTIONS: True},
        stored_options={
            cf_mod.CONF_SCAN_INTERVAL: 120,
            cf_mod.CONF_DEVICE_TRACKER_ENABLED: True,
            cf_mod.CONF_DEVICES: [],
        },
    )
    options_values = options_schema({})
    assert options_values[cf_mod.CONF_SCAN_INTERVAL] == 45
    assert options_values[cf_mod.CONF_DEVICE_TRACKING_MODE] == cf_mod.DEVICE_TRACKING_MODE_SELECTED
    assert options_values[cf_mod.CONF_GRANULAR_SYNC_OPTIONS] is True


@pytest.mark.parametrize(
    ("input_value", "expected"),
    [
        (150, 150),  # within range -> unchanged
    ],
)
def test_options_scan_interval_accepts_native_selector_range(
    input_value: Any, expected: Any
) -> None:
    """_build_options_init_schema should accept CONF_SCAN_INTERVAL values in range."""
    oschema = cf_mod._build_options_init_schema(user_input=None)
    # pass a dict with the scan interval set to the test value
    validated = oschema({cf_mod.CONF_SCAN_INTERVAL: input_value})
    assert validated.get(cf_mod.CONF_SCAN_INTERVAL) == expected


@pytest.mark.parametrize("input_value", [5, 1000])
def test_options_scan_interval_rejects_values_outside_selector_range(input_value: Any) -> None:
    """_build_options_init_schema should reject CONF_SCAN_INTERVAL values outside range."""
    oschema = cf_mod._build_options_init_schema(user_input=None)

    with pytest.raises(vol.Invalid):
        oschema({cf_mod.CONF_SCAN_INTERVAL: input_value})


@pytest.mark.parametrize(
    ("stored_options", "field", "expected"),
    [
        (
            {cf_mod.CONF_SCAN_INTERVAL: 1000},
            cf_mod.CONF_SCAN_INTERVAL,
            300,
        ),
        (
            {cf_mod.CONF_DEVICE_TRACKER_SCAN_INTERVAL: 5},
            cf_mod.CONF_DEVICE_TRACKER_SCAN_INTERVAL,
            30,
        ),
        (
            {cf_mod.CONF_DEVICE_TRACKER_CONSIDER_HOME: 5000},
            cf_mod.CONF_DEVICE_TRACKER_CONSIDER_HOME,
            3600,
        ),
    ],
)
def test_options_schema_clamps_legacy_stored_defaults(
    stored_options: dict[str, Any], field: str, expected: int
) -> None:
    """_build_options_init_schema should clamp legacy stored defaults into range."""
    oschema = cf_mod._build_options_init_schema(
        user_input=None,
        stored_options=stored_options,
    )

    validated = oschema({})
    assert validated[field] == expected


@pytest.mark.parametrize(
    "option_key",
    list(cf_mod.OPTIONS_INIT_NUMBER_BOUNDS),
)
def test_options_init_schema_boundaries_match_keyed_lookup(option_key: str) -> None:
    """Selector bounds for options should come from keyed bounds lookup values."""
    oschema = cf_mod._build_options_init_schema(user_input=None)
    minimum, maximum = cf_mod.OPTIONS_INIT_NUMBER_BOUNDS[option_key]

    assert oschema({option_key: minimum}).get(option_key) == minimum
    assert oschema({option_key: maximum}).get(option_key) == maximum

    with pytest.raises(vol.Invalid):
        oschema({option_key: minimum - 1})
    with pytest.raises(vol.Invalid):
        oschema({option_key: maximum + 1})


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(None, id="none"),
        pytest.param("invalid", id="invalid-string"),
    ],
)
def test_normalize_int_option_invalid_values_fall_back_to_minimum(value: Any) -> None:
    """Invalid persisted numeric options should fall back to the selector minimum."""
    assert cf_mod._normalize_int_option(value, 5, 3600) == 5


@pytest.mark.parametrize(
    ("input_value", "expected"),
    [
        (300, 300),  # within range -> unchanged
        (1200, 1200),  # within new range (20 minutes) -> unchanged
        (3600, 3600),  # at maximum (1 hour) -> unchanged
    ],
)
def test_options_device_tracker_consider_home_accepts_native_selector_range(
    input_value: Any, expected: Any
) -> None:
    """_build_options_init_schema should accept consider_home values in range."""
    oschema = cf_mod._build_options_init_schema(user_input=None)
    # pass a dict with the consider_home value set to the test value
    validated = oschema({cf_mod.CONF_DEVICE_TRACKER_CONSIDER_HOME: input_value})
    assert validated.get(cf_mod.CONF_DEVICE_TRACKER_CONSIDER_HOME) == expected


@pytest.mark.parametrize("input_value", [-10, 5000])
def test_options_device_tracker_consider_home_rejects_values_outside_selector_range(
    input_value: Any,
) -> None:
    """_build_options_init_schema should reject consider_home values outside range."""
    oschema = cf_mod._build_options_init_schema(user_input=None)

    with pytest.raises(vol.Invalid):
        oschema({cf_mod.CONF_DEVICE_TRACKER_CONSIDER_HOME: input_value})


def test_async_get_options_flow_returns_options_flow() -> None:
    """async_get_options_flow should return an OPNsenseOptionsFlow instance."""
    cfg = MagicMock()
    res = cf_mod.OPNsenseConfigFlow.async_get_options_flow(cfg)
    assert isinstance(res, cf_mod.OPNsenseOptionsFlow)
    assert isinstance(cf_mod.OPNsenseOptionsFlow(), cf_mod.OPNsenseOptionsFlow)


@pytest.mark.asyncio
async def test_options_flow_init_for_carp_entry_only_allows_scan_interval(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """CARP options init should render scan interval form and skip device-tracker fields."""
    cfg = make_config_entry(
        data={
            cf_mod.CONF_URL: "https://x",
            cf_mod.CONF_USERNAME: "u",
            cf_mod.CONF_PASSWORD: "p",
            cf_mod.CONF_ENTRY_TYPE: ENTRY_TYPE_CARP,
        },
        options={cf_mod.CONF_SCAN_INTERVAL: 45},
    )
    flow = _make_options_flow(cfg)
    flow._config = dict(cfg.data)
    flow._options = dict(cfg.options)

    res = await flow.async_step_init()

    assert res["type"] == "form"
    assert res["step_id"] == "init"
    assert res["description_placeholders"]["options_scope"] == (
        "scan interval only for this CARP VIP entry"
    )
    data = res["data_schema"]({})
    assert data == {cf_mod.CONF_SCAN_INTERVAL: 45}


@pytest.mark.asyncio
async def test_options_flow_init_for_carp_entry_saves_scan_interval(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Submitting CARP options should normalize scan interval and preserve unrelated options."""
    cfg = make_config_entry(
        data={
            cf_mod.CONF_URL: "https://x",
            cf_mod.CONF_USERNAME: "u",
            cf_mod.CONF_PASSWORD: "p",
            cf_mod.CONF_ENTRY_TYPE: ENTRY_TYPE_CARP,
        },
        options={
            cf_mod.CONF_SCAN_INTERVAL: 60,
            cf_mod.CONF_DEVICE_TRACKER_ENABLED: False,
            cf_mod.CONF_DEVICE_TRACKING_MODE: cf_mod.DEVICE_TRACKING_MODE_SELECTED,
        },
    )
    flow = _make_options_flow(cfg)
    flow._config = dict(cfg.data)
    flow._options = dict(cfg.options)

    res = await flow.async_step_init(user_input={cf_mod.CONF_SCAN_INTERVAL: 120})

    assert res["type"] == "create_entry"
    assert flow._options == {
        cf_mod.CONF_SCAN_INTERVAL: 120,
        cf_mod.CONF_DEVICE_TRACKER_ENABLED: False,
        cf_mod.CONF_DEVICE_TRACKING_MODE: cf_mod.DEVICE_TRACKING_MODE_SELECTED,
    }


@pytest.mark.asyncio
async def test_options_flow_init_with_user_triggers_update() -> None:
    """Submitting user input to async_step_init should update entry and create entry."""
    cfg = MagicMock()
    cfg.data = {cf_mod.CONF_URL: "https://x", cf_mod.CONF_USERNAME: "u", cf_mod.CONF_PASSWORD: "p"}
    cfg.options = {cf_mod.CONF_DEVICE_TRACKER_ENABLED: False}

    flow = _make_options_flow(cfg)

    # populate internals to avoid Home Assistant property lookups in this unit test
    flow._config = dict(cfg.data)
    flow._options = dict(cfg.options)

    user_input = {cf_mod.CONF_SCAN_INTERVAL: 30}
    res = await flow.async_step_init(user_input=user_input)

    # should have called update_entry and returned create_entry
    flow.hass.config_entries.async_update_entry.assert_called()
    assert res["type"] == "create_entry"
    assert flow._options.get(cf_mod.CONF_SCAN_INTERVAL) == 30
    assert isinstance(flow._options.get(cf_mod.CONF_SCAN_INTERVAL), int)


@pytest.mark.asyncio
async def test_options_flow_init_for_device_shows_resolved_description_scope(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Device options form render should include normal options-scope description placeholders."""
    cfg = make_config_entry(
        data={cf_mod.CONF_URL: "https://x", cf_mod.CONF_USERNAME: "u", cf_mod.CONF_PASSWORD: "p"},
        options={},
    )
    flow = _make_options_flow(cfg)
    flow._config = dict(cfg.data)
    flow._options = dict(cfg.options)

    res = await flow.async_step_init()

    assert res["type"] == "form"
    assert res["step_id"] == "init"
    assert res["description_placeholders"] == {
        "options_scope": "all available integration and device-tracker options"
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    [
        (cf_mod.CONF_SCAN_INTERVAL, 30.0),
        (cf_mod.CONF_DEVICE_TRACKER_SCAN_INTERVAL, 150.0),
        (cf_mod.CONF_DEVICE_TRACKER_CONSIDER_HOME, 120.0),
    ],
)
async def test_options_flow_init_normalizes_numeric_values(field: str, value: float) -> None:
    """Submitting numeric options should persist integer values."""
    cfg = MagicMock()
    cfg.data = {cf_mod.CONF_URL: "https://x", cf_mod.CONF_USERNAME: "u", cf_mod.CONF_PASSWORD: "p"}
    cfg.options = {cf_mod.CONF_DEVICE_TRACKER_ENABLED: False}

    flow = _make_options_flow(cfg)
    flow._config = dict(cfg.data)
    flow._options = dict(cfg.options)

    res = await flow.async_step_init(user_input={field: value})

    flow.hass.config_entries.async_update_entry.assert_called()
    assert res["type"] == "create_entry"
    assert flow._options[field] == int(value)
    assert isinstance(flow._options[field], int)


@pytest.mark.asyncio
async def test_options_flow_granular_sync_calls_validate_and_updates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """async_step_granular_sync should call validate_input and update entry when no errors."""
    cfg = MagicMock()
    cfg.data = {cf_mod.CONF_URL: "https://x", cf_mod.CONF_USERNAME: "u", cf_mod.CONF_PASSWORD: "p"}
    cfg.options = {cf_mod.CONF_DEVICE_TRACKER_ENABLED: False}

    flow = _make_options_flow(cfg)

    # monkeypatch validate_input to return no errors
    async def fake_validate(hass: HomeAssistant, user_input: Any, errors: Any, **kwargs) -> Any:
        """Return an empty error mapping so the options flow can proceed.

        Args:
            hass: Home Assistant instance that owns the integration state, entity registry, and services.
            user_input: Values submitted for the current configuration or options flow step.
            errors: Mutable error mapping that would normally be populated by validation.
            **kwargs: Additional validation context forwarded by the caller and ignored here.
        """
        return {}

    monkeypatch.setattr(cf_mod, "validate_input", fake_validate)

    # use an actual granular sync key present in the module
    gkey = next(iter(cf_mod.GRANULAR_SYNC_ITEMS))
    # populate internals so the flow method doesn't access Home Assistant internals
    flow._config = dict(cfg.data)
    flow._options = dict(cfg.options)
    user_input = {gkey: True}
    res = await flow.async_step_granular_sync(user_input=user_input)
    flow.hass.config_entries.async_update_entry.assert_called()
    assert res["type"] == "create_entry"


@pytest.mark.asyncio
async def test_device_tracker_shows_form_when_no_user_input(
    monkeypatch: pytest.MonkeyPatch, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """async_step_device_tracker should show form containing data_schema when called without user_input."""
    cfg = make_config_entry(
        data={cf_mod.CONF_URL: "https://x", cf_mod.CONF_USERNAME: "u", cf_mod.CONF_PASSWORD: "p"},
        options={cf_mod.CONF_DEVICES: ["11:22:33:44:55:66"]},
    )

    flow = _make_options_flow(cfg)

    # monkeypatch _get_dt_entries to return an ordered dict-like mapping
    async def fake_get_dt_entries(hass: HomeAssistant, config: Any, selected_devices: Any) -> Any:
        """Return a deterministic mapping of selectable device-tracker entries.

        Args:
            hass: Home Assistant instance that owns the integration state, entity registry, and services.
            config: Integration configuration used to build the selector entries.
            selected_devices: MAC addresses that should remain selected in the form.
        """
        return {"11:22:33:44:55:66": "label1", "aa:bb:cc:dd:ee:ff": "label2"}

    monkeypatch.setattr(cf_mod, "_get_dt_entries", fake_get_dt_entries)

    # ensure internals are present so we don't trigger config_entry property lookup
    flow._config = dict(cfg.data)
    flow._options = dict(cfg.options)
    res = await flow.async_step_device_tracker(user_input=None)
    assert res["type"] == "form"
    assert "data_schema" in res
    validated = res["data_schema"]({})
    assert cf_mod.CONF_DEVICES in validated


@pytest.mark.parametrize(
    ("exception_factory", "expected_base_error"),
    [
        (aiopnsense_exceptions.OPNsenseConnectionError, "cannot_connect"),
        (aiopnsense_exceptions.OPNsenseInvalidAuth, "invalid_auth"),
        (cf_mod.OPNsenseSSLError, "cannot_connect_ssl"),
        (aiopnsense_exceptions.OPNsensePrivilegeMissing, "privilege_missing"),
        (aiopnsense_exceptions.OPNsenseTimeoutError, "connect_timeout"),
        (ServerTimeoutError, "connect_timeout"),
        (ClientError, "cannot_connect"),
    ],
    ids=[
        "cannot_connect",
        "invalid_auth",
        "ssl",
        "privilege_missing",
        "timeout",
        "server_timeout",
        "aiohttp",
    ],
)
@pytest.mark.asyncio
async def test_device_tracker_handles_arp_lookup_failure(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
    exception_factory: type[BaseException],
    expected_base_error: str,
) -> None:
    """ARP lookup failures should not abort device tracker form rendering."""
    exc = exception_factory("boom")
    cfg = make_config_entry(
        data={cf_mod.CONF_URL: "https://x", cf_mod.CONF_USERNAME: "u", cf_mod.CONF_PASSWORD: "p"},
        options={cf_mod.CONF_DEVICES: ["AA-BB-CC-DD-EE-FF"]},
    )
    flow = _make_options_flow(cfg)
    flow._config = dict(cfg.data)
    flow._options = dict(cfg.options)

    async def _raise(*args, **kwargs) -> Never:
        """Raise the parametrized exception so device-tracker lookup failures can be tested.

        Args:
            *args: Additional positional arguments forwarded by the function.
            **kwargs: Additional keyword arguments forwarded by the function.

        Raises:
            BaseException: Always raised to exercise error handling in the options flow.
        """
        raise exc

    monkeypatch.setattr(cf_mod, "_get_dt_entries", _raise)

    res = await flow.async_step_device_tracker(user_input=None)
    assert res["type"] == "form"
    assert res["errors"]["base"] == expected_base_error
    validated = res["data_schema"]({})
    assert validated[cf_mod.CONF_DEVICES] == ["aa:bb:cc:dd:ee:ff"]


@pytest.mark.asyncio
async def test_device_tracker_handles_builtin_timeout_lookup_failure(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Builtin TimeoutError from ARP lookup should map to connect_timeout."""
    cfg = make_config_entry(
        data={cf_mod.CONF_URL: "https://x", cf_mod.CONF_USERNAME: "u", cf_mod.CONF_PASSWORD: "p"},
        options={cf_mod.CONF_DEVICES: ["AA-BB-CC-DD-EE-FF"]},
    )
    flow = _make_options_flow(cfg)
    flow._config = dict(cfg.data)
    flow._options = dict(cfg.options)

    async def _raise(*args, **kwargs) -> Never:
        raise TimeoutError("timed out")

    monkeypatch.setattr(cf_mod, "_get_dt_entries", _raise)

    res = await flow.async_step_device_tracker(user_input=None)
    assert res["type"] == "form"
    assert res["errors"]["base"] == "connect_timeout"
    validated = res["data_schema"]({})
    assert validated[cf_mod.CONF_DEVICES] == ["aa:bb:cc:dd:ee:ff"]


@pytest.mark.asyncio
async def test_device_tracker_handles_opnsense_timeout_error(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """OPNsense timeouts should keep picker rendering with the saved MAC fallback."""
    cfg = make_config_entry(
        data={cf_mod.CONF_URL: "https://x", cf_mod.CONF_USERNAME: "u", cf_mod.CONF_PASSWORD: "p"},
        options={cf_mod.CONF_DEVICES: ["AA-BB-CC-DD-EE-FF"]},
    )
    flow = _make_options_flow(cfg)
    flow._config = dict(cfg.data)
    flow._options = dict(cfg.options)

    async def _raise_timeout(*args: object, **kwargs: object) -> Never:
        """Raise an OPNsense timeout to exercise connect_timeout mapping."""
        raise aiopnsense_exceptions.OPNsenseTimeoutError("request timed out")

    monkeypatch.setattr(cf_mod, "_get_dt_entries", _raise_timeout)
    res_timeout = await flow.async_step_device_tracker(user_input=None)
    assert res_timeout["type"] == "form"
    assert res_timeout["errors"]["base"] == "connect_timeout"
    validated_timeout = res_timeout["data_schema"]({})
    assert validated_timeout[cf_mod.CONF_DEVICES] == ["aa:bb:cc:dd:ee:ff"]


@pytest.mark.asyncio
async def test_options_flow_device_tracker_user_input(
    monkeypatch: pytest.MonkeyPatch, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """When user submits manual devices, they should be parsed and saved to options."""
    # Build a fake config_entry using shared factory
    config_entry = make_config_entry(
        data={
            cf_mod.CONF_URL: "https://x",
            cf_mod.CONF_USERNAME: "u",
            cf_mod.CONF_PASSWORD: "p",
        },
        options={cf_mod.CONF_DEVICE_TRACKER_ENABLED: True, cf_mod.CONF_DEVICES: []},
    )

    flow = _make_options_flow(config_entry)

    # emulate what async_step_init would do: populate _config and _options from entry
    flow._config = dict(config_entry.data)
    flow._options = dict(config_entry.options)

    user_input = {
        cf_mod.CONF_MANUAL_DEVICES: "aa:bb:cc:dd:ee:ff\nbad\n11:22:33:44:55:66",
        cf_mod.CONF_DEVICES: ["11:22:33:44:55:66"],
    }

    result = await flow.async_step_device_tracker(user_input=user_input)

    # flow should have returned a create_entry
    assert result["type"] == "create_entry"

    # The flow should have parsed manual devices into _options
    assert cf_mod.CONF_DEVICES in flow._options
    assert "aa:bb:cc:dd:ee:ff" in flow._options[cf_mod.CONF_DEVICES]
    assert "11:22:33:44:55:66" in flow._options[cf_mod.CONF_DEVICES]
    assert flow._options[cf_mod.CONF_DEVICES] == ["11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff"]


@pytest.mark.asyncio
async def test_options_flow_device_tracker_track_all_clears_device_list(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Track-all mode from init should persist the legacy empty-device-list behavior."""
    config_entry = make_config_entry(
        data={
            cf_mod.CONF_URL: "https://x",
            cf_mod.CONF_USERNAME: "u",
            cf_mod.CONF_PASSWORD: "p",
        },
        options={
            cf_mod.CONF_DEVICE_TRACKER_ENABLED: True,
            cf_mod.CONF_DEVICES: ["aa:bb:cc:dd:ee:ff"],
        },
    )

    flow = _make_options_flow(config_entry)
    flow._config = dict(config_entry.data)
    flow._options = dict(config_entry.options)

    result = await flow.async_step_init(
        user_input={
            cf_mod.CONF_DEVICE_TRACKING_MODE: cf_mod.DEVICE_TRACKING_MODE_ALL,
            cf_mod.CONF_GRANULAR_SYNC_OPTIONS: False,
        }
    )

    assert result["type"] == "create_entry"
    assert flow._options[cf_mod.CONF_DEVICES] == []


@pytest.mark.asyncio
async def test_options_flow_init_selected_mode_shows_picker_step(
    monkeypatch: pytest.MonkeyPatch, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Selected-only mode should continue to the device picker step."""
    config_entry = make_config_entry(
        data={
            cf_mod.CONF_URL: "https://x",
            cf_mod.CONF_USERNAME: "u",
            cf_mod.CONF_PASSWORD: "p",
        },
        options={cf_mod.CONF_DEVICE_TRACKER_ENABLED: False, cf_mod.CONF_DEVICES: []},
    )
    flow = _make_options_flow(config_entry)
    monkeypatch.setattr(cf_mod, "_get_dt_entries", AsyncMock(return_value={}))

    result = await flow.async_step_init(
        user_input={
            cf_mod.CONF_DEVICE_TRACKING_MODE: cf_mod.DEVICE_TRACKING_MODE_SELECTED,
            cf_mod.CONF_GRANULAR_SYNC_OPTIONS: False,
        }
    )
    assert result["type"] == "form"
    assert result["step_id"] == "device_tracker"


@pytest.mark.asyncio
async def test_reconfigure_updates_entry_when_validation_succeeds(
    monkeypatch: pytest.MonkeyPatch, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Successful reconfigure submissions should update and abort the flow."""
    config_entry = make_config_entry(
        data={
            cf_mod.CONF_URL: "https://x",
            cf_mod.CONF_USERNAME: "u",
            cf_mod.CONF_PASSWORD: "p",
            cf_mod.CONF_DEVICE_UNIQUE_ID: "device-1",
        },
        options={},
        unique_id="device-1",
    )
    flow = cf_mod.OPNsenseConfigFlow()
    flow.hass = MagicMock()
    validate = AsyncMock(return_value={})
    set_unique_id = AsyncMock()
    update_and_abort = MagicMock(return_value={"type": "abort", "reason": "reconfigure_successful"})

    monkeypatch.setattr(cf_mod, "validate_input", validate)
    object.__setattr__(flow, "_get_reconfigure_entry", lambda: config_entry)
    object.__setattr__(flow, "async_set_unique_id", set_unique_id)
    object.__setattr__(flow, "_abort_if_unique_id_mismatch", lambda: None)
    object.__setattr__(flow, "async_update_and_abort", update_and_abort)

    result = await flow.async_step_reconfigure(
        user_input={
            cf_mod.CONF_URL: "https://router.example",
            cf_mod.CONF_USERNAME: "u",
            cf_mod.CONF_PASSWORD: "p",
        }
    )

    assert result == {"type": "abort", "reason": "reconfigure_successful"}
    validate.assert_awaited_once()
    validate_call = validate.await_args
    assert validate_call is not None
    assert validate_call.kwargs["expected_id"] == "device-1"
    set_unique_id.assert_awaited_once_with("device-1")
    update_and_abort.assert_called_once_with(
        entry=config_entry,
        data={
            cf_mod.CONF_URL: "https://router.example",
            cf_mod.CONF_USERNAME: "u",
            cf_mod.CONF_PASSWORD: "p",
            cf_mod.CONF_DEVICE_UNIQUE_ID: "device-1",
        },
    )


@pytest.mark.asyncio
async def test_reconfigure_device_aborts_on_carp_url_conflict(
    monkeypatch: pytest.MonkeyPatch, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """Device reconfigure should reject a changed URL used by a CARP entry."""
    config_entry = make_config_entry(
        data={
            cf_mod.CONF_URL: "https://old.example",
            cf_mod.CONF_USERNAME: "u",
            cf_mod.CONF_PASSWORD: "p",
            cf_mod.CONF_DEVICE_UNIQUE_ID: "device-1",
        },
        options={},
        unique_id="device-1",
    )
    existing_entry = make_config_entry(
        data={
            cf_mod.CONF_URL: "https://router.example:443",
            cf_mod.CONF_USERNAME: "carp-user",
            cf_mod.CONF_PASSWORD: "carp-pass",
            cf_mod.CONF_ENTRY_TYPE: ENTRY_TYPE_CARP,
        },
        options={},
    )
    flow = cf_mod.OPNsenseConfigFlow()
    flow.hass = MagicMock()
    flow.hass.config_entries = MagicMock()
    flow.hass.config_entries.async_entries = MagicMock(return_value=[existing_entry])
    validate = AsyncMock(return_value={})
    set_unique_id = AsyncMock()
    update_and_abort = MagicMock()

    monkeypatch.setattr(cf_mod, "validate_input", validate)
    object.__setattr__(flow, "_get_reconfigure_entry", lambda: config_entry)
    object.__setattr__(flow, "async_set_unique_id", set_unique_id)
    object.__setattr__(flow, "_abort_if_unique_id_mismatch", lambda: None)
    object.__setattr__(flow, "async_update_and_abort", update_and_abort)

    result = await flow.async_step_reconfigure(
        user_input={
            cf_mod.CONF_URL: "https://router.example",
            cf_mod.CONF_USERNAME: "u",
            cf_mod.CONF_PASSWORD: "p",
        }
    )

    assert result["type"] == "abort"
    assert result["reason"] == "carp_device_url_conflict"
    validate.assert_awaited_once()
    flow.hass.config_entries.async_entries.assert_called_once_with(cf_mod.DOMAIN)
    set_unique_id.assert_not_awaited()
    update_and_abort.assert_not_called()


@pytest.mark.asyncio
async def test_reconfigure_carp_updates_entry_without_unique_id_checks(
    monkeypatch: pytest.MonkeyPatch, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """CARP reconfigure should validate with CARP mode and skip unique-id checks."""
    config_entry = make_config_entry(
        data={
            cf_mod.CONF_URL: "https://x",
            cf_mod.CONF_USERNAME: "u",
            cf_mod.CONF_PASSWORD: "p",
            cf_mod.CONF_ENTRY_TYPE: ENTRY_TYPE_CARP,
            cf_mod.CONF_FIRMWARE_VERSION: "26.1.11",
            cf_mod.CONF_NAME: "Router CARP VIP",
        },
        options={},
    )
    flow = cf_mod.OPNsenseConfigFlow()
    flow.hass = MagicMock()
    validate = AsyncMock(return_value={})
    set_unique_id = AsyncMock()
    update_and_abort = MagicMock(return_value={"type": "abort", "reason": "reconfigure_successful"})

    monkeypatch.setattr(cf_mod, "validate_input", validate)
    object.__setattr__(flow, "_get_reconfigure_entry", lambda: config_entry)
    object.__setattr__(flow, "async_set_unique_id", set_unique_id)
    object.__setattr__(flow, "_abort_if_unique_id_mismatch", lambda: None)
    object.__setattr__(flow, "async_update_and_abort", update_and_abort)

    result = await flow.async_step_reconfigure(
        user_input={
            cf_mod.CONF_URL: "https://carp-router.example",
            cf_mod.CONF_USERNAME: "admin",
            cf_mod.CONF_PASSWORD: "secret",
            cf_mod.CONF_VERIFY_SSL: True,
        }
    )

    assert result == {"type": "abort", "reason": "reconfigure_successful"}
    validate.assert_awaited_once()
    validate_call = validate.await_args
    assert validate_call is not None
    assert validate_call.kwargs["carp"] is True
    assert "expected_id" not in validate_call.kwargs
    set_unique_id.assert_not_awaited()


@pytest.mark.asyncio
async def test_reconfigure_carp_aborts_on_device_url_conflict(
    monkeypatch: pytest.MonkeyPatch, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """CARP reconfigure should reject a changed URL used by a device entry."""
    config_entry = make_config_entry(
        data={
            cf_mod.CONF_URL: "https://old-carp.example",
            cf_mod.CONF_USERNAME: "u",
            cf_mod.CONF_PASSWORD: "p",
            cf_mod.CONF_ENTRY_TYPE: ENTRY_TYPE_CARP,
        },
        options={},
    )
    existing_entry = make_config_entry(
        data={
            cf_mod.CONF_URL: "http://router.example:80",
            cf_mod.CONF_USERNAME: "device-user",
            cf_mod.CONF_PASSWORD: "device-pass",
        },
        options={},
    )
    flow = cf_mod.OPNsenseConfigFlow()
    flow.hass = MagicMock()
    flow.hass.config_entries = MagicMock()
    flow.hass.config_entries.async_entries = MagicMock(return_value=[existing_entry])
    validate = AsyncMock(return_value={})
    abort_match = MagicMock(return_value={"type": "abort", "reason": "already_configured"})
    update_and_abort = MagicMock()

    monkeypatch.setattr(cf_mod, "validate_input", validate)
    object.__setattr__(flow, "_get_reconfigure_entry", lambda: config_entry)
    object.__setattr__(flow, "_async_abort_entries_match", abort_match)
    object.__setattr__(flow, "async_update_and_abort", update_and_abort)

    result = await flow.async_step_reconfigure(
        user_input={
            cf_mod.CONF_URL: "http://router.example",
            cf_mod.CONF_USERNAME: "admin",
            cf_mod.CONF_PASSWORD: "secret",
            cf_mod.CONF_VERIFY_SSL: True,
        }
    )

    assert result["type"] == "abort"
    assert result["reason"] == "carp_device_url_conflict"
    validate.assert_awaited_once()
    flow.hass.config_entries.async_entries.assert_called_once_with(cf_mod.DOMAIN)
    abort_match.assert_not_called()
    update_and_abort.assert_not_called()


@pytest.mark.asyncio
async def test_reconfigure_carp_returns_form_on_validation_error(
    monkeypatch: pytest.MonkeyPatch, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """CARP reconfigure validation errors should return form and not update."""
    config_entry = make_config_entry(
        data={
            cf_mod.CONF_URL: "https://x",
            cf_mod.CONF_USERNAME: "u",
            cf_mod.CONF_PASSWORD: "p",
            cf_mod.CONF_ENTRY_TYPE: ENTRY_TYPE_CARP,
        },
        options={},
    )
    flow = cf_mod.OPNsenseConfigFlow()
    flow.hass = MagicMock()
    validate = AsyncMock(return_value={"base": "invalid_host"})
    abort_match = MagicMock(return_value={"type": "abort", "reason": "already_configured"})
    update_and_abort = MagicMock()

    monkeypatch.setattr(cf_mod, "validate_input", validate)
    object.__setattr__(flow, "_get_reconfigure_entry", lambda: config_entry)
    object.__setattr__(flow, "_async_abort_entries_match", abort_match)
    object.__setattr__(flow, "async_update_and_abort", update_and_abort)

    result = await flow.async_step_reconfigure(
        user_input={
            cf_mod.CONF_URL: "https://router.example",
            cf_mod.CONF_USERNAME: "admin",
            cf_mod.CONF_PASSWORD: "secret",
            cf_mod.CONF_VERIFY_SSL: True,
        }
    )

    assert result["type"] == "form"
    assert result["step_id"] == "reconfigure"
    assert result["errors"] == {"base": "invalid_host"}
    abort_match.assert_not_called()
    update_and_abort.assert_not_called()


@pytest.mark.asyncio
async def test_reconfigure_carp_skips_duplicate_check_when_url_unchanged(
    monkeypatch: pytest.MonkeyPatch, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """CARP reconfigure should skip URL duplicate checks when the URL is unchanged."""
    config_entry = make_config_entry(
        entry_id="carp-entry",
        data={
            cf_mod.CONF_URL: "https://carp-router.example",
            cf_mod.CONF_USERNAME: "u",
            cf_mod.CONF_PASSWORD: "p",
            cf_mod.CONF_ENTRY_TYPE: ENTRY_TYPE_CARP,
        },
        options={},
    )
    flow = cf_mod.OPNsenseConfigFlow()
    flow.hass = MagicMock()
    validate = AsyncMock(
        side_effect=lambda **kwargs: kwargs["user_input"].update(
            {cf_mod.CONF_URL: "https://carp-router.example"}
        )
    )
    monkeypatch.setattr(cf_mod, "validate_input", validate)
    object.__setattr__(flow, "_get_reconfigure_entry", lambda: config_entry)
    abort_match = MagicMock(return_value={"type": "abort", "reason": "already_configured"})
    object.__setattr__(flow, "_async_abort_entries_match", abort_match)
    update_and_abort = MagicMock(return_value={"type": "abort", "reason": "reconfigure_successful"})
    object.__setattr__(flow, "async_update_and_abort", update_and_abort)

    result = await flow.async_step_reconfigure(
        user_input={
            cf_mod.CONF_URL: "https://carp-router.example/",
            cf_mod.CONF_USERNAME: "admin",
            cf_mod.CONF_PASSWORD: "secret",
            cf_mod.CONF_VERIFY_SSL: True,
        }
    )

    assert result == {"type": "abort", "reason": "reconfigure_successful"}
    validate.assert_awaited_once()
    abort_match.assert_not_called()
    update_and_abort.assert_called_once_with(
        entry=config_entry,
        data={
            cf_mod.CONF_URL: "https://carp-router.example",
            cf_mod.CONF_USERNAME: "admin",
            cf_mod.CONF_PASSWORD: "secret",
            cf_mod.CONF_VERIFY_SSL: True,
            cf_mod.CONF_ENTRY_TYPE: ENTRY_TYPE_CARP,
        },
    )


@pytest.mark.asyncio
async def test_reconfigure_carp_aborts_on_normalized_duplicate_url(
    monkeypatch: pytest.MonkeyPatch, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """CARP reconfigure should reject a normalized URL used by another entry."""
    config_entry = make_config_entry(
        entry_id="carp-entry",
        data={
            cf_mod.CONF_URL: "https://old.example",
            cf_mod.CONF_USERNAME: "u",
            cf_mod.CONF_PASSWORD: "p",
            cf_mod.CONF_ENTRY_TYPE: ENTRY_TYPE_CARP,
        },
        options={},
    )
    flow = cf_mod.OPNsenseConfigFlow()
    flow.hass = MagicMock()
    validate = AsyncMock(
        side_effect=lambda **kwargs: kwargs["user_input"].update(
            {cf_mod.CONF_URL: "https://carp-router.example"}
        )
    )
    monkeypatch.setattr(cf_mod, "validate_input", validate)
    object.__setattr__(flow, "_get_reconfigure_entry", lambda: config_entry)
    duplicate_abort = {"type": "abort", "reason": "already_configured"}
    abort_match = MagicMock(return_value=duplicate_abort)
    object.__setattr__(flow, "_async_abort_entries_match", abort_match)
    update_and_abort = MagicMock()
    object.__setattr__(flow, "async_update_and_abort", update_and_abort)

    result = await flow.async_step_reconfigure(
        user_input={
            cf_mod.CONF_URL: "https://carp-router.example/",
            cf_mod.CONF_USERNAME: "admin",
            cf_mod.CONF_PASSWORD: "secret",
            cf_mod.CONF_VERIFY_SSL: True,
        }
    )

    assert result == duplicate_abort
    abort_match.assert_called_once_with({cf_mod.CONF_URL: "https://carp-router.example"})
    update_and_abort.assert_not_called()


@pytest.mark.asyncio
async def test_reconfigure_carp_preserves_self_url_when_no_duplicate(
    monkeypatch: pytest.MonkeyPatch, make_config_entry: Callable[..., MockConfigEntry]
) -> None:
    """CARP reconfigure should keep its own normalized URL when no other entry matches."""
    config_entry = make_config_entry(
        entry_id="carp-entry",
        data={
            cf_mod.CONF_URL: "https://old.example",
            cf_mod.CONF_USERNAME: "u",
            cf_mod.CONF_PASSWORD: "p",
            cf_mod.CONF_ENTRY_TYPE: ENTRY_TYPE_CARP,
        },
        options={},
    )
    flow = cf_mod.OPNsenseConfigFlow()
    flow.hass = MagicMock()
    validate = AsyncMock(
        side_effect=lambda **kwargs: kwargs["user_input"].update(
            {cf_mod.CONF_URL: "https://carp-router.example"}
        )
    )
    monkeypatch.setattr(cf_mod, "validate_input", validate)
    object.__setattr__(flow, "_get_reconfigure_entry", lambda: config_entry)
    abort_match = MagicMock(return_value=None)
    object.__setattr__(flow, "_async_abort_entries_match", abort_match)
    update_and_abort = MagicMock(return_value={"type": "abort", "reason": "reconfigure_successful"})
    object.__setattr__(flow, "async_update_and_abort", update_and_abort)

    result = await flow.async_step_reconfigure(
        user_input={
            cf_mod.CONF_URL: "https://carp-router.example/",
            cf_mod.CONF_USERNAME: "admin",
            cf_mod.CONF_PASSWORD: "secret",
            cf_mod.CONF_VERIFY_SSL: True,
        }
    )

    assert result == {"type": "abort", "reason": "reconfigure_successful"}
    abort_match.assert_called_once_with({cf_mod.CONF_URL: "https://carp-router.example"})
    update_and_abort.assert_called_once()


@pytest.mark.asyncio
async def test_validate_input_granular_sync_uses_native_validation_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Granular sync flow should validate firmware without removed backend checks."""

    class FakeClient:
        """Client stub that asserts removed backend checks are not called."""

        def __init__(self, firmware_version: str) -> None:
            """Initialize the fake client with a known firmware version."""
            self.firmware_version = firmware_version
            self.is_plugin_installed = AsyncMock(
                side_effect=AssertionError("legacy plugin check called")
            )
            self.set_use_snake_case = AsyncMock(
                side_effect=AssertionError("snake-case backend selection called")
            )
            self.validate = AsyncMock()
            self.async_close = AsyncMock()

        async def get_host_firmware_version(self) -> str:
            """Return the fake firmware version."""
            return self.firmware_version

        async def get_system_info(self) -> dict[str, str]:
            """Return static system metadata for validation."""
            return {"name": "OPNsense"}

        async def get_device_unique_id(
            self, _expected_id: str | None = None, **_kwargs: Any
        ) -> str:
            """Return a stable device unique id."""
            return "dev-01"

    client = FakeClient("25.1")
    monkeypatch.setattr(cf_mod, "create_opnsense_client", lambda **_kwargs: client)

    user_input = {
        cf_mod.CONF_URL: "https://host.example",
        cf_mod.CONF_USERNAME: "user",
        cf_mod.CONF_PASSWORD: "pass",
        cf_mod.CONF_GRANULAR_SYNC_OPTIONS: True,
        CONF_SYNC_FIREWALL_AND_NAT: True,
    }
    errors: dict[str, Any] = {}

    res = await cf_mod.validate_input(
        hass=MagicMock(),
        user_input=user_input,
        errors=errors,
    )

    assert res == {}
    assert user_input[cf_mod.CONF_FIRMWARE_VERSION] == "25.1"
    client.validate.assert_awaited_once()
    client.is_plugin_installed.assert_not_awaited()
    client.set_use_snake_case.assert_not_awaited()
    client.async_close.assert_awaited_once()
