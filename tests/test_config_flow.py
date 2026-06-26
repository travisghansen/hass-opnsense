"""Unit tests for the config flow and options flow of the hass-opnsense integration.

Tests include URL parsing/validation, exception mapping for user input,
and options flow behaviors such as device tracker handling.
"""

from collections.abc import Callable
import importlib
from typing import Any, Never
from unittest.mock import AsyncMock, MagicMock

from aiopnsense import exceptions as aiopnsense_exceptions
from homeassistant.core import HomeAssistant
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
import voluptuous as vol

from custom_components.opnsense.const import (
    CONF_SYNC_FIREWALL_AND_NAT,
    CONF_SYNC_SMART,
    CONF_SYNC_TELEMETRY,
)
from tests.utilities import patch_opnsense_client

cf_mod = importlib.import_module("custom_components.opnsense.config_flow")


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
async def test_clean_and_parse_url_rejects_missing_host() -> None:
    """_clean_and_parse_url should reject URLs with a netloc but no host."""
    with pytest.raises(cf_mod.OPNsenseInvalidURL):
        await cf_mod._clean_and_parse_url({cf_mod.CONF_URL: "https://:443"})


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
async def test_validate_input_builtin_timeout_uses_connect_timeout_error(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Builtin TimeoutError should map to connect_timeout and redact credentials in logs."""
    username = "admin"
    password = "supersecret"

    async def _raiser(*args: object, **kwargs: object) -> Never:
        """Raise a built-in TimeoutError that includes secrets in the message."""
        raise TimeoutError(f"timed out for user={username} pass={password}")

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


def test_record_validation_error_sets_base(caplog: pytest.LogCaptureFixture) -> None:
    """_record_validation_error should log the message and set errors['base']."""
    errors: dict[str, str] = {}
    cf_mod._record_validation_error(errors=errors, key="test_key", message="an msg")
    assert errors.get("base") == "test_key"
    assert "an msg" in caplog.text


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
async def test_get_dt_entries_closes_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """_get_dt_entries should always close the temporary client."""

    class _Client:
        last_instance = None

        def __init__(self, *args, **kwargs) -> None:
            """Capture last created client instance for close assertions.

            Args:
                *args: Unused positional constructor args from factory helper.
                **kwargs: Unused keyword constructor args from factory helper.
            """
            type(self).last_instance = self
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
    _Client.last_instance.async_close.assert_awaited_once()


@pytest.mark.asyncio
async def test_validate_client_details_closes_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """_validate_client_details should always close the temporary client."""

    class _Client:
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


@pytest.mark.asyncio
async def test_device_tracker_handles_arp_lookup_failure(
    monkeypatch: pytest.MonkeyPatch,
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """ARP lookup failures should not abort device tracker form rendering."""
    exc = aiopnsense_exceptions.OPNsenseConnectionError("boom")
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
    assert res["errors"]["base"] == "cannot_connect"
    validated = res["data_schema"]({})
    assert validated[cf_mod.CONF_DEVICES] == ["aa:bb:cc:dd:ee:ff"]


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
async def test_validate_input_granular_sync_uses_native_validation_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Granular sync flow should validate firmware without removed backend checks."""

    class FakeClient:
        """Client stub that asserts removed backend checks are not called."""

        def __init__(self, firmware_version: str) -> None:
            """Initialize the fake client with a known firmware version."""
            self.firmware_version = firmware_version
            self.removed_backend_check = AsyncMock(
                side_effect=AssertionError("removed backend check called")
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

    assert client.removed_backend_check.await_count == 0
    res = await cf_mod.validate_input(
        hass=MagicMock(),
        user_input=user_input,
        errors=errors,
    )

    assert res == {}
    assert user_input[cf_mod.CONF_FIRMWARE_VERSION] == "25.1"
    client.validate.assert_awaited_once()
    client.removed_backend_check.assert_not_awaited()
    client.async_close.assert_awaited_once()
