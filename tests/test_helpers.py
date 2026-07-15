"""Unit tests for shared OPNsense integration helpers."""

from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock

import aiohttp
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.opnsense import helpers as helpers_mod
from custom_components.opnsense.const import (
    CONF_DEVICE_UNIQUE_ID,
    CONF_ENTRY_TYPE,
    DEFAULT_VERIFY_SSL,
    ENTRY_TYPE_CARP,
)
from custom_components.opnsense.helpers import (
    coerce_bool,
    config_entry_identity,
    create_opnsense_client,
    create_opnsense_client_from_config_entry,
    firewall_nat_switch_unique_ids_from_payload,
    firewall_rule_id_from_payload,
    firewall_rule_switch_unique_ids_from_payload,
    get_arp_ip,
    get_arp_mac,
    get_smart_device_name,
    is_carp_entry,
    is_usable_carp_vip,
    normalize_arp_mac,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(True, True, id="true"),
        pytest.param(False, False, id="false"),
        pytest.param(1, True, id="int-one"),
        pytest.param(0, False, id="int-zero"),
        pytest.param(2.5, True, id="float-non-zero"),
        pytest.param(0.0, False, id="float-zero"),
        pytest.param("1", True, id="string-one"),
        pytest.param("0", False, id="string-zero"),
        pytest.param("true", True, id="string-true"),
        pytest.param("false", False, id="string-false"),
        pytest.param("yes", True, id="string-yes"),
        pytest.param("no", False, id="string-no"),
        pytest.param("on", True, id="string-on"),
        pytest.param("off", False, id="string-off"),
    ],
)
def test_coerce_bool_parses_bool_like_values(value: Any, expected: bool) -> None:
    """Verify bool-like values are converted to booleans."""
    assert coerce_bool(value) is expected


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("", id="empty-string"),
        pytest.param("maybe", id="unknown-string"),
        pytest.param(None, id="none"),
        pytest.param(object(), id="object"),
    ],
)
def test_coerce_bool_returns_none_for_unknown_values(value: Any) -> None:
    """Verify unknown values are not coerced into a boolean."""
    assert coerce_bool(value) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param("AA:BB:CC", "aa:bb:cc", id="colon-separated"),
        pytest.param(" AA-BB-CC ", "aa:bb:cc", id="hyphen-separated"),
        pytest.param(None, "", id="non-string"),
    ],
)
def test_normalize_arp_mac(value: object, expected: str) -> None:
    """Normalize ARP MAC values into the shared representation."""
    assert normalize_arp_mac(value) == expected


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        pytest.param({"mac": "AA:BB:CC"}, "aa:bb:cc", id="normalized-key"),
        pytest.param({"mac-address": "AA-BB-CC"}, "aa:bb:cc", id="raw-key"),
        pytest.param(
            {"mac": 1, "mac-address": "AA-BB-CC"},
            "aa:bb:cc",
            id="fallback-key",
        ),
    ],
)
def test_get_arp_mac(entry: dict[str, Any], expected: str) -> None:
    """Read normalized and raw ARP MAC keys through one helper."""
    assert get_arp_mac(entry) == expected


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        pytest.param({"ip": " 192.0.2.1 "}, "192.0.2.1", id="normalized-key"),
        pytest.param({"ip-address": " 192.0.2.2 "}, "192.0.2.2", id="raw-key"),
        pytest.param({"ip": 1}, "", id="invalid-value"),
    ],
)
def test_get_arp_ip(entry: dict[str, Any], expected: str) -> None:
    """Read and strip normalized and raw ARP IP keys through one helper."""
    assert get_arp_ip(entry) == expected


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        pytest.param({"device": " nvme0 "}, "nvme0", id="device"),
        pytest.param({"ident": " SERIAL-ONLY "}, "SERIAL-ONLY", id="ident-fallback"),
        pytest.param(
            {"device": "", "ident": "serial-only"},
            "serial-only",
            id="blank-device",
        ),
        pytest.param({"device": 1}, "", id="invalid-values"),
    ],
)
def test_get_smart_device_name(entry: dict[str, Any], expected: str) -> None:
    """Read SMART device identifiers from the shared helper."""
    assert get_smart_device_name(entry) == expected


@pytest.mark.parametrize(
    "value",
    [
        {"vhid": 1, "subnet": "192.0.2.1"},
        {"vhid": " 2 ", "subnet": " 192.0.2.2 "},
    ],
)
def test_is_usable_carp_vip_accepts_normalized_identity_without_interface(
    value: dict[str, Any],
) -> None:
    """CARP VIP usability should accept integer/string VHIDs without interface names."""
    assert is_usable_carp_vip(value) is True


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        [],
        {"vhid": "", "subnet": "192.0.2.1"},
        {"vhid": 1, "subnet": ""},
        {"vhid": True, "subnet": "192.0.2.1"},
    ],
)
def test_is_usable_carp_vip_rejects_missing_or_blank_identity(value: Any) -> None:
    """CARP VIP usability should reject malformed or blank identity rows."""
    assert is_usable_carp_vip(value) is False


@pytest.mark.parametrize(
    (
        "throw_errors",
        "name",
    ),
    [
        pytest.param(True, None, id="config-flow-validation"),
        pytest.param(False, "router", id="runtime-client"),
    ],
)
def test_create_opnsense_client_builds_client_with_expected_options(
    monkeypatch: pytest.MonkeyPatch,
    throw_errors: bool,
    name: str | None,
) -> None:
    """Create OPNsense clients with the caller-specific session and client options."""
    created: dict[str, Any] = {}
    session = MagicMock(spec=aiohttp.ClientSession)
    hass = MagicMock()

    def _async_create_clientsession(hass: Any, **kwargs: Any) -> aiohttp.ClientSession:
        """Capture session construction options and return a fake session."""
        created["hass"] = hass
        created["session_kwargs"] = kwargs
        return session

    def _client(**kwargs: Any) -> MagicMock:
        """Capture OPNsense client construction options and return a fake client."""
        created["client_kwargs"] = kwargs
        return MagicMock()

    class _CookieJar:
        """Fake aiohttp cookie jar that records its safety setting."""

        def __init__(self, *, unsafe: bool) -> None:
            """Capture the unsafe flag without requiring a running event loop."""
            self._unsafe = unsafe

    monkeypatch.setattr(helpers_mod, "async_create_clientsession", _async_create_clientsession)
    monkeypatch.setattr(helpers_mod.aiohttp, "CookieJar", _CookieJar)
    monkeypatch.setattr(helpers_mod, "OPNsenseClient", _client)

    password = "pass"
    client = create_opnsense_client(
        hass=hass,
        url="http://10.0.0.1",
        username="user",
        password=password,
        verify_ssl=False,
        throw_errors=throw_errors,
        name=name,
    )

    assert isinstance(client, MagicMock)
    assert created["hass"] is hass
    assert created["session_kwargs"]["raise_for_status"] is False
    assert created["session_kwargs"]["cookie_jar"]._unsafe is True
    expected_client_kwargs = {
        "url": "http://10.0.0.1",
        "username": "user",
        "password": password,
        "session": session,
        "opts": {"verify_ssl": False},
        "throw_errors": throw_errors,
    }
    if name is not None:
        expected_client_kwargs["name"] = name
    assert created["client_kwargs"] == expected_client_kwargs


@pytest.mark.parametrize(
    ("entry_data", "throw_errors", "expected_verify_ssl"),
    [
        pytest.param(
            {
                "url": "https://router.example",
                "username": "user",
                "password": "pass",
                "verify_ssl": False,
            },
            True,
            False,
            id="forwards-explicit-verify-ssl",
        ),
        pytest.param(
            {
                "url": "https://router.example",
                "username": "user",
                "password": "pass",
            },
            False,
            DEFAULT_VERIFY_SSL,
            id="defaults-missing-verify-ssl",
        ),
    ],
)
def test_create_opnsense_client_from_config_entry_forwards_entry_data(
    monkeypatch: pytest.MonkeyPatch,
    entry_data: dict[str, Any],
    throw_errors: bool,
    expected_verify_ssl: bool,
) -> None:
    """Create OPNsense clients from config entries through the shared helper."""
    captured: dict[str, Any] = {}
    hass = MagicMock()
    client = MagicMock()
    entry = MockConfigEntry(
        data=entry_data,
        title="router",
    )

    def _create_opnsense_client(**kwargs: Any) -> MagicMock:
        """Capture forwarded client settings."""
        captured.update(kwargs)
        return client

    monkeypatch.setattr(helpers_mod, "create_opnsense_client", _create_opnsense_client)

    result = create_opnsense_client_from_config_entry(
        hass=hass,
        config_entry=entry,
        throw_errors=throw_errors,
    )

    assert result is client
    assert captured == {
        "hass": hass,
        "url": "https://router.example",
        "username": "user",
        "password": "pass",
        "verify_ssl": expected_verify_ssl,
        "throw_errors": throw_errors,
        "name": "router",
    }


@pytest.mark.parametrize(
    ("rule_key", "rule", "expected"),
    [
        pytest.param("r1", {"uuid": "uuid-1"}, "uuid-1", id="has-uuid"),
        pytest.param("r1", {}, "r1", id="uuid-missing-falls-back-to-key"),
        pytest.param("r1", {"uuid": ""}, "r1", id="empty-uuid-falls-back-to-key"),
        pytest.param("r1", {"uuid": 123}, "r1", id="bad-uuid-falls-back-to-key"),
        pytest.param("r1", "not-a-mapping", None, id="non-mapping-row-no-id"),
        pytest.param(3, {}, None, id="non-string-key-no-uuid"),
    ],
)
def test_firewall_rule_id_from_payload(
    rule_key: object,
    rule: object,
    expected: str | None,
) -> None:
    """Read rule IDs from payload with fallback to the payload key when safe."""
    assert firewall_rule_id_from_payload(rule_key, rule) == expected


def test_firewall_rule_switch_unique_ids_from_payload_skips_invalid_rules() -> None:
    """Only include mapping rows with string interface values and valid rule IDs."""
    rules: dict[str, Any] = {
        "r1": {"description": "rule-with-key"},
        "r2": {"uuid": "uuid-2", "%interface": ["wan", "lan"]},
        "r3": ["bad-row"],
        "r4": {"uuid": "uuid-4", "interface": "wan"},
    }

    ids = firewall_rule_switch_unique_ids_from_payload("deviceid", rules)
    assert ids == {
        "deviceid_firewall_rule_r1",
        "deviceid_firewall_rule_uuid_4",
    }


def test_firewall_nat_switch_unique_ids_from_payload_builds_nat_ids() -> None:
    """Build native NAT unique IDs from supported NAT sections."""
    rules: dict[str | int, Any] = {
        "r1": {"uuid": "uuid-1"},
        "r2": {"uuid": "uuid-2"},
        "r3": "bad-row",
        7: {},
        "r4": {},
    }

    ids = firewall_nat_switch_unique_ids_from_payload("deviceid", "source_nat", rules)
    assert ids == {
        "deviceid_firewall_nat_source_nat_uuid_1",
        "deviceid_firewall_nat_source_nat_uuid_2",
        "deviceid_firewall_nat_source_nat_r4",
    }


def test_entry_type_and_identity_helpers(
    make_config_entry: Callable[..., MockConfigEntry],
) -> None:
    """Validate config entry identity rules for device and CARP entries."""
    device_entry = make_config_entry(
        entry_id="device-entry",
        data={CONF_DEVICE_UNIQUE_ID: "aa_bb_cc_dd_ee_ff"},
    )
    carp_entry = make_config_entry(
        entry_id="carp-entry",
        data={CONF_ENTRY_TYPE: ENTRY_TYPE_CARP},
    )

    assert is_carp_entry(device_entry) is False
    assert config_entry_identity(device_entry) == "aa_bb_cc_dd_ee_ff"
    assert is_carp_entry(carp_entry) is True
    assert config_entry_identity(carp_entry) == "carp-entry"
