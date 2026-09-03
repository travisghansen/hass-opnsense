"""Unit tests for shared OPNsense integration helpers."""

from collections.abc import Callable
from types import SimpleNamespace
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
    async_get_device_by_connection,
    async_get_device_by_identifier,
    async_get_devices_by_connection,
    coerce_bool,
    config_entry_identity,
    create_opnsense_client,
    create_opnsense_client_from_config_entry,
    detach_shared_router_parent,
    device_belongs_to_config_entry,
    dict_get,
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


@pytest.mark.parametrize("use_modern_api", [True, False], ids=["modern", "legacy"])
def test_async_get_device_by_identifier_supports_ha_versions(
    use_modern_api: bool,
) -> None:
    """Use the scoped identifier API when available and retain the HA 2026.3 fallback.

    Args:
        use_modern_api (bool): Whether the fake registry exposes the current scoped API.
    """
    device = MagicMock()
    legacy_get = MagicMock(return_value=device)
    registry: Any = SimpleNamespace()
    if use_modern_api:
        modern_get = MagicMock(return_value=device)
        registry.async_get_device_by_identifier = modern_get
    else:
        registry.async_get_device = legacy_get

    result = async_get_device_by_identifier(
        registry,
        ("opnsense", "router-id"),
        "entry-id",
    )

    assert result is device
    if use_modern_api:
        modern_get.assert_called_once_with(("opnsense", "router-id"), "entry-id")
        legacy_get.assert_not_called()
    else:
        legacy_get.assert_called_once_with(identifiers={("opnsense", "router-id")})


@pytest.mark.parametrize("use_modern_api", [True, False], ids=["modern", "legacy"])
def test_async_get_device_by_connection_supports_ha_versions(
    use_modern_api: bool,
) -> None:
    """Use the scoped connection API when available and retain the HA 2026.3 fallback.

    Args:
        use_modern_api (bool): Whether the fake registry exposes the current scoped API.
    """
    device = MagicMock()
    legacy_get = MagicMock(return_value=device)
    registry: Any = SimpleNamespace()
    if use_modern_api:
        modern_get = MagicMock(return_value=device)
        registry.async_get_device_by_connection = modern_get
    else:
        registry.async_get_device = legacy_get

    result = async_get_device_by_connection(
        registry,
        ("mac", "aa:bb:cc:dd:ee:ff"),
        "entry-id",
    )

    assert result is device
    if use_modern_api:
        modern_get.assert_called_once_with(("mac", "aa:bb:cc:dd:ee:ff"), "entry-id")
        legacy_get.assert_not_called()
    else:
        legacy_get.assert_called_once_with(connections={("mac", "aa:bb:cc:dd:ee:ff")})


@pytest.mark.parametrize("use_modern_api", [True, False], ids=["modern", "legacy"])
def test_async_get_devices_by_connection_supports_ha_versions(
    use_modern_api: bool,
) -> None:
    """Return every current match while adapting the singular HA 2026.3 fallback.

    Args:
        use_modern_api (bool): Whether the fake registry exposes the current multi-device API.
    """
    device = MagicMock()
    legacy_get = MagicMock(return_value=device)
    registry: Any = SimpleNamespace()
    if use_modern_api:
        modern_get = MagicMock(return_value=[device, MagicMock()])
        registry.async_get_devices = modern_get
    else:
        registry.async_get_device = legacy_get

    result = async_get_devices_by_connection(
        registry,
        ("mac", "aa:bb:cc:dd:ee:ff"),
    )

    if use_modern_api:
        assert len(result) == 2
        modern_get.assert_called_once_with(connections={("mac", "aa:bb:cc:dd:ee:ff")})
        legacy_get.assert_not_called()
    else:
        assert result == [device]
        legacy_get.assert_called_once_with(connections={("mac", "aa:bb:cc:dd:ee:ff")})


@pytest.mark.parametrize(
    ("device", "expected"),
    [
        pytest.param(SimpleNamespace(config_entry_id="entry-id"), True, id="modern-owner"),
        pytest.param(SimpleNamespace(config_entry_id="other-entry"), False, id="modern-foreign"),
        pytest.param(
            SimpleNamespace(config_entries={"entry-id", "other-entry"}),
            True,
            id="legacy-shared",
        ),
    ],
)
def test_device_belongs_to_config_entry_supports_ha_versions(
    device: Any,
    expected: bool,
) -> None:
    """Read singular modern ownership before falling back to the legacy set.

    Args:
        device (Any): Device entry shaped for the selected Home Assistant API generation.
        expected (bool): Whether the helper should report ownership by ``entry-id``.
    """
    assert device_belongs_to_config_entry(device, "entry-id") is expected


@pytest.mark.parametrize(
    ("owner_entry_id", "expected_removed"),
    [
        pytest.param("entry-id", True, id="owned"),
        pytest.param("other-entry", False, id="foreign"),
    ],
)
def test_detach_tracker_uses_modern_device_removal(
    owner_entry_id: str,
    expected_removed: bool,
) -> None:
    """Remove a singly-owned modern device without deprecated update parameters.

    Args:
        owner_entry_id (str): Config entry that owns the simulated tracker device.
        expected_removed (bool): Whether the tracker should be removed.
    """
    device: Any = SimpleNamespace(
        id="tracker-id",
        config_entry_id=owner_entry_id,
        via_device_id="router-id",
    )
    registry = MagicMock()

    result = detach_shared_router_parent(
        shared_config_entry_id="entry-id",
        shared_device_entry=device,
        router_device_id="router-id",
        config_entries=MagicMock(),
        device_registry=registry,
    )

    assert result == (True, None)
    if expected_removed:
        registry.async_remove_device.assert_called_once_with("tracker-id")
    else:
        registry.async_remove_device.assert_not_called()
    registry.async_update_device.assert_not_called()


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        pytest.param("items.1.name", "second", id="valid-index"),
        pytest.param("items.invalid.name", "missing", id="invalid-segment"),
        pytest.param("items.2.name", "missing", id="out-of-range-index"),
    ],
)
def test_dict_get_traverses_list_indexes(path: str, expected: str) -> None:
    """Traverse list indexes safely when resolving dotted paths.

    Args:
        path (str): Nested data path resolved by the helper.
        expected (str): Outcome asserted by the parameterized scenario.
    """
    data = {"items": [{"name": "first"}, {"name": "second"}]}

    assert dict_get(data, path, "missing") == expected


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
    """Verify bool-like values are converted to booleans.

    Args:
        value (Any): Input value exercised by the helper.
        expected (bool): Outcome asserted by the parameterized scenario.
    """
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
    """Verify unknown values are not coerced into a boolean.

    Args:
        value (Any): Input value exercised by the helper.
    """
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
    """Normalize ARP MAC values into the shared representation.

    Args:
        value (object): Input value exercised by the helper.
        expected (str): Outcome asserted by the parameterized scenario.
    """
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
        pytest.param(
            {"mac": "  ", "mac-address": "AA-BB-CC"},
            "aa:bb:cc",
            id="blank-normalized-key-fallback",
        ),
        pytest.param(
            {"mac": "  ", "mac-address": " \t"},
            "",
            id="both-keys-blank",
        ),
    ],
)
def test_get_arp_mac(entry: dict[str, Any], expected: str) -> None:
    """Read normalized and raw ARP MAC keys through one helper.

    Args:
        entry (dict[str, Any]): Registry or payload entry being formatted.
        expected (str): Outcome asserted by the parameterized scenario.
    """
    assert get_arp_mac(entry) == expected


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        pytest.param({"ip": " 192.0.2.1 "}, "192.0.2.1", id="normalized-key"),
        pytest.param({"ip-address": " 192.0.2.2 "}, "192.0.2.2", id="raw-key"),
        pytest.param({"ip": 1}, "", id="invalid-value"),
        pytest.param(
            {"ip": "  ", "ip-address": " 192.0.2.3 "},
            "192.0.2.3",
            id="blank-normalized-key-fallback",
        ),
        pytest.param(
            {"ip": " \t", "ip-address": "  "},
            "",
            id="both-keys-blank",
        ),
    ],
)
def test_get_arp_ip(entry: dict[str, Any], expected: str) -> None:
    """Read and strip normalized and raw ARP IP keys through one helper.

    Args:
        entry (dict[str, Any]): Registry or payload entry being formatted.
        expected (str): Outcome asserted by the parameterized scenario.
    """
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
    """Read SMART device identifiers from the shared helper.

    Args:
        entry (dict[str, Any]): Registry or payload entry being formatted.
        expected (str): Outcome asserted by the parameterized scenario.
    """
    assert get_smart_device_name(entry) == expected


@pytest.mark.parametrize(
    "value",
    [
        {"vhid": 1, "subnet": "192.0.2.1"},
        {"vhid": 255, "subnet": "192.0.2.255"},
        {"vhid": " 2 ", "subnet": " 192.0.2.2 "},
    ],
)
def test_is_usable_carp_vip_accepts_normalized_identity_without_interface(
    value: dict[str, Any],
) -> None:
    """CARP VIP usability should accept integer/string VHIDs without interface names.

    Args:
        value (dict[str, Any]): Input value exercised by the helper.
    """
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
        {"vhid": 0, "subnet": "192.0.2.1"},
        {"vhid": -1, "subnet": "192.0.2.1"},
        {"vhid": 256, "subnet": "192.0.2.1"},
        {"vhid": "not-a-vhid", "subnet": "192.0.2.1"},
    ],
)
def test_is_usable_carp_vip_rejects_missing_or_blank_identity(value: Any) -> None:
    """CARP VIP usability should reject malformed or blank identity rows.

    Args:
        value (Any): Input value exercised by the helper.
    """
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
    """Create OPNsense clients with the caller-specific session and client options.

    Args:
        monkeypatch (pytest.MonkeyPatch): pytest fixture used to replace dependencies.
        throw_errors (bool): Whether the created client should propagate API errors.
        name (str | None): Optional logging name assigned to the created client.
    """
    created: dict[str, Any] = {}
    session = MagicMock(spec=aiohttp.ClientSession)
    hass = MagicMock()

    def _async_create_clientsession(hass: Any, **_kwargs: Any) -> aiohttp.ClientSession:
        """Capture session construction options and return a fake session.

        Returns:
            aiohttp.ClientSession: aiohttp session supplied to client construction.

        Args:
            hass (Any): Home Assistant test instance used by the helper.
            _kwargs (Any): Additional keyword arguments accepted by the test double.
        """
        created["hass"] = hass
        created["session_kwargs"] = _kwargs
        return session

    def _client(**kwargs: Any) -> MagicMock:
        """Capture OPNsense client construction options and return a fake client.

        Args:
            kwargs (Any): Additional keyword arguments accepted by the test double.

        Returns:
            MagicMock: Mock client or dependency configured for the scenario.
        """
        created["client_kwargs"] = kwargs
        return MagicMock()

    class _CookieJar:
        """Fake aiohttp cookie jar that records its safety setting."""

        def __init__(self, *, unsafe: bool) -> None:
            """Capture the unsafe flag without requiring a running event loop.

            Args:
                unsafe (bool): Whether the fake cookie jar accepts unsafe origins.
            """
            created["cookie_jar_unsafe"] = unsafe

    monkeypatch.setattr(helpers_mod, "async_create_clientsession", _async_create_clientsession)
    monkeypatch.setattr(aiohttp, "CookieJar", _CookieJar)
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
    assert created["cookie_jar_unsafe"] is True
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
    """Create OPNsense clients from config entries through the shared helper.

    Args:
        monkeypatch (pytest.MonkeyPatch): pytest fixture used to replace dependencies.
        entry_data (dict[str, Any]): Configuration data used to create the client.
        throw_errors (bool): Whether the created client should propagate API errors.
        expected_verify_ssl (bool): TLS verification setting expected on the client.
    """
    captured: dict[str, Any] = {}
    hass = MagicMock()
    client = MagicMock()
    entry = MockConfigEntry(
        data=entry_data,
        title="router",
    )

    def _create_opnsense_client(**kwargs: Any) -> MagicMock:
        """Capture forwarded client settings.

        Args:
            kwargs (Any): Additional keyword arguments accepted by the test double.

        Returns:
            MagicMock: Mock client or dependency configured for the scenario.
        """
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
    """Read rule IDs from payload with fallback to the payload key when safe.

    Args:
        rule_key (object): Rule identifier rendered by the helper.
        rule (object): Firewall or NAT rule rendered by the helper.
        expected (str | None): Outcome asserted by the parameterized scenario.
    """
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
    """Validate config entry identity rules for device and CARP entries.

    Args:
        make_config_entry (Callable[..., MockConfigEntry]): Fixture that creates a mock configuration entry.
    """
    device_entry = make_config_entry(
        entry_id="device-entry",
        data={CONF_DEVICE_UNIQUE_ID: "aa_bb_cc_dd_ee_ff"},
    )
    carp_entry = make_config_entry(
        entry_id="carp-entry",
        data={
            CONF_ENTRY_TYPE: ENTRY_TYPE_CARP,
            CONF_DEVICE_UNIQUE_ID: "stale-device-id",
        },
    )
    blank_device_entry = make_config_entry(
        entry_id="blank-device-entry",
        data={CONF_DEVICE_UNIQUE_ID: "  \t"},
    )
    padded_device_entry = make_config_entry(
        entry_id="padded-device-entry",
        data={CONF_DEVICE_UNIQUE_ID: "  padded-device-id  "},
    )

    assert is_carp_entry(device_entry) is False
    assert config_entry_identity(device_entry) == "aa_bb_cc_dd_ee_ff"
    assert is_carp_entry(carp_entry) is True
    assert config_entry_identity(carp_entry) == "carp-entry"
    assert config_entry_identity(blank_device_entry) == "blank-device-entry"
    assert config_entry_identity(padded_device_entry) == "padded-device-id"
