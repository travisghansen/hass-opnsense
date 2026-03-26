"""Tests for `pyopnsense.firewall`."""

from collections.abc import MutableMapping
import copy
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

from custom_components.opnsense import pyopnsense


@pytest.fixture
def toggle_alias_client(make_client):
    """Provide a preconfigured OPNsenseClient for toggle_alias tests."""
    session = MagicMock(spec=aiohttp.ClientSession)
    return make_client(session=session)


@pytest.mark.asyncio
async def test_enable_and_disable_filter_rules_and_nat_port_forward(make_client) -> None:
    """Cover enabling/disabling filter rules and NAT port forward rule flows."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        # enable_filter_rule_by_created_time_legacy: rule has 'disabled' -> should remove and call restore+configure
        cfg_enable = {"filter": {"rule": [{"created": {"time": "t-enable"}, "disabled": "1"}]}}
        client.get_config = AsyncMock(return_value=cfg_enable)
        client._restore_config_section = AsyncMock()
        client._filter_configure = AsyncMock()
        await client.enable_filter_rule_by_created_time_legacy("t-enable")
        client._restore_config_section.assert_awaited()
        client._filter_configure.assert_awaited()

        # disable_filter_rule_by_created_time_legacy: rule missing 'disabled' -> should add it and call restore+configure
        cfg_disable = {"filter": {"rule": [{"created": {"time": "t-disable"}}]}}
        client.get_config = AsyncMock(return_value=cfg_disable)
        client._restore_config_section = AsyncMock()
        client._filter_configure = AsyncMock()
        await client.disable_filter_rule_by_created_time_legacy("t-disable")
        client._restore_config_section.assert_awaited()
        client._filter_configure.assert_awaited()

        # enable_nat_port_forward_rule_by_created_time_legacy: similar flow under 'nat' section
        cfg_nat = {"nat": {"rule": [{"created": {"time": "t-nat"}, "disabled": "1"}]}}
        client.get_config = AsyncMock(return_value=cfg_nat)
        client._restore_config_section = AsyncMock()
        client._filter_configure = AsyncMock()
        await client.enable_nat_port_forward_rule_by_created_time_legacy("t-nat")
        client._restore_config_section.assert_awaited()
        client._filter_configure.assert_awaited()
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_toggle_alias_flows(make_client) -> None:
    """toggle_alias returns False when not found or when subsequent calls fail; True on full success."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        # alias not found
        client._use_snake_case = True
        client._safe_dict_get = AsyncMock(return_value={"rows": []})
        assert await client.toggle_alias("nope", "on") is False

        # alias found but toggle fails
        client._safe_dict_get = AsyncMock(
            return_value={"rows": [{"name": "myalias", "uuid": "aid"}]}
        )
        client._safe_dict_post = AsyncMock(return_value={"result": "failed"})
        assert await client.toggle_alias("myalias", "on") is False

        # full success path
        client._safe_dict_get = AsyncMock(
            return_value={"rows": [{"name": "myalias", "uuid": "aid"}]}
        )
        client._safe_dict_post = AsyncMock(
            side_effect=[{"result": "ok"}, {"result": "saved"}, {"status": "ok"}]
        )
        assert await client.toggle_alias("myalias", "on") is True
    finally:
        await client.async_close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "safe_get_rows, safe_post_result, expected",
    [
        ([], None, False),
        ([{"name": "a", "uuid": "u1"}], {"result": "failed"}, False),
        (
            [{"name": "a", "uuid": "u1"}],
            [{"result": "ok"}, {"result": "saved"}, {"status": "ok"}],
            True,
        ),
    ],
)
async def test_toggle_alias_scenarios(
    safe_get_rows, safe_post_result, expected, toggle_alias_client
) -> None:
    """Parametrized toggle_alias scenarios: not found, failed toggle, and full success."""
    client = toggle_alias_client
    try:
        client._safe_dict_get = AsyncMock(return_value={"rows": safe_get_rows})

        # alias not found path expects immediate False
        if not safe_get_rows:
            assert await client.toggle_alias("nope", "on") is expected
            return

        # when rows are present, set up _safe_dict_post appropriately
        if isinstance(safe_post_result, list):
            client._safe_dict_post = AsyncMock(side_effect=safe_post_result)
        else:
            client._safe_dict_post = AsyncMock(return_value=safe_post_result)

        assert await client.toggle_alias("a", "on") is expected
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_config_and_rule_enable_disable_branches() -> None:
    """Exercise get_config and enable/disable filter/nat rule flows."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        # _exec_php returns a mapping with 'data' containing filter and nat rules
        fake_config = {
            "data": {
                "filter": {"rule": [{"created": {"time": "t1"}, "disabled": "1"}]},
                "nat": {"rule": [{"created": {"time": "n1"}}], "outbound": {"rule": []}},
            }
        }

        client._exec_php = AsyncMock(return_value=fake_config)
        client._restore_config_section = AsyncMock()
        client._filter_configure = AsyncMock()
        # calling enable should remove 'disabled' and call restore/configure (no exception)
        await client.enable_filter_rule_by_created_time_legacy("t1")
        client._restore_config_section.assert_awaited()
        client._filter_configure.assert_awaited()

        # disable_nat_port_forward: add a rule without 'disabled' and expect it to set 'disabled'
        client._exec_php = AsyncMock(
            return_value={"data": {"nat": {"rule": [{"created": {"time": "n1"}}]}}}
        )
        # patch _restore_config_section and _filter_configure to be no-ops
        client._restore_config_section = AsyncMock()
        client._filter_configure = AsyncMock()
        await client.disable_nat_port_forward_rule_by_created_time_legacy("n1")
        client._exec_php.assert_awaited()
        client._restore_config_section.assert_awaited_once()
        client._filter_configure.assert_awaited_once()
        restore_args = client._restore_config_section.await_args.args
        assert restore_args[0] == "nat"
        nat_section = restore_args[1]
        assert nat_section["rule"][0]["created"]["time"] == "n1"
        assert nat_section["rule"][0]["disabled"] == "1"
    finally:
        await client.async_close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rules,created_time,should_call",
    [
        # matching rule with disabled -> should call restore/configure and remove 'disabled'
        ([{"created": {"time": "t1"}, "disabled": "1"}], "t1", True),
        # matching rule without disabled -> no restore/configure
        ([{"created": {"time": "t1"}}], "t1", False),
        # missing 'created' key -> skipped
        ([{"foo": "bar"}], "t1", False),
        # created present but missing 'time' -> skipped
        ([{"created": {}}], "t1", False),
        # time doesn't match -> skipped
        ([{"created": {"time": "t2"}, "disabled": "1"}], "t1", False),
        # multiple rules, one matches and is disabled -> should call once
        (
            [
                {"created": {"time": "a"}},
                {"created": {"time": "match"}, "disabled": "1"},
                {"created": {"time": "b"}, "disabled": "1"},
            ],
            "match",
            True,
        ),
    ],
)
async def test_enable_filter_rule_by_created_time_legacy(
    make_client, rules, created_time, should_call
) -> None:
    """Ensure enabling a filter rule removes 'disabled' and triggers restore/configure only when appropriate. Parameterized to exercise matching and non-matching branches."""

    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        config = {"filter": {"rule": [dict(r) for r in rules]}}
        client.get_config = AsyncMock(return_value=config)
        client._restore_config_section = AsyncMock()
        client._filter_configure = AsyncMock()

        await client.enable_filter_rule_by_created_time_legacy(created_time)

        if should_call:
            client._restore_config_section.assert_awaited()
            client._filter_configure.assert_awaited()
            # Inspect what was passed to _restore_config_section and ensure 'disabled' removed
            called = client._restore_config_section.await_args.args
            # first arg should be 'filter'
            assert called[0] == "filter"
            # second arg is the filter section; ensure the matching rule no longer has 'disabled'
            filter_section = called[1]
            assert isinstance(filter_section, MutableMapping)
            # find the matching rule inside the passed filter section
            rules_passed = filter_section.get("rule", [])
            matched = [r for r in rules_passed if r.get("created", {}).get("time") == created_time]
            assert matched
            for m in matched:
                assert "disabled" not in m
        else:
            client._restore_config_section.assert_not_awaited()
            client._filter_configure.assert_not_awaited()
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_enable_disable_nat_outbound_rules(make_client) -> None:
    """Cover enable/disable NAT outbound rule flows."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        # Enable: rule has disabled flag -> should remove and call helpers
        cfg_enable = {"nat": {"outbound": {"rule": [{"created": {"time": "t1"}, "disabled": "1"}]}}}
        client.get_config = AsyncMock(return_value=cfg_enable)
        client._restore_config_section = AsyncMock()
        client._filter_configure = AsyncMock()
        await client.enable_nat_outbound_rule_by_created_time_legacy("t1")
        client._restore_config_section.assert_awaited()
        client._filter_configure.assert_awaited()

        # Disable: rule missing disabled -> should add and call helpers
        cfg_disable = {"nat": {"outbound": {"rule": [{"created": {"time": "t2"}}]}}}
        client.get_config = AsyncMock(return_value=cfg_disable)
        client._restore_config_section = AsyncMock()
        client._filter_configure = AsyncMock()
        await client.disable_nat_outbound_rule_by_created_time_legacy("t2")
        client._restore_config_section.assert_awaited()
        client._filter_configure.assert_awaited()
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_firewall_legacy_fallback(make_client) -> None:
    """get_firewall falls back to legacy config for OPNsense < 26.1.1."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client._firmware_version = "25.7.0"

        # Mock get_config for legacy fallback
        client.get_config = AsyncMock(return_value={"filter": {"rule": []}})

        result = await client.get_firewall()
        assert result == {"config": {"filter": {"rule": []}}}
        client.get_config.assert_awaited_once()
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_firewall_new_api(make_client) -> None:
    """get_firewall uses new API for OPNsense >= 26.1.1."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client._firmware_version = "26.1.1"

        # Mock all the methods called in the new API path
        client.is_plugin_installed = AsyncMock(return_value=True)
        client.get_config = AsyncMock(return_value={"filter": {"rule": []}})
        client._get_firewall_rules = AsyncMock(return_value={"rule1": {"uuid": "rule1"}})
        client._get_nat_destination_rules = AsyncMock(return_value={"nat1": {"uuid": "nat1"}})
        client._get_nat_one_to_one_rules = AsyncMock(return_value={"one1": {"uuid": "one1"}})
        client._get_nat_source_rules = AsyncMock(return_value={"src1": {"uuid": "src1"}})
        client._get_nat_npt_rules = AsyncMock(return_value={"npt1": {"uuid": "npt1"}})

        result = await client.get_firewall()
        expected = {
            "config": {"filter": {"rule": []}},
            "rules": {"rule1": {"uuid": "rule1"}},
            "nat": {
                "d_nat": {"nat1": {"uuid": "nat1"}},
                "one_to_one": {"one1": {"uuid": "one1"}},
                "source_nat": {"src1": {"uuid": "src1"}},
                "npt": {"npt1": {"uuid": "npt1"}},
            },
        }
        assert result == expected
        client.is_plugin_installed.assert_awaited_once()
        client.get_config.assert_awaited_once()
        client._get_firewall_rules.assert_awaited_once()
        client._get_nat_destination_rules.assert_awaited_once()
        client._get_nat_one_to_one_rules.assert_awaited_once()
        client._get_nat_source_rules.assert_awaited_once()
        client._get_nat_npt_rules.assert_awaited_once()
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_firewall_new_api_plugin_not_installed(make_client) -> None:
    """get_firewall uses new API for OPNsense >= 26.1.1 but when plugin not installed it should skip config."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client._firmware_version = "26.1.1"

        # Plugin not installed: shouldn't call get_config
        client.is_plugin_installed = AsyncMock(return_value=False)
        client.get_config = AsyncMock(return_value={"filter": {"rule": []}})
        client._get_firewall_rules = AsyncMock(return_value={"rule1": {"uuid": "rule1"}})
        client._get_nat_destination_rules = AsyncMock(return_value={"nat1": {"uuid": "nat1"}})
        client._get_nat_one_to_one_rules = AsyncMock(return_value={"one1": {"uuid": "one1"}})
        client._get_nat_source_rules = AsyncMock(return_value={"src1": {"uuid": "src1"}})
        client._get_nat_npt_rules = AsyncMock(return_value={"npt1": {"uuid": "npt1"}})

        result = await client.get_firewall()
        expected = {
            "rules": {"rule1": {"uuid": "rule1"}},
            "nat": {
                "d_nat": {"nat1": {"uuid": "nat1"}},
                "one_to_one": {"one1": {"uuid": "one1"}},
                "source_nat": {"src1": {"uuid": "src1"}},
                "npt": {"npt1": {"uuid": "npt1"}},
            },
        }
        assert result == expected
        client.is_plugin_installed.assert_awaited_once()
        client.get_config.assert_not_awaited()
        client._get_firewall_rules.assert_awaited_once()
        client._get_nat_destination_rules.assert_awaited_once()
        client._get_nat_one_to_one_rules.assert_awaited_once()
        client._get_nat_source_rules.assert_awaited_once()
        client._get_nat_npt_rules.assert_awaited_once()
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_firewall_version_compare_exception(make_client) -> None:
    """get_firewall handles AwesomeVersionCompareException gracefully."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client._firmware_version = "invalid"

        result = await client.get_firewall()
        assert result == {}
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_firewall_rules_successful_parsing(make_client) -> None:
    """_get_firewall_rules successfully parses rows returned from the REST API."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        rows = [
            {
                "uuid": "rule1",
                "enabled": "1",
                "action": "pass",
                "interface": "lan",
                "descr": "Allow HTTP",
            },
            {
                "uuid": "rule2",
                "enabled": "0",
                "action": "block",
                "interface": "wan",
                "descr": "Block traffic",
            },
        ]

        client._safe_dict_post = AsyncMock(return_value={"rows": rows})

        result = await client._get_firewall_rules()

        expected = {r["uuid"]: r.copy() for r in rows}
        assert result == expected
        client._safe_dict_post.assert_awaited_once_with(
            "/api/firewall/filter/search_rule", payload={"current": 1, "sort": {}}
        )
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_firewall_rules_empty_response(make_client) -> None:
    """_get_firewall_rules returns empty dict when API response has no rows."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client._safe_dict_post = AsyncMock(return_value={})

        result = await client._get_firewall_rules()
        assert result == {}
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_firewall_rules_skips_invalid_rows(make_client) -> None:
    """_get_firewall_rules skips rules without uuid and lockout rules."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        rows = [
            "bad-row",
            None,
            {"enabled": "1", "action": "pass"},  # missing uuid
            {"uuid": "lockout-1", "enabled": "1"},  # lockout rule
            {"uuid": "rule-ok", "enabled": "1"},  # valid
        ]

        client._safe_dict_post = AsyncMock(return_value={"rows": rows})

        result = await client._get_firewall_rules()
        assert list(result.keys()) == ["rule-ok"]
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_nat_rule_helpers_skip_non_mapping_rows(make_client) -> None:
    """NAT rule helpers should skip malformed non-mapping rows safely."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        methods = (
            "_get_nat_destination_rules",
            "_get_nat_one_to_one_rules",
            "_get_nat_source_rules",
            "_get_nat_npt_rules",
        )
        for method_name in methods:
            rows: list[Any] = ["bad-row", None, {"uuid": "rule-ok", "descr": "d", "disabled": "0"}]
            client._safe_dict_post = AsyncMock(return_value={"rows": rows})
            method = getattr(client, method_name)
            result = await method()
            assert list(result.keys()) == ["rule-ok"]
    finally:
        await client.async_close()


@pytest.mark.parametrize(
    ("method_name", "api_endpoint", "has_transformations"),
    [
        ("_get_nat_destination_rules", "/api/firewall/d_nat/search_rule", True),
        ("_get_nat_one_to_one_rules", "/api/firewall/one_to_one/search_rule", False),
        ("_get_nat_source_rules", "/api/firewall/source_nat/search_rule", False),
        ("_get_nat_npt_rules", "/api/firewall/npt/search_rule", False),
    ],
)
@pytest.mark.parametrize(
    ("test_case", "expected_result"),
    [
        (
            "successful_parsing",
            {
                "test-rule-1": {
                    "uuid": "test-rule-1",
                    "description": "Test rule 1",
                    "enabled": "1",
                    "interface": "wan",
                    "protocol": "tcp",
                },
                "test-rule-2": {
                    "uuid": "test-rule-2",
                    "description": "Test rule 2",
                    "enabled": "0",
                    "interface": "lan",
                    "protocol": "udp",
                },
            },
        ),
        (
            "filters_lockout_rules",
            {
                "normal-rule": {
                    "uuid": "normal-rule",
                    "description": "Normal rule",
                    "enabled": "1",
                }
            },
        ),
        ("empty_response", {}),
        ("response_without_rows", {}),
    ],
)
@pytest.mark.asyncio
async def test_nat_rules_parsing(
    make_client,
    method_name,
    api_endpoint,
    has_transformations,
    test_case,
    expected_result,
) -> None:
    """Test NAT rules parsing for all NAT rule types."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        # Build API-style mock response depending on whether the endpoint uses
        # transformations (d_nat-like endpoints use 'descr'/'disabled').
        mock_response: dict[str, Any]
        if test_case == "empty_response":
            mock_response = {}
        elif test_case == "response_without_rows":
            mock_response = {"some_other_key": "value"}
        else:
            normalized_rows: list[dict[str, Any]] = []
            extra_rows: list[dict[str, Any]] = []
            if test_case == "successful_parsing":
                for uid, info in expected_result.items():
                    row = {"uuid": uid}
                    row["description"] = info.get("description")
                    row["enabled"] = info.get("enabled")
                    if "interface" in info:
                        row["interface"] = info.get("interface")
                    if "protocol" in info:
                        row["protocol"] = info.get("protocol")
                    normalized_rows.append(row)
            elif test_case == "filters_lockout_rules":
                normalized_rows = [
                    {"uuid": "normal-rule", "description": "Normal rule", "enabled": "1"}
                ]
                extra_rows = [
                    {"uuid": "lockout-rule", "description": "Lockout rule", "enabled": "1"},
                    {"uuid": "another-lockout", "description": "Another lockout", "enabled": "1"},
                    {"uuid": None, "description": "No UUID rule", "enabled": "1"},
                ]

            api_rows: list[dict[str, Any]] = []
            for row in normalized_rows + extra_rows:
                if has_transformations:
                    new_row = row.copy()
                    if "description" in new_row:
                        new_row["descr"] = new_row.pop("description")
                    if "enabled" in new_row:
                        new_row["disabled"] = "0" if new_row.pop("enabled") == "1" else "1"
                    api_rows.append(new_row)
                else:
                    api_rows.append(row.copy())

            mock_response = {"rows": api_rows}

        client._safe_dict_post = AsyncMock(return_value=mock_response)

        # Call the appropriate method
        method = getattr(client, method_name)
        result = await method()

        # Make a deep copy of expected_result so we don't mutate the shared fixture
        expected = copy.deepcopy(expected_result)

        assert result == expected

        # Verify the correct API endpoint was called
        client._safe_dict_post.assert_awaited_once_with(
            api_endpoint, payload={"current": 1, "sort": {}}
        )
    finally:
        await client.async_close()
