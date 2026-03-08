"""Tests for `pyopnsense.unbound`."""

from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

from custom_components.opnsense import pyopnsense


@pytest.mark.asyncio
async def test_enable_disable_unbound_with_uuid(make_client) -> None:
    """Test enabling/disabling extended unbound blocklists with a UUID."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    # simulate firmware >= 25.7.8 so extended API is used
    client._firmware_version = "25.7.8"

    # toggling endpoint responds with Enabled/Disabled; service status also required
    client._safe_dict_post = AsyncMock(return_value={"result": "Enabled"})
    client._get = AsyncMock(return_value={"status": "OK"})
    res_on = await client.enable_unbound_blocklist("uuid1")
    assert res_on is True

    client._safe_dict_post = AsyncMock(return_value={"result": "Disabled"})
    client._get = AsyncMock(return_value={"status": "OK"})
    res_off = await client.disable_unbound_blocklist("uuid1")
    assert res_off is True

    await client.async_close()


@pytest.mark.asyncio
async def test_get_unbound_blocklist_firmware_fetch(make_client) -> None:
    """Test get_unbound_blocklist fetches firmware when None."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    # Ensure firmware is None initially
    client._firmware_version = None
    client.get_host_firmware_version = AsyncMock(return_value="25.7.8")
    client._safe_dict_get = AsyncMock(
        return_value={"rows": [{"uuid": "test-uuid", "enabled": "1"}]}
    )

    result = await client.get_unbound_blocklist()
    assert "test-uuid" in result
    client.get_host_firmware_version.assert_called_once()
    await client.async_close()


@pytest.mark.parametrize(
    "firmware_version,expected_legacy_call,expected_result",
    [
        ("25.1.0", True, {"legacy": {"legacy": "data"}}),  # Legacy path
        (
            "25.7.8",
            False,
            {
                "uuid1": {"uuid": "uuid1", "enabled": "1", "name": "blocklist1"},
                "uuid2": {"uuid": "uuid2", "enabled": "0", "name": "blocklist2"},
            },
        ),  # Extended path
    ],
)
@pytest.mark.asyncio
async def test_get_unbound_blocklist_version_paths(
    firmware_version, expected_legacy_call, expected_result, make_client
) -> None:
    """Test get_unbound_blocklist version-dependent behavior."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    client._firmware_version = firmware_version

    if expected_legacy_call:
        client.get_unbound_blocklist_legacy = AsyncMock(return_value={"legacy": "data"})
    else:
        client._safe_dict_get = AsyncMock(
            return_value={
                "rows": [
                    {"uuid": "uuid1", "enabled": "1", "name": "blocklist1"},
                    {"uuid": "uuid2", "enabled": "0", "name": "blocklist2"},
                    {"no_uuid": "invalid"},  # Should be skipped
                ]
            }
        )

    result = await client.get_unbound_blocklist()
    assert result == expected_result

    if expected_legacy_call:
        client.get_unbound_blocklist_legacy.assert_called_once()
    await client.async_close()


@pytest.mark.parametrize(
    "api_response,expected_result",
    [
        ({}, {}),  # Empty response
        ({"rows": []}, {}),  # Empty rows
        (
            {"rows": [{"uuid": "test", "enabled": "1"}]},
            {"test": {"uuid": "test", "enabled": "1"}},
        ),  # Valid data
    ],
)
@pytest.mark.asyncio
async def test_get_unbound_blocklist_extended_responses(
    api_response, expected_result, make_client
) -> None:
    """Test get_unbound_blocklist handles various extended API responses."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    client._firmware_version = "25.7.8"
    client._safe_dict_get = AsyncMock(return_value=api_response)

    result = await client.get_unbound_blocklist()
    assert result == expected_result
    await client.async_close()


@pytest.mark.asyncio
async def test_get_unbound_blocklist_version_comparison_error(make_client) -> None:
    """Test get_unbound_blocklist handles version comparison errors."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    client._firmware_version = "invalid.version"
    client._safe_dict_get = AsyncMock(return_value={"rows": [{"uuid": "test", "enabled": "1"}]})

    result = await client.get_unbound_blocklist()
    assert "test" in result
    await client.async_close()


@pytest.mark.parametrize(
    "method_name",
    ["enable_unbound_blocklist", "disable_unbound_blocklist"],
)
@pytest.mark.asyncio
async def test_enable_disable_unbound_firmware_fetch(method_name, make_client) -> None:
    """Test enable/disable_unbound_blocklist fetch firmware when None."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    client._firmware_version = None
    client.get_host_firmware_version = AsyncMock(return_value="25.7.8")
    client._safe_dict_post = AsyncMock(
        return_value={
            "result": "Enabled" if method_name == "enable_unbound_blocklist" else "Disabled"
        }
    )
    # new behaviour requires service status check after toggle
    client._get = AsyncMock(return_value={"status": "OK"})

    method = getattr(client, method_name)
    result = await method("test-uuid")
    assert result is True
    client.get_host_firmware_version.assert_called_once()
    await client.async_close()


@pytest.mark.parametrize(
    "method_name,set_state",
    [
        ("enable_unbound_blocklist", True),
        ("disable_unbound_blocklist", False),
    ],
)
@pytest.mark.asyncio
async def test_enable_disable_unbound_legacy_fallback(method_name, set_state, make_client) -> None:
    """Test enable/disable_unbound_blocklist fallback to legacy on version error."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    client._firmware_version = "invalid.version"
    client._set_unbound_blocklist_legacy = AsyncMock(return_value=True)

    method = getattr(client, method_name)
    result = await method()
    assert result is True
    client._set_unbound_blocklist_legacy.assert_called_once_with(set_state=set_state)
    await client.async_close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "blocklist_return, post_side_effects, get_return, expected",
    [
        ({}, None, None, False),
        ({"enabled": "0"}, [{"result": "saved"}, {"response": "OK"}], {"status": "OK"}, True),
    ],
)
async def test_set_unbound_blocklist_legacy_scenarios(
    blocklist_return, post_side_effects, get_return, expected
) -> None:
    """Parametrized _set_unbound_blocklist_legacy scenarios: empty and full success."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        client.get_unbound_blocklist_legacy = AsyncMock(return_value=blocklist_return)

        if not expected:
            assert await client._set_unbound_blocklist_legacy(True) is False
            return

        # success path: arrange the sequence of network calls
        client._post = AsyncMock(side_effect=post_side_effects)
        client._get = AsyncMock(return_value=get_return)
        assert await client._set_unbound_blocklist_legacy(True) is True
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_toggle_unbound_blocklist_success_and_errors() -> None:
    """Ensure _toggle_unbound_blocklist returns True on happy path and handles expected errors.

    The helper performs a follow‑up GET/POST after toggling.  Network issues or
    malformed responses should be caught and simply result in False; we expect
    aiohttp.ClientError, asyncio.TimeoutError, ValueError and TypeError to be
    the common failure modes.
    """
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        # happy path — toggle endpoint succeeded and service reports OK
        client._safe_dict_post = AsyncMock(return_value={"result": "Enabled"})
        client._get = AsyncMock(return_value={"status": "OK"})
        assert await client._toggle_unbound_blocklist(True, "uuid") is True

        # client error on dnsbl GET should be swallowed and return False
        client._get = AsyncMock(side_effect=aiohttp.ClientError("boom"))
        assert await client._toggle_unbound_blocklist(True, "uuid") is False

        # timeout while fetching service status should also be swallowed
        client._get = AsyncMock(side_effect=TimeoutError())
        assert await client._toggle_unbound_blocklist(True, "uuid") is False

        # malformed response raising ValueError
        client._get = AsyncMock(side_effect=ValueError("bad json"))
        assert await client._toggle_unbound_blocklist(True, "uuid") is False

        # type error from unexpected response structures
        client._get = AsyncMock(side_effect=TypeError("not mapping"))
        assert await client._toggle_unbound_blocklist(True, "uuid") is False
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_unbound_blocklist_legacy_parsing() -> None:
    """Ensure get_unbound_blocklist_legacy properly extracts and joins nested mappings."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        dnsbl = {
            "unbound": {
                "dnsbl": {
                    "enabled": "1",
                    "type": {"t": {"selected": 1}},
                    "lists": {"a": {"selected": 1}, "b": {"selected": 0}},
                    "whitelists": {},
                    "blocklists": {"x": {"selected": 1}},
                    "wildcards": {},
                }
            }
        }

        client._safe_dict_get = AsyncMock(return_value=dnsbl)
        parsed = await client.get_unbound_blocklist_legacy()
        assert parsed.get("enabled") == "1"
        assert parsed.get("lists") == "a"
        assert parsed.get("blocklists") == "x"
    finally:
        await client.async_close()
