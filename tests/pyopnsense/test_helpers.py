"""Tests for `pyopnsense.helpers` utility and decorator helpers."""

import asyncio
from datetime import UTC, datetime
from typing import Any, Never
from unittest.mock import MagicMock

import aiohttp
import pytest

from custom_components.opnsense import pyopnsense
from custom_components.opnsense.pyopnsense import helpers as pyopnsense_helpers

TEST_PASSWORD = "p"


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [
        pytest.param(0, "0 seconds", id="zero"),
        pytest.param(1, "1 second", id="singular-second"),
        pytest.param(2, "2 seconds", id="plural-seconds"),
        pytest.param(60, "1 minute", id="singular-minute"),
        pytest.param(61, "1 minute, 1 second", id="minute-and-second"),
        pytest.param(65, "1 minute, 5 seconds", id="minute-and-seconds"),
        pytest.param(3600, "1 hour", id="singular-hour"),
        pytest.param(7200, "2 hours", id="plural-hours"),
        pytest.param(86400, "1 day", id="singular-day"),
        pytest.param(604800, "1 week", id="singular-week"),
        pytest.param(1209600, "2 weeks", id="plural-weeks"),
        pytest.param(2419200, "1 month", id="singular-month"),
        pytest.param(4838400, "2 months", id="plural-months"),
    ],
)
def test_human_friendly_duration(seconds: int, expected: str) -> None:
    """Convert seconds into human-friendly duration strings."""
    assert pyopnsense_helpers.human_friendly_duration(seconds) == expected


@pytest.mark.parametrize(
    ("item", "expected_type", "expected"),
    [
        pytest.param({"address": "192.168.1.1"}, 0, None, id="ipv4"),
        pytest.param({"address": "::1"}, 1, None, id="ipv6"),
        pytest.param({"address": "notanip"}, 2, (2, ""), id="invalid"),
        pytest.param({}, 3, (3, ""), id="missing"),
    ],
)
def test_get_ip_key(
    item: dict[str, str], expected_type: int, expected: tuple[int, str] | None
) -> None:
    """Compute sorting key for IP addresses across IPv4, IPv6, and invalid forms."""
    key = pyopnsense_helpers.get_ip_key(item)
    assert key[0] == expected_type
    if expected is not None:
        assert key == expected


def test_dict_get() -> None:
    """Retrieve nested values from dicts and lists using dotted paths."""
    data = {"a": {"b": {"c": 1}}, "x": [0, 1, 2]}
    assert pyopnsense_helpers.dict_get(data, "a.b.c") == 1
    assert pyopnsense_helpers.dict_get(data, "x.1") == 1
    assert pyopnsense_helpers.dict_get(data, "x.10", default=42) == 42
    assert pyopnsense_helpers.dict_get({"a": {"b": [10, {"c": 3}]}}, "a.b") == [10, {"c": 3}]
    assert pyopnsense_helpers.dict_get(data, "missing.path", default=5) == 5


def test_timestamp_to_datetime() -> None:
    """Convert timestamp integers to datetime objects, handling None."""
    ts = int(datetime.now(UTC).timestamp())
    dt = pyopnsense_helpers.timestamp_to_datetime(ts)
    assert isinstance(dt, datetime)
    assert dt.tzinfo is not None
    assert pyopnsense_helpers.timestamp_to_datetime(None) is None


@pytest.mark.parametrize(
    ("value", "default", "expected"),
    [
        pytest.param("5", 0, 5, id="numeric-string"),
        pytest.param(None, 7, 7, id="none-default"),
    ],
)
def test_try_to_int(value: object, default: int, expected: int) -> None:
    """Coerce numeric-like values to integers with defaults."""
    assert pyopnsense_helpers.try_to_int(value, default) == expected


@pytest.mark.parametrize(
    ("value", "default", "expected"),
    [
        pytest.param("5.5", 0.0, 5.5, id="numeric-string"),
        pytest.param(None, 3.3, 3.3, id="none-default"),
    ],
)
def test_try_to_float(value: object, default: float, expected: float) -> None:
    """Coerce numeric-like values to floats with defaults."""
    assert pyopnsense_helpers.try_to_float(value, default) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(True, True, id="true"),
        pytest.param(False, False, id="false"),
        pytest.param(1, True, id="int-one"),
        pytest.param(0, False, id="int-zero"),
        pytest.param(0.0, False, id="float-zero"),
        pytest.param("1", True, id="string-one"),
        pytest.param("true", True, id="string-true"),
        pytest.param("yes", True, id="string-yes"),
        pytest.param("on", True, id="string-on"),
        pytest.param("", False, id="empty-string"),
        pytest.param(None, False, id="none"),
    ],
)
def test_coerce_bool(value: object, expected: bool) -> None:
    """Verify ``coerce_bool`` handles common bool-like edge cases."""
    assert pyopnsense_helpers.coerce_bool(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param("Hello", "hello", id="lowercase"),
        pytest.param("  WORLD  ", "world", id="strip"),
        pytest.param(42, "42", id="coerce-int"),
        pytest.param(None, "", id="none"),
    ],
)
def test_normalize_lookup_token(value: object, expected: str) -> None:
    """Verify ``normalize_lookup_token`` lower-cases and trims lookup values."""
    assert pyopnsense_helpers.normalize_lookup_token(value) == expected


def test_get_ip_key_sorting() -> None:
    """Sort IP-like items using get_ip_key ordering."""
    items = [
        {"address": "192.168.1.2"},
        {"address": "::1"},
        {"address": "notanip"},
        {},
    ]
    sorted_items = sorted(items, key=pyopnsense_helpers.get_ip_key)
    assert sorted_items[0]["address"] == "192.168.1.2"
    assert sorted_items[1]["address"] == "::1"
    assert sorted_items[2]["address"] == "notanip"
    assert sorted_items[3] == {}


@pytest.mark.asyncio
async def test_log_errors_decorator_re_raise_and_suppress() -> None:
    """The _log_errors decorator should re-raise when self._initial is True, otherwise suppress."""

    class Dummy:
        def __init__(self, initial: bool) -> None:
            """Initialize Dummy."""
            self._initial = initial

        @pyopnsense_helpers._log_errors
        async def boom(self) -> None:
            """Raise a runtime error so `_log_errors` can be exercised.

            Raises:
                RuntimeError: Always raised to test generic exception handling.
            """
            raise RuntimeError("boom")

    # When not initial, errors are logged and suppressed (function returns None)
    d = Dummy(initial=False)
    res = await d.boom()
    assert res is None

    # When initial, errors are re-raised
    d2 = Dummy(initial=True)
    with pytest.raises(RuntimeError):
        await d2.boom()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exception",
    [
        pytest.param(TimeoutError("boom"), id="timeout"),
        pytest.param(aiohttp.ServerTimeoutError("srv"), id="server-timeout"),
    ],
)
async def test_log_errors_timeout_re_raise_and_suppress(exception: Exception) -> None:
    """_log_errors should re-raise timeouts when initial and suppress them otherwise."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://x", username="u", password=TEST_PASSWORD, session=session
    )
    try:

        async def raising_timeout(*args, **kwargs) -> Never:
            """Raise ``TimeoutError`` so the timeout branch of `_log_errors` runs.

            Args:
                *args: Additional positional arguments forwarded by the function.
                **kwargs: Additional keyword arguments forwarded by the function.

            Raises:
                Exception: Always raised to test timeout suppression and re-raise behavior.
            """
            raise exception

        # wrap the coroutine with the decorator
        decorated = pyopnsense_helpers._log_errors(raising_timeout)

        # When initial is True we expect the TimeoutError to propagate
        client._initial = True
        with pytest.raises(type(exception)):
            await decorated(client)

        # When initial is False the decorator should suppress TimeoutError and return None
        client._initial = False
        res = await decorated(client)
        assert res is None
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_xmlrpc_timeout_uses_per_call_asyncio_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_xmlrpc_timeout should use asyncio.wait_for with DEFAULT_REQUEST_TIMEOUT_SECONDS."""
    monkeypatch.setattr(pyopnsense_helpers, "DEFAULT_REQUEST_TIMEOUT_SECONDS", 0.01)

    @pyopnsense_helpers._xmlrpc_timeout
    async def fast_func(self: Any) -> str:
        """Fast func."""
        return "ok"

    got = await fast_func(None)
    assert got == "ok"

    @pyopnsense_helpers._xmlrpc_timeout
    async def slow_func(self: Any) -> str:
        """Slow func."""
        await asyncio.sleep(0.05)
        return "late"

    with pytest.raises(TimeoutError):
        await slow_func(None)
