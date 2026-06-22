"""Unit tests for shared OPNsense integration helpers."""

from typing import Any
from unittest.mock import MagicMock

import aiohttp
import pytest

from custom_components.opnsense import helpers as helpers_mod
from custom_components.opnsense.helpers import coerce_bool, create_opnsense_client


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

    def _async_create_clientsession(**kwargs: Any) -> aiohttp.ClientSession:
        """Capture session construction options and return a fake session."""
        created["session_kwargs"] = kwargs
        return session

    def _client(**kwargs: Any) -> MagicMock:
        """Capture OPNsense client construction options and return a fake client."""
        created["client_kwargs"] = kwargs
        return MagicMock()

    class _CookieJar:
        def __init__(self, *, unsafe: bool) -> None:
            """Capture the unsafe flag without requiring a running event loop."""
            self._unsafe = unsafe

    monkeypatch.setattr(helpers_mod, "async_create_clientsession", _async_create_clientsession)
    monkeypatch.setattr(helpers_mod.aiohttp, "CookieJar", _CookieJar)
    monkeypatch.setattr(helpers_mod, "OPNsenseClient", _client)

    password = "pass"
    client = create_opnsense_client(
        hass=MagicMock(),
        url="http://10.0.0.1",
        username="user",
        password=password,
        verify_ssl=False,
        throw_errors=throw_errors,
        name=name,
    )

    assert isinstance(client, MagicMock)
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
