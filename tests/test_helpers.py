"""Unit tests for shared OPNsense integration helpers."""

from typing import Any

import pytest

from custom_components.opnsense.helpers import coerce_bool


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
