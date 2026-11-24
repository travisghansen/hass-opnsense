"""Guard production code against firmware requests that can contact package mirrors.

Some OPNsense firmware endpoints that look like reads make the Router contact its
mirrors, and this integration polls every 30 seconds by default. aiopnsense owns
those requests, as recorded in its
``docs/adr/0002-firmware-reads-never-contact-upstream.md``. Production code may
reach firmware only through the client methods in ``ALLOWED_FIRMWARE_METHODS``.

This is a static check of literal text and names. It cannot resolve a path that is
assembled entirely from runtime values.
"""

import ast
from pathlib import Path
import re

from aiopnsense import OPNsenseClient
import pytest

PRODUCTION_ROOT = Path(__file__).resolve().parents[1] / "custom_components" / "opnsense"
DATA_FILE_SUFFIXES = frozenset({".json", ".yaml", ".yml"})
REQUIRED_FIRMWARE_METHODS = frozenset(
    {"get_firmware_update_info", "get_host_firmware_version", "install_firmware"}
)
# The static thresholds accessor performs no Router I/O and is absent from aiopnsense 1.4.1.
ALLOWED_FIRMWARE_METHODS = REQUIRED_FIRMWARE_METHODS | {"get_firmware_requirements"}
# The web UI link ``/ui/core/firmware`` is not an API request.
FIRMWARE_API_PATH = re.compile(
    r"(?<!ui/)core/+firmware\b|\bfirmware/+(?:check|info|status)\b", re.IGNORECASE
)
CLIENT_RECEIVERS = frozenset({"client", "_client"})
FORBIDDEN_CLIENT_NAMES = (
    {name for name in dir(OPNsenseClient) if "firmware" in name.lower()}
    | {name for name in dir(OPNsenseClient) if name.startswith(("_do_", "_safe_"))}
    | {"_get", "_post", "get_firmware_info"}
) - ALLOWED_FIRMWARE_METHODS


def _docstring_node_ids(tree: ast.Module) -> set[int]:
    """Return the node IDs of docstrings, which describe requests but cannot send them.

    Args:
        tree (ast.Module): Parsed module.

    Returns:
        set[int]: ``id`` values of docstring constant nodes.
    """
    docstrings: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
            and node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        ):
            docstrings.add(id(node.body[0].value))
    return docstrings


def _static_text(node: ast.AST) -> str | None:
    """Return the literal text of a string expression, with ``{}`` for runtime values.

    Args:
        node (ast.AST): Expression to inspect.

    Returns:
        str | None: Literal text, or ``None`` when the node is not a string expression.
    """
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.JoinedStr):
        return "".join(_static_text(value) or "{}" for value in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _static_text(node.left), _static_text(node.right)
        if left is not None or right is not None:
            return f"{left or '{}'}{right or '{}'}"
    return None


def _forbidden_reference(node: ast.AST) -> str | None:
    """Describe a forbidden client member or firmware module reference.

    Args:
        node (ast.AST): Node to inspect.

    Returns:
        str | None: Violation description, or ``None`` when the node is allowed.
    """
    if isinstance(node, ast.Name) and node.id in FORBIDDEN_CLIENT_NAMES:
        return f"uses client member {node.id}"
    if isinstance(node, ast.Attribute):
        if node.attr in FORBIDDEN_CLIENT_NAMES:
            return f"uses client member {node.attr}"
        receiver = node.value
        receiver_name = (
            receiver.id
            if isinstance(receiver, ast.Name)
            else receiver.attr
            if isinstance(receiver, ast.Attribute)
            else None
        )
        if (
            receiver_name in CLIENT_RECEIVERS
            and node.attr.startswith("_")
            and not node.attr.startswith("__")
        ):
            return f"bypasses the client API through {node.attr}"
    if isinstance(node, ast.Import):
        for alias in node.names:
            if alias.name.startswith("aiopnsense.firmware"):
                return f"imports {alias.name}"
    if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("aiopnsense"):
        if (node.module or "").startswith("aiopnsense.firmware"):
            return f"imports {node.module}"
        for alias in node.names:
            if alias.name == "firmware" or alias.name in FORBIDDEN_CLIENT_NAMES:
                return f"imports {alias.name} from {node.module}"
    return None


def find_python_violations(source: str) -> list[str]:
    """Find forbidden firmware access in Python source.

    Args:
        source (str): Python source text.

    Returns:
        list[str]: Sorted ``line: reason`` descriptions.
    """
    tree = ast.parse(source)
    docstrings = _docstring_node_ids(tree)
    violations: set[tuple[int, str]] = set()
    for node in ast.walk(tree):
        line = getattr(node, "lineno", 0)
        if (reason := _forbidden_reference(node)) is not None:
            violations.add((line, reason))
        if id(node) in docstrings or (text := _static_text(node)) is None:
            continue
        if FIRMWARE_API_PATH.search(text):
            violations.add((line, f"references firmware API path {text!r}"))
        elif text in FORBIDDEN_CLIENT_NAMES:
            violations.add((line, f"dispatches client member {text!r}"))
    return [f"{line}: {reason}" for line, reason in sorted(violations)]


def find_data_file_violations(text: str) -> list[str]:
    """Find firmware API paths in a non-Python production file.

    Args:
        text (str): File contents.

    Returns:
        list[str]: ``line: reason`` descriptions.
    """
    return [
        f"{number}: references firmware API path {line.strip()!r}"
        for number, line in enumerate(text.splitlines(), start=1)
        if FIRMWARE_API_PATH.search(line)
    ]


def test_production_code_avoids_upstream_firmware_requests() -> None:
    """Fail when production code can reach firmware outside the allowed client methods."""
    python_files = sorted(PRODUCTION_ROOT.rglob("*.py"))
    assert python_files, f"No production Python files found under {PRODUCTION_ROOT}"
    assert set(dir(OPNsenseClient)) >= REQUIRED_FIRMWARE_METHODS

    violations = [
        f"{path.relative_to(PRODUCTION_ROOT)}:{violation}"
        for path in python_files
        for violation in find_python_violations(path.read_text(encoding="utf-8"))
    ]
    violations.extend(
        f"{path.relative_to(PRODUCTION_ROOT)}:{violation}"
        for path in sorted(PRODUCTION_ROOT.rglob("*"))
        if path.suffix in DATA_FILE_SUFFIXES
        for violation in find_data_file_violations(path.read_text(encoding="utf-8"))
    )

    assert not violations, "Firmware access must go through aiopnsense:\n" + "\n".join(violations)


@pytest.mark.parametrize(
    "source",
    [
        'PATH = "/api/core/firmware/info"',
        'PATH = "/api/core/firmware/check"',
        'client._safe_dict_post("/api/core/firmware/status")',
        'session.post(f"{url}/api/core/firmware/status")',
        'PATH = "/api/core/" + "firmware/info"',
        'PATH = base + "firmware/check"',
        'PATH = f"/api/core/firmware/{action}"',
        "client.get_firmware_info()",
        'getattr(client, "get_firmware_info")',
        'getattr(client, "get_" + "firmware_info")',
        'CATEGORY = {"function": "get_firmware_info"}',
        'client.upgrade_firmware("update")',
        'client.firmware_changelog("26.7")',
        "client._do_post(path)",
        "client._session.post(url)",
        "self._client._firmware_request(path)",
        "from aiopnsense.firmware import FIRMWARE_CHECK_ENDPOINT",
        "from aiopnsense import firmware",
        "import aiopnsense.firmware",
    ],
)
def test_guard_rejects_forbidden_firmware_access(source: str) -> None:
    """Report each way production code could reach a firmware endpoint.

    Args:
        source (str): Python source containing forbidden access.
    """
    assert find_python_violations(source)


@pytest.mark.parametrize(
    "source",
    [
        "client.get_firmware_update_info()",
        'self._client.install_firmware("update", target_version="26.7")',
        "client.get_host_firmware_version()",
        'CATEGORY = {"function": "get_firmware_update_info"}',
        'URL = base + "/ui/core/firmware#changelog"',
        'STATE = state["firmware_update_info"]',
        '"""Explain why /api/core/firmware/info is never called."""',
    ],
)
def test_guard_allows_supported_firmware_access(source: str) -> None:
    """Keep supported polling, installation, UI links, and documentation valid.

    Args:
        source (str): Python source containing allowed access.
    """
    assert find_python_violations(source) == []


@pytest.mark.parametrize(
    ("text", "expected_count"),
    [
        ("path: /api/core/firmware/info\nother: value\n", 1),
        ('{"url": "/ui/core/firmware#changelog"}', 0),
    ],
)
def test_guard_scans_data_files(text: str, expected_count: int) -> None:
    """Detect firmware API paths in data files without flagging web UI links.

    Args:
        text (str): Data file contents.
        expected_count (int): Expected number of violations.
    """
    assert len(find_data_file_violations(text)) == expected_count
