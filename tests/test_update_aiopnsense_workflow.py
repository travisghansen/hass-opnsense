"""Tests for the aiopnsense dependency update workflow."""

from importlib import util
import json
from pathlib import Path
import sys
from types import ModuleType

import pytest

WORKFLOW_PATH = Path(".github/workflows/update_aiopnsense.yml")
SCRIPT_PATH = Path(".github/scripts/update_aiopnsense_pins.py")


def _write_pin_files(
    tmp_path: Path,
    *,
    manifest_version: str,
    pyproject_version: str | None = None,
    pyproject_text: str | None = None,
) -> tuple[Path, Path]:
    """Write temporary manifest and pyproject files with aiopnsense pins."""
    manifest_path = tmp_path / "manifest.json"
    pyproject_path = tmp_path / "pyproject.toml"
    manifest_path.write_text(
        json.dumps(
            {
                "requirements": [
                    "xmltodict==0.14.2",
                    f"aiopnsense=={manifest_version}",
                ],
            },
        ),
    )

    if pyproject_text is None:
        pyproject_text = f"""[dependency-groups]
ha = [
    "aiopnsense=={pyproject_version or manifest_version}",
]
"""
    pyproject_path.write_text(pyproject_text)
    return manifest_path, pyproject_path


@pytest.fixture
def updater_script() -> ModuleType:
    """Load the aiopnsense pin updater script as a test module."""
    spec = util.spec_from_file_location("update_aiopnsense_pins", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = util.module_from_spec(spec)
    sys.modules["update_aiopnsense_pins"] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("needle", "reason"),
    [
        ("actions/setup-python@v6", "pins a Python runtime"),
        ("python-version: '3.14'", "uses a tomllib-capable Python"),
        ("Automated update of aiopnsense dependency pins.", "describes generated PRs"),
        ("custom_components/opnsense/manifest.json", "updates the integration manifest"),
        ("pyproject.toml", "updates the local dependency pin"),
        ("pyproject_current", "reports pyproject drift in PR metadata"),
        (str(SCRIPT_PATH), "runs the checked-in updater helper"),
        ("status === 422", "handles GitHub missing-reference responses"),
        ('message.includes("Reference does not exist")', "detects stale deleted branches"),
        ("Branch ${branch} was already deleted.", "logs stale branch cleanup"),
        ("function isPrerelease(version)", "detects prerelease release tags"),
        ("function stableVersion(version)", "normalizes prerelease current pins"),
        ("const currentIsPrerelease = isPrerelease(current);", "tracks prerelease repairs"),
        ("const currentStable = stableVersion(current);", "compares against stable base"),
        ("const lowerBound = compareVersions(tagVersion, currentStable);", "bounds notes"),
        ("!isPrerelease(tagVersion)", "filters prerelease release notes"),
        (
            "(lowerBound > 0 || (currentIsPrerelease && lowerBound === 0))",
            "excludes current stable except prerelease repairs",
        ),
        (
            "const title = sanitizeReleaseBody(release.name || release.tag_name);",
            "sanitizes release-note headings",
        ),
        ("const tag = sanitizeReleaseBody(release.tag_name);", "sanitizes tag headings"),
        ("`### ${title} (${tag})`", "uses sanitized heading values"),
        (r"@(?=[A-Za-z0-9-]+(?:\/[A-Za-z0-9-]+)?)", "neutralizes mentions"),
        ('"@<!-- -->"', "breaks GitHub mention syntax"),
        ("reference.replace", "escapes issue references"),
        (r'"\\#"', "breaks GitHub closing keywords"),
        ("close[sd]?|fix(?:e[sd])?|resolve[sd]?", "matches closing keywords"),
    ],
)
def test_workflow_contains_expected_update_logic(needle: str, reason: str) -> None:
    """Workflow should include the expected aiopnsense updater logic."""
    del reason
    workflow = WORKFLOW_PATH.read_text()

    assert needle in workflow


@pytest.mark.parametrize(
    (
        "manifest_version",
        "pyproject_version",
        "latest_version",
        "expected_update_needed",
        "expected_target",
    ),
    [
        ("1.0.8", "1.0.8", "1.0.9", True, "1.0.9"),
        ("1.0.0", "1.0.0", "1.0.1rc1", False, "1.0.0"),
        ("1.0.1rc1", "1.0.1rc1", "1.0.1", True, "1.0.1"),
        ("1.0.10", "1.0.9", "1.0.9", True, "1.0.10"),
    ],
)
def test_updater_script_pin_update_scenarios(
    tmp_path: Path,
    updater_script: ModuleType,
    manifest_version: str,
    pyproject_version: str,
    latest_version: str,
    expected_update_needed: bool,
    expected_target: str,
) -> None:
    """Updater script should handle stable, prerelease, and drift pin scenarios."""
    manifest_path, pyproject_path = _write_pin_files(
        tmp_path,
        manifest_version=manifest_version,
        pyproject_version=pyproject_version,
    )

    result = updater_script.update_pins(
        manifest_path=manifest_path,
        pyproject_path=pyproject_path,
        latest_version=latest_version,
    )

    assert result.current == manifest_version
    assert result.pyproject_current == pyproject_version
    assert result.latest == expected_target
    assert result.update_needed is expected_update_needed
    assert f"aiopnsense=={expected_target}" in manifest_path.read_text()
    assert f'    "aiopnsense=={expected_target}",' in pyproject_path.read_text()


def test_updater_script_updates_pyproject_pin_without_trailing_comma(
    tmp_path: Path, updater_script: ModuleType
) -> None:
    """Updater script should preserve valid TOML dependency-list formatting."""
    manifest_path, pyproject_path = _write_pin_files(
        tmp_path,
        manifest_version="1.0.8",
        pyproject_text="""[dependency-groups]
ha = [
    "homeassistant",
    "aiopnsense==1.0.8"
]
""",
    )

    result = updater_script.update_pins(
        manifest_path=manifest_path,
        pyproject_path=pyproject_path,
        latest_version="1.0.9",
    )

    assert result.update_needed is True
    assert '    "aiopnsense==1.0.9"\n' in pyproject_path.read_text()


@pytest.mark.parametrize(
    ("payload", "expected_latest"),
    [
        (
            {
                "info": {"version": "1.1.0rc1"},
                "releases": {
                    "1.0.8": [{"filename": "aiopnsense-1.0.8.tar.gz"}],
                    "1.0.9": [{"filename": "aiopnsense-1.0.9.tar.gz"}],
                    "1.1.0rc1": [{"filename": "aiopnsense-1.1.0rc1.tar.gz"}],
                },
            },
            "1.0.9",
        ),
        (
            {
                "releases": {
                    "1.0.8": [{"filename": "aiopnsense-1.0.8.tar.gz"}],
                    "1.0.9": [],
                    "1.0.10": [{"filename": "aiopnsense-1.0.10.tar.gz", "yanked": True}],
                },
            },
            "1.0.8",
        ),
    ],
)
def test_updater_script_selects_latest_stable_from_pypi_payload(
    updater_script: ModuleType,
    payload: dict[str, object],
    expected_latest: str,
) -> None:
    """Updater script should select the latest installable stable PyPI release."""
    latest = updater_script._select_latest_stable_version(
        payload,
    )

    assert latest == expected_latest


def test_updater_script_rejects_duplicate_pyproject_pins(
    tmp_path: Path,
    updater_script: ModuleType,
) -> None:
    """Updater script should fail clearly when pyproject has ambiguous pins."""
    manifest_path, pyproject_path = _write_pin_files(
        tmp_path,
        manifest_version="1.0.8",
        pyproject_text="""[dependency-groups]
ha = [
    "aiopnsense==1.0.8",
    "aiopnsense==1.0.9",
]
""",
    )

    with pytest.raises(ValueError, match="Expected exactly one pinned aiopnsense dependency"):
        updater_script.update_pins(
            manifest_path=manifest_path,
            pyproject_path=pyproject_path,
            latest_version="1.0.10",
        )
