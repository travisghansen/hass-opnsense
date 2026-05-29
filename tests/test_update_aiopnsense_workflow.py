"""Tests for the aiopnsense dependency update workflow."""

from importlib import util
import json
from pathlib import Path
import sys
from types import ModuleType

import pytest

WORKFLOW_PATH = Path(".github/workflows/update_aiopnsense.yml")
SCRIPT_PATH = Path(".github/scripts/update_aiopnsense_pins.py")


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


def test_workflow_updates_manifest_and_pyproject_pins() -> None:
    """Workflow should include both aiopnsense dependency pin files in update PRs."""
    workflow = WORKFLOW_PATH.read_text()

    assert "Automated update of aiopnsense dependency pins." in workflow
    assert "custom_components/opnsense/manifest.json" in workflow
    assert "pyproject.toml" in workflow
    assert "pyproject_current" in workflow
    assert str(SCRIPT_PATH) in workflow


def test_workflow_treats_missing_stale_branch_as_success() -> None:
    """Workflow should not fail when GitHub reports an absent branch as a 422."""
    workflow = WORKFLOW_PATH.read_text()

    assert "status === 422" in workflow
    assert 'message.includes("Reference does not exist")' in workflow
    assert "Branch ${branch} was already deleted." in workflow


def test_workflow_filters_prerelease_release_notes() -> None:
    """Workflow should not include prerelease release notes for stable updates."""
    workflow = WORKFLOW_PATH.read_text()

    assert "function isPrerelease(version)" in workflow
    assert "!isPrerelease(tagVersion)" in workflow


def test_workflow_neutralizes_release_note_closing_keywords() -> None:
    """Workflow should prevent copied release notes from closing local issues."""
    workflow = WORKFLOW_PATH.read_text()

    assert "reference.replace" in workflow
    assert r'"\\#"' in workflow
    assert "close[sd]?|fix(?:e[sd])?|resolve[sd]?" in workflow


def test_updater_script_updates_manifest_and_pyproject(
    tmp_path: Path, updater_script: ModuleType
) -> None:
    """Updater script should rewrite exactly one pin in each dependency file."""
    manifest_path = tmp_path / "manifest.json"
    pyproject_path = tmp_path / "pyproject.toml"
    manifest_path.write_text(
        json.dumps(
            {
                "requirements": [
                    "xmltodict==0.14.2",
                    "aiopnsense==1.0.8",
                ],
            },
        ),
    )
    pyproject_path.write_text(
        """[dependency-groups]
ha = [
    "aiopnsense==1.0.8",
    "homeassistant",
]
""",
    )

    result = updater_script.update_pins(
        manifest_path=manifest_path,
        pyproject_path=pyproject_path,
        latest_version="1.0.9",
    )

    assert result.current == "1.0.8"
    assert result.pyproject_current == "1.0.8"
    assert result.latest == "1.0.9"
    assert result.update_needed is True
    assert "aiopnsense==1.0.9" in manifest_path.read_text()
    assert '    "aiopnsense==1.0.9",' in pyproject_path.read_text()


def test_updater_script_ignores_prerelease_updates(
    tmp_path: Path, updater_script: ModuleType
) -> None:
    """Updater script should not treat prereleases as newer stable pins."""
    manifest_path = tmp_path / "manifest.json"
    pyproject_path = tmp_path / "pyproject.toml"
    manifest_path.write_text(json.dumps({"requirements": ["aiopnsense==1.0.0"]}))
    pyproject_path.write_text(
        """[dependency-groups]
ha = [
    "aiopnsense==1.0.0",
]
""",
    )

    result = updater_script.update_pins(
        manifest_path=manifest_path,
        pyproject_path=pyproject_path,
        latest_version="1.0.1rc1",
    )

    assert result.update_needed is False
    assert result.latest == "1.0.0"
    assert "aiopnsense==1.0.0" in manifest_path.read_text()
    assert '    "aiopnsense==1.0.0",' in pyproject_path.read_text()


def test_updater_script_updates_prerelease_pin_to_matching_stable(
    tmp_path: Path, updater_script: ModuleType
) -> None:
    """Updater script should replace current prerelease pins with stable releases."""
    manifest_path = tmp_path / "manifest.json"
    pyproject_path = tmp_path / "pyproject.toml"
    manifest_path.write_text(json.dumps({"requirements": ["aiopnsense==1.0.1rc1"]}))
    pyproject_path.write_text(
        """[dependency-groups]
ha = [
    "aiopnsense==1.0.1rc1",
]
""",
    )

    result = updater_script.update_pins(
        manifest_path=manifest_path,
        pyproject_path=pyproject_path,
        latest_version="1.0.1",
    )

    assert result.update_needed is True
    assert result.latest == "1.0.1"
    assert "aiopnsense==1.0.1" in manifest_path.read_text()
    assert '    "aiopnsense==1.0.1",' in pyproject_path.read_text()


def test_updater_script_selects_latest_stable_from_pypi_payload(
    updater_script: ModuleType,
) -> None:
    """Updater script should ignore prereleases when reading PyPI releases."""
    latest = updater_script._select_latest_stable_version(
        {
            "info": {"version": "1.1.0rc1"},
            "releases": {
                "1.0.8": [{"filename": "aiopnsense-1.0.8.tar.gz"}],
                "1.0.9": [{"filename": "aiopnsense-1.0.9.tar.gz"}],
                "1.1.0rc1": [{"filename": "aiopnsense-1.1.0rc1.tar.gz"}],
            },
        },
    )

    assert latest == "1.0.9"


def test_updater_script_ignores_stable_releases_without_usable_files(
    updater_script: ModuleType,
) -> None:
    """Updater script should ignore PyPI releases with no installable files."""
    latest = updater_script._select_latest_stable_version(
        {
            "releases": {
                "1.0.8": [{"filename": "aiopnsense-1.0.8.tar.gz"}],
                "1.0.9": [],
                "1.0.10": [{"filename": "aiopnsense-1.0.10.tar.gz", "yanked": True}],
            },
        },
    )

    assert latest == "1.0.8"


def test_updater_script_repairs_pyproject_drift_when_manifest_is_newer(
    tmp_path: Path,
    updater_script: ModuleType,
) -> None:
    """Updater script should align pyproject to a newer manifest pin."""
    manifest_path = tmp_path / "manifest.json"
    pyproject_path = tmp_path / "pyproject.toml"
    manifest_path.write_text(json.dumps({"requirements": ["aiopnsense==1.0.10"]}))
    pyproject_path.write_text(
        """[dependency-groups]
ha = [
    "aiopnsense==1.0.9",
]
""",
    )

    result = updater_script.update_pins(
        manifest_path=manifest_path,
        pyproject_path=pyproject_path,
        latest_version="1.0.9",
    )

    assert result.update_needed is True
    assert result.latest == "1.0.10"
    assert "aiopnsense==1.0.10" in manifest_path.read_text()
    assert '    "aiopnsense==1.0.10",' in pyproject_path.read_text()


def test_updater_script_rejects_duplicate_pyproject_pins(
    tmp_path: Path,
    updater_script: ModuleType,
) -> None:
    """Updater script should fail clearly when pyproject has ambiguous pins."""
    manifest_path = tmp_path / "manifest.json"
    pyproject_path = tmp_path / "pyproject.toml"
    manifest_path.write_text(json.dumps({"requirements": ["aiopnsense==1.0.8"]}))
    pyproject_path.write_text(
        """[dependency-groups]
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
