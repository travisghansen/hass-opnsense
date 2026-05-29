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
