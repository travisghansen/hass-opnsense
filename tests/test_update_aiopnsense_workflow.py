"""Tests for the aiopnsense dependency update workflow."""

from importlib import util
from io import StringIO
import json
from pathlib import Path
import sys
import tomllib
from types import ModuleType
from typing import Never

import pytest

SCRIPT_PATH = Path(".github/scripts/update_aiopnsense_pins.py")
WORKFLOW_PATH = Path(".github/workflows/update_aiopnsense.yml")
RELEASE_NOTES_SCRIPT_PATH = Path(".github/scripts/build_aiopnsense_release_notes.py")
CLEANUP_SCRIPT_PATH = Path(".github/scripts/cleanup_aiopnsense_update_branches.py")


class FakeCleanupClient:
    """Fake GitHub cleanup client that records mutating calls."""

    def __init__(
        self,
        *,
        open_pulls: list[dict[str, object]],
        closed_pulls: list[dict[str, object]],
        fail_on_close: bool = False,
    ) -> None:
        """Initialize fake pull request state.

        Args:
            open_pulls (list[dict[str, object]]): Pull requests to return for open PR lookups.
            closed_pulls (list[dict[str, object]]): Pull requests to return for closed PR lookups.
            fail_on_close (bool): Whether closing a PR should fail the test.
        """
        self.open_pulls = open_pulls
        self.closed_pulls = closed_pulls
        self.fail_on_close = fail_on_close
        self.closed_prs: list[int] = []
        self.deleted_refs: list[str] = []

    def list_pulls(self, *, state: str) -> list[dict[str, object]]:
        """Return fake pull requests by state.

        Returns:
            list[dict[str, object]]: Pull request records stored by the fake GitHub client.

        Args:
            state (str): Pull request state recorded by the fake GitHub client.
        """
        return self.open_pulls if state == "open" else self.closed_pulls

    def close_pull(self, pull_number: int) -> None:
        """Record or reject a closed pull request.

        Args:
            pull_number (int): Pull request number queried by the fake GitHub client.

        Raises:
            AssertionError: The fake was configured to reject close requests.
        """
        if self.fail_on_close:
            raise AssertionError(f"Unexpected close for PR {pull_number}")
        self.closed_prs.append(pull_number)

    def delete_ref(self, ref: str) -> None:
        """Record a deleted git ref.

        Args:
            ref (str): Git reference queried by the fake GitHub client.
        """
        self.deleted_refs.append(ref)


def _workflow_pull(
    *,
    number: int,
    ref: str = "chore/update-aiopnsense-manifest",
    label: str = "aiopnsense-auto-update",
    merged_at: str | None = None,
) -> dict[str, object]:
    """Return a fake workflow pull request object.

    Args:
        number (int): Pull request number.
        ref (str): Pull request head ref.
        label (str): Pull request label name.
        merged_at (str | None): Optional merge timestamp for closed PRs.

    Returns:
        dict[str, object]: Fake pull request object shaped like the GitHub REST API response.
    """
    return {
        "number": number,
        "merged_at": merged_at,
        "head": {"ref": ref, "repo": {"full_name": "o/r"}},
        "labels": [{"name": label}],
    }


def _write_pin_files(
    tmp_path: Path,
    *,
    manifest_version: str,
    pyproject_version: str | None = None,
    pyproject_text: str | None = None,
) -> tuple[Path, Path]:
    """Write temporary manifest and pyproject files with aiopnsense pins.

    Returns:
        tuple[Path, Path]: Paths to the generated manifest and pyproject files.

    Args:
        tmp_path (Path): pytest temporary directory containing test configuration files.
        manifest_version (str): aiopnsense version written to the test manifest.
        pyproject_version (str | None): aiopnsense version written to the test pyproject.
        pyproject_text (str | None): Optional complete pyproject content for the fixture.
    """
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
    """Load the aiopnsense pin updater script as a test module.

    Returns:
        ModuleType: Imported workflow helper module.
    """
    return _load_script("update_aiopnsense_pins", SCRIPT_PATH)


@pytest.fixture
def release_notes_script() -> ModuleType:
    """Load the aiopnsense release-note builder script as a test module.

    Returns:
        ModuleType: Imported workflow helper module.
    """
    return _load_script("build_aiopnsense_release_notes", RELEASE_NOTES_SCRIPT_PATH)


@pytest.fixture
def cleanup_script() -> ModuleType:
    """Load the aiopnsense cleanup script as a test module.

    Returns:
        ModuleType: Imported workflow helper module.
    """
    return _load_script("cleanup_aiopnsense_update_branches", CLEANUP_SCRIPT_PATH)


def _load_script(module_name: str, script_path: Path) -> ModuleType:
    """Load a checked-in workflow helper script as a test module.

    Returns:
        ModuleType: Imported workflow helper module.

    Args:
        module_name (str): Import name assigned to the loaded workflow helper.
        script_path (Path): Filesystem path of the workflow helper to load.
    """
    spec = util.spec_from_file_location(module_name, script_path)
    assert spec is not None
    assert spec.loader is not None
    module = util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_workflow_regenerates_uv_lock_after_updating_pins() -> None:
    """Workflow should refresh and include the lockfile after a pin update."""
    workflow = WORKFLOW_PATH.read_text()

    assert "uses: astral-sh/setup-uv@v9.0.0" in workflow
    assert workflow.index("- name: Update aiopnsense dependency pins") < workflow.index(
        "- name: Regenerate uv lock"
    )
    assert "        run: uv lock" in workflow
    assert "            uv.lock" in workflow
    assert "prek.toml" not in workflow


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
    """Updater script should handle stable, prerelease, and drift pin scenarios.

    Args:
        tmp_path (Path): pytest temporary directory containing test configuration files.
        updater_script (ModuleType): Loaded aiopnsense pin-updater helper module.
        manifest_version (str): aiopnsense version written to the test manifest.
        pyproject_version (str): aiopnsense version written to the test pyproject.
        latest_version (str): Release version reported by the mocked package index.
        expected_update_needed (bool): Whether pin evaluation should request an update.
        expected_target (str): Version target expected from pin evaluation.
    """
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
    manifest = json.loads(manifest_path.read_text())
    pyproject = tomllib.loads(pyproject_path.read_text())
    expected_pin = f"aiopnsense=={expected_target}"
    assert expected_pin in manifest["requirements"]
    assert expected_pin in pyproject["dependency-groups"]["ha"]


def test_updater_script_updates_pyproject_pin_without_trailing_comma(
    tmp_path: Path, updater_script: ModuleType
) -> None:
    """Updater script should preserve valid TOML dependency-list formatting.

    Args:
        tmp_path (Path): pytest temporary directory containing test configuration files.
        updater_script (ModuleType): Loaded aiopnsense pin-updater helper module.
    """
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
    pyproject = tomllib.loads(pyproject_path.read_text())
    assert "aiopnsense==1.0.9" in pyproject["dependency-groups"]["ha"]


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
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object],
    expected_latest: str,
) -> None:
    """Updater script should select the latest installable stable PyPI release.

    Args:
        updater_script (ModuleType): Loaded aiopnsense pin-updater helper module.
        monkeypatch (pytest.MonkeyPatch): pytest fixture used to replace dependencies.
        payload (dict[str, object]): Synthetic API response payload.
        expected_latest (str): Latest release version expected from the response.
    """

    def open_pypi_response(*_: object, **__: object) -> StringIO:
        """Return the fake PyPI response as a readable context manager.

        Args:
            _ (object): Additional positional arguments accepted by the test double.
            __ (object): Additional keyword arguments accepted by the test double.

        Returns:
            StringIO: In-memory stream containing the mocked HTTP response.
        """
        return StringIO(json.dumps(payload))

    monkeypatch.setattr(updater_script, "urlopen", open_pypi_response)

    assert updater_script.fetch_latest_version() == expected_latest


def test_updater_script_rejects_duplicate_pyproject_pins(
    tmp_path: Path,
    updater_script: ModuleType,
) -> None:
    """Updater script should fail clearly when pyproject has ambiguous pins.

    Args:
        tmp_path (Path): pytest temporary directory containing test configuration files.
        updater_script (ModuleType): Loaded aiopnsense pin-updater helper module.
    """
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


def test_release_note_script_builds_sanitized_pr_body(
    tmp_path: Path,
    release_notes_script: ModuleType,
) -> None:
    """Release-note script should build a mention-safe PR body file.

    Args:
        tmp_path (Path): pytest temporary directory containing test configuration files.
        release_notes_script (ModuleType): Loaded release-notes workflow helper module.
    """
    releases = [
        {
            "tag_name": "1.0.8",
            "name": "Ignored current",
            "body": "old",
            "html_url": "https://example.test/1.0.8",
        },
        {
            "tag_name": "1.0.9",
            "name": "Fixes @someone",
            "body": "fixes #123 and thanks [@helper](https://github.com/helper)",
            "html_url": "https://example.test/1.0.9",
        },
        {
            "tag_name": "1.1.0rc1",
            "name": "Ignored prerelease",
            "body": "future",
            "html_url": "https://example.test/1.1.0rc1",
        },
    ]
    body_path = tmp_path / "body.md"

    release_notes_script.write_pr_body(
        body_path=body_path,
        releases=releases,
        current_version="1.0.8",
        pyproject_current_version="1.0.8",
        latest_version="1.0.9",
    )

    body = body_path.read_text()
    assert "Automated update of aiopnsense dependency pins." in body
    assert "Updated pinned version: `aiopnsense==1.0.9`" in body
    assert "### Fixes @<!-- -->someone (1.0.9)" in body
    assert "fixes \\#123 and thanks helper" in body
    assert "Ignored current" not in body
    assert "Ignored prerelease" not in body


def test_release_note_script_handles_url_errors(
    tmp_path: Path,
    release_notes_script: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Release-note script should report network failures without a traceback.

    Args:
        tmp_path (Path): pytest temporary directory containing test configuration files.
        release_notes_script (ModuleType): Loaded release-notes workflow helper module.
        monkeypatch (pytest.MonkeyPatch): pytest fixture used to replace dependencies.
    """

    def raise_url_error(**_: object) -> Never:
        """Raise a urlopen-style network failure.

        Args:
            _ (object): Additional keyword arguments accepted by the test double.

        Returns:
            Never: Never returns normally because ``URLError`` is always raised.

        Raises:
            release_notes_script.URLError: Always raised to simulate a network failure.
        """
        raise release_notes_script.URLError("DNS failure")

    monkeypatch.setattr(release_notes_script, "fetch_releases", raise_url_error)

    result = release_notes_script.main(
        [
            "--current-version",
            "1.0.8",
            "--pyproject-current-version",
            "1.0.8",
            "--latest-version",
            "1.0.9",
            "--release-owner",
            "Snuffy2",
            "--release-repo",
            "aiopnsense",
            "--body-path",
            str(tmp_path / "body.md"),
        ],
    )

    assert result == 1


def test_cleanup_script_closes_stale_prs_and_deletes_workflow_branches(
    cleanup_script: ModuleType,
) -> None:
    """Cleanup script should close stale PRs and remove workflow-created branches.

    Args:
        cleanup_script (ModuleType): Loaded branch-cleanup workflow helper module.
    """
    client = FakeCleanupClient(
        open_pulls=[
            _workflow_pull(number=10),
            _workflow_pull(number=9, ref="chore/update-aiopnsense-old"),
            _workflow_pull(number=11, ref="feature/manual"),
        ],
        closed_pulls=[
            _workflow_pull(number=8, merged_at="2026-05-28T00:00:00Z"),
            _workflow_pull(number=7, ref="chore/update-aiopnsense-old"),
        ],
    )

    result = cleanup_script.cleanup_update_branches(
        client=client,
        repository="o/r",
        branch="chore/update-aiopnsense-manifest",
        branch_prefix="chore/update-aiopnsense",
        label_name="aiopnsense-auto-update",
        keep_pr_number=None,
        close_stale_prs=True,
        delete_stale_branch=True,
        delete_merged_branches=True,
    )

    assert sorted(client.closed_prs) == [9, 10]
    assert sorted(client.deleted_refs) == [
        "heads/chore/update-aiopnsense-manifest",
        "heads/chore/update-aiopnsense-old",
    ]
    assert sorted(result.closed_prs) == [9, 10]
    assert sorted(result.deleted_branches) == [
        "chore/update-aiopnsense-manifest",
        "chore/update-aiopnsense-old",
    ]


def test_cleanup_script_keeps_active_update_branch(cleanup_script: ModuleType) -> None:
    """Cleanup script should not delete the branch for the kept update PR.

    Args:
        cleanup_script (ModuleType): Loaded branch-cleanup workflow helper module.
    """
    client = FakeCleanupClient(
        open_pulls=[_workflow_pull(number=12)],
        closed_pulls=[
            _workflow_pull(number=8, merged_at="2026-05-28T00:00:00Z"),
            _workflow_pull(
                number=6,
                ref="chore/update-aiopnsense-old",
                merged_at="2026-05-20T00:00:00Z",
            ),
        ],
        fail_on_close=True,
    )

    result = cleanup_script.cleanup_update_branches(
        client=client,
        repository="o/r",
        branch="chore/update-aiopnsense-manifest",
        branch_prefix="chore/update-aiopnsense",
        label_name="aiopnsense-auto-update",
        keep_pr_number=12,
        close_stale_prs=True,
        delete_stale_branch=False,
        delete_merged_branches=True,
    )

    assert client.deleted_refs == ["heads/chore/update-aiopnsense-old"]
    assert result.closed_prs == []
    assert result.deleted_branches == ["chore/update-aiopnsense-old"]
