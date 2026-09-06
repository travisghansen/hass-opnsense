"""Executable behavior tests for Dependabot auto-merge authorization."""

import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any

import pytest

AUTHORIZER = Path(__file__).parents[1] / ".github" / "scripts" / "dependabot-auto-merge.mjs"
BASE_SHA = "4" * 40
DEPENDABOT_SHA = "1" * 40
HEAD_SHA = "5" * 40
REPOSITORY = "Snuffy2/hass-opnsense"
NODE = shutil.which("node")


def _event(action: str, head_ref: str) -> dict[str, Any]:
    """Build a same-repository Dependabot pull-request event fixture.

    Args:
        action (str): Pull-request event action.
        head_ref (str): Dependabot branch name.

    Returns:
        dict[str, Any]: Event consumed by the authorizer.
    """
    return {
        "action": action,
        "repository": {"default_branch": "main", "fork": False, "full_name": REPOSITORY},
        "pull_request": {
            "base": {"ref": "main", "sha": BASE_SHA},
            "head": {"ref": head_ref, "repo": {"full_name": REPOSITORY}, "sha": HEAD_SHA},
            "user": {"login": "dependabot[bot]"},
        },
    }


def _dependabot_commit(sha: str = HEAD_SHA, *, verified: bool = True) -> dict[str, Any]:
    """Build a Dependabot commit fixture.

    Args:
        sha (str): Commit SHA.
        verified (bool): Whether GitHub verified the commit.

    Returns:
        dict[str, Any]: Commit data returned by the pull-request API.
    """
    return {
        "author": {"login": "dependabot[bot]"},
        "commit": {"verification": {"verified": verified}},
        "parents": [],
        "sha": sha,
    }


def _update_commit(previous: str) -> dict[str, Any]:
    """Build a verified GitHub Update branch merge commit.

    Args:
        previous (str): SHA of the preceding Dependabot commit.

    Returns:
        dict[str, Any]: Commit data for the current-base merge.
    """
    return {
        "author": {"login": "Snuffy2"},
        "commit": {"verification": {"verified": True}},
        "committer": {"login": "web-flow"},
        "parents": [{"sha": previous}, {"sha": BASE_SHA}],
        "sha": HEAD_SHA,
    }


def _authorize(
    tmp_path: Path,
    *,
    actor: str,
    changed_files: list[str],
    commits: list[dict[str, Any]],
    event: dict[str, Any],
) -> subprocess.CompletedProcess[str]:
    """Run the checked-in authorization command with API-shaped inputs.

    Args:
        tmp_path (Path): Trusted base checkout fixture directory.
        actor (str): GitHub Actions actor.
        changed_files (list[str]): Files reported by the pull-request API.
        commits (list[dict[str, Any]]): Commit pages returned by the API.
        event (dict[str, Any]): Pull-request event payload.

    Returns:
        subprocess.CompletedProcess[str]: Result from the authorizer process.

    Raises:
        RuntimeError: If Node.js is unavailable.
    """
    event_path = tmp_path / "event.json"
    changed_files_path = tmp_path / "changed-files"
    commits_path = tmp_path / "commits.json"
    event_path.write_text(json.dumps(event), encoding="utf-8")
    changed_files_path.write_text("\n".join(changed_files), encoding="utf-8")
    commits_path.write_text(json.dumps([commits]), encoding="utf-8")
    if NODE is None:
        raise RuntimeError("Node.js is required to run the Dependabot authorizer.")
    return subprocess.run(  # noqa: S603
        [NODE, str(AUTHORIZER), str(event_path), str(changed_files_path), str(commits_path)],
        check=False,
        cwd=tmp_path,
        env={**os.environ, "GITHUB_ACTOR": actor},
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize(
    ("changed_files", "authorized"),
    [(["uv.lock"], True), (["pyproject.toml", "uv.lock"], False)],
)
def test_uv_authorization_requires_only_the_lockfile(
    tmp_path: Path, changed_files: list[str], authorized: bool
) -> None:
    """Authorize direct uv updates only when their API file list is lockfile-only.

    Args:
        tmp_path (Path): Trusted base checkout fixture directory.
        changed_files (list[str]): Files reported by the pull-request API.
        authorized (bool): Whether the update should pass authorization.
    """
    result = _authorize(
        tmp_path,
        actor="dependabot[bot]",
        changed_files=changed_files,
        commits=[_dependabot_commit()],
        event=_event("opened", "dependabot/uv/pytest-9.0.0"),
    )

    assert (result.returncode == 0) is authorized


def test_authorization_accepts_only_verified_update_branch_history(tmp_path: Path) -> None:
    """Accept a GitHub Update branch merge and reject an unverified base commit.

    Args:
        tmp_path (Path): Trusted base checkout fixture directory.
    """
    valid = _authorize(
        tmp_path,
        actor="Snuffy2",
        changed_files=["uv.lock"],
        commits=[_dependabot_commit(DEPENDABOT_SHA), _update_commit(DEPENDABOT_SHA)],
        event=_event("synchronize", "dependabot/uv/pytest-9.0.0"),
    )
    invalid = _authorize(
        tmp_path,
        actor="Snuffy2",
        changed_files=["uv.lock"],
        commits=[
            _dependabot_commit(DEPENDABOT_SHA, verified=False),
            _update_commit(DEPENDABOT_SHA),
        ],
        event=_event("synchronize", "dependabot/uv/pytest-9.0.0"),
    )

    assert valid.returncode == 0
    assert invalid.returncode != 0


@pytest.mark.parametrize(
    ("changed_file", "trusted_file", "authorized"),
    [
        (".github/workflows/pytest_check.yml", ".github/workflows/pytest_check.yml", True),
        (".github/workflows/nested/unsafe.yml", ".github/workflows/nested/unsafe.yml", False),
    ],
)
def test_actions_authorization_requires_an_existing_top_level_file(
    tmp_path: Path, changed_file: str, trusted_file: str, authorized: bool
) -> None:
    """Authorize only trusted-base top-level GitHub Actions workflow updates.

    Args:
        tmp_path (Path): Trusted base checkout fixture directory.
        changed_file (str): File reported by the pull-request API.
        trusted_file (str): Corresponding file present in the trusted checkout.
        authorized (bool): Whether the update should pass authorization.
    """
    trusted_path = tmp_path / trusted_file
    trusted_path.parent.mkdir(parents=True)
    trusted_path.write_text("name: trusted\n", encoding="utf-8")
    result = _authorize(
        tmp_path,
        actor="dependabot[bot]",
        changed_files=[changed_file],
        commits=[_dependabot_commit()],
        event=_event("opened", "dependabot/github_actions/actions/checkout-7"),
    )

    assert (result.returncode == 0) is authorized
