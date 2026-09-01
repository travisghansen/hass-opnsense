"""Tests for the Dependabot auto-merge workflow contracts."""

from pathlib import Path
from typing import Any

import yaml

WORKFLOW_PATH = Path(__file__).parents[1] / ".github" / "workflows" / "dependabot-auto-merge.yml"
TRUSTED_PULL_REQUEST_GUARD = (
    "github.event.repository.fork == false && "
    "github.event.pull_request.user.login == 'dependabot[bot]' && "
    "github.event.pull_request.head.repo.full_name == github.repository && "
    "github.event.pull_request.base.ref == github.event.repository.default_branch"
)


def _load_workflow() -> dict[str, Any]:
    """Load the Dependabot workflow while normalizing YAML's boolean `on` key.

    Returns:
        dict[str, Any]: Parsed workflow document.
    """
    document = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    if True in document:
        document["on"] = document.pop(True)
    return document


def _named_steps(document: dict[str, Any], job_id: str) -> dict[str, dict[str, Any]]:
    """Index named steps in one workflow job.

    Args:
        document (dict[str, Any]): Parsed workflow document.
        job_id (str): Workflow job identifier.

    Returns:
        dict[str, dict[str, Any]]: Named workflow steps.
    """
    job = document["jobs"][job_id]
    assert isinstance(job, dict)
    steps = job["steps"]
    assert isinstance(steps, list)
    return {step["name"]: step for step in steps if isinstance(step, dict) and "name" in step}


def test_verify_job_guards_source_and_changed_file_allowlist() -> None:
    """Require trusted Dependabot pull requests and the supported file allowlists."""
    document = _load_workflow()
    verify_job = document["jobs"]["verify-dependency-update"]
    assert isinstance(verify_job, dict)
    assert verify_job["if"] == TRUSTED_PULL_REQUEST_GUARD

    verify_run = _named_steps(document, "verify-dependency-update")[
        "Verify supported dependency update"
    ]["run"]
    assert isinstance(verify_run, str)
    assert '[[ "${changed_files}" == "uv.lock" ]]' in verify_run
    assert r"grep -Ev '^\.github/workflows/[^/]+\.ya?ml$'" in verify_run


def test_disable_job_repeats_failure_and_trusted_source_guards() -> None:
    """Keep failure handling and trusted pull-request constraints on disable."""
    document = _load_workflow()
    disable_job = document["jobs"]["disable-auto-merge"]
    assert isinstance(disable_job, dict)
    disable_guard = disable_job["if"]
    assert isinstance(disable_guard, str)
    assert disable_guard.startswith("failure() && !cancelled() &&")
    for constraint in TRUSTED_PULL_REQUEST_GUARD.split(" && "):
        assert constraint in disable_guard


def test_merge_jobs_keep_write_permissions_and_head_commit_match() -> None:
    """Preserve merge mutation permissions and the exact head SHA check."""
    document = _load_workflow()
    jobs = document["jobs"]
    assert isinstance(jobs, dict)
    for job_id in ("enable-auto-merge", "disable-auto-merge"):
        job = jobs[job_id]
        assert isinstance(job, dict)
        assert job["permissions"] == {
            "contents": "write",
            "pull-requests": "write",
        }

    enable_run = _named_steps(document, "enable-auto-merge")["Enable auto-merge"]["run"]
    assert enable_run == 'gh pr merge --auto --squash --match-head-commit "${HEAD_SHA}" "${PR_URL}"'
