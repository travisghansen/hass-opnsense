"""Tests for immutable release-check verification and workflow contracts."""

from collections.abc import Sequence
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

SCRIPT_PATH = Path(__file__).parents[1] / ".github" / "scripts" / "verify_release_checks.py"
SCRIPT_SPEC = importlib.util.spec_from_file_location("verify_release_checks", SCRIPT_PATH)
assert SCRIPT_SPEC is not None
assert SCRIPT_SPEC.loader is not None
verify = importlib.util.module_from_spec(SCRIPT_SPEC)
SCRIPT_SPEC.loader.exec_module(verify)

WORKFLOW_ROOT = Path(__file__).parents[1] / ".github" / "workflows"
REPOSITORY = "owner/repository"
REF = "release-validation/v1.0.6-123-1"
SHA = "a" * 40


def _load_workflow(name: str) -> dict[str, Any]:
    """Load a workflow while normalizing YAML's boolean `on` key.

    Args:
        name (str): Workflow filename.

    Returns:
        dict[str, Any]: Parsed workflow document.
    """
    document = yaml.safe_load((WORKFLOW_ROOT / name).read_text(encoding="utf-8"))
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


def test_dispatch_workflow_uses_expected_ref_sha_and_authoritative_run_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Send the candidate identity and accept only GitHub's returned run ID.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing the API helper.
    """
    calls: list[tuple[list[str], int | None]] = []

    def fake_api(arguments: Sequence[str], expected_status: int | None = None) -> dict[str, Any]:
        calls.append((list(arguments), expected_status))
        return {"workflow_run_id": 42}

    monkeypatch.setattr(verify, "github_api", fake_api)

    assert verify.dispatch_workflow(REPOSITORY, "validate.yml", REF, SHA) == 42
    arguments, status = calls[0]
    assert status == 200
    assert f"repos/{REPOSITORY}/actions/workflows/validate.yml/dispatches" in arguments
    assert f"ref={REF}" in arguments
    assert f"inputs[expected_sha]={SHA}" in arguments


@pytest.mark.parametrize("run_id", [None, 0, -1, True, "42"])
def test_dispatch_workflow_rejects_missing_or_invalid_run_id(
    monkeypatch: pytest.MonkeyPatch, run_id: object
) -> None:
    """Fail closed when the dispatch response is not an authoritative run ID.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing the API helper.
        run_id (object): Invalid response value.
    """
    monkeypatch.setattr(
        verify,
        "github_api",
        lambda _arguments, expected_status=None: {"workflow_run_id": run_id},
    )

    with pytest.raises(verify.GitHubCommandError, match="valid workflow_run_id"):
        verify.dispatch_workflow(REPOSITORY, "validate.yml", REF, SHA)


def test_wait_for_workflow_requires_exact_identity_and_successful_jobs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify the exact dispatched run, Actions suite, and exact required job.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing API and time helpers.
    """
    responses = iter(
        [
            {"id": 7},
            {
                "id": 42,
                "workflow_id": 7,
                "event": "workflow_dispatch",
                "head_branch": REF,
                "head_sha": SHA,
                "status": "completed",
                "conclusion": "success",
                "check_suite_id": 99,
            },
            {"head_sha": SHA, "app": {"slug": "github-actions"}},
            {
                "total_count": 1,
                "jobs": [{"name": "HACS Validation", "conclusion": "success"}],
            },
        ]
    )
    monkeypatch.setattr(verify, "github_api", lambda _arguments: next(responses))
    monkeypatch.setattr(verify.time, "monotonic", lambda: 0.0)

    assert (
        verify.wait_for_workflow(
            REPOSITORY,
            "validate.yml",
            REF,
            SHA,
            {"HACS Validation"},
            deadline=1.0,
            expected_run_id=42,
        )
        == 42
    )


@pytest.mark.parametrize(
    "run",
    [
        {"id": 41},
        {
            "id": 42,
            "workflow_id": 7,
            "event": "push",
            "head_branch": REF,
            "head_sha": SHA,
        },
    ],
)
def test_wait_for_workflow_rejects_non_authoritative_identity(
    monkeypatch: pytest.MonkeyPatch, run: dict[str, Any]
) -> None:
    """Reject a mismatched run ID or workflow identity.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing API and time helpers.
        run (dict[str, Any]): Invalid workflow run response.
    """
    monkeypatch.setattr(
        verify,
        "github_api",
        lambda _arguments: {"id": 7} if "/workflows/" in _arguments[0] else run,
    )
    monkeypatch.setattr(verify.time, "monotonic", lambda: 0.0)

    with pytest.raises(verify.GitHubCommandError, match="does not match"):
        verify.wait_for_workflow(
            REPOSITORY, "validate.yml", REF, SHA, set(), deadline=1.0, expected_run_id=42
        )


def test_verify_jobs_rejects_missing_duplicate_or_unsuccessful_required_jobs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail promotion when any exact required check is not uniquely successful.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing the API helper.
    """
    monkeypatch.setattr(
        verify,
        "github_api",
        lambda _arguments: {
            "total_count": 3,
            "jobs": [
                {"name": "required", "conclusion": "success"},
                {"name": "duplicate", "conclusion": "success"},
                {"name": "duplicate", "conclusion": "success"},
            ],
        },
    )

    with pytest.raises(verify.GitHubCommandError, match=r"missing=.*missing"):
        verify.verify_jobs(REPOSITORY, 42, {"required", "duplicate", "missing"})


def test_github_api_rejects_malformed_or_non_authoritative_http_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail closed for absent CLI, malformed JSON, and wrong dispatch status.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing CLI discovery and execution.
    """
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(verify.GitHubCommandError, match="unavailable"):
        verify.github_api([])

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/gh")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout="HTTP/2 204 No Content\n\n", stderr=""
        ),
    )
    with pytest.raises(verify.GitHubCommandError, match="unexpected HTTP"):
        verify.github_api([], expected_status=200)

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="{", stderr=""),
    )
    with pytest.raises(json.JSONDecodeError):
        verify.github_api([])


def test_release_workflow_has_guarded_promotion_and_firmware_archive_contract() -> None:
    """Preserve published-release handling, lease promotion, and opnsense.zip uploads."""
    document = _load_workflow("release.yml")
    assert document["on"] == {"release": {"types": ["published"]}}
    job = document["jobs"]["release"]
    assert job["permissions"] == {
        "actions": "write",
        "checks": "read",
        "contents": "write",
        "statuses": "read",
    }
    steps = _named_steps(document, "release")
    assert (
        steps["Checkout trusted default-branch workflow revision"]["with"]["persist-credentials"]
        is False
    )
    assert (
        steps["Build prerelease archive without mutating refs"]["if"]
        == "github.event.release.prerelease"
    )
    dispatch = steps["Dispatch and verify immutable release gates"]["run"]
    assert "pytest_check.yml::pytest and coverage report" in dispatch
    assert "linters.yml::Run Linters" in dispatch
    promotion = steps["Atomically advance target and guarded release tag"]["run"]
    assert "push --atomic" in promotion
    assert "refs/heads/$RELEASE_TARGET:$TARGET_SHA" in promotion
    assert "refs/tags/$RELEASE_TAG:$ORIGINAL_TAG_OID" in promotion
    assert "opnsense.zip" in steps["Verify release identity and upload B archive"]["run"]
    assert (
        "opnsense-firmware-compatibility"
        in steps["Verify release identity and upload B archive"]["run"]
    )
    assert steps["Delete validated temporary branch"]["if"] == (
        "github.event.release.prerelease == false && success()"
    )


@pytest.mark.parametrize(
    ("workflow", "jobs"),
    [
        ("validate.yml", ["ha_validation", "hacs_validation"]),
        ("pytest_check.yml", ["tests"]),
        ("linters.yml", ["linters"]),
    ],
)
def test_release_gate_workflows_guard_and_checkout_the_exact_dispatch_sha(
    workflow: str, jobs: list[str]
) -> None:
    """Require lowercase SHA validation and credential-free immutable checkout.

    Args:
        workflow (str): Workflow filename.
        jobs (list[str]): Guarded job identifiers.
    """
    document = _load_workflow(workflow)
    if workflow == "validate.yml":
        assert document["permissions"] == {"contents": "read"}
    assert document["on"]["workflow_dispatch"]["inputs"]["expected_sha"]["required"] is True
    for job_id in jobs:
        steps = _named_steps(document, job_id)
        guard = steps["Require expected release commit"]
        assert guard["run"] == (
            '[[ "$EXPECTED_SHA" =~ ^[0-9a-f]{40}$ ]]\ntest "$WORKFLOW_SHA" = "$EXPECTED_SHA"\n'
        )
        checkout = next(
            step for step in steps.values() if step.get("uses") == "actions/checkout@v7"
        )
        assert checkout["with"]["ref"] == "${{ inputs.expected_sha || github.sha }}"
        assert checkout["with"]["persist-credentials"] is False

    if workflow == "pytest_check.yml":
        assert document["jobs"]["tests"]["permissions"] == {"contents": "read"}
        assert document["jobs"]["coverage_publisher"]["if"].startswith(
            "github.event_name != 'workflow_dispatch'"
        )
