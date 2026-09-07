"""Tests for immutable release check verification and workflow contracts."""

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
REF = "release-validation/v3.0.1-123-1"
SHA = "a" * 40
LINT_WORKFLOW = (
    "prek-autofix-review.yml"
    if (WORKFLOW_ROOT / "prek-autofix-review.yml").exists()
    else "linters.yml"
)


def _required_check_values() -> list[str]:
    """Read the release gate manifest from the caller workflow.

    Returns:
        list[str]: Ordered workflow and job gate declarations.
    """
    document = yaml.safe_load((WORKFLOW_ROOT / "release.yml").read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    if True in document:
        document["on"] = document.pop(True)
    environment = document["jobs"]["release"]["env"]
    assert isinstance(environment, dict)
    values = str(environment["REQUIRED_CHECKS"]).splitlines()
    return [value for value in values if value]


def test_dispatch_workflow_sends_ref_and_expected_sha(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dispatch the named workflow for exactly the candidate ref and SHA.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing the API helper.
    """
    calls: list[tuple[list[str], int | None]] = []

    def fake_api(arguments: Sequence[str], expected_status: int | None = None) -> dict[str, Any]:
        calls.append((list(arguments), expected_status))
        return {"workflow_run_id": 42}

    monkeypatch.setattr(verify, "github_api", fake_api)

    assert verify.dispatch_workflow(REPOSITORY, "validate.yml", REF, SHA) == 42

    assert len(calls) == 1
    arguments, expected_status = calls[0]
    assert expected_status == 200
    assert arguments[arguments.index("--method") + 1] == "POST"
    assert f"repos/{REPOSITORY}/actions/workflows/validate.yml/dispatches" in arguments
    assert f"ref={REF}" in arguments
    assert f"inputs[expected_sha]={SHA}" in arguments
    assert "Accept: application/vnd.github+json" in arguments
    assert "X-GitHub-Api-Version: 2026-03-10" in arguments


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"workflow_run_id": None},
        {"workflow_run_id": 0},
        {"workflow_run_id": -1},
        {"workflow_run_id": True},
        {"workflow_run_id": "42"},
    ],
)
def test_dispatch_workflow_rejects_invalid_authoritative_run_id(
    monkeypatch: pytest.MonkeyPatch, response: dict[str, Any]
) -> None:
    """Fail closed when dispatch omits or corrupts the authoritative run ID.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing the API helper.
        response (dict[str, Any]): Invalid dispatch response fixture.
    """
    monkeypatch.setattr(
        verify,
        "github_api",
        lambda _arguments, expected_status=None: response,
    )

    with pytest.raises(verify.GitHubCommandError, match="valid workflow_run_id"):
        verify.dispatch_workflow(REPOSITORY, "validate.yml", REF, SHA)


@pytest.mark.parametrize(("status", "body"), [(204, ""), (200, ""), (200, "not-json")])
def test_dispatch_workflow_rejects_non_authoritative_http_responses(
    monkeypatch: pytest.MonkeyPatch, status: int, body: str
) -> None:
    """Reject 204, empty, and malformed dispatch API responses.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing CLI execution.
        status (int): HTTP status returned by the fixture.
        body (str): Response body returned by the fixture.
    """
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/gh")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=f"HTTP/2 {status} status\n\n{body}",
            stderr="",
        ),
    )

    with pytest.raises((verify.GitHubCommandError, json.JSONDecodeError)):
        verify.dispatch_workflow(REPOSITORY, "validate.yml", REF, SHA)


def test_wait_for_workflow_returns_completed_run_id_after_pending_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Return the exact completed run ID after tolerating an in-progress run.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing clock and checks.
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
                "status": "in_progress",
            },
            {
                "id": 42,
                "workflow_id": 7,
                "event": "workflow_dispatch",
                "head_branch": REF,
                "head_sha": SHA,
                "status": "completed",
                "conclusion": "success",
            },
        ]
    )
    sleeps: list[float] = []
    suite_calls: list[tuple[dict[str, Any], str]] = []
    job_calls: list[tuple[int, set[str]]] = []
    clock = iter([0.0, 0.1])

    monkeypatch.setattr(verify, "github_api", lambda _arguments: next(responses))
    monkeypatch.setattr(verify.time, "monotonic", lambda: next(clock, 1.0))
    monkeypatch.setattr(verify.time, "sleep", sleeps.append)
    monkeypatch.setattr(
        verify,
        "verify_check_suite",
        lambda _repository, run, sha: suite_calls.append((run, sha)),
    )
    monkeypatch.setattr(
        verify,
        "verify_jobs",
        lambda _repository, run_id, checks: job_calls.append((run_id, checks)),
    )

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
    assert sleeps == [10]
    assert suite_calls == [
        (
            {
                "id": 42,
                "workflow_id": 7,
                "event": "workflow_dispatch",
                "head_branch": REF,
                "head_sha": SHA,
                "status": "completed",
                "conclusion": "success",
            },
            SHA,
        )
    ]
    assert job_calls == [(42, {"HACS Validation"})]


@pytest.mark.parametrize("conclusion", ["failure", "cancelled"])
def test_wait_for_workflow_rejects_unsuccessful_conclusion(
    monkeypatch: pytest.MonkeyPatch, conclusion: str
) -> None:
    """Stop promotion for both failed and cancelled workflow conclusions.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing workflow polling.
        conclusion (str): Unsuccessful conclusion under test.
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
                "conclusion": conclusion,
            },
        ]
    )
    monkeypatch.setattr(verify, "github_api", lambda _arguments: next(responses))
    monkeypatch.setattr(verify.time, "monotonic", lambda: 0.0)

    with pytest.raises(verify.GitHubCommandError, match=f"{conclusion!r}"):
        verify.wait_for_workflow(
            REPOSITORY,
            "validate.yml",
            REF,
            SHA,
            set(),
            deadline=1.0,
            expected_run_id=42,
        )


def test_wait_for_workflow_times_out_with_bounded_polling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stop polling at the deadline when no matching run is returned.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing clock and polling.
    """
    sleeps: list[float] = []
    clock = iter([0.0, 1.0])
    responses = iter([{"id": 7}, verify.GitHubCommandError("404 Not Found")])

    def fake_api(_arguments: Sequence[str]) -> dict[str, Any]:
        response = next(responses)
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(verify, "github_api", fake_api)
    monkeypatch.setattr(verify.time, "monotonic", lambda: next(clock, 1.0))
    monkeypatch.setattr(verify.time, "sleep", sleeps.append)

    with pytest.raises(verify.GitHubCommandError, match="Timed out"):
        verify.wait_for_workflow(
            REPOSITORY,
            "validate.yml",
            REF,
            SHA,
            set(),
            deadline=1.0,
            expected_run_id=42,
        )

    assert sleeps == [5]


def test_wait_for_workflow_rejects_mismatched_authoritative_run_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a response whose ID does not equal the authoritative dispatch ID.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing workflow polling.
    """
    responses = iter(
        [
            {"id": 7},
            {
                "id": 41,
                "workflow_id": 7,
                "event": "workflow_dispatch",
                "head_branch": REF,
                "head_sha": SHA,
                "status": "completed",
                "conclusion": "success",
            },
        ]
    )
    monkeypatch.setattr(verify, "github_api", lambda _arguments: next(responses))
    monkeypatch.setattr(verify.time, "monotonic", lambda: 0.0)

    with pytest.raises(verify.GitHubCommandError, match="does not match"):
        verify.wait_for_workflow(
            REPOSITORY,
            "validate.yml",
            REF,
            SHA,
            set(),
            deadline=1.0,
            expected_run_id=42,
        )


@pytest.mark.parametrize(
    ("suite", "message"),
    [
        ({"head_sha": "b" * 40, "app": {"slug": "github-actions"}}, "check suite"),
        ({"head_sha": SHA, "app": {"slug": "other-app"}}, "check suite"),
        ({"head_sha": SHA}, "check suite"),
    ],
)
def test_verify_check_suite_requires_github_actions_source_and_sha(
    monkeypatch: pytest.MonkeyPatch,
    suite: dict[str, Any],
    message: str,
) -> None:
    """Accept only a GitHub Actions check suite attached to the candidate SHA.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing the API helper.
        suite (dict[str, Any]): Check-suite response fixture.
        message (str): Expected validation-error fragment.
    """
    monkeypatch.setattr(verify, "github_api", lambda _arguments: suite)

    with pytest.raises(verify.GitHubCommandError, match=message):
        verify.verify_check_suite(REPOSITORY, {"check_suite_id": 99}, SHA)


@pytest.mark.parametrize(
    ("required_checks", "jobs", "failed_category", "failed_name"),
    [
        ({"missing"}, [], "missing", "missing"),
        (
            {"duplicate"},
            [
                {"name": "duplicate", "conclusion": "success"},
                {"name": "duplicate", "conclusion": "success"},
                {"name": "unrelated", "conclusion": "failure"},
            ],
            "duplicate",
            "duplicate",
        ),
        (
            {"failed"},
            [
                {"name": "failed", "conclusion": "failure"},
                {"name": "unrelated", "conclusion": "success"},
            ],
            "unsuccessful",
            "failed",
        ),
    ],
)
def test_verify_jobs_reports_mutually_exclusive_fail_closed_categories(
    monkeypatch: pytest.MonkeyPatch,
    required_checks: set[str],
    jobs: list[dict[str, Any]],
    failed_category: str,
    failed_name: str,
) -> None:
    """Report missing, duplicate, and single unsuccessful jobs separately.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing the API helper.
        required_checks (set[str]): Required job names for the deterministic fixture.
        jobs (list[dict[str, Any]]): Workflow jobs returned by the API fixture.
        failed_category (str): Diagnostic category expected for the fixture.
        failed_name (str): Required job expected in that category.
    """
    monkeypatch.setattr(
        verify,
        "github_api",
        lambda _arguments: {"total_count": len(jobs), "jobs": jobs},
    )

    with pytest.raises(verify.GitHubCommandError) as error:
        verify.verify_jobs(REPOSITORY, 42, required_checks)

    message = str(error.value)
    assert f"{failed_category}=[{failed_name!r}]" in message
    for category in {"missing", "duplicate", "unsuccessful"} - {failed_category}:
        assert f"{category}=[]" in message


def test_parse_required_checks_groups_exact_names_and_rejects_malformed_values() -> None:
    """Group checks by workflow while retaining exact job-name boundaries."""
    values = [
        "pytest_check.yml::pytest check and post coverage",
        "uv-lock-check.yml::Validate uv lock consistency",
        "validate.yml::Hassfest Validation",
        "validate.yml::HACS Validation",
        f"{LINT_WORKFLOW}::review",
    ]
    checks = verify.parse_required_checks([*values, values[0]])

    expected_workflows = ["pytest_check.yml", "uv-lock-check.yml", "validate.yml", LINT_WORKFLOW]
    assert list(checks) == expected_workflows
    assert checks == {
        "pytest_check.yml": {"pytest check and post coverage"},
        "uv-lock-check.yml": {"Validate uv lock consistency"},
        "validate.yml": {"HACS Validation", "Hassfest Validation"},
        LINT_WORKFLOW: {"review"},
    }

    with pytest.raises(ValueError, match="workflow::exact job name"):
        verify.parse_required_checks(["validate.yml:HACS Validation"])


def test_main_dispatches_workflows_in_required_check_first_seen_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use the required-check manifest as the sole ordered workflow input.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing dispatch and polling helpers.
    """
    dispatches: list[str] = []
    waits: list[tuple[str, set[str], int]] = []

    def fake_dispatch(_repository: str, workflow: str, _ref: str, _sha: str) -> int:
        dispatches.append(workflow)
        return len(dispatches)

    def fake_wait(
        _repository: str,
        workflow: str,
        _ref: str,
        _sha: str,
        checks: set[str],
        _deadline: float,
        run_id: int,
    ) -> int:
        waits.append((workflow, checks, run_id))
        return run_id

    monkeypatch.setattr(verify, "dispatch_workflow", fake_dispatch)
    monkeypatch.setattr(verify, "wait_for_workflow", fake_wait)
    monkeypatch.setattr(verify.time, "monotonic", lambda: 100.0)
    values = _required_check_values()
    assert set(values) == {
        "pytest_check.yml::pytest check and post coverage",
        "uv-lock-check.yml::Validate uv lock consistency",
        "validate.yml::Hassfest Validation",
        "validate.yml::HACS Validation",
        f"{LINT_WORKFLOW}::review",
    }
    arguments: list[str] = [
        "verify_release_checks.py",
        "--repository",
        REPOSITORY,
        "--ref",
        REF,
        "--sha",
        SHA,
    ]
    for value in values:
        arguments.extend(["--required-check", value])
    monkeypatch.setattr(
        verify.sys,
        "argv",
        arguments,
    )

    assert verify.main() == 0
    assert dispatches == ["pytest_check.yml", "uv-lock-check.yml", "validate.yml", LINT_WORKFLOW]
    assert waits == [
        ("pytest_check.yml", {"pytest check and post coverage"}, 1),
        ("uv-lock-check.yml", {"Validate uv lock consistency"}, 2),
        ("validate.yml", {"HACS Validation", "Hassfest Validation"}, 3),
        (LINT_WORKFLOW, {"review"}, 4),
    ]


def test_github_api_fails_closed_for_unavailable_or_malformed_responses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject missing CLI, command errors, non-object JSON, and malformed JSON.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing CLI discovery and calls.
    """
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(verify.GitHubCommandError, match="unavailable"):
        verify.github_api([])

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/gh")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout="", stderr="API failed"),
    )
    with pytest.raises(verify.GitHubCommandError, match="API failed"):
        verify.github_api([])

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="[]", stderr=""),
    )
    with pytest.raises(verify.GitHubCommandError, match="not an object"):
        verify.github_api([])

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="{", stderr=""),
    )
    with pytest.raises(json.JSONDecodeError):
        verify.github_api([])


def test_github_api_uses_a_bounded_request_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bound each GitHub API request so network stalls cannot defeat polling bounds.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing CLI discovery and calls.
    """
    calls: list[dict[str, Any]] = []

    def fake_run(*_args: object, **kwargs: Any) -> SimpleNamespace:
        calls.append(kwargs)
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/gh")
    monkeypatch.setattr(subprocess, "run", fake_run)

    assert verify.github_api(["repos/example/repo"]) == {}
    assert len(calls) == 1
    assert calls[0]["timeout"] == 30
