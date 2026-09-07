"""Tests for immutable release-check verification and workflow contracts."""

from collections.abc import Sequence
import importlib.util
import json
import os
from pathlib import Path
import re
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


def _git(repository: Path, *arguments: str) -> str:
    """Run one Git command in a temporary release-fixture repository.

    Args:
        repository (Path): Fixture repository.
        *arguments (str): Arguments following the Git executable.

    Returns:
        str: Standard output from the successful command.
    """
    return subprocess.run(  # noqa: S603 -- test arguments are fixed by fixture helpers.
        ["git", *arguments],  # noqa: S607 -- Git is the fixed test executable.
        check=True,
        cwd=repository,
        text=True,
        capture_output=True,
    ).stdout.strip()


def _release_fixture(tmp_path: Path, tag: str) -> tuple[Path, str, str]:
    """Create a pushed tag whose release-subject commit also changes a third path.

    Args:
        tmp_path (Path): Pytest temporary directory.
        tag (str): Release tag used by the fixture.

    Returns:
        tuple[Path, str, str]: Repository, tagged source SHA, and annotated tag OID.
    """
    remote = tmp_path / "remote.git"
    repository = tmp_path / "repository"
    subprocess.run(  # noqa: S603 -- test-only fixture repository initialization.
        ["git", "init", "--bare", str(remote)],  # noqa: S607 -- test fixture executable.
        check=True,
        capture_output=True,
    )
    _git(tmp_path, "init", "-b", "main", str(repository))
    _git(repository, "config", "user.name", "Release Test")
    _git(repository, "config", "user.email", "release-test@example.invalid")
    integration = repository / "custom_components" / "opnsense"
    integration.mkdir(parents=True)
    (integration / "manifest.json").write_text('{"version": "v0.0.0"}\n', encoding="utf-8")
    (integration / "const.py").write_text(
        'VERSION = "v0.0.0"\nOPNSENSE_LTD_FIRMWARE = "26.1"\nOPNSENSE_MIN_FIRMWARE = "25.1"\n',
        encoding="utf-8",
    )
    helper = repository / ".github" / "scripts"
    helper.mkdir(parents=True)
    shutil.copy2(SCRIPT_PATH.parent / "prepare_release.py", helper / "prepare_release.py")
    shutil.copy2(SCRIPT_PATH.parent / "verify_hacs_archive.py", helper / "verify_hacs_archive.py")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "Initial component")
    _git(repository, "remote", "add", "origin", str(remote))
    _git(repository, "push", "-u", "origin", "main")
    (integration / "manifest.json").write_text(f'{{"version": "{tag}"}}\n', encoding="utf-8")
    (integration / "const.py").write_text(
        f'VERSION = "{tag}"\nOPNSENSE_LTD_FIRMWARE = "26.1"\nOPNSENSE_MIN_FIRMWARE = "25.1"\n',
        encoding="utf-8",
    )
    (repository / "release-notes.txt").write_text("third changed path\n", encoding="utf-8")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", f"Release {tag}")
    source_sha = _git(repository, "rev-parse", "HEAD")
    _git(repository, "tag", "-a", tag, "-m", tag)
    tag_oid = _git(repository, "rev-parse", f"refs/tags/{tag}")
    _git(repository, "push", "origin", "main", tag)
    return repository, source_sha, tag_oid


def _run_workflow_shell(
    repository: Path, run: str, environment: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    """Run an extracted workflow shell block in a release fixture.

    Args:
        repository (Path): Fixture repository.
        run (str): Workflow step shell content.
        environment (dict[str, str]): Step-specific environment values.

    Returns:
        subprocess.CompletedProcess[str]: The completed workflow shell process.
    """
    component = next(
        path.name for path in (repository / "custom_components").iterdir() if path.is_dir()
    )
    workflow_environment = {
        "ARCHIVE_NAME": f"{component}.zip",
        "COMPONENT_PATH": f"custom_components/{component}",
        "FIRMWARE_NOTES": str(component == "opnsense").lower(),
        "STABLE_TAG_PARTS": "2,3,4",
    }
    return subprocess.run(  # noqa: S603 -- extracted trusted workflow shell is under test.
        ["bash", "-c", run],  # noqa: S607 -- test shell for extracted workflow source.
        cwd=repository,
        env={**os.environ, **workflow_environment, **environment},
        text=True,
        capture_output=True,
        check=False,
    )


def _stub_gh(tmp_path: Path) -> tuple[Path, Path]:
    """Create a deterministic GitHub CLI stub that records release mutations.

    Args:
        tmp_path (Path): Pytest temporary directory.

    Returns:
        tuple[Path, Path]: Stub binary directory and its command log path.
    """
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    log_path = tmp_path / "gh.log"
    gh = binary_dir / "gh"
    gh.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        'printf "%s\\n" "$*" >> "$GH_LOG"\n'
        'if [[ "$1 $2" == "release view" ]]; then\n'
        '  printf "%s" "${GH_RELEASE_BODY:-}"\n'
        "fi\n",
        encoding="utf-8",
    )
    gh.chmod(0o755)
    return binary_dir, log_path


def test_prerelease_release_subject_with_extra_path_reaches_archive_upload(tmp_path: Path) -> None:
    """Keep archive-only prereleases outside stable resume provenance validation.

    Args:
        tmp_path (Path): Temporary fixture directory.
    """
    tag = "v1.2.3-beta.1"
    repository, source_sha, tag_oid = _release_fixture(tmp_path, tag)
    steps = _named_steps(_load_workflow("release.yml"), "release")
    output = tmp_path / "base-output"
    base = _run_workflow_shell(
        repository,
        steps["Validate trusted release metadata and immutable starting refs"]["run"],
        {
            "GITHUB_OUTPUT": str(output),
            "IS_PRERELEASE": "true",
            "RELEASE_TAG": tag,
            "RELEASE_TARGET": "main",
        },
    )

    assert base.returncode == 0, base.stderr
    assert "resume=false" in output.read_text(encoding="utf-8")
    binary_dir, log_path = _stub_gh(tmp_path)
    archive = tmp_path / "opnsense.zip"
    prerelease = _run_workflow_shell(
        repository,
        steps["Build prerelease archive without mutating refs"]["run"],
        {
            "GH_LOG": str(log_path),
            "GH_TOKEN": "test-token",
            "PATH": f"{binary_dir}:{os.environ['PATH']}",
            "RELEASE_ARCHIVE": str(archive),
            "RELEASE_TAG": tag,
            "RELEASE_TARGET": "main",
            "SOURCE_SHA": source_sha,
            "TAG_OID": tag_oid,
        },
    )

    assert prerelease.returncode == 0, prerelease.stderr
    assert archive.is_file()
    upload = _run_workflow_shell(
        repository,
        steps["Verify prerelease identity and upload archive"]["run"],
        {
            "GH_LOG": str(log_path),
            "GH_TOKEN": "test-token",
            "PATH": f"{binary_dir}:{os.environ['PATH']}",
            "RELEASE_ARCHIVE": str(archive),
            "RELEASE_TAG": tag,
            "RELEASE_TARGET": "main",
            "SOURCE_SHA": source_sha,
            "TAG_OID": tag_oid,
        },
    )
    assert upload.returncode == 0, upload.stderr
    assert "release upload" in log_path.read_text(encoding="utf-8")


def test_stable_release_subject_with_extra_path_rejects_invalid_resume(tmp_path: Path) -> None:
    """Reject stable retry candidates whose version transform changed a third path.

    Args:
        tmp_path (Path): Temporary fixture directory.
    """
    tag = "v1.2.3"
    repository, _source_sha, _tag_oid = _release_fixture(tmp_path, tag)
    output = tmp_path / "base-output"
    base = _run_workflow_shell(
        repository,
        _named_steps(_load_workflow("release.yml"), "release")[
            "Validate trusted release metadata and immutable starting refs"
        ]["run"],
        {
            "GITHUB_OUTPUT": str(output),
            "IS_PRERELEASE": "false",
            "RELEASE_TAG": tag,
            "RELEASE_TARGET": "main",
        },
    )

    assert base.returncode != 0
    assert "invalid release contents" in base.stderr


def test_prerelease_ref_mismatch_does_not_edit_or_upload_release(tmp_path: Path) -> None:
    """Fail before any GitHub release mutation when the source branch advances.

    Args:
        tmp_path (Path): Temporary fixture directory.
    """
    tag = "v1.2.3-beta.1"
    repository, source_sha, tag_oid = _release_fixture(tmp_path, tag)
    (repository / "advanced.txt").write_text("moved branch\n", encoding="utf-8")
    _git(repository, "add", "advanced.txt")
    _git(repository, "commit", "-m", "Advance main")
    _git(repository, "push", "origin", "HEAD:main")
    _git(repository, "checkout", "--detach", source_sha)
    binary_dir, log_path = _stub_gh(tmp_path)
    archive = tmp_path / "opnsense.zip"
    prerelease = _run_workflow_shell(
        repository,
        _named_steps(_load_workflow("release.yml"), "release")[
            "Verify prerelease identity and upload archive"
        ]["run"],
        {
            "GH_LOG": str(log_path),
            "GH_TOKEN": "test-token",
            "PATH": f"{binary_dir}:{os.environ['PATH']}",
            "RELEASE_ARCHIVE": str(archive),
            "RELEASE_TAG": tag,
            "RELEASE_TARGET": "main",
            "SOURCE_SHA": source_sha,
            "TAG_OID": tag_oid,
        },
    )

    assert prerelease.returncode != 0
    assert not log_path.exists()


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

    with pytest.raises(verify.GitHubCommandError):
        verify.dispatch_workflow(REPOSITORY, "validate.yml", REF, SHA)


def test_parse_required_checks_derives_workflows_in_first_seen_order() -> None:
    """Group required jobs while preserving workflow dispatch order."""
    checks = verify.parse_required_checks(
        [
            "pytest_check.yml::pytest and coverage report",
            "validate.yml::HACS Validation",
            "validate.yml::Hassfest Validation",
            "pytest_check.yml::pytest and coverage report",
        ]
    )

    assert list(checks) == ["pytest_check.yml", "validate.yml"]
    assert checks == {
        "pytest_check.yml": {"pytest and coverage report"},
        "validate.yml": {"HACS Validation", "Hassfest Validation"},
    }


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


def test_wait_for_workflow_retries_a_transient_run_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retry a transient run lookup failure before verifying its completed checks.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing API and time helpers.
    """
    responses: list[dict[str, Any] | RuntimeError] = [
        {"id": 7},
        verify.GitHubCommandError("HTTP 404 Not Found"),
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
    sleeps: list[int] = []

    def fake_api(_arguments: Sequence[str]) -> dict[str, Any]:
        """Return the next scripted API response.

        Args:
            _arguments (Sequence[str]): API request arguments, unused by this scripted response.

        Returns:
            dict[str, Any]: The scripted API response.

        Raises:
            verify.GitHubCommandError: When simulating a transient run lookup failure.
        """
        response = responses.pop(0)
        if isinstance(response, RuntimeError):
            raise verify.GitHubCommandError(str(response))
        return response

    monkeypatch.setattr(verify, "github_api", fake_api)
    monkeypatch.setattr(verify.time, "monotonic", lambda: 0.0)
    monkeypatch.setattr(verify.time, "sleep", sleeps.append)

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
    assert any(delay > 0 for delay in sleeps)


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

    with pytest.raises(verify.GitHubCommandError):
        verify.wait_for_workflow(
            REPOSITORY, "validate.yml", REF, SHA, set(), deadline=1.0, expected_run_id=42
        )


def test_verify_jobs_rejects_incomplete_required_check_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject required checks unless every requested job has one successful result.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing the API helper.
    """
    monkeypatch.setattr(
        verify,
        "github_api",
        lambda _arguments: {
            "total_count": 4,
            "jobs": [
                {"name": "required", "conclusion": "success"},
                {"name": "duplicate", "conclusion": "success"},
                {"name": "duplicate", "conclusion": "success"},
                {"name": "failed", "conclusion": "failure"},
            ],
        },
    )

    with pytest.raises(verify.GitHubCommandError):
        verify.verify_jobs(REPOSITORY, 42, {"required", "duplicate", "failed", "missing"})


def test_github_api_rejects_malformed_or_non_authoritative_http_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail closed for absent CLI, malformed JSON, and wrong dispatch status.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing CLI discovery and execution.
    """
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(verify.GitHubCommandError):
        verify.github_api([])

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/gh")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout="HTTP/2 204 No Content\n\n", stderr=""
        ),
    )
    with pytest.raises(verify.GitHubCommandError):
        verify.github_api([], expected_status=200)

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="{", stderr=""),
    )
    with pytest.raises(json.JSONDecodeError):
        verify.github_api([])


def test_verify_check_suite_rejects_mismatched_candidate_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a check suite that is tied to a different candidate commit.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing the API helper.
    """
    monkeypatch.setattr(
        verify,
        "github_api",
        lambda _arguments: {"head_sha": "b" * 40, "app": {"slug": "github-actions"}},
    )

    with pytest.raises(verify.GitHubCommandError):
        verify.verify_check_suite(REPOSITORY, {"check_suite_id": 99}, SHA)


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
    assert "--workflow" not in dispatch
    assert '"${required_check_args[@]}"' in dispatch
    assert job["env"]["REQUIRED_CHECKS"].splitlines() == [
        "linters.yml::Run Linters",
        "pytest_check.yml::pytest and coverage report",
        "validate.yml::Hassfest Validation",
        "validate.yml::HACS Validation",
    ]
    promotion = steps["Atomically advance target and guarded release tag"]["run"]
    assert "push --atomic" in promotion
    assert "refs/heads/$RELEASE_TARGET:$SOURCE_SHA" in promotion
    assert "refs/tags/$RELEASE_TAG:$ORIGINAL_TAG_OID" in promotion
    upload = steps["Verify release identity and upload verified archive"]["run"]
    assert '"$RELEASE_ARCHIVE#$ARCHIVE_NAME"' in upload
    assert "opnsense-firmware-compatibility" in upload
    assert steps["Delete validated temporary branch"]["if"] == (
        "github.event.release.prerelease == false && success()"
    )


def test_release_workflow_uses_scoped_github_cli_credentials_for_git_pushes() -> None:
    """Authenticate release pushes without persisting checkout credentials."""
    document = _load_workflow("release.yml")
    steps = _named_steps(document, "release")
    push_step_names = (
        "Publish B to an isolated validation branch",
        "Atomically advance target and guarded release tag",
        "Delete validated temporary branch",
    )

    for step_name in push_step_names:
        step = steps[step_name]
        assert step["env"]["GH_TOKEN"] == "${{ github.token }}"
        assert "extraheader" not in step["run"].lower()

    assert "gh auth setup-git" in steps["Publish B to an isolated validation branch"]["run"]


def test_release_workflow_preserves_resume_wiring_for_validated_release_commit() -> None:
    """Preserve resume wiring for a previously validated stable release commit."""
    document = _load_workflow("release.yml")
    steps = _named_steps(document, "release")
    base = steps["Validate trusted release metadata and immutable starting refs"]
    candidate = steps["Create deterministic stable release commit B"]
    promotion = steps["Atomically advance target and guarded release tag"]

    assert re.search(
        r'echo\s+"candidate-sha=\$target_sha"\s*>>\s*"\$GITHUB_OUTPUT"',
        base["run"],
        re.DOTALL,
    )
    assert candidate["env"]["RESUME"] == "${{ steps.base.outputs.resume }}"
    assert candidate["env"]["RESUME_SHA"] == "${{ steps.base.outputs.candidate-sha }}"
    candidate_run = candidate["run"]
    assert re.search(
        r'if\s+\[\[\s*"\$RESUME"\s*==\s*true\s*\]\]\s*;\s*then.*?'
        r'echo\s+"sha=\$RESUME_SHA"\s*>>\s*"\$GITHUB_OUTPUT".*?exit\s+0\b',
        candidate_run,
        re.DOTALL,
    )
    promotion_if = promotion["if"]
    assert "github.event.release.prerelease == false" in promotion_if
    assert "steps.base.outputs.resume != 'true'" in promotion_if


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
        guard_run = guard["run"]
        assert re.search(
            r'\[\[\s*"\$EXPECTED_SHA"\s*=~\s*\^\[0-9a-f\]\{40\}\$\s*\]\]',
            guard_run,
            re.DOTALL,
        )
        assert re.search(
            r'test\s+"\$WORKFLOW_SHA"\s*=\s*"\$EXPECTED_SHA"',
            guard_run,
            re.DOTALL,
        )
        checkout = next(
            step
            for step in steps.values()
            if isinstance(step.get("uses"), str)
            and step["uses"].split("@", 1)[0] == "actions/checkout"
            and step.get("with", {}).get("ref") == "${{ inputs.expected_sha || github.sha }}"
        )
        assert checkout["with"]["persist-credentials"] is False

    if workflow == "pytest_check.yml":
        assert document["jobs"]["tests"]["permissions"] == {
            "contents": "read",
            "pull-requests": "read",
        }
