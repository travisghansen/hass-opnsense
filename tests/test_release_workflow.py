"""Tests for published-release workflow contracts."""

import os
from pathlib import Path
import shutil
import subprocess
from typing import Any

import pytest
import yaml

PROCESS_RUN = subprocess.run
WORKFLOW_ROOT = Path(__file__).parents[1] / ".github" / "workflows"
SCRIPT_PATH = Path(__file__).parents[1] / ".github" / "scripts" / "verify_release_checks.py"
LINT_WORKFLOW = (
    "prek-autofix-review.yml"
    if (WORKFLOW_ROOT / "prek-autofix-review.yml").exists()
    else "linters.yml"
)


def _load_workflow(name: str) -> dict[str, Any]:
    """Load one workflow with normalized trigger keys for semantic checks.

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


def _workflow_events(document: dict[str, Any]) -> dict[str, Any]:
    """Return the parsed workflow trigger map.

    Args:
        document (dict[str, Any]): Parsed workflow document.

    Returns:
        dict[str, Any]: Workflow event configuration.
    """
    events = document["on"]
    assert isinstance(events, dict)
    return events


def _named_steps(document: dict[str, Any], job_id: str) -> dict[str, dict[str, Any]]:
    """Index named steps for stable semantic assertions.

    Args:
        document (dict[str, Any]): Parsed workflow document.
        job_id (str): Workflow job identifier.

    Returns:
        dict[str, dict[str, Any]]: Named steps in the selected job.
    """
    job = document["jobs"][job_id]
    assert isinstance(job, dict)
    steps = job["steps"]
    assert isinstance(steps, list)
    return {step["name"]: step for step in steps if isinstance(step, dict) and "name" in step}


def _release_environment() -> dict[str, str]:
    """Read release fixture settings from the repository workflow.

    Returns:
        dict[str, str]: Environment values required by the extracted shell fixtures.
    """
    document = _load_workflow("release.yml")
    environment = document["jobs"]["release"]["env"]
    assert isinstance(environment, dict)
    return {
        "ARCHIVE_NAME": str(environment["ARCHIVE_NAME"]),
        "COMPONENT_PATH": str(environment["COMPONENT_PATH"]),
        "FIRMWARE_NOTES": str(environment["FIRMWARE_NOTES"]),
        "STABLE_TAG_PARTS": str(environment["STABLE_TAG_PARTS"]),
    }


def _git(repository: Path, *arguments: str) -> str:
    """Run one Git command in a temporary release-fixture repository.

    Args:
        repository (Path): Fixture repository.
        *arguments (str): Arguments following the Git executable.

    Returns:
        str: Standard output from the successful command.
    """
    return PROCESS_RUN(
        ["git", *arguments],
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
    PROCESS_RUN(
        ["git", "init", "--bare", str(remote)],
        check=True,
        capture_output=True,
    )
    _git(tmp_path, "init", "-b", "main", str(repository))
    _git(repository, "config", "user.name", "Release Test")
    _git(repository, "config", "user.email", "release-test@example.invalid")
    release_environment = _release_environment()
    component_path = release_environment["COMPONENT_PATH"]
    integration = repository / component_path
    integration.mkdir(parents=True)
    (integration / "manifest.json").write_text('{"version": "v0.0.0"}\n', encoding="utf-8")
    const = 'VERSION = "v0.0.0"\n'
    if release_environment["FIRMWARE_NOTES"] == "true":
        const += 'OPNSENSE_LTD_FIRMWARE = "26.1"\nOPNSENSE_MIN_FIRMWARE = "25.1"\n'
    (integration / "const.py").write_text(const, encoding="utf-8")
    helper = repository / ".github" / "scripts"
    helper.mkdir(parents=True)
    shutil.copy2(SCRIPT_PATH.parent / "prepare_release.py", helper / "prepare_release.py")
    shutil.copy2(SCRIPT_PATH.parent / "verify_hacs_archive.py", helper / "verify_hacs_archive.py")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "Initial component")
    _git(repository, "remote", "add", "origin", str(remote))
    _git(repository, "push", "-u", "origin", "main")
    (integration / "manifest.json").write_text(f'{{"version": "{tag}"}}\n', encoding="utf-8")
    const = f'VERSION = "{tag}"\n'
    if release_environment["FIRMWARE_NOTES"] == "true":
        const += 'OPNSENSE_LTD_FIRMWARE = "26.1"\nOPNSENSE_MIN_FIRMWARE = "25.1"\n'
    (integration / "const.py").write_text(const, encoding="utf-8")
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
    release_environment = _release_environment()
    workflow_environment = {
        **release_environment,
    }
    return PROCESS_RUN(
        ["bash", "-c", run],
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
    archive = tmp_path / _release_environment()["ARCHIVE_NAME"]
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


def test_release_workflow_has_published_trigger_and_stable_prerelease_split() -> None:
    """Keep release promotion event-driven with distinct stable and prerelease paths."""
    document = _load_workflow("release.yml")
    events = _workflow_events(document)
    assert events == {"release": {"types": ["published"]}}

    steps = _named_steps(document, "release")
    assert steps["Build prerelease archive without mutating refs"]["if"] == (
        "github.event.release.prerelease"
    )
    assert steps["Create deterministic stable release commit B"]["if"] == (
        "github.event.release.prerelease == false"
    )
    assert steps["Atomically advance target and guarded release tag"]["if"] == (
        "github.event.release.prerelease == false && steps.base.outputs.resume != 'true'"
    )

    dispatch_run = steps["Dispatch and verify immutable release gates"]["run"]
    assert "--workflow" not in dispatch_run
    assert '"${required_check_args[@]}"' in dispatch_run
    assert document["jobs"]["release"]["env"]["REQUIRED_CHECKS"].splitlines() == [
        "pytest_check.yml::pytest check and post coverage",
        "uv-lock-check.yml::Validate uv lock consistency",
        "validate.yml::Hassfest Validation",
        "validate.yml::HACS Validation",
        f"{LINT_WORKFLOW}::review",
    ]


def test_release_workflow_uses_guarded_atomic_promotion_and_resumable_cleanup() -> None:
    """Require guarded branch/tag promotion, explicit resume state, and cleanup on success."""
    document = _load_workflow("release.yml")
    steps = _named_steps(document, "release")
    promotion = steps["Atomically advance target and guarded release tag"]
    promotion_run = promotion["run"]
    assert "push --atomic" in promotion_run
    assert "refs/tags/$RELEASE_TAG:$ORIGINAL_TAG_OID" in promotion_run
    assert "refs/heads/$RELEASE_TARGET:$SOURCE_SHA" in promotion_run
    assert '[[ "$(git rev-parse HEAD^)" == "$SOURCE_SHA" ]]' in promotion_run
    assert 'git push origin "refs/tags/$RELEASE_TAG"' not in promotion_run
    assert '[[ "$(git rev-parse "refs/remotes/origin/$RELEASE_TARGET")" == "$SOURCE_SHA" ]]' in (
        promotion_run
    )

    candidate_run = steps["Create deterministic stable release commit B"]["run"]
    assert 'if [[ "$RESUME" == true ]]' in candidate_run
    assert 'echo "sha=$RESUME_SHA"' in candidate_run
    cleanup = steps["Delete validated temporary branch"]
    assert cleanup["if"] == "github.event.release.prerelease == false && success()"
    assert 'push --force-with-lease="refs/heads/$TEMP_REF:$CANDIDATE_SHA"' in cleanup["run"]


def test_release_workflow_trusts_only_default_branch_and_scopes_tokens() -> None:
    """Require default-target validation, credential-free checkout, and step-scoped tokens."""
    document = _load_workflow("release.yml")
    job = document["jobs"]["release"]
    assert job["permissions"] == {
        "actions": "write",
        "checks": "read",
        "contents": "write",
        "statuses": "read",
    }
    steps = _named_steps(document, "release")
    target = steps["Require the default-branch release target"]
    assert '"$RELEASE_TARGET" == "$DEFAULT_BRANCH"' in target["run"]
    assert target["env"] == {
        "DEFAULT_BRANCH": "${{ github.event.repository.default_branch }}",
        "RELEASE_TARGET": "${{ github.event.release.target_commitish }}",
    }
    checkout = steps["Checkout trusted default-branch workflow revision"]
    assert checkout["with"]["ref"] == "${{ github.event.repository.default_branch }}"
    assert checkout["with"]["persist-credentials"] is False

    token_steps = {
        name: step
        for name, step in steps.items()
        if name
        in {
            "Publish B to an isolated validation branch",
            "Dispatch and verify immutable release gates",
            "Atomically advance target and guarded release tag",
            "Verify release identity and upload verified archive",
            "Verify prerelease identity and upload archive",
            "Delete validated temporary branch",
        }
    }
    for step in token_steps.values():
        assert step["env"]["GH_TOKEN"] == "${{ github.token }}"


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
        assert "gh auth setup-git --hostname github.com" in step["run"]


@pytest.mark.parametrize(
    "workflow_name",
    ["pytest_check.yml", "uv-lock-check.yml", "validate.yml", LINT_WORKFLOW],
)
def test_release_dispatch_guards_require_lowercase_sha_and_match_workflow_sha(
    workflow_name: str,
) -> None:
    """Validate the exact lowercase 40-hex guard used for release dispatches.

    Args:
        workflow_name (str): Workflow filename under test.
    """
    document = _load_workflow(workflow_name)
    required_names = {
        value.partition("::")[2]
        for value in _load_workflow("release.yml")["jobs"]["release"]["env"][
            "REQUIRED_CHECKS"
        ].splitlines()
        if value.partition("::")[0] == workflow_name
    }
    candidate_jobs = [
        (job_id, job)
        for job_id, job in document["jobs"].items()
        if isinstance(job, dict) and job.get("name", job_id) in required_names
    ]
    assert {job.get("name", job_id) for job_id, job in candidate_jobs} == required_names
    for _job_id, job in candidate_jobs:
        steps = job["steps"]
        guard = next(
            step
            for step in steps
            if isinstance(step, dict) and step.get("name") == "Require expected release commit"
        )
        assert guard["run"] == (
            '[[ "$EXPECTED_SHA" =~ ^[0-9a-f]{40}$ ]]\ntest "$WORKFLOW_SHA" = "$EXPECTED_SHA"\n'
        )
        assert guard["env"]["EXPECTED_SHA"] == "${{ inputs.expected_sha }}"
        assert guard["env"]["WORKFLOW_SHA"] == "${{ github.sha }}"


def test_dispatch_pytest_job_is_read_only_and_preserves_required_check_name() -> None:
    """Run release-dispatched pytest with read-only contents and the required job name."""
    document = _load_workflow("pytest_check.yml")
    pytest_job = next(
        job
        for job in document["jobs"].values()
        if isinstance(job, dict) and job.get("name") == "pytest check and post coverage"
    )
    assert pytest_job["permissions"]["contents"] == "read"
    assert pytest_job["name"] == "pytest check and post coverage"
    assert (
        _workflow_events(document)["workflow_dispatch"]["inputs"]["expected_sha"]["required"]
        is True
    )
    pytest_run = next(
        step
        for step in pytest_job["steps"]
        if "uv run --locked --group pytest pytest" in step.get("run", "")
    )
    assert "uv run --locked --group pytest pytest" in pytest_run["run"]
    checkout = next(
        step
        for step in pytest_job["steps"]
        if (
            isinstance(step, dict)
            and str(step.get("uses", "")).startswith("actions/checkout@v")
            and "inputs.expected_sha" in step.get("with", {}).get("ref", "")
        )
    )
    assert checkout["with"]["persist-credentials"] is False


@pytest.mark.parametrize(
    "workflow_name",
    ["validate.yml", "pytest_check.yml", LINT_WORKFLOW],
)
def test_release_gate_workflows_retain_normal_triggers_and_expected_sha_dispatch(
    workflow_name: str,
) -> None:
    """Keep PR/push validation while allowing release dispatches to pin one SHA.

    Args:
        workflow_name (str): Workflow filename under test.
    """
    document = _load_workflow(workflow_name)
    events = _workflow_events(document)
    assert "pull_request" in events
    dispatch = events["workflow_dispatch"]
    assert dispatch["inputs"]["expected_sha"]["required"] is True

    jobs = document["jobs"]
    assert isinstance(jobs, dict)
    guarded_jobs = []
    for job in jobs.values():
        assert isinstance(job, dict)
        steps = job["steps"]
        has_guard = any(
            isinstance(step, dict)
            and '[[ "$EXPECTED_SHA" =~ ^[0-9a-f]{40}$ ]]' in step.get("run", "")
            for step in steps
        )
        if has_guard:
            guarded_jobs.append(job)
    assert guarded_jobs
    for job in guarded_jobs:
        checkout = next(
            step
            for step in job["steps"]
            if isinstance(step, dict)
            and str(step.get("uses", "")).startswith("actions/checkout@v")
            and "inputs.expected_sha || github.sha" in step.get("with", {}).get("ref", "")
        )
        assert checkout["with"]["persist-credentials"] is False
