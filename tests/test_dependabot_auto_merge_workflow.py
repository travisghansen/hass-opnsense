"""Executable behavior tests for Dependabot auto-merge authorization."""

import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any

import pytest
import yaml

AUTHORIZER = Path(__file__).parents[1] / ".github" / "scripts" / "dependabot-auto-merge.mjs"
WORKFLOW_ROOT = Path(__file__).parents[1] / ".github" / "workflows"
BASE_SHA = "4" * 40
DEPENDABOT_SHA = "1" * 40
FIRST_BASE_SHA = "2" * 40
FIRST_UPDATE_SHA = "3" * 40
HEAD_SHA = "5" * 40
REPOSITORY = "Snuffy2/hass-opnsense"
NODE = shutil.which("node")


def _event(
    action: str = "reopened", head_ref: str = "dependabot/uv/pytest-9.0.0"
) -> dict[str, Any]:
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
        "committer": {"login": "web-flow"},
        "parents": [],
        "sha": sha,
    }


def _update_commit(sha: str, previous: str, base: str) -> dict[str, Any]:
    """Build a verified GitHub Update branch merge commit.

    Args:
        sha (str): SHA of the merge commit.
        previous (str): SHA of the preceding pull-request commit.
        base (str): SHA of the base commit merged into the pull request.

    Returns:
        dict[str, Any]: Commit data for the current-base merge.
    """
    return {
        "author": {"login": "Snuffy2"},
        "commit": {"verification": {"verified": True}},
        "committer": {"login": "web-flow"},
        "parents": [{"sha": previous}, {"sha": base}],
        "sha": sha,
    }


def _ancestry_proof(parent_sha: str, status: str = "ahead") -> dict[str, Any]:
    """Build compare API evidence that a merge parent reaches the current base.

    Args:
        parent_sha (str): Merge second-parent SHA to compare against the current base.
        status (str): GitHub compare status for the parent/base pair.

    Returns:
        dict[str, Any]: Reduced compare API response used by the authorizer.
    """
    return {
        "ahead_by": 0 if status == "identical" else 1,
        "base_commit": parent_sha,
        "base_sha": BASE_SHA,
        "behind_by": 0,
        "head_commit": BASE_SHA,
        "merge_base_commit": parent_sha,
        "parent_sha": parent_sha,
        "status": status,
    }


def _update_chain() -> list[dict[str, Any]]:
    """Build a reopened Dependabot PR with two GitHub Update branch merges.

    Returns:
        list[dict[str, Any]]: Pull-request commits in API order.
    """
    return [
        _dependabot_commit(DEPENDABOT_SHA),
        _update_commit(FIRST_UPDATE_SHA, DEPENDABOT_SHA, FIRST_BASE_SHA),
        _update_commit(HEAD_SHA, FIRST_UPDATE_SHA, BASE_SHA),
    ]


def _update_chain_proofs() -> list[dict[str, Any]]:
    """Build compare evidence for every merge in :func:`_update_chain`.

    Returns:
        list[dict[str, Any]]: Reduced compare API responses in merge order.
    """
    return [_ancestry_proof(FIRST_BASE_SHA), _ancestry_proof(BASE_SHA, "identical")]


def _authorize(
    tmp_path: Path,
    *,
    ancestry_proofs: list[dict[str, Any]],
    changed_files: list[str],
    commits: list[dict[str, Any]],
    event: dict[str, Any],
    trusted_base_files: list[str],
) -> subprocess.CompletedProcess[str]:
    """Run the checked-in authorization command with API-shaped inputs.

    Args:
        tmp_path (Path): Trusted base checkout fixture directory.
        ancestry_proofs (list[dict[str, Any]]): Compare results for merge parents.
        changed_files (list[str]): Files reported by the pull-request API.
        commits (list[dict[str, Any]]): Commit pages returned by the API.
        event (dict[str, Any]): Pull-request event payload.
        trusted_base_files (list[str]): Files present in the trusted base checkout.

    Returns:
        subprocess.CompletedProcess[str]: Result from the authorizer process.

    Raises:
        RuntimeError: If Node.js is unavailable.
    """
    event_path = tmp_path / "event.json"
    changed_files_path = tmp_path / "changed-files"
    commits_path = tmp_path / "commits.json"
    ancestry_proofs_path = tmp_path / "ancestry-proofs.json"
    for trusted_base_file in trusted_base_files:
        trusted_path = tmp_path / trusted_base_file
        trusted_path.parent.mkdir(parents=True, exist_ok=True)
        trusted_path.write_text("fixture\n", encoding="utf-8")
    event_path.write_text(json.dumps(event), encoding="utf-8")
    changed_files_path.write_text("\n".join(changed_files), encoding="utf-8")
    commits_path.write_text(json.dumps([commits]), encoding="utf-8")
    ancestry_proofs_path.write_text(json.dumps(ancestry_proofs), encoding="utf-8")
    if NODE is None:
        raise RuntimeError("Node.js is required to run the Dependabot authorizer.")
    return subprocess.run(  # noqa: S603
        [
            NODE,
            str(AUTHORIZER),
            str(event_path),
            str(changed_files_path),
            str(commits_path),
            str(ancestry_proofs_path),
        ],
        check=False,
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize(
    ("head_ref", "trusted_base_files", "changed_files", "authorized"),
    [
        ("dependabot/uv/pytest-9.0.0", ["uv.lock"], ["uv.lock"], True),
        ("dependabot/uv/pytest-9.0.0", ["uv.lock"], ["pyproject.toml", "uv.lock"], False),
        (
            "dependabot/uv/pytest-9.0.0",
            ["package.json", "package-lock.json"],
            ["uv.lock"],
            False,
        ),
        (
            "dependabot/npm_and_yarn/pytest-9.0.0",
            ["package.json", "package-lock.json"],
            ["package-lock.json"],
            True,
        ),
        ("dependabot/npm_and_yarn/pytest-9.0.0", ["uv.lock"], ["package-lock.json"], False),
    ],
)
def test_authorization_derives_dependency_policy_from_the_trusted_base(
    tmp_path: Path,
    head_ref: str,
    trusted_base_files: list[str],
    changed_files: list[str],
    authorized: bool,
) -> None:
    """Authorize matching lockfile updates only when their trusted base uses that ecosystem.

    Args:
        tmp_path (Path): Trusted base checkout fixture directory.
        head_ref (str): Dependabot branch associated with the update.
        trusted_base_files (list[str]): Files in the trusted base checkout.
        changed_files (list[str]): Files reported by the pull-request API.
        authorized (bool): Whether the update should pass authorization.
    """
    result = _authorize(
        tmp_path,
        ancestry_proofs=[],
        changed_files=changed_files,
        commits=[_dependabot_commit()],
        event=_event("opened", head_ref),
        trusted_base_files=trusted_base_files,
    )

    assert (result.returncode == 0) is authorized


def test_authorization_accepts_reopened_verified_update_branch_history(tmp_path: Path) -> None:
    """Accept a reopened GitHub Update branch chain with complete ancestry evidence.

    Args:
        tmp_path (Path): Trusted base checkout fixture directory.
    """
    valid = _authorize(
        tmp_path,
        ancestry_proofs=_update_chain_proofs(),
        changed_files=["uv.lock"],
        commits=_update_chain(),
        event=_event(),
        trusted_base_files=["uv.lock"],
    )
    invalid = _authorize(
        tmp_path,
        ancestry_proofs=_update_chain_proofs(),
        changed_files=["uv.lock"],
        commits=[
            _dependabot_commit(DEPENDABOT_SHA, verified=False),
            _update_commit(HEAD_SHA, DEPENDABOT_SHA, BASE_SHA),
        ],
        event=_event(),
        trusted_base_files=["uv.lock"],
    )

    assert valid.returncode == 0
    assert invalid.returncode != 0


def test_authorization_accepts_a_direct_reopened_dependabot_update(tmp_path: Path) -> None:
    """Accept a verified one-commit Dependabot pull request after reopening.

    Args:
        tmp_path (Path): Trusted base checkout fixture directory.
    """
    result = _authorize(
        tmp_path,
        ancestry_proofs=[],
        changed_files=["uv.lock"],
        commits=[_dependabot_commit()],
        event=_event(),
        trusted_base_files=["uv.lock"],
    )

    assert result.returncode == 0


@pytest.mark.parametrize("is_update_branch", [False, True], ids=["direct", "update-branch"])
@pytest.mark.parametrize("committer", [None, "maintainer"], ids=["missing", "maintainer"])
def test_authorization_rejects_untrusted_dependabot_root_committer(
    tmp_path: Path, is_update_branch: bool, committer: str | None
) -> None:
    """Reject direct and reopened roots without a verified GitHub web-flow committer.

    Args:
        tmp_path (Path): Trusted base checkout fixture directory.
        is_update_branch (bool): Whether to exercise a GitHub Update branch chain.
        committer (str | None): Missing or untrusted root committer identity.
    """
    commits = _update_chain() if is_update_branch else [_dependabot_commit()]
    if committer is None:
        commits[0].pop("committer")
    else:
        commits[0]["committer"] = {"login": committer}
    result = _authorize(
        tmp_path,
        ancestry_proofs=_update_chain_proofs() if is_update_branch else [],
        changed_files=["uv.lock"],
        commits=commits,
        event=_event(),
        trusted_base_files=["uv.lock"],
    )

    assert result.returncode != 0


def test_authorization_rejects_invalid_dependabot_provenance(tmp_path: Path) -> None:
    """Reject forked, foreign-head, and non-default-base Dependabot pull requests.

    Args:
        tmp_path (Path): Trusted base checkout fixture directory.
    """
    fork = _event()
    fork["repository"]["fork"] = True
    foreign_head = _event()
    foreign_head["pull_request"]["head"]["repo"]["full_name"] = "fork/repository"
    non_default_base = _event()
    non_default_base["pull_request"]["base"]["ref"] = "release"
    for event in (fork, foreign_head, non_default_base):
        result = _authorize(
            tmp_path,
            ancestry_proofs=[],
            changed_files=["uv.lock"],
            commits=[_dependabot_commit()],
            event=event,
            trusted_base_files=["uv.lock"],
        )
        assert result.returncode != 0


def test_authorization_rejects_non_web_flow_update_merge(tmp_path: Path) -> None:
    """Reject a reopened update chain containing a maintainer-created merge.

    Args:
        tmp_path (Path): Trusted base checkout fixture directory.
    """
    commits = _update_chain()
    commits[1]["committer"] = {"login": "maintainer"}
    result = _authorize(
        tmp_path,
        ancestry_proofs=_update_chain_proofs(),
        changed_files=["uv.lock"],
        commits=commits,
        event=_event(),
        trusted_base_files=["uv.lock"],
    )

    assert result.returncode != 0


@pytest.mark.parametrize(
    "ancestry_proofs",
    [
        [],
        [{}, _ancestry_proof(BASE_SHA, "identical")],
        [_ancestry_proof(FIRST_BASE_SHA), _ancestry_proof("9" * 40)],
        [_ancestry_proof(FIRST_BASE_SHA, "diverged"), _ancestry_proof(BASE_SHA, "identical")],
        [
            {**_ancestry_proof(FIRST_BASE_SHA), "head_commit": "8" * 40},
            _ancestry_proof(BASE_SHA, "identical"),
        ],
    ],
)
def test_authorization_rejects_incomplete_or_invalid_merge_ancestry(
    tmp_path: Path, ancestry_proofs: list[dict[str, Any]]
) -> None:
    """Fail closed when any GitHub Update branch merge lacks current-base proof.

    Args:
        tmp_path (Path): Trusted base checkout fixture directory.
        ancestry_proofs (list[dict[str, Any]]): Invalid compare API evidence.
    """
    result = _authorize(
        tmp_path,
        ancestry_proofs=ancestry_proofs,
        changed_files=["uv.lock"],
        commits=_update_chain(),
        event=_event(),
        trusted_base_files=["uv.lock"],
    )

    assert result.returncode != 0


def test_authorization_requires_current_event_head_and_base(tmp_path: Path) -> None:
    """Reject stale merge-parent and direct-commit event state.

    Args:
        tmp_path (Path): Trusted base checkout fixture directory.
    """
    stale_parent_chain = _update_chain()
    stale_parent_chain[-1] = _update_commit(HEAD_SHA, FIRST_UPDATE_SHA, FIRST_BASE_SHA)
    for commits, proofs in [
        (stale_parent_chain, _update_chain_proofs()),
        ([_dependabot_commit(DEPENDABOT_SHA)], []),
    ]:
        result = _authorize(
            tmp_path,
            ancestry_proofs=proofs,
            changed_files=["uv.lock"],
            commits=commits,
            event=_event(),
            trusted_base_files=["uv.lock"],
        )
        assert result.returncode != 0


@pytest.mark.parametrize(
    ("changed_file", "trusted_base_files", "authorized"),
    [
        (".github/workflows/pytest_check.yml", [".github/workflows/pytest_check.yml"], True),
        ("actions/release/action.yaml", ["actions/release/action.yaml"], True),
        (".github/workflows/nested/unsafe.yml", [".github/workflows/nested/unsafe.yml"], False),
    ],
)
def test_actions_authorization_requires_trusted_allowed_files(
    tmp_path: Path, changed_file: str, trusted_base_files: list[str], authorized: bool
) -> None:
    """Authorize only trusted-base top-level workflows and action manifests.

    Args:
        tmp_path (Path): Trusted base checkout fixture directory.
        changed_file (str): File reported by the pull-request API.
        trusted_base_files (list[str]): Files in the trusted base checkout.
        authorized (bool): Whether the update should pass authorization.
    """
    result = _authorize(
        tmp_path,
        ancestry_proofs=[],
        changed_files=[changed_file],
        commits=[_dependabot_commit()],
        event=_event("opened", "dependabot/github_actions/actions/checkout-7"),
        trusted_base_files=trusted_base_files,
    )

    assert (result.returncode == 0) is authorized


def _load_workflow(name: str) -> dict[str, Any]:
    """Parse a checked-in GitHub Actions workflow into semantic YAML values.

    Args:
        name (str): Workflow filename.

    Returns:
        dict[str, Any]: Parsed workflow document.
    """
    document = yaml.safe_load((WORKFLOW_ROOT / name).read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the parsed workflow steps from a job.

    Args:
        job (dict[str, Any]): Parsed workflow job.

    Returns:
        list[dict[str, Any]]: Job steps.
    """
    steps = job["steps"]
    assert isinstance(steps, list)
    return steps


def _step_with_run(job: dict[str, Any], marker: str) -> dict[str, Any]:
    """Find a step by a required command fragment.

    Args:
        job (dict[str, Any]): Parsed workflow job.
        marker (str): Command fragment identifying the step.

    Returns:
        dict[str, Any]: Matching workflow step.
    """
    return next(step for step in _steps(job) if marker in str(step.get("run", "")))


def _step_with_major_action(job: dict[str, Any], action: str) -> dict[str, Any]:
    """Find a step that invokes an action through a major-version reference.

    Args:
        job (dict[str, Any]): Parsed workflow job.
        action (str): Action owner/name identifying the step.

    Returns:
        dict[str, Any]: Matching workflow step.
    """
    return next(
        step
        for step in _steps(job)
        if re.fullmatch(rf"{re.escape(action)}@v\d+(?:\.\d+)*", str(step.get("uses", "")))
    )


def _step_with_activity(job: dict[str, Any], activity: str) -> dict[str, Any]:
    """Find a coverage action step by its explicit activity.

    Args:
        job (dict[str, Any]): Parsed workflow job.
        activity (str): Coverage action activity value.

    Returns:
        dict[str, Any]: Matching coverage action step.
    """
    return next(
        step
        for step in _steps(job)
        if re.fullmatch(
            r"py-cov-action/python-coverage-comment-action@v\d+(?:\.\d+)*",
            str(step.get("uses", "")),
        )
        and step.get("with", {}).get("ACTIVITY") == activity
    )


def _job_with_run(document: dict[str, Any], marker: str) -> tuple[str, dict[str, Any]]:
    """Find a workflow job by a command capability.

    Args:
        document (dict[str, Any]): Parsed workflow document.
        marker (str): Command fragment identifying the job.

    Returns:
        tuple[str, dict[str, Any]]: Workflow job key and parsed job.
    """
    return next(
        (job_id, job)
        for job_id, job in document["jobs"].items()
        if any(marker in str(step.get("run", "")) for step in _steps(job))
    )


def _job_with_activity(document: dict[str, Any], activity: str) -> tuple[str, dict[str, Any]]:
    """Find a workflow job by a coverage action activity.

    Args:
        document (dict[str, Any]): Parsed workflow document.
        activity (str): Coverage action activity value.

    Returns:
        tuple[str, dict[str, Any]]: Workflow job key and parsed job.
    """
    return next(
        (job_id, job)
        for job_id, job in document["jobs"].items()
        if any(step.get("with", {}).get("ACTIVITY") == activity for step in _steps(job))
    )


def _assert_eligible_dependabot_condition(condition: object) -> None:
    """Assert the provenance constraints required before trusted authorization.

    Args:
        condition (object): Parsed GitHub Actions expression.
    """
    value = str(condition)
    for required_term in (
        "repository.fork == false",
        "pull_request.user.login == 'dependabot[bot]'",
        "pull_request.head.repo.full_name == github.repository",
        "pull_request.base.ref == github.event.repository.default_branch",
    ):
        assert required_term in value


def _assert_dependabot_author_condition(condition: object) -> None:
    """Assert that a workflow dispatches authorization for every Dependabot author.

    Args:
        condition (object): Parsed GitHub Actions expression.
    """
    value = str(condition)
    assert "pull_request.user.login == 'dependabot[bot]'" in value
    for disallowed_restriction in (
        "repository.fork == false",
        "pull_request.head.repo.full_name == github.repository",
        "pull_request.base.ref == github.event.repository.default_branch",
    ):
        assert disallowed_restriction not in value


def _assert_trusted_checkout_precedes_authorization(job: dict[str, Any]) -> None:
    """Assert that only the credential-free base checkout precedes the helper run.

    Args:
        job (dict[str, Any]): Parsed workflow job.
    """
    authorization_step = _step_with_run(job, "dependabot-auto-merge.mjs")
    authorization_index = _steps(job).index(authorization_step)
    checkout = next(
        step
        for step in _steps(job)[:authorization_index]
        if str(step.get("uses", "")).startswith("actions/checkout@")
        and step.get("with", {}).get("ref") == "${{ github.event.pull_request.base.sha }}"
    )
    assert checkout["with"]["persist-credentials"] is False


def _assert_current_base_evidence_collector(step: dict[str, Any]) -> None:
    """Assert that compare evidence receives the event base SHA through its environment.

    Args:
        step (dict[str, Any]): Authorization shell step from a parsed workflow.
    """
    assert step["env"]["BASE_SHA"] == "${{ github.event.pull_request.base.sha }}"
    run = step["run"]
    assert "compare/${second_parent}...${BASE_SHA}" in run
    assert '--arg base_sha "${BASE_SHA}"' in run
    assert 'base_sha="${{ github.event.pull_request.base.sha }}"' not in run


def test_dependabot_and_coverage_workflow_trust_contracts() -> None:
    """Keep authorization inputs read-only and coverage comments in the checkout-free writer.

    The assertions operate on parsed YAML structures and command dataflow, rather than
    source formatting or step labels, so they protect the trust boundary across harmless
    workflow cleanup.
    """
    auto_merge = _load_workflow("dependabot-auto-merge.yml")
    pytest_check = _load_workflow("pytest_check.yml")
    post_coverage = _load_workflow("pytest_post_coverage.yml")
    assert "concurrency" not in post_coverage
    authorization_id, authorization = _job_with_run(auto_merge, "dependabot-auto-merge.mjs")

    assert authorization["permissions"]["contents"] == "read"
    assert authorization["permissions"]["pull-requests"] == "read"
    _assert_dependabot_author_condition(authorization["if"])
    _assert_trusted_checkout_precedes_authorization(authorization)
    authorization_step = _step_with_run(authorization, "dependabot-auto-merge.mjs")
    authorization_run = authorization_step["run"]
    _assert_current_base_evidence_collector(authorization_step)
    for required_dataflow in (
        "pulls/${PR_NUMBER}/files",
        "pulls/${PR_NUMBER}/commits",
        "compare/",
        "ancestry_proofs",
    ):
        assert required_dataflow in authorization_run
    _, enable_auto_merge = _job_with_run(auto_merge, "gh pr merge --auto")
    assert enable_auto_merge["needs"] == authorization_id
    assert "if" not in enable_auto_merge
    assert enable_auto_merge["permissions"]["contents"] == "write"
    assert enable_auto_merge["permissions"]["pull-requests"] == "write"
    _, disable_auto_merge = _job_with_run(auto_merge, "gh pr merge --disable-auto")
    assert "failure()" in str(disable_auto_merge["if"])
    assert "!cancelled()" in str(disable_auto_merge["if"])
    _assert_eligible_dependabot_condition(disable_auto_merge["if"])
    for job in auto_merge["jobs"].values():
        permissions = job.get("permissions", {})
        if "write" in permissions.values():
            assert not any("actions/checkout@" in str(step.get("uses", "")) for step in _steps(job))

    _, tests = _job_with_activity(pytest_check, "process_pr")
    assert tests["permissions"]["contents"] == "read"
    assert tests["permissions"]["pull-requests"] == "read"
    trusted_checkout = _step_with_major_action(tests, "actions/checkout")
    trusted_checkout_with = trusted_checkout["with"]
    assert trusted_checkout_with["persist-credentials"] is False
    assert trusted_checkout_with["ref"] == "${{ github.event.pull_request.base.sha }}"
    authorizer = _step_with_run(tests, "dependabot-auto-merge.mjs")
    for step in (trusted_checkout, authorizer):
        condition = str(step["if"])
        assert "github.event_name == 'pull_request'" in condition
        assert "pull_request.user.login == 'dependabot[bot]'" in condition
        for disallowed_restriction in (
            "repository.fork == false",
            "pull_request.head.repo.full_name == github.repository",
            "pull_request.base.ref == github.event.repository.default_branch",
        ):
            assert disallowed_restriction not in condition
    _assert_trusted_checkout_precedes_authorization(tests)
    _assert_current_base_evidence_collector(authorizer)
    authorization_index = _steps(tests).index(authorizer)
    head_checkout_index = next(
        index
        for index, step in enumerate(_steps(tests))
        if re.fullmatch(r"actions/checkout@v\d+(?:\.\d+)*", str(step.get("uses", "")))
        and step.get("with", {}).get("ref") == "${{ inputs.expected_sha || github.sha }}"
    )
    assert head_checkout_index > authorization_index
    assert all(
        "write" not in permissions.values()
        for job in pytest_check["jobs"].values()
        for permissions in [job.get("permissions", {})]
    )
    coverage = _step_with_activity(tests, "process_pr")
    coverage_with = coverage["with"]
    assert coverage_with["GITHUB_TOKEN"] == "${{ secrets.GITHUB_TOKEN }}"
    assert coverage_with["ACTIVITY"] == "process_pr"
    assert coverage_with["MINIMUM_GREEN"] == 90
    assert coverage_with["MINIMUM_ORANGE"] == 70
    stored_coverage = next(
        step for step in _steps(tests) if step.get("with", {}).get("name") == "python-coverage-data"
    )
    assert re.fullmatch(r"actions/upload-artifact@v\d+(?:\.\d+)*", str(stored_coverage["uses"]))
    assert "github.event_name == 'push'" in str(stored_coverage["if"])
    stored_coverage_with = stored_coverage["with"]
    assert stored_coverage_with["name"] == "python-coverage-data"
    assert stored_coverage_with["path"] == ".coverage"
    assert stored_coverage_with["include-hidden-files"] is True
    assert stored_coverage_with["retention-days"] == 1

    _, post_job = _job_with_activity(post_coverage, "post_comment")
    assert post_job["permissions"]["pull-requests"] == "write"
    assert post_job["permissions"]["contents"] == "read"
    assert post_job["permissions"]["actions"] == "read"
    assert all(
        permission in {"actions", "contents", "pull-requests"}
        for permission in post_job["permissions"]
    )
    assert "concurrency" not in post_job
    assert "workflow_run.event == 'pull_request'" in str(post_job["if"])
    assert "workflow_run.conclusion == 'success'" in str(post_job["if"])
    assert not any(
        re.fullmatch(r"actions/checkout@v\d+(?:\.\d+)*", str(step.get("uses", "")))
        for step in _steps(post_job)
    )
    post = _step_with_activity(post_job, "post_comment")
    assert post["with"]["GITHUB_PR_RUN_ID"] == "${{ github.event.workflow_run.id }}"

    _, publisher = _job_with_activity(post_coverage, "save_coverage_data_files")
    assert publisher["permissions"]["actions"] == "read"
    assert publisher["permissions"]["contents"] == "write"
    assert all(permission in {"actions", "contents"} for permission in publisher["permissions"])
    for required_term in (
        "workflow_run.event == 'push'",
        "workflow_run.conclusion == 'success'",
        "workflow_run.head_branch == github.event.repository.default_branch",
        "workflow_run.head_repository.full_name == github.repository",
    ):
        assert required_term in str(publisher["if"])
    checkout = _step_with_major_action(publisher, "actions/checkout")
    checkout_with = checkout["with"]
    assert checkout_with["persist-credentials"] is False
    assert checkout_with["ref"] == "${{ github.event.repository.default_branch }}"
    verification = _step_with_run(publisher, "git rev-parse HEAD")
    assert verification["env"]["EXPECTED_SHA"] == "${{ github.event.workflow_run.head_sha }}"
    download = _step_with_major_action(publisher, "actions/download-artifact")
    download_with = download["with"]
    assert download_with["github-token"] == "${{ secrets.GITHUB_TOKEN }}"
    assert download_with["run-id"] == "${{ github.event.workflow_run.id }}"
    assert download_with["name"] == "python-coverage-data"
    assert download_with["path"] == "."
    publisher_concurrency = publisher["concurrency"]
    assert publisher_concurrency["cancel-in-progress"] is True
    assert "github.event.repository.default_branch" in str(publisher_concurrency["group"])
    assert (
        _steps(publisher).index(checkout)
        < _steps(publisher).index(verification)
        < _steps(publisher).index(download)
    )
    published_coverage = _step_with_activity(publisher, "save_coverage_data_files")
    assert published_coverage["with"]["MINIMUM_GREEN"] == 90
    assert published_coverage["with"]["MINIMUM_ORANGE"] == 70
