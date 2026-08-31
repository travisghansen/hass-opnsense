"""Dispatch and verify release-gate workflows for one immutable commit."""

from __future__ import annotations

import argparse
from collections import defaultdict
from collections.abc import Sequence
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any


class GitHubCommandError(RuntimeError):
    """Raised when a GitHub CLI request fails."""


def github_api(arguments: Sequence[str], expected_status: int | None = None) -> dict[str, Any]:
    """Run a GitHub API request and parse its JSON response.

    Args:
        arguments: GitHub CLI API arguments.
        expected_status: Optional required HTTP response status.

    Returns:
        Parsed JSON object response.

    Raises:
        GitHubCommandError: If the CLI, response status, or response shape is invalid.
    """
    executable = shutil.which("gh")
    if executable is None:
        raise GitHubCommandError("GitHub CLI executable is unavailable.")
    try:
        result = subprocess.run(  # noqa: S603 -- API arguments are constructed internally.
            [str(Path(executable)), "api", *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired as error:
        raise GitHubCommandError(f"GitHub API request timed out: {error.cmd!r}") from error
    if result.returncode != 0:
        raise GitHubCommandError(result.stderr.strip() or result.stdout.strip())
    output = result.stdout
    if expected_status is not None:
        header, separator, output = output.replace("\r\n", "\n").partition("\n\n")
        status_line = header.splitlines()[0] if header else ""
        status_parts = status_line.split(maxsplit=2)
        if not separator or len(status_parts) < 2 or status_parts[1] != str(expected_status):
            raise GitHubCommandError(
                f"GitHub API returned an unexpected HTTP response: {header!r}."
            )
    if not output.strip():
        return {}
    payload = json.loads(output)
    if not isinstance(payload, dict):
        raise GitHubCommandError("GitHub API response was not an object.")
    return payload


def dispatch_workflow(repository: str, workflow: str, ref: str, sha: str) -> int:
    """Dispatch one workflow for the validated temporary branch.

    Args:
        repository: GitHub owner and repository name.
        workflow: Workflow filename.
        ref: Temporary branch containing the candidate.
        sha: Candidate commit SHA.

    Returns:
        The authoritative workflow run ID returned by GitHub.

    Raises:
        GitHubCommandError: If GitHub does not return a valid run ID.
    """
    response = github_api(
        [
            "--include",
            "--method",
            "POST",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "X-GitHub-Api-Version: 2026-03-10",
            f"repos/{repository}/actions/workflows/{workflow}/dispatches",
            "-f",
            f"ref={ref}",
            "-f",
            f"inputs[expected_sha]={sha}",
        ],
        expected_status=200,
    )
    run_id = response.get("workflow_run_id")
    if type(run_id) is not int or run_id <= 0:
        raise GitHubCommandError("Dispatch response did not contain a valid workflow_run_id.")
    return run_id


def verify_check_suite(repository: str, run: dict[str, Any], sha: str) -> None:
    """Require the workflow run's GitHub Actions check suite to use the candidate SHA."""
    suite_id = run.get("check_suite_id")
    if not isinstance(suite_id, int):
        raise GitHubCommandError("Workflow run did not expose a check suite ID.")
    suite = github_api([f"repos/{repository}/check-suites/{suite_id}"])
    app = suite.get("app")
    if (
        suite.get("head_sha") != sha
        or not isinstance(app, dict)
        or app.get("slug") != "github-actions"
    ):
        raise GitHubCommandError("Workflow run is not a GitHub Actions check suite for B.")


def verify_jobs(repository: str, run_id: int, required_checks: set[str]) -> None:
    """Require every named job to have passed in the selected workflow run."""
    payload = github_api([f"repos/{repository}/actions/runs/{run_id}/jobs?per_page=100"])
    jobs = payload.get("jobs", [])
    total_count = payload.get("total_count")
    if not isinstance(jobs, list) or not isinstance(total_count, int) or total_count > len(jobs):
        raise GitHubCommandError("Workflow job list was truncated or unverifiable.")
    outcomes: dict[str, list[Any]] = defaultdict(list)
    for job in jobs:
        if isinstance(job, dict) and isinstance(job.get("name"), str):
            outcomes[job["name"]].append(job.get("conclusion"))
    missing = sorted(required_checks - outcomes.keys())
    duplicate = sorted(name for name in required_checks if len(outcomes.get(name, [])) != 1)
    failed = sorted(name for name in required_checks if outcomes.get(name) != ["success"])
    if missing or duplicate or failed:
        raise GitHubCommandError(
            "Required checks "
            f"missing={missing!r}, duplicate={duplicate!r}, unsuccessful={failed!r}."
        )


def wait_for_workflow(
    repository: str,
    workflow: str,
    ref: str,
    sha: str,
    required_checks: set[str],
    deadline: float,
    expected_run_id: int,
) -> int:
    """Wait for a dispatched workflow and verify its completed checks."""
    metadata = github_api([f"repos/{repository}/actions/workflows/{workflow}"])
    workflow_id = metadata.get("id")
    if not isinstance(workflow_id, int):
        raise GitHubCommandError(f"Workflow {workflow!r} has no numeric ID.")
    while time.monotonic() < deadline:
        try:
            run = github_api([f"repos/{repository}/actions/runs/{expected_run_id}"])
        except GitHubCommandError as error:
            if "404" not in str(error):
                raise
            time.sleep(5)
            continue
        if run.get("id") != expected_run_id:
            raise GitHubCommandError("Workflow run ID does not match the dispatch response.")
        if (
            run.get("workflow_id") != workflow_id
            or run.get("event") != "workflow_dispatch"
            or run.get("head_branch") != ref
            or run.get("head_sha") != sha
        ):
            raise GitHubCommandError("Workflow run does not match the dispatched identity.")
        if run.get("status") != "completed":
            time.sleep(10)
            continue
        if run.get("conclusion") != "success":
            raise GitHubCommandError(
                f"Workflow {workflow!r} run {expected_run_id} concluded {run.get('conclusion')!r}."
            )
        verify_check_suite(repository, run, sha)
        verify_jobs(repository, expected_run_id, required_checks)
        return expected_run_id
    raise GitHubCommandError(f"Timed out waiting for workflow {workflow!r}.")


def parse_required_checks(values: Sequence[str]) -> dict[str, set[str]]:
    """Group exact required check names by workflow filename."""
    checks: dict[str, set[str]] = defaultdict(set)
    for value in values:
        workflow, separator, check = value.partition("::")
        if not separator or not workflow or not check:
            raise ValueError("Required checks must use workflow::exact job name.")
        checks[workflow].add(check)
    return checks


def main() -> int:
    """Dispatch and verify all supplied workflows for one candidate commit."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--workflow", action="append", required=True)
    parser.add_argument("--required-check", action="append", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    args = parser.parse_args()
    try:
        checks = parse_required_checks(args.required_check)
        workflows = list(dict.fromkeys(args.workflow))
        if set(workflows) != checks.keys():
            raise ValueError("Every workflow must have exact required checks and vice versa.")
        if args.timeout_seconds <= 0:
            raise ValueError("timeout-seconds must be positive.")
        dispatched = {
            workflow: dispatch_workflow(args.repository, workflow, args.ref, args.sha)
            for workflow in workflows
        }
        deadline = time.monotonic() + args.timeout_seconds
        for workflow in workflows:
            run_id = wait_for_workflow(
                args.repository,
                workflow,
                args.ref,
                args.sha,
                checks[workflow],
                deadline,
                dispatched[workflow],
            )
            sys.stdout.write(f"Verified {workflow} run {run_id} for {args.sha}.\n")
    except (GitHubCommandError, ValueError, json.JSONDecodeError) as error:
        sys.stderr.write(f"Release check verification failed: {error}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
