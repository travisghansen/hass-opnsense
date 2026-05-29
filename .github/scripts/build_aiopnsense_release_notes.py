"""Build the aiopnsense dependency update pull request body."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import json
import logging
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

GITHUB_API_URL = "https://api.github.com"
LOGGER = logging.getLogger(__name__)
MENTION_RE = re.compile(r"@(?=[A-Za-z0-9-]+(?:/[A-Za-z0-9-]+)?)")
MENTION_LINK_RE = re.compile(r"\[@([A-Za-z0-9-]+)\]\(https?://github\.com/[A-Za-z0-9-]+\)")
CLOSING_KEYWORD_RE = re.compile(
    r"\b(close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s+"
    r"((?:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)?#\d+)",
    re.IGNORECASE,
)
PRERELEASE_RE = re.compile(r"(?i)(?:[.\-_]?(?:a|alpha|b|beta|c|pre|preview|rc|dev)\d*)")


def _version_key(version: str) -> tuple[tuple[int, int | str], ...]:
    """Return a tolerant comparison key for release versions.

    Args:
        version: Version string to normalize.

    Returns:
        Tuple suitable for comparing common dotted release versions.
    """
    parts = re.findall(r"\d+|[A-Za-z]+", version.lstrip("vV"))
    return tuple((0, int(part)) if part.isdigit() else (1, part.lower()) for part in parts)


def _is_prerelease(version: str) -> bool:
    """Return whether a version string appears to be a prerelease.

    Args:
        version: Version string to evaluate.

    Returns:
        True when the version has a common prerelease marker.
    """
    return PRERELEASE_RE.search(version) is not None


def _stable_version(version: str) -> str:
    """Return the stable base of a version string.

    Args:
        version: Version string to normalize.

    Returns:
        Stable release portion of the version.
    """
    match = PRERELEASE_RE.search(version)
    return version[: match.start()].rstrip(".-_") if match else version


def _sanitize_release_body(body: str) -> str:
    """Return release text that is safe to embed in a generated PR body.

    Args:
        body: Release text from GitHub.

    Returns:
        Sanitized release text.
    """
    body = MENTION_LINK_RE.sub(r"\1", body)
    body = MENTION_RE.sub("@<!-- -->", body)
    return CLOSING_KEYWORD_RE.sub(
        lambda match: f"{match.group(1)} {match.group(2).replace('#', r'\#')}",
        body,
    )


def build_release_notes(
    *,
    releases: Sequence[Mapping[str, object]],
    current_version: str,
    latest_version: str,
) -> str:
    """Build sanitized release notes for the updated version range.

    Args:
        releases: GitHub releases from the aiopnsense repository.
        current_version: Currently pinned aiopnsense version.
        latest_version: Target aiopnsense version.

    Returns:
        Markdown release notes for matching stable releases.
    """
    current = current_version.removeprefix("v").removeprefix("V")
    latest = latest_version.removeprefix("v").removeprefix("V")
    current_is_prerelease = _is_prerelease(current)
    current_stable = _stable_version(current)

    selected: list[Mapping[str, object]] = []
    for release in releases:
        tag_name = release.get("tag_name")
        if not isinstance(tag_name, str):
            continue

        tag_version = tag_name.removeprefix("v").removeprefix("V")
        lower_bound = _version_key(tag_version) > _version_key(current_stable)
        prerelease_repair = current_is_prerelease and _version_key(tag_version) == _version_key(
            current_stable,
        )
        if (
            not _is_prerelease(tag_version)
            and (lower_bound or prerelease_repair)
            and _version_key(tag_version) <= _version_key(latest)
        ):
            selected.append(release)

    if not selected:
        return "No matching GitHub release notes were found for this version range."

    selected.sort(key=lambda release: _version_key(str(release["tag_name"])))
    notes: list[str] = []
    for release in selected:
        tag_name = str(release["tag_name"])
        title = _sanitize_release_body(str(release.get("name") or tag_name))
        tag = _sanitize_release_body(tag_name)
        html_url = str(release.get("html_url") or "")
        raw_body = str(release.get("body") or "No release body provided.").strip()
        body = _sanitize_release_body(raw_body)
        notes.append("\n".join([f"### {title} ({tag})", html_url, "", body]))

    return "\n\n---\n\n".join(notes)


def write_pr_body(
    *,
    body_path: Path,
    releases: Sequence[Mapping[str, object]],
    current_version: str,
    pyproject_current_version: str,
    latest_version: str,
) -> None:
    """Write the generated aiopnsense update PR body.

    Args:
        body_path: Path to write the markdown body to.
        releases: GitHub releases from the aiopnsense repository.
        current_version: Currently pinned manifest version.
        pyproject_current_version: Currently pinned pyproject version.
        latest_version: Target aiopnsense version.
    """
    release_notes = build_release_notes(
        releases=releases,
        current_version=current_version,
        latest_version=latest_version,
    )
    body_path.write_text(
        "\n".join(
            [
                "Automated update of aiopnsense dependency pins.",
                "",
                f"- Previous manifest pinned version: `aiopnsense=={current_version}`",
                f"- Previous pyproject pinned version: `aiopnsense=={pyproject_current_version}`",
                f"- Updated pinned version: `aiopnsense=={latest_version}`",
                "",
                "## aiopnsense release notes in range",
                release_notes,
                "",
            ],
        ),
    )


def fetch_releases(*, owner: str, repo: str, token: str | None = None) -> list[dict[str, object]]:
    """Fetch releases from the GitHub REST API.

    Args:
        owner: Repository owner.
        repo: Repository name.
        token: Optional GitHub token.

    Returns:
        List of GitHub release objects.
    """
    releases: list[dict[str, object]] = []
    url: str | None = f"{GITHUB_API_URL}/repos/{owner}/{repo}/releases?per_page=100"
    while url is not None:
        request = Request(url, headers=_github_headers(token))  # noqa: S310
        with urlopen(request, timeout=30) as response:  # noqa: S310
            payload = json.load(response)
            if not isinstance(payload, list):
                raise TypeError(f"Expected a list of releases from {url}")
            releases.extend(release for release in payload if isinstance(release, dict))
            url = _next_link(response.headers.get("Link"))
    return releases


def _github_headers(token: str | None) -> dict[str, str]:
    """Build GitHub API request headers.

    Args:
        token: Optional GitHub token.

    Returns:
        Request headers.
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "hass-opnsense-update-aiopnsense",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _next_link(link_header: str | None) -> str | None:
    """Return the next pagination URL from a GitHub Link header.

    Args:
        link_header: Raw Link header value.

    Returns:
        Next URL when present.
    """
    if not link_header:
        return None
    for link in link_header.split(","):
        url_part, *params = link.split(";")
        if any(param.strip() == 'rel="next"' for param in params):
            return url_part.strip()[1:-1]
    return None


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    """Parse command-line arguments.

    Args:
        argv: Command-line arguments excluding the executable name.

    Returns:
        Parsed arguments.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current-version", required=True)
    parser.add_argument("--pyproject-current-version", required=True)
    parser.add_argument("--latest-version", required=True)
    parser.add_argument("--release-owner", required=True)
    parser.add_argument("--release-repo", required=True)
    parser.add_argument("--body-path", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Build the update PR body file.

    Args:
        argv: Optional command-line arguments excluding the executable name.

    Returns:
        Process exit code.
    """
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    token = os.environ.get("GITHUB_TOKEN")
    try:
        releases = fetch_releases(owner=args.release_owner, repo=args.release_repo, token=token)
    except HTTPError as err:
        LOGGER.error(
            "Failed to fetch releases for %s/%s: %s",
            args.release_owner,
            args.release_repo,
            err,
        )
        return 1
    if not releases:
        LOGGER.error(
            "No releases found for %s/%s. Check workflow inputs or repository variables "
            "(AIOPNSENSE_RELEASE_OWNER/AIOPNSENSE_RELEASE_REPO).",
            args.release_owner,
            args.release_repo,
        )
        return 1

    write_pr_body(
        body_path=args.body_path,
        releases=releases,
        current_version=args.current_version,
        pyproject_current_version=args.pyproject_current_version,
        latest_version=args.latest_version,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
