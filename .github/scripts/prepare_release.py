"""Validate a release tag and prepare the integration version files."""

from __future__ import annotations

import argparse
from collections.abc import Iterable
import json
from pathlib import Path
import re
import sys

TAG_PATTERN = re.compile(
    r"^v[0-9]+(?:\.[0-9]+){1,3}(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?(?:[A-Za-z]+[0-9]+)?$"
)
MANIFEST_VERSION_PATTERN = re.compile(r'("version"\s*:\s*)"[^"]*"')
CONST_VERSION_PATTERN = re.compile(r'^(VERSION\s*=\s*)"[^"]*"', re.MULTILINE)
STABLE_TAG_PATTERN = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?$"
)
NUMERIC_TAG_PATTERN = re.compile(r"^v[0-9]+(?:\.[0-9]+){1,3}$")


def validate_release_tag(tag: str) -> None:
    """Validate a release tag against the repository's supported formats.

    Args:
        tag: Candidate release tag.

    Raises:
        ValueError: If the tag does not use a supported version format.
    """
    if TAG_PATTERN.fullmatch(tag) is None:
        msg = f"Invalid release tag: {tag}"
        raise ValueError(msg)


def validate_release_request(tag: str, prerelease: bool) -> None:
    """Validate that a release tag agrees with the prerelease selection.

    Args:
        tag: Candidate release tag.
        prerelease: Whether the release should be treated as a prerelease.

    Raises:
        ValueError: If the tag format and prerelease selection disagree.
    """
    validate_release_tag(tag)
    tag_is_prerelease = NUMERIC_TAG_PATTERN.fullmatch(tag) is None
    if tag_is_prerelease != prerelease:
        tag_kind = "Prerelease" if tag_is_prerelease else "Stable"
        required_value = str(tag_is_prerelease).lower()
        msg = f"{tag_kind} tag {tag} requires prerelease={required_value}."
        raise ValueError(msg)


def next_stable_release_tag(tags: Iterable[str], bump_type: str) -> str:
    """Return the next stable tag after the highest released stable version.

    Args:
        tags: Candidate tag names from the release repository.
        bump_type: Requested stable version increment.

    Returns:
        The next stable release tag.

    Raises:
        ValueError: If the bump type is unsupported or no stable tag is found.
    """
    if bump_type not in {"patch", "minor", "major"}:
        msg = f"Unsupported bump type: {bump_type}"
        raise ValueError(msg)

    versions = [
        tuple(int(component or 0) for component in match.groups())
        for tag in tags
        if (match := STABLE_TAG_PATTERN.fullmatch(tag)) is not None
    ]
    if not versions:
        msg = "No stable released tag found."
        raise ValueError(msg)

    major, minor, patch, _build = max(versions)
    if bump_type == "patch":
        patch += 1
    elif bump_type == "minor":
        minor += 1
        patch = 0
    else:
        major += 1
        minor = 0
        patch = 0
    return f"v{major}.{minor}.{patch}"


def _replace_version(
    content: str,
    pattern: re.Pattern[str],
    tag: str,
    path: Path,
) -> str:
    """Replace one version declaration while preserving its formatting.

    Args:
        content: Original file content.
        pattern: Pattern whose first group precedes the version string.
        tag: Validated release tag.
        path: Source path used in error messages.

    Returns:
        Content containing the requested release version.

    Raises:
        ValueError: If the file does not contain exactly one version declaration.
    """
    updated, replacements = pattern.subn(lambda match: f'{match.group(1)}"{tag}"', content)
    if replacements != 1:
        msg = f"Expected one version declaration in {path}, found {replacements}."
        raise ValueError(msg)
    return updated


def update_release_versions(repository: Path, tag: str) -> None:
    """Update manifest.json and const.py to the release tag.

    Both files are validated before either is written, preventing a partial update.

    Args:
        repository: Repository root containing the integration.
        tag: Requested release tag.

    Raises:
        ValueError: If the tag or either version declaration is invalid.
    """
    validate_release_tag(tag)
    integration = repository / "custom_components" / "opnsense"
    manifest_path = integration / "manifest.json"
    const_path = integration / "const.py"

    manifest = _replace_version(
        manifest_path.read_text(encoding="utf-8"),
        MANIFEST_VERSION_PATTERN,
        tag,
        manifest_path,
    )
    const = _replace_version(
        const_path.read_text(encoding="utf-8"),
        CONST_VERSION_PATTERN,
        tag,
        const_path,
    )

    if json.loads(manifest).get("version") != tag:
        msg = f"Failed to update {manifest_path} to {tag}."
        raise ValueError(msg)

    manifest_path.write_text(manifest, encoding="utf-8")
    const_path.write_text(const, encoding="utf-8")


def main() -> int:
    """Run the release preparation command.

    Returns:
        Zero when validation or version preparation succeeds.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag", nargs="?", help="Release tag, such as v1.0.6")
    parser.add_argument(
        "--next-tag",
        metavar="BUMP_TYPE",
        help="Print the next stable tag for patch, minor, or major",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Validate the tag without updating version files",
    )
    parser.add_argument(
        "--expected-prerelease",
        choices=("true", "false"),
        help="Require the tag to match the workflow prerelease selection",
    )
    args = parser.parse_args()

    try:
        if (args.tag is None) == (args.next_tag is None):
            msg = "Provide exactly one release tag or --next-tag BUMP_TYPE."
            raise ValueError(msg)
        if args.next_tag is not None:
            if args.check_only or args.expected_prerelease is not None:
                msg = "Validation options cannot be used with --next-tag."
                raise ValueError(msg)
            sys.stdout.write(
                f"{next_stable_release_tag(sys.stdin.read().splitlines(), args.next_tag)}\n"
            )
        elif args.check_only:
            if args.expected_prerelease is None:
                validate_release_tag(args.tag)
            else:
                validate_release_request(args.tag, args.expected_prerelease == "true")
        else:
            if args.expected_prerelease is not None:
                msg = "--expected-prerelease requires --check-only."
                raise ValueError(msg)
            update_release_versions(Path.cwd(), args.tag)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
