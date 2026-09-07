"""Validate a release tag and prepare the integration version files."""
# ruff: noqa: E501

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


def _stable_tag_pattern(parts: tuple[int, ...]) -> re.Pattern[str]:
    """Return the numeric release-tag pattern for permitted component counts."""
    component = r"(?:0|[1-9][0-9]*)"
    suffixes = "|".join(rf"(?:\.{component}){{{part - 1}}}" for part in sorted(parts))
    return re.compile(rf"^v{component}(?:{suffixes})$")


def _parse_stable_parts(value: str) -> tuple[int, ...]:
    """Parse supported stable version component counts from workflow configuration."""
    try:
        parts = tuple(sorted({int(part) for part in value.split(",")}))
    except ValueError as error:
        raise ValueError("stable-parts must be comma-separated integers.") from error
    if not parts or any(part < 2 or part > 4 for part in parts):
        raise ValueError("stable-parts must contain values from 2 through 4.")
    return parts


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


def validate_release_request(
    tag: str, prerelease: bool, stable_parts: tuple[int, ...] = (2, 3, 4)
) -> None:
    """Validate that a release tag agrees with the prerelease selection.

    Args:
        tag: Candidate release tag.
        prerelease: Whether the release should be treated as a prerelease.
        stable_parts: Accepted numeric component counts for stable tags.

    Raises:
        ValueError: If the tag format and prerelease selection disagree.
    """
    validate_release_tag(tag)
    tag_is_prerelease = _stable_tag_pattern(stable_parts).fullmatch(tag) is None
    if tag_is_prerelease != prerelease:
        tag_kind = "Prerelease" if tag_is_prerelease else "Stable"
        required_value = str(tag_is_prerelease).lower()
        msg = f"{tag_kind} tag {tag} requires prerelease={required_value}."
        raise ValueError(msg)


def next_stable_release_tag(
    tags: Iterable[str], bump_type: str, stable_parts: tuple[int, ...] = (2, 3, 4)
) -> str:
    """Return the next stable tag after the highest released stable version.

    Args:
        tags: Candidate tag names from the release repository.
        bump_type: Requested stable version increment.
        stable_parts: Accepted numeric component counts for stable tags.

    Returns:
        The next stable release tag.

    Raises:
        ValueError: If the bump type is unsupported or no stable tag is found.
    """
    if bump_type not in {"patch", "minor", "major"}:
        msg = f"Unsupported bump type: {bump_type}"
        raise ValueError(msg)

    versions = [
        tuple(int(component) for component in tag.removeprefix("v").split("."))
        + (0,) * (4 - len(tag.removeprefix("v").split(".")))
        for tag in tags
        if _stable_tag_pattern(stable_parts).fullmatch(tag) is not None
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


def update_release_versions(repository: Path, tag: str, component_path: str | None = None) -> None:
    """Update manifest.json and const.py to the release tag.

    Both files are validated before either is written, preventing a partial update.

    Args:
        repository: Repository root containing the integration.
        tag: Requested release tag.
        component_path: Integration directory relative to the repository.

    Raises:
        ValueError: If the tag or either version declaration is invalid.
    """
    validate_release_tag(tag)
    if component_path is None:
        components = [
            path for path in (repository / "custom_components").iterdir() if path.is_dir()
        ]
        if len(components) != 1:
            msg = "component-path is required unless the repository has one component."
            raise ValueError(msg)
        integration = components[0]
    else:
        integration = repository / component_path
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
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path.cwd(),
        help="Repository root whose version files should be validated or updated",
    )
    parser.add_argument(
        "--component-path",
        help="Integration directory relative to --repository.",
    )
    parser.add_argument(
        "--stable-parts",
        default="2,3,4",
        help="Comma-separated stable release version component counts.",
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
                f"{next_stable_release_tag(sys.stdin.read().splitlines(), args.next_tag, _parse_stable_parts(args.stable_parts))}\n"
            )
        elif args.check_only:
            if args.expected_prerelease is None:
                validate_release_tag(args.tag)
            else:
                validate_release_request(
                    args.tag,
                    args.expected_prerelease == "true",
                    _parse_stable_parts(args.stable_parts),
                )
        else:
            if args.expected_prerelease is not None:
                msg = "--expected-prerelease requires --check-only."
                raise ValueError(msg)
            update_release_versions(args.repository, args.tag, args.component_path)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
