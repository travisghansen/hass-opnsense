"""Update aiopnsense dependency pins in manifest and pyproject files."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys
import tomllib
from urllib.request import urlopen

PYPI_URL = "https://pypi.org/pypi/aiopnsense/json"
PIN_PREFIX = "aiopnsense=="
PYPROJECT_PIN_RE = re.compile(r'(?m)^(\s*)"aiopnsense==[^"]+",\s*$')
PRERELEASE_RE = re.compile(r"(?i)(?:[.\-_]?(?:a|alpha|b|beta|c|pre|preview|rc|dev)\d*)")


@dataclass(frozen=True)
class UpdateResult:
    """Result of evaluating aiopnsense dependency pins.

    Attributes:
        current: Current manifest aiopnsense pin version.
        pyproject_current: Current pyproject aiopnsense pin version.
        latest: aiopnsense version selected as the update target.
        update_needed: Whether at least one pin should be updated.
    """

    current: str
    pyproject_current: str
    latest: str
    update_needed: bool


def _version_key(version: str) -> tuple[tuple[int, int | str], ...]:
    """Return a tolerant comparison key for aiopnsense version strings.

    Args:
        version: Version string to normalize.

    Returns:
        Tuple suitable for comparing common dotted release versions.
    """
    parts = re.findall(r"\d+|[A-Za-z]+", version.lstrip("vV"))
    return tuple((0, int(part)) if part.isdigit() else (1, part.lower()) for part in parts)


def _latest_is_newer(current: str, latest: str) -> bool:
    """Return whether the latest version is newer than the current version.

    Args:
        current: Current pinned version.
        latest: Latest available version.

    Returns:
        True when latest sorts after current.
    """
    return not _is_prerelease(latest) and _version_key(latest) > _version_key(current)


def _is_prerelease(version: str) -> bool:
    """Return whether a version string appears to be a prerelease.

    Args:
        version: Version string to evaluate.

    Returns:
        True when the version has a common prerelease marker.
    """
    return PRERELEASE_RE.search(version) is not None


def fetch_latest_version() -> str:
    """Fetch the latest stable aiopnsense version from PyPI.

    Returns:
        Latest stable version string.

    Raises:
        ValueError: If PyPI does not return a usable version.
    """
    with urlopen(PYPI_URL, timeout=30) as response:  # noqa: S310
        payload = json.load(response)

    return _select_latest_stable_version(payload)


def _select_latest_stable_version(payload: Mapping[str, object]) -> str:
    """Select the newest stable version from a PyPI JSON payload.

    Args:
        payload: PyPI JSON response payload.

    Returns:
        Newest non-prerelease version from the release list.

    Raises:
        ValueError: If PyPI does not return any stable versions.
    """
    releases = payload.get("releases", {})
    if not isinstance(releases, dict):
        raise TypeError("Expected releases mapping in PyPI response")

    stable_versions = [
        version for version in releases if isinstance(version, str) and not _is_prerelease(version)
    ]
    if not stable_versions:
        raise ValueError("Unable to determine latest stable aiopnsense version from PyPI response")
    return max(stable_versions, key=_version_key)


def _read_manifest_version(manifest_path: Path) -> str:
    """Read the aiopnsense pin version from a Home Assistant manifest.

    Args:
        manifest_path: Path to the integration manifest.

    Returns:
        Current aiopnsense version.

    Raises:
        ValueError: If there is not exactly one pinned aiopnsense requirement.
    """
    manifest = json.loads(manifest_path.read_text())
    requirements = manifest.get("requirements", [])
    if not isinstance(requirements, list):
        raise TypeError(f"Expected requirements list in {manifest_path}")

    pins = [requirement for requirement in requirements if _is_aiopnsense_pin(requirement)]
    if len(pins) != 1:
        raise ValueError(
            f"Expected exactly one aiopnsense requirement in {manifest_path}; found {len(pins)}"
        )
    return pins[0].removeprefix(PIN_PREFIX)


def _read_pyproject_version(pyproject_path: Path) -> str:
    """Read the aiopnsense pin version from dependency groups in pyproject.

    Args:
        pyproject_path: Path to pyproject.toml.

    Returns:
        Current aiopnsense version.

    Raises:
        ValueError: If there is not exactly one pinned aiopnsense dependency.
    """
    pyproject = tomllib.loads(pyproject_path.read_text())
    dependency_groups = pyproject.get("dependency-groups", {})
    if not isinstance(dependency_groups, dict):
        raise TypeError(f"Expected dependency-groups table in {pyproject_path}")

    pins: list[str] = []
    for dependencies in dependency_groups.values():
        if not isinstance(dependencies, list):
            continue
        pins.extend(dependency for dependency in dependencies if _is_aiopnsense_pin(dependency))

    if len(pins) != 1:
        raise ValueError(
            f"Expected exactly one pinned aiopnsense dependency in {pyproject_path}; "
            f"found {len(pins)}"
        )
    return pins[0].removeprefix(PIN_PREFIX)


def _is_aiopnsense_pin(requirement: object) -> bool:
    """Return whether a dependency entry is an aiopnsense exact pin.

    Args:
        requirement: Dependency entry read from JSON or TOML.

    Returns:
        True when the entry is an exact aiopnsense pin.
    """
    return isinstance(requirement, str) and requirement.startswith(PIN_PREFIX)


def _write_manifest_version(manifest_path: Path, latest_version: str) -> None:
    """Write the aiopnsense pin version into the manifest.

    Args:
        manifest_path: Path to the integration manifest.
        latest_version: Version to pin.

    Raises:
        ValueError: If there is not exactly one pinned aiopnsense requirement.
    """
    manifest = json.loads(manifest_path.read_text())
    requirements = manifest.get("requirements", [])
    if not isinstance(requirements, list):
        raise TypeError(f"Expected requirements list in {manifest_path}")

    updated_count = 0
    updated_requirements: list[object] = []
    for requirement in requirements:
        if _is_aiopnsense_pin(requirement):
            updated_count += 1
            updated_requirements.append(f"{PIN_PREFIX}{latest_version}")
        else:
            updated_requirements.append(requirement)

    if updated_count != 1:
        raise ValueError(
            f"Expected to update exactly one aiopnsense requirement in {manifest_path}; "
            f"updated {updated_count}"
        )

    manifest["requirements"] = updated_requirements
    manifest_path.write_text(f"{json.dumps(manifest, indent=2)}\n")


def _write_pyproject_version(pyproject_path: Path, latest_version: str) -> None:
    """Write the aiopnsense pin version into pyproject while preserving layout.

    Args:
        pyproject_path: Path to pyproject.toml.
        latest_version: Version to pin.

    Raises:
        ValueError: If there is not exactly one pinned aiopnsense dependency line.
    """
    text = pyproject_path.read_text()
    updated, count = PYPROJECT_PIN_RE.subn(rf'\1"{PIN_PREFIX}{latest_version}",', text)
    if count != 1:
        raise ValueError(
            f"Expected to update exactly one aiopnsense pin in {pyproject_path}; updated {count}"
        )
    pyproject_path.write_text(updated)


def update_pins(
    *,
    manifest_path: Path,
    pyproject_path: Path,
    latest_version: str,
    write: bool = True,
) -> UpdateResult:
    """Evaluate and optionally update aiopnsense dependency pins.

    Args:
        manifest_path: Path to manifest.json.
        pyproject_path: Path to pyproject.toml.
        latest_version: Latest aiopnsense version available for evaluation.
        write: Whether to rewrite dependency files when an update is needed.

    Returns:
        Evaluation result for workflow outputs and tests.
    """
    current = _read_manifest_version(manifest_path)
    pyproject_current = _read_pyproject_version(pyproject_path)
    latest_is_newer = _latest_is_newer(current, latest_version)
    target_version = latest_version if latest_is_newer else current
    update_needed = latest_is_newer or pyproject_current != target_version

    if write and update_needed:
        _write_manifest_version(manifest_path, target_version)
        _write_pyproject_version(pyproject_path, target_version)

    return UpdateResult(
        current=current,
        pyproject_current=pyproject_current,
        latest=target_version,
        update_needed=update_needed,
    )


def _write_github_outputs(result: UpdateResult, output_path: Path) -> None:
    """Append update result values to the GitHub Actions output file.

    Args:
        result: Update result to write.
        output_path: Path from the GITHUB_OUTPUT environment variable.
    """
    with output_path.open("a") as output_file:
        output_file.write(f"current={result.current}\n")
        output_file.write(f"pyproject_current={result.pyproject_current}\n")
        output_file.write(f"latest={result.latest}\n")
        output_file.write(f"update_needed={str(result.update_needed).lower()}\n")


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    """Parse command-line arguments.

    Args:
        argv: Command-line arguments excluding the executable name.

    Returns:
        Parsed arguments.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-path", type=Path, required=True)
    parser.add_argument("--pyproject-path", type=Path, required=True)
    parser.add_argument("--latest-version")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--github-output", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the aiopnsense dependency pin updater.

    Args:
        argv: Optional command-line arguments excluding the executable name.

    Returns:
        Process exit code.
    """
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    latest_version = args.latest_version or fetch_latest_version()
    result = update_pins(
        manifest_path=args.manifest_path,
        pyproject_path=args.pyproject_path,
        latest_version=latest_version,
        write=args.write,
    )
    if args.github_output is not None:
        _write_github_outputs(result, args.github_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
