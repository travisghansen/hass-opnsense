"""Select and verify the test environment for the minimum supported Home Assistant.

The minimum comes from ``hacs.json``. ``pytest-homeassistant`` covers Home Assistant
2026.11 and later; its predecessor, ``pytest-homeassistant-custom-component``, covers
earlier releases through 2026.10.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
from pathlib import Path
import re
import sys

FIRST_PYTEST_HOMEASSISTANT = (2026, 11)
PYTEST_HOMEASSISTANT_REQUIREMENT = "pytest-homeassistant>=2026.11.0"
# Releases before 0.13 do not pin homeassistant, so the lowest-version resolve would
# otherwise pick one of them.
PREDECESSOR_REQUIREMENT = "pytest-homeassistant-custom-component>=0.13"
_RELEASE_PATTERN = re.compile(r"^(\d+)\.(\d+)")


def read_minimum_version(hacs_path: Path) -> str:
    """Read the minimum Home Assistant version from ``hacs.json``.

    Args:
        hacs_path (Path): Path to ``hacs.json``.

    Returns:
        str: The declared minimum Home Assistant version.

    Raises:
        ValueError: If the file does not declare a string ``homeassistant`` version.
    """
    minimum = json.loads(hacs_path.read_text(encoding="utf-8")).get("homeassistant")
    if not isinstance(minimum, str) or not minimum:
        raise ValueError(f"{hacs_path} does not declare a homeassistant version")
    return minimum


def requirements_for(minimum: str) -> list[str]:
    """Build the lowest-version resolver input for the minimum Home Assistant.

    Args:
        minimum (str): Minimum Home Assistant version, for example ``2026.3.0b0``.

    Returns:
        list[str]: The test plugin requirement and the Home Assistant lower bound.

    Raises:
        ValueError: If the version does not start with a ``YYYY.M`` release.
    """
    match = _RELEASE_PATTERN.match(minimum)
    if match is None:
        raise ValueError(f"Unsupported Home Assistant version: {minimum!r}")
    release = (int(match.group(1)), int(match.group(2)))
    plugin = (
        PYTEST_HOMEASSISTANT_REQUIREMENT
        if release >= FIRST_PYTEST_HOMEASSISTANT
        else PREDECESSOR_REQUIREMENT
    )
    return [plugin, f"homeassistant>={minimum}"]


def verify_installed(minimum: str, resolved: str) -> str:
    """Verify the installed Home Assistant matches the resolved minimum.

    Run this with the test environment's interpreter.

    Args:
        minimum (str): Minimum Home Assistant version from ``hacs.json``.
        resolved (str): Home Assistant version pinned by the resolver.

    Returns:
        str: The installed Home Assistant version.

    Raises:
        SystemExit: If the installed version differs from the resolved pin or is
            older than the minimum.
    """
    from homeassistant.const import __version__  # noqa: PLC0415
    from packaging.version import Version  # noqa: PLC0415

    if __version__ != resolved or Version(__version__) < Version(minimum):
        raise SystemExit(
            f"Installed Home Assistant {__version__}; expected {resolved} (minimum {minimum})"
        )
    return __version__


def main(argv: Sequence[str] | None = None) -> None:
    """Print resolver input or verify the installed Home Assistant version.

    Args:
        argv (Sequence[str] | None): Command-line arguments; defaults to ``sys.argv``.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hacs", type=Path, default=Path("hacs.json"))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("requirements", help="Print lowest-version resolver input.")
    verify = commands.add_parser("verify", help="Check the installed Home Assistant.")
    verify.add_argument("resolved", help="Home Assistant version pinned by the resolver.")
    args = parser.parse_args(argv)

    minimum = read_minimum_version(args.hacs)
    if args.command == "requirements":
        sys.stdout.write("\n".join(requirements_for(minimum)) + "\n")
    else:
        installed = verify_installed(minimum, args.resolved)
        sys.stdout.write(f"Home Assistant {installed} (minimum {minimum})\n")


if __name__ == "__main__":
    main()
