"""Select the minimum Home Assistant test environment and verify test environments.

The minimum comes from ``hacs.json``. ``pytest-homeassistant`` covers Home Assistant
2026.11 and later; its predecessor, ``pytest-homeassistant-custom-component``, covers
earlier releases through 2026.10.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from importlib import metadata
import json
from pathlib import Path
import platform
import re
import sys

FIRST_PYTEST_HOMEASSISTANT = (2026, 11)
PYTEST_HOMEASSISTANT_REQUIREMENT = "pytest-homeassistant>=2026.11.0"
# Releases before 0.13 do not pin homeassistant, so the lowest-version resolve would
# otherwise pick one of them.
PREDECESSOR_REQUIREMENT = "pytest-homeassistant-custom-component>=0.13"
TEST_PLUGINS = ("pytest-homeassistant", "pytest-homeassistant-custom-component")
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


def installed_test_plugins() -> dict[str, str]:
    """Find the installed Home Assistant test plugins.

    Returns:
        dict[str, str]: Installed version of each installed test plugin.
    """
    installed = {}
    for name in TEST_PLUGINS:
        try:
            installed[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            continue
    return installed


def verify_installed(minimum: str, pins_path: Path | None = None) -> str:
    """Verify the installed test environment and describe it.

    Run this with the test environment's interpreter.

    Args:
        minimum (str): Minimum Home Assistant version from ``hacs.json``.
        pins_path (Path | None): File of ``name==version`` lines naming the resolved
            Home Assistant and test plugin releases, if the environment was resolved.

    Returns:
        str: The Python, Home Assistant and test plugin versions.

    Raises:
        SystemExit: If there is not exactly one test plugin, the plugin does not pin
            the installed Home Assistant, Home Assistant is older than the minimum,
            or the installed releases differ from the resolved pins.
    """
    from homeassistant.const import __version__  # noqa: PLC0415
    from packaging.requirements import Requirement  # noqa: PLC0415
    from packaging.version import Version  # noqa: PLC0415

    plugins = installed_test_plugins()
    if len(plugins) != 1:
        raise SystemExit(f"Expected exactly one Home Assistant test plugin; installed: {plugins}")
    ((plugin, plugin_version),) = plugins.items()
    if Version(__version__) < Version(minimum):
        raise SystemExit(f"Home Assistant {__version__} is older than the minimum {minimum}")
    requirements = [Requirement(line) for line in metadata.requires(plugin) or []]
    if not any(
        requirement.name == "homeassistant" and str(requirement.specifier) == f"=={__version__}"
        for requirement in requirements
    ):
        raise SystemExit(
            f"{plugin} {plugin_version} does not pin the installed Home Assistant {__version__}"
        )
    if pins_path is not None:
        pins = dict(
            line.strip().split("==", 1)
            for line in pins_path.read_text(encoding="utf-8").splitlines()
        )
        installed = {"homeassistant": __version__, plugin: plugin_version}
        if pins != installed:
            raise SystemExit(f"Installed {installed} differs from the resolved pins {pins}")
    return (
        f"Python {platform.python_version()}; Home Assistant {__version__} "
        f"(minimum {minimum}); {plugin} {plugin_version}"
    )


def main(argv: Sequence[str] | None = None) -> None:
    """Print resolver input or verify the installed test environment.

    Args:
        argv (Sequence[str] | None): Command-line arguments; defaults to ``sys.argv``.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hacs", type=Path, default=Path("hacs.json"))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("requirements", help="Print lowest-version resolver input.")
    verify = commands.add_parser("verify", help="Check the installed test environment.")
    verify.add_argument("--pins", type=Path, help="Resolved name==version lines to match.")
    args = parser.parse_args(argv)

    minimum = read_minimum_version(args.hacs)
    if args.command == "requirements":
        sys.stdout.write("\n".join(requirements_for(minimum)) + "\n")
    else:
        sys.stdout.write(verify_installed(minimum, args.pins) + "\n")


if __name__ == "__main__":
    main()
