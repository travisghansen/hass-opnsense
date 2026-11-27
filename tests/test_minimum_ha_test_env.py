"""Tests for the minimum Home Assistant test environment workflow helper."""

from importlib import util
import json
from pathlib import Path
import sys
from types import ModuleType

import pytest

SCRIPT_PATH = Path(".github/scripts/minimum_ha_test_env.py")


def _load_script() -> ModuleType:
    """Import the workflow helper script as a module.

    Returns:
        ModuleType: Imported workflow helper module.
    """
    spec = util.spec_from_file_location("minimum_ha_test_env", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = util.module_from_spec(spec)
    sys.modules["minimum_ha_test_env"] = module
    spec.loader.exec_module(module)
    return module


SCRIPT = _load_script()


def _write_hacs(tmp_path: Path, payload: object) -> Path:
    """Write a hacs.json file.

    Args:
        tmp_path (Path): Directory for the file.
        payload (object): JSON payload to write.

    Returns:
        Path: Path to the written file.
    """
    hacs_path = tmp_path / "hacs.json"
    hacs_path.write_text(json.dumps(payload), encoding="utf-8")
    return hacs_path


@pytest.mark.parametrize(
    ("minimum", "plugin"),
    [
        ("2026.3.0b0", "pytest-homeassistant-custom-component>=0.13"),
        ("2026.10.4", "pytest-homeassistant-custom-component>=0.13"),
        ("2026.11.0b0", "pytest-homeassistant>=2026.11.0"),
        ("2026.11.0", "pytest-homeassistant>=2026.11.0"),
        ("2027.1.0", "pytest-homeassistant>=2026.11.0"),
    ],
)
def test_requirements_select_plugin_for_minimum(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], minimum: str, plugin: str
) -> None:
    """Print the plugin covering the hacs.json minimum and the HA lower bound.

    Args:
        tmp_path (Path): Directory for the hacs.json fixture.
        capsys (pytest.CaptureFixture[str]): Captures the printed requirements.
        minimum (str): Minimum Home Assistant version declared in hacs.json.
        plugin (str): Expected test plugin requirement.
    """
    hacs_path = _write_hacs(tmp_path, {"homeassistant": minimum})

    SCRIPT.main(["--hacs", str(hacs_path), "requirements"])

    assert capsys.readouterr().out.splitlines() == [plugin, f"homeassistant>={minimum}"]


@pytest.mark.parametrize(
    "payload",
    [{}, {"homeassistant": ""}, {"homeassistant": 2026.3}, {"homeassistant": "latest"}],
)
def test_requirements_reject_unusable_minimum(tmp_path: Path, payload: object) -> None:
    """Fail instead of resolving an unbounded Home Assistant version.

    Args:
        tmp_path (Path): Directory for the hacs.json fixture.
        payload (object): hacs.json content without a usable minimum.
    """
    hacs_path = _write_hacs(tmp_path, payload)

    with pytest.raises(ValueError):
        SCRIPT.main(["--hacs", str(hacs_path), "requirements"])


@pytest.mark.parametrize(
    ("minimum", "resolved", "passes"),
    [
        ("2026.3.0b0", "installed", True),
        ("2026.3.0b0", "2026.3.1", False),
        ("2999.1.0", "installed", False),
    ],
)
def test_verify_checks_installed_home_assistant(
    tmp_path: Path, minimum: str, resolved: str, passes: bool
) -> None:
    """Accept only the resolved Home Assistant release at or above the minimum.

    Args:
        tmp_path (Path): Directory for the hacs.json fixture.
        minimum (str): Minimum Home Assistant version declared in hacs.json.
        resolved (str): Resolved pin, or ``installed`` for the installed version.
        passes (bool): Whether verification should succeed.
    """
    from homeassistant.const import __version__  # noqa: PLC0415

    if resolved == "installed":
        resolved = __version__
    elif resolved == __version__:
        pytest.skip("Fixture pin matches the installed Home Assistant version")
    hacs_path = _write_hacs(tmp_path, {"homeassistant": minimum})
    args = ["--hacs", str(hacs_path), "verify", resolved]

    if passes:
        SCRIPT.main(args)
    else:
        with pytest.raises(SystemExit):
            SCRIPT.main(args)
