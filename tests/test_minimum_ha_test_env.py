"""Tests for the minimum Home Assistant test environment workflow helper."""

from importlib import util
import json
from pathlib import Path
import platform
import sys
from types import ModuleType

from homeassistant.const import __version__
import pytest

SCRIPT_PATH = Path(__file__).parents[1] / ".github/scripts/minimum_ha_test_env.py"


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
    ("minimum", "pin_changes", "error"),
    [
        ("2026.3.0b0", None, None),
        # Resolved pins that match the installed releases.
        ("2026.3.0b0", {}, None),
        ("2999.1.0", None, "older than the minimum"),
        ("2026.3.0b0", {"homeassistant": "2000.1.0"}, "differs from the resolved pins"),
        ("2026.3.0b0", {"plugin": "0.0.0"}, "differs from the resolved pins"),
    ],
)
def test_verify_checks_installed_environment(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    minimum: str,
    pin_changes: dict[str, str] | None,
    error: str | None,
) -> None:
    """Report the installed releases, or reject ones that were not expected.

    Args:
        tmp_path (Path): Directory for the hacs.json and pin fixtures.
        capsys (pytest.CaptureFixture[str]): Captures the printed versions.
        minimum (str): Minimum Home Assistant version declared in hacs.json.
        pin_changes (dict[str, str] | None): Resolved pins that differ from the
            installed releases, or ``None`` to verify without pins.
        error (str | None): Expected failure message, or ``None`` for success.
    """
    ((plugin, plugin_version),) = SCRIPT.installed_test_plugins().items()
    hacs_path = _write_hacs(tmp_path, {"homeassistant": minimum})
    args = ["--hacs", str(hacs_path), "verify"]
    if pin_changes is not None:
        pins = {"homeassistant": __version__, plugin: plugin_version}
        pins.update(
            {plugin if name == "plugin" else name: pin for name, pin in pin_changes.items()}
        )
        pins_path = tmp_path / "pins.txt"
        pins_path.write_text(
            "".join(f"{name}=={pin}\n" for name, pin in pins.items()), encoding="utf-8"
        )
        args += ["--pins", str(pins_path)]

    if error is None:
        SCRIPT.main(args)
        output = capsys.readouterr().out
        assert f"Home Assistant {__version__} (minimum {minimum})" in output
        assert f"{plugin} {plugin_version}" in output
        assert f"Python {platform.python_version()}" in output
    else:
        with pytest.raises(SystemExit, match=error):
            SCRIPT.main(args)


@pytest.mark.parametrize(
    ("plugins", "requirements", "error"),
    [
        ({}, [], "exactly one"),
        (
            {"pytest-homeassistant": "1", "pytest-homeassistant-custom-component": "2"},
            [],
            "exactly one",
        ),
        ({"pytest-homeassistant": "1"}, ["homeassistant==2000.1.0"], "does not pin"),
        ({"pytest-homeassistant": "1"}, ["homeassistant>=2000.1.0"], "does not pin"),
    ],
)
def test_verify_rejects_unusable_test_plugins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    plugins: dict[str, str],
    requirements: list[str],
    error: str,
) -> None:
    """Require exactly one test plugin that pins the installed Home Assistant.

    Args:
        tmp_path (Path): Directory for the hacs.json fixture.
        monkeypatch (pytest.MonkeyPatch): Replaces the installed plugin metadata.
        plugins (dict[str, str]): Installed test plugins and their versions.
        requirements (list[str]): Requirements declared by the installed plugin.
        error (str): Expected failure message.
    """
    monkeypatch.setattr(SCRIPT, "installed_test_plugins", lambda: plugins)
    monkeypatch.setattr(SCRIPT.metadata, "requires", lambda _name: requirements)
    hacs_path = _write_hacs(tmp_path, {"homeassistant": "2026.3.0b0"})

    with pytest.raises(SystemExit, match=error):
        SCRIPT.main(["--hacs", str(hacs_path), "verify"])
