"""Test the Release Please configuration and archive handoff contract."""

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release-please.yml"
CONFIG = ROOT / "release-please-config.json"


def test_release_please_updates_both_tagged_versions_without_changelog() -> None:
    """Keep the release tag and integration versions aligned without a file changelog."""
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    package = config["packages"]["."]
    const = (ROOT / "custom_components" / "opnsense" / "const.py").read_text(encoding="utf-8")
    manifest = json.loads(
        (ROOT / "custom_components" / "opnsense" / "manifest.json").read_text(encoding="utf-8")
    )

    assert config["include-v-in-tag"] is True
    assert config["include-component-in-tag"] is False
    assert config["changelog-sections"]
    assert package["skip-changelog"] is True
    assert package["extra-files"] == [
        {"type": "generic", "path": "custom_components/opnsense/const.py"},
        {
            "type": "json",
            "path": "custom_components/opnsense/manifest.json",
            "jsonpath": "$.version",
        },
    ]
    assert f'VERSION = "{manifest["version"]}"  # x-release-please-version' in const
    assert (
        manifest["version"]
        == "v"
        + json.loads((ROOT / ".release-please-manifest.json").read_text(encoding="utf-8"))["."]
    )


def test_release_please_owns_archive_publication() -> None:
    """Require one release owner and a verified OPNsense archive."""
    document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    events = document.get("on", document.get(True))
    steps = document["jobs"]["release-please"]["steps"]
    release = next(step for step in steps if step.get("id") == "release")
    archive = next(
        step for step in steps if step.get("name") == "Build and upload the HACS archive"
    )
    script = archive["run"]

    assert not (ROOT / ".github" / "workflows" / "release.yml").exists()
    assert events["push"]["branches"] == ["main"]
    assert "workflow_dispatch" in events
    assert release["uses"] == "googleapis/release-please-action@v5"
    assert "token" not in release["with"]
    assert archive["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert "HEAD:custom_components/opnsense" in script
    assert "verify_hacs_archive.py" in script
    assert "opnsense.zip#opnsense.zip" in script
    assert "opnsense-firmware-compatibility" in script
    assert "custom_components/places" not in script
