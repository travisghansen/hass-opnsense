"""Tests for release version preparation."""

import importlib.util
import io
import json
from pathlib import Path
import sys

import pytest

SCRIPT_PATH = Path(__file__).parents[1] / ".github" / "scripts" / "prepare_release.py"
SCRIPT_SPEC = importlib.util.spec_from_file_location("prepare_release", SCRIPT_PATH)
assert SCRIPT_SPEC is not None
assert SCRIPT_SPEC.loader is not None
prepare_release = importlib.util.module_from_spec(SCRIPT_SPEC)
SCRIPT_SPEC.loader.exec_module(prepare_release)


@pytest.mark.parametrize(
    "tag",
    ["v1.0.6", "v1.1.0-beta.1", "v0.6.5.1", "v1.0.0b1"],
)
def test_validate_release_tag_accepts_supported_formats(tag: str) -> None:
    """Accept supported release tag formats.

    Args:
        tag (str): Supported release tag under test.
    """
    prepare_release.validate_release_tag(tag)


@pytest.mark.parametrize(
    "tag",
    ["", "1.0.6", "v1", "v1.0.6 beta", "v1.0.6;echo-bad"],
)
def test_validate_release_tag_rejects_unsupported_formats(tag: str) -> None:
    """Reject malformed release tags.

    Args:
        tag (str): Unsupported release tag under test.
    """
    with pytest.raises(ValueError, match="Invalid release tag"):
        prepare_release.validate_release_tag(tag)


@pytest.mark.parametrize(
    ("tag", "prerelease"),
    [
        ("v1.0.6", False),
        ("v0.6.5.1", False),
        ("v1.1.0-beta.1", True),
        ("v1.0.0b1", True),
    ],
)
def test_validate_release_request_accepts_matching_classification(
    tag: str, prerelease: bool
) -> None:
    """Accept release requests whose tag and prerelease input agree.

    Args:
        tag (str): Supported release tag under test.
        prerelease (bool): Matching prerelease selection.
    """
    prepare_release.validate_release_request(tag, prerelease)


@pytest.mark.parametrize(
    ("tag", "prerelease", "message"),
    [
        ("v1.1.0-beta.1", False, "Prerelease tag.*requires prerelease=true"),
        ("v1.0.0b1", False, "Prerelease tag.*requires prerelease=true"),
        ("v1.0.6", True, "Stable tag.*requires prerelease=false"),
        ("v0.6.5.1", True, "Stable tag.*requires prerelease=false"),
    ],
)
def test_validate_release_request_rejects_mismatched_classification(
    tag: str, prerelease: bool, message: str
) -> None:
    """Reject release requests whose tag and prerelease input disagree.

    Args:
        tag (str): Supported release tag under test.
        prerelease (bool): Mismatched prerelease selection.
        message (str): Expected validation error.
    """
    with pytest.raises(ValueError, match=message):
        prepare_release.validate_release_request(tag, prerelease)


@pytest.mark.parametrize(
    ("bump_type", "expected_tag"),
    [("patch", "v1.0.6"), ("minor", "v1.1.0"), ("major", "v2.0.0")],
)
def test_next_stable_release_tag_uses_highest_stable_version(
    bump_type: str, expected_tag: str
) -> None:
    """Ignore prereleases while incrementing the highest stable release.

    Args:
        bump_type (str): Requested version increment.
        expected_tag (str): Expected next stable release tag.
    """
    tags = [
        "v1.0.4",
        "v1.0.5-beta.1",
        "v1.0.5",
        "v1.0.5b1",
        "invalid",
        "v0.99.99",
    ]

    assert prepare_release.next_stable_release_tag(tags, bump_type) == expected_tag


@pytest.mark.parametrize(
    ("tags", "bump_type", "expected_tag"),
    [
        (["v1.0.5", "v1.0.5.1"], "patch", "v1.0.6"),
        (["v1.0.5", "v1.0.5.1"], "minor", "v1.1.0"),
        (["v1.9.9", "v2.0.0.1"], "major", "v3.0.0"),
    ],
)
def test_next_stable_release_tag_considers_four_component_versions(
    tags: list[str], bump_type: str, expected_tag: str
) -> None:
    """Use four-component stable tags when selecting the next release.

    Args:
        tags (list[str]): Candidate stable tag names.
        bump_type (str): Requested version increment.
        expected_tag (str): Expected next stable release tag.
    """
    assert prepare_release.next_stable_release_tag(tags, bump_type) == expected_tag


@pytest.mark.parametrize(
    ("tags", "bump_type", "message"),
    [
        (["v1.0.6-beta.1", "v1.0.6b1"], "patch", "No stable released tag"),
        (["v1.0.6"], "feature", "Unsupported bump type"),
    ],
)
def test_next_stable_release_tag_rejects_invalid_requests(
    tags: list[str], bump_type: str, message: str
) -> None:
    """Reject requests without a supported stable release increment.

    Args:
        tags (list[str]): Candidate release tag names.
        bump_type (str): Requested version increment.
        message (str): Expected failure message.
    """
    with pytest.raises(ValueError, match=message):
        prepare_release.next_stable_release_tag(tags, bump_type)


def test_next_tag_cli_reads_tags_from_standard_input(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Print the next stable tag without writing version files.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing CLI inputs.
        capsys (pytest.CaptureFixture[str]): Fixture for capturing CLI output.
    """
    monkeypatch.setattr(sys, "argv", [str(SCRIPT_PATH), "--next-tag", "minor"])
    monkeypatch.setattr(sys, "stdin", io.StringIO("v0.7.4\nv1.0.0-beta.1\nv0.8.1\n"))

    assert prepare_release.main() == 0
    assert capsys.readouterr().out == "v0.9.0\n"


@pytest.mark.parametrize(
    ("arguments", "expected_message"),
    [
        ((), "Provide exactly one release tag"),
        (("v1.0.6", "--next-tag", "patch"), "Provide exactly one release tag"),
        (("--next-tag", "patch", "--check-only"), "Validation options"),
        (
            ("--next-tag", "patch", "--expected-prerelease", "false"),
            "Validation options",
        ),
        (
            ("v1.0.6", "--expected-prerelease", "false"),
            "--expected-prerelease requires --check-only",
        ),
    ],
)
def test_main_rejects_invalid_option_combinations(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: tuple[str, ...],
    expected_message: str,
) -> None:
    """Reject missing, conflicting, or incorrectly gated CLI options.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing CLI arguments.
        capsys (pytest.CaptureFixture[str]): Fixture for capturing parser errors.
        arguments (tuple[str, ...]): CLI arguments to reject.
        expected_message (str): Expected parser error text.
    """
    monkeypatch.setattr(sys, "argv", [str(SCRIPT_PATH), *arguments])

    with pytest.raises(SystemExit) as error:
        prepare_release.main()

    assert error.value.code == 2
    assert expected_message in capsys.readouterr().err


def test_check_only_cli_accepts_matching_expected_prerelease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Accept the release workflow's stable check-only validation request.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing CLI arguments.
    """
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT_PATH),
            "--check-only",
            "--expected-prerelease",
            "false",
            "v1.0.6",
        ],
    )

    assert prepare_release.main() == 0


def _write_version_files(repository: Path, const_content: str | None = None) -> tuple[Path, Path]:
    """Create representative integration version files.

    Args:
        repository (Path): Temporary repository root.
        const_content (str | None): Optional const.py content override.

    Returns:
        tuple[Path, Path]: Paths to manifest.json and const.py.
    """
    integration = repository / "custom_components" / "opnsense"
    integration.mkdir(parents=True)
    manifest_path = integration / "manifest.json"
    const_path = integration / "const.py"
    manifest_path.write_text(
        '{\n  "domain": "opnsense",\n  "version" : "v1.0.5"\n}\n',
        encoding="utf-8",
    )
    const_path.write_text(
        const_content or 'VERSION = "v1.0.5"\nOTHER_VERSION = "v1.0.0"\n',
        encoding="utf-8",
    )
    return manifest_path, const_path


def test_update_release_versions_updates_only_release_declarations(tmp_path: Path) -> None:
    """Update both version declarations without changing unrelated versions.

    Args:
        tmp_path (Path): Temporary repository root.
    """
    manifest_path, const_path = _write_version_files(tmp_path)

    prepare_release.update_release_versions(tmp_path, "v1.0.6")

    assert json.loads(manifest_path.read_text(encoding="utf-8"))["version"] == "v1.0.6"
    assert const_path.read_text(encoding="utf-8") == (
        'VERSION = "v1.0.6"\nOTHER_VERSION = "v1.0.0"\n'
    )


def test_update_release_versions_does_not_partially_write(tmp_path: Path) -> None:
    """Leave both files unchanged when either declaration is missing.

    Args:
        tmp_path (Path): Temporary repository root.
    """
    manifest_path, const_path = _write_version_files(tmp_path, 'DOMAIN = "opnsense"\n')
    original_manifest = manifest_path.read_text(encoding="utf-8")
    original_const = const_path.read_text(encoding="utf-8")

    with pytest.raises(ValueError, match="Expected one version declaration"):
        prepare_release.update_release_versions(tmp_path, "v1.0.6")

    assert manifest_path.read_text(encoding="utf-8") == original_manifest
    assert const_path.read_text(encoding="utf-8") == original_const
