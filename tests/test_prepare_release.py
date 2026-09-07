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

INITIAL_TAG = "v1.2.3"
RELEASE_TAG = "v1.2.4"
COMPONENT_PATH = "custom_components/example"


@pytest.mark.parametrize(
    "tag",
    [
        "v1.2",
        "v1.2.3",
        "v1.2.3.4",
        "v1.2.3-beta.1",
        "v1.2.3b1",
    ],
)
def test_validate_release_tag_accepts_supported_formats(tag: str) -> None:
    """Accept supported stable and prerelease tag formats.

    Args:
        tag (str): Supported release tag under test.
    """
    prepare_release.validate_release_tag(tag)


@pytest.mark.parametrize(
    "tag",
    ["", "1.2.3", "v1", "v1.2.3 beta", "v1.2.3;echo-bad"],
)
def test_validate_release_tag_rejects_unsupported_formats(tag: str) -> None:
    """Reject malformed release tags before they reach release commands.

    Args:
        tag (str): Unsupported release tag under test.
    """
    with pytest.raises(ValueError, match="Invalid release tag"):
        prepare_release.validate_release_tag(tag)


@pytest.mark.parametrize(
    ("tag", "prerelease"),
    [
        ("v1.2", False),
        ("v1.2.3", False),
        ("v1.2.3.4", False),
        ("v1.2.3-beta.1", True),
        ("v1.2.3b1", True),
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
        ("v1.2.3-beta.1", False, "Prerelease tag.*requires prerelease=true"),
        ("v1.2.3b1", False, "Prerelease tag.*requires prerelease=true"),
        ("v1.2.3", True, "Stable tag.*requires prerelease=false"),
        ("v1.2.3.4", True, "Stable tag.*requires prerelease=false"),
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


@pytest.mark.parametrize("tag", ["v1.2", "v1.2.3", "v1.2.3.4"])
def test_validate_release_request_accepts_fixed_numeric_component_counts(tag: str) -> None:
    """Accept every supported fixed numeric stable-tag length.

    Args:
        tag (str): Numeric release tag under test.
    """
    prepare_release.validate_release_request(tag, False)


@pytest.mark.parametrize("tag", ["v01.2", "v1.02.3", "v1.2.03", "v1.2.3.04"])
def test_validate_release_request_rejects_leading_zero_components(tag: str) -> None:
    """Reject stable tags with leading zeros at every supported length.

    Args:
        tag (str): Stable tag containing a leading-zero component.
    """
    with pytest.raises(ValueError, match=r"Prerelease tag.*requires prerelease=true"):
        prepare_release.validate_release_request(tag, False)


@pytest.mark.parametrize("tag", ["v1", "v1.2.3.4.5"])
def test_validate_release_request_rejects_unsupported_numeric_lengths(tag: str) -> None:
    """Reject numeric tags outside the fixed two- through four-part range.

    Args:
        tag (str): Numeric tag using an unsupported component count.
    """
    with pytest.raises(ValueError, match="Invalid release tag"):
        prepare_release.validate_release_request(tag, False)


@pytest.mark.parametrize(
    ("bump_type", "expected_tag"),
    [("patch", "v1.0.6"), ("minor", "v1.1.0"), ("major", "v2.0.0")],
)
def test_next_stable_release_tag_uses_highest_stable_version(
    bump_type: str, expected_tag: str
) -> None:
    """Ignore prereleases and malformed tags when incrementing the highest stable release.

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
        "v1.0.5-rc.1",
        "v1.0.5",
    ]

    assert prepare_release.next_stable_release_tag(tags, bump_type) == expected_tag


@pytest.mark.parametrize(
    ("tags", "bump_type", "expected_tag"),
    [
        (["v1.0.5", "v1.0.5.1"], "patch", "v1.0.6"),
        (["v1.0.0", "v1.0.5.1"], "minor", "v1.1.0"),
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
    """Print the next stable tag without writing integration version files.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing CLI inputs.
        capsys (pytest.CaptureFixture[str]): Fixture for capturing CLI output.
    """
    monkeypatch.setattr(sys, "argv", [str(SCRIPT_PATH), "--next-tag", "minor"])
    monkeypatch.setattr(sys, "stdin", io.StringIO("v0.7.4\nv1.0.0-beta.1\nv0.8.1\n"))

    assert prepare_release.main() == 0
    assert capsys.readouterr().out == "v0.9.0\n"


def test_next_tag_cli_considers_fixed_component_counts(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Use supported two- through four-part tags when selecting the next tag.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing CLI inputs.
        capsys (pytest.CaptureFixture[str]): Fixture for capturing CLI output.
    """
    monkeypatch.setattr(sys, "argv", [str(SCRIPT_PATH), "--next-tag", "patch"])
    monkeypatch.setattr(sys, "stdin", io.StringIO("v1.2\nv1.2.3\nv1.2.3.4\n"))

    assert prepare_release.main() == 0
    assert capsys.readouterr().out == "v1.2.4\n"


@pytest.mark.parametrize(
    ("arguments", "expected_message"),
    [
        ((), "Provide exactly one release tag"),
        ((INITIAL_TAG, "--next-tag", "patch"), "Provide exactly one release tag"),
        (("--next-tag", "patch", "--check-only"), "Validation options"),
        (
            ("--next-tag", "patch", "--expected-prerelease", "false"),
            "Validation options",
        ),
        (
            (INITIAL_TAG, "--expected-prerelease", "false"),
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


def test_check_only_cli_preserves_positional_tag_contract(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Validate an explicit positional tag without writing files.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing CLI arguments.
        capsys (pytest.CaptureFixture[str]): Fixture for capturing CLI output.
    """
    monkeypatch.setattr(sys, "argv", [str(SCRIPT_PATH), "--check-only", INITIAL_TAG])

    assert prepare_release.main() == 0
    assert capsys.readouterr().out == ""


def test_check_only_cli_rejects_prerelease_input_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a prerelease tag when the workflow input marks it stable.

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
            "v1.2.3-beta.1",
        ],
    )

    with pytest.raises(SystemExit, match="2"):
        prepare_release.main()


@pytest.mark.parametrize("tag", ["v1.2", "v1.2.3", "v1.2.3.4"])
def test_check_only_cli_accepts_fixed_component_counts(
    monkeypatch: pytest.MonkeyPatch, tag: str
) -> None:
    """Accept each fixed stable component count through the CLI contract.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing CLI arguments.
        tag (str): Stable tag using a supported component count.
    """
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT_PATH),
            "--check-only",
            "--expected-prerelease",
            "false",
            tag,
        ],
    )

    assert prepare_release.main() == 0


def _write_version_files(
    repository: Path,
    *,
    manifest_content: str | None = None,
    const_content: str | None = None,
) -> tuple[Path, Path]:
    """Create representative integration version files.

    Args:
        repository (Path): Temporary repository root.
        manifest_content (str | None): Optional manifest.json content override.
        const_content (str | None): Optional const.py content override.

    Returns:
        tuple[Path, Path]: Paths to manifest.json and const.py.
    """
    integration = repository / COMPONENT_PATH
    integration.mkdir(parents=True)
    manifest_path = integration / "manifest.json"
    const_path = integration / "const.py"
    manifest_path.write_text(
        manifest_content or '{\n  "domain": "example",\n  "version" : "v1.2.3"\n}\n',
        encoding="utf-8",
    )
    const_path.write_text(
        const_content or 'VERSION = "v1.2.3"\nOTHER_VERSION = "v1.0.0"\n',
        encoding="utf-8",
    )
    return manifest_path, const_path


def test_update_release_versions_updates_only_release_declarations(tmp_path: Path) -> None:
    """Update both release declarations without changing unrelated versions.

    Args:
        tmp_path (Path): Temporary repository root.
    """
    manifest_path, const_path = _write_version_files(tmp_path)

    prepare_release.update_release_versions(tmp_path, RELEASE_TAG, COMPONENT_PATH)

    assert json.loads(manifest_path.read_text(encoding="utf-8"))["version"] == RELEASE_TAG
    assert const_path.read_text(encoding="utf-8") == (
        f'VERSION = "{RELEASE_TAG}"\nOTHER_VERSION = "v1.0.0"\n'
    )


def test_default_cli_updates_versions_in_working_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Update both version files through the workflow's default CLI path.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing CLI arguments and
            the process working directory.
        tmp_path (Path): Temporary repository root.
    """
    manifest_path, const_path = _write_version_files(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT_PATH), RELEASE_TAG])

    assert prepare_release.main() == 0
    assert json.loads(manifest_path.read_text(encoding="utf-8"))["version"] == RELEASE_TAG
    assert const_path.read_text(encoding="utf-8") == (
        f'VERSION = "{RELEASE_TAG}"\nOTHER_VERSION = "v1.0.0"\n'
    )


def test_default_cli_rejects_expected_prerelease_without_check_only(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Reject the prerelease option when version preparation is requested.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture for replacing CLI arguments and
            the process working directory.
        tmp_path (Path): Temporary repository root.
        capsys (pytest.CaptureFixture[str]): Fixture for capturing CLI errors.
    """
    manifest_path, const_path = _write_version_files(tmp_path)
    original_manifest = manifest_path.read_text(encoding="utf-8")
    original_const = const_path.read_text(encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT_PATH), "--expected-prerelease", "false", RELEASE_TAG],
    )

    with pytest.raises(SystemExit, match="2"):
        prepare_release.main()

    assert "--expected-prerelease requires --check-only" in capsys.readouterr().err
    assert manifest_path.read_text(encoding="utf-8") == original_manifest
    assert const_path.read_text(encoding="utf-8") == original_const


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param({"const_content": 'DOMAIN = "example"\n'}, id="const-missing"),
        pytest.param(
            {"manifest_content": '{\n  "domain": "example"\n}\n'},
            id="manifest-missing",
        ),
    ],
)
def test_update_release_versions_does_not_partially_write(
    tmp_path: Path, failure: dict[str, str]
) -> None:
    """Leave both files unchanged when either declaration is missing.

    Args:
        tmp_path (Path): Temporary repository root.
        failure (dict[str, str]): Version-file content that should fail validation.
    """
    manifest_path, const_path = _write_version_files(tmp_path, **failure)
    original_manifest = manifest_path.read_text(encoding="utf-8")
    original_const = const_path.read_text(encoding="utf-8")

    with pytest.raises(ValueError, match="Expected one version declaration"):
        prepare_release.update_release_versions(tmp_path, RELEASE_TAG, COMPONENT_PATH)

    assert manifest_path.read_text(encoding="utf-8") == original_manifest
    assert const_path.read_text(encoding="utf-8") == original_const
