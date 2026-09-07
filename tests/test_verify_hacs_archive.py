"""Tests for HACS release archive validation."""

from collections.abc import Sequence
import importlib.util
import json
from pathlib import Path
import stat
import struct
import zipfile

import pytest

SCRIPT_PATH = Path(__file__).parents[1] / ".github" / "scripts" / "verify_hacs_archive.py"
SCRIPT_SPEC = importlib.util.spec_from_file_location("verify_hacs_archive", SCRIPT_PATH)
assert SCRIPT_SPEC is not None
assert SCRIPT_SPEC.loader is not None
archive_verifier = importlib.util.module_from_spec(SCRIPT_SPEC)
SCRIPT_SPEC.loader.exec_module(archive_verifier)

RELEASE_TAG = "v1.2.3"


def _archive(
    path: Path,
    extra: Sequence[tuple[str | zipfile.ZipInfo, bytes | str]] | None = None,
    *,
    manifest: bytes | str | None = None,
    const: bytes | str | None = None,
    compression: int = zipfile.ZIP_STORED,
) -> None:
    """Build a small archive with valid version files and optional members.

    Args:
        path (Path): Destination ZIP path.
        extra (Sequence[tuple[str | zipfile.ZipInfo, bytes | str]] | None): Optional members.
        manifest (bytes | str | None): Optional manifest.json contents.
        const (bytes | str | None): Optional const.py contents.
        compression (int): ZIP compression method for string-named members.
    """
    members: list[tuple[str | zipfile.ZipInfo, bytes | str]] = [
        (
            "manifest.json",
            manifest if manifest is not None else json.dumps({"version": RELEASE_TAG}).encode(),
        ),
        ("const.py", const if const is not None else f'VERSION = "{RELEASE_TAG}"\n'),
    ]
    members.extend(extra or [])
    with zipfile.ZipFile(path, "w", compression=compression) as output:
        for name, contents in members:
            output.writestr(name, contents)


def _set_compressed_size(path: Path, member_name: str, compressed_size: int) -> None:
    """Corrupt one central-directory size field for a malformed archive fixture.

    Args:
        path (Path): ZIP archive to modify.
        member_name (str): Member whose central-directory record is changed.
        compressed_size (int): Replacement compressed-size field.

    Raises:
        AssertionError: If the requested member is not present in the archive.
    """
    data = bytearray(path.read_bytes())
    offset = 0
    while (offset := data.find(b"PK\x01\x02", offset)) >= 0:
        name_length = struct.unpack_from("<H", data, offset + 28)[0]
        name_start = offset + 46
        name = bytes(data[name_start : name_start + name_length]).decode()
        if name == member_name:
            struct.pack_into("<I", data, offset + 20, compressed_size)
            path.write_bytes(data)
            return
        offset += 1
    raise AssertionError(f"Archive member not found: {member_name}")


def test_verify_archive_accepts_a_real_zip_artifact(tmp_path: Path) -> None:
    """Accept a normal integration archive produced for the release tag.

    Args:
        tmp_path (Path): Temporary test directory.
    """
    archive = tmp_path / "integration.zip"
    _archive(archive)

    archive_verifier.verify_archive(str(archive), RELEASE_TAG)
    assert archive_verifier.main([str(archive), RELEASE_TAG]) == 0


def test_verify_archive_allows_safe_directory_entries(tmp_path: Path) -> None:
    """Allow directories emitted by git archive while validating their contents.

    Args:
        tmp_path (Path): Temporary test directory.
    """
    archive = tmp_path / "directory.zip"
    _archive(archive, [("client/", b""), ("client/module.py", b"VALUE = 1\n")])

    archive_verifier.verify_archive(str(archive), RELEASE_TAG)


@pytest.mark.parametrize(
    "member", ["", "/absolute.py", "../manifest.json", "nested/../../const.py"]
)
def test_verify_archive_rejects_unsafe_member_paths(tmp_path: Path, member: str) -> None:
    """Reject empty, absolute, and traversal member paths.

    Args:
        tmp_path (Path): Temporary test directory.
        member (str): Unsafe archive member path.
    """
    archive = tmp_path / "unsafe.zip"
    _archive(archive, [(member, b"unsafe")])

    with pytest.raises(archive_verifier.ArchiveError, match="Invalid archive member path"):
        archive_verifier.verify_archive(str(archive), RELEASE_TAG)


def test_verify_archive_rejects_duplicate_members(tmp_path: Path) -> None:
    """Reject duplicate member names before an archive is uploaded.

    Args:
        tmp_path (Path): Temporary test directory.
    """
    archive = tmp_path / "duplicate.zip"
    with pytest.warns(UserWarning, match="Duplicate name"):
        _archive(archive, [("const.py", f'VERSION = "{RELEASE_TAG}"\n')])

    with pytest.raises(archive_verifier.ArchiveError, match="Duplicate archive member"):
        archive_verifier.verify_archive(str(archive), RELEASE_TAG)


@pytest.mark.parametrize("file_type", [stat.S_IFLNK, stat.S_IFIFO])
def test_verify_archive_rejects_non_regular_members(tmp_path: Path, file_type: int) -> None:
    """Reject symlink and other non-regular POSIX members.

    Args:
        tmp_path (Path): Temporary test directory.
        file_type (int): POSIX type encoded in the ZIP member metadata.
    """
    archive = tmp_path / "non-regular.zip"
    info = zipfile.ZipInfo("linked.py")
    info.external_attr = (file_type | 0o644) << 16
    _archive(archive, [(info, b"const.py")])

    with pytest.raises(archive_verifier.ArchiveError, match="not a regular file"):
        archive_verifier.verify_archive(str(archive), RELEASE_TAG)


def test_verify_archive_rejects_empty_and_oversized_file_lists(tmp_path: Path) -> None:
    """Reject empty archives and archives above the member-count bound.

    Args:
        tmp_path (Path): Temporary test directory.
    """
    empty = tmp_path / "empty.zip"
    with zipfile.ZipFile(empty, "w"):
        pass
    with pytest.raises(archive_verifier.ArchiveError, match="invalid number of files"):
        archive_verifier.verify_archive(str(empty), RELEASE_TAG)

    oversized = tmp_path / "many-files.zip"
    extras = [(f"payload-{index}.txt", b"") for index in range(archive_verifier.MAX_FILES)]
    _archive(oversized, extras)
    with pytest.raises(archive_verifier.ArchiveError, match="invalid number of files"):
        archive_verifier.verify_archive(str(oversized), RELEASE_TAG)


def test_verify_archive_rejects_oversized_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reject a member above the configured per-file size bound.

    Args:
        tmp_path (Path): Temporary test directory.
        monkeypatch (pytest.MonkeyPatch): Fixture reducing the test-only bound.
    """
    archive = tmp_path / "oversized-member.zip"
    _archive(archive, [("payload.bin", b"x" * 9)])
    with monkeypatch.context() as context:
        context.setattr(archive_verifier, "MAX_FILE_BYTES", 8)
        with pytest.raises(archive_verifier.ArchiveError, match="size limit"):
            archive_verifier.verify_archive(str(archive), RELEASE_TAG)
    assert archive_verifier.MAX_FILE_BYTES == 10 * 1024 * 1024


def test_verify_archive_rejects_expansion_beyond_cap_with_isolated_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reject 72 expanded bytes against a test-only 64-byte cap.

    Args:
        tmp_path (Path): Temporary test directory.
        monkeypatch (pytest.MonkeyPatch): Fixture isolating the reduced cap.
    """
    archive = tmp_path / "expanded.zip"
    _archive(archive, [("payload.bin", b"x" * 72)])
    with monkeypatch.context() as context:
        context.setattr(archive_verifier, "MAX_EXPANDED_BYTES", 64)
        with pytest.raises(archive_verifier.ArchiveError, match="expanded size"):
            archive_verifier.verify_archive(str(archive), RELEASE_TAG)
    assert archive_verifier.MAX_EXPANDED_BYTES == 64 * 1024 * 1024


def test_verify_archive_rejects_unsafe_compression_ratio(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reject highly compressible members above the configured ratio.

    Args:
        tmp_path (Path): Temporary test directory.
        monkeypatch (pytest.MonkeyPatch): Fixture reducing the test-only ratio.
    """
    archive = tmp_path / "compressed.zip"
    _archive(archive, [("payload.bin", b"x" * 1_024)], compression=zipfile.ZIP_DEFLATED)
    with monkeypatch.context() as context:
        context.setattr(archive_verifier, "MAX_COMPRESSION_RATIO", 2)
        with pytest.raises(archive_verifier.ArchiveError, match="compression ratio"):
            archive_verifier.verify_archive(str(archive), RELEASE_TAG)
    assert archive_verifier.MAX_COMPRESSION_RATIO == 100


def test_verify_archive_rejects_nonzero_file_with_zero_compressed_size(tmp_path: Path) -> None:
    """Reject a malformed member claiming no compressed bytes for payload data.

    Args:
        tmp_path (Path): Temporary test directory.
    """
    archive = tmp_path / "zero-compression.zip"
    _archive(archive, [("payload.bin", b"payload")])
    _set_compressed_size(archive, "payload.bin", 0)

    with pytest.raises(archive_verifier.ArchiveError, match="invalid compression"):
        archive_verifier.verify_archive(str(archive), RELEASE_TAG)


@pytest.mark.parametrize("missing", ["manifest.json", "const.py"])
def test_verify_archive_rejects_missing_version_files(tmp_path: Path, missing: str) -> None:
    """Reject archives missing either required version file.

    Args:
        tmp_path (Path): Temporary test directory.
        missing (str): Required member omitted from the archive.
    """
    archive = tmp_path / f"missing-{missing.replace('.', '-')}.zip"
    members = {
        "manifest.json": json.dumps({"version": RELEASE_TAG}),
        "const.py": f'VERSION = "{RELEASE_TAG}"\n',
    }
    with zipfile.ZipFile(archive, "w") as output:
        for name, contents in members.items():
            if name != missing:
                output.writestr(name, contents)

    with pytest.raises(archive_verifier.ArchiveError, match="required version files"):
        archive_verifier.verify_archive(str(archive), RELEASE_TAG)


def test_verify_archive_rejects_manifest_and_const_version_mismatches(tmp_path: Path) -> None:
    """Reject manifest and const.py versions that differ from the release tag.

    Args:
        tmp_path (Path): Temporary test directory.
    """
    manifest_mismatch = tmp_path / "manifest-mismatch.zip"
    _archive(manifest_mismatch)
    with pytest.raises(archive_verifier.ArchiveError, match="manifest version"):
        archive_verifier.verify_archive(str(manifest_mismatch), "v1.2.4")

    const_mismatch = tmp_path / "const-mismatch.zip"
    _archive(const_mismatch, const='VERSION = "v1.2.4"\n')
    with pytest.raises(archive_verifier.ArchiveError, match=r"const\.py version"):
        archive_verifier.verify_archive(str(const_mismatch), RELEASE_TAG)


def test_verify_archive_rejects_invalid_const_encoding(tmp_path: Path) -> None:
    """Wrap invalid const.py encoding as an archive validation failure.

    Args:
        tmp_path (Path): Temporary test directory.
    """
    archive = tmp_path / "invalid-encoding.zip"
    _archive(archive, const=b"\xff")

    with pytest.raises(archive_verifier.ArchiveError, match="Unable to validate"):
        archive_verifier.verify_archive(str(archive), RELEASE_TAG)


@pytest.mark.parametrize("archive_name", ["missing.zip", "broken.zip"])
def test_verify_archive_rejects_unreadable_archives(tmp_path: Path, archive_name: str) -> None:
    """Wrap missing and malformed ZIP files as archive validation failures.

    Args:
        tmp_path (Path): Temporary test directory.
        archive_name (str): Missing or malformed archive filename.
    """
    archive = tmp_path / archive_name
    if archive_name == "broken.zip":
        archive.write_bytes(b"not a zip archive")

    with pytest.raises(archive_verifier.ArchiveError, match="Unable to validate"):
        archive_verifier.verify_archive(str(archive), RELEASE_TAG)
