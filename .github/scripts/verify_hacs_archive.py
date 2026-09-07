"""Validate a release HACS archive before it is uploaded."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
from pathlib import PurePosixPath
import stat
import zipfile

MAX_FILES = 1_000
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100
REQUIRED_FILES = frozenset({"manifest.json", "const.py"})


class ArchiveError(ValueError):
    """Raised when a release archive is not a safe integration archive."""


def _validate_name(name: str) -> None:
    """Reject archive member names that can escape the integration root.

    Args:
        name (str): Archive member filename.

    Raises:
        ArchiveError: If the filename is absolute, a directory, or traverses upward.
    """
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts:
        raise ArchiveError(f"Invalid archive member path: {name!r}")


def _validate_regular_file(member: zipfile.ZipInfo) -> None:
    """Reject symlinks and non-regular POSIX members when metadata is present.

    Args:
        member (zipfile.ZipInfo): ZIP member metadata to inspect.

    Raises:
        ArchiveError: If POSIX metadata identifies a non-regular member.
    """
    mode = member.external_attr >> 16
    file_type = stat.S_IFMT(mode)
    if file_type and not stat.S_ISREG(mode):
        raise ArchiveError(f"Archive member is not a regular file: {member.filename!r}")


def verify_archive(archive_path: str, release_tag: str) -> None:
    """Verify HACS archive structure, resource bounds, and embedded versions.

    Args:
        archive_path (str): Path to the ZIP archive.
        release_tag (str): Exact tag expected in the integration version files.

    Raises:
        ArchiveError: If the archive is unreadable, unsafe, or version-mismatched.
    """
    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            if not members or len(members) > MAX_FILES:
                raise ArchiveError("Archive has an invalid number of files.")
            names: set[str] = set()
            expanded_bytes = 0
            for member in members:
                _validate_name(member.filename)
                if member.filename in names:
                    raise ArchiveError(f"Duplicate archive member: {member.filename!r}")
                names.add(member.filename)
                if member.is_dir():
                    continue
                _validate_regular_file(member)
                if member.file_size > MAX_FILE_BYTES:
                    raise ArchiveError(f"Archive member exceeds size limit: {member.filename!r}")
                expanded_bytes += member.file_size
                if expanded_bytes > MAX_EXPANDED_BYTES:
                    raise ArchiveError("Archive expanded size exceeds limit.")
                if member.file_size and member.compress_size == 0:
                    raise ArchiveError(
                        f"Archive member has invalid compression: {member.filename!r}"
                    )
                if (
                    member.compress_size
                    and member.file_size / member.compress_size > MAX_COMPRESSION_RATIO
                ):
                    raise ArchiveError(
                        f"Archive member compression ratio is unsafe: {member.filename!r}"
                    )
            if not names >= REQUIRED_FILES:
                raise ArchiveError("Archive does not contain required version files.")
            manifest = json.loads(archive.read("manifest.json"))
            if not isinstance(manifest, dict) or manifest.get("version") != release_tag:
                raise ArchiveError("Archive manifest version does not match the release tag.")
            const = archive.read("const.py").decode("utf-8")
            if f'VERSION = "{release_tag}"' not in const.splitlines():
                raise ArchiveError("Archive const.py version does not match the release tag.")
    except (OSError, UnicodeDecodeError, zipfile.BadZipFile) as error:
        raise ArchiveError(f"Unable to validate release archive: {error}") from error


def main(argv: Sequence[str] | None = None) -> int:
    """Run archive validation from the command line.

    Args:
        argv (Sequence[str] | None): Optional arguments excluding executable name.

    Returns:
        int: Zero after successful archive validation.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive")
    parser.add_argument("release_tag")
    args = parser.parse_args(argv)
    verify_archive(args.archive, args.release_tag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
