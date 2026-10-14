"""Shared platform utilities for scanner modules.

This module contains common utility functions used across all scanner
implementations to avoid code duplication.
"""

from __future__ import annotations

import os
import platform
import sys
import tarfile
import zipfile
from pathlib import Path


def get_platform_info() -> tuple[str, str]:
    """Get current platform and architecture.

    Returns:
        Tuple of (system, machine) normalized for download URLs.
        - system: Darwin, Linux, or Windows (capitalized)
        - machine: x86_64 or arm64
    """
    system = platform.system()
    machine = platform.machine()

    # Normalize architecture names
    if machine in ("AMD64", "amd64"):
        machine = "x86_64"
    elif machine in ("arm64", "aarch64"):
        machine = "arm64"
    elif machine == "x86_64":
        pass  # Keep as is

    return system, machine


def scan_argument(path: Path) -> str:
    """The path argument for a gitleaks or Infisical run on ``path``.

    Both binaries run in our cwd and get ``path`` as given, the way a user runs
    ``gitleaks dir <path>`` from that directory. They report each finding's
    ``File``, which their ignore-file fingerprints are built from, as that
    argument joined with the file's path below it: relative in, relative out,
    absolute in, absolute out. So ``File`` is already a path from our cwd, and
    a repo-root ``.gitleaksignore`` matches a file the same way whichever path
    reached it (#854). In history mode ``File`` is relative to the repository
    root instead.

    A directory gets a trailing separator. Given a symlink to a directory as
    the root, both binaries treat it as a file and skip it without an error;
    with the separator, path resolution follows the link and they walk the
    directory (#853). The separator does not change ``File``. A symlink to a
    file is skipped even as the root, so it is passed as its target (see
    :func:`symlinked_file`).

    Both binaries build each walked file's path by joining it onto the
    directory and cleaning the result lexically. After a symlink, ``..`` names
    the link target's parent, so in ``linkproj/..`` the cleaned path of every
    file names a file that is not there, and they skip it without an error. A
    directory whose ``..`` changes meaning that way is passed in its physical
    form.

    Args:
        path: File or directory to scan, absolute or relative to the cwd.

    Returns:
        The argument to give the binary.
    """
    if path.is_dir():
        path = _without_ambiguous_parent_refs(path)
        # ``.`` (``guard .``) and filesystem roots have no name and keep their form.
        return f"{path}{os.sep}" if path.name else str(path)
    if symlinked_file(path) is None:
        return str(path)
    return str(_physical(path))


def symlinked_file(path: Path) -> Path | None:
    """``path`` when it is a symlink to a file, otherwise ``None``.

    gitleaks and Infisical skip a symlink to a file even when it is the path
    they are given, so :func:`scan_argument` gives them its target and they
    name the target in every finding. Each of those findings belongs to the
    link the caller gave, the name the native scanner reports it by, so the
    scanners report them under that name, which path-based ignores match.
    """
    return path if path.is_symlink() and path.is_file() else None


def _physical(path: Path) -> Path:
    """``path`` with every symlink resolved, relative to the cwd if ``path`` is."""
    target = path.resolve()
    if path.is_absolute():
        return target
    try:
        return Path(os.path.relpath(target))
    except ValueError:
        # Windows: a target on another drive than the cwd has no relative form.
        return target


def _without_ambiguous_parent_refs(path: Path) -> Path:
    """``path``, or its physical form when cleaning it lexically changes what it names.

    Only ``..`` changes meaning under lexical cleaning, and only after a
    symlink on POSIX: Windows collapses ``..`` lexically itself.
    """
    if os.pardir not in path.parts:
        return path
    try:
        if Path(os.path.normpath(path)).resolve() == path.resolve():
            return path
        return _physical(path)
    except (OSError, RuntimeError):  # RuntimeError: a symlink loop before Python 3.13
        return path


def get_venv_bin_dir() -> Path:
    """Get the virtual environment's bin directory.

    Returns:
        Path to the bin directory where binaries should be installed.

    Raises:
        RuntimeError: If no suitable bin directory can be found.
    """
    # Check for virtual environment
    venv_path = os.environ.get("VIRTUAL_ENV")
    if venv_path:
        venv = Path(venv_path)
        if platform.system() == "Windows":
            return venv / "Scripts"
        return venv / "bin"

    # Try to find venv relative to the package
    for path in sys.path:
        p = Path(path)
        if ".venv" in p.parts or "venv" in p.parts:
            while p.name not in (".venv", "venv") and p.parent != p:
                p = p.parent
            if p.name in (".venv", "venv"):
                if platform.system() == "Windows":
                    return p / "Scripts"
                return p / "bin"

    # Default to .venv in current directory
    cwd_venv = Path.cwd() / ".venv"
    if cwd_venv.exists():
        if platform.system() == "Windows":
            return cwd_venv / "Scripts"
        return cwd_venv / "bin"

    # Fallback to user bin directory
    if platform.system() == "Windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            user_scripts = Path(appdata) / "Python" / "Scripts"
            user_scripts.mkdir(parents=True, exist_ok=True)
            return user_scripts
    else:
        user_bin = Path.home() / ".local" / "bin"
        user_bin.mkdir(parents=True, exist_ok=True)
        return user_bin

    raise RuntimeError("Cannot find suitable bin directory for installation")


def safe_extract_tar(
    tar_file: tarfile.TarFile,
    target_dir: Path,
    error_class: type[Exception],
) -> None:
    """Safely extract a tar archive with path traversal protection.

    Args:
        tar_file: Open tarfile object to extract from.
        target_dir: Directory to extract to.
        error_class: Exception class to raise on unsafe paths.

    Raises:
        error_class: If an archive member has an unsafe path.
    """
    for member in tar_file.getmembers():
        member_path = target_dir / member.name
        if not member_path.resolve().is_relative_to(target_dir.resolve()):
            raise error_class(f"Unsafe path in archive: {member.name}")
        tar_file.extract(member, target_dir, filter="data")


def safe_extract_zip(
    zip_file: zipfile.ZipFile,
    target_dir: Path,
    error_class: type[Exception],
) -> None:
    """Safely extract a zip archive with path traversal protection.

    Args:
        zip_file: Open zipfile object to extract from.
        target_dir: Directory to extract to.
        error_class: Exception class to raise on unsafe paths.

    Raises:
        error_class: If an archive member has an unsafe path.
    """
    for member in zip_file.namelist():
        member_path = target_dir / member
        if not member_path.resolve().is_relative_to(target_dir.resolve()):
            raise error_class(f"Unsafe path in archive: {member}")
        zip_file.extract(member, target_dir)
