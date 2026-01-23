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
