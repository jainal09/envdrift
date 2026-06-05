"""Integration tests for the dotenvx binary installer/wrapper.

These exercise the real ``DotenvxWrapper`` / ``DotenvxInstaller`` code paths in
``envdrift.integrations.dotenvx`` against the real ``dotenvx`` binary (when on
PATH) and against real archive files on disk. No mocking of the behavior under
test: archives are built with the real ``tarfile`` / ``zipfile`` modules and
extracted by the real installer code.

Tests that require the ``dotenvx`` binary skip (rather than fail) when it is not
installed on this machine.
"""

from __future__ import annotations

import re
import shutil
import tarfile
import zipfile
from pathlib import Path

import pytest

from envdrift.integrations import dotenvx as dotenvx_mod
from envdrift.integrations.dotenvx import (
    DotenvxInstaller,
    DotenvxInstallError,
    DotenvxWrapper,
)

# Mark all tests in this module
pytestmark = [pytest.mark.integration]

_SEMVER_RE = re.compile(r"\d+\.\d+\.\d+")


@pytest.fixture
def real_dotenvx_on_path() -> str:
    """Return the path to a real ``dotenvx`` binary or skip the test."""
    path = shutil.which("dotenvx")
    if path is None:
        pytest.skip("dotenvx binary not found on PATH")
    return path


def test_get_version_returns_real_dotenvx_version_string(
    real_dotenvx_on_path: str,
) -> None:
    """HP-11: get_version() returns the real ``--version`` string and is stable."""
    wrapper = DotenvxWrapper(auto_install=False)

    version = wrapper.get_version()

    assert isinstance(version, str)
    assert version, "version string must be non-empty"
    assert _SEMVER_RE.search(version), f"expected a semver in {version!r}"

    # Two calls return the same value (binary path is cached on first lookup).
    second = wrapper.get_version()
    assert second == version


def test_binary_discovery_uses_system_path_when_venv_absent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    real_dotenvx_on_path: str,
) -> None:
    """HP-14: with an empty venv bin, ``_find_binary`` falls back to PATH."""
    # Build an empty venv whose bin dir contains NO dotenvx binary.
    venv = tmp_path / "venv"
    bin_dir = venv / "bin"
    bin_dir.mkdir(parents=True)
    monkeypatch.setenv("VIRTUAL_ENV", str(venv))

    wrapper = DotenvxWrapper(auto_install=False)
    resolved = wrapper.binary_path

    which_dotenvx = shutil.which("dotenvx")
    assert which_dotenvx is not None, "dotenvx must be on PATH for this test"
    expected = Path(which_dotenvx)
    assert resolved == expected
    assert resolved.exists()
    # Resolution did NOT come from the empty venv we created.
    assert str(venv) not in str(resolved)


def test_get_download_url_unsupported_platform_raises_install_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BP-09: get_download_url() rejects an unsupported platform tuple."""
    monkeypatch.setattr(
        dotenvx_mod,
        "get_platform_info",
        lambda: ("Plan9", "sparc"),
    )

    installer = DotenvxInstaller()
    with pytest.raises(DotenvxInstallError) as exc_info:
        installer.get_download_url()

    message = str(exc_info.value)
    assert "Unsupported platform" in message
    assert "Plan9" in message
    assert "sparc" in message


def test_download_failure_unreachable_url_raises_install_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BP-10: a download against an unreachable URL raises a clear error."""
    # Port 1 is privileged and never listening -> urlopen fails fast.
    unreachable = "http://127.0.0.1:1/dotenvx.tar.gz"
    monkeypatch.setattr(
        DotenvxInstaller,
        "get_download_url",
        lambda self: unreachable,
    )

    target = tmp_path / "bin" / "dotenvx"
    installer = DotenvxInstaller()
    with pytest.raises(DotenvxInstallError) as exc_info:
        installer.download_and_extract(target)

    assert str(exc_info.value).startswith("Download failed:")
    # Nothing was installed at the target.
    assert not target.exists()


def test_extract_archive_missing_binary_raises_install_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BP-11: a real tar.gz lacking the dotenvx binary is rejected after extract."""
    # Build a real .tar.gz containing only a README (no dotenvx binary).
    src = tmp_path / "src"
    src.mkdir()
    readme = src / "README.txt"
    readme.write_text("no binary here\n", encoding="utf-8")

    archive = tmp_path / "dotenvx.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(readme, arcname="README.txt")

    # Serve the local archive via file:// so the real download path runs.
    monkeypatch.setattr(
        DotenvxInstaller,
        "get_download_url",
        lambda self: archive.as_uri(),
    )

    target = tmp_path / "out" / "dotenvx"
    installer = DotenvxInstaller()
    with pytest.raises(DotenvxInstallError) as exc_info:
        installer.download_and_extract(target)

    assert "not found in archive" in str(exc_info.value)
    # The binary was never produced at the target path.
    assert not target.exists()


def test_extract_tar_gz_path_traversal_member_rejected(tmp_path: Path) -> None:
    """BP-12: a tar member escaping the target dir is rejected."""
    target_dir = tmp_path / "extract"
    target_dir.mkdir()
    parent = tmp_path  # member '../evil.txt' would land here if not guarded

    # Build a malicious tar.gz with a traversal member name.
    payload = tmp_path / "payload.txt"
    payload.write_text("pwned\n", encoding="utf-8")
    archive = tmp_path / "evil.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(payload, arcname="../evil.txt")

    installer = DotenvxInstaller()
    with pytest.raises(DotenvxInstallError) as exc_info:
        installer._extract_tar_gz(archive, target_dir)

    message = str(exc_info.value)
    assert "Unsafe path in archive" in message
    assert "../evil" in message
    # The guard fired BEFORE any extraction, so nothing escaped.
    assert not (parent / "evil.txt").exists()


def test_extract_zip_path_traversal_member_rejected(tmp_path: Path) -> None:
    """BP-12 (zip): a zip member escaping the target dir is rejected."""
    target_dir = tmp_path / "extract"
    target_dir.mkdir()
    parent = tmp_path

    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../evil.txt", "pwned\n")

    installer = DotenvxInstaller()
    with pytest.raises(DotenvxInstallError) as exc_info:
        installer._extract_zip(archive, target_dir)

    assert "Unsafe path in archive" in str(exc_info.value)
    # Nothing escaped the target directory.
    assert not (parent / "evil.txt").exists()


def test_tar_extraction_fallback_when_filter_unsupported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """XC-06: tar fallback runs when ``filter=`` kwarg is unsupported (Py<3.12)."""
    # Build a real, safe tar.gz that contains a dotenvx binary.
    src = tmp_path / "src"
    src.mkdir()
    binary = src / "dotenvx"
    binary.write_text("#!/bin/sh\necho fake\n", encoding="utf-8")
    archive = tmp_path / "dotenvx.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(binary, arcname="dotenvx")

    target_dir = tmp_path / "extract"
    target_dir.mkdir()

    # Simulate the Python<3.12 tarfile API: extractall rejects the
    # ``filter`` keyword with TypeError, forcing the documented fallback.
    real_extractall = tarfile.TarFile.extractall

    def extractall_no_filter(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        if "filter" in kwargs:
            raise TypeError("extractall() got an unexpected keyword argument 'filter'")
        return real_extractall(self, *args, **kwargs)

    monkeypatch.setattr(tarfile.TarFile, "extractall", extractall_no_filter)

    installer = DotenvxInstaller()
    # Must not raise: the fallback (unfiltered extractall) handles it.
    installer._extract_tar_gz(archive, target_dir)

    assert (target_dir / "dotenvx").exists()
    assert (target_dir / "dotenvx").read_text(encoding="utf-8").startswith("#!/bin/sh")
