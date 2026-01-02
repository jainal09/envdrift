"""Tests for envdrift.integrations.sops module."""

from __future__ import annotations

import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from envdrift.integrations.sops import SopsInstaller, SopsInstallError, get_sops_path


def test_get_sops_path_uses_venv_bin(monkeypatch, tmp_path: Path):
    """get_sops_path should resolve to venv bin directory."""
    monkeypatch.setattr("envdrift.integrations.sops.get_venv_bin_dir", lambda: tmp_path)
    monkeypatch.setattr("platform.system", lambda: "Linux")

    assert get_sops_path() == tmp_path / "sops"


def test_get_sops_path_windows(monkeypatch, tmp_path: Path):
    """get_sops_path should use .exe on Windows."""
    monkeypatch.setattr("envdrift.integrations.sops.get_venv_bin_dir", lambda: tmp_path)
    monkeypatch.setattr("platform.system", lambda: "Windows")

    assert get_sops_path().name == "sops.exe"


def test_install_downloads_binary(monkeypatch, tmp_path: Path):
    """Installer downloads binary into target path."""
    target_dir = tmp_path / "bin"
    monkeypatch.setattr("envdrift.integrations.sops.get_venv_bin_dir", lambda: target_dir)
    monkeypatch.setattr("platform.system", lambda: "Linux")

    def fake_urlretrieve(_url: str, filename: str):
        Path(filename).write_text("binary")
        return filename, None

    monkeypatch.setattr("envdrift.integrations.sops.urllib.request.urlretrieve", fake_urlretrieve)
    monkeypatch.setattr(
        "envdrift.integrations.sops.SopsInstaller._get_download_url",
        lambda _self: "https://example.com/sops",
    )

    installer = SopsInstaller(version="0.0.0")
    binary_path = installer.install()

    assert binary_path.exists()
    assert binary_path.name == "sops"
    assert binary_path.stat().st_mode & stat.S_IEXEC


def test_install_unsupported_platform():
    """Installer raises for unsupported platforms."""
    installer = SopsInstaller(version="0.0.0")
    with (
        patch("envdrift.integrations.sops.get_platform_info", return_value=("AIX", "ppc")),
        pytest.raises(SopsInstallError),
    ):
        installer._get_download_url()


def test_get_download_url_supported(monkeypatch):
    """Installer returns platform download URL with version."""
    installer = SopsInstaller(version="9.9.9")
    monkeypatch.setattr("envdrift.integrations.sops.get_platform_info", lambda: ("Linux", "x86_64"))
    url = installer._get_download_url()
    assert "9.9.9" in url


def test_install_failure_cleans_temp_file(monkeypatch, tmp_path: Path):
    """Installer should remove temp file on failure."""
    target = tmp_path / "sops"
    monkeypatch.setattr("envdrift.integrations.sops.get_sops_path", lambda: target)
    monkeypatch.setattr("envdrift.integrations.sops.platform.system", lambda: "Linux")

    def fake_urlretrieve(_url: str, filename: str):
        Path(filename).write_text("partial")
        raise RuntimeError("boom")

    monkeypatch.setattr("envdrift.integrations.sops.urllib.request.urlretrieve", fake_urlretrieve)

    installer = SopsInstaller(version="0.0.0")
    with pytest.raises(SopsInstallError):
        installer.install()

    tmp_file = target.with_suffix(".download")
    assert not tmp_file.exists()
