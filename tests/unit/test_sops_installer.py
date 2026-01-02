"""Tests for envdrift.integrations.sops module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from envdrift.integrations.sops import SopsInstaller, SopsInstallError, get_sops_path


def test_get_sops_path_uses_venv_bin(monkeypatch, tmp_path: Path):
    """get_sops_path should resolve to venv bin directory."""
    monkeypatch.setattr("envdrift.integrations.sops.get_venv_bin_dir", lambda: tmp_path)
    monkeypatch.setattr("platform.system", lambda: "Linux")

    assert get_sops_path() == tmp_path / "sops"


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


def test_install_unsupported_platform():
    """Installer raises for unsupported platforms."""
    installer = SopsInstaller(version="0.0.0")
    with (
        patch("envdrift.integrations.sops.get_platform_info", return_value=("AIX", "ppc")),
        pytest.raises(SopsInstallError),
    ):
        installer._get_download_url()
