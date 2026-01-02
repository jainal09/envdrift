"""SOPS installer helpers for optional auto-install."""

from __future__ import annotations

import json
import platform
import stat
import urllib.request
from pathlib import Path

from envdrift.integrations.dotenvx import get_platform_info, get_venv_bin_dir


class SopsInstallError(Exception):
    """Failed to install SOPS."""

    pass


def _load_constants() -> dict:
    constants_path = Path(__file__).parent.parent / "constants.json"
    with open(constants_path) as f:
        return json.load(f)


def _get_sops_version() -> str:
    return _load_constants()["sops_version"]


def _get_download_url_templates() -> dict[str, str]:
    return _load_constants()["sops_download_urls"]


SOPS_VERSION = _get_sops_version()

_URL_TEMPLATES = _get_download_url_templates()
SOPS_DOWNLOAD_URLS = {
    ("Darwin", "x86_64"): _URL_TEMPLATES["darwin_amd64"],
    ("Darwin", "arm64"): _URL_TEMPLATES["darwin_arm64"],
    ("Linux", "x86_64"): _URL_TEMPLATES["linux_amd64"],
    ("Linux", "aarch64"): _URL_TEMPLATES["linux_arm64"],
    ("Windows", "AMD64"): _URL_TEMPLATES["windows_amd64"],
    ("Windows", "x86_64"): _URL_TEMPLATES["windows_amd64"],
}


def get_sops_path() -> Path:
    bin_dir = get_venv_bin_dir()
    binary_name = "sops.exe" if platform.system() == "Windows" else "sops"
    return bin_dir / binary_name


class SopsInstaller:
    """Install SOPS binary to the virtual environment or user bin directory."""

    def __init__(self, version: str = SOPS_VERSION):
        self.version = version

    def _get_download_url(self) -> str:
        system, machine = get_platform_info()
        template = SOPS_DOWNLOAD_URLS.get((system, machine))
        if not template:
            raise SopsInstallError(f"Unsupported platform: {system} {machine}")
        return template.format(version=self.version)

    def install(self, target_path: Path | None = None) -> Path:
        if target_path is None:
            target_path = get_sops_path()

        target_path.parent.mkdir(parents=True, exist_ok=True)
        url = self._get_download_url()
        tmp_path = target_path.with_suffix(target_path.suffix + ".download")

        try:
            urllib.request.urlretrieve(url, tmp_path)  # nosec B310
            if platform.system() != "Windows":
                st = tmp_path.stat()
                tmp_path.chmod(st.st_mode | stat.S_IEXEC)
            tmp_path.replace(target_path)
        except Exception as e:  # nosec B110
            if tmp_path.exists():
                tmp_path.unlink()
            raise SopsInstallError(f"Failed to install SOPS: {e}") from e

        return target_path
