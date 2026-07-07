"""SOPS installer helpers for optional auto-install."""

from __future__ import annotations

import json
import platform
import shutil
import stat
import urllib.request
from pathlib import Path

from envdrift.install_integrity import verify_download
from envdrift.integrations.dotenvx import (
    DOWNLOAD_TIMEOUT_SECONDS,
    get_platform_info,
    get_venv_bin_dir,
)


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


def _get_checksums_url_template() -> str:
    return _load_constants().get("sops_checksums_url", "")


SOPS_VERSION = _get_sops_version()

SOPS_CHECKSUMS_URL_TEMPLATE = _get_checksums_url_template()

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

    def get_checksums_url(self) -> str:
        """Get the URL of the upstream-published checksums file for this version."""
        template = SOPS_CHECKSUMS_URL_TEMPLATE
        return template.format(version=self.version) if template else ""

    def install(self, target_path: Path | None = None) -> Path:
        """Download, verify, and install the SOPS binary.

        The downloaded binary's SHA256 is checked against the upstream
        checksums file BEFORE it replaces the target path; verification fails
        closed, so a tampered or unverifiable download never replaces a
        previously working binary (#490).
        """
        if target_path is None:
            target_path = get_sops_path()

        target_path.parent.mkdir(parents=True, exist_ok=True)
        url = self._get_download_url()
        tmp_path = target_path.with_suffix(target_path.suffix + ".download")

        try:
            # Bounded download (mirrors the dotenvx installer fix, #311): the
            # urlopen timeout caps connect and every socket read, so a server
            # that accepts the connection and then stalls cannot hang
            # auto-install forever. urlretrieve has no timeout parameter (#475).
            # Stream in chunks rather than response.read(): buffering the whole
            # binary would double peak memory, and each chunked read still gets
            # the same per-read socket timeout.
            with (
                urllib.request.urlopen(  # nosec B310
                    url, timeout=DOWNLOAD_TIMEOUT_SECONDS
                ) as response,
                tmp_path.open("wb") as tmp_file,
            ):
                shutil.copyfileobj(response, tmp_file)
            # Verify against the published checksums before installing.
            verify_download(tmp_path, url.split("/")[-1], self.get_checksums_url(), "sops")
            if platform.system() != "Windows":
                st = tmp_path.stat()
                tmp_path.chmod(st.st_mode | stat.S_IEXEC)
            tmp_path.replace(target_path)
        except Exception as e:  # nosec B110
            if tmp_path.exists():
                tmp_path.unlink()
            raise SopsInstallError(f"Failed to install SOPS from {url}: {e}") from e

        return target_path
