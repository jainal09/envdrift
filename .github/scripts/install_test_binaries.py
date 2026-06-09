#!/usr/bin/env python3
"""Install the external CLI binaries the integration tests drive, cross-platform.

Reads pinned versions + download URLs from ``src/envdrift/constants.json`` (the
single source of truth, kept current by Renovate — no hardcoded versions here)
and installs each tool into a per-user bin directory, which it appends to
``GITHUB_PATH`` so later steps and the test subprocesses find them on ``PATH``.

Works on Linux, macOS and Windows. Standalone (no ``envdrift`` import) so the
production installer's own cross-platform behaviour is exercised by *its* tests,
not entangled with the feature tests this enables.

Resilient by design: each tool installs independently and a failure is logged
and skipped (it becomes a real finding — the test that needs it then skips for an
honest "binary absent" reason) rather than aborting every other tool's install.
Exit code is non-zero only if *nothing* installed, so the workflow surfaces a
total failure but tolerates a partial one.
"""

from __future__ import annotations

import json
import os
import platform
import stat
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CONST = json.loads((REPO / "src" / "envdrift" / "constants.json").read_text(encoding="utf-8"))
IS_WIN = sys.platform == "win32"

# (binary name, URL-map key in constants.json, version key in constants.json)
TOOLS: list[tuple[str, str, str]] = [
    ("dotenvx", "download_urls", "dotenvx_version"),
    ("sops", "sops_download_urls", "sops_version"),
    ("gitleaks", "gitleaks_download_urls", "gitleaks_version"),
    ("trufflehog", "trufflehog_download_urls", "trufflehog_version"),
    ("talisman", "talisman_download_urls", "talisman_version"),
    ("trivy", "trivy_download_urls", "trivy_version"),
    ("infisical", "infisical_download_urls", "infisical_version"),
]


def _platform_key(urls: dict[str, str]) -> str:
    osname = {"linux": "linux", "darwin": "darwin", "win32": "windows"}[sys.platform]
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
    key = f"{osname}_{arch}"
    # Fall back to amd64 when a tool publishes no arm64 build for this OS.
    if key not in urls and arch == "arm64":
        key = f"{osname}_amd64"
    return key


def _download(url: str, dest: Path) -> None:
    print(f"    GET {url}")
    urllib.request.urlretrieve(url, dest)


def _make_executable(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _find_binary(root: Path, binary: str) -> Path:
    """Locate the extracted binary by exact name, then by prefix."""
    target = f"{binary}.exe" if IS_WIN else binary
    for candidate in (target, binary):
        matches = [p for p in root.rglob(candidate) if p.is_file()]
        if matches:
            return matches[0]
    matches = [p for p in root.rglob(f"{binary}*") if p.is_file()]
    if matches:
        return matches[0]
    raise FileNotFoundError(f"{binary!r} not found in extracted archive under {root}")


def _install_tool(bindir: Path, binary: str, urls_key: str, version_key: str) -> None:
    urls = CONST[urls_key]
    key = _platform_key(urls)
    if key not in urls:
        raise RuntimeError(f"no download URL for platform {key}")
    url = urls[key].format(version=CONST[version_key])
    final_name = f"{binary}.exe" if IS_WIN else binary
    dest = bindir / final_name
    archive = bindir / Path(url).name

    if url.endswith((".tar.gz", ".tgz")):
        _download(url, archive)
        extract_dir = bindir / f"_{binary}_x"
        with tarfile.open(archive) as tf:
            tf.extractall(extract_dir)
        dest.write_bytes(_find_binary(extract_dir, binary).read_bytes())
    elif url.endswith(".zip"):
        _download(url, archive)
        extract_dir = bindir / f"_{binary}_x"
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(extract_dir)
        dest.write_bytes(_find_binary(extract_dir, binary).read_bytes())
    else:
        # Raw, single-file binary (e.g. sops, talisman).
        _download(url, dest)

    if not IS_WIN:
        _make_executable(dest)
    print(f"    -> {dest}")


def main() -> int:
    bindir = Path.home() / ".envdrift-test-bin"
    bindir.mkdir(parents=True, exist_ok=True)
    print(f"platform={sys.platform}/{platform.machine()}  bindir={bindir}\n")

    installed: list[str] = []
    failed: list[str] = []
    for binary, urls_key, version_key in TOOLS:
        print(f"installing {binary} {CONST[version_key]}")
        try:
            _install_tool(bindir, binary, urls_key, version_key)
            installed.append(binary)
        except Exception as exc:
            print(f"    !! FAILED to install {binary}: {exc}")
            failed.append(binary)

    print(f"\ninstalled: {', '.join(installed) or '(none)'}")
    if failed:
        print(f"failed:    {', '.join(failed)}")

    gh_path = os.environ.get("GITHUB_PATH")
    if gh_path and installed:
        with open(gh_path, "a", encoding="utf-8") as fh:
            fh.write(f"{bindir}\n")

    return 0 if installed else 1


if __name__ == "__main__":
    raise SystemExit(main())
