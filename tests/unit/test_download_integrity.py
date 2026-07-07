"""Regression tests for #490: binary download integrity must fail closed.

Every auto-install download path (scanner installers, the dotenvx/sops
integrations, and ``envdrift install agent``) must verify the artifact's
SHA256 against the upstream-published checksums file BEFORE the binary is
placed on its final path, and must abort loudly when the checksum is
missing, unreachable, or mismatched.

These tests drive the real installers and the real CLI against a local HTTP
server (a real download over a real socket); only configuration (download /
checksums URLs, HOME / PATH, install destination discovery) is monkeypatched.
"""

from __future__ import annotations

import hashlib
import io
import json
import socket
import sys
import tarfile
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import envdrift
import envdrift.integrations.dotenvx as dotenvx_mod
import envdrift.integrations.sops as sops_mod
import envdrift.scanner.gitleaks as gitleaks_mod
import envdrift.scanner.infisical as infisical_mod
import envdrift.scanner.talisman as talisman_mod
import envdrift.scanner.trivy as trivy_mod
import envdrift.scanner.trufflehog as trufflehog_mod
from envdrift.cli import app
from envdrift.cli_commands import install as install_mod

runner = CliRunner()

CONSTANTS_PATH = Path(envdrift.__file__).parent / "constants.json"

# Every key the installers may look up for the current platform.
ALL_URL_KEYS = (
    "darwin_amd64",
    "darwin_arm64",
    "linux_amd64",
    "linux_arm64",
    "windows_amd64",
)

WRONG_DIGEST = "0" * 64

IS_WINDOWS = sys.platform == "win32"


class _QuietHandler(SimpleHTTPRequestHandler):
    """SimpleHTTPRequestHandler without per-request stderr logging."""

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture
def file_server(tmp_path: Path):
    """Serve a tmp docroot over real HTTP on an ephemeral localhost port."""
    docroot = tmp_path / "release-server"
    docroot.mkdir()
    handler = partial(_QuietHandler, directory=str(docroot))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        yield SimpleNamespace(base_url=base_url, docroot=docroot)
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _make_tar_gz(docroot: Path, archive_name: str, binary_name: str, payload: bytes) -> bytes:
    """Create a .tar.gz archive containing a single fake binary; return its bytes."""
    buffer = io.BytesIO()
    info = tarfile.TarInfo(name=binary_name)
    info.size = len(payload)
    info.mode = 0o755
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        tar.addfile(info, io.BytesIO(payload))
    data = buffer.getvalue()
    (docroot / archive_name).write_bytes(data)
    return data


def _write_checksums(docroot: Path, name: str, entries: dict[str, str]) -> None:
    lines = "".join(f"{digest}  {fname}\n" for fname, digest in entries.items())
    (docroot / name).write_text(lines, encoding="utf-8")


def _exe(tool: str) -> str:
    return f"{tool}.exe" if IS_WINDOWS else tool


# ---------------------------------------------------------------------------
# constants.json must carry a checksums URL for every downloaded tool
# ---------------------------------------------------------------------------


def test_constants_declare_checksums_url_for_every_downloaded_tool():
    """Each auto-installed tool needs an upstream checksums URL in constants.json.

    The templates must use the ``{version}`` placeholder so Renovate version
    bumps keep working without touching the checksums URL (no hardcoded
    versions in the URL).
    """
    constants = json.loads(CONSTANTS_PATH.read_text(encoding="utf-8"))
    downloaded_tools = (
        "dotenvx",
        "sops",
        "gitleaks",
        "trufflehog",
        "talisman",
        "trivy",
        "infisical",
    )
    for tool in downloaded_tools:
        key = f"{tool}_checksums_url"
        assert key in constants, f"constants.json is missing {key} (see #490)"
        url = constants[key]
        assert url.startswith("https://"), f"{key} must be an https URL"
        assert "{version}" in url, f"{key} must use the {{version}} placeholder (Renovate-managed)"


# ---------------------------------------------------------------------------
# Scanner auto-install (archive-based: gitleaks/trufflehog/trivy/infisical)
# ---------------------------------------------------------------------------

SCANNER_CASES = [
    pytest.param(gitleaks_mod, "Gitleaks", "gitleaks", id="gitleaks"),
    pytest.param(trufflehog_mod, "Trufflehog", "trufflehog", id="trufflehog"),
    pytest.param(trivy_mod, "Trivy", "trivy", id="trivy"),
    pytest.param(infisical_mod, "Infisical", "infisical", id="infisical"),
]


def _point_scanner_at_server(monkeypatch, mod, tool: str, server, archive_name: str) -> None:
    """Point a scanner module's download + checksums URLs at the local server."""
    urls = dict.fromkeys(ALL_URL_KEYS, f"{server.base_url}/{archive_name}")
    monkeypatch.setattr(mod, f"_get_{tool}_download_urls", lambda: urls)
    monkeypatch.setattr(
        mod,
        f"_get_{tool}_checksums_url",
        lambda: f"{server.base_url}/checksums.txt",
        raising=False,
    )


@pytest.mark.parametrize(("mod", "prefix", "tool"), SCANNER_CASES)
class TestScannerAutoInstallIntegrity:
    """Scanner installers must verify SHA256 before installing (see #490)."""

    def test_tampered_archive_is_rejected_before_install(
        self, mod, prefix, tool, file_server, tmp_path: Path, monkeypatch
    ):
        """A download whose hash mismatches the published checksum must not install."""
        archive_name = f"{tool}-release.tar.gz"
        _make_tar_gz(file_server.docroot, archive_name, _exe(tool), b"tampered-binary-bytes")
        # The published checksum does NOT match the served (tampered) archive.
        _write_checksums(file_server.docroot, "checksums.txt", {archive_name: WRONG_DIGEST})
        _point_scanner_at_server(monkeypatch, mod, tool, file_server, archive_name)

        installer = getattr(mod, f"{prefix}Installer")()
        install_error = getattr(mod, f"{prefix}InstallError")
        target = tmp_path / "bin" / _exe(tool)

        with pytest.raises(install_error):
            installer.download_and_extract(target)
        assert not target.exists(), "tampered binary must never reach the install path"

    def test_missing_checksums_fails_closed(
        self, mod, prefix, tool, file_server, tmp_path: Path, monkeypatch
    ):
        """No checksums published (HTTP 404) must abort the install, not skip verification."""
        archive_name = f"{tool}-release.tar.gz"
        _make_tar_gz(file_server.docroot, archive_name, _exe(tool), b"unverifiable-binary")
        # checksums.txt is intentionally NOT served.
        _point_scanner_at_server(monkeypatch, mod, tool, file_server, archive_name)

        installer = getattr(mod, f"{prefix}Installer")()
        install_error = getattr(mod, f"{prefix}InstallError")
        target = tmp_path / "bin" / _exe(tool)

        with pytest.raises(install_error):
            installer.download_and_extract(target)
        assert not target.exists(), "unverifiable binary must never reach the install path"

    def test_verified_archive_installs(
        self, mod, prefix, tool, file_server, tmp_path: Path, monkeypatch
    ):
        """A download matching the published checksum installs normally."""
        payload = b"good-binary-payload"
        archive_name = f"{tool}-release.tar.gz"
        archive_bytes = _make_tar_gz(file_server.docroot, archive_name, _exe(tool), payload)
        _write_checksums(
            file_server.docroot, "checksums.txt", {archive_name: _sha256_bytes(archive_bytes)}
        )
        _point_scanner_at_server(monkeypatch, mod, tool, file_server, archive_name)

        installer = getattr(mod, f"{prefix}Installer")()
        target = tmp_path / "bin" / _exe(tool)

        installer.download_and_extract(target)
        assert target.exists()
        assert target.read_bytes() == payload

    def test_failed_final_install_keeps_previous_binary(
        self, mod, prefix, tool, file_server, tmp_path: Path, monkeypatch
    ):
        """Regression (#519 cubic P1): the final install is atomic — a copy that
        fails mid-way (disk full / crash) must leave a previously working binary
        intact and leave no partial/staging file behind."""
        import envdrift.install_integrity as integrity_mod

        payload = b"good-binary-payload"
        archive_name = f"{tool}-release.tar.gz"
        archive_bytes = _make_tar_gz(file_server.docroot, archive_name, _exe(tool), payload)
        _write_checksums(
            file_server.docroot, "checksums.txt", {archive_name: _sha256_bytes(archive_bytes)}
        )
        _point_scanner_at_server(monkeypatch, mod, tool, file_server, archive_name)

        target = tmp_path / "bin" / _exe(tool)
        target.parent.mkdir(parents=True)
        target.write_bytes(b"previously-working-binary")

        def boom_copy(*_a, **_k):
            raise OSError("simulated disk full during install")

        monkeypatch.setattr(integrity_mod.shutil, "copy2", boom_copy)

        installer = getattr(mod, f"{prefix}Installer")()
        install_error = getattr(mod, f"{prefix}InstallError")
        with pytest.raises(install_error):
            installer.download_and_extract(target)

        assert target.read_bytes() == b"previously-working-binary", (
            "a failed install must not corrupt the previously working binary"
        )
        leftovers = [p.name for p in target.parent.iterdir() if p.name != target.name]
        assert leftovers == [], f"staging file(s) left behind: {leftovers}"


# ---------------------------------------------------------------------------
# Talisman (direct binary download, no archive)
# ---------------------------------------------------------------------------


class TestTalismanInstallIntegrity:
    """Talisman downloads a bare binary; it must be verified before install."""

    def _point_at_server(self, monkeypatch, server, asset_name: str) -> None:
        urls = dict.fromkeys(ALL_URL_KEYS, f"{server.base_url}/{asset_name}")
        monkeypatch.setattr(talisman_mod, "_get_talisman_download_urls", lambda: urls)
        monkeypatch.setattr(
            talisman_mod,
            "_get_talisman_checksums_url",
            lambda: f"{server.base_url}/checksums",
            raising=False,
        )

    def test_tampered_binary_does_not_replace_existing(
        self, file_server, tmp_path: Path, monkeypatch
    ):
        """A tampered download must neither install nor clobber a working binary."""
        asset = "talisman_test_binary"
        (file_server.docroot / asset).write_bytes(b"tampered-talisman")
        _write_checksums(file_server.docroot, "checksums", {asset: WRONG_DIGEST})
        self._point_at_server(monkeypatch, file_server, asset)

        target = tmp_path / "bin" / _exe("talisman")
        target.parent.mkdir(parents=True)
        target.write_bytes(b"previously-working-talisman")

        installer = talisman_mod.TalismanInstaller()
        with pytest.raises(talisman_mod.TalismanInstallError):
            installer.download_binary(target)

        assert target.read_bytes() == b"previously-working-talisman", (
            "a tampered download must not replace the previously installed binary"
        )
        leftovers = [p.name for p in target.parent.iterdir() if p.name != target.name]
        assert leftovers == [], f"staging file(s) left behind: {leftovers}"

    def test_missing_checksums_fails_closed(self, file_server, tmp_path: Path, monkeypatch):
        """No published checksums must abort instead of installing unverified."""
        asset = "talisman_test_binary"
        (file_server.docroot / asset).write_bytes(b"unverifiable-talisman")
        self._point_at_server(monkeypatch, file_server, asset)

        target = tmp_path / "bin" / _exe("talisman")
        installer = talisman_mod.TalismanInstaller()
        with pytest.raises(talisman_mod.TalismanInstallError):
            installer.download_binary(target)
        assert not target.exists()

    def test_verified_binary_installs(self, file_server, tmp_path: Path, monkeypatch):
        """A matching checksum installs the binary (executable on POSIX)."""
        payload = b"good-talisman-binary"
        asset = "talisman_test_binary"
        (file_server.docroot / asset).write_bytes(payload)
        _write_checksums(file_server.docroot, "checksums", {asset: _sha256_bytes(payload)})
        self._point_at_server(monkeypatch, file_server, asset)

        target = tmp_path / "bin" / _exe("talisman")
        installer = talisman_mod.TalismanInstaller()
        installer.download_binary(target)

        assert target.read_bytes() == payload
        if not IS_WINDOWS:
            assert target.stat().st_mode & 0o100, "installed binary must be executable"

    def test_rename_failure_raises_install_error(self, file_server, tmp_path: Path, monkeypatch):
        """Regression (#519 review): a failed final rename must surface as
        TalismanInstallError, not escape as a raw OSError."""
        payload = b"good-talisman-binary"
        asset = "talisman_test_binary"
        (file_server.docroot / asset).write_bytes(payload)
        _write_checksums(file_server.docroot, "checksums", {asset: _sha256_bytes(payload)})
        self._point_at_server(monkeypatch, file_server, asset)

        # A non-empty directory at the target path makes the verified rename fail.
        target = tmp_path / "bin" / _exe("talisman")
        target.mkdir(parents=True)
        (target / "occupied").write_text("x")

        installer = talisman_mod.TalismanInstaller()
        with pytest.raises(talisman_mod.TalismanInstallError, match="move verified binary"):
            installer.download_binary(target)
        staging = target.parent / (target.name + ".download")
        assert not staging.exists(), "staging file must be cleaned up on rename failure"


# ---------------------------------------------------------------------------
# sops integration installer
# ---------------------------------------------------------------------------


class TestSopsInstallIntegrity:
    """The in-process sops installer must verify SHA256 before install."""

    def _point_at_server(self, monkeypatch, server, asset_name: str) -> None:
        system, machine = sops_mod.get_platform_info()
        urls = dict(sops_mod.SOPS_DOWNLOAD_URLS)
        urls[(system, machine)] = f"{server.base_url}/{asset_name}"
        monkeypatch.setattr(sops_mod, "SOPS_DOWNLOAD_URLS", urls)
        monkeypatch.setattr(
            sops_mod,
            "SOPS_CHECKSUMS_URL_TEMPLATE",
            f"{server.base_url}/sops.checksums.txt",
            raising=False,
        )

    def test_tampered_binary_does_not_replace_existing(
        self, file_server, tmp_path: Path, monkeypatch
    ):
        asset = "sops-test-binary"
        (file_server.docroot / asset).write_bytes(b"tampered-sops")
        _write_checksums(file_server.docroot, "sops.checksums.txt", {asset: WRONG_DIGEST})
        self._point_at_server(monkeypatch, file_server, asset)

        target = tmp_path / "bin" / _exe("sops")
        target.parent.mkdir(parents=True)
        target.write_bytes(b"previously-working-sops")

        installer = sops_mod.SopsInstaller()
        with pytest.raises(sops_mod.SopsInstallError):
            installer.install(target_path=target)

        assert target.read_bytes() == b"previously-working-sops"
        leftovers = [p.name for p in target.parent.iterdir() if p.name != target.name]
        assert leftovers == [], f"staging file(s) left behind: {leftovers}"

    def test_missing_checksums_fails_closed(self, file_server, tmp_path: Path, monkeypatch):
        asset = "sops-test-binary"
        (file_server.docroot / asset).write_bytes(b"unverifiable-sops")
        self._point_at_server(monkeypatch, file_server, asset)

        target = tmp_path / "bin" / _exe("sops")
        installer = sops_mod.SopsInstaller()
        with pytest.raises(sops_mod.SopsInstallError):
            installer.install(target_path=target)
        assert not target.exists()

    def test_verified_binary_installs(self, file_server, tmp_path: Path, monkeypatch):
        payload = b"good-sops-binary"
        asset = "sops-test-binary"
        (file_server.docroot / asset).write_bytes(payload)
        _write_checksums(file_server.docroot, "sops.checksums.txt", {asset: _sha256_bytes(payload)})
        self._point_at_server(monkeypatch, file_server, asset)

        target = tmp_path / "bin" / _exe("sops")
        installer = sops_mod.SopsInstaller()
        result = installer.install(target_path=target)
        assert result == target
        assert target.read_bytes() == payload


# ---------------------------------------------------------------------------
# dotenvx integration installer
# ---------------------------------------------------------------------------


class TestDotenvxInstallIntegrity:
    """The in-process dotenvx installer must verify SHA256 before install."""

    def _point_at_server(self, monkeypatch, server, archive_name: str) -> None:
        system, machine = dotenvx_mod.get_platform_info()
        urls = dict(dotenvx_mod.DOWNLOAD_URLS)
        urls[(system, machine)] = f"{server.base_url}/{archive_name}"
        monkeypatch.setattr(dotenvx_mod, "DOWNLOAD_URLS", urls)
        monkeypatch.setattr(
            dotenvx_mod,
            "DOTENVX_CHECKSUMS_URL_TEMPLATE",
            f"{server.base_url}/checksums.txt",
            raising=False,
        )

    def test_tampered_archive_is_rejected_before_install(
        self, file_server, tmp_path: Path, monkeypatch
    ):
        archive_name = "dotenvx-release.tar.gz"
        _make_tar_gz(file_server.docroot, archive_name, _exe("dotenvx"), b"tampered-dotenvx")
        _write_checksums(file_server.docroot, "checksums.txt", {archive_name: WRONG_DIGEST})
        self._point_at_server(monkeypatch, file_server, archive_name)

        target = tmp_path / "bin" / _exe("dotenvx")
        installer = dotenvx_mod.DotenvxInstaller()
        with pytest.raises(dotenvx_mod.DotenvxInstallError):
            installer.download_and_extract(target)
        assert not target.exists()

    def test_missing_checksums_fails_closed(self, file_server, tmp_path: Path, monkeypatch):
        archive_name = "dotenvx-release.tar.gz"
        _make_tar_gz(file_server.docroot, archive_name, _exe("dotenvx"), b"unverifiable-dotenvx")
        self._point_at_server(monkeypatch, file_server, archive_name)

        target = tmp_path / "bin" / _exe("dotenvx")
        installer = dotenvx_mod.DotenvxInstaller()
        with pytest.raises(dotenvx_mod.DotenvxInstallError):
            installer.download_and_extract(target)
        assert not target.exists()

    def test_verified_archive_installs(self, file_server, tmp_path: Path, monkeypatch):
        payload = b"good-dotenvx-binary"
        archive_name = "dotenvx-release.tar.gz"
        archive_bytes = _make_tar_gz(file_server.docroot, archive_name, _exe("dotenvx"), payload)
        _write_checksums(
            file_server.docroot, "checksums.txt", {archive_name: _sha256_bytes(archive_bytes)}
        )
        self._point_at_server(monkeypatch, file_server, archive_name)

        target = tmp_path / "bin" / _exe("dotenvx")
        installer = dotenvx_mod.DotenvxInstaller()
        installer.download_and_extract(target)
        assert target.read_bytes() == payload

    def test_failed_final_install_keeps_previous_binary(
        self, file_server, tmp_path: Path, monkeypatch
    ):
        """Regression (#519 cubic P1): a failing final copy must not corrupt a
        previously working dotenvx binary or leave a partial write."""
        import envdrift.install_integrity as integrity_mod

        payload = b"good-dotenvx-binary"
        archive_name = "dotenvx-release.tar.gz"
        archive_bytes = _make_tar_gz(file_server.docroot, archive_name, _exe("dotenvx"), payload)
        _write_checksums(
            file_server.docroot, "checksums.txt", {archive_name: _sha256_bytes(archive_bytes)}
        )
        self._point_at_server(monkeypatch, file_server, archive_name)

        target = tmp_path / "bin" / _exe("dotenvx")
        target.parent.mkdir(parents=True)
        target.write_bytes(b"previously-working-dotenvx")
        monkeypatch.setattr(
            integrity_mod.shutil, "copy2", lambda *a, **k: (_ for _ in ()).throw(OSError("full"))
        )

        installer = dotenvx_mod.DotenvxInstaller()
        with pytest.raises(dotenvx_mod.DotenvxInstallError):
            installer.download_and_extract(target)
        assert target.read_bytes() == b"previously-working-dotenvx"
        leftovers = [p.name for p in target.parent.iterdir() if p.name != target.name]
        assert leftovers == []


# ---------------------------------------------------------------------------
# envdrift install agent (CLI, end to end against the local server)
# ---------------------------------------------------------------------------


@pytest.fixture
def agent_env(file_server, tmp_path: Path, monkeypatch):
    """Isolate PATH/HOME and point agent release resolution at the local server."""
    # No pre-existing envdrift-agent on PATH.
    empty_path_dir = tmp_path / "empty-path"
    empty_path_dir.mkdir()
    monkeypatch.setenv("PATH", str(empty_path_dir))

    if IS_WINDOWS:
        appdata = tmp_path / "appdata"
        monkeypatch.setenv("LOCALAPPDATA", str(appdata))
        install_path = appdata / "Programs" / "envdrift" / "envdrift-agent.exe"
    else:
        home = tmp_path / "home"
        (home / ".envdrift" / "bin").mkdir(parents=True)
        monkeypatch.setenv("HOME", str(home))
        install_path = home / ".envdrift" / "bin" / "envdrift-agent"

    monkeypatch.setattr(
        install_mod,
        "_resolve_agent_release_url",
        lambda: (file_server.base_url, f"{file_server.base_url}/checksums.txt"),
    )

    plat = install_mod._detect_platform()
    asset = f"envdrift-agent-{plat}"
    if plat.startswith("windows"):
        asset += ".exe"

    return SimpleNamespace(
        server=file_server,
        install_path=install_path,
        staging_path=install_path.parent / (install_path.name + ".download"),
        plat=plat,
        asset=asset,
    )


AGENT_ARGS = ["install", "agent", "--skip-autostart", "--skip-register"]


class TestInstallAgentFailClosed:
    """`envdrift install agent` must verify before install and fail closed (see #490)."""

    def test_missing_checksums_file_aborts(self, agent_env):
        """An unreachable/missing checksums.txt must abort, not warn-and-install."""
        (agent_env.server.docroot / agent_env.asset).write_bytes(b"agent-binary-bytes")
        # checksums.txt intentionally NOT served (HTTP 404).

        result = runner.invoke(app, AGENT_ARGS)

        assert result.exit_code == 1, (
            "install must fail when the checksums file cannot be fetched; "
            f"output: {' '.join(result.output.split())}"
        )
        assert not agent_env.install_path.exists(), "unverified binary must not be installed"
        assert not agent_env.staging_path.exists(), "staging download must be cleaned up"

    def test_checksums_without_platform_entry_aborts(self, agent_env):
        """A checksums file lacking this platform's entry must abort, not skip."""
        (agent_env.server.docroot / agent_env.asset).write_bytes(b"agent-binary-bytes")
        _write_checksums(
            agent_env.server.docroot,
            "checksums.txt",
            {"envdrift-agent-some-other-platform": WRONG_DIGEST},
        )

        result = runner.invoke(app, AGENT_ARGS)

        assert result.exit_code == 1
        assert not agent_env.install_path.exists()
        assert not agent_env.staging_path.exists()

    def test_tampered_binary_keeps_previous_install(self, agent_env):
        """A checksum mismatch must keep the previously installed agent intact."""
        (agent_env.server.docroot / agent_env.asset).write_bytes(b"tampered-agent-bytes")
        _write_checksums(agent_env.server.docroot, "checksums.txt", {agent_env.asset: WRONG_DIGEST})
        agent_env.install_path.parent.mkdir(parents=True, exist_ok=True)
        agent_env.install_path.write_bytes(b"previously-working-agent")

        result = runner.invoke(app, AGENT_ARGS)

        assert result.exit_code == 1
        assert agent_env.install_path.exists(), (
            "a failed verification must not delete the previously installed agent"
        )
        assert agent_env.install_path.read_bytes() == b"previously-working-agent", (
            "the tampered download must never replace the working binary"
        )
        assert not agent_env.staging_path.exists()

    def test_verified_binary_installs(self, agent_env):
        """A download matching the published checksum installs and reports success."""
        payload = b"verified-agent-binary"
        (agent_env.server.docroot / agent_env.asset).write_bytes(payload)
        _write_checksums(
            agent_env.server.docroot, "checksums.txt", {agent_env.asset: _sha256_bytes(payload)}
        )

        result = runner.invoke(app, AGENT_ARGS)

        normalized = " ".join(result.output.split())
        assert result.exit_code == 0, f"expected success, got: {normalized}"
        assert agent_env.install_path.read_bytes() == payload
        assert not agent_env.staging_path.exists()
        assert "Checksum verified" in normalized

    def test_insecure_skip_checksum_flag_installs_unverified(self, agent_env):
        """The explicit --insecure-skip-checksum escape hatch installs without checksums."""
        payload = b"unverified-agent-binary"
        (agent_env.server.docroot / agent_env.asset).write_bytes(payload)
        # No checksums.txt served: only the explicit flag may allow this.

        result = runner.invoke(app, [*AGENT_ARGS, "--insecure-skip-checksum"])

        normalized = " ".join(result.output.split())
        assert result.exit_code == 0, f"expected success with escape hatch, got: {normalized}"
        assert agent_env.install_path.read_bytes() == payload
        assert "Skipping checksum verification" in normalized
        assert "--insecure-skip-checksum" in normalized

    def test_env_var_skip_warning_names_the_env_var(self, agent_env, monkeypatch):
        """Regression (#519 review): a skip triggered by the environment variable
        must attribute the bypass to the env var, not to --insecure-skip-checksum."""
        payload = b"unverified-agent-binary"
        (agent_env.server.docroot / agent_env.asset).write_bytes(payload)
        # No checksums.txt served: the skip comes from the environment, not the flag.
        monkeypatch.setenv("ENVDRIFT_INSECURE_SKIP_CHECKSUM", "1")

        result = runner.invoke(app, AGENT_ARGS)

        normalized = " ".join(result.output.split())
        assert result.exit_code == 0, f"expected success with env escape hatch, got: {normalized}"
        assert agent_env.install_path.read_bytes() == payload
        assert "Skipping checksum verification" in normalized
        assert "ENVDRIFT_INSECURE_SKIP_CHECKSUM" in normalized
        assert "--insecure-skip-checksum" not in normalized

    def test_staging_cleanup_error_does_not_mask_verification_failure(self, agent_env, monkeypatch):
        """Regression (#519 cubic P2): if the finally-block cleanup unlink itself
        fails, that OSError must not mask the real verification failure — the
        command still exits 1 and keeps the previously working agent."""
        (agent_env.server.docroot / agent_env.asset).write_bytes(b"tampered-agent-bytes")
        _write_checksums(agent_env.server.docroot, "checksums.txt", {agent_env.asset: WRONG_DIGEST})
        agent_env.install_path.parent.mkdir(parents=True, exist_ok=True)
        agent_env.install_path.write_bytes(b"previously-working-agent")

        real_unlink = Path.unlink

        def boom_unlink(self, *a, **k):
            if self.name.endswith(".download"):
                raise PermissionError("cannot remove staging")
            return real_unlink(self, *a, **k)

        monkeypatch.setattr(Path, "unlink", boom_unlink)

        result = runner.invoke(app, AGENT_ARGS)

        assert result.exit_code == 1
        assert not isinstance(result.exception, OSError), (
            f"cleanup OSError masked the real failure: {result.exception!r}"
        )
        assert agent_env.install_path.read_bytes() == b"previously-working-agent"


# ---------------------------------------------------------------------------
# Shared integrity helper unit tests (module added by the #490 fix)
# ---------------------------------------------------------------------------


@pytest.fixture
def integrity():
    return pytest.importorskip("envdrift.install_integrity")


class TestInstallIntegrityHelpers:
    """Unit tests for the shared fail-closed verification helpers."""

    def test_parse_checksums_handles_sha256sum_formats(self, integrity):
        content = (
            f"{'a' * 64}  plain-name.tar.gz\n"
            f"{'b' * 64} *binary-mode-name.zip\r\n"
            f"{'c' * 64}  ./dir/path-name\n"
            "not-a-checksum-line\n"
            "deadbeef  short-digest-is-ignored\n"
            "\n"
        )
        parsed = integrity.parse_checksums(content)
        assert parsed == {
            "plain-name.tar.gz": "a" * 64,
            "binary-mode-name.zip": "b" * 64,
            "path-name": "c" * 64,
        }

    def test_parse_checksums_preserves_names_with_spaces(self, integrity):
        """Regression (#519 review): ``parts[-1]`` used to truncate a filename
        containing spaces to its last word (``my binary.tar.gz`` -> ``binary.tar.gz``)."""
        content = f"{'d' * 64}  my binary.tar.gz\n{'e' * 64}  ./dir/my tool.zip\n"
        parsed = integrity.parse_checksums(content)
        assert parsed == {
            "my binary.tar.gz": "d" * 64,
            "my tool.zip": "e" * 64,
        }

    def test_sha256_file_missing_raises_typed_error(self, integrity, tmp_path: Path):
        """Regression (#519 cubic P2): an unreadable file surfaces a typed
        ChecksumVerificationError, never a raw OSError that escapes callers."""
        missing = tmp_path / "does-not-exist"
        with pytest.raises(integrity.ChecksumVerificationError, match="could not read"):
            integrity.sha256_file(missing)

    def test_atomic_install_replaces_target(self, integrity, tmp_path: Path):
        """atomic_install installs the source and (POSIX) makes it executable."""
        source = tmp_path / "src-binary"
        source.write_bytes(b"new-binary")
        target = tmp_path / "bin" / "tool"
        integrity.atomic_install(source, target)
        assert target.read_bytes() == b"new-binary"
        if not IS_WINDOWS:
            assert target.stat().st_mode & 0o100, "installed binary must be executable"
        assert not (target.parent / (target.name + ".install")).exists()

    def test_atomic_install_failed_copy_keeps_original(
        self, integrity, tmp_path: Path, monkeypatch
    ):
        """Regression (#519 cubic P1): a copy that fails mid-way leaves the
        previously working binary intact and no partial/staging file behind."""
        source = tmp_path / "src-binary"
        source.write_bytes(b"new-binary")
        target = tmp_path / "bin" / "tool"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"previously-working")

        def boom_copy(*_a, **_k):
            raise OSError("simulated disk full")

        monkeypatch.setattr(integrity.shutil, "copy2", boom_copy)
        with pytest.raises(OSError):
            integrity.atomic_install(source, target)

        assert target.read_bytes() == b"previously-working"
        leftovers = [p.name for p in target.parent.iterdir() if p.name != target.name]
        assert leftovers == [], f"staging file(s) left behind: {leftovers}"

    def test_atomic_install_cleanup_does_not_mask_error(
        self, integrity, tmp_path: Path, monkeypatch
    ):
        """The staging cleanup must not replace the real copy failure with an
        unlink OSError (#519 cubic P2)."""
        source = tmp_path / "src-binary"
        source.write_bytes(b"new-binary")
        target = tmp_path / "bin" / "tool"

        def boom_copy(*_a, **_k):
            raise OSError("real copy failure")

        monkeypatch.setattr(integrity.shutil, "copy2", boom_copy)
        # Make cleanup's unlink also raise; it must be suppressed so the real
        # copy failure is what propagates.
        real_unlink = Path.unlink

        def boom_unlink(self, *a, **k):
            if self.name.endswith(".install"):
                raise PermissionError("cannot remove staging")
            return real_unlink(self, *a, **k)

        monkeypatch.setattr(Path, "unlink", boom_unlink)
        with pytest.raises(OSError, match="real copy failure"):
            integrity.atomic_install(source, target)

    def test_verify_download_accepts_matching_checksum(
        self, integrity, file_server, tmp_path: Path
    ):
        artifact = tmp_path / "tool.tar.gz"
        artifact.write_bytes(b"artifact-bytes")
        _write_checksums(
            file_server.docroot,
            "checksums.txt",
            {"tool.tar.gz": _sha256_bytes(b"artifact-bytes")},
        )
        # Must not raise.
        integrity.verify_download(
            artifact, "tool.tar.gz", f"{file_server.base_url}/checksums.txt", "tool"
        )

    def test_verify_download_rejects_mismatch(self, integrity, file_server, tmp_path: Path):
        artifact = tmp_path / "tool.tar.gz"
        artifact.write_bytes(b"artifact-bytes")
        _write_checksums(file_server.docroot, "checksums.txt", {"tool.tar.gz": WRONG_DIGEST})
        with pytest.raises(integrity.ChecksumVerificationError, match="mismatch"):
            integrity.verify_download(
                artifact, "tool.tar.gz", f"{file_server.base_url}/checksums.txt", "tool"
            )

    def test_verify_download_rejects_missing_entry(self, integrity, file_server, tmp_path: Path):
        artifact = tmp_path / "tool.tar.gz"
        artifact.write_bytes(b"artifact-bytes")
        _write_checksums(file_server.docroot, "checksums.txt", {"other-artifact": WRONG_DIGEST})
        with pytest.raises(integrity.ChecksumVerificationError, match=r"[Nn]o checksum entry"):
            integrity.verify_download(
                artifact, "tool.tar.gz", f"{file_server.base_url}/checksums.txt", "tool"
            )

    def test_verify_download_rejects_unreachable_checksums(self, integrity, tmp_path: Path):
        artifact = tmp_path / "tool.tar.gz"
        artifact.write_bytes(b"artifact-bytes")
        # Grab a port that is not listening (bind+close to find a free one).
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            dead_port = sock.getsockname()[1]
        with pytest.raises(integrity.ChecksumVerificationError):
            integrity.verify_download(
                artifact,
                "tool.tar.gz",
                f"http://127.0.0.1:{dead_port}/checksums.txt",
                "tool",
            )

    def test_verify_download_rejects_unconfigured_url(self, integrity, tmp_path: Path):
        artifact = tmp_path / "tool.tar.gz"
        artifact.write_bytes(b"artifact-bytes")
        with pytest.raises(integrity.ChecksumVerificationError, match="checksums URL"):
            integrity.verify_download(artifact, "tool.tar.gz", "", "tool")

    def test_env_escape_hatch_skips_verification_loudly(
        self, integrity, tmp_path: Path, monkeypatch, capsys
    ):
        monkeypatch.setenv(integrity.INSECURE_SKIP_ENV, "1")
        artifact = tmp_path / "tool.tar.gz"
        artifact.write_bytes(b"artifact-bytes")
        # No URL configured and no server: only the env escape hatch lets this pass.
        integrity.verify_download(artifact, "tool.tar.gz", "", "tool")
        # The bypass must be loud (on stderr, keeping stdout machine-readable)
        # so verification can never be disabled silently.
        err = capsys.readouterr().err
        assert integrity.INSECURE_SKIP_ENV in err
        assert "UNVERIFIED" in err

    def test_env_escape_hatch_disabled_by_default(self, integrity, monkeypatch):
        monkeypatch.delenv(integrity.INSECURE_SKIP_ENV, raising=False)
        assert integrity.verification_disabled() is False
