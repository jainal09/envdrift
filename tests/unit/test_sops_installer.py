"""Tests for envdrift.integrations.sops module."""

from __future__ import annotations

import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from envdrift.integrations.sops import SopsInstaller, SopsInstallError, get_sops_path
from tests.helpers import write_checksums_for


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


def _serve_bytes(body: bytes):
    """Start a real local HTTP server serving ``body``; return (server, url)."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # http.server handler API name
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args) -> None:
            pass  # silence request logging

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    import threading

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/sops"


def test_install_downloads_binary(monkeypatch, tmp_path: Path):
    """Installer downloads the binary into the target path (real local HTTP)."""
    target_dir = tmp_path / "bin"
    monkeypatch.setattr("envdrift.integrations.sops.get_venv_bin_dir", lambda: target_dir)
    monkeypatch.setattr("platform.system", lambda: "Linux")

    body = b"sops-binary-bytes"
    server, url = _serve_bytes(body)
    artifact = tmp_path / "served-sops"
    artifact.write_bytes(body)
    checksums_url = write_checksums_for(artifact, tmp_path / "stub-checksums.txt", "sops")
    monkeypatch.setattr(
        "envdrift.integrations.sops.SopsInstaller._get_download_url",
        lambda _self: url,
    )
    monkeypatch.setattr(
        "envdrift.integrations.sops.SopsInstaller.get_checksums_url",
        lambda _self: checksums_url,
    )

    try:
        installer = SopsInstaller(version="0.0.0")
        binary_path = installer.install()
    finally:
        server.shutdown()
        server.server_close()

    assert binary_path.exists()
    assert binary_path.name == "sops"
    assert binary_path.read_bytes() == b"sops-binary-bytes"
    # The chmod +x is POSIX-only; Windows has no executable bit to assert.
    if sys.platform != "win32":
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
    """Installer removes the staged .download temp file when install fails after
    the download itself succeeded (here: the final rename onto a directory)."""
    # Make the *target* a directory so tmp_path.replace(target) fails after the
    # download succeeded, exercising the cleanup branch with a real download.
    target = tmp_path / "sops"
    target.mkdir()
    monkeypatch.setattr("envdrift.integrations.sops.get_sops_path", lambda: target)
    monkeypatch.setattr("envdrift.integrations.sops.platform.system", lambda: "Linux")

    body = b"partial"
    server, url = _serve_bytes(body)
    artifact = tmp_path / "served-sops"
    artifact.write_bytes(body)
    checksums_url = write_checksums_for(artifact, tmp_path / "stub-checksums.txt", "sops")
    monkeypatch.setattr(
        "envdrift.integrations.sops.SopsInstaller._get_download_url",
        lambda _self: url,
    )
    monkeypatch.setattr(
        "envdrift.integrations.sops.SopsInstaller.get_checksums_url",
        lambda _self: checksums_url,
    )

    try:
        installer = SopsInstaller(version="0.0.0")
        with pytest.raises(SopsInstallError):
            installer.install()
    finally:
        server.shutdown()
        server.server_close()

    tmp_file = target.with_suffix(".download")
    assert not tmp_file.exists()


# --------------------------------------------------------------------------- #
# #475: bounded download (no urlretrieve hang), surfaced failure causes
# --------------------------------------------------------------------------- #


def test_install_stalled_download_aborts_with_bounded_timeout(monkeypatch, tmp_path: Path):
    """Regression for #475 (defect class fixed for dotenvx in #311): a server
    that accepts the connection and then stalls must NOT hang install() forever.
    The download must use a bounded timeout and fail with SopsInstallError.

    A real local socket plays the stalling server; only the timeout *value* is
    shrunk so the test is fast.
    """
    import contextlib
    import socket
    import threading
    import time

    server = socket.create_server(("127.0.0.1", 0))
    server.settimeout(30)
    port = server.getsockname()[1]
    accepted: list[socket.socket] = []

    def stall() -> None:
        with contextlib.suppress(OSError, TimeoutError):
            conn, _ = server.accept()
            accepted.append(conn)
            conn.settimeout(30)
            with contextlib.suppress(OSError, TimeoutError):
                conn.recv(65536)  # read the request, then never respond

    thread = threading.Thread(target=stall, daemon=True)
    thread.start()

    # The bounded-download constant must exist (its absence IS the bug) — shrink
    # it so the test completes quickly.
    monkeypatch.setattr("envdrift.integrations.sops.DOWNLOAD_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(
        "envdrift.integrations.sops.SopsInstaller._get_download_url",
        lambda self: f"http://127.0.0.1:{port}/sops",
    )

    installer = SopsInstaller(version="0.0.0")
    target = tmp_path / "bin" / "sops"

    start = time.monotonic()
    try:
        with pytest.raises(SopsInstallError):
            installer.install(target_path=target)
        elapsed = time.monotonic() - start
        assert elapsed < 20, f"install() did not abort promptly ({elapsed:.1f}s)"
        assert not target.exists()
        assert not target.with_suffix(".download").exists()
    finally:
        for conn in accepted:
            with contextlib.suppress(OSError):
                conn.close()
        server.close()
        thread.join(timeout=5)


def test_install_connection_refused_raises_clean_error(monkeypatch, tmp_path: Path):
    """A refused connection (fail-fast download) surfaces as SopsInstallError with
    the underlying cause, never a bare swallow."""
    import socket

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    refused_port = probe.getsockname()[1]
    probe.close()

    monkeypatch.setattr(
        "envdrift.integrations.sops.SopsInstaller._get_download_url",
        lambda self: f"http://127.0.0.1:{refused_port}/sops",
    )

    installer = SopsInstaller(version="0.0.0")
    target = tmp_path / "bin" / "sops"

    with pytest.raises(SopsInstallError, match="Failed to install SOPS"):
        installer.install(target_path=target)

    assert not target.exists()
    assert not target.with_suffix(".download").exists()
