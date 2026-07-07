"""Coverage-focused tests for envdrift.cli_commands.install.

These tests target previously-uncovered branches: GitHub release resolution,
checksum verification internals, agent install subprocess error handling, and
the various install/check command branches (auto-start, project registration,
PATH warnings, version display).
"""

from __future__ import annotations

import hashlib
import io
import subprocess
import urllib.error
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

import envdrift.agent.registry as registry_module
from envdrift.cli import app
from envdrift.cli_commands import install as install_mod

if TYPE_CHECKING:
    pass

runner = CliRunner()


def _make_response(payload: bytes) -> MagicMock:
    """Build a context-manager mock mimicking urllib.request.urlopen()."""
    resp = MagicMock()
    resp.read.return_value = payload
    cm = MagicMock()
    cm.__enter__.return_value = resp
    cm.__exit__.return_value = False
    return cm


class TestResolveAgentReleaseUrl:
    """Tests for _resolve_agent_release_url (lines 59-68)."""

    def test_skips_prerelease_and_draft_then_finds_agent(self):
        """Prerelease/draft releases are skipped; first agent-v* tag wins."""
        payload = (
            b'[{"tag_name": "agent-v9.9.9", "prerelease": true},'
            b' {"tag_name": "vscode-v1.0.0", "draft": false},'
            b' {"tag_name": "agent-v2.0.0", "prerelease": false, "draft": false}]'
        )
        with patch("urllib.request.urlopen", return_value=_make_response(payload)):
            base, checksum = install_mod._resolve_agent_release_url()

        assert base.endswith("releases/download/agent-v2.0.0")
        assert checksum == f"{base}/checksums.txt"

    def test_no_agent_release_raises_runtimeerror(self):
        """When no agent-v* tag exists, a RuntimeError is raised (lines 67-68)."""
        payload = b'[{"tag_name": "vscode-v1.0.0", "prerelease": false, "draft": false}]'
        with (
            patch("urllib.request.urlopen", return_value=_make_response(payload)),
            pytest.raises(RuntimeError, match="No agent release found"),
        ):
            install_mod._resolve_agent_release_url()

    def test_empty_release_list_raises(self):
        """Empty release list still raises RuntimeError."""
        with (
            patch("urllib.request.urlopen", return_value=_make_response(b"[]")),
            pytest.raises(RuntimeError, match="No agent release found"),
        ):
            install_mod._resolve_agent_release_url()


class TestVerifyChecksum:
    """Tests for _verify_checksum internals (lines 159-193)."""

    def test_checksum_match_returns_true(self, tmp_path: Path):
        """Matching checksum prints verified and returns True (lines 180-193)."""
        binary = tmp_path / "agent"
        binary.write_bytes(b"hello-world-binary")
        digest = hashlib.sha256(b"hello-world-binary").hexdigest()
        checksums = f"{digest}  envdrift-agent-darwin-arm64\n".encode()

        with patch("urllib.request.urlopen", return_value=_make_response(checksums)):
            ok = install_mod._verify_checksum(
                binary, "darwin-arm64", "https://example/checksums.txt"
            )
        assert ok is True

    def test_checksum_mismatch_returns_false(self, tmp_path: Path):
        """Mismatched checksum returns False (lines 186-190)."""
        binary = tmp_path / "agent"
        binary.write_bytes(b"actual-bytes")
        checksums = b"deadbeef  envdrift-agent-linux-amd64\n"

        with patch("urllib.request.urlopen", return_value=_make_response(checksums)):
            ok = install_mod._verify_checksum(
                binary, "linux-amd64", "https://example/checksums.txt"
            )
        assert ok is False

    def test_windows_binary_name_suffix(self, tmp_path: Path):
        """Windows platform appends .exe to the binary name (lines 164-165)."""
        binary = tmp_path / "agent.exe"
        binary.write_bytes(b"win-bytes")
        digest = hashlib.sha256(b"win-bytes").hexdigest()
        checksums = f"{digest}  envdrift-agent-windows-amd64.exe\n".encode()

        with patch("urllib.request.urlopen", return_value=_make_response(checksums)):
            ok = install_mod._verify_checksum(
                binary, "windows-amd64", "https://example/checksums.txt"
            )
        assert ok is True

    def test_platform_not_in_checksums_fails_closed(self, tmp_path: Path):
        """A checksums file lacking this platform's entry fails closed (#490)."""
        binary = tmp_path / "agent"
        binary.write_bytes(b"x")
        checksums = b"abc123  envdrift-agent-some-other-platform\n"

        with patch("urllib.request.urlopen", return_value=_make_response(checksums)):
            ok = install_mod._verify_checksum(
                binary, "darwin-arm64", "https://example/checksums.txt"
            )
        assert ok is False

    def test_download_error_fails_closed(self, tmp_path: Path):
        """An unreachable checksums file fails closed instead of warning (#490)."""
        binary = tmp_path / "agent"
        binary.write_bytes(b"x")
        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("no net"),
        ):
            ok = install_mod._verify_checksum(
                binary, "darwin-arm64", "https://example/checksums.txt"
            )
        assert ok is False

    def test_unreadable_staging_file_fails_closed(self, tmp_path: Path):
        """An unreadable staging file (AV quarantine / vanished) fails closed (#490).

        ``sha256_file`` raises ``ChecksumVerificationError`` when it cannot read
        the file; that must be caught and turned into a refused install, not
        escape as an unhandled traceback.
        """
        from envdrift.install_integrity import ChecksumVerificationError

        binary = tmp_path / "agent"
        binary.write_bytes(b"x")
        checksums = b"abc123  envdrift-agent-darwin-arm64\n"
        with (
            patch("urllib.request.urlopen", return_value=_make_response(checksums)),
            patch(
                "envdrift.cli_commands.install.sha256_file",
                side_effect=ChecksumVerificationError("could not read file"),
            ),
        ):
            ok = install_mod._verify_checksum(
                binary, "darwin-arm64", "https://example/checksums.txt"
            )
        assert ok is False


class TestRunAgentInstall:
    """Tests for _run_agent_install (lines 270-285)."""

    def test_success(self, tmp_path: Path):
        """Returncode 0 returns True (line 277)."""
        result = MagicMock()
        result.returncode = 0
        with patch("subprocess.run", return_value=result):
            assert install_mod._run_agent_install(tmp_path / "agent") is True

    def test_nonzero_returncode(self, tmp_path: Path):
        """Non-zero returncode returns False."""
        result = MagicMock()
        result.returncode = 3
        with patch("subprocess.run", return_value=result):
            assert install_mod._run_agent_install(tmp_path / "agent") is False

    def test_timeout_returns_false(self, tmp_path: Path):
        """TimeoutExpired is handled (lines 278-280)."""
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="agent", timeout=30),
        ):
            assert install_mod._run_agent_install(tmp_path / "agent") is False

    def test_oserror_missing_binary(self, tmp_path: Path):
        """OSError with a non-existent binary path (lines 281-285)."""
        missing = tmp_path / "does-not-exist"
        with patch("subprocess.run", side_effect=OSError("boom")):
            assert install_mod._run_agent_install(missing) is False


class TestInstallAgentBranches:
    """Tests exercising install_agent command branches."""

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        registry_module._registry = None
        yield
        registry_module._registry = None

    def test_detect_platform_failure_exits(self, tmp_path: Path):
        """BadParameter from _detect_platform exits with code 1 (lines 358-360)."""
        with (
            patch("shutil.which", return_value=None),
            patch(
                "envdrift.cli_commands.install._detect_platform",
                side_effect=typer.BadParameter("bad os"),
            ),
        ):
            result = runner.invoke(app, ["install", "agent"])
        assert result.exit_code == 1
        assert "bad os" in result.stdout

    def test_resolve_release_failure_exits(self, tmp_path: Path):
        """Failure resolving release URL exits 1 and prints manual link (371-375)."""
        with (
            patch("shutil.which", return_value=None),
            patch(
                "envdrift.cli_commands.install._detect_platform",
                return_value="linux-amd64",
            ),
            patch(
                "envdrift.cli_commands.install._get_install_path",
                return_value=tmp_path / "envdrift-agent",
            ),
            patch(
                "envdrift.cli_commands.install._resolve_agent_release_url",
                side_effect=RuntimeError("No agent release found on GitHub"),
            ),
        ):
            result = runner.invoke(app, ["install", "agent"])
        assert result.exit_code == 1
        assert "No agent release found" in result.stdout
        assert "releases" in result.stdout

    def test_checksum_failure_keeps_existing_binary_and_exits(self, tmp_path: Path):
        """Checksum failure removes the staging file, keeps the old binary, exits 1 (#490)."""
        binary_path = tmp_path / "envdrift-agent"
        binary_path.write_bytes(b"previously-working")
        staging_path = tmp_path / "envdrift-agent.download"
        staging_path.write_bytes(b"corrupt")

        with (
            patch("shutil.which", return_value=None),
            patch(
                "envdrift.cli_commands.install._detect_platform",
                return_value="linux-amd64",
            ),
            patch(
                "envdrift.cli_commands.install._get_install_path",
                return_value=binary_path,
            ),
            patch("envdrift.cli_commands.install._download_binary", return_value=True),
            patch(
                "envdrift.cli_commands.install._resolve_agent_release_url",
                return_value=("https://base", "https://base/checksums.txt"),
            ),
            patch("envdrift.cli_commands.install._verify_checksum", return_value=False),
        ):
            result = runner.invoke(app, ["install", "agent"])
        assert result.exit_code == 1
        assert "Checksum verification failed" in result.stdout
        assert not staging_path.exists(), "the unverified download must be removed"
        assert binary_path.read_bytes() == b"previously-working", (
            "a failed verification must not touch the previously installed binary"
        )

    def test_autostart_failure_warns(self, tmp_path: Path, monkeypatch):
        """Auto-start failure prints a warning branch (lines 428-429)."""
        binary_path = tmp_path / "envdrift-agent"
        binary_path.write_bytes(b"bin")
        # _download_binary is mocked; pre-create the staging file the verified
        # install flow moves onto the final path (#490).
        (tmp_path / "envdrift-agent.download").write_bytes(b"bin")
        monkeypatch.setenv("PATH", str(tmp_path))

        version_result = MagicMock()
        version_result.returncode = 0
        version_result.stdout = "v1.0.0"

        with (
            patch("shutil.which", return_value=None),
            patch(
                "envdrift.cli_commands.install._detect_platform",
                return_value="linux-amd64",
            ),
            patch(
                "envdrift.cli_commands.install._get_install_path",
                return_value=binary_path,
            ),
            patch("envdrift.cli_commands.install._download_binary", return_value=True),
            patch(
                "envdrift.cli_commands.install._resolve_agent_release_url",
                return_value=("https://base", "https://base/checksums.txt"),
            ),
            patch("envdrift.cli_commands.install._verify_checksum", return_value=True),
            patch("subprocess.run", return_value=version_result),
            patch(
                "envdrift.cli_commands.install._run_agent_install",
                return_value=False,
            ),
            patch("envdrift.config.find_config", return_value=None),
        ):
            result = runner.invoke(app, ["install", "agent", "--skip-register"])
        assert result.exit_code == 0
        assert "Could not configure auto-start" in result.stdout

    def test_register_project_success(self, tmp_path: Path, monkeypatch):
        """Project registration success branch (lines 436-442)."""
        binary_path = tmp_path / "envdrift-agent"
        binary_path.write_bytes(b"bin")
        # _download_binary is mocked; pre-create the staging file the verified
        # install flow moves onto the final path (#490).
        (tmp_path / "envdrift-agent.download").write_bytes(b"bin")
        monkeypatch.setenv("PATH", str(tmp_path))

        version_result = MagicMock()
        version_result.returncode = 0
        version_result.stdout = "v1.0.0"

        with (
            patch("shutil.which", return_value=None),
            patch(
                "envdrift.cli_commands.install._detect_platform",
                return_value="linux-amd64",
            ),
            patch(
                "envdrift.cli_commands.install._get_install_path",
                return_value=binary_path,
            ),
            patch("envdrift.cli_commands.install._download_binary", return_value=True),
            patch(
                "envdrift.cli_commands.install._resolve_agent_release_url",
                return_value=("https://base", "https://base/checksums.txt"),
            ),
            patch("envdrift.cli_commands.install._verify_checksum", return_value=True),
            patch("subprocess.run", return_value=version_result),
            patch("envdrift.config.find_config", return_value=Path("envdrift.yml")),
            patch(
                "envdrift.agent.registry.register_project",
                return_value=(True, "registered ok"),
            ),
        ):
            result = runner.invoke(app, ["install", "agent", "--skip-autostart"])
        assert result.exit_code == 0
        assert "registered ok" in result.stdout

    def test_register_project_failure(self, tmp_path: Path, monkeypatch):
        """Project registration failure branch (lines 443-444)."""
        binary_path = tmp_path / "envdrift-agent"
        binary_path.write_bytes(b"bin")
        # _download_binary is mocked; pre-create the staging file the verified
        # install flow moves onto the final path (#490).
        (tmp_path / "envdrift-agent.download").write_bytes(b"bin")
        monkeypatch.setenv("PATH", str(tmp_path))

        version_result = MagicMock()
        version_result.returncode = 0
        version_result.stdout = "v1.0.0"

        with (
            patch("shutil.which", return_value=None),
            patch(
                "envdrift.cli_commands.install._detect_platform",
                return_value="linux-amd64",
            ),
            patch(
                "envdrift.cli_commands.install._get_install_path",
                return_value=binary_path,
            ),
            patch("envdrift.cli_commands.install._download_binary", return_value=True),
            patch(
                "envdrift.cli_commands.install._resolve_agent_release_url",
                return_value=("https://base", "https://base/checksums.txt"),
            ),
            patch("envdrift.cli_commands.install._verify_checksum", return_value=True),
            patch("subprocess.run", return_value=version_result),
            patch("envdrift.config.find_config", return_value=Path("envdrift.yml")),
            patch(
                "envdrift.agent.registry.register_project",
                return_value=(False, "could not register"),
            ),
        ):
            result = runner.invoke(app, ["install", "agent", "--skip-autostart"])
        assert result.exit_code == 0
        assert "could not register" in result.stdout

    def test_path_warning_when_install_dir_not_in_path(self, tmp_path: Path, monkeypatch):
        """Warns when install dir is a user-local dir not in PATH (lines 455-459)."""
        envdrift_bin = tmp_path / ".envdrift" / "bin"
        envdrift_bin.mkdir(parents=True)
        binary_path = envdrift_bin / "envdrift-agent"
        binary_path.write_bytes(b"bin")
        # _download_binary is mocked; pre-create the staging file the verified
        # install flow moves onto the final path (#490).
        (envdrift_bin / "envdrift-agent.download").write_bytes(b"bin")
        # PATH deliberately excludes envdrift_bin.
        monkeypatch.setenv("PATH", "/somewhere/else")

        version_result = MagicMock()
        version_result.returncode = 0
        version_result.stdout = "v1.0.0"

        with (
            patch("shutil.which", return_value=None),
            patch.object(Path, "home", return_value=tmp_path),
            patch(
                "envdrift.cli_commands.install._detect_platform",
                return_value="linux-amd64",
            ),
            patch(
                "envdrift.cli_commands.install._get_install_path",
                return_value=binary_path,
            ),
            patch("envdrift.cli_commands.install._download_binary", return_value=True),
            patch(
                "envdrift.cli_commands.install._resolve_agent_release_url",
                return_value=("https://base", "https://base/checksums.txt"),
            ),
            patch("envdrift.cli_commands.install._verify_checksum", return_value=True),
            patch("subprocess.run", return_value=version_result),
            patch("envdrift.config.find_config", return_value=None),
        ):
            result = runner.invoke(app, ["install", "agent", "--skip-autostart", "--skip-register"])
        assert result.exit_code == 0
        assert "not in your PATH" in result.stdout

    def test_version_check_timeout_ignored(self, tmp_path: Path, monkeypatch):
        """Version subprocess timeout is swallowed (lines 417-420)."""
        binary_path = tmp_path / "envdrift-agent"
        binary_path.write_bytes(b"bin")
        # _download_binary is mocked; pre-create the staging file the verified
        # install flow moves onto the final path (#490).
        (tmp_path / "envdrift-agent.download").write_bytes(b"bin")
        monkeypatch.setenv("PATH", str(tmp_path))

        with (
            patch("shutil.which", return_value=None),
            patch(
                "envdrift.cli_commands.install._detect_platform",
                return_value="linux-amd64",
            ),
            patch(
                "envdrift.cli_commands.install._get_install_path",
                return_value=binary_path,
            ),
            patch("envdrift.cli_commands.install._download_binary", return_value=True),
            patch(
                "envdrift.cli_commands.install._resolve_agent_release_url",
                return_value=("https://base", "https://base/checksums.txt"),
            ),
            patch("envdrift.cli_commands.install._verify_checksum", return_value=True),
            patch(
                "subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="agent", timeout=5),
            ),
            patch("envdrift.config.find_config", return_value=None),
        ):
            result = runner.invoke(app, ["install", "agent", "--skip-autostart", "--skip-register"])
        assert result.exit_code == 0
        assert "Installation complete" in result.stdout

    def test_force_status_check_oserror_proceeds(self, tmp_path: Path):
        """OSError during force status check is swallowed (lines 351-353)."""
        with (
            patch("shutil.which", return_value="/usr/local/bin/envdrift-agent"),
            patch("subprocess.run", side_effect=OSError("cannot exec")),
            patch(
                "envdrift.cli_commands.install._detect_platform",
                side_effect=typer.BadParameter("stop here"),
            ),
        ):
            result = runner.invoke(app, ["install", "agent", "--force"])
        # Status check failed silently, then platform detection forces exit 1.
        assert result.exit_code == 1
        assert "stop here" in result.stdout


class TestCheckCommandBranches:
    """Tests for check_installation extra branches."""

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        registry_module._registry = None
        yield
        registry_module._registry = None

    def test_version_import_error_shows_unknown(self):
        """ImportError on _version shows 'unknown' (lines 481-482)."""
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "envdrift._version":
                raise ImportError("no version")
            return real_import(name, *args, **kwargs)

        with (
            patch("shutil.which", return_value=None),
            patch("builtins.__import__", side_effect=fake_import),
        ):
            result = runner.invoke(app, ["install", "check"])
        assert result.exit_code == 0
        assert "Version: unknown" in result.stdout

    def test_check_registry_exists_shows_projects(self, tmp_path: Path):
        """Existing registry prints path and project count (lines 525-527)."""
        registry_path = tmp_path / "projects.json"
        registry_path.write_text("{}")
        fake_registry = MagicMock()
        fake_registry.path = registry_path
        fake_registry.projects = {"proj-a": {}, "proj-b": {}}

        with (
            patch("shutil.which", return_value=None),
            patch("envdrift.agent.registry.get_registry", return_value=fake_registry),
        ):
            result = runner.invoke(app, ["install", "check"])
        assert result.exit_code == 0
        assert "Registry at" in result.stdout
        assert "Registered projects: 2" in result.stdout


class TestDownloadBinaryOSError:
    """Cover the OSError branch of _download_binary (lines 250-253)."""

    def test_oserror_during_move_returns_false(self, tmp_path: Path):
        """An OSError (e.g. failed shutil.move) returns False (lines 250-253)."""
        from rich.progress import Progress, SpinnerColumn, TextColumn

        dest = tmp_path / "subdir" / "agent"  # parent missing -> move fails

        # response.read(chunk_size) returns bytes once, then b"" to stop the loop.
        resp = MagicMock()
        resp.read.side_effect = [b"binary-bytes", b""]
        cm = MagicMock()
        cm.__enter__.return_value = resp
        cm.__exit__.return_value = False

        with (
            patch("urllib.request.urlopen", return_value=cm),
            patch("shutil.move", side_effect=OSError("no such dir")),
        ):
            with Progress(
                SpinnerColumn(),
                TextColumn("{task.description}"),
                console=install_mod.console,
            ) as progress:
                ok = install_mod._download_binary("https://x/bin", dest, progress)
        assert ok is False


def test_response_helper_reads_stream():
    """Sanity check the local _make_response helper yields a readable stream."""
    cm = _make_response(b"data")
    with cm as resp:
        assert resp.read() == b"data"
    # Confirm io import is used meaningfully.
    assert io.BytesIO(b"data").read() == b"data"
