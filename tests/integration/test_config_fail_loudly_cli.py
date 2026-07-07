"""End-to-end regression tests for #491: config loading fails loudly.

Every test runs the real CLI as a subprocess (``python -m envdrift.cli``)
against real files in ``tmp_path`` — no mocks, no containers, no network. The
subprocess boundary is the point: it proves users see a clean one-line error
(and machine-readable stdout stays parseable) instead of a Rich traceback or a
silent wrong-backend fallback.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration]


def _run_cli(
    args: list[str],
    cwd: Path,
    integration_pythonpath: str,
    timeout: float = 60.0,
) -> subprocess.CompletedProcess[str]:
    """Run the real envdrift CLI as a subprocess (same pattern as test_diff_cli)."""
    env = os.environ.copy()
    env["PYTHONPATH"] = integration_pythonpath
    return subprocess.run(
        [sys.executable, "-m", "envdrift.cli", *args],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _assert_no_traceback(result: subprocess.CompletedProcess[str]) -> None:
    combined = result.stdout + result.stderr
    assert "Traceback" not in combined, combined


class TestEncryptAbortsOnBrokenConfig:
    """#491 item 1: a SOPS project must never get dotenvx-encrypted on exit 0."""

    def test_encrypt_does_not_fall_back_to_dotenvx(
        self, tmp_path: Path, integration_pythonpath: str
    ):
        (tmp_path / "envdrift.toml").write_text(
            '[encryption]\nbackend = "sops"\n\n[encryption.sops]\nage_recipients = "age1abc\n',
            encoding="utf-8",
        )
        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar\n", encoding="utf-8")

        result = _run_cli(["encrypt", ".env"], tmp_path, integration_pythonpath)

        assert result.returncode == 1, result.stdout + result.stderr
        combined = " ".join((result.stdout + result.stderr).split())
        assert "TOML syntax error in" in combined
        # The file must be untouched: no dotenvx header, no stray keypair.
        assert env_file.read_text(encoding="utf-8") == "FOO=bar\n"
        assert not (tmp_path / ".env.keys").exists()
        _assert_no_traceback(result)


class TestVaultCommandsReportParseError:
    """#491 item 2: vault-pull/vault-push must report the parse failure."""

    def test_vault_pull_mentions_syntax_error(self, tmp_path: Path, integration_pythonpath: str):
        (tmp_path / "envdrift.toml").write_text('[vault]\nprovider = "azure\n', encoding="utf-8")

        result = _run_cli(
            ["vault-pull", ".", "any-secret", "--env", "production"],
            tmp_path,
            integration_pythonpath,
        )

        assert result.returncode == 1, result.stdout + result.stderr
        combined = " ".join((result.stdout + result.stderr).split())
        assert "TOML syntax error in" in combined
        assert "Vault provider required" not in combined
        _assert_no_traceback(result)


class TestSyncFamilyCleanErrors:
    """#491 item 4: pull/lock dump no tracebacks on malformed/unreadable config."""

    @pytest.mark.parametrize("command", ["pull", "lock"])
    def test_wrong_typed_vault_section(
        self, tmp_path: Path, integration_pythonpath: str, command: str
    ):
        (tmp_path / "envdrift.toml").write_text('vault = "a string"\n', encoding="utf-8")

        result = _run_cli([command], tmp_path, integration_pythonpath)

        assert result.returncode == 1, result.stdout + result.stderr
        _assert_no_traceback(result)
        combined = " ".join((result.stdout + result.stderr).split())
        assert "Invalid config in" in combined

    def test_mapping_missing_secret_name(self, tmp_path: Path, integration_pythonpath: str):
        (tmp_path / "envdrift.toml").write_text(
            '[vault]\nprovider = "aws"\n\n[[vault.sync.mappings]]\nfolder_path = "."\n',
            encoding="utf-8",
        )

        result = _run_cli(["pull"], tmp_path, integration_pythonpath)

        assert result.returncode == 1, result.stdout + result.stderr
        _assert_no_traceback(result)
        assert "secret_name" in result.stdout + result.stderr

    @pytest.mark.skipif(
        sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
        reason="POSIX permission bits; root bypasses chmod 000",
    )
    def test_unreadable_config(self, tmp_path: Path, integration_pythonpath: str):
        cfg = tmp_path / "envdrift.toml"
        cfg.write_text('[vault]\nprovider = "aws"\n', encoding="utf-8")
        cfg.chmod(0o000)
        try:
            result = _run_cli(["pull"], tmp_path, integration_pythonpath)
        finally:
            cfg.chmod(0o644)

        assert result.returncode == 1, result.stdout + result.stderr
        _assert_no_traceback(result)
        combined = " ".join((result.stdout + result.stderr).split())
        assert "Cannot read config file" in combined


class TestDirectoryNamedConfig:
    """#491 item 5: a directory named envdrift.toml never crashes discovery."""

    def test_guard_json_stdout_stays_parseable(self, tmp_path: Path, integration_pythonpath: str):
        (tmp_path / "envdrift.toml").mkdir()
        (tmp_path / ".env").write_text("FOO=bar\n", encoding="utf-8")

        result = _run_cli(
            ["guard", ".env", "--json", "--no-gitleaks"],
            tmp_path,
            integration_pythonpath,
        )

        _assert_no_traceback(result)
        # stdout used to be 0 bytes; it must be a real JSON document now. The
        # plaintext .env deterministically yields the unencrypted-env-file
        # finding, so guard exits 2 (blocking findings), not a crash exit 1.
        payload = json.loads(result.stdout)
        assert [f["rule_id"] for f in payload["findings"]] == ["unencrypted-env-file"]
        assert result.returncode == 2, result.stdout + result.stderr

    def test_pull_clean_error(self, tmp_path: Path, integration_pythonpath: str):
        (tmp_path / "envdrift.toml").mkdir()

        result = _run_cli(["pull"], tmp_path, integration_pythonpath)

        assert result.returncode == 1, result.stdout + result.stderr
        _assert_no_traceback(result)
        combined = " ".join((result.stdout + result.stderr).split())
        assert "No sync configuration found" in combined


class TestUnknownKeyWarning:
    """#491 item 3: typo'd keys warn on stderr; machine stdout stays clean."""

    def test_guard_json_warns_on_stderr_only(self, tmp_path: Path, integration_pythonpath: str):
        (tmp_path / "envdrift.toml").write_text(
            '[guard]\nfail_on_severty = "critical"\n', encoding="utf-8"
        )
        (tmp_path / ".env").write_text("FOO=bar\n", encoding="utf-8")

        result = _run_cli(
            ["guard", ".env", "--json", "--no-gitleaks"],
            tmp_path,
            integration_pythonpath,
        )

        _assert_no_traceback(result)
        payload = json.loads(result.stdout)  # stdout must remain pure JSON
        assert isinstance(payload, dict)
        assert result.returncode == 2, result.stdout + result.stderr
        assert "fail_on_severty" in result.stderr
        assert "fail_on_severity" in result.stderr
