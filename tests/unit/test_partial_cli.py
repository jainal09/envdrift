"""Tests for partial encryption CLI commands."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

from envdrift.cli import app

runner = CliRunner()


def test_push_adds_combined_file_to_gitignore(monkeypatch, tmp_path: Path):
    """Push should register combined files in .gitignore."""
    combined_path = tmp_path / ".env.production"
    env_config = SimpleNamespace(
        name="production",
        clear_file=str(tmp_path / ".env.production.clear"),
        secret_file=str(tmp_path / ".env.production.secret"),
        combined_file=str(combined_path),
        secrets_only=False,
    )
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[env_config])
    )

    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.push_partial_encryption",
        lambda _env: {"clear_lines": 1, "secret_vars": 1},
    )

    captured_paths: list[Path] = []

    def _fake_ensure(paths):
        captured_paths.extend(paths)
        return [Path(paths[0]).name]

    monkeypatch.setattr(
        "envdrift.cli_commands.partial.ensure_gitignore_entries",
        _fake_ensure,
    )

    result = runner.invoke(app, ["push"])

    assert result.exit_code == 0
    assert captured_paths == [combined_path]
    assert "updated .gitignore" in result.output.lower()


def test_push_secrets_only_mode(monkeypatch, tmp_path: Path):
    """push with secrets_only=True calls push_secrets_only, not push_partial_encryption."""
    env_config = SimpleNamespace(
        name="production",
        secrets_only=True,
        secrets_dir=str(tmp_path / "secrets"),
        pattern=".env*",
        combined_file="",
    )
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[env_config])
    )

    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)

    push_partial_called = []
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.push_partial_encryption",
        lambda _: push_partial_called.append(True) or {},
    )
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.push_secrets_only",
        lambda _: {"encrypted": 3, "already_encrypted": 1},
    )
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.ensure_gitignore_entries",
        lambda _paths: [],
    )

    result = runner.invoke(app, ["push"])

    assert result.exit_code == 0
    assert not push_partial_called, "combine-mode function must not be called in secrets_only mode"
    assert "3 file(s)" in result.output


def test_pull_partial_secrets_only_mode(monkeypatch, tmp_path: Path):
    """pull-partial with secrets_only=True calls pull_secrets_only, not pull_partial_encryption."""
    env_config = SimpleNamespace(
        name="production",
        secrets_only=True,
        secrets_dir=str(tmp_path / "secrets"),
        pattern=".env*",
        combined_file="",
    )
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[env_config])
    )

    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)

    pull_partial_called = []
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.pull_partial_encryption",
        lambda _: pull_partial_called.append(True) or True,
    )
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.pull_secrets_only",
        lambda _: {"decrypted": 2, "already_decrypted": 0},
    )
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.ensure_gitignore_entries",
        lambda _paths: [],
    )

    result = runner.invoke(app, ["pull-partial"])

    assert result.exit_code == 0
    assert not pull_partial_called, "combine-mode function must not be called in secrets_only mode"
    assert "2 file(s)" in result.output


def test_push_summary_uses_files_label_in_secrets_only_mode(monkeypatch, tmp_path: Path):
    """Push summary must label secrets_only counts as files, not vars."""
    env_config = SimpleNamespace(
        name="production",
        secrets_only=True,
        secrets_dir=str(tmp_path / "secrets"),
        pattern=".env*",
        combined_file="",
    )
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[env_config])
    )

    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.push_secrets_only",
        lambda _: {"encrypted": 4, "already_encrypted": 0},
    )
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.ensure_gitignore_entries",
        lambda _paths: [],
    )

    result = runner.invoke(app, ["push"])

    assert result.exit_code == 0
    assert "Encrypted files (secrets-only): 4" in result.output
    # In a pure secrets-only run, the combine-mode lines should be absent.
    assert "Encrypted vars:" not in result.output
    assert "Combined files:" not in result.output


def test_pull_summary_counts_skipped_when_some_decrypted(monkeypatch, tmp_path: Path):
    """Pull summary must count already_decrypted files even when others were decrypted."""
    env_config = SimpleNamespace(
        name="production",
        secrets_only=True,
        secrets_dir=str(tmp_path / "secrets"),
        pattern=".env*",
        combined_file="",
    )
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[env_config])
    )

    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.pull_secrets_only",
        lambda _: {"decrypted": 2, "already_decrypted": 3},
    )
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.ensure_gitignore_entries",
        lambda _paths: [],
    )

    result = runner.invoke(app, ["pull-partial"])

    assert result.exit_code == 0
    assert "Decrypted: 2" in result.output
    assert "Skipped: 3" in result.output


def test_push_fails_when_partial_encryption_disabled(monkeypatch):
    """push exits non-zero with a helpful error when partial_encryption.enabled is False."""
    config = SimpleNamespace(partial_encryption=SimpleNamespace(enabled=False, environments=[]))
    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)

    result = runner.invoke(app, ["push"])
    assert result.exit_code == 1
    assert "not enabled" in result.output.lower()


def test_pull_fails_when_partial_encryption_disabled(monkeypatch):
    """pull-partial exits non-zero when partial_encryption.enabled is False."""
    config = SimpleNamespace(partial_encryption=SimpleNamespace(enabled=False, environments=[]))
    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)

    result = runner.invoke(app, ["pull-partial"])
    assert result.exit_code == 1
    assert "not enabled" in result.output.lower()


def test_push_fails_when_env_filter_matches_nothing(monkeypatch, tmp_path: Path):
    """push --env unknown exits non-zero when no environment matches."""
    env_config = SimpleNamespace(
        name="production",
        secrets_only=True,
        secrets_dir=str(tmp_path),
        pattern=".env*",
        combined_file="",
    )
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[env_config])
    )
    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)
    monkeypatch.setattr("envdrift.cli_commands.partial.ensure_gitignore_entries", lambda _paths: [])

    result = runner.invoke(app, ["push", "--env", "staging"])
    assert result.exit_code == 1
    assert "no partial encryption configuration" in result.output.lower()


def test_pull_fails_when_env_filter_matches_nothing(monkeypatch, tmp_path: Path):
    """pull-partial --env unknown exits non-zero."""
    env_config = SimpleNamespace(
        name="production",
        secrets_only=True,
        secrets_dir=str(tmp_path),
        pattern=".env*",
        combined_file="",
    )
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[env_config])
    )
    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)
    monkeypatch.setattr("envdrift.cli_commands.partial.ensure_gitignore_entries", lambda _paths: [])

    result = runner.invoke(app, ["pull-partial", "--env", "staging"])
    assert result.exit_code == 1


def test_push_reports_partial_encryption_error_and_exits_nonzero(monkeypatch, tmp_path: Path):
    """push surfaces PartialEncryptionError from the underlying helpers and exits non-zero."""
    from envdrift.core.partial_encryption import PartialEncryptionError

    env_config = SimpleNamespace(
        name="production",
        secrets_only=True,
        secrets_dir=str(tmp_path / "secrets"),
        pattern=".env*",
        combined_file="",
    )
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[env_config])
    )

    def _raise(_env):
        raise PartialEncryptionError("boom")

    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)
    monkeypatch.setattr("envdrift.cli_commands.partial.push_secrets_only", _raise)
    monkeypatch.setattr("envdrift.cli_commands.partial.ensure_gitignore_entries", lambda _paths: [])

    result = runner.invoke(app, ["push"])
    assert result.exit_code == 1
    assert "boom" in result.output


def test_pull_reports_partial_encryption_error_and_exits_nonzero(monkeypatch, tmp_path: Path):
    """pull-partial surfaces PartialEncryptionError and exits non-zero."""
    from envdrift.core.partial_encryption import PartialEncryptionError

    env_config = SimpleNamespace(
        name="production",
        secrets_only=True,
        secrets_dir=str(tmp_path / "secrets"),
        pattern=".env*",
        combined_file="",
    )
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[env_config])
    )

    def _raise(_env):
        raise PartialEncryptionError("kaboom")

    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)
    monkeypatch.setattr("envdrift.cli_commands.partial.pull_secrets_only", _raise)
    monkeypatch.setattr("envdrift.cli_commands.partial.ensure_gitignore_entries", lambda _paths: [])

    result = runner.invoke(app, ["pull-partial"])
    assert result.exit_code == 1
    assert "kaboom" in result.output


def test_push_load_config_failure_exits_nonzero(monkeypatch):
    """push exits non-zero when load_config itself raises."""

    def _raise():
        raise RuntimeError("bad toml")

    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", _raise)

    result = runner.invoke(app, ["push"])
    assert result.exit_code == 1
    assert "failed to load configuration" in result.output.lower()


def test_push_summary_shows_processed_when_nothing_encrypted(monkeypatch, tmp_path: Path):
    """Push summary still shows Processed counts when all files were already encrypted."""
    env_config = SimpleNamespace(
        name="production",
        secrets_only=True,
        secrets_dir=str(tmp_path / "secrets"),
        pattern=".env*",
        combined_file="",
    )
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[env_config])
    )

    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.push_secrets_only",
        lambda _: {"encrypted": 0, "already_encrypted": 3},
    )
    monkeypatch.setattr("envdrift.cli_commands.partial.ensure_gitignore_entries", lambda _paths: [])

    result = runner.invoke(app, ["push"])
    assert result.exit_code == 0
    assert "Processed: 1/1" in result.output
    # All files were already encrypted; the optional encrypted-files line is omitted.
    assert "Encrypted files" not in result.output


def test_push_secrets_only_does_not_add_combined_to_gitignore(monkeypatch, tmp_path: Path):
    """push with secrets_only=True must not add anything to .gitignore (no combined file)."""
    env_config = SimpleNamespace(
        name="production",
        secrets_only=True,
        secrets_dir=str(tmp_path / "secrets"),
        pattern=".env*",
        combined_file="",
    )
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[env_config])
    )

    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.push_secrets_only",
        lambda _: {"encrypted": 1, "already_encrypted": 0},
    )

    captured_paths: list = []

    def _fake_ensure(paths):
        captured_paths.extend(paths)
        return []

    monkeypatch.setattr("envdrift.cli_commands.partial.ensure_gitignore_entries", _fake_ensure)

    result = runner.invoke(app, ["push"])

    assert result.exit_code == 0
    assert captured_paths == [], (
        "secrets_only mode must not register any combined_file in .gitignore"
    )
