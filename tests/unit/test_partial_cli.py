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
