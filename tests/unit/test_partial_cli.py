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
