"""Tests for partial encryption CLI commands."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner, Result

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
        lambda _env, check=False: {"clear_lines": 1, "secret_vars": 1, "in_sync": True},
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
    # The combined file plus the private-key file dotenvx writes next to the
    # secret file are both protected (#961: not the cwd's ./.env.keys).
    assert captured_paths == [combined_path, tmp_path / ".env.keys"]
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
        lambda _env, check=False: push_partial_called.append(True) or {},
    )
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.push_secrets_only",
        lambda _env, check=False: {"encrypted": 3, "already_encrypted": 1, "in_sync": False},
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
        lambda _env, check=False: {"encrypted": 4, "already_encrypted": 0, "in_sync": False},
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
    # The enable hint must be valid, copy-pasteable TOML — the `[[...]]` array
    # header must render literally, not get eaten by Rich markup into "[]".
    assert "[[partial_encryption.environments]]" in result.output
    assert "[partial_encryption]" in result.output
    assert "\n[]\n" not in result.output


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

    def _raise(_env, check=False):
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
        lambda _env, check=False: {"encrypted": 0, "already_encrypted": 3, "in_sync": True},
    )
    monkeypatch.setattr("envdrift.cli_commands.partial.ensure_gitignore_entries", lambda _paths: [])

    result = runner.invoke(app, ["push"])
    assert result.exit_code == 0
    assert "Processed: 1/1" in result.output
    # All files were already encrypted; the optional encrypted-files line is omitted.
    assert "Encrypted files" not in result.output


def test_push_secrets_only_does_not_add_combined_to_gitignore(monkeypatch, tmp_path: Path):
    """secrets_only mode adds no combined_file to .gitignore, but still protects .env.keys."""
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
        lambda _env, check=False: {"encrypted": 1, "already_encrypted": 0, "in_sync": False},
    )

    captured_paths: list = []

    def _fake_ensure(paths):
        captured_paths.extend(paths)
        return []

    monkeypatch.setattr("envdrift.cli_commands.partial.ensure_gitignore_entries", _fake_ensure)

    result = runner.invoke(app, ["push"])

    assert result.exit_code == 0
    # No combined_file (secrets_only has none) — only the private-key file
    # dotenvx writes in secrets_dir (#961: not the cwd's ./.env.keys).
    assert captured_paths == [tmp_path / "secrets" / ".env.keys"], (
        "secrets_only mode must protect secrets_dir/.env.keys but register no combined_file"
    )


def test_push_protects_env_keys_in_gitignore(monkeypatch, tmp_path: Path):
    """push must add the .env.keys dotenvx writes next to the secret file (#961)."""
    env_config = SimpleNamespace(
        name="production",
        clear_file=str(tmp_path / ".env.production.clear"),
        secret_file=str(tmp_path / ".env.production.secret"),
        combined_file=str(tmp_path / ".env.production"),
        secrets_only=False,
    )
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[env_config])
    )

    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.push_partial_encryption",
        lambda _env, check=False: {"clear_lines": 1, "secret_vars": 1, "in_sync": True},
    )

    captured_paths: list = []

    def _fake_ensure(paths):
        captured_paths.extend(paths)
        return []

    monkeypatch.setattr("envdrift.cli_commands.partial.ensure_gitignore_entries", _fake_ensure)

    result = runner.invoke(app, ["push"])

    assert result.exit_code == 0
    assert tmp_path / ".env.keys" in captured_paths
    assert Path(".env.keys") not in captured_paths


def test_push_check_passes_when_combined_in_sync(monkeypatch, tmp_path: Path):
    """push --check exits 0 and writes nothing when the combined file is up to date."""
    env_config = SimpleNamespace(
        name="production",
        clear_file=str(tmp_path / ".env.production.clear"),
        secret_file=str(tmp_path / ".env.production.secret"),
        combined_file=str(tmp_path / ".env.production"),
        secrets_only=False,
    )
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[env_config])
    )

    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)

    received_check = []
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.push_partial_encryption",
        lambda _env, check=False: (
            received_check.append(check) or {"clear_lines": 1, "secret_vars": 1, "in_sync": True}
        ),
    )

    gitignore_called = []
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.ensure_gitignore_entries",
        lambda paths: gitignore_called.append(paths) or [],
    )

    result = runner.invoke(app, ["push", "--check"])

    assert result.exit_code == 0
    assert received_check == [True], "push must forward check=True to the helper"
    assert gitignore_called == [], "--check must not modify .gitignore"
    assert "up to date" in result.output.lower()


def test_push_check_fails_when_combined_out_of_sync(monkeypatch, tmp_path: Path):
    """push --check exits non-zero when a combined file is stale."""
    env_config = SimpleNamespace(
        name="production",
        clear_file=str(tmp_path / ".env.production.clear"),
        secret_file=str(tmp_path / ".env.production.secret"),
        combined_file=str(tmp_path / ".env.production"),
        secrets_only=False,
    )
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[env_config])
    )

    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.push_partial_encryption",
        lambda _env, check=False: {"clear_lines": 1, "secret_vars": 1, "in_sync": False},
    )
    monkeypatch.setattr("envdrift.cli_commands.partial.ensure_gitignore_entries", lambda _p: [])

    result = runner.invoke(app, ["push", "--check"])

    assert result.exit_code == 1
    assert "out of date" in result.output.lower()


def test_push_check_secrets_only_message_is_mode_agnostic(monkeypatch, tmp_path: Path):
    """--check failure for secrets-only mode must not talk about 'combined file(s)'."""
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
        lambda _env, check=False: {"encrypted": 2, "already_encrypted": 0, "in_sync": False},
    )
    monkeypatch.setattr("envdrift.cli_commands.partial.ensure_gitignore_entries", lambda _p: [])

    result = runner.invoke(app, ["push", "--check"])

    assert result.exit_code == 1
    # Secrets-only mode has no combined files; the summary must not claim it does.
    assert "combined file" not in result.output.lower()
    assert "out of date" in result.output.lower()


def test_pull_shows_security_notice_when_secrets_decrypted(monkeypatch, tmp_path: Path):
    """pull-partial shows the yellow warning panel when at least one file is decrypted."""
    env_config = SimpleNamespace(
        name="production",
        secrets_only=False,
        clear_file=str(tmp_path / ".env.clear"),
        secret_file=str(tmp_path / ".env.secret"),
        combined_file=str(tmp_path / ".env"),
    )
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[env_config])
    )

    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.pull_partial_encryption",
        lambda _: (True, True),  # (was_decrypted, protected)
    )
    monkeypatch.setattr("envdrift.cli_commands.partial.ensure_gitignore_entries", lambda _: [])

    result = runner.invoke(app, ["pull-partial"])

    assert result.exit_code == 0
    assert "Security Notice" in result.output


def test_pull_no_security_notice_when_already_decrypted(monkeypatch, tmp_path: Path):
    """pull-partial omits the warning panel when all files were already plaintext."""
    env_config = SimpleNamespace(
        name="production",
        secrets_only=False,
        clear_file=str(tmp_path / ".env.clear"),
        secret_file=str(tmp_path / ".env.secret"),
        combined_file=str(tmp_path / ".env"),
    )
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[env_config])
    )

    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.pull_partial_encryption",
        lambda _: (False, True),  # (was_decrypted=False — already plaintext, protected)
    )
    monkeypatch.setattr("envdrift.cli_commands.partial.ensure_gitignore_entries", lambda _: [])

    result = runner.invoke(app, ["pull-partial"])

    assert result.exit_code == 0
    assert "Security Notice" not in result.output


def test_pull_danger_warning_when_skip_worktree_failed(monkeypatch, tmp_path: Path):
    """If files were decrypted but skip-worktree never succeeded, a DANGER warning must
    be shown — not the yellow Security Notice — so the user knows they have no git protection."""
    env_config = SimpleNamespace(
        name="production",
        secrets_only=False,
        clear_file=str(tmp_path / ".env.clear"),
        secret_file=str(tmp_path / ".env.secret"),
        combined_file=str(tmp_path / ".env"),
    )
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[env_config])
    )

    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.pull_partial_encryption",
        lambda _: (True, False),  # decrypted, but skip-worktree failed
    )
    monkeypatch.setattr("envdrift.cli_commands.partial.ensure_gitignore_entries", lambda _: [])

    result = runner.invoke(app, ["pull-partial"])

    assert result.exit_code == 0
    assert "Security Notice" not in result.output
    assert "DANGER" in result.output
    assert "No Git Protection Applied" in result.output


def test_pull_secrets_only_danger_warning_when_unprotected(monkeypatch, tmp_path: Path):
    """secrets-only: DANGER warning shown when files were decrypted but no skip-worktree succeeded."""
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
        lambda _: {"decrypted": 2, "already_decrypted": 0, "protected": 0},
    )
    monkeypatch.setattr("envdrift.cli_commands.partial.ensure_gitignore_entries", lambda _: [])

    result = runner.invoke(app, ["pull-partial"])

    assert result.exit_code == 0
    assert "Security Notice" not in result.output
    assert "DANGER" in result.output
    assert "No Git Protection Applied" in result.output


def test_push_message_combine_mode_mentions_combined_files(monkeypatch, tmp_path: Path):
    """Combine-mode push completion text must reference combined files as runtime artifacts."""
    env_config = SimpleNamespace(
        name="production",
        clear_file=str(tmp_path / ".env.production.clear"),
        secret_file=str(tmp_path / ".env.production.secret"),
        combined_file=str(tmp_path / ".env.production"),
        secrets_only=False,
    )
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[env_config])
    )

    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.push_partial_encryption",
        lambda _env, check=False: {"clear_lines": 1, "secret_vars": 1, "in_sync": True},
    )
    monkeypatch.setattr("envdrift.cli_commands.partial.ensure_gitignore_entries", lambda _paths: [])

    result = runner.invoke(app, ["push"])

    assert result.exit_code == 0
    # New contract: success line is about source files; combined files are runtime artifacts.
    assert "Source files are encrypted" in result.output
    assert "Combined files are ready to commit" not in result.output
    assert "runtime artifact" in result.output


def test_push_message_secrets_only_omits_combined_wording(monkeypatch, tmp_path: Path):
    """Secrets-only push must not claim a combined file was produced."""
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
        lambda _env, check=False: {"encrypted": 2, "already_encrypted": 0, "in_sync": False},
    )
    monkeypatch.setattr("envdrift.cli_commands.partial.ensure_gitignore_entries", lambda _paths: [])

    result = runner.invoke(app, ["push"])

    assert result.exit_code == 0
    output = " ".join(result.output.split())
    assert "Source files are encrypted" in output
    assert (
        "Secrets-only files are encrypted in place; run 'envdrift pull-partial' to edit them."
    ) in output
    assert "run 'envdrift pull' to edit them." not in output
    # No combined file was produced, so the combined-artifact line must be absent.
    assert "runtime artifact" not in output


def test_load_partial_encryption_paths_skips_secrets_only(monkeypatch, tmp_path: Path):
    """_load_partial_encryption_paths must skip secrets_only envs so Path('') never
    collapses to the current directory and pollute the clear/secret/combined sets."""
    from envdrift.cli_commands import sync as sync_mod

    secrets_env = SimpleNamespace(
        name="secrets",
        secrets_only=True,
        secrets_dir=str(tmp_path / "secrets"),
        clear_file="",
        secret_file="",
        combined_file="",
    )
    combine_env = SimpleNamespace(
        name="production",
        secrets_only=False,
        clear_file=str(tmp_path / ".env.production.clear"),
        secret_file=str(tmp_path / ".env.production.secret"),
        combined_file=str(tmp_path / ".env.production"),
    )
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[secrets_env, combine_env])
    )

    monkeypatch.setattr(sync_mod, "_find_config_path", lambda _cf: tmp_path / "envdrift.toml")
    monkeypatch.setattr("envdrift.config.load_config", lambda _path: config)

    clear_files, secret_files, combined_files = sync_mod._load_partial_encryption_paths(None)

    cwd = Path.cwd()
    # The secrets-only env contributes nothing; only the combine-mode env's files appear.
    assert clear_files == {Path(combine_env.clear_file).resolve()}
    assert secret_files == {Path(combine_env.secret_file).resolve()}
    assert combined_files == {Path(combine_env.combined_file).resolve()}
    # And crucially the current directory was never added by the empty secrets-only paths.
    assert cwd not in clear_files
    assert cwd not in secret_files
    assert cwd not in combined_files


def _patch_sync_command_seams(monkeypatch, tmp_path: Path, partial_config):
    """Mock the vault/engine/backend seams so `pull`/`lock` reach their Step-3
    partial-encryption handling without a real vault or encryption backend."""
    from envdrift.cli_commands import sync as sync_mod
    from envdrift.encryption import EncryptionProvider
    from envdrift.sync.config import ServiceMapping, SyncConfig

    # Force a wide console so long tmp_path values do not soft-wrap rendered output
    # (CliRunner has no tty, so Rich would otherwise fall back to an 80-col width).
    monkeypatch.setenv("COLUMNS", "200")

    service_dir = tmp_path / "svc"
    service_dir.mkdir()
    sync_config = SyncConfig(
        mappings=[
            ServiceMapping(secret_name="s", folder_path=service_dir, environment="production")
        ],
        default_vault_name="v",
    )
    monkeypatch.setattr(
        sync_mod,
        "load_sync_config_and_client",
        lambda **_kw: (sync_config, None, "azure", None, None, None),
    )
    monkeypatch.setattr(
        "envdrift.integrations.hook_check.ensure_git_hook_setup",
        lambda config_file=None: [],
    )
    backend = SimpleNamespace(
        name="dotenvx",
        is_installed=lambda: True,
        install_instructions=lambda: "",
    )
    monkeypatch.setattr(
        "envdrift.cli_commands.encryption_helpers.resolve_encryption_backend",
        lambda _cf: (backend, EncryptionProvider.DOTENVX, None),
    )
    monkeypatch.setattr(sync_mod, "_find_config_path", lambda _cf: tmp_path / "envdrift.toml")
    monkeypatch.setattr("envdrift.config.load_config", lambda _p: partial_config)


def test_sync_pull_dispatches_secrets_only(monkeypatch, tmp_path: Path):
    """`pull` must dispatch a secrets_only env to pull_secrets_only and never treat
    its empty secret_file (Path('') -> cwd) as a real, existing file."""
    secrets_env = SimpleNamespace(
        name="secrets",
        secrets_only=True,
        secrets_dir=str(tmp_path / "secrets"),
        clear_file="",
        secret_file="",
        combined_file="",
    )
    partial_config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[secrets_env])
    )
    _patch_sync_command_seams(monkeypatch, tmp_path, partial_config)

    called = {}

    def _fake_pull_secrets_only(env):
        called["env"] = env
        return {"decrypted": 2, "already_decrypted": 1}

    monkeypatch.setattr(
        "envdrift.core.partial_encryption.pull_secrets_only", _fake_pull_secrets_only
    )

    def _fail_combine(_env):
        raise AssertionError("combine-mode pull must not run for a secrets_only env")

    monkeypatch.setattr("envdrift.core.partial_encryption.pull_partial_encryption", _fail_combine)

    result = runner.invoke(app, ["pull", "--skip-sync", "--force"])

    assert result.exit_code == 0, result.output
    assert called.get("env") is secrets_env
    assert "2 file(s) decrypted" in result.output


def test_lock_all_skips_secrets_only(monkeypatch, tmp_path: Path):
    """`lock --all` must skip secrets_only envs instead of treating empty secret_file/
    combined_file (Path('') -> cwd) as files to encrypt or delete."""
    secrets_env = SimpleNamespace(
        name="secrets",
        secrets_only=True,
        secrets_dir=str(tmp_path / "secrets"),
        clear_file="",
        secret_file="",
        combined_file="",
    )
    partial_config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[secrets_env])
    )
    _patch_sync_command_seams(monkeypatch, tmp_path, partial_config)

    result = runner.invoke(app, ["lock", "--all", "--check", "--force"])

    assert result.exit_code == 0, result.output
    assert "secrets-only, managed by 'envdrift push'" in result.output
    # No combined file was deleted and nothing in the cwd was touched.
    assert "Combined files to delete: 0" in result.output


def test_sync_pull_secrets_only_already_decrypted(monkeypatch, tmp_path: Path):
    """`pull` reports the already-decrypted branch (no newly decrypted files)."""
    secrets_env = SimpleNamespace(
        name="secrets",
        secrets_only=True,
        secrets_dir=str(tmp_path / "secrets"),
        clear_file="",
        secret_file="",
        combined_file="",
    )
    partial_config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[secrets_env])
    )
    _patch_sync_command_seams(monkeypatch, tmp_path, partial_config)
    monkeypatch.setattr(
        "envdrift.core.partial_encryption.pull_secrets_only",
        lambda _env: {"decrypted": 0, "already_decrypted": 4},
    )

    result = runner.invoke(app, ["pull", "--skip-sync", "--force"])

    assert result.exit_code == 0, result.output
    assert "skipped (already decrypted)" in result.output


def test_sync_pull_secrets_only_error(monkeypatch, tmp_path: Path):
    """`pull` records a PartialEncryptionError from a secrets_only env and exits non-zero."""
    from envdrift.core.partial_encryption import PartialEncryptionError

    secrets_env = SimpleNamespace(
        name="secrets",
        secrets_only=True,
        secrets_dir=str(tmp_path / "secrets"),
        clear_file="",
        secret_file="",
        combined_file="",
    )
    partial_config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[secrets_env])
    )
    _patch_sync_command_seams(monkeypatch, tmp_path, partial_config)

    def _raise(_env):
        raise PartialEncryptionError("secrets_dir not found")

    monkeypatch.setattr("envdrift.core.partial_encryption.pull_secrets_only", _raise)

    result = runner.invoke(app, ["pull", "--skip-sync", "--force"])

    assert result.exit_code == 1, result.output
    assert "secrets_dir not found" in result.output


def test_push_stops_before_any_environment_when_git_still_sees_a_key_file(
    monkeypatch, tmp_path: Path
):
    """A `!` rule after envdrift's entry: exit 1 naming the key file, nothing pushed."""
    if shutil.which("git") is None:
        pytest.skip("git not available")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / ".gitignore").write_text("!.env.keys\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    env_config = SimpleNamespace(
        name="production",
        clear_file="config/.env.production.clear",
        secret_file="config/.env.production.secret",
        combined_file="config/.env.production",
        secrets_only=False,
    )
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[env_config])
    )
    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)
    pushed: list[object] = []
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.push_partial_encryption",
        lambda env, check=False: pushed.append(env),
    )

    result = runner.invoke(app, ["push"])

    output = " ".join(result.output.split())
    assert result.exit_code == 1, output
    assert "git does not ignore config/.env.keys" in output, output
    assert pushed == []


def test_push_says_to_untrack_a_key_file_git_already_tracks(monkeypatch, tmp_path: Path):
    """A tracked key file is not ignored whatever .gitignore says: say to untrack it.

    git check-ignore does not report a tracked path as ignored, so the message blamed a
    `!` rule: the user edited .gitignore, and push stopped again.
    """
    if shutil.which("git") is None:
        pytest.skip("git not available")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / ".env.keys").write_text("# keys\n", encoding="utf-8")
    subprocess.run(["git", "add", "config/.env.keys"], cwd=tmp_path, check=True)
    monkeypatch.chdir(tmp_path)

    result, output, pushed = _push_recording(monkeypatch, [_combine_env("production", "config")])

    assert result.exit_code == 1, output
    assert "git does not ignore config/.env.keys" in output, output
    assert "git already tracks it" in output and "git rm --cached" in output, output
    assert pushed == []


def _push_recording(monkeypatch, environments) -> tuple[Result, str, list[object]]:
    """Run push over ``environments`` with the encryption step recorded, not run."""
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=environments)
    )
    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)
    pushed: list[object] = []
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.push_partial_encryption",
        lambda env, check=False: pushed.append(env),
    )
    result = runner.invoke(app, ["push"])
    return result, " ".join(result.output.split()), pushed


def _combine_env(name: str, folder: str) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        clear_file=f"{folder}/.env.{name}.clear",
        secret_file=f"{folder}/.env.{name}.secret",
        combined_file=f"{folder}/.env.{name}",
        secrets_only=False,
    )


def test_push_stops_when_git_cannot_say_whether_a_key_file_is_ignored(monkeypatch, tmp_path: Path):
    """git check-ignore fails (exit 128): exit 1 with git's error, nothing pushed.

    The 128 used to count as ignored, so push went on. The message does not blame a
    `!` rule that is not there.
    """
    if shutil.which("git") is None:
        pytest.skip("git not available")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / ".git" / "index").write_bytes(b"not an index")  # check-ignore exits 128
    monkeypatch.chdir(tmp_path)

    result, output, pushed = _push_recording(monkeypatch, [_combine_env("production", "config")])

    assert result.exit_code == 1, output
    assert (
        "git could not say whether it ignores config/.env.keys "
        "(git check-ignore exited 128: fatal:" in output
    ), output
    assert "re-includes" not in output, output
    assert "stopped before it encrypted or decrypted any partial-encryption file" in output
    assert pushed == []


def test_push_names_each_key_file_git_does_not_confirm_and_why(monkeypatch, tmp_path: Path):
    """Each key file is asked about in its own repository, and each failure is named.

    ``app`` and ``lib`` are repositories of their own inside the working directory's:
    a rule in ``app`` re-includes its key, and git fails in ``lib``.
    """
    if shutil.which("git") is None:
        pytest.skip("git not available")
    for repo in (tmp_path, tmp_path / "app", tmp_path / "lib"):
        repo.mkdir(exist_ok=True)
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    (tmp_path / "app" / "config").mkdir()
    (tmp_path / "app" / "config" / ".gitignore").write_text("!.env.keys\n", encoding="utf-8")
    (tmp_path / "lib" / ".git" / "index").write_bytes(b"not an index")
    monkeypatch.chdir(tmp_path)

    result, output, pushed = _push_recording(
        monkeypatch,
        [_combine_env("production", "app/config"), _combine_env("staging", "lib/config")],
    )

    assert result.exit_code == 1, output
    assert "git does not ignore app/config/.env.keys, where dotenvx" in output, output
    assert (
        "git could not say whether it ignores lib/config/.env.keys "
        "(git check-ignore exited 128: fatal:" in output
    ), output
    # Each entry is in the .gitignore of the repository that would stage the file.
    assert "config/.env.keys" in (tmp_path / "app" / ".gitignore").read_text(encoding="utf-8")
    assert "config/.env.keys" in (tmp_path / "lib" / ".gitignore").read_text(encoding="utf-8")
    assert not (tmp_path / ".gitignore").exists()
    assert pushed == []


def test_sync_pull_reports_any_combine_mode_failure_for_that_environment(
    monkeypatch, tmp_path: Path
):
    """`pull` caught only PartialEncryptionError, so anything else was a traceback."""
    secret = tmp_path / ".env.production.secret"
    secret.write_text("K=v\n", encoding="utf-8")
    env = SimpleNamespace(
        name="production",
        secrets_only=False,
        clear_file=str(tmp_path / ".env.production.clear"),
        secret_file=str(secret),
        combined_file=str(tmp_path / ".env.production"),
    )

    def _raise(_env):
        raise RuntimeError("dotenvx vanished")

    monkeypatch.setattr("envdrift.core.partial_encryption.pull_partial_encryption", _raise)

    result, output = _sync_pull(monkeypatch, tmp_path, [env])

    assert result.exit_code == 1, output
    assert not isinstance(result.exception, RuntimeError), result.exception
    assert "• production: dotenvx vanished" in output, output


# ---------------------------------------------------------------------------
# #948: a pull that fails part way reports the true tally and still warns about
# the files it left decrypted.
# ---------------------------------------------------------------------------


def _secrets_only_env(tmp_path: Path, name: str = "production") -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        secrets_only=True,
        secrets_dir=str(tmp_path / "secrets"),
        pattern=".env*",
        combined_file="",
        clear_file="",
        secret_file="",
    )


def _raise_after(decrypted: int, already_decrypted: int, protected: int):
    """A pull_secrets_only stand-in that fails after decrypting some files."""
    from envdrift.core.partial_encryption import SecretsOnlyPullError

    def _pull(_env):
        raise SecretsOnlyPullError(
            "Failed to decrypt secrets/.env.db: could not decrypt STRIPE_API_KEY",
            decrypted=decrypted,
            already_decrypted=already_decrypted,
            protected=protected,
        )

    return _pull


def test_pull_partial_counts_files_decrypted_before_a_secrets_only_error(
    monkeypatch, tmp_path: Path
):
    """#948: the files decrypted before the failure are counted and announced."""
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[_secrets_only_env(tmp_path)])
    )
    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)
    monkeypatch.setattr("envdrift.cli_commands.partial.pull_secrets_only", _raise_after(2, 1, 2))
    monkeypatch.setattr("envdrift.cli_commands.partial.ensure_gitignore_entries", lambda _: [])

    result = runner.invoke(app, ["pull-partial"])

    output = " ".join(result.output.split())
    assert result.exit_code == 1, output
    assert "Decrypted 2 file(s) in" in output and "before the error" in output
    assert "Decrypted: 2" in output and "Skipped: 1" in output and "Errors: 1" in output
    assert "could not decrypt STRIPE_API_KEY" in output
    # The two plaintext files are protected, so the yellow notice is shown.
    assert "SECRET FILES ARE NOW PLAINTEXT" in output
    assert "Pull complete!" not in output


def test_pull_partial_danger_notice_for_unprotected_files_decrypted_before_an_error(
    monkeypatch, tmp_path: Path
):
    """#948: with no skip-worktree protection the DANGER notice is shown."""
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[_secrets_only_env(tmp_path)])
    )
    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)
    monkeypatch.setattr("envdrift.cli_commands.partial.pull_secrets_only", _raise_after(1, 0, 0))
    monkeypatch.setattr("envdrift.cli_commands.partial.ensure_gitignore_entries", lambda _: [])

    result = runner.invoke(app, ["pull-partial"])

    output = " ".join(result.output.split())
    assert result.exit_code == 1, output
    assert "Decrypted: 1" in output
    assert "No Git Protection Applied" in output
    assert "Security Notice" not in output


def test_pull_partial_shows_notice_when_another_environment_failed(monkeypatch, tmp_path: Path):
    """#948: a decrypted file is plaintext even if a later environment fails."""
    from envdrift.core.partial_encryption import PartialEncryptionError

    combine_env = SimpleNamespace(
        name="production",
        secrets_only=False,
        clear_file=str(tmp_path / ".env.clear"),
        secret_file=str(tmp_path / ".env.secret"),
        combined_file=str(tmp_path / ".env"),
    )
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(
            enabled=True, environments=[combine_env, _secrets_only_env(tmp_path, "staging")]
        )
    )

    def _fail(_env):
        raise PartialEncryptionError("secrets_dir not found")

    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.pull_partial_encryption", lambda _: (True, True)
    )
    monkeypatch.setattr("envdrift.cli_commands.partial.pull_secrets_only", _fail)
    monkeypatch.setattr("envdrift.cli_commands.partial.ensure_gitignore_entries", lambda _: [])

    result = runner.invoke(app, ["pull-partial"])

    output = " ".join(result.output.split())
    assert result.exit_code == 1, output
    assert "Decrypted: 1" in output and "Errors: 1" in output
    assert "secrets_dir not found" in output
    assert "SECRET FILES ARE NOW PLAINTEXT" in output


def test_sync_pull_counts_secrets_only_files_decrypted_before_an_error(monkeypatch, tmp_path: Path):
    """#948: `pull` reports the files decrypted before a secrets-only failure."""
    partial_config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[_secrets_only_env(tmp_path)])
    )
    _patch_sync_command_seams(monkeypatch, tmp_path, partial_config)
    monkeypatch.setattr("envdrift.core.partial_encryption.pull_secrets_only", _raise_after(2, 3, 2))

    result = runner.invoke(app, ["pull", "--skip-sync", "--force"])

    output = " ".join(result.output.split())
    assert result.exit_code == 1, output
    summary = output.split("Partial Encryption Summary", 1)[1]
    assert "Decrypted: 2" in summary and "Skipped: 3" in summary and "Errors: 1" in summary
    assert "could not decrypt STRIPE_API_KEY" in output


def test_pull_partial_first_secrets_only_file_failing_reports_nothing_decrypted(
    monkeypatch, tmp_path: Path
):
    """#948: when the first file fails, nothing is claimed and no notice is shown."""
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=[_secrets_only_env(tmp_path)])
    )
    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)
    monkeypatch.setattr("envdrift.cli_commands.partial.pull_secrets_only", _raise_after(0, 0, 0))
    monkeypatch.setattr("envdrift.cli_commands.partial.ensure_gitignore_entries", lambda _: [])

    result = runner.invoke(app, ["pull-partial"])

    output = " ".join(result.output.split())
    assert result.exit_code == 1, output
    assert "Decrypted: 0" in output and "Errors: 1" in output
    assert "before the error" not in output
    assert "SECRET FILES ARE" not in output


# ---------------------------------------------------------------------------
# #999: `pull` gives pull-partial's warning for decrypted secret files it could
# not protect, instead of dropping the result.
# ---------------------------------------------------------------------------


def _sync_pull(monkeypatch, tmp_path: Path, environments):
    partial_config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=environments)
    )
    _patch_sync_command_seams(monkeypatch, tmp_path, partial_config)
    monkeypatch.setenv("COLUMNS", "1000")  # no tmp_path folded inside the panel
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.unprotected_reason",
        lambda path: f"why-{path.name}",
        raising=False,
    )
    result = runner.invoke(app, ["pull", "--skip-sync", "--force"])
    return result, " ".join(result.output.replace("│", " ").split())


def test_sync_pull_warns_about_an_unprotected_decrypted_secret_file(monkeypatch, tmp_path: Path):
    secret = tmp_path / ".env.production.secret"
    secret.write_text("K=v\n", encoding="utf-8")
    env = SimpleNamespace(
        name="production",
        secrets_only=False,
        clear_file=str(tmp_path / ".env.production.clear"),
        secret_file=str(secret),
        combined_file=str(tmp_path / ".env.production"),
    )
    monkeypatch.setattr(
        "envdrift.core.partial_encryption.pull_partial_encryption", lambda _env: (True, False)
    )

    result, output = _sync_pull(monkeypatch, tmp_path, [env])

    assert result.exit_code == 0, output  # decrypting succeeded
    assert f"{secret} (why-.env.production.secret)" in output
    assert output.index("Setup complete!") < output.index("No Git Protection Applied")


def test_sync_pull_warns_about_unprotected_secrets_only_files(monkeypatch, tmp_path: Path):
    unprotected = [tmp_path / "secrets" / ".env.b"]
    monkeypatch.setattr(
        "envdrift.core.partial_encryption.pull_secrets_only",
        lambda _env: {
            "decrypted": 2,
            "already_decrypted": 0,
            "protected": 1,
            "unprotected": unprotected,
        },
    )

    result, output = _sync_pull(monkeypatch, tmp_path, [_secrets_only_env(tmp_path)])

    assert result.exit_code == 0, output
    assert f"{unprotected[0]} (why-.env.b)" in output
    assert "The other 1 decrypted file(s) are marked skip-worktree." in output


def test_sync_pull_warns_before_exiting_on_a_secrets_only_error(monkeypatch, tmp_path: Path):
    from envdrift.core.partial_encryption import SecretsOnlyPullError

    unprotected = [tmp_path / "secrets" / ".env.a"]

    def _fail(_env):
        raise SecretsOnlyPullError(
            "Failed to decrypt secrets/.env.db",
            decrypted=1,
            already_decrypted=0,
            protected=0,
            unprotected=unprotected,
        )

    monkeypatch.setattr("envdrift.core.partial_encryption.pull_secrets_only", _fail)

    result, output = _sync_pull(monkeypatch, tmp_path, [_secrets_only_env(tmp_path)])

    assert result.exit_code == 1, output
    assert f"{unprotected[0]} (why-.env.a)" in output
    assert "Setup complete!" not in output


def test_sync_pull_gives_no_warning_when_every_secret_file_is_protected(
    monkeypatch, tmp_path: Path
):
    secret = tmp_path / ".env.production.secret"
    secret.write_text("K=v\n", encoding="utf-8")
    env = SimpleNamespace(
        name="production",
        secrets_only=False,
        clear_file=str(tmp_path / ".env.production.clear"),
        secret_file=str(secret),
        combined_file=str(tmp_path / ".env.production"),
    )
    monkeypatch.setattr(
        "envdrift.core.partial_encryption.pull_partial_encryption", lambda _env: (True, True)
    )

    result, output = _sync_pull(monkeypatch, tmp_path, [env])

    assert result.exit_code == 0, output
    assert "No Git Protection Applied" not in output
