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


def test_pull_shows_security_notice_when_secrets_decrypted(monkeypatch, tmp_path: Path):
    """pull-partial shows the yellow warning panel when at least one file is decrypted."""
    env_config = SimpleNamespace(
        name="production",
        secrets_only=False,
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


def test_pull_no_security_notice_when_skip_worktree_failed(monkeypatch, tmp_path: Path):
    """If files were decrypted but skip-worktree never succeeded, the notice must not
    claim protection — so it is suppressed entirely."""
    env_config = SimpleNamespace(
        name="production",
        secrets_only=False,
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


def test_pull_secrets_only_notice_suppressed_when_unprotected(monkeypatch, tmp_path: Path):
    """secrets-only: notice suppressed when no file was successfully skip-worktree'd."""
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
        lambda _env: {"clear_lines": 1, "secret_vars": 1},
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
        lambda _: {"encrypted": 2, "already_encrypted": 0},
    )
    monkeypatch.setattr("envdrift.cli_commands.partial.ensure_gitignore_entries", lambda _paths: [])

    result = runner.invoke(app, ["push"])

    assert result.exit_code == 0
    assert "Source files are encrypted" in result.output
    assert "Secrets-only files are encrypted in place" in result.output
    # No combined file was produced, so the combined-artifact line must be absent.
    assert "runtime artifact" not in result.output


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
