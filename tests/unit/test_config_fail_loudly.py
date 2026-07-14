"""Regression tests for #491: config loading fails loudly.

Config loading used to degrade silently: a TOML syntax error made ``encrypt``
fall back to the default dotenvx backend with exit 0, ``vault-pull``/
``vault-push`` suppressed the parse error and told the user to "configure in
envdrift.toml" (the broken file itself), typo'd keys were dropped without any
warning, and several malformed/unreadable-config shapes escaped as raw Rich
tracebacks. These tests drive the real CLI commands (CliRunner) and the real
``load_config``/``find_config`` functions over real files in ``tmp_path`` —
no mocking of the behavior under test.
"""

from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path
from textwrap import dedent

import pytest
from typer.testing import CliRunner

from envdrift.cli import app

runner = CliRunner()
# Click 8.3 always captures stderr separately and no longer accepts the old
# ``mix_stderr`` option. Keep a dedicated runner for these stream-contract
# tests so a future capture-semantics change fails their explicit assertions.
separate_streams_runner = CliRunner()


def _flat(output: str) -> str:
    """Normalize Rich output for substring asserts (CI wraps narrow COLUMNS)."""
    return " ".join(output.split())


# ---------------------------------------------------------------------------
# find_config: auto-discovery must return only regular files (#491 item 5)
# ---------------------------------------------------------------------------


class TestFindConfigSkipsNonFiles:
    def test_directory_named_envdrift_toml_is_skipped(self, tmp_path: Path):
        """A directory named envdrift.toml must not be returned by discovery."""
        from envdrift.config import find_config

        (tmp_path / "envdrift.toml").mkdir()
        assert find_config(tmp_path) is None

    def test_walks_past_directory_to_parent_config(self, tmp_path: Path):
        """Discovery keeps walking up past a directory-shaped envdrift.toml."""
        from envdrift.config import find_config

        parent_config = tmp_path / "envdrift.toml"
        parent_config.write_text("[envdrift]\n", encoding="utf-8")
        child = tmp_path / "child"
        child.mkdir()
        (child / "envdrift.toml").mkdir()

        assert find_config(child) == parent_config

    def test_directory_named_pyproject_toml_is_skipped(self, tmp_path: Path):
        """A directory named pyproject.toml must not crash discovery."""
        from envdrift.config import find_config

        (tmp_path / "pyproject.toml").mkdir()
        assert find_config(tmp_path) is None

    def test_malformed_pyproject_toml_is_skipped(self, tmp_path: Path):
        """Discovery skips an unparseable pyproject.toml and keeps walking."""
        from envdrift.config import find_config

        (tmp_path / "pyproject.toml").write_text("bad = [\n", encoding="utf-8")
        assert find_config(tmp_path) is None

    def test_load_config_autodiscovery_with_directory_config_returns_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """load_config() auto-discovery never open()s a directory (#491)."""
        from envdrift.config import EnvdriftConfig, load_config

        (tmp_path / "envdrift.toml").mkdir()
        monkeypatch.chdir(tmp_path)
        config = load_config()
        assert isinstance(config, EnvdriftConfig)


# ---------------------------------------------------------------------------
# load_config: every malformed/unreadable shape raises ConfigLoadError
# ---------------------------------------------------------------------------


class TestLoadConfigFailsLoudly:
    def test_malformed_toml_raises_config_load_error(self, tmp_path: Path):
        from envdrift.config import ConfigLoadError, load_config

        cfg = tmp_path / "envdrift.toml"
        cfg.write_text('[encryption]\nbackend = "sops\n', encoding="utf-8")
        with pytest.raises(ConfigLoadError, match="TOML syntax error"):
            load_config(cfg)

    def test_wrong_typed_vault_section_raises_config_load_error(self, tmp_path: Path):
        """``vault = "a string"`` used to escape as an AttributeError traceback."""
        from envdrift.config import ConfigLoadError, load_config

        cfg = tmp_path / "envdrift.toml"
        cfg.write_text('vault = "a string"\n', encoding="utf-8")
        with pytest.raises(ConfigLoadError, match="Invalid config"):
            load_config(cfg)

    def test_mapping_folder_path_wrong_type_raises_config_load_error(self, tmp_path: Path):
        """``folder_path = 456`` used to crash later with a raw TypeError."""
        from envdrift.config import ConfigLoadError, load_config

        cfg = tmp_path / "envdrift.toml"
        cfg.write_text(
            '[[vault.sync.mappings]]\nsecret_name = "k"\nfolder_path = 456\n',
            encoding="utf-8",
        )
        with pytest.raises(ConfigLoadError, match="folder_path"):
            load_config(cfg)

    def test_mapping_missing_secret_name_raises_config_load_error(self, tmp_path: Path):
        from envdrift.config import ConfigLoadError, load_config

        cfg = tmp_path / "envdrift.toml"
        cfg.write_text('[[vault.sync.mappings]]\nfolder_path = "."\n', encoding="utf-8")
        with pytest.raises(ConfigLoadError, match="secret_name"):
            load_config(cfg)

    def test_mapping_env_file_and_activate_to_wrong_type_raise_config_load_error(
        self, tmp_path: Path
    ):
        """``env_file = 456`` / ``activate_to = 789`` used to crash later inside
        Path() with a raw TypeError traceback (#491 review; same class as #488)."""
        from envdrift.config import ConfigLoadError, load_config

        cfg = tmp_path / "envdrift.toml"
        cfg.write_text(
            dedent(
                """\
                [[vault.sync.mappings]]
                secret_name = "k"
                folder_path = "."
                env_file = 456
                activate_to = 789
                """
            ),
            encoding="utf-8",
        )
        with pytest.raises(ConfigLoadError, match="env_file, activate_to"):
            load_config(cfg)

    def test_sync_config_from_toml_env_file_wrong_type_clean_error(self):
        """The explicit --config layer must reject non-string mapping values too,
        as a SyncConfigError, not a TypeError from Path() (#491 review, #488)."""
        from envdrift.sync.config import SyncConfig, SyncConfigError

        with pytest.raises(SyncConfigError, match="env_file"):
            SyncConfig.from_toml(
                {"mappings": [{"secret_name": "k", "folder_path": ".", "env_file": 456}]}
            )

    def test_sync_config_from_toml_activate_to_wrong_type_clean_error(self):
        from envdrift.sync.config import SyncConfig, SyncConfigError

        with pytest.raises(SyncConfigError, match="activate_to"):
            SyncConfig.from_toml(
                {"mappings": [{"secret_name": "k", "folder_path": ".", "activate_to": 789}]}
            )

    @pytest.mark.skipif(
        sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
        reason="POSIX permission bits; root bypasses chmod 000",
    )
    def test_unreadable_config_raises_config_load_error(self, tmp_path: Path):
        from envdrift.config import ConfigLoadError, load_config

        cfg = tmp_path / "envdrift.toml"
        cfg.write_text("[envdrift]\n", encoding="utf-8")
        cfg.chmod(0o000)
        try:
            with pytest.raises(ConfigLoadError, match="Cannot read config file"):
                load_config(cfg)
        finally:
            cfg.chmod(0o644)

    def test_config_load_error_is_value_error(self, tmp_path: Path):
        """Existing ``except ValueError`` boundaries keep catching it."""
        from envdrift.config import ConfigLoadError, load_config

        cfg = tmp_path / "envdrift.toml"
        cfg.write_text("bad = [\n", encoding="utf-8")
        with pytest.raises(ValueError):
            load_config(cfg)
        assert issubclass(ConfigLoadError, ValueError)


# ---------------------------------------------------------------------------
# Unknown-key warnings (#491 item 3)
# ---------------------------------------------------------------------------


class TestUnknownKeyWarnings:
    def test_typoed_guard_key_warns_with_suggestion(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ):
        """A misspelled [guard] fail_on_severity must warn with a did-you-mean."""
        from envdrift.config import load_config

        cfg = tmp_path / "envdrift.toml"
        cfg.write_text('[guard]\nfail_on_severty = "critical"\n', encoding="utf-8")
        load_config(cfg)
        err = capsys.readouterr().err
        assert "fail_on_severty" in err
        assert "fail_on_severity" in err

    def test_typoed_top_level_section_warns(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ):
        from envdrift.config import load_config

        cfg = tmp_path / "envdrift.toml"
        cfg.write_text("[gaurd]\ncheck_entropy = true\n", encoding="utf-8")
        load_config(cfg)
        err = capsys.readouterr().err
        assert "gaurd" in err
        assert "guard" in err

    def test_typoed_strictness_knob_warns(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        """The laxer-default footgun: typo'd ephemeral_keys must not be silent."""
        from envdrift.config import load_config

        cfg = tmp_path / "envdrift.toml"
        cfg.write_text("[vault.sync]\nephemerl_keys = true\n", encoding="utf-8")
        load_config(cfg)
        err = capsys.readouterr().err
        assert "ephemerl_keys" in err
        assert "ephemeral_keys" in err

    def test_unknown_mapping_key_warns(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        from envdrift.config import load_config

        cfg = tmp_path / "envdrift.toml"
        cfg.write_text(
            dedent(
                """\
                [[vault.sync.mappings]]
                secret_name = "k"
                folder_path = "."
                enviroment = "production"
                """
            ),
            encoding="utf-8",
        )
        load_config(cfg)
        err = capsys.readouterr().err
        assert "enviroment" in err
        assert "environment" in err

    def test_freeform_tables_do_not_warn(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        """User-keyed tables (vault.mappings, guard.ignore_rules, precommit.schemas)
        hold arbitrary keys by design and must stay warning-free."""
        from envdrift.config import load_config

        cfg = tmp_path / "envdrift.toml"
        cfg.write_text(
            dedent(
                """\
                [vault.mappings]
                MY_SECRET = "vault-secret-name"

                [guard.ignore_rules]
                "high-entropy-string" = ["**/*.clear"]

                [precommit.schemas]
                production = "config.settings:ProductionSettings"
                """
            ),
            encoding="utf-8",
        )
        load_config(cfg)
        assert capsys.readouterr().err == ""

    def test_example_config_has_no_unknown_keys(self):
        """The shipped EXAMPLE_CONFIG must parse warning-free (spec stays in sync)."""
        from envdrift.config import EXAMPLE_CONFIG, find_unknown_config_keys

        data = tomllib.loads(EXAMPLE_CONFIG)
        assert find_unknown_config_keys(data) == []

    def test_non_dict_data_yields_no_findings(self):
        """A wrong-typed section is a ConfigLoadError concern, not a key warning."""
        from envdrift.config import find_unknown_config_keys

        assert find_unknown_config_keys("not a dict") == []  # type: ignore[arg-type]

    def test_warning_emitted_once_per_process(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ):
        """Commands load the config more than once; the warning must not repeat."""
        from envdrift.config import load_config

        cfg = tmp_path / "envdrift.toml"
        cfg.write_text("[guard]\nautoinstall = true\n", encoding="utf-8")
        load_config(cfg)
        first = capsys.readouterr().err
        assert "autoinstall" in first
        load_config(cfg)
        assert "autoinstall" not in capsys.readouterr().err

    def test_pyproject_tool_envdrift_unknown_key_warns(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ):
        from envdrift.config import load_config

        cfg = tmp_path / "pyproject.toml"
        cfg.write_text(
            dedent(
                """\
                [tool.envdrift.guard]
                fail_on_severty = "critical"
                """
            ),
            encoding="utf-8",
        )
        load_config(cfg)
        err = capsys.readouterr().err
        assert "fail_on_severty" in err

    def test_pyproject_typoed_section_warns_with_real_location_and_hint(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ):
        """A typo'd [tool.envdrift.gaurd] must be reported where the user wrote
        it — not as a mystery key ``in [envdrift]`` — with a did-you-mean for
        the real section name (#491 review)."""
        from envdrift.config import load_config

        cfg = tmp_path / "pyproject.toml"
        cfg.write_text(
            dedent(
                """\
                [tool.envdrift.gaurd]
                check_entropy = true
                """
            ),
            encoding="utf-8",
        )
        load_config(cfg)
        err = capsys.readouterr().err
        assert "unknown config key 'gaurd' in [tool.envdrift]" in err
        assert "did you mean 'guard'" in err

    def test_pyproject_nested_unknown_key_names_full_section(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ):
        """Nested findings name the section as written in pyproject.toml."""
        from envdrift.config import load_config

        cfg = tmp_path / "pyproject.toml"
        cfg.write_text(
            dedent(
                """\
                [tool.envdrift.vault.sync]
                ephemerl_keys = true
                """
            ),
            encoding="utf-8",
        )
        load_config(cfg)
        err = capsys.readouterr().err
        assert "in [tool.envdrift.vault.sync]" in err
        assert "did you mean 'ephemeral_keys'" in err

    def test_plain_pyproject_does_not_warn(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ):
        """A pyproject.toml without [tool.envdrift] consumes nothing — no noise."""
        from envdrift.config import load_config

        cfg = tmp_path / "pyproject.toml"
        cfg.write_text(
            dedent(
                """\
                [project]
                name = "someapp"

                [build-system]
                requires = ["hatchling"]
                """
            ),
            encoding="utf-8",
        )
        load_config(cfg)
        assert capsys.readouterr().err == ""

    def test_warnings_go_to_stderr_not_stdout(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ):
        """Machine-readable stdout (--format json) must stay clean."""
        from envdrift.config import load_config

        cfg = tmp_path / "envdrift.toml"
        cfg.write_text("[validation]\ncheck_encrypton = true\n", encoding="utf-8")
        load_config(cfg)
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "check_encrypton" in captured.err


# ---------------------------------------------------------------------------
# encrypt / decrypt: existing-but-broken config aborts (#491 item 1)
# ---------------------------------------------------------------------------


class TestEncryptDecryptAbortOnBrokenConfig:
    def _write_broken_sops_project(self, tmp_path: Path) -> Path:
        (tmp_path / "envdrift.toml").write_text(
            '[encryption]\nbackend = "sops"\n\n[encryption.sops]\nage_recipients = "age1abc\n',
            encoding="utf-8",
        )
        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar\n", encoding="utf-8")
        return env_file

    def test_encrypt_aborts_and_leaves_file_untouched(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """A SOPS project with a TOML syntax error must NOT get dotenvx-encrypted."""
        env_file = self._write_broken_sops_project(tmp_path)
        monkeypatch.chdir(tmp_path)

        result = separate_streams_runner.invoke(app, ["encrypt", str(env_file)])

        assert result.exit_code == 1, result.output
        out = _flat(result.stderr)
        assert "[ERROR] TOML syntax error in" in out
        assert result.stdout == ""
        assert env_file.read_text(encoding="utf-8") == "FOO=bar\n"
        assert not (tmp_path / ".env.keys").exists()

    def test_decrypt_aborts_on_malformed_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """decrypt shares the loader and must abort just like encrypt."""
        env_file = self._write_broken_sops_project(tmp_path)
        monkeypatch.chdir(tmp_path)

        result = separate_streams_runner.invoke(app, ["decrypt", str(env_file)])

        assert result.exit_code == 1, result.output
        out = _flat(result.stderr)
        assert "[ERROR] TOML syntax error in" in out
        assert result.stdout == ""
        assert env_file.read_text(encoding="utf-8") == "FOO=bar\n"


# ---------------------------------------------------------------------------
# vault-pull / vault-push: parse errors are reported, not hidden (#491 item 2)
# ---------------------------------------------------------------------------


class TestVaultSettingsFailLoudly:
    def test_vault_pull_reports_toml_error_not_provider_hint(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        (tmp_path / "envdrift.toml").write_text('[vault]\nprovider = "azure\n', encoding="utf-8")
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(
            app, ["vault-pull", str(tmp_path), "any-secret", "--env", "production"]
        )

        assert result.exit_code == 1, result.output
        out = _flat(result.output)
        assert "TOML syntax error in" in out
        assert "Vault provider required" not in out

    def test_vault_push_single_reports_toml_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        (tmp_path / "envdrift.toml").write_text('[vault]\nprovider = "azure\n', encoding="utf-8")
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(
            app, ["vault-push", str(tmp_path), "any-secret", "--env", "production"]
        )

        assert result.exit_code == 1, result.output
        out = _flat(result.output)
        assert "TOML syntax error in" in out
        assert "Vault provider required" not in out

    def test_vault_pull_explicit_missing_config_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """An explicit --config that does not exist is an error, not a shrug."""
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "any-secret",
                "--env",
                "production",
                "-c",
                str(tmp_path / "missing.toml"),
            ],
        )

        assert result.exit_code == 1, result.output
        assert "not found" in _flat(result.output)


# ---------------------------------------------------------------------------
# pull / lock / sync: clean one-line errors, never tracebacks (#491 item 4)
# ---------------------------------------------------------------------------


class TestSyncFamilyCleanErrors:
    def test_pull_wrong_typed_vault_section_clean_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """``vault = "a string"`` used to dump an AttributeError traceback."""
        (tmp_path / "envdrift.toml").write_text('vault = "a string"\n', encoding="utf-8")
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["pull"])

        assert result.exit_code == 1, result.output
        assert not isinstance(result.exception, AttributeError)
        assert "Invalid config in" in _flat(result.output)

    def test_pull_mapping_missing_secret_name_clean_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """The #443 ValueError must surface as a clean message, not a traceback."""
        (tmp_path / "envdrift.toml").write_text(
            '[vault]\nprovider = "aws"\n\n[[vault.sync.mappings]]\nfolder_path = "."\n',
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["pull"])

        assert result.exit_code == 1, result.output
        assert isinstance(result.exception, SystemExit)
        assert "secret_name" in _flat(result.output)

    def test_pull_mapping_folder_path_wrong_type_clean_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        (tmp_path / "envdrift.toml").write_text(
            '[vault]\nprovider = "aws"\n\n'
            '[[vault.sync.mappings]]\nsecret_name = "k"\nfolder_path = 456\n',
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["pull"])

        assert result.exit_code == 1, result.output
        assert isinstance(result.exception, SystemExit)
        assert "folder_path" in _flat(result.output)

    def test_pull_mapping_env_file_wrong_type_clean_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """``env_file = 456`` used to escape pull as a raw TypeError traceback
        from Path() (#491 review; same class as #488)."""
        (tmp_path / "envdrift.toml").write_text(
            '[vault]\nprovider = "aws"\n\n'
            '[[vault.sync.mappings]]\nsecret_name = "k"\nfolder_path = "."\nenv_file = 456\n',
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["pull"])

        assert result.exit_code == 1, result.output
        assert isinstance(result.exception, SystemExit)
        assert "env_file" in _flat(result.output)

    def test_lock_autodiscovered_malformed_config_hard_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """A broken discovered config is a hard error, not a warn-and-continue."""
        (tmp_path / "envdrift.toml").write_text("bad = [\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["lock"])

        assert result.exit_code == 1, result.output
        out = _flat(result.output)
        assert "TOML syntax error in" in out
        assert "No sync configuration found" not in out
