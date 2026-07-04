"""Regression tests for `envdrift hook --install` correctness (#493).

Covers the three findings of issue #493:

1. The generated pre-commit config must be runnable as emitted: no active
   ``envdrift-validate`` hook without a ``--schema`` (it is shipped commented
   out until configured), and the file-passing hooks accept multi-file batches
   (``validate`` / ``encrypt --check`` take multiple env-file arguments).
2. ``hook --install`` must not round-trip the user's
   ``.pre-commit-config.yaml`` through ``yaml.dump`` — comments and formatting
   are preserved via targeted text insertion.
3. Malformed or non-mapping YAML fails cleanly (exit 1, no traceback).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.integrations.precommit import (
    HOOK_CONFIG,
    install_hooks,
    uninstall_hooks,
    verify_hooks_installed,
)

runner = CliRunner()


def _active_hook_ids(config_text: str) -> list[str]:
    """Hook ids that are *active* (uncommented) in a pre-commit YAML document."""
    config = yaml.safe_load(config_text) or {}
    hook_ids: list[str] = []
    for repo in config.get("repos") or []:
        for hook in repo.get("hooks") or []:
            hook_ids.append(hook.get("id", ""))
    return hook_ids


def _normalized(output: str) -> str:
    return " ".join(output.split())


class TestGeneratedConfigShape:
    """Finding 1: the emitted config must be runnable as-is."""

    def test_template_has_no_active_validate_hook(self):
        """The validate hook needs --schema, so it must not be active by default."""
        active = _active_hook_ids(HOOK_CONFIG)
        assert "envdrift-validate" not in active

    def test_template_active_hooks_are_encryption_and_guard(self):
        active = _active_hook_ids(HOOK_CONFIG)
        assert "envdrift-encryption" in active
        assert "envdrift-guard" in active

    def test_template_keeps_validate_as_commented_example_with_schema(self):
        """The validate hook ships as a commented example that carries --schema."""
        assert "# - id: envdrift-validate" in HOOK_CONFIG
        commented = [line for line in HOOK_CONFIG.splitlines() if "envdrift validate" in line]
        assert commented, "template lost the validate hook example"
        for line in commented:
            assert line.lstrip().startswith("#"), f"active validate entry in template: {line!r}"
            assert "--schema" in line, f"validate entry without --schema: {line!r}"

    def test_no_active_entry_requires_unset_schema(self):
        """No *active* entry may invoke `envdrift validate` without --schema."""
        config = yaml.safe_load(HOOK_CONFIG) or {}
        for repo in config.get("repos") or []:
            for hook in repo.get("hooks") or []:
                entry = hook.get("entry", "")
                if entry.startswith("envdrift validate"):
                    assert "--schema" in entry

    def test_hook_command_snippet_matches_template(self, monkeypatch: pytest.MonkeyPatch):
        """`envdrift hook --config` prints the same (fixed) template, not a stale copy."""
        result = runner.invoke(app, ["hook", "--config"])
        assert result.exit_code == 0
        out = _normalized(result.output)
        assert "# - id: envdrift-validate" in _normalized(HOOK_CONFIG)
        assert "envdrift-encryption" in out
        assert "envdrift-guard" in out
        # The always-failing bare entry must be gone from the printed snippet too.
        assert "entry: envdrift validate --ci pass_filenames" not in out
        for line in result.output.splitlines():
            stripped = line.strip()
            if stripped.startswith("entry:") and "envdrift validate" in stripped:
                pytest.fail(f"hook --config still prints an active schema-less entry: {line!r}")

    def test_installed_config_has_no_active_validate_hook(self, tmp_path: Path):
        config_file = tmp_path / ".pre-commit-config.yaml"
        assert install_hooks(config_path=config_file) is True
        content = config_file.read_text(encoding="utf-8")
        active = _active_hook_ids(content)
        assert "envdrift-validate" not in active
        assert "envdrift-encryption" in active
        assert "envdrift-guard" in active
        # The commented example stays available for the user to enable.
        assert "# - id: envdrift-validate" in content


class TestInstallPreservesYaml:
    """Finding 2: --install must not destroy the user's comments/formatting."""

    ORIGINAL = textwrap.dedent(
        """\
        # DO NOT EDIT without talking to the platform team
        # See https://wiki.example.com/pre-commit for the policy.
        default_language_version:
          python: python3.11  # pinned for CI parity
        repos:
          - repo: https://github.com/psf/black
            rev: 24.3.0  # bump quarterly
            hooks:
              - id: black
        """
    )

    def test_install_keeps_every_original_line(self, tmp_path: Path):
        config_file = tmp_path / ".pre-commit-config.yaml"
        config_file.write_text(self.ORIGINAL, encoding="utf-8")

        assert install_hooks(config_path=config_file) is True

        updated = config_file.read_text(encoding="utf-8")
        updated_lines = updated.splitlines()
        for line in self.ORIGINAL.splitlines():
            assert line in updated_lines, f"--install destroyed original line: {line!r}"

    def test_install_result_is_valid_and_hooks_are_registered(self, tmp_path: Path):
        config_file = tmp_path / ".pre-commit-config.yaml"
        config_file.write_text(self.ORIGINAL, encoding="utf-8")

        install_hooks(config_path=config_file)

        config = yaml.safe_load(config_file.read_text(encoding="utf-8"))
        assert isinstance(config, dict)
        hook_ids = _active_hook_ids(config_file.read_text(encoding="utf-8"))
        assert "black" in hook_ids
        assert "envdrift-encryption" in hook_ids
        assert "envdrift-guard" in hook_ids

    def test_install_inserts_inside_repos_when_repos_is_not_last(self, tmp_path: Path):
        original = textwrap.dedent(
            """\
            repos:
              - repo: https://github.com/psf/black
                rev: 24.3.0
                hooks:
                  - id: black
            ci:
              autofix_prs: false  # keep bots quiet
            """
        )
        config_file = tmp_path / ".pre-commit-config.yaml"
        config_file.write_text(original, encoding="utf-8")

        assert install_hooks(config_path=config_file) is True

        updated = config_file.read_text(encoding="utf-8")
        config = yaml.safe_load(updated)
        assert config["ci"] == {"autofix_prs": False}
        assert "# keep bots quiet" in updated
        hook_ids = _active_hook_ids(updated)
        assert "envdrift-encryption" in hook_ids
        assert "envdrift-guard" in hook_ids

    def test_install_into_empty_flow_repos(self, tmp_path: Path):
        config_file = tmp_path / ".pre-commit-config.yaml"
        config_file.write_text("# my config\nrepos: []\n", encoding="utf-8")

        assert install_hooks(config_path=config_file) is True

        updated = config_file.read_text(encoding="utf-8")
        assert "# my config" in updated
        hook_ids = _active_hook_ids(updated)
        assert "envdrift-encryption" in hook_ids
        assert "envdrift-guard" in hook_ids

    def test_install_into_null_repos(self, tmp_path: Path):
        config_file = tmp_path / ".pre-commit-config.yaml"
        config_file.write_text("# my config\nrepos:\n", encoding="utf-8")

        assert install_hooks(config_path=config_file) is True

        updated = config_file.read_text(encoding="utf-8")
        assert "# my config" in updated
        hook_ids = _active_hook_ids(updated)
        assert "envdrift-encryption" in hook_ids
        assert "envdrift-guard" in hook_ids

    def test_install_appends_repos_key_when_missing(self, tmp_path: Path):
        config_file = tmp_path / ".pre-commit-config.yaml"
        config_file.write_text("# just a comment\nexclude: ^vendored/\n", encoding="utf-8")

        assert install_hooks(config_path=config_file) is True

        updated = config_file.read_text(encoding="utf-8")
        assert "# just a comment" in updated
        config = yaml.safe_load(updated)
        assert config["exclude"] == "^vendored/"
        hook_ids = _active_hook_ids(updated)
        assert "envdrift-encryption" in hook_ids
        assert "envdrift-guard" in hook_ids

    def test_second_install_is_a_no_op(self, tmp_path: Path):
        config_file = tmp_path / ".pre-commit-config.yaml"
        config_file.write_text(self.ORIGINAL, encoding="utf-8")

        assert install_hooks(config_path=config_file) is True
        after_first = config_file.read_text(encoding="utf-8")
        assert install_hooks(config_path=config_file) is False
        assert config_file.read_text(encoding="utf-8") == after_first

    def test_uninstall_after_install_restores_original_file(self, tmp_path: Path):
        """install followed by uninstall must leave the user's file byte-identical."""
        config_file = tmp_path / ".pre-commit-config.yaml"
        config_file.write_text(self.ORIGINAL, encoding="utf-8")

        install_hooks(config_path=config_file)
        assert uninstall_hooks(config_path=config_file) is True

        assert config_file.read_text(encoding="utf-8") == self.ORIGINAL


class TestInstallFailsCleanly:
    """Finding 3: malformed / non-mapping YAML must not produce a traceback."""

    def test_install_hooks_raises_clean_error_on_malformed_yaml(self, tmp_path: Path):
        from envdrift.integrations.precommit import PrecommitConfigError

        config_file = tmp_path / ".pre-commit-config.yaml"
        config_file.write_text("repos: [unclosed\n", encoding="utf-8")

        with pytest.raises(PrecommitConfigError, match=r"[Cc]ould not parse"):
            install_hooks(config_path=config_file)
        # The broken file is left untouched.
        assert config_file.read_text(encoding="utf-8") == "repos: [unclosed\n"

    def test_install_hooks_raises_clean_error_on_non_mapping_yaml(self, tmp_path: Path):
        from envdrift.integrations.precommit import PrecommitConfigError

        config_file = tmp_path / ".pre-commit-config.yaml"
        config_file.write_text("- just\n- a list\n", encoding="utf-8")

        with pytest.raises(PrecommitConfigError, match="mapping"):
            install_hooks(config_path=config_file)
        assert config_file.read_text(encoding="utf-8") == "- just\n- a list\n"

    def test_hook_install_cli_malformed_yaml_exits_1_without_traceback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".pre-commit-config.yaml").write_text("repos: [unclosed\n", encoding="utf-8")

        result = runner.invoke(app, ["hook", "--install"])

        assert result.exit_code == 1
        assert result.exception is None or isinstance(result.exception, SystemExit), (
            f"hook --install leaked {type(result.exception).__name__}: {result.exception}"
        )
        out = _normalized(result.output)
        assert "Traceback" not in result.output
        assert "could not parse" in out.lower()

    def test_hook_install_cli_non_mapping_yaml_exits_1_without_traceback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".pre-commit-config.yaml").write_text("- just\n- a list\n", encoding="utf-8")

        result = runner.invoke(app, ["hook", "--install"])

        assert result.exit_code == 1
        assert result.exception is None or isinstance(result.exception, SystemExit), (
            f"hook --install leaked {type(result.exception).__name__}: {result.exception}"
        )
        out = _normalized(result.output)
        assert "Traceback" not in result.output
        assert "mapping" in out.lower()

    def test_verify_hooks_handles_null_repos_and_non_mapping_repo_items(self, tmp_path: Path):
        """Sibling robustness: verify must not crash on `repos:` null or odd items."""
        config_file = tmp_path / ".pre-commit-config.yaml"
        config_file.write_text("repos:\n", encoding="utf-8")
        result = verify_hooks_installed(config_path=config_file)
        assert result == dict.fromkeys(result, False)

        config_file.write_text("repos:\n  - not-a-mapping\n  - repo: local\n", encoding="utf-8")
        result = verify_hooks_installed(config_path=config_file)
        assert result == dict.fromkeys(result, False)

    def test_uninstall_hooks_returns_false_on_malformed_yaml(self, tmp_path: Path):
        config_file = tmp_path / ".pre-commit-config.yaml"
        config_file.write_text("repos: [unclosed\n", encoding="utf-8")
        assert uninstall_hooks(config_path=config_file) is False
        assert config_file.read_text(encoding="utf-8") == "repos: [unclosed\n"

    def test_uninstall_hooks_returns_false_on_non_mapping_yaml(self, tmp_path: Path):
        config_file = tmp_path / ".pre-commit-config.yaml"
        config_file.write_text("- just\n- a list\n", encoding="utf-8")
        assert uninstall_hooks(config_path=config_file) is False

    def test_uninstall_hooks_handles_null_repos_without_markers(self, tmp_path: Path):
        """Legacy (marker-less) uninstall on `repos:` null must not raise TypeError.

        `_parse_precommit_config` lets an explicit `repos: null` through, so the
        legacy rewrite path used to iterate over None (PR #512 review).
        """
        original = "# hand-crafted config\nrepos:\n"
        config_file = tmp_path / ".pre-commit-config.yaml"
        config_file.write_text(original, encoding="utf-8")

        assert uninstall_hooks(config_path=config_file) is False
        assert config_file.read_text(encoding="utf-8") == original

    def test_uninstall_hooks_removes_legacy_marker_less_hooks(self, tmp_path: Path):
        """Pre-#493 installs (no markers) still uninstall via the rewrite path."""
        legacy = textwrap.dedent(
            """\
            repos:
              - repo: local
                hooks:
                  - id: envdrift-encryption
                    entry: envdrift encrypt --check
                  - id: other-hook
                    entry: echo test
            """
        )
        config_file = tmp_path / ".pre-commit-config.yaml"
        config_file.write_text(legacy, encoding="utf-8")

        assert uninstall_hooks(config_path=config_file) is True

        config = yaml.safe_load(config_file.read_text(encoding="utf-8"))
        hook_ids = [hook.get("id") for repo in config["repos"] for hook in repo.get("hooks") or []]
        assert "envdrift-encryption" not in hook_ids
        assert "other-hook" in hook_ids


class TestRenderedYamlQuoting:
    """Rendered hook lines must stay valid YAML even for tricky scalar values."""

    def test_render_hook_lines_quote_unsafe_scalars(self):
        """Values with `: `, ` #`, or a leading indicator must round-trip (PR #512 review)."""
        from envdrift.integrations.precommit import _render_hook_lines

        hook = {
            "id": "envdrift-example",
            "name": "note: a colon-space clause",
            "entry": "envdrift validate --ci # not a comment",
            "files": "- leading indicator",
            "description": "it's quoted ' correctly",
            "pass_filenames": True,
        }
        parsed = yaml.safe_load("\n".join(_render_hook_lines(hook)))
        assert parsed == [hook]

    def test_current_template_values_stay_plain(self):
        """Today's HOOK_ENTRY values are safe plain scalars — no quoting noise."""
        assert "'" not in HOOK_CONFIG


class TestHookInstallCliMessages:
    """The CLI reports what actually happened (truthful results)."""

    def test_fresh_install_reports_success_and_writes_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["hook", "--install"])

        assert result.exit_code == 0
        assert (tmp_path / ".pre-commit-config.yaml").exists()
        assert "installed" in _normalized(result.output).lower()

    def test_reinstall_reports_already_installed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.chdir(tmp_path)
        first = runner.invoke(app, ["hook", "--install"])
        assert first.exit_code == 0

        result = runner.invoke(app, ["hook", "--install"])

        assert result.exit_code == 0
        assert "already" in _normalized(result.output).lower()


class TestMultiFileCliArguments:
    """Finding 1 (CLI side): validate / encrypt --check accept multiple env files."""

    def test_validate_accepts_multiple_env_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "settings_hook_reg_ok.py").write_text(
            textwrap.dedent(
                """\
                from pydantic_settings import BaseSettings


                class Settings(BaseSettings):
                    FOO: str = "unset"
                """
            ),
            encoding="utf-8",
        )
        (tmp_path / ".env.production").write_text("FOO=bar\n", encoding="utf-8")
        (tmp_path / ".env.staging").write_text("FOO=baz\n", encoding="utf-8")

        result = runner.invoke(
            app,
            [
                "validate",
                "--ci",
                "--schema",
                "settings_hook_reg_ok:Settings",
                ".env.production",
                ".env.staging",
            ],
        )

        out = _normalized(result.output)
        assert result.exit_code == 0, out
        assert ".env.production" in out
        assert ".env.staging" in out

    def test_validate_ci_fails_when_any_of_multiple_files_invalid(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "settings_hook_reg_fail.py").write_text(
            textwrap.dedent(
                """\
                from pydantic_settings import BaseSettings


                class Settings(BaseSettings):
                    FOO: str
                """
            ),
            encoding="utf-8",
        )
        (tmp_path / ".env.production").write_text("FOO=bar\n", encoding="utf-8")
        (tmp_path / ".env.staging").write_text("OTHER=value\n", encoding="utf-8")

        result = runner.invoke(
            app,
            [
                "validate",
                "--ci",
                "--schema",
                "settings_hook_reg_fail:Settings",
                ".env.production",
                ".env.staging",
            ],
        )

        assert result.exit_code == 1, _normalized(result.output)

    def test_validate_reports_missing_file_among_multiple(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "settings_hook_reg_missing.py").write_text(
            "from pydantic_settings import BaseSettings\n\n\n"
            'class Settings(BaseSettings):\n    FOO: str = "unset"\n',
            encoding="utf-8",
        )
        (tmp_path / ".env.production").write_text("FOO=bar\n", encoding="utf-8")

        result = runner.invoke(
            app,
            [
                "validate",
                "--ci",
                "--schema",
                "settings_hook_reg_missing:Settings",
                ".env.production",
                ".env.missing",
            ],
        )

        out = _normalized(result.output)
        assert result.exit_code == 1, out
        assert "not found" in out.lower()

    def test_encrypt_check_accepts_multiple_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env.production").write_text("FOO=bar\n", encoding="utf-8")
        (tmp_path / ".env.staging").write_text("BAR=baz\n", encoding="utf-8")

        result = runner.invoke(app, ["encrypt", "--check", ".env.production", ".env.staging"])

        out = _normalized(result.output)
        assert result.exit_code == 0, out
        assert ".env.production" in out
        assert ".env.staging" in out

    def test_encrypt_check_multiple_files_blocks_on_any_secret(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env.production").write_text("FOO=bar\n", encoding="utf-8")
        (tmp_path / ".env.staging").write_text("DB_PASSWORD=hunter2\n", encoding="utf-8")

        result = runner.invoke(app, ["encrypt", "--check", ".env.production", ".env.staging"])

        assert result.exit_code == 1, _normalized(result.output)

    def test_encrypt_check_reports_missing_file_among_multiple(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env.production").write_text("FOO=bar\n", encoding="utf-8")

        result = runner.invoke(app, ["encrypt", "--check", ".env.production", ".env.missing"])

        out = _normalized(result.output)
        assert result.exit_code == 1, out
        assert "not found" in out.lower()
