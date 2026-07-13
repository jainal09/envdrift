"""Tests for the agent CLI commands."""

from __future__ import annotations

import json
import os
import platform
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

import envdrift.agent.registry as registry_module
from envdrift.cli import app

runner = CliRunner()


class TestAgentRegisterCommand:
    """Tests for 'envdrift agent register' command."""

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        """Reset the global registry singleton before each test."""

        registry_module._registry = None
        yield
        registry_module._registry = None

    def test_register_current_directory(self, tmp_path: Path, monkeypatch):
        """Test registering the current directory."""

        # Set up a temp registry
        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        # Create a project with envdrift.toml
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        (project_dir / "envdrift.toml").write_text("[envdrift]\n")

        monkeypatch.chdir(project_dir)

        result = runner.invoke(app, ["agent", "register"])

        assert result.exit_code == 0
        assert "Registered" in result.stdout or "✓" in result.stdout

    def test_register_specific_path(self, tmp_path: Path):
        """Test registering a specific path."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project_dir = tmp_path / "myproject"
        project_dir.mkdir()

        result = runner.invoke(app, ["agent", "register", str(project_dir)])

        assert result.exit_code == 0
        assert "Registered" in result.stdout or "✓" in result.stdout

    def test_register_already_registered(self, tmp_path: Path):
        """Test registering a project that's already registered."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project_dir = tmp_path / "myproject"
        project_dir.mkdir()

        # Register once
        runner.invoke(app, ["agent", "register", str(project_dir)])

        # Register again
        result = runner.invoke(app, ["agent", "register", str(project_dir)])

        assert result.exit_code == 0  # Not an error, just a warning
        assert "already registered" in result.stdout

    def test_register_nonexistent_path(self, tmp_path: Path):
        """Test registering a path that doesn't exist."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        result = runner.invoke(app, ["agent", "register", str(tmp_path / "nonexistent")])

        assert result.exit_code == 1
        assert "does not exist" in result.stdout

    def test_register_guardian_hint_emits_literal_section_header(self, tmp_path: Path):
        """The 'enable guardian' hint prints a literal ``[guardian]`` header (#413).

        Rich would otherwise parse ``[guardian]`` as a markup tag and strip it,
        emitting invalid TOML that silently never turns auto-encryption on. We
        render through a real no-color Console so the assertion is independent of
        FORCE_COLOR / NO_COLOR in the environment.
        """
        import io

        from rich.console import Console

        import envdrift.cli_commands.agent as agent_module

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        # Guardian explicitly disabled -> the hint block is printed.
        (project_dir / "envdrift.toml").write_text("[guardian]\nenabled = false\n")

        buf = io.StringIO()
        capture = Console(file=buf, force_terminal=False, no_color=True, width=200)
        with patch.object(agent_module, "console", capture):
            result = runner.invoke(app, ["agent", "register", str(project_dir)])

        assert result.exit_code == 0
        output = buf.getvalue()
        assert "[guardian]" in output
        assert "enabled = true" in output

    def test_register_invalid_config_shows_warning(self, tmp_path: Path):
        """Register reports an unparseable config without crashing.

        With deferred guardian validation (#413) a bad idle_timeout no longer
        fails at load time, so this exercises the load-failure branch with
        genuinely malformed TOML instead.
        """

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        # Missing closing bracket -> tomllib.TOMLDecodeError -> the register
        # command surfaces it via the "Failed to load" branch (no crash).
        (project_dir / "envdrift.toml").write_text("[guardian\nenabled = true\n")

        result = runner.invoke(app, ["agent", "register", str(project_dir)])

        assert result.exit_code == 0
        assert "Failed to load envdrift config" in result.stdout

    def test_register_invalid_guardian_idle_timeout_when_enabled(self, tmp_path: Path):
        """Register surfaces a bad idle_timeout only when guardian is enabled (#413).

        idle_timeout validation is deferred to GuardianWatchConfig.validate(),
        which register calls at the agent surface when [guardian].enabled = true.
        """

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        (project_dir / "envdrift.toml").write_text("""
[guardian]
enabled = true
idle_timeout = "invalid"
""")

        result = runner.invoke(app, ["agent", "register", str(project_dir)])

        # Registration still succeeds; the invalid agent-only knob is reported
        # without crashing.
        assert result.exit_code == 0
        assert "Invalid [guardian] config" in result.stdout

    def test_register_invalid_guardian_idle_timeout_disabled_is_ignored(self, tmp_path: Path):
        """A bad idle_timeout with guardian disabled does not error (#413)."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        (project_dir / "envdrift.toml").write_text("""
[guardian]
idle_timeout = "invalid"
""")

        result = runner.invoke(app, ["agent", "register", str(project_dir)])

        # Deferred validation: guardian isn't enabled, so the typo isn't
        # consumed — registration succeeds and prints the enable hint.
        assert result.exit_code == 0
        assert "Failed to load envdrift config" not in result.stdout
        assert "Guardian is not enabled" in result.stdout


class TestAgentUnregisterCommand:
    """Tests for 'envdrift agent unregister' command."""

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        """Reset the global registry singleton before each test."""

        registry_module._registry = None
        yield
        registry_module._registry = None

    def test_unregister_registered_project(self, tmp_path: Path):
        """Test unregistering a registered project."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project_dir = tmp_path / "myproject"
        project_dir.mkdir()

        # Register first
        runner.invoke(app, ["agent", "register", str(project_dir)])

        # Unregister
        result = runner.invoke(app, ["agent", "unregister", str(project_dir)])

        assert result.exit_code == 0
        assert "Unregistered" in result.stdout or "✓" in result.stdout

    def test_unregister_not_registered(self, tmp_path: Path):
        """Test unregistering a project that's not registered."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project_dir = tmp_path / "myproject"
        project_dir.mkdir()

        result = runner.invoke(app, ["agent", "unregister", str(project_dir)])

        assert result.exit_code == 0  # Not an error, just a warning
        assert "not registered" in result.stdout


class TestAgentListCommand:
    """Tests for 'envdrift agent list' command."""

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        """Reset the global registry singleton before each test."""

        registry_module._registry = None
        yield
        registry_module._registry = None

    def test_list_empty(self, tmp_path: Path):
        """Test listing when no projects are registered."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        result = runner.invoke(app, ["agent", "list"])

        assert result.exit_code == 0
        assert "No projects registered" in result.stdout

    def test_list_with_projects(self, tmp_path: Path):
        """Test listing registered projects."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project1 = tmp_path / "project1"
        project2 = tmp_path / "project2"
        project1.mkdir()
        project2.mkdir()

        runner.invoke(app, ["agent", "register", str(project1)])
        runner.invoke(app, ["agent", "register", str(project2)])

        result = runner.invoke(app, ["agent", "list"])

        assert result.exit_code == 0
        # Check table is shown (header row)
        assert "Registered Projects" in result.stdout
        assert "Path" in result.stdout
        # Verify registry file contains both projects
        registry_data = json.loads(registry_path.read_text())
        assert len(registry_data["projects"]) == 2
        paths = [p["path"] for p in registry_data["projects"]]
        assert str(project1.resolve()) in paths
        assert str(project2.resolve()) in paths


class TestAgentStatusCommand:
    """Tests for 'envdrift agent status' command."""

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        """Reset the global registry singleton before each test."""

        registry_module._registry = None
        yield
        registry_module._registry = None

    def test_status_agent_not_installed(self, tmp_path: Path):
        """Test status when agent is not installed."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        with patch("envdrift.cli_commands.agent._find_agent_binary", return_value=None):
            result = runner.invoke(app, ["agent", "status"])

        assert result.exit_code == 0
        assert "not installed" in result.stdout

    def test_status_shows_registered_projects(self, tmp_path: Path):
        """Test status shows count of registered projects."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project = tmp_path / "myproject"
        project.mkdir()
        runner.invoke(app, ["agent", "register", str(project)])

        with patch("envdrift.cli_commands.agent._find_agent_binary", return_value=None):
            result = runner.invoke(app, ["agent", "status"])

        assert result.exit_code == 0
        assert "Registered Projects" in result.stdout
        assert "1" in result.stdout

    def test_status_missing_running_line(self, tmp_path: Path):
        """Test status handles missing Running line as error."""
        import subprocess

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        def fake_run(args, **_kwargs):
            if args[1] == "status":
                stdout = "Installed: true\nConfig:    /tmp/envdrift.toml\nenvdrift:  true\n"
                return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")
            if args[1] == "version":  # the agent only has a `version` subcommand (#482)
                return subprocess.CompletedProcess(
                    args, 0, stdout="envdrift-agent v1.2.3\n", stderr=""
                )
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="")

        with patch(
            "envdrift.cli_commands.agent._find_agent_binary",
            return_value=Path("/usr/local/bin/envdrift-agent"),
        ):
            with patch("envdrift.cli_commands.agent.subprocess.run", side_effect=fake_run):
                result = runner.invoke(app, ["agent", "status"])

        assert result.exit_code == 0
        assert "Agent status check failed" in result.stdout

    def test_status_running_parses_running_line(self, tmp_path: Path):
        """Test status parses running state from the Running line."""
        import subprocess

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        def fake_run(args, **_kwargs):
            if args[1] == "status":
                stdout = (
                    "Installed: true\n"
                    "Running:   true\n"
                    "Config:    /tmp/envdrift.toml\n"
                    "envdrift:  true\n"
                )
                return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")
            if args[1] == "version":  # the agent only has a `version` subcommand (#482)
                return subprocess.CompletedProcess(
                    args, 0, stdout="envdrift-agent v1.2.3\n", stderr=""
                )
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="")

        with patch(
            "envdrift.cli_commands.agent._find_agent_binary",
            return_value=Path("/usr/local/bin/envdrift-agent"),
        ):
            with patch("envdrift.cli_commands.agent.subprocess.run", side_effect=fake_run):
                result = runner.invoke(app, ["agent", "status"])

        assert result.exit_code == 0
        assert "Agent is running" in result.stdout
        assert "Version: envdrift-agent v1.2.3" in result.stdout

    def test_status_stopped_parses_running_false(self, tmp_path: Path):
        """Test status treats 'Running: false' as stopped."""
        import subprocess

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        def fake_run(args, **_kwargs):
            if args[1] == "status":
                stdout = (
                    "Installed: true\n"
                    "Running:   false\n"
                    "Config:    /tmp/envdrift.toml\n"
                    "envdrift:  true\n"
                )
                return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")
            if args[1] == "version":  # the agent only has a `version` subcommand (#482)
                return subprocess.CompletedProcess(
                    args, 0, stdout="envdrift-agent v1.2.3\n", stderr=""
                )
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="")

        with patch(
            "envdrift.cli_commands.agent._find_agent_binary",
            return_value=Path("/usr/local/bin/envdrift-agent"),
        ):
            with patch("envdrift.cli_commands.agent.subprocess.run", side_effect=fake_run):
                result = runner.invoke(app, ["agent", "status"])

        assert result.exit_code == 0
        assert "Agent is stopped" in result.stdout
        assert "Version:" not in result.stdout

    def test_status_broken_binary_names_cause_and_reinstall_hint(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Regression for #441: a broken agent binary must not dead-end on itself.

        With a real garbage executable on PATH (no subprocess mocks), running it
        raises OSError (Exec format error). ``agent status`` previously printed
        the generic 'Agent status check failed / Run envdrift-agent status for
        details' — a suggestion that itself cannot run. It must surface the
        underlying OS error and point at ``envdrift install agent --force``.
        """
        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        fake_dir = tmp_path / "fakebin"
        fake_dir.mkdir()
        binary_name = (
            "envdrift-agent.exe" if platform.system().lower() == "windows" else "envdrift-agent"
        )
        fake_agent = fake_dir / binary_name
        fake_agent.write_bytes(b"\x7fELF\xff\xffgarbage")
        fake_agent.chmod(0o755)
        monkeypatch.setenv("PATH", str(fake_dir))

        result = runner.invoke(app, ["agent", "status"])

        out = " ".join(result.output.split())
        assert result.exit_code == 0
        assert "Run envdrift-agent status for details" not in out
        assert "cannot run" in out
        assert "envdrift install agent --force" in out
        if os.name == "posix":
            # The underlying OS error must be carried into the output.
            assert "Exec format error" in out


class TestAgentHelpCommand:
    """Tests for 'envdrift agent --help' command."""

    def test_agent_help(self):
        """Test that agent --help shows subcommands."""
        result = runner.invoke(app, ["agent", "--help"])

        assert result.exit_code == 0
        assert "register" in result.stdout
        assert "unregister" in result.stdout
        assert "list" in result.stdout
        assert "status" in result.stdout


class TestAgentRegistryCorruptionCli:
    """Regression tests for #492: corrupt registries surfaced cleanly via the CLI."""

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        """Reset the global registry singleton before each test."""

        registry_module._registry = None
        yield
        registry_module._registry = None

    @staticmethod
    def _normalize(output: str) -> str:
        """Collapse Rich line-wrapping so substring asserts are width-stable."""
        return " ".join(output.split())

    def test_register_on_corrupt_registry_warns_and_backs_up(self, tmp_path: Path):
        """Register over a truncated registry succeeds but names the backup."""
        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_path.parent.mkdir(parents=True)
        registry_path.write_text('{"projects": [{"path": "/old/pro', encoding="utf-8")
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project_dir = tmp_path / "myproject"
        project_dir.mkdir()

        result = runner.invoke(app, ["agent", "register", str(project_dir)])

        assert result.exit_code == 0
        out = self._normalize(result.stdout)
        assert "Registered" in out
        assert "corrupt" in out.lower()
        backups = sorted(registry_path.parent.glob("projects.json.corrupt-*"))
        assert len(backups) == 1
        # Rich may wrap the long backup path mid-token; squash ALL whitespace
        # before asserting so the check is terminal-width independent.
        assert backups[0].name in "".join(result.stdout.split())

    def test_list_top_level_array_exits_zero_with_warning(self, tmp_path: Path):
        """`agent list` on a top-level JSON array warns instead of crashing."""
        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_path.parent.mkdir(parents=True)
        registry_path.write_text("[]", encoding="utf-8")
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        result = runner.invoke(app, ["agent", "list"])

        assert result.exit_code == 0, result.output
        assert result.exception is None
        out = self._normalize(result.stdout)
        assert "corrupt" in out.lower()
        assert "No projects registered" in out
        # Read-only command: the corrupt file must be left in place untouched.
        assert registry_path.read_text(encoding="utf-8") == "[]"

    def test_status_string_entries_exits_zero_with_warning(self, tmp_path: Path):
        """`agent status` on string project entries warns instead of crashing."""
        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_path.parent.mkdir(parents=True)
        registry_path.write_text('{"projects": ["/tmp/foo"]}', encoding="utf-8")
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        with patch("envdrift.cli_commands.agent._find_agent_binary", return_value=None):
            result = runner.invoke(app, ["agent", "status"])

        assert result.exit_code == 0, result.output
        assert result.exception is None
        out = self._normalize(result.stdout)
        assert "corrupt" in out.lower()
        assert "Registered Projects: 0" in out

    def test_unregister_miss_on_corrupt_registry_warns_without_backup(self, tmp_path: Path):
        """A no-op unregister on a corrupt registry warns but leaves the file."""
        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_path.parent.mkdir(parents=True)
        corrupt = "{ not json"
        registry_path.write_text(corrupt, encoding="utf-8")
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project_dir = tmp_path / "myproject"
        project_dir.mkdir()

        result = runner.invoke(app, ["agent", "unregister", str(project_dir)])

        assert result.exit_code == 0, result.output
        out = self._normalize(result.stdout)
        assert "not registered" in out.lower()
        assert "corrupt" in out.lower()
        # The hint must name only `register` — an unregister miss never saves,
        # so it can never perform the backup (#506 review).
        assert "by the next register." in out
        assert registry_path.read_text(encoding="utf-8") == corrupt

    @pytest.mark.parametrize("command", ["register", "unregister"])
    def test_lock_held_exits_one_with_clean_error(self, tmp_path: Path, command: str):
        """A held registry lock fails the write command cleanly, not with a hang."""
        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path, lock_timeout=0.3)
        holder = registry_module.ProjectRegistry(registry_path)

        project_dir = tmp_path / "myproject"
        project_dir.mkdir()

        with holder._exclusive_lock():
            result = runner.invoke(app, ["agent", command, str(project_dir)])

        assert result.exit_code == 1, result.output
        assert result.exception is None or isinstance(result.exception, SystemExit)
        out = self._normalize(result.stdout)
        assert "lock" in out.lower()

    def test_register_backup_failure_is_reported_truthfully(self, tmp_path: Path, monkeypatch):
        """If the corrupt-file backup rename fails, the CLI says so honestly."""
        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_path.parent.mkdir(parents=True)
        registry_path.write_text("{ not json", encoding="utf-8")
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project_dir = tmp_path / "myproject"
        project_dir.mkdir()

        original_replace = Path.replace

        def failing_backup_replace(self: Path, target):
            if ".corrupt-" in str(target):
                raise OSError("simulated rename failure")
            return original_replace(self, target)

        monkeypatch.setattr(Path, "replace", failing_backup_replace)

        result = runner.invoke(app, ["agent", "register", str(project_dir)])

        assert result.exit_code == 0, result.output
        out = self._normalize(result.stdout)
        assert "could not be backed up" in out.lower()
