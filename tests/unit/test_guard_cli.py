"""Tests for envdrift guard CLI command."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.config import (
    EnvdriftConfig,
    PartialEncryptionConfig,
    PartialEncryptionEnvironmentConfig,
    SyncConfig,
    SyncMappingConfig,
    VaultConfig,
)
from envdrift.config import (
    GuardConfig as FileGuardConfig,
)
from envdrift.scanner.base import AggregatedScanResult, FindingSeverity, ScanFinding
from envdrift.scanner.engine import GuardConfig as EngineGuardConfig

runner = CliRunner()


def _build_result(findings: list[ScanFinding]) -> AggregatedScanResult:
    return AggregatedScanResult(
        results=[],
        total_findings=len(findings),
        unique_findings=findings,
        scanners_used=["native"],
        total_duration_ms=5,
    )


def _make_finding(severity: FindingSeverity) -> ScanFinding:
    return ScanFinding(
        file_path=Path("config.py"),
        line_number=1,
        rule_id="test-rule",
        rule_description="Test Rule",
        description="Test finding",
        severity=severity,
        scanner="native",
    )


def _patch_guard_dependencies(monkeypatch, config: EnvdriftConfig, result: AggregatedScanResult):
    created_configs: list[EngineGuardConfig] = []
    info_calls: list[bool] = []

    class DummyScanner:
        def __init__(self, name: str):
            self.name = name

    class DummyEngine:
        def __init__(self, guard_config: EngineGuardConfig):
            created_configs.append(guard_config)
            self.scanners = [DummyScanner("native")]

        def get_scanner_info(self):
            info_calls.append(True)
            return [{"name": "native", "installed": True, "version": "1.0.0"}]

        def scan(self, _paths, on_scanner_complete=None):
            return result

        def check_combined_files_security(self):
            return []  # No warnings in tests

    monkeypatch.setattr("envdrift.cli_commands.guard.load_config", lambda _p=None: config)
    monkeypatch.setattr("envdrift.cli_commands.guard.ScanEngine", DummyEngine)
    return created_configs, info_calls


def test_guard_missing_path_exits(tmp_path: Path):
    """Missing paths exit with code 1."""
    missing = tmp_path / "nope"
    result = runner.invoke(app, ["guard", str(missing)])
    assert result.exit_code == 1
    assert "path not found" in result.output.lower()


def test_guard_invalid_fail_on_exits(tmp_path: Path, monkeypatch):
    """Invalid --fail-on values exit with code 1."""
    config = EnvdriftConfig()
    dummy_result = _build_result([])
    _patch_guard_dependencies(monkeypatch, config, dummy_result)

    result = runner.invoke(app, ["guard", str(tmp_path), "--fail-on", "invalid"])
    assert result.exit_code == 1
    assert "invalid severity" in result.output.lower()


def test_guard_defaults_to_cwd(tmp_path: Path, monkeypatch):
    """No path arguments default to the current directory."""
    config = EnvdriftConfig()
    dummy_result = _build_result([])
    scan_paths: list[list[Path]] = []

    class DummyEngine:
        def __init__(self, guard_config):
            self.scanners = []

        def get_scanner_info(self):
            return []

        def scan(self, paths, on_scanner_complete=None):
            scan_paths.append(paths)
            return dummy_result

    monkeypatch.setattr("envdrift.cli_commands.guard.load_config", lambda _p=None: config)
    monkeypatch.setattr("envdrift.cli_commands.guard.ScanEngine", DummyEngine)

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["guard"])
    assert result.exit_code == 0
    assert scan_paths
    assert scan_paths[0] == [Path.cwd()]


def test_guard_uses_config_scanners(tmp_path: Path, monkeypatch):
    """Config scanners enable trufflehog and detect-secrets by default."""
    config = EnvdriftConfig(
        guard=FileGuardConfig(
            scanners=["native", "gitleaks", "trufflehog", "detect-secrets"],
            include_history=True,
            check_entropy=True,
            ignore_paths=["vendor/**"],
        )
    )
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(app, ["guard", str(tmp_path)])
    assert result.exit_code == 0

    guard_config = created_configs[0]
    assert guard_config.use_gitleaks is True
    assert guard_config.use_trufflehog is True
    assert guard_config.use_detect_secrets is True
    assert guard_config.include_git_history is True
    assert guard_config.check_entropy is True
    assert guard_config.ignore_paths == ["vendor/**"]


def test_guard_passes_custom_env_files_to_engine(tmp_path: Path, monkeypatch):
    """vault.sync env_file mappings should be treated as guard env files."""
    service_dir = tmp_path / "secrets" / "postgresql"
    service_dir.mkdir(parents=True)
    config = EnvdriftConfig(
        vault=VaultConfig(
            sync=SyncConfig(
                mappings=[
                    SyncMappingConfig(
                        secret_name="postgres-key",
                        folder_path="secrets/postgresql",
                        environment="production",
                        env_file="postgresql.env",
                    )
                ]
            )
        )
    )
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["guard", "."])

    assert result.exit_code == 0, result.output
    # Guard resolves mapped env files to absolute paths so the scanner matches
    # them regardless of which directory is scanned.
    assert created_configs[0].mapped_env_files == [str((service_dir / "postgresql.env").resolve())]


def test_guard_rejects_custom_env_files_outside_folder(tmp_path: Path, monkeypatch):
    """guard should fail fast when a configured env_file escapes folder_path."""
    config = EnvdriftConfig(
        vault=VaultConfig(
            sync=SyncConfig(
                mappings=[
                    SyncMappingConfig(
                        secret_name="postgres-key",
                        folder_path="secrets/postgresql",
                        environment="production",
                        env_file="../outside.env",
                    )
                ]
            )
        )
    )
    _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(app, ["guard", str(tmp_path)])

    assert result.exit_code == 1
    assert "invalid env_file" in result.output.lower()


def test_guard_pr_base_fetch_warns_on_failure(tmp_path: Path, monkeypatch):
    """Fetch failures in PR mode should emit a warning when verbose."""
    config = EnvdriftConfig()
    dummy_result = _build_result([])
    _patch_guard_dependencies(monkeypatch, config, dummy_result)

    fetch_result = SimpleNamespace(returncode=1, stdout="", stderr="fetch failed")
    diff_result = SimpleNamespace(returncode=0, stdout="", stderr="")

    def fake_run(args, **_kwargs):
        if args[:2] == ["git", "fetch"]:
            return fetch_result
        return diff_result

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = runner.invoke(app, ["guard", "--pr-base", "origin/", "--verbose"])
    assert result.exit_code == 0
    assert "warning" in result.output.lower()


def test_guard_pr_base_strips_only_leading_origin_prefix(tmp_path: Path, monkeypatch):
    """--pr-base must strip only a leading ``origin/`` when deriving the fetch ref.

    Regression for #319: a global ``str.replace('origin/', '')`` corrupts refs
    that contain ``origin/`` elsewhere (e.g. ``origin/release/origin-mirror``).
    The fetch must request ``release/origin-mirror`` unchanged.
    """
    import subprocess

    config = EnvdriftConfig()
    _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    fetched_refs: list[str] = []

    def mock_run(cmd, *args, **kwargs):
        if "fetch" in cmd:
            fetched_refs.append(cmd[-1])
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", mock_run)

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["guard", "--pr-base", "origin/release/origin-mirror"])
    assert result.exit_code == 0
    assert fetched_refs == ["release/origin-mirror"], fetched_refs


def test_guard_config_can_disable_gitleaks(tmp_path: Path, monkeypatch):
    """Config scanners can disable gitleaks when not listed."""
    config = EnvdriftConfig(guard=FileGuardConfig(scanners=["native"]))
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(app, ["guard", str(tmp_path)])
    assert result.exit_code == 0

    guard_config = created_configs[0]
    assert guard_config.use_gitleaks is False


def test_guard_cli_overrides_config_scanners(tmp_path: Path, monkeypatch):
    """CLI flags override config scanner selection."""
    config = EnvdriftConfig(
        guard=FileGuardConfig(scanners=["native", "gitleaks", "trufflehog", "detect-secrets"])
    )
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(
        app,
        [
            "guard",
            str(tmp_path),
            "--no-gitleaks",
            "--no-trufflehog",
            "--no-detect-secrets",
        ],
    )
    assert result.exit_code == 0

    guard_config = created_configs[0]
    assert guard_config.use_gitleaks is False
    assert guard_config.use_trufflehog is False
    assert guard_config.use_detect_secrets is False


def test_guard_cli_enables_gitleaks_when_config_disables(tmp_path: Path, monkeypatch):
    """CLI --gitleaks enables gitleaks even when config disables it."""
    config = EnvdriftConfig(guard=FileGuardConfig(scanners=["native"]))
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(app, ["guard", str(tmp_path), "--gitleaks"])
    assert result.exit_code == 0

    guard_config = created_configs[0]
    assert guard_config.use_gitleaks is True


def test_guard_native_only_disables_external_scanners(tmp_path: Path, monkeypatch):
    """--native-only disables external scanners."""
    config = EnvdriftConfig(
        guard=FileGuardConfig(scanners=["native", "gitleaks", "trufflehog", "detect-secrets"])
    )
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(app, ["guard", str(tmp_path), "--native-only"])
    assert result.exit_code == 0

    guard_config = created_configs[0]
    assert guard_config.use_gitleaks is False
    assert guard_config.use_trufflehog is False
    assert guard_config.use_detect_secrets is False


def test_guard_history_and_entropy_flags_override_config(tmp_path: Path, monkeypatch):
    """--history and --entropy override config defaults."""
    config = EnvdriftConfig(guard=FileGuardConfig(include_history=False, check_entropy=False))
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(app, ["guard", str(tmp_path), "--history", "--entropy"])
    assert result.exit_code == 0

    guard_config = created_configs[0]
    assert guard_config.include_git_history is True
    assert guard_config.check_entropy is True


def test_guard_verbose_prints_scanner_info(tmp_path: Path, monkeypatch):
    """--verbose triggers scanner info output."""
    config = EnvdriftConfig()
    created_configs, info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(app, ["guard", str(tmp_path), "--verbose"])
    assert result.exit_code == 0
    assert created_configs
    assert info_calls


def test_guard_ci_respects_fail_on_threshold(tmp_path: Path, monkeypatch):
    """CI mode uses fail-on threshold to set exit code."""
    config = EnvdriftConfig()
    findings = [_make_finding(FindingSeverity.HIGH)]
    created_configs, _info_calls = _patch_guard_dependencies(
        monkeypatch, config, _build_result(findings)
    )

    result = runner.invoke(app, ["guard", str(tmp_path), "--ci", "--fail-on", "critical"])
    assert result.exit_code == 0
    assert created_configs


def test_guard_exits_with_findings_non_ci(tmp_path: Path, monkeypatch):
    """Non-CI runs exit with scan-derived exit codes."""
    config = EnvdriftConfig()
    findings = [_make_finding(FindingSeverity.HIGH)]
    _patch_guard_dependencies(monkeypatch, config, _build_result(findings))

    result = runner.invoke(app, ["guard", str(tmp_path)])
    assert result.exit_code == 2


def test_guard_json_output(tmp_path: Path, monkeypatch):
    """--json outputs serialized results."""
    config = EnvdriftConfig()
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))
    monkeypatch.setattr("envdrift.cli_commands.guard.format_json", lambda _r: "JSON-OUT")

    result = runner.invoke(app, ["guard", str(tmp_path), "--json"])
    assert result.exit_code == 0
    assert "JSON-OUT" in result.output
    assert created_configs


def test_guard_sarif_output(tmp_path: Path, monkeypatch):
    """--sarif outputs SARIF content."""
    config = EnvdriftConfig()
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))
    monkeypatch.setattr("envdrift.cli_commands.guard.format_sarif", lambda _r: "SARIF-OUT")

    result = runner.invoke(app, ["guard", str(tmp_path), "--sarif"])
    assert result.exit_code == 0
    assert "SARIF-OUT" in result.output
    assert created_configs


def test_guard_staged_with_no_staged_files(tmp_path: Path, monkeypatch):
    """--staged with no staged files exits cleanly."""
    import subprocess

    config = EnvdriftConfig()
    _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    # Mock git diff --cached to return empty
    def mock_run(*args, **kwargs):
        result = subprocess.CompletedProcess(args[0], 0, stdout="", stderr="")
        return result

    monkeypatch.setattr("subprocess.run", mock_run)

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["guard", "--staged"])
    assert result.exit_code == 0
    assert "no staged files" in result.output.lower()


def test_guard_missing_config_emits_json_error(tmp_path: Path):
    """--json --config <missing> exits 1 with a JSON error, not a traceback (#413).

    Uses the real load_config so a ConfigNotFoundError is raised at the real
    call site; the command must convert it to a clean ``{"error": ...}`` document
    on stdout instead of letting a Rich traceback contaminate machine output.
    """
    missing = tmp_path / "nope.toml"
    target = tmp_path / "a.env"
    target.write_text("FOO=bar\n")

    result = runner.invoke(
        app, ["guard", "--native-only", "--json", "--config", str(missing), str(target)]
    )
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert "error" in payload
    assert "Could not load config" in payload["error"]
    # No Rich traceback leaked into stdout.
    assert "Traceback" not in result.stdout


def test_guard_malformed_config_emits_json_error(tmp_path: Path):
    """--json --config <malformed.toml> exits 1 with a JSON error (#413)."""
    bad = tmp_path / "envdrift.toml"
    bad.write_text("[guard\n")  # missing closing bracket -> TOMLDecodeError
    target = tmp_path / "a.env"
    target.write_text("FOO=bar\n")

    result = runner.invoke(
        app, ["guard", "--native-only", "--json", "--config", str(bad), str(target)]
    )
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert "error" in payload
    assert "Traceback" not in result.stdout


def test_guard_path_not_found_emits_json_error(tmp_path: Path):
    """--json with a non-existent path emits a JSON error, not prose (#413)."""
    missing = tmp_path / "does-not-exist"

    result = runner.invoke(app, ["guard", "--native-only", "--json", str(missing)])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert "error" in payload
    assert "Path not found" in payload["error"]


def test_guard_staged_no_files_emits_empty_json(tmp_path: Path, monkeypatch):
    """--json --staged with nothing staged emits valid empty-findings JSON (#413).

    Previously this branch printed ``No staged files to scan.`` prose, breaking
    any consumer that always parses guard stdout as JSON.
    """
    import subprocess

    config = EnvdriftConfig()
    _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    def mock_run(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", mock_run)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["guard", "--json", "--staged"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["findings"] == []
    assert payload["summary"]["total"] == 0
    assert "No staged files" not in result.stdout


def test_guard_staged_scans_only_staged_files(tmp_path: Path, monkeypatch):
    """--staged only scans git staged files."""
    import subprocess

    config = EnvdriftConfig()
    scan_paths: list[list[Path]] = []
    dummy_result = _build_result([])

    class DummyScanner:
        def __init__(self, name: str):
            self.name = name

    class DummyEngine:
        def __init__(self, guard_config):
            self.scanners = [DummyScanner("native")]

        def get_scanner_info(self):
            return []

        def scan(self, paths, on_scanner_complete=None):
            scan_paths.append(paths)
            return dummy_result

    monkeypatch.setattr("envdrift.cli_commands.guard.load_config", lambda _p=None: config)
    monkeypatch.setattr("envdrift.cli_commands.guard.ScanEngine", DummyEngine)

    # Mock git diff --cached to return staged files
    def mock_run(cmd, *args, **kwargs):
        if "diff" in cmd and "--cached" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="file1.py\nfile2.env\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", mock_run)

    monkeypatch.chdir(tmp_path)
    # Create the staged files
    Path("file1.py").write_text("# test")
    Path("file2.env").write_text("SECRET=value")

    result = runner.invoke(app, ["guard", "--staged"])
    assert result.exit_code == 0
    assert scan_paths  # Verify scan was called
    assert len(scan_paths[0]) == 2  # Two staged files


def test_guard_staged_resolves_repo_relative_paths_against_toplevel(tmp_path: Path, monkeypatch):
    """--staged resolves git's repo-relative paths against the toplevel.

    Regression for #302: ``git diff --cached`` emits repo-root-relative paths.
    Run from a subdirectory, the staged file lives at ``<root>/sub/leak.env``
    but git reports ``sub/leak.env``. The guard must join against the git
    toplevel (not the subdir cwd) or ``Path.exists()`` drops the file and the
    leak is silently skipped.
    """
    import subprocess

    config = EnvdriftConfig()
    scan_paths: list[list[Path]] = []
    dummy_result = _build_result([])

    class DummyScanner:
        def __init__(self, name: str):
            self.name = name

    class DummyEngine:
        def __init__(self, guard_config):
            self.scanners = [DummyScanner("native")]

        def get_scanner_info(self):
            return []

        def scan(self, paths, on_scanner_complete=None):
            scan_paths.append(paths)
            return dummy_result

    monkeypatch.setattr("envdrift.cli_commands.guard.load_config", lambda _p=None: config)
    monkeypatch.setattr("envdrift.cli_commands.guard.ScanEngine", DummyEngine)

    repo_root = tmp_path
    sub_dir = repo_root / "sub"
    sub_dir.mkdir()
    (sub_dir / "leak.env").write_text("SECRET=value")

    def mock_run(cmd, *args, **kwargs):
        if "rev-parse" in cmd and "--show-toplevel" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout=f"{repo_root}\n", stderr="")
        if "diff" in cmd and "--cached" in cmd:
            # git reports the path relative to the repo root, not the cwd.
            return subprocess.CompletedProcess(cmd, 0, stdout="sub/leak.env\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", mock_run)

    # Run from the subdirectory: the file must still be found and scanned.
    monkeypatch.chdir(sub_dir)
    result = runner.invoke(app, ["guard", "--staged"])
    assert result.exit_code == 0, result.output
    assert "no staged files" not in result.output.lower(), result.output
    assert scan_paths
    # The repo-relative "sub/leak.env" is resolved against the repo root for the
    # existence check, then handed to the scanner as a cwd-relative path (we run
    # from sub/, so it is just "leak.env"). It must resolve to the same file.
    assert len(scan_paths[0]) == 1
    assert (Path.cwd() / scan_paths[0][0]).resolve() == (repo_root / "sub" / "leak.env").resolve()


def _patch_dummy_engine(monkeypatch, config, scan_paths):
    """Wire load_config + a recording DummyEngine for the path-resolution tests."""

    class DummyScanner:
        def __init__(self, name: str):
            self.name = name

    class DummyEngine:
        def __init__(self, guard_config):
            self.scanners = [DummyScanner("native")]

        def get_scanner_info(self):
            return []

        def scan(self, paths, on_scanner_complete=None):
            scan_paths.append(paths)
            return _build_result([])

    monkeypatch.setattr("envdrift.cli_commands.guard.load_config", lambda _p=None: config)
    monkeypatch.setattr("envdrift.cli_commands.guard.ScanEngine", DummyEngine)


def test_guard_staged_git_toplevel_falls_back_to_cwd(tmp_path: Path, monkeypatch):
    """When ``git rev-parse --show-toplevel`` raises (git missing/timeout),
    _git_toplevel swallows it and falls back to cwd so staged files relative to
    cwd are still scanned (not dropped)."""
    import subprocess

    scan_paths: list[list[Path]] = []
    _patch_dummy_engine(monkeypatch, EnvdriftConfig(), scan_paths)
    (tmp_path / "leak.env").write_text("SECRET=value")

    def mock_run(cmd, *args, **kwargs):
        if "rev-parse" in cmd and "--show-toplevel" in cmd:
            # Exercise the except (subprocess.TimeoutExpired, FileNotFoundError) path.
            raise FileNotFoundError("git not found")
        if "diff" in cmd and "--cached" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="leak.env\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", mock_run)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["guard", "--staged"])
    assert result.exit_code == 0, result.output
    assert scan_paths
    assert (Path.cwd() / scan_paths[0][0]).resolve() == (tmp_path / "leak.env").resolve()


def test_guard_pr_base_no_changed_files(tmp_path: Path, monkeypatch):
    """--pr-base with an empty diff reports 'No changed files' and exits 0."""
    import subprocess

    scan_paths: list[list[Path]] = []
    _patch_dummy_engine(monkeypatch, EnvdriftConfig(), scan_paths)

    def mock_run(cmd, *args, **kwargs):
        if "rev-parse" in cmd and "--show-toplevel" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout=f"{tmp_path}\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", mock_run)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["guard", "--pr-base", "origin/main"])
    assert result.exit_code == 0, result.output
    assert "no changed files" in result.output.lower()
    assert not scan_paths


def test_guard_pr_base_resolves_repo_relative_paths_against_toplevel(tmp_path: Path, monkeypatch):
    """--pr-base resolves git's repo-relative diff paths against the toplevel
    (regression for #302, --pr-base branch)."""
    import subprocess

    scan_paths: list[list[Path]] = []
    _patch_dummy_engine(monkeypatch, EnvdriftConfig(), scan_paths)

    repo_root = tmp_path
    sub_dir = repo_root / "sub"
    sub_dir.mkdir()
    (sub_dir / "leak.env").write_text("SECRET=value")

    def mock_run(cmd, *args, **kwargs):
        if "rev-parse" in cmd and "--show-toplevel" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout=f"{repo_root}\n", stderr="")
        if "diff" in cmd:
            # git reports the path relative to the repo root, not the cwd.
            return subprocess.CompletedProcess(cmd, 0, stdout="sub/leak.env\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", mock_run)
    monkeypatch.chdir(sub_dir)

    result = runner.invoke(app, ["guard", "--pr-base", "origin/main"])
    assert result.exit_code == 0, result.output
    assert scan_paths
    assert len(scan_paths[0]) == 1
    assert (Path.cwd() / scan_paths[0][0]).resolve() == (repo_root / "sub" / "leak.env").resolve()


def test_guard_staged_without_git_fails(tmp_path: Path, monkeypatch):
    """--staged fails gracefully without git."""
    config = EnvdriftConfig()
    _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    # Mock subprocess.run to raise FileNotFoundError (git not installed)
    def mock_run(*args, **kwargs):
        raise FileNotFoundError("git not found")

    monkeypatch.setattr("subprocess.run", mock_run)

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["guard", "--staged"])
    assert result.exit_code == 1
    assert "git not found" in result.output.lower()


def test_guard_pr_base_with_no_changed_files(tmp_path: Path, monkeypatch):
    """--pr-base with no changed files exits cleanly."""
    import subprocess

    config = EnvdriftConfig()
    _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    # Mock git commands
    def mock_run(cmd, *args, **kwargs):
        if "fetch" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if "diff" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", mock_run)

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["guard", "--pr-base", "origin/main"])
    assert result.exit_code == 0
    assert "no changed files" in result.output.lower()


def test_guard_pr_base_scans_diff_files(tmp_path: Path, monkeypatch):
    """--pr-base scans files changed since base."""
    import subprocess

    config = EnvdriftConfig()
    scan_paths: list[list[Path]] = []
    dummy_result = _build_result([])

    class DummyScanner:
        def __init__(self, name: str):
            self.name = name

    class DummyEngine:
        def __init__(self, guard_config):
            self.scanners = [DummyScanner("native")]

        def get_scanner_info(self):
            return []

        def scan(self, paths, on_scanner_complete=None):
            scan_paths.append(paths)
            return dummy_result

    monkeypatch.setattr("envdrift.cli_commands.guard.load_config", lambda _p=None: config)
    monkeypatch.setattr("envdrift.cli_commands.guard.ScanEngine", DummyEngine)

    # Mock git commands
    def mock_run(cmd, *args, **kwargs):
        if "fetch" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if "diff" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="changed.py\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", mock_run)

    monkeypatch.chdir(tmp_path)
    Path("changed.py").write_text("# changed file")

    result = runner.invoke(app, ["guard", "--pr-base", "origin/main"])
    assert result.exit_code == 0
    assert scan_paths
    assert len(scan_paths[0]) == 1


def test_guard_pr_base_without_git_fails(tmp_path: Path, monkeypatch):
    """--pr-base fails gracefully without git."""
    config = EnvdriftConfig()
    _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    def mock_run(*args, **kwargs):
        raise FileNotFoundError("git not found")

    monkeypatch.setattr("subprocess.run", mock_run)

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["guard", "--pr-base", "origin/main"])
    assert result.exit_code == 1
    assert "git not found" in result.output.lower()


def test_guard_history_flag(tmp_path: Path, monkeypatch):
    """--history flag enables git history scanning."""
    config = EnvdriftConfig()
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(app, ["guard", str(tmp_path), "--history"])
    assert result.exit_code == 0
    assert created_configs
    assert created_configs[0].include_git_history is True


def test_guard_staged_timeout(tmp_path: Path, monkeypatch):
    """--staged handles git timeout gracefully."""
    import subprocess

    config = EnvdriftConfig()
    _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="git", timeout=10)

    monkeypatch.setattr("subprocess.run", mock_run)

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["guard", "--staged"])
    assert result.exit_code == 1
    assert "timed out" in result.output.lower()


def test_guard_pr_base_timeout(tmp_path: Path, monkeypatch):
    """--pr-base handles git timeout gracefully."""
    import subprocess

    config = EnvdriftConfig()
    _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="git", timeout=10)

    monkeypatch.setattr("subprocess.run", mock_run)

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["guard", "--pr-base", "origin/main"])
    assert result.exit_code == 1
    assert "timed out" in result.output.lower()


def test_guard_staged_files_not_exist(tmp_path: Path, monkeypatch):
    """--staged handles staged files that no longer exist on disk."""
    import subprocess

    config = EnvdriftConfig()
    _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    # Mock git to return files that don't exist
    def mock_run(cmd, *args, **kwargs):
        if "diff" in cmd and "--cached" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="deleted_file.py\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", mock_run)

    monkeypatch.chdir(tmp_path)
    # Don't create the file - it should show "no staged files"
    result = runner.invoke(app, ["guard", "--staged"])
    assert result.exit_code == 0
    assert "no staged files" in result.output.lower()


def test_guard_with_partial_encryption_config(tmp_path: Path, monkeypatch):
    """Guard passes allowed_clear_files and combined_files from partial_encryption config."""
    partial_encryption = PartialEncryptionConfig(
        enabled=True,
        environments=[
            PartialEncryptionEnvironmentConfig(
                name="production",
                clear_file=".env.production.clear",
                secret_file=".env.production.secret",
                combined_file=".env.production",
            ),
        ],
    )
    config = EnvdriftConfig(partial_encryption=partial_encryption)
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(app, ["guard", str(tmp_path)])
    assert result.exit_code == 0
    assert created_configs
    # Verify clear_file was passed to guard config
    assert created_configs[0].allowed_clear_files == [".env.production.clear"]
    # Verify combined_file was passed to guard config
    assert created_configs[0].combined_files == [".env.production"]


def test_guard_skip_clear_flag(tmp_path: Path, monkeypatch):
    """--skip-clear flag enables skipping .clear files."""
    config = EnvdriftConfig()
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(app, ["guard", str(tmp_path), "--skip-clear"])
    assert result.exit_code == 0
    assert created_configs
    assert created_configs[0].skip_clear_files is True


def test_guard_no_skip_clear_flag(tmp_path: Path, monkeypatch):
    """--no-skip-clear flag explicitly disables skipping .clear files."""
    config = EnvdriftConfig(guard=FileGuardConfig(skip_clear_files=True))
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(app, ["guard", str(tmp_path), "--no-skip-clear"])
    assert result.exit_code == 0
    assert created_configs
    assert created_configs[0].skip_clear_files is False


def test_guard_skip_clear_from_config(tmp_path: Path, monkeypatch):
    """skip_clear_files from config is passed to guard."""
    config = EnvdriftConfig(guard=FileGuardConfig(skip_clear_files=True))
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(app, ["guard", str(tmp_path)])
    assert result.exit_code == 0
    assert created_configs
    assert created_configs[0].skip_clear_files is True


def test_guard_skip_clear_cli_overrides_config(tmp_path: Path, monkeypatch):
    """CLI --skip-clear overrides config setting."""
    # Config has skip_clear_files=False
    config = EnvdriftConfig(guard=FileGuardConfig(skip_clear_files=False))
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    # CLI sets --skip-clear
    result = runner.invoke(app, ["guard", str(tmp_path), "--skip-clear"])
    assert result.exit_code == 0
    assert created_configs
    assert created_configs[0].skip_clear_files is True


def test_guard_skip_clear_default_is_false(tmp_path: Path, monkeypatch):
    """By default, skip_clear_files is False (scan .clear files)."""
    config = EnvdriftConfig()
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(app, ["guard", str(tmp_path)])
    assert result.exit_code == 0
    assert created_configs
    assert created_configs[0].skip_clear_files is False


def test_guard_ignore_rules_from_config(tmp_path: Path, monkeypatch):
    """ignore_rules from config is passed to guard."""
    config = EnvdriftConfig(
        guard=FileGuardConfig(
            ignore_rules={
                "ftp-password": ["**/*.json"],
                "django-secret-key": ["**/test_settings.py"],
            }
        )
    )
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(app, ["guard", str(tmp_path)])
    assert result.exit_code == 0
    assert created_configs
    assert created_configs[0].ignore_rules == {
        "ftp-password": ["**/*.json"],
        "django-secret-key": ["**/test_settings.py"],
    }


def test_guard_kingfisher_flag(tmp_path: Path, monkeypatch):
    """--kingfisher flag enables kingfisher scanner."""
    config = EnvdriftConfig()
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(app, ["guard", str(tmp_path), "--kingfisher"])
    assert result.exit_code == 0
    assert created_configs
    assert created_configs[0].use_kingfisher is True


def test_guard_no_kingfisher_flag(tmp_path: Path, monkeypatch):
    """--no-kingfisher flag disables kingfisher scanner."""
    config = EnvdriftConfig(guard=FileGuardConfig(scanners=["native", "kingfisher"]))
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(app, ["guard", str(tmp_path), "--no-kingfisher"])
    assert result.exit_code == 0
    assert created_configs
    assert created_configs[0].use_kingfisher is False


def test_guard_skip_duplicate_flag(tmp_path: Path, monkeypatch):
    """--skip-duplicate flag enables deduplication by secret value."""
    config = EnvdriftConfig()
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(app, ["guard", str(tmp_path), "--skip-duplicate"])
    assert result.exit_code == 0
    assert created_configs
    assert created_configs[0].skip_duplicate is True


def test_guard_no_skip_duplicate_flag(tmp_path: Path, monkeypatch):
    """--no-skip-duplicate flag disables deduplication by secret value."""
    config = EnvdriftConfig(guard=FileGuardConfig(skip_duplicate=True))
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(app, ["guard", str(tmp_path), "--no-skip-duplicate"])
    assert result.exit_code == 0
    assert created_configs
    assert created_configs[0].skip_duplicate is False


def test_guard_skip_duplicate_from_config(tmp_path: Path, monkeypatch):
    """skip_duplicate from config is used when CLI flag not provided."""
    config = EnvdriftConfig(guard=FileGuardConfig(skip_duplicate=True))
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(app, ["guard", str(tmp_path)])
    assert result.exit_code == 0
    assert created_configs
    assert created_configs[0].skip_duplicate is True


def test_guard_skip_gitignored_flag(tmp_path: Path, monkeypatch):
    """--skip-gitignored flag enables skipping gitignored files."""
    config = EnvdriftConfig()
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(app, ["guard", str(tmp_path), "--skip-gitignored"])
    assert result.exit_code == 0
    assert created_configs
    assert created_configs[0].skip_gitignored is True


def test_guard_no_skip_gitignored_flag(tmp_path: Path, monkeypatch):
    """--no-skip-gitignored flag disables skipping gitignored files."""
    config = EnvdriftConfig(guard=FileGuardConfig(skip_gitignored=True))
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(app, ["guard", str(tmp_path), "--no-skip-gitignored"])
    assert result.exit_code == 0
    assert created_configs
    assert created_configs[0].skip_gitignored is False


def test_guard_skip_gitignored_from_config(tmp_path: Path, monkeypatch):
    """skip_gitignored from config is used when CLI flag not provided."""
    config = EnvdriftConfig(guard=FileGuardConfig(skip_gitignored=True))
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(app, ["guard", str(tmp_path)])
    assert result.exit_code == 0
    assert created_configs
    assert created_configs[0].skip_gitignored is True


def test_guard_skip_gitignored_default_is_false(tmp_path: Path, monkeypatch):
    """By default, skip_gitignored is False (scan gitignored files)."""
    config = EnvdriftConfig()
    created_configs, _info_calls = _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    result = runner.invoke(app, ["guard", str(tmp_path)])
    assert result.exit_code == 0
    assert created_configs
    assert created_configs[0].skip_gitignored is False
