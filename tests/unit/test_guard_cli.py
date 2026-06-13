"""Tests for envdrift guard CLI command."""

from __future__ import annotations

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
        # History-capable so flag-plumbing tests that pass --history keep
        # exercising their target behavior (guard refuses --history when no
        # active scanner supports git history, #476).
        supports_git_history = True

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


def test_guard_survives_bad_guardian_idle_timeout(tmp_path: Path, monkeypatch):
    """A bad [guardian] idle_timeout must not crash 'envdrift guard' (#413).

    guard never reads the agent-only [guardian] section, so a typo there should
    not be fatal. This exercises the REAL load_config (only ScanEngine is
    stubbed); before the deferred-validation fix, load_config raised ValueError
    eagerly and guard died with a traceback.
    """
    dummy_result = _build_result([])

    class DummyEngine:
        def __init__(self, guard_config):
            self.scanners = []

        def get_scanner_info(self):
            return []

        def scan(self, paths, on_scanner_complete=None):
            return dummy_result

        def check_combined_files_security(self):
            return []

    # Deliberately NOT patching load_config — the real loader must tolerate this.
    monkeypatch.setattr("envdrift.cli_commands.guard.ScanEngine", DummyEngine)

    (tmp_path / "envdrift.toml").write_text("""
[guardian]
idle_timeout = "five minutes"
""")
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["guard", "."])

    assert result.exit_code == 0
    assert result.exception is None
    assert "guardian.idle_timeout" not in result.output


def test_guard_survives_bad_partial_encryption(tmp_path: Path, monkeypatch):
    """A bad [[partial_encryption.environments]] must not crash 'envdrift guard' (#413)."""
    dummy_result = _build_result([])

    class DummyEngine:
        def __init__(self, guard_config):
            self.scanners = []

        def get_scanner_info(self):
            return []

        def scan(self, paths, on_scanner_complete=None):
            return dummy_result

        def check_combined_files_security(self):
            return []

    monkeypatch.setattr("envdrift.cli_commands.guard.ScanEngine", DummyEngine)

    (tmp_path / "envdrift.toml").write_text(
        """
[partial_encryption]
enabled = true

[[partial_encryption.environments]]
name = "production"
secrets_only = true
# secrets_dir omitted — invalid, but guard must not care
""",
        # TOML is UTF-8 by spec; don't let the em-dash become cp1252 on Windows.
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["guard", "."])

    assert result.exit_code == 0
    assert result.exception is None
    assert "secrets_dir is required" not in result.output


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
    """Fetch failures in PR mode emit a warning even without --verbose (#476).

    The warning used to be verbose-gated (and swallowed entirely in machine
    modes), hiding the usual root cause of an unresolvable base ref.
    """
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

    result = runner.invoke(app, ["guard", "--pr-base", "origin/"])
    assert result.exit_code == 0
    assert "warning" in result.output.lower()
    assert "could not fetch" in result.output.lower()


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


def test_guard_ci_fail_on_low_blocks_on_low_only_findings(tmp_path: Path, monkeypatch):
    """#413 — ``--ci --fail-on low`` must fail CI on LOW-only findings.

    The CI exit code was seeded from ``result.exit_code`` (LOW -> 0) and the CI
    block could only *lower* it, never raise 0 -> nonzero. So a blocking LOW
    finding (``has_blocking`` True) still exited 0 and CI silently passed. The
    exit code is now derived from ``has_blocking``.
    """
    config = EnvdriftConfig()
    findings = [_make_finding(FindingSeverity.LOW)]
    created_configs, _info_calls = _patch_guard_dependencies(
        monkeypatch, config, _build_result(findings)
    )

    result = runner.invoke(app, ["guard", str(tmp_path), "--ci", "--fail-on", "low"])
    assert result.exit_code != 0, "a blocking LOW finding under --fail-on low must fail CI"
    assert created_configs


def test_guard_ci_fail_on_low_passes_on_info_only_findings(tmp_path: Path, monkeypatch):
    """INFO is unblockable by design (no --fail-on info) — LOW-only fix must not regress this."""
    config = EnvdriftConfig()
    findings = [_make_finding(FindingSeverity.INFO)]
    _patch_guard_dependencies(monkeypatch, config, _build_result(findings))

    result = runner.invoke(app, ["guard", str(tmp_path), "--ci", "--fail-on", "low"])
    assert result.exit_code == 0, "INFO-only findings must not block CI even under --fail-on low"


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


def test_guard_staged_scans_only_staged_files(tmp_path: Path, monkeypatch):
    """--staged scans the staged *index blobs*, not the working-tree copies (#476).

    The two staged names are materialized from ``git show :<path>`` into a
    temporary mirror; the scanner must receive exactly those mirror copies
    (carrying the index content), never the working-tree files.
    """
    import subprocess

    config = EnvdriftConfig()
    scan_paths: list[list[Path]] = []
    scanned_contents: dict[str, str] = {}
    dummy_result = _build_result([])

    class DummyScanner:
        supports_git_history = True

        def __init__(self, name: str):
            self.name = name

    class DummyEngine:
        def __init__(self, guard_config):
            self.scanners = [DummyScanner("native")]

        def get_scanner_info(self):
            return []

        def scan(self, paths, on_scanner_complete=None):
            scan_paths.append(paths)
            # The mirror is cleaned up right after the scan; capture now.
            scanned_contents.update({p.name: p.read_text(encoding="utf-8") for p in paths})
            return dummy_result

    monkeypatch.setattr("envdrift.cli_commands.guard.load_config", lambda _p=None: config)
    monkeypatch.setattr("envdrift.cli_commands.guard.ScanEngine", DummyEngine)

    # Mock git: diff --cached lists two staged files; show :<path> returns the
    # index blob (which differs from the working-tree copies on disk).
    def mock_run(cmd, *args, **kwargs):
        if "diff" in cmd and "--cached" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="file1.py\nfile2.env\n", stderr="")
        if "show" in cmd:
            rel = cmd[-1].removeprefix(":")
            return subprocess.CompletedProcess(
                cmd, 0, stdout=f"STAGED {rel}\n".encode(), stderr=b""
            )
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", mock_run)

    monkeypatch.chdir(tmp_path)
    # Working-tree copies hold DIFFERENT content than the staged blobs.
    Path("file1.py").write_text("# worktree only", encoding="utf-8")
    Path("file2.env").write_text("SECRET=worktree-only", encoding="utf-8")

    result = runner.invoke(app, ["guard", "--staged"])
    assert result.exit_code == 0, result.output
    assert scan_paths  # Verify scan was called
    assert len(scan_paths[0]) == 2  # Two staged files
    # The scanned files are mirror copies of the index blobs, not the worktree.
    assert all(tmp_path not in p.parents for p in scan_paths[0]), scan_paths[0]
    assert scanned_contents == {
        "file1.py": "STAGED file1.py\n",
        "file2.env": "STAGED file2.env\n",
    }


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
    (sub_dir / "leak.env").write_text("SECRET=worktree")

    show_cwds: list[str] = []

    def mock_run(cmd, *args, **kwargs):
        if "rev-parse" in cmd and "--show-toplevel" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout=f"{repo_root}\n", stderr="")
        if "diff" in cmd and "--cached" in cmd:
            # git reports the path relative to the repo root, not the cwd.
            return subprocess.CompletedProcess(cmd, 0, stdout="sub/leak.env\n", stderr="")
        if "show" in cmd:
            show_cwds.append(kwargs.get("cwd", ""))
            return subprocess.CompletedProcess(cmd, 0, stdout=b"SECRET=staged\n", stderr=b"")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", mock_run)

    # Run from the subdirectory: the file must still be found and scanned.
    monkeypatch.chdir(sub_dir)
    result = runner.invoke(app, ["guard", "--staged"])
    assert result.exit_code == 0, result.output
    assert "no staged files" not in result.output.lower(), result.output
    assert scan_paths
    # The repo-relative "sub/leak.env" is read from the index with cwd at the
    # git toplevel (not the subdir cwd) and mirrored under the same relative
    # layout, so the staged file is never dropped when run from a subdirectory.
    assert len(scan_paths[0]) == 1
    assert show_cwds == [str(repo_root)]
    assert scan_paths[0][0].parts[-2:] == ("sub", "leak.env")


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

    show_cwds: list[str] = []

    def mock_run(cmd, *args, **kwargs):
        if "rev-parse" in cmd and "--show-toplevel" in cmd:
            # Exercise the except (subprocess.TimeoutExpired, FileNotFoundError) path.
            raise FileNotFoundError("git not found")
        if "diff" in cmd and "--cached" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="leak.env\n", stderr="")
        if "show" in cmd:
            show_cwds.append(kwargs.get("cwd", ""))
            return subprocess.CompletedProcess(cmd, 0, stdout=b"SECRET=staged\n", stderr=b"")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", mock_run)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["guard", "--staged"])
    assert result.exit_code == 0, result.output
    assert scan_paths
    # The index blob is read with cwd falling back to the process cwd, and the
    # staged file is still mirrored and scanned (not dropped).
    assert [Path(c).resolve() for c in show_cwds] == [tmp_path.resolve()]
    assert len(scan_paths[0]) == 1
    assert scan_paths[0][0].name == "leak.env"


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


def test_guard_pr_base_unresolvable_ref_errors(tmp_path: Path, monkeypatch):
    """A failing ``git diff <base>...HEAD`` is an error, not "no changes" (#476).

    git exits 128 for an unknown revision; guard must exit 1 with an error that
    names the base ref instead of passing green with "No changed files to scan".
    """
    import subprocess

    config = EnvdriftConfig()
    _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    def mock_run(cmd, *args, **kwargs):
        if "diff" in cmd:
            return subprocess.CompletedProcess(
                cmd,
                128,
                stdout="",
                stderr="fatal: ambiguous argument 'nope...HEAD': unknown revision\n",
            )
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", mock_run)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["guard", "--pr-base", "nope"])
    out = " ".join(result.output.split())
    assert result.exit_code == 1, out
    assert "Error" in out, out
    assert "'nope'" in out, out
    assert "unknown revision" in out, out
    assert "no changed files" not in out.lower(), out


def test_guard_pr_base_unresolvable_ref_errors_json(tmp_path: Path, monkeypatch):
    """--json gets a clean ``{"error": ...}`` document for a bad --pr-base (#476)."""
    import json as json_module
    import subprocess

    config = EnvdriftConfig()
    _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    def mock_run(cmd, *args, **kwargs):
        if "diff" in cmd:
            return subprocess.CompletedProcess(
                cmd, 128, stdout="", stderr="fatal: bad revision 'nope...HEAD'\n"
            )
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", mock_run)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["guard", "--pr-base", "nope", "--json"])
    assert result.exit_code == 1
    payload = json_module.loads(result.stdout)
    assert "error" in payload
    assert "'nope'" in payload["error"]


def test_guard_staged_git_diff_failure_errors(tmp_path: Path, monkeypatch):
    """A failing ``git diff --cached`` is an error, not "no staged files" (#476)."""
    import subprocess

    config = EnvdriftConfig()
    _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    def mock_run(cmd, *args, **kwargs):
        if "diff" in cmd and "--cached" in cmd:
            return subprocess.CompletedProcess(
                cmd, 128, stdout="", stderr="fatal: not a git repository\n"
            )
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", mock_run)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["guard", "--staged"])
    out = " ".join(result.output.split())
    assert result.exit_code == 1, out
    assert "Error" in out, out
    assert "not a git repository" in out, out
    assert "no staged files" not in out.lower(), out


def test_guard_history_without_capable_scanner_errors(tmp_path: Path, monkeypatch):
    """--history with no history-capable scanner active exits 1 loudly (#476)."""
    config = EnvdriftConfig()
    _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    # Simulate a scanner set with no git-history support (e.g. --native-only).
    class NoHistoryScanner:
        supports_git_history = False
        name = "native"

    class NoHistoryEngine:
        def __init__(self, guard_config):
            self.scanners = [NoHistoryScanner()]

        def get_scanner_info(self):
            return []

        def scan(self, paths, on_scanner_complete=None):
            raise AssertionError("scan must not run when --history is unsatisfiable")

        def check_combined_files_security(self):
            return []

    monkeypatch.setattr("envdrift.cli_commands.guard.ScanEngine", NoHistoryEngine)

    result = runner.invoke(app, ["guard", str(tmp_path), "--history"])
    out = " ".join(result.output.split())
    assert result.exit_code == 1, out
    assert "history" in out.lower(), out
    assert "gitleaks" in out.lower(), out


def test_guard_history_without_capable_scanner_errors_json(tmp_path: Path, monkeypatch):
    """--history refusal stays a clean ``{"error": ...}`` under --json (#476)."""
    import json as json_module

    config = EnvdriftConfig()
    _patch_guard_dependencies(monkeypatch, config, _build_result([]))

    class NoHistoryScanner:
        supports_git_history = False
        name = "native"

    class NoHistoryEngine:
        def __init__(self, guard_config):
            self.scanners = [NoHistoryScanner()]

        def get_scanner_info(self):
            return []

        def scan(self, paths, on_scanner_complete=None):
            raise AssertionError("scan must not run when --history is unsatisfiable")

        def check_combined_files_security(self):
            return []

    monkeypatch.setattr("envdrift.cli_commands.guard.ScanEngine", NoHistoryEngine)

    result = runner.invoke(app, ["guard", str(tmp_path), "--history", "--json"])
    assert result.exit_code == 1
    payload = json_module.loads(result.stdout)
    assert "error" in payload
    assert "history" in payload["error"].lower()


def test_guard_staged_unreadable_blob_skipped_with_warning(tmp_path: Path, monkeypatch):
    """A staged entry whose index blob can't be read is skipped LOUDLY (#476).

    E.g. a submodule (gitlink) entry has no blob to content-scan: it must be
    skipped with a stderr warning while the readable entries are still scanned.
    """
    import subprocess

    scan_paths: list[list[Path]] = []
    _patch_dummy_engine(monkeypatch, EnvdriftConfig(), scan_paths)

    def mock_run(cmd, *args, **kwargs):
        if "diff" in cmd and "--cached" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="submodule\ngood.py\n", stderr="")
        if "show" in cmd:
            if cmd[-1] == ":submodule":
                return subprocess.CompletedProcess(
                    cmd, 128, stdout=b"", stderr=b"fatal: bad object\n"
                )
            return subprocess.CompletedProcess(cmd, 0, stdout=b"x = 1\n", stderr=b"")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", mock_run)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["guard", "--staged"])
    out = " ".join(result.output.split())
    assert result.exit_code == 0, out
    assert "warning" in out.lower(), out
    assert "submodule" in out, out
    assert scan_paths
    assert [p.name for p in scan_paths[0]] == ["good.py"]


def test_guard_staged_all_blobs_unreadable_errors(tmp_path: Path, monkeypatch):
    """--staged with NO readable index blob is an error, not a green pass (#476)."""
    import subprocess

    scan_paths: list[list[Path]] = []
    _patch_dummy_engine(monkeypatch, EnvdriftConfig(), scan_paths)

    def mock_run(cmd, *args, **kwargs):
        if "diff" in cmd and "--cached" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="submodule\n", stderr="")
        if "show" in cmd:
            return subprocess.CompletedProcess(cmd, 128, stdout=b"", stderr=b"fatal: bad object\n")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", mock_run)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["guard", "--staged"])
    out = " ".join(result.output.split())
    assert result.exit_code == 1, out
    assert "Error" in out, out
    assert "could not read any staged file content" in out, out
    assert not scan_paths


def test_git_index_mirror_failure_warns(tmp_path: Path, monkeypatch, capsys):
    """_git_index_mirror degrades to a stderr warning when git fails (#476).

    Failure only weakens git-state rules (committed-private-key); the content
    scan itself must proceed, so the helper warns instead of raising.
    """
    from envdrift.cli_commands.guard import _git_index_mirror

    def mock_run(cmd, *args, **kwargs):
        raise FileNotFoundError("git not found")

    monkeypatch.setattr("subprocess.run", mock_run)

    _git_index_mirror(tmp_path)  # must not raise

    err = capsys.readouterr().err
    assert "Warning" in err
    assert "staged-file mirror" in err


def test_remap_finding_paths_rewrites_mirror_paths(tmp_path: Path):
    """_remap_finding_paths rewrites mirror finding paths to display paths (#476)."""
    from envdrift.cli_commands.guard import _remap_finding_paths
    from envdrift.scanner.base import ScanResult

    mirror_file = tmp_path / "sub" / "app.env"
    mirror_file.parent.mkdir(parents=True)
    mirror_file.write_text("x=1\n", encoding="utf-8")
    display = Path("sub") / "app.env"

    finding = _make_finding(FindingSeverity.CRITICAL)
    mirror_finding = ScanFinding(
        file_path=mirror_file,
        line_number=1,
        rule_id="test-rule",
        rule_description="Test Rule",
        description="Test finding",
        severity=FindingSeverity.CRITICAL,
        scanner="native",
    )
    result = AggregatedScanResult(
        results=[ScanResult(scanner_name="native", findings=[mirror_finding, finding])],
        total_findings=2,
        unique_findings=[mirror_finding, finding],
        scanners_used=["native"],
        total_duration_ms=5,
    )

    remapped = _remap_finding_paths(result, {mirror_file.resolve(): display})

    assert remapped.unique_findings[0].file_path == display
    # A finding outside the mirror map is left untouched.
    assert remapped.unique_findings[1].file_path == finding.file_path
    assert remapped.results[0].findings[0].file_path == display
    assert remapped.total_findings == 2
    assert remapped.scanners_used == ["native"]


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
    """--staged scans a staged file even when it no longer exists on disk (#476).

    The commit ships the staged index blob, so a ``git add file; rm file``
    sequence must still be scanned. The old collection resolved staged names to
    worktree paths and dropped missing ones, reporting "no staged files" with
    exit 0 — a silent pass over a real about-to-be-committed secret.
    """
    import subprocess

    scan_paths: list[list[Path]] = []
    _patch_dummy_engine(monkeypatch, EnvdriftConfig(), scan_paths)

    # Mock git: the staged name has no working-tree copy, but its index blob
    # is still readable via ``git show :deleted_file.py``.
    def mock_run(cmd, *args, **kwargs):
        if "diff" in cmd and "--cached" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="deleted_file.py\n", stderr="")
        if "show" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout=b"SECRET=staged\n", stderr=b"")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", mock_run)

    monkeypatch.chdir(tmp_path)
    # The file is intentionally absent from the working tree.
    result = runner.invoke(app, ["guard", "--staged"])
    assert result.exit_code == 0, result.output
    assert "no staged files" not in result.output.lower(), result.output
    assert scan_paths
    assert len(scan_paths[0]) == 1
    assert scan_paths[0][0].name == "deleted_file.py"


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


def test_guard_json_and_sarif_warns_about_precedence(tmp_path: Path):
    """#31: passing --json and --sarif together is no longer silent.

    SARIF takes precedence; the precedence warning goes to stderr ONLY, so a
    --json/--sarif consumer still gets a clean, parseable document on stdout —
    that separation is the whole point of the fix.
    """
    import json

    env = tmp_path / ".env"
    env.write_text("API_KEY=sk-test123\n")

    result = runner.invoke(app, ["guard", str(env), "--native-only", "--json", "--sarif"])

    # The precedence warning lands on stderr.
    assert "--json is ignored" in result.stderr
    # stdout (the captured output with the stderr portion removed) is a clean,
    # parseable SARIF document — the warning must NOT leak into it.
    stdout = result.output.replace(result.stderr, "")
    assert "--json is ignored" not in stdout
    sarif = json.loads(stdout)
    assert "runs" in sarif
