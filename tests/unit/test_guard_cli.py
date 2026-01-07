"""Tests for envdrift guard CLI command."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.config import EnvdriftConfig, GuardConfig as FileGuardConfig
from envdrift.scanner.base import AggregatedScanResult, FindingSeverity, ScanFinding

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
    created_configs: list[object] = []
    info_calls: list[bool] = []

    class DummyEngine:
        def __init__(self, guard_config):
            created_configs.append(guard_config)

        def get_scanner_info(self):
            info_calls.append(True)
            return [{"name": "native", "installed": True, "version": "1.0.0"}]

        def scan(self, _paths):
            return result

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
    created_configs, _info_calls = _patch_guard_dependencies(
        monkeypatch, config, _build_result([])
    )

    result = runner.invoke(app, ["guard", str(tmp_path)])
    assert result.exit_code == 0

    guard_config = created_configs[0]
    assert guard_config.use_gitleaks is True
    assert guard_config.use_trufflehog is True
    assert guard_config.use_detect_secrets is True
    assert guard_config.include_git_history is True
    assert guard_config.check_entropy is True
    assert guard_config.ignore_paths == ["vendor/**"]


def test_guard_config_can_disable_gitleaks(tmp_path: Path, monkeypatch):
    """Config scanners can disable gitleaks when not listed."""
    config = EnvdriftConfig(guard=FileGuardConfig(scanners=["native"]))
    created_configs, _info_calls = _patch_guard_dependencies(
        monkeypatch, config, _build_result([])
    )

    result = runner.invoke(app, ["guard", str(tmp_path)])
    assert result.exit_code == 0

    guard_config = created_configs[0]
    assert guard_config.use_gitleaks is False


def test_guard_cli_overrides_config_scanners(tmp_path: Path, monkeypatch):
    """CLI flags override config scanner selection."""
    config = EnvdriftConfig(
        guard=FileGuardConfig(
            scanners=["native", "gitleaks", "trufflehog", "detect-secrets"]
        )
    )
    created_configs, _info_calls = _patch_guard_dependencies(
        monkeypatch, config, _build_result([])
    )

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
    created_configs, _info_calls = _patch_guard_dependencies(
        monkeypatch, config, _build_result([])
    )

    result = runner.invoke(app, ["guard", str(tmp_path), "--gitleaks"])
    assert result.exit_code == 0

    guard_config = created_configs[0]
    assert guard_config.use_gitleaks is True


def test_guard_native_only_disables_external_scanners(tmp_path: Path, monkeypatch):
    """--native-only disables external scanners."""
    config = EnvdriftConfig(
        guard=FileGuardConfig(
            scanners=["native", "gitleaks", "trufflehog", "detect-secrets"]
        )
    )
    created_configs, _info_calls = _patch_guard_dependencies(
        monkeypatch, config, _build_result([])
    )

    result = runner.invoke(app, ["guard", str(tmp_path), "--native-only"])
    assert result.exit_code == 0

    guard_config = created_configs[0]
    assert guard_config.use_gitleaks is False
    assert guard_config.use_trufflehog is False
    assert guard_config.use_detect_secrets is False


def test_guard_history_and_entropy_flags_override_config(tmp_path: Path, monkeypatch):
    """--history and --entropy override config defaults."""
    config = EnvdriftConfig(
        guard=FileGuardConfig(include_history=False, check_entropy=False)
    )
    created_configs, _info_calls = _patch_guard_dependencies(
        monkeypatch, config, _build_result([])
    )

    result = runner.invoke(app, ["guard", str(tmp_path), "--history", "--entropy"])
    assert result.exit_code == 0

    guard_config = created_configs[0]
    assert guard_config.include_git_history is True
    assert guard_config.check_entropy is True


def test_guard_verbose_prints_scanner_info(tmp_path: Path, monkeypatch):
    """--verbose triggers scanner info output."""
    config = EnvdriftConfig()
    created_configs, info_calls = _patch_guard_dependencies(
        monkeypatch, config, _build_result([])
    )

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


def test_guard_json_output(tmp_path: Path, monkeypatch):
    """--json outputs serialized results."""
    config = EnvdriftConfig()
    created_configs, _info_calls = _patch_guard_dependencies(
        monkeypatch, config, _build_result([])
    )
    monkeypatch.setattr("envdrift.cli_commands.guard.format_json", lambda _r: "JSON-OUT")

    result = runner.invoke(app, ["guard", str(tmp_path), "--json"])
    assert result.exit_code == 0
    assert "JSON-OUT" in result.output
    assert created_configs


def test_guard_sarif_output(tmp_path: Path, monkeypatch):
    """--sarif outputs SARIF content."""
    config = EnvdriftConfig()
    created_configs, _info_calls = _patch_guard_dependencies(
        monkeypatch, config, _build_result([])
    )
    monkeypatch.setattr("envdrift.cli_commands.guard.format_sarif", lambda _r: "SARIF-OUT")

    result = runner.invoke(app, ["guard", str(tmp_path), "--sarif"])
    assert result.exit_code == 0
    assert "SARIF-OUT" in result.output
    assert created_configs
