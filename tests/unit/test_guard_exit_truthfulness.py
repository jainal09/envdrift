"""Regression tests for guard exit-code truthfulness and config validation (#478).

Six contracts, each reproduced on the base branch before the fix:

1. A selected scanner that RAN AND FAILED must not produce the all-clear exit 0
   (default, ``--ci``, ``--json``, and ``--sarif`` modes) — exit 5 instead.
2. Under ``--ci --fail-on`` the ``--json``/``--sarif`` ``exit_code`` /
   ``has_blocking_findings`` fields must agree with the actual process exit.
3. ``[guard] ignore_rules`` given as a TOML list (not the documented table) must
   fail fast at config load with a clean error, not a mid-scan TypeError.
4. A quoted-number ``entropy_threshold`` ("3.5") must be coerced (and garbage
   rejected) at config load instead of crashing the native scanner into a
   green false PASS.
5. ``check_entropy = false`` / ``--no-entropy`` must actually disable entropy
   detection (env files included); the env-file default stays on.
6. Operational errors (bad config, missing path, invalid ``--fail-on``) exit 6,
   distinct from the severity codes 1-4.

The config-validation and entropy tests drive the real ``load_config`` and the
real native scanner through the CLI; only the exit-code matrix tests stub the
engine's *result* (the behavior under test is the CLI's exit-code derivation).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.config import EnvdriftConfig
from envdrift.scanner.base import (
    AggregatedScanResult,
    FindingSeverity,
    ScanFinding,
    ScanResult,
)

runner = CliRunner()

# Prefix-less, non-keyword high-entropy value (built by concatenation so no
# realistic secret literal lands in the repo): only the entropy gate flags it.
_ENTROPY_SECRET = "Zx9Kq2Wm7" + "Lp4Rt8Nv6" + "Bs3Yd1Hf5Gj0Qc"
# 64 hex chars, the issue's repro token shape for the entropy crash.
_HEX_TOKEN = "a1b2c3d4" * 8


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


def _result(
    findings: list[ScanFinding],
    *,
    errors: dict[str, str] | None = None,
) -> AggregatedScanResult:
    """Build an aggregated result; ``errors`` maps scanner name -> error text."""
    results = [ScanResult(scanner_name="native", findings=findings, files_scanned=1)]
    for name, error in (errors or {}).items():
        results.append(ScanResult(scanner_name=name, error=error))
    return AggregatedScanResult(
        results=results,
        total_findings=len(findings),
        unique_findings=findings,
        scanners_used=[r.scanner_name for r in results],
        total_duration_ms=5,
    )


def _patch_engine(monkeypatch, result: AggregatedScanResult) -> None:
    """Stub the engine to return ``result`` (the input, not the logic under test)."""

    class DummyScanner:
        def __init__(self, name: str):
            self.name = name

    class DummyEngine:
        def __init__(self, _guard_config):
            self.scanners = [DummyScanner(r.scanner_name) for r in result.results]

        def get_scanner_info(self):
            return []

        def scan(self, _paths, on_scanner_complete=None):
            return result

        def check_combined_files_security(self):
            return []

    monkeypatch.setattr("envdrift.cli_commands.guard.load_config", lambda _p=None: EnvdriftConfig())
    monkeypatch.setattr("envdrift.cli_commands.guard.ScanEngine", DummyEngine)


# --- 1. scan errors must fail the run (exit 5) in every mode --------------------


class TestScanErrorExitCode:
    """#478: a scanner that ran and failed must never yield the all-clear exit 0."""

    def test_default_mode_exits_scan_error_code(self, tmp_path: Path, monkeypatch):
        _patch_engine(monkeypatch, _result([], errors={"talisman": "exit status 128"}))
        result = runner.invoke(app, ["guard", str(tmp_path)])
        assert result.exit_code == 5, (
            f"scanner error must surface as exit 5, got {result.exit_code}\n{result.output}"
        )

    def test_ci_mode_exits_scan_error_code(self, tmp_path: Path, monkeypatch):
        _patch_engine(monkeypatch, _result([], errors={"talisman": "exit status 128"}))
        result = runner.invoke(app, ["guard", str(tmp_path), "--ci"])
        assert result.exit_code == 5, (
            f"--ci with a scanner error must fail closed (exit 5), got {result.exit_code}"
        )

    def test_json_mode_exit_code_field_matches_process(self, tmp_path: Path, monkeypatch):
        _patch_engine(monkeypatch, _result([], errors={"talisman": "exit status 128"}))
        result = runner.invoke(app, ["guard", str(tmp_path), "--json"])
        assert result.exit_code == 5
        payload = json.loads(result.stdout)
        assert payload["exit_code"] == 5
        assert payload["has_blocking_findings"] is False
        errors = [r["error"] for r in payload["scanner_results"] if r["error"]]
        assert errors, "the scanner error must be carried in scanner_results"

    def test_sarif_mode_reports_failed_invocation(self, tmp_path: Path, monkeypatch):
        _patch_engine(monkeypatch, _result([], errors={"talisman": "exit status 128"}))
        result = runner.invoke(app, ["guard", str(tmp_path), "--sarif"])
        assert result.exit_code == 5
        payload = json.loads(result.stdout)
        invocation = payload["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is False
        assert invocation["exitCode"] == 5

    def test_rich_mode_does_not_print_green_all_clear(self, tmp_path: Path, monkeypatch):
        _patch_engine(monkeypatch, _result([], errors={"talisman": "exit status 128"}))
        result = runner.invoke(app, ["guard", str(tmp_path)])
        normalized = " ".join(result.output.split())
        assert "No secrets or policy violations detected" not in normalized, (
            "an errored scan must not be presented as a clean pass"
        )

    def test_blocking_findings_take_precedence_over_scan_error(self, tmp_path: Path, monkeypatch):
        """Severity codes stay distinguishable when findings AND errors coexist."""
        _patch_engine(
            monkeypatch,
            _result(
                [_make_finding(FindingSeverity.CRITICAL)],
                errors={"talisman": "exit status 128"},
            ),
        )
        result = runner.invoke(app, ["guard", str(tmp_path)])
        assert result.exit_code == 1

    def test_ci_below_threshold_findings_with_error_fail_closed(self, tmp_path: Path, monkeypatch):
        """A would-pass thresholded run still fails closed when a scanner errored."""
        _patch_engine(
            monkeypatch,
            _result(
                [_make_finding(FindingSeverity.HIGH)],
                errors={"talisman": "exit status 128"},
            ),
        )
        result = runner.invoke(app, ["guard", str(tmp_path), "--ci", "--fail-on", "critical"])
        assert result.exit_code == 5


# --- 2. JSON/SARIF fields agree with the process exit under --ci --fail-on ------


class TestMachineFieldsMatchProcessExit:
    """#478: one source of truth — fields and process exit must never contradict."""

    def test_json_fields_zeroed_when_threshold_passes(self, tmp_path: Path, monkeypatch):
        """HIGH finding under --fail-on critical: process passes, JSON must agree."""
        _patch_engine(monkeypatch, _result([_make_finding(FindingSeverity.HIGH)]))
        result = runner.invoke(
            app, ["guard", str(tmp_path), "--json", "--ci", "--fail-on", "critical"]
        )
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["exit_code"] == 0, "JSON exit_code must match the process exit"
        assert payload["has_blocking_findings"] is False

    def test_json_blocking_true_when_medium_blocks_ci(self, tmp_path: Path, monkeypatch):
        """MEDIUM finding under --fail-on medium: CI fails (3), JSON must say blocking."""
        _patch_engine(monkeypatch, _result([_make_finding(FindingSeverity.MEDIUM)]))
        result = runner.invoke(
            app, ["guard", str(tmp_path), "--json", "--ci", "--fail-on", "medium"]
        )
        assert result.exit_code == 3
        payload = json.loads(result.stdout)
        assert payload["exit_code"] == 3
        assert payload["has_blocking_findings"] is True, (
            "a finding that fails CI must be reported as blocking"
        )

    def test_sarif_invocation_exit_code_matches_process(self, tmp_path: Path, monkeypatch):
        _patch_engine(monkeypatch, _result([_make_finding(FindingSeverity.HIGH)]))
        result = runner.invoke(
            app, ["guard", str(tmp_path), "--sarif", "--ci", "--fail-on", "critical"]
        )
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        invocation = payload["runs"][0]["invocations"][0]
        assert invocation["exitCode"] == 0
        assert invocation["executionSuccessful"] is True

    def test_json_exit_code_matches_in_non_ci_mode(self, tmp_path: Path, monkeypatch):
        _patch_engine(monkeypatch, _result([_make_finding(FindingSeverity.HIGH)]))
        result = runner.invoke(app, ["guard", str(tmp_path), "--json"])
        assert result.exit_code == 2
        payload = json.loads(result.stdout)
        assert payload["exit_code"] == 2
        assert payload["has_blocking_findings"] is True


# --- 3. ignore_rules as a TOML list fails fast with a clean config error --------


class TestIgnoreRulesShapeValidation:
    """#478: wrong-typed ignore_rules must be a clean config error, not a crash."""

    @staticmethod
    def _write_fixture(tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("API_KEY=plainvalue123\n", encoding="utf-8")
        (tmp_path / "envdrift.toml").write_text(
            '[guard]\nignore_rules = ["unencrypted-env-file"]\n', encoding="utf-8"
        )

    def test_list_shape_rejected_with_clean_json_error(self, tmp_path: Path, monkeypatch):
        self._write_fixture(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["guard", "--json", "--native-only", "--no-auto-install", "."])
        assert result.exit_code == 6, (
            f"expected operational-error exit 6, got {result.exit_code}\n{result.output}"
        )
        payload = json.loads(result.stdout)  # stdout must be a clean JSON document
        assert "ignore_rules" in payload["error"]
        assert "Traceback" not in result.output

    def test_list_shape_rejected_in_human_mode(self, tmp_path: Path, monkeypatch):
        self._write_fixture(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["guard", "--native-only", "--no-auto-install", "."])
        assert result.exit_code == 6
        normalized = " ".join(result.output.split())
        assert "ignore_rules" in normalized
        assert "Traceback" not in result.output

    def test_string_pattern_value_is_coerced_to_list(self, tmp_path: Path, monkeypatch):
        """A single-string pattern value is accepted (coerced to a one-item list)."""
        (tmp_path / ".env").write_text("API_KEY=plainvalue123\n", encoding="utf-8")
        (tmp_path / "envdrift.toml").write_text(
            '[guard.ignore_rules]\n"unencrypted-env-file" = "**/.env"\n', encoding="utf-8"
        )
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["guard", "--json", "--native-only", "--no-auto-install", "."])
        payload = json.loads(result.stdout)
        rule_ids = {f["rule_id"] for f in payload["findings"]}
        assert "unencrypted-env-file" not in rule_ids
        assert result.exit_code == 0


# --- 4. entropy_threshold is validated/coerced at config load -------------------


class TestEntropyThresholdValidation:
    """#478: a config typo must not silently disable the security gate."""

    def test_quoted_number_is_coerced_and_scan_completes(self, tmp_path: Path, monkeypatch):
        (tmp_path / ".env").write_text(f"TOKEN={_HEX_TOKEN}\n", encoding="utf-8")
        (tmp_path / "envdrift.toml").write_text(
            '[guard]\nscanners = ["native"]\ncheck_entropy = true\nentropy_threshold = "3.5"\n',
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["guard", "--json", "--no-auto-install", "."])
        payload = json.loads(result.stdout)
        native_errors = [r["error"] for r in payload["scanner_results"] if r["error"]]
        assert native_errors == [], f"native scanner must not crash: {native_errors}"
        rule_ids = {f["rule_id"] for f in payload["findings"]}
        assert "unencrypted-env-file" in rule_ids, (
            "the HIGH unencrypted-env-file finding must survive a quoted threshold"
        )
        assert result.exit_code != 0, "a run with findings must not exit 0"

    def test_non_numeric_threshold_is_clean_config_error(self, tmp_path: Path, monkeypatch):
        (tmp_path / ".env").write_text(f"TOKEN={_HEX_TOKEN}\n", encoding="utf-8")
        (tmp_path / "envdrift.toml").write_text(
            '[guard]\nscanners = ["native"]\ncheck_entropy = true\n'
            'entropy_threshold = "not-a-number"\n',
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["guard", "--json", "--no-auto-install", "."])
        assert result.exit_code == 6, (
            f"expected operational-error exit 6, got {result.exit_code}\n{result.output}"
        )
        payload = json.loads(result.stdout)
        assert "entropy_threshold" in payload["error"]
        assert "Traceback" not in result.output

    @pytest.mark.parametrize(
        "raw",
        ['"nan"', '"inf"', '"-inf"', '"1e400"', "nan", "inf"],
        ids=["quoted-nan", "quoted-inf", "quoted-neg-inf", "quoted-1e400", "bare-nan", "bare-inf"],
    )
    def test_non_finite_threshold_is_clean_config_error(
        self, tmp_path: Path, monkeypatch, raw: str
    ):
        """#478 review: nan/inf parse as floats but make every ``entropy >=
        threshold`` comparison False, silently disabling the entropy gate."""
        (tmp_path / ".env").write_text(f"TOKEN={_HEX_TOKEN}\n", encoding="utf-8")
        (tmp_path / "envdrift.toml").write_text(
            f'[guard]\nscanners = ["native"]\ncheck_entropy = true\nentropy_threshold = {raw}\n',
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["guard", "--json", "--no-auto-install", "."])
        assert result.exit_code == 6, (
            f"expected operational-error exit 6, got {result.exit_code}\n{result.output}"
        )
        payload = json.loads(result.stdout)
        assert "entropy_threshold" in payload["error"]
        assert "finite" in payload["error"]


# --- 4b. fail_on_severity is type-validated at config load ----------------------


class TestFailOnSeverityValidation:
    """#478 review: a non-string ``fail_on_severity`` crashed past the CLI's
    ``except ValueError``.

    ``fail_on_severity = 123`` raised ``AttributeError: 'int' object has no
    attribute 'lower'`` — a Rich traceback, empty ``--json`` stdout, and exit 1
    colliding with critical's code: the exact bug triad this feature eliminates
    for the other guard knobs.
    """

    def test_non_string_fail_on_severity_is_clean_json_error(self, tmp_path: Path, monkeypatch):
        (tmp_path / ".env").write_text("API_KEY=plainvalue123\n", encoding="utf-8")
        (tmp_path / "envdrift.toml").write_text(
            "[guard]\nfail_on_severity = 123\n", encoding="utf-8"
        )
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["guard", "--json", "--native-only", "--no-auto-install", "."])
        assert result.exit_code == 6, (
            f"expected operational-error exit 6, got {result.exit_code}\n{result.output}"
        )
        payload = json.loads(result.stdout)  # stdout must be a clean JSON document
        assert "fail_on_severity" in payload["error"]
        assert "Traceback" not in result.output

    def test_non_string_fail_on_severity_human_mode(self, tmp_path: Path, monkeypatch):
        (tmp_path / "envdrift.toml").write_text(
            "[guard]\nfail_on_severity = 123\n", encoding="utf-8"
        )
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["guard", "--native-only", "--no-auto-install", "."])
        assert result.exit_code == 6
        assert "fail_on_severity" in " ".join(result.output.split())
        assert "Traceback" not in result.output


# --- 5. check_entropy=false / --no-entropy actually disable entropy -------------


class TestEntropyKnobHonored:
    """#478: the documented entropy knob must actually control entropy detection."""

    @staticmethod
    def _entropy_rules(result) -> set[str]:
        payload = json.loads(result.stdout)
        return {f["rule_id"] for f in payload["findings"]}

    def test_config_false_disables_entropy_on_env_files(self, tmp_path: Path, monkeypatch):
        (tmp_path / ".env").write_text(f"SOMEVALUE={_ENTROPY_SECRET}\n", encoding="utf-8")
        (tmp_path / "envdrift.toml").write_text(
            "[guard]\ncheck_entropy = false\n", encoding="utf-8"
        )
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["guard", "--json", "--native-only", "--no-auto-install", "."])
        rule_ids = self._entropy_rules(result)
        assert "high-entropy-string" not in rule_ids, (
            "check_entropy = false must disable entropy detection"
        )
        # The env-file policy finding is unaffected by the entropy knob.
        assert "unencrypted-env-file" in rule_ids

    def test_no_entropy_flag_overrides_config_true(self, tmp_path: Path, monkeypatch):
        (tmp_path / ".env").write_text(f"SOMEVALUE={_ENTROPY_SECRET}\n", encoding="utf-8")
        (tmp_path / "envdrift.toml").write_text("[guard]\ncheck_entropy = true\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(
            app,
            ["guard", "--json", "--native-only", "--no-auto-install", "--no-entropy", "."],
        )
        rule_ids = self._entropy_rules(result)
        assert "high-entropy-string" not in rule_ids, (
            "--no-entropy must override check_entropy = true"
        )

    def test_default_keeps_entropy_on_for_env_files(self, tmp_path: Path, monkeypatch):
        """No config, no flag: env files keep entropy coverage (#477 gap 3)."""
        (tmp_path / ".env").write_text(f"SOMEVALUE={_ENTROPY_SECRET}\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["guard", "--json", "--native-only", "--no-auto-install", "."])
        rule_ids = self._entropy_rules(result)
        assert "high-entropy-string" in rule_ids, (
            "the env-file entropy default must stay on when the knob is unset"
        )


# --- 6. operational errors exit 6, distinct from severity codes -----------------


class TestOperationalErrorExitCode:
    """#478: an exit-code-only pipeline must tell config errors from criticals."""

    def test_missing_config_exits_operational_code(self, tmp_path: Path):
        missing = tmp_path / "nope.toml"
        target = tmp_path / "a.txt"
        target.write_text("HELLO=world\n", encoding="utf-8")
        result = runner.invoke(
            app,
            ["guard", "--native-only", "--json", "--config", str(missing), str(target)],
        )
        assert result.exit_code == 6, (
            f"a config-load failure must exit 6 (not critical's 1), got {result.exit_code}"
        )
        payload = json.loads(result.stdout)
        assert "Could not load config" in payload["error"]

    def test_path_not_found_exits_operational_code(self, tmp_path: Path):
        missing = tmp_path / "does-not-exist"
        result = runner.invoke(app, ["guard", "--native-only", "--json", str(missing)])
        assert result.exit_code == 6
        payload = json.loads(result.stdout)
        assert "Path not found" in payload["error"]

    def test_invalid_fail_on_exits_operational_code(self, tmp_path: Path, monkeypatch):
        _patch_engine(monkeypatch, _result([]))
        result = runner.invoke(app, ["guard", str(tmp_path), "--fail-on", "bogus"])
        assert result.exit_code == 6
        assert "invalid severity" in result.output.lower()

    def test_sarif_error_doc_carries_operational_exit_code(self, tmp_path: Path):
        missing = tmp_path / "does-not-exist"
        result = runner.invoke(app, ["guard", "--native-only", "--sarif", str(missing)])
        assert result.exit_code == 6
        payload = json.loads(result.stdout)
        invocation = payload["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is False
        assert invocation["exitCode"] == 6


# --- 6b. git/env_file failures keep --json/--sarif stdout parseable --------------


class TestGitDiscoveryErrorMachineOutput:
    """#478 review: git timeout/not-found under ``--staged``/``--pr-base`` (and an
    invalid ``env_file`` mapping) exited 6 via prose on stdout, so ``--json``/
    ``--sarif`` consumers got a parse failure instead of an error document."""

    def test_git_not_found_staged_json_is_parseable(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        # A real missing-git environment: nothing on PATH resolves ``git``.
        monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
        result = runner.invoke(app, ["guard", "--staged", "--json", "--native-only"])
        assert result.exit_code == 6
        payload = json.loads(result.stdout)  # stdout must be a clean JSON document
        assert "Git not found" in payload["error"]

    def test_git_not_found_staged_sarif_is_parseable(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
        result = runner.invoke(app, ["guard", "--staged", "--sarif", "--native-only"])
        assert result.exit_code == 6
        invocation = json.loads(result.stdout)["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is False
        assert invocation["exitCode"] == 6

    def test_git_timeout_pr_base_json_is_parseable(self, tmp_path: Path, monkeypatch):
        import subprocess

        def raise_timeout(cmd, *_args, **kwargs):
            # Inject the timeout (test input); the behavior under test is the
            # CLI's error emission, not git itself.
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get("timeout", 10))

        monkeypatch.setattr(subprocess, "run", raise_timeout)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(
            app, ["guard", "--pr-base", "origin/main", "--json", "--native-only"]
        )
        assert result.exit_code == 6
        payload = json.loads(result.stdout)
        assert "timed out" in payload["error"]

    def test_invalid_env_file_mapping_json_is_parseable(self, tmp_path: Path, monkeypatch):
        (tmp_path / "envdrift.toml").write_text(
            "[[vault.sync.mappings]]\n"
            'secret_name = "s"\n'
            'folder_path = "."\n'
            'env_file = "../escape.env"\n',
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["guard", "--json", "--native-only", "--no-auto-install", "."])
        assert result.exit_code == 6
        payload = json.loads(result.stdout)
        assert "Invalid env_file" in payload["error"]


# --- 7. missing binary: default-set scanner skips, explicit selection fails -----


class TestDefaultScannerUnavailableSkips:
    """#641: gitleaks in the DEFAULT set with a missing binary and auto-install
    disabled must SKIP with a visible warning (exit unaffected); the same
    scanner selected EXPLICITLY (CLI flag or a config ``scanners`` list) keeps
    failing closed with the scan-incomplete exit 5.

    These drive the real engine and the real native scanner; only the binary
    discovery environment (``PATH`` / ``VIRTUAL_ENV``) is pointed away from any
    gitleaks binary, so the missing-binary condition is real, not mocked.
    """

    @staticmethod
    def _hide_gitleaks(monkeypatch, tmp_path: Path) -> Path:
        """Make gitleaks genuinely undiscoverable, return a clean scan dir."""
        empty_bin = tmp_path / "empty-bin"
        empty_bin.mkdir()
        monkeypatch.setenv("PATH", str(empty_bin))
        monkeypatch.setenv("VIRTUAL_ENV", str(tmp_path / "no-venv"))
        monkeypatch.chdir(tmp_path)
        scan_dir = tmp_path / "clean"
        scan_dir.mkdir()
        (scan_dir / "note.txt").write_text("nothing secret here\n", encoding="utf-8")
        return scan_dir

    def test_default_set_missing_binary_skips_and_exits_zero(self, tmp_path: Path, monkeypatch):
        scan_dir = self._hide_gitleaks(monkeypatch, tmp_path)
        result = runner.invoke(app, ["guard", "--no-auto-install", "--json", str(scan_dir)])
        assert result.exit_code == 0, (
            f"a skipped default scanner must not fail the run, got {result.exit_code}\n"
            f"{result.output}"
        )
        payload = json.loads(result.stdout)
        assert payload["exit_code"] == 0
        assert payload["has_blocking_findings"] is False
        gitleaks = next(r for r in payload["scanner_results"] if r["name"] == "gitleaks")
        assert gitleaks["skipped"] is True
        assert gitleaks["error"] is None
        assert gitleaks["skip_reason"] is not None
        assert "not installed" in gitleaks["skip_reason"]
        assert "gitleaks" not in payload["scanners"], "a skipped scanner did not run"
        assert "skipping this default-selection scanner" in result.stderr, (
            "the skip must be visible on stderr in machine modes"
        )

    def test_default_set_missing_binary_skip_visible_in_human_output(
        self, tmp_path: Path, monkeypatch
    ):
        scan_dir = self._hide_gitleaks(monkeypatch, tmp_path)
        result = runner.invoke(app, ["guard", "--no-auto-install", str(scan_dir)])
        assert result.exit_code == 0
        normalized = " ".join(result.output.split())
        assert "Scanners Skipped" in normalized
        assert "gitleaks" in normalized
        assert "No secrets or policy violations detected" in normalized

    def test_explicit_flag_missing_binary_fails_closed(self, tmp_path: Path, monkeypatch):
        scan_dir = self._hide_gitleaks(monkeypatch, tmp_path)
        result = runner.invoke(
            app, ["guard", "--gitleaks", "--no-auto-install", "--json", str(scan_dir)]
        )
        assert result.exit_code == 5, (
            f"an explicit scanner with a missing binary must exit 5, got {result.exit_code}\n"
            f"{result.output}"
        )
        payload = json.loads(result.stdout)
        assert payload["exit_code"] == 5
        gitleaks = next(r for r in payload["scanner_results"] if r["name"] == "gitleaks")
        assert gitleaks["skipped"] is False
        assert gitleaks["error"], "the explicit scanner's failure must be recorded"

    def test_config_listed_scanner_missing_binary_fails_closed(self, tmp_path: Path, monkeypatch):
        """A ``scanners`` list written in envdrift.toml is an explicit selection."""
        scan_dir = self._hide_gitleaks(monkeypatch, tmp_path)
        (tmp_path / "envdrift.toml").write_text(
            '[guard]\nscanners = ["native", "gitleaks"]\n', encoding="utf-8"
        )
        result = runner.invoke(app, ["guard", "--no-auto-install", "--json", str(scan_dir)])
        assert result.exit_code == 5, (
            f"a config-listed scanner with a missing binary must exit 5, got {result.exit_code}\n"
            f"{result.output}"
        )
        payload = json.loads(result.stdout)
        gitleaks = next(r for r in payload["scanner_results"] if r["name"] == "gitleaks")
        assert gitleaks["skipped"] is False
        assert gitleaks["error"]


# --- pure exit-semantics unit coverage on the single source of truth ------------


class TestAggregatedResultExitSemantics:
    """Unit coverage for the one-source-of-truth exit-code computation."""

    def test_error_only_result_exit_code_is_scan_error(self):
        result = _result([], errors={"talisman": "exit status 128"})
        assert result.exit_code == 5
        assert result.has_errors is True
        assert result.has_blocking_findings is False

    def test_empty_string_error_still_fails_the_run(self):
        """#478 review: has_errors follows the ScanResult.success contract.

        A backend that fails with an EMPTY error string used to slip through
        the truthiness check (``any(r.error ...)``) into the all-clear exit 0.
        """
        result = _result([], errors={"talisman": ""})
        assert result.has_errors is True
        assert result.exit_code == 5

    def test_empty_string_error_sarif_carries_a_notification(self):
        """#478 review (greptile P1): an empty-error failure flips
        executionSuccessful to false, so the SARIF notifications list must still
        explain it — the truthiness filter used to drop the empty-error entry,
        leaving 'execution failed' with no reason."""
        from envdrift.scanner.output import format_sarif

        result = _result([], errors={"talisman": ""})
        invocation = json.loads(format_sarif(result))["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is False
        notifications = invocation["toolExecutionNotifications"]
        assert any(n["message"]["text"].startswith("talisman:") for n in notifications), (
            "an empty-error scan failure must still emit a SARIF notification"
        )

    def test_clean_empty_result_still_exits_zero(self):
        result = _result([])
        assert result.exit_code == 0
        assert result.has_errors is False

    @pytest.mark.parametrize(
        ("severity", "code"),
        [
            (FindingSeverity.CRITICAL, 1),
            (FindingSeverity.HIGH, 2),
            (FindingSeverity.MEDIUM, 3),
            (FindingSeverity.LOW, 4),
        ],
    )
    def test_severity_codes_unchanged(self, severity: FindingSeverity, code: int):
        assert _result([_make_finding(severity)]).exit_code == code

    def test_effective_exit_code_applies_threshold(self):
        result = _result([_make_finding(FindingSeverity.HIGH)])
        assert result.effective_exit_code(FindingSeverity.CRITICAL) == 0
        assert result.effective_exit_code(FindingSeverity.HIGH) == 2
        assert result.effective_exit_code(FindingSeverity.LOW) == 2

    def test_effective_exit_code_fails_closed_below_threshold_with_errors(self):
        result = _result(
            [_make_finding(FindingSeverity.HIGH)],
            errors={"talisman": "exit status 128"},
        )
        assert result.effective_exit_code(FindingSeverity.CRITICAL) == 5
        assert result.effective_exit_code(FindingSeverity.HIGH) == 2

    def test_info_findings_never_block_even_with_low_threshold(self):
        result = _result([_make_finding(FindingSeverity.INFO)])
        assert result.effective_exit_code(FindingSeverity.LOW) == 0
        assert result.exit_code == 0
