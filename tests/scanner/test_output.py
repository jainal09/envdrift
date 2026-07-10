"""Tests for scanner output formatters."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from rich.console import Console

from envdrift.scanner.base import (
    AggregatedScanResult,
    FindingSeverity,
    ScanFinding,
    ScanResult,
)
from envdrift.scanner.output import (
    format_json,
    format_rich,
    format_sarif,
    format_sarif_error,
)


class TestJsonOutput:
    """Tests for JSON output formatter."""

    @pytest.fixture
    def sample_result(self) -> AggregatedScanResult:
        """Create a sample result for testing."""
        findings = [
            ScanFinding(
                file_path=Path(".env"),
                rule_id="unencrypted-env-file",
                rule_description="Unencrypted .env File",
                description="File is not encrypted",
                severity=FindingSeverity.HIGH,
                scanner="native",
            ),
            ScanFinding(
                file_path=Path("config.py"),
                line_number=10,
                rule_id="aws-access-key-id",
                rule_description="AWS Access Key ID",
                description="AWS key detected",
                severity=FindingSeverity.CRITICAL,
                secret_preview="AKIA****MPLE",
                scanner="native",
            ),
        ]
        return AggregatedScanResult(
            results=[
                ScanResult(
                    scanner_name="native",
                    findings=findings,
                    files_scanned=5,
                    duration_ms=100,
                )
            ],
            total_findings=2,
            unique_findings=findings,
            scanners_used=["native"],
            total_duration_ms=100,
        )

    def test_json_output_is_valid_json(self, sample_result: AggregatedScanResult):
        """Test that output is valid JSON."""
        output = format_json(sample_result)
        data = json.loads(output)  # Should not raise

        assert isinstance(data, dict)

    def test_json_has_findings(self, sample_result: AggregatedScanResult):
        """Test that JSON contains findings."""
        output = format_json(sample_result)
        data = json.loads(output)

        assert "findings" in data
        assert len(data["findings"]) == 2

    def test_json_has_summary(self, sample_result: AggregatedScanResult):
        """Test that JSON contains summary."""
        output = format_json(sample_result)
        data = json.loads(output)

        assert "summary" in data
        assert data["summary"]["total"] == 2
        assert data["summary"]["unique"] == 2
        assert "by_severity" in data["summary"]

    def test_json_severity_counts(self, sample_result: AggregatedScanResult):
        """Test severity counts in JSON output."""
        output = format_json(sample_result)
        data = json.loads(output)

        by_severity = data["summary"]["by_severity"]
        assert by_severity["critical"] == 1
        assert by_severity["high"] == 1
        assert by_severity["medium"] == 0

    def test_json_has_exit_code(self, sample_result: AggregatedScanResult):
        """Test that JSON contains exit code."""
        output = format_json(sample_result)
        data = json.loads(output)

        assert "exit_code" in data
        assert data["exit_code"] == 1  # CRITICAL finding

    def test_json_has_blocking_findings_flag(self, sample_result: AggregatedScanResult):
        """Test that JSON contains blocking findings flag."""
        output = format_json(sample_result)
        data = json.loads(output)

        assert "has_blocking_findings" in data
        assert data["has_blocking_findings"] is True

    def test_json_empty_result(self):
        """Test JSON output for empty results."""
        result = AggregatedScanResult(
            results=[],
            total_findings=0,
            unique_findings=[],
            scanners_used=["native"],
            total_duration_ms=50,
        )
        output = format_json(result)
        data = json.loads(output)

        assert data["findings"] == []
        assert data["exit_code"] == 0
        assert data["has_blocking_findings"] is False

    def test_json_includes_scanner_results(self):
        """JSON output includes per-scanner results and errors."""
        result = AggregatedScanResult(
            results=[
                ScanResult(
                    scanner_name="native",
                    findings=[],
                    files_scanned=3,
                    duration_ms=10,
                ),
                ScanResult(
                    scanner_name="gitleaks",
                    findings=[],
                    files_scanned=0,
                    duration_ms=5,
                    error="boom",
                ),
            ],
            total_findings=0,
            unique_findings=[],
            scanners_used=["native", "gitleaks"],
            total_duration_ms=15,
        )
        data = json.loads(format_json(result))

        assert "scanner_results" in data
        assert len(data["scanner_results"]) == 2
        assert data["scanner_results"][1]["error"] == "boom"


class TestSarifOutput:
    """Tests for SARIF output formatter."""

    @pytest.fixture
    def sample_result(self) -> AggregatedScanResult:
        """Create a sample result for testing."""
        findings = [
            ScanFinding(
                file_path=Path(".env"),
                rule_id="unencrypted-env-file",
                rule_description="Unencrypted .env File",
                description="File is not encrypted",
                severity=FindingSeverity.HIGH,
                scanner="native",
            ),
            ScanFinding(
                file_path=Path("config.py"),
                line_number=10,
                column_number=5,
                rule_id="aws-access-key-id",
                rule_description="AWS Access Key ID",
                description="AWS key detected",
                severity=FindingSeverity.CRITICAL,
                secret_preview="AKIA****MPLE",
                scanner="native",
            ),
        ]
        return AggregatedScanResult(
            results=[
                ScanResult(
                    scanner_name="native",
                    findings=findings,
                    files_scanned=5,
                    duration_ms=100,
                )
            ],
            total_findings=2,
            unique_findings=findings,
            scanners_used=["native"],
            total_duration_ms=100,
        )

    def test_sarif_is_valid_json(self, sample_result: AggregatedScanResult):
        """Test that SARIF output is valid JSON."""
        output = format_sarif(sample_result)
        data = json.loads(output)

        assert isinstance(data, dict)

    def test_sarif_schema_version(self, sample_result: AggregatedScanResult):
        """Test SARIF schema and version."""
        output = format_sarif(sample_result)
        data = json.loads(output)

        assert data["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
        assert data["version"] == "2.1.0"

    def test_sarif_has_runs(self, sample_result: AggregatedScanResult):
        """Test that SARIF has runs array."""
        output = format_sarif(sample_result)
        data = json.loads(output)

        assert "runs" in data
        assert len(data["runs"]) == 1

    def test_sarif_tool_info(self, sample_result: AggregatedScanResult):
        """Test SARIF tool information."""
        output = format_sarif(sample_result)
        data = json.loads(output)

        tool = data["runs"][0]["tool"]["driver"]
        assert tool["name"] == "envdrift guard"
        assert "rules" in tool

    def test_sarif_rules(self, sample_result: AggregatedScanResult):
        """Test SARIF rules array."""
        output = format_sarif(sample_result)
        data = json.loads(output)

        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 2

        rule_ids = {r["id"] for r in rules}
        assert "unencrypted-env-file" in rule_ids
        assert "aws-access-key-id" in rule_ids

    def test_sarif_results(self, sample_result: AggregatedScanResult):
        """Test SARIF results array."""
        output = format_sarif(sample_result)
        data = json.loads(output)

        results = data["runs"][0]["results"]
        assert len(results) == 2

    def test_sarif_result_structure(self, sample_result: AggregatedScanResult):
        """Test SARIF result structure."""
        output = format_sarif(sample_result)
        data = json.loads(output)

        result = data["runs"][0]["results"][0]
        assert "ruleId" in result
        assert "level" in result
        assert "message" in result
        assert "locations" in result

    def test_sarif_location_structure(self, sample_result: AggregatedScanResult):
        """Test SARIF location structure."""
        output = format_sarif(sample_result)
        data = json.loads(output)

        # Find result with line number
        result = next(r for r in data["runs"][0]["results"] if r["ruleId"] == "aws-access-key-id")
        location = result["locations"][0]["physicalLocation"]

        assert "artifactLocation" in location
        assert location["artifactLocation"]["uri"] == "config.py"
        assert location["region"]["startLine"] == 10
        assert location["region"]["startColumn"] == 5

    def test_sarif_severity_mapping(self, sample_result: AggregatedScanResult):
        """Test SARIF severity level mapping."""
        output = format_sarif(sample_result)
        data = json.loads(output)

        results = data["runs"][0]["results"]

        # Find critical result
        critical_result = next(r for r in results if r["ruleId"] == "aws-access-key-id")
        assert critical_result["level"] == "error"

        # Find high result
        high_result = next(r for r in results if r["ruleId"] == "unencrypted-env-file")
        assert high_result["level"] == "error"

    def test_sarif_fingerprints(self, sample_result: AggregatedScanResult):
        """Test SARIF fingerprints for deduplication."""
        output = format_sarif(sample_result)
        data = json.loads(output)

        result = data["runs"][0]["results"][0]
        assert "fingerprints" in result
        assert "primary" in result["fingerprints"]

    def test_sarif_empty_result(self):
        """Test SARIF output for empty results."""
        result = AggregatedScanResult(
            results=[],
            total_findings=0,
            unique_findings=[],
            scanners_used=["native"],
            total_duration_ms=50,
        )
        output = format_sarif(result)
        data = json.loads(output)

        assert data["runs"][0]["results"] == []
        assert data["runs"][0]["tool"]["driver"]["rules"] == []

    def test_sarif_error_is_valid_schema(self):
        """format_sarif_error emits a schema-valid failed-invocation SARIF doc."""
        output = format_sarif_error("Could not load config: boom")
        data = json.loads(output)

        assert data["version"] == "2.1.0"
        assert data["runs"][0]["results"] == []
        invocation = data["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is False
        notification = invocation["toolConfigurationNotifications"][0]
        assert notification["level"] == "error"
        assert notification["message"]["text"] == "Could not load config: boom"

    def test_sarif_error_message_not_double_escaped(self):
        """The literal message is preserved verbatim (no ANSI / Rich markup)."""
        output = format_sarif_error("Path not found: a/b.env")
        data = json.loads(output)

        text = data["runs"][0]["invocations"][0]["toolConfigurationNotifications"][0]["message"][
            "text"
        ]
        assert text == "Path not found: a/b.env"
        assert "\x1b[" not in output


class TestRichOutput:
    """Tests for Rich output formatting."""

    def test_format_rich_no_findings(self):
        """No findings prints a success panel."""
        result = AggregatedScanResult(
            results=[],
            total_findings=0,
            unique_findings=[],
            scanners_used=["native"],
            total_duration_ms=10,
        )
        console = Console(record=True, force_terminal=True)
        format_rich(result, console)
        output = console.export_text()

        assert "No secrets or policy violations detected" in output
        assert "Scanners:" in output

    def test_format_rich_with_findings(self):
        """Findings print a summary and remediation hint."""
        findings = [
            ScanFinding(
                file_path=Path(".env"),
                rule_id="unencrypted-env-file",
                rule_description="Unencrypted .env File",
                description="File is not encrypted",
                severity=FindingSeverity.HIGH,
                scanner="native",
            )
        ]
        result = AggregatedScanResult(
            results=[ScanResult(scanner_name="native", findings=findings)],
            total_findings=1,
            unique_findings=findings,
            scanners_used=["native"],
            total_duration_ms=10,
        )
        console = Console(record=True, force_terminal=True, width=120)
        format_rich(result, console)
        output = console.export_text()

        assert "Findings Summary" in output
        assert "Remediation" in output

    # A long, realistic description: a revert to overflow="fold" would wrap its
    # tail onto extra lines (the regression this PR fixes), so the truncation
    # assertion below would catch it.
    _LONG_DESCRIPTION = (
        "Potential AWS Access Key ID detected; rotate this credential immediately "
        "and remove it from version control history"
    )

    @classmethod
    def _aws_finding_result(cls) -> AggregatedScanResult:
        findings = [
            ScanFinding(
                file_path=Path(".env"),
                rule_id="aws-access-key-id",
                rule_description="AWS key",
                description=cls._LONG_DESCRIPTION,
                severity=FindingSeverity.CRITICAL,
                scanner="native",
                secret_preview="AKIA1234",
            )
        ]
        return AggregatedScanResult(
            results=[ScanResult(scanner_name="native", findings=findings)],
            total_findings=1,
            unique_findings=findings,
            scanners_used=["native"],
            total_duration_ms=1,
        )

    def test_format_rich_narrow_terminal_keeps_severity_drops_secondary(self):
        """Interactive narrow terminal: keep Sev/Location/Description (one line
        each, ellipsized) and drop the Rule/Preview columns.
        """
        console = Console(record=True, force_terminal=True, width=80)
        format_rich(self._aws_finding_result(), console)
        out = console.export_text()

        assert "CRIT" in out  # severity column rendered (not collapsed to width 0)
        # Description on ONE line, ellipsized — its head shows, the tail is
        # truncated away (a fold-revert would wrap the tail onto a second line).
        assert "Potential AWS Access Key ID detected" in out
        assert "…" in out
        assert "version control history" not in out
        assert "aws-access-key-id" not in out  # Rule column dropped at narrow width
        assert "AKIA1234" not in out  # Preview column dropped at narrow width

    def test_format_rich_non_interactive_keeps_all_columns(self):
        """A non-interactive console (`guard --ci`, piped) keeps all five columns
        even at the default width 80, so CI logs retain rule_id and the preview.
        """
        console = Console(record=True, force_terminal=False, no_color=True, width=80)
        format_rich(self._aws_finding_result(), console)
        out = console.export_text()

        assert "aws-access-key-id" in out  # Rule kept for CI triage
        assert "AKIA1234" in out  # Preview kept

    @pytest.mark.xfail(
        strict=False,
        reason="format_rich ignores the supplied wide Console under pytest capture (see #441)",
    )
    def test_format_rich_wide_terminal_shows_all_columns(self):
        """Wide terminal shows the Rule and Preview columns too."""
        console = Console(record=True, force_terminal=True, width=140)
        format_rich(self._aws_finding_result(), console)
        out = console.export_text()

        assert "CRIT" in out
        assert "aws-access-key-id" in out  # Rule column present
        assert "AKIA1234" in out  # Preview column present

    def test_build_findings_table_column_count(self):
        """Interactive narrow drops to 3 columns; interactive wide keeps 5;
        non-interactive (CI/logs) always keeps all 5 regardless of width."""
        from envdrift.scanner.output import _build_findings_table

        r = self._aws_finding_result()
        narrow = _build_findings_table(r, interactive=True, wide=False)
        wide = _build_findings_table(r, interactive=True, wide=True)
        ci = _build_findings_table(r, interactive=False, wide=False)
        assert len(narrow.columns) == 3
        assert len(wide.columns) == 5
        assert len(ci.columns) == 5  # non-interactive keeps all columns even when narrow

    def test_format_rich_threshold_99_is_narrow(self):
        """Width 99 (one below the threshold) drops the secondary Preview column."""
        console = Console(record=True, force_terminal=True, width=99)
        format_rich(self._aws_finding_result(), console)
        assert "AKIA1234" not in console.export_text()

    @pytest.mark.xfail(
        strict=False,
        reason="format_rich ignores the supplied wide Console under pytest capture (see #441)",
    )
    def test_format_rich_threshold_100_is_wide(self):
        """Width 100 (exactly the threshold) shows the secondary Preview column."""
        console = Console(record=True, force_terminal=True, width=100)
        format_rich(self._aws_finding_result(), console)
        assert "AKIA1234" in console.export_text()

    def test_format_rich_shows_scanner_errors(self):
        """Scanner errors render a dedicated panel."""
        result = AggregatedScanResult(
            results=[
                ScanResult(
                    scanner_name="native", findings=[], files_scanned=0, duration_ms=5, error="boom"
                )
            ],
            total_findings=0,
            unique_findings=[],
            scanners_used=["native"],
            total_duration_ms=5,
        )
        console = Console(record=True, force_terminal=True, width=120)
        format_rich(result, console)
        output = console.export_text()

        assert "Scanner Errors" in output
        assert "native" in output
        assert "boom" in output
        assert "Files with findings" in output


def _aggregate(findings: list[ScanFinding]) -> AggregatedScanResult:
    """Wrap findings in a single-scanner AggregatedScanResult."""
    return AggregatedScanResult(
        results=[ScanResult(scanner_name="native", findings=findings)],
        total_findings=len(findings),
        unique_findings=findings,
        scanners_used=["native"],
        total_duration_ms=1,
    )


class TestSarifPortability:
    """Regression tests for #489 — portable SARIF for Code Scanning uploads.

    Three defects: absolute filesystem URIs under ``SRCROOT`` (alerts cannot
    map to repo files), colliding fingerprints for two distinct same-line
    secrets (Code Scanning merges them), and placeholder driver metadata.
    """

    @staticmethod
    def _secret_finding(column: int, secret_hash: str, preview: str) -> ScanFinding:
        """A same-file/line/rule finding distinguished only by column + hash."""
        return ScanFinding(
            file_path=Path("configs/.env"),
            line_number=1,
            column_number=column,
            rule_id="aws-access-key-id",
            rule_description="AWS Access Key ID",
            description="AWS key detected",
            severity=FindingSeverity.CRITICAL,
            scanner="native",
            secret_preview=preview,
            secret_hash=secret_hash,
        )

    def test_two_distinct_secrets_same_line_get_distinct_fingerprints(self):
        """Two distinct secrets on one line must not share fingerprints.primary."""
        findings = [
            self._secret_finding(5, "a" * 64, "AKIA************MPLE"),
            self._secret_finding(26, "b" * 64, "AKIA************EXMP"),
        ]
        data = json.loads(format_sarif(_aggregate(findings)))

        primaries = [r["fingerprints"]["primary"] for r in data["runs"][0]["results"]]
        assert len(primaries) == 2
        assert primaries[0] != primaries[1]

    def test_partial_fingerprints_distinct_and_hash_based(self):
        """partialFingerprints must derive from the stable content hash, so two
        distinct secrets whose redacted previews collide stay distinct."""
        preview = "AKIA************SAME"  # redaction can collapse distinct secrets
        findings = [
            self._secret_finding(5, "a" * 64, preview),
            self._secret_finding(26, "b" * 64, preview),
        ]
        data = json.loads(format_sarif(_aggregate(findings)))

        partials = [r["partialFingerprints"] for r in data["runs"][0]["results"]]
        assert partials[0] != partials[1]

    def test_fingerprint_includes_rule_id_but_never_raw_secret_text(self):
        """The fingerprint carries the rule id and a content hash — never the
        matched text or the redacted preview."""
        finding = self._secret_finding(5, "c" * 64, "AKIA************MPLE")
        data = json.loads(format_sarif(_aggregate([finding])))

        result = data["runs"][0]["results"][0]
        primary = result["fingerprints"]["primary"]
        assert "aws-access-key-id" in primary
        assert "AKIA" not in primary
        assert "AKIA" not in json.dumps(result["fingerprints"])
        assert "AKIA" not in json.dumps(result.get("partialFingerprints", {}))

    def test_secret_preview_preserved_as_result_property(self):
        """The human-readable redacted preview survives, but as a property —
        not as a fingerprint that drives alert deduplication."""
        finding = self._secret_finding(5, "d" * 64, "AKIA************MPLE")
        data = json.loads(format_sarif(_aggregate([finding])))

        result = data["runs"][0]["results"][0]
        assert result["properties"]["secretPreview"] == "AKIA************MPLE"

    def test_finding_without_secret_hash_disambiguated_by_column(self):
        """Scanners that report no secret_hash still get column-distinct
        fingerprints for two same-line findings."""
        findings = [
            self._secret_finding(5, "", "AKIA************MPLE"),
            self._secret_finding(26, "", "AKIA************EXMP"),
        ]
        data = json.loads(format_sarif(_aggregate(findings)))

        primaries = [r["fingerprints"]["primary"] for r in data["runs"][0]["results"]]
        assert primaries[0] != primaries[1]

    def test_driver_metadata_is_real_package_metadata(self):
        """driver.version/informationUri must be the real package metadata."""
        import envdrift

        finding = self._secret_finding(5, "e" * 64, "AKIA************MPLE")
        data = json.loads(format_sarif(_aggregate([finding])))

        driver = data["runs"][0]["tool"]["driver"]
        assert driver["version"] == envdrift.__version__
        assert driver["version"] != "0.1.0"
        assert driver["informationUri"] == "https://github.com/jainal09/envdrift"

    def test_error_document_driver_metadata_is_real(self):
        """The error path emits the same real driver metadata."""
        import envdrift

        data = json.loads(format_sarif_error("Could not load config: boom"))

        driver = data["runs"][0]["tool"]["driver"]
        assert driver["version"] == envdrift.__version__
        assert driver["informationUri"] == "https://github.com/jainal09/envdrift"
        assert "your-org" not in driver["informationUri"]

    def test_absolute_path_under_srcroot_becomes_relative_uri(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """An absolute finding path under the source root must emit a relative
        URI with ``uriBaseId: SRCROOT`` and declare the base in
        ``originalUriBaseIds`` under the exact same key (SARIF 2.1.0 §3.4.4 /
        §3.14.14 — resolution is by exact string lookup)."""
        monkeypatch.chdir(tmp_path)
        finding = ScanFinding(
            file_path=tmp_path / "configs" / ".env",
            line_number=1,
            rule_id="aws-access-key-id",
            rule_description="AWS Access Key ID",
            description="AWS key detected",
            severity=FindingSeverity.CRITICAL,
            scanner="native",
        )
        data = json.loads(format_sarif(_aggregate([finding])))

        run = data["runs"][0]
        location = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
        assert location["uri"] == "configs/.env"
        assert location["uriBaseId"] == "SRCROOT"
        # Regression (#533 review): the uriBaseId must be resolvable by exact
        # key lookup in originalUriBaseIds — "%SRCROOT%" vs "SRCROOT" drift
        # left the base undeclared for strict consumers.
        assert location["uriBaseId"] in run["originalUriBaseIds"]
        srcroot_uri = run["originalUriBaseIds"]["SRCROOT"]["uri"]
        assert srcroot_uri == tmp_path.resolve().as_uri() + "/"

    def test_relative_finding_path_resolves_against_cwd(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """A cwd-relative finding path is absolutized before relativizing, so
        the emitted URI is stable and source-root-relative."""
        monkeypatch.chdir(tmp_path)
        finding = ScanFinding(
            file_path=Path("configs/.env"),
            line_number=1,
            rule_id="aws-access-key-id",
            rule_description="AWS Access Key ID",
            description="AWS key detected",
            severity=FindingSeverity.CRITICAL,
            scanner="native",
        )
        data = json.loads(format_sarif(_aggregate([finding])))

        location = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "configs/.env"

    def test_absolute_path_outside_srcroot_falls_back_to_file_uri(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """A path outside the source root cannot be relativized: emit an
        absolute ``file://`` URI and no ``uriBaseId`` (a base id on an absolute
        URI is contradictory and Code Scanning drops the alert)."""
        inside = tmp_path / "inside"
        inside.mkdir()
        monkeypatch.chdir(inside)
        outside_file = tmp_path / "outside" / ".env"
        finding = ScanFinding(
            file_path=outside_file,
            line_number=1,
            rule_id="aws-access-key-id",
            rule_description="AWS Access Key ID",
            description="AWS key detected",
            severity=FindingSeverity.CRITICAL,
            scanner="native",
        )
        data = json.loads(format_sarif(_aggregate([finding])))

        location = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        artifact = location["artifactLocation"]
        assert artifact["uri"] == outside_file.resolve().as_uri()
        assert "uriBaseId" not in artifact

    def test_windows_paths_emit_forward_slash_uris(self):
        """SARIF URIs must use forward slashes on Windows too (§3.4.4)."""
        from pathlib import PureWindowsPath

        from envdrift.scanner.output import _sarif_artifact_location

        location = _sarif_artifact_location(
            PureWindowsPath(r"C:\repo\configs\.env"), PureWindowsPath(r"C:\repo")
        )
        assert location == {"uri": "configs/.env", "uriBaseId": "SRCROOT"}

    # PurePath.as_uri() is deprecated on 3.14+ (use Path.as_uri()); production
    # always passes a concrete Path — only this Windows-shape test drives the
    # fallback with a PureWindowsPath, which cannot be a concrete Path on CI.
    @pytest.mark.filterwarnings("ignore:pathlib.PurePath.as_uri:DeprecationWarning")
    def test_windows_path_outside_srcroot_is_absolute_file_uri(self):
        """A Windows path outside the source root falls back to a file:// URI."""
        from pathlib import PureWindowsPath

        from envdrift.scanner.output import _sarif_artifact_location

        location = _sarif_artifact_location(
            PureWindowsPath(r"D:\elsewhere\.env"), PureWindowsPath(r"C:\repo")
        )
        assert location["uri"] == "file:///D:/elsewhere/.env"
        assert "uriBaseId" not in location

    def test_path_with_space_and_hash_is_percent_encoded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """A repo path with a space or ``#`` must be RFC 3986 percent-encoded
        (SARIF 2.1.0 §3.4.3) — a raw space is an invalid URI-reference and a
        raw ``#`` truncates the path at the fragment when parsed."""
        monkeypatch.chdir(tmp_path)
        finding = ScanFinding(
            file_path=tmp_path / "My Project#1" / ".env",
            line_number=1,
            rule_id="aws-access-key-id",
            rule_description="AWS Access Key ID",
            description="AWS key detected",
            severity=FindingSeverity.CRITICAL,
            scanner="native",
        )
        data = json.loads(format_sarif(_aggregate([finding])))

        location = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "My%20Project%231/.env"

    def test_non_ascii_path_is_percent_encoded_as_utf8(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Non-ASCII path segments are percent-encoded as UTF-8 octets,
        matching the encoding ``Path.as_uri()`` uses on the fallback branch."""
        monkeypatch.chdir(tmp_path)
        finding = ScanFinding(
            file_path=tmp_path / "sécrets" / ".env",
            line_number=1,
            rule_id="aws-access-key-id",
            rule_description="AWS Access Key ID",
            description="AWS key detected",
            severity=FindingSeverity.CRITICAL,
            scanner="native",
        )
        data = json.loads(format_sarif(_aggregate([finding])))

        location = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "s%C3%A9crets/.env"

    def test_unreserved_path_is_not_over_encoded(self):
        """A plain path must pass through unchanged — encoding is applied only
        where RFC 3986 requires it, keeping existing fingerprints stable."""
        from pathlib import PurePosixPath

        from envdrift.scanner.output import _sarif_artifact_location

        location = _sarif_artifact_location(
            PurePosixPath("/repo/configs/.env"), PurePosixPath("/repo")
        )
        assert location == {"uri": "configs/.env", "uriBaseId": "SRCROOT"}


def _validate_against_sarif_schema(document: dict) -> None:
    """Validate a SARIF document against the official 2.1.0 JSON schema."""
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = Path(__file__).parents[1] / "fixtures" / "sarif-schema-2.1.0.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.validate(instance=document, schema=schema)


class TestSarifSchemaConformance:
    """The emitted documents must validate against the official SARIF 2.1.0
    schema (oasis-tcs/sarif-spec), vendored at tests/fixtures/."""

    def test_full_document_validates_against_official_schema(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """A run with findings (hash, preview, encoded URI), a failed scanner
        notification and a declared SRCROOT base must be schema-valid."""
        monkeypatch.chdir(tmp_path)
        findings = [
            ScanFinding(
                file_path=tmp_path / "My Project" / ".env",
                line_number=1,
                column_number=5,
                rule_id="aws-access-key-id",
                rule_description="AWS Access Key ID",
                description="AWS key detected",
                severity=FindingSeverity.CRITICAL,
                scanner="native",
                secret_preview="AKIA************MPLE",
                secret_hash="a" * 64,
            ),
            ScanFinding(
                file_path=Path("configs/.env"),
                line_number=2,
                rule_id="unencrypted-env-file",
                rule_description="Unencrypted .env File",
                description="File is not encrypted",
                severity=FindingSeverity.HIGH,
                scanner="native",
            ),
        ]
        result = AggregatedScanResult(
            results=[
                ScanResult(scanner_name="native", findings=findings),
                ScanResult(scanner_name="gitleaks", error="binary exploded"),
            ],
            total_findings=len(findings),
            unique_findings=findings,
            scanners_used=["native", "gitleaks"],
            total_duration_ms=1,
        )

        _validate_against_sarif_schema(json.loads(format_sarif(result, exit_code=1)))

    def test_error_document_validates_against_official_schema(self):
        """The error-path document must be schema-valid too."""
        _validate_against_sarif_schema(json.loads(format_sarif_error("Could not load config")))

    def test_empty_error_scan_incomplete_document_validates_against_schema(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Merge-seam battle test (#489 SARIF x #478 exit-truthfulness).

        A scanner that failed with an EMPTY error string flips
        ``executionSuccessful`` to false via the ``not r.success`` contract and
        must still emit a ``toolExecutionNotifications`` entry (#478) — while a
        finding carries a SRCROOT-relative, percent-encoded artifact URI (#489).
        Both live in the same ``format_sarif`` document; validate the whole
        thing against the official 2.1.0 schema so the empty-text notification
        can never produce a malformed message on the scan-incomplete (exit 5)
        path.
        """
        monkeypatch.chdir(tmp_path)
        finding = ScanFinding(
            file_path=tmp_path / "sub dir" / ".env",
            line_number=1,
            column_number=5,
            rule_id="aws-access-key-id",
            rule_description="AWS Access Key ID",
            description="AWS key detected",
            severity=FindingSeverity.LOW,
            scanner="native",
        )
        result = AggregatedScanResult(
            results=[
                ScanResult(scanner_name="native", findings=[finding]),
                # Empty-string error: the #478 edge the truthiness filter dropped.
                ScanResult(scanner_name="talisman", error=""),
            ],
            total_findings=1,
            unique_findings=[finding],
            scanners_used=["native", "talisman"],
            total_duration_ms=1,
        )

        document = json.loads(format_sarif(result, exit_code=5))
        _validate_against_sarif_schema(document)

        invocation = document["runs"][0]["invocations"][0]
        assert invocation["exitCode"] == 5
        assert invocation["executionSuccessful"] is False
        notifications = invocation["toolExecutionNotifications"]
        assert any(n["message"]["text"].startswith("talisman:") for n in notifications), (
            "an empty-error scan failure must still emit a schema-valid notification"
        )
        # #489 delta is intact on the same document: SRCROOT-relative, encoded URI.
        location = document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "sub%20dir/.env"
        assert location["artifactLocation"]["uriBaseId"] == "SRCROOT"
