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
from envdrift.scanner.output import format_json, format_rich, format_sarif


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

    def test_format_rich_shows_scanner_errors(self):
        """Scanner errors render a dedicated panel."""
        result = AggregatedScanResult(
            results=[
                ScanResult(scanner_name="native", findings=[], files_scanned=0, duration_ms=5, error="boom")
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
