"""Tests for scanner base module."""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.scanner.base import (
    AggregatedScanResult,
    FindingSeverity,
    ScanFinding,
    ScannerBackend,
    ScanResult,
)


class TestFindingSeverity:
    """Tests for FindingSeverity enum."""

    def test_severity_values(self):
        """Test that all severity values exist."""
        assert FindingSeverity.CRITICAL.value == "critical"
        assert FindingSeverity.HIGH.value == "high"
        assert FindingSeverity.MEDIUM.value == "medium"
        assert FindingSeverity.LOW.value == "low"
        assert FindingSeverity.INFO.value == "info"

    def test_severity_ordering_less_than(self):
        """Test that severities can be compared with <."""
        assert FindingSeverity.INFO < FindingSeverity.LOW
        assert FindingSeverity.LOW < FindingSeverity.MEDIUM
        assert FindingSeverity.MEDIUM < FindingSeverity.HIGH
        assert FindingSeverity.HIGH < FindingSeverity.CRITICAL

    def test_severity_ordering_greater_than(self):
        """Test that severities can be compared with >."""
        assert FindingSeverity.CRITICAL > FindingSeverity.HIGH
        assert FindingSeverity.HIGH > FindingSeverity.MEDIUM
        assert FindingSeverity.MEDIUM > FindingSeverity.LOW
        assert FindingSeverity.LOW > FindingSeverity.INFO

    def test_severity_equality(self):
        """Test severity equality."""
        assert FindingSeverity.HIGH == FindingSeverity.HIGH
        assert FindingSeverity.HIGH != FindingSeverity.LOW

    def test_severity_le_ge(self):
        """Test <= and >= operators."""
        assert FindingSeverity.HIGH <= FindingSeverity.CRITICAL
        assert FindingSeverity.HIGH <= FindingSeverity.HIGH
        assert FindingSeverity.CRITICAL >= FindingSeverity.HIGH
        assert FindingSeverity.HIGH >= FindingSeverity.HIGH

    def test_severity_comparison_with_non_severity(self):
        """Test that comparison with non-severity returns NotImplemented."""
        assert FindingSeverity.HIGH.__lt__("high") == NotImplemented
        assert FindingSeverity.HIGH.__gt__(5) == NotImplemented

    def test_severity_le_ge_with_non_severity(self):
        """Test <= and >= with non-severity return NotImplemented."""
        assert FindingSeverity.HIGH.__le__("high") == NotImplemented
        assert FindingSeverity.HIGH.__ge__(5) == NotImplemented


class TestScanFinding:
    """Tests for ScanFinding dataclass."""

    @pytest.fixture
    def sample_finding(self) -> ScanFinding:
        """Create a sample finding for testing."""
        return ScanFinding(
            file_path=Path(".env"),
            rule_id="test-rule",
            rule_description="Test Rule",
            description="Test finding description",
            severity=FindingSeverity.HIGH,
            scanner="native",
            line_number=10,
            column_number=5,
            secret_preview="AKIA****XXXX",
        )

    def test_finding_creation(self, sample_finding: ScanFinding):
        """Test that findings can be created."""
        assert sample_finding.file_path == Path(".env")
        assert sample_finding.rule_id == "test-rule"
        assert sample_finding.severity == FindingSeverity.HIGH

    def test_finding_is_frozen(self, sample_finding: ScanFinding):
        """Test that findings are immutable."""
        with pytest.raises(AttributeError):
            sample_finding.rule_id = "new-rule"  # type: ignore

    def test_to_dict(self, sample_finding: ScanFinding):
        """Test conversion to dictionary."""
        data = sample_finding.to_dict()

        assert data["file_path"] == ".env"
        assert data["rule_id"] == "test-rule"
        assert data["severity"] == "high"
        assert data["scanner"] == "native"
        assert data["line_number"] == 10
        assert data["column_number"] == 5
        assert data["secret_preview"] == "AKIA****XXXX"

    def test_location_with_line_and_column(self, sample_finding: ScanFinding):
        """Test location property with line and column."""
        assert sample_finding.location == ".env:10:5"

    def test_location_with_line_only(self):
        """Test location property with line only."""
        finding = ScanFinding(
            file_path=Path("config.py"),
            rule_id="test",
            rule_description="Test",
            description="Test",
            severity=FindingSeverity.HIGH,
            scanner="native",
            line_number=42,
        )
        assert finding.location == "config.py:42"

    def test_location_without_line(self):
        """Test location property without line number."""
        finding = ScanFinding(
            file_path=Path("secrets.txt"),
            rule_id="test",
            rule_description="Test",
            description="Test",
            severity=FindingSeverity.HIGH,
            scanner="native",
        )
        assert finding.location == "secrets.txt"

    def test_default_values(self):
        """Test that optional fields have correct defaults."""
        finding = ScanFinding(
            file_path=Path(".env"),
            rule_id="test",
            rule_description="Test",
            description="Test",
            severity=FindingSeverity.LOW,
            scanner="native",
        )
        assert finding.line_number is None
        assert finding.column_number is None
        assert finding.secret_preview == ""
        assert finding.commit_sha is None
        assert finding.entropy is None
        assert finding.verified is False


class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_empty_result(self):
        """Test creating an empty scan result."""
        result = ScanResult(scanner_name="native")

        assert result.scanner_name == "native"
        assert result.findings == []
        assert result.files_scanned == 0
        assert result.duration_ms == 0
        assert result.error is None
        assert result.success is True

    def test_result_with_findings(self):
        """Test creating a result with findings."""
        finding = ScanFinding(
            file_path=Path(".env"),
            rule_id="test",
            rule_description="Test",
            description="Test",
            severity=FindingSeverity.HIGH,
            scanner="native",
        )
        result = ScanResult(
            scanner_name="native",
            findings=[finding],
            files_scanned=10,
            duration_ms=500,
        )

        assert len(result.findings) == 1
        assert result.files_scanned == 10
        assert result.duration_ms == 500

    def test_result_with_error(self):
        """Test creating a result with an error."""
        result = ScanResult(
            scanner_name="gitleaks",
            error="Binary not found",
        )

        assert result.error == "Binary not found"
        assert result.success is False


class TestAggregatedScanResult:
    """Tests for AggregatedScanResult dataclass."""

    @pytest.fixture
    def critical_finding(self) -> ScanFinding:
        """Create a critical severity finding."""
        return ScanFinding(
            file_path=Path("secrets.py"),
            rule_id="aws-key",
            rule_description="AWS Key",
            description="AWS key detected",
            severity=FindingSeverity.CRITICAL,
            scanner="native",
        )

    @pytest.fixture
    def high_finding(self) -> ScanFinding:
        """Create a high severity finding."""
        return ScanFinding(
            file_path=Path(".env"),
            rule_id="unencrypted",
            rule_description="Unencrypted",
            description="Unencrypted file",
            severity=FindingSeverity.HIGH,
            scanner="native",
        )

    @pytest.fixture
    def medium_finding(self) -> ScanFinding:
        """Create a medium severity finding."""
        return ScanFinding(
            file_path=Path("config.py"),
            rule_id="entropy",
            rule_description="High Entropy",
            description="High entropy string",
            severity=FindingSeverity.MEDIUM,
            scanner="native",
        )

    def test_empty_result(self):
        """Test empty aggregated result."""
        result = AggregatedScanResult(
            results=[],
            total_findings=0,
            unique_findings=[],
            scanners_used=["native"],
            total_duration_ms=100,
        )

        assert result.exit_code == 0
        assert result.has_blocking_findings is False

    def test_exit_code_critical(self, critical_finding: ScanFinding):
        """Test exit code with critical finding."""
        result = AggregatedScanResult(
            results=[],
            total_findings=1,
            unique_findings=[critical_finding],
            scanners_used=["native"],
            total_duration_ms=100,
        )

        assert result.exit_code == 1
        assert result.has_blocking_findings is True

    def test_exit_code_high(self, high_finding: ScanFinding):
        """Test exit code with high finding."""
        result = AggregatedScanResult(
            results=[],
            total_findings=1,
            unique_findings=[high_finding],
            scanners_used=["native"],
            total_duration_ms=100,
        )

        assert result.exit_code == 2
        assert result.has_blocking_findings is True

    def test_exit_code_medium(self, medium_finding: ScanFinding):
        """Test exit code with medium finding."""
        result = AggregatedScanResult(
            results=[],
            total_findings=1,
            unique_findings=[medium_finding],
            scanners_used=["native"],
            total_duration_ms=100,
        )

        assert result.exit_code == 3
        assert result.has_blocking_findings is False

    def test_exit_code_mixed_severities(
        self,
        critical_finding: ScanFinding,
        high_finding: ScanFinding,
        medium_finding: ScanFinding,
    ):
        """Test exit code with mixed severities (uses highest)."""
        result = AggregatedScanResult(
            results=[],
            total_findings=3,
            unique_findings=[medium_finding, high_finding, critical_finding],
            scanners_used=["native"],
            total_duration_ms=100,
        )

        assert result.exit_code == 1  # Critical is highest

    def test_findings_by_severity(
        self,
        critical_finding: ScanFinding,
        high_finding: ScanFinding,
    ):
        """Test grouping findings by severity."""
        result = AggregatedScanResult(
            results=[],
            total_findings=2,
            unique_findings=[critical_finding, high_finding],
            scanners_used=["native"],
            total_duration_ms=100,
        )

        by_severity = result.findings_by_severity

        assert len(by_severity[FindingSeverity.CRITICAL]) == 1
        assert len(by_severity[FindingSeverity.HIGH]) == 1
        assert FindingSeverity.MEDIUM not in by_severity

    def test_get_summary(
        self,
        critical_finding: ScanFinding,
        high_finding: ScanFinding,
        medium_finding: ScanFinding,
    ):
        """Test getting count summary."""
        result = AggregatedScanResult(
            results=[],
            total_findings=3,
            unique_findings=[critical_finding, high_finding, medium_finding],
            scanners_used=["native"],
            total_duration_ms=100,
        )

        summary = result.get_summary()

        assert summary["critical"] == 1
        assert summary["high"] == 1
        assert summary["medium"] == 1
        assert summary["low"] == 0
        assert summary["info"] == 0


class TestScannerBackendDefaults:
    """Tests for ScannerBackend default implementations."""

    def test_default_install_and_version(self):
        """install/get_version default to None for base scanners."""

        class DummyScanner(ScannerBackend):
            @property
            def name(self) -> str:
                return "dummy"

            @property
            def description(self) -> str:
                return "dummy scanner"

            def is_installed(self) -> bool:
                return True

            def scan(self, paths: list[Path], include_git_history: bool = False) -> ScanResult:
                return ScanResult(scanner_name=self.name)

        scanner = DummyScanner()
        assert scanner.install() is None
        assert scanner.get_version() is None
