"""Tests for scan engine module."""

from __future__ import annotations

from pathlib import Path
import sys
import types

from envdrift.scanner.base import FindingSeverity, ScanFinding, ScanResult, ScannerBackend
from envdrift.scanner.engine import GuardConfig, ScanEngine


class TestGuardConfig:
    """Tests for GuardConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = GuardConfig()

        assert config.use_native is True
        assert config.use_gitleaks is True
        assert config.use_trufflehog is False
        assert config.auto_install is True
        assert config.include_git_history is False
        assert config.check_entropy is False
        assert config.entropy_threshold == 4.5
        assert config.ignore_paths == []
        assert config.fail_on_severity == FindingSeverity.HIGH

    def test_config_from_dict_empty(self):
        """Test creating config from empty dict."""
        config = GuardConfig.from_dict({})

        assert config.use_native is True
        assert config.use_gitleaks is True

    def test_config_from_dict_with_guard_section(self):
        """Test creating config from dict with guard section."""
        config = GuardConfig.from_dict(
            {
                "guard": {
                    "scanners": ["native", "trufflehog"],
                    "auto_install": False,
                    "include_history": True,
                    "fail_on_severity": "critical",
                }
            }
        )

        assert config.use_native is True
        assert config.use_gitleaks is False
        assert config.use_trufflehog is True
        assert config.auto_install is False
        assert config.include_git_history is True
        assert config.fail_on_severity == FindingSeverity.CRITICAL

    def test_config_from_dict_native_only(self):
        """Test config with only native scanner."""
        config = GuardConfig.from_dict(
            {"guard": {"scanners": ["native"]}}
        )

        assert config.use_native is True
        assert config.use_gitleaks is False
        assert config.use_trufflehog is False

    def test_config_from_dict_all_scanners(self):
        """Test config with all scanners enabled."""
        config = GuardConfig.from_dict(
            {"guard": {"scanners": ["native", "gitleaks", "trufflehog"]}}
        )

        assert config.use_native is True
        assert config.use_gitleaks is True
        assert config.use_trufflehog is True

    def test_config_from_dict_invalid_severity(self):
        """Test config with invalid severity falls back to HIGH."""
        config = GuardConfig.from_dict(
            {"guard": {"fail_on_severity": "invalid"}}
        )

        assert config.fail_on_severity == FindingSeverity.HIGH

    def test_config_from_dict_with_string_scanner(self):
        """Test config handles scanners as a string."""
        config = GuardConfig.from_dict({"guard": {"scanners": "gitleaks"}})

        assert config.use_native is False
        assert config.use_gitleaks is True


class TestScanEngine:
    """Tests for ScanEngine class."""

    def test_engine_with_default_config(self):
        """Test creating engine with default config."""
        engine = ScanEngine()

        assert len(engine.scanners) >= 1
        assert any(s.name == "native" for s in engine.scanners)

    def test_engine_native_only(self):
        """Test engine with only native scanner."""
        config = GuardConfig(
            use_native=True,
            use_gitleaks=False,
            use_trufflehog=False,
        )
        engine = ScanEngine(config)

        assert len(engine.scanners) == 1
        assert engine.scanners[0].name == "native"

    def test_engine_no_scanners(self):
        """Test engine with no scanners enabled."""
        config = GuardConfig(
            use_native=False,
            use_gitleaks=False,
            use_trufflehog=False,
        )
        engine = ScanEngine(config)

        assert len(engine.scanners) == 0

    def test_engine_initializes_external_scanners(self, monkeypatch):
        """External scanners are added when installed."""

        def make_scanner(class_name: str, scanner_name: str, installed: bool):
            def __init__(self, auto_install: bool = True):
                self._installed = installed

            def name(self) -> str:
                return scanner_name

            def description(self) -> str:
                return f"{scanner_name} scanner"

            def is_installed(self) -> bool:
                return self._installed

            def scan(
                self,
                paths: list[Path],
                include_git_history: bool = False,
            ) -> ScanResult:
                return ScanResult(scanner_name=self.name)

            return type(
                class_name,
                (ScannerBackend,),
                {
                    "__init__": __init__,
                    "name": property(name),
                    "description": property(description),
                    "is_installed": is_installed,
                    "scan": scan,
                },
            )

        gitleaks_mod = types.ModuleType("envdrift.scanner.gitleaks")
        gitleaks_mod.GitleaksScanner = make_scanner(
            "GitleaksScanner", "gitleaks", True
        )
        truffle_mod = types.ModuleType("envdrift.scanner.trufflehog")
        truffle_mod.TrufflehogScanner = make_scanner(
            "TrufflehogScanner", "trufflehog", True
        )
        detect_mod = types.ModuleType("envdrift.scanner.detect_secrets")
        detect_mod.DetectSecretsScanner = make_scanner(
            "DetectSecretsScanner", "detect-secrets", True
        )

        monkeypatch.setitem(sys.modules, "envdrift.scanner.gitleaks", gitleaks_mod)
        monkeypatch.setitem(sys.modules, "envdrift.scanner.trufflehog", truffle_mod)
        monkeypatch.setitem(sys.modules, "envdrift.scanner.detect_secrets", detect_mod)

        config = GuardConfig(
            use_native=False,
            use_gitleaks=True,
            use_trufflehog=True,
            use_detect_secrets=True,
            auto_install=False,
        )
        engine = ScanEngine(config)
        names = {scanner.name for scanner in engine.scanners}

        assert names == {"gitleaks", "trufflehog", "detect-secrets"}

    def test_engine_auto_install_adds_uninstalled_scanner(self, monkeypatch):
        """Auto-install allows uninstalled scanners to be added."""

        def make_scanner(class_name: str, scanner_name: str):
            def __init__(self, auto_install: bool = True):
                self._installed = False

            def name(self) -> str:
                return scanner_name

            def description(self) -> str:
                return f"{scanner_name} scanner"

            def is_installed(self) -> bool:
                return self._installed

            def scan(
                self,
                paths: list[Path],
                include_git_history: bool = False,
            ) -> ScanResult:
                return ScanResult(scanner_name=self.name)

            return type(
                class_name,
                (ScannerBackend,),
                {
                    "__init__": __init__,
                    "name": property(name),
                    "description": property(description),
                    "is_installed": is_installed,
                    "scan": scan,
                },
            )

        gitleaks_mod = types.ModuleType("envdrift.scanner.gitleaks")
        gitleaks_mod.GitleaksScanner = make_scanner(
            "GitleaksScanner", "gitleaks"
        )
        monkeypatch.setitem(sys.modules, "envdrift.scanner.gitleaks", gitleaks_mod)

        config = GuardConfig(
            use_native=False,
            use_gitleaks=True,
            use_trufflehog=False,
            use_detect_secrets=False,
            auto_install=True,
        )
        engine = ScanEngine(config)
        names = [scanner.name for scanner in engine.scanners]

        assert names == ["gitleaks"]

    def test_engine_skips_uninstalled_when_auto_install_disabled(self, monkeypatch):
        """Disabled auto-install skips unavailable scanners."""

        def make_scanner(class_name: str, scanner_name: str):
            def __init__(self, auto_install: bool = True):
                self._installed = False

            def name(self) -> str:
                return scanner_name

            def description(self) -> str:
                return f"{scanner_name} scanner"

            def is_installed(self) -> bool:
                return self._installed

            def scan(
                self,
                paths: list[Path],
                include_git_history: bool = False,
            ) -> ScanResult:
                return ScanResult(scanner_name=self.name)

            return type(
                class_name,
                (ScannerBackend,),
                {
                    "__init__": __init__,
                    "name": property(name),
                    "description": property(description),
                    "is_installed": is_installed,
                    "scan": scan,
                },
            )

        gitleaks_mod = types.ModuleType("envdrift.scanner.gitleaks")
        gitleaks_mod.GitleaksScanner = make_scanner(
            "GitleaksScanner", "gitleaks"
        )
        monkeypatch.setitem(sys.modules, "envdrift.scanner.gitleaks", gitleaks_mod)

        config = GuardConfig(
            use_native=False,
            use_gitleaks=True,
            use_trufflehog=False,
            use_detect_secrets=False,
            auto_install=False,
        )
        engine = ScanEngine(config)
        assert engine.scanners == []

    def test_scan_empty_directory(self, tmp_path: Path):
        """Test scanning an empty directory."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        result = engine.scan([tmp_path])

        assert result.total_findings == 0
        assert len(result.unique_findings) == 0
        assert "native" in result.scanners_used

    def test_scan_with_findings(self, tmp_path: Path):
        """Test scanning directory with secrets."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        # Create file with secret
        secret_file = tmp_path / "config.py"
        secret_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')

        result = engine.scan([tmp_path])

        assert result.total_findings >= 1
        assert len(result.unique_findings) >= 1

    def test_scan_records_scanner_errors(self):
        """Scanner errors are captured without failing the run."""

        class FailingScanner(ScannerBackend):
            @property
            def name(self) -> str:
                return "failing"

            @property
            def description(self) -> str:
                return "failing scanner"

            def is_installed(self) -> bool:
                return True

            def scan(
                self,
                paths: list[Path],
                include_git_history: bool = False,
            ) -> ScanResult:
                raise RuntimeError("boom")

        config = GuardConfig(
            use_native=False,
            use_gitleaks=False,
            use_trufflehog=False,
            use_detect_secrets=False,
        )
        engine = ScanEngine(config)
        engine.scanners = [FailingScanner()]

        result = engine.scan([Path(".")])

        assert result.results[0].error == "boom"

    def test_get_scanner_info(self):
        """Test getting scanner information."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        info = engine.get_scanner_info()

        assert len(info) == 1
        assert info[0]["name"] == "native"
        assert info[0]["installed"] is True


class TestDeduplication:
    """Tests for finding deduplication."""

    def test_deduplicate_identical_findings(self):
        """Test that identical findings are deduplicated."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=Path("config.py"),
                line_number=10,
                rule_id="aws-key",
                rule_description="AWS Key",
                description="AWS key",
                severity=FindingSeverity.CRITICAL,
                scanner="scanner1",
            ),
            ScanFinding(
                file_path=Path("config.py"),
                line_number=10,
                rule_id="aws-key",
                rule_description="AWS Key",
                description="AWS key",
                severity=FindingSeverity.CRITICAL,
                scanner="scanner2",
            ),
        ]

        unique = engine._deduplicate(findings)

        assert len(unique) == 1

    def test_deduplicate_keeps_higher_severity(self):
        """Test that deduplication keeps higher severity."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=Path("config.py"),
                line_number=10,
                rule_id="secret",
                rule_description="Secret",
                description="Secret",
                severity=FindingSeverity.MEDIUM,
                scanner="scanner1",
            ),
            ScanFinding(
                file_path=Path("config.py"),
                line_number=10,
                rule_id="secret",
                rule_description="Secret",
                description="Secret",
                severity=FindingSeverity.CRITICAL,
                scanner="scanner2",
            ),
        ]

        unique = engine._deduplicate(findings)

        assert len(unique) == 1
        assert unique[0].severity == FindingSeverity.CRITICAL

    def test_deduplicate_prefers_verified(self):
        """Test that deduplication prefers verified findings."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=Path("config.py"),
                line_number=10,
                rule_id="secret",
                rule_description="Secret",
                description="Secret",
                severity=FindingSeverity.HIGH,
                scanner="scanner1",
                verified=False,
            ),
            ScanFinding(
                file_path=Path("config.py"),
                line_number=10,
                rule_id="secret",
                rule_description="Secret",
                description="Secret",
                severity=FindingSeverity.HIGH,
                scanner="scanner2",
                verified=True,
            ),
        ]

        unique = engine._deduplicate(findings)

        assert len(unique) == 1
        assert unique[0].verified is True

    def test_deduplicate_different_locations(self):
        """Test that findings at different locations are kept."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=Path("config1.py"),
                line_number=10,
                rule_id="secret",
                rule_description="Secret",
                description="Secret",
                severity=FindingSeverity.HIGH,
                scanner="native",
            ),
            ScanFinding(
                file_path=Path("config2.py"),
                line_number=10,
                rule_id="secret",
                rule_description="Secret",
                description="Secret",
                severity=FindingSeverity.HIGH,
                scanner="native",
            ),
        ]

        unique = engine._deduplicate(findings)

        assert len(unique) == 2

    def test_deduplicate_sorted_by_severity(self):
        """Test that results are sorted by severity."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=Path("a.py"),
                rule_id="low",
                rule_description="Low",
                description="Low",
                severity=FindingSeverity.LOW,
                scanner="native",
            ),
            ScanFinding(
                file_path=Path("b.py"),
                rule_id="critical",
                rule_description="Critical",
                description="Critical",
                severity=FindingSeverity.CRITICAL,
                scanner="native",
            ),
            ScanFinding(
                file_path=Path("c.py"),
                rule_id="medium",
                rule_description="Medium",
                description="Medium",
                severity=FindingSeverity.MEDIUM,
                scanner="native",
            ),
        ]

        unique = engine._deduplicate(findings)

        # Should be sorted: CRITICAL, MEDIUM, LOW
        assert unique[0].severity == FindingSeverity.CRITICAL
        assert unique[1].severity == FindingSeverity.MEDIUM
        assert unique[2].severity == FindingSeverity.LOW


class TestIntegration:
    """Integration tests for the scan engine."""

    def test_full_scan_workflow(self, tmp_path: Path):
        """Test complete scan workflow."""
        # Setup: Create files with various issues
        (tmp_path / ".env").write_text("DATABASE_URL=postgres://localhost/db\n")
        (tmp_path / "config.py").write_text(
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
            'GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n'
        )

        # Run scan
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)
        result = engine.scan([tmp_path])

        # Verify results
        assert result.total_findings >= 3  # .env + AWS + GitHub
        assert result.has_blocking_findings is True
        assert result.exit_code in (1, 2)  # CRITICAL or HIGH

    def test_scan_with_entropy_enabled(self, tmp_path: Path):
        """Test scan with entropy detection enabled."""
        config = GuardConfig(
            use_native=True,
            use_gitleaks=False,
            check_entropy=True,
            entropy_threshold=4.0,
        )
        engine = ScanEngine(config)

        # Create file with high-entropy string
        (tmp_path / "config.py").write_text(
            'SECRET = "aB3xK9mN2pQ5vR8tY1wZ4cF7hJ0kL6"\n'
        )

        result = engine.scan([tmp_path])

        entropy_findings = [
            f for f in result.unique_findings if f.rule_id == "high-entropy-string"
        ]
        assert len(entropy_findings) >= 1
