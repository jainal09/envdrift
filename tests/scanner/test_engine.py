"""Tests for scan engine module."""

from __future__ import annotations

import sys
import types
from pathlib import Path

from envdrift.scanner.base import FindingSeverity, ScanFinding, ScannerBackend, ScanResult
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
        assert config.ignore_rules == {}
        assert config.skip_clear_files is False
        assert config.allowed_clear_files == []
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
        config = GuardConfig.from_dict({"guard": {"scanners": ["native"]}})

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
        config = GuardConfig.from_dict({"guard": {"fail_on_severity": "invalid"}})

        assert config.fail_on_severity == FindingSeverity.HIGH

    def test_config_from_dict_with_string_scanner(self):
        """Test config handles scanners as a string."""
        config = GuardConfig.from_dict({"guard": {"scanners": "gitleaks"}})

        assert config.use_native is False
        assert config.use_gitleaks is True

    def test_config_with_ignore_rules(self):
        """Test config with ignore_rules from dict."""
        config = GuardConfig.from_dict(
            {
                "guard": {
                    "ignore_rules": {
                        "ftp-password": ["**/*.json"],
                        "django-secret-key": ["**/test_settings.py"],
                    }
                }
            }
        )

        assert config.ignore_rules == {
            "ftp-password": ["**/*.json"],
            "django-secret-key": ["**/test_settings.py"],
        }

    def test_config_with_skip_clear_files(self):
        """Test config with skip_clear_files."""
        config = GuardConfig(skip_clear_files=True)
        assert config.skip_clear_files is True

    def test_config_with_allowed_clear_files(self):
        """Test config with allowed_clear_files."""
        config = GuardConfig(allowed_clear_files=[".env.production.clear"])
        assert config.allowed_clear_files == [".env.production.clear"]


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
        gitleaks_mod.GitleaksScanner = make_scanner("GitleaksScanner", "gitleaks", True)
        truffle_mod = types.ModuleType("envdrift.scanner.trufflehog")
        truffle_mod.TrufflehogScanner = make_scanner("TrufflehogScanner", "trufflehog", True)
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
        gitleaks_mod.GitleaksScanner = make_scanner("GitleaksScanner", "gitleaks")
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
        gitleaks_mod.GitleaksScanner = make_scanner("GitleaksScanner", "gitleaks")
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

        result = engine.scan([Path()])

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

    def test_deduplicate_skip_duplicate_by_secret_value(self):
        """Test skip_duplicate deduplicates by secret value only."""
        config = GuardConfig(use_native=True, use_gitleaks=False, skip_duplicate=True)
        engine = ScanEngine(config)

        # Same secret appearing in different files
        findings = [
            ScanFinding(
                file_path=Path("config1.py"),
                line_number=10,
                rule_id="aws-key",
                rule_description="AWS Key",
                description="AWS Key found",
                severity=FindingSeverity.HIGH,
                scanner="native",
                secret_preview="AKIA****XXXX",
            ),
            ScanFinding(
                file_path=Path("config2.py"),
                line_number=20,
                rule_id="aws-key",
                rule_description="AWS Key",
                description="AWS Key found",
                severity=FindingSeverity.HIGH,
                scanner="gitleaks",
                secret_preview="AKIA****XXXX",  # Same secret value
            ),
        ]

        unique = engine._deduplicate(findings)

        # Should be deduplicated to 1 since same secret_preview
        assert len(unique) == 1

    def test_deduplicate_skip_duplicate_keeps_different_secrets(self):
        """Test skip_duplicate keeps findings with different secret values."""
        config = GuardConfig(use_native=True, use_gitleaks=False, skip_duplicate=True)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=Path("config.py"),
                line_number=10,
                rule_id="aws-key",
                rule_description="AWS Key",
                description="AWS Key found",
                severity=FindingSeverity.HIGH,
                scanner="native",
                secret_preview="AKIA****XXXX",
            ),
            ScanFinding(
                file_path=Path("config.py"),
                line_number=20,
                rule_id="aws-key",
                rule_description="AWS Key",
                description="AWS Key found",
                severity=FindingSeverity.HIGH,
                scanner="native",
                secret_preview="AKIA****YYYY",  # Different secret value
            ),
        ]

        unique = engine._deduplicate(findings)

        # Should keep both since different secret values
        assert len(unique) == 2

    def test_deduplicate_skip_duplicate_disabled_keeps_all_locations(self):
        """Test that with skip_duplicate=False, same secret in different locations is kept."""
        config = GuardConfig(use_native=True, use_gitleaks=False, skip_duplicate=False)
        engine = ScanEngine(config)

        # Same secret appearing in different files
        findings = [
            ScanFinding(
                file_path=Path("config1.py"),
                line_number=10,
                rule_id="aws-key",
                rule_description="AWS Key",
                description="AWS Key found",
                severity=FindingSeverity.HIGH,
                scanner="native",
                secret_preview="AKIA****XXXX",
            ),
            ScanFinding(
                file_path=Path("config2.py"),
                line_number=20,
                rule_id="aws-key",
                rule_description="AWS Key",
                description="AWS Key found",
                severity=FindingSeverity.HIGH,
                scanner="native",
                secret_preview="AKIA****XXXX",  # Same secret value
            ),
        ]

        unique = engine._deduplicate(findings)

        # Should keep both since they're in different files
        assert len(unique) == 2


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
        (tmp_path / "config.py").write_text('SECRET = "aB3xK9mN2pQ5vR8tY1wZ4cF7hJ0kL6"\n')

        result = engine.scan([tmp_path])

        entropy_findings = [f for f in result.unique_findings if f.rule_id == "high-entropy-string"]
        assert len(entropy_findings) >= 1

    def test_scan_with_skip_clear_files(self, tmp_path: Path):
        """Test scan with skip_clear_files enabled."""
        config = GuardConfig(
            use_native=True,
            use_gitleaks=False,
            skip_clear_files=True,
        )
        engine = ScanEngine(config)

        # Create .clear file with secret - should be skipped
        (tmp_path / ".env.production.clear").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')

        result = engine.scan([tmp_path])

        # No findings because .clear file is skipped
        assert result.total_findings == 0

    def test_scan_without_skip_clear_files(self, tmp_path: Path):
        """Test scan without skip_clear_files (default behavior)."""
        config = GuardConfig(
            use_native=True,
            use_gitleaks=False,
            skip_clear_files=False,
        )
        engine = ScanEngine(config)

        # Create .clear file with secret - should be scanned
        (tmp_path / ".env.production.clear").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')

        result = engine.scan([tmp_path])

        # Should have findings from .clear file
        assert result.total_findings >= 1

    def test_scan_with_ignore_rules(self, tmp_path: Path):
        """Test scan with ignore_rules filters findings."""
        config = GuardConfig(
            use_native=True,
            use_gitleaks=False,
            ignore_rules={"aws-access-key-id": ["**/ignored/**"]},
        )
        engine = ScanEngine(config)

        # Create file in ignored path
        ignored_dir = tmp_path / "ignored"
        ignored_dir.mkdir()
        (ignored_dir / "config.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')

        # Create file in non-ignored path
        (tmp_path / "config.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')

        result = engine.scan([tmp_path])

        # Should only have finding from non-ignored path
        aws_findings = [f for f in result.unique_findings if "aws" in f.rule_id.lower()]
        # Only the one in the root should be found
        ignored_findings = [f for f in aws_findings if "ignored" in str(f.file_path)]
        assert len(ignored_findings) == 0

    def test_scan_with_inline_ignore_comments(self, tmp_path: Path):
        """Test scan respects inline ignore comments."""
        config = GuardConfig(
            use_native=True,
            use_gitleaks=False,
        )
        engine = ScanEngine(config)

        # Create file with secret that has inline ignore
        (tmp_path / "config.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # envdrift:ignore\n')

        result = engine.scan([tmp_path])

        # Finding should be filtered by inline ignore
        aws_findings = [f for f in result.unique_findings if "aws" in f.rule_id.lower()]
        assert len(aws_findings) == 0

    def test_scan_with_inline_ignore_specific_rule(self, tmp_path: Path):
        """Test scan respects inline ignore with specific rule."""
        config = GuardConfig(
            use_native=True,
            use_gitleaks=False,
        )
        engine = ScanEngine(config)

        # Create file with secret that has rule-specific inline ignore
        (tmp_path / "config.py").write_text(
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # envdrift:ignore:aws-access-key-id\n'
        )

        result = engine.scan([tmp_path])

        # AWS finding should be filtered
        aws_findings = [f for f in result.unique_findings if f.rule_id == "aws-access-key-id"]
        assert len(aws_findings) == 0


class TestFilterEncryptedFiles:
    """Tests for _filter_encrypted_files method."""

    def test_filter_encrypted_files_empty_list(self):
        """Test filter with empty findings list."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        result = engine._filter_encrypted_files([])
        assert result == []

    def test_filter_encrypted_files_no_encrypted_markers(self, tmp_path):
        """Test that findings from regular files are not filtered."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=tmp_path / "config.py",
                rule_id="test-rule",
                rule_description="Test",
                description="Test finding",
                severity=FindingSeverity.HIGH,
                scanner="native",
            ),
        ]

        result = engine._filter_encrypted_files(findings)
        assert len(result) == 1

    def test_filter_encrypted_files_with_sops_file(self, tmp_path):
        """Test that findings from SOPS encrypted files are filtered."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        # Create a SOPS encrypted file
        sops_file = tmp_path / "secrets.sops.yaml"
        sops_file.write_text("sops:\n  kms: []\n  encrypted_regex: .*\n")

        findings = [
            ScanFinding(
                file_path=sops_file,
                rule_id="test-rule",
                rule_description="Test",
                description="Test finding",
                severity=FindingSeverity.HIGH,
                scanner="native",
            ),
        ]

        result = engine._filter_encrypted_files(findings)
        # Should be filtered due to SOPS encryption markers
        assert len(result) == 0

    def test_filter_encrypted_files_with_dotenvx_file(self, tmp_path):
        """Test that findings from dotenvx encrypted files are filtered."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        # Create a dotenvx encrypted file with encryption marker
        # Must contain 'encrypted:' to be detected as encrypted
        dotenvx_file = tmp_path / ".env.encrypted"
        dotenvx_file.write_text(
            '#/-------------------[DOTENV_PUBLIC_KEY]--------------------/\nSECRET="encrypted:abc123"\n'
        )

        findings = [
            ScanFinding(
                file_path=dotenvx_file,
                rule_id="test-rule",
                rule_description="Test",
                description="Test finding",
                severity=FindingSeverity.HIGH,
                scanner="native",
            ),
        ]

        result = engine._filter_encrypted_files(findings)
        # Should be filtered due to dotenvx encryption markers
        assert len(result) == 0


class TestFilterPublicKeys:
    """Tests for _filter_public_keys method."""

    def test_filter_public_keys_empty_list(self):
        """Test filter with empty findings list."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        result = engine._filter_public_keys([])
        assert result == []

    def test_filter_public_keys_ec_compressed_key(self):
        """Test that EC compressed public keys are filtered."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        # EC secp256k1 compressed public key - exactly 66 hex chars starting with 02 or 03
        ec_pubkey = "02" + "a" * 64  # 66 chars total

        findings = [
            ScanFinding(
                file_path=Path("test.py"),
                rule_id="test-rule",
                rule_description="Test",
                description="Test finding",
                severity=FindingSeverity.HIGH,
                scanner="native",
                secret_preview=ec_pubkey,
            ),
        ]

        result = engine._filter_public_keys(findings)
        assert len(result) == 0

    def test_filter_public_keys_short_hex_not_filtered(self):
        """Test that short hex strings starting with 02/03 are NOT filtered."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        # Short hex that starts with 02 but is not a full EC public key
        short_secret = "0200abcd"

        findings = [
            ScanFinding(
                file_path=Path("test.py"),
                rule_id="test-rule",
                rule_description="Test",
                description="Test finding",
                severity=FindingSeverity.HIGH,
                scanner="native",
                secret_preview=short_secret,
            ),
        ]

        result = engine._filter_public_keys(findings)
        # Should NOT be filtered - too short to be an EC public key
        assert len(result) == 1

    def test_filter_public_keys_non_hex_not_filtered(self):
        """Test that non-hex strings are not filtered."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        # Starts with 02 but contains non-hex characters
        non_hex = "02" + "g" * 64  # 'g' is not hex

        findings = [
            ScanFinding(
                file_path=Path("test.py"),
                rule_id="test-rule",
                rule_description="Test",
                description="Test finding",
                severity=FindingSeverity.HIGH,
                scanner="native",
                secret_preview=non_hex,
            ),
        ]

        result = engine._filter_public_keys(findings)
        # Should NOT be filtered - not valid hex
        assert len(result) == 1

    def test_filter_public_keys_preserves_normal_findings(self):
        """Test that normal findings are not filtered."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=Path("test.py"),
                rule_id="test-rule",
                rule_description="Test",
                description="Test finding",
                severity=FindingSeverity.HIGH,
                scanner="native",
                secret_preview="AKIA****WXYZ",  # AWS key preview
            ),
        ]

        result = engine._filter_public_keys(findings)
        assert len(result) == 1


class TestGitignoreFilter:
    """Tests for gitignore-based filtering."""

    def test_filter_gitignored_files_empty_list(self):
        """Test filter with empty findings list."""
        config = GuardConfig(use_native=True, use_gitleaks=False, skip_gitignored=True)
        engine = ScanEngine(config)

        result = engine._filter_gitignored_files([])
        assert result == []

    def test_filter_gitignored_files_no_git(self, tmp_path, monkeypatch):
        """Test filter when git is not available."""
        import subprocess

        config = GuardConfig(use_native=True, use_gitleaks=False, skip_gitignored=True)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=Path("test.py"),
                rule_id="test-rule",
                rule_description="Test",
                description="Test finding",
                severity=FindingSeverity.HIGH,
                scanner="native",
            ),
        ]

        # Mock subprocess.run to raise FileNotFoundError (git not found)
        def mock_run(*args, **kwargs):
            raise FileNotFoundError("git not found")

        monkeypatch.setattr(subprocess, "run", mock_run)

        result = engine._filter_gitignored_files(findings)
        # Should return original findings when git is not available
        assert len(result) == 1

    def test_filter_gitignored_files_filters_ignored(self, tmp_path, monkeypatch):
        """Test that gitignored files are filtered."""
        import subprocess

        config = GuardConfig(use_native=True, use_gitleaks=False, skip_gitignored=True)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=Path("ignored.py"),
                rule_id="test-rule",
                rule_description="Test",
                description="Test finding",
                severity=FindingSeverity.HIGH,
                scanner="native",
            ),
            ScanFinding(
                file_path=Path("tracked.py"),
                rule_id="test-rule",
                rule_description="Test",
                description="Test finding",
                severity=FindingSeverity.HIGH,
                scanner="native",
            ),
        ]

        # Mock subprocess.run to return "ignored.py" as gitignored
        def mock_run(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 0, stdout="ignored.py\n", stderr="")

        monkeypatch.setattr(subprocess, "run", mock_run)

        result = engine._filter_gitignored_files(findings)
        # Should only have "tracked.py"
        assert len(result) == 1
        assert result[0].file_path == Path("tracked.py")

    def test_config_skip_gitignored_default_false(self):
        """Test that skip_gitignored defaults to False."""
        config = GuardConfig()
        assert config.skip_gitignored is False

    def test_config_skip_gitignored_can_be_enabled(self):
        """Test that skip_gitignored can be enabled."""
        config = GuardConfig(skip_gitignored=True)
        assert config.skip_gitignored is True


class TestCombinedFilesSecurity:
    """Tests for combined files security check."""

    def test_no_combined_files(self):
        """Test check with no combined files."""
        config = GuardConfig(use_native=True, use_gitleaks=False, combined_files=[])
        engine = ScanEngine(config)

        warnings = engine.check_combined_files_security()
        assert warnings == []

    def test_combined_file_in_gitignore(self, monkeypatch):
        """Test that combined file in gitignore produces no warning."""
        import subprocess

        config = GuardConfig(
            use_native=True,
            use_gitleaks=False,
            combined_files=[".env.production"],
        )
        engine = ScanEngine(config)

        # Mock subprocess.run to return the file as gitignored (batched stdin approach)
        def mock_run(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 0, stdout=".env.production\n", stderr="")

        monkeypatch.setattr(subprocess, "run", mock_run)

        warnings = engine.check_combined_files_security()
        assert warnings == []

    def test_combined_file_not_in_gitignore(self, monkeypatch):
        """Test that combined file NOT in gitignore produces warning."""
        import subprocess

        config = GuardConfig(
            use_native=True,
            use_gitleaks=False,
            combined_files=[".env.production"],
        )
        engine = ScanEngine(config)

        # Mock subprocess.run to return empty (file is NOT ignored - batched approach)
        def mock_run(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", mock_run)

        warnings = engine.check_combined_files_security()
        assert len(warnings) == 1
        assert "SECURITY WARNING" in warnings[0]
        assert ".env.production" in warnings[0]

    def test_combined_files_git_not_available(self, monkeypatch):
        """Test graceful handling when git is not available."""
        import subprocess

        config = GuardConfig(
            use_native=True,
            use_gitleaks=False,
            combined_files=[".env.production"],
        )
        engine = ScanEngine(config)

        # Mock subprocess.run to raise FileNotFoundError
        def mock_run(*args, **kwargs):
            raise FileNotFoundError("git not found")

        monkeypatch.setattr(subprocess, "run", mock_run)

        # Should not raise, just return empty warnings
        warnings = engine.check_combined_files_security()
        assert warnings == []

    def test_combined_files_multiple_files(self, monkeypatch):
        """Test with multiple combined files, some in gitignore, some not."""
        import subprocess

        config = GuardConfig(
            use_native=True,
            use_gitleaks=False,
            combined_files=[".env.production", ".env.staging", ".env.dev"],
        )
        engine = ScanEngine(config)

        # Mock subprocess.run - only .env.production is gitignored
        def mock_run(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 0, stdout=".env.production\n", stderr="")

        monkeypatch.setattr(subprocess, "run", mock_run)

        warnings = engine.check_combined_files_security()
        # Should have 2 warnings for .env.staging and .env.dev
        assert len(warnings) == 2
        assert any(".env.staging" in w for w in warnings)
        assert any(".env.dev" in w for w in warnings)
        assert not any(".env.production" in w for w in warnings)
