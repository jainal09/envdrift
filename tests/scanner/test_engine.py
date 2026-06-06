"""Tests for scan engine module."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from envdrift.scanner.base import (
    AggregatedScanResult,
    FindingSeverity,
    ScanFinding,
    ScannerBackend,
    ScanResult,
)
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

    def test_config_from_dict_partial_encryption_files(self):
        """from_dict must preserve allowed_clear_files/combined_files (issue #314).

        Previously from_dict dropped partial_encryption awareness, so declared
        .clear files were flagged as unencrypted and combined-file security
        checks returned nothing for SDK callers.
        """
        config = GuardConfig.from_dict(
            {
                "guard": {"scanners": ["native"]},
                "partial_encryption": {
                    "enabled": True,
                    "environments": [
                        {
                            "clear_file": ".env.production.clear",
                            "combined_file": ".env.production",
                        },
                        {
                            "clear_file": ".env.staging.clear",
                            "combined_file": ".env.staging",
                        },
                    ],
                },
            }
        )

        assert config.allowed_clear_files == [
            ".env.production.clear",
            ".env.staging.clear",
        ]
        assert config.combined_files == [".env.production", ".env.staging"]

    def test_config_from_dict_partial_encryption_disabled(self):
        """Disabled partial_encryption yields no clear/combined files."""
        config = GuardConfig.from_dict(
            {
                "partial_encryption": {
                    "enabled": False,
                    "environments": [
                        {
                            "clear_file": ".env.production.clear",
                            "combined_file": ".env.production",
                        }
                    ],
                }
            }
        )

        assert config.allowed_clear_files == []
        assert config.combined_files == []

    def test_config_from_dict_mapped_env_files(self, tmp_path):
        """from_dict must resolve vault.sync mapped env files (issue #314)."""
        folder = tmp_path / "service"
        folder.mkdir()
        config = GuardConfig.from_dict(
            {
                "vault": {
                    "sync": {
                        "mappings": [
                            {
                                "secret_name": "svc-secret",
                                "folder_path": str(folder),
                                "env_file": "custom.env",
                            }
                        ]
                    }
                }
            }
        )

        expected = str((folder / "custom.env").resolve())
        assert config.mapped_env_files == [expected]

    def test_config_from_dict_mapped_env_file_escape_is_skipped(self, tmp_path):
        """An env_file that escapes folder_path is skipped, not raised."""
        folder = tmp_path / "service"
        folder.mkdir()
        config = GuardConfig.from_dict(
            {
                "vault": {
                    "sync": {
                        "mappings": [
                            {
                                "secret_name": "svc-secret",
                                "folder_path": str(folder),
                                "env_file": "../escape.env",
                            }
                        ]
                    }
                }
            }
        )

        assert config.mapped_env_files == []

    def test_config_from_dict_mapped_env_file_incomplete_mapping_skipped(self, tmp_path):
        """A mapping missing env_file or folder_path is skipped, not raised.

        Covers the guard branch that drops incomplete vault.sync mappings so a
        partially-specified config cannot crash :meth:`GuardConfig.from_dict`.
        """
        folder = tmp_path / "service"
        folder.mkdir()
        config = GuardConfig.from_dict(
            {
                "vault": {
                    "sync": {
                        "mappings": [
                            # Missing env_file.
                            {"secret_name": "a", "folder_path": str(folder)},
                            # Missing folder_path.
                            {"secret_name": "b", "env_file": "custom.env"},
                            # Empty values are also treated as missing.
                            {"secret_name": "c", "folder_path": "", "env_file": ""},
                            # Fully specified -> resolved.
                            {
                                "secret_name": "d",
                                "folder_path": str(folder),
                                "env_file": "ok.env",
                            },
                        ]
                    }
                }
            }
        )

        # Only the complete mapping survives; the incomplete ones are skipped.
        assert config.mapped_env_files == [str((folder / "ok.env").resolve())]

    def test_config_from_dict_skips_non_dict_entries(self, tmp_path):
        """Malformed (non-dict) environments/mappings entries are skipped, not raised.

        from_dict is a pure constructor for SDK callers, so a bad config
        (None / strings / lists where a dict is expected) must be ignored rather
        than crashing with AttributeError on ``.get``.
        """
        folder = tmp_path / "service"
        folder.mkdir()
        config = GuardConfig.from_dict(
            {
                "partial_encryption": {
                    "enabled": True,
                    "environments": [
                        None,
                        "oops",
                        ["list", "entry"],
                        {"clear_file": ".env.production.clear"},
                    ],
                },
                "vault": {
                    "sync": {
                        "mappings": [
                            None,
                            "not-a-mapping",
                            {"folder_path": str(folder), "env_file": "ok.env"},
                        ]
                    }
                },
            }
        )

        # The single valid entry in each list survives; the junk is skipped.
        assert config.allowed_clear_files == [".env.production.clear"]
        assert config.mapped_env_files == [str((folder / "ok.env").resolve())]


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

        gitleaks_mod = SimpleNamespace(
            GitleaksScanner=make_scanner("GitleaksScanner", "gitleaks", True),
        )
        truffle_mod = SimpleNamespace(
            TrufflehogScanner=make_scanner("TrufflehogScanner", "trufflehog", True),
        )
        detect_mod = SimpleNamespace(
            DetectSecretsScanner=make_scanner("DetectSecretsScanner", "detect-secrets", True),
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

        gitleaks_mod = SimpleNamespace(
            GitleaksScanner=make_scanner("GitleaksScanner", "gitleaks"),
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

        gitleaks_mod = SimpleNamespace(
            GitleaksScanner=make_scanner("GitleaksScanner", "gitleaks"),
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

    def test_deduplicate_prefers_secret_hash(self):
        """Test that deduplication prefers findings with secret_hash when tied."""
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
                verified=False,
                secret_hash="hash-123",
            ),
        ]

        unique = engine._deduplicate(findings)

        assert len(unique) == 1
        assert unique[0].secret_hash == "hash-123"

    def test_deduplicate_deterministic_tie_breaker(self):
        """Test deterministic tie-breaker for equal findings."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        finding_a = ScanFinding(
            file_path=Path("config.py"),
            line_number=10,
            rule_id="secret",
            rule_description="Secret",
            description="Secret",
            severity=FindingSeverity.HIGH,
            scanner="a-scanner",
            verified=False,
            secret_hash="hash-123",
        )
        finding_b = ScanFinding(
            file_path=Path("config.py"),
            line_number=10,
            rule_id="secret",
            rule_description="Secret",
            description="Secret",
            severity=FindingSeverity.HIGH,
            scanner="b-scanner",
            verified=False,
            secret_hash="hash-123",
        )

        unique_first = engine._deduplicate([finding_b, finding_a])
        unique_second = engine._deduplicate([finding_a, finding_b])

        assert len(unique_first) == 1
        assert len(unique_second) == 1
        assert unique_first[0].scanner == unique_second[0].scanner == "a-scanner"

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

    def test_deduplicate_skip_duplicate_prefers_secret_hash_key(self):
        """Test skip_duplicate uses secret_hash as key when available."""
        config = GuardConfig(use_native=True, use_gitleaks=False, skip_duplicate=True)
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
                secret_preview="PREVIEW-1",
                secret_hash="hash-xyz",
            ),
            ScanFinding(
                file_path=Path("config2.py"),
                line_number=20,
                rule_id="secret",
                rule_description="Secret",
                description="Secret",
                severity=FindingSeverity.HIGH,
                scanner="gitleaks",
                secret_preview="PREVIEW-2",
                secret_hash="hash-xyz",
            ),
        ]

        unique = engine._deduplicate(findings)

        # Should deduplicate to 1 since secret_hash matches
        assert len(unique) == 1

    def test_deduplicate_skip_duplicate_fallback_location(self):
        """Test skip_duplicate falls back to location when no secret value is present."""
        config = GuardConfig(use_native=True, use_gitleaks=False, skip_duplicate=True)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=Path("policy.json"),
                line_number=5,
                rule_id="policy-violation",
                rule_description="Policy",
                description="Policy finding",
                severity=FindingSeverity.MEDIUM,
                scanner="scanner1",
            ),
            ScanFinding(
                file_path=Path("policy.json"),
                line_number=5,
                rule_id="policy-violation",
                rule_description="Policy",
                description="Policy finding",
                severity=FindingSeverity.MEDIUM,
                scanner="scanner2",
            ),
        ]

        unique = engine._deduplicate(findings)

        # Should be deduplicated by location since no secret_hash/preview
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

    def test_scan_results_are_deterministic(self, tmp_path: Path):
        """Repeated scans return stable ordering and counts."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        # Create files in a nested structure to exercise os.walk ordering
        (tmp_path / "b").mkdir()
        (tmp_path / "a").mkdir()
        (tmp_path / "b" / "config.py").write_text('AWS_KEY="AKIAIOSFODNN7EXAMPLE"\n')
        (tmp_path / "a" / ".env").write_text("DATABASE_URL=postgres://localhost/db\n")
        (tmp_path / "root.env").write_text("TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n")

        def snapshot(result: AggregatedScanResult) -> list[tuple]:
            return [
                (
                    f.rule_id,
                    str(f.file_path),
                    f.line_number or 0,
                    f.severity.value,
                    f.scanner,
                )
                for f in result.unique_findings
            ]

        first = snapshot(engine.scan([tmp_path]))
        second = snapshot(engine.scan([tmp_path]))
        third = snapshot(engine.scan([tmp_path]))

        assert first == second == third

    def test_scan_skip_duplicate_deduplicates_stably(self, tmp_path: Path):
        """skip_duplicate yields stable, deterministic deduplication across runs."""
        config = GuardConfig(use_native=True, use_gitleaks=False, skip_duplicate=True)
        engine = ScanEngine(config)

        secret_line = 'AWS_KEY="AKIAIOSFODNN7EXAMPLE"\n'
        (tmp_path / "a.py").write_text(secret_line)
        (tmp_path / "b.py").write_text(secret_line)

        result = engine.scan([tmp_path])
        aws_findings = [f for f in result.unique_findings if f.rule_id == "aws-access-key-id"]
        assert len(aws_findings) == 1
        assert aws_findings[0].file_path.name == "a.py"

        repeat = engine.scan([tmp_path])
        repeat_findings = [f for f in repeat.unique_findings if f.rule_id == "aws-access-key-id"]
        assert len(repeat_findings) == 1
        assert repeat_findings[0].file_path.name == "a.py"


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

    def test_filter_keeps_cleartext_line_finding_in_combined_file(self, tmp_path):
        """A finding on the cleartext line of a combined file must survive the filter.

        Regression: the filter used to drop every finding from any file containing
        an ``encrypted:`` marker, which discarded real secrets pasted into the
        cleartext half of a partial-encryption combined file (the whole point of
        the line-level S4 scan). The cleartext finding must reach guard.
        """
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        combined = tmp_path / ".env.production"
        combined.write_text(
            "#/---[DOTENV_PUBLIC_KEY]---/\n"  # line 1
            "LOG_LEVEL=info\n"  # line 2
            'AWS_KEY="AKIAIOSFODNN7EXAMPLE"\n'  # line 3 (cleartext secret)
            'SECRET="encrypted:vault1xyz"\n'  # line 4 (ciphertext)
        )

        cleartext_finding = ScanFinding(
            file_path=combined,
            line_number=3,
            rule_id="aws-access-key-id",
            rule_description="AWS key",
            description="cleartext secret",
            severity=FindingSeverity.CRITICAL,
            scanner="native",
        )
        ciphertext_finding = ScanFinding(
            file_path=combined,
            line_number=4,
            rule_id="high-entropy-string",
            rule_description="entropy",
            description="ciphertext blob",
            severity=FindingSeverity.MEDIUM,
            scanner="detect-secrets",
        )

        result = engine._filter_encrypted_files([cleartext_finding, ciphertext_finding])

        kept = {(f.rule_id, f.line_number) for f in result}
        assert ("aws-access-key-id", 3) in kept, "cleartext-line finding must survive"
        assert ("high-entropy-string", 4) not in kept, "ciphertext-line finding must be dropped"

    def test_filter_drops_lineless_finding_in_encrypted_file(self, tmp_path):
        """A finding with no line info on an encrypted file is still dropped.

        External scanners that flag a high-entropy ciphertext blob without a line
        number must keep being suppressed (the original false-positive guard).
        """
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        enc = tmp_path / ".env.encrypted"
        enc.write_text('SECRET="encrypted:abc123"\n')

        finding = ScanFinding(
            file_path=enc,
            line_number=None,
            rule_id="high-entropy-string",
            rule_description="entropy",
            description="blob",
            severity=FindingSeverity.MEDIUM,
            scanner="detect-secrets",
        )

        assert engine._filter_encrypted_files([finding]) == []

    def test_filter_encrypted_marker_beyond_2kb_still_filters(self, tmp_path):
        """#368: the dotenvx ``encrypted:`` marker can sit far past the first 2KB
        in a combined file (cleartext config first, encrypted secrets after).

        The old 2KB-only read misjudged such files as unencrypted and leaked
        their ciphertext lines as findings. Reading the whole file recognizes the
        marker and drops the ciphertext finding.
        """
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        f = tmp_path / ".env.production"
        filler = "".join(
            f"CONFIG_{i}=plain_padding_value_xxxxxxxxxxxxxxxxxxxxxxxx\n" for i in range(60)
        )
        assert len(filler) > 2048  # marker is genuinely beyond the old window
        f.write_text(filler + 'SECRET="encrypted:vault1GENUINECIPHERTEXTblob+/="\n')
        cipher_line = filler.count("\n") + 1

        finding = ScanFinding(
            file_path=f,
            line_number=cipher_line,
            rule_id="high-entropy-string",
            rule_description="entropy",
            description="blob",
            severity=FindingSeverity.MEDIUM,
            scanner="detect-secrets",
        )
        assert engine._filter_encrypted_files([finding]) == []

    def test_filter_cleartext_finding_survives_when_marker_beyond_2kb(self, tmp_path):
        """#368 regression-guard: a finding on a *cleartext* line of the same
        combined file (whose marker is past 2KB) must still survive."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        f = tmp_path / ".env.production"
        filler = "".join(
            f"CONFIG_{i}=plain_padding_value_xxxxxxxxxxxxxxxxxxxxxxxx\n" for i in range(60)
        )
        assert len(filler) > 2048
        f.write_text(filler + 'SECRET="encrypted:vault1CIPHERTEXTblob+/="\n')

        cleartext_finding = ScanFinding(
            file_path=f,
            line_number=1,  # a cleartext CONFIG_0 line
            rule_id="generic-secret",
            rule_description="secret",
            description="cleartext",
            severity=FindingSeverity.HIGH,
            scanner="native",
        )
        result = engine._filter_encrypted_files([cleartext_finding])
        assert result == [cleartext_finding]


class TestFilterPublicKeys:
    """Tests for _filter_public_keys (#370).

    The filter operates on *production* data: findings carry a redacted
    ``secret_preview`` and a one-way ``secret_hash`` — never the full secret.
    Public keys are identified by hashing the file's own ``DOTENV_PUBLIC_KEY*``
    declaration and matching ``secret_hash``. The previous raw-un-redacted-preview
    tests were invalid (the pipeline never produces a 66-char preview) and masked
    the bug; these tests reflect the real pipeline.
    """

    def test_filter_public_keys_empty_list(self):
        """Test filter with empty findings list."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        result = engine._filter_public_keys([])
        assert result == []

    def test_filter_public_keys_by_hash_with_redacted_preview(self, tmp_path):
        """A finding carrying the file's DOTENV_PUBLIC_KEY value (matched by
        ``secret_hash``) is filtered, even though its preview is redacted."""
        from envdrift.scanner.patterns import hash_secret, redact_secret

        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        pubkey = "02" + "a" * 64  # 66-hex compressed EC public key
        env_file = tmp_path / ".env"
        env_file.write_text(f'DOTENV_PUBLIC_KEY="{pubkey}"\nSECRET="encrypted:xyz"\n')

        pub_finding = ScanFinding(
            file_path=env_file,
            rule_id="high-entropy-string",
            rule_description="entropy",
            description="x",
            severity=FindingSeverity.MEDIUM,
            scanner="gitleaks",
            secret_preview=redact_secret(pubkey),  # PRODUCTION form (redacted)
            secret_hash=hash_secret(pubkey),
        )

        result = engine._filter_public_keys([pub_finding])
        assert result == []

    def test_filter_public_keys_preserves_real_secret(self, tmp_path):
        """A real secret (whose hash is not the file's public key) survives."""
        from envdrift.scanner.patterns import hash_secret, redact_secret

        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        pubkey = "03" + "b" * 64
        env_file = tmp_path / ".env"
        env_file.write_text(f'DOTENV_PUBLIC_KEY="{pubkey}"\n')

        real = "sk_live_" + "realsecretvalue0123456789"  # split: dodge push-protection
        real_finding = ScanFinding(
            file_path=env_file,
            rule_id="generic-secret",
            rule_description="secret",
            description="x",
            severity=FindingSeverity.HIGH,
            scanner="gitleaks",
            secret_preview=redact_secret(real),
            secret_hash=hash_secret(real),
        )

        result = engine._filter_public_keys([real_finding])
        assert result == [real_finding]

    def test_filter_public_keys_unreadable_file_swallows_oserror(self, tmp_path):
        """A finding whose file can't be opened doesn't crash pubkey collection (#370)."""
        from envdrift.scanner.patterns import hash_secret, redact_secret

        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        real = "sk_live_" + "anotherrealsecretvalue012345"  # split: dodge push-protection
        finding = ScanFinding(
            file_path=tmp_path / "does-not-exist.env",  # open() -> OSError -> skipped
            rule_id="generic-secret",
            rule_description="secret",
            description="x",
            severity=FindingSeverity.HIGH,
            scanner="gitleaks",
            secret_preview=redact_secret(real),
            secret_hash=hash_secret(real),
        )

        # No public keys are collectible (file unreadable), so the finding
        # survives and no exception escapes.
        result = engine._filter_public_keys([finding])
        assert result == [finding]

    def test_filter_public_keys_mixed_findings(self, tmp_path):
        """In a mixed batch only the public-key finding is dropped."""
        from envdrift.scanner.patterns import hash_secret, redact_secret

        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        pubkey = "02" + "c" * 64
        env_file = tmp_path / ".env"
        env_file.write_text(f"DOTENV_PUBLIC_KEY={pubkey}\nSECRET=encrypted:xyz\n")

        real = "ghp_realgithubtoken0123456789abcdef0123"
        pub_finding = ScanFinding(
            file_path=env_file,
            rule_id="high-entropy-string",
            rule_description="entropy",
            description="x",
            severity=FindingSeverity.MEDIUM,
            scanner="trufflehog",
            secret_preview=redact_secret(pubkey),
            secret_hash=hash_secret(pubkey),
        )
        real_finding = ScanFinding(
            file_path=env_file,
            rule_id="github-pat",
            rule_description="GitHub PAT",
            description="x",
            severity=FindingSeverity.CRITICAL,
            scanner="trufflehog",
            secret_preview=redact_secret(real),
            secret_hash=hash_secret(real),
        )

        result = engine._filter_public_keys([pub_finding, real_finding])
        kept_rules = {f.rule_id for f in result}
        assert "high-entropy-string" not in kept_rules
        assert "github-pat" in kept_rules

    def test_filter_public_keys_no_pubkey_in_file_keeps_all(self, tmp_path):
        """When no file declares a public key, nothing is filtered."""
        from envdrift.scanner.patterns import hash_secret, redact_secret

        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=plainvalue123\n")  # no DOTENV_PUBLIC_KEY

        secret = "02" + "d" * 64  # pubkey-shaped value but not declared in file
        finding = ScanFinding(
            file_path=env_file,
            rule_id="high-entropy-string",
            rule_description="entropy",
            description="x",
            severity=FindingSeverity.MEDIUM,
            scanner="gitleaks",
            secret_preview=redact_secret(secret),
            secret_hash=hash_secret(secret),
        )

        # No DOTENV_PUBLIC_KEY line -> no known hashes -> finding survives.
        result = engine._filter_public_keys([finding])
        assert result == [finding]


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

        # Create a fake git repo structure
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        ignored_file = tmp_path / "ignored.py"
        tracked_file = tmp_path / "tracked.py"
        ignored_file.touch()
        tracked_file.touch()

        config = GuardConfig(use_native=True, use_gitleaks=False, skip_gitignored=True)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=ignored_file,
                rule_id="test-rule",
                rule_description="Test",
                description="Test finding",
                severity=FindingSeverity.HIGH,
                scanner="native",
            ),
            ScanFinding(
                file_path=tracked_file,
                rule_id="test-rule",
                rule_description="Test",
                description="Test finding",
                severity=FindingSeverity.HIGH,
                scanner="native",
            ),
        ]

        # Mock subprocess.run to return "ignored.py" as gitignored (null-separated)
        def mock_run(cmd, **kwargs):
            # git check-ignore with -z returns null-separated output
            return subprocess.CompletedProcess(cmd, 0, stdout="ignored.py\0", stderr="")

        monkeypatch.setattr(subprocess, "run", mock_run)

        result = engine._filter_gitignored_files(findings)
        # Should only have "tracked.py"
        assert len(result) == 1
        assert result[0].file_path == tracked_file

    def test_filter_gitignored_files_multiple_roots(self, tmp_path, monkeypatch):
        """Test gitignore filtering across multiple repo roots."""
        import subprocess

        repo1 = tmp_path / "repo1"
        repo2 = tmp_path / "repo2"
        repo1.mkdir()
        repo2.mkdir()
        (repo1 / ".git").mkdir()
        (repo2 / ".git").mkdir()

        ignored_file = repo1 / "ignored.txt"
        kept_file = repo2 / "kept.txt"
        ignored_file.touch()
        kept_file.touch()

        config = GuardConfig(use_native=True, use_gitleaks=False, skip_gitignored=True)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=ignored_file,
                rule_id="test-rule",
                rule_description="Test",
                description="Test finding",
                severity=FindingSeverity.HIGH,
                scanner="native",
            ),
            ScanFinding(
                file_path=kept_file,
                rule_id="test-rule",
                rule_description="Test",
                description="Test finding",
                severity=FindingSeverity.HIGH,
                scanner="native",
            ),
        ]

        calls: list[tuple[Path, str]] = []

        def mock_run(cmd, **kwargs):
            cwd = Path(kwargs.get("cwd") or ".")
            calls.append((cwd, kwargs.get("input") or ""))
            if cwd.name == "repo1":
                return subprocess.CompletedProcess(cmd, 0, stdout="ignored.txt\0", stderr="")
            if cwd.name == "repo2":
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", mock_run)

        result = engine._filter_gitignored_files(findings)
        assert len(result) == 1
        assert result[0].file_path == kept_file
        assert any("ignored.txt" in call_input for _cwd, call_input in calls)

    def test_filter_gitignored_files_outside_repo(self, tmp_path, monkeypatch):
        """Files outside any git repo are not filtered."""
        import subprocess

        file_outside = tmp_path / "outside.txt"
        file_outside.touch()

        config = GuardConfig(use_native=True, use_gitleaks=False, skip_gitignored=True)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=file_outside,
                rule_id="test-rule",
                rule_description="Test",
                description="Test finding",
                severity=FindingSeverity.HIGH,
                scanner="native",
            ),
        ]

        def mock_run(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", mock_run)

        result = engine._filter_gitignored_files(findings)
        assert len(result) == 1

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

    def test_push_gitignore_satisfies_security_check(self, tmp_path, monkeypatch):
        """The .gitignore entry push writes must satisfy guard's security check.

        push (`_ensure_combined_gitignore` → `ensure_gitignore_entries`) and guard
        (`check_combined_files_security`) must agree on the combined-file path so
        they don't contradict each other: push says "I ignored it", guard must see
        it as ignored. This uses real git to catch path-format mismatches.
        """
        import shutil
        import subprocess

        from envdrift.utils.git import ensure_gitignore_entries

        if shutil.which("git") is None:
            pytest.skip("git not available")

        subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
        monkeypatch.chdir(tmp_path)

        combined = ".env.production"
        config = GuardConfig(use_native=True, use_gitleaks=False, combined_files=[combined])
        engine = ScanEngine(config)

        # Before push protects it, guard must warn.
        assert any("SECURITY WARNING" in w for w in engine.check_combined_files_security())

        # push writes the .gitignore entry...
        added = ensure_gitignore_entries([Path(combined)])
        assert added == [combined]

        # ...and guard must now agree the file is protected (no contradiction).
        assert engine.check_combined_files_security() == []

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
