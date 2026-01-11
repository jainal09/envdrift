"""Tests for centralized ignore system."""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.scanner.base import FindingSeverity, ScanFinding
from envdrift.scanner.ignores import (
    IGNORE_PATTERN,
    IgnoreConfig,
    IgnoreFilter,
    parse_ignore_comment,
)


class TestIgnorePattern:
    """Tests for the IGNORE_PATTERN regex."""

    def test_matches_hash_comment(self):
        """Test matching # style ignore comment."""
        match = IGNORE_PATTERN.search("x = 1  # envdrift:ignore")
        assert match is not None

    def test_matches_double_slash_comment(self):
        """Test matching // style ignore comment."""
        match = IGNORE_PATTERN.search("const x = 1;  // envdrift:ignore")
        assert match is not None

    def test_matches_block_comment(self):
        """Test matching /* */ style ignore comment."""
        match = IGNORE_PATTERN.search("x = 1; /* envdrift:ignore */")
        assert match is not None

    def test_matches_with_rule_id(self):
        """Test matching ignore comment with specific rule ID."""
        match = IGNORE_PATTERN.search("x = 1  # envdrift:ignore:aws-access-key-id")
        assert match is not None
        assert match.group(1) == "aws-access-key-id"

    def test_matches_with_reason(self):
        """Test matching ignore comment with reason."""
        match = IGNORE_PATTERN.search('x = 1  # envdrift:ignore reason="test fixture"')
        assert match is not None
        assert match.group(2) == "test fixture"

    def test_matches_with_rule_and_reason(self):
        """Test matching ignore comment with both rule and reason."""
        match = IGNORE_PATTERN.search(
            "x = 1  # envdrift:ignore:django-secret-key reason='test settings'"
        )
        assert match is not None
        assert match.group(1) == "django-secret-key"
        assert match.group(2) == "test settings"

    def test_case_insensitive(self):
        """Test that pattern matching is case insensitive."""
        match = IGNORE_PATTERN.search("x = 1  # ENVDRIFT:IGNORE")
        assert match is not None

    def test_no_match_without_ignore(self):
        """Test that lines without ignore comment don't match."""
        match = IGNORE_PATTERN.search("x = 1  # just a comment")
        assert match is None


class TestParseIgnoreComment:
    """Tests for parse_ignore_comment function."""

    def test_basic_ignore(self):
        """Test parsing basic ignore comment."""
        has_ignore, rule_id, reason = parse_ignore_comment("x = 1  # envdrift:ignore")
        assert has_ignore is True
        assert rule_id is None
        assert reason is None

    def test_ignore_with_rule(self):
        """Test parsing ignore comment with rule ID."""
        has_ignore, rule_id, reason = parse_ignore_comment(
            "x = 1  # envdrift:ignore:django-secret-key"
        )
        assert has_ignore is True
        assert rule_id == "django-secret-key"
        assert reason is None

    def test_ignore_with_reason(self):
        """Test parsing ignore comment with reason."""
        has_ignore, rule_id, reason = parse_ignore_comment(
            'x = 1  # envdrift:ignore reason="test fixture"'
        )
        assert has_ignore is True
        assert rule_id is None
        assert reason == "test fixture"

    def test_no_ignore(self):
        """Test parsing line without ignore comment."""
        has_ignore, rule_id, reason = parse_ignore_comment("x = 1  # normal comment")
        assert has_ignore is False
        assert rule_id is None
        assert reason is None


class TestIgnoreConfig:
    """Tests for IgnoreConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = IgnoreConfig()
        assert config.ignore_paths == []
        assert config.ignore_rules == {}

    def test_from_dict_empty(self):
        """Test creating config from empty dict."""
        config = IgnoreConfig.from_dict({})
        assert config.ignore_paths == []
        assert config.ignore_rules == {}

    def test_from_dict_with_values(self):
        """Test creating config from dict with values."""
        config = IgnoreConfig.from_dict(
            {
                "guard": {
                    "ignore_paths": ["**/tests/**", "**/fixtures/**"],
                    "ignore_rules": {
                        "ftp-password": ["**/*.json"],
                        "django-secret-key": ["**/test_settings.py"],
                    },
                }
            }
        )
        assert config.ignore_paths == ["**/tests/**", "**/fixtures/**"]
        assert config.ignore_rules == {
            "ftp-password": ["**/*.json"],
            "django-secret-key": ["**/test_settings.py"],
        }

    def test_from_dict_missing_guard_section(self):
        """Test creating config when guard section is missing."""
        config = IgnoreConfig.from_dict({"other": "value"})
        assert config.ignore_paths == []
        assert config.ignore_rules == {}


class TestIgnoreFilter:
    """Tests for IgnoreFilter class."""

    @pytest.fixture
    def sample_finding(self, tmp_path: Path) -> ScanFinding:
        """Create a sample finding for testing."""
        return ScanFinding(
            rule_id="aws-access-key-id",
            rule_description="AWS Access Key ID",
            file_path=tmp_path / "config.py",
            line_number=5,
            description="AWS Access Key ID found",
            severity=FindingSeverity.CRITICAL,
            scanner="native",
        )

    def test_filter_empty_config(self, sample_finding: ScanFinding):
        """Test filter with empty config passes all findings."""
        filter_ = IgnoreFilter()
        result = filter_.filter([sample_finding])
        assert len(result) == 1
        assert result[0] == sample_finding

    def test_filter_no_findings(self):
        """Test filter with no findings."""
        filter_ = IgnoreFilter()
        result = filter_.filter([])
        assert result == []


class TestIgnoreFilterInlineComments:
    """Tests for inline ignore comment filtering."""

    def test_basic_ignore_filters_finding(self, tmp_path: Path):
        """Test that # envdrift:ignore filters a finding."""
        config_file = tmp_path / "config.py"
        config_file.write_text('SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"  # envdrift:ignore\n')

        finding = ScanFinding(
            rule_id="aws-access-key-id",
            rule_description="AWS Access Key ID",
            file_path=config_file,
            line_number=1,
            description="AWS key found",
            severity=FindingSeverity.CRITICAL,
            scanner="native",
        )

        filter_ = IgnoreFilter()
        result = filter_.filter([finding])

        assert len(result) == 0

    def test_ignore_with_specific_rule_matches(self, tmp_path: Path):
        """Test that ignore with specific rule ID only matches that rule."""
        config_file = tmp_path / "config.py"
        config_file.write_text(
            'KEY = "AKIAIOSFODNN7EXAMPLE"  # envdrift:ignore:aws-access-key-id\n'
        )

        finding = ScanFinding(
            rule_id="aws-access-key-id",
            rule_description="AWS Access Key ID",
            file_path=config_file,
            line_number=1,
            description="AWS key found",
            severity=FindingSeverity.CRITICAL,
            scanner="native",
        )

        filter_ = IgnoreFilter()
        result = filter_.filter([finding])

        assert len(result) == 0

    def test_ignore_with_different_rule_does_not_match(self, tmp_path: Path):
        """Test that ignore with different rule ID doesn't filter finding."""
        config_file = tmp_path / "config.py"
        config_file.write_text('KEY = "AKIAIOSFODNN7EXAMPLE"  # envdrift:ignore:github-token\n')

        finding = ScanFinding(
            rule_id="aws-access-key-id",
            rule_description="AWS Access Key ID",
            file_path=config_file,
            line_number=1,
            description="AWS key found",
            severity=FindingSeverity.CRITICAL,
            scanner="native",
        )

        filter_ = IgnoreFilter()
        result = filter_.filter([finding])

        assert len(result) == 1

    def test_ignore_on_different_line_does_not_filter(self, tmp_path: Path):
        """Test that ignore comment on different line doesn't filter."""
        config_file = tmp_path / "config.py"
        config_file.write_text('# envdrift:ignore\nKEY = "AKIAIOSFODNN7EXAMPLE"\n')

        finding = ScanFinding(
            rule_id="aws-access-key-id",
            rule_description="AWS Access Key ID",
            file_path=config_file,
            line_number=2,
            description="AWS key found",
            severity=FindingSeverity.CRITICAL,
            scanner="native",
        )

        filter_ = IgnoreFilter()
        result = filter_.filter([finding])

        # Ignore is on line 1, finding is on line 2
        assert len(result) == 1

    def test_javascript_style_ignore(self, tmp_path: Path):
        """Test // style ignore comment."""
        config_file = tmp_path / "config.js"
        config_file.write_text('const KEY = "AKIAIOSFODNN7EXAMPLE";  // envdrift:ignore\n')

        finding = ScanFinding(
            rule_id="aws-access-key-id",
            rule_description="AWS Access Key ID",
            file_path=config_file,
            line_number=1,
            description="AWS key found",
            severity=FindingSeverity.CRITICAL,
            scanner="native",
        )

        filter_ = IgnoreFilter()
        result = filter_.filter([finding])

        assert len(result) == 0

    def test_block_comment_style_ignore(self, tmp_path: Path):
        """Test /* */ style ignore comment."""
        config_file = tmp_path / "config.c"
        config_file.write_text('const char* KEY = "AKIAIOSFODNN7EXAMPLE"; /* envdrift:ignore */\n')

        finding = ScanFinding(
            rule_id="aws-access-key-id",
            rule_description="AWS Access Key ID",
            file_path=config_file,
            line_number=1,
            description="AWS key found",
            severity=FindingSeverity.CRITICAL,
            scanner="native",
        )

        filter_ = IgnoreFilter()
        result = filter_.filter([finding])

        assert len(result) == 0


class TestIgnoreFilterRulePathIgnores:
    """Tests for rule+path combination ignores from config."""

    def test_rule_path_ignore_matches(self, tmp_path: Path):
        """Test that rule+path combination from config filters finding."""
        config_file = tmp_path / "locales" / "en.json"
        config_file.parent.mkdir(parents=True)
        config_file.write_text('{"password": "Mot de passe"}\n')

        finding = ScanFinding(
            rule_id="ftp-password",
            rule_description="FTP Password",
            file_path=config_file,
            line_number=1,
            description="Password found",
            severity=FindingSeverity.MEDIUM,
            scanner="native",
        )

        config = IgnoreConfig(ignore_rules={"ftp-password": ["**/locales/**"]})
        filter_ = IgnoreFilter(config)
        result = filter_.filter([finding])

        assert len(result) == 0

    def test_rule_path_ignore_with_extension_pattern(self, tmp_path: Path):
        """Test rule+path ignore with file extension pattern."""
        config_file = tmp_path / "translations.json"
        config_file.write_text('{"password": "value"}\n')

        finding = ScanFinding(
            rule_id="ftp-password",
            rule_description="FTP Password",
            file_path=config_file,
            line_number=1,
            description="Password found",
            severity=FindingSeverity.MEDIUM,
            scanner="native",
        )

        config = IgnoreConfig(ignore_rules={"ftp-password": ["**/*.json"]})
        filter_ = IgnoreFilter(config)
        result = filter_.filter([finding])

        assert len(result) == 0

    def test_rule_path_ignore_different_rule_not_filtered(self, tmp_path: Path):
        """Test that different rule ID in same path is not filtered."""
        config_file = tmp_path / "config.json"
        config_file.write_text('{"aws_key": "AKIAIOSFODNN7EXAMPLE"}\n')

        finding = ScanFinding(
            rule_id="aws-access-key-id",
            rule_description="AWS Access Key ID",
            file_path=config_file,
            line_number=1,
            description="AWS key found",
            severity=FindingSeverity.CRITICAL,
            scanner="native",
        )

        # Only ignore ftp-password in JSON files, not aws-access-key-id
        config = IgnoreConfig(ignore_rules={"ftp-password": ["**/*.json"]})
        filter_ = IgnoreFilter(config)
        result = filter_.filter([finding])

        assert len(result) == 1

    def test_rule_path_ignore_no_match_path(self, tmp_path: Path):
        """Test that rule+path ignore doesn't filter non-matching paths."""
        config_file = tmp_path / "src" / "config.py"
        config_file.parent.mkdir(parents=True)
        config_file.write_text('password = "value"\n')

        finding = ScanFinding(
            rule_id="ftp-password",
            rule_description="FTP Password",
            file_path=config_file,
            line_number=1,
            description="Password found",
            severity=FindingSeverity.MEDIUM,
            scanner="native",
        )

        # Only ignore ftp-password in locales, not src
        config = IgnoreConfig(ignore_rules={"ftp-password": ["**/locales/**"]})
        filter_ = IgnoreFilter(config)
        result = filter_.filter([finding])

        assert len(result) == 1


class TestIgnoreFilterGlobalPathIgnores:
    """Tests for global path ignores from config."""

    def test_global_path_ignore_matches(self, tmp_path: Path):
        """Test that global path ignore filters finding."""
        test_file = tmp_path / "tests" / "test_config.py"
        test_file.parent.mkdir(parents=True)
        test_file.write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n')

        finding = ScanFinding(
            rule_id="aws-access-key-id",
            rule_description="AWS Access Key ID",
            file_path=test_file,
            line_number=1,
            description="AWS key found",
            severity=FindingSeverity.CRITICAL,
            scanner="native",
        )

        config = IgnoreConfig(ignore_paths=["**/tests/**"])
        filter_ = IgnoreFilter(config)
        result = filter_.filter([finding])

        assert len(result) == 0

    def test_global_path_ignore_no_match(self, tmp_path: Path):
        """Test that global path ignore doesn't filter non-matching paths."""
        src_file = tmp_path / "src" / "config.py"
        src_file.parent.mkdir(parents=True)
        src_file.write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n')

        finding = ScanFinding(
            rule_id="aws-access-key-id",
            rule_description="AWS Access Key ID",
            file_path=src_file,
            line_number=1,
            description="AWS key found",
            severity=FindingSeverity.CRITICAL,
            scanner="native",
        )

        config = IgnoreConfig(ignore_paths=["**/tests/**"])
        filter_ = IgnoreFilter(config)
        result = filter_.filter([finding])

        assert len(result) == 1


class TestIgnoreFilterPriority:
    """Tests for ignore filter priority order."""

    def test_inline_comment_takes_precedence(self, tmp_path: Path):
        """Test that inline comment is checked before config ignores."""
        config_file = tmp_path / "src" / "config.py"
        config_file.parent.mkdir(parents=True)
        config_file.write_text('KEY = "AKIAIOSFODNN7EXAMPLE"  # envdrift:ignore\n')

        finding = ScanFinding(
            rule_id="aws-access-key-id",
            rule_description="AWS Access Key ID",
            file_path=config_file,
            line_number=1,
            description="AWS key found",
            severity=FindingSeverity.CRITICAL,
            scanner="native",
        )

        # No config ignores
        filter_ = IgnoreFilter()
        result = filter_.filter([finding])

        # Should still be filtered by inline comment
        assert len(result) == 0

    def test_multiple_findings_mixed_filtering(self, tmp_path: Path):
        """Test filtering multiple findings with different ignore methods."""
        # File 1: Inline ignore
        file1 = tmp_path / "config1.py"
        file1.write_text('KEY1 = "secret1"  # envdrift:ignore\n')

        # File 2: In ignored path
        tests_dir = tmp_path / "tests"
        tests_dir.mkdir()
        file2 = tests_dir / "config2.py"
        file2.write_text('KEY2 = "secret2"\n')

        # File 3: Not ignored
        file3 = tmp_path / "config3.py"
        file3.write_text('KEY3 = "secret3"\n')

        findings = [
            ScanFinding(
                rule_id="generic-secret",
                rule_description="Generic Secret",
                file_path=file1,
                line_number=1,
                description="Secret found",
                severity=FindingSeverity.MEDIUM,
                scanner="native",
            ),
            ScanFinding(
                rule_id="generic-secret",
                rule_description="Generic Secret",
                file_path=file2,
                line_number=1,
                description="Secret found",
                severity=FindingSeverity.MEDIUM,
                scanner="native",
            ),
            ScanFinding(
                rule_id="generic-secret",
                rule_description="Generic Secret",
                file_path=file3,
                line_number=1,
                description="Secret found",
                severity=FindingSeverity.MEDIUM,
                scanner="native",
            ),
        ]

        config = IgnoreConfig(ignore_paths=["**/tests/**"])
        filter_ = IgnoreFilter(config)
        result = filter_.filter(findings)

        # Only file3 finding should remain
        assert len(result) == 1
        assert result[0].file_path == file3


class TestIgnoreFilterFileCaching:
    """Tests for file content caching in IgnoreFilter."""

    def test_file_cache_populated(self, tmp_path: Path):
        """Test that file content is cached after first read."""
        config_file = tmp_path / "config.py"
        config_file.write_text('KEY = "secret"  # envdrift:ignore\n')

        finding = ScanFinding(
            rule_id="generic-secret",
            rule_description="Generic Secret",
            file_path=config_file,
            line_number=1,
            description="Secret found",
            severity=FindingSeverity.MEDIUM,
            scanner="native",
        )

        filter_ = IgnoreFilter()
        filter_.filter([finding])

        # File should be cached
        assert config_file in filter_._file_cache
        assert filter_._file_cache[config_file] == ['KEY = "secret"  # envdrift:ignore']

    def test_file_cache_reused(self, tmp_path: Path):
        """Test that cached file content is reused."""
        config_file = tmp_path / "config.py"
        config_file.write_text('KEY = "secret"  # envdrift:ignore\n')

        findings = [
            ScanFinding(
                rule_id="generic-secret",
                rule_description="Generic Secret",
                file_path=config_file,
                line_number=1,
                description="Secret 1",
                severity=FindingSeverity.MEDIUM,
                scanner="native",
            ),
            ScanFinding(
                rule_id="another-secret",
                rule_description="Another Secret",
                file_path=config_file,
                line_number=1,
                description="Secret 2",
                severity=FindingSeverity.MEDIUM,
                scanner="native",
            ),
        ]

        filter_ = IgnoreFilter()
        filter_.filter(findings)

        # File should only be read once
        assert len(filter_._file_cache) == 1

    def test_nonexistent_file_returns_empty(self, tmp_path: Path):
        """Test that nonexistent file returns empty lines."""
        filter_ = IgnoreFilter()
        nonexistent = tmp_path / "nonexistent.py"

        lines = filter_._get_file_lines(nonexistent)

        assert lines == []
        assert nonexistent in filter_._file_cache


class TestIgnoreFilterEdgeCases:
    """Tests for edge cases in IgnoreFilter."""

    def test_finding_without_line_number(self, tmp_path: Path):
        """Test filtering finding without line number."""
        config_file = tmp_path / "config.py"
        config_file.write_text('KEY = "secret"  # envdrift:ignore\n')

        finding = ScanFinding(
            rule_id="generic-secret",
            rule_description="Generic Secret",
            file_path=config_file,
            line_number=None,  # No line number
            description="Secret found",
            severity=FindingSeverity.MEDIUM,
            scanner="native",
        )

        filter_ = IgnoreFilter()
        result = filter_.filter([finding])

        # Without line number, inline comments can't be checked
        assert len(result) == 1

    def test_finding_with_invalid_line_number(self, tmp_path: Path):
        """Test filtering finding with invalid line number."""
        config_file = tmp_path / "config.py"
        config_file.write_text('KEY = "secret"\n')

        finding = ScanFinding(
            rule_id="generic-secret",
            rule_description="Generic Secret",
            file_path=config_file,
            line_number=100,  # Line doesn't exist
            description="Secret found",
            severity=FindingSeverity.MEDIUM,
            scanner="native",
        )

        filter_ = IgnoreFilter()
        result = filter_.filter([finding])

        # Invalid line number, finding should pass through
        assert len(result) == 1

    def test_empty_file(self, tmp_path: Path):
        """Test filtering finding in empty file."""
        config_file = tmp_path / "config.py"
        config_file.write_text("")

        finding = ScanFinding(
            rule_id="generic-secret",
            rule_description="Generic Secret",
            file_path=config_file,
            line_number=1,
            description="Secret found",
            severity=FindingSeverity.MEDIUM,
            scanner="native",
        )

        filter_ = IgnoreFilter()
        result = filter_.filter([finding])

        # Empty file, finding should pass through
        assert len(result) == 1
