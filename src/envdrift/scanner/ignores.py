"""Centralized ignore system for envdrift guard.

This module provides a unified way to filter false positives across ALL scanners
(native, gitleaks, trufflehog, etc.). It supports:

1. Inline ignore comments (travels with code, visible in PRs)
2. Rule+path ignores in TOML config
3. Global path ignores

Usage in code:
    password = ref(false)  # envdrift:ignore
    SECRET_KEY = "test"    # envdrift:ignore:django-secret-key
    API_KEY = "xxx"        # envdrift:ignore reason="test fixture"

Usage in envdrift.toml:
    [guard]
    ignore_paths = ["**/locales/**", "**/tests/**"]

    [guard.ignore_rules]
    "ftp-password" = ["**/*.json"]
    "connection-string-password" = ["**/helm/**"]
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from envdrift.scanner.base import ScanFinding


# Regex to match ignore comments in various languages
# Supports: # envdrift:ignore, // envdrift:ignore, /* envdrift:ignore */
IGNORE_PATTERN = re.compile(
    r'(?:#|//|/\*)\s*envdrift:ignore(?::([a-zA-Z0-9_-]+))?(?:\s+reason\s*=\s*["\']([^"\']+)["\'])?',
    re.IGNORECASE,
)


@dataclass
class IgnoreConfig:
    """Configuration for ignore rules.

    Attributes:
        ignore_paths: Global path patterns to ignore completely.
        ignore_rules: Rule ID -> list of path patterns where that rule is ignored.
    """

    ignore_paths: list[str] = field(default_factory=list)
    ignore_rules: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, config: dict) -> IgnoreConfig:
        """Create from TOML config dict.

        Args:
            config: The full config dict (expects guard.ignore_paths, guard.ignore_rules).

        Returns:
            IgnoreConfig instance.
        """
        guard = config.get("guard", {})
        return cls(
            ignore_paths=guard.get("ignore_paths", []),
            ignore_rules=guard.get("ignore_rules", {}),
        )


class IgnoreFilter:
    """Centralized filter for ignoring false positives.

    This filter is applied AFTER all scanners run, so it works uniformly
    across native, gitleaks, trufflehog, and any other scanner.

    Example:
        filter = IgnoreFilter(config)
        filtered_findings = filter.filter(findings)
    """

    def __init__(self, config: IgnoreConfig | None = None) -> None:
        """Initialize the filter.

        Args:
            config: Ignore configuration. Uses empty config if None.
        """
        self.config = config or IgnoreConfig()
        self._file_cache: dict[Path, list[str]] = {}

    def filter(self, findings: list[ScanFinding]) -> list[ScanFinding]:
        """Filter out ignored findings.

        Args:
            findings: List of findings from all scanners.

        Returns:
            Filtered list with ignored findings removed.
        """
        filtered = []

        for finding in findings:
            if self._should_ignore(finding):
                continue
            filtered.append(finding)

        return filtered

    def _should_ignore(self, finding: ScanFinding) -> bool:
        """Check if a finding should be ignored.

        Checks in order:
        1. Inline ignore comments in the source file
        2. Rule+path combinations from config
        3. Global path ignores from config

        Args:
            finding: The finding to check.

        Returns:
            True if the finding should be ignored.
        """
        file_path = finding.file_path
        rule_id = finding.rule_id
        line_number = finding.line_number

        # Check 1: Inline ignore comments
        if line_number is not None and self._has_inline_ignore(file_path, line_number, rule_id):
            return True

        # Check 2: Rule+path combinations
        if self._matches_rule_path_ignore(rule_id, file_path):
            return True

        # Check 3: Global path ignores (already handled by scanner, but double-check)
        return bool(self._matches_global_ignore(file_path))

    def _has_inline_ignore(self, file_path: Path, line_number: int, rule_id: str) -> bool:
        """Check if a specific line has an ignore comment.

        Args:
            file_path: Path to the file.
            line_number: 1-based line number.
            rule_id: The rule ID to check.

        Returns:
            True if the line has a matching ignore comment.
        """
        lines = self._get_file_lines(file_path)

        if not lines or line_number < 1 or line_number > len(lines):
            return False

        line = lines[line_number - 1]

        match = IGNORE_PATTERN.search(line)
        if not match:
            return False

        # Extract the specific rule being ignored (if any)
        ignored_rule = match.group(1)

        # If no specific rule, ignore all rules on this line
        if ignored_rule is None:
            return True

        # If specific rule, only ignore that rule
        return ignored_rule == rule_id

    def _get_file_lines(self, file_path: Path) -> list[str]:
        """Get cached file lines.

        Args:
            file_path: Path to the file.

        Returns:
            List of lines (empty if file can't be read).
        """
        if file_path in self._file_cache:
            return self._file_cache[file_path]

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
            self._file_cache[file_path] = lines
            return lines
        except (OSError, UnicodeDecodeError):
            self._file_cache[file_path] = []
            return []

    def _matches_rule_path_ignore(self, rule_id: str, file_path: Path) -> bool:
        """Check if rule+path combination is ignored in config.

        Args:
            rule_id: The rule ID.
            file_path: The file path.

        Returns:
            True if this rule is ignored for this path.
        """
        if rule_id not in self.config.ignore_rules:
            return False

        path_patterns = self.config.ignore_rules[rule_id]
        path_str = str(file_path)

        for pattern in path_patterns:
            # Try full path match first
            if fnmatch.fnmatch(path_str, pattern):
                return True
            # Try matching suffix paths (optimization: break on first match)
            for i in range(len(file_path.parts)):
                partial = "/".join(file_path.parts[i:])
                if fnmatch.fnmatch(partial, pattern):
                    return True
                # Early break: if pattern doesn't contain wildcards and partial is longer,
                # no point checking shorter suffixes
                if "*" not in pattern and "?" not in pattern and len(partial) < len(pattern):
                    break

        return False

    def _matches_global_ignore(self, file_path: Path) -> bool:
        """Check if path matches global ignore patterns.

        Args:
            file_path: The file path.

        Returns:
            True if path should be globally ignored.
        """
        path_str = str(file_path)

        for pattern in self.config.ignore_paths:
            if fnmatch.fnmatch(path_str, pattern):
                return True
            for i in range(len(file_path.parts)):
                partial = "/".join(file_path.parts[i:])
                if fnmatch.fnmatch(partial, pattern):
                    return True

        return False


def parse_ignore_comment(line: str) -> tuple[bool, str | None, str | None]:
    """Parse an envdrift:ignore comment from a line.

    Args:
        line: The line to parse.

    Returns:
        Tuple of (has_ignore, rule_id, reason).
        - has_ignore: True if line has an ignore comment
        - rule_id: Specific rule being ignored (None = all rules)
        - reason: Optional reason provided

    Examples:
        >>> parse_ignore_comment('x = 1  # envdrift:ignore')
        (True, None, None)
        >>> parse_ignore_comment('x = 1  # envdrift:ignore:django-secret-key')
        (True, 'django-secret-key', None)
        >>> parse_ignore_comment('x = 1  # envdrift:ignore reason="test"')
        (True, None, 'test')
    """
    match = IGNORE_PATTERN.search(line)
    if not match:
        return (False, None, None)

    return (True, match.group(1), match.group(2))
