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
from pathlib import Path, PurePath
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from envdrift.scanner.base import ScanFinding


# Regex to match ignore comments in various languages
# Supports: # envdrift:ignore, // envdrift:ignore, /* envdrift:ignore */
IGNORE_PATTERN = re.compile(
    r'(?:#|//|/\*)\s*envdrift:ignore(?::([a-zA-Z0-9_-]+))?(?:\s+reason\s*=\s*["\']([^"\']+)["\'])?',
    re.IGNORECASE,
)


# Rule-id markers identifying *noisy*, low-confidence detections: keyword- and
# entropy-driven rules that routinely false-positive on config/build/lock files
# ("secret"/"token" keywords, integrity hashes). Matched as case-insensitive
# substrings so scanner-namespaced ids are covered too (native generic-secret /
# high-entropy-string, gitleaks-generic-api-key, detect-secrets keyword/entropy
# detectors, ...). Distinctive-prefix detections (ghp_, AKIA, pypi-, ...) never
# match and are therefore never suppressed by noisy-scoped path ignores (#477).
NOISY_RULE_ID_MARKERS = ("generic", "entropy", "keyword")


def is_noisy_rule(rule_id: str) -> bool:
    """Whether ``rule_id`` is a noisy keyword/entropy-style detection."""
    rule = rule_id.lower()
    return any(marker in rule for marker in NOISY_RULE_ID_MARKERS)


# A pattern that names files by their absolute path: ``/repo/x``,
# ``//server/share/x`` or ``C:/repo/x``, also spelled with Windows backslashes.
_ABSOLUTE_PATTERN = re.compile(r"(?:[A-Za-z]:)?[/\\]")


def is_absolute_pattern(pattern: str) -> bool:
    """Whether the path pattern ``pattern`` names files by their absolute path."""
    return _ABSOLUTE_PATTERN.match(pattern) is not None


def _matches_name_or_trailing_part(name: PurePath, pattern: str) -> bool:
    """Whether ``pattern`` matches ``name`` or a trailing part of it (``sub/x`` of ``a/sub/x``).

    Every trailing part is tried. ``ignore_rules`` used to stop once a part
    was shorter than a pattern without ``*`` or ``?``, but a character class
    matches fewer characters than it spells, so ``[ab].env`` missed the
    ``a.env`` of ``x/a.env`` that ``ignore_paths`` matched.
    """
    if fnmatch.fnmatch(name.as_posix(), pattern):
        return True
    parts = name.parts
    return any(fnmatch.fnmatch("/".join(parts[i:]), pattern) for i in range(len(parts)))


@dataclass(frozen=True)
class PathForms:
    """The names of one file that path patterns are matched against (#859).

    A relative pattern is matched against each ``relative`` name and every
    trailing part of it, so ``config/settings.txt`` matches
    ``deploy/config/settings.txt``. An absolute pattern is matched against each
    ``absolute`` name as a whole. Names are compared with ``/`` separators,
    the separator patterns use on every platform.
    """

    relative: tuple[PurePath, ...]
    absolute: tuple[PurePath, ...] = ()

    @classmethod
    def of(cls, *paths: PurePath) -> PathForms:
        """``paths`` matched on their own: each as given, with its trailing parts.

        An absolute one is also matched whole by an absolute pattern.
        """
        return cls(paths, tuple(path for path in paths if path.is_absolute()))

    def match(self, patterns: Iterable[str]) -> bool:
        """Whether any pattern of ``patterns`` matches one of these names."""
        for pattern in patterns:
            if is_absolute_pattern(pattern):
                if any(fnmatch.fnmatch(name.as_posix(), pattern) for name in self.absolute):
                    return True
            elif any(_matches_name_or_trailing_part(name, pattern) for name in self.relative):
                return True
        return False


@dataclass
class IgnoreConfig:
    """Configuration for ignore rules.

    Attributes:
        ignore_paths: Global path patterns to ignore completely.
        ignore_rules: Rule ID -> list of path patterns where that rule is ignored.
        noisy_rule_paths: Path patterns where only noisy keyword/entropy rules
            (see :func:`is_noisy_rule`) are ignored. Used for the engine's
            built-in config/lock-file defaults so they can never swallow a
            high-confidence distinctive-prefix finding (#477).
    """

    ignore_paths: list[str] = field(default_factory=list)
    ignore_rules: dict[str, list[str]] = field(default_factory=dict)
    noisy_rule_paths: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, config: dict) -> IgnoreConfig:
        """Create from TOML config dict.

        Args:
            config: The full config dict (expects guard.ignore_paths,
                guard.ignore_rules, guard.noisy_rule_paths).

        Returns:
            IgnoreConfig instance.
        """
        guard = config.get("guard", {})
        return cls(
            ignore_paths=guard.get("ignore_paths", []),
            ignore_rules=guard.get("ignore_rules", {}),
            noisy_rule_paths=guard.get("noisy_rule_paths", []),
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

    def filter(
        self,
        findings: list[ScanFinding],
        path_forms: Callable[[Path], PathForms | Iterable[Path]] | None = None,
    ) -> list[ScanFinding]:
        """Filter out ignored findings.

        Args:
            findings: List of findings from all scanners.
            path_forms: Gives the names of the file at a finding path that
                path patterns are matched against, so one file is matched the
                same way whichever form a scanner reported it in. Defaults to
                the finding path alone (:meth:`PathForms.of`). Plain paths, the
                form 11.0.9 took, are each matched on their own.

        Returns:
            Filtered list with ignored findings removed.
        """
        filtered = []

        for finding in findings:
            forms = path_forms(finding.file_path) if path_forms else None
            if forms is not None and not isinstance(forms, PathForms):
                forms = PathForms.of(*forms)
            if self._should_ignore(finding, forms):
                continue
            filtered.append(finding)

        return filtered

    def _should_ignore(self, finding: ScanFinding, forms: PathForms | None = None) -> bool:
        """Check if a finding should be ignored.

        Checks in order:
        1. Inline ignore comments in the source file
        2. Rule+path combinations from config
        3. Noisy-rule path ignores (built-in config/lock-file defaults)
        4. Global path ignores from config

        Args:
            finding: The finding to check.
            forms: The names of the finding's file that path patterns are
                matched against. Defaults to the finding path alone.

        Returns:
            True if the finding should be ignored.
        """
        file_path = finding.file_path
        rule_id = finding.rule_id
        line_number = finding.line_number
        forms = PathForms.of(file_path) if forms is None else forms

        # Check 1: Inline ignore comments (read from the file as reported)
        if line_number is not None and self._has_inline_ignore(file_path, line_number, rule_id):
            return True

        # Check 2: Rule+path combinations
        if self._matches_rule_path_ignore(rule_id, forms):
            return True

        # Check 3: Noisy-rule path ignores — suppress only low-confidence
        # keyword/entropy detections in these paths; a distinctive-prefix
        # CRITICAL token in pyproject.toml / a lock file must still surface (#477)
        if is_noisy_rule(rule_id) and forms.match(self.config.noisy_rule_paths):
            return True

        # Check 4: Global path ignores (already handled by scanner, but double-check)
        return self._matches_global_ignore(forms)

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

    def _matches_rule_path_ignore(self, rule_id: str, forms: PathForms) -> bool:
        """Check if rule+path combination is ignored in config.

        Matched like the global path ignores.

        Args:
            rule_id: The rule ID.
            forms: The names of the file.

        Returns:
            True if this rule is ignored for this path.
        """
        return rule_id in self.config.ignore_rules and forms.match(
            self.config.ignore_rules[rule_id]
        )

    def _matches_global_ignore(self, forms: PathForms) -> bool:
        """Check if path matches global ignore patterns.

        Args:
            forms: The names of the file.

        Returns:
            True if path should be globally ignored.
        """
        return forms.match(self.config.ignore_paths)


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
