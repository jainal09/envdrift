"""Shared builders for the finding path tests: findings, symlinks and a scan engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.scanner.base import FindingSeverity, ScanFinding, ScannerBackend, ScanResult
from envdrift.scanner.engine import GuardConfig, ScanEngine

# Visibly synthetic, and fragment-assembled so GitHub push protection never
# sees the whole literal. It keeps the 36-character shape the detectors match.
GITHUB_TOKEN = "ghp_" + "SYNTHETIC0TEST0TOKEN0FOR0UNIT0TESTS0"


def make_finding(
    path: Path | str,
    *,
    scanner: str = "native",
    rule: str = "github-pat",
    description: str = "Secret detected",
) -> ScanFinding:
    return ScanFinding(
        file_path=Path(path),
        rule_id=rule,
        rule_description=rule,
        description=description,
        severity=FindingSeverity.CRITICAL,
        scanner=scanner,
        line_number=1,
        secret_hash="0123abcd",
    )


def symlink(link: Path, target: Path) -> None:
    """Create ``link`` -> ``target``, skipping where symlinks need a privilege."""
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except OSError as exc:  # Windows without the symlink privilege
        pytest.skip(f"cannot create a symlink here: {exc}")


class FixedScanner(ScannerBackend):
    """A scanner that reports the findings it was built with."""

    def __init__(self, name: str, findings: list[ScanFinding]) -> None:
        self._name = name
        self._findings = findings

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return f"{self._name} stand-in"

    def is_installed(self) -> bool:
        return True

    def scan(self, paths: list[Path], include_git_history: bool = False) -> ScanResult:
        return ScanResult(scanner_name=self._name, findings=list(self._findings))


def scan_engine(
    *scanners: ScannerBackend,
    ignore_paths: list[str] | None = None,
    ignore_rules: dict[str, list[str]] | None = None,
    skip_duplicate: bool = False,
) -> ScanEngine:
    engine = ScanEngine(
        GuardConfig(
            use_native=False,
            use_gitleaks=False,
            ignore_paths=ignore_paths or [],
            ignore_rules=ignore_rules or {},
            skip_duplicate=skip_duplicate,
        )
    )
    engine.scanners = list(scanners)
    return engine
