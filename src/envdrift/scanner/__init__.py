"""Secret scanning module for envdrift guard command.

This module provides secret detection capabilities through multiple scanner backends:
- NativeScanner: Built-in scanner with zero external dependencies
- GitleaksScanner: Integration with gitleaks (auto-installable)
- TrufflehogScanner: Integration with trufflehog (auto-installable)

The ScanEngine orchestrates multiple scanners and aggregates results.
"""

from envdrift.scanner.base import (
    AggregatedScanResult,
    FindingSeverity,
    ScanFinding,
    ScannerBackend,
    ScanResult,
)
from envdrift.scanner.engine import GuardConfig, ScanEngine
from envdrift.scanner.native import NativeScanner

__all__ = [
    "AggregatedScanResult",
    "FindingSeverity",
    "GuardConfig",
    "NativeScanner",
    "ScanEngine",
    "ScanFinding",
    "ScannerBackend",
    "ScanResult",
]
