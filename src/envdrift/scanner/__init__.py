"""Secret scanning module for envdrift guard command.

This module provides secret detection capabilities through multiple scanner backends:
- NativeScanner: Built-in scanner with zero external dependencies
- GitleaksScanner: Integration with gitleaks (auto-installable)
- TrufflehogScanner: Integration with trufflehog (auto-installable)
- DetectSecretsScanner: Yelp's detect-secrets - the "final boss" (auto-installable)
- KingfisherScanner: MongoDB's Kingfisher - 700+ rules, password hashes, validation
- GitSecretsScanner: AWS git-secrets for pre-commit hooks (auto-installable)

The ScanEngine orchestrates multiple scanners and aggregates results.
"""

from envdrift.scanner.base import (
    AggregatedScanResult,
    FindingSeverity,
    ScanFinding,
    ScannerBackend,
    ScanResult,
)
from envdrift.scanner.detect_secrets import DetectSecretsScanner
from envdrift.scanner.engine import GuardConfig, ScanEngine
from envdrift.scanner.git_secrets import GitSecretsScanner
from envdrift.scanner.gitleaks import GitleaksScanner
from envdrift.scanner.kingfisher import KingfisherScanner
from envdrift.scanner.native import NativeScanner
from envdrift.scanner.trufflehog import TrufflehogScanner

__all__ = [
    "AggregatedScanResult",
    "DetectSecretsScanner",
    "FindingSeverity",
    "GitSecretsScanner",
    "GitleaksScanner",
    "GuardConfig",
    "KingfisherScanner",
    "NativeScanner",
    "ScanEngine",
    "ScanFinding",
    "ScannerBackend",
    "ScanResult",
    "TrufflehogScanner",
]
