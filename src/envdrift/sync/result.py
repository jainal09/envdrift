"""Sync result models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class SyncAction(Enum):
    """Action taken during sync."""

    CREATED = "created"
    UPDATED = "updated"
    SKIPPED = "skipped"
    ERROR = "error"


class DecryptionTestResult(Enum):
    """Result of decryption test."""

    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ServiceSyncResult:
    """Result of syncing a single service."""

    secret_name: str
    folder_path: Path
    action: SyncAction
    message: str
    vault_value_preview: str | None = None
    local_value_preview: str | None = None
    backup_path: Path | None = None
    decryption_result: DecryptionTestResult | None = None
    schema_valid: bool | None = None
    error: str | None = None


@dataclass
class SyncResult:
    """Aggregate sync results."""

    services: list[ServiceSyncResult] = field(default_factory=list)

    @property
    def total_processed(self) -> int:
        """Total number of services processed."""
        return len(self.services)

    @property
    def created_count(self) -> int:
        """Number of keys created."""
        return sum(1 for s in self.services if s.action == SyncAction.CREATED)

    @property
    def updated_count(self) -> int:
        """Number of keys updated."""
        return sum(1 for s in self.services if s.action == SyncAction.UPDATED)

    @property
    def skipped_count(self) -> int:
        """Number of keys skipped (no change needed)."""
        return sum(1 for s in self.services if s.action == SyncAction.SKIPPED)

    @property
    def error_count(self) -> int:
        """Number of services that failed."""
        return sum(1 for s in self.services if s.action == SyncAction.ERROR)

    @property
    def decryption_tested(self) -> int:
        """Number of services where decryption was tested."""
        return sum(1 for s in self.services if s.decryption_result is not None)

    @property
    def decryption_passed(self) -> int:
        """Number of services where decryption passed."""
        return sum(1 for s in self.services if s.decryption_result == DecryptionTestResult.PASSED)

    @property
    def decryption_failed(self) -> int:
        """Number of services where decryption failed."""
        return sum(1 for s in self.services if s.decryption_result == DecryptionTestResult.FAILED)

    @property
    def has_errors(self) -> bool:
        """Check if any errors occurred."""
        return self.error_count > 0 or self.decryption_failed > 0

    @property
    def exit_code(self) -> int:
        """Return appropriate CI exit code."""
        if self.error_count > 0 or self.decryption_failed > 0:
            return 1
        return 0
