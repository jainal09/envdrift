"""Tests for EncryptionBackend base helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.encryption.base import (
    EncryptionBackend,
    EncryptionNotFoundError,
    EncryptionResult,
    EncryptionStatus,
)


class DummyBackend(EncryptionBackend):
    """Minimal backend to exercise base helpers."""

    def __init__(self, installed: bool = True):
        self._installed = installed

    @property
    def name(self) -> str:
        return "dummy"

    @property
    def encrypted_value_prefix(self) -> str:
        return "ENC:"

    def is_installed(self) -> bool:
        return self._installed

    def get_version(self) -> str | None:
        return "0.0.0" if self._installed else None

    def encrypt(self, env_file: Path | str, keys_file: Path | str | None = None, **kwargs):
        return EncryptionResult(success=True, message="ok", file_path=Path(env_file))

    def decrypt(self, env_file: Path | str, keys_file: Path | str | None = None, **kwargs):
        return EncryptionResult(success=True, message="ok", file_path=Path(env_file))

    def detect_encryption_status(self, value: str) -> EncryptionStatus:
        if value.startswith("ENC:"):
            return EncryptionStatus.ENCRYPTED
        return EncryptionStatus.PLAINTEXT

    def has_encrypted_header(self, content: str) -> bool:
        return "ENC:" in content

    def install_instructions(self) -> str:
        return "install dummy"


def test_is_file_encrypted_uses_header(tmp_path: Path):
    """Base helper should consult has_encrypted_header."""
    backend = DummyBackend()
    env_file = tmp_path / ".env"
    env_file.write_text("ENC:secret")
    assert backend.is_file_encrypted(env_file) is True


def test_is_file_encrypted_missing_file(tmp_path: Path):
    """Missing files should be treated as unencrypted."""
    backend = DummyBackend()
    assert backend.is_file_encrypted(tmp_path / "missing.env") is False


def test_ensure_installed_raises():
    """ensure_installed should raise when not installed."""
    backend = DummyBackend(installed=False)
    with pytest.raises(EncryptionNotFoundError):
        backend.ensure_installed()


def test_is_value_encrypted_uses_status():
    """is_value_encrypted should reflect detect_encryption_status."""
    backend = DummyBackend()
    assert backend.is_value_encrypted("ENC:secret") is True
    assert backend.is_value_encrypted("plain") is False
