"""Coverage-focused tests for ``envdrift.encryption.base``.

The abstract methods on :class:`EncryptionBackend` have ``...`` ellipsis
bodies. A concrete subclass whose overrides invoke the *underlying* abstract
function objects forces those ellipsis statements to execute, which exercises
the otherwise uncovered lines (the abstract-method bodies and the
abstract-property getters).

The abstract bodies are reached through the raw function objects stored on
``EncryptionBackend`` (e.g. ``EncryptionBackend.is_installed``) rather than via
``super()``; a type checker rejects calling an unimplemented abstract method
through ``super()``, but the plain function object is just a callable that runs
its ``...`` body and returns ``None``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.encryption.base import (
    EncryptionBackend,
    EncryptionNotFoundError,
    EncryptionResult,
    EncryptionStatus,
)


class SuperCallingBackend(EncryptionBackend):
    """Backend whose overrides delegate to the abstract ``super()`` bodies.

    Every override invokes the parent implementation so the ellipsis body of
    each abstract method/property runs, then returns a concrete value so the
    subclass is still usable for behavioural assertions.
    """

    def __init__(self, *, installed: bool = True) -> None:
        self._installed = installed

    @property
    def name(self) -> str:
        # Executes the abstract ``name`` getter body (line 63).
        # Call the abstract getter body purely for coverage; ignore the result.
        _ = EncryptionBackend.name.fget(self)  # type: ignore[attr-defined]
        return "supercaller"

    @property
    def encrypted_value_prefix(self) -> str | None:
        # Executes the abstract ``encrypted_value_prefix`` getter body (line 75).
        _ = EncryptionBackend.encrypted_value_prefix.fget(self)  # type: ignore[attr-defined]
        return "ENC:"

    def is_installed(self) -> bool:
        # Executes the abstract ``is_installed`` body (line 85).
        _ = EncryptionBackend.is_installed(self)
        return self._installed

    def get_version(self) -> str | None:
        # Executes the abstract ``get_version`` body (line 95).
        _ = EncryptionBackend.get_version(self)
        return "1.2.3" if self._installed else None

    def encrypt(
        self,
        env_file: Path | str,
        keys_file: Path | str | None = None,
        **kwargs,
    ) -> EncryptionResult:
        # Executes the abstract ``encrypt`` body (line 119).
        _ = EncryptionBackend.encrypt(self, env_file, keys_file, **kwargs)
        return EncryptionResult(success=True, message="encrypted", file_path=Path(env_file))

    def decrypt(
        self,
        env_file: Path | str,
        keys_file: Path | str | None = None,
        **kwargs,
    ) -> EncryptionResult:
        # Executes the abstract ``decrypt`` body (line 143).
        _ = EncryptionBackend.decrypt(self, env_file, keys_file, **kwargs)
        return EncryptionResult(success=True, message="decrypted", file_path=Path(env_file))

    def detect_encryption_status(self, value: str) -> EncryptionStatus:
        # Executes the abstract ``detect_encryption_status`` body (line 157).
        _ = EncryptionBackend.detect_encryption_status(self, value)
        if value == "":
            return EncryptionStatus.EMPTY
        if value.startswith("ENC:"):
            return EncryptionStatus.ENCRYPTED
        return EncryptionStatus.PLAINTEXT

    def has_encrypted_header(self, content: str) -> bool:
        # Executes the abstract ``has_encrypted_header`` body (line 170).
        _ = EncryptionBackend.has_encrypted_header(self, content)
        return "ENC:" in content

    def install_instructions(self) -> str:
        # Executes the abstract ``install_instructions`` body (line 208).
        _ = EncryptionBackend.install_instructions(self)
        return "install supercaller"


def test_abstract_property_bodies_run() -> None:
    """Calling the super property getters runs lines 63 and 75."""
    backend = SuperCallingBackend()
    assert backend.name == "supercaller"
    assert backend.encrypted_value_prefix == "ENC:"


def test_abstract_method_bodies_run() -> None:
    """Delegating to the abstract bodies runs lines 85, 95 and 208."""
    backend = SuperCallingBackend()
    assert backend.is_installed() is True
    assert backend.get_version() == "1.2.3"
    assert backend.install_instructions() == "install supercaller"


def test_encrypt_decrypt_delegate_to_super(tmp_path: Path) -> None:
    """encrypt/decrypt overrides run the abstract bodies (lines 119, 143)."""
    backend = SuperCallingBackend()
    env_file = tmp_path / ".env"
    env_file.write_text("ENC:secret")

    enc = backend.encrypt(env_file, keys_file=None)
    dec = backend.decrypt(env_file)

    assert enc.success is True
    assert enc.file_path == env_file
    assert dec.success is True
    assert dec.message == "decrypted"


def test_detect_status_and_header_run_super() -> None:
    """detect_encryption_status / has_encrypted_header run lines 157, 170."""
    backend = SuperCallingBackend()
    assert backend.detect_encryption_status("") is EncryptionStatus.EMPTY
    assert backend.detect_encryption_status("ENC:abc") is EncryptionStatus.ENCRYPTED
    assert backend.detect_encryption_status("plain") is EncryptionStatus.PLAINTEXT
    assert backend.has_encrypted_header("ENC:abc") is True
    assert backend.has_encrypted_header("nope") is False


def test_is_value_encrypted_via_concrete_helper() -> None:
    """is_value_encrypted bridges to detect_encryption_status."""
    backend = SuperCallingBackend()
    assert backend.is_value_encrypted("ENC:abc") is True
    assert backend.is_value_encrypted("plain") is False


def test_is_file_encrypted_reads_content(tmp_path: Path) -> None:
    """is_file_encrypted reads the file and consults has_encrypted_header."""
    backend = SuperCallingBackend()
    encrypted = tmp_path / "enc.env"
    encrypted.write_text("ENC:secret", encoding="utf-8")
    plain = tmp_path / "plain.env"
    plain.write_text("KEY=value", encoding="utf-8")

    assert backend.is_file_encrypted(encrypted) is True
    assert backend.is_file_encrypted(plain) is False
    assert backend.is_file_encrypted(tmp_path / "absent.env") is False


def test_ensure_installed_passes_when_installed() -> None:
    """ensure_installed returns None and does not raise when installed.

    Covers the ``217->exit`` branch where ``is_installed()`` is truthy.
    """
    backend = SuperCallingBackend(installed=True)
    assert backend.ensure_installed() is None


def test_ensure_installed_raises_when_missing() -> None:
    """ensure_installed raises with name + instructions when not installed."""
    backend = SuperCallingBackend(installed=False)
    with pytest.raises(EncryptionNotFoundError) as excinfo:
        backend.ensure_installed()
    message = str(excinfo.value)
    assert "supercaller" in message
    assert "install supercaller" in message
