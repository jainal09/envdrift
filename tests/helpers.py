"""Test helpers shared across unit tests."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from envdrift.encryption.base import EncryptionResult


class DummyEncryptionBackend:
    """Minimal encryption backend for unit tests."""

    def __init__(
        self,
        *,
        name: str = "dotenvx",
        installed: bool = True,
        encrypt_side_effect: Exception | None = None,
        decrypt_side_effect: Exception | None = None,
        has_encrypted_header: Callable[[str], bool] | None = None,
    ) -> None:
        self._name = name
        self._installed = installed
        self._encrypt_side_effect = encrypt_side_effect
        self._decrypt_side_effect = decrypt_side_effect
        self._has_encrypted_header = has_encrypted_header
        self.encrypt_calls: list[Path] = []
        self.decrypt_calls: list[Path] = []
        self.encrypt_kwargs: list[dict[str, object]] = []
        self.decrypt_kwargs: list[dict[str, object]] = []

    @property
    def name(self) -> str:
        return self._name

    def is_installed(self) -> bool:
        return self._installed

    def install_instructions(self) -> str:
        return f"install {self._name}"

    def has_encrypted_header(self, content: str) -> bool:
        if self._has_encrypted_header is not None:
            return self._has_encrypted_header(content)
        return (
            "#/---BEGIN DOTENV ENCRYPTED---/" in content
            or "DOTENV_PUBLIC_KEY" in content
            or "ENC[AES256_GCM," in content
            or "sops:" in content
        )

    def encrypt(self, env_file: Path | str, **kwargs) -> EncryptionResult:
        if self._encrypt_side_effect is not None:
            raise self._encrypt_side_effect
        path = Path(env_file)
        self.encrypt_calls.append(path)
        self.encrypt_kwargs.append(kwargs)
        return EncryptionResult(success=True, message="ok", file_path=path)

    def decrypt(self, env_file: Path | str, **kwargs) -> EncryptionResult:
        if self._decrypt_side_effect is not None:
            raise self._decrypt_side_effect
        path = Path(env_file)
        self.decrypt_calls.append(path)
        self.decrypt_kwargs.append(kwargs)
        return EncryptionResult(success=True, message="ok", file_path=path)

    def reset_tracking(self) -> None:
        """Clear recorded encrypt/decrypt calls and kwargs."""
        self.encrypt_calls.clear()
        self.decrypt_calls.clear()
        self.encrypt_kwargs.clear()
        self.decrypt_kwargs.clear()
