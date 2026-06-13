"""Dotenvx encryption backend implementation."""

from __future__ import annotations

import re
from pathlib import Path
from threading import Lock
from typing import ClassVar

from envdrift.encryption.base import (
    EncryptionBackend,
    EncryptionBackendError,
    EncryptionNotFoundError,
    EncryptionResult,
    EncryptionStatus,
)
from envdrift.integrations.dotenvx import is_dotenvx_safe_filename


class DotenvxEncryptionBackend(EncryptionBackend):
    """Encryption backend using dotenvx CLI.

    dotenvx is a tool for encrypting .env files with a public/private key pair.
    It stores encrypted values with the prefix "encrypted:" and adds file headers.
    """

    # Patterns that indicate encrypted values (dotenvx format)
    ENCRYPTED_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^encrypted:")

    # Header patterns that indicate the file has been encrypted by dotenvx
    ENCRYPTED_FILE_MARKERS: ClassVar[list[str]] = [
        "#/---BEGIN DOTENV ENCRYPTED---/",
        "DOTENV_PUBLIC_KEY",
    ]

    def __init__(self, auto_install: bool = False):
        """
        Initialize the dotenvx encryption backend.

        Parameters:
            auto_install (bool): If True, attempt to auto-install dotenvx if not found.
        """
        self._auto_install = auto_install
        self._wrapper = None
        self._wrapper_lock = Lock()

    @property
    def name(self) -> str:
        """Return backend name."""
        return "dotenvx"

    @property
    def encrypted_value_prefix(self) -> str:
        """Return the prefix used to identify encrypted values."""
        return "encrypted:"

    def _get_wrapper(self):
        """Lazily initialize the DotenvxWrapper."""
        if self._wrapper is None:
            with self._wrapper_lock:
                if self._wrapper is None:
                    from envdrift.integrations.dotenvx import DotenvxWrapper

                    self._wrapper = DotenvxWrapper(auto_install=self._auto_install)
        return self._wrapper

    def is_installed(self) -> bool:
        """Check if dotenvx is installed."""
        from envdrift.integrations.dotenvx import DotenvxError, DotenvxNotFoundError

        try:
            return self._get_wrapper().is_installed()
        except (DotenvxNotFoundError, DotenvxError, OSError, RuntimeError):
            return False

    def get_version(self) -> str | None:
        """Get the installed dotenvx version."""
        from envdrift.integrations.dotenvx import DotenvxError, DotenvxNotFoundError

        try:
            if not self.is_installed():
                return None
            return self._get_wrapper().get_version()
        except (DotenvxNotFoundError, DotenvxError, OSError, RuntimeError):
            return None

    def encrypt(
        self,
        env_file: Path | str,
        keys_file: Path | str | None = None,
        **kwargs,
    ) -> EncryptionResult:
        """
        Encrypt a .env file using dotenvx.

        Parameters:
            env_file (Path | str): Path to the .env file to encrypt.
            keys_file (Path | str | None): Optional path to .env.keys file.
            **kwargs: Additional options:
                - env (dict): Environment variables to pass to subprocess.
                - cwd (Path | str): Working directory for subprocess.

        Returns:
            EncryptionResult: Result of the encryption operation.
        """
        env_file = Path(env_file)

        if not env_file.exists():
            return EncryptionResult(
                success=False,
                message=f"File not found: {env_file}",
                file_path=env_file,
            )

        # Refuse companion files by name — most critically the dotenvx
        # private-key store itself. ``encrypt .env.keys`` rewrites every
        # DOTENV_PRIVATE_KEY* value as ciphertext under a brand-new keypair
        # whose private half is never persisted, permanently locking out every
        # file encrypted with those keys — previously under a clean exit 0
        # (#474). Reuses the canonical predicate that already excludes these
        # names from push/pull.
        from envdrift.env_files import _is_excluded_env_file

        if _is_excluded_env_file(env_file.name):
            return EncryptionResult(
                success=False,
                message=(
                    f"Refusing to encrypt {env_file}: it is a companion file "
                    "(.keys/.example/.sample/.template), not an env file. "
                    "Encrypting the dotenvx private-key store would permanently "
                    "lock out every file encrypted with its keys."
                ),
                file_path=env_file,
            )

        # Refuse to "encrypt" a file with no assignments. Handed an empty or
        # comment-only file, dotenvx scaffolds a placeholder-secrets template
        # (HELLO, AWS_ACCESS_KEY_ID, ...) into it and still exits 0, so a blind
        # delegation fabricates secrets the user never wrote and destroys the
        # original content. ``file_has_assignment`` counts ANY assignment line
        # (including non-identifier keys like ``X-API-KEY`` the strict parser
        # rejects) and tolerates non-UTF-8 bytes, so it neither false-refuses a
        # file of non-identifier secrets nor crashes on a non-UTF-8 file (#443).
        from envdrift.core.partial_encryption import (
            file_has_assignment,
            has_plaintext_secret_value,
        )

        if not file_has_assignment(env_file):
            return EncryptionResult(
                success=False,
                message=(
                    f"Nothing to encrypt: {env_file} has no variables. Refusing "
                    "to run the encryptor, which would otherwise scaffold "
                    "placeholder secrets into the file."
                ),
                file_path=env_file,
            )

        # Refuse a filename dotenvx would turn into an invalid private-key
        # variable name. dotenvx derives the DOTENV_PRIVATE_KEY_<SLUG> env-var
        # name from the filename; a space or non-ASCII character produces an
        # invalid name (e.g. "DOTENV_PRIVATE_KEY_MY SECRETS..."), so the value
        # encrypts and dotenvx exits 0 — but the file is then permanently
        # undecryptable: the original plaintext is destroyed and the secret is
        # locked out for good, and the plaintext-survival check below cannot
        # catch it (the value *is* encrypted, only the key name is unusable).
        # Only [A-Za-z0-9._-] filenames round-trip safely (#443). The same
        # predicate guards DotenvxWrapper.encrypt so the partial-encryption paths
        # that bypass this backend are covered too (#467).
        if not is_dotenvx_safe_filename(env_file.name):
            return EncryptionResult(
                success=False,
                message=(
                    f"Refusing to encrypt {env_file}: its filename contains "
                    "characters dotenvx cannot turn into a valid key name, which "
                    "would leave the file permanently undecryptable. Rename it to "
                    "use only letters, digits, '.', '-' and '_'."
                ),
                file_path=env_file,
            )

        if not self.is_installed():
            raise EncryptionNotFoundError(
                f"dotenvx is not installed.\n{self.install_instructions()}"
            )

        from envdrift.integrations.dotenvx import DotenvxError

        try:
            wrapper = self._get_wrapper()
            wrapper.encrypt(
                env_file=env_file,
                env_keys_file=keys_file,
                env=kwargs.get("env"),
                cwd=kwargs.get("cwd"),
            )
        except DotenvxError as e:
            raise EncryptionBackendError(f"dotenvx encryption failed: {e}") from e

        # Verify the encryption actually took effect rather than trusting the
        # exit code. dotenvx can exit 0 *without* encrypting when the private key
        # is missing or malformed (e.g. .env.keys is a directory, garbage, or a
        # mismatched key); it only prints a warning to stderr. Re-read the file
        # and confirm no plaintext value survived (envdrift #443).
        if has_plaintext_secret_value(env_file):
            return EncryptionResult(
                success=False,
                message=(
                    f"Encryption did not take effect: {env_file} still contains "
                    "plaintext values. This usually means the encryption key was "
                    "missing or invalid."
                ),
                file_path=env_file,
            )

        return EncryptionResult(
            success=True,
            message=f"Encrypted {env_file}",
            file_path=env_file,
        )

    def decrypt(
        self,
        env_file: Path | str,
        keys_file: Path | str | None = None,
        **kwargs,
    ) -> EncryptionResult:
        """
        Decrypt a .env file using dotenvx.

        Parameters:
            env_file (Path | str): Path to the .env file to decrypt.
            keys_file (Path | str | None): Optional path to .env.keys file.
            **kwargs: Additional options:
                - env (dict): Environment variables to pass to subprocess.
                - cwd (Path | str): Working directory for subprocess.

        Returns:
            EncryptionResult: Result of the decryption operation.
        """
        env_file = Path(env_file)

        if not env_file.exists():
            return EncryptionResult(
                success=False,
                message=f"File not found: {env_file}",
                file_path=env_file,
            )

        from envdrift.core.partial_encryption import is_file_encrypted

        # Nothing to decrypt: the file holds no ciphertext value. dotenvx would
        # still rewrite it (line-ending normalization, header cleanup) and exit 0
        # — and handed a binary blob it corrupts the file outright — so report an
        # honest no-op instead of a misleading "[OK] Decrypted" and never invoke
        # the backend on a file that isn't encrypted. ``is_file_encrypted`` reads
        # with errors="replace", so a binary/non-UTF-8 file cannot crash here
        # (envdrift #443).
        if not is_file_encrypted(env_file):
            return EncryptionResult(
                success=True,
                changed=False,
                message=f"Nothing to decrypt: {env_file} has no encrypted values.",
                file_path=env_file,
            )

        if not self.is_installed():
            raise EncryptionNotFoundError(
                f"dotenvx is not installed.\n{self.install_instructions()}"
            )

        from envdrift.integrations.dotenvx import DotenvxError

        try:
            wrapper = self._get_wrapper()
            wrapper.decrypt(
                env_file=env_file,
                env_keys_file=keys_file,
                env=kwargs.get("env"),
                cwd=kwargs.get("cwd"),
            )
        except DotenvxError as e:
            raise EncryptionBackendError(f"dotenvx decryption failed: {e}") from e

        # Verify the decryption took effect rather than trusting the exit code:
        # dotenvx can exit 0 while leaving ciphertext in place when the key is
        # missing or invalid. If any encrypted value survived, report failure.
        if is_file_encrypted(env_file):
            return EncryptionResult(
                success=False,
                changed=False,
                message=(
                    f"Decryption did not take effect: {env_file} still contains "
                    "encrypted values. The decryption key may be missing or invalid."
                ),
                file_path=env_file,
            )

        return EncryptionResult(
            success=True,
            message=f"Decrypted {env_file}",
            file_path=env_file,
        )

    def detect_encryption_status(self, value: str) -> EncryptionStatus:
        """
        Detect the encryption status of a value.

        Parameters:
            value (str): The unquoted value string to classify.

        Returns:
            EncryptionStatus: EMPTY if value is empty, ENCRYPTED if it starts
                              with "encrypted:", PLAINTEXT otherwise.
        """
        if not value:
            return EncryptionStatus.EMPTY

        if self.ENCRYPTED_PATTERN.match(value):
            return EncryptionStatus.ENCRYPTED

        return EncryptionStatus.PLAINTEXT

    def has_encrypted_header(self, content: str) -> bool:
        """
        Check if file content contains dotenvx encryption markers.

        Parameters:
            content (str): Raw file content to inspect.

        Returns:
            bool: True if dotenvx encryption markers are present.
        """
        for marker in self.ENCRYPTED_FILE_MARKERS:
            if marker in content:
                return True
        return False

    def install_instructions(self) -> str:
        """Return installation instructions for dotenvx."""
        from envdrift.integrations.dotenvx import DOTENVX_VERSION

        return f"""
dotenvx is not installed.

Option 1 - Install to ~/.local/bin (recommended):
  curl -sfS "https://dotenvx.sh?directory=$HOME/.local/bin" | sh -s -- --version={DOTENVX_VERSION}
  (Make sure ~/.local/bin is in your PATH)

Option 2 - Install to current directory:
  curl -sfS "https://dotenvx.sh?directory=." | sh -s -- --version={DOTENVX_VERSION}

Option 3 - System-wide install (requires sudo):
  curl -sfS https://dotenvx.sh | sudo sh -s -- --version={DOTENVX_VERSION}

After installing, run your envdrift command again.
"""
