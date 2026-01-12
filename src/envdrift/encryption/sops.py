"""SOPS encryption backend implementation.

Mozilla SOPS (Secrets OPerationS) is a tool for encrypting values within files
while keeping the structure visible. It supports various key management systems
including AWS KMS, GCP KMS, Azure Key Vault, age, and PGP.

For .env files, SOPS encrypts the values while keeping the key names visible.
Encrypted values have the format: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
"""

from __future__ import annotations

import re
import shutil
import subprocess  # nosec B404
from pathlib import Path
from threading import Lock

from envdrift.encryption.base import (
    EncryptionBackend,
    EncryptionBackendError,
    EncryptionNotFoundError,
    EncryptionResult,
    EncryptionStatus,
)


class SOPSEncryptionBackend(EncryptionBackend):
    """Encryption backend using Mozilla SOPS.

    SOPS encrypts values in-place while preserving file structure.
    It supports multiple key management systems:
    - AWS KMS
    - GCP KMS
    - Azure Key Vault
    - age (modern, simple encryption)
    - PGP

    Configuration is typically stored in .sops.yaml in the project root.
    """

    # Pattern to match SOPS encrypted values
    # Format: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
    ENCRYPTED_PATTERN = re.compile(r"^ENC\[AES256_GCM,")

    # Alternative SOPS patterns (for YAML/JSON metadata)
    SOPS_METADATA_MARKERS = [
        "sops:",  # YAML metadata section
        '"sops":',  # JSON metadata section
        "sops_version:",  # Version marker in metadata
    ]

    def __init__(
        self,
        config_file: Path | str | None = None,
        age_key: str | None = None,
        age_key_file: Path | str | None = None,
        auto_install: bool = False,
    ):
        """
        Initialize the SOPS encryption backend.

        Parameters:
            config_file (Path | str | None): Path to .sops.yaml configuration file.
            age_key (str | None): Age private key for decryption (can also be set via
                                  SOPS_AGE_KEY environment variable).
            age_key_file (Path | str | None): Path to age key file (SOPS_AGE_KEY_FILE).
            auto_install (bool): If True, attempt to auto-install SOPS when missing.
        """
        self._config_file = Path(config_file) if config_file else None
        self._age_key = age_key
        self._age_key_file = Path(age_key_file) if age_key_file else None
        self._auto_install = auto_install
        self._binary_path: Path | None = None
        self._binary_path_lock = Lock()

    @property
    def name(self) -> str:
        """Return backend name."""
        return "sops"

    @property
    def encrypted_value_prefix(self) -> str:
        """Return the prefix used to identify encrypted values."""
        return "ENC["

    def _find_binary(self) -> Path | None:
        """Find the SOPS binary in PATH."""
        if self._binary_path and self._binary_path.exists():
            return self._binary_path

        with self._binary_path_lock:
            if self._binary_path and self._binary_path.exists():
                return self._binary_path

            try:
                from envdrift.integrations.sops import get_sops_path

                venv_path = get_sops_path()
                if venv_path.exists():
                    self._binary_path = venv_path
                    return self._binary_path
            except RuntimeError:
                pass

            # Check system PATH
            sops_path = shutil.which("sops")
            if sops_path:
                self._binary_path = Path(sops_path)
                return self._binary_path

            if self._auto_install:
                from envdrift.integrations.sops import SopsInstaller, SopsInstallError

                try:
                    installer = SopsInstaller()
                    self._binary_path = installer.install()
                    return self._binary_path
                except SopsInstallError:
                    return None

        return None

    def is_installed(self) -> bool:
        """Check if SOPS is installed."""
        return self._find_binary() is not None

    def get_version(self) -> str | None:
        """Get the installed SOPS version."""
        binary = self._find_binary()
        if not binary:
            return None

        try:
            result = subprocess.run(  # nosec B603
                [str(binary), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                # Output is like "sops 3.8.1 (latest)"
                return result.stdout.strip().split()[1] if result.stdout else None
        except Exception:  # nosec B110
            # Intentionally return None for any error during version check
            return None
        return None

    def _build_env(self, env: dict[str, str] | None = None) -> dict[str, str]:
        """Build environment dict with SOPS-specific variables."""
        import os

        result = dict(os.environ)
        if env:
            result.update(env)

        # Add age key if configured
        if self._age_key and "SOPS_AGE_KEY" not in result:
            result["SOPS_AGE_KEY"] = self._age_key
        if self._age_key_file and "SOPS_AGE_KEY_FILE" not in result:
            result["SOPS_AGE_KEY_FILE"] = str(self._age_key_file)

        return result

    def _run(
        self,
        args: list[str],
        env: dict[str, str] | None = None,
        cwd: Path | str | None = None,
    ) -> subprocess.CompletedProcess:
        """Run SOPS command."""
        binary = self._find_binary()
        if not binary:
            raise EncryptionNotFoundError(f"SOPS is not installed.\n{self.install_instructions()}")

        cmd = [str(binary)]

        # Add config file before positional args; SOPS treats late flags as extra paths.
        if self._config_file and self._config_file.exists():
            cmd.extend(["--config", str(self._config_file)])

        cmd.extend(args)

        try:
            result = subprocess.run(  # nosec B603
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                env=self._build_env(env),
                cwd=str(cwd) if cwd else None,
            )
            return result
        except subprocess.TimeoutExpired as e:
            raise EncryptionBackendError("SOPS command timed out") from e
        except FileNotFoundError as e:
            raise EncryptionNotFoundError(f"SOPS binary not found: {e}") from e

    def encrypt(
        self,
        env_file: Path | str,
        keys_file: Path | str | None = None,
        **kwargs,
    ) -> EncryptionResult:
        """
        Encrypt a .env file using SOPS.

        Parameters:
            env_file (Path | str): Path to the .env file to encrypt.
            keys_file (Path | str | None): Not used for SOPS (keys come from .sops.yaml
                                           or environment).
            **kwargs: Additional options:
                - env (dict): Environment variables to pass to subprocess.
                - cwd (Path | str): Working directory for subprocess.
                - in_place (bool): Encrypt in-place (default True).
                - age_recipients (str): Age public keys for encryption.
                - kms_arn (str): AWS KMS key ARN.
                - gcp_kms (str): GCP KMS resource ID.
                - azure_kv (str): Azure Key Vault key URL.

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

        if not self.is_installed():
            raise EncryptionNotFoundError(f"SOPS is not installed.\n{self.install_instructions()}")

        # Build SOPS arguments
        args = ["--encrypt"]

        # Add encryption key options if provided
        if kwargs.get("age_recipients"):
            args.extend(["--age", kwargs["age_recipients"]])
        if kwargs.get("kms_arn"):
            args.extend(["--kms", kwargs["kms_arn"]])
        if kwargs.get("gcp_kms"):
            args.extend(["--gcp-kms", kwargs["gcp_kms"]])
        if kwargs.get("azure_kv"):
            args.extend(["--azure-kv", kwargs["azure_kv"]])

        # In-place encryption by default
        in_place = kwargs.get("in_place", True)
        if in_place:
            args.append("--in-place")

        # Specify input type for .env files
        args.extend(["--input-type", "dotenv", "--output-type", "dotenv"])

        args.append(str(env_file))

        result = self._run(
            args,
            env=kwargs.get("env"),
            cwd=kwargs.get("cwd"),
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            raise EncryptionBackendError(f"SOPS encryption failed: {error_msg}")

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
        Decrypt a .env file using SOPS.

        Parameters:
            env_file (Path | str): Path to the .env file to decrypt.
            keys_file (Path | str | None): Not used for SOPS.
            **kwargs: Additional options:
                - env (dict): Environment variables to pass to subprocess.
                - cwd (Path | str): Working directory for subprocess.
                - in_place (bool): Decrypt in-place (default True).
                - output_file (Path | str): Write output to different file.

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

        if not self.is_installed():
            raise EncryptionNotFoundError(f"SOPS is not installed.\n{self.install_instructions()}")

        # Build SOPS arguments
        args = ["--decrypt"]

        # In-place decryption by default
        in_place = kwargs.get("in_place", True)
        output_file = kwargs.get("output_file")

        if output_file:
            args.extend(["--output", str(output_file)])
        elif in_place:
            args.append("--in-place")

        # Specify input type for .env files
        args.extend(["--input-type", "dotenv", "--output-type", "dotenv"])

        args.append(str(env_file))

        result = self._run(
            args,
            env=kwargs.get("env"),
            cwd=kwargs.get("cwd"),
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            raise EncryptionBackendError(f"SOPS decryption failed: {error_msg}")

        output_path = Path(output_file) if output_file else env_file
        return EncryptionResult(
            success=True,
            message=f"Decrypted {output_path}",
            file_path=output_path,
        )

    def detect_encryption_status(self, value: str) -> EncryptionStatus:
        """
        Detect the encryption status of a value.

        Parameters:
            value (str): The unquoted value string to classify.

        Returns:
            EncryptionStatus: EMPTY if value is empty, ENCRYPTED if it matches
                              SOPS encrypted pattern (ENC[...), PLAINTEXT otherwise.
        """
        if not value:
            return EncryptionStatus.EMPTY

        if self.ENCRYPTED_PATTERN.match(value):
            return EncryptionStatus.ENCRYPTED

        return EncryptionStatus.PLAINTEXT

    def has_encrypted_header(self, content: str) -> bool:
        """
        Check if file content contains SOPS encryption markers.

        Parameters:
            content (str): Raw file content to inspect.

        Returns:
            bool: True if SOPS encryption markers are present.
        """
        # Check for ENC[] encrypted values anywhere in content
        # The pattern is re-created without anchoring to search anywhere
        if "ENC[AES256_GCM," in content:
            return True

        # Check for SOPS metadata markers (in YAML/JSON files)
        for marker in self.SOPS_METADATA_MARKERS:
            if marker in content:
                return True

        return False

    def install_instructions(self) -> str:
        """Return installation instructions for SOPS."""
        from envdrift.integrations.sops import SOPS_VERSION

        return f"""
SOPS is not installed.

Installation options:

macOS (Homebrew):
  brew install sops

Linux (apt):
  # Download latest release from https://github.com/getsops/sops/releases
  wget https://github.com/getsops/sops/releases/download/v{SOPS_VERSION}/sops-v{SOPS_VERSION}.linux.amd64
  chmod +x sops-v{SOPS_VERSION}.linux.amd64
  sudo mv sops-v{SOPS_VERSION}.linux.amd64 /usr/local/bin/sops

Windows (Chocolatey):
  choco install sops

Optional auto-install:
  Set [encryption.sops] auto_install = true in envdrift.toml

After installing SOPS, you'll also need to set up encryption keys.
Common options:
  - age: Simple, modern encryption (recommended for local dev)
    Install: brew install age  # or download from https://github.com/FiloSottile/age
    Generate key: age-keygen -o key.txt
    Set env: export SOPS_AGE_KEY_FILE=key.txt

  - AWS KMS: For AWS-based workflows
  - GCP KMS: For Google Cloud workflows
  - Azure Key Vault: For Azure workflows

See https://github.com/getsops/sops for full documentation.
"""

    def exec_env(
        self,
        env_file: Path | str,
        command: list[str],
        **kwargs,
    ) -> subprocess.CompletedProcess:
        """
        Execute a command with decrypted environment variables.

        SOPS supports running commands with decrypted secrets injected
        as environment variables without writing them to disk.

        Parameters:
            env_file (Path | str): Path to the encrypted .env file.
            command (list[str]): Command and arguments to execute.
            **kwargs: Additional options:
                - env (dict): Additional environment variables.
                - cwd (Path | str): Working directory.

        Returns:
            subprocess.CompletedProcess: Result of the command execution.
        """
        env_file = Path(env_file)

        if not env_file.exists():
            raise EncryptionBackendError(f"File not found: {env_file}")

        if not self.is_installed():
            raise EncryptionNotFoundError(f"SOPS is not installed.\n{self.install_instructions()}")

        # SOPS exec-env runs a command with secrets as environment variables
        args = [
            "exec-env",
            "--input-type",
            "dotenv",
            str(env_file),
            "--",
        ] + command

        return self._run(
            args,
            env=kwargs.get("env"),
            cwd=kwargs.get("cwd"),
        )
