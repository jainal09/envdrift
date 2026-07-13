"""Encryption detection for .env files.

Supports multiple encryption backends:
- dotenvx: Uses "encrypted:" prefix and dotenvx file headers
- SOPS: Uses "ENC[AES256_GCM,..." format
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from envdrift.core.parser import EncryptionStatus, EnvFile
from envdrift.core.partial_encryption import _is_sops_metadata_key
from envdrift.core.schema import SchemaMetadata
from envdrift.encryption.sops import SOPSEncryptionBackend

if TYPE_CHECKING:
    pass

# dotenvx writes its public key as ``DOTENV_PUBLIC_KEY`` (default env) or
# ``DOTENV_PUBLIC_KEY_<ENV>``. The public key is, by definition, public — never a
# secret to encrypt or flag. Shared so the scanner and encryption analysis agree
# on what the artifact looks like (single source of truth).
DOTENVX_PUBLIC_KEY_PREFIX = "DOTENV_PUBLIC_KEY"


def is_dotenvx_public_key_var(var_name: str) -> bool:
    """Return True if ``var_name`` is dotenvx's public-key artifact.

    Matches the exact ``DOTENV_PUBLIC_KEY`` default and the ``DOTENV_PUBLIC_KEY_<ENV>``
    per-environment form, but not an unrelated variable that merely shares the
    prefix (e.g. ``DOTENV_PUBLIC_KEYSTORE``).
    """
    return var_name == DOTENVX_PUBLIC_KEY_PREFIX or var_name.startswith(
        f"{DOTENVX_PUBLIC_KEY_PREFIX}_"
    )


@dataclass
class EncryptionReport:
    """Report on encryption status of an env file."""

    path: Path
    is_fully_encrypted: bool = False
    encrypted_vars: set[str] = field(default_factory=set)
    plaintext_vars: set[str] = field(default_factory=set)
    empty_vars: set[str] = field(default_factory=set)
    plaintext_secrets: set[str] = field(
        default_factory=set
    )  # Plaintext vars that look like secrets
    warnings: list[str] = field(default_factory=list)
    detected_backend: str | None = None  # Which encryption backend was detected

    @property
    def encryption_ratio(self) -> float:
        """
        Compute the fraction of non-empty variables that are encrypted.

        Returns:
            encryption_ratio (float): Fraction between 0.0 and 1.0 equal to encrypted_vars / (encrypted_vars + plaintext_vars). Returns 0.0 when there are no non-empty variables.
        """
        total = len(self.encrypted_vars) + len(self.plaintext_vars)
        if total == 0:
            return 0.0
        return len(self.encrypted_vars) / total

    @property
    def total_vars(self) -> int:
        """
        Total number of variables considered by the report.

        Returns:
            int: Count of encrypted, plaintext, and empty variables.
        """
        return len(self.encrypted_vars) + len(self.plaintext_vars) + len(self.empty_vars)


class EncryptionDetector:
    """Detect encryption status of .env files.

    Supports multiple encryption backends:
    - dotenvx: Values prefixed with "encrypted:", file has dotenvx headers
    - SOPS: Values in format "ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]"
    """

    # Patterns that indicate encrypted values (dotenvx format)
    DOTENVX_ENCRYPTED_PREFIXES = [
        "encrypted:",
    ]

    # Patterns that indicate encrypted values (SOPS format)
    SOPS_ENCRYPTED_PATTERN = re.compile(r"^ENC\[AES256_GCM,")

    # All encrypted prefixes for backward compatibility
    ENCRYPTED_PREFIXES = DOTENVX_ENCRYPTED_PREFIXES + ["ENC["]

    # Header patterns that indicate the file has been encrypted by dotenvx
    DOTENVX_FILE_MARKERS = [
        "#/---BEGIN DOTENV ENCRYPTED---/",
        "DOTENV_PUBLIC_KEY",
    ]

    # Canonical SOPS encrypted-value envelope (substring is specific enough to
    # match anywhere without false positives).
    SOPS_ENC_VALUE_MARKER = "ENC[AES256_GCM,"

    # Line-anchored SOPS metadata markers (YAML/JSON/dotenv), matched with
    # re.MULTILINE so a bare in-line ``sops:`` substring in a plaintext value
    # (e.g. ``VAULT_ADDR=https://sops:8200``) does NOT match, but a genuine SOPS
    # metadata block in any output format does (#413). Aliased directly to the
    # canonical set on ``SOPSEncryptionBackend`` (the single source of truth) so a
    # new SOPS format variant added there is automatically honoured here — the
    # scanner / ``is_file_encrypted`` / ``detect_backend_for_file`` paths can never
    # silently diverge and false-flag a real SOPS file as "unencrypted".
    SOPS_METADATA_PATTERNS = SOPSEncryptionBackend.SOPS_METADATA_PATTERNS

    # Patterns for suspicious plaintext secrets
    SECRET_VALUE_PATTERNS = [
        re.compile(r"^sk[-_]", re.IGNORECASE),  # Stripe, OpenAI keys
        re.compile(r"^pk[-_]", re.IGNORECASE),  # Public keys
        re.compile(r"^ghp_"),  # GitHub personal tokens
        re.compile(r"^gho_"),  # GitHub OAuth tokens
        re.compile(r"^xox[baprs]-"),  # Slack tokens
        re.compile(r"^AKIA[0-9A-Z]{16}$"),  # AWS access keys
        re.compile(r"^eyJ[A-Za-z0-9_-]+\.eyJ"),  # JWT tokens
        re.compile(r"^postgres(ql)?://[^:]+:[^@]+@"),  # DB URLs with creds
        re.compile(r"^mysql://[^:]+:[^@]+@"),
        re.compile(r"^redis://[^:]+:[^@]+@"),
        re.compile(r"^mongodb(\+srv)?://[^:]+:[^@]+@"),
    ]

    # Variable names that suggest sensitive content
    SENSITIVE_NAME_PATTERNS = [
        re.compile(r".*_KEY$", re.IGNORECASE),
        re.compile(r".*_SECRET$", re.IGNORECASE),
        re.compile(r".*_TOKEN$", re.IGNORECASE),
        re.compile(r".*_PASSWORD$", re.IGNORECASE),
        re.compile(r".*_PASS$", re.IGNORECASE),
        re.compile(r".*_CREDENTIAL.*", re.IGNORECASE),
        re.compile(r".*_API_KEY$", re.IGNORECASE),
        re.compile(r"^JWT_.*", re.IGNORECASE),
        re.compile(r"^AUTH_.*", re.IGNORECASE),
        re.compile(r"^PRIVATE_.*", re.IGNORECASE),
        re.compile(r".*_DSN$", re.IGNORECASE),
    ]

    def analyze(
        self,
        env_file: EnvFile,
        schema: SchemaMetadata | None = None,
        *,
        include_overridden_assignments: bool = False,
    ) -> EncryptionReport:
        """
        Analyze an EnvFile to determine which variables are encrypted, plaintext, empty, and which plaintext values appear to be secrets.

        Parameters:
            env_file (EnvFile): Parsed env file to analyze.
            schema (SchemaMetadata | None): Optional schema whose sensitive_fields will be treated as sensitive names.
            include_overridden_assignments: Analyze every accepted assignment,
                including occurrences hidden by a later duplicate. This is for
                on-disk safety checks; normal config semantics remain
                last-assignment-wins.

        Returns:
            EncryptionReport: Report containing the file path, sets of encrypted/plaintext/empty variables, detected plaintext secrets, collected warnings, and the is_fully_encrypted flag.
        """
        report = EncryptionReport(path=env_file.path)

        # Get sensitive fields from schema
        schema_sensitive = set(schema.sensitive_fields) if schema else set()

        assignments = env_file.variables.values()
        if include_overridden_assignments and env_file.assignments:
            assignments = env_file.assignments
        for env_var in assignments:
            var_name = env_var.name
            # dotenvx's DOTENV_PUBLIC_KEY* artifact is a public key: always
            # plaintext, safe to commit, and never a value to encrypt. Skip it so it
            # neither counts as a plaintext var (which would keep is_fully_encrypted
            # False for a correctly-encrypted file) nor trips the sensitive-name
            # heuristic — a partial-encryption ``.secret`` file's key is named
            # ``DOTENV_PUBLIC_KEY_<ENV>_SECRET``, which matches the ``*_SECRET``
            # pattern and would otherwise be reported as a plaintext secret.
            if is_dotenvx_public_key_var(var_name):
                continue
            # SOPS appends a flat metadata trailer to an encrypted dotenv file
            # (sops_version= / sops_lastmodified= / the recipient public key /
            # sops_mac=). It is bookkeeping, not user data: the plaintext entries
            # are not secrets and sops_mac's ciphertext is not a user variable, so
            # none of it may sway the encrypted/plaintext tallies — counting it
            # reported a fully SOPS-encrypted file as "partially encrypted" in
            # `encrypt --check`. Matches the EXACT metadata key family shared with
            # partial_encryption (#416) — the fixed scalars plus the
            # double-underscore-flattened key-group entries — so a user var merely
            # named sops_token=…, or even one literally named sops_age=…, is
            # still scanned.
            if _is_sops_metadata_key(var_name):
                continue
            if env_var.encryption_status == EncryptionStatus.ENCRYPTED:
                report.encrypted_vars.add(var_name)
            elif env_var.encryption_status == EncryptionStatus.EMPTY:
                report.empty_vars.add(var_name)
            else:
                report.plaintext_vars.add(var_name)

                # Check if this plaintext value looks like a secret
                is_suspicious = self.is_value_suspicious(env_var.value)
                is_name_sensitive = self.is_name_sensitive(var_name)
                is_schema_sensitive = var_name in schema_sensitive

                if is_suspicious or is_name_sensitive or is_schema_sensitive:
                    report.plaintext_secrets.add(var_name)

                    if is_schema_sensitive:
                        report.warnings.append(
                            f"'{var_name}' is marked sensitive in schema but has plaintext value"
                        )
                    elif is_suspicious:
                        report.warnings.append(f"'{var_name}' has a value that looks like a secret")
                    elif is_name_sensitive:
                        report.warnings.append(f"'{var_name}' has a name suggesting sensitive data")

        # Determine if fully encrypted
        non_empty_vars = report.encrypted_vars | report.plaintext_vars
        if non_empty_vars:
            report.is_fully_encrypted = len(report.plaintext_vars) == 0

        detected_backends = {
            env_var.encryption_backend for env_var in assignments if env_var.encryption_backend
        }
        if len(detected_backends) == 1:
            report.detected_backend = next(iter(detected_backends))

        return report

    def should_block_commit(self, report: EncryptionReport) -> bool:
        """
        Decides whether a commit should be blocked due to plaintext secrets found in the report.

        Parameters:
            report (EncryptionReport): Analysis report to evaluate.

        Returns:
            `true` if the report contains any plaintext secrets, `false` otherwise.
        """
        return len(report.plaintext_secrets) > 0

    def has_encrypted_header(self, content: str) -> bool:
        """
        Determine whether the given file content contains encryption markers.

        Parameters:
            content (str): Raw file content to inspect for encryption markers.

        Returns:
            `true` if any encrypted-file marker is present in content, `false` otherwise.
        """
        return self.has_dotenvx_header(content) or self.has_sops_header(content)

    def has_dotenvx_header(self, content: str) -> bool:
        """
        Determine whether the given file content contains a dotenvx encryption header.

        Parameters:
            content (str): Raw file content to inspect for encryption markers.

        Returns:
            `true` if any dotenvx marker is present in content, `false` otherwise.
        """
        for marker in self.DOTENVX_FILE_MARKERS:
            if marker in content:
                return True
        return False

    def has_sops_header(self, content: str) -> bool:
        """
        Determine whether the given file content contains SOPS encryption markers.

        Parameters:
            content (str): Raw file content to inspect for encryption markers.

        Returns:
            `true` if any SOPS marker is present in content, `false` otherwise.

        Structure-aware: requires a canonical ``ENC[AES256_GCM,`` encrypted-value
        envelope or a line-anchored SOPS metadata key, not a bare ``sops:``
        substring. A plaintext value or comment that merely mentions ``sops:``
        (e.g. ``VAULT_ADDR=https://sops:8200``) is NOT treated as encrypted (#413).
        """
        if self.SOPS_ENC_VALUE_MARKER in content:
            return True
        return any(pattern.search(content) for pattern in self.SOPS_METADATA_PATTERNS)

    def detect_backend(self, content: str) -> str | None:
        """
        Detect which encryption backend was used for the content.

        Parameters:
            content (str): Raw file content to inspect.

        Returns:
            "dotenvx", "sops", or None if no encryption detected.
        """
        if self.has_dotenvx_header(content):
            return "dotenvx"
        if self.has_sops_header(content):
            return "sops"
        return None

    def detect_backend_for_file(self, path: Path) -> str | None:
        """
        Detect which encryption backend was used for a file.

        Parameters:
            path (Path): Filesystem path to the file to inspect.

        Returns:
            "dotenvx", "sops", or None if no encryption detected.
        """
        if not path.exists():
            return None

        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            # Not readable as UTF-8 text (binary blob, directory, ...): it is not a
            # dotenvx/sops-encrypted file, so no backend is detected. Returning
            # None (rather than crashing) lets decrypt auto-detect fall back to a
            # clean per-backend message instead of a raw traceback (#13).
            return None
        return self.detect_backend(content)

    def is_file_encrypted(self, path: Path) -> bool:
        """
        Determine whether a file contains encryption markers.

        Parameters:
            path (Path): Filesystem path to the file to inspect.

        Returns:
            `true` if the file contains encryption markers, `false` otherwise.
        """
        if not path.exists():
            return False

        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            # A non-UTF-8/binary file or a directory holds no encryption markers.
            return False
        return self.has_encrypted_header(content)

    def is_value_encrypted(self, value: str) -> bool:
        """
        Determine whether a value is encrypted by any supported backend.

        Parameters:
            value (str): The value to check.

        Returns:
            True if the value appears encrypted, False otherwise.
        """
        if not value:
            return False

        # Check dotenvx format
        for prefix in self.DOTENVX_ENCRYPTED_PREFIXES:
            if value.startswith(prefix):
                return True

        # Check SOPS format
        return bool(self.SOPS_ENCRYPTED_PATTERN.match(value))

    def detect_value_backend(self, value: str) -> str | None:
        """
        Detect which encryption backend was used for a specific value.

        Parameters:
            value (str): The value to check.

        Returns:
            "dotenvx", "sops", or None if not encrypted.
        """
        if not value:
            return None

        # Check dotenvx format
        for prefix in self.DOTENVX_ENCRYPTED_PREFIXES:
            if value.startswith(prefix):
                return "dotenvx"

        # Check SOPS format
        if self.SOPS_ENCRYPTED_PATTERN.match(value):
            return "sops"

        return None

    def is_value_suspicious(self, value: str) -> bool:
        """
        Determine whether a plaintext value matches any configured secret patterns.

        Returns:
            `true` if the value appears to be a secret, `false` otherwise.
        """
        for pattern in self.SECRET_VALUE_PATTERNS:
            if pattern.search(value):
                return True
        return False

    def is_name_sensitive(self, name: str) -> bool:
        """
        Determine whether an environment variable name indicates sensitive data.

        Parameters:
            name (str): The environment variable name to test.

        Returns:
            True if the name matches any configured sensitive-name pattern, False otherwise.
        """
        for pattern in self.SENSITIVE_NAME_PATTERNS:
            if pattern.match(name):
                return True
        return False

    def get_recommendations(
        self,
        report: EncryptionReport,
        backend: str | None = None,
    ) -> list[str]:
        """
        Builds human-readable remediation recommendations derived from an EncryptionReport.

        Parameters:
            report (EncryptionReport): Analysis result for a single .env file used to derive recommendations.
            backend (str | None): Encryption backend to recommend ("dotenvx", "sops", or None for auto-detect).

        Returns:
            list[str]: Ordered list of recommendation strings; empty if no actions are suggested.
        """
        recommendations = []

        # Use detected backend if not specified
        if backend is None:
            backend = report.detected_backend or "dotenvx"

        if report.plaintext_secrets:
            recommendations.append(
                f"Encrypt the following variables before committing: "
                f"{', '.join(sorted(report.plaintext_secrets))}"
            )

            if backend == "sops":
                recommendations.append(f"Run: envdrift encrypt --backend sops {report.path}")
            else:
                recommendations.append(f"Run: envdrift encrypt {report.path}")

        if not report.is_fully_encrypted and report.encrypted_vars:
            recommendations.append(
                "File is partially encrypted. Consider encrypting all sensitive values."
            )

        return recommendations
