"""Encryption detection for .env files."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from envdrift.core.parser import EncryptionStatus, EnvFile
from envdrift.core.schema import SchemaMetadata


@dataclass
class EncryptionReport:
    """Report on encryption status of an env file."""

    path: Path
    is_fully_encrypted: bool = False
    encrypted_vars: set[str] = field(default_factory=set)
    plaintext_vars: set[str] = field(default_factory=set)
    empty_vars: set[str] = field(default_factory=set)
    plaintext_secrets: set[str] = field(default_factory=set)  # Plaintext vars that look like secrets
    warnings: list[str] = field(default_factory=list)

    @property
    def encryption_ratio(self) -> float:
        """Calculate encryption ratio (encrypted / total non-empty)."""
        total = len(self.encrypted_vars) + len(self.plaintext_vars)
        if total == 0:
            return 0.0
        return len(self.encrypted_vars) / total

    @property
    def total_vars(self) -> int:
        """Total number of variables."""
        return len(self.encrypted_vars) + len(self.plaintext_vars) + len(self.empty_vars)


class EncryptionDetector:
    """Detect encryption status of .env files."""

    # Patterns that indicate encrypted values (dotenvx format)
    ENCRYPTED_PREFIXES = [
        "encrypted:",
    ]

    # Header patterns that indicate the file has been encrypted by dotenvx
    ENCRYPTED_FILE_MARKERS = [
        "#/---BEGIN DOTENV ENCRYPTED---/",
        "DOTENV_PUBLIC_KEY",
    ]

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
    ) -> EncryptionReport:
        """Analyze encryption status of env file.

        Args:
            env_file: Parsed env file
            schema: Optional schema for sensitive field detection

        Returns:
            EncryptionReport with analysis results
        """
        report = EncryptionReport(path=env_file.path)

        # Get sensitive fields from schema
        schema_sensitive = set(schema.sensitive_fields) if schema else set()

        for var_name, env_var in env_file.variables.items():
            if env_var.encryption_status == EncryptionStatus.ENCRYPTED:
                report.encrypted_vars.add(var_name)
            elif env_var.encryption_status == EncryptionStatus.EMPTY:
                report.empty_vars.add(var_name)
            else:
                report.plaintext_vars.add(var_name)

                # Check if this plaintext value looks like a secret
                is_suspicious = self._is_value_suspicious(env_var.value)
                is_name_sensitive = self._is_name_sensitive(var_name)
                is_schema_sensitive = var_name in schema_sensitive

                if is_suspicious or is_name_sensitive or is_schema_sensitive:
                    report.plaintext_secrets.add(var_name)

                    if is_schema_sensitive:
                        report.warnings.append(
                            f"'{var_name}' is marked sensitive in schema but has plaintext value"
                        )
                    elif is_suspicious:
                        report.warnings.append(
                            f"'{var_name}' has a value that looks like a secret"
                        )
                    elif is_name_sensitive:
                        report.warnings.append(
                            f"'{var_name}' has a name suggesting sensitive data"
                        )

        # Determine if fully encrypted
        non_empty_vars = report.encrypted_vars | report.plaintext_vars
        if non_empty_vars:
            report.is_fully_encrypted = len(report.plaintext_vars) == 0

        return report

    def should_block_commit(self, report: EncryptionReport) -> bool:
        """Determine if this file should block a commit.

        Args:
            report: Encryption report

        Returns:
            True if commit should be blocked
        """
        return len(report.plaintext_secrets) > 0

    def has_encrypted_header(self, content: str) -> bool:
        """Check if file content has dotenvx encryption header.

        Args:
            content: Raw file content

        Returns:
            True if encrypted header is present
        """
        for marker in self.ENCRYPTED_FILE_MARKERS:
            if marker in content:
                return True
        return False

    def is_file_encrypted(self, path: Path) -> bool:
        """Quick check if a file appears to be encrypted.

        Args:
            path: Path to the .env file

        Returns:
            True if file appears to be encrypted
        """
        if not path.exists():
            return False

        content = path.read_text(encoding="utf-8")
        return self.has_encrypted_header(content)

    def _is_value_suspicious(self, value: str) -> bool:
        """Check if a plaintext value looks like a secret.

        Args:
            value: The value to check

        Returns:
            True if value appears to be a secret
        """
        for pattern in self.SECRET_VALUE_PATTERNS:
            if pattern.search(value):
                return True
        return False

    def _is_name_sensitive(self, name: str) -> bool:
        """Check if variable name suggests sensitive content.

        Args:
            name: Variable name to check

        Returns:
            True if name suggests sensitive data
        """
        for pattern in self.SENSITIVE_NAME_PATTERNS:
            if pattern.match(name):
                return True
        return False

    def get_recommendations(self, report: EncryptionReport) -> list[str]:
        """Get recommendations based on encryption report.

        Args:
            report: The encryption report

        Returns:
            List of recommendation strings
        """
        recommendations = []

        if report.plaintext_secrets:
            recommendations.append(
                f"Encrypt the following variables before committing: "
                f"{', '.join(sorted(report.plaintext_secrets))}"
            )
            recommendations.append(
                "Run: dotenvx encrypt -f <env_file>"
            )

        if not report.is_fully_encrypted and report.encrypted_vars:
            recommendations.append(
                "File is partially encrypted. Consider encrypting all sensitive values."
            )

        return recommendations
