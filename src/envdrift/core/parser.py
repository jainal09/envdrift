"""ENV file parser with dotenvx encryption detection."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class EncryptionStatus(Enum):
    """Encryption status of an environment variable."""

    ENCRYPTED = "encrypted"  # dotenvx encrypted value (starts with "encrypted:")
    PLAINTEXT = "plaintext"  # Unencrypted value
    EMPTY = "empty"  # No value (KEY= or KEY="")


@dataclass
class EnvVar:
    """Parsed environment variable."""

    name: str
    value: str
    line_number: int
    encryption_status: EncryptionStatus
    raw_line: str

    @property
    def is_encrypted(self) -> bool:
        """Check if this variable is encrypted."""
        return self.encryption_status == EncryptionStatus.ENCRYPTED

    @property
    def is_empty(self) -> bool:
        """Check if this variable has an empty value."""
        return self.encryption_status == EncryptionStatus.EMPTY


@dataclass
class EnvFile:
    """Parsed .env file."""

    path: Path
    variables: dict[str, EnvVar] = field(default_factory=dict)
    comments: list[str] = field(default_factory=list)

    @property
    def is_encrypted(self) -> bool:
        """Check if ANY variable in this file is encrypted."""
        return any(var.is_encrypted for var in self.variables.values())

    @property
    def is_fully_encrypted(self) -> bool:
        """Check if ALL non-empty variables are encrypted."""
        non_empty_vars = [v for v in self.variables.values() if not v.is_empty]
        if not non_empty_vars:
            return False
        return all(var.is_encrypted for var in non_empty_vars)

    def get(self, name: str) -> EnvVar | None:
        """Get a variable by name."""
        return self.variables.get(name)

    def __contains__(self, name: str) -> bool:
        """Check if a variable exists."""
        return name in self.variables

    def __len__(self) -> int:
        """Return number of variables."""
        return len(self.variables)


class EnvParser:
    """Parse .env files with dotenvx encryption awareness.

    Handles:
    - Standard KEY=value
    - Quoted values: KEY="value" or KEY='value'
    - dotenvx encrypted: KEY="encrypted:xxxx"
    - Comments and blank lines (skipped)
    - Multiline values (basic support)
    """

    # dotenvx encrypted value pattern
    ENCRYPTED_PATTERN = re.compile(r"^encrypted:")

    # Pattern to match KEY=value lines
    LINE_PATTERN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")

    def parse(self, path: Path | str) -> EnvFile:
        """Parse .env file and return structured data.

        Args:
            path: Path to the .env file

        Returns:
            EnvFile with parsed variables

        Raises:
            FileNotFoundError: If the file doesn't exist
        """
        path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"ENV file not found: {path}")

        content = path.read_text(encoding="utf-8")
        env_file = self.parse_string(content)
        env_file.path = path

        return env_file

    def parse_string(self, content: str) -> EnvFile:
        """Parse .env content from string.

        Args:
            content: String content of .env file

        Returns:
            EnvFile with parsed variables
        """
        env_file = EnvFile(path=Path())
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            original_line = line
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            # Collect comments
            if line.startswith("#"):
                env_file.comments.append(line)
                continue

            # Parse KEY=value
            match = self.LINE_PATTERN.match(line)
            if not match:
                continue

            key = match.group(1)
            value = match.group(2).strip()

            # Remove surrounding quotes
            value = self._unquote(value)

            # Determine encryption status
            encryption_status = self._detect_encryption_status(value)

            env_var = EnvVar(
                name=key,
                value=value,
                line_number=line_num,
                encryption_status=encryption_status,
                raw_line=original_line,
            )

            env_file.variables[key] = env_var

        return env_file

    def _unquote(self, value: str) -> str:
        """Remove surrounding quotes from a value.

        Handles:
        - Double quotes: "value"
        - Single quotes: 'value'
        """
        if len(value) >= 2:
            if (value.startswith('"') and value.endswith('"')) or (
                value.startswith("'") and value.endswith("'")
            ):
                return value[1:-1]
        return value

    def _detect_encryption_status(self, value: str) -> EncryptionStatus:
        """Detect the encryption status of a value.

        Args:
            value: The unquoted value string

        Returns:
            EncryptionStatus enum value
        """
        if not value:
            return EncryptionStatus.EMPTY

        if self.ENCRYPTED_PATTERN.match(value):
            return EncryptionStatus.ENCRYPTED

        return EncryptionStatus.PLAINTEXT
