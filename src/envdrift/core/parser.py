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
        """
        Determine whether this environment variable's value is encrypted.

        Returns:
            True if the variable is encrypted, False otherwise.
        """
        return self.encryption_status == EncryptionStatus.ENCRYPTED

    @property
    def is_empty(self) -> bool:
        """
        Indicates whether the variable's value is empty.

        Returns:
            True if the variable's value is empty, False otherwise.
        """
        return self.encryption_status == EncryptionStatus.EMPTY


@dataclass
class EnvFile:
    """Parsed .env file."""

    path: Path
    variables: dict[str, EnvVar] = field(default_factory=dict)
    comments: list[str] = field(default_factory=list)

    @property
    def is_encrypted(self) -> bool:
        """
        Determine whether the file contains at least one encrypted environment variable.

        Returns:
            `true` if at least one variable in the file is encrypted, `false` otherwise.
        """
        return any(var.is_encrypted for var in self.variables.values())

    @property
    def is_fully_encrypted(self) -> bool:
        """
        Determine whether every non-empty environment variable in the file is encrypted.

        Returns:
            `true` if all non-empty variables have encryption status `ENCRYPTED`, `false` otherwise (also `false` when there are no non-empty variables).
        """
        non_empty_vars = [v for v in self.variables.values() if not v.is_empty]
        if not non_empty_vars:
            return False
        return all(var.is_encrypted for var in non_empty_vars)

    def get(self, name: str) -> EnvVar | None:
        """
        Retrieve the environment variable with the specified name from this EnvFile.

        Parameters:
            name (str): The variable name to look up.

        Returns:
            EnvVar | None: The matching EnvVar if found, `None` otherwise.
        """
        return self.variables.get(name)

    def __contains__(self, name: str) -> bool:
        """
        Determine whether the EnvFile contains a variable with the given name.

        Returns:
            True if a variable with the given name exists in the file, False otherwise.
        """
        return name in self.variables

    def __len__(self) -> int:
        """
        Number of environment variables contained in the EnvFile.

        Returns:
            int: The count of parsed variables.
        """
        return len(self.variables)


class EnvParser:
    """Parse .env files with dotenvx encryption awareness.

    Handles:
    - Standard KEY=value
    - Quoted values: KEY="value" or KEY='value'
    - dotenvx encrypted: KEY="encrypted:xxxx"
    - Comments and blank lines (skipped)

    Note:
        Multiline values are not currently supported. Each line is parsed
        independently. For multiline secrets (e.g., PEM keys), consider
        base64 encoding or using a single-line escaped format.
    """

    # dotenvx encrypted value pattern
    ENCRYPTED_PATTERN = re.compile(r"^encrypted:")

    # Pattern to match KEY=value lines
    LINE_PATTERN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")

    def parse(self, path: Path | str) -> EnvFile:
        """
        Parse a .env file and produce an EnvFile representing its parsed contents.

        Parameters:
            path (Path | str): Filesystem path to the .env file.

        Returns:
            EnvFile: Parsed file containing variables and comments.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"ENV file not found: {path}")

        content = path.read_text(encoding="utf-8")
        env_file = self.parse_string(content)
        env_file.path = path

        return env_file

    def parse_string(self, content: str) -> EnvFile:
        """
        Parse .env formatted text, extracting variables (with detected encryption status) and comments.

        Parameters:
            content (str): The complete text content of a .env file to parse.

        Returns:
            EnvFile: An EnvFile populated with parsed EnvVar entries keyed by variable name and a list of comment lines.
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
        """
        Remove a single matching pair of surrounding single or double quotes from the value.

        Returns:
                the unquoted string if the value is enclosed in matching single quotes ('...') or double quotes ("..."); otherwise the original value
        """
        if len(value) >= 2:
            if (value.startswith('"') and value.endswith('"')) or (
                value.startswith("'") and value.endswith("'")
            ):
                return value[1:-1]
        return value

    def _detect_encryption_status(self, value: str) -> EncryptionStatus:
        """
        Detects the encryption status of an environment variable value.

        Parameters:
            value (str): The unquoted value string to classify.

        Returns:
            EncryptionStatus: `EncryptionStatus.EMPTY` if the value is empty, `EncryptionStatus.ENCRYPTED` if it starts with "encrypted:", otherwise `EncryptionStatus.PLAINTEXT`.
        """
        if not value:
            return EncryptionStatus.EMPTY

        if self.ENCRYPTED_PATTERN.match(value):
            return EncryptionStatus.ENCRYPTED

        return EncryptionStatus.PLAINTEXT
