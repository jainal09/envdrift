"""ENV file parser with multi-backend encryption detection.

Supports:
- dotenvx: Values starting with "encrypted:"
- SOPS: Values starting with "ENC[AES256_GCM,"
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class EncryptionStatus(Enum):
    """Encryption status of an environment variable."""

    ENCRYPTED = "encrypted"  # Encrypted value (dotenvx or SOPS)
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
    encryption_backend: str | None = None  # "dotenvx", "sops", or None

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
    """Parse .env files with multi-backend encryption awareness.

    Handles:
    - Standard KEY=value
    - Quoted values: KEY="value" or KEY='value'
    - dotenvx encrypted: KEY="encrypted:xxxx"
    - SOPS encrypted: KEY="ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]"
    - Comments and blank lines (skipped)

    Note:
        Multiline values are not currently supported. Each line is parsed
        independently. For multiline secrets (e.g., PEM keys), consider
        base64 encoding or using a single-line escaped format.
    """

    # dotenvx encrypted value pattern
    DOTENVX_ENCRYPTED_PATTERN = re.compile(r"^encrypted:")

    # SOPS encrypted value pattern
    SOPS_ENCRYPTED_PATTERN = re.compile(r"^ENC\[AES256_GCM,")

    # Combined pattern for backward compatibility
    ENCRYPTED_PATTERN = re.compile(r"^(encrypted:|ENC\[AES256_GCM,)")

    # Pattern to match KEY=value lines (optionally prefixed with `export `)
    # Note: no `\s*` after `=` — leading value whitespace is captured in group(2)
    # so _strip_inline_comment can distinguish `K= # c` (comment) from `K=#v`
    # (a value beginning with `#`). Leading/trailing whitespace is stripped after.
    LINE_PATTERN = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")

    # Lenient variant for ``lenient=True``: accepts ANY key the strict pattern
    # rejects (leading digit ``1PW``, dash ``X-API-KEY``, dot, non-ASCII letter
    # ``CAFÉ``). ``init`` and ``validate`` use it so a non-identifier key is
    # represented end-to-end (in the generated schema *and* matched against the
    # .env), keeping the init→validate round-trip intact. Other callers keep the
    # strict pattern so their behaviour is unchanged.
    LENIENT_LINE_PATTERN = re.compile(r"^(?:export\s+)?([^\s=#]+)\s*=(.*)$")

    def parse(self, path: Path | str, *, lenient: bool = False) -> EnvFile:
        """
        Parse a .env file and produce an EnvFile representing its parsed contents.

        Parameters:
            path (Path | str): Filesystem path to the .env file.
            lenient (bool): When True, also recover keys the strict pattern
                rejects (non-identifier / non-ASCII), so the parsed variable set
                matches every assignment in the file.

        Returns:
            EnvFile: Parsed file containing variables and comments.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"ENV file not found: {path}")

        content = path.read_text(encoding="utf-8")
        env_file = self.parse_string(content, lenient=lenient)
        env_file.path = path

        return env_file

    def parse_string(self, content: str, *, lenient: bool = False) -> EnvFile:
        """
        Parse .env formatted text, extracting variables (with detected encryption status) and comments.

        Parameters:
            content (str): The complete text content of a .env file to parse.
            lenient (bool): When True, accept non-identifier / non-ASCII keys too
                (see ``LENIENT_LINE_PATTERN``).

        Returns:
            EnvFile: An EnvFile populated with parsed EnvVar entries keyed by variable name and a list of comment lines.
        """
        env_file = EnvFile(path=Path())
        lines = content.splitlines()
        pattern = self.LENIENT_LINE_PATTERN if lenient else self.LINE_PATTERN

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
            match = pattern.match(line)
            if not match:
                continue

            key = match.group(1)
            value = self.value_from_raw(match.group(2))

            # Determine encryption status and backend
            encryption_status, encryption_backend = self._detect_encryption_status(value)

            env_var = EnvVar(
                name=key,
                value=value,
                line_number=line_num,
                encryption_status=encryption_status,
                raw_line=original_line,
                encryption_backend=encryption_backend,
            )

            env_file.variables[key] = env_var

        return env_file

    def value_from_raw(self, raw_value: str) -> str:
        """Normalize the raw RHS of a ``KEY=value`` line to its final value.

        Strips an unquoted inline comment, then surrounding whitespace, then a
        single matching pair of surrounding quotes — the same transformation
        ``parse`` applies. Public so callers that recover assignments the strict
        ``LINE_PATTERN`` rejects (e.g. ``init`` for non-identifier keys) reuse
        this canonical handling instead of the private helpers. The whitespace
        context matters, so pass the RAW value (the regex's ``=`` group),
        unstripped: ``K= # c`` is a comment but ``K=#FF0000`` is a value.
        """
        return self._unquote(self._strip_inline_comment(raw_value).strip())

    def _strip_inline_comment(self, value: str) -> str:
        """Strip an unquoted trailing ` #...` comment from a (raw) value.

        A `#` starts a comment only when it is outside quotes AND preceded by
        whitespace. A `#` at the very start of the value (e.g. `#FF0000`), inside
        matching quotes, glued to a token (`http://x#frag`), or escaped (`\\#`,
        and an escaped quote `\\"` that must not toggle quote state), is
        preserved. Call this on the raw `value` (before stripping) so the
        whitespace context is intact.
        """
        # Fast path: the overwhelming majority of values contain no `#`, so skip
        # the per-character quote-tracking scan entirely for them.
        if "#" not in value:
            return value

        in_single = False
        in_double = False
        i = 0
        n = len(value)
        while i < n:
            ch = value[i]
            if ch == "\\" and i + 1 < n:
                # An escaped char can't open/close a quote or start a comment.
                i += 2
                continue
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                in_double = not in_double
            elif ch == "#" and not in_single and not in_double and i > 0 and value[i - 1].isspace():
                return value[:i].rstrip()
            i += 1
        return value

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

    def _detect_encryption_status(self, value: str) -> tuple[EncryptionStatus, str | None]:
        """
        Detects the encryption status and backend of an environment variable value.

        Parameters:
            value (str): The unquoted value string to classify.

        Returns:
            tuple[EncryptionStatus, str | None]: A tuple of (status, backend) where:
                - status is EncryptionStatus.EMPTY, ENCRYPTED, or PLAINTEXT
                - backend is "dotenvx", "sops", or None
        """
        if not value:
            return EncryptionStatus.EMPTY, None

        # Check for dotenvx encrypted format
        if self.DOTENVX_ENCRYPTED_PATTERN.match(value):
            return EncryptionStatus.ENCRYPTED, "dotenvx"

        # Check for SOPS encrypted format
        if self.SOPS_ENCRYPTED_PATTERN.match(value):
            return EncryptionStatus.ENCRYPTED, "sops"

        return EncryptionStatus.PLAINTEXT, None
