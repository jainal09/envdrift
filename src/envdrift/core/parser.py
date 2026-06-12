"""ENV file parser with multi-backend encryption detection.

Supports:
- dotenvx: Values starting with "encrypted:"
- SOPS: Values starting with "ENC[AES256_GCM,"
"""

from __future__ import annotations

import codecs
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
    - Quoted multiline values (#458): a value opened with ``"`` or ``'``
      continues across physical lines until the matching unescaped close
      quote, exactly like python-dotenv (the parser pydantic-settings uses).
      Newlines inside the value are preserved (normalized to ``\\n``), and the
      python-dotenv escape sets are decoded inside quoted values
      (``\\\\ \\' \\" \\a \\b \\f \\n \\r \\t \\v`` in double quotes,
      ``\\\\ \\'`` in single quotes). An unterminated quote falls back to the
      legacy per-line treatment so malformed files still parse line by line.
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

    # python-dotenv's quoted-value escape sets (dotenv/parser.py): decoded
    # inside double-/single-quoted values so `validate`/`diff` see exactly the
    # values pydantic-settings loads (#458). The value itself runs to the first
    # unescaped close quote — across physical lines — found by
    # ``_find_close_quote`` (an escape-aware scan, equivalent to dotenv's
    # greedy `(?:\\"|[^"])*` lexing without its backtracking pathologies).
    DOUBLE_QUOTE_ESCAPES_PATTERN = re.compile(r"\\[\\'\"abfnrtv]")
    SINGLE_QUOTE_ESCAPES_PATTERN = re.compile(r"\\[\\']")

    # What may legally follow a closing quote on its physical line: optional
    # whitespace and an optional `#...` comment (python-dotenv's `_comment` +
    # `_end_of_line`). Anything else means the quote did not cleanly terminate
    # the assignment, and the legacy raw treatment applies.
    TRAILING_AFTER_QUOTE_PATTERN = re.compile(r"[^\S\r\n]*(?:#.*)?")

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

        # A directory passed where a file is expected used to fall through to
        # read_text and surface an uncaught IsADirectoryError traceback across
        # init/encrypt/decrypt/validate; raise a clean, typed error instead (#25).
        if not path.is_file():
            raise IsADirectoryError(f"Not a file: {path}")

        # A binary / non-UTF-8 file raised a raw UnicodeDecodeError traceback;
        # convert it to a clean ValueError with an actionable message (#24).
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(
                f"Could not read {path} as UTF-8 text (not a valid .env file)"
            ) from exc
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

        index = 0
        while index < len(lines):
            line_num = index + 1
            original_line = lines[index]
            index += 1
            line = original_line.strip()

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
            raw_value = match.group(2)
            raw_lines = [original_line]

            # Quoted multiline continuation (#458): when the RHS opens a quote
            # that closes on a later physical line, the continuation lines are
            # part of THIS value — not new assignments or comments.
            joined_raw, consumed = self._continue_quoted_value(raw_value, lines, index)
            if consumed:
                raw_value = joined_raw
                raw_lines.extend(lines[index : index + consumed])
                index += consumed

            value = self.value_from_raw(raw_value)

            # Determine encryption status and backend
            encryption_status, encryption_backend = self._detect_encryption_status(value)

            env_var = EnvVar(
                name=key,
                value=value,
                line_number=line_num,
                encryption_status=encryption_status,
                raw_line="\n".join(raw_lines),
                encryption_backend=encryption_backend,
            )

            env_file.variables[key] = env_var

        return env_file

    def value_from_raw(self, raw_value: str) -> str:
        """Normalize the raw RHS of a ``KEY=value`` assignment to its final value.

        A cleanly quoted value (single- or multi-line) is lexed exactly like
        python-dotenv: the value runs to the matching unescaped close quote,
        anything after it must be whitespace or a ``#`` comment, and the
        quote-appropriate escape set is decoded (#458). Otherwise the legacy
        treatment applies: strip an unquoted inline comment, then surrounding
        whitespace, then a single matching pair of surrounding quotes. Public so
        callers that recover assignments the strict ``LINE_PATTERN`` rejects
        (e.g. ``init`` for non-identifier keys) reuse this canonical handling
        instead of the private helpers. The whitespace context matters, so pass
        the RAW value (the regex's ``=`` group), unstripped: ``K= # c`` is a
        comment but ``K=#FF0000`` is a value.
        """
        quoted = self._match_quoted_value(raw_value.strip())
        if quoted is not None:
            return quoted
        return self._unquote(self._strip_inline_comment(raw_value).strip())

    def _match_quoted_value(self, text: str) -> str | None:
        """Lex ``text`` as a python-dotenv quoted value, or return ``None``.

        ``text`` must start at the opening quote (callers strip leading
        whitespace). Returns the decoded inner value when the quote closes and
        only whitespace / a ``#`` comment follows on the closing line;
        ``None`` when ``text`` is not quoted, the quote never closes, or
        non-comment content trails the close quote (legacy handling applies).
        """
        if len(text) < 2 or text[0] not in "\"'":
            return None
        close = self._find_close_quote(text)
        if close is None:
            return None
        if not self.TRAILING_AFTER_QUOTE_PATTERN.fullmatch(text, close + 1):
            return None
        escapes = (
            self.DOUBLE_QUOTE_ESCAPES_PATTERN
            if text[0] == '"'
            else self.SINGLE_QUOTE_ESCAPES_PATTERN
        )
        return self._decode_escapes(escapes, text[1:close])

    @staticmethod
    def _find_close_quote(text: str) -> int | None:
        """Index of the unescaped quote closing ``text[0]``, or ``None``.

        Escape-aware scan: a backslash consumes the next character, so ``\\"``
        (or ``\\'``) never closes the value — matching python-dotenv's quoted
        value lexing, where newlines are ordinary value characters.
        """
        quote = text[0]
        i = 1
        n = len(text)
        while i < n:
            ch = text[i]
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                return i
            i += 1
        return None

    def _continue_quoted_value(
        self, raw_value: str, lines: list[str], start: int
    ) -> tuple[str, int]:
        """Extend a quote-opening RHS across physical lines until it closes.

        ``raw_value`` is the RHS of the assignment on the line before
        ``lines[start]``. When it opens a quote that does not terminate on its
        own line, successive lines are joined with ``\\n`` until the matching
        unescaped close quote is found (python-dotenv semantics, #458).

        Returns:
            tuple[str, int]: ``(joined_raw, consumed)`` where ``consumed`` is
            the number of continuation lines absorbed into the value. ``(raw_value, 0)``
            when the RHS is not quoted, already terminates on its own line, is
            never terminated (legacy per-line fallback), or closes with
            non-comment trailing content.
        """
        text = raw_value.strip()
        if not text or text[0] not in "\"'":
            return raw_value, 0
        quote = text[0]
        if self._find_close_quote(text) is not None:
            # The quote terminates on this physical line (validly or not);
            # single-line handling owns it.
            return raw_value, 0

        joined = raw_value
        for offset, next_line in enumerate(lines[start:], start=1):
            joined += "\n" + next_line
            if quote not in next_line:
                continue  # close quote can't be here; skip the re-scan
            lstripped = joined.lstrip()
            close = self._find_close_quote(lstripped)
            if close is None:
                continue  # the quote(s) on this line were escaped
            if self.TRAILING_AFTER_QUOTE_PATTERN.fullmatch(lstripped, close + 1):
                return joined, offset
            # Closes, but non-comment content trails the quote — not a clean
            # quoted value; keep the legacy per-line treatment.
            return raw_value, 0
        return raw_value, 0  # unterminated: legacy per-line fallback

    @staticmethod
    def _decode_escapes(escapes: re.Pattern[str], value: str) -> str:
        """Decode a quoted value's escape sequences like python-dotenv."""
        return escapes.sub(
            lambda match: codecs.decode(match.group(0), "unicode-escape"),
            value,
        )

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
