"""ENV file parser with multi-backend encryption detection.

Supports:
- dotenvx: Values starting with "encrypted:"
- SOPS: Values starting with "ENC[AES256_GCM,"
"""

from __future__ import annotations

import os
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
    # True when the source text began with a UTF-8 BOM (U+FEFF). The parser
    # strips it so reports name the variable the user wrote — but
    # pydantic-settings reads .env files as plain UTF-8 and would see a
    # ``U+FEFF``-prefixed first key, so `validate` surfaces a warning (#486).
    leading_bom: bool = False

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
      continues across physical lines until the matching close quote, exactly
      like python-dotenv (the parser pydantic-settings uses). Newlines inside
      the value are preserved (normalized to ``\\n``), and the python-dotenv
      escape sets are decoded inside quoted values
      (``\\\\ \\' \\" \\a \\b \\f \\n \\r \\t \\v`` in double quotes,
      ``\\\\ \\'`` in single quotes). Malformed quoted bindings are rejected
      exactly like python-dotenv — no variable is registered for them.
      Non-comment content after the close quote consumes the physical lines
      through the close-quote line, so interior lines never re-parse as
      phantom assignments; an unterminated quote (no quote left anywhere)
      consumes only its opening line — dotenv's rest-of-line error recovery —
      and the following lines are parsed normally.
    - ``${VAR}`` / ``${VAR:-default}`` interpolation (#486), resolved exactly
      like python-dotenv's default ``interpolate=True``: earlier values in the
      same file win over ``os.environ``; an unset name yields the default or
      ``""``.
    - Unquoted values follow python-dotenv's ``parse_unquoted_value`` rule
      (#486/#537): the whitespace right after ``=`` is consumed first, then
      the value is cut at the first whitespace-preceded ``#`` — so ``K= # c``
      is the value ``# c``, and a stray quote mid-token never opens a quote
      context.
    - Physical lines end at ``\\n`` / ``\\r\\n`` / ``\\r`` only; other Unicode
      line boundaries (U+2028, form feed, ...) are value content (#486).
    - A leading UTF-8 BOM is an encoding artifact: it is stripped from the
      first key and recorded on ``EnvFile.leading_bom`` so ``validate`` can
      warn (pydantic-settings reads plain UTF-8 and keeps the BOM) (#486).
    """

    # dotenvx encrypted value pattern
    DOTENVX_ENCRYPTED_PATTERN = re.compile(r"^encrypted:")

    # SOPS encrypted value pattern
    SOPS_ENCRYPTED_PATTERN = re.compile(r"^ENC\[AES256_GCM,")

    # Combined pattern for backward compatibility
    ENCRYPTED_PATTERN = re.compile(r"^(encrypted:|ENC\[AES256_GCM,)")

    # Pattern to match KEY=value lines (optionally prefixed with `export `)
    # Note: no `\s*` after `=` — leading value whitespace is captured in group(2)
    # so the unquoted-value rule can consume it exactly like python-dotenv's
    # `_equal_sign` lexer (`=[^\S\r\n]*`) before the value starts (#537).
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
    # values pydantic-settings loads (#458). The value itself runs to the
    # close quote — across physical lines — found by ``_find_close_quote``,
    # which reproduces dotenv's greedy `"((?:\\"|[^"])*)"` lexing exactly.
    DOUBLE_QUOTE_ESCAPES_PATTERN = re.compile(r"\\[\\'\"abfnrtv]")
    SINGLE_QUOTE_ESCAPES_PATTERN = re.compile(r"\\[\\']")

    # What each escape sequence decodes to (python-dotenv's decode_escapes
    # output). The tables are total for the patterns above, so decoding is a
    # plain lookup — no `codecs` bytes-codec coercion on `str` input.
    ESCAPE_DECODE_TABLE = {
        "\\\\": "\\",
        "\\'": "'",
        '\\"': '"',
        "\\a": "\a",
        "\\b": "\b",
        "\\f": "\f",
        "\\n": "\n",
        "\\r": "\r",
        "\\t": "\t",
        "\\v": "\v",
    }

    # What may legally follow a closing quote on its physical line: optional
    # whitespace and an optional `#...` comment (python-dotenv's `_comment` +
    # `_end_of_line`). Anything else means the quote did not cleanly terminate
    # the assignment, and the legacy raw treatment applies.
    TRAILING_AFTER_QUOTE_PATTERN = re.compile(r"[^\S\r\n]*(?:#.*)?")

    # .env line boundaries are `\n` / `\r\n` / `\r` ONLY (python-dotenv's
    # `_end_of_line`). `str.splitlines()` also severed values at the wider
    # Unicode line-boundary set (U+2028, form feed, NEL, ...), truncating the
    # value and fabricating phantom variables from its tail (#486).
    LINE_BOUNDARY_PATTERN = re.compile(r"\r\n|\r|\n")

    # python-dotenv's `${name}` / `${name:-default}` interpolation pattern
    # (dotenv/variables.py `_posix_variable`), expanded by `_interpolate` (#486).
    POSIX_VARIABLE_PATTERN = re.compile(r"\$\{(?P<name>[^}:]*)(?::-(?P<default>[^}]*))?\}")

    # python-dotenv's unquoted-value comment rule (dotenv/parser.py
    # `parse_unquoted_value`): applied AFTER the post-`=` whitespace is
    # consumed, the first whitespace-preceded `#` starts the comment. A `#`
    # that begins the value (`K= # c`, `K=#FF0000`) is value content, and a
    # quote character mid-token never opens a quote context (#486/#537).
    UNQUOTED_COMMENT_PATTERN = re.compile(r"\s+#.*")

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
        # Plain utf-8 (not utf-8-sig) so a leading BOM reaches parse_string,
        # which strips it AND records it on EnvFile.leading_bom (#486).
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
        content, env_file.leading_bom = self._strip_leading_bom(content)
        lines = self.LINE_BOUNDARY_PATTERN.split(content)
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

            # Parse KEY=value. Match the lstripped line — NOT the fully
            # stripped one — so the RHS keeps its trailing whitespace: when a
            # quote opens here and closes on a later line, python-dotenv keeps
            # that whitespace inside the value (`CERT="abc   \nrest"` parses
            # as `abc   \nrest`); single-line values strip it downstream.
            match = pattern.match(original_line.lstrip())
            if not match:
                continue

            key = match.group(1)
            raw_value = match.group(2)
            raw_lines = [original_line]

            # Quoted multiline continuation (#458): when the RHS opens a quote
            # that closes on a later physical line, the continuation lines are
            # part of THIS value — not new assignments or comments.
            joined_raw, consumed, dropped = self._continue_quoted_value(raw_value, lines, index)
            index += consumed
            if dropped:
                # python-dotenv rejects this binding and NO variable is
                # registered (#458). Trailing junk after the close quote:
                # `consumed` covers through the close-quote line, so interior
                # lines never become phantom assignments. Unterminated quote:
                # `consumed` is 0 — only the opening line is dropped and the
                # following lines re-parse normally, exactly like dotenv's
                # rest-of-line error recovery.
                continue
            if consumed:
                raw_value = joined_raw
                raw_lines.extend(lines[index - consumed : index])

            value = self.value_from_raw(raw_value)

            # ${VAR} interpolation (#486): expand exactly like dotenv_values —
            # the loader pydantic-settings uses — so validate/diff judge the
            # value the application receives, not the unexpanded literal.
            if "${" in value:
                value = self._interpolate(value, env_file.variables)

            # Determine encryption status and backend. Detection runs on the
            # interpolated value, so an alias of an encrypted variable
            # (`B=${A}` with `A=encrypted:...`) is classified ENCRYPTED too —
            # deliberate: the file stores only the reference (no plaintext
            # secret on disk), and classifying it PLAINTEXT would make
            # encrypt/lock re-encrypt the literal `${A}` on every run.
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

    @staticmethod
    def _strip_leading_bom(content: str) -> tuple[str, bool]:
        """Strip a leading UTF-8 BOM, reporting whether one was present.

        A leading BOM is an encoding artifact (Notepad/PowerShell), not part
        of the first key — keeping it produced an invisible phantom
        ``U+FEFF``-prefixed ``NAME`` variable and self-contradictory
        MISSING+EXTRA output. It is stripped but recorded on
        ``EnvFile.leading_bom``: pydantic-settings reads plain UTF-8 and WOULD
        see the ``U+FEFF``-prefixed key, so ``validate`` warns (#486).
        """
        if content.startswith("\ufeff"):
            return content.removeprefix("\ufeff"), True
        return content, False

    def value_from_raw(self, raw_value: str) -> str:
        """Normalize the raw RHS of a ``KEY=value`` assignment to its final value.

        A cleanly quoted value (single- or multi-line) is lexed exactly like
        python-dotenv: the value runs to the matching close quote (see
        ``_scan_chunk``), anything after it must be whitespace or a ``#``
        comment, and the quote-appropriate escape set is decoded (#458). A
        value that does not open with a quote follows python-dotenv's
        ``parse_unquoted_value`` rule (see ``_parse_unquoted_value``). A value
        that opens a quote which does not terminate cleanly keeps the legacy
        treatment (quote-aware comment strip, then surrounding whitespace,
        then one pair of surrounding quotes) — note ``parse_string`` never
        takes that path (it drops malformed quoted bindings like
        python-dotenv); it serves direct callers only. The whitespace context
        matters, so pass the RAW value (the regex's ``=`` group), unstripped:
        ``K= # c`` is the value ``# c`` but ``K=v # c`` is ``v``.
        """
        stripped = raw_value.strip()
        quoted = self._match_quoted_value(stripped)
        if quoted is not None:
            return quoted
        if stripped[:1] in ("'", '"'):
            # Malformed quoted binding: parse_string drops these before ever
            # calling here (dotenv parity, #458); legacy handling for direct
            # callers that need a best-effort value.
            return self._unquote(self._strip_inline_comment(raw_value).strip())
        return self._parse_unquoted_value(raw_value)

    def _parse_unquoted_value(self, raw_value: str) -> str:
        """Lex an unquoted RHS exactly like python-dotenv (#486/#537).

        python-dotenv's ``_equal_sign`` lexer (``=[^\\S\\r\\n]*``) consumes the
        whitespace right after ``=`` BEFORE the value starts, then
        ``parse_unquoted_value`` applies ``re.sub(r"\\s+#.*", "", part)`` and
        ``.rstrip()``. A ``#`` at the start of the value therefore has no
        preceding whitespace inside the value and is content: ``K= # c`` is
        ``# c`` (dotenv_values: ``{'K': '# c'}``), while ``K= v # c`` is
        ``v``.
        """
        part = raw_value.lstrip()
        return self.UNQUOTED_COMMENT_PATTERN.sub("", part).rstrip()

    def _match_quoted_value(self, text: str) -> str | None:
        """Lex ``text`` as a python-dotenv quoted value, or return ``None``.

        ``text`` must start at the opening quote (callers strip leading
        whitespace). Returns the decoded inner value when the quote closes and
        only whitespace / a ``#`` comment follows on the closing line;
        ``None`` when ``text`` is not quoted, the quote never closes, or
        non-comment content trails the close quote. The trailing check is safe
        on multiline ``text``: ``TRAILING_AFTER_QUOTE_PATTERN`` cannot match
        across a newline (``[^\\S\\r\\n]`` excludes them and ``#.*`` stops at
        one), and ``parse_string`` only builds joined values that end on the
        close-quote line.
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
    def _scan_chunk(chunk: str, quote: str, start: int) -> tuple[int | None, int | None]:
        """Scan ``chunk[start:]`` for close-quote candidates (dotenv semantics).

        python-dotenv lexes a quoted value with the greedy backtracking regex
        ``"((?:\\\\"|[^"])*)"``: a quote can sit INSIDE the value only when it
        is immediately preceded by a backslash, so the value closes at the
        first quote NOT preceded by a backslash — or, when every quote is
        backslash-preceded, at the last quote (the regex gives the final
        ``\\"`` pair back and reads it as backslash + close quote).

        Returns:
            tuple[int | None, int | None]: ``(definitive, fallback)`` —
            ``definitive`` is the index of the first quote in ``chunk[start:]``
            not immediately preceded by a backslash (the value must close
            there); ``fallback`` is the index of the last backslash-preceded
            quote seen before it (the close python-dotenv settles on when no
            definitive close exists anywhere in the remaining input). A quote
            at index 0 is always definitive: its predecessor in the joined
            text is the ``\\n`` joiner (or the opening quote), never a
            backslash.
        """
        fallback = None
        i = chunk.find(quote, start)
        while i != -1:
            if i > 0 and chunk[i - 1] == "\\":
                fallback = i
                i = chunk.find(quote, i + 1)
                continue
            return i, fallback
        return None, fallback

    @staticmethod
    def _find_close_quote(text: str) -> int | None:
        """Index of the quote closing ``text[0]``, or ``None`` (dotenv rules).

        The first quote not immediately preceded by a backslash; when every
        quote is backslash-preceded, the last one (see ``_scan_chunk``).
        Newlines are ordinary value characters.
        """
        definitive, fallback = EnvParser._scan_chunk(text, text[0], 1)
        return definitive if definitive is not None else fallback

    def _continue_quoted_value(
        self, raw_value: str, lines: list[str], start: int
    ) -> tuple[str, int, bool]:
        """Lex a quote-opening RHS exactly like python-dotenv (#458).

        ``raw_value`` is the RHS of the assignment on the line before
        ``lines[start]``. When it opens a quote, the close quote is searched
        across the remaining physical lines (python-dotenv's value regex spans
        newlines). Each line is scanned once with ``_scan_chunk`` — a cursor
        never re-visits earlier lines, so the scan is linear in the input.

        Returns:
            tuple[str, int, bool]: ``(joined_raw, consumed, dropped)``.
            ``consumed`` is the number of continuation lines absorbed (0 when
            the binding starts and ends on its own line). ``dropped`` is True
            when python-dotenv rejects the binding and registers nothing:
            non-comment content after the close quote (input consumed through
            the close-quote line), or no quote left anywhere (unterminated —
            only the opening line is consumed, matching dotenv's
            rest-of-line error recovery). ``(raw_value, 0, False)`` when the
            RHS does not open with a quote.
        """
        text = raw_value.strip()
        if not text or text[0] not in "\"'":
            return raw_value, 0, False
        quote = text[0]

        # Chunk 0 is the (stripped) opening RHS; chunks 1.. are raw lines.
        close: tuple[int, int] | None = None  # (chunk number, index in chunk)
        last_fallback: tuple[int, int] | None = None
        chunks = [text]
        definitive, fallback = self._scan_chunk(text, quote, 1)
        if fallback is not None:
            last_fallback = (0, fallback)
        if definitive is not None:
            close = (0, definitive)
        else:
            for offset, next_line in enumerate(lines[start:], start=1):
                chunks.append(next_line)
                if quote not in next_line:
                    continue  # close quote can't be here; skip the scan
                definitive, fallback = self._scan_chunk(next_line, quote, 0)
                if fallback is not None:
                    last_fallback = (offset, fallback)
                if definitive is not None:
                    close = (offset, definitive)
                    break
            if close is None:
                if last_fallback is None:
                    # Unterminated: dotenv's value regex never matches, its
                    # error path consumes the rest of the opening line only,
                    # and the binding is dropped.
                    return raw_value, 0, True
                close = last_fallback

        # After the close quote, only whitespace and a `#` comment may follow
        # on the closing line (dotenv's `_comment` + `_end_of_line`); anything
        # else raises in dotenv and drops the binding, consuming the input
        # through the close-quote line.
        close_chunk, close_idx = close
        if not self.TRAILING_AFTER_QUOTE_PATTERN.fullmatch(chunks[close_chunk], close_idx + 1):
            return raw_value, close_chunk, True
        if close_chunk == 0:
            return raw_value, 0, False
        joined = raw_value + "\n" + "\n".join(lines[start : start + close_chunk])
        return joined, close_chunk, False

    def _decode_escapes(self, escapes: re.Pattern[str], value: str) -> str:
        """Decode a quoted value's escape sequences like python-dotenv.

        ``ESCAPE_DECODE_TABLE`` is total for both escape patterns, and non-
        matching text (including any non-ASCII) is passed through untouched —
        no whole-string ``unicode-escape`` round-trip that could mojibake it.
        """
        return escapes.sub(lambda match: self.ESCAPE_DECODE_TABLE[match.group(0)], value)

    def _interpolate(self, value: str, parsed: dict[str, EnvVar]) -> str:
        """Expand ``${NAME}`` / ``${NAME:-default}`` like python-dotenv (#486).

        ``dotenv_values`` (the loader pydantic-settings wraps) resolves
        variable references in every value — quoted or not — sequentially:
        a name already defined earlier in the file wins over ``os.environ``
        (``override=True`` semantics), an unset name falls back to the ``:-``
        default or ``""``, and replacement text is never re-expanded.

        python-dotenv materializes ``os.environ`` into a plain dict
        (``env.update(os.environ)`` in ``resolve_variables``) and looks names
        up case-SENSITIVELY. Mirror that with a dict snapshot: on Windows,
        ``os.environ.get`` is case-insensitive (``os._Environ`` upper-cases
        keys), so ``${path}`` would expand here but not in pydantic-settings.
        """
        environ = dict(os.environ)

        def resolve(match: re.Match[str]) -> str:
            name = match.group("name")
            var = parsed.get(name)
            if var is not None:
                return var.value
            default = match.group("default")
            return environ.get(name, default if default is not None else "")

        return self.POSIX_VARIABLE_PATTERN.sub(resolve, value)

    def _strip_inline_comment(self, value: str) -> str:
        """Strip an unquoted trailing ` #...` comment from a (raw) value.

        Legacy quote-aware scan, reachable only through ``value_from_raw``'s
        malformed-quoted-binding fallback (direct callers): ``parse_string``
        drops those bindings like python-dotenv, and unquoted values go
        through ``_parse_unquoted_value`` instead. A `#` starts a comment only
        when it is outside quotes AND preceded by whitespace; a `#` inside
        matching quotes, glued to a token, or escaped (`\\#`, and an escaped
        quote `\\"` that must not toggle quote state) is preserved. Call this
        on the raw `value` (before stripping) so the whitespace context is
        intact.
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
