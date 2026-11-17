"""Partial encryption functionality for envdrift.

This module implements a simple build pattern for partial encryption:
- Source files: .env.{env}.clear + .env.{env}.secret
- Generated file: .env.{env} (combined with warning header)
"""

from __future__ import annotations

import logging
import os
import re
import shlex
import subprocess  # nosec B404
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple, TypedDict

from envdrift.config import PartialEncryptionEnvironmentConfig
from envdrift.env_files import _is_excluded_env_file
from envdrift.integrations.dotenvx import DotenvxError, DotenvxFilenameError, DotenvxWrapper
from envdrift.integrations.dotenvx_keys import (
    is_plain_key,
    multiline_value_spans,
    plain_keys_apply,
)
from envdrift.sync.operations import atomic_write
from envdrift.utils.git import git_location_for, literal_pathspec_env

if TYPE_CHECKING:
    from types import TracebackType

logger = logging.getLogger(__name__)

# The dotenvx public-key header is a 4-line "#/" border/comment block:
#   #/---...[DOTENV_PUBLIC_KEY]---/   (top border, carries the marker)
#   #/ public-key encryption ... /   (inner comment)
#   #/ [how it works] ...         /   (inner comment)
#   #/---...---/                      (bottom border)
# combine_files strips ONLY this block from the secret file so the boilerplate
# does not clutter the combined artifact, while keeping the DOTENV_PUBLIC_KEY
# assignment and any legitimate user "#/" comment line intact. This mirrors the
# leading four "#/" lines of DotenvxWrapper.DOTENVX_HEADER_BLOCK_PATTERN
# (integrations/dotenvx.py) but stops before the public-key assignment so that
# line survives into the combined file.
_DOTENVX_HEADER_COMMENT_BLOCK = re.compile(
    r"#/-+\[DOTENV_PUBLIC_KEY\]-+/\n"
    r"#/[^\n]*/\n"
    r"#/[^\n]*/\n"
    r"#/-+/\n",
)

# Minimum inner width of the warning box. Long file paths expand the box beyond
# this so the right-hand border always stays aligned (see _build_warning_header).
_WARNING_BOX_MIN_WIDTH = 50

# dotenvx writes a public-key assignment into encrypted files. It is not a
# secret (public keys are public) so it must not be counted as a secret var.
_DOTENVX_PUBLIC_KEY_PREFIX = "DOTENV_PUBLIC_KEY"

# SOPS appends a flat metadata trailer to a fully-encrypted dotenv file:
#   sops_version=3.13.1
#   sops_lastmodified=2021-...
#   sops_unencrypted_suffix=_unencrypted
#   sops_age__list_0__map_recipient=age1...   (or sops_kms_*/sops_pgp_*/...)
#   sops_mac=ENC[AES256_GCM,...]               (the ONLY ciphertext line)
# Every line except sops_mac= is PLAINTEXT (the version, timestamp, recipient
# public key, etc.), but none is a real secret — they are SOPS bookkeeping. A
# genuine SOPS .secret is therefore "fully encrypted" even though most of this
# trailer is plaintext, so has_plaintext_secret_value() must ignore the trailer
# instead of flagging it as leftover plaintext secrets (#416).
#
# Match the EXACT SOPS metadata key family, not a bare ``sops_`` prefix: a broad
# prefix match would also exclude a real user variable that merely starts with
# ``sops_`` (e.g. ``sops_token=AKIA…`` / ``sops_api_key=…``) from the plaintext
# scan, silently dropping a genuine secret. The flat scalar keys are a fixed set
# (``sops_version``/``sops_mac``/``sops_lastmodified``/the *_suffix/*_regex
# toggles/``sops_mac_only_encrypted``/``sops_shamir_threshold``); the key-group
# providers (age/pgp/kms/gcp_kms/azure_kv/hc_vault) appear ONLY as
# double-underscore-flattened ``sops_<provider>__list_N__map_M_<field>`` entries
# (verified against the pinned sops binary — it never emits a bare
# ``sops_<provider>`` nor a single-underscore ``sops_<provider>_<field>`` key).
# Only a key in that family is treated as bookkeeping.
_SOPS_METADATA_SCALAR_KEYS = frozenset(
    {
        "sops_version",
        "sops_mac",
        "sops_lastmodified",
        "sops_unencrypted_suffix",
        "sops_encrypted_suffix",
        "sops_unencrypted_regex",
        "sops_encrypted_regex",
        "sops_unencrypted_comment_regex",
        "sops_encrypted_comment_regex",
        "sops_mac_only_encrypted",
        "sops_shamir_threshold",
    }
)
# Key-group providers SOPS records (one nested block per recipient). In dotenv
# output these ALWAYS flatten with a double-underscore separator
# (``sops_<provider>__list_N__map_M_<field>``), so require ``__`` right after
# the provider token: a user var literally named ``sops_age`` or a lookalike
# such as ``sops_age_backup`` / ``sops_agent`` / ``sops_token`` is NOT metadata
# and stays in the plaintext scan.
_SOPS_METADATA_GROUP_KEY = re.compile(r"^sops_(?:age|pgp|kms|gcp_kms|azure_kv|hc_vault)__")


def _is_sops_metadata_key(key: str) -> bool:
    """Return True if ``key`` is a genuine SOPS metadata key, not a user var.

    Matches the EXACT SOPS metadata family — the fixed scalar bookkeeping keys
    and the double-underscore-flattened key-group provider entries
    (``sops_age__*``/``sops_pgp__*``/…) — rather than a bare ``sops_`` prefix,
    so a real user variable that happens to start with ``sops_`` (e.g.
    ``sops_token``, or one literally named ``sops_age``) is NOT misclassified
    as bookkeeping and stays in the plaintext-secret scan (#416).
    """
    return key in _SOPS_METADATA_SCALAR_KEYS or bool(_SOPS_METADATA_GROUP_KEY.match(key))


# A dotenvx-encrypted value starts with this prefix; a SOPS-encrypted dotenv
# value starts with the AES-GCM marker. Detection keys off an actual assigned
# VALUE being ciphertext — never a header comment or a public-key line, both of
# which survive ``dotenvx decrypt`` while the values revert to plaintext (#352).
_DOTENVX_CIPHERTEXT_PREFIX = "encrypted:"
_SOPS_CIPHERTEXT_PREFIX = "ENC[AES256_GCM,"


def _build_warning_header(clear_file: str, secret_file: str) -> str:
    """Build the auto-generated-file warning box, sized to fit its content.

    The right-hand ``/`` border stays aligned regardless of how long the
    ``clear_file`` / ``secret_file`` paths are, because the box width grows to
    fit the longest line instead of using a fixed pad.
    """
    body = [
        "WARNING: AUTO-GENERATED FILE",
        "DO NOT EDIT THIS FILE DIRECTLY",
        "",
        "This file is generated by: envdrift push",
        "",
        "To make changes:",
        "  1. Run:  envdrift pull-partial (decrypts the .secret file)",
        f"  2. Edit: {clear_file}",
        f"  3. Edit: {secret_file}",
        "  4. Run:  envdrift push (re-encrypts .secret and regenerates this)",
    ]
    # Inner width includes the single leading space after "#/", hence +1.
    inner = max(_WARNING_BOX_MIN_WIDTH, max(len(line) for line in body) + 1)
    border = "#/" + "-" * inner + "/"
    lines = [border]
    lines.extend("#/ " + line.ljust(inner - 1) + "/" for line in body)
    lines.append(border)
    return "\n".join(lines) + "\n"


def _is_secret_var_line(line: str) -> bool:
    """Return True if ``line`` is a real secret variable assignment.

    Excludes comments, dotenvx's ``DOTENV_PUBLIC_KEY_*`` artifact and SOPS's
    metadata trailer (version/timestamp/recipient/mac bookkeeping, not real
    secrets — see #416) so the reported secret-var count and the plaintext scan
    reflect only the actual secrets. The SOPS exclusion matches the EXACT
    metadata key family (``_is_sops_metadata_key``), not a bare ``sops_`` prefix,
    so a real user variable such as ``sops_token=…`` is still scanned.
    """
    stripped = line.strip()
    if "=" not in stripped or stripped.startswith("#"):
        return False
    key = stripped.partition("=")[0].strip()
    if _is_sops_metadata_key(key):
        return False
    return not stripped.startswith(_DOTENVX_PUBLIC_KEY_PREFIX)


class PartialEncryptionError(Exception):
    """Partial encryption operation failed."""

    @classmethod
    def encrypt_failed(cls, path: Path, cause: Exception) -> PartialEncryptionError:
        """Create error for encryption failure."""
        return cls(f"Failed to encrypt {path}: {cause}")

    @classmethod
    def decrypt_failed(cls, path: Path, cause: Exception, note: str = "") -> PartialEncryptionError:
        """Create error for decryption failure.

        ``note`` says what happened to the file (``DecryptSnapshot.restore``).
        """
        message = f"Failed to decrypt {path}: {cause}"
        return cls(f"{message}\n{note}" if note else message)

    @classmethod
    def still_encrypted(cls, path: Path, ciphertext: str, note: str) -> PartialEncryptionError:
        """Create error for a decrypt that exited 0 but left ciphertext (#963).

        ``ciphertext`` names the format still in the file (``_leftover_ciphertext``).
        """
        if ciphertext == "SOPS":
            # Shared by pull-partial and pull. `envdrift decrypt` alone left the
            # plaintext in a tracked file that `git add .` staged: mark it first, in the
            # repository that tracks the file. Run from the superproject, the mark for a
            # file in a submodule failed: the superproject tracks only the gitlink.
            git, name = _git_for_written_file(path)
            word = _command_word(str(path))
            reason = (
                "it still holds SOPS ciphertext. Partial encryption decrypts with "
                "dotenvx, which does not read SOPS files. To move it to dotenvx, run "
                f"`{git} update-index --skip-worktree {name}` so `git add .` cannot stage "
                "its plaintext (git can mark only a tracked file), then "
                f"`envdrift decrypt {word} --backend sops`, then `envdrift push` before "
                "you stage anything: push encrypts it with dotenvx and lifts the mark."
            ) + _expansion_note(git, name, word)
        else:
            reason = (
                "it still holds dotenvx ciphertext after the decrypt. The decryption "
                "key may be missing or invalid."
            )
        return cls(f"Failed to decrypt {path}: {reason}\n{note}")

    @classmethod
    def file_not_found(cls, path: Path) -> PartialEncryptionError:
        """Create error for missing file."""
        return cls(f"Secret file not found: {path}")

    @classmethod
    def nothing_to_encrypt(cls, path: Path) -> PartialEncryptionError:
        """Create error for a secret file with no variable assignments (#471).

        Handed an empty or comment-only file, dotenvx scaffolds its
        placeholder-secrets template (HELLO, AWS_ACCESS_KEY_ID, ...) into it and
        exits 0, so a blind delegation would fabricate ~13 secrets the user
        never wrote and report them as encrypted.
        """
        return cls(
            f"Nothing to encrypt: {path} has no variables. Refusing to run the "
            "encryptor, which would otherwise scaffold placeholder secrets "
            "into the file."
        )

    @classmethod
    def encryption_did_not_take_effect(cls, path: Path) -> PartialEncryptionError:
        """Create error for an encrypt run that left plaintext behind (#471).

        dotenvx exits 0 *without* encrypting when it cannot write or use the
        private key (e.g. ``.env.keys`` is read-only, a directory, or garbage) —
        it only prints a warning. The exit code alone must never be trusted.
        """
        return cls(
            f"Encryption did not take effect: {path} still contains plaintext "
            "values. This usually means the encryption key was missing or "
            "invalid (e.g. an unwritable or malformed .env.keys)."
        )

    @classmethod
    def sources_missing(
        cls, clear_file: Path, secret_file: Path, combined_file: Path
    ) -> PartialEncryptionError:
        """Create error for a combine with BOTH source files absent (#471)."""
        return cls(
            f"Neither clear file ({clear_file}) nor secret file ({secret_file}) "
            f"exists; refusing to overwrite {combined_file} with an empty "
            "scaffold. Restore the source files or fix the paths in "
            "envdrift.toml."
        )


class SecretsOnlyPullError(PartialEncryptionError):
    """A secrets-only pull stopped at a file it could not decrypt (#948).

    The files decrypted before the failure are plaintext on disk, so the error
    carries the tally for callers to report: ``pull-partial`` and ``pull`` count
    them, and both warn about the ones git skip-worktree could not protect.
    ``protected`` and ``unprotected`` cover only files this pull decrypted (#998).
    """

    def __init__(
        self,
        message: str,
        *,
        decrypted: int,
        already_decrypted: int,
        protected: int,
        unprotected: list[Path] | None = None,
    ) -> None:
        """Store the message and the counts reached before the failure."""
        super().__init__(message)
        self.decrypted = decrypted
        self.already_decrypted = already_decrypted
        self.protected = protected
        self.unprotected = list(unprotected or [])


class SecretsOnlyPullResult(TypedDict):
    """Outcome of a secrets-only pull (``pull_secrets_only``).

    ``protected`` counts the files this pull decrypted and marked skip-worktree;
    ``unprotected`` lists the ones it decrypted but could not mark. A file that
    was plaintext already is in neither (#998).
    """

    decrypted: int
    already_decrypted: int
    protected: int
    unprotected: list[Path]


# The quote styles dotenvx reads and keeps around the ciphertext it writes. dotenv and
# SOPS emit ``"`` and ``'``; dotenvx also takes a backtick-quoted value as quoted and
# writes ``KEY=`encrypted:...` `` (#950).
_VALUE_QUOTES = ('"', "'", "`")


def _is_quote_wrapped(v: str) -> bool:
    """Return True if ``v`` is wrapped in a single matching pair of quotes.

    Recognises ``"..."``, ``'...'`` and ``` `...` ``` (``_VALUE_QUOTES``). A bare
    quote or unbalanced quotes are not wrapped.
    """
    return len(v) >= 2 and v[0] in _VALUE_QUOTES and v[-1] == v[0]


def _strip_inline_comment_after_quoted_value(value: str) -> str:
    """Drop a trailing comment after one complete dotenv-quoted value.

    A comment is removable only when nothing but optional whitespace and a
    ``#`` comment follows the closing quote. Keeping any other suffix makes the
    whole value non-quoted, so malformed assignments remain fail-closed.
    """
    if not value or value[0] not in _VALUE_QUOTES:
        return value

    quote = value[0]
    escaped = False
    for index, char in enumerate(value[1:], start=1):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char != quote:
            continue

        suffix = value[index + 1 :].strip()
        if not suffix or suffix.startswith("#"):
            return value[: index + 1]
        return value
    return value


def _unquote_value(value: str) -> str:
    """Strip surrounding whitespace and a single layer of matching quotes.

    SOPS emits ``KEY="ENC[AES256_GCM,...]"`` (quoted) while dotenvx emits an
    unquoted ``KEY=encrypted:...``, or keeps the quotes the value had, backticks
    included; quoted empty placeholders appear as ``KEY=""`` / ``KEY=''``.
    Callers compare the returned bare value against the ciphertext prefixes or
    test it for emptiness, so the quotes and surrounding whitespace must be
    removed first.
    """
    v = value.strip()
    v = _strip_inline_comment_after_quoted_value(v)
    if _is_quote_wrapped(v):
        v = v[1:-1].strip()
    return v


def _value_is_ciphertext(value: str) -> bool:
    """Return True if an assigned dotenv VALUE is genuine ciphertext."""
    v = _unquote_value(value)
    return v.startswith(_DOTENVX_CIPHERTEXT_PREFIX) or v.startswith(_SOPS_CIPHERTEXT_PREFIX)


# python-dotenv's unquoted-value comment: a "#" after whitespace starts it.
_UNQUOTED_COMMENT_RE = re.compile(r"\s+#.*")


def _value_is_only_ciphertext(value: str) -> bool:
    """Return True if an assigned VALUE is ciphertext with no plaintext glued after it.

    dotenvx ciphertext is base64, which never holds a ``#``. dotenvx ends an unquoted
    value at its first ``#``, so ``KEY=hunter2#Spring`` became
    ``KEY=encrypted:...#Spring``: ciphertext, then plaintext dotenvx read as a comment.
    python-dotenv reads that ``#`` as value text (a comment starts only at a ``#`` after
    whitespace), so such a value still holds plaintext (#947). It is ciphertext all the
    same for ``is_file_encrypted``: dotenvx decrypts it.
    """
    v = _unquote_value(value)
    if v.startswith(_DOTENVX_CIPHERTEXT_PREFIX):
        # Only an unquoted value ends at a comment: inside quotes a "#" is value text, so
        # KEY="encrypted:... #hunter2" holds plaintext too.
        rest = v if _is_quoted(value) else _UNQUOTED_COMMENT_RE.sub("", v)
        return "#" not in rest
    return v.startswith(_SOPS_CIPHERTEXT_PREFIX)


def _is_quoted(value: str) -> bool:
    """Whether an assigned VALUE is one quoted value, a comment after its closing quote aside."""
    return _is_quote_wrapped(_strip_inline_comment_after_quoted_value(value.strip()))


def _own_lines(content: str) -> list[str]:
    """The lines of ``content`` but those inside a value that spans lines, as dotenvx reads it.

    A quoted value can hold line breaks, and a line inside it, such as ``TOKEN=hello``, is
    part of the value, not an assignment of its own (#1048). The value's first line stays.
    A line dotenvx cannot read at all stays too, and is judged as before.
    """
    spans = multiline_value_spans(content)
    lines: list[str] = []
    offset = 0
    for line in content.splitlines(keepends=True):
        if not any(start < offset < end for start, end in spans):
            lines.append(line.splitlines()[0])
        offset += len(line)
    return lines


def _line_has_plaintext_secret(line: str, *, plain_keys: bool = False) -> bool:
    """Return True if a single ``.secret`` line is a PLAINTEXT secret assignment.

    Comments, blank lines, non-assignments and dotenvx's ``DOTENV_PUBLIC_KEY_*``
    artifact (a public key is not a secret) are filtered by ``_is_secret_var_line``
    and return False. Among real secret assignments, empty values
    (``KEY=`` / ``KEY=""`` / ``KEY=''``) carry no secret to leak, and ciphertext
    values are already encrypted; only a non-empty plaintext value, or ciphertext
    with plaintext glued after a ``#`` (#947), returns True.

    With ``plain_keys``, a key dotenvx's encrypt never encrypts (``is_plain_key``;
    an ``export`` prefix leaves the name's ``_PLAIN`` end as it is) is not leftover
    plaintext either (#1048). The default is SOPS's view, which has no such rule.
    """
    if not _is_secret_var_line(line):
        return False
    name, _, value = line.strip().partition("=")
    if plain_keys and is_plain_key(name.strip()):
        return False
    # Empty assignment (KEY=, KEY="", KEY='') carries no secret to leak.
    return bool(_unquote_value(value)) and not _value_is_only_ciphertext(value)


def _dotenvx_plain_keys(content: str, plain_keys: bool) -> bool:
    """Whether the ``_PLAIN`` exemption applies to ``content`` (``has_plaintext_secret_value``).

    Only for a caller that checks a dotenvx encryption, and never for SOPS ciphertext:
    SOPS has no ``_PLAIN`` convention, and a SOPS-encrypted file keeps its own rules.
    """
    return plain_keys and not _holds_sops_ciphertext(content)


def _holds_sops_ciphertext(content: str) -> bool:
    """Whether a value of ``content`` is SOPS ciphertext; a mention of it in a comment is not."""
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or "=" not in stripped:
            continue
        if _unquote_value(stripped.partition("=")[2]).startswith(_SOPS_CIPHERTEXT_PREFIX):
            return True
    return False


def has_plaintext_secret_value(file_path: Path, *, plain_keys: bool = False) -> bool:
    """Return True if the file still holds at least one PLAINTEXT secret value.

    A "plaintext secret value" is a real variable assignment whose value is not
    ciphertext — excluding comments, blank lines, dotenvx's
    ``DOTENV_PUBLIC_KEY_*`` artifact (a public key is not a secret) and SOPS's
    ``sops_*`` metadata trailer. A genuine SOPS dotenv file carries plaintext
    bookkeeping lines (``sops_version=``, ``sops_lastmodified=``,
    ``sops_unencrypted_suffix=``, the recipient public key, …; only ``sops_mac=``
    is ciphertext); those are not leftover plaintext secrets, so a fully
    SOPS-encrypted ``.secret`` is correctly treated as fully encrypted (#416).

    This distinguishes a MIXED-STATE file (some values already ``encrypted:``,
    at least one freshly-added plaintext value) from a fully-encrypted one.
    ``is_file_encrypted`` returns True on the *first* ciphertext value, so a
    mixed file looks "already encrypted" to it and the push path would early-
    return — shipping the new plaintext secret verbatim into the committed
    ``.secret`` file and the generated combined file. Callers force a re-encrypt
    when this returns True (``dotenvx encrypt`` is idempotent: it re-encrypts
    only the plaintext values and leaves existing ciphertext untouched).

    ``plain_keys`` is for a caller that judges what dotenvx encrypts, passed as
    ``plain_keys_apply()``: dotenvx never encrypts a ``_PLAIN`` key (#1048), so its
    value is not plaintext the encryption missed. A file holding SOPS ciphertext
    keeps SOPS's rules all the same.
    """
    if not file_path.exists():
        return False

    # errors="replace" for the same reason as is_file_encrypted: callers have no
    # surrounding handler, and a ciphertext marker is ASCII so replacement chars
    # cannot make a plaintext value look like ciphertext.
    content = file_path.read_text(encoding="utf-8", errors="replace")

    plain_keys = _dotenvx_plain_keys(content, plain_keys)
    return any(
        _line_has_plaintext_secret(raw_line, plain_keys=plain_keys)
        for raw_line in _own_lines(content)
    )


def file_has_assignment(file_path: Path) -> bool:
    """Return True if the file contains at least one ``KEY=value`` assignment.

    Deliberately looser than ``EnvParser`` (and robust to non-UTF-8 bytes via
    ``errors="replace"``): it counts ANY assignment line, including keys the
    strict parser rejects (a leading digit like ``1PW``, a dash like
    ``X-API-KEY``, or a non-ASCII identifier). Used to decide whether a file has
    anything to encrypt — a parser-variable count would miss non-identifier-keyed
    secrets and wrongly report the file as empty, and ``EnvParser.parse`` would
    raise ``UnicodeDecodeError`` on a non-UTF-8 file.
    """
    if not file_path.exists():
        return False

    content = file_path.read_text(encoding="utf-8", errors="replace")
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, _ = line.partition("=")
        if sep and key.strip():
            return True
    return False


def is_file_encrypted(file_path: Path) -> bool:
    """Return True only when the file actually contains CIPHERTEXT.

    True requires at least one assigned VALUE to be genuinely encrypted
    (dotenvx ``encrypted:`` or SOPS ``ENC[AES256_GCM,``), or a real SOPS
    metadata block.

    The #352 bug this fixes: the old check was
    ``"encrypted:" in content or "DOTENV_VAULT" in content``, so a PLAINTEXT
    value that merely *contained* the substring ``encrypted:`` (e.g.
    ``NOTE=... the secret is stored encrypted: see docs``) false-positived as
    "already encrypted". ``encrypt_secret_file`` then early-returned and the
    real secrets in that file were committed in cleartext. Anchoring detection
    to a VALUE that *starts with* a ciphertext prefix removes that false
    positive.

    Related safety property (a forward-guard, not the #352 bug itself): a
    dotenvx file that has been DECRYPTED keeps its ``DOTENV_PUBLIC_KEY_*`` line
    and header comment while its values revert to plaintext. Those markers must
    not count as encrypted either, so re-encryption (lock -> pull -> lock) still
    fires. The old substring check already returned False for such files (they
    hold neither substring); the value-scan preserves that.

    Args:
        file_path: Path to check

    Returns:
        True if the file holds at least one encrypted value or a SOPS metadata block.
    """
    if not file_path.exists():
        return False

    # errors="replace": a non-UTF-8 file (e.g. a Latin-1 byte in a value) must not
    # raise UnicodeDecodeError here — is_file_encrypted is called from the push/
    # pull/encrypt paths with no surrounding handler, so an exception would abort
    # the whole operation. A real dotenvx/SOPS ciphertext marker is ASCII, so
    # replacement characters cannot turn a plaintext file into a false positive.
    content = file_path.read_text(encoding="utf-8", errors="replace")

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        _, _, value = line.partition("=")
        if _value_is_ciphertext(value):
            return True

    # Real SOPS metadata block: the trailer carries sops_version alongside an
    # encrypted MAC value. Both present means it is a genuine SOPS file even if
    # the assignment scan above did not trip (defensive belt-and-suspenders).
    return "sops_version" in content and _SOPS_CIPHERTEXT_PREFIX in content


def holds_only_plain_keys(content: str) -> bool:
    """Return True if every variable in ``content`` is a ``_PLAIN`` key (``is_plain_key``).

    dotenvx's encrypt changes nothing in such a file (#1048): it writes no ciphertext and
    no header to it, so the file never holds the ciphertext ``is_file_encrypted`` looks
    for, though a dotenvx push or lock has nothing left to do in it. Content with no
    variable is not such a file.
    """
    names = [
        line.strip().partition("=")[0].strip()
        for line in _own_lines(content)
        if _is_secret_var_line(line)
    ]
    return bool(names) and all(is_plain_key(name) for name in names)


def _file_holds_only_plain_keys(file_path: Path) -> bool:
    """``holds_only_plain_keys`` for the file at ``file_path``; False when there is none."""
    if not file_path.exists():
        return False
    return holds_only_plain_keys(file_path.read_text(encoding="utf-8", errors="replace"))


def is_fully_encrypted(file_path: Path, *, plain_keys: bool = False) -> bool:
    """Return True only when the file is FULLY encrypted (push would no-op).

    Fully encrypted means ciphertext is present AND no leftover plaintext secret
    value remains. ``is_file_encrypted`` trips on the *first* ciphertext value,
    so a MIXED-STATE file (some values encrypted, one freshly-added plaintext)
    looks "encrypted" to it alone; pairing it with ``has_plaintext_secret_value``
    distinguishes a file a real push would re-encrypt from one it would skip.

    This is the canonical shared predicate: the push paths, ``envdrift lock``
    and the dry-run ``--check`` sync test all use it so they agree on what
    "already pushed/encrypted" means. Those callers encrypt with dotenvx and pass
    ``plain_keys=plain_keys_apply()``: a ``_PLAIN`` key a push would leave plaintext
    is no reason to call the file unpushed (#1048). Nor is a file of nothing but
    ``_PLAIN`` keys, which holds no ciphertext and which a push leaves as it is.
    """
    pushed = is_file_encrypted(file_path) or (plain_keys and _file_holds_only_plain_keys(file_path))
    return pushed and not has_plaintext_secret_value(file_path, plain_keys=plain_keys)


# Backward-compatible alias for the pre-#507 private name (in-flight branches
# still import it); new code should use ``is_fully_encrypted``.
_is_fully_encrypted = is_fully_encrypted


def _build_combined_content(
    env_config: PartialEncryptionEnvironmentConfig,
    clear_lines: list[str],
    secret_file_content: str | None,
) -> str:
    """Assemble the combined-file text: warning header + clear + encrypted sections.

    The dotenvx public-key header block is stripped from the secret section —
    ONLY the precise 4-line "#/" border/comment boilerplate, so a legitimate
    user comment such as "#/ note about this key" survives into the generated
    combined file.
    """
    warning = _build_warning_header(env_config.clear_file, env_config.secret_file)
    combined_lines = warning.splitlines()
    combined_lines.append("")

    if clear_lines:
        combined_lines.append(f"# From {env_config.clear_file}")
        combined_lines.extend(clear_lines)
        combined_lines.append("")

    if secret_file_content:
        stripped_text = _DOTENVX_HEADER_COMMENT_BLOCK.sub("", secret_file_content)
        combined_lines.append(f"# From {env_config.secret_file} (encrypted)")
        combined_lines.extend(stripped_text.splitlines())

    return "\n".join(combined_lines) + "\n"


def combine_files(
    env_config: PartialEncryptionEnvironmentConfig, *, write: bool = True
) -> dict[str, int | bool]:
    """
    Combine clear and encrypted secret files into a single combined file.

    Process:
        1. Read .env.{env}.clear (cleartext vars)
        2. Read .env.{env}.secret (encrypted vars)
        3. Combine with warning header → .env.{env}

    Args:
        env_config: Environment configuration
        write: When True (default) the combined file is written to disk. When
            False this is a dry run that computes the would-be content and
            reports whether it matches the existing combined file, without
            touching disk. Used by ``envdrift push --check``.

    Returns:
        Dict with counts: {"clear_lines": X, "secret_vars": Y, "in_sync": bool}.
        ``in_sync`` reports whether the on-disk combined file already matches the
        freshly-computed content (always True after a real write).

    Raises:
        PartialEncryptionError: If operation fails
    """
    clear_file = Path(env_config.clear_file)
    secret_file = Path(env_config.secret_file)
    combined_file = Path(env_config.combined_file)

    # Refuse to fabricate an empty scaffold when BOTH source files are missing
    # (deleted by mistake, or a clear_file/secret_file typo in envdrift.toml).
    # The combined file may be the only remaining copy of the runtime env;
    # pre-#471 push silently replaced it with a header-only scaffold under the
    # "[OK] Push complete!" banner. Erroring here is symmetric with
    # pull-partial's "Secret file not found". A single missing source is still
    # tolerated (clear-only and secret-only environments are valid).
    if not clear_file.exists() and not secret_file.exists():
        raise PartialEncryptionError.sources_missing(clear_file, secret_file, combined_file)

    # Read files
    clear_lines = []
    if clear_file.exists():
        clear_lines = clear_file.read_text(encoding="utf-8").splitlines()

    secret_file_content = None
    if secret_file.exists():
        secret_file_content = secret_file.read_text(encoding="utf-8")

    new_content = _build_combined_content(env_config, clear_lines, secret_file_content)

    existing = combined_file.read_text(encoding="utf-8") if combined_file.exists() else None
    in_sync = existing == new_content

    if write:
        # The combined file carries the encrypted secret section here, and the
        # same artifact holds DECRYPTED values after `pull --merge` — so write
        # it like .env.keys: 0600 for a fresh file, fchmod on the fd, atomic
        # rename. Never a bare write_text at the process umask (#471).
        atomic_write(combined_file, new_content, max_permissions=0o600)
        in_sync = True

    return {
        "clear_lines": len(clear_lines),
        "secret_vars": _encrypted_var_count(secret_file_content or ""),
        "in_sync": in_sync,
    }


def _encrypted_var_count(content: str) -> int:
    """How many variables of a secret file push reports as encrypted (``combine_files``).

    Comments and dotenvx's public-key line are no variables, nor is a line inside a value
    that spans lines. A key dotenvx leaves plaintext by its ``_PLAIN`` rule is not encrypted
    (#1048), unless SOPS encrypted the file.
    """
    plain_keys = _dotenvx_plain_keys(content, plain_keys_apply())
    names = [
        line.strip().partition("=")[0].strip()
        for line in _own_lines(content)
        if _is_secret_var_line(line)
    ]
    return sum(1 for name in names if not (plain_keys and is_plain_key(name)))


def _written_file(path: Path) -> Path:
    """The file a write to ``path`` lands in: ``path`` with every symlink resolved.

    dotenvx writes through a symlinked secret file into its target. Marking the
    link skip-worktree protected nothing: the plaintext landed in the tracked
    target, which `git add .` staged, while pull-partial called it protected. A
    symlinked directory on the way sends the write elsewhere the same way.
    """
    try:
        return path.resolve()
    except (OSError, RuntimeError):  # a symlink loop: no file to write either
        return path


def _run_git_update_index(flag: str, path: Path) -> bool:
    """Run ``git update-index <flag>`` on the file ``path`` writes to; report success.

    That is the target of a symlinked ``path`` (``_written_file``), so the bit is
    set on, and lifted from, the file that holds the plaintext. git runs in the
    repository that tracks that file (``git_location_for``): run from the
    superproject, git could not mark a file in a submodule, and run from the
    superproject's git hook, it marked the superproject's file at the same path
    and exited 0, so a pull called the submodule's plaintext protected.

    Returns True only when git exits 0. A non-zero exit (e.g. the file is not
    tracked) is logged as a warning rather than failing silently; git being
    unavailable is logged at debug level. Either way the caller gets False so it
    can avoid claiming protection that was never applied.
    """
    # The file's path is not logged: git's own message names the file ("fatal: Unable
    # to mark file <path>"), and CodeQL reads a secret file's path as the secret
    # (py/clear-text-logging-sensitive-data).
    try:
        # In the try too: the lookup runs git, and its failure means no mark, not a crash
        # (pull_secrets_only marks each file outside its own error handling).
        target = _written_file(path)
        folder, env = git_location_for(target)
        result = subprocess.run(  # nosec B603, B607
            ["git", "-C", str(folder), "update-index", flag, "--", str(target)],
            capture_output=True,
            timeout=10,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        # Not ``exc`` itself: its text is the whole command, the file's path included.
        logger.debug("git update-index %s not applied: timed out after %ss", flag, exc.timeout)
        return False
    except (OSError, RuntimeError) as exc:  # git could not start, or a path could not resolve
        reason = getattr(exc, "strerror", None) or type(exc).__name__
        logger.debug("git update-index %s not applied: %s", flag, reason)
        return False
    if result.returncode != 0:
        stderr = result.stderr
        if isinstance(stderr, (bytes, bytearray)):
            stderr = stderr.decode(errors="replace")
        message = (stderr or "").strip()
        # Running outside a git repo isn't an error worth surfacing — skip-worktree
        # is simply not applicable there, so log it at debug like git-unavailable
        # (otherwise `push`/`pull` in a non-repo dir print scary git noise).
        if "not a git repository" in message.lower():
            logger.debug("git update-index %s skipped (not a git repo): %s", flag, message)
            return False
        logger.warning("git update-index %s failed (exit %s): %s", flag, result.returncode, message)
        return False
    return True


def _git_skip_worktree(path: Path) -> bool:
    """Mark path as skip-worktree so git ignores local changes while the file is decrypted.

    This prevents `git add .` from staging a plaintext .secret file after pull-partial.
    Best-effort: returns False (and logs) if git is unavailable or the file is not tracked.
    """
    return _run_git_update_index("--skip-worktree", path)


def _git_unskip_worktree(path: Path) -> bool:
    """Unmark path from skip-worktree so git can track the re-encrypted version.

    Called after encrypt_secret_file so the encrypted diff is visible to git.
    Best-effort: returns False (and logs) if git is unavailable or the file is not tracked.
    """
    return _run_git_update_index("--no-skip-worktree", path)


def unprotected_reason(path: Path) -> str:
    """Say why ``git update-index --skip-worktree`` could not protect ``path`` (#998).

    Asks git, by exit code rather than by its (translated) messages, whether the
    file the protection was for (``_written_file``) is in the index, in the
    repository and index the protection ran in (``git_location_for``):
    ``untracked`` (exit 1), ``outside a git repository`` (exit 128), else
    ``skip-worktree failed`` (a tracked file, for example while another git
    process holds the index lock). The name is a literal pathspec: as a glob,
    ``[prod]`` could match another, tracked file and call an untracked one
    tracked. When a symlink sends ``path`` elsewhere, the reason names the file
    the plaintext is in.
    """
    target = _written_file(path)
    try:
        # In the try: the lookup fails where it failed for the mark (_run_git_update_index),
        # and the notice that names the plaintext file must still print.
        folder, env = git_location_for(target)
        listed = subprocess.run(  # nosec B603, B607
            [
                "git",
                "-C",
                str(folder),
                "ls-files",
                "--error-unmatch",
                "--",
                f":(literal){target.relative_to(folder).as_posix()}",
            ],
            capture_output=True,
            timeout=10,
            env=literal_pathspec_env(env),
        )
    except FileNotFoundError:
        return "skip-worktree failed: git is not installed"
    except (subprocess.TimeoutExpired, OSError, RuntimeError) as exc:
        return f"skip-worktree failed: {exc}"
    if listed.returncode == 1:
        reason = "untracked"
    elif listed.returncode != 0:
        reason = "outside a git repository"
    else:
        reason = "skip-worktree failed"
    if _through_symlink(path):
        reason += f"; through a symlink, the plaintext is in {_shown(target)}"
    return reason


def _through_symlink(path: Path) -> bool:
    """Whether ``path``, or a directory on the way to it, is a symlink."""
    return any(part.is_symlink() for part in (path, *path.parents))


def _shown(path: Path) -> Path:
    """``path`` relative to the working directory, or in full when it is not under it."""
    try:
        return path.relative_to(Path.cwd().resolve())
    except (ValueError, OSError):
        return path


def _git_for_written_file(path: Path) -> tuple[str, str]:
    """The ``git`` to type, and the file to name, to act on the file ``path`` writes to.

    The skip-worktree mark is set on that file, by git run in the repository that
    tracks it (``_run_git_update_index``): for a symlinked ``path`` the link's
    target, and for a file in a submodule the submodule's repository. Recovery
    advice that named ``path`` from the working directory unmarked and checked out
    the link, or was refused in the superproject, so the plaintext stayed. The
    commands run git in that file's directory (``git -C``), where git finds that
    repository, unless it is the working directory, where a file not reached
    through a symlink keeps the name it was given.
    """
    target = _written_file(path)
    folder = _shown(target.parent)
    git = "git" if folder == Path() else f"git -C {_command_word(str(folder))}"
    if folder == Path() and not _through_symlink(path):
        return git, _command_word(str(path))
    return git, _command_word(target.name)


def _command_word(text: str) -> str:
    """``text`` as one word of a command the user pastes into a shell.

    A path with a space, ``secrets/my app/.env.a`` say, split into two arguments, so
    the printed command failed or acted on the wrong file. POSIX shells read
    ``shlex.quote``; Windows shells read ``_windows_word``. A word that starts with ``-``
    is given a leading ``./`` (``.\\`` on Windows), the same file: git read ``-prod.env`` as
    an option and refused the command, and envdrift's own commands would too.
    """
    if text.startswith("-"):
        text = f"{os.curdir}{os.sep}{text}"  # not Path: it drops a leading "."
    if os.name == "nt":
        return _windows_word(text)
    return shlex.quote(text)


def _windows_word(text: str) -> str:
    """``text`` as one word for cmd.exe and PowerShell alike.

    A word of only letters, digits and ``_.:\\/~-`` means nothing else to either shell,
    so it stays as it is (``C:\\Users\\RUNNER~1\\...``). Any other word is put in double
    quotes, which both read: a space or ``&`` there split the command in two, and
    ``|``, ``<``, ``>``, ``^``, ``(``, ``)``, ``;``, ``,`` and ``@`` are each special to one
    of them. A Windows file name cannot hold a double quote, so none needs escaping.
    """
    if re.fullmatch(r"[\w.:\\/~-]+", text):
        return text
    return f'"{text}"'


# Read even inside double quotes: cmd.exe expands %NAME% (and !NAME! with delayed expansion), and
# PowerShell expands $NAME, escapes with a backtick and ends a string at a curly double quote.
_READ_IN_DOUBLE_QUOTES = frozenset("%!$`\u201c\u201d\u201e")


def _expansion_note(*words: str, windows: bool = os.name == "nt") -> str:
    """A warning when a printed Windows command word holds what a shell still changes, else "".

    Double quotes (``_windows_word``) keep a space or ``&`` in one word, but no quoting keeps
    ``%NAME%`` from cmd.exe and ``$NAME`` from PowerShell alike. A command that names such a file
    acts on another path: the SOPS advice's mark misses the file, and the decrypt after it leaves
    plaintext that `git add .` stages. POSIX words (``shlex.quote``) keep every character.
    """
    if not windows or not _READ_IN_DOUBLE_QUOTES.intersection("".join(words)):
        return ""
    return (
        " A file name in these commands holds `%`, `!`, `$`, a backtick or a curly quote, which "
        "cmd.exe or PowerShell can change even in double quotes: check that your shell passes "
        "it as it is (in PowerShell, put it in single quotes) before you run them."
    )


class DecryptSnapshot:
    """The exact bytes of a file about to be decrypted in place by dotenvx.

    dotenvx decrypts value by value. When one value is encrypted under another
    key (after a merge, or through key drift), it writes the values it could
    decrypt to the file and then exits 1, so a failed decrypt left plaintext
    secrets in a tracked file (#948, #962). Take the snapshot before dotenvx
    runs; ``restore`` writes it back when the decrypt fails, or exits 0 but
    leaves ciphertext behind, if the file changed (byte for byte, so CRLF line
    endings survive the wrapper's LF normalization).

    Used as a context manager, it restores the file on any exception from the
    body and keeps the outcome in ``note`` for the caller's error message. The
    pull-partial paths and the dotenvx backend (decrypt, pull and vault-pull)
    share it.
    """

    def __init__(self, path: Path) -> None:
        """Read ``path``'s bytes; an ``OSError`` means nothing can be restored."""
        self.path = path
        self.original = path.read_bytes()
        self.note = ""

    def __enter__(self) -> DecryptSnapshot:
        """Return the snapshot; the body runs the decrypt."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Restore the file when the decrypt raised; the exception propagates."""
        if exc_type is not None:
            self.note = self.restore()

    def restore(self) -> str:
        """Put the original bytes back if the file changed; return what happened.

        The bytes go back whole or not at all: to a temp file next to the file
        the write lands in (``_written_file``, so a symlink stays a symlink),
        synced, then renamed over it with its mode kept. Written in place, a
        write that failed part way (a full disk, a file size limit) left the
        file cut short, with neither the values dotenvx decrypted nor the
        ciphertext it left, and an untracked file had no copy anywhere.

        The returned sentence ends the caller's error message. When the write
        itself fails the file is as dotenvx left it and may hold decrypted
        plaintext, so it is marked skip-worktree and the sentence says whether
        that protection worked, and how to recover the file.
        """
        try:
            changed = self.path.read_bytes() != self.original
        except OSError:
            changed = True  # Unreadable now: write the original back to be safe.
        if not changed:
            return f"{self.path} was left as it was."
        written = _written_file(self.path)
        try:
            atomic_write(written, self.original)
            failure = "" if self.path.read_bytes() == self.original else "its bytes still differ"
        except OSError as exc:
            failure = str(exc)
        if not failure:
            return (
                f"{self.path} was left as it was: envdrift restored the bytes it had "
                "before the decrypt."
            )
        return _unrestored_advice(self.path, written, failure)


def _unrestored_advice(path: Path, written: Path, failure: str) -> str:
    """The sentence for a failed decrypt of ``path`` that ``restore`` could not undo.

    ``written`` is the file the bytes are in (``_written_file``), and ``failure`` says why
    the write back failed. The file may hold decrypted plaintext, so it is marked
    skip-worktree, and the sentence says whether that protection worked and how to
    recover the file.
    """
    lead = (
        f"envdrift could not restore {path} ({failure}), so it may now hold "
        "decrypted plaintext values"
    )
    if _through_symlink(path):
        lead += f" (through a symlink, they are in {_shown(written)})"
    # The commands act on that file, in the repository the mark was set in.
    git, name = _git_for_written_file(path)
    if _git_skip_worktree(path):
        # git checkout refuses a skip-worktree path, so lift the bit first.
        return (
            f"{lead}. It is marked skip-worktree, so a plain `git add .` won't stage it. "
            f"To restore it, run `{git} update-index --no-skip-worktree {name}` and "
            f"then `{git} checkout -- {name}`."
        ) + _expansion_note(git, name)
    # The advice depends on why the mark failed: git checkout can restore
    # only a file git has a copy of.
    reason = unprotected_reason(path)
    word = _command_word(str(path))
    if reason.startswith("untracked"):
        return (
            f"{lead}, and git does not track it, so a plain `git add .` WILL stage "
            "it and git has no copy to restore. Re-encrypt it with "
            f"`envdrift encrypt {word}` before you commit."
        ) + _expansion_note(word)
    if reason.startswith("outside a git repository"):
        return (
            f"{lead}. It is outside a git repository, so git cannot stage it or "
            f"restore it: re-encrypt it with `envdrift encrypt {word}`."
        ) + _expansion_note(word)
    return (
        f"{lead}, and it could not be marked skip-worktree: a plain `git add .` "
        f"WILL stage it. Run `{git} checkout -- {name}` before you commit."
    ) + _expansion_note(git, name)


def _leftover_ciphertext(file_path: Path) -> str | None:
    """Name the ciphertext format still in ``file_path``, or None when it has none.

    SOPS ciphertext carries the ``ENC[AES256_GCM,`` marker, which never occurs in
    dotenvx ciphertext (base64 after ``encrypted:``), so its presence tells the
    two formats apart.
    """
    if not is_file_encrypted(file_path):
        return None
    content = file_path.read_text(encoding="utf-8", errors="replace")
    return "SOPS" if _SOPS_CIPHERTEXT_PREFIX in content else "dotenvx"


def _decrypt_in_place(dotenvx: DotenvxWrapper, file: Path) -> None:
    """Decrypt ``file`` in place, leaving it as it was if the decrypt fails.

    A value under another key makes dotenvx write the values it could decrypt
    and exit 1; without the snapshot that plaintext stayed in the tracked file,
    unprotected, because the caller raised before marking it skip-worktree
    (#948). The error keeps dotenvx's reason, which names the value.

    The exit code alone is not trusted either: on a SOPS-encrypted file dotenvx
    finds nothing to decrypt, prints "no change" and exits 0, and it can exit 0
    leaving its own ciphertext when the key is missing or invalid. The file is
    read back, and if it still holds ciphertext it is put back as it was and
    reported, so the caller neither counts it as decrypted nor marks it
    skip-worktree (#963).

    Any failure, not only a ``DotenvxError`` (dotenvx missing, the read-back
    failing), is a ``PartialEncryptionError`` that says what became of the file,
    so a secrets-only pull can report the files it decrypted before it.
    """
    try:
        snapshot = DecryptSnapshot(file)
    except OSError as e:
        raise PartialEncryptionError.decrypt_failed(file, e, f"{file} was left as it was.") from e
    try:
        with snapshot:
            dotenvx.decrypt(file)
            # Inside the snapshot, so a read-back that fails restores the file too.
            ciphertext = _leftover_ciphertext(file)
    except Exception as e:
        raise PartialEncryptionError.decrypt_failed(file, e, snapshot.note) from e
    if ciphertext:
        raise PartialEncryptionError.still_encrypted(file, ciphertext, snapshot.restore())


def _holds_ciphertext(file: Path) -> bool:
    """``is_file_encrypted``, with a file that cannot be read refused as a failed decrypt.

    An unreadable secret file raised a bare ``PermissionError``: pull-partial
    called it an "Unexpected error", ``envdrift pull`` crashed, and a
    secrets-only pull lost the tally of the files it had decrypted before it.
    """
    try:
        return is_file_encrypted(file)
    except OSError as e:
        raise PartialEncryptionError.decrypt_failed(file, e, f"{file} was left as it was.") from e


def _encrypt_and_verify(dotenvx: DotenvxWrapper, file: Path) -> None:
    """Encrypt ``file`` in place and verify ciphertext actually landed.

    dotenvx exits 0 *without* encrypting when it cannot write or use the
    private key (.env.keys read-only / a directory / garbage), so trusting the
    exit code alone reports false success — re-read the file and fail loudly
    while it is still skip-worktree protected (#471). ``DotenvxFilenameError``
    is the pre-flight refusal of a name dotenvx would turn into an invalid key
    (silent lockout), raised BEFORE encrypting with the plaintext intact (#467).
    """
    try:
        dotenvx.encrypt(file)
    except (DotenvxError, DotenvxFilenameError) as e:
        raise PartialEncryptionError.encrypt_failed(file, e) from e
    # dotenvx ran in the working directory, and leaves its _PLAIN keys plain (#1048).
    if has_plaintext_secret_value(file, plain_keys=plain_keys_apply()):
        raise PartialEncryptionError.encryption_did_not_take_effect(file)


def encrypt_secret_file(env_config: PartialEncryptionEnvironmentConfig) -> None:
    """
    Encrypt the secret file in-place using dotenvx.

    Args:
        env_config: Environment configuration

    Raises:
        PartialEncryptionError: If encryption fails
    """
    secret_file = Path(env_config.secret_file)

    if not secret_file.exists():
        return

    # Skip re-encryption ONLY when the file is FULLY encrypted: it holds
    # ciphertext AND no leftover plaintext secret value. A MIXED file (some
    # values already encrypted, one freshly-added plaintext) must still be
    # re-encrypted — otherwise the new plaintext secret leaks into the committed
    # .secret file and the combined file. is_file_encrypted() returns True on
    # the first ciphertext value, so it alone cannot tell the two apart. A _PLAIN
    # key, which dotenvx would leave as it is, is no reason to run it (#1048).
    if is_fully_encrypted(secret_file, plain_keys=plain_keys_apply()):
        # Already fully encrypted (e.g. push run twice) — still lift any stale
        # skip-worktree protection so the encrypted diff is visible to git.
        _git_unskip_worktree(secret_file)
        return

    # Refuse a file with no variable assignments BEFORE invoking dotenvx:
    # handed an empty/comment-only file, dotenvx scaffolds its placeholder
    # template (HELLO, AWS_ACCESS_KEY_ID, OPENAI_API_KEY, ...) and exits 0, so
    # push would fabricate ~13 secrets the user never wrote and count them as
    # encrypted. Same guard as the bare-encrypt backend (#443, #471).
    if not file_has_assignment(secret_file):
        raise PartialEncryptionError.nothing_to_encrypt(secret_file)

    # Encrypt using dotenvx (idempotent: re-encrypts only the plaintext values,
    # leaving any already-encrypted values untouched), then verify ciphertext
    # actually landed BEFORE lifting the git skip-worktree protection so a
    # still-plaintext file stays protected from a routine `git add .` (#471).
    _encrypt_and_verify(DotenvxWrapper(), secret_file)

    # Re-enable git tracking now the file is encrypted again
    _git_unskip_worktree(secret_file)


def decrypt_secret_file(env_config: PartialEncryptionEnvironmentConfig) -> bool:
    """
    Decrypt the secret file in-place using dotenvx.

    Args:
        env_config: Environment configuration

    Returns:
        True if the file was successfully marked skip-worktree, False otherwise.

    Raises:
        PartialEncryptionError: If decryption fails. The file is left as it was.
    """
    secret_file = Path(env_config.secret_file)

    if not secret_file.exists():
        raise PartialEncryptionError.file_not_found(secret_file)

    # Check if already decrypted
    if not _holds_ciphertext(secret_file):
        # Already plaintext on disk — still protect it from accidental commit.
        return _git_skip_worktree(secret_file)

    # Decrypt using dotenvx; a failed decrypt leaves the file as it was (#948).
    _decrypt_in_place(DotenvxWrapper(), secret_file)

    # Prevent accidental commit of the now-plaintext secret file.
    # git update-index --skip-worktree hides local changes from git add / git status
    # until encrypt_secret_file calls --no-skip-worktree after re-encryption.
    return _git_skip_worktree(secret_file)


def push_partial_encryption(
    env_config: PartialEncryptionEnvironmentConfig, *, check: bool = False
) -> dict[str, int | bool]:
    """
    Push operation: Encrypt secret file + combine with clear file.

    Steps:
    1. Encrypt .env.{env}.secret using dotenvx (in-place)
    2. Combine .env.{env}.clear + encrypted .secret → .env.{env}

    Args:
        env_config: Environment configuration
        check: When True, run as a dry run — do not encrypt and do not write the
            combined file. ``in_sync`` is True only when BOTH the combined file
            already matches the source files AND the secret file is FULLY
            encrypted. A plaintext or mixed-state secret file (a freshly-added
            plaintext value alongside existing ciphertext) always reports out of
            sync — a real push would re-encrypt it — even if the combined file
            happens to match.

    Returns:
        Dict with stats: {"clear_lines": X, "secret_vars": Y, "in_sync": bool}

    Raises:
        PartialEncryptionError: If push operation fails
    """
    if check:
        # Dry run: never mutate the secret file or overwrite the combined file.
        stats = combine_files(env_config, write=False)
        # A real push would re-encrypt the secret file first, so a secret that is
        # not fully encrypted on disk means the project is NOT in a pushed state —
        # regardless of whether the combined-file text happens to line up. This
        # mirrors the encrypt-path skip guard (is_file_encrypted AND no leftover
        # plaintext secret): a mixed-state file (some ciphertext, one freshly
        # added plaintext value) trips is_file_encrypted but would still be
        # re-encrypted, so it must report out of sync. The same _PLAIN rule as the
        # real push applies (#1048).
        secret_file = Path(env_config.secret_file)
        if secret_file.exists() and not is_fully_encrypted(
            secret_file, plain_keys=plain_keys_apply()
        ):
            stats["in_sync"] = False
        return stats

    # Step 1: Encrypt secret file
    encrypt_secret_file(env_config)

    # Step 2: Combine files
    stats = combine_files(env_config)

    return stats


def _resolve_secrets_dir(env_config: PartialEncryptionEnvironmentConfig) -> Path:
    # Guard against an empty secrets_dir, which Path() would normalise to the
    # current working directory and silently process unrelated .env* files.
    raw = env_config.secrets_dir.strip()
    if not raw:
        raise PartialEncryptionError(
            f"secrets_dir must be set for secrets_only environment '{env_config.name}'"
        )
    secrets_dir = Path(raw)
    if not secrets_dir.exists() or not secrets_dir.is_dir():
        raise PartialEncryptionError(f"secrets_dir not found or not a directory: {secrets_dir}")
    return secrets_dir


def push_secrets_only(
    env_config: PartialEncryptionEnvironmentConfig, *, check: bool = False
) -> dict[str, int | bool]:
    """
    Secrets-only push: encrypt all matching files in secrets_dir in place.

    Does not touch any configs directory and does not produce a combined file.

    Note:
        ``pattern`` is applied via ``Path.glob`` and is non-recursive by default.
        To include nested subdirectories, use a recursive glob like ``**/.env*``.

    Args:
        env_config: Environment configuration with secrets_only=True
        check: When True, run as a dry run — do not encrypt anything. ``encrypted``
            then reports how many files *would* be encrypted.

    Returns:
        Dict with counts: {"encrypted": N, "already_encrypted": M, "in_sync": bool}

    Raises:
        PartialEncryptionError: If the secrets_dir does not exist or encryption fails
    """
    secrets_dir = _resolve_secrets_dir(env_config)

    files = sorted(secrets_dir.glob(env_config.pattern))
    encrypted = 0
    already_encrypted = 0
    dotenvx = DotenvxWrapper()

    for file in files:
        if not _is_pushable_secret_file(file):
            continue
        if _encrypt_secrets_only_file(dotenvx, file, check=check):
            encrypted += 1
        else:
            already_encrypted += 1

    return {
        "encrypted": encrypted,
        "already_encrypted": already_encrypted,
        "in_sync": encrypted == 0,
    }


def _is_pushable_secret_file(file: Path) -> bool:
    """Return True if ``file`` is a real secret file eligible for encryption.

    Skips non-files and companion files (.example/.sample/.template) or the
    dotenvx key file (.keys), even if they match the glob pattern (#358).
    """
    return file.is_file() and not _is_excluded_env_file(file.name)


def dotenvx_key_files(env_config: PartialEncryptionEnvironmentConfig) -> list[Path]:
    """Return the ``.env.keys`` files dotenvx writes for one environment (#961).

    ``DotenvxWrapper`` passes ``-fk`` with the ``.env.keys`` next to the file it
    encrypts, so the private key lands beside the secret file, not in the
    working directory. Combine mode has one key file, next to ``secret_file``.
    Secrets-only mode has one in ``secrets_dir`` and one in every folder its
    ``pattern`` reaches (a recursive pattern reaches nested folders).
    """
    if not env_config.secrets_only:
        secret_file = env_config.secret_file.strip()
        return [Path(secret_file).parent / ".env.keys"] if secret_file else []
    raw_dir = env_config.secrets_dir.strip()
    if not raw_dir:
        return []
    keys: list[Path] = []
    for folder in _secrets_only_key_folders(Path(raw_dir), env_config.pattern):
        key_file = folder / ".env.keys"
        if key_file not in keys:
            keys.append(key_file)
    return keys


def _secrets_only_key_folders(secrets_dir: Path, pattern: str) -> list[Path]:
    """``secrets_dir``, then the folder of every secret file ``pattern`` matches in it."""
    if secrets_dir.exists() and not secrets_dir.is_dir():
        # push and pull refuse it for this environment, so dotenvx writes no key
        # under it; a path below a regular file made git crash the whole command.
        return []
    if not secrets_dir.is_dir():
        return [secrets_dir]
    try:
        matched = sorted(secrets_dir.glob(pattern))
    except (ValueError, NotImplementedError, OSError):
        # Path.glob raises ValueError for an empty pattern and NotImplementedError
        # for an absolute one; the push/pull step reports either for this environment.
        matched = []
    return [secrets_dir, *(file.parent for file in matched if _is_pushable_secret_file(file))]


def _encrypt_secrets_only_file(dotenvx: DotenvxWrapper, file: Path, *, check: bool) -> bool:
    """Encrypt a single secrets-only file in place; return True if it was (re)encrypted.

    A file counts as "already encrypted" only when it is FULLY encrypted:
    ciphertext present AND no leftover plaintext secret value. A MIXED file
    (some values encrypted, one freshly-added plaintext) must be re-encrypted,
    or the new plaintext secret ships verbatim. ``is_file_encrypted`` trips on
    the first ciphertext value, so it alone treats a mixed file as done —
    ``has_plaintext_secret_value`` catches the leak.

    Returns False (already-encrypted) without touching ``dotenvx`` when the file
    is fully encrypted, a ``_PLAIN`` key dotenvx leaves plain aside (#1048). In
    ``check`` mode no file is modified.
    """
    if is_fully_encrypted(file, plain_keys=plain_keys_apply()):
        if not check:
            # Already fully encrypted — lift any stale skip-worktree protection
            # so the encrypted diff is visible to git.
            _git_unskip_worktree(file)
        return False
    # Refuse a file with no variable assignments BEFORE invoking dotenvx (and
    # before counting it as would-encrypt in check mode): dotenvx scaffolds
    # placeholder secrets into an empty file and exits 0 (#443, #471). The same
    # guard as encrypt_secret_file / the bare-encrypt backend.
    if not file_has_assignment(file):
        raise PartialEncryptionError.nothing_to_encrypt(file)
    if check:
        # Dry run: this plaintext / mixed file would be encrypted by a real push.
        return True
    # Encrypt and verify ciphertext actually landed BEFORE lifting the git
    # skip-worktree protection, so a still-plaintext file stays protected (#471).
    _encrypt_and_verify(dotenvx, file)
    # Re-enable git tracking now the file is encrypted again.
    _git_unskip_worktree(file)
    return True


def pull_secrets_only(env_config: PartialEncryptionEnvironmentConfig) -> SecretsOnlyPullResult:
    """
    Secrets-only pull: decrypt all matching files in secrets_dir in place.

    Does not touch any configs directory.

    Note:
        ``pattern`` is applied via ``Path.glob`` and is non-recursive by default.
        To include nested subdirectories, use a recursive glob like ``**/.env*``.

    Args:
        env_config: Environment configuration with secrets_only=True

    Returns:
        ``{"decrypted": N, "already_decrypted": M, "protected": P, "unprotected": [...]}``.
        ``protected`` counts the files this pull decrypted and marked skip-worktree,
        and ``unprotected`` lists the ones it decrypted but could not mark. Files that
        were plaintext already are still marked, but counted in neither (#998).

    Raises:
        PartialEncryptionError: If the secrets_dir does not exist.
        SecretsOnlyPullError: If a file fails to decrypt. That file is left as it
            was; the error carries the counts for the files handled before it.
    """
    secrets_dir = _resolve_secrets_dir(env_config)

    files = sorted(secrets_dir.glob(env_config.pattern))
    decrypted = 0
    already_decrypted = 0
    protected = 0
    unprotected: list[Path] = []
    dotenvx = DotenvxWrapper()

    for file in files:
        try:
            if not file.is_file():
                continue
            if _is_excluded_env_file(file.name):
                # Never decrypt companion files (.example/.sample/.template) or the
                # dotenvx key file (.keys), even if they match the glob pattern (#358).
                continue
            if not _holds_ciphertext(file):
                # Already plaintext on disk — still protect it from accidental commit.
                # This pull did not decrypt it, so it does not count as protected:
                # counting it let the notice call an unprotected set protected (#998).
                _git_skip_worktree(file)
                already_decrypted += 1
                continue
            _decrypt_in_place(dotenvx, file)
        except Exception as e:
            # Whatever failed, the files decrypted before this one are plaintext
            # now: report them instead of an environment that looks untouched (#948).
            message = str(e)
            if not isinstance(e, PartialEncryptionError):
                message = f"Failed to decrypt {file}: {message}"
            raise SecretsOnlyPullError(
                message,
                decrypted=decrypted,
                already_decrypted=already_decrypted,
                protected=protected,
                unprotected=unprotected,
            ) from e
        decrypted += 1
        # Prevent accidental commit of the now-plaintext secret file until
        # push_secrets_only re-encrypts it and lifts the protection.
        if _git_skip_worktree(file):
            protected += 1
        else:
            unprotected.append(file)

    return {
        "decrypted": decrypted,
        "already_decrypted": already_decrypted,
        "protected": protected,
        "unprotected": unprotected,
    }


class PullPartialResult(NamedTuple):
    """Outcome of a combine-mode pull for a single environment."""

    was_decrypted: bool  # True if the file was encrypted before this pull (i.e. got decrypted)
    # True if the file is now marked skip-worktree. Callers count it only for a
    # file this pull decrypted: one that was plaintext already proves nothing (#998).
    protected: bool


def pull_partial_encryption(env_config: PartialEncryptionEnvironmentConfig) -> PullPartialResult:
    """
    Pull operation: Decrypt secret file for editing.

    Steps:
    1. Decrypt .env.{env}.secret in-place

    Args:
        env_config: Environment configuration

    Returns:
        PullPartialResult(was_decrypted, protected): whether the file was decrypted
        by this call, and whether it is now marked skip-worktree.

    Raises:
        PartialEncryptionError: If pull operation fails
    """
    secret_file = Path(env_config.secret_file)

    if not secret_file.exists():
        raise PartialEncryptionError.file_not_found(secret_file)

    was_encrypted = _holds_ciphertext(secret_file)

    # Decrypt secret file
    protected = decrypt_secret_file(env_config)

    return PullPartialResult(was_decrypted=was_encrypted, protected=protected)
