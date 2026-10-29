"""Pure structure-aware filters for the native scanner.

Extracted from ``native.py`` so the scanner module stays within CodeScene's
single-file LOC budget and the line/content classification helpers form a
cohesive, independently testable unit. These functions have no scanner state —
they take a line or file content and answer a yes/no structural question.
"""

from __future__ import annotations

import re

from envdrift.core.encryption import is_dotenvx_public_key_var
from envdrift.encryption.sops import SOPSEncryptionBackend

# A dotenvx public key is a secp256k1 *compressed* EC point: a 0x02/0x03 prefix
# byte followed by 32 bytes (64 hex chars) — 66 hex chars total. It is public by
# definition (not a secret) but is high-entropy and matches generic patterns, so
# we drop it at detection by value shape (anchored) regardless of var name. This
# complements the var-name skip (is_dotenvx_public_key_var) for cases where the
# key appears under an unexpected name. See #370.
_EC_PUBKEY_RE = re.compile(r"^0[23][0-9a-fA-F]{64}$")


# Code member-access shape: identifier segments chained by ``.`` / ``?.`` / ``->``,
# optional trailing call parens — e.g. ``config.Password``, ``handler.ReadToken()``,
# ``obj?.Property``, ``ptr->field``, ``this.props.apiKey``. The generic-secret rule
# uses this to drop values that look like dotted *code references* without
# discarding every value that merely contains a ``.``/``?`` — a high-entropy
# dotted password like ``Xk9.mQ2vLp8wRt4nZs6yBdFh`` is a real secret and must
# still be reported (it already cleared the entropy gate) (#413).
_MEMBER_ACCESS_SHAPE_RE = re.compile(
    r"^[A-Za-z_$][A-Za-z0-9_$]*"  # leading identifier
    r"(?:\s*(?:\?\.|\.|->)\s*[A-Za-z_$][A-Za-z0-9_$]*(?:\(\s*\))?)+$"
)
# Real code segments are word-like identifiers; split a chain on its access ops.
_MEMBER_SPLIT_RE = re.compile(r"\?\.|->|\.")
_VOWEL_RE = re.compile(r"[AaEeIiOoUu]")
# Min vowel density of a real identifier: >=1 vowel per 6 chars. A single-vowel
# test is too permissive — random base62 noise with one stray vowel (e.g.
# ``mQ2vLpaWRt4nZs6yBdFh``, 1/20) would be misread as code and a dotted secret
# silently skipped (#413). Density admits identifiers, rejects high-entropy noise.
_VOWEL_DENSITY_CHARS = 6


def _segment_is_word_like(seg: str) -> bool:
    """True if a member-access segment is real code, not random secret noise.

    Word-like: a trailing ``()`` call, a short member (<=4 chars), or a longer
    identifier with natural vowel density. Long vowel-sparse segments are noise.
    """
    if seg.endswith("()") or len(seg) <= 4:  # method call / short member (env, id)
        return True
    return len(_VOWEL_RE.findall(seg)) * _VOWEL_DENSITY_CHARS >= len(seg)


def _looks_like_code_member_access(value: str) -> bool:
    """True if ``value`` is a dotted/arrow code member-access chain, not a secret.

    Requires the member-access shape AND that *every* segment is word-like, so a
    high-entropy dotted password whose segments are random base62 noise — even
    noise with a stray vowel — is reported as a generic-secret, not skipped (#413).
    """
    if not _MEMBER_ACCESS_SHAPE_RE.match(value):
        return False
    # The shape regex guarantees a non-empty identifier after each access operator.
    return all(_segment_is_word_like(seg.strip()) for seg in _MEMBER_SPLIT_RE.split(value))


# Structure-aware encryption detection (#348). A bare ``"encrypted:" in content``
# / ``"sops:" in content`` substring check misfires on plaintext that merely
# mentions the marker — e.g. a comment ``# this is not encrypted: true`` or a
# value ``MESSAGE=not encrypted: yes`` would suppress the unencrypted-env-file
# policy and hide a real leak. We instead require the marker in its real
# structural position.

# dotenvx: ``encrypted:`` must be the (optionally quoted) start of an assignment's
# *value* — ``NAME="encrypted:..."`` / ``NAME=encrypted:...`` — not anywhere in the
# line (and never inside a comment line, which is excluded separately).
_DOTENVX_VALUE_RE = re.compile(
    r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*[\"']?encrypted:",
)

# SOPS: a canonical ``ENC[AES256_GCM,...]`` value envelope (dotenv- or YAML-style).
_SOPS_ENC_RE = re.compile(r"ENC\[AES256_GCM,")

# SOPS metadata block markers, matched per (non-comment) line. *Derived* from the
# canonical set on ``envdrift.encryption.sops.SOPSEncryptionBackend`` (the single
# source of truth) so the scanner and the encryption backend can never silently
# diverge: a new SOPS format variant added there is honoured here automatically.
# The canonical patterns are compiled with ``re.MULTILINE`` for whole-content
# ``.search()``; the scanner instead matches each line with ``.match()``, so we
# recompile the same source strings without ``re.MULTILINE`` (with per-line input
# the multiline ``^``/``$`` anchors are equivalent to plain ``.match()`` anchoring,
# verified by parity test). A bare ``^sops[:_]`` prefix was too loose: it matched
# plaintext dotenv assignments like ``sops_token=...`` / ``sops_enabled=...`` (vars
# that merely *start with* ``sops_``), misclassifying an unencrypted file as
# encrypted (#348). SOPS only emits ``sops_version`` / ``sops_mac`` keys in its
# dotenv metadata trailer.
_SOPS_METADATA_RES = tuple(
    re.compile(pattern.pattern, pattern.flags & ~re.MULTILINE)
    for pattern in SOPSEncryptionBackend.SOPS_METADATA_PATTERNS
)


def _line_is_dotenvx_encrypted(line: str) -> bool:
    """True if ``line`` assigns an actual dotenvx-encrypted value."""
    return bool(_DOTENVX_VALUE_RE.match(line))


def _line_is_sops_metadata(line: str) -> bool:
    """True if ``line`` is a canonical SOPS metadata-block marker."""
    return any(pattern.match(line) for pattern in _SOPS_METADATA_RES)


# The extent of an already-encrypted value on a line, its assignment included: a dotenvx value
# runs to the end of its ``encrypted:`` token (and its closing quote), a SOPS value to the end of
# its ``ENC[AES256_GCM,...]`` envelope. Neither holds whitespace, so whatever follows on the line
# is plaintext.
_DOTENVX_VALUE_SPAN_RE = re.compile(
    r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*[\"']?encrypted:[^\s\"']*[\"']?",
)
_SOPS_VALUE_SPAN_RE = re.compile(
    r"(?:[\"']?[A-Za-z_][\w.-]*[\"']?\s*[=:]\s*[\"']?)?ENC\[AES256_GCM,[^\]]*\]?",
)
# The value of an assignment, as far as its first whitespace (and closing quote).
_VALUE_TOKEN_RE = re.compile(r"\s*[\"']?[^\s\"']*[\"']?")


def _encrypted_value_spans(line: str) -> list[tuple[int, int]]:
    """The ``(start, end)`` spans of ``line`` that hold an already-encrypted value.

    Structure-aware (mirrors the file-level ``_content_is_encrypted``): a bare
    ``"encrypted:" in line`` / ``"ENC[" in line`` substring check misfires on a
    plaintext line that merely *mentions* the marker — e.g.
    ``DATA=ENC[something] AKIA…`` or ``URL=https://x/encrypted:y?key=AKIA…`` (#413).
    We instead require the marker in its real structural position: a
    dotenvx-encrypted value (anchored value-position ``encrypted:``) or a
    canonical SOPS ``ENC[AES256_GCM,`` envelope — not a bare ``ENC[``.

    Only the value is skipped, not its whole line: a plaintext secret after it
    on the same line, past a space or a form feed, is still found (#937).
    """
    spans = [match.span() for match in _SOPS_VALUE_SPAN_RE.finditer(line)]
    dotenvx = _DOTENVX_VALUE_SPAN_RE.match(line)
    if dotenvx:
        spans.append(dotenvx.span())
    return spans


def _skipped_value_spans(line: str) -> list[tuple[int, int]]:
    """The spans of ``line`` that pattern and entropy scanning leave out.

    The encrypted values, which are never re-flagged, and dotenvx's public key. Shared by
    both scans so they stay in sync.
    """
    spans = _encrypted_value_spans(line)
    name, equals, _ = line.partition("=")
    if equals and is_dotenvx_public_key_var(name.strip()):
        value = _VALUE_TOKEN_RE.match(line, len(name) + 1)
        spans.append((0, value.end() if value else len(line)))
    return spans


def _within_spans(spans: list[tuple[int, int]], start: int, end: int) -> bool:
    """True if ``[start, end)`` overlaps one of ``spans``."""
    return any(start < span_end and span_start < end for span_start, span_end in spans)


def _outside_encrypted_values(line: str, column_number: int | None) -> bool:
    """True if a finding at 1-based ``column_number`` of ``line`` is in none of its encrypted values.

    Without a column, only a line that holds no encrypted value qualifies. With one, a
    plaintext secret after an encrypted value on the same line does (#937).
    """
    spans = _encrypted_value_spans(line)
    if column_number is None:
        return not spans
    return not _within_spans(spans, column_number - 1, column_number)


def _content_has_sops_markers(content: str) -> bool:
    """True if ``content`` carries canonical SOPS structural markers.

    Requires either an ``ENC[AES256_GCM,...]`` value envelope or a canonical SOPS
    metadata key (top-level ``sops:`` / ``"sops":`` / ``sops_version=`` /
    ``sops_mac=``), each on a non-comment line — not a loose substring match and
    not an arbitrary ``sops_*`` plaintext var. Comment lines are skipped so the
    SOPS path is consistent with the dotenvx path in ``_content_is_encrypted``.
    """
    for line in content.splitlines():
        if line.lstrip().startswith("#"):
            continue
        if _SOPS_ENC_RE.search(line):
            return True
        if _line_is_sops_metadata(line):
            return True
    return False


def _content_is_encrypted(content: str) -> bool:
    """True if ``content`` is dotenvx- or SOPS-encrypted (structure-aware).

    Comment lines (stripped form starts with ``#``) never count on any path, so
    the dotenvx, SOPS-envelope, and SOPS-metadata checks stay consistent: a plain
    comment that merely *mentions* ``encrypted:`` / ``ENC[AES256_GCM,`` / ``sops:``
    does not suppress the unencrypted-file policy (#348). The dotenvx marker must
    sit in value position on an assignment line; SOPS detection (envelope or
    canonical metadata key) is delegated to ``_content_has_sops_markers``, which
    applies the same comment filter.
    """
    for line in content.splitlines():
        if line.lstrip().startswith("#"):
            continue
        if _line_is_dotenvx_encrypted(line):
            return True
    return _content_has_sops_markers(content)
