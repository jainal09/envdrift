"""How dotenvx reads ``.env.keys`` and names its keys, reproduced for envdrift.

envdrift has to know which private key a folder holds for a file *exactly as the
dotenvx binary sees it*. If it reads a different key than dotenvx, it seeds,
compares or verifies one key while dotenvx uses another (#938). This module is
that single rule, ported from the pinned dotenvx 2.38.2 bundle and checked
against the real binary:

- :func:`parse_assignments` is dotenvx's ``.env`` scanner. A UTF-8 BOM,
  ``export``, spaces around ``=``, the ``KEY: value`` form, all three quote
  styles and inline comments read the same way here as in dotenvx. Repeated
  names keep every value, in file order, as dotenvx does.
- :func:`private_key_candidates` splits values on ``,`` the way dotenvx builds
  its key ring, so ``KEY=a,b`` holds two keys.
- :func:`dotenvx_key_names` derives ``DOTENV_PUBLIC_KEY*`` and
  ``DOTENV_PRIVATE_KEY*`` from a filename as dotenvx does
  (``.env.prod.eu.west`` gives ``PROD_EU``, ``secrets.env`` gives
  ``SECRETSDEVELOPMENT``).
- :func:`public_key_for` derives the compressed secp256k1 public key of a
  private key with plain integer arithmetic (no new dependency). It accepts a
  key exactly when dotenvx's ``new PrivateKey(Buffer.from(hex, "hex"))`` does.
- :func:`plan_key_reuse` and :func:`key_outcome_problem` are the checks the
  dotenvx wrapper runs before and after ``dotenvx encrypt``.

Everything here works on text. Reading and writing files, and turning a refusal
into a ``DotenvxError``, is left to the callers.
"""

from __future__ import annotations

import os
import re
from bisect import bisect_left
from dataclasses import dataclass
from pathlib import Path

# JavaScript's ``\s`` and ``String.prototype.trim`` set. It differs from Python's
# ``str.isspace``: it includes the BOM (U+FEFF) and leaves out U+001C-U+001F and
# U+0085. dotenvx relies on it to read a BOM-prefixed first line.
_JS_SPACE_CLASS = "\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
_JS_SPACE_CHARS = (
    "\t\n\v\f\r \u00a0\u1680"
    + "".join(chr(code) for code in range(0x2000, 0x200B))
    + "\u2028\u2029\u202f\u205f\u3000\ufeff"
)
_S = f"[{_JS_SPACE_CLASS}]"
# JavaScript's multiline ``^`` and ``$``: a line starts after any of its line
# terminators, not only after ``\n``.
_BOL = r"(?:(?<=[\n\r\u2028\u2029])|\A)"
_EOL = r"(?=[\n\r\u2028\u2029]|\Z)"

# dotenvx's LINE regex, with JavaScript's ``\w`` (ASCII only), ``\s`` and ``.``.
_LINE_RE = re.compile(
    _BOL
    + _S
    + "*(?:export"
    + _S
    + "+)?([A-Za-z0-9_.-]+)(?:"
    + _S
    + "*="
    + _S
    + "*?|:"
    + _S
    + "+?)("
    + _S
    + r"*'(?:\\'|[^'])*'|"
    + _S
    + r'*"(?:\\"|[^"])*"|'
    + _S
    + r"*`(?:\\`|[^`])*`|[^#\r\n]+)?"
    + _S
    + r"*(?:#[^\n\r\u2028\u2029]*)?"
    + _EOL
)
_SURROUNDING_QUOTES_RE = re.compile(_BOL + r"(['\"`])([\s\S]*)\1" + _EOL)

PRIVATE_KEY_PREFIX = "DOTENV_PRIVATE_KEY"
PUBLIC_KEY_PREFIX = "DOTENV_PUBLIC_KEY"
ENCRYPTED_PREFIX = "encrypted:"

# secp256k1 domain parameters (SEC 2, section 2.4.1).
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_PUBLIC_KEY_HEX_RE = re.compile(r"(?:0[23][0-9a-f]{64}|04[0-9a-f]{128})")

# The banner dotenvx writes above a file's public key (prependPublicKey).
PUBLIC_KEY_BANNER = (
    "#/-------------------[DOTENV_PUBLIC_KEY]--------------------/\n"
    "#/            public-key encryption for .env files          /\n"
    "#/       [how it works](https://dotenvx.com/encryption)     /\n"
    "#/----------------------------------------------------------/"
)


class KeyReuseError(ValueError):
    """The keys file cannot tell which key a file must be encrypted with."""


def _clean_value(raw: str | None) -> str:
    """Turn a matched raw value into the value dotenvx stores, quotes removed."""
    text = (raw or "").strip(_JS_SPACE_CHARS)
    quote = text[:1] if text[:1] in ("'", '"', "`") else ""
    text = _SURROUNDING_QUOTES_RE.sub(r"\2", text)
    if quote == "'":
        text = text.replace("\\'", "'")
    elif quote == '"':
        text = text.replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t")
    return text


def parse_assignments(text: str) -> dict[str, list[str]]:
    """Parse dotenv text the way dotenvx does.

    Returns each name with all of its values in file order. dotenvx keeps
    every value of a repeated name and builds its key ring from all of them,
    so a second ``DOTENV_PRIVATE_KEY_PRODUCTION`` line is a second key, not a
    replacement of the first.
    """
    normalized = re.sub(r"\r\n?", "\n", text)
    parsed: dict[str, list[str]] = {}
    for match in _LINE_RE.finditer(normalized):
        parsed.setdefault(match.group(1), []).append(_clean_value(match.group(2)))
    return parsed


def value_continuation_lines(text: str, name: str | None = None) -> set[int]:
    """Return the indices of the ``text.split("\\n")`` lines that continue a quoted value.

    dotenvx reads a quoted value across lines. Those lines are the value's text,
    not comments or assignments of their own, so a writer that edits lines must
    leave them alone, or drop them with the value it replaces. With ``name``,
    only the lines of the values assigned to ``name`` are returned.
    """
    flat = text.replace("\r\n", "\n")
    breaks = [index for index, char in enumerate(flat) if char == "\n"]
    inside: set[int] = set()
    for match in _LINE_RE.finditer(flat):
        if match.group(2) is None or name not in (None, match.group(1)):
            continue
        first = bisect_left(breaks, match.start(2))
        inside.update(range(first + 1, bisect_left(breaks, match.end(2)) + 1))
    return inside


def assignment_values(text: str, name: str) -> list[str]:
    """Return every value assigned to ``name`` in ``text``, in file order."""
    return list(parse_assignments(text).get(name, []))


_LINE_SPACE = f"[{_JS_SPACE_CLASS.replace(chr(10), '').replace(chr(13), '')}]"


def assignment_line_pattern(name: str) -> re.Pattern[str]:
    """Match the start of one line that dotenvx reads as an assignment to ``name``.

    The per-line form of :func:`parse_assignments`: optional whitespace (a BOM
    included), optional ``export``, the name, then ``=`` or ``: ``. Writers use
    it to find every line a reader would load for ``name``.
    """
    return re.compile(
        rf"^{_LINE_SPACE}*(?:export{_LINE_SPACE}+)?{re.escape(name)}{_LINE_SPACE}*(?:=|:{_LINE_SPACE})"
    )


def private_key_candidates(values: list[str]) -> list[str]:
    """Split private-key values on ``,`` like dotenvx's key ring does."""
    return [piece for value in values for piece in value.split(",")]


def private_keys(text: str) -> dict[str, list[str]]:
    """Return every ``DOTENV_PRIVATE_KEY*`` name in ``text`` with all its values."""
    return {
        name: values
        for name, values in parse_assignments(text).items()
        if name.startswith(PRIVATE_KEY_PREFIX)
    }


def public_key_values(text: str) -> list[str]:
    """Return the value of every ``DOTENV_PUBLIC_KEY*`` assignment in ``text``."""
    return [
        value
        for name, values in parse_assignments(text).items()
        if name.startswith(PUBLIC_KEY_PREFIX)
        for value in values
    ]


def has_encrypted_values(text: str) -> bool:
    """Return True if any non-public-key value in ``text`` is dotenvx ciphertext."""
    return any(
        value.startswith(ENCRYPTED_PREFIX)
        for name, values in parse_assignments(text).items()
        if not name.startswith(PUBLIC_KEY_PREFIX)
        for value in values
    )


def unverifiable_ciphertext(text: str) -> bool:
    """Whether ``text`` holds ciphertext but no public key to tie a private key to it.

    A file's public key is the only sign of which key its values were
    encrypted with, so without one no held key can be checked against them.
    """
    return has_encrypted_values(text) and not public_key_values(text)


def _canonical_env_filename(name: str) -> str:
    """dotenvx's canonicalEnvFilename: lowercase, ``.env*.txt`` loses ``.txt``."""
    base = name.lower()
    if base.startswith(".env") and base.endswith(".txt"):
        base = base[: -len(".txt")]
    return base


def dotenvx_environment(filename: str) -> str:
    """Return the environment name dotenvx derives from ``filename``.

    Mirrors dotenvx's ``environment()`` helper: the parts after ``.env.`` name
    it, joined with ``_``, and at most two of them count
    (``.env.prod.eu.west`` is ``prod_eu``). A name with no such part becomes
    ``development`` in place of its first ``.env`` (``secrets.env`` is
    ``secretsdevelopment``).
    """
    canonical = _canonical_env_filename(filename)
    parts = canonical.split(".")[2:]
    if not parts:
        return canonical.replace(".env", "development", 1)
    if len(parts) == 1:
        return parts[0]
    return "_".join(parts[:2])


def dotenvx_key_names(filename: str | Path) -> tuple[str, str]:
    """Return the ``(public, private)`` key names dotenvx gives ``filename``.

    This is the name dotenvx uses when the file has no public key of its own:
    ``DOTENV_PUBLIC_KEY``/``DOTENV_PRIVATE_KEY`` for ``.env``, otherwise
    ``DOTENV_*_KEY_<ENVIRONMENT>`` from :func:`dotenvx_environment`.
    """
    canonical = _canonical_env_filename(Path(filename).name)
    if canonical == ".env":
        return PUBLIC_KEY_PREFIX, PRIVATE_KEY_PREFIX
    suffix = dotenvx_environment(canonical).upper()
    return f"{PUBLIC_KEY_PREFIX}_{suffix}", f"{PRIVATE_KEY_PREFIX}_{suffix}"


def _node_hex_bytes(text: str) -> bytes:
    """Decode hex like Node's ``Buffer.from(text, "hex")``.

    Node decodes whole digit pairs from the start and stops at the first pair
    that is not hex, so ``<64 hex>zz`` still yields the 32-byte key and a
    trailing odd digit is dropped. dotenvx builds its private keys this way.
    """
    out = bytearray()
    for index in range(0, len(text) - 1, 2):
        pair = text[index : index + 2]
        if pair[0] not in _HEX_DIGITS or pair[1] not in _HEX_DIGITS:
            break
        out.append(int(pair, 16))
    return bytes(out)


def _point_add(
    left: tuple[int, int] | None, right: tuple[int, int] | None
) -> tuple[int, int] | None:
    """Add two points on secp256k1 (affine coordinates, ``None`` is infinity)."""
    if left is None:
        return right
    if right is None:
        return left
    if left[0] == right[0] and (left[1] + right[1]) % _P == 0:
        return None
    if left == right:
        slope = 3 * left[0] * left[0] * pow(2 * left[1], -1, _P) % _P
    else:
        slope = (right[1] - left[1]) * pow(right[0] - left[0], -1, _P) % _P
    x = (slope * slope - left[0] - right[0]) % _P
    return x, (slope * (left[0] - x) - left[1]) % _P


def _scalar_multiply(scalar: int) -> tuple[int, int]:
    """Return ``scalar * G`` by double-and-add.

    Not constant time. It only derives the public key of a key already on
    disk, to compare it with a file's header, so timing reveals nothing new.
    """
    result: tuple[int, int] | None = None
    addend: tuple[int, int] | None = _G
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    if result is None:  # pragma: no cover - impossible for 0 < scalar < N
        raise ValueError("not a valid secp256k1 scalar")
    return result


def private_key_scalar(private_key: str) -> int | None:
    """Return the secp256k1 scalar dotenvx reads from ``private_key``, or None.

    ``None`` means dotenvx's key ring would silently skip the value.
    """
    secret = _node_hex_bytes(private_key)
    if len(secret) != 32:
        return None
    scalar = int.from_bytes(secret, "big")
    return scalar if 0 < scalar < _N else None


def public_key_for(private_key: str) -> str:
    """Return the compressed public key (lowercase hex) of a dotenvx private key.

    Raises:
        ValueError: dotenvx would not accept ``private_key`` as a key.
    """
    scalar = private_key_scalar(private_key)
    if scalar is None:
        raise ValueError("not a valid dotenvx private key")
    x, y = _scalar_multiply(scalar)
    return ("03" if y & 1 else "02") + format(x, "064x")


def normalize_public_key(value: str) -> str:
    """Return a public key in compressed lowercase form so two spellings compare equal.

    An uncompressed ``04<x><y>`` key becomes ``02<x>``/``03<x>``. Anything that
    is not a public key is returned lowercased, so it never matches a real key.
    """
    lowered = value.lower()
    if _PUBLIC_KEY_HEX_RE.fullmatch(lowered) and lowered.startswith("04"):
        x_hex, y_hex = lowered[2:66], lowered[66:]
        return ("03" if int(y_hex, 16) & 1 else "02") + x_hex
    return lowered


def key_identity(private_key: str) -> str:
    """Return a value that is equal for two spellings of the same key."""
    scalar = private_key_scalar(private_key)
    return format(scalar, "064x") if scalar is not None else private_key


def distinct_keys(values: list[str]) -> list[str]:
    """Return the distinct keys in ``values`` (first spelling kept, file order)."""
    seen: set[str] = set()
    distinct: list[str] = []
    for value in values:
        identity = key_identity(value)
        if identity not in seen:
            seen.add(identity)
            distinct.append(value)
    return distinct


def _keys_file_hint(env_file: Path, keys_file: Path) -> str:
    """Return the `` # -fk <path>`` suffix dotenvx adds for a non-default keys file."""
    try:
        relative = os.path.relpath(keys_file, Path(env_file).parent)
    except ValueError:  # another drive on Windows: Node's path.relative gives it absolute
        relative = str(Path(keys_file).absolute())
    return "" if relative == ".env.keys" else f" # -fk {relative}"


def seed_public_key(text: str, env_file: Path, keys_file: Path, public_key: str) -> str:
    """Prepend the public-key header dotenvx itself would write (mutateSrc).

    The block, its ``# <filename>`` line and the position after a ``#!`` first
    line all match dotenvx, so a seeded file looks exactly like one dotenvx
    encrypted. The name is the one dotenvx derives from the filename, which
    both dotenvx 1.x (looked up by name) and 2.x (first public key) then use.
    """
    public_name, _ = dotenvx_key_names(env_file)
    header = (
        f"{PUBLIC_KEY_BANNER}\n"
        f'{public_name}="{public_key}"{_keys_file_hint(env_file, keys_file)}\n'
        f"\n# {env_file.name}"
    )
    first, _, rest = text.partition("\n")
    if first.startswith("#!"):
        return f"{first}\n{header}\n{rest}"
    return f"{header}\n{text}"


_PUBLIC_KEY_LINE_RE = re.compile(
    r"^(?P<head>[ \t\ufeff]*(?:export[ \t]+)?DOTENV_PUBLIC_KEY[A-Za-z0-9_.-]*"
    r"[ \t]*(?:=|:[ \t])[ \t]*)"
    r"(?P<value>\"[^\"\n]*\"|'[^'\n]*'|`[^`\n]*`|[^#\s]*)"
    r"(?P<tail>[^\n]*)$"
)


def rewrite_public_keys(text: str, public_key: str) -> str:
    """Set every single-line ``DOTENV_PUBLIC_KEY*`` value in ``text`` to ``public_key``.

    A line inside a quoted value that spans lines is that value's text, not a
    public key, so it stays as it is. A public key whose own quoted value spans
    lines is replaced whole: its other lines go with it.
    """
    in_values = value_continuation_lines(text)
    own = set().union(
        *(
            value_continuation_lines(text, name)
            for name in parse_assignments(text)
            if name.startswith(PUBLIC_KEY_PREFIX)
        )
    )
    rewritten: list[str] = []
    for index, line in enumerate(text.split("\n")):
        match = None if index in in_values else _PUBLIC_KEY_LINE_RE.match(line)
        if match:
            rewritten.append(f'{match.group("head")}"{public_key}"{match.group("tail")}')
        elif index not in own:
            rewritten.append(line)
    return "\n".join(rewritten)


@dataclass(frozen=True)
class KeyReusePlan:
    """What the wrapper hands dotenvx, and what must hold afterwards.

    Attributes:
        key_name: The ``DOTENV_PRIVATE_KEY*`` name the folder holds for the file.
        held_key: The one key held under ``key_name``, or ``None`` when the
            folder holds none (dotenvx then creates one, as before).
        public_key: ``public_key_for(held_key)`` when a key is held.
        env_text: The env text to encrypt, with the header seeded or corrected.
    """

    key_name: str
    held_key: str | None
    public_key: str | None
    env_text: str


@dataclass(frozen=True)
class KeyTarget:
    """The env file to encrypt, its keys file, and the key name it is encrypted under."""

    env_file: Path
    keys_file: Path
    key_name: str


def plan_key_reuse(env_text: str, keys_text: str | None, target: KeyTarget) -> KeyReusePlan:
    """Decide how to make dotenvx encrypt ``env_text`` with the key the folder holds.

    dotenvx 2.x encrypts with the file's first ``DOTENV_PUBLIC_KEY*`` value and,
    when the file has none, creates a brand-new key next to the existing one
    (#938). So when ``keys_text`` holds exactly one key under ``target.key_name``,
    the file must carry that key's public key: an absent header is seeded, a
    header for another key is corrected while nothing is encrypted yet, and a
    file already encrypted under another key is refused.

    Raises:
        KeyReuseError: the key name holds more than one key, holds a value
            dotenvx cannot use, or the file is encrypted under another key.
    """
    held = _held_key(keys_text, target)
    if held is None:
        return KeyReusePlan(target.key_name, None, None, env_text)
    public_key = _usable_public_key(held, target)
    return KeyReusePlan(
        target.key_name, held, public_key, _with_public_key(env_text, public_key, target)
    )


def _held_key(keys_text: str | None, target: KeyTarget) -> str | None:
    """Return the one key ``target.key_name`` holds, None for none; refuse two."""
    values = assignment_values(keys_text, target.key_name) if keys_text else []
    held = distinct_keys(private_key_candidates(values))
    if len(held) > 1:
        raise KeyReuseError(
            f"{target.keys_file} holds {len(held)} different keys under {target.key_name}, "
            f"so envdrift cannot tell which one {target.env_file.name} must be encrypted "
            f"with. Keep the key your team uses (the vault key) and delete the other "
            f"{target.key_name} value."
        )
    return held[0] if held else None


def _usable_public_key(held: str, target: KeyTarget) -> str:
    """Return the public key of ``held``; refuse a value dotenvx cannot use as a key."""
    try:
        return public_key_for(held)
    except ValueError:
        raise KeyReuseError(
            f"{target.key_name} in {target.keys_file} is not a valid dotenvx key, so "
            f"envdrift will not encrypt {target.env_file.name} with it. Restore the key "
            f"(envdrift sync or vault-pull) or delete the line."
        ) from None


def _with_public_key(env_text: str, public_key: str, target: KeyTarget) -> str:
    """Return ``env_text`` carrying ``public_key`` as its only public key, or refuse."""
    present = [normalize_public_key(value) for value in public_key_values(env_text)]
    if not present and has_encrypted_values(env_text):
        raise KeyReuseError(
            f"{target.env_file.name} holds encrypted values but no DOTENV_PUBLIC_KEY, so it "
            f"is not known whether they were encrypted with {target.key_name} in "
            f"{target.keys_file}. Restore the DOTENV_PUBLIC_KEY line of the key they were "
            f"encrypted with and re-run."
        )
    if not present:
        return seed_public_key(env_text, target.env_file, target.keys_file, public_key)
    if all(value == public_key for value in present):
        return env_text
    return _corrected_public_key(env_text, public_key, target)


def _corrected_public_key(env_text: str, public_key: str, target: KeyTarget) -> str:
    """Rewrite a header for another key while nothing is encrypted under it yet."""
    if has_encrypted_values(env_text):
        raise KeyReuseError(
            f"{target.env_file.name} is encrypted with another public key than the one of "
            f"{target.key_name} in {target.keys_file}, so values encrypted now could not be "
            f"decrypted together with the existing ones. Restore the key the file was "
            f"encrypted with, or decrypt the file with it first."
        )
    rewritten = rewrite_public_keys(env_text, public_key)
    if any(normalize_public_key(value) != public_key for value in public_key_values(rewritten)):
        raise KeyReuseError(
            f"{target.env_file.name} carries a public key for another key than "
            f"{target.key_name} in {target.keys_file}, and envdrift could not rewrite it "
            f"safely. Delete its DOTENV_PUBLIC_KEY lines and re-run."
        )
    return rewritten


def held_key_problem(env_text: str, keys_text: str | None, key_name: str) -> str | None:
    """Describe why an encrypted file does not match the key held for it, or None.

    The read-only form of :func:`plan_key_reuse` for a file that is already
    encrypted: ``key_name`` must hold one key that dotenvx can use, and every
    public key in the file must be that key's. No key held is not a problem:
    anyone may encrypt with the file's public key. A held key cannot be checked
    against ciphertext in a file without a public key, so that is one.
    """
    values = assignment_values(keys_text, key_name) if keys_text else []
    problem = held_values_problem(env_text, values, key_name)
    if problem is None and values and unverifiable_ciphertext(env_text):
        return (
            f"the file holds encrypted values but no DOTENV_PUBLIC_KEY to check {key_name} against"
        )
    return problem


def held_values_problem(env_text: str, values: list[str], key_name: str) -> str | None:
    """:func:`held_key_problem` for ``values``, the values held under ``key_name``."""
    held = distinct_keys(private_key_candidates(values))
    if len(held) > 1:
        return f"the keys file holds {len(held)} different keys under {key_name}"
    if not held:
        return None
    if private_key_scalar(held[0]) is None:
        # dotenvx's key ring skips such a value, so nothing could decrypt the file.
        return f"{key_name} in the keys file is not a valid dotenvx key"
    public_key = public_key_for(held[0])
    present = {normalize_public_key(value) for value in public_key_values(env_text)}
    if present - {public_key}:
        return f"the file is encrypted with another public key than the one of {key_name}"
    return None


def _changed_key_names(before: dict[str, list[str]], after: dict[str, list[str]]) -> list[str]:
    """Return the names that existed before and no longer hold the same values."""
    return [name for name, values in before.items() if after.get(name) != values]


def key_outcome_problem(
    plan: KeyReusePlan,
    keys_before: str | None,
    keys_after: str | None,
    env_after: str,
) -> str | None:
    """Describe how dotenvx broke the key plan, or return ``None`` when it held.

    Checks, in order: no key that existed before changed or gained a value; when
    a key was held, no new key name appeared and every public key in the file
    is the held key's. When none was held, a public key the file did not carry
    before must be its only one, and its private key must be saved in the keys
    file. A public key the file already carried is the team's and needs no
    local private key (anyone may encrypt with it).
    """
    before = private_keys(keys_before or "")
    after = private_keys(keys_after or "")
    changed = _changed_key_names(before, after)
    if changed:
        return f"dotenvx changed {', '.join(changed)} in the keys file"
    present = {normalize_public_key(value) for value in public_key_values(env_after)}
    if plan.held_key is not None:
        added = [name for name in after if name not in before]
        return _held_key_outcome(plan, added, present)
    return _created_key_outcome(plan, after, present)


def _held_key_outcome(plan: KeyReusePlan, added: list[str], present: set[str]) -> str | None:
    """With a key held: dotenvx added no key name and left only the held key's public key."""
    if added:
        return f"dotenvx created {', '.join(added)} instead of using {plan.key_name}"
    if not present:
        # The header envdrift seeded is gone, so nothing says the values are the held key's.
        return f"the file carries no public key after dotenvx ran, so it is not {plan.key_name}'s"
    if present - {plan.public_key}:
        return f"dotenvx encrypted the file with another key than {plan.key_name}"
    return None


def _created_key_outcome(
    plan: KeyReusePlan, after: dict[str, list[str]], present: set[str]
) -> str | None:
    """With no key held: a new public key is the file's only one, and its key was saved."""
    carried = {normalize_public_key(value) for value in public_key_values(plan.env_text)}
    new_public = present - carried
    if not new_public:
        return None
    if carried or len(new_public) > 1:
        return "the file now carries two different public keys"
    if new_public - _saved_public_keys(after):
        return "dotenvx encrypted the file with a key it did not save in the keys file"
    return None


def _saved_public_keys(keys: dict[str, list[str]]) -> set[str]:
    """The public keys of every usable private key in ``keys``."""
    return {
        public_key_for(candidate)
        for values in keys.values()
        for candidate in private_key_candidates(values)
        if private_key_scalar(candidate) is not None
    }
