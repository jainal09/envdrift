"""Give an encrypted file's key the name its mapping expects, without re-encrypting.

A file encrypted as ``.env.local`` and renamed to ``.env.localenv`` keeps its key
under ``DOTENV_PRIVATE_KEY_LOCAL`` while its mapping expects
``DOTENV_PRIVATE_KEY_LOCALENV``. ``lock`` used to decrypt and re-encrypt such a
file and counted on dotenvx creating a key under the new name once the old header
was stripped. Now that the header is kept (#938), that re-encryption used the old
key again, so "re-encrypted with new key" was false and the next ``lock`` tried
again. Re-labeling writes the same key under the expected name and renames the
file's public-key header to match, so the ciphertext and the key stay as they are.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from envdrift.integrations.dotenvx_keys import (
    PRIVATE_KEY_PREFIX,
    PUBLIC_KEY_PREFIX,
    assignment_values,
    distinct_keys,
    key_identity,
    normalize_public_key,
    private_key_candidates,
    private_key_scalar,
    private_keys,
    public_key_for,
    public_key_values,
)
from envdrift.sync.operations import atomic_write

# A DOTENV_PUBLIC_KEY* assignment line, split around its name.
_HEADER_LINE_RE = re.compile(
    r"^(?P<lead>[ \t\ufeff]*(?:export[ \t]+)?)(?P<name>DOTENV_PUBLIC_KEY[A-Za-z0-9_.-]*)"
    r"(?P<rest>[ \t]*(?:=|:[ \t]).*)$"
)

RelabelAction = Literal["none", "planned", "relabeled", "no_key", "failed"]


@dataclass(frozen=True)
class RelabelOutcome:
    """What :func:`relabel_dotenvx_key` found or did.

    ``none``: nothing to do (the expected key is there, or no other key is).
    ``planned``: a dry run found the key under ``old_name``.
    ``relabeled``: the key is now also saved under the expected name.
    ``no_key``: the keys file holds other keys, but not this file's.
    ``failed``: the files could not be read, or the change could not be
    confirmed and was undone; ``message`` says why.
    """

    action: RelabelAction
    old_name: str | None = None
    message: str = ""


def _read_text(path: Path) -> str | None:
    """Read ``path`` as UTF-8, ``None`` when it does not exist."""
    if not path.exists():
        return None
    return path.read_bytes().decode("utf-8")


def _find_source(env_text: str, others: dict[str, list[str]]) -> list[tuple[str, str]]:
    """Return the distinct ``(name, key)`` pairs whose public key the file carries."""
    present = {normalize_public_key(value) for value in public_key_values(env_text)}
    found: dict[str, tuple[str, str]] = {}
    for name, values in others.items():
        for candidate in private_key_candidates(values):
            if private_key_scalar(candidate) is None:
                continue
            if public_key_for(candidate) in present:
                found.setdefault(key_identity(candidate), (name, candidate))
    return list(found.values())


def _renamed_header_line(line: str, public_key: str, public_name: str) -> str | None:
    """Return ``line`` renamed to ``public_name`` if it is ``public_key``'s header, else None."""
    body = line.rstrip("\r")
    match = _HEADER_LINE_RE.match(body)
    if match is None:
        return None
    values = assignment_values(body, match.group("name"))
    if not values or normalize_public_key(values[0]) != public_key:
        return None
    return f"{match.group('lead')}{public_name}{match.group('rest')}{line[len(body) :]}"


def _has_filename_comment(lines: list[str], header: int) -> bool:
    """Whether dotenvx's ``# <filename>`` line sits two lines below ``lines[header]``."""
    comment = header + 2
    if comment >= len(lines) or lines[header + 1].strip():
        return False
    return lines[comment].startswith("# ")


def _rename_header(env_text: str, public_key: str, public_name: str, basename: str) -> str:
    """Rename the header carrying ``public_key`` to ``public_name``.

    The ``# <filename>`` line dotenvx writes two lines below the public key is
    updated too, so the header reads as if dotenvx had written it for this file.
    """
    lines = env_text.split("\n")
    for index, line in enumerate(lines):
        renamed = _renamed_header_line(line, public_key, public_name)
        if renamed is not None:
            _put_renamed_header(lines, index, renamed, basename)
    return "\n".join(lines)


def _put_renamed_header(lines: list[str], header: int, renamed: str, basename: str) -> None:
    """Write ``renamed`` at ``lines[header]``, and ``basename`` into its ``# <filename>`` line."""
    lines[header] = renamed
    if _has_filename_comment(lines, header):
        ending = "\r" if lines[header + 2].endswith("\r") else ""
        lines[header + 2] = f"# {basename}{ending}"


@dataclass(frozen=True)
class _Relabel:
    """The key ``env_file`` is encrypted with, found under ``old_name``, to save as ``expected``."""

    env_file: Path
    keys_file: Path
    expected: str
    old_name: str
    value: str

    @property
    def public_name(self) -> str:
        """The public-key name dotenvx pairs with ``expected``."""
        return PUBLIC_KEY_PREFIX + self.expected[len(PRIVATE_KEY_PREFIX) :]


def _confirmed(relabel: _Relabel) -> bool:
    """Re-read both files: one key under ``expected``, and only its public key."""
    keys_text = _read_text(relabel.keys_file) or ""
    env_text = _read_text(relabel.env_file) or ""
    held = distinct_keys(private_key_candidates(assignment_values(keys_text, relabel.expected)))
    present = {normalize_public_key(item) for item in public_key_values(env_text)}
    return (
        [key_identity(item) for item in held] == [key_identity(relabel.value)]
        and present == {public_key_for(relabel.value)}
        and bool(assignment_values(env_text, relabel.public_name))
    )


def _write_relabel(
    env_file: Path, keys_file: Path, writes: list[tuple[Path, bytes, bytes]]
) -> str | None:
    """Write each ``(path, before, after)``; on failure put every written file back.

    Each file is replaced whole (a temp file renamed over it), so a write that
    fails or is interrupted leaves the file as it was, never half written.
    """
    written: list[tuple[Path, bytes]] = []
    try:
        for path, before, after in writes:
            atomic_write(path, after.decode("utf-8"))
            written.append((path, before))
    except OSError as exc:
        return f"could not write {env_file.name} or {keys_file}: {exc}{_put_back(written)}"
    return None


def _put_back(written: list[tuple[Path, bytes]]) -> str:
    """Write back each file's old bytes; describe the files that could not be."""
    failed: list[str] = []
    for path, before in reversed(written):
        try:
            atomic_write(path, before.decode("utf-8"))
        except OSError as exc:
            failed.append(f"{path} ({exc})")
    return f"; could not put back {', '.join(failed)}" if failed else ""


def _locate(
    env_file: Path, keys_file: Path, expected: str
) -> tuple[_Relabel, str, str] | RelabelOutcome:
    """Find the key to save under ``expected``, or the outcome that ends the search.

    Returns the key with both files' text, so the change is made to what was read.
    """
    try:
        # No keys file holds no other key, so it ends the search as "none" below.
        keys_text = _read_text(keys_file) or ""
        env_text = _read_text(env_file) or ""
    except (OSError, ValueError) as exc:
        return RelabelOutcome(
            "failed", message=f"cannot read {env_file.name} or {keys_file}: {exc}"
        )
    keys = private_keys(keys_text)
    others = {name: values for name, values in keys.items() if name != expected}
    if expected in keys or not others:
        return RelabelOutcome("none")
    sources = _find_source(env_text, others)
    if len(sources) != 1:
        return _no_single_source(keys_file, expected, len(sources))
    old_name, value = sources[0]
    return _Relabel(env_file, keys_file, expected, old_name, value), keys_text, env_text


def _no_single_source(keys_file: Path, expected: str, count: int) -> RelabelOutcome:
    """The outcome when the file's public keys match no key, or several, in ``keys_file``."""
    if count == 0:
        return RelabelOutcome(
            "no_key", message=f"{keys_file} holds no key for this file (expected {expected})"
        )
    return RelabelOutcome(
        "failed", message=f"the file carries public keys of {count} different keys in {keys_file}"
    )


def _apply(relabel: _Relabel, keys_text: str, env_text: str) -> RelabelOutcome:
    """Save the key under ``expected`` and rename the header; undo both unless confirmed."""
    env_file, keys_file = relabel.env_file, relabel.keys_file
    new_keys = f"{keys_text}\n# {env_file.name}\n{relabel.expected}={relabel.value}\n"
    new_env = _rename_header(
        env_text, public_key_for(relabel.value), relabel.public_name, env_file.name
    )
    writes = [
        (keys_file, keys_text.encode("utf-8"), new_keys.encode("utf-8")),
        (env_file, env_text.encode("utf-8"), new_env.encode("utf-8")),
    ]
    problem = _write_relabel(env_file, keys_file, writes)
    if problem is None and not _confirmed(relabel):
        undone = _write_relabel(
            env_file, keys_file, [(path, after, before) for path, before, after in writes]
        )
        problem = f"the re-labeled key could not be confirmed in {keys_file}; " + (
            "nothing was changed" if undone is None else f"putting the files back failed: {undone}"
        )
    if problem is not None:
        return RelabelOutcome("failed", old_name=relabel.old_name, message=problem)
    return RelabelOutcome("relabeled", old_name=relabel.old_name)


def relabel_dotenvx_key(
    env_file: Path, keys_file: Path, expected: str, *, apply: bool
) -> RelabelOutcome:
    """Save the key ``env_file`` is encrypted with under ``expected``.

    The key is found by the public key in the file's header, not by guessing a
    name. The old name stays in the keys file (another file may still use it),
    the same value is appended under ``expected`` in dotenvx's own layout, and
    the header is renamed to the public name dotenvx pairs with ``expected``.
    The result is re-read; if it does not hold, both files are put back.
    """
    found = _locate(env_file, keys_file, expected)
    if isinstance(found, RelabelOutcome):
        return found
    relabel, keys_text, env_text = found
    if not apply:
        return RelabelOutcome("planned", old_name=relabel.old_name)
    return _apply(relabel, keys_text, env_text)
