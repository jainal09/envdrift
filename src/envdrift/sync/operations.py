"""Atomic file operations for sync."""

from __future__ import annotations

import contextlib
import hashlib
import os
import secrets
import shutil
import stat
import tempfile
from datetime import datetime
from pathlib import Path

from envdrift.integrations.dotenvx_keys import (
    assignment_line_pattern,
    assignment_values,
    parse_assignments,
    value_continuation_lines,
)

# Per-process salt so the redaction digest is a within-run discriminator only
# (local vs vault in the same output), never an offline brute-force / rainbow
# target across runs. Not persisted.
_REDACTION_SALT = secrets.token_bytes(16)

# dotenvx .env.keys header — byte-identical to the header dotenvx itself writes
# (#474): box lines end in "/" (not "\#"), the link and armor lines keep
# dotenvx's padding so the box edges align, and the "ARMORED KEYS" line matches
# the pinned dotenvx (see constants.json). EnvKeysFile claims dotenvx format
# preservation, so a later dotenvx append must not introduce a second, visibly
# different header style. The integration test derives the expected block from
# the real pinned binary's output, so a dotenvx bump that changes the header
# fails CI pointing here.
DOTENVX_HEADER = """#/------------------!DOTENV_PRIVATE_KEYS!-------------------/
#/ private decryption keys. DO NOT commit to source control /
#/     [how it works](https://dotenvx.com/encryption)       /
#/          ⛨ ARMORED KEYS: `dotenvx armor up`              /
#/----------------------------------------------------------/"""


def _rewrite_key_lines(lines: list[str], key_name: str, value: str) -> tuple[list[str], bool]:
    """Set every line dotenvx reads as ``key_name`` to ``value``.

    A quoted value that spans lines is replaced whole: its other lines go with
    it, so none of its text is left to be read as a line of its own. A line
    inside another value is that value's text and stays as it is. Returns the
    new lines and whether any line was ``key_name``'s.
    """
    text = "\n".join(lines)
    own = value_continuation_lines(text, key_name)
    inside = value_continuation_lines(text)
    key_pattern = assignment_line_pattern(key_name)
    rewritten: list[str] = []
    found = False
    for index, line in enumerate(lines):
        if index in own:
            continue
        if index not in inside and key_pattern.match(line):
            rewritten.append(f"{key_name}={value}")
            found = True
        else:
            rewritten.append(line)
    return rewritten, found


class EnvKeysFile:
    """Read and write .env.keys files with dotenvx format preservation."""

    def __init__(self, path: Path):
        """Initialize with path to .env.keys file."""
        self.path = path

    def exists(self) -> bool:
        """Check if the file exists."""
        return self.path.exists()

    def read_values(self, key_name: str) -> list[str]:
        """
        Return every value of ``key_name`` in the file, in file order.

        The file is parsed exactly as dotenvx parses it (a BOM, ``export``,
        spaces around ``=``, quotes and inline comments included), so the
        values are the ones dotenvx would load (#938). dotenvx keeps every
        value of a repeated name, so a second line is a second key, not a
        replacement. Returns ``[]`` when the file or the key is absent.

        Raises:
            OSError: The path exists but cannot be read (e.g. a directory).
            UnicodeDecodeError: The file is not valid UTF-8.
        """
        if not self.path.exists():
            return []
        # dotenvx (Node.js) reads/writes .env.keys as UTF-8, and the header now
        # contains a non-ASCII character — pin the codec so a non-UTF-8 locale
        # (Windows cp1252, LC_ALL=C) cannot raise UnicodeDecodeError (#474).
        return assignment_values(self.path.read_bytes().decode("utf-8"), key_name)

    def read_key(self, key_name: str) -> str | None:
        """
        Read a specific key value from the file: the first one, as dotenvx parses it.

        Returns None if file doesn't exist or key not found, and "" for a
        present-but-empty value (``KEY=``): None means "key absent";
        conflating the two made an empty vault secret re-sync forever as
        CREATED and report a false "Key file does not exist" in verify-only
        mode (#413). Use :meth:`read_values` to see every value.
        """
        values = self.read_values(key_name)
        return values[0] if values else None

    def write_key(
        self,
        key_name: str,
        value: str,
        environment: str = "production",
        expected: list[str] | None = None,
    ) -> None:
        """
        Write/update a key, preserving existing content and header.

        Every line dotenvx would read as ``key_name`` (``export`` and spaces
        around ``=`` included) is rewritten, so no older value is left behind
        for dotenvx to load. Creates the file with proper header if it doesn't
        exist. A value dotenvx would not read back as given is refused first.

        ``expected`` is every value the caller read under ``key_name`` when it
        decided to write (``[]`` for none). When the file holds anything else
        by now, another writer changed it in between, and nothing is written.
        Nor is it when the file changes while the new copy is written: it is
        read again right before that copy replaces it.
        """
        self.require_readable_value(key_name, value)
        if self.path.exists():
            # UTF-8 like dotenvx itself, regardless of the platform locale (#474).
            raw = self.path.read_bytes()
            content = raw.decode("utf-8")
            self._require_unchanged(key_name, content, expected)
            new_lines, key_found = _rewrite_key_lines(content.splitlines(), key_name, value)

            if not key_found:
                # Add environment comment if not present
                env_comment = f"# .env.{environment}"
                if env_comment not in content:
                    new_lines.append(env_comment)
                new_lines.append(f"{key_name}={value}")

            new_content = "\n".join(new_lines)
            if not new_content.endswith("\n"):
                new_content += "\n"

            self._require_only_value(key_name, value, content, new_content)
            if not replace_if_unchanged(self.path, raw, new_content):
                raise self._changed_error(key_name)
        else:
            self._require_unchanged(key_name, "", expected)
            # Create new file with header. dotenvx leaves a blank line between
            # the header block and the first "# .env.<environment>" comment —
            # reproduce its layout byte-for-byte (#474).
            content = f"{DOTENVX_HEADER}\n\n# .env.{environment}\n{key_name}={value}\n"
            try:
                create_new_file(self.path, content)
            except FileExistsError:
                raise self._changed_error(key_name) from None

    def _require_unchanged(self, key_name: str, content: str, expected: list[str] | None) -> None:
        """Refuse when ``content`` no longer holds the ``expected`` values of ``key_name``.

        Raises:
            ValueError: Another writer changed the key after the caller read it.
        """
        if expected is not None and assignment_values(content, key_name) != expected:
            raise self._changed_error(key_name)

    def _changed_error(self, key_name: str) -> ValueError:
        """The refusal for a key another writer changed after it was read."""
        return ValueError(
            f"{self.path} changed while envdrift was working on it: it no longer holds "
            f"the {key_name} envdrift read. Nothing was changed; run the command again."
        )

    def require_readable_value(self, key_name: str, value: str) -> None:
        """Refuse a value that ``key_name=<value>`` would not load as given.

        dotenvx reads ``#`` as the start of a comment and strips quotes and
        surrounding spaces, so such a value would be stored as another key.

        Raises:
            ValueError: dotenvx would load another value. The message never
                includes the value, which is secret material.
        """
        if assignment_values(f"{key_name}={value}\n", key_name) != [value]:
            raise ValueError(
                f"dotenvx would not read the new {key_name} for {self.path} as it was "
                f"given: the value holds a character dotenvx reads specially, such as '#' "
                f"or a quote. Nothing was changed."
            )

    def _require_only_value(
        self, key_name: str, value: str, content: str, new_content: str
    ) -> None:
        """Refuse a rewrite after which a reader would load anything but ``value`` anew.

        dotenvx also reads ``KEY:`` with the value on the next line. That layout
        cannot be rewritten line by line, so the old key would stay loaded next
        to the new one; nothing is written instead. Every other name must read
        as it did in ``content``.

        Raises:
            ValueError: ``new_content`` holds a value for ``key_name`` that is
                not ``value`` (``value`` on several lines is the same key), or
                another name reads differently than in ``content``.
        """
        before = parse_assignments(content)
        after = parse_assignments(new_content)
        before.pop(key_name, None)
        if set(after.pop(key_name, [])) != {value} or after != before:
            raise ValueError(
                f"{self.path} holds {key_name} in a layout envdrift cannot rewrite without "
                f"changing what dotenvx reads, such as '{key_name}:' with the key on the "
                f"next line. Write it as {key_name}=<key> and re-run. Nothing was changed."
            )

    def has_dotenvx_header(self) -> bool:
        """Check if file has the dotenvx header."""
        if not self.path.exists():
            return False
        # UTF-8 like dotenvx itself, regardless of the platform locale (#474).
        content = self.path.read_text(encoding="utf-8")
        return "DOTENV_PRIVATE_KEYS" in content

    def create_backup(self) -> Path:
        """Create a timestamped backup of the file.

        Uses microsecond precision and, on the off chance two backups land on
        the same timestamp (coarse clock, or two calls within one tick), appends
        an incrementing suffix so an earlier backup is never silently
        overwritten (#413). The target path is claimed atomically with
        ``O_CREAT | O_EXCL`` so a concurrent ``envdrift`` run sharing the
        workspace can't slip a file in between the name choice and the copy.

        A backup holds the same private keys as the file, and a ``.gitignore``
        entry for ``.env.keys`` does not cover ``.env.keys.backup.<ts>``. So
        before anything is copied, ``<name>.backup.*`` in this folder is added
        to ``.gitignore`` when git would not already ignore it; if that fails,
        no backup is made.
        """
        if not self.path.exists():
            raise FileNotFoundError(f"Cannot backup non-existent file: {self.path}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        backup_path = self.path.parent / f"{self.path.name}.backup.{timestamp}"
        from envdrift.utils.git import ensure_gitignore_glob, gitignore_escape

        ensure_gitignore_glob(backup_path, f"{gitignore_escape(self.path.name)}.backup.*")
        counter = 1
        while True:
            try:
                # O_EXCL atomically fails if the path already exists, closing the
                # TOCTOU window between an existence check and the copy.
                fd = os.open(str(backup_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                backup_path = self.path.parent / f"{self.path.name}.backup.{timestamp}.{counter}"
                counter += 1
                continue
            os.close(fd)
            break
        try:
            shutil.copy2(self.path, backup_path)
        except BaseException:
            # A failed copy must not leave the empty O_EXCL placeholder behind —
            # an empty "backup" is worse than none. Mirrors atomic_write().
            with contextlib.suppress(FileNotFoundError):
                backup_path.unlink()
            raise
        return backup_path


def atomic_write(
    path: Path,
    content: str | bytes,
    permissions: int = 0o600,
    *,
    max_permissions: int | None = None,
) -> None:
    """
    Write file atomically with proper permissions.

    ``content`` is written byte for byte: bytes as given, text as UTF-8 with its
    line ends as they are.

    Creates the temp file in the destination directory with an unguessable name
    via ``tempfile.mkstemp`` (``O_EXCL``, owned by us, never following a
    pre-existing symlink) and applies permissions to the *fd we created* with
    ``os.fchmod`` -- not a path-based ``chmod`` that could be redirected through
    a symlinked sibling. The temp file is then atomically renamed onto ``path``.
    If the destination already exists as a *real file*, its current mode is
    preserved instead of unconditionally forcing ``permissions``; a destination
    that is a symlink is ignored for mode purposes so a pre-planted symlink
    cannot inject an overly permissive mode onto the new secret.

    ``max_permissions`` caps the effective mode for secret-bearing writes: a
    preserved pre-existing mode is intersected with the cap, so a combined or
    merged file that was created world-readable (0o644) by a pre-fix
    ``write_text`` is tightened to the cap on the next write instead of staying
    exposed forever (#510 review). Modes are only ever narrowed, never widened.
    """
    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    mode = _destination_mode(path, permissions, max_permissions)

    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".envdrift-tmp"
    )
    tmp_path = Path(tmp_name)
    # ``mkstemp`` returns an fd we own. Hand it to ``os.fdopen`` *immediately* so
    # the wrapper owns it for the entire body and closes it exactly once on
    # ``__exit__`` (success *or* exception). We never close the fd ourselves --
    # doing so would either double-close (masking the real error with ``EBADF``
    # and leaking the temp file) or leak it. ``fchmod`` and ``fsync`` operate on
    # the same fd via ``fileno()`` while the wrapper still owns it.
    try:
        # Bytes, with text encoded as UTF-8: a text-mode file would use the
        # platform codec, and content can be non-ASCII (the dotenvx .env.keys
        # header contains "⛨") — under a non-UTF-8 locale (Windows cp1252,
        # LC_ALL=C) the write would raise UnicodeEncodeError. And Windows text
        # mode would translate "\n" to "\r\n", but dotenvx (Node.js) writes
        # these files byte-exactly with LF on every platform, and its Windows
        # parser is known to fail on CRLF ("Input string must contain hex
        # characters" — the reason DotenvxWrapper._normalize_line_endings
        # exists). Match dotenvx (#474).
        data = content.encode("utf-8") if isinstance(content, str) else content
        with os.fdopen(fd, "wb") as tmp_file:
            # ``os.fchmod`` applies to the fd we own, never a symlink target. It
            # is absent on Windows, where permission bits are largely a no-op.
            if hasattr(os, "fchmod"):
                os.fchmod(tmp_file.fileno(), mode)
            tmp_file.write(data)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        # The fdopen wrapper has closed the fd; the rename promotes the temp
        # file atomically onto the destination (``Path.replace`` delegates to
        # ``os.replace``).
        tmp_path.replace(path)
    except BaseException:
        # The fd is owned/closed by the fdopen wrapper, so we never close it
        # here. Only ever unlink the temp file we created, never the
        # destination; suppress its absence so the original error propagates.
        with contextlib.suppress(FileNotFoundError):
            tmp_path.unlink()
        raise


def _destination_mode(path: Path, permissions: int, max_permissions: int | None = None) -> int:
    """The mode a file written over ``path`` gets: the mode of the file there, if any.

    ``lstat`` does not follow symlinks, and a destination that is a symlink keeps
    ``permissions``: an attacker who pre-plants a symlink at the destination
    pointing at a 0o777 file they own must not be able to force that permissive
    mode onto the freshly written secret.
    """
    mode = permissions
    with contextlib.suppress(FileNotFoundError):
        dest_stat = path.lstat()
        if not stat.S_ISLNK(dest_stat.st_mode):
            mode = dest_stat.st_mode & 0o777
    if max_permissions is not None:
        mode &= max_permissions
    return mode


def replace_if_unchanged(path: Path, before: bytes, content: str) -> bool:
    """Replace ``path`` with ``content`` whole, but only while it still holds ``before``.

    The new content is written to a temp file and synced first. Only then is
    ``path`` read again, and the temp file renamed over it when that read gives
    ``before``. So a writer that changed the file while envdrift worked on it is
    not overwritten, except in the moment between that read and the rename.
    Returns False, with nothing written, when the file changed.
    """
    mode = _destination_mode(path, 0o600)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".envdrift-tmp"
    )
    tmp_path = Path(tmp_name)
    try:
        _write_fd(fd, content.encode("utf-8"), mode)
        if _read_bytes_or_none(path) != before:
            return False
        tmp_path.replace(path)
        return True
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp_path.unlink()


def _read_bytes_or_none(path: Path) -> bytes | None:
    """Return the bytes of ``path``, or ``None`` when no file is there."""
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None


def create_new_file(path: Path, content: str, permissions: int = 0o600) -> None:
    """Write ``path`` whole, but only when no file is there yet.

    The content goes to a temp file next to ``path``, which is then hard-linked
    to ``path``. The link fails with ``FileExistsError`` when another writer
    created the file first, so that file is never overwritten, and ``path``
    never holds part of ``content``. Where the filesystem has no hard links,
    ``path`` is created with ``O_EXCL`` and written in place.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    data = content.encode("utf-8")
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".envdrift-tmp"
    )
    tmp_path = Path(tmp_name)
    try:
        _write_fd(fd, data, permissions)
        try:
            os.link(tmp_path, path)
        except FileExistsError:
            raise
        except OSError:
            # No hard links here (FAT, some network shares): O_EXCL still
            # refuses a file another writer created.
            _write_new_file(path, data, permissions)
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp_path.unlink()


def _write_new_file(path: Path, data: bytes, permissions: int) -> None:
    """Create ``path`` with ``O_EXCL`` and write ``data`` to it in place.

    A write that fails removes the file it created, so no part of ``data`` is left.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, permissions)
    try:
        _write_fd(fd, data, permissions)
    except BaseException:
        with contextlib.suppress(OSError):
            path.unlink()
        raise


def _write_fd(fd: int, data: bytes, permissions: int) -> None:
    """Write ``data`` to the file ``fd`` opens, synced to disk, and close it."""
    with os.fdopen(fd, "wb") as handle:
        if hasattr(os, "fchmod"):
            os.fchmod(handle.fileno(), permissions)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def ensure_directory(path: Path) -> None:
    """Create directory if it doesn't exist."""
    path.mkdir(parents=True, exist_ok=True)


def redact_value(value: str | None) -> str | None:
    """Return a non-reversible, within-run discriminator for a secret value.

    Emits ``<redacted len=N sha=XXXXXXXX>`` -- never any plaintext of the secret.
    Two different values yield different output (a visible mismatch signal);
    identical values yield identical output. The digest is salted per process,
    so it cannot be brute-forced offline or correlated across runs.
    """
    if value is None:
        return None
    if value == "":
        return "<empty>"
    digest = hashlib.blake2b(value.encode("utf-8"), salt=_REDACTION_SALT, digest_size=4).hexdigest()
    return f"<redacted len={len(value)} sha={digest}>"
