"""Atomic file operations for sync."""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import secrets
import shutil
import stat
import tempfile
from datetime import datetime
from pathlib import Path

# Per-process salt so the redaction digest is a within-run discriminator only
# (local vs vault in the same output), never an offline brute-force / rainbow
# target across runs. Not persisted.
_REDACTION_SALT = secrets.token_bytes(16)

# dotenvx .env.keys header — byte-identical to the header dotenvx itself writes
# (#474): box lines end in "/" (not "\#") and the link line keeps dotenvx's
# padding so the box edges align. EnvKeysFile claims dotenvx format
# preservation, so a later dotenvx append must not introduce a second,
# visibly different header style.
DOTENVX_HEADER = """#/------------------!DOTENV_PRIVATE_KEYS!-------------------/
#/ private decryption keys. DO NOT commit to source control /
#/     [how it works](https://dotenvx.com/encryption)       /
#/----------------------------------------------------------/"""


class EnvKeysFile:
    """Read and write .env.keys files with dotenvx format preservation."""

    def __init__(self, path: Path):
        """Initialize with path to .env.keys file."""
        self.path = path

    def exists(self) -> bool:
        """Check if the file exists."""
        return self.path.exists()

    def read_key(self, key_name: str) -> str | None:
        """
        Read a specific key value from the file.

        Returns None if file doesn't exist or key not found.
        """
        if not self.path.exists():
            return None

        content = self.path.read_text()
        # ``(.*)`` (not ``(.+)``) so a present-but-empty value (``KEY=``) returns
        # "" rather than None. None means "key absent"; conflating the two made
        # an empty vault secret re-sync forever as CREATED and report a false
        # "Key file does not exist" in verify-only mode (#413).
        pattern = rf"^{re.escape(key_name)}=(.*)$"

        for line in content.splitlines():
            match = re.match(pattern, line)
            if match:
                value = match.group(1).strip()
                # Remove quotes if present
                if (value.startswith('"') and value.endswith('"')) or (
                    value.startswith("'") and value.endswith("'")
                ):
                    value = value[1:-1]
                return value

        return None

    def write_key(self, key_name: str, value: str, environment: str = "production") -> None:
        """
        Write/update a key, preserving existing content and header.

        Creates the file with proper header if it doesn't exist.
        """
        if self.path.exists():
            content = self.path.read_text()
            lines = content.splitlines()

            # Check if key already exists
            key_pattern = rf"^{re.escape(key_name)}="
            key_found = False
            new_lines = []

            for line in lines:
                if re.match(key_pattern, line):
                    new_lines.append(f"{key_name}={value}")
                    key_found = True
                else:
                    new_lines.append(line)

            if not key_found:
                # Add environment comment if not present
                env_comment = f"# .env.{environment}"
                if env_comment not in content:
                    new_lines.append(env_comment)
                new_lines.append(f"{key_name}={value}")

            new_content = "\n".join(new_lines)
            if not new_content.endswith("\n"):
                new_content += "\n"

            atomic_write(self.path, new_content)
        else:
            # Create new file with header. dotenvx leaves a blank line between
            # the header block and the first "# .env.<environment>" comment —
            # reproduce its layout byte-for-byte (#474).
            content = f"{DOTENVX_HEADER}\n\n# .env.{environment}\n{key_name}={value}\n"
            atomic_write(self.path, content)

    def has_dotenvx_header(self) -> bool:
        """Check if file has the dotenvx header."""
        if not self.path.exists():
            return False
        content = self.path.read_text()
        return "DOTENV_PRIVATE_KEYS" in content

    def create_backup(self) -> Path:
        """Create a timestamped backup of the file.

        Uses microsecond precision and, on the off chance two backups land on
        the same timestamp (coarse clock, or two calls within one tick), appends
        an incrementing suffix so an earlier backup is never silently
        overwritten (#413). The target path is claimed atomically with
        ``O_CREAT | O_EXCL`` so a concurrent ``envdrift`` run sharing the
        workspace can't slip a file in between the name choice and the copy.
        """
        if not self.path.exists():
            raise FileNotFoundError(f"Cannot backup non-existent file: {self.path}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        backup_path = self.path.parent / f"{self.path.name}.backup.{timestamp}"
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


def atomic_write(path: Path, content: str, permissions: int = 0o600) -> None:
    """
    Write file atomically with proper permissions.

    Creates the temp file in the destination directory with an unguessable name
    via ``tempfile.mkstemp`` (``O_EXCL``, owned by us, never following a
    pre-existing symlink) and applies permissions to the *fd we created* with
    ``os.fchmod`` -- not a path-based ``chmod`` that could be redirected through
    a symlinked sibling. The temp file is then atomically renamed onto ``path``.
    If the destination already exists as a *real file*, its current mode is
    preserved instead of unconditionally forcing ``permissions``; a destination
    that is a symlink is ignored for mode purposes so a pre-planted symlink
    cannot inject an overly permissive mode onto the new secret.
    """
    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    # Preserve the destination's existing mode if it already exists as a real
    # file. Use ``lstat`` (does not follow symlinks) and skip preservation when
    # the destination is a symlink: an attacker who pre-plants a symlink at the
    # destination pointing at a 0o777 file they own must not be able to force
    # that permissive mode onto the freshly written secret.
    mode = permissions
    with contextlib.suppress(FileNotFoundError):
        dest_stat = path.lstat()
        if not stat.S_ISLNK(dest_stat.st_mode):
            mode = dest_stat.st_mode & 0o777

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
        with os.fdopen(fd, "w") as tmp_file:
            # ``os.fchmod`` applies to the fd we own, never a symlink target. It
            # is absent on Windows, where permission bits are largely a no-op.
            if hasattr(os, "fchmod"):
                os.fchmod(tmp_file.fileno(), mode)
            tmp_file.write(content)
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
