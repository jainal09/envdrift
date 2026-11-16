"""dotenvx CLI wrapper with local binary installation.

This module wraps the dotenvx binary for encryption/decryption of .env files.
Key features:
- Installs dotenvx binary inside .venv/bin/ (NOT system-wide)
- Pins version from constants.json for reproducibility
- Cross-platform support (Windows, macOS, Linux)
- Automatic line ending normalization for cross-platform compatibility
- No Node.js dependency required
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import urllib.request
from bisect import bisect_left
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from envdrift.install_integrity import (
    DOWNLOAD_TIMEOUT_SECONDS,
    ChecksumVerificationError,
    atomic_install,
    verify_download,
)
from envdrift.integrations.dotenvx_keys import (
    KeyReuseError,
    KeyReusePlan,
    KeyTarget,
    assignment_values,
    comment_cut_names,
    distinct_keys,
    dotenvx_key_names,
    has_encrypted_values,
    key_outcome_problem,
    normalize_public_key,
    parse_assignments,
    plan_key_reuse,
    private_key_candidates,
    value_continuation_lines,
)
from envdrift.utils.text import strip_ansi


def _load_constants() -> dict:
    """
    Load and return the parsed contents of the package's constants.json.

    The file is resolved relative to this module (../constants.json).

    Returns:
        dict: Parsed JSON object from constants.json.
    """
    constants_path = Path(__file__).parent.parent / "constants.json"
    with open(constants_path) as f:
        return json.load(f)


def _get_dotenvx_version() -> str:
    """
    Return the pinned dotenvx version from the package constants.

    Returns:
        version (str): The pinned dotenvx version string (for example, "1.2.3").
    """
    return _load_constants()["dotenvx_version"]


def _get_download_url_templates() -> dict[str, str]:
    """
    Return the download URL templates loaded from constants.json.

    Returns:
        download_urls (dict[str, str]): Mapping from platform/architecture identifiers to URL templates that include a version placeholder.
    """
    return _load_constants()["download_urls"]


def _get_checksums_url_template() -> str:
    """
    Return the dotenvx checksums file URL template from constants.json.

    Returns:
        checksums_url (str): URL template with a ``{version}`` placeholder, or
            an empty string when unconfigured (verification then fails closed).
    """
    return _load_constants().get("dotenvx_checksums_url", "")


# Load version from constants.json
DOTENVX_VERSION = _get_dotenvx_version()

# Upstream-published checksums file used to verify downloads (fail closed).
DOTENVX_CHECKSUMS_URL_TEMPLATE = _get_checksums_url_template()

# Download URLs by platform - loaded from constants.json and mapped to tuples
_URL_TEMPLATES = _get_download_url_templates()
DOWNLOAD_URLS = {
    ("Darwin", "x86_64"): _URL_TEMPLATES["darwin_amd64"],
    ("Darwin", "arm64"): _URL_TEMPLATES["darwin_arm64"],
    ("Linux", "x86_64"): _URL_TEMPLATES["linux_amd64"],
    ("Linux", "aarch64"): _URL_TEMPLATES["linux_arm64"],
    ("Windows", "AMD64"): _URL_TEMPLATES["windows_amd64"],
    ("Windows", "x86_64"): _URL_TEMPLATES["windows_amd64"],
}


class DotenvxNotFoundError(Exception):
    """dotenvx binary not found."""

    pass


class DotenvxError(Exception):
    """dotenvx command failed."""

    pass


class DotenvxKeyError(DotenvxError):
    """envdrift refused a dotenvx key change, and left both files as they were.

    Raised when the keys file cannot tell which key a file must be encrypted
    with, when ``dotenvx encrypt`` created or replaced a key instead of using
    the one the folder holds (#938), or when normalizing a custom filename
    would write one key over a different one. The message describes the state
    of the files, so every command can show it as it is.
    """


class DotenvxValueError(DotenvxError):
    """envdrift refused to encrypt a value dotenvx would not encrypt whole.

    Raised before dotenvx runs, so the file is left as it was: dotenvx ends an
    unquoted value at a ``#`` that touches it and would leave the rest of the
    value in the file as a plaintext comment (#947).
    """


class DotenvxInstallError(Exception):
    """Failed to install dotenvx."""

    pass


class DotenvxFilenameError(Exception):
    """Filename not compatible with dotenvx due to known bugs."""

    pass


# Only filenames matching this round-trip through dotenvx's key-name derivation.
# dotenvx builds the DOTENV_PRIVATE_KEY_<SLUG> env-var name from the filename, so
# a space or non-ASCII character yields an invalid name and a file that encrypts
# (exit 0) yet is permanently undecryptable — see is_dotenvx_safe_filename.
_DOTENVX_SAFE_FILENAME_RE = re.compile(r"[A-Za-z0-9._-]+")


def is_dotenvx_safe_filename(name: str) -> bool:
    """Return True if ``name`` survives dotenvx's ``DOTENV_*_<SLUG>`` key derivation.

    dotenvx derives the public/private-key env-var names from the filename, so
    only ``[A-Za-z0-9._-]`` characters round-trip into a usable key name. A space
    or non-ASCII character produces an invalid name (e.g.
    ``DOTENV_PRIVATE_KEY_MY SECRET``): the value still encrypts and dotenvx exits
    0, but the file is then permanently undecryptable and the original plaintext
    is destroyed — a silent secret lockout (#443/#457, #467). Both the guarded
    ``DotenvxEncryptionBackend`` and the ``DotenvxWrapper.encrypt`` seam used by
    the partial-encryption push/lock paths share this single predicate so the two
    cannot drift.
    """
    return bool(_DOTENVX_SAFE_FILENAME_RE.fullmatch(name))


def _dash_safe_path(path: Path | str) -> str:
    """Return ``path`` as an argv string dotenvx cannot misparse as CLI flags.

    dotenvx's commander-based CLI treats a leading-dash argv value as bundled
    options: ``encrypt -f -dash.env`` eats ``-dash.env`` as flags, leaves the
    real file untouched, fabricates a different file (``-ash.env``) full of
    placeholder secrets, and appends a junk ``DOTENV_PRIVATE_KEY_-ASH...`` entry
    to ``.env.keys`` (#474). Prefixing a dash-leading relative path with the
    current directory makes it unambiguous; the key slug dotenvx derives from
    the basename is unchanged, so encrypt/decrypt round-trip normally.

    The ``./`` prefix is built literally (not via ``Path``): path arithmetic
    normalizes ``./-dash.env`` back to ``-dash.env``, which would silently
    defeat the protection.
    """
    text = str(path)
    if text.startswith("-"):
        return f".{os.sep}{text}"
    return text


def _sibling_env_keys_file(env_file: Path, env_keys_file: Path | str | None) -> Path | str:
    """Return the ``.env.keys`` path to hand dotenvx as ``-fk``.

    dotenvx **v2** writes and reads ``.env.keys`` in the *process working
    directory* when ``-fk`` is omitted; **v1** kept it next to the target file.
    envdrift's model — and every caller here — expects one key store per folder,
    living beside the env file (``env_file.parent/.env.keys``): the sync engine,
    :func:`normalize_dotenvx_metadata` and ``EnvKeysFile`` all read it there. So
    when the caller does not pin a keys file, default it to that sibling path,
    preserving v1's layout under v2 — a file in a subfolder keeps its private key
    beside it (and stays decryptable) instead of scattering it into cwd, where a
    later decrypt could not find it.
    """
    if env_keys_file is None:
        return env_file.parent / ".env.keys"
    return env_keys_file


# The status line dotenvx ends a run with: "◇ decrypted <file> (...) via .env.keys"
# (v2; "◈ encrypted ..." for an encrypt, "✔ decrypted" in v1). It is printed even
# when the run failed on a value.
_STATUS_LINE_RE = re.compile(r"^\s*[\u2714\u25c7\u25c8]\s+(?:de|en)crypted\b")


def _without_status_lines(output: str) -> str:
    """dotenvx's ``output`` for an error message, without its "decrypted" status line.

    A decrypt that fails on one value still prints ``◇ decrypted <file>``. In the
    error it read as a success, right before "<file> was left as it was".
    """
    lines = (line for line in output.splitlines() if not _STATUS_LINE_RE.match(line))
    return "\n".join(lines).strip()


# A public-key assignment at the start of an env-file line, as dotenvx parses
# one: optional leading whitespace or BOM, optional ``export``, then the name.
_PUBLIC_KEY_NAME_LINE_RE = re.compile(
    r"^(?P<head>[ \t\ufeff]*(?:export[ \t]+)?)DOTENV_PUBLIC_KEY(?:_[A-Za-z0-9_.-]+)?"
    r"(?P<tail>[ \t]*(?:=|:[ \t]))"
)
# The same for a private key in ``.env.keys``; ``name`` is the whole key name.
_PRIVATE_KEY_NAME_LINE_RE = re.compile(
    r"^(?P<head>[ \t\ufeff]*(?:export[ \t]+)?)(?P<name>DOTENV_PRIVATE_KEY(?:_[A-Za-z0-9_.-]+)?)"
    r"(?P<tail>[ \t]*(?:=|:[ \t]).*)$"
)

# A private-key assignment as dotenvx writes it into ``.env.keys``: bare
# ``DOTENV_PRIVATE_KEY=`` (for a plain ``.env``) or ``DOTENV_PRIVATE_KEY_<SLUG>=``,
# with a non-empty value. A legitimate encrypt target only ever carries
# ``DOTENV_PUBLIC_KEY*`` lines, so a match identifies a (possibly renamed or
# symlinked) private-key store (#474).
_PRIVATE_KEY_ASSIGNMENT_RE = re.compile(
    r"^DOTENV_PRIVATE_KEY(?:_[A-Za-z0-9_-]+)?=.*\S", re.MULTILINE
)


def dotenvx_filename_needs_normalization(env_file: Path | str, environment: str) -> bool:
    """Return True when a dotenvx file's metadata must be normalized to canonical.

    dotenvx derives ``DOTENV_*_<NAME>`` from the filename, so only the canonical
    ``.env`` and ``.env.<environment>`` names already map to the
    ``DOTENV_*_<ENVIRONMENT>`` key envdrift uses. Any other name — service-prefixed
    or infix custom files, whether configured via ``env_file`` or auto-detected —
    yields a non-canonical key that :func:`normalize_dotenvx_metadata` must rewrite.
    """
    name = Path(env_file).name
    return name != ".env" and name != f".env.{environment}"


def _decode_utf8(data: bytes, path: Path) -> str:
    """Decode ``data`` as UTF-8 (BOM kept), raising ValueError naming ``path``."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{path} is not valid UTF-8 ({exc.reason})") from None


def _canonical_env_text(
    text: str, custom_comment: str, canonical_comment: str, public_key: str
) -> str:
    """Rename the dotenvx filename comment and public-key names in an env file.

    Line-anchored and split on ``\\n`` only, so a value holding another line
    separator, a ``\\r`` line ending or prose that mentions a key name is never
    touched, nor is a line inside a quoted value that spans lines.
    """
    lines = text.split("\n")
    in_values = value_continuation_lines(text)
    for index, line in enumerate(lines):
        if index in in_values:
            continue
        body = line[:-1] if line.endswith("\r") else line
        ending = line[len(body) :]
        if body.strip() == custom_comment:
            lines[index] = canonical_comment + ending
            continue
        match = _PUBLIC_KEY_NAME_LINE_RE.match(body)
        if match:
            lines[index] = f"{match.group('head')}{public_key}{match.group('tail')}" + (
                body[match.end() :] + ending
            )
    return "\n".join(lines)


def _generated_key_line(lines: list[str], custom_comment: str) -> tuple[int, int, str, str] | None:
    """Find the key dotenvx wrote under ``# <custom filename>`` in ``.env.keys``.

    Returns ``(comment_index, line_index, name, value)`` for the first
    private-key line after the comment (blank lines skipped, another comment
    ends the search), or ``None``.
    """
    comment_index = next(
        (index for index, line in enumerate(lines) if line.strip() == custom_comment), None
    )
    if comment_index is None:
        return None
    for index in range(comment_index + 1, len(lines)):
        stripped = lines[index].strip()
        if not stripped:
            continue
        match = _PRIVATE_KEY_NAME_LINE_RE.match(lines[index].rstrip("\r"))
        if stripped.startswith("#") or match is None:
            return None
        values = assignment_values(lines[index], match.group("name"))
        return comment_index, index, match.group("name"), values[0] if values else ""
    return None


def _holds_another_key(held: list[str], value: str) -> bool:
    """Whether ``held`` is two keys, or one that is not ``value``."""
    return len(held) > 1 or distinct_keys([*held, value]) != held


def _canonical_keys_text(
    text: str,
    env_file: Path,
    keys_file: Path,
    environment: str,
) -> str:
    """Rename the key dotenvx generated for ``env_file`` to the canonical name.

    Never writes one key over another: when the canonical name already holds a
    different key, both stay and :class:`DotenvxKeyError` is raised (#938).
    """
    canonical_private = f"DOTENV_PRIVATE_KEY_{environment.upper()}"
    lines = text.split("\n")
    generated = _generated_key_line(lines, f"# {env_file.name}")
    if generated is None:
        return text
    comment_index, line_index, name, value = generated
    if name == canonical_private:
        lines[comment_index] = f"# .env.{environment}"
        return "\n".join(lines)
    held = distinct_keys(private_key_candidates(parse_assignments(text).get(canonical_private, [])))
    if held and _holds_another_key(held, value):
        raise DotenvxKeyError(
            f"{keys_file} holds two different keys for {env_file.name}: "
            f"{canonical_private} and {name} (written under '# {env_file.name}'). "
            f"envdrift will not write one over the other, so both files were left as "
            f"they are. Keep the key your vault holds for {canonical_private}, delete "
            f"the other line, and re-run."
        )
    if held:
        # The same key under both names: drop the duplicate dotenvx wrote.
        del lines[line_index]
        del lines[comment_index]
        return "\n".join(lines)
    match = _PRIVATE_KEY_NAME_LINE_RE.match(lines[line_index].rstrip("\r"))
    if match is not None:
        ending = lines[line_index][len(lines[line_index].rstrip("\r")) :]
        lines[line_index] = f"{match.group('head')}{canonical_private}{match.group('tail')}{ending}"
    lines[comment_index] = f"# .env.{environment}"
    return "\n".join(lines)


def normalize_dotenvx_metadata(
    env_file: Path | str,
    env_keys_file: Path | str,
    environment: str,
) -> None:
    """Normalize dotenvx metadata to envdrift's configured environment name.

    dotenvx can encrypt any dotenv-format filename via ``--env-file``, but it
    derives ``DOTENV_PUBLIC_KEY_*`` and ``DOTENV_PRIVATE_KEY_*`` names from that
    filename. Vault sync uses the configured mapping environment as the source of
    truth, so mapped custom filenames are normalized back to
    ``DOTENV_*_<environment>`` after dotenvx runs.

    Both new contents are computed before anything is written. A key dotenvx
    generated is renamed to the canonical name only when that name is free or
    already holds the same key; a different held key is never overwritten
    (#938) and :class:`DotenvxKeyError` leaves both files untouched. Each file is
    replaced whole with its new bytes (a temp file renamed over it), so Windows
    newline translation cannot turn ``\\n`` into ``\\r\\n`` and an interrupted write
    leaves the old file; a failed second write puts the first file back.

    Raises:
        DotenvxKeyError: ``.env.keys`` holds a different key under the canonical name.
        OSError: A file cannot be read or written.
        ValueError: A file is not valid UTF-8.
    """
    env_file = Path(env_file)
    env_keys_file = Path(env_keys_file)
    custom_comment = f"# {env_file.name}"
    canonical_comment = f"# .env.{environment}"
    canonical_public = f"DOTENV_PUBLIC_KEY_{environment.upper()}"

    planned: list[tuple[Path, bytes, bytes]] = []
    if env_keys_file.exists():
        keys_before = env_keys_file.read_bytes()
        keys_text = _decode_utf8(keys_before, env_keys_file)
        keys_after = _canonical_keys_text(keys_text, env_file, env_keys_file, environment)
        planned.append((env_keys_file, keys_before, keys_after.encode("utf-8")))
    if env_file.exists():
        env_before = env_file.read_bytes()
        env_text = _decode_utf8(env_before, env_file)
        env_after = _canonical_env_text(
            env_text, custom_comment, canonical_comment, canonical_public
        )
        planned.append((env_file, env_before, env_after.encode("utf-8")))

    written: list[tuple[Path, bytes]] = []
    try:
        for path, before, after in planned:
            if after != before:
                _replace_file(path, after)
                written.append((path, before))
    except OSError:
        for path, before in reversed(written):
            _replace_file(path, before)
        raise


def _replace_file(path: Path, data: bytes) -> None:
    """Replace ``path`` with ``data`` whole: a temp file renamed over it, its mode kept.

    A write that fails or is interrupted leaves the old file, never half of it.
    """
    from envdrift.sync.operations import atomic_write

    atomic_write(path, data)


def get_platform_info() -> tuple[str, str]:
    """
    Return the current platform name and a normalized architecture identifier.

    The returned architecture value normalizes common variants (for example, AMD64 -> `x86_64` on non-Windows systems; `arm64` vs `aarch64` differs between Darwin and other OSes).

    Returns:
        tuple: `(system, machine)` where `system` is the platform name (e.g., "Darwin", "Linux", "Windows") and `machine` is the normalized architecture (e.g., "x86_64", "arm64", "aarch64", "AMD64").
    """
    system = platform.system()
    machine = platform.machine()

    # Normalize some architecture names
    if machine == "x86_64":
        pass  # Keep as is
    elif machine in ("AMD64", "amd64"):
        machine = "AMD64" if system == "Windows" else "x86_64"
    elif machine in ("arm64", "aarch64"):
        machine = "arm64" if system == "Darwin" else "aarch64"

    return system, machine


def get_venv_bin_dir() -> Path:
    """
    Determine the filesystem path to the current virtual environment's executable directory.

    Searches these locations in order: the VIRTUAL_ENV environment variable, candidate venv directories found on sys.path (including uv tool and pipx installs), a .venv directory in the current working directory, and finally falls back to user bin directories (~/.local/bin on Linux/macOS or %APPDATA%\\Python\\Scripts on Windows). Returns the venv's "bin" subdirectory on POSIX systems or "Scripts" on Windows.

    Returns:
        Path: Path to the virtual environment's bin directory (or Scripts on Windows).

    Raises:
        RuntimeError: If no virtual environment directory can be located.
    """
    # Check for virtual environment
    venv_path = os.environ.get("VIRTUAL_ENV")
    if venv_path:
        venv = Path(venv_path)
        if platform.system() == "Windows":
            return venv / "Scripts"
        return venv / "bin"

    # Try to find venv relative to the package
    # This handles cases where VIRTUAL_ENV isn't set
    for path in sys.path:
        p = Path(path)
        # Check for standard venv directories
        if ".venv" in p.parts or "venv" in p.parts:
            # Walk up to find the venv root
            while p.name not in (".venv", "venv") and p.parent != p:
                p = p.parent
            if p.name in (".venv", "venv"):
                if platform.system() == "Windows":
                    return p / "Scripts"
                return p / "bin"
        # Check for uv tool install (e.g., ~/.local/share/uv/tools/envdrift/)
        # or pipx install (e.g., ~/.local/pipx/venvs/envdrift/)
        is_uv_tool = "uv" in p.parts and "tools" in p.parts
        is_pipx = "pipx" in p.parts and "venvs" in p.parts
        if is_uv_tool or is_pipx:
            # Walk up to find the tool's venv root
            # Linux: lib/pythonX.Y/site-packages (3 levels up)
            # Windows: Lib/site-packages (2 levels up)
            while p.name != "site-packages" and p.parent != p:
                p = p.parent
            if p.name == "site-packages":
                # Check parent structure to determine levels
                if platform.system() == "Windows":
                    # Windows: site-packages -> Lib -> tool_venv
                    tool_venv = p.parent.parent
                    bin_dir = tool_venv / "Scripts"
                else:
                    # Linux: site-packages -> pythonX.Y -> lib -> tool_venv
                    tool_venv = p.parent.parent.parent
                    bin_dir = tool_venv / "bin"
                # Validate path exists before returning
                if bin_dir.parent.exists():
                    return bin_dir

    # Default to creating in current directory's .venv
    cwd_venv = Path.cwd() / ".venv"
    if cwd_venv.exists():
        if platform.system() == "Windows":
            return cwd_venv / "Scripts"
        return cwd_venv / "bin"

    # Fallback for plain pip install (system or --user)
    # Use user-writable bin directory
    if platform.system() == "Windows":
        # Windows user scripts: %APPDATA%\Python\Scripts
        appdata = os.environ.get("APPDATA")
        if appdata:
            user_scripts = Path(appdata) / "Python" / "Scripts"
            user_scripts.mkdir(parents=True, exist_ok=True)
            return user_scripts
    else:
        # Linux/macOS: ~/.local/bin (standard user bin directory)
        user_bin = Path.home() / ".local" / "bin"
        user_bin.mkdir(parents=True, exist_ok=True)
        return user_bin

    # Only reachable on Windows when APPDATA is not set
    raise RuntimeError(
        "Cannot find virtual environment or user bin directory. "
        "On Windows, ensure the APPDATA environment variable is set, "
        "or activate a virtual environment with: python -m venv .venv"
    )


def get_dotenvx_path() -> Path:
    """
    Return the expected filesystem path of the dotenvx executable within the project's virtual environment.

    Returns:
        Path to the dotenvx binary inside the virtual environment's bin (or Scripts on Windows).
    """
    bin_dir = get_venv_bin_dir()
    binary_name = "dotenvx.exe" if platform.system() == "Windows" else "dotenvx"
    return bin_dir / binary_name


def _read_text_for_check(path: Path) -> str | None:
    """Read ``path`` as UTF-8 text, or ``None`` when it cannot be read."""
    try:
        return path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None


@dataclass(frozen=True)
class _EncryptSnapshot:
    """The bytes of an env file and its keys file before ``encrypt`` touched them."""

    env_file: Path
    env_bytes: bytes
    keys_file: Path
    keys_bytes: bytes | None
    keys_text: str | None

    @classmethod
    def take(cls, env_file: Path, keys_file: Path) -> _EncryptSnapshot:
        """Read both files, failing cleanly on a keys file dotenvx could not use.

        A keys file that is a directory, unreadable or not UTF-8 raises
        ``DotenvxError`` instead of a traceback, before anything changed.
        """
        try:
            env_bytes = env_file.read_bytes()
        except OSError as exc:
            raise DotenvxError(f"Cannot read {env_file}: {exc.strerror or exc}") from None
        if not keys_file.exists():
            return cls(env_file, env_bytes, keys_file, None, None)
        try:
            keys_bytes = keys_file.read_bytes()
            keys_text = keys_bytes.decode("utf-8")
        except OSError as exc:
            raise DotenvxError(
                f"Cannot read the keys file {keys_file}: {exc.strerror or exc}. "
                f"Nothing was changed."
            ) from None
        except UnicodeDecodeError:
            raise DotenvxError(
                f"Cannot read the keys file {keys_file}: it is not valid UTF-8. "
                f"Nothing was changed."
            ) from None
        return cls(env_file, env_bytes, keys_file, keys_bytes, keys_text)

    def restore(self) -> None:
        """Put both files back exactly as they were (a created keys file goes).

        Each file is put back on its own, so one that cannot be put back does
        not keep the other from it: the keys file can hold the only copy of a
        key. An env file that cannot be put back may hold values dotenvx
        encrypted with a key it wrote to the keys file. That keys file is then
        saved to a gitignored backup before it is put back, or left as dotenvx
        wrote it when no backup can be made. No key is deleted either way.

        Raises:
            DotenvxError: A file could not be put back; the message says which.
        """
        failures: list[str] = []
        try:
            self._put_back_env_file()
        except OSError as exc:
            failures.append(f"{self.env_file} ({exc})")
        try:
            if failures:
                failures.extend(self._save_keys_dotenvx_wrote())
            self._put_back_keys_file()
        except OSError as exc:
            failures.append(f"{self.keys_file} is left as dotenvx wrote it ({exc})")
        if failures:
            raise DotenvxError(
                f"Could not put everything back after a failed encryption: {'; '.join(failures)}"
            )

    def _save_keys_dotenvx_wrote(self) -> list[str]:
        """Back up the keys file when dotenvx changed it, and say where it went."""
        if _read_bytes_or_none(self.keys_file) in (None, self.keys_bytes):
            return []
        from envdrift.sync.operations import EnvKeysFile

        backup = EnvKeysFile(self.keys_file).create_backup()
        return [
            f"the keys file dotenvx wrote, whose key {self.env_file.name} may now need, "
            f"is saved in {backup}"
        ]

    def _put_back_env_file(self) -> None:
        if _read_bytes_or_none(self.env_file) != self.env_bytes:
            _replace_file(self.env_file, self.env_bytes)

    def _put_back_keys_file(self) -> None:
        current_keys = _read_bytes_or_none(self.keys_file)
        if self.keys_bytes is None:
            if current_keys is not None:
                self.keys_file.unlink()
        elif current_keys != self.keys_bytes:
            _replace_file(self.keys_file, self.keys_bytes)


def _read_bytes_or_none(path: Path) -> bytes | None:
    """Return the bytes of ``path``, or ``None`` when it does not exist as a file."""
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None


class DotenvxInstaller:
    """Install dotenvx binary to the virtual environment."""

    def __init__(
        self,
        version: str = DOTENVX_VERSION,
        progress_callback: Callable[[str], None] | None = None,
    ):
        """Initialize installer.

        Args:
            version: dotenvx version to install
            progress_callback: Optional callback for progress updates
        """
        self.version = version
        self.progress = progress_callback or (lambda x: None)

    def get_download_url(self) -> str:
        """
        Determine the platform-specific download URL for the configured dotenvx version.

        Returns:
            download_url (str): The concrete URL for the current system and architecture with the target version substituted.

        Raises:
            DotenvxInstallError: If the current platform/architecture is not supported.
        """
        system, machine = get_platform_info()
        key = (system, machine)

        if key not in DOWNLOAD_URLS:
            raise DotenvxInstallError(
                f"Unsupported platform: {system} {machine}. "
                f"Supported: {', '.join(f'{s}/{m}' for s, m in DOWNLOAD_URLS)}"
            )

        # Replace version in URL
        url = DOWNLOAD_URLS[key]
        if "{version}" in url:
            return url.format(version=self.version)
        return url.replace(DOTENVX_VERSION, self.version)

    def get_checksums_url(self) -> str:
        """
        Return the URL of the upstream-published checksums file for this version.

        Returns:
            checksums_url (str): Concrete URL, or an empty string when no
                template is configured (verification then fails closed).
        """
        template = DOTENVX_CHECKSUMS_URL_TEMPLATE
        return template.format(version=self.version) if template else ""

    def download_and_extract(self, target_path: Path) -> None:
        """
        Download the packaged dotenvx release for the current platform and place the extracted binary at the given target path.

        The function creates the target directory if necessary, extracts the platform-specific archive, copies the included dotenvx binary to target_path (overwriting if present), and sets executable permissions on non-Windows systems.

        Parameters:
            target_path (Path): Destination path for the dotenvx executable.

        Raises:
            DotenvxInstallError: If the download, extraction, or locating/copying of the binary fails.
        """
        url = self.get_download_url()
        self.progress(f"Downloading dotenvx v{self.version}...")

        # Create temp directory
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            archive_name = url.split("/")[-1]
            archive_path = tmp_path / archive_name

            # Download with a per-request timeout so a server that accepts the
            # connection then stalls cannot hang install() forever. urlopen's
            # timeout is local to this request, unlike socket.setdefaulttimeout
            # which mutates process-global socket state.
            try:
                with urllib.request.urlopen(  # nosec B310
                    url, timeout=DOWNLOAD_TIMEOUT_SECONDS
                ) as response:
                    archive_path.write_bytes(response.read())
            except Exception as e:
                raise DotenvxInstallError(f"Download failed: {e}") from e

            # Verify against the published checksums before extracting anything,
            # so a tampered or unverifiable archive never installs (#490).
            self.progress("Verifying checksum...")
            try:
                verify_download(archive_path, archive_name, self.get_checksums_url(), "dotenvx")
            except ChecksumVerificationError as e:
                raise DotenvxInstallError(str(e)) from e

            self.progress("Extracting...")

            # Extract based on archive type
            if archive_name.endswith(".tar.gz"):
                self._extract_tar_gz(archive_path, tmp_path)
            elif archive_name.endswith(".zip"):
                self._extract_zip(archive_path, tmp_path)
            else:
                raise DotenvxInstallError(f"Unknown archive format: {archive_name}")

            # Find the binary
            binary_name = "dotenvx.exe" if platform.system() == "Windows" else "dotenvx"
            extracted_binary = None

            for f in tmp_path.rglob(binary_name):
                if f.is_file():
                    extracted_binary = f
                    break

            if not extracted_binary:
                raise DotenvxInstallError(f"Binary '{binary_name}' not found in archive")

            # Stage next to the target and atomically replace it, so an
            # interrupted copy (disk full, crash) can never corrupt a working
            # binary or leave a partial write behind (#490).
            try:
                atomic_install(extracted_binary, target_path)
            except OSError as e:
                raise DotenvxInstallError(f"Failed to install binary: {e}") from e

            self.progress(f"Installed to {target_path}")

    def _extract_tar_gz(self, archive_path: Path, target_dir: Path) -> None:
        """
        Extracts all files from a gzip-compressed tar archive into the given target directory.

        Parameters:
            archive_path (Path): Path to the .tar.gz archive to extract.
            target_dir (Path): Destination directory where the archive contents will be extracted.
        """
        import tarfile

        with tarfile.open(archive_path, "r:gz") as tar:
            # Filter to prevent path traversal attacks (CVE-2007-4559)
            for member in tar.getmembers():
                member_path = target_dir / member.name
                # Resolve to absolute and ensure it's within target_dir
                if not member_path.resolve().is_relative_to(target_dir.resolve()):
                    raise DotenvxInstallError(f"Unsafe path in archive: {member.name}")
            try:
                tar.extractall(target_dir, filter="data")  # nosec B202
            except TypeError:
                # Python <3.12 doesn't support the filter argument.
                tar.extractall(target_dir)  # nosec B202

    def _extract_zip(self, archive_path: Path, target_dir: Path) -> None:
        """
        Extract the contents of a ZIP archive into the given target directory.

        Parameters:
            archive_path (Path): Path to the ZIP archive to extract.
            target_dir (Path): Directory where archive contents will be extracted.
        """
        import zipfile

        with zipfile.ZipFile(archive_path, "r") as zip_ref:
            # Filter to prevent path traversal attacks
            for name in zip_ref.namelist():
                member_path = target_dir / name
                # Resolve to absolute and ensure it's within target_dir
                if not member_path.resolve().is_relative_to(target_dir.resolve()):
                    raise DotenvxInstallError(f"Unsafe path in archive: {name}")
            zip_ref.extractall(target_dir)  # nosec B202

    def install(self, force: bool = False) -> Path:
        """
        Install the pinned dotenvx binary into the virtual environment.

        If the target binary already exists and `force` is False, verifies the installed version and skips reinstallation when it matches the requested version; otherwise downloads and installs the requested version.

        Parameters:
            force (bool): Reinstall even if a binary already exists.

        Returns:
            Path: Path to the installed dotenvx binary.

        Raises:
            DotenvxInstallError: If installation fails.
        """
        target_path = get_dotenvx_path()

        if target_path.exists() and not force:
            # Verify version
            try:
                result = subprocess.run(  # nosec B603
                    [str(target_path), "--version"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=10,
                )
                if self.version in result.stdout:
                    self.progress(f"dotenvx v{self.version} already installed")
                    return target_path
            except Exception as e:  # nosec B110
                # Version check failed, will reinstall
                import logging

                logging.debug(f"Version check failed: {e}")

        self.download_and_extract(target_path)
        return target_path

    @staticmethod
    def ensure_installed(version: str = DOTENVX_VERSION) -> Path:
        """
        Ensure the dotenvx binary of the given version is installed into the virtual environment.

        Parameters:
            version (str): Target dotenvx version to install.

        Returns:
            Path: Path to the installed dotenvx binary
        """
        installer = DotenvxInstaller(version=version)
        return installer.install()


class DotenvxWrapper:
    """Wrapper around dotenvx CLI.

    This wrapper:
    - Optionally installs dotenvx if not found (auto_install defaults to False)
    - Uses the binary from .venv/bin/ (not system-wide)
    - Provides Python-friendly interface to dotenvx commands
    """

    def __init__(self, auto_install: bool = False, version: str = DOTENVX_VERSION):
        """
        Create a DotenvxWrapper that provides methods to run and manage the dotenvx CLI within a virtual environment.

        Parameters:
            auto_install (bool): If True, attempt to install dotenvx into the project's virtual environment when it cannot be found.
            version (str): Pinned dotenvx version to use for lookups and installations.
        """
        self.auto_install = auto_install
        self.version = version
        self._binary_path: Path | None = None

    def _find_binary(self) -> Path:
        """
        Locate and return the filesystem path to the dotenvx executable, caching the result.

        Searches the virtual environment, then the system PATH, and attempts to auto-install the binary when configured to do so.

        Returns:
            Path: Filesystem path to the found dotenvx executable.

        Raises:
            DotenvxNotFoundError: If the executable cannot be found and auto-installation is not enabled or fails.
        """
        if self._binary_path and self._binary_path.exists():
            return self._binary_path

        # Check in venv first
        try:
            venv_path = get_dotenvx_path()
            if venv_path.exists():
                self._binary_path = venv_path
                return venv_path
        except RuntimeError:
            pass

        # Check system PATH
        system_path = shutil.which("dotenvx")
        if system_path:
            self._binary_path = Path(system_path)
            return self._binary_path

        # Auto-install if enabled
        if self.auto_install:
            try:
                installer = DotenvxInstaller(version=self.version)
                self._binary_path = installer.install()
                return self._binary_path
            except DotenvxInstallError as e:
                raise DotenvxNotFoundError(f"dotenvx not found and auto-install failed: {e}") from e

        raise DotenvxNotFoundError("dotenvx not found.\n" + self.install_instructions())

    @property
    def binary_path(self) -> Path:
        """
        Resolve and return the path to the dotenvx executable.

        Returns:
            path (Path): The resolved filesystem path to the dotenvx binary.
        """
        return self._find_binary()

    def is_installed(self) -> bool:
        """
        Determine whether the dotenvx binary is available (will attempt installation when auto_install is enabled).

        Returns:
            `true` if the dotenvx binary was found or successfully installed, `false` otherwise.
        """
        try:
            self._find_binary()
            return True
        except DotenvxNotFoundError:
            return False

    def get_version(self) -> str:
        """
        Get the installed dotenvx CLI version.

        Returns:
            str: The version string reported by the dotenvx binary (trimmed).
        """
        result = self._run(["--version"])
        return result.stdout.strip()

    def _run(
        self,
        args: list[str],
        check: bool = True,
        capture_output: bool = True,
        env: dict[str, str] | None = None,
        cwd: Path | str | None = None,
    ) -> subprocess.CompletedProcess:
        """
        Execute the dotenvx CLI with the provided arguments.

        Parameters:
            args (list[str]): Arguments to pass to the dotenvx executable (excluding the binary path).
            check (bool): If True, raise DotenvxError when the process exits with a non-zero status.
            capture_output (bool): If True, capture stdout and stderr and include them on the returned CompletedProcess.
            env (dict[str, str] | None): Optional environment mapping to use for the subprocess; defaults to the current environment.
            cwd (Path | str | None): Optional working directory for the subprocess.

        Returns:
            subprocess.CompletedProcess: The finished process result, including returncode, stdout, and stderr.

        Raises:
            DotenvxError: If the command times out or (when `check` is True) exits with a non-zero status.
            DotenvxNotFoundError: If the dotenvx executable cannot be found.
        """
        binary = self._find_binary()
        cmd = [str(binary)] + args

        try:
            result = subprocess.run(  # nosec B603
                cmd,
                capture_output=capture_output,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
                env=env,
                cwd=str(cwd) if cwd else None,
            )

            if check and result.returncode != 0:
                stderr = (result.stderr or "").strip()
                if stderr:
                    stderr = strip_ansi(stderr).strip()
                    if not stderr:
                        stderr = "no error output"
                else:
                    stderr = "no error output"
                raise DotenvxError(f"dotenvx command failed (exit {result.returncode}): {stderr}")

            return result
        except subprocess.TimeoutExpired as e:
            raise DotenvxError("dotenvx command timed out") from e
        except FileNotFoundError as e:
            raise DotenvxNotFoundError(f"dotenvx binary not found: {e}") from e

    # Error patterns that indicate an encrypt/decrypt failure even when dotenvx
    # exits 0 (its historical false-success behavior). dotenvx renamed these
    # error codes across major versions and — for the decrypt path, which has no
    # plaintext post-check — the exit code alone is the only other signal, so the
    # net must cover both wordings:
    #   * v1: MISSING_PRIVATE_KEY / WRONG_PRIVATE_KEY / MISPAIRED_PRIVATE_KEY
    #     ("does not match the existing public key"); the mispaired encrypt exits 0.
    #   * v2: DECRYPTION_FAILED ("could not decrypt"), "second arg must be public
    #     key"; these now exit non-zero, but match them anyway for defense in depth.
    ENCRYPT_ERROR_PATTERNS: ClassVar[list[str]] = [
        "does not match the existing public key",
        "MISSING_DOTENV_KEY",
        "MISSING_PRIVATE_KEY",
        "WRONG_PRIVATE_KEY",
        "DECRYPTION_FAILED",
        "could not decrypt",
        "second arg must be public key",
        "private key not found",
        "decryption failed",
    ]

    @classmethod
    def _clean_output(cls, text: str) -> str:
        """Strip ANSI escape codes and normalize Unicode characters for clean output."""
        # Strip ANSI escape codes, cursor/erase sequences included (not just colors)
        text = strip_ansi(text)
        # Replace Unicode ellipsis with ASCII equivalent (avoids encoding issues on Windows)
        text = text.replace("…", "...")
        # Also handle the mojibake version (UTF-8 ellipsis decoded as Windows-1252)
        text = text.replace("â€¦", "...")
        return text

    @staticmethod
    def _normalize_line_endings(file_path: Path) -> bool:
        """
        Normalize line endings in a file to Unix-style (LF) for cross-platform compatibility.

        dotenvx has known issues on Windows when files contain CRLF line endings or
        certain characters that get misinterpreted. This method normalizes the file
        to use Unix line endings (LF) which works consistently across all platforms.

        Parameters:
            file_path (Path): Path to the file to normalize.

        Returns:
            bool: True if the file was modified, False if already normalized.
        """
        try:
            # Read as binary to detect actual line endings
            content = file_path.read_bytes()

            # Check if normalization is needed (contains CRLF)
            if b"\r\n" not in content and b"\r" not in content:
                return False  # Already normalized

            # Normalize: CRLF -> LF, then any remaining CR -> LF
            normalized = content.replace(b"\r\n", b"\n").replace(b"\r", b"\n")

            # Write back
            file_path.write_bytes(normalized)
            return True
        except OSError:
            # If normalization fails, proceed anyway - dotenvx might still work
            return False

    @staticmethod
    def _validate_encryptable_filename(file_path: Path) -> None:
        """Refuse a filename dotenvx would turn into an invalid private-key name.

        dotenvx derives ``DOTENV_PRIVATE_KEY_<SLUG>`` from the filename; a space or
        non-ASCII character yields an invalid name, so the value encrypts and
        dotenvx exits 0 — but the file is then permanently undecryptable and the
        original plaintext is destroyed (a silent secret lockout). This guard runs
        on every platform (the lockout is not Windows-specific) and before dotenvx
        is invoked, so the plaintext is preserved.

        The guarded ``DotenvxEncryptionBackend`` already performs this check, but
        the partial-encryption push/lock paths (``encrypt_secret_file`` /
        ``_encrypt_secrets_only_file``) reach dotenvx through this wrapper directly,
        so the guard must live here too or those paths silently lock the secret out
        (#443/#457, #467). Both share the ``is_dotenvx_safe_filename`` predicate.

        Parameters:
            file_path (Path): Path to the file to validate.

        Raises:
            DotenvxFilenameError: If the filename is not a safe dotenvx key slug.
        """
        if not is_dotenvx_safe_filename(file_path.name):
            raise DotenvxFilenameError(
                f"Refusing to encrypt '{file_path.name}': its filename contains "
                "characters dotenvx cannot turn into a valid key name, which would "
                "leave the file permanently undecryptable. Rename it to use only "
                "letters, digits, '.', '-' and '_'."
            )

    @staticmethod
    def _validate_not_key_store(file_path: Path) -> None:
        """Refuse to encrypt the dotenvx private-key store itself.

        ``encrypt -f .env.keys`` rewrites every ``DOTENV_PRIVATE_KEY*`` value as
        ciphertext under a brand-new keypair whose private half is never
        persisted: dotenvx exits 0, but every file encrypted with those keys is
        permanently locked out. The guarded backend and the bare CLI commands
        refuse companion files by name, but the partial-encryption push/lock
        paths reach dotenvx through this wrapper directly, so the guard must
        live here too (#474).

        Two checks, both case-insensitive-filesystem safe:

        - **Name**: casefolded ``.keys`` suffix, so ``.env.KEYS`` (the same
          file as ``.env.keys`` on macOS/Windows default filesystems) cannot
          slip past a case-sensitive comparison.
        - **Content**: a renamed or symlinked key store (``mv .env.keys
          prodkeys.env``) passes any name check, so refuse any file carrying a
          ``DOTENV_PRIVATE_KEY*=`` assignment. A legitimate encrypt target only
          ever carries ``DOTENV_PUBLIC_KEY*`` lines, so there are no false
          positives; an unreadable file is left for dotenvx itself to reject.

        Parameters:
            file_path (Path): Path to the file to validate.

        Raises:
            DotenvxFilenameError: If the file names or contains a private-key
                store.
        """
        if file_path.name.casefold().endswith(".keys"):
            raise DotenvxFilenameError(
                f"Refusing to encrypt '{file_path.name}': it is the dotenvx "
                "private-key store. Encrypting it would permanently lock out "
                "every file encrypted with its keys."
            )
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        if _PRIVATE_KEY_ASSIGNMENT_RE.search(content):
            raise DotenvxFilenameError(
                f"Refusing to encrypt '{file_path.name}': it contains "
                "DOTENV_PRIVATE_KEY entries, so it is the dotenvx private-key "
                "store (possibly renamed). Encrypting it would permanently "
                "lock out every file encrypted with its keys."
            )

    # A public-key header block as dotenvx writes it (prependPublicKey): the
    # four-line banner, the DOTENV_PUBLIC_KEY* line (with dotenvx's optional
    # " # -fk <path>" hint), a blank line and the "# <filename>" line.
    DOTENVX_HEADER_BLOCK_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"#/---+\[DOTENV_PUBLIC_KEY\]---+/\n"
        r"#/[^\n]+/\n"
        r"#/[^\n]+/\n"
        r"#/---+/\n"
        r'(DOTENV_PUBLIC_KEY[A-Za-z0-9_.-]*)="([^"\n]*)"[^\n]*\n'
        r"\n"
        r"# [^\n]*\n",
    )

    @classmethod
    def _clean_mismatched_header_text(
        cls, text: str, filename: str, environment: str | None = None
    ) -> str:
        """Drop another file's header block, but only next to this file's own one.

        dotenvx 1.x prepended a new header to a renamed file and kept the old
        one, so a file could carry two blocks. Removing the old block is safe
        only when the file's own block is there to replace it. A lone header
        under another name still holds the public key the file's values were
        encrypted with, and removing it made dotenvx create a new key next to
        the folder's key (#938), so it stays. A block is the file's own when its
        name is the one dotenvx derives from the filename or, for a mapped
        file, the canonical ``DOTENV_PUBLIC_KEY_<ENVIRONMENT>``.
        """
        own = {dotenvx_key_names(filename)[0]}
        if environment:
            own.add(f"DOTENV_PUBLIC_KEY_{environment.upper()}")
        blocks = cls._header_blocks(text)
        stale = [block for block in blocks if block.group(1) not in own]
        if not stale or len(stale) == len(blocks):
            return text
        if has_encrypted_values(text):
            stale = cls._redundant_blocks(blocks, stale, own)
        cleaned = text
        for block in reversed(stale):
            cleaned = cleaned[: block.start()] + cleaned[block.end() :]
        return cleaned.lstrip("\n")

    @classmethod
    def _header_blocks(cls, text: str) -> list[re.Match[str]]:
        """The header blocks in ``text`` that start a line outside every quoted value.

        A banner quoted inside a value is that value's text, so it is never a
        header that cleanup may remove.
        """
        in_values = value_continuation_lines(text)
        breaks = [index for index, char in enumerate(text) if char == "\n"]
        return [
            block
            for block in cls.DOTENVX_HEADER_BLOCK_PATTERN.finditer(text)
            if block.start() == 0 or text[block.start() - 1] == "\n"
            if bisect_left(breaks, block.start()) not in in_values
        ]

    @staticmethod
    def _redundant_blocks(
        blocks: list[re.Match[str]], stale: list[re.Match[str]], own: set[str]
    ) -> list[re.Match[str]]:
        """The stale blocks that carry the same public key as the file's own block.

        In a file that already holds ciphertext, a stale block with another
        public key may be the key its values were encrypted with. It stays, so
        the key check that follows sees both keys and refuses (#938), instead of
        the file losing the only sign that its values are another key's.
        """
        own_keys = {
            normalize_public_key(block.group(2)) for block in blocks if block.group(1) in own
        }
        return [block for block in stale if normalize_public_key(block.group(2)) in own_keys]

    @classmethod
    def _clean_mismatched_headers(cls, file_path: Path, environment: str | None = None) -> bool:
        """
        Remove another file's header blocks when this file's own header is present.

        See :meth:`_clean_mismatched_header_text`. The file is rewritten as
        bytes, so Windows newline translation cannot change its line endings.
        The header patterns read ``\n`` line ends, so a file with CRLF line ends
        is matched with ``\n`` ones and written back with CRLF.

        Parameters:
            file_path (Path): Path to the env file to clean.
            environment (str | None): The mapping environment, for a mapped file.

        Returns:
            bool: True if any headers were removed, False otherwise.
        """
        try:
            content = file_path.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            return False
        crlf = "\r\n" in content
        text = content.replace("\r\n", "\n") if crlf else content
        cleaned = cls._clean_mismatched_header_text(text, file_path.name, environment)
        if cleaned == text:
            return False
        if crlf:
            cleaned = cleaned.replace("\n", "\r\n")
        file_path.write_bytes(cleaned.encode("utf-8"))
        return True

    def _raise_on_error_output(self, result: subprocess.CompletedProcess, action: str) -> None:
        """Raise ``DotenvxError`` if a dotenvx run reported a failure.

        dotenvx sometimes prints an error (e.g. "decryption failed", a missing key)
        while still exiting 0, so both the combined output and the return code are
        inspected. ``action`` is the human-readable verb ("encryption"/"decryption")
        used in the error message.

        Parameters:
            result: The completed dotenvx subprocess.
            action: Verb describing the operation for the error message.

        Raises:
            DotenvxError: If an error pattern is present in the output or the
                command exited non-zero.
        """
        combined_output = (result.stdout or "") + (result.stderr or "")
        for pattern in self.ENCRYPT_ERROR_PATTERNS:
            if pattern.lower() in combined_output.lower():
                clean_output = _without_status_lines(self._clean_output(combined_output))
                raise DotenvxError(f"dotenvx {action} failed: {clean_output}")

        if result.returncode != 0:
            clean_stderr = _without_status_lines(self._clean_output(result.stderr or ""))
            raise DotenvxError(f"dotenvx command failed (exit {result.returncode}): {clean_stderr}")

    def encrypt(
        self,
        env_file: Path | str,
        env_keys_file: Path | str | None = None,
        env: dict[str, str] | None = None,
        cwd: Path | str | None = None,
        environment: str | None = None,
    ) -> None:
        """
        Encrypt the specified .env file in place, with the key the folder holds.

        Automatically normalizes line endings to Unix-style (LF) before encryption
        to ensure cross-platform compatibility with dotenvx.

        dotenvx 2.x creates a brand-new key whenever the file carries no public
        key, even when ``.env.keys`` already holds the file's key (#938). So
        before dotenvx runs, the key the keys file holds for this file is looked
        up (``DOTENV_PRIVATE_KEY_<ENVIRONMENT>`` for a mapped file, else the name
        dotenvx gives the filename) and the file's header is seeded with its
        public key; see :func:`~envdrift.integrations.dotenvx_keys.plan_key_reuse`.
        dotenvx is not trusted afterwards either: when a held key ends up
        replaced or joined by another value, a new key appears although one was
        held, or a failed run leaves anything behind, both files are put back
        byte for byte (as they were before line endings were normalized) and
        the call fails.

        Parameters:
            env_file (Path | str): Path to the .env file to encrypt.
            env_keys_file (Path | str | None): Optional path to the .env.keys file to use.
            env (dict[str, str] | None): Optional environment variables for the subprocess.
            cwd (Path | str | None): Optional working directory for the subprocess.
            environment (str | None): The mapping environment of a mapped file, whose
                key the folder holds as ``DOTENV_PRIVATE_KEY_<ENVIRONMENT>``.

        Raises:
            DotenvxFilenameError: If the filename is not compatible with dotenvx.
            DotenvxKeyError: If the keys file cannot tell which key to use, or
                dotenvx did not use it. Both files are left as they were.
            DotenvxValueError: If dotenvx would end an unquoted value at a ``#``
                and leave the rest of it in plaintext. Nothing is changed.
            DotenvxError: If a file cannot be read or the encryption command fails.
        """
        env_file = Path(env_file)
        if not env_file.exists():
            raise DotenvxError(f"File not found: {env_file}")

        # Refuse to encrypt the private-key store itself BEFORE invoking
        # dotenvx: it would rewrite the keys as ciphertext under a brand-new,
        # never-persisted keypair — an irreversible project-wide lockout (#474).
        self._validate_not_key_store(env_file)

        # Refuse a filename dotenvx can't turn into a valid key name BEFORE
        # invoking it, on every platform, so the plaintext is preserved. dotenvx
        # would otherwise encrypt the value, exit 0, and leave the file
        # permanently undecryptable. The partial-encryption push/lock paths use
        # this wrapper directly, not the guarded backend (#443/#457, #467).
        self._validate_encryptable_filename(env_file)

        # Pin -fk to the sibling .env.keys: dotenvx v2 otherwise writes the key
        # store into the process cwd (v1 kept it next to the file), scattering a
        # subfolder file's private key away from it (#566).
        keys_file = Path(_sibling_env_keys_file(env_file, env_keys_file))

        # Snapshot both files before anything changes, so every refusal or
        # failure below restores the exact original bytes (CRLF included).
        snapshot = _EncryptSnapshot.take(env_file, keys_file)
        plan = self._plan_encryption(env_file, keys_file, snapshot, environment)

        # Leading-dash paths must be ./-prefixed or dotenvx's commander CLI
        # misparses them as flags and fabricates a different file (#474).
        args = ["encrypt", "-f", _dash_safe_path(env_file)]
        args.extend(["-fk", _dash_safe_path(keys_file)])

        try:
            self._stage(env_file, plan.env_text.encode("utf-8"), snapshot)
            # Run with check=False to handle exit code 0 errors ourselves
            result = self._run(args, env=env, cwd=cwd, check=False)
            self._raise_on_error_output(result, "encryption")
            problem = self._key_outcome_problem(plan, snapshot)
        except BaseException:
            snapshot.restore()
            raise
        if problem is not None:
            snapshot.restore()
            raise DotenvxKeyError(
                f"Refusing to keep the encryption of {env_file}: {problem}. Both "
                f"{env_file.name} and {keys_file} were put back as they were."
            )

    @staticmethod
    def _stage(env_file: Path, staged: bytes, snapshot: _EncryptSnapshot) -> None:
        """Write the prepared text for dotenvx, failing cleanly when it cannot."""
        if staged == snapshot.env_bytes:
            return
        try:
            _replace_file(env_file, staged)
        except OSError as exc:
            raise DotenvxError(f"Cannot write {env_file}: {exc.strerror or exc}") from None

    def _plan_encryption(
        self,
        env_file: Path,
        keys_file: Path,
        snapshot: _EncryptSnapshot,
        environment: str | None,
    ) -> KeyReusePlan:
        """Prepare the text dotenvx will encrypt, refusing before anything is written.

        Line endings are normalized (CRLF/CR -> LF, so a file encrypted on
        Windows decrypts on Linux/macOS), another file's stale header is dropped
        when the file's own one is present, and the header is seeded or
        corrected for the held key.
        """
        try:
            env_text = snapshot.env_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise DotenvxError(
                f"Cannot encrypt {env_file}: it is not valid UTF-8, and dotenvx would "
                f"replace its undecodable bytes. Nothing was changed."
            ) from None
        env_text = env_text.replace("\r\n", "\n").replace("\r", "\n")
        cut = comment_cut_names(env_text)
        if cut:
            raise DotenvxValueError(
                f"Refusing to encrypt {env_file}: dotenvx ends an unquoted value at a `#` "
                "that touches it and keeps the rest as a plaintext comment, so it would "
                f"leave part of {', '.join(cut)} unencrypted. Put each of those values in "
                "quotes (for example KEY='a#b'), then encrypt again. Nothing was changed."
            )
        env_text = self._clean_mismatched_header_text(env_text, env_file.name, environment)
        if environment:
            key_name = f"DOTENV_PRIVATE_KEY_{environment.upper()}"
        else:
            key_name = dotenvx_key_names(env_file)[1]
        try:
            return plan_key_reuse(
                env_text, snapshot.keys_text, KeyTarget(env_file, keys_file, key_name)
            )
        except KeyReuseError as exc:
            raise DotenvxKeyError(f"{exc} Nothing was changed.") from None

    @staticmethod
    def _key_outcome_problem(plan: KeyReusePlan, snapshot: _EncryptSnapshot) -> str | None:
        """Re-read both files after dotenvx and describe any broken key promise."""
        env_after = _read_text_for_check(snapshot.env_file)
        keys_exist = snapshot.keys_file.exists()
        keys_after = _read_text_for_check(snapshot.keys_file) if keys_exist else None
        unreadable_keys = keys_exist and keys_after is None
        if env_after is None or unreadable_keys:
            return "the files could not be read back after dotenvx ran"
        return key_outcome_problem(plan, snapshot.keys_text, keys_after, env_after)

    def decrypt(
        self,
        env_file: Path | str,
        env_keys_file: Path | str | None = None,
        env: dict[str, str] | None = None,
        cwd: Path | str | None = None,
    ) -> None:
        """
        Decrypt the specified dotenv file in place.

        Automatically normalizes line endings to Unix-style (LF) before decryption
        to ensure cross-platform compatibility with dotenvx.

        Parameters:
            env_file (Path | str): Path to the .env file to decrypt.
            env_keys_file (Path | str | None): Optional path to a .env.keys file to use for decryption.
            env (dict[str, str] | None): Optional environment variables to supply to the subprocess.
            cwd (Path | str | None): Optional working directory for the subprocess.

        Raises:
            DotenvxError: If env_file does not exist or the decryption command fails.
            DotenvxNotFoundError: If the dotenvx binary cannot be located when running the command.
        """
        env_file = Path(env_file)
        if not env_file.exists():
            raise DotenvxError(f"File not found: {env_file}")

        # Normalize CRLF -> LF for cross-platform consistency (see encrypt()).
        self._normalize_line_endings(env_file)

        # Pin -fk to the sibling .env.keys: dotenvx v2 otherwise looks for the
        # key store in the process cwd (v1 read it next to the file), so a
        # subfolder file would fail to decrypt (#566).
        env_keys_file = _sibling_env_keys_file(env_file, env_keys_file)

        # Leading-dash paths must be ./-prefixed or dotenvx's commander CLI
        # misparses them as flags (#474).
        args = ["decrypt", "-f", _dash_safe_path(env_file)]
        args.extend(["-fk", _dash_safe_path(env_keys_file)])

        # Run with check=False so we can detect the case where dotenvx prints a
        # decrypt error (e.g. "decryption failed", "private key not found",
        # "MISSING_DOTENV_KEY") while still exiting 0. Without this post-check a
        # 0-exit-with-error-output would be reported as a successful decrypt.
        result = self._run(args, env=env, cwd=cwd, check=False)
        self._raise_on_error_output(result, "decryption")

    def run(self, env_file: Path | str, command: list[str]) -> subprocess.CompletedProcess:
        """
        Run the given command with environment variables loaded from the specified env file.

        The command is executed via the installed dotenvx CLI and will not raise on non-zero exit; inspect the returned CompletedProcess to determine success.

        Parameters:
            env_file (Path | str): Path to the dotenv file whose variables should be loaded.
            command (list[str]): The command and its arguments to execute (e.g. ["python", "script.py"]).

        Returns:
            subprocess.CompletedProcess: The completed process result containing return code, stdout, and stderr.
        """
        env_file = Path(env_file)
        return self._run(["run", "-f", _dash_safe_path(env_file), "--"] + command, check=False)

    def get(self, env_file: Path | str, key: str) -> str | None:
        """
        Retrieve the value for `key` from the given env file.

        Parameters:
            env_file (Path | str): Path to the env file to read.
            key (str): Name of the variable to retrieve.

        Returns:
            str | None: Trimmed value of the variable if present, `None` if the key is not present or the command fails.
        """
        env_file = Path(env_file)
        result = self._run(["get", "-f", _dash_safe_path(env_file), key], check=False)

        if result.returncode != 0:
            return None

        return result.stdout.strip()

    def set(self, env_file: Path | str, key: str, value: str) -> None:
        """
        Set a key to the given value in the specified dotenv file.

        Parameters:
            env_file (Path | str): Path to the .env file to modify.
            key (str): The environment variable name to set.
            value (str): The value to assign to `key`.
        """
        env_file = Path(env_file)
        self._run(["set", "-f", _dash_safe_path(env_file), key, value])

    @staticmethod
    def install_instructions() -> str:
        """
        Provide multi-option installation instructions for obtaining the dotenvx CLI.

        Returns:
            str: Multi-line installation instructions containing installation options
                 for different scenarios. The pinned version is interpolated into
                 the instructions.
        """
        return f"""
dotenvx is not installed.

Option 1 - Install to ~/.local/bin (recommended):
  curl -sfS "https://dotenvx.sh?directory=$HOME/.local/bin" | sh -s -- --version={DOTENVX_VERSION}
  (Make sure ~/.local/bin is in your PATH)

Option 2 - Install to current directory:
  curl -sfS "https://dotenvx.sh?directory=." | sh -s -- --version={DOTENVX_VERSION}

Option 3 - System-wide install (requires sudo):
  curl -sfS https://dotenvx.sh | sudo sh -s -- --version={DOTENVX_VERSION}

After installing, run your envdrift command again.
"""
