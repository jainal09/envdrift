"""Helpers for resolving encryption backends from config."""

from __future__ import annotations

import contextlib
import logging
import os
import re
import tempfile
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING

from envdrift.config import ConfigNotFoundError, find_config, load_config
from envdrift.encryption import EncryptionProvider, get_encryption_backend
from envdrift.utils.git import get_file_from_git, is_file_tracked, restore_file_from_git

if TYPE_CHECKING:
    from envdrift.config import EncryptionConfig
    from envdrift.encryption.base import EncryptionBackend

logger = logging.getLogger(__name__)


def _resolve_relative(path_str: str, base_dir: Path | None) -> str:
    """Resolve a possibly-relative path against ``base_dir`` (the config dir).

    Absolute paths and ``~`` are returned expanded but otherwise unchanged. A
    relative path is joined onto ``base_dir`` when known, so it resolves against
    the envdrift config file's directory rather than the process cwd.
    """
    candidate = Path(path_str).expanduser()
    if candidate.is_absolute() or base_dir is None:
        return str(candidate)
    return str((base_dir / candidate).resolve())


def resolve_encryption_backend(
    config_file: Path | None,
) -> tuple[EncryptionBackend, EncryptionProvider, EncryptionConfig | None]:
    """
    Resolve the encryption backend using an explicit config file or auto-discovery.

    Returns the instantiated backend, selected provider, and the encryption config
    (if available).
    """
    config_path = None
    if config_file is not None and config_file.suffix.lower() == ".toml":
        config_path = config_file
    elif config_file is None:
        config_path = find_config()

    envdrift_config = None
    if config_path:
        try:
            envdrift_config = load_config(config_path)
        except (ConfigNotFoundError, tomllib.TOMLDecodeError) as exc:
            logger.warning("Failed to load config from %s: %s", config_path, exc)
            envdrift_config = None

    encryption_config = getattr(envdrift_config, "encryption", None) if envdrift_config else None
    backend_name = encryption_config.backend if encryption_config else "dotenvx"
    provider = EncryptionProvider(backend_name)

    backend_config: dict[str, object] = {}
    if provider == EncryptionProvider.DOTENVX:
        backend_config["auto_install"] = (
            encryption_config.dotenvx_auto_install if encryption_config else False
        )
    else:
        backend_config["auto_install"] = (
            encryption_config.sops_auto_install if encryption_config else False
        )
        if encryption_config:
            # Relative sops_config_file / age_key_file are meant to be relative to
            # the envdrift config file's directory, not the process cwd. Resolve
            # them here so running from another cwd still finds the intended
            # .sops.yaml / age key (#348a). Absolute paths are passed through.
            config_dir = config_path.parent if config_path else None
            if encryption_config.sops_config_file:
                backend_config["config_file"] = _resolve_relative(
                    encryption_config.sops_config_file, config_dir
                )
            if encryption_config.sops_age_key_file:
                backend_config["age_key_file"] = _resolve_relative(
                    encryption_config.sops_age_key_file, config_dir
                )

    backend = get_encryption_backend(provider, **backend_config)
    return backend, provider, encryption_config


def build_sops_encrypt_kwargs(encryption_config: EncryptionConfig | None) -> dict[str, str]:
    """Build SOPS encryption kwargs from config."""
    if not encryption_config:
        return {}

    kwargs: dict[str, str] = {}
    if encryption_config.sops_age_recipients:
        kwargs["age_recipients"] = encryption_config.sops_age_recipients
    if encryption_config.sops_kms_arn:
        kwargs["kms_arn"] = encryption_config.sops_kms_arn
    if encryption_config.sops_gcp_kms:
        kwargs["gcp_kms"] = encryption_config.sops_gcp_kms
    if encryption_config.sops_azure_kv:
        kwargs["azure_kv"] = encryption_config.sops_azure_kv
    return kwargs


def is_encrypted_content(
    provider: EncryptionProvider,
    backend: EncryptionBackend,
    content: str,
) -> bool:
    """Determine if file content is encrypted for the selected backend."""
    # For DOTENVX, having a public key header doesn't mean values are encrypted.
    # We need to check for actual "KEY=encrypted:" values in the content.
    # Use regex to match the DOTENVX encrypted value pattern to avoid false
    # positives from comments or other text containing "encrypted:".
    if provider == EncryptionProvider.DOTENVX:
        return bool(re.search(r"=\s*encrypted:", content, re.IGNORECASE))
    # For SOPS the canonical metadata block (not the looser has_encrypted_header
    # substring scan) is the signal: a bare ENC[AES256_GCM, token in a plaintext
    # value or comment must not count (#475), and a file without the block is
    # not decryptable by sops anyway. Surviving-plaintext (mixed-state) handling
    # is deliberately NOT folded in here: the lock flow reports mixed files
    # precisely via has_plaintext_secret_value ("plaintext values remain", #470)
    # and the backend's encrypt() refuses to bless them (#475) — folding it in
    # would reroute mixed files to the generic "not encrypted" path and lose
    # that precision.
    return _has_backend_ciphertext_marker(backend, content)


def _has_backend_ciphertext_marker(backend: EncryptionBackend, content: str) -> bool:
    """Does ``content`` carry the backend's canonical encryption marker?

    Prefers the backend's genuine metadata-block signal (``has_metadata_block``,
    SOPS) over the looser ``has_encrypted_header`` substring scan: a plaintext
    file that merely mentions ``ENC[AES256_GCM,`` in a value or comment carries
    no SOPS metadata, so it is neither encrypted nor decryptable and must not be
    treated as either. Backends without the method keep the header check.
    """
    has_metadata_block = getattr(backend, "has_metadata_block", None)
    if callable(has_metadata_block):
        return bool(has_metadata_block(content))
    return bool(backend.has_encrypted_header(content))


def should_attempt_decryption(
    provider: EncryptionProvider,
    backend: EncryptionBackend,
    content: str,
) -> bool:
    """Decrypt-direction predicate: does ``content`` carry this backend's ciphertext?

    Deliberately more lenient than :func:`is_encrypted_content`, which asserts a
    fully encrypted post-state (#475). In the decrypt direction a mixed SOPS file
    (metadata block + surviving plaintext value) must still be handed to sops so
    the outcome is loud — sops refuses it (MAC mismatch) unless the file's own
    ``sops_mac_only_encrypted`` metadata makes the mix legitimate — instead of
    ``pull`` silently skipping it as "not encrypted" (and even activating it as
    the working profile) while its values are still ciphertext.

    Gated on the canonical metadata block (when the backend exposes it): a file
    without the block is not decryptable by sops at all — including a plaintext
    file that merely mentions ``ENC[AES256_GCM,`` in a value — so it stays a
    clean "not encrypted" skip rather than an avoidable decrypt failure.
    """
    if provider == EncryptionProvider.DOTENVX:
        return bool(re.search(r"=\s*encrypted:", content, re.IGNORECASE))
    return _has_backend_ciphertext_marker(backend, content)


def should_skip_reencryption(
    env_file: Path,
    backend: EncryptionBackend,
    *,
    enabled: bool = False,
) -> tuple[bool, str]:
    """
    Determine if re-encryption should be skipped because content is unchanged.

    This function addresses the issue where dotenvx uses non-deterministic encryption
    (ECIES with ephemeral keys), causing the encrypted output to change even when
    the plaintext is unchanged. This creates unnecessary git noise.

    The solution:
    1. Check if the file is tracked in git
    2. Get the encrypted version from git (HEAD)
    3. Decrypt the git version to a temp file
    4. Compare the decrypted content with the current file content
    5. If identical, restore the original encrypted version from git

    Parameters:
        env_file: Path to the currently decrypted .env file.
        backend: The encryption backend (must support decrypt).
        enabled: Whether smart encryption is enabled (opt-in feature).
                 When False, always returns (False, "smart encryption disabled").

    Returns:
        A tuple of (should_skip, reason):
        - should_skip: True if re-encryption should be skipped
        - reason: Human-readable explanation of the decision
    """
    # Check if feature is enabled (opt-in)
    if not enabled:
        return False, "smart encryption disabled"

    # Only supported for dotenvx and sops backends currently
    if backend.name.lower() not in ("dotenvx", "sops"):
        return False, "smart encryption not supported for this backend"

    # Check if file is tracked in git
    if not is_file_tracked(env_file):
        return False, "file is not tracked in git"

    # Get the encrypted version from git
    git_content = get_file_from_git(env_file)
    if git_content is None:
        return False, "could not retrieve file from git"

    # Check if git version is encrypted
    if backend.name.lower() == "dotenvx":
        if "encrypted:" not in git_content.lower():
            return False, "git version is not encrypted"
    elif not backend.has_encrypted_header(git_content):
        return False, "git version is not encrypted"

    # Decrypt the git version to compare. Use a unique temp file in the SAME
    # directory as env_file so backend decrypt (which may rename a sibling) and
    # the comparison keep their same-dir semantics, while never clobbering a real
    # project file at a predictable path (#348b). mkstemp creates the file
    # atomically and we only ever unlink the file we created.
    fd, tmp_name = tempfile.mkstemp(
        dir=str(env_file.parent),
        prefix=f".{env_file.name}.",
        suffix=".envdrift-tmp",
    )
    temp_path = Path(tmp_name)
    try:
        try:
            # newline="" so text-mode writing does NOT translate "\n" to "\r\n"
            # on Windows: that would corrupt the encrypted bytes and make the
            # decrypt below fail, so smart encryption would needlessly re-encrypt
            # (a new IV/MAC) instead of restoring the identical git version.
            with os.fdopen(fd, "w", newline="") as tmp_fh:
                tmp_fh.write(git_content)

            # Try to decrypt the git version
            result = backend.decrypt(temp_path)
            if not result.success:
                return False, f"could not decrypt git version: {result.message}"

            # Read the decrypted content from git
            git_decrypted = temp_path.read_text()
        finally:
            # Cleanup only the temp file we created.
            with contextlib.suppress(OSError):
                temp_path.unlink()

        # Read current file content
        current_content = env_file.read_text()

        # Normalize line endings for comparison
        git_decrypted_normalized = git_decrypted.replace("\r\n", "\n").strip()
        current_normalized = current_content.replace("\r\n", "\n").strip()

        # Compare contents
        if git_decrypted_normalized == current_normalized:
            # Content unchanged! Restore the original encrypted version
            if restore_file_from_git(env_file):
                return True, "content unchanged, restored encrypted version from git"
            else:
                return False, "content unchanged but failed to restore from git"
        else:
            return False, "content has changed, re-encryption required"

    except Exception as e:
        logger.debug("Error during smart encryption comparison: %s", e)
        return False, f"error comparing content: {e}"
