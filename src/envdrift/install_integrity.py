"""Fail-closed SHA256 verification for downloaded binaries (#490).

Every code path that downloads an executable (scanner auto-install, the
dotenvx/sops integrations, ``envdrift install agent``) verifies the artifact
against the upstream-published checksums file BEFORE the binary reaches its
final install path. Verification fails closed: a missing, unreachable, or
mismatched checksum aborts the install.

The only escape hatch is explicit: the ``ENVDRIFT_INSECURE_SKIP_CHECKSUM``
environment variable (or ``envdrift install agent --insecure-skip-checksum``),
mirroring ``install.sh --insecure-skip-checksum``.
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
import urllib.request
from pathlib import Path

#: Environment variable that disables checksum verification (unsafe).
#: Shared with install.ps1, which uses the same name.
INSECURE_SKIP_ENV = "ENVDRIFT_INSECURE_SKIP_CHECKSUM"

#: Timeout (seconds) for fetching the checksums file.
FETCH_TIMEOUT_SECONDS = 30.0

_SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class ChecksumVerificationError(Exception):
    """A downloaded artifact could not be verified against published checksums."""


def verification_disabled() -> bool:
    """Return True when the explicit insecure escape hatch is enabled."""
    return os.environ.get(INSECURE_SKIP_ENV, "").strip().lower() in {"1", "true", "yes"}


def sha256_file(path: Path) -> str:
    """Compute the SHA256 hex digest of a file."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_checksums(content: str) -> dict[str, str]:
    """Parse ``sha256sum``-style checksum lines into ``{filename: digest}``.

    Accepts the formats published by GitHub release pipelines: ``digest  name``,
    binary-mode markers (``digest *name``), and path-prefixed names
    (``digest  ./dir/name``). Lines without a 64-char hex digest are ignored.
    """
    checksums: dict[str, str] = {}
    for line in content.splitlines():
        # Split digest from name on the first whitespace run only, so
        # filenames containing spaces keep their full name intact.
        parts = line.strip().split(None, 1)
        if len(parts) != 2:
            continue
        digest, name = parts[0], parts[1].strip()
        if not _SHA256_HEX_RE.match(digest):
            continue
        # Strip sha256sum binary-mode marker and any path prefix.
        name = name.lstrip("*").replace("\\", "/").rsplit("/", 1)[-1]
        checksums[name] = digest.lower()
    return checksums


def fetch_checksums(url: str, timeout: float = FETCH_TIMEOUT_SECONDS) -> dict[str, str]:
    """Download and parse a checksums file; fail closed on any error."""
    if not url:
        raise ChecksumVerificationError(
            "no checksums URL configured — refusing to install an unverified binary "
            f"(set {INSECURE_SKIP_ENV}=1 to override at your own risk)"
        )
    try:
        # URL comes from the Renovate-managed constants.json (https templates).
        with urllib.request.urlopen(url, timeout=timeout) as response:  # nosec B310
            content = response.read().decode("utf-8")
    except Exception as exc:
        raise ChecksumVerificationError(
            f"could not fetch checksums from {url}: {exc} — refusing to install "
            f"an unverified binary (set {INSECURE_SKIP_ENV}=1 to override at your own risk)"
        ) from exc
    return parse_checksums(content)


def verify_download(
    file_path: Path,
    artifact_name: str,
    checksums_url: str,
    tool_name: str,
) -> None:
    """Verify ``file_path`` against the published checksum for ``artifact_name``.

    Raises:
        ChecksumVerificationError: when the checksums file is unconfigured,
            unreachable, lacks an entry for ``artifact_name``, or the SHA256
            digest does not match. Callers must abort the install (fail closed)
            and leave any previously installed binary untouched.
    """
    if verification_disabled():
        # The bypass must be loud: stderr keeps machine-readable stdout clean.
        print(
            f"WARNING: {INSECURE_SKIP_ENV} is set — skipping checksum verification "
            f"for {tool_name}; installing an UNVERIFIED binary",
            file=sys.stderr,
        )
        return
    checksums = fetch_checksums(checksums_url)
    expected = checksums.get(artifact_name)
    if expected is None:
        raise ChecksumVerificationError(
            f"no checksum entry for {artifact_name} in {checksums_url} — refusing to "
            f"install an unverified {tool_name} binary "
            f"(set {INSECURE_SKIP_ENV}=1 to override at your own risk)"
        )
    actual = sha256_file(file_path)
    if actual != expected:
        raise ChecksumVerificationError(
            f"checksum mismatch for {artifact_name}: expected {expected}, got {actual} — "
            f"the downloaded {tool_name} binary was NOT installed"
        )
