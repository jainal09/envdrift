"""Test helpers shared across unit tests."""

from __future__ import annotations

import contextlib
import os
import re
import stat
import sys
import tomllib
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from envdrift.encryption.base import EncryptionResult

REPO_ROOT = Path(__file__).resolve().parents[1]

_REQUIREMENT_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_FLOOR_RE = re.compile(r">=\s*([0-9]+(?:\.[0-9]+)*)")


def _canonical_name(name: str) -> str:
    """PEP 503 normalization: hyphens, underscores, and dots are equivalent."""
    return re.sub(r"[-_.]+", "-", name).lower()


def declared_dependency_floor(package: str) -> str:
    """Return the ``>=`` floor declared for *package* in ``pyproject.toml``.

    Reads ``[project] dependencies`` dynamically so tests never hardcode a
    version that Renovate (or a maintainer) later bumps. Raises ``AssertionError``
    if the package is missing or declares no lower bound — a silent absence
    would let a broken floor regress unnoticed (see issue #496).
    """
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    for requirement in pyproject["project"]["dependencies"]:
        name_match = _REQUIREMENT_NAME_RE.match(requirement)
        if name_match is None or _canonical_name(name_match.group(1)) != _canonical_name(package):
            continue
        floor_match = _FLOOR_RE.search(requirement)
        assert floor_match is not None, (
            f"dependency {requirement!r} declares no '>=' floor in pyproject.toml"
        )
        return floor_match.group(1)
    raise AssertionError(f"{package!r} not found in [project] dependencies of pyproject.toml")


def version_tuple(version: str) -> tuple[int, ...]:
    """Parse a release version string like ``0.13`` into an int tuple."""
    return tuple(int(part) for part in version.split("."))


# secp256k1 key pairs minted by the real dotenvx binary (``dotenvx encrypt`` of a
# scratch ``.env``): the DOTENV_PRIVATE_KEY it saved and the DOTENV_PUBLIC_KEY it
# wrote into the file. Split in halves so no whole key literal is in the source
# (push protection). Tests derive public keys with envdrift's own arithmetic and
# check it against these dotenvx-made pairs.
DOTENVX_KEY_PAIRS: tuple[tuple[str, str], ...] = (
    (
        "8d035dcb76ef61ce6421cca90802489d" + "341d19fa58ec886f781f68f61ac6f374",
        "03e0f88dd23b3a2444ddcb00e5427bcf3" + "9677e45c4ecf3454979812b89c2326819",
    ),
    (
        "32a511ac477afab9f2f7e20a58f2375d" + "2069d38a58208f7d81ce31124665609f",
        "024419652e149b752e5c9b0d89e68a1e3" + "c1dd93772fd12d592d9c7a55395cec521",
    ),
    (
        "bb0a4f70aebc97170fa607766207577a" + "acbc1e97f1fa16ac5448a5331f074557",
        "03113cdc847cd8e1464e4b0f035d7a5b1" + "f0004d997f9f13ce4bf4b2463d0dfaf7c",
    ),
    (
        "908c71d57aea0f21553dd1b680212f94" + "5acafd9cdaf4d76fcbc026e4200cb2b8",
        "028433c0817ba0277b4a2acd80a20df3e" + "0bac8075c82c81e9e4b200c122b4e3b69",
    ),
)


class DummyEncryptionBackend:
    """Minimal encryption backend for unit tests."""

    def __init__(
        self,
        *,
        name: str = "dotenvx",
        installed: bool = True,
        encrypt_side_effect: Exception | None = None,
        decrypt_side_effect: Exception | None = None,
        has_encrypted_header: Callable[[str], bool] | None = None,
    ) -> None:
        self._name = name
        self._installed = installed
        self._encrypt_side_effect = encrypt_side_effect
        self._decrypt_side_effect = decrypt_side_effect
        self._has_encrypted_header = has_encrypted_header
        self.encrypt_calls: list[Path] = []
        self.decrypt_calls: list[Path] = []
        self.encrypt_kwargs: list[dict[str, object]] = []
        self.decrypt_kwargs: list[dict[str, object]] = []

    @property
    def name(self) -> str:
        return self._name

    def is_installed(self) -> bool:
        return self._installed

    def install_instructions(self) -> str:
        return f"install {self._name}"

    def has_encrypted_header(self, content: str) -> bool:
        if self._has_encrypted_header is not None:
            return self._has_encrypted_header(content)
        return (
            "#/---BEGIN DOTENV ENCRYPTED---/" in content
            or "DOTENV_PUBLIC_KEY" in content
            or "ENC[AES256_GCM," in content
            or "sops:" in content
        )

    def encrypt(self, env_file: Path | str, **kwargs) -> EncryptionResult:
        if self._encrypt_side_effect is not None:
            raise self._encrypt_side_effect
        path = Path(env_file)
        self.encrypt_calls.append(path)
        self.encrypt_kwargs.append(kwargs)
        return EncryptionResult(success=True, message="ok", file_path=path)

    def decrypt(self, env_file: Path | str, **kwargs) -> EncryptionResult:
        if self._decrypt_side_effect is not None:
            raise self._decrypt_side_effect
        path = Path(env_file)
        self.decrypt_calls.append(path)
        self.decrypt_kwargs.append(kwargs)
        return EncryptionResult(success=True, message="ok", file_path=path)

    def reset_tracking(self) -> None:
        """Clear recorded encrypt/decrypt calls and kwargs."""
        self.encrypt_calls.clear()
        self.decrypt_calls.clear()
        self.encrypt_kwargs.clear()
        self.decrypt_kwargs.clear()


def write_checksums_for(
    artifact: Path, checksums_path: Path, artifact_name: str | None = None
) -> str:
    """Write a sha256sum-style checksums file for ``artifact``; return a file:// URL.

    Installer tests point ``get_checksums_url`` at the returned URL so the
    fail-closed download verification (#490) succeeds against locally created
    fixture archives/binaries.
    """
    import hashlib

    name = artifact_name or artifact.name
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    checksums_path.write_text(f"{digest}  {name}\n", encoding="utf-8")
    return checksums_path.resolve().as_uri()


@contextlib.contextmanager
def unreadable_file(path: Path) -> Iterator[None]:
    """Make the file ``path`` really unreadable to this process while the block runs.

    ``chmod 000`` is enough for a normal user. root reads any file whatever its mode,
    so as root the block runs with the effective uid of ``nobody``, and ``path`` must
    be in a directory ``nobody`` can search (the ``searchable_tmp_path`` fixture).
    Skips where neither works: on Windows, which has no such mode bits, or as root
    without a ``nobody`` account.
    """
    if sys.platform == "win32":
        pytest.skip("Windows has no POSIX mode bits to make a file unreadable")
    mode = stat.S_IMODE(path.stat().st_mode)
    path.chmod(0)
    try:
        with _as_nobody_if_root():
            path.stat()  # still reachable: only reading it is refused
            try:
                path.open("rb").close()
            except PermissionError:
                pass
            else:
                pytest.skip("this process reads a chmod 000 file (CAP_DAC_OVERRIDE?)")
            yield
    finally:
        path.chmod(mode)


@contextlib.contextmanager
def _as_nobody_if_root() -> Iterator[None]:
    """Run the block with the effective uid of ``nobody`` when this process is root."""
    if sys.platform == "win32" or os.geteuid() != 0:
        yield
        return
    import pwd

    try:
        nobody = pwd.getpwnam("nobody").pw_uid
    except KeyError:
        pytest.skip("running as root, with no 'nobody' account to drop privileges to")
    os.seteuid(nobody)
    try:
        yield
    finally:
        os.seteuid(0)
