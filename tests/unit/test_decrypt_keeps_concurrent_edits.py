"""A change another writer saves while a decrypt runs is kept (#946).

envdrift has dotenvx decrypt a copy of the file, and writes the file last, whole or not at
all, so a decrypt that fails, or finds the file changed, has written nothing. The snapshot
that the dotenvx backend and pull-partial take before the decrypt (``DecryptSnapshot``) was
put back on any failure all the same, over the other writer's change. Here an editor saves
the file while the stand-in dotenvx runs, or while the copy for it is made; the snapshot, the
wrapper and its write run for real. The real binary decrypts in
tests/integration/test_decrypt_keeps_values_e2e.py.
"""

from __future__ import annotations

import errno
import subprocess
import tempfile
from pathlib import Path

import pytest

from envdrift.core.partial_encryption import (
    DecryptSnapshot,
    PartialEncryptionError,
    _decrypt_in_place,
)
from envdrift.encryption.base import EncryptionBackendError
from envdrift.encryption.dotenvx import DotenvxEncryptionBackend
from envdrift.integrations.dotenvx import (
    DotenvxFileChangedError,
    DotenvxNotFoundError,
    DotenvxWrapper,
)

# A dotenvx-encrypted file, with CRLF line endings so that any rewrite of it would show.
_ENCRYPTED = (
    b'DOTENV_PUBLIC_KEY_PRODUCTION="03abc"\r\n'
    b"JWT_SECRET=encrypted:BAAA\r\n"
    b"STRIPE_API_KEY=encrypted:BFOREIGN\r\n"
)
# What the editor saves into the file meanwhile.
_EDIT = b"ADDED_BY_HAND=yes\r\n"
# How the decrypt ends after the save: dotenvx prints the values and the wrapper finds the
# file changed, dotenvx fails on a value under another key, the copy cannot be made, or
# dotenvx has gone missing since the caller checked for it.
_ENDINGS = ["file-changed", "dotenvx-failed", "copy-failed", "dotenvx-gone"]


def _save_edit(target: Path) -> None:
    with target.open("ab") as handle:
        handle.write(_EDIT)


def _wrapper(
    target: Path, ending: str, monkeypatch: pytest.MonkeyPatch, *, edit: bool = True
) -> DotenvxWrapper:
    """A wrapper that decrypts ``target`` while an editor saves it, and ends as ``ending`` says.

    Nothing is decrypted: the stand-in dotenvx prints the copy as it is, which does not
    matter, since envdrift must write nothing either way.
    """
    wrapper = DotenvxWrapper(auto_install=False)
    wrapper.is_installed = lambda: True  # type: ignore[method-assign]

    def _run_raw(args, env=None, cwd=None) -> subprocess.CompletedProcess[bytes]:
        if edit:
            _save_edit(target)
        if ending == "dotenvx-gone":  # what _run_raw raises when the binary is not there
            raise DotenvxNotFoundError("dotenvx binary not found: [Errno 2] No such file")
        if ending == "dotenvx-failed":
            stderr = b"[DECRYPTION_FAILED] could not decrypt STRIPE_API_KEY"
            return subprocess.CompletedProcess(args, 1, b"", stderr)
        copy = Path(args[args.index("-f") + 1]).read_bytes()
        return subprocess.CompletedProcess(args, 0, copy, b"")

    def _no_room(*_args: object, **_kwargs: object) -> None:
        if edit:
            _save_edit(target)
        raise OSError(errno.ENOSPC, "No space left on device")

    wrapper._run_raw = _run_raw  # type: ignore[method-assign]
    if ending == "copy-failed":
        monkeypatch.setattr(tempfile, "TemporaryDirectory", _no_room)
    return wrapper


def test_the_snapshot_keeps_a_file_envdrift_did_not_write(tmp_path: Path) -> None:
    target = tmp_path / ".env.production"
    target.write_bytes(_ENCRYPTED)

    with pytest.raises(DotenvxFileChangedError):
        with DecryptSnapshot(target) as snapshot:
            _save_edit(target)
            raise DotenvxFileChangedError("changed while it was being decrypted")

    assert target.read_bytes() == _ENCRYPTED + _EDIT
    assert "changed while it was being decrypted, and keeps that change" in snapshot.note


@pytest.mark.parametrize("ending", _ENDINGS)
def test_decrypt_keeps_the_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ending: str
) -> None:
    target = tmp_path / ".env.production"
    target.write_bytes(_ENCRYPTED)
    backend = DotenvxEncryptionBackend()
    backend._wrapper = _wrapper(target, ending, monkeypatch)

    with pytest.raises(EncryptionBackendError) as excinfo:
        backend.decrypt(target)

    assert target.read_bytes() == _ENCRYPTED + _EDIT
    assert "keeps that change" in " ".join(str(excinfo.value).split())


@pytest.mark.parametrize("ending", _ENDINGS)
def test_pull_partial_keeps_the_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ending: str
) -> None:
    target = tmp_path / ".env.production.secret"
    target.write_bytes(_ENCRYPTED)

    with pytest.raises(PartialEncryptionError) as excinfo:
        _decrypt_in_place(_wrapper(target, ending, monkeypatch), target)

    assert target.read_bytes() == _ENCRYPTED + _EDIT
    assert "keeps that change" in " ".join(str(excinfo.value).split())


@pytest.mark.parametrize("ending", ["dotenvx-failed", "copy-failed", "dotenvx-gone"])
def test_a_failed_decrypt_of_a_file_nobody_changed_says_it_was_left_as_it_was(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ending: str
) -> None:
    target = tmp_path / ".env.production"
    target.write_bytes(_ENCRYPTED)
    backend = DotenvxEncryptionBackend()
    backend._wrapper = _wrapper(target, ending, monkeypatch, edit=False)

    with pytest.raises(EncryptionBackendError) as excinfo:
        backend.decrypt(target)

    assert target.read_bytes() == _ENCRYPTED
    assert str(excinfo.value).endswith(f"{target} was left as it was.")
