"""A failed dotenvx decrypt leaves the file as it was (#962).

dotenvx decrypts value by value: with one value under another key it writes the
values it could decrypt and exits 1. ``DecryptSnapshot`` takes the file's bytes
before dotenvx runs and puts them back when the decrypt fails, or exits 0 but
leaves ciphertext behind. The dotenvx backend (``envdrift decrypt``, ``pull``,
``vault-pull`` and ``lock``'s re-key) uses it.

The real-binary proof is ``tests/integration/test_decrypt_failure_e2e.py``.
Here the dotenvx subprocess seam is replaced by a stand-in that writes what the
real binary writes, so every branch of the restore can be reached; the restore
itself, the read-back and git run for real.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from envdrift.encryption.base import EncryptionBackendError
from envdrift.encryption.dotenvx import DotenvxEncryptionBackend
from envdrift.integrations.dotenvx import DotenvxError
from tests.helpers import unreadable_file

# A dotenvx-encrypted file whose second value is under another key, with CRLF
# line endings so a restore that is not byte for byte would show.
_ENCRYPTED = (
    b'DOTENV_PUBLIC_KEY_PRODUCTION="03abc"\r\n'
    b"JWT_SECRET=encrypted:BAAA\r\n"
    b"STRIPE_API_KEY=encrypted:BFOREIGN\r\n"
)
# What dotenvx leaves behind after it decrypted JWT_SECRET and failed on the
# foreign value (the wrapper has already normalized the line endings to LF).
_PARTLY_DECRYPTED = (
    b'DOTENV_PUBLIC_KEY_PRODUCTION="03abc"\n'
    b"JWT_SECRET=" + b"super-" + b"secret\n"
    b"STRIPE_API_KEY=encrypted:BFOREIGN\n"
)
_DOTENVX_FAILURE = "dotenvx decryption failed: [DECRYPTION_FAILED] could not decrypt STRIPE_API_KEY"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True
    ).stdout


@pytest.fixture
def tracked_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """``.env.production`` committed in a real git repository (cwd = repo)."""
    if shutil.which("git") is None:
        pytest.skip("git not available")
    monkeypatch.chdir(tmp_path)
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    target = tmp_path / ".env.production"
    target.write_bytes(_ENCRYPTED)
    _git(tmp_path, "add", ".env.production")
    _git(tmp_path, "commit", "-q", "-m", "encrypted")
    return target


def _snapshot(path: Path):
    """Take a ``DecryptSnapshot`` (imported here so the backend tests below
    still run, and fail on their assertions, against code without it)."""
    from envdrift.core.partial_encryption import DecryptSnapshot

    return DecryptSnapshot(path)


def _fail_writes(monkeypatch: pytest.MonkeyPatch, target: Path) -> None:
    """Make writing ``target`` fail (the restore's own write), like a full disk."""
    real_write_bytes = Path.write_bytes

    def _write_bytes(self: Path, data: bytes) -> int:
        if self == target:
            raise OSError(28, "No space left on device")
        return real_write_bytes(self, data)

    monkeypatch.setattr(Path, "write_bytes", _write_bytes)


class TestDecryptSnapshotRestore:
    def test_unchanged_file_is_left_alone(self, tmp_path: Path) -> None:
        target = tmp_path / ".env.production"
        target.write_bytes(_ENCRYPTED)
        snapshot = _snapshot(target)
        before = target.stat().st_mtime_ns

        note = snapshot.restore()

        assert note == f"{target} was left as it was."
        assert target.read_bytes() == _ENCRYPTED
        assert target.stat().st_mtime_ns == before  # never rewritten

    def test_changed_file_is_put_back_byte_for_byte(self, tmp_path: Path) -> None:
        target = tmp_path / ".env.production"
        target.write_bytes(_ENCRYPTED)
        snapshot = _snapshot(target)
        target.write_bytes(_PARTLY_DECRYPTED)

        note = snapshot.restore()

        assert target.read_bytes() == _ENCRYPTED  # CRLF included
        assert note.startswith(f"{target} was left as it was: envdrift restored")

    def test_deleted_file_is_recreated(self, tmp_path: Path) -> None:
        target = tmp_path / ".env.production"
        target.write_bytes(_ENCRYPTED)
        snapshot = _snapshot(target)
        target.unlink()

        snapshot.restore()

        assert target.read_bytes() == _ENCRYPTED

    def test_failed_restore_marks_a_tracked_file_skip_worktree(
        self, tracked_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        snapshot = _snapshot(tracked_file)
        tracked_file.write_bytes(_PARTLY_DECRYPTED)
        _fail_writes(monkeypatch, tracked_file)

        note = snapshot.restore()

        flat = " ".join(note.split())
        assert "could not restore" in flat and "No space left on device" in flat
        assert "may now hold decrypted plaintext values" in flat
        assert "It is marked skip-worktree" in flat
        assert "WILL stage" not in flat
        # The protection is real: git reports the file as skip-worktree ("S").
        repo = tracked_file.parent
        assert _git(repo, "ls-files", "-v", ".env.production").startswith("S ")
        # The printed recovery works (git checkout alone refuses a skip-worktree
        # path). git writes the file itself, so the failing Python write above
        # does not get in its way.
        assert f"`git update-index --no-skip-worktree {tracked_file}`" in flat
        assert f"`git checkout -- {tracked_file}`" in flat
        _git(repo, "update-index", "--no-skip-worktree", str(tracked_file))
        _git(repo, "checkout", "--", str(tracked_file))
        assert tracked_file.read_bytes() == _ENCRYPTED

    def test_failed_restore_outside_a_repository_says_to_re_encrypt(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No repository: git can neither stage the file nor restore it.

        The advice was ``git checkout -- <file>``, and that `git add .` WILL stage it.
        """
        monkeypatch.chdir(tmp_path)  # not a git repository: no protection possible
        target = tmp_path / ".env.production"
        target.write_bytes(_ENCRYPTED)
        snapshot = _snapshot(target)
        target.write_bytes(_PARTLY_DECRYPTED)
        _fail_writes(monkeypatch, target)

        flat = " ".join(snapshot.restore().split())

        assert "It is outside a git repository" in flat, flat
        assert f"`envdrift encrypt {target}`" in flat, flat
        assert "git checkout" not in flat and "WILL stage" not in flat, flat

    def test_failed_restore_of_an_untracked_file_says_to_re_encrypt(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """git has no copy of an untracked file, so ``git checkout -- <file>`` fails."""
        if shutil.which("git") is None:
            pytest.skip("git not available")
        monkeypatch.chdir(tmp_path)
        _git(tmp_path, "init", "-q")
        target = tmp_path / ".env.production"
        target.write_bytes(_ENCRYPTED)
        snapshot = _snapshot(target)
        target.write_bytes(_PARTLY_DECRYPTED)
        _fail_writes(monkeypatch, target)

        flat = " ".join(snapshot.restore().split())

        assert "git does not track it" in flat, flat
        assert "a plain `git add .` WILL stage it" in flat, flat
        assert f"`envdrift encrypt {target}`" in flat, flat
        assert "git checkout" not in flat, flat
        # The advice it replaces cannot work here.
        checkout = subprocess.run(
            ["git", "checkout", "--", str(target)], cwd=tmp_path, capture_output=True
        )
        assert checkout.returncode != 0

    def test_restore_that_does_not_stick_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A write that returns but leaves other bytes is not a restore."""
        monkeypatch.chdir(tmp_path)
        target = tmp_path / ".env.production"
        target.write_bytes(_ENCRYPTED)
        snapshot = _snapshot(target)
        target.write_bytes(_PARTLY_DECRYPTED)
        monkeypatch.setattr(Path, "write_bytes", lambda self, data: len(data))

        flat = " ".join(snapshot.restore().split())

        assert "could not restore" in flat and "its bytes still differ" in flat

    def test_context_manager_restores_on_any_exception(self, tmp_path: Path) -> None:
        target = tmp_path / ".env.production"
        target.write_bytes(_ENCRYPTED)

        with pytest.raises(KeyboardInterrupt):
            with _snapshot(target) as snapshot:
                target.write_bytes(_PARTLY_DECRYPTED)
                raise KeyboardInterrupt

        assert target.read_bytes() == _ENCRYPTED
        assert "was left as it was" in snapshot.note

    def test_context_manager_does_nothing_on_success(self, tmp_path: Path) -> None:
        target = tmp_path / ".env.production"
        target.write_bytes(_ENCRYPTED)

        with _snapshot(target) as snapshot:
            target.write_bytes(b"JWT_SECRET=plain\n")

        assert target.read_bytes() == b"JWT_SECRET=plain\n"
        assert snapshot.note == ""


def _backend_with(decrypt_effect) -> tuple[DotenvxEncryptionBackend, MagicMock]:
    """A backend whose dotenvx seam runs ``decrypt_effect(env_file=...)``."""
    wrapper = MagicMock()
    wrapper.is_installed.return_value = True
    wrapper.decrypt.side_effect = decrypt_effect
    backend = DotenvxEncryptionBackend()
    backend._wrapper = wrapper
    return backend, wrapper


class TestDotenvxBackendDecryptRestores:
    def test_partly_failed_decrypt_restores_and_names_the_value(self, tracked_file: Path) -> None:
        def _partial(env_file: Path, **_kwargs) -> None:
            env_file.write_bytes(_PARTLY_DECRYPTED)
            raise DotenvxError(_DOTENVX_FAILURE)

        with pytest.raises(EncryptionBackendError) as excinfo:
            _backend_with(_partial)[0].decrypt(tracked_file)

        message = str(excinfo.value)
        assert tracked_file.read_bytes() == _ENCRYPTED
        assert _git(tracked_file.parent, "status", "--porcelain") == ""
        assert "could not decrypt STRIPE_API_KEY" in message
        assert message.count("dotenvx decryption failed:") == 1
        assert f"{tracked_file} was left as it was" in message

    def test_failure_before_any_write_reports_the_file_untouched(self, tmp_path: Path) -> None:
        target = tmp_path / ".env.production"
        target.write_bytes(_ENCRYPTED)

        def _missing_key(**_kwargs) -> None:
            raise DotenvxError("dotenvx command failed (exit 1): no private key")

        with pytest.raises(EncryptionBackendError) as excinfo:
            _backend_with(_missing_key)[0].decrypt(target)

        message = str(excinfo.value)
        assert message.startswith("dotenvx decryption failed: dotenvx command failed (exit 1)")
        assert message.endswith(f"{target} was left as it was.")
        assert target.read_bytes() == _ENCRYPTED

    def test_exit_zero_with_ciphertext_left_restores_the_decrypted_values(
        self, tmp_path: Path
    ) -> None:
        target = tmp_path / ".env.production"
        target.write_bytes(_ENCRYPTED)

        def _silent_partial(env_file: Path, **_kwargs) -> None:
            env_file.write_bytes(_PARTLY_DECRYPTED)  # exits 0, ciphertext left

        result = _backend_with(_silent_partial)[0].decrypt(target)

        assert result.success is False
        assert "did not take effect" in result.message.lower()
        assert f"{target} was left as it was: envdrift restored" in result.message
        assert target.read_bytes() == _ENCRYPTED

    def test_interrupted_decrypt_restores_and_reraises(self, tmp_path: Path) -> None:
        target = tmp_path / ".env.production"
        target.write_bytes(_ENCRYPTED)

        def _interrupted(env_file: Path, **_kwargs) -> None:
            env_file.write_bytes(_PARTLY_DECRYPTED)
            raise KeyboardInterrupt

        with pytest.raises(KeyboardInterrupt):
            _backend_with(_interrupted)[0].decrypt(target)

        assert target.read_bytes() == _ENCRYPTED

    def test_unreadable_file_is_refused_before_dotenvx_runs(
        self, searchable_tmp_path: Path
    ) -> None:
        """A file this process really cannot read, not a patched ``read_bytes``.

        The "nothing to decrypt" check read it before the snapshot did, so the
        caller got a bare PermissionError instead of this refusal.
        """
        target = searchable_tmp_path / ".env.production"
        target.write_bytes(_ENCRYPTED)
        backend, wrapper = _backend_with(lambda **_kwargs: None)

        with unreadable_file(target), pytest.raises(EncryptionBackendError) as excinfo:
            backend.decrypt(target)

        wrapper.decrypt.assert_not_called()
        message = str(excinfo.value)
        assert message.startswith(f"Could not read {target} before decrypting it: [Errno 13]")
        assert message.endswith("Nothing was decrypted."), message
        assert target.read_bytes() == _ENCRYPTED


class TestDotenvxBackendPrefixOnce:
    """#962: the wrapper's ``dotenvx <action> failed:`` prefix is not repeated."""

    def test_encrypt_failure_prefix_is_printed_once(self, tmp_path: Path) -> None:
        target = tmp_path / ".env.production"
        target.write_text("API_KEY=plain\n", encoding="utf-8")
        wrapper = MagicMock()
        wrapper.encrypt.side_effect = DotenvxError("dotenvx encryption failed: WRONG_PRIVATE_KEY")
        backend = DotenvxEncryptionBackend()
        backend._wrapper = wrapper

        with (
            patch.object(backend, "is_installed", return_value=True),
            pytest.raises(EncryptionBackendError) as excinfo,
        ):
            backend.encrypt(target)

        assert str(excinfo.value) == "dotenvx encryption failed: WRONG_PRIVATE_KEY"

    def test_other_encrypt_errors_still_get_the_prefix(self, tmp_path: Path) -> None:
        target = tmp_path / ".env.production"
        target.write_text("API_KEY=plain\n", encoding="utf-8")
        wrapper = MagicMock()
        wrapper.encrypt.side_effect = DotenvxError("dotenvx command failed (exit 2): boom")
        backend = DotenvxEncryptionBackend()
        backend._wrapper = wrapper

        with (
            patch.object(backend, "is_installed", return_value=True),
            pytest.raises(EncryptionBackendError) as excinfo,
        ):
            backend.encrypt(target)

        assert str(excinfo.value) == (
            "dotenvx encryption failed: dotenvx command failed (exit 2): boom"
        )


class TestFailureMessageLeavesOutTheStatusLine:
    """dotenvx prints "◇ decrypted <file>" even when the decrypt failed on a value.

    In the error it read as a success, right before "<file> was left as it was".
    Only the dotenvx subprocess is replaced, by the output dotenvx 2.38.2 gives.
    """

    def test_partly_failed_decrypt(self) -> None:
        from envdrift.integrations.dotenvx import DotenvxWrapper

        failed = subprocess.CompletedProcess(
            [],
            1,
            "",
            "☠ [DECRYPTION_FAILED] could not decrypt STRIPE_API_KEY. fix: [https://x.test/757]\n"
            "◇ decrypted .env.production (029 823) via .env.keys ⛉\n",
        )

        with pytest.raises(DotenvxError) as excinfo:
            DotenvxWrapper()._raise_on_error_output(failed, "decryption")

        assert str(excinfo.value) == (
            "dotenvx decryption failed: ☠ [DECRYPTION_FAILED] could not decrypt "
            "STRIPE_API_KEY. fix: [https://x.test/757]"
        )

    @pytest.mark.parametrize(
        "status", ["◈ encrypted .env (031 DB4) via .env.keys ⛉", "✔ encrypted (.env)"]
    )
    def test_failed_encrypt_and_dotenvx_1_lines(self, status: str) -> None:
        from envdrift.integrations.dotenvx import DotenvxWrapper

        failed = subprocess.CompletedProcess([], 1, "", f"{status}\nWRONG_PRIVATE_KEY\n")

        with pytest.raises(DotenvxError) as excinfo:
            DotenvxWrapper()._raise_on_error_output(failed, "encryption")

        assert str(excinfo.value) == "dotenvx encryption failed: WRONG_PRIVATE_KEY"

    def test_other_lines_are_kept(self) -> None:
        from envdrift.integrations.dotenvx import DotenvxWrapper

        failed = subprocess.CompletedProcess(
            [], 2, "", "○ no change to .env (031 DB4)\nunexpected failure\n"
        )

        with pytest.raises(DotenvxError) as excinfo:
            DotenvxWrapper()._raise_on_error_output(failed, "decryption")

        assert str(excinfo.value) == (
            "dotenvx command failed (exit 2): ○ no change to .env (031 DB4)\nunexpected failure"
        )
