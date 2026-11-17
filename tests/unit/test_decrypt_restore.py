"""A failed dotenvx decrypt leaves the file as it was (#962).

dotenvx decrypts value by value: with one value under another key it writes the
values it could decrypt and exits 1. ``DecryptSnapshot`` takes the file's bytes
before dotenvx runs and puts them back when the decrypt fails, or exits 0 but
leaves ciphertext behind. The dotenvx backend (``envdrift decrypt``, ``pull`` and
``vault-pull``) uses it.

The real-binary proof is ``tests/integration/test_decrypt_failure_e2e.py``.
Here the dotenvx subprocess seam is replaced by a stand-in that writes what the
real binary writes, so every branch of the restore can be reached; the restore
itself, the read-back and git run for real. A restore that cannot write is a
real write failure where the platform has file size limits (POSIX), and
elsewhere a rename onto the file that is made to fail.
"""

from __future__ import annotations

import errno
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from envdrift.encryption.base import EncryptionBackendError
from envdrift.encryption.dotenvx import DotenvxEncryptionBackend
from envdrift.integrations.dotenvx import DotenvxError, DotenvxFileChangedError, DotenvxWrapper
from tests.helpers import file_size_limit, unreadable_file

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
# The same file with many more values: a file size limit of half of it stops
# the restore's write part way, and stays far above anything else written
# while it is on (git's index, pytest's capture files).
_LARGE_ENCRYPTED = _ENCRYPTED + b"".join(
    b"VALUE_%04d=encrypted:B%s\r\n" % (number, b"A" * 96) for number in range(600)
)


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
    """Make putting ``target``'s bytes back fail, like a full disk.

    The restore writes them to a temp file and renames it over the file. Here
    the rename onto ``target`` fails, as it can when the directory has no room
    left for the entry, so these tests run on every platform; the real write
    failures in ``TestRestoreIsWholeOrNothing`` need POSIX.
    """
    real_replace = os.replace
    written = target.resolve()

    def _replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        if Path(dst).resolve() == written:
            raise OSError(errno.ENOSPC, "No space left on device")
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", _replace)


def _init_repo(repo: Path) -> None:
    """A real git repository at ``repo``, with an identity to commit as."""
    if shutil.which("git") is None:
        pytest.skip("git not available")
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")


def _symlink(link: Path, target: str) -> None:
    if sys.platform == "win32":
        pytest.skip("git checks symlinks out as plain files on Windows by default")
    link.symlink_to(target)


def _flag(repo: Path, path: str) -> str:
    """``git ls-files -v`` for ``path``: ``S`` skip-worktree, ``H`` tracked."""
    return _git(repo, "ls-files", "-v", "--", path)[:2].strip()


def _recovery_commands(note: str) -> tuple[str, str]:
    """The two commands the note of a marked file says to run, in order."""
    found = re.search(r"To restore it, run `([^`]+)` and then `([^`]+)`", " ".join(note.split()))
    assert found, note
    return found.group(1), found.group(2)


def _run_each(repo: Path, *commands: str) -> None:
    """Run each printed command in ``repo``, as a user would paste it there."""
    for command in commands:
        ran = subprocess.run(shlex.split(command), cwd=repo, capture_output=True, text=True)
        assert ran.returncode == 0, f"{command}: {ran.stderr}"


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
        if shutil.which("git") is None:
            pytest.skip("git not available: the reason would be that git is missing")
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

    def test_failed_restore_of_a_tracked_file_git_could_not_mark_says_git_checkout(
        self, tracked_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Tracked, but not marked while another git process holds the index lock."""
        snapshot = _snapshot(tracked_file)
        tracked_file.write_bytes(_PARTLY_DECRYPTED)
        _fail_writes(monkeypatch, tracked_file)
        lock = tracked_file.parent / ".git" / "index.lock"
        lock.write_text("", encoding="utf-8")

        flat = " ".join(snapshot.restore().split())

        assert "could not be marked skip-worktree" in flat, flat
        assert "a plain `git add .` WILL stage it" in flat, flat
        assert f"`git checkout -- {tracked_file}`" in flat, flat
        # The advice works once the other git process is done.
        lock.unlink()
        _git(tracked_file.parent, "checkout", "--", str(tracked_file))
        assert tracked_file.read_bytes() == _ENCRYPTED

    def test_restore_that_does_not_stick_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A write that returns but leaves other bytes is not a restore.

        Here another writer (a second dotenvx run, say) writes the file right
        after the restore renamed its copy over it.
        """
        monkeypatch.chdir(tmp_path)
        target = tmp_path / ".env.production"
        target.write_bytes(_ENCRYPTED)
        snapshot = _snapshot(target)
        target.write_bytes(_PARTLY_DECRYPTED)
        real_replace = os.replace

        def _replace_then_overwritten(
            src: str | os.PathLike[str], dst: str | os.PathLike[str]
        ) -> None:
            real_replace(src, dst)
            Path(dst).write_bytes(_PARTLY_DECRYPTED)

        monkeypatch.setattr(os, "replace", _replace_then_overwritten)

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


class TestRestoreIsWholeOrNothing:
    """The original bytes go back whole, or the file is left as dotenvx wrote it.

    ``restore`` wrote them in place, and a write truncates the file first. One
    that failed part way (a full disk, a file size limit) left the file cut
    short: the values dotenvx decrypted and the ciphertext it left were gone,
    and an untracked file had no copy anywhere. The write failures here are
    real: the kernel refuses a write past a file size limit.
    """

    def test_a_write_that_fails_part_way_leaves_the_file_as_it_was(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        target = tmp_path / ".env.production"
        target.write_bytes(_LARGE_ENCRYPTED)
        snapshot = _snapshot(target)
        target.write_bytes(_PARTLY_DECRYPTED)

        with file_size_limit(len(_LARGE_ENCRYPTED) // 2):
            note = snapshot.restore()

        # Not the first half of the original: what dotenvx wrote is all there.
        assert target.read_bytes() == _PARTLY_DECRYPTED
        flat = " ".join(note.split())
        assert f"envdrift could not restore {target} ([Errno {errno.EFBIG}]" in flat, flat
        assert "may now hold decrypted plaintext values" in flat, flat
        # The copy that could not be written is not left next to it either.
        assert [path.name for path in tmp_path.iterdir()] == [".env.production"]

    def test_a_symlink_stays_a_symlink_with_its_target_s_mode(self, tmp_path: Path) -> None:
        """The bytes land in the file the link points to, which keeps its mode."""
        (tmp_path / "shared").mkdir()
        target = tmp_path / "shared" / "production.secret"
        target.write_bytes(_ENCRYPTED)
        target.chmod(0o640)
        link = tmp_path / ".env.production"
        _symlink(link, "shared/production.secret")
        snapshot = _snapshot(link)
        target.write_bytes(_PARTLY_DECRYPTED)

        note = snapshot.restore()

        assert note.startswith(f"{link} was left as it was: envdrift restored"), note
        assert link.is_symlink()
        assert target.read_bytes() == _ENCRYPTED
        assert stat.S_IMODE(target.stat().st_mode) == 0o640


class TestRecoveryAdviceActsOnTheFileThePlaintextIsIn:
    """The printed commands run git where the skip-worktree mark was set.

    The mark goes on the file the write lands in, by git run in that file's own
    directory: for a symlinked secret file the link's target, and for a file in
    a submodule the submodule's repository. The advice named the path from the
    working directory, so for a link it unmarked and checked out the link while
    the target kept the plaintext and the mark, and for a file in a submodule
    git refused it.
    """

    def test_a_symlinked_secret_file(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _init_repo(tmp_path)
        monkeypatch.chdir(tmp_path)
        (tmp_path / "shared").mkdir()
        (tmp_path / "config").mkdir()
        target = tmp_path / "shared" / "production.secret"
        target.write_bytes(_LARGE_ENCRYPTED)
        link = Path("config/.env.production.secret")
        _symlink(tmp_path / link, "../shared/production.secret")
        _git(tmp_path, "add", "-A")
        _git(tmp_path, "commit", "-q", "-m", "symlinked secret")
        snapshot = _snapshot(link)
        target.write_bytes(_PARTLY_DECRYPTED)

        with file_size_limit(len(_LARGE_ENCRYPTED) // 2):
            note = snapshot.restore()

        assert _flag(tmp_path, "shared/production.secret") == "S"
        commands = _recovery_commands(note)
        assert commands == (
            "git -C shared update-index --no-skip-worktree production.secret",
            "git -C shared checkout -- production.secret",
        ), note
        _run_each(tmp_path, *commands)
        assert _flag(tmp_path, "shared/production.secret") == "H"
        assert target.read_bytes() == _LARGE_ENCRYPTED
        assert (tmp_path / link).is_symlink()
        # The sentence says why the commands name another file.
        flat = " ".join(note.split())
        assert "(through a symlink, they are in shared/production.secret)" in flat, flat

    def test_a_secret_file_in_a_submodule(
        self,
        tmp_path: Path,
        tmp_path_factory: pytest.TempPathFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        inner = tmp_path_factory.mktemp("inner")
        _init_repo(inner)
        (inner / ".env.secret").write_bytes(_LARGE_ENCRYPTED)
        _git(inner, "add", ".env.secret")
        _git(inner, "commit", "-q", "-m", "inner")
        _init_repo(tmp_path)
        allow_local = ("-c", "protocol.file.allow=always")  # git refuses a local one otherwise
        _git(tmp_path, *allow_local, "submodule", "add", "-q", str(inner), "sub")
        _git(tmp_path, "commit", "-q", "-m", "submodule")
        monkeypatch.chdir(tmp_path)
        secret = tmp_path / "sub" / ".env.secret"
        snapshot = _snapshot(Path("sub/.env.secret"))
        secret.write_bytes(_PARTLY_DECRYPTED)

        with file_size_limit(len(_LARGE_ENCRYPTED) // 2):
            note = snapshot.restore()

        assert _flag(tmp_path / "sub", ".env.secret") == "S"
        commands = _recovery_commands(note)
        assert commands == (
            "git -C sub update-index --no-skip-worktree .env.secret",
            "git -C sub checkout -- .env.secret",
        ), note
        _run_each(tmp_path, *commands)
        assert _flag(tmp_path / "sub", ".env.secret") == "H"
        assert secret.read_bytes() == _LARGE_ENCRYPTED

    @pytest.mark.parametrize("name", ["prod secrets.env", "-prod.env"], ids=["space", "dash"])
    def test_a_secret_file_whose_name_a_command_could_misread(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
    ) -> None:
        """A name with a space, or one that starts with ``-``, names one file in the commands.

        Unquoted, ``git checkout -- prod secrets.env`` named two files, and git read
        ``git update-index --no-skip-worktree -prod.env`` as an unknown option. Either way
        the advice failed, and the file kept its plaintext and its mark.
        """
        _init_repo(tmp_path)
        monkeypatch.chdir(tmp_path)
        secret = tmp_path / name
        secret.write_bytes(_LARGE_ENCRYPTED)
        _git(tmp_path, "add", "-A")
        _git(tmp_path, "commit", "-q", "-m", "a secret file a command could misread")
        snapshot = _snapshot(Path(name))
        secret.write_bytes(_PARTLY_DECRYPTED)

        with file_size_limit(len(_LARGE_ENCRYPTED) // 2):
            note = snapshot.restore()

        assert _flag(tmp_path, name) == "S"
        _run_each(tmp_path, *_recovery_commands(note))
        assert _flag(tmp_path, name) == "H"
        assert secret.read_bytes() == _LARGE_ENCRYPTED

    def test_the_sops_advice_marks_a_submodule_file_in_the_submodule(
        self,
        tmp_path: Path,
        tmp_path_factory: pytest.TempPathFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The mark the SOPS advice prints runs in the repository that tracks the file.

        Run from the superproject, ``git update-index --skip-worktree sub/.env.secret``
        failed: the superproject tracks the submodule as one gitlink, not its files, so
        the decrypt after it left plaintext that ``git add .`` in the submodule staged.
        """
        from envdrift.core.partial_encryption import PartialEncryptionError

        inner = tmp_path_factory.mktemp("inner")
        _init_repo(inner)
        (inner / ".env.secret").write_bytes(_LARGE_ENCRYPTED)
        _git(inner, "add", ".env.secret")
        _git(inner, "commit", "-q", "-m", "inner")
        _init_repo(tmp_path)
        allow_local = ("-c", "protocol.file.allow=always")  # git refuses a local one otherwise
        _git(tmp_path, *allow_local, "submodule", "add", "-q", str(inner), "sub")
        _git(tmp_path, "commit", "-q", "-m", "submodule")
        monkeypatch.chdir(tmp_path)

        error = PartialEncryptionError.still_encrypted(Path("sub/.env.secret"), "SOPS", "")

        flat = " ".join(str(error).split())
        mark = re.search(r"run `([^`]+)` so `git add \.` cannot stage", flat)
        assert mark, flat
        _run_each(tmp_path, mark.group(1))
        assert _flag(tmp_path / "sub", ".env.secret") == "S"


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


# What an editor saves into the file while dotenvx runs.
_EDIT = b"ADDED_BY_HAND=yes\r\n"


def _wrapper_edited_meanwhile(target: Path) -> DotenvxWrapper:
    """A wrapper whose dotenvx runs while an editor saves ``target``, then prints the copy.

    Nothing is decrypted, which does not matter here: envdrift must write nothing either way.
    """
    wrapper = DotenvxWrapper(auto_install=False)

    def _run_raw(args, env=None, cwd=None) -> subprocess.CompletedProcess[bytes]:
        with target.open("ab") as handle:
            handle.write(_EDIT)
        copy = Path(args[args.index("-f") + 1]).read_bytes()
        return subprocess.CompletedProcess(args, 0, copy, b"")

    wrapper._run_raw = _run_raw  # type: ignore[method-assign]
    wrapper.is_installed = lambda: True  # type: ignore[method-assign]
    return wrapper


class TestAChangeMadeWhileDotenvxRunsIsKept:
    """The snapshot predates another writer's change, so putting it back would destroy it.

    The wrapper writes nothing over a file that changed while dotenvx ran; the snapshot
    then put its earlier bytes back over the change all the same, and the edit was lost.
    """

    def test_the_snapshot_keeps_a_change_it_is_told_to(self, tmp_path: Path) -> None:
        target = tmp_path / ".env.production"
        target.write_bytes(_ENCRYPTED)

        with pytest.raises(DotenvxFileChangedError):
            with _snapshot(target) as snapshot:
                target.write_bytes(_ENCRYPTED + _EDIT)
                raise DotenvxFileChangedError("changed while it was being decrypted")

        assert target.read_bytes() == _ENCRYPTED + _EDIT
        assert snapshot.note == f"{target} keeps that change."

    def test_decrypt_keeps_the_change(self, tmp_path: Path) -> None:
        target = tmp_path / ".env.production"
        target.write_bytes(_ENCRYPTED)
        backend = DotenvxEncryptionBackend()
        backend._wrapper = _wrapper_edited_meanwhile(target)

        with pytest.raises(EncryptionBackendError) as excinfo:
            backend.decrypt(target)

        assert target.read_bytes() == _ENCRYPTED + _EDIT
        flat = " ".join(str(excinfo.value).split())
        assert "changed while it was being decrypted" in flat
        assert f"{target} keeps that change." in flat

    def test_pull_partial_keeps_the_change(self, tmp_path: Path) -> None:
        from envdrift.core.partial_encryption import PartialEncryptionError, _decrypt_in_place

        target = tmp_path / ".env.production.secret"
        target.write_bytes(_ENCRYPTED)

        with pytest.raises(PartialEncryptionError) as excinfo:
            _decrypt_in_place(_wrapper_edited_meanwhile(target), target)

        assert target.read_bytes() == _ENCRYPTED + _EDIT
        assert "keeps that change" in " ".join(str(excinfo.value).split())
