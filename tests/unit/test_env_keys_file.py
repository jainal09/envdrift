"""EnvKeysFile reads and rewrites key lines the way dotenvx reads them (#938).

A rewrite replaces every value a reader would load for the key, all the lines
of a quoted value included, and changes nothing else a reader would load. A
backup is gitignored first: no copy is made while git would still track it.
"""

from __future__ import annotations

import errno
import os
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path

import pytest

from envdrift.sync.operations import EnvKeysFile


def test_read_values_returns_every_value_as_dotenvx_reads_it(tmp_path: Path) -> None:
    keys_path = tmp_path / ".env.keys"
    keys_path.write_text(
        chr(0xFEFF) + "DOTENV_PRIVATE_KEY_PRODUCTION=first # comment\n"
        "export DOTENV_PRIVATE_KEY_PRODUCTION = 'second'\n",
        encoding="utf-8",
    )
    keys = EnvKeysFile(keys_path)

    assert keys.read_values("DOTENV_PRIVATE_KEY_PRODUCTION") == ["first", "second"]
    assert keys.read_key("DOTENV_PRIVATE_KEY_PRODUCTION") == "first"
    assert EnvKeysFile(tmp_path / "missing").read_values("X") == []


def test_write_key_rewrites_every_line_a_reader_would_load(tmp_path: Path) -> None:
    """An ``export`` or spaced line is the same key: rewrite it, never append a second."""
    keys_path = tmp_path / ".env.keys"
    keys_path.write_text(
        "# .env.production\nexport DOTENV_PRIVATE_KEY_PRODUCTION = old\n", encoding="utf-8"
    )

    EnvKeysFile(keys_path).write_key("DOTENV_PRIVATE_KEY_PRODUCTION", "new")

    assert keys_path.read_text(encoding="utf-8") == (
        "# .env.production\nDOTENV_PRIVATE_KEY_PRODUCTION=new\n"
    )


@pytest.mark.parametrize(
    "case",
    [
        # dotenvx reads ``KEY:`` + newline + value as the key: never append a second one.
        pytest.param(
            (
                "# .env.production\nDOTENV_PRIVATE_KEY_PRODUCTION:\nold\n",
                "new",
                ["old"],
                "cannot rewrite",
            ),
            id="key-on-the-next-line",
        ),
        # dotenvx reads one value of A here, which a line-by-line rewrite would split.
        pytest.param(
            ("A=1\u2028DOTENV_PRIVATE_KEY_PRODUCTION=old\n", "new", [], "cannot rewrite"),
            id="line-separator-inside-a-value",
        ),
        # dotenvx reads ``#`` as a comment, so it would load "new", not the value given.
        pytest.param(
            ("DOTENV_PRIVATE_KEY_PRODUCTION=old\n", "new#tail", ["old"], "would not read"),
            id="value-with-a-hash",
        ),
        pytest.param((None, "new#tail", [], "would not read"), id="value-with-a-hash-new-file"),
    ],
)
def test_write_key_writes_nothing_dotenvx_would_read_otherwise(
    tmp_path: Path, case: tuple[str | None, str, list[str], str]
) -> None:
    """No write when dotenvx would load another value, or read another name differently."""
    original, value, held, message = case
    keys_path = tmp_path / ".env.keys"
    if original is not None:
        keys_path.write_text(original, encoding="utf-8")
    keys = EnvKeysFile(keys_path)
    assert keys.read_values("DOTENV_PRIVATE_KEY_PRODUCTION") == held

    with pytest.raises(ValueError, match=message):
        keys.write_key("DOTENV_PRIVATE_KEY_PRODUCTION", value)

    assert keys.read_values("DOTENV_PRIVATE_KEY_PRODUCTION") == held
    if original is None:
        assert not keys_path.exists()
    else:
        assert keys_path.read_text(encoding="utf-8") == original


@pytest.mark.parametrize("before", [None, "DOTENV_PRIVATE_KEY_PRODUCTION=theirs\n"])
def test_write_key_refuses_a_key_written_since_it_was_read(
    tmp_path: Path, before: str | None
) -> None:
    """Another writer added a key after the caller read none: write nothing."""
    keys_path = tmp_path / ".env.keys"
    if before is not None:
        keys_path.write_text(before, encoding="utf-8")

    with pytest.raises(ValueError, match="changed while envdrift was working on it"):
        EnvKeysFile(keys_path).write_key(
            "DOTENV_PRIVATE_KEY_PRODUCTION", "new", expected=["mine"] if before is None else []
        )

    if before is None:
        assert not keys_path.exists()
    else:
        assert keys_path.read_text(encoding="utf-8") == before


def test_write_key_does_not_overwrite_a_file_created_after_its_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Another writer creates the keys file after write_key found none: it is kept."""
    keys_path = tmp_path / ".env.keys"
    theirs = "DOTENV_PRIVATE_KEY_PRODUCTION=theirs\n"
    keys_path.write_text(theirs, encoding="utf-8")
    real_exists = Path.exists

    def exists_before_the_other_writer(self: Path, *args, **kwargs) -> bool:
        return False if self == keys_path else real_exists(self, *args, **kwargs)

    monkeypatch.setattr(Path, "exists", exists_before_the_other_writer)

    with pytest.raises(ValueError, match="changed while envdrift was working on it"):
        EnvKeysFile(keys_path).write_key("DOTENV_PRIVATE_KEY_PRODUCTION", "new", expected=[])

    assert keys_path.read_text(encoding="utf-8") == theirs


def test_write_key_does_not_replace_a_key_written_while_it_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Another writer commits while envdrift writes its new copy of the file: theirs is kept.

    The check of the key read was done by then, so only the file read again
    right before the rename shows the change.
    """
    keys_path = tmp_path / ".env.keys"
    keys_path.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=old\n", encoding="utf-8")
    theirs = "DOTENV_PRIVATE_KEY_PRODUCTION=old\nDOTENV_PRIVATE_KEY_STAGING=theirs\n"
    real_fsync = os.fsync

    def other_writer_commits(fd: int) -> None:
        real_fsync(fd)
        keys_path.write_text(theirs, encoding="utf-8")

    monkeypatch.setattr(os, "fsync", other_writer_commits)

    with pytest.raises(ValueError, match="changed while envdrift was working on it"):
        EnvKeysFile(keys_path).write_key("DOTENV_PRIVATE_KEY_PRODUCTION", "new", expected=["old"])

    assert keys_path.read_text(encoding="utf-8") == theirs
    assert sorted(path.name for path in tmp_path.iterdir()) == [".env.keys"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_write_key_keeps_the_mode_of_the_file_it_rewrites(tmp_path: Path) -> None:
    keys_path = tmp_path / ".env.keys"
    keys_path.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=old\n", encoding="utf-8")
    keys_path.chmod(0o640)

    EnvKeysFile(keys_path).write_key("DOTENV_PRIVATE_KEY_PRODUCTION", "new", expected=["old"])

    assert EnvKeysFile(keys_path).read_values("DOTENV_PRIVATE_KEY_PRODUCTION") == ["new"]
    assert keys_path.stat().st_mode & 0o777 == 0o640


def test_write_key_does_not_overwrite_a_file_created_while_it_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Another writer creates the file just before envdrift puts its own in place: it is kept.

    ``os.link`` is that step. ``atomic_write`` was, after an ``O_EXCL`` claim of
    the name, and it replaced the file the other writer had made.
    """
    from envdrift.sync import operations

    keys_path = tmp_path / ".env.keys"
    theirs = "DOTENV_PRIVATE_KEY_PRODUCTION=theirs\n"
    real_link, real_atomic_write = os.link, operations.atomic_write

    def other_writer_then(step):
        def run(*args, **kwargs):
            keys_path.write_text(theirs, encoding="utf-8")
            return step(*args, **kwargs)

        return run

    monkeypatch.setattr(os, "link", other_writer_then(real_link))
    monkeypatch.setattr(operations, "atomic_write", other_writer_then(real_atomic_write))

    with pytest.raises(ValueError, match="changed while envdrift was working on it"):
        EnvKeysFile(keys_path).write_key("DOTENV_PRIVATE_KEY_PRODUCTION", "new", expected=[])

    assert keys_path.read_text(encoding="utf-8") == theirs
    assert sorted(path.name for path in tmp_path.iterdir()) == [".env.keys"]


def _no_hard_links(*args, **kwargs):
    raise OSError(errno.EPERM, "hard links are not supported here")


def test_write_key_creates_a_file_where_there_are_no_hard_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "link", _no_hard_links)
    keys_path = tmp_path / ".env.keys"

    EnvKeysFile(keys_path).write_key("DOTENV_PRIVATE_KEY_PRODUCTION", "new", expected=[])

    assert EnvKeysFile(keys_path).read_values("DOTENV_PRIVATE_KEY_PRODUCTION") == ["new"]
    assert sorted(path.name for path in tmp_path.iterdir()) == [".env.keys"]


def test_write_key_leaves_no_part_of_a_key_it_failed_to_write_without_hard_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The disk fills up while the new file is written in place: no part of it is left."""
    from envdrift.sync import operations

    real_write_fd = operations._write_fd
    calls: list[int] = []

    def disk_full_after_the_temp_file(fd: int, data: bytes, permissions: int) -> None:
        calls.append(fd)
        if len(calls) == 1:
            return real_write_fd(fd, data, permissions)
        real_write_fd(fd, data[:10], permissions)
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, "link", _no_hard_links)
    monkeypatch.setattr(operations, "_write_fd", disk_full_after_the_temp_file)

    with pytest.raises(OSError, match="No space left on device"):
        EnvKeysFile(tmp_path / ".env.keys").write_key(
            "DOTENV_PRIVATE_KEY_PRODUCTION", "new", expected=[]
        )

    assert list(tmp_path.iterdir()) == []


def test_write_key_writes_when_the_key_is_still_what_was_read(tmp_path: Path) -> None:
    keys_path = tmp_path / ".env.keys"
    keys_path.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=old\n", encoding="utf-8")

    EnvKeysFile(keys_path).write_key("DOTENV_PRIVATE_KEY_PRODUCTION", "new", expected=["old"])

    assert keys_path.read_text(encoding="utf-8") == "DOTENV_PRIVATE_KEY_PRODUCTION=new\n"


def test_write_key_replaces_a_multiline_value_whole(tmp_path: Path) -> None:
    """The lines of a quoted value go with it: none is left to be read as a key."""
    keys_path = tmp_path / ".env.keys"
    keys_path.write_text(
        '# .env.production\nDOTENV_PRIVATE_KEY_PRODUCTION="part1\n'
        'DOTENV_PRIVATE_KEY_STAGING=hidden\n"\n',
        encoding="utf-8",
    )
    keys = EnvKeysFile(keys_path)
    assert keys.read_values("DOTENV_PRIVATE_KEY_STAGING") == []

    keys.write_key("DOTENV_PRIVATE_KEY_PRODUCTION", "new")

    assert keys_path.read_text(encoding="utf-8") == (
        "# .env.production\nDOTENV_PRIVATE_KEY_PRODUCTION=new\n"
    )
    assert keys.read_values("DOTENV_PRIVATE_KEY_STAGING") == []


def test_write_key_leaves_a_line_inside_another_value_alone(tmp_path: Path) -> None:
    """A key-like line in another quoted value is that value's text, not the key."""
    keys_path = tmp_path / ".env.keys"
    note = 'NOTE="text\nDOTENV_PRIVATE_KEY_PRODUCTION=inside\n"\n'
    keys_path.write_text(note + "DOTENV_PRIVATE_KEY_PRODUCTION=old\n", encoding="utf-8")

    EnvKeysFile(keys_path).write_key("DOTENV_PRIVATE_KEY_PRODUCTION", "new")

    assert keys_path.read_text(encoding="utf-8") == note + "DOTENV_PRIVATE_KEY_PRODUCTION=new\n"


def _git_init(path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)  # nosec B603 B607


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_create_backup_is_gitignored_before_it_is_written(tmp_path: Path) -> None:
    """N2: a ``.env.keys`` entry does not cover ``.env.keys.backup.<ts>``."""
    _git_init(tmp_path)
    (tmp_path / ".gitignore").write_text(".env.keys\n", encoding="utf-8")
    folder = tmp_path / "svc"
    folder.mkdir()
    keys_path = folder / ".env.keys"
    keys_path.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n", encoding="utf-8")

    backup = EnvKeysFile(keys_path).create_backup()

    assert (tmp_path / ".gitignore").read_text(encoding="utf-8") == (
        ".env.keys\nsvc/.env.keys.backup.*\n"
    )
    check = subprocess.run(  # nosec B603 B607
        ["git", "check-ignore", "-q", backup.relative_to(tmp_path).as_posix()], cwd=tmp_path
    )
    assert check.returncode == 0
    # A second backup needs no new entry.
    EnvKeysFile(keys_path).create_backup()
    assert (tmp_path / ".gitignore").read_text(encoding="utf-8").count("backup") == 1


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
@pytest.mark.parametrize("already_listed", [False, True])
def test_create_backup_refuses_a_backup_a_rule_re_includes(
    tmp_path: Path, already_listed: bool
) -> None:
    """A nested ``!*.backup.*`` keeps the backup tracked, entry or not: write no backup."""
    _git_init(tmp_path)
    listed = "svc/.env.keys.backup.*\n" if already_listed else ""
    (tmp_path / ".gitignore").write_text(f".env.keys\n{listed}", encoding="utf-8")
    folder = tmp_path / "svc"
    folder.mkdir()
    (folder / ".gitignore").write_text("!*.backup.*\n", encoding="utf-8")
    keys_path = folder / ".env.keys"
    keys_path.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n", encoding="utf-8")

    with pytest.raises(OSError, match="would still track"):
        EnvKeysFile(keys_path).create_backup()

    assert sorted(path.name for path in folder.iterdir()) == [".env.keys", ".gitignore"]


def _is_ignored(repo: Path, path: Path) -> bool:
    check = subprocess.run(  # nosec B603 B607
        ["git", "check-ignore", "-q", path.relative_to(repo).as_posix()], cwd=repo
    )
    return check.returncode == 0


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
@pytest.mark.parametrize(
    ("folder_name", "keys_name"),
    [
        pytest.param("svc[1]", ".env.keys", id="bracket-folder"),
        pytest.param("svc", "[prod].keys", id="bracket-keys-file"),
        pytest.param(
            "a*b",
            ".env.keys",
            id="star-folder",
            marks=pytest.mark.skipif(
                sys.platform == "win32", reason="Windows does not allow * in a file name"
            ),
        ),
        pytest.param("", "#keys", id="root-hash-keys-file"),
    ],
)
def test_create_backup_ignores_names_gitignore_would_read_as_patterns(
    tmp_path: Path, folder_name: str, keys_name: str
) -> None:
    """``[``, ``*`` and a leading ``#`` are escaped, so the entry matches the backup itself."""
    _git_init(tmp_path)
    folder = tmp_path / folder_name
    folder.mkdir(exist_ok=True)
    keys_path = folder / keys_name
    keys_path.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n", encoding="utf-8")

    backup = EnvKeysFile(keys_path).create_backup()

    assert _is_ignored(tmp_path, backup)


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_create_backup_extends_a_gitignore_that_is_not_utf8(tmp_path: Path) -> None:
    _git_init(tmp_path)
    (tmp_path / ".gitignore").write_bytes(b"# caf\xe9\n.env.keys")
    keys_path = tmp_path / ".env.keys"
    keys_path.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n", encoding="utf-8")

    backup = EnvKeysFile(keys_path).create_backup()

    assert _is_ignored(tmp_path, backup)
    assert (tmp_path / ".gitignore").read_bytes() == b"# caf\xe9\n.env.keys\n.env.keys.backup.*\n"


def test_create_backup_refuses_when_git_cannot_name_the_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A ``.git`` above the folder but no root from git is a git failure: copy nothing."""
    (tmp_path / ".git").mkdir()
    keys_path = tmp_path / ".env.keys"
    keys_path.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n", encoding="utf-8")
    monkeypatch.setattr("envdrift.utils.git.get_git_root", lambda path: None)

    with pytest.raises(OSError, match="did not report the repository"):
        EnvKeysFile(keys_path).create_backup()

    assert sorted(path.name for path in tmp_path.iterdir()) == [".env.keys", ".git"]


def test_create_backup_refuses_a_folder_outside_the_reported_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    keys_path = tmp_path / ".env.keys"
    keys_path.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    monkeypatch.setattr("envdrift.utils.git.get_git_root", lambda path: elsewhere)
    monkeypatch.setattr("envdrift.utils.git._is_path_ignored", lambda path, root: False)

    with pytest.raises(OSError, match="not under the repository root"):
        EnvKeysFile(keys_path).create_backup()

    assert sorted(path.name for path in tmp_path.iterdir()) == [".env.keys"]


def test_create_backup_makes_no_copy_when_gitignore_cannot_be_updated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    keys_path = tmp_path / ".env.keys"
    keys_path.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n", encoding="utf-8")

    def unwritable(*args, **kwargs):
        raise PermissionError(".gitignore is read-only")

    monkeypatch.setattr("envdrift.utils.git.ensure_gitignore_glob", unwritable)

    with pytest.raises(PermissionError):
        EnvKeysFile(keys_path).create_backup()

    assert sorted(path.name for path in tmp_path.iterdir()) == [".env.keys"]
