"""EnvKeysFile reads and rewrites key lines the way dotenvx reads them (#938).

A rewrite replaces every value a reader would load for the key, all the lines
of a quoted value included, and changes nothing else a reader would load. A
backup is gitignored first: no copy is made while git would still track it.
"""

from __future__ import annotations

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


def test_write_key_refuses_a_layout_it_cannot_rewrite(tmp_path: Path) -> None:
    """dotenvx reads ``KEY:`` + newline + value as the key: never append a second one."""
    keys_path = tmp_path / ".env.keys"
    original = "# .env.production\nDOTENV_PRIVATE_KEY_PRODUCTION:\nold\n"
    keys_path.write_text(original, encoding="utf-8")
    keys = EnvKeysFile(keys_path)
    assert keys.read_values("DOTENV_PRIVATE_KEY_PRODUCTION") == ["old"]

    with pytest.raises(ValueError, match="cannot rewrite"):
        keys.write_key("DOTENV_PRIVATE_KEY_PRODUCTION", "new")

    assert keys_path.read_text(encoding="utf-8") == original
    assert keys.read_values("DOTENV_PRIVATE_KEY_PRODUCTION") == ["old"]


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


def test_write_key_refuses_a_rewrite_that_changes_another_name(tmp_path: Path) -> None:
    """dotenvx reads this as one value of A, which a line-by-line rewrite would split."""
    keys_path = tmp_path / ".env.keys"
    original = "A=1\u2028DOTENV_PRIVATE_KEY_PRODUCTION=old\n"
    keys_path.write_text(original, encoding="utf-8")
    keys = EnvKeysFile(keys_path)
    assert keys.read_values("DOTENV_PRIVATE_KEY_PRODUCTION") == []

    with pytest.raises(ValueError, match="cannot rewrite"):
        keys.write_key("DOTENV_PRIVATE_KEY_PRODUCTION", "new")

    assert keys_path.read_text(encoding="utf-8") == original


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
