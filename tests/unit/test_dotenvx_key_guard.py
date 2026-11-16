"""The dotenvx wrapper's key guard: seed the held key, then verify what dotenvx did.

dotenvx itself is replaced by a stand-in ``_run`` that mutates the files the way
a misbehaving dotenvx would (create a key, replace a key, crash half way). The
behavior under test is envdrift's: refuse before running, and put both files
back byte for byte when the outcome breaks the key the folder holds (#938).
The real binary is exercised in tests/integration/test_dotenvx_key_reuse.py.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from envdrift.encryption.dotenvx import DotenvxEncryptionBackend
from envdrift.integrations.dotenvx import (
    DotenvxError,
    DotenvxKeyError,
    DotenvxWrapper,
    _EncryptSnapshot,
    normalize_dotenvx_metadata,
)
from envdrift.integrations.dotenvx_keys import public_key_values
from envdrift.sync.operations import EnvKeysFile
from tests.helpers import DOTENVX_KEY_PAIRS

K1, PUB1 = DOTENVX_KEY_PAIRS[0]
K2, PUB2 = DOTENVX_KEY_PAIRS[1]
NAME = "DOTENV_PRIVATE_KEY_PRODUCTION"

Effect = Callable[[Path, Path], None]


def _wrapper(effect: Effect, returncode: int = 0) -> tuple[DotenvxWrapper, list[str]]:
    """A wrapper whose dotenvx run applies ``effect`` to (env file, keys file)."""
    wrapper = DotenvxWrapper(auto_install=False)
    seen: list[str] = []

    def run(args, env=None, cwd=None, check=True):
        env_file, keys_file = Path(args[2]), Path(args[4])
        seen.append(env_file.read_text(encoding="utf-8"))
        effect(env_file, keys_file)
        return MagicMock(returncode=returncode, stdout="", stderr="boom" if returncode else "")

    wrapper._run = run  # type: ignore[method-assign]
    return wrapper, seen


def _encrypt_values(env_file: Path, keys_file: Path) -> None:
    """An honest dotenvx: plaintext values become ciphertext, the header stays."""
    lines = []
    for line in env_file.read_text(encoding="utf-8").split("\n"):
        if "=" in line and not line.startswith(("DOTENV_PUBLIC_KEY", "#")):
            line = line.split("=", 1)[0] + "=encrypted:abc"
        lines.append(line)
    env_file.write_text("\n".join(lines), encoding="utf-8")


def _mint_second_key(env_file: Path, keys_file: Path) -> None:
    """dotenvx 2.x without a header: a brand-new key next to the held one."""
    with keys_file.open("a", encoding="utf-8") as handle:
        handle.write(f"\n# .env.production\n{NAME}={K2}\n")
    env_file.write_text(f'DOTENV_PUBLIC_KEY_PRODUCTION="{PUB2}"\nA=encrypted:abc\n')


def _setup(tmp_path: Path, env_bytes: bytes = b"A=1\r\n", keys: str | None = None):
    env_file = tmp_path / ".env.production"
    env_file.write_bytes(env_bytes)
    keys_file = tmp_path / ".env.keys"
    if keys is not None:
        keys_file.write_text(keys, encoding="utf-8")
    return env_file, keys_file


def test_held_key_is_seeded_before_dotenvx_runs(tmp_path: Path):
    env_file, keys_file = _setup(tmp_path, keys=f"{NAME}={K1}\n")
    wrapper, seen = _wrapper(_encrypt_values)

    wrapper.encrypt(env_file)

    assert public_key_values(seen[0]) == [PUB1]  # dotenvx saw the held key's header
    assert "\r" not in seen[0]  # line endings normalized for dotenvx
    assert keys_file.read_text(encoding="utf-8") == f"{NAME}={K1}\n"


def test_a_minted_second_key_is_rolled_back_byte_for_byte(tmp_path: Path):
    """#938 + N3: both files return to their exact bytes, CRLF included."""
    env_file, keys_file = _setup(tmp_path, keys=f"{NAME}={K1}\n")
    before = (env_file.read_bytes(), keys_file.read_bytes())
    wrapper, _ = _wrapper(_mint_second_key)

    with pytest.raises(DotenvxKeyError, match=f"dotenvx changed {NAME} in the keys file"):
        wrapper.encrypt(env_file)

    assert (env_file.read_bytes(), keys_file.read_bytes()) == before


def test_a_new_key_name_is_rolled_back_when_one_was_held(tmp_path: Path):
    env_file, keys_file = _setup(tmp_path, keys=f"{NAME}={K1}\n")
    before = (env_file.read_bytes(), keys_file.read_bytes())

    def mint_under_another_name(env: Path, keys: Path) -> None:
        with keys.open("a", encoding="utf-8") as handle:
            handle.write(f"DOTENV_PRIVATE_KEY_PROD={K2}\n")

    wrapper, _ = _wrapper(mint_under_another_name)

    with pytest.raises(DotenvxKeyError, match="created DOTENV_PRIVATE_KEY_PROD instead of using"):
        wrapper.encrypt(env_file, environment="production")

    assert (env_file.read_bytes(), keys_file.read_bytes()) == before


def test_a_failed_dotenvx_run_takes_the_seeded_header_back(tmp_path: Path):
    env_file, _ = _setup(tmp_path, keys=f"{NAME}={K1}\n")
    before = env_file.read_bytes()

    def half_written(env: Path, keys: Path) -> None:
        env.write_text("garbage", encoding="utf-8")

    wrapper, _ = _wrapper(half_written, returncode=1)

    with pytest.raises(DotenvxError, match="exit 1"):
        wrapper.encrypt(env_file)

    assert env_file.read_bytes() == before


def test_a_keys_file_dotenvx_created_after_a_refusal_is_removed(tmp_path: Path):
    """No key was held, dotenvx minted one but did not keep the header: undo all."""
    env_file, keys_file = _setup(tmp_path, env_bytes=f'DOTENV_PUBLIC_KEY="{PUB2}"\nA=1\n'.encode())

    def mint_and_prepend(env: Path, keys: Path) -> None:
        keys.write_text(f"DOTENV_PRIVATE_KEY={K1}\n", encoding="utf-8")
        env.write_text(f'DOTENV_PUBLIC_KEY="{PUB1}"\n' + env.read_text(encoding="utf-8"))

    wrapper, _ = _wrapper(mint_and_prepend)
    env_file = env_file.rename(tmp_path / ".env")

    with pytest.raises(DotenvxKeyError, match="two different public keys"):
        wrapper.encrypt(env_file)

    assert not keys_file.exists()
    assert env_file.read_text(encoding="utf-8") == f'DOTENV_PUBLIC_KEY="{PUB2}"\nA=1\n'


def test_unreadable_result_is_rolled_back(tmp_path: Path):
    env_file, _ = _setup(tmp_path, keys=f"{NAME}={K1}\n")
    before = env_file.read_bytes()

    def write_non_utf8(env: Path, keys: Path) -> None:
        env.write_bytes(b"\xff\xfe")

    wrapper, _ = _wrapper(write_non_utf8)

    with pytest.raises(DotenvxKeyError, match="could not be read back"):
        wrapper.encrypt(env_file)

    assert env_file.read_bytes() == before


def test_a_restore_that_cannot_write_says_so(tmp_path: Path):
    env_file, _ = _setup(tmp_path, keys=f"{NAME}={K1}\n")

    def replace_with_directory(env: Path, keys: Path) -> None:
        env.unlink()
        env.mkdir()

    wrapper, _ = _wrapper(replace_with_directory)

    with pytest.raises(DotenvxError, match="Could not put"):
        wrapper.encrypt(env_file)


def _replace_key_and_env_file(env: Path, keys: Path) -> None:
    """A dotenvx run that replaces the held key, and an env file nothing can write back."""
    keys.write_text(f"{NAME}={K2}\n", encoding="utf-8")
    env.unlink()
    env.mkdir()


def test_an_env_file_that_cannot_be_put_back_does_not_keep_the_keys_file_from_it(
    tmp_path: Path,
):
    """dotenvx replaced the held key: it is put back although the env file cannot be.

    The env file may now hold values encrypted with the key dotenvx wrote, so the
    keys file dotenvx wrote is kept in a backup first: no key is deleted.
    """
    env_file, keys_file = _setup(tmp_path, keys=f"{NAME}={K1}\n")
    wrapper, _ = _wrapper(_replace_key_and_env_file)

    with pytest.raises(DotenvxError, match="Could not put") as excinfo:
        wrapper.encrypt(env_file)

    assert keys_file.read_text(encoding="utf-8") == f"{NAME}={K1}\n"
    backups = sorted(tmp_path.glob(".env.keys.backup.*"))
    assert [backup.read_text(encoding="utf-8") for backup in backups] == [f"{NAME}={K2}\n"]
    assert str(env_file) in str(excinfo.value)
    assert str(backups[0]) in str(excinfo.value)


def test_a_keys_file_that_cannot_be_backed_up_is_left_as_dotenvx_wrote_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """With no backup, putting the keys file back could delete the key the env file needs."""
    env_file, keys_file = _setup(tmp_path, keys=f"{NAME}={K1}\n")

    def no_backup(self: EnvKeysFile) -> Path:
        raise OSError("No space left on device")

    monkeypatch.setattr(EnvKeysFile, "create_backup", no_backup)
    wrapper, _ = _wrapper(_replace_key_and_env_file)

    with pytest.raises(DotenvxError, match="left as dotenvx wrote it"):
        wrapper.encrypt(env_file)

    assert keys_file.read_text(encoding="utf-8") == f"{NAME}={K2}\n"


def test_a_file_that_cannot_be_written_is_a_clean_error(tmp_path: Path, monkeypatch):
    """The seeded header cannot be written: a DotenvxError, not a raw OSError."""
    env_file, _ = _setup(tmp_path, keys=f"{NAME}={K1}\n")
    before = env_file.read_bytes()
    real_replace = Path.replace

    def read_only(self: Path, target):
        # Files are replaced whole (a temp file renamed over them): fail that rename.
        if Path(target) == env_file:
            raise PermissionError(13, "Permission denied")
        return real_replace(self, target)

    monkeypatch.setattr(Path, "replace", read_only)
    wrapper, seen = _wrapper(_encrypt_values)

    with pytest.raises(DotenvxError, match=r"Cannot write .*Permission denied"):
        wrapper.encrypt(env_file)

    assert seen == []
    assert env_file.read_bytes() == before


def _header(name: str, public_key: str, filename: str) -> str:
    return (
        "#/-------------------[DOTENV_PUBLIC_KEY]--------------------/\n"
        "#/            public-key encryption for .env files          /\n"
        "#/       [how it works](https://dotenvx.com/encryption)     /\n"
        "#/----------------------------------------------------------/\n"
        f'{name}="{public_key}"\n\n# {filename}\n'
    )


def test_a_stale_header_with_another_key_is_kept_and_refused(tmp_path: Path):
    """Ciphertext next to another key's header: that may be the values' key, so refuse."""
    own = _header("DOTENV_PUBLIC_KEY_PRODUCTION", PUB1, ".env.production")
    stale = _header("DOTENV_PUBLIC_KEY_STAGING", PUB2, ".env.staging")
    env_file, keys_file = _setup(
        tmp_path, env_bytes=(own + stale + "A=encrypted:abc\nB=2\n").encode(), keys=f"{NAME}={K1}\n"
    )
    before = (env_file.read_bytes(), keys_file.read_bytes())
    wrapper, seen = _wrapper(_encrypt_values)

    with pytest.raises(DotenvxKeyError, match="encrypted with another public key"):
        wrapper.encrypt(env_file)

    assert seen == []
    assert (env_file.read_bytes(), keys_file.read_bytes()) == before


def test_a_stale_header_with_the_same_key_is_dropped(tmp_path: Path):
    own = _header("DOTENV_PUBLIC_KEY_PRODUCTION", PUB1, ".env.production")
    stale = _header("DOTENV_PUBLIC_KEY_STAGING", PUB1, ".env.staging")
    text = own + stale + "A=encrypted:abc\n"

    cleaned = DotenvxWrapper._clean_mismatched_header_text(text, ".env.production")

    assert cleaned == own + "A=encrypted:abc\n"


@pytest.mark.parametrize("opening", ["NOTE='", "NOTE='\n"], ids=["same-line", "next-line"])
def test_a_header_quoted_inside_a_value_is_left_alone(opening: str):
    """A banner inside a quoted value is the value's text, not a header to clean up."""
    own = _header("DOTENV_PUBLIC_KEY_PRODUCTION", PUB1, ".env.production")
    text = own + opening + _header("DOTENV_PUBLIC_KEY", PUB2, ".env") + "'\nA=1\n"

    assert DotenvxWrapper._clean_mismatched_header_text(text, ".env.production") == text


def test_refusals_happen_before_dotenvx_and_change_nothing(tmp_path: Path):
    env_file, keys_file = _setup(tmp_path, keys=f"{NAME}={K1}\n{NAME}={K2}\n")
    before = (env_file.read_bytes(), keys_file.read_bytes())
    wrapper, seen = _wrapper(_encrypt_values)

    with pytest.raises(DotenvxKeyError, match="holds 2 different keys"):
        wrapper.encrypt(env_file)

    assert seen == []
    assert (env_file.read_bytes(), keys_file.read_bytes()) == before


@pytest.mark.parametrize(
    ("make_keys", "message"),
    [
        (lambda path: path.mkdir(), "Cannot read the keys file"),
        (lambda path: path.write_bytes(b"DOTENV_PRIVATE_KEY=caf\xe9\n"), "is not valid UTF-8"),
    ],
    ids=["directory", "non-utf8"],
)
def test_an_unreadable_keys_file_is_a_clean_dotenvx_error(tmp_path: Path, make_keys, message):
    """B2: a directory or non-UTF-8 keys file never escapes as a traceback."""
    env_file, keys_file = _setup(tmp_path)
    make_keys(keys_file)
    wrapper, seen = _wrapper(_encrypt_values)

    with pytest.raises(DotenvxError, match=message):
        wrapper.encrypt(env_file)

    assert seen == []


def test_a_non_utf8_env_file_is_refused_before_dotenvx(tmp_path: Path):
    env_file, _ = _setup(tmp_path, env_bytes=b"A=caf\xe9\n")
    wrapper, seen = _wrapper(_encrypt_values)

    with pytest.raises(DotenvxError, match="not valid UTF-8"):
        wrapper.encrypt(env_file)

    assert seen == []
    assert env_file.read_bytes() == b"A=caf\xe9\n"


def test_snapshot_reports_an_unreadable_env_file(tmp_path: Path):
    env_dir = tmp_path / ".env.production"
    env_dir.mkdir()
    with pytest.raises(DotenvxError, match="Cannot read"):
        _EncryptSnapshot.take(env_dir, tmp_path / ".env.keys")


def test_backend_turns_a_key_refusal_into_a_failed_result(tmp_path: Path, monkeypatch):
    """The garbage-key case fails closed with an accurate message, not a traceback."""
    env_file, keys_file = _setup(tmp_path, keys="garbage\nDOTENV_PRIVATE_KEY_PRODUCTION=zzz\n")
    backend = DotenvxEncryptionBackend()
    wrapper, seen = _wrapper(_encrypt_values)
    monkeypatch.setattr(backend, "_get_wrapper", lambda: wrapper)
    monkeypatch.setattr(backend, "is_installed", lambda: True)

    result = backend.encrypt(env_file, keys_file=keys_file, environment="production")

    assert result.success is False
    assert "is not a valid dotenvx key" in result.message
    assert seen == []


# --- normalize_dotenvx_metadata edge cases --------------------------------------


def test_normalize_puts_the_keys_file_back_when_the_env_write_fails(tmp_path: Path, monkeypatch):
    env_file = tmp_path / "postgresql.env"
    env_file.write_text("# postgresql.env\nA=1\n", encoding="utf-8")
    keys_file = tmp_path / ".env.keys"
    keys_file.write_text("# postgresql.env\nDOTENV_PRIVATE_KEY_POSTGRESQLDEVELOPMENT=k\n")
    keys_before = keys_file.read_bytes()
    env_before = env_file.read_bytes()
    real_replace = Path.replace

    def failing_replace(self: Path, target):
        if Path(target) == env_file:
            raise OSError("disk full")
        return real_replace(self, target)

    monkeypatch.setattr(Path, "replace", failing_replace)

    with pytest.raises(OSError, match="disk full"):
        normalize_dotenvx_metadata(env_file, keys_file, "production")

    assert keys_file.read_bytes() == keys_before
    assert env_file.read_bytes() == env_before
    assert sorted(path.name for path in tmp_path.iterdir()) == [".env.keys", "postgresql.env"]


@pytest.mark.parametrize(
    "keys_text",
    [
        "# postgresql.env\n# another comment\nDOTENV_PRIVATE_KEY_X=k\n",
        "# postgresql.env\nNOT_A_KEY=1\n",
        "# postgresql.env\n\n",
    ],
    ids=["comment-ends-search", "non-key-line", "nothing-after"],
)
def test_normalize_leaves_keys_alone_without_a_generated_key(tmp_path: Path, keys_text: str):
    env_file = tmp_path / "postgresql.env"
    env_file.write_text("A=1\n", encoding="utf-8")
    keys_file = tmp_path / ".env.keys"
    keys_file.write_text(keys_text, encoding="utf-8")

    normalize_dotenvx_metadata(env_file, keys_file, "production")

    assert keys_file.read_text(encoding="utf-8") == keys_text


def test_normalize_leaves_the_lines_of_a_quoted_value_alone(tmp_path: Path):
    """A value read across lines may hold header-like text: it is the value, never renamed."""
    env_file = tmp_path / "postgresql.env"
    value = 'NOTE="first\n# postgresql.env\nDOTENV_PUBLIC_KEY_POSTGRESQLDEVELOPMENT=x\nlast"\n'
    env_file.write_bytes(
        ('DOTENV_PUBLIC_KEY_POSTGRESQLDEVELOPMENT="03ab"\n\n# postgresql.env\n' + value).encode(
            "utf-8"
        )
    )

    normalize_dotenvx_metadata(env_file, tmp_path / ".env.keys", "production")

    assert env_file.read_bytes().decode("utf-8") == (
        'DOTENV_PUBLIC_KEY_PRODUCTION="03ab"\n\n# .env.production\n' + value
    )


def test_normalize_only_renames_the_comment_of_an_already_canonical_key(tmp_path: Path):
    env_file = tmp_path / "postgresql.env"
    env_file.write_text("A=1\n", encoding="utf-8")
    keys_file = tmp_path / ".env.keys"
    keys_file.write_text(f"# postgresql.env\n{NAME}={K1}\n", encoding="utf-8")

    normalize_dotenvx_metadata(env_file, keys_file, "production")

    assert keys_file.read_text(encoding="utf-8") == f"# .env.production\n{NAME}={K1}\n"


def test_normalize_refuses_when_the_canonical_name_already_holds_two_keys(tmp_path: Path):
    env_file = tmp_path / "postgresql.env"
    env_file.write_text("A=1\n", encoding="utf-8")
    keys_file = tmp_path / ".env.keys"
    keys_file.write_text(
        f"{NAME}={K1}\n{NAME}={K2}\n# postgresql.env\nDOTENV_PRIVATE_KEY_POSTGRESQLDEVELOPMENT={K1}\n",
        encoding="utf-8",
    )
    before = keys_file.read_bytes()

    with pytest.raises(DotenvxKeyError):
        normalize_dotenvx_metadata(env_file, keys_file, "production")

    assert keys_file.read_bytes() == before
