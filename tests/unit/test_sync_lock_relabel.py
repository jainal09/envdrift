"""Edge cases of lock's key re-label (B5): find the file's key by its public key.

The CLI flow (re-label, dry run, warning, idempotence) is covered in
tests/unit/coverage/test_cov_cli_commands_sync.py and, against the real dotenvx
binary, in tests/integration/test_dotenvx_key_reuse.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.cli_commands.sync_lock_relabel import relabel_dotenvx_key
from tests.helpers import DOTENVX_KEY_PAIRS

(K1, PUB1), (K2, PUB2) = DOTENVX_KEY_PAIRS[0], DOTENVX_KEY_PAIRS[1]
EXPECTED = "DOTENV_PRIVATE_KEY_PRODUCTION"


def _files(tmp_path: Path, env_text: str, keys_text: str | None) -> tuple[Path, Path]:
    # Bytes, so Windows newline translation cannot change the line ends under test.
    env_file = tmp_path / ".env.production"
    env_file.write_bytes(env_text.encode("utf-8"))
    keys_file = tmp_path / ".env.keys"
    if keys_text is not None:
        keys_file.write_bytes(keys_text.encode("utf-8"))
    return env_file, keys_file


@pytest.mark.parametrize(
    "keys_text",
    [None, f"{EXPECTED}={K1}\n", ""],
    ids=["no-keys-file", "expected-already-held", "no-other-key"],
)
def test_nothing_to_relabel(tmp_path: Path, keys_text: str | None):
    env_file, keys_file = _files(tmp_path, f'DOTENV_PUBLIC_KEY_STAGING="{PUB1}"\n', keys_text)

    outcome = relabel_dotenvx_key(env_file, keys_file, EXPECTED, apply=True)

    assert outcome.action == "none"


def test_a_value_dotenvx_cannot_use_is_not_a_source(tmp_path: Path):
    env_file, keys_file = _files(
        tmp_path, f'DOTENV_PUBLIC_KEY_STAGING="{PUB1}"\n', "DOTENV_PRIVATE_KEY_STAGING=garbage\n"
    )

    outcome = relabel_dotenvx_key(env_file, keys_file, EXPECTED, apply=True)

    assert outcome.action == "no_key"
    assert "holds no key for this file" in outcome.message


def test_two_matching_keys_are_ambiguous(tmp_path: Path):
    env_file, keys_file = _files(
        tmp_path,
        f'DOTENV_PUBLIC_KEY_STAGING="{PUB1}"\nDOTENV_PUBLIC_KEY_QA="{PUB2}"\n',
        f"DOTENV_PRIVATE_KEY_STAGING={K1}\nDOTENV_PRIVATE_KEY_QA={K2}\n",
    )
    before = (env_file.read_bytes(), keys_file.read_bytes())

    outcome = relabel_dotenvx_key(env_file, keys_file, EXPECTED, apply=True)

    assert outcome.action == "failed"
    assert "2 different keys" in outcome.message
    assert (env_file.read_bytes(), keys_file.read_bytes()) == before


def test_an_unreadable_keys_file_fails_cleanly(tmp_path: Path):
    env_file, keys_file = _files(tmp_path, "A=encrypted:x\n", None)
    keys_file.write_bytes(b"DOTENV_PRIVATE_KEY_STAGING=caf\xe9\n")

    outcome = relabel_dotenvx_key(env_file, keys_file, EXPECTED, apply=True)

    assert outcome.action == "failed"
    assert "cannot read" in outcome.message


def _renamed_pair(tmp_path: Path) -> tuple[Path, Path, dict[Path, bytes]]:
    env_file, keys_file = _files(
        tmp_path,
        f'DOTENV_PUBLIC_KEY_STAGING="{PUB1}"\n\n# .env.staging\nA=encrypted:x\n',
        f"DOTENV_PRIVATE_KEY_STAGING={K1}\n",
    )
    return env_file, keys_file, {env_file: env_file.read_bytes(), keys_file: keys_file.read_bytes()}


def test_a_failed_write_puts_both_files_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    env_file, keys_file, before = _renamed_pair(tmp_path)
    real_replace = Path.replace

    def failing_replace(self: Path, target):
        # The keys file is written first; the env file's rename then fails.
        if Path(target) == env_file:
            raise OSError("disk full")
        return real_replace(self, target)

    monkeypatch.setattr(Path, "replace", failing_replace)

    outcome = relabel_dotenvx_key(env_file, keys_file, EXPECTED, apply=True)

    assert outcome.action == "failed"
    assert "disk full" in outcome.message
    assert "could not put back" not in outcome.message
    assert {path: path.read_bytes() for path in before} == before
    # A failed write leaves no temp file next to the keys.
    assert sorted(path.name for path in tmp_path.iterdir()) == [".env.keys", ".env.production"]


def test_a_failed_put_back_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """When the keys file cannot be put back, the message says so instead of "nothing"."""
    env_file, keys_file, _ = _renamed_pair(tmp_path)
    real_replace = Path.replace
    keys_writes = 0

    def failing_replace(self: Path, target):
        nonlocal keys_writes
        if Path(target) == env_file:
            raise OSError("disk full")
        keys_writes += 1
        if keys_writes > 1:
            raise OSError("read-only now")
        return real_replace(self, target)

    monkeypatch.setattr(Path, "replace", failing_replace)

    outcome = relabel_dotenvx_key(env_file, keys_file, EXPECTED, apply=True)

    assert outcome.action == "failed"
    assert "disk full" in outcome.message
    assert f"could not put back {keys_file} (read-only now)" in outcome.message


def test_relabel_renames_the_header_and_its_filename_line(tmp_path: Path):
    env_file, keys_file = _files(
        tmp_path,
        f'export DOTENV_PUBLIC_KEY_STAGING="{PUB1}" # -fk .env.keys\r\n\r\n# .env.staging\r\nA=encrypted:x\r\n',
        f"# .env.staging\nDOTENV_PRIVATE_KEY_STAGING={K1}\n",
    )

    outcome = relabel_dotenvx_key(env_file, keys_file, EXPECTED, apply=True)

    assert outcome.action == "relabeled"
    assert outcome.old_name == "DOTENV_PRIVATE_KEY_STAGING"
    assert (
        env_file.read_bytes()
        == (
            f'export DOTENV_PUBLIC_KEY_PRODUCTION="{PUB1}" # -fk .env.keys\r\n'
            "\r\n# .env.production\r\nA=encrypted:x\r\n"
        ).encode()
    )
    assert keys_file.read_text(encoding="utf-8") == (
        f"# .env.staging\nDOTENV_PRIVATE_KEY_STAGING={K1}\n\n# .env.production\n{EXPECTED}={K1}\n"
    )
