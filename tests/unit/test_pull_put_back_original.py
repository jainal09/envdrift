"""A pulled file whose decrypt fails gets back the bytes it had before pull rewrote its header.

pull rewrites a custom env_file's dotenvx header to the mapping's environment before the decrypt,
so the decrypt's own restore put back the rewritten header, and the message said the file "was
left as it was" (#962). The end-to-end case is in tests/integration/test_pull_protection_e2e.py.
"""

from __future__ import annotations

import os
from pathlib import Path

from envdrift.cli_commands.sync_helpers import _DecryptTask, _put_back_original
from envdrift.sync.config import ServiceMapping
from tests.helpers import file_size_limit


def _task(env_file: Path, original: bytes | None) -> _DecryptTask:
    mapping = ServiceMapping(secret_name="app", folder_path=env_file.parent)
    return _DecryptTask(mapping=mapping, env_file=env_file, original=original)


def test_the_original_bytes_are_written_back(tmp_path: Path) -> None:
    env_file = tmp_path / "custom.env"
    env_file.write_bytes(b"# .env.production\n")

    assert _put_back_original(_task(env_file, b"# custom.env\n")) == ""
    assert env_file.read_bytes() == b"# custom.env\n"


def test_a_file_already_as_it_was_is_not_written(tmp_path: Path) -> None:
    env_file = tmp_path / "custom.env"
    env_file.write_bytes(b"# custom.env\n")
    os.utime(env_file, ns=(1_000_000_000, 1_000_000_000))

    assert _put_back_original(_task(env_file, b"# custom.env\n")) == ""
    assert env_file.stat().st_mtime_ns == 1_000_000_000


def test_no_original_leaves_the_file_alone(tmp_path: Path) -> None:
    env_file = tmp_path / "custom.env"
    env_file.write_bytes(b"# .env.production\n")

    assert _put_back_original(_task(env_file, None)) == ""
    assert env_file.read_bytes() == b"# .env.production\n"


def test_a_file_that_cannot_be_read_is_reported(tmp_path: Path) -> None:
    missing = tmp_path / "gone" / "custom.env"

    note = _put_back_original(_task(missing, b"# custom.env\n"))

    assert note.startswith(" envdrift could not put back its dotenvx header: ")
    assert not missing.exists()


def test_a_write_back_that_fails_part_way_leaves_the_file_as_it_was(tmp_path: Path) -> None:
    """The read succeeds and the write fails (a full disk, a file size limit).

    Written in place, the file was truncated first and then cut short at the limit, so
    it held neither the decrypt's output nor its original bytes.
    """
    env_file = tmp_path / "custom.env"
    rewritten = b"# .env.production\n" + b"API_TOKEN=encrypted:QUJD\n" * 100
    env_file.write_bytes(rewritten)
    original = b"# custom.env\n" + b"API_TOKEN=encrypted:QUJD\n" * 4000

    with file_size_limit(len(original) // 2):
        note = _put_back_original(_task(env_file, original))

    assert note.startswith(" envdrift could not put back its dotenvx header: ")
    assert env_file.read_bytes() == rewritten
    assert [p.name for p in tmp_path.iterdir()] == ["custom.env"]
