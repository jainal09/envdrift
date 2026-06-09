"""Real-outcome bench for the dotenvx ``encrypt`` seam (envdrift #443).

Every test drives the REAL encryption seam (``DotenvxEncryptionBackend`` over the
real ``dotenvx`` binary) and asserts the TRUE on-disk state after the call —
never just the returned ``success`` flag or an ``[OK]`` message. This is the
discipline the adversarial sweep showed was missing:

* dotenvx **fabricates** a placeholder-secrets template (``HELLO``,
  ``AWS_ACCESS_KEY_ID`` …) when handed an empty / content-free file, and exits 0;
* dotenvx exits 0 **without encrypting** when the private key is missing or
  malformed (``.env.keys`` is a directory, garbage, or a mismatched key).

The pre-#443 backend trusted the exit code and reported ``success=True`` in both
cases, so the only way to catch the regression is to re-read the file. Tests that
need the real binary skip-gate cleanly when it is absent.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from envdrift.encryption.dotenvx import DotenvxEncryptionBackend

# Mark all tests in this module
pytestmark = [pytest.mark.integration]


@pytest.fixture
def dotenvx_on_path() -> None:
    """Skip the test if the real ``dotenvx`` binary is not installed."""
    if shutil.which("dotenvx") is None:
        pytest.skip("dotenvx binary not found on PATH")


# --- Empty / content-free input must NOT fabricate secrets (#1, #8, #23) -------
# The empty-variable guard runs before dotenvx is invoked, so these assert the
# guard itself and do not require the binary.


def test_encrypt_empty_file_refuses_and_leaves_it_untouched(tmp_path: Path) -> None:
    """#1/#8: a 0-byte .env must be declined, not scaffolded into a fake template."""
    env_file = tmp_path / ".env"
    env_file.write_text("")  # genuinely 0 bytes

    result = DotenvxEncryptionBackend().encrypt(env_file)

    assert result.success is False
    assert "nothing to encrypt" in result.message.lower()
    # The original empty file is byte-identical — NOT a 3KB fabricated template.
    after = env_file.read_text()
    assert after == ""
    assert "HELLO" not in after
    assert "AWS_ACCESS_KEY_ID" not in after
    # No private-key file littered for a file that was never encrypted.
    assert not (tmp_path / ".env.keys").exists()


def test_encrypt_blank_lines_only_file_refuses(tmp_path: Path) -> None:
    """#8: a file of only blank lines carries no variable — decline, don't fabricate."""
    env_file = tmp_path / ".env"
    env_file.write_text("\n\n\n\n")
    before = env_file.read_text()

    result = DotenvxEncryptionBackend().encrypt(env_file)

    assert result.success is False
    assert env_file.read_text() == before
    assert not (tmp_path / ".env.keys").exists()


def test_encrypt_comment_only_file_refuses_instead_of_noop_ok(tmp_path: Path) -> None:
    """#23: a comment-only file used to print [OK] while doing nothing — now declined."""
    env_file = tmp_path / ".env"
    env_file.write_text("# only comments here\n# nothing else\n")
    before = env_file.read_text()

    result = DotenvxEncryptionBackend().encrypt(env_file)

    assert result.success is False
    assert env_file.read_text() == before  # byte-identical, no silent no-op
    assert not (tmp_path / ".env.keys").exists()


def test_encrypt_file_of_only_non_identifier_keys_is_not_refused(
    tmp_path: Path, dotenvx_on_path: None
) -> None:
    """#444 review regression: non-identifier keys are content, not emptiness.

    A file whose only keys are non-identifier (``X-API-KEY``, ``1PASSWORD``) parses
    to zero *strict-parser* variables, so an EnvParser-based empty-guard would
    wrongly refuse it and leave real secrets unencrypted. The guard counts raw
    assignments instead, so this file is encrypted normally.
    """
    env_file = tmp_path / ".env"
    env_file.write_text("X-API-KEY=supersecret123\n1PASSWORD=hunter2\n", encoding="utf-8")

    result = DotenvxEncryptionBackend().encrypt(env_file, cwd=tmp_path)

    assert result.success is True, result.message
    on_disk = env_file.read_text()
    assert "encrypted:" in on_disk
    assert "supersecret123" not in on_disk
    assert "hunter2" not in on_disk


# --- Silent crypto-seam failure must be reported, not reported as success ------
# dotenvx exits 0 but leaves plaintext when the key is broken; the backend must
# verify the on-disk outcome and report failure (#4, #5, #6, #7).


def test_encrypt_with_keys_dir_reports_failure_not_success(
    tmp_path: Path, dotenvx_on_path: None
) -> None:
    """#4/#7: .env.keys as a directory -> dotenvx can't write its key, exits 0, file stays plaintext."""
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=supersecret123\nDB_PASS=hunter2\n")
    (tmp_path / ".env.keys").mkdir()  # dotenvx cannot write a key here

    result = DotenvxEncryptionBackend().encrypt(env_file, cwd=tmp_path)

    # The fix: we must NOT claim success while the secret sits in plaintext.
    assert result.success is False
    assert "did not take effect" in result.message.lower()
    # On-disk truth: the secret really is still plaintext (we are not lying).
    assert "API_KEY=supersecret123" in env_file.read_text()


def test_encrypt_with_garbage_keys_file_reports_failure(
    tmp_path: Path, dotenvx_on_path: None
) -> None:
    """#5: a malformed .env.keys -> nothing gets encrypted, but exit code is 0."""
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=supersecret123\nDB_PASS=hunter2\n")
    (tmp_path / ".env.keys").write_text("garbage not a key\nDOTENV_PRIVATE_KEY=zzz_not_hex\n")

    result = DotenvxEncryptionBackend().encrypt(env_file, cwd=tmp_path)

    assert result.success is False
    on_disk = env_file.read_text()
    assert "API_KEY=supersecret123" in on_disk
    assert "encrypted:" not in on_disk


def test_reencrypt_with_corrupted_keys_does_not_hide_plaintext_leak(
    tmp_path: Path, dotenvx_on_path: None
) -> None:
    """#6: corrupt the key, append a new plaintext secret -> the leak must be reported, not OK'd."""
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=supersecret123\n")

    first = DotenvxEncryptionBackend().encrypt(env_file, cwd=tmp_path)
    assert first.success is True  # valid first encrypt

    # Corrupt the key file, then add a brand-new plaintext secret.
    (tmp_path / ".env.keys").write_text("not a key @@@\nDOTENV_PRIVATE_KEY=NOTHEX_zzz\n")
    env_file.write_text(env_file.read_text() + "NEW_SECRET=plaintextleak999\n")

    result = DotenvxEncryptionBackend().encrypt(env_file, cwd=tmp_path)

    assert result.success is False  # must not report OK while a plaintext secret survives
    assert "NEW_SECRET=plaintextleak999" in env_file.read_text()


# --- Control: the happy path must still succeed (no false-positive) ------------


def test_encrypt_real_file_succeeds_and_removes_all_plaintext(
    tmp_path: Path, dotenvx_on_path: None
) -> None:
    """The outcome check must NOT false-fail a genuine encryption."""
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=supersecret123\nDB_PASS=hunter2\n")

    result = DotenvxEncryptionBackend().encrypt(env_file, cwd=tmp_path)

    assert result.success is True
    on_disk = env_file.read_text()
    assert "encrypted:" in on_disk
    # The plaintext values are gone from disk.
    assert "supersecret123" not in on_disk
    assert "hunter2" not in on_disk
