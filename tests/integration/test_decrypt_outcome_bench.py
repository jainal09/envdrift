"""Real-outcome bench for the dotenvx ``decrypt`` seam (envdrift #443).

Every test drives the REAL decryption seam (``DotenvxEncryptionBackend`` over the
real ``dotenvx`` binary) and asserts the TRUE on-disk state. The adversarial
sweep showed the pre-#443 backend reported ``[OK] Decrypted`` unconditionally:

* on a plaintext file it claimed a decryption happened (and dotenvx's line-ending
  normalisation silently rewrote bytes);
* on a binary blob it corrupted the file outright while still exiting 0.

The fix reports an honest no-op (``changed=False``) and never invokes dotenvx on
a file that holds no ciphertext, so a non-encrypted/binary file is left byte-for-
byte untouched. Tests that need the real binary skip-gate cleanly when absent.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from envdrift.encryption.base import EncryptionBackendError
from envdrift.encryption.dotenvx import DotenvxEncryptionBackend
from envdrift.encryption.sops import SOPSEncryptionBackend

# Mark all tests in this module
pytestmark = [pytest.mark.integration]


@pytest.fixture
def dotenvx_on_path() -> None:
    """Skip the test if the real ``dotenvx`` binary is not installed."""
    if shutil.which("dotenvx") is None:
        pytest.skip("dotenvx binary not found on PATH")


@pytest.fixture
def sops_on_path() -> None:
    """Skip the test if the real ``sops`` binary is not installed."""
    if shutil.which("sops") is None:
        pytest.skip("sops binary not found on PATH")


def test_decrypt_sops_binary_blob_does_not_crash(tmp_path: Path, sops_on_path: None) -> None:
    """#14: decrypting a binary blob with the SOPS backend must not raise an
    uncaught UnicodeDecodeError while decoding sops' (non-UTF-8) stderr.

    sops._run reads the subprocess with encoding='utf-8', errors='replace', so a
    non-UTF-8 stderr byte degrades to U+FFFD instead of crashing. sops rejects
    the blob; the point is it fails *cleanly* and leaves the file intact.
    """
    env_file = tmp_path / ".env"
    blob = bytes(range(256)) * 4  # NUL + non-UTF-8 bytes
    env_file.write_bytes(blob)

    backend = SOPSEncryptionBackend()
    try:
        result = backend.decrypt(env_file, cwd=tmp_path)
        assert result.success is False
    except EncryptionBackendError:
        pass  # a clean, typed failure is the acceptable outcome
    # No silent corruption: the blob is byte-for-byte intact.
    assert env_file.read_bytes() == blob


# --- A non-encrypted file is an honest no-op, never mutated --------------------
# These assert the guard, which runs before dotenvx is invoked (no binary needed).


def test_decrypt_plaintext_file_is_honest_noop(tmp_path: Path) -> None:
    """#18: a plaintext .env reports 'nothing to decrypt', not '[OK] Decrypted'."""
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=plainvalue\nPORT=8080\n", encoding="utf-8")
    before = env_file.read_bytes()

    result = DotenvxEncryptionBackend().decrypt(env_file)

    assert result.success is True
    assert result.changed is False
    assert "nothing to decrypt" in result.message.lower()
    # The file is byte-identical: no spurious rewrite.
    assert env_file.read_bytes() == before


def test_decrypt_crlf_plaintext_file_leaves_bytes_untouched(tmp_path: Path) -> None:
    """#15: a non-encrypted CRLF file must not have its CR bytes stripped."""
    env_file = tmp_path / ".env"
    env_file.write_bytes(b"API_KEY=plainvalue\r\nPORT=8080\r\n")
    before = env_file.read_bytes()

    result = DotenvxEncryptionBackend().decrypt(env_file)

    assert result.changed is False
    assert env_file.read_bytes() == before  # CRLF preserved exactly


def test_decrypt_binary_blob_is_not_corrupted(tmp_path: Path) -> None:
    """#2: a binary blob must not be corrupted (or crash) — it has no ciphertext."""
    env_file = tmp_path / ".env"
    blob = bytes(range(256)) * 4  # includes NUL and non-UTF-8 bytes
    env_file.write_bytes(blob)

    result = DotenvxEncryptionBackend().decrypt(env_file)

    assert result.success is True
    assert result.changed is False
    # The blob is byte-for-byte intact (no silent corruption, no UnicodeDecodeError).
    assert env_file.read_bytes() == blob


# --- A genuinely encrypted file round-trips; a bad key is reported -------------


def test_decrypt_encrypted_file_restores_plaintext(tmp_path: Path, dotenvx_on_path: None) -> None:
    """Control: a real encrypt→decrypt round-trip restores the plaintext."""
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=supersecret123\n", encoding="utf-8")
    backend = DotenvxEncryptionBackend()

    assert backend.encrypt(env_file, cwd=tmp_path).success is True
    assert "encrypted:" in env_file.read_text()

    result = backend.decrypt(env_file, cwd=tmp_path)

    assert result.success is True
    assert result.changed is True
    on_disk = env_file.read_text()
    assert "encrypted:" not in on_disk
    assert "API_KEY=supersecret123" in on_disk


def test_decrypt_with_corrupted_key_errors_and_preserves_ciphertext(
    tmp_path: Path, dotenvx_on_path: None
) -> None:
    """A key that cannot decrypt the ciphertext must error cleanly, not corrupt it.

    dotenvx exits non-zero with INVALID_PRIVATE_KEY here, which the wrapper turns
    into a clean ``EncryptionBackendError`` (the CLI renders it as ``[ERROR]
    Decryption failed`` + exit 1). The ciphertext on disk must be untouched.
    """
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=supersecret123\n", encoding="utf-8")
    backend = DotenvxEncryptionBackend()
    assert backend.encrypt(env_file, cwd=tmp_path).success is True

    # Corrupt the key so dotenvx cannot decrypt the ciphertext.
    (tmp_path / ".env.keys").write_text("not a key @@@\nDOTENV_PRIVATE_KEY=NOTHEX_zzz\n")

    with pytest.raises(EncryptionBackendError):
        backend.decrypt(env_file, cwd=tmp_path)

    # The ciphertext is still on disk — a failed decrypt must not corrupt it.
    assert "encrypted:" in env_file.read_text()
