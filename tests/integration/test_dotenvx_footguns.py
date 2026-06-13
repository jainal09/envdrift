"""Regression tests for dotenvx key-file and filename foot-guns (#474).

These drive the real ``envdrift`` CLI as a subprocess and the real ``dotenvx``
binary — no mocking of the behavior under test:

- ``envdrift encrypt .env.keys`` must refuse to encrypt the dotenvx private-key
  store instead of irreversibly locking out every encrypted file in the project
  under a clean ``[OK]``/exit 0.
- ``envdrift decrypt .env.keys`` must refuse the key store by name instead of
  reporting a misleading no-op.
- A leading-dash filename (``-dash.env``) must be passed to dotenvx in a
  dash-proof form: dotenvx's commander CLI otherwise eats it as bundled flags,
  fabricates a different file full of placeholder secrets, and leaves a junk
  entry in ``.env.keys``.
- ``.env.keys`` files written by envdrift must byte-match the header the real
  dotenvx binary writes (format-preservation contract of ``EnvKeysFile``).

Tests skip (rather than fail) when the ``dotenvx`` binary is not installed.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration]


@pytest.fixture
def dotenvx_on_path() -> str:
    """Return the path to a real ``dotenvx`` binary or skip the test."""
    path = shutil.which("dotenvx")
    if path is None:
        pytest.skip("dotenvx binary not found on PATH")
    return path


def _run_envdrift(
    args: list[str],
    *,
    cwd: Path,
    pythonpath: str,
) -> subprocess.CompletedProcess[str]:
    """Run the real envdrift CLI as a subprocess in ``cwd``."""
    env = os.environ.copy()
    env["PYTHONPATH"] = pythonpath
    return subprocess.run(  # nosec B603
        [sys.executable, "-m", "envdrift.cli", *args],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )


def _flat(text: str) -> str:
    """Normalize Rich output (line wraps, padding) for substring assertions."""
    return " ".join(text.split())


def test_encrypt_cli_refuses_env_keys_store(
    tmp_path: Path,
    integration_pythonpath: str,
    dotenvx_on_path: str,
) -> None:
    """#474: ``envdrift encrypt .env.keys`` must refuse, preserving the keys.

    Encrypting the private-key store rewrites ``DOTENV_PRIVATE_KEY*`` as
    ciphertext under a brand-new keypair whose private half is never persisted,
    permanently locking out every encrypted file in the project — previously
    under a clean ``[OK]`` and exit 0.
    """
    work = tmp_path / "proj"
    work.mkdir()
    (work / ".env").write_text("API_KEY=topvalue123\n", encoding="utf-8")

    encrypted = _run_envdrift(["encrypt", ".env"], cwd=work, pythonpath=integration_pythonpath)
    assert encrypted.returncode == 0, encrypted.stdout + encrypted.stderr
    keys_file = work / ".env.keys"
    assert keys_file.exists()
    keys_before = keys_file.read_text(encoding="utf-8")

    result = _run_envdrift(["encrypt", ".env.keys"], cwd=work, pythonpath=integration_pythonpath)
    output = _flat(result.stdout + result.stderr)

    assert result.returncode == 1, f"must refuse to encrypt the key store: {output}"
    assert "refusing" in output.lower(), output
    assert "private-key store" in output, output
    # The key store is byte-for-byte untouched — no new keypair, no ciphertext.
    assert keys_file.read_text(encoding="utf-8") == keys_before

    # The real post-condition: the project's encrypted file is still decryptable.
    decrypted = _run_envdrift(["decrypt", ".env"], cwd=work, pythonpath=integration_pythonpath)
    assert decrypted.returncode == 0, decrypted.stdout + decrypted.stderr
    assert "API_KEY=topvalue123" in (work / ".env").read_text(encoding="utf-8")


def test_decrypt_cli_refuses_env_keys_store(
    tmp_path: Path,
    integration_pythonpath: str,
    dotenvx_on_path: str,
) -> None:
    """#474: ``envdrift decrypt .env.keys`` refuses the key store by name."""
    work = tmp_path / "proj"
    work.mkdir()
    (work / ".env").write_text("API_KEY=topvalue123\n", encoding="utf-8")

    encrypted = _run_envdrift(["encrypt", ".env"], cwd=work, pythonpath=integration_pythonpath)
    assert encrypted.returncode == 0, encrypted.stdout + encrypted.stderr
    keys_file = work / ".env.keys"
    keys_before = keys_file.read_text(encoding="utf-8")

    result = _run_envdrift(["decrypt", ".env.keys"], cwd=work, pythonpath=integration_pythonpath)
    output = _flat(result.stdout + result.stderr)

    assert result.returncode == 1, f"must refuse to decrypt the key store: {output}"
    assert "refusing" in output.lower(), output
    assert keys_file.read_text(encoding="utf-8") == keys_before


def test_encrypt_leading_dash_filename_roundtrips(
    tmp_path: Path,
    integration_pythonpath: str,
    dotenvx_on_path: str,
) -> None:
    """#474: a leading-dash filename must encrypt and decrypt cleanly.

    Previously ``envdrift encrypt -- -dash.env`` passed ``-dash.env`` as bare
    argv to dotenvx, whose commander CLI misparsed it as bundled flags: the real
    file was untouched, a fabricated ``-ash.env`` full of placeholder secrets
    appeared, ``.env.keys`` gained a junk ``DOTENV_PRIVATE_KEY_-ASH...`` entry,
    and envdrift blamed a "missing or invalid" encryption key.
    """
    work = tmp_path / "dash"
    work.mkdir()
    dash_file = work / "-dash.env"
    dash_file.write_text("API_KEY=abc123\n", encoding="utf-8")

    result = _run_envdrift(
        ["encrypt", "--", "-dash.env"], cwd=work, pythonpath=integration_pythonpath
    )
    output = _flat(result.stdout + result.stderr)

    assert result.returncode == 0, f"encrypt must succeed for -dash.env: {output}"
    content = dash_file.read_text(encoding="utf-8")
    assert "encrypted:" in content, content
    assert "abc123" not in content, "plaintext must not survive encryption"
    # No fabricated sibling file from the flag misparse (e.g. "-ash.env").
    assert not (work / "-ash.env").exists()
    assert sorted(p.name for p in work.iterdir()) == ["-dash.env", ".env.keys"]

    decrypted = _run_envdrift(
        ["decrypt", "--", "-dash.env"], cwd=work, pythonpath=integration_pythonpath
    )
    assert decrypted.returncode == 0, decrypted.stdout + decrypted.stderr
    assert "API_KEY=abc123" in dash_file.read_text(encoding="utf-8")


def test_envdrift_written_env_keys_header_matches_dotenvx(
    tmp_path: Path,
    dotenvx_on_path: str,
) -> None:
    """#474: the ``DOTENVX_HEADER`` constant byte-matches real dotenvx output.

    ``EnvKeysFile`` claims dotenvx format preservation, but envdrift-written
    ``.env.keys`` headers previously ended each line in ``\\#`` (and dropped the
    padding) where dotenvx writes ``/`` — so a later dotenvx append produced a
    file with two visibly different header styles.
    """
    from envdrift.integrations.dotenvx import DotenvxWrapper
    from envdrift.sync.operations import DOTENVX_HEADER, EnvKeysFile

    real_dir = tmp_path / "real"
    real_dir.mkdir()
    env_file = real_dir / ".env"
    env_file.write_text("API_KEY=abc123\n", encoding="utf-8")

    DotenvxWrapper(auto_install=False).encrypt(env_file, cwd=real_dir)
    real_lines = (real_dir / ".env.keys").read_text(encoding="utf-8").splitlines()

    # The constant matches the real binary's four header lines byte-for-byte.
    assert DOTENVX_HEADER.splitlines() == real_lines[:4]

    # An envdrift-written .env.keys reproduces the same header block, including
    # the blank separator line dotenvx leaves after it.
    ours = tmp_path / "ours" / ".env.keys"
    EnvKeysFile(ours).write_key("DOTENV_PRIVATE_KEY_PRODUCTION", "0" * 64)
    ours_lines = ours.read_text(encoding="utf-8").splitlines()
    assert ours_lines[:5] == real_lines[:5]
