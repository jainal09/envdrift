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
import re
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
    # The refusal must not blame the opposing action ("Encrypting it would...").
    assert "Encrypting" not in output, output
    assert keys_file.read_text(encoding="utf-8") == keys_before


def test_encrypt_cli_refuses_env_keys_case_variant(
    tmp_path: Path,
    integration_pythonpath: str,
    dotenvx_on_path: str,
) -> None:
    """#474: ``envdrift encrypt .env.KEYS`` is refused case-insensitively.

    On the default case-insensitive filesystems of macOS (APFS) and Windows
    (NTFS), ``.env.KEYS`` resolves to the real ``.env.keys``, so a
    case-sensitive suffix guard reproduced the exact irreversible lockout the
    guard exists to prevent. The refusal is by (casefolded) name, so it must
    hold on case-sensitive filesystems too.
    """
    work = tmp_path / "proj"
    work.mkdir()
    keys_file = work / ".env.KEYS"
    keys_content = "# .env\nDOTENV_PRIVATE_KEY=" + "b" * 64 + "\n"
    keys_file.write_text(keys_content, encoding="utf-8")

    result = _run_envdrift(["encrypt", ".env.KEYS"], cwd=work, pythonpath=integration_pythonpath)
    output = _flat(result.stdout + result.stderr)

    assert result.returncode == 1, f"must refuse the case-variant key store: {output}"
    assert "refusing" in output.lower(), output
    assert keys_file.read_text(encoding="utf-8") == keys_content


def test_encrypt_cli_refuses_renamed_key_store(
    tmp_path: Path,
    integration_pythonpath: str,
    dotenvx_on_path: str,
) -> None:
    """#474: a renamed key store is refused by its DOTENV_PRIVATE_KEY content.

    ``mv .env.keys prodkeys.env && envdrift encrypt prodkeys.env`` passes every
    name-based guard, yet encrypting it causes the same project-wide lockout:
    the private keys become ciphertext under a never-persisted keypair. The
    wrapper's content sniff must refuse it, cleanly, with the file untouched.
    """
    work = tmp_path / "proj"
    work.mkdir()
    (work / ".env").write_text("API_KEY=topvalue123\n", encoding="utf-8")

    encrypted = _run_envdrift(["encrypt", ".env"], cwd=work, pythonpath=integration_pythonpath)
    assert encrypted.returncode == 0, encrypted.stdout + encrypted.stderr

    renamed = work / "prodkeys.env"
    (work / ".env.keys").rename(renamed)
    keys_before = renamed.read_text(encoding="utf-8")

    result = _run_envdrift(["encrypt", "prodkeys.env"], cwd=work, pythonpath=integration_pythonpath)
    output = _flat(result.stdout + result.stderr)

    assert result.returncode == 1, f"must refuse the renamed key store: {output}"
    assert "refusing" in output.lower(), output
    assert "DOTENV_PRIVATE_KEY" in output, output
    assert renamed.read_text(encoding="utf-8") == keys_before

    # The real post-condition: the keys still decrypt the project's .env.
    renamed.rename(work / ".env.keys")
    decrypted = _run_envdrift(["decrypt", ".env"], cwd=work, pythonpath=integration_pythonpath)
    assert decrypted.returncode == 0, decrypted.stdout + decrypted.stderr
    assert "API_KEY=topvalue123" in (work / ".env").read_text(encoding="utf-8")


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

    The expected header block is derived from the real pinned binary's output
    (opening box line through the closing ``#/---/`` line), never from a
    hardcoded line count: dotenvx grew a fifth "ARMORED KEYS" line between
    releases, and a fixed ``[:4]`` slice silently compared the wrong lines.
    """
    from envdrift.integrations.dotenvx import DotenvxWrapper
    from envdrift.sync.operations import DOTENVX_HEADER, EnvKeysFile

    real_dir = tmp_path / "real"
    real_dir.mkdir()
    env_file = real_dir / ".env"
    env_file.write_text("API_KEY=abc123\n", encoding="utf-8")

    DotenvxWrapper(auto_install=False).encrypt(env_file, cwd=real_dir)
    real_lines = (real_dir / ".env.keys").read_text(encoding="utf-8").splitlines()

    # Locate the header block in the real binary's output: it opens with the
    # !DOTENV_PRIVATE_KEYS! box line and runs through the closing box line.
    assert real_lines[0].startswith("#/") and "DOTENV_PRIVATE_KEYS" in real_lines[0], real_lines[0]
    closing = next(
        i for i, line in enumerate(real_lines[1:], start=1) if re.fullmatch(r"#/-+/", line)
    )
    real_header = real_lines[: closing + 1]

    # The constant matches the real binary's header block byte-for-byte. If a
    # dotenvx bump changes the header, update DOTENVX_HEADER (sync/operations.py).
    assert DOTENVX_HEADER.splitlines() == real_header

    # An envdrift-written .env.keys reproduces the same header block, including
    # the blank separator line dotenvx leaves after it.
    assert real_lines[closing + 1] == ""
    ours = tmp_path / "ours" / ".env.keys"
    EnvKeysFile(ours).write_key("DOTENV_PRIVATE_KEY_PRODUCTION", "0" * 64)
    ours_lines = ours.read_text(encoding="utf-8").splitlines()
    assert ours_lines[: closing + 2] == real_lines[: closing + 2]


def test_encrypt_writes_env_keys_next_to_subdir_file(
    tmp_path: Path,
    dotenvx_on_path: str,
) -> None:
    """#566: the ``.env.keys`` key store lands next to the file, not in the cwd.

    dotenvx **v2** writes and reads ``.env.keys`` in the *process working
    directory* when ``-fk`` is omitted; **v1** kept it beside the target file.
    envdrift's per-folder key model — the sync engine,
    ``normalize_dotenvx_metadata`` and ``EnvKeysFile`` all read
    ``<folder>/.env.keys`` — depends on the beside-the-file layout, so the
    wrapper pins ``-fk`` to the sibling path. Without it a file in a subfolder
    scatters its private key into the cwd and becomes undecryptable.
    """
    from envdrift.integrations.dotenvx import DotenvxWrapper

    root = tmp_path / "root"
    sub = root / "svc"
    sub.mkdir(parents=True)
    env_file = sub / "svc.env"
    env_file.write_text("API_KEY=sekret123\n", encoding="utf-8")

    wrapper = DotenvxWrapper(auto_install=False)
    # cwd is the *root*, distinct from the file's folder, so a v2 regression
    # would drop .env.keys into root instead of svc/.
    wrapper.encrypt(env_file, cwd=root)

    assert (sub / ".env.keys").exists(), "key store must live next to the file"
    assert not (root / ".env.keys").exists(), "key store must not scatter into cwd"
    encrypted = env_file.read_text(encoding="utf-8")
    assert "encrypted:" in encrypted
    assert "sekret123" not in encrypted

    # And it round-trips: decrypt (also ``-fk``-pinned) finds the sibling store.
    wrapper.decrypt(env_file, cwd=root)
    assert "API_KEY=sekret123" in env_file.read_text(encoding="utf-8")


def test_decrypt_with_wrong_key_is_surfaced_not_silently_ok(
    tmp_path: Path,
    dotenvx_on_path: str,
) -> None:
    """#566: a decrypt dotenvx cannot complete must raise, never a misleading no-op.

    dotenvx renamed its decrypt-failure codes across majors (v1
    ``WRONG_PRIVATE_KEY`` / ``MISSING_PRIVATE_KEY``, v2 ``DECRYPTION_FAILED``),
    and the decrypt seam has no plaintext post-check — so the wrapper must still
    surface the failure via the non-zero exit and ``ENCRYPT_ERROR_PATTERNS``
    instead of reporting success while the ciphertext survives.
    """
    from envdrift.integrations.dotenvx import DotenvxError, DotenvxWrapper

    work = tmp_path / "wrongkey"
    work.mkdir()
    env_file = work / ".env"
    env_file.write_text("API_KEY=sekret123\n", encoding="utf-8")

    wrapper = DotenvxWrapper(auto_install=False)
    wrapper.encrypt(env_file, cwd=work)
    assert "encrypted:" in env_file.read_text(encoding="utf-8")

    # Replace the private key with a *different* valid dotenvx key so decrypt
    # fails on a genuine key mismatch (not a malformed key).
    other = tmp_path / "other"
    other.mkdir()
    other_env = other / ".env"
    other_env.write_text("X=1\n", encoding="utf-8")
    wrapper.encrypt(other_env, cwd=other)
    (work / ".env.keys").write_text(
        (other / ".env.keys").read_text(encoding="utf-8"), encoding="utf-8"
    )

    with pytest.raises(DotenvxError):
        wrapper.decrypt(env_file, cwd=work)
    # The ciphertext survives — never half-written or falsely reported plaintext.
    assert "encrypted:" in env_file.read_text(encoding="utf-8")
