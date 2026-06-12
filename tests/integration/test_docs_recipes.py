"""Live verification of the documented recipes corrected in #498.

Each test runs the *corrected* documented command against the real envdrift CLI
(subprocess) and the real ``dotenvx`` binary, and also proves the *old*
documented command fails exactly the way issue #498 reported — so the docs
can't drift back to a recipe that dies at the moment a user needs it:

- ``docs/support/faq.md`` "decrypt in CI" Option 1: a bare ``DOTENV_PRIVATE_KEY``
  in ``.env.keys`` can never decrypt ``.env.production``; the suffixed
  ``DOTENV_PRIVATE_KEY_PRODUCTION`` round-trips.
- ``docs/guides/env-file-sync.md`` key rotation: ``dotenvx encrypt --rotate``
  is rejected ("unknown option"); ``dotenvx rotate -f`` rotates for real.
- ``docs/guides/monorepo-setup.md`` shared keys: ``DOTENV_KEYS_PATH`` is read by
  nothing; dotenvx's ``--env-keys-file`` flag and a symlink both work.

No mocking of the behavior under test.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration]

# Plain fixture value (built by concatenation so push protection never sees a
# realistic secret literal).
_PLAIN_VALUE = "plain-" + "value-" + "498"
_SUFFIXED_KEY_RE = re.compile(r'^DOTENV_PRIVATE_KEY_PRODUCTION="?([0-9a-fA-F]+)"?', re.MULTILINE)


@pytest.fixture
def dotenvx_bin() -> str:
    """Path to a real dotenvx binary, or skip."""
    path = shutil.which("dotenvx")
    if path is None:
        pytest.skip("dotenvx binary not found on PATH")
    return path


def _run(
    cmd: list[str],
    cwd: Path,
    env: dict[str, str],
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    child_env = dict(env)
    if extra_env:
        child_env.update(extra_env)
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=child_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )


def _public_key_line(env_file: Path) -> str:
    """Return the DOTENV_PUBLIC_KEY_* line of an encrypted env file."""
    text = env_file.read_text(encoding="utf-8")
    match = re.search(r"^DOTENV_PUBLIC_KEY[A-Z_]*=.*$", text, re.MULTILINE)
    assert match, f"no public key line in {env_file}:\n{text}"
    return match.group(0)


def _encrypt_production(envdrift_cmd: list[str], cwd: Path, env: dict[str, str]) -> str:
    """Encrypt ``.env.production`` with the real CLI; return its private key."""
    (cwd / ".env.production").write_text(f"SECRET_TOKEN={_PLAIN_VALUE}\n", encoding="utf-8")
    result = _run([*envdrift_cmd, "encrypt", ".env.production"], cwd, env)
    assert result.returncode == 0, result.stdout + result.stderr

    keys_text = (cwd / ".env.keys").read_text(encoding="utf-8")
    match = _SUFFIXED_KEY_RE.search(keys_text)
    assert match, (
        "envdrift encrypt must write the suffixed DOTENV_PRIVATE_KEY_PRODUCTION "
        f"into .env.keys; got:\n{keys_text}"
    )
    encrypted = (cwd / ".env.production").read_text(encoding="utf-8")
    assert "encrypted:" in encrypted
    assert _PLAIN_VALUE not in encrypted
    return match.group(1)


def test_faq_ci_decrypt_recipe_round_trips(
    envdrift_cmd: list[str],
    dotenvx_bin: str,
    work_dir: Path,
    integration_env: dict[str, str],
) -> None:
    """faq.md's corrected CI decrypt recipe works; the old one never could (#498)."""
    private_key = _encrypt_production(envdrift_cmd, work_dir, integration_env)
    encrypted = (work_dir / ".env.production").read_text(encoding="utf-8")

    # Simulate a fresh CI checkout: only the committed encrypted file, no keys.
    (work_dir / ".env.keys").unlink()

    # OLD recipe (pre-#498 faq.md): write a bare DOTENV_PRIVATE_KEY. dotenvx
    # looks up the environment-suffixed name for .env.production, so the
    # published recipe always failed and left the file encrypted.
    (work_dir / ".env.keys").write_text(f"DOTENV_PRIVATE_KEY={private_key}\n", encoding="utf-8")
    result = _run([*envdrift_cmd, "decrypt", ".env.production"], work_dir, integration_env)
    assert result.returncode != 0, (
        "the old unsuffixed-key recipe unexpectedly decrypted .env.production:\n"
        + result.stdout
        + result.stderr
    )
    assert (work_dir / ".env.production").read_text(encoding="utf-8") == encrypted, (
        "file must be left untouched when the private key cannot match"
    )

    # NEW recipe: exactly what the corrected snippet writes in CI.
    (work_dir / ".env.keys").write_text(
        f"DOTENV_PRIVATE_KEY_PRODUCTION={private_key}\n", encoding="utf-8"
    )
    result = _run([*envdrift_cmd, "decrypt", ".env.production"], work_dir, integration_env)
    assert result.returncode == 0, result.stdout + result.stderr
    decrypted = (work_dir / ".env.production").read_text(encoding="utf-8")
    assert _PLAIN_VALUE in decrypted, "corrected recipe must restore the plaintext value"


def test_env_file_sync_rotation_recipe(
    envdrift_cmd: list[str],
    dotenvx_bin: str,
    work_dir: Path,
    integration_env: dict[str, str],
) -> None:
    """env-file-sync.md's rotation one-liner rotates; the old flag is dead (#498).

    Real ``dotenvx rotate`` semantics (pinned here so the doc stays truthful):
    it generates a new keypair, re-encrypts the file to the new public key, and
    *appends* the new private key to the suffixed ``.env.keys`` entry
    (comma-separated, old key kept so older ciphertext stays decryptable).
    """
    old_key = _encrypt_production(envdrift_cmd, work_dir, integration_env)
    old_public = _public_key_line(work_dir / ".env.production")

    # OLD documented command: dotenvx has no `encrypt --rotate` option.
    result = _run(
        [dotenvx_bin, "encrypt", ".env.production", "--rotate"], work_dir, integration_env
    )
    assert result.returncode != 0
    assert "unknown option" in (result.stdout + result.stderr)

    # NEW documented command rotates for real: exit 0, a NEW private key
    # appended to .env.keys, file re-encrypted to a NEW public key.
    result = _run([dotenvx_bin, "rotate", "-f", ".env.production"], work_dir, integration_env)
    assert result.returncode == 0, result.stdout + result.stderr
    keys_text = (work_dir / ".env.keys").read_text(encoding="utf-8")
    match = re.search(
        r'^DOTENV_PRIVATE_KEY_PRODUCTION="?([0-9a-fA-F,]+)"?', keys_text, re.MULTILINE
    )
    assert match, f"rotate must keep the suffixed key entry in .env.keys; got:\n{keys_text}"
    key_chain = match.group(1).split(",")
    assert key_chain[0] == old_key, "rotate keeps the old key so history stays decryptable"
    assert len(key_chain) == 2 and key_chain[-1] != old_key, (
        "rotate must append a NEW private key to the suffixed entry"
    )
    rotated = (work_dir / ".env.production").read_text(encoding="utf-8")
    assert "encrypted:" in rotated
    assert _PLAIN_VALUE not in rotated
    assert _public_key_line(work_dir / ".env.production") != old_public, (
        "rotate must re-encrypt the file to a NEW public key"
    )

    # The rotated file still round-trips with the new key.
    result = _run(
        [dotenvx_bin, "decrypt", "-f", ".env.production", "--stdout"], work_dir, integration_env
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert _PLAIN_VALUE in result.stdout


def test_monorepo_shared_keys_env_keys_file_flag(
    envdrift_cmd: list[str],
    dotenvx_bin: str,
    work_dir: Path,
    integration_env: dict[str, str],
) -> None:
    """monorepo-setup.md's shared-keys mechanisms: --env-keys-file works,
    the fabricated DOTENV_KEYS_PATH does not (#498)."""
    service = work_dir / "services" / "api"
    service.mkdir(parents=True)
    _encrypt_production(envdrift_cmd, service, integration_env)

    # Move the keys to a central location that is neither the service folder
    # nor the cwd, so a fallback lookup cannot mask a failure.
    central_dir = work_dir / "central"
    central_dir.mkdir()
    central_keys = central_dir / ".env.keys"
    (service / ".env.keys").rename(central_keys)
    relative_keys = Path("..") / ".." / "central" / ".env.keys"

    # Fabricated pre-#498 tip: DOTENV_KEYS_PATH is read by nothing, so decrypt
    # still cannot find the private key.
    result = _run(
        [dotenvx_bin, "decrypt", "-f", ".env.production", "--stdout"],
        service,
        integration_env,
        extra_env={"DOTENV_KEYS_PATH": str(central_keys)},
    )
    assert result.returncode != 0, (
        "DOTENV_KEYS_PATH unexpectedly worked — the docs may name it again:\n"
        + result.stdout
        + result.stderr
    )

    # Real documented mechanism: dotenvx's --env-keys-file flag.
    result = _run(
        [
            dotenvx_bin,
            "decrypt",
            "-f",
            ".env.production",
            "--env-keys-file",
            str(relative_keys),
            "--stdout",
        ],
        service,
        integration_env,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert _PLAIN_VALUE in result.stdout


@pytest.mark.skipif(sys.platform == "win32", reason="symlink creation needs privileges on Windows")
def test_monorepo_shared_keys_symlink(
    envdrift_cmd: list[str],
    dotenvx_bin: str,
    work_dir: Path,
    integration_env: dict[str, str],
) -> None:
    """monorepo-setup.md's symlink mechanism for a shared .env.keys works (#498)."""
    service = work_dir / "services" / "api"
    service.mkdir(parents=True)
    _encrypt_production(envdrift_cmd, service, integration_env)

    # Shared keys live at the monorepo root; the service gets a symlink.
    (service / ".env.keys").rename(work_dir / ".env.keys")
    (service / ".env.keys").symlink_to(Path("..") / ".." / ".env.keys")

    result = _run(
        [dotenvx_bin, "decrypt", "-f", ".env.production", "--stdout"],
        service,
        integration_env,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert _PLAIN_VALUE in result.stdout
