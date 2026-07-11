"""Live verification of the documented recipes corrected in #498 and #499.

Each test runs the *corrected* documented command against the real envdrift CLI
(subprocess) and the real ``dotenvx`` binary, and also proves the *old*
documented command fails exactly the way issue #498 reported — so the docs
can't drift back to a recipe that dies at the moment a user needs it:

- ``docs/support/faq.md`` "decrypt in CI" Option 1: a bare ``DOTENV_PRIVATE_KEY``
  in ``.env.keys`` can never decrypt ``.env.production``; the suffixed
  ``DOTENV_PRIVATE_KEY_PRODUCTION`` round-trips.
- ``docs/guides/env-file-sync.md`` key rotation: dotenvx v2 has no local
  ``rotate`` command, and its removed v1 command is a no-op.
- ``docs/guides/monorepo-setup.md`` shared keys: ``DOTENV_KEYS_PATH`` is read by
  nothing; dotenvx's ``--env-keys-file`` flag and a symlink both work.
- dotenvx whole-file encryption: even a non-secret ``DEBUG=false`` value is
  encrypted and the public-key variable is environment-suffixed.

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


def test_dotenvx_encryption_recipe_encrypts_every_value(
    envdrift_cmd: list[str],
    dotenvx_bin: str,
    work_dir: Path,
    integration_env: dict[str, str],
) -> None:
    """Dotenvx encrypts non-secret configuration as well as sensitive values (#499)."""
    del dotenvx_bin  # The fixture guarantees the real pinned binary is on PATH.
    (work_dir / ".env.production").write_text(
        "DATABASE_URL=postgres://user:pass@example.test/app\n"
        "API_KEY=example-api-key\n"
        "DEBUG=false\n",
        encoding="utf-8",
    )

    result = _run([*envdrift_cmd, "encrypt", ".env.production"], work_dir, integration_env)
    assert result.returncode == 0, result.stdout + result.stderr

    encrypted = (work_dir / ".env.production").read_text(encoding="utf-8")
    assert 'DOTENV_PUBLIC_KEY_PRODUCTION="' in encrypted
    assert "DATABASE_URL=encrypted:" in encrypted
    assert "API_KEY=encrypted:" in encrypted
    assert "DEBUG=encrypted:" in encrypted
    assert "DEBUG=false" not in encrypted


def test_faq_ci_decrypt_recipe_round_trips(
    envdrift_cmd: list[str],
    dotenvx_bin: str,
    work_dir: Path,
    integration_env: dict[str, str],
) -> None:
    """faq.md's recommended CI decrypt recipe (suffixed key) round-trips (#498).

    The recipe writes the environment-suffixed ``DOTENV_PRIVATE_KEY_PRODUCTION``
    — the exact name ``envdrift encrypt`` generates — into ``.env.keys`` and
    decrypts. That is unambiguous and correct on every dotenvx version.

    A bare ``DOTENV_PRIVATE_KEY`` used to be a foot-gun: dotenvx v1 looked the key
    up under the env-suffixed name only, so the bare-key recipe failed and left
    the file encrypted (#498). dotenvx v2 changed this — it now accepts the bare
    key as a fallback for any file — so this test no longer asserts the bare key
    *fails*; it pins that the suffixed recipe works and documents the v2 fallback.
    """
    private_key = _encrypt_production(envdrift_cmd, work_dir, integration_env)
    encrypted = (work_dir / ".env.production").read_text(encoding="utf-8")

    # Simulate a fresh CI checkout: only the committed encrypted file, no keys.
    (work_dir / ".env.keys").unlink()

    # RECOMMENDED recipe: the env-suffixed key name envdrift itself writes.
    (work_dir / ".env.keys").write_text(
        f"DOTENV_PRIVATE_KEY_PRODUCTION={private_key}\n", encoding="utf-8"
    )
    result = _run([*envdrift_cmd, "decrypt", ".env.production"], work_dir, integration_env)
    assert result.returncode == 0, result.stdout + result.stderr
    decrypted = (work_dir / ".env.production").read_text(encoding="utf-8")
    assert _PLAIN_VALUE in decrypted, "suffixed recipe must restore the plaintext value"

    # dotenvx v2 behavior change: a bare DOTENV_PRIVATE_KEY now ALSO decrypts a
    # named env file (v1 required the suffixed name and the bare key failed). Pin
    # the v2 truth so a future dotenvx regression that reinstates the v1 lookup is
    # caught here rather than silently breaking the fallback.
    (work_dir / ".env.production").write_text(encrypted, encoding="utf-8")
    (work_dir / ".env.keys").write_text(f"DOTENV_PRIVATE_KEY={private_key}\n", encoding="utf-8")
    result = _run([*envdrift_cmd, "decrypt", ".env.production"], work_dir, integration_env)
    assert result.returncode == 0, (
        "dotenvx v2 accepts a bare DOTENV_PRIVATE_KEY as a fallback:\n"
        + result.stdout
        + result.stderr
    )
    assert _PLAIN_VALUE in (work_dir / ".env.production").read_text(encoding="utf-8")


def test_env_file_sync_rotation_command_is_a_noop_in_dotenvx_v2(
    envdrift_cmd: list[str],
    dotenvx_bin: str,
    work_dir: Path,
    integration_env: dict[str, str],
) -> None:
    """The removed v1 command reports an error but exits 0 without rotating (#585)."""
    _encrypt_production(envdrift_cmd, work_dir, integration_env)
    env_file = work_dir / ".env.production"
    keys_file = work_dir / ".env.keys"
    encrypted_before = env_file.read_bytes()
    keys_before = keys_file.read_bytes()

    result = _run([dotenvx_bin, "rotate", "-f", ".env.production"], work_dir, integration_env)
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "unknown command 'rotate'" in output
    assert env_file.read_bytes() == encrypted_before, "removed rotate must not alter ciphertext"
    assert keys_file.read_bytes() == keys_before, "removed rotate must not alter .env.keys"


def test_replacing_dotenvx_v2_key_cannot_decrypt_prior_ciphertext(
    envdrift_cmd: list[str],
    dotenvx_bin: str,
    work_dir: Path,
    integration_env: dict[str, str],
) -> None:
    """A fresh local key replacement is not a history-preserving rotation (#585)."""
    _encrypt_production(envdrift_cmd, work_dir, integration_env)
    env_file = work_dir / ".env.production"
    keys_file = work_dir / ".env.keys"
    encrypted_before = env_file.read_bytes()
    prior_dir = work_dir / "prior"
    prior_dir.mkdir()
    prior_file = prior_dir / ".env.production"
    prior_file.write_bytes(encrypted_before)

    result = _run([dotenvx_bin, "decrypt", "-f", ".env.production"], work_dir, integration_env)
    assert result.returncode == 0, result.stdout + result.stderr
    keys_file.unlink()
    result = _run([dotenvx_bin, "encrypt", "-f", ".env.production"], work_dir, integration_env)
    assert result.returncode == 0, result.stdout + result.stderr

    result = _run(
        [dotenvx_bin, "decrypt", "-f", ".env.production", "-fk", "../.env.keys"],
        prior_dir,
        integration_env,
    )
    assert result.returncode != 0, "a replacement key must not decrypt prior ciphertext"
    assert prior_file.read_bytes() == encrypted_before


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

    # The doc also advertises the short alias `-fk`; verify the real dotenvx
    # binary accepts it identically so the shorthand is not a fabrication.
    result = _run(
        [
            dotenvx_bin,
            "decrypt",
            "-f",
            ".env.production",
            "-fk",
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
