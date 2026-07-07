"""Regression tests for #454: ``decrypt --verify-vault`` must copy bytes, not text.

The verify flow copies the env file into an isolated temp directory before
test-decrypting it with the vault key. A ``read_text()``/``write_text()`` copy
uses the platform-default encoding (cp1252 on Windows) and translates newlines,
so a UTF-8 file with CRLF endings or non-ASCII content was not copied
byte-for-byte: corrupted (or ``UnicodeDecodeError``) under a non-UTF-8 locale,
and CRLF silently rewritten on every platform.

These tests drive the real verify path against the live HashiCorp Vault
container and the real dotenvx binary.
"""

from __future__ import annotations

import contextlib
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from tests.integration.conftest import VAULT_ROOT_TOKEN

HVAC_AVAILABLE = importlib.util.find_spec("hvac") is not None
DOTENVX_AVAILABLE = shutil.which("dotenvx") is not None

pytestmark = [
    pytest.mark.integration,
    pytest.mark.vault,
    pytest.mark.skipif(
        not HVAC_AVAILABLE,
        reason="hvac not installed - install with: pip install envdrift[hashicorp]",
    ),
    pytest.mark.skipif(
        not DOTENVX_AVAILABLE,
        reason="dotenvx binary required to encrypt/verify .env files",
    ),
]

# A comment whose UTF-8 encoding includes bytes that are *undefined* in cp1252
# (0x8D in 配 = E9 85 8D), so a locale-encoded text copy cannot silently
# round-trip it on Windows either — it raises UnicodeDecodeError instead.
NON_ASCII_COMMENT = "# café ☕ 配置 — verify must copy these bytes exactly"


def _delete_vault_path(vault_client, path: str, mount_point: str = "secret") -> None:
    """Best-effort cleanup of a KV v2 secret path."""
    with contextlib.suppress(Exception):
        vault_client.secrets.kv.v2.delete_metadata_and_all_versions(
            path=path,
            mount_point=mount_point,
        )


def _run_envdrift_cli(
    args: list[str],
    cwd: Path,
    env: dict,
    integration_pythonpath: str,
    timeout: int = 120,
) -> subprocess.CompletedProcess:
    """Run the envdrift CLI as a real subprocess against the live container."""
    run_env = env.copy()
    run_env["PYTHONPATH"] = integration_pythonpath
    return subprocess.run(
        [sys.executable, "-m", "envdrift.cli", *args],
        cwd=cwd,
        env=run_env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _encrypt_crlf_non_ascii_env_file(
    work_dir: Path,
    env: dict,
    integration_pythonpath: str,
) -> tuple[Path, bytes, str]:
    """Encrypt ``.env.production`` with the real CLI, then make it CRLF + UTF-8.

    Returns ``(env_file, original_bytes, private_key)`` where ``original_bytes``
    is the on-disk encrypted file rewritten with CRLF line endings and a
    non-ASCII UTF-8 comment appended — the exact bytes verify must preserve.
    The local ``.env.keys`` is deleted so verification can only succeed via the
    vault-stored key.
    """
    env_file = work_dir / ".env.production"
    env_file.write_text(
        "API_URL=https://example.com\nSECRET_TOKEN=plaintext-value-454\n",
        encoding="utf-8",
    )

    encrypt_result = _run_envdrift_cli(
        ["encrypt", ".env.production"],
        cwd=work_dir,
        env=env,
        integration_pythonpath=integration_pythonpath,
    )
    assert encrypt_result.returncode == 0, (
        f"encrypt failed: {encrypt_result.stdout}\n{encrypt_result.stderr}"
    )
    assert "encrypted:" in env_file.read_text(encoding="utf-8")

    # Extract the generated private key, then drop the local keys file.
    from envdrift.sync.operations import EnvKeysFile

    env_keys = work_dir / ".env.keys"
    priv = EnvKeysFile(env_keys).read_key("DOTENV_PRIVATE_KEY_PRODUCTION")
    assert priv, "dotenvx did not write DOTENV_PRIVATE_KEY_PRODUCTION"
    env_keys.unlink()

    # Rewrite the encrypted file with CRLF endings + a non-ASCII UTF-8 comment.
    data = env_file.read_bytes().replace(b"\r\n", b"\n")
    if not data.endswith(b"\n"):
        data += b"\n"
    data += NON_ASCII_COMMENT.encode("utf-8") + b"\n"
    env_file.write_bytes(data.replace(b"\n", b"\r\n"))

    original = env_file.read_bytes()
    assert b"\r\n" in original
    assert NON_ASCII_COMMENT.encode("utf-8") in original
    return env_file, original, priv


def test_verify_vault_temp_copy_is_byte_exact(
    vault_endpoint: str,
    vault_client,
    work_dir: Path,
    integration_env: dict,
    integration_pythonpath: str,
    monkeypatch: pytest.MonkeyPatch,
):
    """The temp copy handed to dotenvx is byte-identical to the original (#454).

    Pre-fix, the text-mode copy rewrote CRLF to LF (every platform) and decoded
    with the locale encoding (corrupting/crashing on Windows), so the copy was
    not byte-exact.
    """
    secret_path = "test/verify-byte-exact"
    env_file, original, priv = _encrypt_crlf_non_ascii_env_file(
        work_dir, dict(integration_env), integration_pythonpath
    )
    vault_client.secrets.kv.v2.create_or_update_secret(
        path=secret_path,
        secret={"value": f"DOTENV_PRIVATE_KEY_PRODUCTION={priv}"},
        mount_point="secret",
    )
    monkeypatch.setenv("VAULT_TOKEN", VAULT_ROOT_TOKEN)

    from envdrift.cli_commands.encryption import _verify_decryption_with_vault
    from envdrift.integrations.dotenvx import DotenvxWrapper

    captured: dict[str, bytes] = {}
    real_decrypt = DotenvxWrapper.decrypt

    def capturing_decrypt(self, env_file, **kwargs):
        # Pass-through spy: snapshot the temp copy's bytes, then run the REAL
        # dotenvx decrypt unchanged. The temp dir is deleted when verify
        # returns, so this is the only point the copy is observable.
        captured["copy"] = Path(env_file).read_bytes()
        return real_decrypt(self, env_file, **kwargs)

    monkeypatch.setattr(DotenvxWrapper, "decrypt", capturing_decrypt)

    try:
        verified = _verify_decryption_with_vault(
            env_file=env_file,
            provider="hashicorp",
            vault_url=vault_endpoint,
            region=None,
            project_id=None,
            secret_name=secret_path,
            ci=True,
        )

        assert verified is True
        # Byte-for-byte: CRLF endings and non-ASCII UTF-8 bytes preserved.
        assert captured["copy"] == original
        # The original file is never modified by verification.
        assert env_file.read_bytes() == original
    finally:
        _delete_vault_path(vault_client, secret_path)


def test_cli_verify_vault_round_trips_under_non_utf8_locale(
    vault_endpoint: str,
    vault_client,
    work_dir: Path,
    vault_test_env: dict,
    integration_pythonpath: str,
):
    """`decrypt --verify-vault` succeeds when the locale encoding is not UTF-8.

    Reproduces the #454 Windows failure mode on every platform: the CLI runs
    with an ASCII locale (POSIX) or the legacy ANSI code page (Windows), so any
    locale-encoded read of the UTF-8 env file raises UnicodeDecodeError.
    Pre-fix this exited 1 ("Unexpected error during vault verification");
    a byte copy never decodes the file, so verification succeeds.
    """
    secret_path = "test/verify-byte-exact-cli"
    env_file, original, priv = _encrypt_crlf_non_ascii_env_file(
        work_dir, dict(vault_test_env), integration_pythonpath
    )
    vault_client.secrets.kv.v2.create_or_update_secret(
        path=secret_path,
        secret={"value": f"DOTENV_PRIVATE_KEY_PRODUCTION={priv}"},
        mount_point="secret",
    )

    env = dict(vault_test_env)
    # Disable UTF-8 mode; keep the CLI's stdio decodable for assertions.
    env.update({"PYTHONUTF8": "0", "PYTHONIOENCODING": "utf-8"})
    if sys.platform != "win32":
        # Force an ASCII locale encoding (Windows already defaults to a
        # non-UTF-8 ANSI code page); disable PEP 538 C.UTF-8 coercion.
        env.update({"LC_ALL": "C", "LANG": "C", "PYTHONCOERCECLOCALE": "0"})

    try:
        result = _run_envdrift_cli(
            [
                "decrypt",
                ".env.production",
                "-b",
                "dotenvx",
                "--verify-vault",
                "--ci",
                "-p",
                "hashicorp",
                "--vault-url",
                vault_endpoint,
                "--secret",
                secret_path,
            ],
            cwd=work_dir,
            env=env,
            integration_pythonpath=integration_pythonpath,
        )

        combined = " ".join((result.stdout + result.stderr).split())
        assert result.returncode == 0, (
            f"verify failed: {result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}"
        )
        assert "keys are in sync" in combined
        # Verification is read-only: the original bytes are untouched.
        assert env_file.read_bytes() == original
    finally:
        _delete_vault_path(vault_client, secret_path)
