"""A check that a key decrypts a file must not pass a file with nothing to decrypt.

When a file holds no ``encrypted:`` value, dotenvx has nothing to decrypt and exits 0,
so ``decrypt --verify-vault`` (#1023) and ``sync --check-decryption`` (#1024) reported
success without ever using the key. These run the real dotenvx binary, and
``--verify-vault`` runs against the live HashiCorp Vault container. Each test asserts
the right verdict, and is an expected failure until its issue is fixed.
"""

from __future__ import annotations

import contextlib
import importlib.util
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from tests.helpers import DOTENVX_KEY_PAIRS

from envdrift.sync.config import ServiceMapping, SyncConfig
from envdrift.sync.engine import SyncEngine, SyncMode
from envdrift.sync.result import DecryptionTestResult

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("dotenvx") is None, reason="dotenvx binary not installed"),
]

PRODUCTION = "DOTENV_PRIVATE_KEY_PRODUCTION"


class _KnownFalsePassError(AssertionError):
    """The false verdict its issue reports: only this one makes a test an expected failure.

    A Vault, CLI or setup failure is still a real failure, never mistaken for the bug.
    """


@dataclass
class _VaultCli:
    """The live HashiCorp Vault container, and the real CLI run against it."""

    client: Any
    url: str
    env: dict[str, str]

    def verify(self, work_dir: Path, path: str) -> subprocess.CompletedProcess[str]:
        args = ["decrypt", ".env.production", "--verify-vault", "-p", "hashicorp"]
        args += ["--vault-url", self.url, "--secret", path]
        return subprocess.run(
            [sys.executable, "-m", "envdrift.cli", *args],
            cwd=work_dir,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=120,
        )


@pytest.fixture
def vault_cli(
    vault_endpoint: str, vault_client, vault_test_env: dict[str, str], integration_pythonpath: str
) -> _VaultCli:
    env = dict(vault_test_env, PYTHONPATH=integration_pythonpath)
    return _VaultCli(client=vault_client, url=vault_endpoint, env=env)


@pytest.mark.vault
@pytest.mark.skipif(importlib.util.find_spec("hvac") is None, reason="hvac not installed")
@pytest.mark.xfail(
    strict=False,
    raises=_KnownFalsePassError,
    reason="verify-vault passes a file with no encrypted value (see #1023)",
)
@pytest.mark.parametrize("header", [False, True], ids=["plaintext", "decrypted-dotenvx-file"])
def test_verify_vault_fails_a_file_with_no_encrypted_value(
    vault_cli: _VaultCli, work_dir: Path, header: bool
) -> None:
    """The vault's key was never used, so the check must not say the keys are in sync.

    A file that dotenvx decrypted keeps its ``DOTENV_PUBLIC_KEY_PRODUCTION`` header,
    so it still looks like a dotenvx file. The vault holds the key of another pair,
    which cannot decrypt anything encrypted for that header. The fix must say why it
    fails (the file has no encrypted value), so a vault, auth or configuration error,
    which also exits 1 without "keys are in sync", fails this test instead of passing it.
    """
    (_, public), (other_private, _) = DOTENVX_KEY_PAIRS[0], DOTENVX_KEY_PAIRS[1]
    lines = [f'DOTENV_PUBLIC_KEY_PRODUCTION="{public}"'] if header else []
    (work_dir / ".env.production").write_text("\n".join([*lines, "API_TOKEN=value", ""]))
    path = f"test/verify-nothing-to-decrypt-{'header' if header else 'plain'}"
    kv = vault_cli.client.secrets.kv.v2
    kv.create_or_update_secret(
        path=path, secret={"value": f"{PRODUCTION}={other_private}"}, mount_point="secret"
    )
    try:
        result = vault_cli.verify(work_dir, path)
    finally:
        with contextlib.suppress(Exception):
            kv.delete_metadata_and_all_versions(path=path, mount_point="secret")

    output = " ".join((result.stdout + result.stderr).split())
    if "keys are in sync" in output and result.returncode == 0:
        raise _KnownFalsePassError(output)
    assert "keys are in sync" not in output, output
    assert result.returncode == 1, output
    assert "no encrypted value" in output.lower(), output


def _decryption_check(folder: Path, content: str) -> DecryptionTestResult:
    key, _ = DOTENVX_KEY_PAIRS[0]
    (folder / ".env.production").write_text(content)
    (folder / ".env.keys").write_text(f"{PRODUCTION}={key}\n")
    mapping = ServiceMapping(secret_name="k", folder_path=folder, environment="production")
    engine = SyncEngine(
        config=SyncConfig(mappings=[mapping]), vault_client=MagicMock(), mode=SyncMode()
    )
    return engine._test_decryption(mapping)


def test_sync_decryption_check_skips_a_plaintext_file(tmp_path: Path) -> None:
    """The control: a file with no encrypted value is skipped, not passed."""
    result = _decryption_check(tmp_path, "API_TOKEN=value\n")

    assert result == DecryptionTestResult.SKIPPED


@pytest.mark.xfail(
    strict=False,
    raises=_KnownFalsePassError,
    reason="the decryption check reads a comment holding encrypted: as ciphertext (see #1024)",
)
def test_sync_decryption_check_skips_a_plaintext_file_whose_comment_says_encrypted(
    tmp_path: Path,
) -> None:
    """A comment is not a value: nothing was decrypted, so nothing was verified."""
    content = "# note: values here are not encrypted: local dev only\nAPI_TOKEN=value\n"

    result = _decryption_check(tmp_path, content)

    if result == DecryptionTestResult.PASSED:
        raise _KnownFalsePassError("a plaintext file passed the decryption check")
    assert result == DecryptionTestResult.SKIPPED
