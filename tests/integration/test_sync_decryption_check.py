"""sync --check-decryption tests one key, never a key ring of two (#938).

dotenvx splits a value on "," into a key ring and decrypts with any of its
keys, so a first value of two keys could pass a check meant for one of them.
These run the real dotenvx binary on a file it encrypted itself.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
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


def test_sync_decryption_check_does_not_pass_through_a_second_key_of_a_ring(
    tmp_path: Path,
) -> None:
    """A first value "K1,K2" hands dotenvx both keys, so K2 could pass a check of K1.

    The file is encrypted under K2. K1 alone fails the check and K2 alone
    passes it; the key ring of both must fail, not pass through K2.
    """
    (k1, _), (k2, k2_public) = DOTENVX_KEY_PAIRS[0], DOTENVX_KEY_PAIRS[1]
    env_file = tmp_path / ".env.production"
    env_file.write_text(f'DOTENV_PUBLIC_KEY_PRODUCTION="{k2_public}"\nSECRET=hello\n')
    keys_file = tmp_path / ".env.keys"
    keys_file.write_text(f"{PRODUCTION}={k2}\n")
    dotenvx = shutil.which("dotenvx") or "dotenvx"
    encrypted = subprocess.run(
        [dotenvx, "encrypt", "-f", env_file.name],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert encrypted.returncode == 0, encrypted.stderr
    mapping = ServiceMapping(secret_name="k", folder_path=tmp_path, environment="production")
    engine = SyncEngine(
        config=SyncConfig(mappings=[mapping]), vault_client=MagicMock(), mode=SyncMode()
    )

    verdicts = {}
    for label, held in (("K1", k1), ("K2", k2), ("ring", f"{k1},{k2}")):
        keys_file.write_text(f"{PRODUCTION}={held}\n")
        verdicts[label] = engine._test_decryption(mapping)

    assert verdicts == {
        "K1": DecryptionTestResult.FAILED,
        "K2": DecryptionTestResult.PASSED,
        "ring": DecryptionTestResult.FAILED,
    }
