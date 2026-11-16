"""guard, validate and ``encrypt --check`` read backtick-quoted values as dotenvx does (#964).

dotenvx accepts a value quoted with backticks and keeps the backticks around the
ciphertext it writes: ``KEY=`encrypted:...` ``. Three checks knew only ``"`` and
``'``:

1. guard flagged a correctly encrypted file: HIGH ``unencrypted-env-file`` and
   MEDIUM ``high-entropy-string``, exit 2.
2. validate type-checked the ciphertext: ``PORT=`encrypted:...` `` failed with
   ``Expected integer``.
3. ``encrypt --check`` missed a plaintext secret (fail-open): the secret patterns
   match from the start of the value, and the value started with a backtick.

The ciphertext comes from the real dotenvx binary, and every check runs through
the real ``envdrift`` CLI.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration]

_needs_dotenvx = pytest.mark.skipif(
    shutil.which("dotenvx") is None,
    reason="dotenvx binary not installed (required for real backtick ciphertext)",
)

# Built by concatenation so push protection never sees a whole secret literal.
_API_KEY = "sk_" + "test_" + "abc123"
_STRIPE_LIVE = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"

_SCHEMA = """\
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    API_KEY: str
    PORT: int
"""


def _run_envdrift(
    args: list[str],
    *,
    cwd: Path,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
) -> subprocess.CompletedProcess[str]:
    """Run the real envdrift CLI as a subprocess and capture its output."""
    env = os.environ.copy()
    env["PYTHONPATH"] = integration_pythonpath
    return subprocess.run(
        [*envdrift_cmd, *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _flat(result: subprocess.CompletedProcess[str]) -> str:
    """stdout+stderr with whitespace collapsed, so wrapping cannot split a phrase."""
    return " ".join((result.stdout + result.stderr).split())


def _dotenvx_encrypt(env_file: Path) -> None:
    """Encrypt ``env_file`` in place with the real dotenvx binary."""
    subprocess.run(
        ["dotenvx", "encrypt", "-f", env_file.name, "-fk", ".env.keys"],
        cwd=env_file.parent,
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )


def _encrypted_file(folder: Path, quote: str) -> Path:
    """A ``.env.production`` whose values dotenvx encrypted inside ``quote``."""
    env_file = folder / ".env.production"
    env_file.write_text(
        f"API_KEY={quote}{_API_KEY}{quote}\nPORT={quote}8080{quote}\n", encoding="utf-8"
    )
    _dotenvx_encrypt(env_file)
    text = env_file.read_text(encoding="utf-8")
    assert f"API_KEY={quote}encrypted:" in text and _API_KEY not in text
    return env_file


@_needs_dotenvx
class TestGuardReadsBacktickCiphertextAsEncrypted:
    """#964.1: guard does not flag a file dotenvx encrypted inside backticks."""

    @pytest.mark.parametrize("quote", ["", '"', "'", "`"], ids=["bare", "double", "single", "tick"])
    def test_encrypted_file_has_no_findings(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
        quote: str,
    ) -> None:
        _encrypted_file(work_dir, quote)

        result = _run_envdrift(
            ["guard", "--native-only", "--json", ".env.production"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        report = json.loads(result.stdout)
        rules = sorted(finding["rule_id"] for finding in report["findings"])
        assert rules == [], _flat(result)
        assert result.returncode == 0, _flat(result)


@_needs_dotenvx
class TestValidateSkipsBacktickCiphertext:
    """#964.2: validate does not type-check ciphertext inside backticks."""

    @pytest.mark.parametrize("quote", ['"', "`"], ids=["double", "tick"])
    def test_encrypted_int_field_passes(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
        quote: str,
    ) -> None:
        _encrypted_file(work_dir, quote)
        (work_dir / "schema_mod.py").write_text(_SCHEMA, encoding="utf-8")

        result = _run_envdrift(
            [
                "validate",
                ".env.production",
                "--schema",
                "schema_mod:Settings",
                "--service-dir",
                ".",
                "--ci",
            ],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        output = _flat(result)
        assert "Expected integer" not in output
        assert "Validation PASSED" in output
        assert result.returncode == 0, output


class TestCheckFindsBacktickPlaintextSecrets:
    """#964.3: ``encrypt --check`` reports a plaintext secret inside backticks."""

    @pytest.mark.parametrize("quote", ['"', "`"], ids=["double", "tick"])
    def test_plaintext_secret_blocks_the_commit(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
        quote: str,
    ) -> None:
        # STRIPE does not look sensitive by name: only the value gives it away.
        (work_dir / ".env").write_text(f"STRIPE={quote}{_STRIPE_LIVE}{quote}\n", encoding="utf-8")

        result = _run_envdrift(
            ["encrypt", "--check", ".env"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        output = _flat(result)
        assert "PLAINTEXT SECRETS DETECTED" in output
        assert "'STRIPE' has a value that looks like a secret" in output
        assert result.returncode == 1, output
