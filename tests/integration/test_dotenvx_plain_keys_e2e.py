"""A key dotenvx never encrypts is not leftover plaintext, and still not safe (#1048).

dotenvx 2.38.2 never encrypts a key whose name ends with ``_PLAIN`` (its ``/_PLAIN$/``
test, case-sensitive), unless it reads an ``Envfile`` in its working directory, whose
policy then decides. envdrift counted such a key as plaintext the encryption missed:
``encrypt`` and ``push`` failed with "Encryption did not take effect ... the encryption
key was missing or invalid" after dotenvx had encrypted the rest, and ``lock --check``
never passed. The value is still unencrypted, so ``encrypt --check`` and guard keep
reporting a secret-looking one.

Every test runs the real dotenvx binary, and all but the first the real ``envdrift`` CLI.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which("dotenvx") is None,
        reason="dotenvx binary not installed (required to see which keys it encrypts)",
    ),
]

# Built by concatenation so push protection never sees a whole secret literal.
_API_KEY = "abc" + "123"
_STRIPE_LIVE = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"

_LOCK_CONFIG = """\
[vault]
provider = "aws"

[vault.aws]
region = "us-east-1"

[encryption]
backend = "dotenvx"

[[vault.sync.mappings]]
secret_name = "svc-key"
folder_path = "svc"
environment = "production"
"""

_PARTIAL_CONFIG = """\
[partial_encryption]
enabled = true

[[partial_encryption.environments]]
name = "production"
clear_file = ".env.production.clear"
secret_file = ".env.production.secret"
combined_file = ".env.production"
"""


def _run_envdrift(
    args: list[str], *, cwd: Path, integration_pythonpath: str, envdrift_cmd: list[str]
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


def _plaintext_names(env_file: Path) -> set[str]:
    """The names whose value dotenvx left as written, ``export`` or quotes aside."""
    names = set()
    for line in env_file.read_text(encoding="utf-8").splitlines():
        if line.startswith(("#", "DOTENV_PUBLIC_KEY")) or "encrypted:" in line or not line:
            continue
        names.add(line.removeprefix("export ").split("=")[0].strip())
    return names


class TestTheRuleIsTheBinarys:
    """envdrift's ``is_plain_key`` and ``plain_keys_apply`` match what dotenvx does."""

    _NAMES = [
        "NOTE_PLAIN",
        "_PLAIN",
        "note_plain",
        "NOTE_plain",
        "PLAIN",
        "PLAIN_NOTE",
        "X_PLAIN_Y",
        "X_PLAINS",
        "dot.key_PLAIN",
        "dash-key_PLAIN",
        "NOTE",
    ]

    def _encrypt(self, folder: Path) -> Path:
        env_file = folder / ".env"
        lines = [f"{name}=x" for name in self._NAMES]
        lines += ['QUOTED_PLAIN="x"', "SINGLE_PLAIN='x'", "export EXPORTED_PLAIN=x"]
        lines += ["export EXPORTED=x"]
        env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        subprocess.run(
            ["dotenvx", "encrypt", "-f", ".env", "-fk", ".env.keys"],
            cwd=folder,
            capture_output=True,
            check=True,
            timeout=120,
        )
        return env_file

    def test_dotenvx_leaves_exactly_the_plain_keys(self, tmp_path: Path) -> None:
        from envdrift.integrations.dotenvx_keys import is_plain_key, plain_keys_apply

        env_file = self._encrypt(tmp_path)

        names = [*self._NAMES, "QUOTED_PLAIN", "SINGLE_PLAIN", "EXPORTED_PLAIN", "EXPORTED"]
        assert plain_keys_apply(tmp_path)
        assert _plaintext_names(env_file) == {name for name in names if is_plain_key(name)}

    def test_an_envfile_in_the_working_directory_turns_the_rule_off(self, tmp_path: Path) -> None:
        from envdrift.integrations.dotenvx_keys import plain_keys_apply

        (tmp_path / "Envfile").write_text("", encoding="utf-8")

        env_file = self._encrypt(tmp_path)

        assert not plain_keys_apply(tmp_path)
        assert _plaintext_names(env_file) == set()


class TestEncryptAcceptsWhatDotenvxLeavesPlain:
    """``envdrift encrypt`` reports the encryption dotenvx did, not a key problem."""

    def test_encrypt_succeeds_and_keeps_the_plain_key(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        env_file = git_repo / ".env"
        env_file.write_text(f"API_KEY={_API_KEY}\nNOTE_PLAIN=hello\n", encoding="utf-8")

        result = _run_envdrift(
            ["encrypt", ".env"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        output = _flat(result)
        assert result.returncode == 0, output
        assert "Encrypted .env using dotenvx" in output
        assert "did not take effect" not in output
        text = env_file.read_text(encoding="utf-8")
        assert "API_KEY=encrypted:" in text and _API_KEY not in text
        assert "NOTE_PLAIN=hello" in text

    def test_a_secret_in_a_plain_key_is_still_reported(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        env_file = git_repo / ".env"
        env_file.write_text(f"API_KEY={_API_KEY}\nAPI_KEY_PLAIN={_STRIPE_LIVE}\n", encoding="utf-8")
        encrypted = _run_envdrift(
            ["encrypt", ".env"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        assert encrypted.returncode == 0, _flat(encrypted)
        assert _STRIPE_LIVE in env_file.read_text(encoding="utf-8")

        check = _run_envdrift(
            ["encrypt", "--check", ".env"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        guard = _run_envdrift(
            ["guard", "--native-only", "--json", ".env"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        output = _flat(check)
        assert check.returncode == 1, output
        assert "PLAINTEXT SECRETS DETECTED" in output
        assert "'API_KEY_PLAIN' has a value that looks like a secret" in output
        rules = {finding["rule_id"] for finding in json.loads(guard.stdout)["findings"]}
        assert "stripe-secret-key" in rules, _flat(guard)
        assert guard.returncode != 0, _flat(guard)


class TestLockAcceptsWhatDotenvxLeavesPlain:
    """``lock`` treats a dotenvx file with a ``_PLAIN`` key as fully encrypted."""

    def test_lock_check_and_lock_pass(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        (git_repo / "envdrift.toml").write_text(_LOCK_CONFIG, encoding="utf-8")
        env_file = git_repo / "svc" / ".env.production"
        env_file.parent.mkdir()
        env_file.write_text(f"API_KEY={_API_KEY}\nNOTE_PLAIN=hello\n", encoding="utf-8")

        def run(*args: str) -> subprocess.CompletedProcess[str]:
            return _run_envdrift(
                list(args),
                cwd=git_repo,
                integration_pythonpath=integration_pythonpath,
                envdrift_cmd=envdrift_cmd,
            )

        encrypted = run("encrypt", "svc/.env.production")
        assert encrypted.returncode == 0, _flat(encrypted)
        before = env_file.read_bytes()

        check = run("lock", "--check")
        lock = run("lock", "--force")

        assert check.returncode == 0, _flat(check)
        assert "skipped (already encrypted)" in _flat(check)
        assert "plaintext values remain" not in _flat(check)
        assert lock.returncode == 0, _flat(lock)
        assert env_file.read_bytes() == before


class TestPushAcceptsWhatDotenvxLeavesPlain:
    """The partial-encryption ``push`` encrypts the rest and counts only that as encrypted."""

    def test_push_succeeds_and_check_stays_in_sync(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        (git_repo / "envdrift.toml").write_text(_PARTIAL_CONFIG, encoding="utf-8")
        (git_repo / ".env.production.clear").write_text("APP=shop\n", encoding="utf-8")
        secret = git_repo / ".env.production.secret"
        secret.write_text(f"DB_PASSWORD={_API_KEY}\nREGION_PLAIN=eu\n", encoding="utf-8")

        def run(*args: str) -> subprocess.CompletedProcess[str]:
            return _run_envdrift(
                list(args),
                cwd=git_repo,
                integration_pythonpath=integration_pythonpath,
                envdrift_cmd=envdrift_cmd,
            )

        push = run("push")
        check = run("push", "--check")

        output = _flat(push)
        assert push.returncode == 0, output
        assert "(1 clear + 1 encrypted)" in output
        text = secret.read_text(encoding="utf-8")
        assert "DB_PASSWORD=encrypted:" in text and "REGION_PLAIN=eu" in text
        assert check.returncode == 0, _flat(check)
