"""Partial encryption end-to-end integration tests (real dotenvx binary + real git).

These tests exercise the ``envdrift push`` / ``envdrift pull-partial`` commands
as real subprocesses against the **real dotenvx binary** and **real git**. No
mocking of the behavior under test: encryption/decryption is performed by the
actual dotenvx CLI and the combined-file / secrets-only logic runs end to end.

Test categories:
- Secrets-only push/pull-partial (HP-05/06/07, BP-09/13)
- Combine-mode push --check staleness (BP-12) and combined-file structure (HP-01, EC-07)
- Full lock/pull/lock cycle (HP-11) and .env.keys exclusion (EC-09)

Gating:
- The dotenvx binary is required; tests skip if it is absent (CI installs it).
- git is required and is provided by the ``git_repo`` fixture (skips if absent).

Resource isolation: each test uses its own ``tmp_path``-backed ``work_dir`` and
secrets directory, so concurrent / repeated runs never collide.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

# Mark all tests in this module. No container needed: real dotenvx + real git.
pytestmark = [pytest.mark.integration]

# dotenvx is the encryption backend used by partial encryption. Skip the whole
# module locally when it is not installed (CI installs it). git is gated per-test
# via the ``git_repo`` fixture.
pytestmark.append(
    pytest.mark.skipif(
        shutil.which("dotenvx") is None,
        reason="dotenvx binary not installed (required for real partial-encryption e2e)",
    )
)


# --- Local helpers (defined here so conftest.py is never modified) ---


def _run_envdrift(
    args: list[str],
    *,
    cwd: Path,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
    timeout: int = 60,
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
        timeout=timeout,
    )


def _write_secrets_only_config(work_dir: Path, *, name: str, secrets_dir: str) -> None:
    """Write a secrets-only envdrift.toml for one environment."""
    (work_dir / "envdrift.toml").write_text(
        "[partial_encryption]\n"
        "enabled = true\n\n"
        "[[partial_encryption.environments]]\n"
        f'name = "{name}"\n'
        "secrets_only = true\n"
        f'secrets_dir = "{secrets_dir}"\n'
    )


def _write_combine_config(
    work_dir: Path,
    *,
    name: str,
    clear_file: str,
    secret_file: str,
    combined_file: str,
) -> None:
    """Write a combine-mode envdrift.toml for one environment."""
    (work_dir / "envdrift.toml").write_text(
        "[partial_encryption]\n"
        "enabled = true\n\n"
        "[[partial_encryption.environments]]\n"
        f'name = "{name}"\n'
        f'clear_file = "{clear_file}"\n'
        f'secret_file = "{secret_file}"\n'
        f'combined_file = "{combined_file}"\n'
    )


def _out(result: subprocess.CompletedProcess[str]) -> str:
    """Combined stdout+stderr for substring assertions."""
    return result.stdout + result.stderr


# ---------------------------------------------------------------------------
# P0 tests
# ---------------------------------------------------------------------------


class TestSecretsOnlyPushPull:
    """Secrets-only push/pull-partial against the real dotenvx binary."""

    def test_secrets_only_push_encrypts_all_matching_files_real_binary(
        self,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """HP-06: push encrypts every matching file in secrets_dir in place."""
        work_dir = git_repo
        secrets = work_dir / "secrets"
        secrets.mkdir()
        _write_secrets_only_config(work_dir, name="prod", secrets_dir="secrets")

        api = secrets / ".env.api"
        web = secrets / ".env.web"
        api.write_text("STRIPE_KEY=sk_live_fake\nDB=postgres://x\n")
        web.write_text("TOKEN=abc123\n")

        result = _run_envdrift(
            ["push"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        assert result.returncode == 0, _out(result)
        assert "Encrypted 2 file(s)" in _out(result), _out(result)

        for f in (api, web):
            content = f.read_text()
            assert "encrypted:" in content, f"{f} not encrypted:\n{content}"
            assert "DOTENV_PUBLIC_KEY" in content, f"{f} missing public-key header:\n{content}"

        # dotenvx writes the private key file next to the encrypted files.
        assert (secrets / ".env.keys").exists(), "private key file (.env.keys) was not created"

    def test_secrets_only_pull_decrypts_all_matching_files_real_binary(
        self,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """HP-07: pull-partial decrypts every encrypted file back to plaintext."""
        work_dir = git_repo
        secrets = work_dir / "secrets"
        secrets.mkdir()
        _write_secrets_only_config(work_dir, name="prod", secrets_dir="secrets")

        api = secrets / ".env.api"
        web = secrets / ".env.web"
        api.write_text("STRIPE_KEY=sk_live_fake\n")
        web.write_text("TOKEN=abc123\n")

        push = _run_envdrift(
            ["push"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        assert push.returncode == 0, _out(push)
        assert "encrypted:" in api.read_text()

        pull = _run_envdrift(
            ["pull-partial"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        assert pull.returncode == 0, _out(pull)
        assert "Decrypted 2 file(s)" in _out(pull), _out(pull)

        api_content = api.read_text()
        assert "STRIPE_KEY=sk_live_fake" in api_content, api_content
        # No encrypted value lines should remain after a real decrypt.
        assert "encrypted:" not in api_content, api_content
        assert "TOKEN=abc123" in web.read_text()

    def test_secrets_only_push_check_reports_in_sync_when_all_encrypted(
        self,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """HP-05: push --check is a dry run reporting in_sync (exit 0), mutating nothing."""
        work_dir = git_repo
        secrets = work_dir / "secrets"
        secrets.mkdir()
        _write_secrets_only_config(work_dir, name="prod", secrets_dir="secrets")

        api = secrets / ".env.api"
        api.write_text("STRIPE_KEY=sk_live_fake\n")

        push = _run_envdrift(
            ["push"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        assert push.returncode == 0, _out(push)

        before = api.read_bytes()

        check = _run_envdrift(
            ["push", "--check"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        assert check.returncode == 0, _out(check)
        out = _out(check)
        assert "up to date" in out, out
        assert "Out of date: 0" in out, out
        # Dry run must not touch the encrypted file.
        assert api.read_bytes() == before, "push --check mutated the encrypted file"

    def test_secrets_only_push_check_fails_when_files_unencrypted(
        self,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """BP-13: push --check exits non-zero when a secrets-only file is still plaintext."""
        work_dir = git_repo
        secrets = work_dir / "secrets"
        secrets.mkdir()
        _write_secrets_only_config(work_dir, name="prod", secrets_dir="secrets")

        api = secrets / ".env.api"
        api.write_text("STRIPE_KEY=sk_live_fake\n")

        check = _run_envdrift(
            ["push", "--check"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        assert check.returncode == 1, _out(check)
        out = _out(check).lower()
        assert "not encrypted" in out or "out of date" in out, _out(check)
        # Dry run leaves the file plaintext.
        assert "encrypted:" not in api.read_text(), api.read_text()
        # secrets-only mode never produces a combined file.
        assert "combined file" not in out, _out(check)

    def test_secrets_only_pull_partial_missing_keys_surfaces_error_real_binary(
        self,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """BP-09: pull-partial with .env.keys removed surfaces MISSING_PRIVATE_KEY, exits non-zero."""
        work_dir = git_repo
        secrets = work_dir / "secrets"
        secrets.mkdir()
        _write_secrets_only_config(work_dir, name="prod", secrets_dir="secrets")

        api = secrets / ".env.api"
        api.write_text("STRIPE_KEY=sk_live_fake\n")

        push = _run_envdrift(
            ["push"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        assert push.returncode == 0, _out(push)
        assert "encrypted:" in api.read_text()

        # Remove every private-key file so dotenvx cannot decrypt.
        for keys in (secrets / ".env.keys", work_dir / ".env.keys"):
            if keys.exists():
                keys.unlink()

        pull = _run_envdrift(
            ["pull-partial"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        assert pull.returncode == 1, _out(pull)
        out = _out(pull)
        assert "Failed to decrypt" in out, out
        assert "MISSING_PRIVATE_KEY" in out or "private key" in out.lower(), out
        assert "Errors: 1" in out, out
        # File must remain encrypted (no partial/half-written state).
        assert "encrypted:" in api.read_text(), api.read_text()


class TestCombineModePush:
    """Combine-mode push --check staleness and combined-file structure (real binary)."""

    def test_combine_push_check_fails_when_combined_stale_real_binary(
        self,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """BP-12: push --check exits non-zero when the combined file is stale after a manual edit."""
        work_dir = git_repo
        _write_combine_config(
            work_dir,
            name="production",
            clear_file=".env.production.clear",
            secret_file=".env.production.secret",
            combined_file=".env.production",
        )
        (work_dir / ".env.production.clear").write_text("APP_NAME=myapp\n")
        secret = work_dir / ".env.production.secret"
        secret.write_text("STRIPE_KEY=sk_live_x\n")

        push = _run_envdrift(
            ["push", "--env", "production"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        assert push.returncode == 0, _out(push)
        assert "encrypted:" in secret.read_text()

        # Manually corrupt the generated combined file so it is now stale.
        combined = work_dir / ".env.production"
        combined.write_text(combined.read_text() + "STALE=yes\n")

        check = _run_envdrift(
            ["push", "--check", "--env", "production"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        assert check.returncode == 1, _out(check)
        assert "out of date" in _out(check).lower(), _out(check)
        # Dry run must not regenerate the combined file: manual edit survives.
        assert "STALE=yes" in combined.read_text(), combined.read_text()
        # Secret source stays encrypted.
        assert "encrypted:" in secret.read_text(), secret.read_text()

    def test_combine_push_strips_public_key_border_and_excludes_it_from_count_real_binary(
        self,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """EC-07: dotenvx public-key border lines are stripped and the public key is not counted."""
        work_dir = git_repo
        _write_combine_config(
            work_dir,
            name="production",
            clear_file=".env.production.clear",
            secret_file=".env.production.secret",
            combined_file=".env.production",
        )
        (work_dir / ".env.production.clear").write_text("APP_NAME=myapp\n")
        secret = work_dir / ".env.production.secret"
        secret.write_text("STRIPE_KEY=sk_live_x\nDB_PASS=hunter2\n")

        push = _run_envdrift(
            ["push", "--env", "production"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        assert push.returncode == 0, _out(push)

        combined = (work_dir / ".env.production").read_text()
        # Both real secrets land in the combined file as encrypted values.
        assert combined.count("encrypted:") == 2, combined
        # dotenvx's own public-key block border is stripped (it starts with "#/---").
        assert "[DOTENV_PUBLIC_KEY]" not in combined, combined
        # The public key is excluded from the reported secret-var count: 2 (not 3).
        assert "2 encrypted" in _out(push), _out(push)
        assert "Encrypted vars: 2" in _out(push), _out(push)


# ---------------------------------------------------------------------------
# P1 tests
# ---------------------------------------------------------------------------


class TestSecretsOnlyLifecycle:
    """Full lock/pull/lock cycle and .env.keys exclusion (real binary)."""

    def test_secrets_only_full_lock_pull_lock_cycle_real_binary(
        self,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """HP-11: secrets-only push -> pull-partial -> push round-trips losslessly."""
        work_dir = git_repo
        secrets = work_dir / "secrets"
        secrets.mkdir()
        _write_secrets_only_config(work_dir, name="prod", secrets_dir="secrets")

        api = secrets / ".env.api"
        web = secrets / ".env.web"
        api.write_text("STRIPE_KEY=sk_live_fake\nDB=postgres://x\n")
        web.write_text("TOKEN=abc123\n")

        # Step 1: encrypt
        push1 = _run_envdrift(
            ["push"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        assert push1.returncode == 0, _out(push1)
        assert "encrypted:" in api.read_text()
        assert "encrypted:" in web.read_text()

        # Step 2: decrypt — original plaintext secret values are restored.
        # (dotenvx keeps its public-key header in the file, so we assert on the
        # restored values + absence of ciphertext, not byte-for-byte equality.)
        pull = _run_envdrift(
            ["pull-partial"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        assert pull.returncode == 0, _out(pull)
        api_decrypted = api.read_text()
        assert "STRIPE_KEY=sk_live_fake" in api_decrypted, api_decrypted
        assert "DB=postgres://x" in api_decrypted, api_decrypted
        assert "encrypted:" not in api_decrypted, api_decrypted
        web_decrypted = web.read_text()
        assert "TOKEN=abc123" in web_decrypted, web_decrypted
        assert "encrypted:" not in web_decrypted, web_decrypted

        # Step 3: re-encrypt
        push2 = _run_envdrift(
            ["push"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        assert push2.returncode == 0, _out(push2)
        assert "encrypted:" in api.read_text()
        assert "encrypted:" in web.read_text()

    def test_secrets_only_excludes_env_keys_from_encrypt_decrypt_real_binary(
        self,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """EC-09: .env.keys is never encrypted/decrypted even though it matches .env*."""
        work_dir = git_repo
        secrets = work_dir / "secrets"
        secrets.mkdir()
        _write_secrets_only_config(work_dir, name="prod", secrets_dir="secrets")

        api = secrets / ".env.api"
        web = secrets / ".env.web"
        api.write_text("A=1\n")
        web.write_text("B=2\n")

        push = _run_envdrift(
            ["push"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        assert push.returncode == 0, _out(push)
        # Keys file not counted: only the two real files are reported encrypted.
        assert "Encrypted 2 file(s)" in _out(push), _out(push)

        env_keys = secrets / ".env.keys"
        assert env_keys.exists(), "dotenvx did not create .env.keys"
        keys_bytes = env_keys.read_bytes()
        # It must never itself be encrypted.
        assert "encrypted:" not in env_keys.read_text(), env_keys.read_text()
        assert "encrypted:" in api.read_text()
        assert "encrypted:" in web.read_text()

        # A pull-partial must leave .env.keys byte-identical.
        pull = _run_envdrift(
            ["pull-partial"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        assert pull.returncode == 0, _out(pull)
        assert env_keys.read_bytes() == keys_bytes, ".env.keys changed across pull-partial"


class TestCombineModeStructure:
    """Combined-file structure assertions (real binary)."""

    def test_combine_push_produces_correct_combined_file_strong_assertions(
        self,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """HP-01: combine push produces a combined file with header, clear lines, encrypted values."""
        work_dir = git_repo
        _write_combine_config(
            work_dir,
            name="production",
            clear_file=".env.production.clear",
            secret_file=".env.production.secret",
            combined_file=".env.production",
        )
        (work_dir / ".env.production.clear").write_text("APP_NAME=myapp\nDEBUG=false\n")
        secret = work_dir / ".env.production.secret"
        secret.write_text("STRIPE_KEY=sk_live_supersecret\nDB_PASS=hunter2\n")

        push = _run_envdrift(
            ["push", "--env", "production"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        assert push.returncode == 0, _out(push)

        combined = (work_dir / ".env.production").read_text()
        # Auto-generated warning header.
        assert "WARNING: AUTO-GENERATED FILE" in combined, combined
        # Verbatim clear section, with its provenance comment.
        assert "# From .env.production.clear" in combined, combined
        assert "APP_NAME=myapp" in combined, combined
        assert "DEBUG=false" in combined, combined
        # Encrypted secret section with two encrypted values.
        assert "# From .env.production.secret (encrypted)" in combined, combined
        assert combined.count("encrypted:") == 2, combined
        # Raw secret values must never appear in the combined (committed) artifact.
        assert "sk_live_supersecret" not in combined, "plaintext secret leaked into combined file"
        assert "hunter2" not in combined, "plaintext secret leaked into combined file"
        # The .secret source is now encrypted in place.
        assert "encrypted:" in secret.read_text(), secret.read_text()


# ---------------------------------------------------------------------------
# #352: is_file_encrypted must key off a real ciphertext VALUE, not the bare
# substring "encrypted:" anywhere in the file. The actual bug: a PLAINTEXT
# value literally containing "encrypted:" (e.g. NOTE=... stored encrypted: see
# docs) false-positived under the old check
# (`"encrypted:" in content or "DOTENV_VAULT" in content`), so
# encrypt_secret_file early-returned and the real secret was committed in
# cleartext. The load-bearing #352 regression is
# `test_plaintext_value_literally_containing_encrypted_prefix_is_not_encrypted`
# (it fails on the old substring code and passes on the value-scan). The
# residual-public-key and lock->pull->lock cases below are FORWARD-GUARDS: the
# old code already returned False for a decrypted file (it holds neither
# "encrypted:" nor "DOTENV_VAULT"), so they passed pre-fix too — they lock in
# the value-scan behaviour against future regressions.
# ---------------------------------------------------------------------------


class TestIsFileEncryptedRealBinary:
    """is_file_encrypted against real dotenvx output and tricky plaintext (#352)."""

    def _dotenvx(self, args: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["dotenvx", *args], cwd=cwd, capture_output=True, text=True, timeout=60
        )

    def test_genuinely_encrypted_file_is_detected(self, tmp_path: Path):
        """A real dotenvx-encrypted file => is_file_encrypted True."""
        from envdrift.core.partial_encryption import is_file_encrypted

        secret = tmp_path / ".env.secret"
        # Build the fake secret by concatenation so push-protection never sees it.
        secret.write_text("API_KEY=" + "sk_live_" + "0123456789abcdef" * 2 + "\n")
        enc = self._dotenvx(["encrypt", "-f", str(secret)], cwd=tmp_path)
        assert enc.returncode == 0, enc.stdout + enc.stderr
        assert "encrypted:" in secret.read_text()

        assert is_file_encrypted(secret) is True

    def test_decrypted_file_with_residual_public_key_is_not_encrypted(self, tmp_path: Path):
        """Lock then pull: values are plaintext but DOTENV_PUBLIC_KEY remains => False.

        FORWARD-GUARD, not a #352 repro. A dotenvx-decrypted file contains
        neither "encrypted:" nor "DOTENV_VAULT", so the OLD substring check
        already returned False here — this case passed before the fix. It is
        kept to lock in that the new value-scan still reads a leftover
        public-key header (and plaintext values) as NOT encrypted, so a future
        regression that mistook the header for ciphertext — which would make
        encrypt_secret_file skip re-encryption — is caught.
        """
        from envdrift.core.partial_encryption import is_file_encrypted

        secret = tmp_path / ".env.secret"
        plaintext = "sk_live_" + "0123456789abcdef" * 2
        secret.write_text(f"API_KEY={plaintext}\n")

        assert self._dotenvx(["encrypt", "-f", str(secret)], cwd=tmp_path).returncode == 0
        assert is_file_encrypted(secret) is True
        assert self._dotenvx(["decrypt", "-f", str(secret)], cwd=tmp_path).returncode == 0

        decrypted = secret.read_text()
        # dotenvx leaves the public-key header in place but restores plaintext values.
        assert "DOTENV_PUBLIC_KEY" in decrypted
        assert plaintext in decrypted
        assert "encrypted:" not in decrypted
        # Forward-guard: header alone must not read as encrypted.
        assert is_file_encrypted(secret) is False

    def test_plaintext_value_literally_containing_encrypted_prefix_is_not_encrypted(
        self, tmp_path: Path
    ):
        """Plaintext value literally containing 'encrypted:' => False (the real #352 bug).

        This is the load-bearing #352 regression test (real-binary twin). The
        OLD check (``"encrypted:" in content``) false-positived on the NOTE
        value below and returned True, so encrypt_secret_file early-returned and
        the genuinely-secret API_KEY was committed in cleartext. Fails on the
        old substring code; passes on the value-scan.
        """
        from envdrift.core.partial_encryption import is_file_encrypted

        secret = tmp_path / ".env.secret"
        secret.write_text(
            "NOTE=the password is stored encrypted: see the vault docs\n"
            "API_KEY=" + "sk_live_" + "0123456789abcdef" * 2 + "\n"
        )
        assert is_file_encrypted(secret) is False


class TestLockPullLockReEncrypts:
    """encrypt_secret_file re-encrypts a decrypted-with-residual-header file.

    FORWARD-GUARD for the value-scan, not a #352 repro: the decrypted file in
    the middle of this flow holds neither "encrypted:" nor "DOTENV_VAULT", so
    the OLD substring check already returned False for it and this flow
    re-encrypted correctly before the fix too. Kept to ensure lock->pull->lock
    keeps re-encrypting once the value-scan is in place.
    """

    def test_encrypt_secret_file_reencrypts_after_pull(self, git_repo: Path):
        """lock -> pull -> lock: re-encryption produces ciphertext, no plaintext left."""
        from envdrift.config import PartialEncryptionEnvironmentConfig
        from envdrift.core.partial_encryption import (
            decrypt_secret_file,
            encrypt_secret_file,
            is_file_encrypted,
        )

        work = git_repo
        secret = work / ".env.production.secret"
        plaintext = "sk_live_" + "0123456789abcdef" * 2
        secret.write_text(f"API_KEY={plaintext}\n")
        cfg = PartialEncryptionEnvironmentConfig(
            name="production",
            clear_file=str(work / ".env.production.clear"),
            secret_file=str(secret),
            combined_file=str(work / ".env.production"),
        )

        # lock
        encrypt_secret_file(cfg)
        assert is_file_encrypted(secret) is True
        assert plaintext not in secret.read_text()

        # pull (decrypt in place) -> residual public-key header, plaintext value
        decrypt_secret_file(cfg)
        assert is_file_encrypted(secret) is False
        assert plaintext in secret.read_text()

        # lock again -> MUST re-encrypt despite the residual DOTENV_PUBLIC_KEY header
        encrypt_secret_file(cfg)
        assert is_file_encrypted(secret) is True, secret.read_text()
        assert "encrypted:" in secret.read_text()
        assert plaintext not in secret.read_text(), "plaintext secret survived re-encryption"


# ---------------------------------------------------------------------------
# #413 (CRITICAL): a MIXED-STATE .secret file (some values already encrypted,
# one freshly-added plaintext value) must be fully re-encrypted on the next
# push. The old early-return — triggered by is_file_encrypted() returning True
# on the first ciphertext value — skipped re-encryption, leaking the new
# plaintext secret into both the committed .secret file and the combined file.
# ---------------------------------------------------------------------------


class TestMixedStateReEncryption:
    """A mixed encrypted/plaintext .secret must end fully encrypted, no leak (#413)."""

    def test_combine_push_reencrypts_newly_added_plaintext_real_binary(
        self,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """push on a mixed .secret encrypts the new var; no plaintext in either file."""
        work_dir = git_repo
        _write_combine_config(
            work_dir,
            name="production",
            clear_file=".env.production.clear",
            secret_file=".env.production.secret",
            combined_file=".env.production",
        )
        (work_dir / ".env.production.clear").write_text("APP_NAME=myapp\n")
        secret = work_dir / ".env.production.secret"
        # Build the leaked-secret literal by concatenation so push-protection
        # never sees a realistic secret in the test source.
        leak_value = "sk_live_" + "0123456789abcdef" * 2
        secret.write_text("API_KEY=sk_live_initialvalue\n")

        # First push: encrypt the .secret in place + write the combined file.
        push1 = _run_envdrift(
            ["push", "--env", "production"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        assert push1.returncode == 0, _out(push1)
        assert "encrypted:" in secret.read_text(), secret.read_text()

        # Append a NEW plaintext secret to the now-encrypted .secret -> mixed state.
        secret.write_text(secret.read_text() + f"NEW_LEAKED_SECRET={leak_value}\n")
        # Sanity: the file is genuinely mixed (ciphertext + the new plaintext).
        assert "encrypted:" in secret.read_text()
        assert leak_value in secret.read_text()

        # Second push: MUST re-encrypt the mixed file (pre-fix: early-returned).
        push2 = _run_envdrift(
            ["push", "--env", "production"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        assert push2.returncode == 0, _out(push2)

        # The .secret file must now be FULLY encrypted: no plaintext leak.
        secret_after = secret.read_text()
        assert "encrypted:" in secret_after, secret_after
        assert leak_value not in secret_after, (
            "newly-added plaintext secret leaked into the committed .secret file"
        )
        assert secret_after.count("encrypted:") == 2, secret_after

        # The generated combined file must also carry only ciphertext.
        combined = (work_dir / ".env.production").read_text()
        assert leak_value not in combined, (
            "newly-added plaintext secret leaked into the combined file"
        )
        assert combined.count("encrypted:") == 2, combined


# ---------------------------------------------------------------------------
# #358: secrets-only push must encrypt ONLY the real secret file, never the
# .env.example / .env.sample / .env.template companions or .env.keys.
# ---------------------------------------------------------------------------


class TestSecretsOnlyCompanionsUntouched:
    def test_push_secrets_only_encrypts_only_dot_env_not_companions(self, git_repo: Path):
        """push_secrets_only encrypts .env only; companions + .env.keys stay plaintext (#358)."""
        from envdrift.config import PartialEncryptionEnvironmentConfig
        from envdrift.core.partial_encryption import is_file_encrypted, push_secrets_only

        secrets = git_repo / "secrets"
        secrets.mkdir()
        real = secrets / ".env"
        real.write_text("API_KEY=" + "sk_live_" + "0123456789abcdef" * 2 + "\n")
        companions = {
            ".env.example": "API_KEY=changeme\n",
            ".env.sample": "API_KEY=sample\n",
            ".env.template": "API_KEY=tmpl\n",
        }
        for name, body in companions.items():
            (secrets / name).write_text(body)
        # No pre-planted .env.keys: dotenvx GENERATES a real one during encrypt,
        # and our glob loop must skip it (.keys suffix) so the private key is
        # never itself encrypted. (A hand-written placeholder key would break
        # dotenvx's keystore and make the encrypt a silent no-op.)

        cfg = PartialEncryptionEnvironmentConfig(
            name="prod", secrets_only=True, secrets_dir=str(secrets), pattern=".env*"
        )

        result = push_secrets_only(cfg)

        # Only the real secret file was encrypted.
        assert result["encrypted"] == 1, result
        assert is_file_encrypted(real) is True
        assert "encrypted:" in real.read_text()

        # Companions untouched: byte-for-byte the original plaintext.
        for name, body in companions.items():
            assert (secrets / name).read_text() == body, f"{name} was modified"
            assert is_file_encrypted(secrets / name) is False

        # dotenvx wrote a real private-key file; the loop skipped it (.keys
        # suffix) so it was never encrypted and still holds the cleartext key.
        keys_file = secrets / ".env.keys"
        assert keys_file.exists(), "dotenvx should have generated .env.keys"
        assert "DOTENV_PRIVATE_KEY" in keys_file.read_text()
        assert "encrypted:" not in keys_file.read_text()

    def test_pull_secrets_only_decrypts_only_dot_env_not_companions(self, git_repo: Path):
        """pull_secrets_only skips companion files too (#358 pull branch)."""
        from envdrift.config import PartialEncryptionEnvironmentConfig
        from envdrift.core.partial_encryption import (
            is_file_encrypted,
            pull_secrets_only,
            push_secrets_only,
        )

        secrets = git_repo / "secrets"
        secrets.mkdir()
        real = secrets / ".env"
        real.write_text("API_KEY=" + "sk_live_" + "0123456789abcdef" * 2 + "\n")
        companions = {
            ".env.example": "API_KEY=changeme\n",
            ".env.sample": "API_KEY=sample\n",
            ".env.template": "API_KEY=tmpl\n",
        }
        for name, body in companions.items():
            (secrets / name).write_text(body)

        cfg = PartialEncryptionEnvironmentConfig(
            name="prod", secrets_only=True, secrets_dir=str(secrets), pattern=".env*"
        )
        # Encrypt first so there is ciphertext to pull (decrypt).
        push_secrets_only(cfg)
        assert is_file_encrypted(real) is True

        pull_secrets_only(cfg)

        # The real secret file was decrypted; companions were never processed.
        assert is_file_encrypted(real) is False
        for name, body in companions.items():
            assert (secrets / name).read_text() == body, f"{name} was modified by pull"


# ---------------------------------------------------------------------------
# #471: push false success. The partial-encryption push seam bypassed the
# guards the bare `envdrift encrypt` backend already has:
#   1. dotenvx exits 0 WITHOUT encrypting when .env.keys is unwritable (it
#      prints a warning) — push printed "[OK] Push complete!" with the secret
#      still plaintext in both the .secret and the combined file.
#   2. With BOTH source files missing, combine_files silently overwrote the
#      existing combined file with an empty scaffold under the success banner.
#   3. Handed an empty/comment-only .secret, dotenvx scaffolds ~13 placeholder
#      secrets (HELLO, AWS_ACCESS_KEY_ID, OPENAI_API_KEY, ...) and push counted
#      them as "13 encrypted".
#   4. pull --merge wrote the merged combined file (holding DECRYPTED values)
#      world-readable via a bare write_text instead of the 0600 atomic_write
#      used for .env.keys.
# All four run the real envdrift CLI against the real dotenvx binary; together
# with #470's lock/check coverage this closes the #485 regression-coverage gap.
# ---------------------------------------------------------------------------


class TestPushFailsWhenEncryptionDoesNotTakeEffect:
    """#471(1): dotenvx exit-0-without-encrypting must fail the push."""

    def test_push_env_keys_directory_fails_nonzero_and_keeps_source_intact(
        self,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """.env.keys as a DIRECTORY: dotenvx cannot write its private key, warns,
        exits 0 and leaves every value plaintext. push must exit non-zero with no
        success banner, keep the plaintext source intact, and must NOT generate a
        combined file carrying the plaintext secret."""
        work_dir = git_repo
        _write_combine_config(
            work_dir,
            name="production",
            clear_file=".env.production.clear",
            secret_file=".env.production.secret",
            combined_file=".env.production",
        )
        (work_dir / ".env.production.clear").write_text("DEBUG=false\n", encoding="utf-8")
        secret = work_dir / ".env.production.secret"
        # Built by concatenation so push-protection never sees a realistic secret.
        leak_value = "leakme-" + "readonly-" + "secret"
        secret.write_text(f"JWT_SECRET={leak_value}\n", encoding="utf-8")
        # dotenvx cannot write the derived private key into a directory.
        (work_dir / ".env.keys").mkdir()

        result = _run_envdrift(
            ["push", "--env", "production"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        out = " ".join(_out(result).split())
        # Pre-#471 this exited 0 and printed the success banner with the secret
        # still plaintext — the exact false-success the issue reproduces.
        assert result.returncode == 1, f"exit={result.returncode}\n{out}"
        assert "Push complete" not in out, out
        assert "did not take effect" in out, out
        # The plaintext source survives untouched (never destroyed, never lied about).
        assert leak_value in secret.read_text(encoding="utf-8")
        # No combined artifact carrying the plaintext secret is generated.
        assert not (work_dir / ".env.production").exists(), (
            "push generated a combined file despite the failed encryption"
        )

    @pytest.mark.skipif(
        sys.platform == "win32" or not hasattr(os, "geteuid") or os.geteuid() == 0,
        reason="read-only chmod is not enforced on Windows or for root",
    )
    def test_push_readonly_env_keys_file_fails_nonzero(
        self,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """A read-only .env.keys file (the issue's exact repro) also fails the push."""
        work_dir = git_repo
        _write_combine_config(
            work_dir,
            name="production",
            clear_file=".env.production.clear",
            secret_file=".env.production.secret",
            combined_file=".env.production",
        )
        (work_dir / ".env.production.clear").write_text("DEBUG=false\n", encoding="utf-8")
        secret = work_dir / ".env.production.secret"
        leak_value = "leakme-" + "readonly-" + "secret"
        secret.write_text(f"JWT_SECRET={leak_value}\n", encoding="utf-8")
        keys = work_dir / ".env.keys"
        keys.write_text("# placeholder\n", encoding="utf-8")
        keys.chmod(0o444)
        try:
            result = _run_envdrift(
                ["push", "--env", "production"],
                cwd=work_dir,
                integration_pythonpath=integration_pythonpath,
                envdrift_cmd=envdrift_cmd,
            )

            out = " ".join(_out(result).split())
            assert result.returncode == 1, f"exit={result.returncode}\n{out}"
            assert "Push complete" not in out, out
            assert "did not take effect" in out, out
            assert leak_value in secret.read_text(encoding="utf-8")
        finally:
            keys.chmod(0o644)  # let tmp_path cleanup remove it


class TestPushRefusesWhenBothSourcesMissing:
    """#471(2): push must never overwrite the combined file with an empty scaffold."""

    def test_push_with_both_sources_missing_errors_and_preserves_combined(
        self,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        work_dir = git_repo
        _write_combine_config(
            work_dir,
            name="production",
            clear_file=".env.production.clear",
            secret_file=".env.production.secret",
            combined_file=".env.production",
        )
        clear = work_dir / ".env.production.clear"
        secret = work_dir / ".env.production.secret"
        clear.write_text("DEBUG=false\n", encoding="utf-8")
        secret.write_text("API_KEY=" + "sk_live_" + "0123456789abcdef" * 2 + "\n", encoding="utf-8")

        push1 = _run_envdrift(
            ["push", "--env", "production"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        assert push1.returncode == 0, _out(push1)
        combined = work_dir / ".env.production"
        combined_before = combined.read_bytes()
        assert b"encrypted:" in combined_before  # a real, valuable runtime artifact

        # The routine mistake: both source files vanish (rm, or a config typo).
        clear.unlink()
        secret.unlink()

        push2 = _run_envdrift(
            ["push", "--env", "production"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        out = " ".join(_out(push2).split())
        # Pre-#471: exit 0, "[OK] Push complete!", combined replaced by a
        # header-only scaffold (the last copy of the runtime env destroyed).
        assert push2.returncode == 1, f"exit={push2.returncode}\n{out}"
        assert "Push complete" not in out, out
        assert "refusing to overwrite" in out.lower(), out
        assert combined.read_bytes() == combined_before, (
            "push destroyed the combined file after the sources went missing"
        )


class TestPushRefusesEmptySecretFile:
    """#471(3): an empty .secret must not fabricate dotenvx's placeholder secrets."""

    # The names dotenvx scaffolds into an empty file; none may ever appear.
    _FABRICATED_MARKERS = ("HELLO", "AWS_ACCESS_KEY_ID", "OPENAI_API_KEY")

    def test_push_combine_mode_empty_secret_errors_without_fabricating(
        self,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        work_dir = git_repo
        _write_combine_config(
            work_dir,
            name="production",
            clear_file=".env.production.clear",
            secret_file=".env.production.secret",
            combined_file=".env.production",
        )
        (work_dir / ".env.production.clear").write_text("DEBUG=false\n", encoding="utf-8")
        secret = work_dir / ".env.production.secret"
        secret.write_text("", encoding="utf-8")

        result = _run_envdrift(
            ["push", "--env", "production"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        out = " ".join(_out(result).split())
        # Pre-#471: exit 0, "(1 clear + 13 encrypted)", and the .secret now held
        # 13 fabricated placeholder secrets the user never wrote.
        assert result.returncode == 1, f"exit={result.returncode}\n{out}"
        assert "Push complete" not in out, out
        assert "nothing to encrypt" in out.lower(), out
        assert secret.read_bytes() == b"", (
            f"push fabricated content into the empty .secret:\n{secret.read_text(encoding='utf-8')}"
        )
        assert not (work_dir / ".env.production").exists()

    def test_push_secrets_only_empty_file_errors_without_fabricating(
        self,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        work_dir = git_repo
        secrets = work_dir / "secrets"
        secrets.mkdir()
        _write_secrets_only_config(work_dir, name="prod", secrets_dir="secrets")
        api = secrets / ".env.api"
        api.write_text("", encoding="utf-8")

        result = _run_envdrift(
            ["push"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        out = " ".join(_out(result).split())
        # Pre-#471: "Encrypted 1 file(s)", exit 0, and the file gained the
        # fabricated AWS/OpenAI placeholder secrets.
        assert result.returncode == 1, f"exit={result.returncode}\n{out}"
        assert "nothing to encrypt" in out.lower(), out
        content = api.read_text(encoding="utf-8")
        assert api.read_bytes() == b"", f"push fabricated content into the empty file:\n{content}"
        for marker in self._FABRICATED_MARKERS:
            assert marker not in content, f"fabricated placeholder {marker} in:\n{content}"


class TestPullMergeWritesCombinedSecurely:
    """#471(4): merged/combined files hold decrypted secrets -> 0600 + atomic."""

    def test_pull_merge_combined_file_is_owner_only_and_atomic(
        self,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        pytest.importorskip("azure.identity", reason="Azure SDK not installed")
        pytest.importorskip("azure.keyvault.secrets", reason="Azure Key Vault SDK not installed")
        work_dir = git_repo
        service_dir = work_dir / "service"
        service_dir.mkdir()
        clear = service_dir / ".env.prod.clear"
        secret = service_dir / ".env.prod.secret"
        combined = service_dir / ".env.prod"
        clear.write_text("APP_NAME=myapp\n", encoding="utf-8")
        merged_value = "supersecret-" + "merged"
        secret.write_text(f"API_KEY={merged_value}\n", encoding="utf-8")

        # pull needs a vault section; --skip-sync keeps it offline (the fake
        # Azure URL is never contacted). Same pattern as the lock/pull cycle test.
        (work_dir / "envdrift.toml").write_text(
            "[vault]\n"
            'provider = "azure"\n\n'
            "[vault.azure]\n"
            'vault_url = "https://fake-vault.vault.azure.net/"\n\n'
            "[vault.sync]\n"
            "[[vault.sync.mappings]]\n"
            'secret_name = "test-key"\n'
            f'folder_path = "{service_dir.as_posix()}"\n'
            'environment = "prod"\n\n'
            "[partial_encryption]\n"
            "enabled = true\n\n"
            "[[partial_encryption.environments]]\n"
            'name = "prod"\n'
            f'clear_file = "{clear.as_posix()}"\n'
            f'secret_file = "{secret.as_posix()}"\n'
            f'combined_file = "{combined.as_posix()}"\n',
            encoding="utf-8",
        )

        push = _run_envdrift(
            ["push", "--env", "prod"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        assert push.returncode == 0, _out(push)
        assert "encrypted:" in secret.read_text(encoding="utf-8")
        if sys.platform != "win32":
            # The push-side combined file (combine_files) is owner-only too.
            push_mode = stat.S_IMODE(combined.stat().st_mode)
            assert push_mode == 0o600, f"push combined mode {oct(push_mode)} != 0o600"

        # Remove the artifact so pull --merge must CREATE the merged file fresh
        # (a fresh create is where the 0644-at-umask leak appeared).
        combined.unlink()

        pull = _run_envdrift(
            ["pull", "--merge", "--skip-sync", "--force", "--config", "envdrift.toml"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        out = " ".join(_out(pull).split())
        assert pull.returncode == 0, out
        assert "merged" in out.lower(), out
        merged_body = combined.read_text(encoding="utf-8")
        # The merged file genuinely holds the DECRYPTED secret...
        assert f"API_KEY={merged_value}" in merged_body, merged_body
        assert "=encrypted:" not in merged_body, merged_body
        if sys.platform != "win32":
            # ...so it must be owner-only, exactly like .env.keys (pre-#471 it
            # was created world-readable at the process umask).
            mode = stat.S_IMODE(combined.stat().st_mode)
            assert mode == 0o600, f"merged combined file mode {oct(mode)} != 0o600"
        # Atomic write: no half-written temp artifacts left next to the secrets.
        leftovers = list(service_dir.glob("*.envdrift-tmp"))
        assert leftovers == [], f"temp files left behind: {leftovers}"
