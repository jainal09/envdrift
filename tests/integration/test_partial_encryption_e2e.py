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
import subprocess
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
    # encoding="utf-8" so a non-ASCII secret_file name (e.g. "café.env.secret")
    # is written as UTF-8 on every platform. Without it the write uses the
    # locale codec (cp1252 on Windows), and the UTF-8-only tomllib config
    # loader would then fail to parse the file for the wrong reason.
    (work_dir / "envdrift.toml").write_text(
        "[partial_encryption]\n"
        "enabled = true\n\n"
        "[[partial_encryption.environments]]\n"
        f'name = "{name}"\n'
        f'clear_file = "{clear_file}"\n'
        f'secret_file = "{secret_file}"\n'
        f'combined_file = "{combined_file}"\n',
        encoding="utf-8",
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
        """BP-09: pull-partial with .env.keys removed surfaces the decrypt-key failure, exits non-zero."""
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
        # dotenvx surfaces the missing key as MISSING_PRIVATE_KEY (v1) or
        # DECRYPTION_FAILED (v2); accept either so the bump doesn't break this.
        assert (
            "MISSING_PRIVATE_KEY" in out
            or "DECRYPTION_FAILED" in out
            or "private key" in out.lower()
        ), out
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
# Secret-lockout filename guard reaches the partial-encryption CLI paths (#467)
# ---------------------------------------------------------------------------


class TestUnsafeFilenameLockoutGuard:
    """#467: ``envdrift push`` refuses filenames dotenvx cannot key — end to end.

    dotenvx derives ``DOTENV_PRIVATE_KEY_<SLUG>`` from the filename. A space or
    non-ASCII character yields an invalid env-var name: the value encrypts and
    dotenvx exits 0, but the file is then permanently undecryptable and the
    plaintext is destroyed — a silent secret lockout. #457 guarded the bare
    ``encrypt`` backend; the partial-encryption push/lock paths reach dotenvx
    through ``DotenvxWrapper`` instead, so they needed the same guard (#467).

    These drive the REAL ``envdrift push`` CLI as a subprocess with the real
    dotenvx binary available (module skip-gate above) and assert the refusal
    happens BEFORE dotenvx runs: non-zero exit, clean error message, plaintext
    preserved byte-for-byte, and no ``.env.keys`` ever created. Both fail RED on
    the pre-#468 code (push exits 0, the file is encrypted under an unusable
    key, and the plaintext is gone).
    """

    def test_push_secrets_only_refuses_space_filename_real_cli(
        self,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Secrets-only push: a space-named file is refused with plaintext intact."""
        work_dir = git_repo
        secrets = work_dir / "secrets"
        secrets.mkdir()
        # Custom pattern: the default ".env*" glob would never match this name,
        # silently masking the guard. "*.env*" mirrors a real user pattern.
        (work_dir / "envdrift.toml").write_text(
            "[partial_encryption]\n"
            "enabled = true\n\n"
            "[[partial_encryption.environments]]\n"
            'name = "prod"\n'
            "secrets_only = true\n"
            'secrets_dir = "secrets"\n'
            'pattern = "*.env*"\n',
            encoding="utf-8",
        )

        bad = secrets / "my secret.env"
        # Credential-like fixture built by concatenation (push-protection safe).
        bad.write_text("PASSWORD=keep" + "me123\n", encoding="utf-8")
        before = bad.read_bytes()

        result = _run_envdrift(
            ["push"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        out = " ".join(_out(result).split())
        assert result.returncode == 1, out
        assert "Refusing to encrypt" in out, out
        assert "my secret.env" in out, out
        assert "Errors: 1" in out, out
        # The guard fired pre-flight: plaintext byte-for-byte intact (which, as
        # `before` is the plaintext fixture, also proves it was never encrypted).
        assert bad.read_bytes() == before, "plaintext was modified"
        # dotenvx never ran, so no private-key file was ever written.
        assert not (secrets / ".env.keys").exists(), "dotenvx was invoked despite the guard"
        assert not (work_dir / ".env.keys").exists(), "dotenvx was invoked despite the guard"

    def test_push_combine_refuses_non_ascii_secret_filename_real_cli(
        self,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Combine push: a non-ASCII .secret filename is refused, nothing generated."""
        work_dir = git_repo
        clear = work_dir / ".env.prod.clear"
        secret = work_dir / "café.env.secret"  # non-ASCII -> invalid dotenvx key slug
        combined = work_dir / ".env.prod"
        _write_combine_config(
            work_dir,
            name="prod",
            clear_file=clear.name,
            secret_file=secret.name,
            combined_file=combined.name,
        )

        clear.write_text("APP_NAME=myapp\n", encoding="utf-8")
        secret.write_text("API_KEY=top" + "secret42\n", encoding="utf-8")
        before = secret.read_bytes()

        result = _run_envdrift(
            ["push"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        out = " ".join(_out(result).split())
        assert result.returncode == 1, out
        # Assert on the ASCII core of the message so console encoding quirks
        # around the non-ASCII filename can never flake the test.
        assert "Refusing to encrypt" in out, out
        assert "Errors: 1" in out, out
        # Plaintext preserved byte-for-byte; no lockout occurred (byte-equality
        # against the plaintext fixture also proves it was never encrypted).
        assert secret.read_bytes() == before, "plaintext was modified"
        # The failed environment must not generate the combined artifact, and
        # dotenvx must never have run (no private-key file).
        assert not combined.exists(), "combined file generated despite the refusal"
        assert not (work_dir / ".env.keys").exists(), "dotenvx was invoked despite the guard"
