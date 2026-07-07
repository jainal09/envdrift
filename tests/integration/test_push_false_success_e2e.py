"""#471 push-false-success end-to-end regression tests (real dotenvx + real git).

Split out of ``test_partial_encryption_e2e.py`` to keep that module under the
code-health size threshold; same conventions (real subprocesses, no mocking of
the behavior under test, per-test ``tmp_path`` isolation, dotenvx skip-gate).

The four guarded failure modes covered here are described in the banner comment
below; together with #470's lock/check coverage this closes the #485
regression-coverage gap.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which("dotenvx") is None,
        reason="dotenvx binary not installed (required for real partial-encryption e2e)",
    ),
]


# Private copies of the host module's runner helpers: tests/integration is not
# a package, so importing them across test modules would be rootdir-fragile.
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
        timeout=60,
    )


def _write_combine_config(work_dir: Path, *, name: str = "production") -> None:
    """Write a combine-mode envdrift.toml using the standard ``.env.<name>`` layout.

    clear/secret/combined paths follow the conventional ``.env.<name>.clear`` /
    ``.env.<name>.secret`` / ``.env.<name>`` naming, so only the environment
    name varies between tests.
    """
    (work_dir / "envdrift.toml").write_text(
        "[partial_encryption]\n"
        "enabled = true\n\n"
        "[[partial_encryption.environments]]\n"
        f'name = "{name}"\n'
        f'clear_file = ".env.{name}.clear"\n'
        f'secret_file = ".env.{name}.secret"\n'
        f'combined_file = ".env.{name}"\n'
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


def _out(result: subprocess.CompletedProcess[str]) -> str:
    """Combined stdout+stderr for substring assertions."""
    return result.stdout + result.stderr


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
        _write_combine_config(work_dir)
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
        _write_combine_config(work_dir)
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
        _write_combine_config(work_dir)
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
        _write_combine_config(work_dir)
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
