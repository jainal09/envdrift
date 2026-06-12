"""Regression tests for issue #470: lock must use the canonical encryption predicates.

``envdrift lock`` used to decide "already encrypted" with a >=90% ciphertext-line
ratio (and ``lock --all`` with an any-ciphertext regex), instead of the canonical
predicates (``has_plaintext_secret_value`` / ``_is_fully_encrypted``). That cut
both ways:

- a MIXED file (>=18 encrypted values + 1 fresh plaintext secret) was blessed
  "already encrypted" and ``lock --check`` exited 0 — a false security PASS;
- a FULLY-encrypted file with fewer than 9 variables was forever flagged
  "partially encrypted" (the plaintext ``DOTENV_PUBLIC_KEY_*`` header counted in
  the ratio denominator) and ``lock --check`` exited 1 — a false FAIL;
- ``lock --all`` skipped a mixed ``.secret`` file and deleted the combined file
  while the fresh plaintext secret survived, exit 0;
- ``lock --all`` printed the unconditional "ready to commit" banner with exit 0
  while knowingly skipping secrets-only environments that still held plaintext.

These tests drive the real ``envdrift`` CLI as a subprocess with the real
``dotenvx`` binary. All fixtures are produced by a real ``envdrift encrypt`` so
they carry the exact production input shape, including the ``DOTENV_PUBLIC_KEY``
header line (contributes regression coverage for issue #485).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("dotenvx") is None, reason="dotenvx binary not installed"),
]

# Built by concatenation so the fixture never contains a realistic secret
# literal (GitHub push protection).
LEAKED_VALUE = "ghp_" + "realtokenplaintext12345"

CONFIG_BASE = """\
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

CONFIG_COMBINE_PARTIAL = (
    CONFIG_BASE
    + """
[partial_encryption]
enabled = true

[[partial_encryption.environments]]
name = "production"
clear_file = "partial/.env.production.clear"
secret_file = "partial/.env.production.secret"
combined_file = "partial/.env.production"
"""
)

CONFIG_SECRETS_ONLY_PARTIAL = (
    CONFIG_BASE
    + """
[partial_encryption]
enabled = true

[[partial_encryption.environments]]
name = "api"
secrets_only = true
secrets_dir = "secrets"
"""
)


def _run(
    envdrift_cmd: list[str],
    args: list[str],
    cwd: Path,
    pythonpath: str,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    """Run the real envdrift CLI as a subprocess in ``cwd``."""
    env = os.environ.copy()
    env["PYTHONPATH"] = pythonpath
    return subprocess.run(
        [*envdrift_cmd, *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def _norm(result: subprocess.CompletedProcess[str]) -> str:
    """Normalize Rich output (line wraps under narrow CI consoles) for substring asserts."""
    return " ".join((result.stdout + result.stderr).split())


def _write_and_encrypt(
    envdrift_cmd: list[str],
    pythonpath: str,
    project: Path,
    rel_path: str,
    pairs: list[str],
) -> Path:
    """Write ``pairs`` to ``rel_path`` and encrypt it with the real dotenvx backend."""
    file = project / rel_path
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text("\n".join(pairs) + "\n", encoding="utf-8")
    result = _run(envdrift_cmd, ["encrypt", rel_path], project, pythonpath)
    assert result.returncode == 0, f"setup encrypt failed:\n{result.stdout}\n{result.stderr}"
    content = file.read_text(encoding="utf-8")
    # The exact production input shape: dotenvx writes a plaintext public-key
    # header line above the ciphertext (#485).
    assert "DOTENV_PUBLIC_KEY" in content
    assert "encrypted:" in content
    return file


def _append_plaintext(file: Path, line: str) -> None:
    file.write_text(file.read_text(encoding="utf-8") + line + "\n", encoding="utf-8")


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A minimal envdrift project with one dotenvx-backed sync mapping."""
    (tmp_path / "envdrift.toml").write_text(CONFIG_BASE, encoding="utf-8")
    (tmp_path / "svc").mkdir()
    return tmp_path


def _make_mixed_env_file(envdrift_cmd: list[str], pythonpath: str, project: Path) -> Path:
    """18 encrypted values + 1 fresh plaintext secret: >=90% ciphertext lines.

    18 encrypted lines over 20 assignment lines (incl. the public-key header and
    the appended plaintext) is exactly the 0.90 ratio the old heuristic blessed
    as "already encrypted".
    """
    env_file = _write_and_encrypt(
        envdrift_cmd,
        pythonpath,
        project,
        "svc/.env.production",
        [f"SECRET_{i}=value{i}" for i in range(1, 19)],
    )
    _append_plaintext(env_file, "NEW_SECRET=" + LEAKED_VALUE)
    return env_file


class TestLockMixedStateFile:
    """Item 2 of #470: a mixed dotenvx file must never be blessed as encrypted."""

    def test_lock_check_fails_on_mixed_file_with_fresh_plaintext(
        self, project: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ):
        """lock --check must exit 1 when a fresh plaintext secret hides in ciphertext."""
        env_file = _make_mixed_env_file(envdrift_cmd, integration_pythonpath, project)
        before = env_file.read_bytes()

        result = _run(envdrift_cmd, ["lock", "--check"], project, integration_pythonpath)

        assert result.returncode == 1, (
            f"lock --check blessed a mixed file with a plaintext secret:\n{result.stdout}"
        )
        assert "need encryption" in _norm(result).lower()
        # --check is a dry run: the file must not be modified.
        assert env_file.read_bytes() == before

    def test_lock_force_reencrypts_mixed_file(
        self, project: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ):
        """lock --force must re-encrypt the fresh plaintext value, not skip the file."""
        env_file = _make_mixed_env_file(envdrift_cmd, integration_pythonpath, project)

        result = _run(envdrift_cmd, ["lock", "--force"], project, integration_pythonpath)

        assert result.returncode == 0, f"lock --force failed:\n{result.stdout}\n{result.stderr}"
        content = env_file.read_text(encoding="utf-8")
        assert LEAKED_VALUE not in content, "fresh plaintext secret survived lock --force"
        assert "NEW_SECRET=encrypted:" in content.replace('"', "")
        # Post-condition verified end-to-end: a subsequent check now passes.
        recheck = _run(envdrift_cmd, ["lock", "--check"], project, integration_pythonpath)
        assert recheck.returncode == 0, f"re-check after lock failed:\n{recheck.stdout}"


class TestLockFullyEncryptedSmallFile:
    """Item 3 of #470: the public-key header must not count as a plaintext variable."""

    def test_lock_check_passes_fully_encrypted_three_var_file(
        self, project: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ):
        """A fully-encrypted 3-variable file is not 'partially encrypted (75%)'."""
        _write_and_encrypt(
            envdrift_cmd,
            integration_pythonpath,
            project,
            "svc/.env.production",
            ["API_KEY=s1", "DB_PASS=s2", "TOKEN=s3"],
        )

        result = _run(envdrift_cmd, ["lock", "--check"], project, integration_pythonpath)

        assert result.returncode == 0, (
            f"lock --check flagged a fully-encrypted small file:\n{result.stdout}"
        )
        assert "all files are already encrypted" in _norm(result).lower()

    def test_lock_force_does_not_churn_fully_encrypted_small_file(
        self, project: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ):
        """lock --force must skip (not re-encrypt) a fully-encrypted small file."""
        env_file = _write_and_encrypt(
            envdrift_cmd,
            integration_pythonpath,
            project,
            "svc/.env.production",
            ["API_KEY=s1", "DB_PASS=s2", "TOKEN=s3"],
        )
        before = env_file.read_bytes()

        result = _run(envdrift_cmd, ["lock", "--force"], project, integration_pythonpath)

        assert result.returncode == 0, f"lock --force failed:\n{result.stdout}\n{result.stderr}"
        # dotenvx encryption is non-deterministic, so any re-encrypt would change
        # the bytes; identical bytes prove the file was correctly skipped.
        assert env_file.read_bytes() == before
        assert "skipped (already encrypted)" in _norm(result).lower()


class TestLockEncryptCheckParity:
    """Item 2 of #470 (verifier note): lock --check and encrypt --check must agree."""

    def test_gates_agree_on_mixed_file(
        self, project: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ):
        _make_mixed_env_file(envdrift_cmd, integration_pythonpath, project)

        encrypt_check = _run(
            envdrift_cmd,
            ["encrypt", "svc/.env.production", "--check"],
            project,
            integration_pythonpath,
        )
        lock_check = _run(envdrift_cmd, ["lock", "--check"], project, integration_pythonpath)

        assert encrypt_check.returncode == 1, (
            f"encrypt --check missed the plaintext secret:\n{encrypt_check.stdout}"
        )
        assert lock_check.returncode == encrypt_check.returncode, (
            "lock --check and encrypt --check disagree on the same mixed file: "
            f"lock={lock_check.returncode} encrypt={encrypt_check.returncode}\n"
            f"{lock_check.stdout}"
        )

    def test_gates_agree_on_fully_encrypted_file(
        self, project: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ):
        _write_and_encrypt(
            envdrift_cmd,
            integration_pythonpath,
            project,
            "svc/.env.production",
            ["API_KEY=s1", "DB_PASS=s2", "TOKEN=s3"],
        )

        encrypt_check = _run(
            envdrift_cmd,
            ["encrypt", "svc/.env.production", "--check"],
            project,
            integration_pythonpath,
        )
        lock_check = _run(envdrift_cmd, ["lock", "--check"], project, integration_pythonpath)

        assert encrypt_check.returncode == 0, (
            f"encrypt --check flagged a fully-encrypted file:\n{encrypt_check.stdout}"
        )
        assert lock_check.returncode == encrypt_check.returncode, (
            "lock --check and encrypt --check disagree on the same encrypted file: "
            f"lock={lock_check.returncode} encrypt={encrypt_check.returncode}\n"
            f"{lock_check.stdout}"
        )


class TestLockAllMixedSecretFile:
    """Item 1 of #470: lock --all must re-encrypt a mixed-state .secret file."""

    @pytest.fixture
    def partial_project(
        self, tmp_path: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> tuple[Path, Path, Path]:
        """Project with a combine-mode partial env whose .secret is mixed-state."""
        (tmp_path / "envdrift.toml").write_text(CONFIG_COMBINE_PARTIAL, encoding="utf-8")
        (tmp_path / "svc").mkdir()
        # The regular mapping is fully encrypted so step 2 is uneventful.
        _write_and_encrypt(
            envdrift_cmd,
            integration_pythonpath,
            tmp_path,
            "svc/.env.production",
            ["API_KEY=s1", "DB_PASS=s2", "TOKEN=s3"],
        )
        secret_file = _write_and_encrypt(
            envdrift_cmd,
            integration_pythonpath,
            tmp_path,
            "partial/.env.production.secret",
            ["API_KEY=oldvalue1"],
        )
        # A fresh plaintext secret appended after the file was encrypted.
        _append_plaintext(secret_file, "NEW_SECRET=" + LEAKED_VALUE)
        combined_file = tmp_path / "partial" / ".env.production"
        combined_file.write_text("APP_NAME=myapp\nAPI_KEY=oldvalue1\n", encoding="utf-8")
        return tmp_path, secret_file, combined_file

    def test_lock_all_reencrypts_mixed_secret_file(
        self,
        partial_project: tuple[Path, Path, Path],
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """The mixed .secret is re-encrypted; the plaintext never survives exit 0."""
        project, secret_file, combined_file = partial_project

        result = _run(envdrift_cmd, ["lock", "--all", "--force"], project, integration_pythonpath)

        assert result.returncode == 0, (
            f"lock --all --force failed:\n{result.stdout}\n{result.stderr}"
        )
        content = secret_file.read_text(encoding="utf-8")
        assert LEAKED_VALUE not in content, (
            "lock --all skipped a mixed .secret and left the fresh secret plaintext"
        )
        assert "NEW_SECRET=encrypted:" in content.replace('"', "")
        # Combined-file cleanup still happens.
        assert not combined_file.exists()

    def test_lock_all_check_fails_on_mixed_secret_file(
        self,
        partial_project: tuple[Path, Path, Path],
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """lock --all --check must exit 1 while the .secret still needs encryption."""
        project, secret_file, combined_file = partial_project
        before = secret_file.read_bytes()

        result = _run(envdrift_cmd, ["lock", "--all", "--check"], project, integration_pythonpath)

        assert result.returncode == 1, (
            f"lock --all --check blessed a mixed .secret file:\n{result.stdout}"
        )
        # Dry run: nothing was modified or deleted.
        assert secret_file.read_bytes() == before
        assert combined_file.exists()


class TestLockAllSecretsOnlySkip:
    """Item 4 of #470: the final banner/exit must reflect skipped secrets-only envs."""

    @pytest.fixture
    def secrets_only_project(
        self, tmp_path: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> Path:
        (tmp_path / "envdrift.toml").write_text(CONFIG_SECRETS_ONLY_PARTIAL, encoding="utf-8")
        (tmp_path / "svc").mkdir()
        (tmp_path / "secrets").mkdir()
        # The regular mapping is fully encrypted so only the skipped
        # secrets-only environment decides the outcome.
        _write_and_encrypt(
            envdrift_cmd,
            integration_pythonpath,
            tmp_path,
            "svc/.env.production",
            ["API_KEY=s1", "DB_PASS=s2", "TOKEN=s3"],
        )
        return tmp_path

    def test_lock_all_fails_when_skipped_secrets_only_env_holds_plaintext(
        self,
        secrets_only_project: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """No green 'ready to commit' / exit 0 while a skipped env holds plaintext."""
        project = secrets_only_project
        api_file = project / "secrets" / ".env.api"
        api_file.write_text("API_TOKEN=" + LEAKED_VALUE + "\n", encoding="utf-8")

        result = _run(envdrift_cmd, ["lock", "--all", "--force"], project, integration_pythonpath)

        assert result.returncode == 1, (
            "lock --all exited 0 while a skipped secrets-only environment still "
            f"held plaintext:\n{result.stdout}"
        )
        norm = _norm(result).lower()
        assert "envdrift push" in norm
        assert "ready to commit" not in norm
        # lock --all does not own these files; push does. They must be untouched.
        assert api_file.read_text(encoding="utf-8") == "API_TOKEN=" + LEAKED_VALUE + "\n"

    def test_lock_all_passes_when_skipped_secrets_only_env_is_encrypted(
        self,
        secrets_only_project: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """A fully-encrypted secrets-only env is a benign skip: summary notes it, exit 0."""
        project = secrets_only_project
        _write_and_encrypt(
            envdrift_cmd,
            integration_pythonpath,
            project,
            "secrets/.env.api",
            ["API_TOKEN=value1"],
        )

        result = _run(envdrift_cmd, ["lock", "--all", "--force"], project, integration_pythonpath)

        assert result.returncode == 0, (
            f"lock --all failed on a fully-encrypted secrets-only env:\n"
            f"{result.stdout}\n{result.stderr}"
        )
        norm = _norm(result).lower()
        assert "secrets-only environments skipped: 1" in norm
        assert "ready to commit" in norm
