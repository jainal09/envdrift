"""Regression tests for issue #470: lock must use the canonical encryption predicates.

``envdrift lock`` used to decide "already encrypted" with a >=90% ciphertext-line
ratio (and ``lock --all`` with an any-ciphertext regex), instead of the canonical
predicates (``has_plaintext_secret_value`` / ``is_fully_encrypted``). That cut
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

The mixed-state gate is backend-agnostic (PR #507 review): a SOPS-encrypted file
holding a freshly appended plaintext secret must fail ``lock --check`` exactly
like a dotenvx one, and ``--check`` must stay a pure dry run in its messaging
(report "would re-encrypt", never the active "re-encrypting...").

These tests drive the real ``envdrift`` CLI as a subprocess with the real
``dotenvx`` (and, where present, ``sops``) binaries. All dotenvx fixtures are
produced by a real ``envdrift encrypt`` so they carry the exact production input
shape, including the ``DOTENV_PUBLIC_KEY`` header line (contributes regression
coverage for issue #485).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import textwrap
from pathlib import Path
from typing import NamedTuple

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("dotenvx") is None, reason="dotenvx binary not installed"),
]

# Built by concatenation so the fixture never contains a realistic secret
# literal (GitHub push protection).
LEAKED_VALUE = "ghp_" + "realtokenplaintext12345"

# Test-only age keypair, identical to tests/integration/test_encryption_tools.py.
AGE_PUBLIC_KEY = "age1c89jtrvyl72y0muvdp5lm3jpemvc2gr303up4g37tuq4uftcku3q4svqau"
AGE_PRIVATE_KEY = "AGE-SECRET-KEY-1HGE3ZE9NPEN5R76LVKKJ2Z3G9TYZJLW84P2CHAF6UGL43R7TWPUSZ89MK6"

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

CONFIG_SOPS = f"""\
[vault]
provider = "aws"

[vault.aws]
region = "us-east-1"

[encryption]
backend = "sops"

[encryption.sops]
config_file = ".sops.yaml"
age_key_file = "age.key"
age_recipients = "{AGE_PUBLIC_KEY}"

[[vault.sync.mappings]]
secret_name = "svc-key"
folder_path = "svc"
environment = "production"
"""


class Cli(NamedTuple):
    """The real envdrift CLI bound to this test session's interpreter env."""

    cmd: list[str]
    pythonpath: str

    def run(
        self, args: list[str], cwd: Path, timeout: int = 120
    ) -> subprocess.CompletedProcess[str]:
        """Run the real envdrift CLI as a subprocess in ``cwd``."""
        env = os.environ.copy()
        env["PYTHONPATH"] = self.pythonpath
        return subprocess.run(
            [*self.cmd, *args],
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )

    def write_and_encrypt(self, project: Path, rel_path: str, pairs: list[str]) -> Path:
        """Write ``pairs`` to ``rel_path`` and encrypt it with the real dotenvx backend."""
        file = project / rel_path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("\n".join(pairs) + "\n", encoding="utf-8")
        result = self.run(["encrypt", rel_path], project)
        assert result.returncode == 0, f"setup encrypt failed:\n{result.stdout}\n{result.stderr}"
        content = file.read_text(encoding="utf-8")
        # The exact production input shape: dotenvx writes a plaintext public-key
        # header line above the ciphertext (#485).
        assert "DOTENV_PUBLIC_KEY" in content
        assert "encrypted:" in content
        return file


def _norm(result: subprocess.CompletedProcess[str]) -> str:
    """Normalize Rich output (line wraps under narrow CI consoles) for substring asserts."""
    return " ".join((result.stdout + result.stderr).split())


def _append_plaintext(file: Path, line: str) -> None:
    file.write_text(file.read_text(encoding="utf-8") + line + "\n", encoding="utf-8")


@pytest.fixture
def cli(envdrift_cmd: list[str], integration_pythonpath: str) -> Cli:
    """The real envdrift CLI runner for this session."""
    return Cli(cmd=envdrift_cmd, pythonpath=integration_pythonpath)


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A minimal envdrift project with one dotenvx-backed sync mapping."""
    (tmp_path / "envdrift.toml").write_text(CONFIG_BASE, encoding="utf-8")
    (tmp_path / "svc").mkdir()
    return tmp_path


def _make_mixed_env_file(cli: Cli, project: Path) -> Path:
    """18 encrypted values + 1 fresh plaintext secret: >=90% ciphertext lines.

    18 encrypted lines over 20 assignment lines (incl. the public-key header and
    the appended plaintext) is exactly the 0.90 ratio the old heuristic blessed
    as "already encrypted".
    """
    env_file = cli.write_and_encrypt(
        project,
        "svc/.env.production",
        [f"SECRET_{i}=value{i}" for i in range(1, 19)],
    )
    _append_plaintext(env_file, "NEW_SECRET=" + LEAKED_VALUE)
    return env_file


class TestLockMixedStateFile:
    """Item 2 of #470: a mixed dotenvx file must never be blessed as encrypted."""

    def test_lock_check_fails_on_mixed_file_with_fresh_plaintext(self, project: Path, cli: Cli):
        """lock --check must exit 1 when a fresh plaintext secret hides in ciphertext."""
        env_file = _make_mixed_env_file(cli, project)
        before = env_file.read_bytes()

        result = cli.run(["lock", "--check"], project)

        assert result.returncode == 1, (
            f"lock --check blessed a mixed file with a plaintext secret:\n{result.stdout}"
        )
        norm = _norm(result).lower()
        assert "need encryption" in norm
        # --check is a dry run and must SPEAK like one (PR #507 review): the
        # mixed file is reported as "would re-encrypt", never with the active
        # "re-encrypting..." voice that implies the file was touched.
        assert "would re-encrypt (plaintext values remain)" in norm
        assert "re-encrypting" not in norm
        # --check is a dry run: the file must not be modified.
        assert env_file.read_bytes() == before

    def test_lock_force_reencrypts_mixed_file(self, project: Path, cli: Cli):
        """lock --force must re-encrypt the fresh plaintext value, not skip the file."""
        env_file = _make_mixed_env_file(cli, project)

        result = cli.run(["lock", "--force"], project)

        assert result.returncode == 0, f"lock --force failed:\n{result.stdout}\n{result.stderr}"
        content = env_file.read_text(encoding="utf-8")
        assert LEAKED_VALUE not in content, "fresh plaintext secret survived lock --force"
        assert "NEW_SECRET=encrypted:" in content.replace('"', "")
        # Post-condition verified end-to-end: a subsequent check now passes.
        recheck = cli.run(["lock", "--check"], project)
        assert recheck.returncode == 0, f"re-check after lock failed:\n{recheck.stdout}"


class TestLockSopsMixedStateFile:
    """PR #507 review (high): the mixed-state gate must cover SOPS, not just dotenvx.

    A SOPS-encrypted file with a freshly appended plaintext secret used to be
    skipped as "already encrypted" purely because ``is_encrypted_content`` saw a
    SOPS header — the exact #470 item-2 bug class, surviving for the SOPS
    backend. ``lock --check`` must flag it and exit 1. (Whether the SOPS backend
    then re-encrypts such a mixed file correctly is tracked separately in #475.)
    """

    pytestmark = pytest.mark.skipif(
        shutil.which("sops") is None, reason="sops binary not installed"
    )

    @pytest.fixture
    def sops_project(self, tmp_path: Path, cli: Cli) -> tuple[Path, Path]:
        """A SOPS-backed project whose env file is encrypted, then made mixed."""
        (tmp_path / "envdrift.toml").write_text(CONFIG_SOPS, encoding="utf-8")
        (tmp_path / "svc").mkdir()
        (tmp_path / "age.key").write_text(
            textwrap.dedent(
                f"""\
                # public key: {AGE_PUBLIC_KEY}
                {AGE_PRIVATE_KEY}
                """
            ),
            encoding="utf-8",
        )
        (tmp_path / ".sops.yaml").write_text(
            textwrap.dedent(
                f"""\
                creation_rules:
                  - path_regex: \\.env\\.production$
                    age: {AGE_PUBLIC_KEY}
                """
            ),
            encoding="utf-8",
        )
        env_file = tmp_path / "svc" / ".env.production"
        env_file.write_text("API_KEY=oldvalue1\nDB_PASS=oldvalue2\n", encoding="utf-8")
        result = cli.run(["encrypt", "svc/.env.production", "--backend", "sops"], tmp_path)
        assert result.returncode == 0, (
            f"sops setup encrypt failed:\n{result.stdout}\n{result.stderr}"
        )
        content = env_file.read_text(encoding="utf-8")
        assert "ENC[AES256_GCM," in content, f"sops did not encrypt the fixture:\n{content}"
        _append_plaintext(env_file, "NEW_SECRET=" + LEAKED_VALUE)
        return tmp_path, env_file

    def test_lock_check_fails_on_mixed_sops_file(self, sops_project: tuple[Path, Path], cli: Cli):
        """lock --check must exit 1 on a SOPS file holding a fresh plaintext secret."""
        project, env_file = sops_project
        before = env_file.read_bytes()

        result = cli.run(["lock", "--check"], project)

        assert result.returncode == 1, (
            f"lock --check blessed a mixed SOPS file with a plaintext secret:\n{result.stdout}"
        )
        norm = _norm(result).lower()
        assert "would re-encrypt (plaintext values remain)" in norm
        assert "re-encrypting" not in norm
        # Dry run: the file must not be modified.
        assert env_file.read_bytes() == before


class TestLockFullyEncryptedSmallFile:
    """Item 3 of #470: the public-key header must not count as a plaintext variable."""

    def test_lock_check_passes_fully_encrypted_three_var_file(self, project: Path, cli: Cli):
        """A fully-encrypted 3-variable file is not 'partially encrypted (75%)'."""
        cli.write_and_encrypt(
            project, "svc/.env.production", ["API_KEY=s1", "DB_PASS=s2", "TOKEN=s3"]
        )

        result = cli.run(["lock", "--check"], project)

        assert result.returncode == 0, (
            f"lock --check flagged a fully-encrypted small file:\n{result.stdout}"
        )
        assert "all files are already encrypted" in _norm(result).lower()

    def test_lock_force_does_not_churn_fully_encrypted_small_file(self, project: Path, cli: Cli):
        """lock --force must skip (not re-encrypt) a fully-encrypted small file."""
        env_file = cli.write_and_encrypt(
            project, "svc/.env.production", ["API_KEY=s1", "DB_PASS=s2", "TOKEN=s3"]
        )
        before = env_file.read_bytes()

        result = cli.run(["lock", "--force"], project)

        assert result.returncode == 0, f"lock --force failed:\n{result.stdout}\n{result.stderr}"
        # dotenvx encryption is non-deterministic, so any re-encrypt would change
        # the bytes; identical bytes prove the file was correctly skipped.
        assert env_file.read_bytes() == before
        assert "skipped (already encrypted)" in _norm(result).lower()


class TestLockEncryptCheckParity:
    """Item 2 of #470 (verifier note): lock --check and encrypt --check must agree."""

    @pytest.mark.parametrize(
        ("mixed", "expected_rc", "label"),
        [
            pytest.param(True, 1, "mixed file with a fresh plaintext secret", id="mixed"),
            pytest.param(False, 0, "fully-encrypted file", id="fully-encrypted"),
        ],
    )
    def test_gates_agree(self, project: Path, cli: Cli, mixed: bool, expected_rc: int, label: str):
        if mixed:
            _make_mixed_env_file(cli, project)
        else:
            cli.write_and_encrypt(
                project, "svc/.env.production", ["API_KEY=s1", "DB_PASS=s2", "TOKEN=s3"]
            )

        encrypt_check = cli.run(["encrypt", "svc/.env.production", "--check"], project)
        lock_check = cli.run(["lock", "--check"], project)

        assert encrypt_check.returncode == expected_rc, (
            f"encrypt --check gave the wrong verdict on a {label}:\n{encrypt_check.stdout}"
        )
        assert lock_check.returncode == encrypt_check.returncode, (
            f"lock --check and encrypt --check disagree on the same {label}: "
            f"lock={lock_check.returncode} encrypt={encrypt_check.returncode}\n"
            f"{lock_check.stdout}"
        )


class TestLockAllMixedSecretFile:
    """Item 1 of #470: lock --all must re-encrypt a mixed-state .secret file."""

    @pytest.fixture
    def partial_project(self, tmp_path: Path, cli: Cli) -> tuple[Path, Path, Path]:
        """Project with a combine-mode partial env whose .secret is mixed-state."""
        (tmp_path / "envdrift.toml").write_text(CONFIG_COMBINE_PARTIAL, encoding="utf-8")
        (tmp_path / "svc").mkdir()
        # The regular mapping is fully encrypted so step 2 is uneventful.
        cli.write_and_encrypt(
            tmp_path, "svc/.env.production", ["API_KEY=s1", "DB_PASS=s2", "TOKEN=s3"]
        )
        secret_file = cli.write_and_encrypt(
            tmp_path, "partial/.env.production.secret", ["API_KEY=oldvalue1"]
        )
        # A fresh plaintext secret appended after the file was encrypted.
        _append_plaintext(secret_file, "NEW_SECRET=" + LEAKED_VALUE)
        combined_file = tmp_path / "partial" / ".env.production"
        combined_file.write_text("APP_NAME=myapp\nAPI_KEY=oldvalue1\n", encoding="utf-8")
        return tmp_path, secret_file, combined_file

    def test_lock_all_reencrypts_mixed_secret_file(
        self, partial_project: tuple[Path, Path, Path], cli: Cli
    ):
        """The mixed .secret is re-encrypted; the plaintext never survives exit 0."""
        project, secret_file, combined_file = partial_project

        result = cli.run(["lock", "--all", "--force"], project)

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
        self, partial_project: tuple[Path, Path, Path], cli: Cli
    ):
        """lock --all --check must exit 1 while the .secret still needs encryption."""
        project, secret_file, combined_file = partial_project
        before = secret_file.read_bytes()

        result = cli.run(["lock", "--all", "--check"], project)

        assert result.returncode == 1, (
            f"lock --all --check blessed a mixed .secret file:\n{result.stdout}"
        )
        # Dry run: nothing was modified or deleted.
        assert secret_file.read_bytes() == before
        assert combined_file.exists()


class TestLockAllSecretsOnlySkip:
    """Item 4 of #470: the final banner/exit must reflect skipped secrets-only envs."""

    @pytest.fixture
    def secrets_only_project(self, tmp_path: Path, cli: Cli) -> Path:
        (tmp_path / "envdrift.toml").write_text(CONFIG_SECRETS_ONLY_PARTIAL, encoding="utf-8")
        (tmp_path / "svc").mkdir()
        (tmp_path / "secrets").mkdir()
        # The regular mapping is fully encrypted so only the skipped
        # secrets-only environment decides the outcome.
        cli.write_and_encrypt(
            tmp_path, "svc/.env.production", ["API_KEY=s1", "DB_PASS=s2", "TOKEN=s3"]
        )
        return tmp_path

    def test_lock_all_fails_when_skipped_secrets_only_env_holds_plaintext(
        self, secrets_only_project: Path, cli: Cli
    ):
        """No green 'ready to commit' / exit 0 while a skipped env holds plaintext."""
        project = secrets_only_project
        api_file = project / "secrets" / ".env.api"
        api_file.write_text("API_TOKEN=" + LEAKED_VALUE + "\n", encoding="utf-8")

        result = cli.run(["lock", "--all", "--force"], project)

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
        self, secrets_only_project: Path, cli: Cli
    ):
        """A fully-encrypted secrets-only env is a benign skip: summary notes it, exit 0."""
        project = secrets_only_project
        cli.write_and_encrypt(project, "secrets/.env.api", ["API_TOKEN=value1"])

        result = cli.run(["lock", "--all", "--force"], project)

        assert result.returncode == 0, (
            f"lock --all failed on a fully-encrypted secrets-only env:\n"
            f"{result.stdout}\n{result.stderr}"
        )
        norm = _norm(result).lower()
        assert "secrets-only environments skipped: 1" in norm
        assert "ready to commit" in norm
