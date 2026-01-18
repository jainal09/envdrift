"""Integration tests for dotenvx and SOPS encryption flows."""

from __future__ import annotations

import os
import re
import subprocess  # nosec B404
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHONPATH = str(REPO_ROOT / "src")

AGE_PUBLIC_KEY = "age1c89jtrvyl72y0muvdp5lm3jpemvc2gr303up4g37tuq4uftcku3q4svqau"
AGE_PRIVATE_KEY = "AGE-SECRET-KEY-1HGE3ZE9NPEN5R76LVKKJ2Z3G9TYZJLW84P2CHAF6UGL43R7TWPUSZ89MK6"


def _run_envdrift(args: list[str], *, cwd: Path, env: dict[str, str], check: bool = True):
    cmd = [sys.executable, "-m", "envdrift.cli", *args]
    result = subprocess.run(  # nosec B603
        cmd,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            "envdrift failed\n"
            f"cmd: {' '.join(cmd)}\n"
            f"cwd: {cwd}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


@pytest.fixture(scope="session")
def integration_env(tmp_path_factory):
    base_dir = tmp_path_factory.mktemp("envdrift-integration")
    venv_dir = base_dir / ".venv"
    bin_dir = venv_dir / ("Scripts" if os.name == "nt" else "bin")
    bin_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["VIRTUAL_ENV"] = str(venv_dir)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    env["PYTHONPATH"] = f"{PYTHONPATH}{os.pathsep}{env.get('PYTHONPATH', '')}"

    return {"base_dir": base_dir, "env": env}


@pytest.mark.integration
def test_dotenvx_encrypt_decrypt_roundtrip(integration_env):
    work_dir = integration_env["base_dir"] / "dotenvx"
    work_dir.mkdir()
    env = integration_env["env"].copy()

    env_file = work_dir / ".env.dotenvx"
    env_file.write_text(
        textwrap.dedent(
            """\
            API_URL=https://example.com
            API_KEY=supersecret
            DEBUG=true
            PORT=3000
            """
        )
    )

    config = textwrap.dedent(
        """\
        [encryption]
        backend = "dotenvx"

        [encryption.dotenvx]
        auto_install = true
        """
    )
    (work_dir / "envdrift.toml").write_text(config)

    result = _run_envdrift(
        ["encrypt", env_file.name, "--check"],
        cwd=work_dir,
        env=env,
        check=False,
    )
    assert result.returncode == 1

    _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)
    encrypted = env_file.read_text()
    assert "encrypted:" in encrypted
    assert "DOTENV_PUBLIC_KEY" in encrypted

    _run_envdrift(["decrypt", env_file.name], cwd=work_dir, env=env)
    decrypted = env_file.read_text()
    assert "API_KEY=supersecret" in decrypted
    assert "encrypted:" not in decrypted


@pytest.mark.integration
def test_sops_encrypt_decrypt_roundtrip(integration_env):
    work_dir = integration_env["base_dir"] / "sops"
    work_dir.mkdir()
    env = integration_env["env"].copy()

    env_file = work_dir / ".env.sops"
    env_file.write_text(
        textwrap.dedent(
            """\
            DB_USER=admin
            DB_PASSWORD=hunter2
            """
        )
    )

    (work_dir / "age.key").write_text(
        textwrap.dedent(
            f"""\
            # created: 2026-01-01T23:59:46-05:00
            # public key: {AGE_PUBLIC_KEY}
            {AGE_PRIVATE_KEY}
            """
        )
    )

    (work_dir / ".sops.yaml").write_text(
        textwrap.dedent(
            f"""\
            creation_rules:
              - path_regex: \\.env\\.sops$
                age: {AGE_PUBLIC_KEY}
            """
        )
    )

    config = textwrap.dedent(
        f"""\
        [encryption]
        backend = "sops"

        [encryption.sops]
        auto_install = true
        config_file = ".sops.yaml"
        age_key_file = "age.key"
        age_recipients = "{AGE_PUBLIC_KEY}"
        """
    )
    (work_dir / "envdrift.toml").write_text(config)

    _run_envdrift(["encrypt", env_file.name, "--backend", "sops"], cwd=work_dir, env=env)
    encrypted = env_file.read_text()
    assert "ENC[" in encrypted

    check_result = _run_envdrift(
        ["encrypt", env_file.name, "--backend", "sops", "--check"],
        cwd=work_dir,
        env=env,
        check=False,
    )
    assert check_result.returncode == 0

    _run_envdrift(["decrypt", env_file.name], cwd=work_dir, env=env)
    decrypted = env_file.read_text()
    assert "DB_PASSWORD=hunter2" in decrypted
    assert "ENC[" not in decrypted


@pytest.mark.integration
def test_dotenvx_smart_encryption_skips_unchanged(integration_env):
    """Smart encryption should restore from git when content is unchanged.

    This tests the fix for dotenvx's non-deterministic encryption (ECIES)
    which produces different ciphertext each time, causing unnecessary git noise.
    """
    work_dir = integration_env["base_dir"] / "dotenvx-smart"
    work_dir.mkdir()
    env = integration_env["env"].copy()

    # Initialize git repo
    subprocess.run(["git", "init"], cwd=work_dir, capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=work_dir,
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=work_dir,
        capture_output=True,
        check=True,
    )

    # Create env file
    env_file = work_dir / ".env.production"
    env_file.write_text(
        textwrap.dedent(
            """\
            API_URL=https://example.com
            SECRET_KEY=mysupersecretkey123
            DEBUG=false
            """
        )
    )

    # Create config with smart_encryption enabled
    config = textwrap.dedent(
        """\
        [encryption]
        backend = "dotenvx"
        smart_encryption = true

        [encryption.dotenvx]
        auto_install = true
        """
    )
    (work_dir / "envdrift.toml").write_text(config)

    # Encrypt the file
    _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)
    encrypted_content_v1 = env_file.read_text()
    assert "encrypted:" in encrypted_content_v1

    # Commit the encrypted file to git
    subprocess.run(
        ["git", "add", ".env.production", "envdrift.toml"],
        cwd=work_dir,
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "commit", "-m", "initial"],
        cwd=work_dir,
        capture_output=True,
        check=True,
    )

    # Decrypt the file (simulating `envdrift pull`)
    _run_envdrift(["decrypt", env_file.name], cwd=work_dir, env=env)
    decrypted_content = env_file.read_text()
    assert "SECRET_KEY=mysupersecretkey123" in decrypted_content
    assert "encrypted:" not in decrypted_content

    # Now re-encrypt WITHOUT changing the content
    # The smart encryption should detect the content is unchanged
    # and restore the original encrypted file from git
    _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)
    encrypted_content_v2 = env_file.read_text()

    # The encrypted content should be IDENTICAL to v1 (restored from git)
    # If smart encryption works, the file should not have changed
    assert encrypted_content_v2 == encrypted_content_v1, (
        "Smart encryption should restore original encrypted file when content unchanged. "
        "Got different ciphertext, meaning file was re-encrypted instead of restored."
    )

    # Verify git shows no changes
    result = subprocess.run(
        ["git", "status", "--porcelain", ".env.production"],
        cwd=work_dir,
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == "", (
        f"File should have no git changes after smart encryption, but got: {result.stdout}"
    )


@pytest.mark.integration
def test_sops_smart_encryption_skips_unchanged(integration_env):
    """Smart encryption should work for sops as well.

    SOPS also produces non-deterministic output (different IV/mac) each time.
    """
    work_dir = integration_env["base_dir"] / "sops-smart"
    work_dir.mkdir()
    env = integration_env["env"].copy()

    # Initialize git repo
    subprocess.run(["git", "init"], cwd=work_dir, capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=work_dir,
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=work_dir,
        capture_output=True,
        check=True,
    )

    # Setup sops keys
    (work_dir / "age.key").write_text(
        textwrap.dedent(
            f"""\
            # created: 2026-01-01T23:59:46-05:00
            # public key: {AGE_PUBLIC_KEY}
            {AGE_PRIVATE_KEY}
            """
        )
    )

    (work_dir / ".sops.yaml").write_text(
        textwrap.dedent(
            f"""\
            creation_rules:
              - path_regex: \\.env\\.sops$
                age: {AGE_PUBLIC_KEY}
            """
        )
    )

    # Create env file
    env_file = work_dir / ".env.sops"
    env_file.write_text("TEST_VAR=original_value")

    # Create config with smart_encryption enabled
    config = textwrap.dedent(
        f"""\
        [encryption]
        backend = "sops"
        smart_encryption = true

        [encryption.sops]
        auto_install = true
        config_file = ".sops.yaml"
        age_key_file = "age.key"
        age_recipients = "{AGE_PUBLIC_KEY}"
        """
    )
    (work_dir / "envdrift.toml").write_text(config)

    # Encrypt
    _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)
    encrypted_content_v1 = env_file.read_text()
    assert "ENC[" in encrypted_content_v1

    # Commit
    subprocess.run(
        ["git", "add", ".env.sops", "envdrift.toml", ".sops.yaml", "age.key"],
        cwd=work_dir,
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "commit", "-m", "initial"],
        cwd=work_dir,
        capture_output=True,
        check=True,
    )

    # Decrypt
    _run_envdrift(["decrypt", env_file.name], cwd=work_dir, env=env)
    decrypted_content = env_file.read_text()
    assert "TEST_VAR=original_value" in decrypted_content
    assert "ENC[" not in decrypted_content

    # Re-encrypt
    _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)
    encrypted_content_v2 = env_file.read_text()

    # Should be identical (restored from git)
    assert encrypted_content_v2 == encrypted_content_v1, (
        "Smart encryption should restore sops file when content unchanged."
    )

    # Verify git status clean
    result = subprocess.run(
        ["git", "status", "--porcelain", ".env.sops"],
        cwd=work_dir,
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == ""


@pytest.mark.integration
def test_partial_push_updates_gitignore(integration_env):
    work_dir = integration_env["base_dir"] / "partial-gitignore"
    work_dir.mkdir()
    env = integration_env["env"].copy()

    subprocess.run(["git", "init"], cwd=work_dir, capture_output=True, check=True)

    (work_dir / ".env.production.clear").write_text("APP_VERSION=1.2.3\n")
    (work_dir / ".env.production.secret").write_text("SECRET=encrypted:dummy\n")

    config = textwrap.dedent(
        """\
        [partial_encryption]
        enabled = true

        [[partial_encryption.environments]]
        name = "production"
        clear_file = ".env.production.clear"
        secret_file = ".env.production.secret"
        combined_file = ".env.production"
        """
    )
    (work_dir / "envdrift.toml").write_text(config)

    _run_envdrift(["push", "--env", "production"], cwd=work_dir, env=env)

    gitignore_path = work_dir / ".gitignore"
    assert gitignore_path.exists()
    entries = gitignore_path.read_text().splitlines()
    assert ".env.production" in entries


@pytest.mark.integration
def test_partial_push_respects_existing_gitignore(integration_env):
    work_dir = integration_env["base_dir"] / "partial-gitignore-existing"
    work_dir.mkdir()
    env = integration_env["env"].copy()

    subprocess.run(["git", "init"], cwd=work_dir, capture_output=True, check=True)

    (work_dir / ".env.production.clear").write_text("APP_VERSION=1.2.3\n")
    (work_dir / ".env.production.secret").write_text("SECRET=encrypted:dummy\n")
    gitignore_path = work_dir / ".gitignore"
    gitignore_path.write_text(".env.*\n")

    config = textwrap.dedent(
        """\
        [partial_encryption]
        enabled = true

        [[partial_encryption.environments]]
        name = "production"
        clear_file = ".env.production.clear"
        secret_file = ".env.production.secret"
        combined_file = ".env.production"
        """
    )
    (work_dir / "envdrift.toml").write_text(config)

    _run_envdrift(["push", "--env", "production"], cwd=work_dir, env=env)

    assert gitignore_path.read_text() == ".env.*\n"


@pytest.mark.integration
def test_pull_skips_partial_combined_files(integration_env):
    pytest.importorskip("boto3")

    work_dir = integration_env["base_dir"] / "pull-partial-skip"
    work_dir.mkdir()
    env = integration_env["env"].copy()

    service_dir = work_dir / "service"
    service_dir.mkdir()
    (service_dir / ".env.production").write_text("APP_VERSION=1\n")

    config = textwrap.dedent(
        """\
        [vault]
        provider = "aws"

        [vault.sync]
        [[vault.sync.mappings]]
        secret_name = "dummy-secret"
        folder_path = "service"

        [partial_encryption]
        enabled = true

        [[partial_encryption.environments]]
        name = "production"
        clear_file = "service/.env.production.clear"
        secret_file = "service/.env.production.secret"
        combined_file = "service/.env.production"

        [encryption]
        backend = "dotenvx"

        [encryption.dotenvx]
        auto_install = true
        """
    )
    (work_dir / "envdrift.toml").write_text(config)

    result = _run_envdrift(
        ["pull", "--config", "envdrift.toml", "--skip-sync"],
        cwd=work_dir,
        env=env,
    )

    output = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout + result.stderr)
    assert "skipped (partial encryption combined file)" in output


@pytest.mark.integration
def test_full_lock_pull_merge_cycle(integration_env):
    """Integration test for the complete lock -> pull --merge -> lock cycle.

    This tests:
    1. lock --all encrypts .secret files
    2. pull --merge --skip-sync decrypts and creates combined files
    3. lock --all re-encrypts and deletes combined files

    Note: Uses --skip-sync to avoid needing actual vault connectivity.
    The encryption/decryption happens locally using .env.keys files.
    """
    pytest.importorskip("azure.identity", reason="Azure SDK not installed")
    pytest.importorskip("azure.keyvault.secrets", reason="Azure Key Vault SDK not installed")
    work_dir = integration_env["base_dir"] / "lock-pull-merge-cycle"
    work_dir.mkdir()
    env = integration_env["env"].copy()

    # Create partial encryption structure
    service_dir = work_dir / "service"
    service_dir.mkdir()

    # Create .clear file (non-sensitive vars)
    clear_file = service_dir / ".env.prod.clear"
    clear_file.write_text(
        textwrap.dedent(
            """\
            APP_NAME=myapp
            DEBUG=false
            LOG_LEVEL=info
            """
        )
    )

    # Create .secret file (sensitive vars - plaintext initially)
    secret_file = service_dir / ".env.prod.secret"
    secret_file.write_text(
        textwrap.dedent(
            """\
            API_KEY=super_secret_key
            DATABASE_URL=postgres://user:pass@localhost/db
            JWT_SECRET=my_jwt_secret
            """
        )
    )

    # Create config with vault section (required by lock command, but we use --skip-sync)
    config = textwrap.dedent(
        f"""\
        [encryption]
        backend = "dotenvx"

        [encryption.dotenvx]
        auto_install = true

        [vault]
        provider = "azure"

        [vault.azure]
        vault_url = "https://fake-vault.vault.azure.net/"

        [vault.sync]
        [[vault.sync.mappings]]
        secret_name = "test-key"
        folder_path = "{service_dir.as_posix()}"
        environment = "prod"

        [partial_encryption]
        enabled = true

        [[partial_encryption.environments]]
        name = "prod"
        clear_file = "{clear_file.as_posix()}"
        secret_file = "{secret_file.as_posix()}"
        combined_file = "{(service_dir / ".env.prod").as_posix()}"
        """
    )
    (work_dir / "envdrift.toml").write_text(config)

    # Create empty .env.keys (dotenvx will populate on first encrypt)
    keys_file = service_dir / ".env.keys"
    keys_file.write_text("")

    # === Step 1: lock --all - encrypt the .secret file ===
    # Note: No --skip-verify needed, lock encrypts locally without vault check by default
    result = _run_envdrift(
        ["lock", "--all", "--force", "--config", "envdrift.toml"],
        cwd=work_dir,
        env=env,
    )
    output = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout + result.stderr)
    assert "encrypted" in output.lower(), f"Expected 'encrypted' in output: {output}"

    # Verify .secret file is encrypted
    secret_content = secret_file.read_text()
    assert "=encrypted:" in secret_content, "Secret file should contain encrypted values"

    # Verify combined file does not exist yet
    combined_file = service_dir / ".env.prod"
    assert not combined_file.exists(), "Combined file should not exist after lock"

    # === Step 2: pull --merge --skip-sync - decrypt and create combined file ===
    result = _run_envdrift(
        ["pull", "--merge", "--skip-sync", "--force", "--config", "envdrift.toml"],
        cwd=work_dir,
        env=env,
    )
    output = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout + result.stderr)
    assert "merged" in output.lower(), f"Expected 'merged' in output: {output}"

    # Verify combined file exists and has decrypted content
    assert combined_file.exists(), "Combined file should exist after pull --merge"
    combined_content = combined_file.read_text()

    # Check that combined file has content from both .clear and .secret
    assert "APP_NAME=myapp" in combined_content, "Combined should have clear vars"
    assert "DEBUG=false" in combined_content, "Combined should have clear vars"
    assert "API_KEY=" in combined_content, "Combined should have secret vars"
    assert "DATABASE_URL=" in combined_content, "Combined should have secret vars"
    # Verify it's decrypted (no encrypted: prefix)
    assert "=encrypted:" not in combined_content, "Combined file should be decrypted"

    # === Step 3: lock --all again - re-encrypt and delete combined file ===
    result = _run_envdrift(
        ["lock", "--all", "--force", "--config", "envdrift.toml"],
        cwd=work_dir,
        env=env,
    )
    output = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout + result.stderr)
    assert "deleted" in output.lower(), f"Expected 'deleted' in output: {output}"

    # Verify combined file is deleted
    assert not combined_file.exists(), "Combined file should be deleted after lock --all"

    # Verify .secret file is encrypted again
    secret_content = secret_file.read_text()
    assert "=encrypted:" in secret_content, "Secret file should be encrypted after lock"
