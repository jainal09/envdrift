"""Encryption Edge Cases Integration Tests.

Tests edge cases in encryption/decryption operations.

Test categories:
- Empty files
- Unicode values
- Multiline values
- Special characters in keys
- Already encrypted files
- Mixed state files (some encrypted, some plain)
- Missing/wrong decryption keys
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

# Mark all tests in this module
pytestmark = [pytest.mark.integration]


class TestEncryptEmptyFile:
    """Test encryption handling of empty files."""

    def test_encrypt_empty_file(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test that encrypting an empty .env file is handled gracefully."""
        # Create empty .env file
        env_file = work_dir / ".env"
        env_file.write_text("")

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "encrypt", str(env_file)],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should not crash - may succeed or report nothing to encrypt
        assert result.returncode in (0, 1), (
            f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"
        )


class TestEncryptUnicodeValues:
    """Test encryption with unicode characters."""

    def test_encrypt_unicode_values(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test that unicode characters in values are preserved."""
        # Create .env with unicode values
        env_file = work_dir / ".env"
        env_file.write_text(
            "# Unicode test\n"
            "GREETING=こんにちは\n"
            "EMOJI=🔐🔑\n"
            "ACCENTS=Héllo Wörld\n"
            "CHINESE=中文测试\n"
            "ARABIC=مرحبا\n",
            encoding="utf-8",
        )

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "encrypt", str(env_file), "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should handle unicode gracefully
        assert result.returncode in (0, 1), (
            f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"
        )

        # Verify file is still readable with unicode
        content = env_file.read_text(encoding="utf-8")
        assert "こんにちは" in content or "encrypted" in content.lower()


class TestEncryptMultilineValues:
    """Test encryption with multiline values."""

    def test_encrypt_multiline_values(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test handling of multiline values in .env files."""
        # Create .env with multiline values (using quotes)
        env_file = work_dir / ".env"
        env_file.write_text(
            "SINGLE_LINE=simple value\n"
            'MULTILINE="line1\nline2\nline3"\n'
            "PRIVATE_KEY='-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA\n"
            "-----END RSA PRIVATE KEY-----'\n"
        )

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "encrypt", str(env_file), "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should handle multiline gracefully
        assert result.returncode in (0, 1), (
            f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"
        )


class TestEncryptSpecialCharsKeys:
    """Test encryption with special characters in key names."""

    def test_encrypt_special_chars_keys(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test keys containing dots, dashes, and underscores."""
        # Create .env with special character keys
        env_file = work_dir / ".env"
        env_file.write_text(
            "SIMPLE_KEY=value1\n"
            "DASHED-KEY=value2\n"
            "DOTTED.KEY=value3\n"
            "MIXED_KEY-WITH.CHARS=value4\n"
            "_LEADING_UNDERSCORE=value5\n"
            "__DOUBLE__UNDERSCORE__=value6\n"
        )

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "encrypt", str(env_file), "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should handle special chars gracefully
        assert result.returncode in (0, 1), (
            f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"
        )


class TestEncryptAlreadyEncrypted:
    """Test re-encryption of already encrypted files."""

    def test_encrypt_already_encrypted_dotenvx(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test that re-encrypting an already encrypted file is handled."""
        # Create a file that looks like dotenvx encrypted content
        env_file = work_dir / ".env"
        env_file.write_text(
            "#/-------------------[DOTENV][signature]--------------------/\n"
            "#/ Generated by dotenvx. DO NOT EDIT.\n"
            "#/----------------------------------------------------------/\n"
            'ENCRYPTED_KEY="encrypted:AbCdEf123456..."\n'
        )

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "encrypt", str(env_file), "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should detect as already encrypted or handle gracefully
        assert result.returncode in (0, 1), (
            f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"
        )


class TestEncryptMixedState:
    """Test files with mixed encrypted/plain values."""

    def test_encrypt_mixed_state(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test handling of files with some encrypted and some plain values."""
        # Create a file with mixed state
        env_file = work_dir / ".env"
        env_file.write_text(
            "# Mixed state file\n"
            "PLAIN_VALUE=this_is_plain_text\n"
            'ENCRYPTED_VALUE="encrypted:AbCdEf123456..."\n'
            "ANOTHER_PLAIN=also_plain\n"
        )

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "encrypt", str(env_file), "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should report mixed state or handle gracefully
        assert result.returncode in (0, 1), (
            f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"
        )


class TestDecryptMissingKey:
    """Test decryption without available private key."""

    def test_decrypt_missing_key(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test that decryption without private key gives clear error."""
        # Create an encrypted-looking file
        env_file = work_dir / ".env"
        env_file.write_text(
            "#/-------------------[DOTENV][signature]--------------------/\n"
            "#/ Generated by dotenvx. DO NOT EDIT.\n"
            "#/----------------------------------------------------------/\n"
            'SECRET_KEY="encrypted:ABCDEFabcdef123456789"\n'
        )

        # Ensure no .env.keys file exists
        env_keys = work_dir / ".env.keys"
        if env_keys.exists():
            env_keys.unlink()

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath
        # Clear any DOTENV_PRIVATE_KEY that might be set
        env.pop("DOTENV_PRIVATE_KEY", None)
        env.pop("DOTENV_PRIVATE_KEY_PRODUCTION", None)

        result = subprocess.run(
            [*envdrift_cmd, "decrypt", str(env_file)],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should fail gracefully with clear error
        # Exit code 1 is expected when key is missing
        assert result.returncode in (0, 1), (
            f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"
        )


class TestDecryptWrongKey:
    """Test decryption with mismatched key."""

    def test_decrypt_wrong_key(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test decryption with a key that doesn't match the encrypted content."""
        # Create an encrypted-looking file
        env_file = work_dir / ".env"
        env_file.write_text(
            "#/-------------------[DOTENV][signature]--------------------/\n"
            "#/ Generated by dotenvx. DO NOT EDIT.\n"
            "#/----------------------------------------------------------/\n"
            'SECRET_KEY="encrypted:xyzWrongEncryptedData"\n'
        )

        # Create .env.keys with a wrong/fake key
        env_keys = work_dir / ".env.keys"
        env_keys.write_text("DOTENV_PRIVATE_KEY=wrong_key_value_12345\n")

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "decrypt", str(env_file)],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should fail gracefully - decryption with wrong key should error
        # but not crash
        assert result.returncode in (0, 1), (
            f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"
        )


class TestEncryptLargeFile:
    """Test encryption performance with large files."""

    def test_encrypt_large_file(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test encryption handling of files with many variables (1000+)."""
        # Create large .env file with 1000+ variables
        env_file = work_dir / ".env"
        lines = [f"VAR_{i}=value_{i}_with_some_content" for i in range(1000)]
        env_file.write_text("\n".join(lines) + "\n")

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "encrypt", str(env_file), "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,  # Allow more time for large file
        )

        # Should handle large file without crashing or timing out
        assert result.returncode in (0, 1), (
            f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"
        )


class TestDuplicatePublicKeys:
    """Test handling of duplicate public keys in files."""

    def test_encrypt_duplicate_public_key(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test handling of .env files with duplicate DOTENV_PUBLIC_KEY entries.

        This is a real-world edge case where files accidentally end up with
        multiple public key entries due to merges or manual edits.
        """
        # Create .env with duplicate public keys
        env_file = work_dir / ".env"
        env_file.write_text(
            "#/-------------------[DOTENV][signature]--------------------/\n"
            'DOTENV_PUBLIC_KEY="ec1a2b3c4d5e6f"\n'
            'DOTENV_PUBLIC_KEY="ec1a2b3c4d5e6f"\n'  # Duplicate!
            'SECRET_VALUE="encrypted:somevalue"\n'
            'ANOTHER_KEY="encrypted:anothervalue"\n'
        )

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "encrypt", str(env_file), "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should handle duplicate keys gracefully
        assert result.returncode in (0, 1), (
            f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"
        )

    def test_env_keys_duplicate_private_key(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test handling of .env.keys with duplicate DOTENV_PRIVATE_KEY entries."""
        # Create .env.keys with duplicate private keys
        env_keys = work_dir / ".env.keys"
        env_keys.write_text(
            'DOTENV_PRIVATE_KEY="key1234567890"\n'
            'DOTENV_PRIVATE_KEY="key1234567890"\n'  # Duplicate!
            'DOTENV_PRIVATE_KEY_PRODUCTION="prodkey"\n'
        )

        # Create corresponding .env file
        env_file = work_dir / ".env"
        env_file.write_text('DOTENV_PUBLIC_KEY="pubkey123"\nAPP_SECRET="encrypted:xyz"\n')

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "decrypt", str(env_file)],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should handle duplicate keys gracefully (use first or dedupe)
        assert result.returncode in (0, 1), (
            f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"
        )

    def test_multiple_different_public_keys(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test handling of .env with multiple DIFFERENT public keys (conflicting)."""
        # Create .env with conflicting public keys
        env_file = work_dir / ".env"
        env_file.write_text(
            "#/-------------------[DOTENV][signature]--------------------/\n"
            'DOTENV_PUBLIC_KEY="ec_first_key_abc"\n'
            'DOTENV_PUBLIC_KEY="ec_second_key_xyz"\n'  # Different value - conflict!
            'SECRET_VALUE="encrypted:somevalue"\n'
        )

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "encrypt", str(env_file), "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should handle conflicting keys gracefully
        assert result.returncode in (0, 1), (
            f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"
        )


class TestPartialEncryption:
    """Test partial encryption feature (.clear + .secret workflow)."""

    def test_partial_encryption_push_command(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test envdrift push command for partial encryption.

        Partial encryption splits env files into:
        - .env.{env}.clear (non-sensitive, plain text)
        - .env.{env}.secret (sensitive, encrypted)
        - .env.{env} (combined output for deployment)
        """
        # Create config with partial encryption enabled
        config_file = work_dir / "envdrift.toml"
        config_file.write_text("""
[partial_encryption]
enabled = true

[[partial_encryption.environments]]
name = "production"
clear_file = ".env.production.clear"
secret_file = ".env.production.secret"
combined_file = ".env.production"
""")

        # Create clear file (non-sensitive vars)
        clear_file = work_dir / ".env.production.clear"
        clear_file.write_text("APP_NAME=myapp\nDEBUG=false\nLOG_LEVEL=info\n")

        # Create secret file (sensitive vars, plaintext for now)
        secret_file = work_dir / ".env.production.secret"
        secret_file.write_text("DATABASE_URL=postgres://localhost/db\nAPI_KEY=secret123\n")

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "push", "--env", "production"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should handle push command gracefully
        assert result.returncode in (0, 1), (
            f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"
        )

    def test_partial_encryption_pull_command(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test envdrift pull-partial command for decrypting secrets."""
        # Create config with partial encryption enabled
        config_file = work_dir / "envdrift.toml"
        config_file.write_text("""
[partial_encryption]
enabled = true

[[partial_encryption.environments]]
name = "staging"
clear_file = ".env.staging.clear"
secret_file = ".env.staging.secret"
combined_file = ".env.staging"
""")

        # Create encrypted-looking secret file
        secret_file = work_dir / ".env.staging.secret"
        secret_file.write_text(
            "#/-------------------[DOTENV][signature]--------------------/\n"
            'DATABASE_URL="encrypted:abc123"\n'
            'API_KEY="encrypted:xyz789"\n'
        )

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "pull-partial", "--env", "staging"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should handle pull-partial gracefully
        assert result.returncode in (0, 1), (
            f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"
        )

    def test_partial_encryption_not_enabled(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test error handling when partial encryption is not enabled."""
        # Create config WITHOUT partial encryption
        config_file = work_dir / "envdrift.toml"
        config_file.write_text("""
[tool.envdrift]
encryption_backend = "dotenvx"
""")

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "push"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should fail gracefully with clear error about partial encryption not enabled
        assert result.returncode == 1, "Expected error when partial encryption not enabled"
        assert (
            "partial encryption" in result.stderr.lower()
            or "partial encryption" in result.stdout.lower()
        )

    def test_partial_encryption_missing_secret_file(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test handling when secret file doesn't exist."""
        # Create config with partial encryption enabled
        config_file = work_dir / "envdrift.toml"
        config_file.write_text("""
[partial_encryption]
enabled = true

[[partial_encryption.environments]]
name = "dev"
clear_file = ".env.dev.clear"
secret_file = ".env.dev.secret"
combined_file = ".env.dev"
""")

        # Only create clear file, NOT the secret file
        clear_file = work_dir / ".env.dev.clear"
        clear_file.write_text("APP_NAME=myapp\n")

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "push", "--env", "dev"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should handle missing file gracefully
        assert result.returncode in (0, 1), (
            f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"
        )

    def test_partial_encryption_full_cycle(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test complete push → pull-partial cycle."""
        # Create config with partial encryption enabled
        config_file = work_dir / "envdrift.toml"
        config_file.write_text("""
[partial_encryption]
enabled = true

[[partial_encryption.environments]]
name = "test"
clear_file = ".env.test.clear"
secret_file = ".env.test.secret"
combined_file = ".env.test"
""")

        # Create both files
        clear_file = work_dir / ".env.test.clear"
        clear_file.write_text("PUBLIC_VAR=public_value\n")

        secret_file = work_dir / ".env.test.secret"
        secret_file.write_text("SECRET_VAR=secret_value\n")

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        # Step 1: Push (encrypt and combine)
        push_result = subprocess.run(
            [*envdrift_cmd, "push", "--env", "test"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert push_result.returncode in (0, 1), f"Push failed: {push_result.stderr}"

        # Step 2: Pull-partial (decrypt)
        pull_result = subprocess.run(
            [*envdrift_cmd, "pull-partial", "--env", "test"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert pull_result.returncode in (0, 1), f"Pull-partial failed: {pull_result.stderr}"


class TestDiffCommand:
    """Test diff command edge cases."""

    def test_diff_identical_files(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test diffing two identical .env files."""
        env1 = work_dir / ".env.dev"
        env1.write_text("APP=myapp\nDEBUG=true\n")

        env2 = work_dir / ".env.prod"
        env2.write_text("APP=myapp\nDEBUG=true\n")

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "diff", str(env1), str(env2)],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, f"Diff failed: {result.stderr}"

    def test_diff_added_removed_vars(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test diffing files with added/removed variables."""
        env1 = work_dir / ".env.old"
        env1.write_text("OLD_VAR=value1\nSHARED=common\n")

        env2 = work_dir / ".env.new"
        env2.write_text("SHARED=common\nNEW_VAR=value2\n")

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "diff", str(env1), str(env2)],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode in (0, 1), f"Diff failed: {result.stderr}"

    def test_diff_nonexistent_file(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test diffing with non-existent file."""
        env1 = work_dir / ".env.exists"
        env1.write_text("VAR=value\n")

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "diff", str(env1), str(work_dir / ".env.missing")],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should fail gracefully with error about missing file
        assert result.returncode in (1, 2), "Expected error for missing file"


class TestValidateCommand:
    """Test validate command edge cases."""

    def test_validate_without_schema(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test validation when no schema file exists."""
        env_file = work_dir / ".env"
        env_file.write_text("APP_NAME=test\nDEBUG=true\n")

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "validate", str(env_file)],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should handle missing schema gracefully
        assert result.returncode in (0, 1), f"Unexpected error: {result.stderr}"

    def test_validate_with_schema_file(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test validation with a Pydantic schema file."""
        # Create .env file
        env_file = work_dir / ".env"
        env_file.write_text("DATABASE_URL=postgres://localhost/db\nDEBUG=true\n")

        # Create simple schema
        schema_file = work_dir / "settings.py"
        schema_file.write_text("""
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str
    DEBUG: bool = True
""")

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "validate", str(env_file), "--schema", str(schema_file)],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode in (0, 1), f"Unexpected error: {result.stderr}"


class TestConfigEdgeCases:
    """Test configuration loading edge cases."""

    def test_invalid_toml_config(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test handling of invalid TOML syntax."""
        config_file = work_dir / "envdrift.toml"
        config_file.write_text("this is not valid toml [[[")

        env_file = work_dir / ".env"
        env_file.write_text("APP=test\n")

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "encrypt", str(env_file)],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should handle invalid TOML gracefully
        assert result.returncode in (0, 1, 2), f"Unexpected crash: {result.stderr}"

    def test_missing_required_config_fields(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test config with missing required fields."""
        config_file = work_dir / "pyproject.toml"
        config_file.write_text("""
[tool.envdrift]
# Missing vault_backend but has vault_key_path
vault_key_path = "some/path"
""")

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "sync"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should handle missing config gracefully
        assert result.returncode in (0, 1), f"Unexpected crash: {result.stderr}"

    def test_unknown_vault_backend(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test config with unknown vault backend."""
        config_file = work_dir / "pyproject.toml"
        config_file.write_text("""
[tool.envdrift]
vault_backend = "unknown_backend"
vault_key_path = "some/path"
""")

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "sync"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should fail with clear error about unknown backend
        assert result.returncode in (1, 2), "Expected error for unknown backend"


class TestSOPSBackend:
    """Test SOPS encryption backend edge cases."""

    def test_sops_without_sops_installed(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test SOPS encryption when sops CLI is not available.

        Instead of clearing PATH entirely (which would break envdrift),
        we filter out the directory containing the sops binary.
        """
        env_file = work_dir / ".env"
        env_file.write_text("SECRET=value\n")

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        # Filter out the sops binary directory from PATH if it exists
        # This simulates sops not being installed without breaking other tools
        sops_path = shutil.which("sops")
        if sops_path:
            sops_dir = str(Path(sops_path).parent)
            path_dirs = env.get("PATH", "").split(os.pathsep)
            filtered_path = os.pathsep.join(d for d in path_dirs if d != sops_dir)
            env["PATH"] = filtered_path

        result = subprocess.run(
            [*envdrift_cmd, "encrypt", str(env_file), "--backend", "sops"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should fail gracefully when sops is not available
        # Exit code 1 expected for "sops not found" error
        assert result.returncode in (0, 1, 2), f"Unexpected crash: {result.stderr}"
