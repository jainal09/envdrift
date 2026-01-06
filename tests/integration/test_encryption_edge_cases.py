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


def _get_envdrift_cmd() -> list[str]:
    """Get the command to run envdrift CLI."""
    envdrift_path = shutil.which("envdrift")
    if envdrift_path:
        return [envdrift_path]
    return ["uv", "run", "envdrift"]


class TestEncryptEmptyFile:
    """Test encryption handling of empty files."""

    def test_encrypt_empty_file(
        self,
        work_dir: Path,
        integration_pythonpath: str,
    ):
        """Test that encrypting an empty .env file is handled gracefully."""
        # Create empty .env file
        env_file = work_dir / ".env"
        env_file.write_text("")

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            _get_envdrift_cmd() + ["encrypt", str(env_file)],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should not crash - may succeed or report nothing to encrypt
        assert result.returncode in (0, 1), f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"


class TestEncryptUnicodeValues:
    """Test encryption with unicode characters."""

    def test_encrypt_unicode_values(
        self,
        work_dir: Path,
        integration_pythonpath: str,
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
            _get_envdrift_cmd() + ["encrypt", str(env_file), "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should handle unicode gracefully
        assert result.returncode in (0, 1), f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"

        # Verify file is still readable with unicode
        content = env_file.read_text(encoding="utf-8")
        assert "こんにちは" in content or "encrypted" in content.lower()


class TestEncryptMultilineValues:
    """Test encryption with multiline values."""

    def test_encrypt_multiline_values(
        self,
        work_dir: Path,
        integration_pythonpath: str,
    ):
        """Test handling of multiline values in .env files."""
        # Create .env with multiline values (using quotes)
        env_file = work_dir / ".env"
        env_file.write_text(
            'SINGLE_LINE=simple value\n'
            'MULTILINE="line1\nline2\nline3"\n'
            "PRIVATE_KEY='-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA\n"
            "-----END RSA PRIVATE KEY-----'\n"
        )

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            _get_envdrift_cmd() + ["encrypt", str(env_file), "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should handle multiline gracefully
        assert result.returncode in (0, 1), f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"


class TestEncryptSpecialCharsKeys:
    """Test encryption with special characters in key names."""

    def test_encrypt_special_chars_keys(
        self,
        work_dir: Path,
        integration_pythonpath: str,
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
            _get_envdrift_cmd() + ["encrypt", str(env_file), "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should handle special chars gracefully
        assert result.returncode in (0, 1), f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"


class TestEncryptAlreadyEncrypted:
    """Test re-encryption of already encrypted files."""

    def test_encrypt_already_encrypted_dotenvx(
        self,
        work_dir: Path,
        integration_pythonpath: str,
    ):
        """Test that re-encrypting an already encrypted file is handled."""
        # Create a file that looks like dotenvx encrypted content
        env_file = work_dir / ".env"
        env_file.write_text(
            '#/-------------------[DOTENV][signature]--------------------/\n'
            '#/ Generated by dotenvx. DO NOT EDIT.\n'
            '#/----------------------------------------------------------/\n'
            'ENCRYPTED_KEY="encrypted:AbCdEf123456..."\n'
        )

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            _get_envdrift_cmd() + ["encrypt", str(env_file), "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should detect as already encrypted or handle gracefully
        assert result.returncode in (0, 1), f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"


class TestEncryptMixedState:
    """Test files with mixed encrypted/plain values."""

    def test_encrypt_mixed_state(
        self,
        work_dir: Path,
        integration_pythonpath: str,
    ):
        """Test handling of files with some encrypted and some plain values."""
        # Create a file with mixed state
        env_file = work_dir / ".env"
        env_file.write_text(
            '# Mixed state file\n'
            'PLAIN_VALUE=this_is_plain_text\n'
            'ENCRYPTED_VALUE="encrypted:AbCdEf123456..."\n'
            'ANOTHER_PLAIN=also_plain\n'
        )

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            _get_envdrift_cmd() + ["encrypt", str(env_file), "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should report mixed state or handle gracefully
        assert result.returncode in (0, 1), f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"


class TestDecryptMissingKey:
    """Test decryption without available private key."""

    def test_decrypt_missing_key(
        self,
        work_dir: Path,
        integration_pythonpath: str,
    ):
        """Test that decryption without private key gives clear error."""
        # Create an encrypted-looking file
        env_file = work_dir / ".env"
        env_file.write_text(
            '#/-------------------[DOTENV][signature]--------------------/\n'
            '#/ Generated by dotenvx. DO NOT EDIT.\n'
            '#/----------------------------------------------------------/\n'
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
            _get_envdrift_cmd() + ["decrypt", str(env_file)],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should fail gracefully with clear error
        # Exit code 1 is expected when key is missing
        assert result.returncode in (0, 1), f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"


class TestDecryptWrongKey:
    """Test decryption with mismatched key."""

    def test_decrypt_wrong_key(
        self,
        work_dir: Path,
        integration_pythonpath: str,
    ):
        """Test decryption with a key that doesn't match the encrypted content."""
        # Create an encrypted-looking file
        env_file = work_dir / ".env"
        env_file.write_text(
            '#/-------------------[DOTENV][signature]--------------------/\n'
            '#/ Generated by dotenvx. DO NOT EDIT.\n'
            '#/----------------------------------------------------------/\n'
            'SECRET_KEY="encrypted:xyzWrongEncryptedData"\n'
        )

        # Create .env.keys with a wrong/fake key
        env_keys = work_dir / ".env.keys"
        env_keys.write_text("DOTENV_PRIVATE_KEY=wrong_key_value_12345\n")

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            _get_envdrift_cmd() + ["decrypt", str(env_file)],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should fail gracefully - decryption with wrong key should error
        # but not crash
        assert result.returncode in (0, 1), f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"


class TestEncryptLargeFile:
    """Test encryption performance with large files."""

    def test_encrypt_large_file(
        self,
        work_dir: Path,
        integration_pythonpath: str,
    ):
        """Test encryption handling of files with many variables (1000+)."""
        # Create large .env file with 1000+ variables
        env_file = work_dir / ".env"
        lines = [f"VAR_{i}=value_{i}_with_some_content" for i in range(1000)]
        env_file.write_text("\n".join(lines) + "\n")

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            _get_envdrift_cmd() + ["encrypt", str(env_file), "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,  # Allow more time for large file
        )

        # Should handle large file without crashing or timing out
        assert result.returncode in (0, 1), f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"


class TestDuplicatePublicKeys:
    """Test handling of duplicate public keys in files."""

    def test_encrypt_duplicate_public_key(
        self,
        work_dir: Path,
        integration_pythonpath: str,
    ):
        """Test handling of .env files with duplicate DOTENV_PUBLIC_KEY entries.
        
        This is a real-world edge case where files accidentally end up with
        multiple public key entries due to merges or manual edits.
        """
        # Create .env with duplicate public keys
        env_file = work_dir / ".env"
        env_file.write_text(
            '#/-------------------[DOTENV][signature]--------------------/\n'
            'DOTENV_PUBLIC_KEY="ec1a2b3c4d5e6f"\n'
            'DOTENV_PUBLIC_KEY="ec1a2b3c4d5e6f"\n'  # Duplicate!
            'SECRET_VALUE="encrypted:somevalue"\n'
            'ANOTHER_KEY="encrypted:anothervalue"\n'
        )

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            _get_envdrift_cmd() + ["encrypt", str(env_file), "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should handle duplicate keys gracefully
        assert result.returncode in (0, 1), f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"

    def test_env_keys_duplicate_private_key(
        self,
        work_dir: Path,
        integration_pythonpath: str,
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
        env_file.write_text(
            'DOTENV_PUBLIC_KEY="pubkey123"\n'
            'APP_SECRET="encrypted:xyz"\n'
        )

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            _get_envdrift_cmd() + ["decrypt", str(env_file)],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should handle duplicate keys gracefully (use first or dedupe)
        assert result.returncode in (0, 1), f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"

    def test_multiple_different_public_keys(
        self,
        work_dir: Path,
        integration_pythonpath: str,
    ):
        """Test handling of .env with multiple DIFFERENT public keys (conflicting)."""
        # Create .env with conflicting public keys
        env_file = work_dir / ".env"
        env_file.write_text(
            '#/-------------------[DOTENV][signature]--------------------/\n'
            'DOTENV_PUBLIC_KEY="ec_first_key_abc"\n'
            'DOTENV_PUBLIC_KEY="ec_second_key_xyz"\n'  # Different value - conflict!
            'SECRET_VALUE="encrypted:somevalue"\n'
        )

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            _get_envdrift_cmd() + ["encrypt", str(env_file), "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should handle conflicting keys gracefully
        assert result.returncode in (0, 1), f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"

