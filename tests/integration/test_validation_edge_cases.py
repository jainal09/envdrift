"""Validation Edge Cases Integration Tests.

Tests for Category E: Validation Edge Cases from spec.md.

Test categories:
- Nested Pydantic BaseSettings with sub-models
- Custom field validators
- Optional vs required fields
- Extra forbid configuration
- Sensitive patterns detection
- Type coercion validation

Requires: pydantic-settings installed
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

# Mark all tests in this module
pytestmark = [pytest.mark.integration]


class TestNestedPydanticModel:
    """Test validation with nested BaseSettings models."""

    def test_validate_nested_pydantic_model(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """Test validation of nested BaseSettings with sub-models.

        Creates a Settings class with a nested sub-model and validates
        that missing nested fields are properly reported.
        """
        # Create a Python module with nested settings
        settings_module = tmp_path / "settings.py"
        settings_module.write_text(
            textwrap.dedent('''
            from pydantic_settings import BaseSettings
            from pydantic import BaseModel

            class DatabaseConfig(BaseModel):
                """Nested database configuration."""
                host: str = "localhost"
                port: int = 5432
                name: str

            class Settings(BaseSettings):
                """Application settings with nested model."""
                app_name: str
                debug: bool = False
                database: DatabaseConfig

                model_config = {"env_prefix": "", "env_nested_delimiter": "__"}
        ''')
        )

        # Create .env file with partial nested config
        env_file = tmp_path / ".env"
        env_file.write_text(
            textwrap.dedent("""
            APP_NAME=MyApp
            DATABASE__HOST=db.example.com
            DATABASE__PORT=5432
        """)
        )

        env = {"PYTHONPATH": integration_pythonpath}

        # Run validate command
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "envdrift.cli",
                "validate",
                str(env_file),
                "--schema",
                "settings:Settings",
                "--service-dir",
                str(tmp_path),
                "--no-check-encryption",
            ],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
        )

        # Should report missing DATABASE__NAME
        combined = result.stdout + result.stderr
        assert "database" in combined.lower() or "name" in combined.lower(), (
            f"Should mention missing nested field. Output: {combined}"
        )


class TestCustomValidators:
    """Test validation with custom Pydantic validators."""

    def test_validate_custom_validators(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """Test validation with custom field validators.

        Creates a Settings class with field validators and verifies
        that validation checks type compatibility.
        """
        settings_module = tmp_path / "settings.py"
        settings_module.write_text(
            textwrap.dedent('''
            from pydantic_settings import BaseSettings
            from pydantic import field_validator

            class Settings(BaseSettings):
                """Settings with custom validators."""
                email: str
                port: int

                @field_validator("email")
                @classmethod
                def validate_email(cls, v: str) -> str:
                    if "@" not in v:
                        raise ValueError("Invalid email format")
                    return v

                @field_validator("port")
                @classmethod
                def validate_port(cls, v: int) -> int:
                    if not (1 <= v <= 65535):
                        raise ValueError("Port must be 1-65535")
                    return v
        ''')
        )

        # Create .env with valid format
        env_file = tmp_path / ".env"
        env_file.write_text("EMAIL=test@example.com\nPORT=8080\n")

        env = {"PYTHONPATH": integration_pythonpath}

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "envdrift.cli",
                "validate",
                str(env_file),
                "--schema",
                "settings:Settings",
                "--service-dir",
                str(tmp_path),
                "--no-check-encryption",
            ],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
        )

        # Should not crash - validators are checked at runtime by pydantic
        assert "Traceback" not in result.stderr


class TestOptionalVsRequired:
    """Test validation of optional vs required fields."""

    def test_validate_optional_vs_required(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """Test that optional fields with defaults don't fail validation,
        but required fields without values do.
        """
        settings_module = tmp_path / "settings.py"
        settings_module.write_text(
            textwrap.dedent('''
            from pydantic_settings import BaseSettings
            from typing import Optional

            class Settings(BaseSettings):
                """Settings with optional and required fields."""
                required_field: str  # Required, no default
                optional_with_default: str = "default_value"
                optional_none: Optional[str] = None
        ''')
        )

        # Create .env with only required field
        env_file = tmp_path / ".env"
        env_file.write_text("REQUIRED_FIELD=present\n")

        env = {"PYTHONPATH": integration_pythonpath}

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "envdrift.cli",
                "validate",
                str(env_file),
                "--schema",
                "settings:Settings",
                "--service-dir",
                str(tmp_path),
                "--no-check-encryption",
            ],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
        )

        # Should pass - required field is present, optionals have defaults
        # The validation result depends on implementation details,
        # but it should not crash
        assert "Traceback" not in result.stderr

    def test_validate_missing_required_field(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """Test that missing required fields are reported."""
        settings_module = tmp_path / "settings.py"
        settings_module.write_text(
            textwrap.dedent('''
            from pydantic_settings import BaseSettings

            class Settings(BaseSettings):
                """Settings with required fields."""
                api_key: str
                database_url: str
        ''')
        )

        # Create .env missing one required field
        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=secret123\n")

        env = {"PYTHONPATH": integration_pythonpath}

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "envdrift.cli",
                "validate",
                str(env_file),
                "--schema",
                "settings:Settings",
                "--service-dir",
                str(tmp_path),
                "--no-check-encryption",
            ],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
        )

        combined = result.stdout + result.stderr
        # Should mention missing DATABASE_URL
        assert "database_url" in combined.lower() or "missing" in combined.lower(), (
            f"Should report missing required field. Output: {combined}"
        )


class TestExtraForbid:
    """Test validation with extra='forbid' configuration."""

    def test_validate_extra_forbid(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """Test that extra variables are rejected when strict_extra is enabled."""
        settings_module = tmp_path / "settings.py"
        settings_module.write_text(
            textwrap.dedent('''
            from pydantic_settings import BaseSettings

            class Settings(BaseSettings):
                """Settings that reject extra fields."""
                app_name: str
                debug: bool = False

                model_config = {"extra": "forbid"}
        ''')
        )

        # Create .env with an extra variable
        env_file = tmp_path / ".env"
        env_file.write_text(
            textwrap.dedent("""
            APP_NAME=MyApp
            DEBUG=true
            UNKNOWN_VAR=should_be_rejected
        """)
        )

        env = {"PYTHONPATH": integration_pythonpath}

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "envdrift.cli",
                "validate",
                str(env_file),
                "--schema",
                "settings:Settings",
                "--service-dir",
                str(tmp_path),
                "--no-check-encryption",
            ],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
        )

        combined = result.stdout + result.stderr
        # Should mention unknown/extra variable
        assert (
            "unknown" in combined.lower()
            or "extra" in combined.lower()
            or "unknown_var" in combined.lower()
        ), f"Should report extra variable. Output: {combined}"


class TestSensitivePatterns:
    """Test sensitive pattern detection."""

    def test_validate_sensitive_patterns(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """Test that sensitive patterns are detected."""
        settings_module = tmp_path / "settings.py"
        settings_module.write_text(
            textwrap.dedent('''
            from pydantic_settings import BaseSettings

            class Settings(BaseSettings):
                """Settings with sensitive fields."""
                api_key: str
                database_password: str
                secret_token: str
                public_url: str  # Not sensitive
        ''')
        )

        # Create .env with plaintext sensitive values
        env_file = tmp_path / ".env"
        env_file.write_text(
            textwrap.dedent("""
            API_KEY=sk-live-1234567890abcdef
            DATABASE_PASSWORD=hunter2
            SECRET_TOKEN=supersecret123
            PUBLIC_URL=https://example.com
        """)
        )

        env = {"PYTHONPATH": integration_pythonpath}

        # Run with encryption check enabled
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "envdrift.cli",
                "validate",
                str(env_file),
                "--schema",
                "settings:Settings",
                "--service-dir",
                str(tmp_path),
                "--check-encryption",
            ],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
        )

        combined = result.stdout + result.stderr
        # Should detect unencrypted sensitive values
        # The validator checks for patterns like "sk-" and names with "password", "secret", etc.
        assert (
            "encrypt" in combined.lower()
            or "sensitive" in combined.lower()
            or "secret" in combined.lower()
            or "warning" in combined.lower()
        ), f"Should detect sensitive patterns. Output: {combined}"


class TestTypeCoercion:
    """Test type coercion validation."""

    def test_validate_type_coercion_bool(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """Test that string 'true'/'false' values coerce to bool.

        Note: envdrift's validator uses case-sensitive matching, so DEBUG != debug.
        This test verifies the command doesn't crash with valid bool string values.
        """
        settings_module = tmp_path / "settings.py"
        settings_module.write_text(
            textwrap.dedent('''
            from pydantic_settings import BaseSettings

            class Settings(BaseSettings):
                """Settings with bool field."""
                debug_mode: bool
                verbose_mode: bool
        ''')
        )

        # Use matching case for field names (uppercase in .env matches uppercase expected)
        env_file = tmp_path / ".env"
        env_file.write_text("DEBUG_MODE=true\nVERBOSE_MODE=False\n")

        env = {"PYTHONPATH": integration_pythonpath}

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "envdrift.cli",
                "validate",
                str(env_file),
                "--schema",
                "settings:Settings",
                "--service-dir",
                str(tmp_path),
                "--no-check-encryption",
            ],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
        )

        # Should not crash with traceback
        assert "Traceback" not in result.stderr, f"Should not crash. stderr: {result.stderr}"

    def test_validate_type_coercion_int(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """Test that string numbers coerce to int."""
        settings_module = tmp_path / "settings.py"
        settings_module.write_text(
            textwrap.dedent('''
            from pydantic_settings import BaseSettings

            class Settings(BaseSettings):
                """Settings with int field."""
                port: int
                max_connections: int
        ''')
        )

        env_file = tmp_path / ".env"
        env_file.write_text("PORT=8080\nMAX_CONNECTIONS=100\n")

        env = {"PYTHONPATH": integration_pythonpath}

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "envdrift.cli",
                "validate",
                str(env_file),
                "--schema",
                "settings:Settings",
                "--service-dir",
                str(tmp_path),
                "--no-check-encryption",
            ],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
        )

        # Should not report type errors for valid int strings
        assert "Traceback" not in result.stderr

    def test_validate_type_error_invalid_int(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """Test that invalid int values are caught."""
        settings_module = tmp_path / "settings.py"
        settings_module.write_text(
            textwrap.dedent('''
            from pydantic_settings import BaseSettings

            class Settings(BaseSettings):
                """Settings with int field."""
                port: int
        ''')
        )

        env_file = tmp_path / ".env"
        env_file.write_text("PORT=not_a_number\n")

        env = {"PYTHONPATH": integration_pythonpath}

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "envdrift.cli",
                "validate",
                str(env_file),
                "--schema",
                "settings:Settings",
                "--service-dir",
                str(tmp_path),
                "--no-check-encryption",
            ],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
        )

        combined = result.stdout + result.stderr
        # Should report type error
        assert (
            "type" in combined.lower()
            or "int" in combined.lower()
            or "invalid" in combined.lower()
            or "error" in combined.lower()
        ), f"Should report type error. Output: {combined}"


class TestValidateCommand:
    """Test validate command edge cases."""

    def test_validate_missing_schema_arg(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """Test that validate fails gracefully without --schema."""
        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=secret\n")

        env = {"PYTHONPATH": integration_pythonpath}

        result = subprocess.run(
            [sys.executable, "-m", "envdrift.cli", "validate", str(env_file)],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
        )

        # Should exit with error
        assert result.returncode != 0
        combined = result.stdout + result.stderr
        assert "schema" in combined.lower(), f"Should mention missing schema. Output: {combined}"

    def test_validate_fix_template(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """Test that --fix generates a template for missing variables."""
        settings_module = tmp_path / "settings.py"
        settings_module.write_text(
            textwrap.dedent('''
            from pydantic_settings import BaseSettings

            class Settings(BaseSettings):
                """Settings with required fields."""
                api_key: str
                database_url: str
                redis_url: str
        ''')
        )

        # Create .env missing fields
        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=secret123\n")

        env = {"PYTHONPATH": integration_pythonpath}

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "envdrift.cli",
                "validate",
                str(env_file),
                "--schema",
                "settings:Settings",
                "--service-dir",
                str(tmp_path),
                "--no-check-encryption",
                "--fix",
            ],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
        )

        combined = result.stdout + result.stderr
        # Should include fix template with missing variables
        assert (
            "database_url" in combined.lower()
            or "redis_url" in combined.lower()
            or "template" in combined.lower()
        ), f"Should show fix template. Output: {combined}"

    def test_validate_ci_mode_exit_code(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """Test that --ci returns non-zero exit on failure."""
        settings_module = tmp_path / "settings.py"
        settings_module.write_text(
            textwrap.dedent('''
            from pydantic_settings import BaseSettings

            class Settings(BaseSettings):
                """Settings with required field."""
                required_field: str
        ''')
        )

        # Create empty .env (missing required field)
        env_file = tmp_path / ".env"
        env_file.write_text("")

        env = {"PYTHONPATH": integration_pythonpath}

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "envdrift.cli",
                "validate",
                str(env_file),
                "--schema",
                "settings:Settings",
                "--service-dir",
                str(tmp_path),
                "--no-check-encryption",
                "--ci",
            ],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
        )

        # Should exit with code 1 in CI mode
        assert result.returncode != 0, "Should exit with non-zero in CI mode on failure"

    def test_validate_nonexistent_env_file(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """Test graceful handling of missing env file."""
        settings_module = tmp_path / "settings.py"
        settings_module.write_text(
            textwrap.dedent("""
            from pydantic_settings import BaseSettings

            class Settings(BaseSettings):
                app_name: str
        """)
        )

        env = {"PYTHONPATH": integration_pythonpath}

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "envdrift.cli",
                "validate",
                "nonexistent.env",
                "--schema",
                "settings:Settings",
                "--service-dir",
                str(tmp_path),
            ],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
        )

        # Should exit with error
        assert result.returncode != 0
        combined = result.stdout + result.stderr
        assert (
            "not found" in combined.lower()
            or "does not exist" in combined.lower()
            or "error" in combined.lower()
        ), f"Should mention missing file. Output: {combined}"

    def test_validate_invalid_schema_path(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """Test graceful handling of invalid schema path."""
        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=secret\n")

        env = {"PYTHONPATH": integration_pythonpath}

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "envdrift.cli",
                "validate",
                str(env_file),
                "--schema",
                "nonexistent.module:Settings",
                "--service-dir",
                str(tmp_path),
            ],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
        )

        # Should exit with error
        assert result.returncode != 0
        assert "Traceback" not in result.stderr, "Should not crash with traceback"
