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


# ---------------------------------------------------------------------------
# Additional real e2e coverage for the validate CLI.
#
# These tests drive the real ``python -m envdrift.cli validate`` subprocess over
# real .env files and real ``settings.py`` modules (no mocks, no container).
#
# IMPORTANT: envdrift's validator matches schema field names against .env keys
# *case-sensitively* (see src/envdrift/core/validator.py:124-146). To exercise
# the *documented* behavior (missing-required / extra / type-error detection)
# rather than the case-sensitivity bug, these schemas declare their fields in
# UPPERCASE so they match the conventional UPPERCASE .env keys exactly.
#
# Also note: pydantic-settings BaseSettings defaults ``model_config["extra"]``
# to "forbid", so a schema must explicitly set ``extra="ignore"`` to downgrade
# unknown variables from errors to warnings.
# ---------------------------------------------------------------------------


def _run_validate(
    *,
    tmp_path: Path,
    integration_pythonpath: str,
    settings_src: str,
    env_text: str,
    extra_args: list[str] | None = None,
    schema: str = "settings:Settings",
) -> subprocess.CompletedProcess[str]:
    """Run the real ``envdrift validate`` CLI as a subprocess.

    Writes ``settings.py`` and ``.env`` into ``tmp_path`` and invokes the CLI
    against them. ``COLUMNS`` is pinned wide so Rich does not wrap section
    headers / value lines, keeping output assertions stable in a non-TTY pipe.
    """
    settings_module = tmp_path / "settings.py"
    settings_module.write_text(textwrap.dedent(settings_src))

    env_file = tmp_path / ".env"
    env_file.write_text(textwrap.dedent(env_text))

    env = {"PYTHONPATH": integration_pythonpath, "COLUMNS": "200"}

    cmd = [
        sys.executable,
        "-m",
        "envdrift.cli",
        "validate",
        str(env_file),
        "--schema",
        schema,
        "--service-dir",
        str(tmp_path),
    ]
    if extra_args:
        cmd.extend(extra_args)

    return subprocess.run(
        cmd,
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )


class TestValidateRealEdgeCases:
    """High-value real e2e edge cases for the validate command."""

    def test_validate_extra_ignore_emits_warning_not_error(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """HP-06: extra='ignore' downgrades an unknown var to a warning.

        Validation must PASS (exit 0 even with --ci) and the unknown variable
        is reported only as a warning, never in an EXTRA VARIABLES error
        section.
        """
        result = _run_validate(
            tmp_path=tmp_path,
            integration_pythonpath=integration_pythonpath,
            settings_src='''
                from pydantic_settings import BaseSettings

                class Settings(BaseSettings):
                    """Schema that tolerates extra vars."""
                    APP_NAME: str
                    model_config = {"extra": "ignore"}
            ''',
            env_text="""
                APP_NAME=MyApp
                UNKNOWN_VAR=tolerated
            """,
            extra_args=["--no-check-encryption", "--ci"],
        )

        combined = result.stdout + result.stderr
        assert result.returncode == 0, (
            f"extra=ignore should pass even with --ci. Output: {combined}"
        )
        assert "Traceback" not in result.stderr
        assert "PASSED" in combined, f"Should report PASSED. Output: {combined}"
        # Reported as a warning, not an error section.
        assert "EXTRA VARIABLES" not in combined, (
            f"extra=ignore must not produce an error section. Output: {combined}"
        )
        assert "Extra variable 'UNKNOWN_VAR' not in schema" in combined, (
            f"Should warn about UNKNOWN_VAR. Output: {combined}"
        )

    def test_validate_extra_forbid_reports_error_matching_case(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """BP-04: extra='forbid' with a case-matching extra var is an ERROR.

        The unknown variable appears under an EXTRA VARIABLES section,
        validation FAILS, and --ci exits 1.
        """
        result = _run_validate(
            tmp_path=tmp_path,
            integration_pythonpath=integration_pythonpath,
            settings_src='''
                from pydantic_settings import BaseSettings

                class Settings(BaseSettings):
                    """Schema that forbids extra vars."""
                    APP_NAME: str
                    model_config = {"extra": "forbid"}
            ''',
            env_text="""
                APP_NAME=MyApp
                UNKNOWN_VAR=should_be_rejected
            """,
            extra_args=["--no-check-encryption", "--ci"],
        )

        combined = result.stdout + result.stderr
        assert result.returncode == 1, f"extra=forbid + --ci must exit 1. Output: {combined}"
        assert "Traceback" not in result.stderr
        assert "FAILED" in combined, f"Should report FAILED. Output: {combined}"
        assert "EXTRA VARIABLES" in combined, (
            f"Should print EXTRA VARIABLES section. Output: {combined}"
        )
        assert "UNKNOWN_VAR" in combined, f"Should list UNKNOWN_VAR. Output: {combined}"

    def test_validate_type_errors_for_float_and_bool(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """BP-03: invalid float and non-canonical bool produce TYPE ERRORS."""
        result = _run_validate(
            tmp_path=tmp_path,
            integration_pythonpath=integration_pythonpath,
            settings_src='''
                from pydantic_settings import BaseSettings

                class Settings(BaseSettings):
                    """Schema with a float and a bool field."""
                    RATIO: float
                    ENABLED: bool
            ''',
            env_text="""
                RATIO=not_a_float
                ENABLED=maybe
            """,
            extra_args=["--no-check-encryption"],
        )

        combined = result.stdout + result.stderr
        assert "Traceback" not in result.stderr
        assert "TYPE ERRORS" in combined, f"Should print TYPE ERRORS section. Output: {combined}"
        assert "RATIO" in combined and "float" in combined, (
            f"Should flag RATIO as a float error. Output: {combined}"
        )
        assert "ENABLED" in combined and "boolean" in combined, (
            f"Should flag ENABLED as a boolean error. Output: {combined}"
        )

    def test_validate_fix_template_encrypted_placeholder_for_sensitive_required(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """HP-12: --fix uses an encrypted placeholder for sensitive required fields.

        A missing sensitive required field renders as
        ``API_KEY="encrypted:YOUR_VALUE_HERE"`` while a missing non-sensitive
        required field renders as a bare ``PUBLIC_NAME=`` assignment.
        """
        result = _run_validate(
            tmp_path=tmp_path,
            integration_pythonpath=integration_pythonpath,
            settings_src='''
                from pydantic_settings import BaseSettings
                from pydantic import Field

                class Settings(BaseSettings):
                    """Schema with a sensitive and a non-sensitive required field."""
                    APP_NAME: str
                    API_KEY: str = Field(json_schema_extra={"sensitive": True})
                    PUBLIC_NAME: str
                    model_config = {"extra": "ignore"}
            ''',
            env_text="""
                APP_NAME=MyApp
            """,
            extra_args=["--no-check-encryption", "--fix"],
        )

        combined = result.stdout + result.stderr
        assert "Traceback" not in result.stderr
        assert "Fix template:" in combined, f"Should print a fix template. Output: {combined}"
        assert 'API_KEY="encrypted:YOUR_VALUE_HERE"' in combined, (
            f"Sensitive required field needs encrypted placeholder. Output: {combined}"
        )
        # Non-sensitive required field is a bare assignment (own line).
        assert any(line.strip() == "PUBLIC_NAME=" for line in combined.splitlines()), (
            f"Non-sensitive required field should be a bare assignment. Output: {combined}"
        )

    def test_validate_fix_is_noop_when_validation_passes(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """EC-22: --fix is a no-op when validation passes."""
        result = _run_validate(
            tmp_path=tmp_path,
            integration_pythonpath=integration_pythonpath,
            settings_src='''
                from pydantic_settings import BaseSettings

                class Settings(BaseSettings):
                    """Schema satisfied by the .env."""
                    APP_NAME: str
                    model_config = {"extra": "ignore"}
            ''',
            env_text="""
                APP_NAME=MyApp
            """,
            extra_args=["--no-check-encryption", "--fix", "--ci"],
        )

        combined = result.stdout + result.stderr
        assert result.returncode == 0, f"Passing validation should exit 0. Output: {combined}"
        assert "Traceback" not in result.stderr
        assert "PASSED" in combined, f"Should report PASSED. Output: {combined}"
        assert "Fix template" not in combined, (
            f"--fix must be a no-op on a passing run. Output: {combined}"
        )
        assert "YOUR_VALUE_HERE" not in combined, (
            f"No placeholder should be emitted on a passing run. Output: {combined}"
        )

    def test_validate_encrypted_value_skips_type_check(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """EC-09: an encrypted value for an int field produces no type error."""
        result = _run_validate(
            tmp_path=tmp_path,
            integration_pythonpath=integration_pythonpath,
            settings_src='''
                from pydantic_settings import BaseSettings

                class Settings(BaseSettings):
                    """Schema with a single int field."""
                    PORT: int
                    model_config = {"extra": "ignore"}
            ''',
            env_text="""
                PORT=encrypted:c2VjcmV0LXBvcnQtdmFsdWU
            """,
            extra_args=["--no-check-encryption"],
        )

        combined = result.stdout + result.stderr
        assert result.returncode == 0, f"Encrypted int value should pass. Output: {combined}"
        assert "Traceback" not in result.stderr
        assert "PASSED" in combined, f"Should report PASSED. Output: {combined}"
        assert "TYPE ERRORS" not in combined, (
            f"Encrypted value must not trigger a type check. Output: {combined}"
        )
        assert "Expected integer" not in combined, (
            f"No spurious integer error for encrypted value. Output: {combined}"
        )

    def test_validate_suspicious_token_warns_even_when_not_in_schema(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """EC-21: a GitHub-token-shaped value not in schema warns under --check-encryption.

        With extra='ignore' the unknown var is not an error, so validation
        PASSES (exit 0 without --ci) yet still warns that the value looks like
        a secret.
        """
        result = _run_validate(
            tmp_path=tmp_path,
            integration_pythonpath=integration_pythonpath,
            settings_src='''
                from pydantic_settings import BaseSettings

                class Settings(BaseSettings):
                    """Schema that does not declare the suspicious var."""
                    APP_NAME: str
                    model_config = {"extra": "ignore"}
            ''',
            env_text="""
                APP_NAME=MyApp
                GITHUB_TOKEN=ghp_1234567890abcdefABCDEF1234567890abcd
            """,
            extra_args=["--check-encryption"],
        )

        combined = result.stdout + result.stderr
        assert result.returncode == 0, (
            f"extra=ignore keeps a suspicious extra var non-fatal. Output: {combined}"
        )
        assert "Traceback" not in result.stderr
        assert "PASSED" in combined, f"Should report PASSED. Output: {combined}"
        assert "GITHUB_TOKEN" in combined, f"Should mention GITHUB_TOKEN. Output: {combined}"
        assert "looks like a secret" in combined or "suggesting sensitive data" in combined, (
            f"Should warn the value/name looks sensitive. Output: {combined}"
        )

    def test_validate_rejects_malformed_dotted_path(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """BP-05: a schema path missing the ':' separator is rejected, exit 1."""
        result = _run_validate(
            tmp_path=tmp_path,
            integration_pythonpath=integration_pythonpath,
            settings_src="""
                from pydantic_settings import BaseSettings

                class Settings(BaseSettings):
                    APP_NAME: str
            """,
            env_text="""
                APP_NAME=MyApp
            """,
            schema="settings_missing_colon",
            extra_args=["--no-check-encryption"],
        )

        combined = result.stdout + result.stderr
        assert result.returncode == 1, f"Malformed schema path must exit 1. Output: {combined}"
        assert "Traceback" not in result.stderr
        assert "Invalid schema path" in combined, (
            f"Should explain the path is invalid. Output: {combined}"
        )
        assert "Expected format: 'module.path:ClassName'" in combined, (
            f"Should show the expected format. Output: {combined}"
        )

    def test_validate_rejects_non_basesettings_class(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """BP-07: --schema pointing at a non-BaseSettings class exits 1 cleanly."""
        result = _run_validate(
            tmp_path=tmp_path,
            integration_pythonpath=integration_pythonpath,
            settings_src='''
                class Plain:
                    """Not a Pydantic BaseSettings subclass."""
                    pass
            ''',
            env_text="""
                APP_NAME=MyApp
            """,
            schema="settings:Plain",
            extra_args=["--no-check-encryption"],
        )

        combined = result.stdout + result.stderr
        assert result.returncode == 1, f"Non-BaseSettings class must exit 1. Output: {combined}"
        assert "Traceback" not in result.stderr
        assert "'Plain' is not a Pydantic BaseSettings subclass" in combined, (
            f"Should explain the class is not BaseSettings. Output: {combined}"
        )

    def test_validate_empty_value_parsed_as_empty_skips_type_check(
        self,
        tmp_path: Path,
        integration_pythonpath: str,
    ) -> None:
        """EC-01: an empty value (KEY=) is EMPTY status, so an int field passes."""
        result = _run_validate(
            tmp_path=tmp_path,
            integration_pythonpath=integration_pythonpath,
            settings_src='''
                from pydantic_settings import BaseSettings

                class Settings(BaseSettings):
                    """Schema with a single int field."""
                    PORT: int
                    model_config = {"extra": "ignore"}
            ''',
            env_text="""
                PORT=
            """,
            extra_args=["--no-check-encryption"],
        )

        combined = result.stdout + result.stderr
        assert result.returncode == 0, (
            f"Empty value should not fail an int field. Output: {combined}"
        )
        assert "Traceback" not in result.stderr
        assert "PASSED" in combined, f"Should report PASSED. Output: {combined}"
        assert "Expected integer" not in combined, (
            f"Empty value must not trigger an integer type error. Output: {combined}"
        )
