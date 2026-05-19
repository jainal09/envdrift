"""Performance benchmarks for envdrift core modules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from envdrift.config import EnvdriftConfig
from envdrift.core.diff import DiffEngine
from envdrift.core.encryption import EncryptionDetector
from envdrift.core.parser import EnvFile, EnvParser
from envdrift.core.schema import SchemaMetadata
from envdrift.core.validator import Validator
from envdrift.env_files import detect_env_file

# ---------------------------------------------------------------------------
# Fixtures: synthetic .env content
# ---------------------------------------------------------------------------

SMALL_ENV = """\
# Small environment file
APP_NAME=envdrift
DEBUG=true
PORT=8080
DATABASE_URL=postgres://user:pass@localhost/db
SECRET_KEY=sk-abc123def456
"""

MEDIUM_ENV = "\n".join(
    [f"VAR_{i}=value_{i}" for i in range(50)]
    + [f"SECRET_{i}=sk-{'x' * 40}" for i in range(10)]
    + [f"# Comment line {i}" for i in range(10)]
    + [f"ENCRYPTED_{i}=encrypted:abc123def456" for i in range(10)]
)

LARGE_ENV = "\n".join(
    [f"VAR_{i}=value_{i}" for i in range(200)]
    + [f"SECRET_{i}=sk-{'y' * 60}" for i in range(50)]
    + [f"# Comment line {i}" for i in range(30)]
    + [f"ENCRYPTED_{i}=encrypted:xyz789" for i in range(50)]
    + [f'JSON_VAR_{i}={{"key": "value_{i}", "nested": true}}' for i in range(20)]
)


class BenchmarkSettings(BaseSettings):
    """Settings class for benchmark validation tests."""

    model_config = SettingsConfigDict(extra="forbid")

    APP_NAME: str = "default"
    DEBUG: bool = True
    PORT: int = 8080
    DATABASE_URL: str = Field(json_schema_extra={"sensitive": True})
    SECRET_KEY: str = Field(json_schema_extra={"sensitive": True})


def _build_schema_metadata() -> SchemaMetadata:
    """Build a SchemaMetadata from BenchmarkSettings without file I/O."""
    from envdrift.core.schema import SchemaLoader

    loader = SchemaLoader()
    return loader.extract_metadata(BenchmarkSettings)


SCHEMA_META = _build_schema_metadata()


# ---------------------------------------------------------------------------
# Parser benchmarks
# ---------------------------------------------------------------------------


@pytest.mark.benchmark
def test_parse_small_env(benchmark: Any) -> None:
    """Benchmark parsing a small .env file (5 variables)."""
    parser = EnvParser()

    @benchmark
    def _() -> None:
        parser.parse_string(SMALL_ENV)


@pytest.mark.benchmark
def test_parse_medium_env(benchmark: Any) -> None:
    """Benchmark parsing a medium .env file (~80 variables)."""
    parser = EnvParser()

    @benchmark
    def _() -> None:
        parser.parse_string(MEDIUM_ENV)


@pytest.mark.benchmark
def test_parse_large_env(benchmark: Any) -> None:
    """Benchmark parsing a large .env file (~350 entries)."""
    parser = EnvParser()

    @benchmark
    def _() -> None:
        parser.parse_string(LARGE_ENV)


# ---------------------------------------------------------------------------
# Diff engine benchmarks
# ---------------------------------------------------------------------------


def _make_env_file(content: str, path_name: str = "test.env") -> EnvFile:
    """Parse content into an EnvFile without touching the filesystem."""
    parser = EnvParser()
    env = parser.parse_string(content)
    env.path = Path(path_name)
    return env


@pytest.mark.benchmark
def test_diff_identical_files(benchmark: Any) -> None:
    """Benchmark diffing two identical medium .env files."""
    engine = DiffEngine()
    env1 = _make_env_file(MEDIUM_ENV, ".env.dev")
    env2 = _make_env_file(MEDIUM_ENV, ".env.staging")

    @benchmark
    def _() -> None:
        engine.diff(env1, env2, include_unchanged=True)


@pytest.mark.benchmark
def test_diff_divergent_files(benchmark: Any) -> None:
    """Benchmark diffing two divergent .env files."""
    engine = DiffEngine()
    env1_content = "\n".join(
        [f"VAR_{i}=old_value_{i}" for i in range(40)] + [f"REMOVED_{i}=val" for i in range(10)]
    )
    env2_content = "\n".join(
        [f"VAR_{i}=new_value_{i}" for i in range(40)] + [f"ADDED_{i}=val" for i in range(10)]
    )
    env1 = _make_env_file(env1_content, ".env.dev")
    env2 = _make_env_file(env2_content, ".env.staging")

    @benchmark
    def _() -> None:
        engine.diff(env1, env2)


@pytest.mark.benchmark
def test_diff_large_with_normalization(benchmark: Any) -> None:
    """Benchmark diffing large files with value normalization enabled."""
    engine = DiffEngine()
    env1 = _make_env_file(LARGE_ENV, ".env.dev")
    # Slightly different: add whitespace and bool casing changes
    modified = LARGE_ENV.replace("value_0", "  value_0  ").replace("true", "True")
    env2 = _make_env_file(modified, ".env.staging")

    @benchmark
    def _() -> None:
        engine.diff(env1, env2, normalize=True, include_unchanged=True)


# ---------------------------------------------------------------------------
# Validator benchmarks
# ---------------------------------------------------------------------------


@pytest.mark.benchmark
def test_validate_small_env(benchmark: Any) -> None:
    """Benchmark validation of a small .env against a schema."""
    validator = Validator()
    env = _make_env_file(SMALL_ENV)

    @benchmark
    def _() -> None:
        validator.validate(env, SCHEMA_META, check_encryption=True)


@pytest.mark.benchmark
def test_validator_suspicious_values(benchmark: Any) -> None:
    """Benchmark suspicious value detection on a batch of values."""
    validator = Validator()
    values = [
        "sk-abc123",
        "ghp_1234567890abcdef",
        "xoxb-token-here",
        "postgres://user:pass@host/db",
        "normal_value",
        "another_normal",
        "AKIA1234567890ABCDEF",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
        "just-a-string",
        "12345",
    ]

    @benchmark
    def _() -> None:
        for val in values:
            validator.is_value_suspicious(val)


@pytest.mark.benchmark
def test_validator_suspicious_names(benchmark: Any) -> None:
    """Benchmark suspicious name detection on a batch of variable names."""
    validator = Validator()
    names = [
        "API_KEY",
        "DATABASE_SECRET",
        "AUTH_TOKEN",
        "JWT_SECRET",
        "APP_NAME",
        "DEBUG",
        "PORT",
        "PRIVATE_KEY",
        "MY_PASSWORD",
        "SENTRY_DSN",
    ]

    @benchmark
    def _() -> None:
        for name in names:
            validator.is_name_suspicious(name)


# ---------------------------------------------------------------------------
# Encryption detector benchmarks
# ---------------------------------------------------------------------------


@pytest.mark.benchmark
def test_encryption_analyze(benchmark: Any) -> None:
    """Benchmark encryption analysis on a mixed env file."""
    detector = EncryptionDetector()
    env = _make_env_file(MEDIUM_ENV)

    @benchmark
    def _() -> None:
        detector.analyze(env)


@pytest.mark.benchmark
def test_encryption_detect_backend(benchmark: Any) -> None:
    """Benchmark backend detection on file content."""
    detector = EncryptionDetector()
    content = "#/---BEGIN DOTENV ENCRYPTED---/\nDOTENV_PUBLIC_KEY=abc123\nSECRET=encrypted:xyz789\n"

    @benchmark
    def _() -> None:
        detector.detect_backend(content)


# ---------------------------------------------------------------------------
# Config loading benchmarks
# ---------------------------------------------------------------------------


SAMPLE_CONFIG_DICT: dict[str, Any] = {
    "envdrift": {
        "schema": "config:Settings",
        "environments": ["development", "staging", "production"],
        "env_file_pattern": ".env.{environment}",
    },
    "validation": {
        "check_encryption": True,
        "strict_extra": True,
        "secret_patterns": ["^STRIPE_", "^TWILIO_"],
    },
    "vault": {
        "provider": "azure",
        "azure": {"vault_url": "https://my-vault.vault.azure.net/"},
        "sync": {
            "default_vault_name": "my-keyvault",
            "mappings": [
                {
                    "secret_name": "app-key",
                    "folder_path": ".",
                    "environment": "production",
                },
                {
                    "secret_name": "svc-key",
                    "folder_path": "services/api",
                    "vault_name": "other-vault",
                    "environment": "staging",
                },
            ],
        },
    },
    "encryption": {
        "backend": "dotenvx",
        "smart_encryption": False,
        "dotenvx": {"auto_install": False},
        "sops": {"auto_install": False},
    },
    "guard": {
        "scanners": ["native", "gitleaks"],
        "auto_install": True,
        "ignore_paths": ["*.test.py", "tests/**"],
    },
    "guardian": {
        "enabled": False,
        "idle_timeout": "5m",
    },
}


@pytest.mark.benchmark
def test_config_from_dict(benchmark: Any) -> None:
    """Benchmark EnvdriftConfig.from_dict with a realistic configuration."""

    @benchmark
    def _() -> None:
        EnvdriftConfig.from_dict(SAMPLE_CONFIG_DICT)


# ---------------------------------------------------------------------------
# Env file detection benchmark
# ---------------------------------------------------------------------------


@pytest.mark.benchmark
def test_detect_env_file(benchmark: Any, tmp_path: Path) -> None:
    """Benchmark env file detection in a directory with multiple files."""
    # Set up a realistic directory structure
    (tmp_path / ".env").write_text("APP=test\nDEBUG=true\n")
    (tmp_path / ".env.example").write_text("APP=\nDEBUG=\n")
    (tmp_path / "README.md").write_text("# Project\n")
    (tmp_path / "config.py").write_text("x = 1\n")

    @benchmark
    def _() -> None:
        detect_env_file(tmp_path)
