"""Pytest configuration and shared fixtures."""

import pytest
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


@pytest.fixture
def valid_env_content():
    """
    Provide a sample `.env` file content for tests.

    Returns:
        env_content (str): Multi-line string containing sample environment variables for database and cache URLs, API keys and secrets, server host/port/debug settings, and a feature flag.
    """
    return """# Database configuration
DATABASE_URL=postgres://localhost/db
REDIS_URL=redis://localhost:6379

# API Keys
API_KEY=sk-test123
JWT_SECRET=super-secret-key-for-jwt-signing

# Server config
HOST=0.0.0.0
PORT=8000
DEBUG=true

# Feature flags
NEW_FEATURE_FLAG=enabled
"""


@pytest.fixture
def encrypted_env_content():
    """
    Sample dotenvx-format .env content where most values are encrypted.

    Includes a public key line, several encrypted variable values, and a few plaintext entries (host, port, debug, feature flag).

    Returns:
        str: The contents of an encrypted .env file suitable for use in tests.
    """
    return """#/---BEGIN DOTENV ENCRYPTED---/
DOTENV_PUBLIC_KEY_PRODUCTION="03abc123..."
DATABASE_URL="encrypted:BDQE1234567890abcdef..."
REDIS_URL="encrypted:BDQE0987654321fedcba..."
API_KEY="encrypted:BDQEsecretkey123456..."
JWT_SECRET="encrypted:BDQEjwtsecret789012..."
HOST=0.0.0.0
PORT=8000
DEBUG=false
NEW_FEATURE_FLAG=enabled
#/---END DOTENV ENCRYPTED---/
"""


@pytest.fixture
def partial_encrypted_content():
    """
    Provide sample .env content that contains both encrypted and plaintext values.

    Returns:
        env_content (str): Multiline string representing a .env file where some values are encrypted (prefixed with `encrypted:...`) and others are plaintext.
    """
    return """DATABASE_URL="encrypted:BDQE1234567890abcdef..."
API_KEY=sk-plaintext-key-exposed
JWT_SECRET="encrypted:BDQEjwtsecret789012..."
DEBUG=true
"""


@pytest.fixture
def env_with_secrets():
    """
    Sample .env content containing several plaintext secret-looking variables and one non-secret variable.

    Returns:
        env_content (str): Multi-line string representing environment file entries including DATABASE_URL, API_KEY, GITHUB_TOKEN, AWS_ACCESS_KEY_ID, STRIPE_SECRET, and NORMAL_VAR.
    """
    return """DATABASE_URL=postgres://user:password@localhost/db
API_KEY=sk-live-abcd1234
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
STRIPE_SECRET=sk_test_1234567890
NORMAL_VAR=just_a_value
"""


@pytest.fixture
def tmp_env_file(tmp_path, valid_env_content):
    """
    Create a temporary `.env` file containing the provided environment content.

    Parameters:
        tmp_path (Path): Temporary directory fixture provided by pytest.
        valid_env_content (str): Text to write into the `.env` file.

    Returns:
        Path: Path to the created `.env` file.
    """
    env_file = tmp_path / ".env"
    env_file.write_text(valid_env_content)
    return env_file


@pytest.fixture
def tmp_encrypted_env_file(tmp_path, encrypted_env_content):
    """
    Create a temporary .env.production file containing encrypted environment content.

    Parameters:
        tmp_path (pathlib.Path): Temporary directory provided by pytest where the file will be created.
        encrypted_env_content (str): Encrypted dotenv-formatted content to write into the file.

    Returns:
        pathlib.Path: Path to the created .env.production file.
    """
    env_file = tmp_path / ".env.production"
    env_file.write_text(encrypted_env_content)
    return env_file


@pytest.fixture
def test_settings_class():
    """
    Provide a Pydantic BaseSettings subclass configured for tests.

    Returns:
        TestSettings (type): A BaseSettings subclass with extra="forbid". Includes sensitive string fields
        `DATABASE_URL`, `REDIS_URL`, `API_KEY`, and `JWT_SECRET`; defaults `HOST="0.0.0.0"`, `PORT=8000`,
        `DEBUG=False`; and a required `NEW_FEATURE_FLAG` string.
    """

    class TestSettings(BaseSettings):
        model_config = SettingsConfigDict(extra="forbid")

        DATABASE_URL: str = Field(json_schema_extra={"sensitive": True})
        REDIS_URL: str = Field(json_schema_extra={"sensitive": True})
        API_KEY: str = Field(json_schema_extra={"sensitive": True})
        JWT_SECRET: str = Field(json_schema_extra={"sensitive": True})
        HOST: str = "0.0.0.0"
        PORT: int = 8000
        DEBUG: bool = False
        NEW_FEATURE_FLAG: str

    return TestSettings


@pytest.fixture
def permissive_settings_class():
    """Test Pydantic Settings class with extra="ignore"."""

    class PermissiveSettings(BaseSettings):
        model_config = SettingsConfigDict(extra="ignore")

        DATABASE_URL: str = Field(json_schema_extra={"sensitive": True})
        HOST: str = "0.0.0.0"

    return PermissiveSettings


@pytest.fixture
def env_file_dev(tmp_path):
    """
    Create a temporary development `.env.development` file populated with typical development environment variables.

    Parameters:
        tmp_path (Path): Base temporary directory in which the `.env.development` file will be created.

    Returns:
        Path: Path to the created `.env.development` file.
    """
    content = """DATABASE_URL=postgres://localhost/dev_db
API_KEY=dev-api-key
DEBUG=true
LOG_LEVEL=DEBUG
APP_NAME=myapp
DEV_ONLY_VAR=dev_value
"""
    env_file = tmp_path / ".env.development"
    env_file.write_text(content)
    return env_file


@pytest.fixture
def env_file_prod(tmp_path):
    """
    Create a production .env file under the provided temporary path.

    Writes a file named ".env.production" containing typical production environment variables (DATABASE_URL, API_KEY, DEBUG, LOG_LEVEL, APP_NAME, SENTRY_DSN) and returns the Path to the created file.

    Returns:
        Path: Path to the created ".env.production" file.
    """
    content = """DATABASE_URL=postgres://prod-server/prod_db
API_KEY=prod-api-key
DEBUG=false
LOG_LEVEL=WARNING
APP_NAME=myapp
SENTRY_DSN=https://sentry.io/123
"""
    env_file = tmp_path / ".env.production"
    env_file.write_text(content)
    return env_file
