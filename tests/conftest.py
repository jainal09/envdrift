"""Pytest configuration and shared fixtures."""


import pytest
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


@pytest.fixture
def valid_env_content():
    """Valid .env file content."""
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
    """Encrypted .env file content (dotenvx format)."""
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
    """Partially encrypted .env file content."""
    return """DATABASE_URL="encrypted:BDQE1234567890abcdef..."
API_KEY=sk-plaintext-key-exposed
JWT_SECRET="encrypted:BDQEjwtsecret789012..."
DEBUG=true
"""


@pytest.fixture
def env_with_secrets():
    """Env content with suspicious plaintext secrets."""
    return """DATABASE_URL=postgres://user:password@localhost/db
API_KEY=sk-live-abcd1234
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
STRIPE_SECRET=sk_test_1234567890
NORMAL_VAR=just_a_value
"""


@pytest.fixture
def tmp_env_file(tmp_path, valid_env_content):
    """Create a temporary .env file."""
    env_file = tmp_path / ".env"
    env_file.write_text(valid_env_content)
    return env_file


@pytest.fixture
def tmp_encrypted_env_file(tmp_path, encrypted_env_content):
    """Create a temporary encrypted .env file."""
    env_file = tmp_path / ".env.production"
    env_file.write_text(encrypted_env_content)
    return env_file


@pytest.fixture
def test_settings_class():
    """Test Pydantic Settings class."""
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
    """Create a development .env file."""
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
    """Create a production .env file."""
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
