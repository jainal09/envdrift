"""Tests for Validator."""

from envdrift.core.parser import EnvParser
from envdrift.core.schema import SchemaLoader
from envdrift.core.validator import Validator


class TestValidator:
    """Test cases for Validator."""

    def test_validate_missing_required(self, tmp_path, test_settings_class):
        """Detect missing required vars."""
        # Missing API_KEY and JWT_SECRET
        content = """
DATABASE_URL=postgres://localhost/db
REDIS_URL=redis://localhost:6379
HOST=0.0.0.0
PORT=8000
DEBUG=true
NEW_FEATURE_FLAG=enabled
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        env = parser.parse(env_file)

        loader = SchemaLoader()
        schema = loader.extract_metadata(test_settings_class)

        validator = Validator()
        result = validator.validate(env, schema, check_encryption=False)

        assert result.valid is False
        assert "API_KEY" in result.missing_required
        assert "JWT_SECRET" in result.missing_required

    def test_validate_extra_vars_forbid(self, tmp_path, test_settings_class):
        """Reject extra vars when schema has extra=forbid."""
        content = """
DATABASE_URL=postgres://localhost/db
REDIS_URL=redis://localhost:6379
API_KEY=test
JWT_SECRET=secret
HOST=0.0.0.0
PORT=8000
DEBUG=true
NEW_FEATURE_FLAG=enabled
EXTRA_VAR=not_in_schema
ANOTHER_EXTRA=also_not_in_schema
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        env = parser.parse(env_file)

        loader = SchemaLoader()
        schema = loader.extract_metadata(test_settings_class)

        validator = Validator()
        result = validator.validate(env, schema, check_encryption=False)

        assert result.valid is False
        assert "EXTRA_VAR" in result.extra_vars
        assert "ANOTHER_EXTRA" in result.extra_vars

    def test_validate_extra_vars_ignore(self, tmp_path, permissive_settings_class):
        """Allow extra vars when schema has extra=ignore."""
        content = """
DATABASE_URL=postgres://localhost/db
HOST=0.0.0.0
EXTRA_VAR=allowed
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        env = parser.parse(env_file)

        loader = SchemaLoader()
        schema = loader.extract_metadata(permissive_settings_class)

        validator = Validator()
        result = validator.validate(env, schema, check_encryption=False)

        # Should be valid - extra vars are ignored
        assert result.valid is True
        assert "EXTRA_VAR" not in result.extra_vars
        # But should have a warning
        assert any("EXTRA_VAR" in w for w in result.warnings)

    def test_validate_unencrypted_secrets(self, tmp_path, test_settings_class):
        """Detect unencrypted sensitive vars."""
        content = """
DATABASE_URL=postgres://localhost/db
REDIS_URL=redis://localhost:6379
API_KEY=plaintext-secret-exposed
JWT_SECRET=another-plaintext-secret
HOST=0.0.0.0
PORT=8000
DEBUG=true
NEW_FEATURE_FLAG=enabled
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        env = parser.parse(env_file)

        loader = SchemaLoader()
        schema = loader.extract_metadata(test_settings_class)

        validator = Validator()
        result = validator.validate(env, schema, check_encryption=True)

        # Unencrypted secrets are warnings, not errors (valid is still True)
        assert result.valid is True
        assert result.warning_count > 0  # Has warnings for unencrypted secrets
        assert "DATABASE_URL" in result.unencrypted_secrets
        assert "REDIS_URL" in result.unencrypted_secrets
        assert "API_KEY" in result.unencrypted_secrets
        assert "JWT_SECRET" in result.unencrypted_secrets

    def test_validate_encrypted_secrets_pass(self, tmp_path, test_settings_class):
        """Pass when sensitive vars are encrypted."""
        content = """
DATABASE_URL="encrypted:BDQE123..."
REDIS_URL="encrypted:BDQE456..."
API_KEY="encrypted:BDQE789..."
JWT_SECRET="encrypted:BDQEabc..."
HOST=0.0.0.0
PORT=8000
DEBUG=true
NEW_FEATURE_FLAG=enabled
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        env = parser.parse(env_file)

        loader = SchemaLoader()
        schema = loader.extract_metadata(test_settings_class)

        validator = Validator()
        result = validator.validate(env, schema, check_encryption=True)

        assert result.valid is True
        assert len(result.unencrypted_secrets) == 0

    def test_validate_type_mismatch(self, tmp_path, test_settings_class):
        """Detect obvious type mismatches."""
        content = """
DATABASE_URL=postgres://localhost/db
REDIS_URL=redis://localhost:6379
API_KEY=test
JWT_SECRET=secret
HOST=0.0.0.0
PORT=not_a_number
DEBUG=true
NEW_FEATURE_FLAG=enabled
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        env = parser.parse(env_file)

        loader = SchemaLoader()
        schema = loader.extract_metadata(test_settings_class)

        validator = Validator()
        result = validator.validate(env, schema, check_encryption=False)

        assert result.valid is False
        assert "PORT" in result.type_errors

    def test_validate_suspicious_plaintext(self, tmp_path, permissive_settings_class):
        """Warn about plaintext values matching secret patterns."""
        content = """
DATABASE_URL=postgres://user:password@localhost/db
HOST=0.0.0.0
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        env = parser.parse(env_file)

        loader = SchemaLoader()
        schema = loader.extract_metadata(permissive_settings_class)

        validator = Validator()
        result = validator.validate(env, schema, check_encryption=True)

        # Should have warnings about suspicious values
        assert len(result.warnings) > 0
        assert any("GITHUB_TOKEN" in w for w in result.warnings)

    def test_is_value_suspicious(self):
        """Test secret pattern detection."""
        validator = Validator()

        # Should be suspicious
        assert validator.is_value_suspicious("sk-live-abc123") is True
        assert validator.is_value_suspicious("ghp_xxxx") is True
        assert validator.is_value_suspicious("AKIAIOSFODNN7EXAMPLE") is True
        assert validator.is_value_suspicious("postgres://user:pass@host/db") is True

        # Should not be suspicious
        assert validator.is_value_suspicious("hello") is False
        assert validator.is_value_suspicious("localhost") is False
        assert validator.is_value_suspicious("8000") is False

    def test_is_name_suspicious(self):
        """Test sensitive variable name detection."""
        validator = Validator()

        # Should be suspicious
        assert validator.is_name_suspicious("API_KEY") is True
        assert validator.is_name_suspicious("JWT_SECRET") is True
        assert validator.is_name_suspicious("DB_PASSWORD") is True
        assert validator.is_name_suspicious("AUTH_TOKEN") is True

        # Should not be suspicious
        assert validator.is_name_suspicious("HOST") is False
        assert validator.is_name_suspicious("PORT") is False
        assert validator.is_name_suspicious("DEBUG") is False

    def test_generate_fix_template(self, tmp_path, test_settings_class):
        """Test fix template generation."""
        content = """
DATABASE_URL=postgres://localhost/db
HOST=0.0.0.0
PORT=8000
DEBUG=true
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        env = parser.parse(env_file)

        loader = SchemaLoader()
        schema = loader.extract_metadata(test_settings_class)

        validator = Validator()
        result = validator.validate(env, schema, check_encryption=False)
        template = validator.generate_fix_template(result, schema)

        # Should include missing required vars
        assert "REDIS_URL" in template
        assert "API_KEY" in template
        assert "JWT_SECRET" in template
        assert "NEW_FEATURE_FLAG" in template

    def test_validation_result_properties(self, tmp_path, test_settings_class):
        """Test ValidationResult properties."""
        content = """
DATABASE_URL=postgres://localhost/db
HOST=0.0.0.0
PORT=not_a_number
DEBUG=true
EXTRA=extra
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        env = parser.parse(env_file)

        loader = SchemaLoader()
        schema = loader.extract_metadata(test_settings_class)

        validator = Validator()
        result = validator.validate(env, schema, check_encryption=False)

        assert result.has_errors is True
        assert result.error_count > 0
        assert result.warning_count >= 0
