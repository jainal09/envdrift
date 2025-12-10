"""Tests for EncryptionDetector."""

from envdrift.core.encryption import EncryptionDetector
from envdrift.core.parser import EnvParser


class TestEncryptionDetector:
    """Test cases for EncryptionDetector."""

    def test_analyze_fully_encrypted(self, tmp_encrypted_env_file):
        """Analyze fully encrypted file."""
        parser = EnvParser()
        env = parser.parse(tmp_encrypted_env_file)

        detector = EncryptionDetector()
        report = detector.analyze(env)

        # Most vars should be encrypted (HOST, PORT, DEBUG, NEW_FEATURE_FLAG are plaintext)
        assert len(report.encrypted_vars) >= 4
        assert len(report.plaintext_vars) >= 3

    def test_analyze_partial_encrypted(self, tmp_path, partial_encrypted_content):
        """Analyze partially encrypted file."""
        env_file = tmp_path / ".env"
        env_file.write_text(partial_encrypted_content)

        parser = EnvParser()
        env = parser.parse(env_file)

        detector = EncryptionDetector()
        report = detector.analyze(env)

        assert report.is_fully_encrypted is False
        assert len(report.encrypted_vars) > 0
        assert len(report.plaintext_vars) > 0

    def test_detect_plaintext_secrets(self, tmp_path, env_with_secrets):
        """Detect plaintext secrets."""
        env_file = tmp_path / ".env"
        env_file.write_text(env_with_secrets)

        parser = EnvParser()
        env = parser.parse(env_file)

        detector = EncryptionDetector()
        report = detector.analyze(env)

        # Should detect suspicious plaintext values
        assert len(report.plaintext_secrets) > 0
        assert "API_KEY" in report.plaintext_secrets or any(
            "API" in s for s in report.plaintext_secrets
        )

    def test_should_block_commit(self, tmp_path, env_with_secrets):
        """Block commit when plaintext secrets detected."""
        env_file = tmp_path / ".env"
        env_file.write_text(env_with_secrets)

        parser = EnvParser()
        env = parser.parse(env_file)

        detector = EncryptionDetector()
        report = detector.analyze(env)

        assert detector.should_block_commit(report) is True

    def test_should_not_block_encrypted(self, tmp_path):
        """Don't block commit when all secrets encrypted."""
        content = """
API_KEY="encrypted:BDQE123..."
JWT_SECRET="encrypted:BDQE456..."
DEBUG=true
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        env = parser.parse(env_file)

        detector = EncryptionDetector()
        report = detector.analyze(env)

        assert detector.should_block_commit(report) is False

    def test_has_encrypted_header(self):
        """Check for dotenvx encryption header."""
        detector = EncryptionDetector()

        encrypted_content = """#/---BEGIN DOTENV ENCRYPTED---/
DOTENV_PUBLIC_KEY_PRODUCTION="03abc123..."
FOO="encrypted:xyz"
"""
        assert detector.has_encrypted_header(encrypted_content) is True

        plaintext_content = """
FOO=bar
BAZ=qux
"""
        assert detector.has_encrypted_header(plaintext_content) is False

    def test_is_file_encrypted(self, tmp_path):
        """Quick check if file is encrypted."""
        detector = EncryptionDetector()

        encrypted_file = tmp_path / ".env.encrypted"
        encrypted_file.write_text("#/---BEGIN DOTENV ENCRYPTED---/\nFOO=bar")
        assert detector.is_file_encrypted(encrypted_file) is True

        plain_file = tmp_path / ".env.plain"
        plain_file.write_text("FOO=bar")
        assert detector.is_file_encrypted(plain_file) is False

        nonexistent = tmp_path / ".env.nonexistent"
        assert detector.is_file_encrypted(nonexistent) is False

    def test_encryption_ratio(self, tmp_path):
        """Test encryption ratio calculation."""
        # 2 encrypted, 2 plaintext = 50%
        content = """
ENC1="encrypted:abc"
ENC2="encrypted:def"
PLAIN1=value1
PLAIN2=value2
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        env = parser.parse(env_file)

        detector = EncryptionDetector()
        report = detector.analyze(env)

        assert report.encryption_ratio == 0.5

    def test_get_recommendations(self, tmp_path):
        """Test recommendation generation."""
        content = """
API_KEY=sk-plaintext
DATABASE_URL=postgres://user:pass@host/db
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        env = parser.parse(env_file)

        detector = EncryptionDetector()
        report = detector.analyze(env)
        recommendations = detector.get_recommendations(report)

        assert len(recommendations) > 0
        assert any("encrypt" in r.lower() for r in recommendations)

    def test_analyze_with_schema(self, tmp_path, test_settings_class):
        """Analyze with schema for sensitive field detection."""
        from envdrift.core.schema import SchemaLoader

        content = """
DATABASE_URL=postgres://localhost/db
REDIS_URL=redis://localhost:6379
API_KEY=plaintext-key
JWT_SECRET=plaintext-secret
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

        detector = EncryptionDetector()
        report = detector.analyze(env, schema)

        # Should detect schema-defined sensitive fields as plaintext secrets
        assert "DATABASE_URL" in report.plaintext_secrets
        assert "API_KEY" in report.plaintext_secrets
        assert "JWT_SECRET" in report.plaintext_secrets
        assert len(report.warnings) > 0

    def test_empty_file(self, tmp_path):
        """Handle empty env file."""
        env_file = tmp_path / ".env"
        env_file.write_text("")

        parser = EnvParser()
        env = parser.parse(env_file)

        detector = EncryptionDetector()
        report = detector.analyze(env)

        assert report.total_vars == 0
        assert report.encryption_ratio == 0.0
        assert report.is_fully_encrypted is False
