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

    def test_public_key_artifact_not_treated_as_plaintext_secret(self, tmp_path):
        """A fully-encrypted .secret file must not be blocked by its public key.

        dotenvx names the public key of `.env.production.secret` as
        `DOTENV_PUBLIC_KEY_PRODUCTION_SECRET`, which matches the `*_SECRET`
        sensitive-name heuristic. It is a public key (plaintext-safe), so it must
        not count as a plaintext secret nor keep the file from reporting as fully
        encrypted — otherwise the pre-commit hook blocks a correctly-encrypted
        `.secret`.
        """
        content = (
            "#/---[DOTENV_PUBLIC_KEY]---/\n"
            'DOTENV_PUBLIC_KEY_PRODUCTION_SECRET="034c65f520ec607225d1344fdb'
            'ace9c31b06c1c8095f413c9cc50abb105f7124e3"\n'
            'API_KEY="encrypted:BDQE123..."\n'
            'DB_PASSWORD="encrypted:BDQE456..."\n'
        )
        env_file = tmp_path / ".env.production.secret"
        env_file.write_text(content)

        parser = EnvParser()
        env = parser.parse(env_file)

        detector = EncryptionDetector()
        report = detector.analyze(env)

        assert "DOTENV_PUBLIC_KEY_PRODUCTION_SECRET" not in report.plaintext_secrets
        assert "DOTENV_PUBLIC_KEY_PRODUCTION_SECRET" not in report.plaintext_vars
        assert detector.should_block_commit(report) is False
        assert report.is_fully_encrypted is True

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

    def test_detect_sops_backend(self, tmp_path):
        """Detect SOPS markers in content and files."""
        detector = EncryptionDetector()
        content = 'KEY="ENC[AES256_GCM,data:abc,iv:xyz,tag:123,type:str]"'

        assert detector.has_sops_header(content) is True
        assert detector.detect_backend(content) == "sops"

        env_file = tmp_path / ".env"
        env_file.write_text(content)
        assert detector.detect_backend_for_file(env_file) == "sops"

    def test_plaintext_sops_substring_not_detected_as_sops(self, tmp_path):
        """#413 — a bare ``sops:`` substring in plaintext is NOT SOPS-encrypted.

        ``has_sops_header`` / ``detect_backend`` / ``detect_backend_for_file`` /
        ``is_file_encrypted`` used unanchored ``"sops:" in content`` substring
        checks, so a plaintext value like ``VAULT_ADDR=https://sops:8200`` was
        misclassified as SOPS-encrypted — causing ``decrypt`` with no ``--backend``
        to auto-select sops and attempt a SOPS decrypt of a plaintext file. The
        checks are now line-anchored.
        """
        detector = EncryptionDetector()
        content = "VAULT_ADDR=https://sops:8200\nAPI_KEY=plain"

        assert detector.has_sops_header(content) is False
        assert detector.detect_backend(content) is None

        env_file = tmp_path / ".env"
        env_file.write_text(content)
        assert detector.detect_backend_for_file(env_file) is None
        assert detector.is_file_encrypted(env_file) is False

    def test_genuine_sops_metadata_block_still_detected(self, tmp_path):
        """A real line-anchored SOPS metadata block is still detected (no regression)."""
        detector = EncryptionDetector()
        for content in (
            "key: value\nsops:\n  version: 3.8.1\n",  # YAML
            "API_KEY=plain\nsops_version=3.13.1\n",  # dotenv metadata trailer
            "API_KEY=plain\nsops_mac=abc123\n",
        ):
            assert detector.has_sops_header(content) is True, content
            assert detector.detect_backend(content) == "sops", content

    def test_detect_dotenvx_backend(self, tmp_path):
        """Detect dotenvx headers and markers."""
        detector = EncryptionDetector()
        content = "#/---BEGIN DOTENV ENCRYPTED---/\nDOTENV_PUBLIC_KEY=abc\nKEY=encrypted:xyz"

        assert detector.has_dotenvx_header(content) is True
        assert detector.detect_backend(content) == "dotenvx"

        env_file = tmp_path / ".env"
        env_file.write_text(content)
        assert detector.detect_backend_for_file(env_file) == "dotenvx"

    def test_detect_value_backend(self):
        """Detect backend type for encrypted values."""
        detector = EncryptionDetector()

        assert detector.detect_value_backend("encrypted:abc") == "dotenvx"
        assert detector.detect_value_backend("ENC[AES256_GCM,data:abc]") == "sops"
        assert detector.detect_value_backend("plain") is None

    def test_get_recommendations_for_sops(self, tmp_path):
        """Recommendation should use --backend sops when detected."""
        content = "API_KEY=sk-plaintext"
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        env = parser.parse(env_file)

        detector = EncryptionDetector()
        report = detector.analyze(env)
        report.detected_backend = "sops"

        recommendations = detector.get_recommendations(report)

        assert any("--backend sops" in r for r in recommendations)

    def test_is_value_encrypted_sops(self):
        """Treat SOPS values as encrypted."""
        detector = EncryptionDetector()

        assert detector.is_value_encrypted("ENC[AES256_GCM,data:abc]") is True
        assert detector.is_value_encrypted("plaintext") is False
