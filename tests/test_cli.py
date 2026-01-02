"""Tests for CLI commands."""

from typer.testing import CliRunner

from envdrift.cli import app

runner = CliRunner()


def test_version() -> None:
    """Test version command."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    # Check for version output (works with both tagged and dev versions)
    assert "envdrift" in result.stdout
    # Version should contain numbers (e.g., "0.1.0" or "0.1.dev1+g123456")
    assert any(char.isdigit() for char in result.stdout)


def test_validate_requires_schema() -> None:
    """Test validate command requires --schema."""
    result = runner.invoke(app, ["validate"])
    assert result.exit_code == 1
    assert "--schema" in result.stdout or "schema" in result.stdout.lower()


def test_validate_file_not_found(tmp_path) -> None:
    """Test validate with missing env file."""
    result = runner.invoke(
        app, ["validate", str(tmp_path / "nonexistent.env"), "--schema", "app:Settings"]
    )
    assert result.exit_code == 1
    assert "not found" in result.stdout.lower()


def test_diff_requires_two_files() -> None:
    """Test diff requires two file arguments."""
    result = runner.invoke(app, ["diff"])
    assert result.exit_code != 0


def test_diff_file_not_found(tmp_path) -> None:
    """Test diff with missing env file."""
    env1 = tmp_path / ".env1"
    env1.write_text("FOO=bar")

    result = runner.invoke(app, ["diff", str(env1), str(tmp_path / "nonexistent.env")])
    assert result.exit_code == 1
    assert "not found" in result.stdout.lower()


def test_diff_identical_files(tmp_path) -> None:
    """Test diff with identical files."""
    content = "FOO=bar\nBAZ=qux"
    env1 = tmp_path / ".env1"
    env1.write_text(content)
    env2 = tmp_path / ".env2"
    env2.write_text(content)

    result = runner.invoke(app, ["diff", str(env1), str(env2)])
    assert result.exit_code == 0
    assert "No drift" in result.stdout or "match" in result.stdout.lower()


def test_diff_with_differences(tmp_path) -> None:
    """Test diff shows differences."""
    env1 = tmp_path / ".env1"
    env1.write_text("FOO=bar\nONLY_IN_1=value")
    env2 = tmp_path / ".env2"
    env2.write_text("FOO=different\nONLY_IN_2=value")

    result = runner.invoke(app, ["diff", str(env1), str(env2)])
    assert result.exit_code == 0
    # Should show differences
    assert "FOO" in result.stdout or "changed" in result.stdout.lower()


def test_diff_json_format(tmp_path) -> None:
    """Test diff with JSON output format."""
    content = "FOO=bar"
    env1 = tmp_path / ".env1"
    env1.write_text(content)
    env2 = tmp_path / ".env2"
    env2.write_text("FOO=baz")

    result = runner.invoke(app, ["diff", str(env1), str(env2), "--format", "json"])
    assert result.exit_code == 0
    # Should contain JSON structure
    assert "{" in result.stdout
    assert "differences" in result.stdout


def test_encrypt_check_file_not_found(tmp_path) -> None:
    """Test encrypt --check with missing file."""
    result = runner.invoke(app, ["encrypt", str(tmp_path / "nonexistent.env"), "--check"])
    assert result.exit_code == 1


def test_encrypt_check_plaintext(tmp_path) -> None:
    """Test encrypt --check detects plaintext secrets."""
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=sk-plaintext-secret\nDEBUG=true")

    result = runner.invoke(app, ["encrypt", str(env_file), "--check"])
    # Should fail due to plaintext secret
    assert result.exit_code == 1


def test_encrypt_check_no_secrets(tmp_path) -> None:
    """Test encrypt --check passes with no secrets."""
    env_file = tmp_path / ".env"
    env_file.write_text("DEBUG=true\nHOST=localhost")

    result = runner.invoke(app, ["encrypt", str(env_file), "--check"])
    assert result.exit_code == 0


def test_init_creates_settings(tmp_path) -> None:
    """Test init generates settings file."""
    env_file = tmp_path / ".env"
    env_file.write_text("FOO=bar\nPORT=8000\nDEBUG=true")
    output_file = tmp_path / "settings.py"

    result = runner.invoke(app, ["init", str(env_file), "--output", str(output_file)])
    assert result.exit_code == 0
    assert output_file.exists()

    content = output_file.read_text()
    assert "class Settings" in content
    assert "FOO" in content
    assert "PORT" in content
    assert "DEBUG" in content


def test_init_detects_sensitive(tmp_path) -> None:
    """Test init auto-detects sensitive variables."""
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=secret\nDEBUG=true")
    output_file = tmp_path / "settings.py"

    result = runner.invoke(
        app, ["init", str(env_file), "--output", str(output_file), "--detect-sensitive"]
    )
    assert result.exit_code == 0

    content = output_file.read_text()
    assert "sensitive" in content


def test_init_custom_class_name(tmp_path) -> None:
    """Test init with custom class name."""
    env_file = tmp_path / ".env"
    env_file.write_text("FOO=bar")
    output_file = tmp_path / "settings.py"

    result = runner.invoke(
        app, ["init", str(env_file), "--output", str(output_file), "--class-name", "CustomSettings"]
    )
    assert result.exit_code == 0

    content = output_file.read_text()
    assert "class CustomSettings" in content


def test_hook_shows_config() -> None:
    """Test hook command shows pre-commit config."""
    result = runner.invoke(app, ["hook"])
    assert result.exit_code == 0
    assert "pre-commit" in result.stdout.lower()
    assert "envdrift-validate" in result.stdout


def test_hook_config_flag() -> None:
    """Test hook --config shows config snippet."""
    result = runner.invoke(app, ["hook", "--config"])
    assert result.exit_code == 0
    assert "repos:" in result.stdout
    assert "envdrift" in result.stdout


# ============== LOCK COMMAND TESTS ==============


def test_lock_no_config_found(tmp_path) -> None:
    """Test lock fails gracefully when no config is found."""
    # Change to a temp directory with no config
    import os
    from pathlib import Path

    original_cwd = Path.cwd()
    try:
        os.chdir(tmp_path)
        result = runner.invoke(app, ["lock"])
        assert result.exit_code == 1
        # Should indicate no config found
        assert "No sync configuration found" in result.stdout or "provider" in result.stdout.lower()
    finally:
        os.chdir(original_cwd)


def test_lock_help() -> None:
    """Test lock --help shows usage information."""
    import re

    result = runner.invoke(app, ["lock", "--help"])
    assert result.exit_code == 0
    # Strip ANSI escape codes for CI compatibility
    output = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
    assert "lock" in output.lower()
    assert "--verify-vault" in output
    assert "--sync-keys" in output
    assert "--check" in output
    assert "--force" in output
    assert "--profile" in output


def test_lock_check_only_with_encrypted_file(tmp_path) -> None:
    """Test lock --check with already encrypted files."""
    # Create a minimal TOML config
    config_file = tmp_path / "envdrift.toml"
    config_file.write_text("""
[vault]
provider = "azure"

[vault.azure]
vault_url = "https://test-vault.vault.azure.net/"

[vault.sync]
default_vault_name = "test-vault"

[[vault.sync.mappings]]
secret_name = "test-secret"
folder_path = "."
environment = "production"
""")

    # Create an already-encrypted env file
    env_file = tmp_path / ".env.production"
    env_file.write_text("""#/---BEGIN DOTENV ENCRYPTED---/
DOTENV_PUBLIC_KEY_PRODUCTION="03abc123..."
DATABASE_URL="encrypted:BDQE1234567890abcdef..."
API_KEY="encrypted:BDQEsecretkey123456..."
DEBUG=false
#/---END DOTENV ENCRYPTED---/
""")

    import os
    from pathlib import Path

    original_cwd = Path.cwd()
    try:
        os.chdir(tmp_path)
        result = runner.invoke(app, ["lock", "--check", "--force", "-c", str(config_file)])
        # Should complete (may skip encrypted files) or fail because dotenvx not installed
        # The output should mention "already encrypted", "skipped", or "dotenvx" (not installed)
        assert (
            "already encrypted" in result.stdout.lower()
            or "check complete" in result.stdout.lower()
            or "skipped" in result.stdout.lower()
            or "dotenvx" in result.stdout.lower()  # dotenvx not installed in CI
            or "azure sdk not installed" in result.stdout.lower()
        )
    finally:
        os.chdir(original_cwd)


def test_lock_check_mode_with_decrypted_file(tmp_path) -> None:
    """Test lock --check identifies files that would be encrypted."""
    # Create a minimal TOML config
    config_file = tmp_path / "envdrift.toml"
    config_file.write_text("""
[vault]
provider = "azure"

[vault.azure]
vault_url = "https://test-vault.vault.azure.net/"

[vault.sync]
default_vault_name = "test-vault"

[[vault.sync.mappings]]
secret_name = "test-secret"
folder_path = "."
environment = "production"
""")

    # Create a decrypted env file
    env_file = tmp_path / ".env.production"
    env_file.write_text("""DATABASE_URL=postgres://localhost/db
API_KEY=sk-test123
DEBUG=true
""")

    import os
    from pathlib import Path

    original_cwd = Path.cwd()
    try:
        os.chdir(tmp_path)
        result = runner.invoke(app, ["lock", "--check", "--force", "-c", str(config_file)])
        # Should report files would be encrypted and exit with code 1,
        # or fail because dotenvx not installed
        assert (
            "would be encrypted" in result.stdout.lower()
            or "need encryption" in result.stdout.lower()
            or "dotenvx" in result.stdout.lower()  # dotenvx not installed in CI
            or "azure sdk not installed" in result.stdout.lower()
        )
        # If dotenvx is installed, check mode should fail when files need encryption
        if (
            "dotenvx" not in result.stdout.lower()
            and "azure sdk not installed" not in result.stdout.lower()
        ):
            assert result.exit_code == 1
    finally:
        os.chdir(original_cwd)


def test_lock_missing_env_file(tmp_path) -> None:
    """Test lock handles missing env files gracefully."""
    # Create a minimal TOML config pointing to non-existent env file
    config_file = tmp_path / "envdrift.toml"
    config_file.write_text("""
[vault]
provider = "azure"

[vault.azure]
vault_url = "https://test-vault.vault.azure.net/"

[vault.sync]
default_vault_name = "test-vault"

[[vault.sync.mappings]]
secret_name = "test-secret"
folder_path = "."
environment = "production"
""")

    import os
    from pathlib import Path

    original_cwd = Path.cwd()
    try:
        os.chdir(tmp_path)
        result = runner.invoke(app, ["lock", "--check", "--force", "-c", str(config_file)])
        # Should handle missing file gracefully with warning, or fail because dotenvx not installed
        assert (
            "skipped" in result.stdout.lower()
            or "not found" in result.stdout.lower()
            or "dotenvx" in result.stdout.lower()  # dotenvx not installed in CI
            or "azure sdk not installed" in result.stdout.lower()
        )
    finally:
        os.chdir(original_cwd)
