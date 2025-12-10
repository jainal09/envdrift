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
