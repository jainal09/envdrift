"""Tests for DotenvxWrapper integration."""

from unittest.mock import MagicMock, patch

from envdrift.integrations.dotenvx import DotenvxWrapper, normalize_dotenvx_metadata


def test_dotenvx_get_success(tmp_path):
    """Test getting a value successfully."""
    wrapper = DotenvxWrapper(auto_install=False)
    env_file = tmp_path / ".env"

    with patch.object(wrapper, "_run") as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "value\n"
        mock_run.return_value = mock_result

        result = wrapper.get(env_file, "KEY")

        assert result == "value"
        mock_run.assert_called_once_with(["get", "-f", str(env_file), "KEY"], check=False)


def test_dotenvx_get_failure(tmp_path):
    """Test getting a value that doesn't exist."""
    wrapper = DotenvxWrapper(auto_install=False)
    env_file = tmp_path / ".env"

    with patch.object(wrapper, "_run") as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_run.return_value = mock_result

        result = wrapper.get(env_file, "KEY")

        assert result is None
        mock_run.assert_called_once_with(["get", "-f", str(env_file), "KEY"], check=False)


def test_dotenvx_set_success(tmp_path):
    """Test setting a value successfully."""
    wrapper = DotenvxWrapper(auto_install=False)
    env_file = tmp_path / ".env"

    with patch.object(wrapper, "_run") as mock_run:
        wrapper.set(env_file, "KEY", "value")

        mock_run.assert_called_once_with(["set", "-f", str(env_file), "KEY", "value"])


# ---------------------------------------------------------------------------
# normalize_dotenvx_metadata
# ---------------------------------------------------------------------------


def _keys_header() -> str:
    return (
        "#/------------------!DOTENV_PRIVATE_KEYS!-------------------/\n"
        "#/ private decryption keys. DO NOT commit to source control /\n"
        "#/----------------------------------------------------------/\n"
    )


def test_normalize_rewrites_env_file_public_key_and_comment(tmp_path):
    """The env file's public key name and dotenvx comment are canonicalized."""
    env_file = tmp_path / "postgresql.env"
    env_file.write_text(
        "#/-------------------[DOTENV_PUBLIC_KEY]--------------------/\n"
        "# postgresql.env\n"
        "DOTENV_PUBLIC_KEY_POSTGRESQLPRODUCTION=03abc\n"
        'POSTGRES_PASSWORD="encrypted:BASE64=="\n'
    )
    keys_file = tmp_path / ".env.keys"  # absent on purpose

    normalize_dotenvx_metadata(env_file, keys_file, "production")

    content = env_file.read_text()
    assert "DOTENV_PUBLIC_KEY_PRODUCTION=03abc" in content
    assert "POSTGRESQLPRODUCTION" not in content
    assert "# .env.production" in content
    assert "# postgresql.env" not in content


def test_normalize_returns_when_keys_file_missing(tmp_path):
    """A missing .env.keys is a no-op (env file already handled)."""
    env_file = tmp_path / "postgresql.env"
    env_file.write_text("DOTENV_PUBLIC_KEY_PRODUCTION=03abc\n")
    keys_file = tmp_path / ".env.keys"

    normalize_dotenvx_metadata(env_file, keys_file, "production")

    assert not keys_file.exists()


def test_normalize_renames_generated_private_key(tmp_path):
    """A filename-derived private key is renamed to the canonical environment."""
    env_file = tmp_path / "postgresql.env"
    env_file.write_text("DOTENV_PUBLIC_KEY_POSTGRESQLPRODUCTION=03abc\n")
    keys_file = tmp_path / ".env.keys"
    keys_file.write_text(
        _keys_header()
        + "\n# postgresql.env\n"
        + "DOTENV_PRIVATE_KEY_POSTGRESQLPRODUCTION=deadbeef\n"
    )

    normalize_dotenvx_metadata(env_file, keys_file, "production")

    content = keys_file.read_text()
    assert "DOTENV_PRIVATE_KEY_PRODUCTION=deadbeef" in content
    assert "POSTGRESQLPRODUCTION" not in content
    assert "# .env.production" in content
    assert "# postgresql.env" not in content
    assert content.endswith("\n")


def test_normalize_preserves_missing_trailing_newline_in_keys_file(tmp_path):
    """Regression for #320: a .env.keys with no trailing newline keeps none.

    The keys branch must mirror the env-file branch and only re-add a trailing
    newline when the original had one, rather than appending one unconditionally
    after a rewrite.
    """
    env_file = tmp_path / "postgresql.env"
    env_file.write_text("DOTENV_PUBLIC_KEY_POSTGRESQLPRODUCTION=03abc\n")
    keys_file = tmp_path / ".env.keys"
    # No trailing newline on the final private-key line.
    keys_file.write_text(
        _keys_header() + "\n# postgresql.env\n" + "DOTENV_PRIVATE_KEY_POSTGRESQLPRODUCTION=deadbeef"
    )

    normalize_dotenvx_metadata(env_file, keys_file, "production")

    content = keys_file.read_text()
    # The rewrite happened...
    assert "DOTENV_PRIVATE_KEY_PRODUCTION=deadbeef" in content
    assert "POSTGRESQLPRODUCTION" not in content
    # ...but the original no-trailing-newline shape is preserved.
    assert not content.endswith("\n")


def test_normalize_merges_into_existing_canonical_key(tmp_path):
    """When a canonical key already exists, the generated key+comment are merged in."""
    env_file = tmp_path / "postgresql.env"
    env_file.write_text("DOTENV_PUBLIC_KEY_PRODUCTION=03abc\n")
    keys_file = tmp_path / ".env.keys"
    keys_file.write_text(
        _keys_header()
        + "\n# .env.production\n"
        + "DOTENV_PRIVATE_KEY_PRODUCTION=stale\n"
        + "\n# postgresql.env\n"
        + "DOTENV_PRIVATE_KEY_POSTGRESQLPRODUCTION=fresh\n"
    )

    normalize_dotenvx_metadata(env_file, keys_file, "production")

    content = keys_file.read_text()
    # Canonical key takes the freshly generated value, duplicate is removed.
    assert "DOTENV_PRIVATE_KEY_PRODUCTION=fresh" in content
    assert content.count("DOTENV_PRIVATE_KEY_PRODUCTION=") == 1
    assert "POSTGRESQLPRODUCTION" not in content
    assert "# postgresql.env" not in content


def test_normalize_noop_when_no_custom_comment(tmp_path):
    """Without the dotenvx custom-filename comment, .env.keys is left untouched."""
    env_file = tmp_path / "postgresql.env"
    env_file.write_text("DOTENV_PUBLIC_KEY_PRODUCTION=03abc\n")
    keys_file = tmp_path / ".env.keys"
    original = _keys_header() + "\nDOTENV_PRIVATE_KEY_PRODUCTION=already\n"
    keys_file.write_text(original)

    normalize_dotenvx_metadata(env_file, keys_file, "production")

    assert keys_file.read_text() == original


def test_normalize_noop_when_comment_has_no_following_key(tmp_path):
    """A custom comment with no private key after it does not crash or change keys."""
    env_file = tmp_path / "postgresql.env"
    env_file.write_text("DOTENV_PUBLIC_KEY_PRODUCTION=03abc\n")
    keys_file = tmp_path / ".env.keys"
    original = _keys_header() + "\n# postgresql.env\n\n# another-section\n"
    keys_file.write_text(original)

    normalize_dotenvx_metadata(env_file, keys_file, "production")

    assert keys_file.read_text() == original
