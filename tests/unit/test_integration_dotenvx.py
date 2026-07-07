"""Tests for DotenvxWrapper integration."""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

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
# Key-file and leading-dash filename foot-guns (#474)
# ---------------------------------------------------------------------------


def test_wrapper_encrypt_refuses_env_keys_store(tmp_path):
    """#474: the wrapper refuses to encrypt the dotenvx private-key store.

    The partial-encryption push/lock paths reach dotenvx through the wrapper
    directly (not the guarded backend), so the guard must live here too —
    otherwise ``encrypt -f .env.keys`` rewrites the private keys as ciphertext
    under a never-persisted keypair and permanently locks the project out.
    Fires pre-flight: no dotenvx binary is needed and the file stays untouched.
    """
    from envdrift.integrations.dotenvx import DotenvxFilenameError

    keys_file = tmp_path / ".env.keys"
    keys_content = "DOTENV_PRIVATE_KEY=" + "0" * 64 + "\n"
    keys_file.write_text(keys_content, encoding="utf-8")

    wrapper = DotenvxWrapper(auto_install=False)
    with pytest.raises(DotenvxFilenameError, match="private-key store"):
        wrapper.encrypt(keys_file)

    assert keys_file.read_text(encoding="utf-8") == keys_content


@pytest.mark.parametrize("name", [".env.KEYS", ".env.Keys", "service.ENV.KEYS"])
def test_wrapper_encrypt_refuses_env_keys_store_case_insensitively(tmp_path, name):
    """#474: the ``.keys`` name guard must be case-insensitive.

    On the default case-insensitive filesystems of macOS (APFS) and Windows
    (NTFS), ``.env.KEYS`` resolves to the real ``.env.keys``, so a
    case-sensitive ``endswith(".keys")`` let the key store be encrypted anyway
    — the exact irreversible lockout the guard exists to prevent.
    """
    from envdrift.integrations.dotenvx import DotenvxFilenameError

    keys_file = tmp_path / name
    keys_content = "DOTENV_PRIVATE_KEY=" + "0" * 64 + "\n"
    keys_file.write_text(keys_content, encoding="utf-8")

    wrapper = DotenvxWrapper(auto_install=False)
    with pytest.raises(DotenvxFilenameError, match="private-key store"):
        wrapper.encrypt(keys_file)

    assert keys_file.read_text(encoding="utf-8") == keys_content


@pytest.mark.parametrize(
    "key_line",
    [
        "DOTENV_PRIVATE_KEY=" + "0" * 64,  # bare form, as written for plain .env
        "DOTENV_PRIVATE_KEY_PRODUCTION=" + "0" * 64,  # environment-suffixed form
    ],
)
def test_wrapper_encrypt_refuses_renamed_key_store_by_content(tmp_path, key_line):
    """#474: a renamed key store is refused by its DOTENV_PRIVATE_KEY content.

    ``mv .env.keys prodkeys.env`` defeats every name-based guard, but
    encrypting the file still rewrites the private keys as ciphertext under a
    never-persisted keypair — the same project-wide lockout. The wrapper
    sniffs the content pre-flight and leaves the file untouched.
    """
    from envdrift.integrations.dotenvx import DotenvxFilenameError

    renamed = tmp_path / "prodkeys.env"
    content = f"# .env\n{key_line}\n"
    renamed.write_text(content, encoding="utf-8")

    wrapper = DotenvxWrapper(auto_install=False)
    with pytest.raises(DotenvxFilenameError, match="DOTENV_PRIVATE_KEY"):
        wrapper.encrypt(renamed)

    assert renamed.read_text(encoding="utf-8") == content


def test_wrapper_encrypt_allows_public_key_and_plain_assignments(tmp_path):
    """#474: the content sniff never false-positives on a legitimate target.

    Encrypt targets legitimately carry ``DOTENV_PUBLIC_KEY*`` lines (dotenvx
    writes them into the encrypted file) and arbitrary variables — including
    names that merely mention the private key, or an empty
    ``DOTENV_PRIVATE_KEY*=`` placeholder. Only a real non-empty
    ``DOTENV_PRIVATE_KEY*=<value>`` assignment marks the key store.
    """
    env_file = tmp_path / ".env"
    env_file.write_text(
        "DOTENV_PUBLIC_KEY=" + "02" + "a" * 64 + "\n"
        "API_KEY=abc123\n"
        "MENTIONS_DOTENV_PRIVATE_KEY_IN_NAME=ok\n"
        "DOTENV_PRIVATE_KEY_EMPTY_PLACEHOLDER=\n",
        encoding="utf-8",
    )

    wrapper = DotenvxWrapper(auto_install=False)
    with patch.object(wrapper, "_run") as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        wrapper.encrypt(env_file)

    # -fk is pinned to the sibling .env.keys so dotenvx v2 keeps the key store
    # next to the file rather than in the process cwd (#566).
    assert mock_run.call_args[0][0] == [
        "encrypt",
        "-f",
        str(env_file),
        "-fk",
        str(env_file.parent / ".env.keys"),
    ]


def test_dash_safe_path_prefixes_leading_dash():
    """#474: a leading-dash path is made unambiguous for dotenvx argv."""
    from envdrift.integrations.dotenvx import _dash_safe_path

    assert _dash_safe_path("-dash.env") == f".{os.sep}-dash.env"
    assert _dash_safe_path(Path("-dash.env")) == f".{os.sep}-dash.env"


def test_dash_safe_path_passes_through_normal_paths(tmp_path):
    """#474: normal relative and absolute paths are passed through unchanged."""
    from envdrift.integrations.dotenvx import _dash_safe_path

    assert _dash_safe_path(".env") == ".env"
    assert _dash_safe_path(tmp_path / ".env") == str(tmp_path / ".env")
    nested = str(Path("sub") / "-dash.env")
    assert _dash_safe_path(nested) == nested


def test_encrypt_passes_dash_proof_path_to_dotenvx(tmp_path, monkeypatch):
    """#474: ``encrypt -f -dash.env`` argv must be dash-proofed.

    dotenvx's commander CLI parses a bare ``-dash.env`` value as bundled flags,
    fabricating a different file (``-ash.env``) full of placeholder secrets and
    a junk ``.env.keys`` entry. The wrapper must hand dotenvx an unambiguous
    ``./``-prefixed path instead.
    """
    monkeypatch.chdir(tmp_path)
    dash_file = Path("-dash.env")
    dash_file.write_text("API_KEY=abc123\n", encoding="utf-8")

    wrapper = DotenvxWrapper(auto_install=False)
    with patch.object(wrapper, "_run") as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        wrapper.encrypt(dash_file)

    args = mock_run.call_args[0][0]
    # The sibling .env.keys (cwd here) is pinned via -fk (#566); it carries no
    # leading dash, so it is passed through unprefixed.
    assert args == ["encrypt", "-f", f".{os.sep}-dash.env", "-fk", ".env.keys"]


def test_decrypt_passes_dash_proof_path_to_dotenvx(tmp_path, monkeypatch):
    """#474: ``decrypt -f -dash.env`` argv must be dash-proofed too."""
    monkeypatch.chdir(tmp_path)
    dash_file = Path("-dash.env")
    dash_file.write_text("API_KEY=encrypted:abc\n", encoding="utf-8")

    wrapper = DotenvxWrapper(auto_install=False)
    with patch.object(wrapper, "_run") as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        wrapper.decrypt(dash_file, env_keys_file=Path("-dash.env.keys"))

    args = mock_run.call_args[0][0]
    assert args == [
        "decrypt",
        "-f",
        f".{os.sep}-dash.env",
        "-fk",
        f".{os.sep}-dash.env.keys",
    ]


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
