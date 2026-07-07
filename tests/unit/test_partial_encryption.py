"""Tests for partial encryption functionality."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from envdrift.config import PartialEncryptionEnvironmentConfig
from envdrift.core.partial_encryption import (
    PartialEncryptionError,
    combine_files,
    encrypt_secret_file,
    file_has_assignment,
    has_plaintext_secret_value,
    is_file_encrypted,
    pull_secrets_only,
    push_partial_encryption,
    push_secrets_only,
)


class TestFileHasAssignment:
    """``file_has_assignment`` underpins the encrypt empty-guard (#443/#444)."""

    def test_true_for_identifier_keys(self, tmp_path: Path) -> None:
        f = tmp_path / ".env"
        f.write_text("FOO=bar\n", encoding="utf-8")
        assert file_has_assignment(f) is True

    def test_true_for_non_identifier_keys(self, tmp_path: Path) -> None:
        """Dash/digit keys the strict parser rejects are still real content."""
        f = tmp_path / ".env"
        f.write_text("X-API-KEY=secret\n1PASSWORD=hunter2\n", encoding="utf-8")
        assert file_has_assignment(f) is True

    def test_true_for_non_utf8_file_without_crashing(self, tmp_path: Path) -> None:
        """A non-UTF-8 byte must not raise UnicodeDecodeError (errors='replace')."""
        f = tmp_path / ".env"
        f.write_bytes(b"API_KEY=caf\xe9\n")  # 0xe9 = latin-1 'é', invalid UTF-8
        assert file_has_assignment(f) is True

    def test_false_for_empty_comment_only_and_blank(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.env"
        empty.write_text("", encoding="utf-8")
        comments = tmp_path / "comments.env"
        comments.write_text("# just a comment\n\n   \n", encoding="utf-8")
        keyless = tmp_path / "keyless.env"
        keyless.write_text("=novalue\n", encoding="utf-8")  # no key before '='
        assert file_has_assignment(empty) is False
        assert file_has_assignment(comments) is False
        assert file_has_assignment(keyless) is False


@pytest.fixture
def temp_env_files(tmp_path: Path):
    """Create temporary environment files for testing."""
    clear_file = tmp_path / ".env.test.clear"
    secret_file = tmp_path / ".env.test.secret"
    combined_file = tmp_path / ".env.test"

    # Create clear file
    clear_file.write_text(
        """# Application Settings
DEBUG=false
LOG_LEVEL=info
PORT=8080
"""
    )

    # Create secret file (not encrypted yet)
    secret_file.write_text(
        """# Database
DATABASE_URL=postgres://user:pass@localhost/db
JWT_SECRET=my-secret-key
"""
    )

    config = PartialEncryptionEnvironmentConfig(
        name="test",
        clear_file=str(clear_file),
        secret_file=str(secret_file),
        combined_file=str(combined_file),
    )

    return {
        "config": config,
        "clear_file": clear_file,
        "secret_file": secret_file,
        "combined_file": combined_file,
    }


def test_is_file_encrypted_plaintext(temp_env_files):
    """Test detection of plaintext files."""
    secret_file = temp_env_files["secret_file"]
    assert not is_file_encrypted(secret_file)


def test_is_file_encrypted_with_encrypted_prefix(tmp_path: Path):
    """Test detection of encrypted files."""
    encrypted_file = tmp_path / ".env.encrypted"
    encrypted_file.write_text('DATABASE_URL="encrypted:BDaLMxznvYWcHP..."')

    assert is_file_encrypted(encrypted_file)


def test_is_file_encrypted_with_sops_value(tmp_path: Path):
    """A SOPS-encrypted dotenv value (quoted ENC[AES256_GCM,...]) => True (#352)."""
    sops_file = tmp_path / ".env.sops"
    # Build the ciphertext-shaped value by concatenation (no real secret).
    sops_file.write_text(
        'DATABASE_URL="ENC[AES256_GCM,data:' + "ab" * 8 + ',type:str]"\n', encoding="utf-8"
    )

    assert is_file_encrypted(sops_file)


def test_is_file_encrypted_decrypted_file_with_residual_public_key(tmp_path: Path):
    """Decrypted dotenvx file (residual DOTENV_PUBLIC_KEY, plaintext values) => False.

    Forward-guard, NOT a #352 regression. The old substring check
    (``"encrypted:" in content or "DOTENV_VAULT" in content``) already returned
    False here — a decrypted dotenvx file contains neither substring — so this
    case passed before the fix too. It is kept to lock in that the new
    value-scan still treats a leftover public-key header as plaintext, guarding
    against a future regression where the header alone is mistaken for
    ciphertext (which would make encrypt_secret_file skip re-encryption).
    """
    decrypted = tmp_path / ".env.secret"
    decrypted.write_text(
        "#/-------------------[DOTENV_PUBLIC_KEY]--------------------/\n"
        "#/            public-key encryption for .env files          /\n"
        'DOTENV_PUBLIC_KEY_TEST="024f56daf45b' + "0" * 8 + 'fe"\n'
        "API_KEY=" + "sk_live_" + "0123456789abcdef" * 2 + "\n",
        encoding="utf-8",
    )

    assert is_file_encrypted(decrypted) is False


def test_is_file_encrypted_plaintext_value_contains_encrypted_word(tmp_path: Path):
    """Plaintext value literally containing 'encrypted:' => NOT encrypted (the real #352 bug).

    This is the load-bearing #352 regression test. The OLD substring check
    (``"encrypted:" in content``) false-positived on a plaintext value like
    ``NOTE=... stored encrypted: see docs`` and returned True, so
    encrypt_secret_file early-returned and the genuinely-secret API_KEY below it
    was committed in cleartext. The value-scan keys off a VALUE starting with
    the ciphertext prefix, so the substring buried inside a note no longer
    counts. Fails on pre-fix code; passes on the fix.
    """
    note_file = tmp_path / ".env.secret"
    note_file.write_text(
        "NOTE=the password is stored encrypted: see the vault docs\n"
        "API_KEY=" + "sk_live_" + "0123456789abcdef" * 2 + "\n",
        encoding="utf-8",
    )

    assert is_file_encrypted(note_file) is False


# ---------------------------------------------------------------------------
# #413 (CRITICAL): mixed-state .secret file must NOT be treated as already
# encrypted. is_file_encrypted() returns True on the first ciphertext value, so
# a file holding one ciphertext value AND one freshly-added plaintext value
# looks "done" — encrypt_secret_file / push_secrets_only would early-return and
# the new plaintext secret would ship verbatim into the committed files.
# has_plaintext_secret_value() distinguishes the two so re-encryption fires.
# ---------------------------------------------------------------------------


def test_encrypt_secret_file_reencrypts_mixed_state(tmp_path: Path):
    """encrypt_secret_file MUST re-run dotenvx.encrypt on a mixed-state file (#413).

    Pre-fix: is_file_encrypted() returned True on the first ciphertext value, so
    encrypt_secret_file early-returned and never encrypted the newly-added
    plaintext value -> it leaked. This asserts dotenvx.encrypt IS invoked.
    """
    secret_file = tmp_path / ".env.secret"
    secret_file.write_text('API_KEY="encrypted:abc..."\nNEW_LEAKED_SECRET=plaintext_leak_value\n')
    config = PartialEncryptionEnvironmentConfig(
        name="test", clear_file="", secret_file=str(secret_file), combined_file=""
    )
    with patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_cls:
        # Honest mock (#471): a successful encrypt actually encrypts the file,
        # or the new post-encrypt read-back rightly fails the push.
        mock_cls.return_value.encrypt.side_effect = _honest_encrypt_in_place
        encrypt_secret_file(config)
    # The early-return is gone: the wrapper must be asked to encrypt the file.
    mock_cls.return_value.encrypt.assert_called_once_with(secret_file)
    assert "plaintext_leak_value" not in secret_file.read_text(encoding="utf-8")


def test_push_secrets_only_reencrypts_mixed_state(secrets_only_config, secrets_dir):
    """push_secrets_only re-encrypts a MIXED file rather than skipping it (#413)."""
    # One file fully encrypted, the other mixed (ciphertext + new plaintext).
    files = sorted(secrets_dir.iterdir())
    files[0].write_text('KEY="encrypted:abc123"\n')  # fully encrypted -> skipped
    files[1].write_text(
        'KEY="encrypted:abc123"\nNEW_LEAKED_SECRET=plaintext_leak_value\n'  # mixed -> re-encrypt
    )

    with patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_dotenvx_cls:
        instance = mock_dotenvx_cls.return_value
        # Honest mock (#471): the simulated encrypt must leave no plaintext.
        instance.encrypt.side_effect = _honest_encrypt_in_place
        result = push_secrets_only(secrets_only_config)

    assert result["encrypted"] == 1  # the mixed file
    assert result["already_encrypted"] == 1  # the fully-encrypted file
    encrypted_paths = [call.args[0] for call in instance.encrypt.call_args_list]
    assert encrypted_paths == [files[1]]


def test_combine_files_preserves_user_hash_slash_comment(temp_env_files):
    """A user comment beginning with '#/' must survive into the combined file (#413).

    The old filter dropped EVERY line whose stripped form started with '#/',
    silently removing legitimate user comments. combine_files now strips only the
    dotenvx 4-line public-key header block, so a standalone '#/ note' is kept.
    """
    config = temp_env_files["config"]
    secret_file = temp_env_files["secret_file"]
    combined_file = temp_env_files["combined_file"]

    secret_file.write_text('#/ my own note about this key\nDB="encrypted:abc..."\n')

    combine_files(config)

    content = combined_file.read_text()
    marker = f"# From {config.secret_file} (encrypted)"
    secret_section = content.split(marker, 1)[1]
    assert "#/ my own note about this key" in secret_section, secret_section
    assert 'DB="encrypted:abc..."' in secret_section


def test_combine_files(temp_env_files):
    """Test combining clear and secret files."""
    config = temp_env_files["config"]
    combined_file = temp_env_files["combined_file"]

    # Combine files
    stats = combine_files(config)

    # Verify combined file was created
    assert combined_file.exists()

    # Verify stats
    assert stats["clear_lines"] == 4  # Including comments
    assert stats["secret_vars"] == 2  # DATABASE_URL and JWT_SECRET

    # Verify content
    content = combined_file.read_text()

    # Check warning header
    assert "WARNING: AUTO-GENERATED FILE" in content
    assert "DO NOT EDIT THIS FILE DIRECTLY" in content

    # Check clear section
    assert ".env.test.clear" in content
    assert "DEBUG=false" in content
    assert "PORT=8080" in content

    # Check secret section
    assert ".env.test.secret" in content
    assert "DATABASE_URL" in content
    assert "JWT_SECRET" in content


def test_combine_files_with_encrypted_secret(temp_env_files):
    """Test combining with encrypted secret file."""
    config = temp_env_files["config"]
    secret_file = temp_env_files["secret_file"]
    combined_file = temp_env_files["combined_file"]

    # Simulate encrypted secret file
    secret_file.write_text(
        """DATABASE_URL="encrypted:BDaLMxznvYWcHP..."
JWT_SECRET="encrypted:BD9XKwmZvYWcHP..."
"""
    )

    # Combine files
    combine_files(config)

    # Verify content includes encrypted values
    content = combined_file.read_text()
    assert "encrypted:BDaLMxznvYWcHP..." in content
    assert "encrypted:BD9XKwmZvYWcHP..." in content


def test_combine_files_missing_clear(temp_env_files):
    """Test combining when clear file doesn't exist."""
    config = temp_env_files["config"]
    clear_file = temp_env_files["clear_file"]
    combined_file = temp_env_files["combined_file"]

    # Remove clear file
    clear_file.unlink()

    # Should still work (just secret file)
    stats = combine_files(config)

    assert combined_file.exists()
    assert stats["clear_lines"] == 0
    assert stats["secret_vars"] == 2


def test_combine_files_missing_secret(temp_env_files):
    """Test combining when secret file doesn't exist."""
    config = temp_env_files["config"]
    secret_file = temp_env_files["secret_file"]
    combined_file = temp_env_files["combined_file"]

    # Remove secret file
    secret_file.unlink()

    # Should still work (just clear file)
    stats = combine_files(config)

    assert combined_file.exists()
    assert stats["clear_lines"] == 4
    assert stats["secret_vars"] == 0


def test_combine_files_filters_dotenvx_headers(temp_env_files):
    """The full dotenvx public-key header block is stripped from the secret file.

    Regression for #316: the real dotenvx header is a 4-line block whose two
    inner lines start with "#/ " (not "#/---"). The old filter only matched the
    "#/---" border lines, leaking the inner public-key comment lines into the
    combined output. All four lines must now be stripped.
    """
    config = temp_env_files["config"]
    secret_file = temp_env_files["secret_file"]
    combined_file = temp_env_files["combined_file"]

    # The exact 4-line public-key header dotenvx writes to encrypted files.
    secret_file.write_text(
        "#/-------------------[DOTENV_PUBLIC_KEY]--------------------/\n"
        "#/            public-key encryption for .env files          /\n"
        "#/       [how it works](https://dotenvx.com/encryption)     /\n"
        "#/----------------------------------------------------------/\n"
        'DOTENV_PUBLIC_KEY_TEST="03abc123..."\n'
        "\n"
        "# .env.test\n"
        'DATABASE_URL="encrypted:BDaLMxznvYWcHP..."\n'
    )

    # Combine files
    combine_files(config)

    # Verify the entire header block is filtered, including the two inner
    # "#/ ..." comment lines that previously leaked through.
    content = combined_file.read_text()
    assert "[DOTENV_PUBLIC_KEY]" not in content
    assert "public-key encryption for .env files" not in content
    assert "https://dotenvx.com/encryption" not in content

    # No leftover dotenvx header lines in the secret section. (The auto-generated
    # warning box at the top also uses "#/" lines, so only inspect everything
    # after the secret-section marker.)
    marker = f"# From {config.secret_file} (encrypted)"
    secret_section = content.split(marker, 1)[1]
    assert not any(line.lstrip().startswith("#/") for line in secret_section.splitlines())

    # But the public key and encrypted value should still be present.
    assert "DOTENV_PUBLIC_KEY_TEST" in content
    assert "DATABASE_URL" in content
    assert "encrypted:BDaLMxznvYWcHP..." in content


def test_combine_files_excludes_dotenvx_public_key_from_count(temp_env_files):
    """DOTENV_PUBLIC_KEY is not a secret and must not inflate secret_vars."""
    config = temp_env_files["config"]
    secret_file = temp_env_files["secret_file"]
    combined_file = temp_env_files["combined_file"]

    # A real dotenvx-encrypted file: one public-key line + two encrypted secrets.
    secret_file.write_text(
        'DOTENV_PUBLIC_KEY_TEST="03abc123..."\n'
        'DATABASE_URL="encrypted:BDaLMxznvYWcHP..."\n'
        'JWT_SECRET="encrypted:BD9XKwmZvYWcHP..."\n'
    )

    stats = combine_files(config)

    # Only the two real secrets count — the public key is excluded.
    assert stats["secret_vars"] == 2
    # The public key still passes through into the combined file (it is public).
    assert "DOTENV_PUBLIC_KEY_TEST" in combined_file.read_text()


def test_combine_files_count_ignores_comments(temp_env_files):
    """Commented-out secret lines must not be counted as secret vars."""
    config = temp_env_files["config"]
    secret_file = temp_env_files["secret_file"]

    secret_file.write_text('# DISABLED_TOKEN=old-value\nAPI_KEY="encrypted:abc..."\n')

    stats = combine_files(config)

    assert stats["secret_vars"] == 1


def test_combine_files_check_does_not_write(temp_env_files):
    """combine_files(write=False) is a dry run and never touches disk."""
    config = temp_env_files["config"]
    combined_file = temp_env_files["combined_file"]

    assert not combined_file.exists()

    stats = combine_files(config, write=False)

    # Nothing written; combined file would differ from (missing) on-disk content.
    assert not combined_file.exists()
    assert stats["in_sync"] is False


def test_combine_files_check_reports_in_sync(temp_env_files):
    """After a real combine, a check run reports the combined file is in sync."""
    config = temp_env_files["config"]

    combine_files(config)  # real write
    stats = combine_files(config, write=False)

    assert stats["in_sync"] is True


def test_combine_files_check_detects_manual_edit(temp_env_files):
    """A user edit to the generated combined file is reported as out of sync."""
    config = temp_env_files["config"]
    combined_file = temp_env_files["combined_file"]

    combine_files(config)  # real write
    combined_file.write_text(combined_file.read_text() + "\nINJECTED=oops\n")

    stats = combine_files(config, write=False)

    assert stats["in_sync"] is False
    # Dry run must not have reverted the manual edit.
    assert "INJECTED=oops" in combined_file.read_text()


def test_push_partial_check_does_not_encrypt(tmp_path: Path):
    """push_partial_encryption(check=True) must not mutate the secret file."""
    clear_file = tmp_path / ".env.test.clear"
    secret_file = tmp_path / ".env.test.secret"
    combined_file = tmp_path / ".env.test"
    clear_file.write_text("DEBUG=false\n")
    secret_file.write_text("API_KEY=plaintext-value\n")

    config = PartialEncryptionEnvironmentConfig(
        name="test",
        clear_file=str(clear_file),
        secret_file=str(secret_file),
        combined_file=str(combined_file),
    )

    stats = push_partial_encryption(config, check=True)

    # Secret file untouched (still plaintext), no combined file written.
    assert secret_file.read_text() == "API_KEY=plaintext-value\n"
    assert not combined_file.exists()
    assert stats["in_sync"] is False


def test_push_partial_check_out_of_sync_when_secret_plaintext(tmp_path: Path):
    """--check must report out-of-sync if .secret is plaintext, even if combined matches.

    Regression: a plaintext secret + an up-to-date combined file previously
    returned in_sync=True, hiding the fact that a real push would encrypt the
    secret. --check must require the secret file to be encrypted too.
    """
    clear_file = tmp_path / ".env.test.clear"
    secret_file = tmp_path / ".env.test.secret"
    combined_file = tmp_path / ".env.test"
    clear_file.write_text("DEBUG=false\n")
    secret_file.write_text("API_KEY=plaintext-value\n")

    config = PartialEncryptionEnvironmentConfig(
        name="test",
        clear_file=str(clear_file),
        secret_file=str(secret_file),
        combined_file=str(combined_file),
    )

    # Build the combined file straight from the plaintext secret, so the combined
    # text is byte-for-byte in sync — yet the secret on disk is still plaintext.
    combine_files(config)
    assert not is_file_encrypted(secret_file)

    stats = push_partial_encryption(config, check=True)

    # Combined text matches, but the plaintext secret forces out-of-sync.
    assert stats["in_sync"] is False


def test_push_partial_check_out_of_sync_when_secret_mixed_state(tmp_path: Path):
    """--check must report out-of-sync for a MIXED-STATE secret file.

    Regression for the greptile P1 on #416: a mixed file (some values already
    ``encrypted:``, one freshly-added plaintext) trips ``is_file_encrypted`` on
    the first ciphertext value, so the dry-run path used to leave ``in_sync``
    True even though a real push would re-encrypt the new plaintext secret. The
    check path now uses the same fully-encrypted predicate as the push path.
    """
    clear_file = tmp_path / ".env.test.clear"
    secret_file = tmp_path / ".env.test.secret"
    combined_file = tmp_path / ".env.test"
    clear_file.write_text("DEBUG=false\n")
    # Mixed state: one already-encrypted value, one freshly-added plaintext value.
    secret_file.write_text('OLD_KEY="encrypted:abc..."\nNEW_LEAK=plaintext-value\n')

    config = PartialEncryptionEnvironmentConfig(
        name="test",
        clear_file=str(clear_file),
        secret_file=str(secret_file),
        combined_file=str(combined_file),
    )

    # Build the combined file straight from the mixed secret so the combined text
    # is byte-for-byte in sync — yet a plaintext secret still leaks on disk.
    combine_files(config)
    assert is_file_encrypted(secret_file)  # the ciphertext value trips this
    assert has_plaintext_secret_value(secret_file)  # but a plaintext leak remains

    stats = push_partial_encryption(config, check=True)

    # is_file_encrypted alone would say "in sync"; the plaintext leak forces False.
    assert stats["in_sync"] is False


def test_warning_header_format(temp_env_files):
    """Test that warning header has correct format."""
    config = temp_env_files["config"]
    combined_file = temp_env_files["combined_file"]

    combine_files(config)

    content = combined_file.read_text()
    lines = content.splitlines()

    # First line is an all-dashes border box.
    assert lines[0].startswith("#/") and lines[0].endswith("/")
    assert set(lines[0][2:-1]) == {"-"}

    # Check it mentions both source files
    assert any(".env.test.clear" in line for line in lines[:15])
    assert any(".env.test.secret" in line for line in lines[:15])

    # Check commands mentioned
    assert any("envdrift pull-partial" in line for line in lines[:15])
    assert any("envdrift push" in line for line in lines[:15])


def test_warning_header_alignment_with_long_paths(tmp_path: Path):
    """The box border stays aligned even when source paths are very long."""
    long_clear = tmp_path / ("nested/" * 6) / ".env.production.clear"
    long_secret = tmp_path / ("nested/" * 6) / ".env.production.secret"
    long_clear.parent.mkdir(parents=True, exist_ok=True)
    long_clear.write_text("DEBUG=false\n")
    long_secret.write_text("TOKEN=abc\n")

    config = PartialEncryptionEnvironmentConfig(
        name="production",
        clear_file=str(long_clear),
        secret_file=str(long_secret),
        combined_file=str(tmp_path / ".env.production"),
    )

    combine_files(config)
    header_lines = [
        line
        for line in (tmp_path / ".env.production").read_text().splitlines()
        if line.startswith("#/")
    ]

    # Every box line (borders + content) must be exactly the same width, so the
    # right-hand "/" border lines up no matter how long the paths are.
    widths = {len(line) for line in header_lines}
    assert len(widths) == 1, f"warning box lines are not aligned: {widths}"
    # The long path must be present and fully contained inside the box.
    assert any(str(long_clear) in line for line in header_lines)


# ---------------------------------------------------------------------------
# secrets_only mode
# ---------------------------------------------------------------------------


@pytest.fixture
def secrets_dir(tmp_path: Path):
    """Create a temporary secrets directory with two plaintext env files."""
    sdir = tmp_path / "secrets" / "production"
    sdir.mkdir(parents=True)
    (sdir / ".env.api").write_text("STRIPE_KEY=sk_fake\nSENDGRID_KEY=SG.fake\n")
    (sdir / ".env.db").write_text("DATABASE_URL=postgresql://fake\n")
    return sdir


@pytest.fixture
def secrets_only_config(secrets_dir: Path):
    return PartialEncryptionEnvironmentConfig(
        name="production",
        secrets_only=True,
        secrets_dir=str(secrets_dir),
        pattern=".env*",
    )


def test_push_secrets_only_encrypts_plaintext_files(secrets_only_config, secrets_dir):
    """push_secrets_only encrypts every plaintext file in secrets_dir."""
    with patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_dotenvx_cls:
        instance = mock_dotenvx_cls.return_value
        # Honest mock (#471): the simulated encrypt must leave no plaintext.
        instance.encrypt.side_effect = _honest_encrypt_in_place
        result = push_secrets_only(secrets_only_config)

    assert result["encrypted"] == 2
    assert result["already_encrypted"] == 0
    assert instance.encrypt.call_count == 2


def test_push_secrets_only_skips_already_encrypted(secrets_only_config, secrets_dir):
    """push_secrets_only skips files that are FULLY encrypted (every value ciphertext)."""
    # Overwrite with all-ciphertext values so the files are fully encrypted (no
    # leftover plaintext secret value). Appending to the plaintext fixture would
    # instead leave a MIXED file, which must be re-encrypted (see the dedicated
    # mixed-state regression test below).
    for f in secrets_dir.iterdir():
        f.write_text('KEY="encrypted:abc123"\n')

    with patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_dotenvx_cls:
        instance = mock_dotenvx_cls.return_value
        result = push_secrets_only(secrets_only_config)

    assert result["encrypted"] == 0
    assert result["already_encrypted"] == 2
    instance.encrypt.assert_not_called()


def test_push_secrets_only_check_dry_run_counts_plaintext_without_encrypting(
    secrets_only_config, secrets_dir
):
    """check=True is a dry run: plaintext files are counted as 'would-encrypt', untouched."""
    before = {f: f.read_bytes() for f in secrets_dir.iterdir()}

    with patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_dotenvx_cls:
        instance = mock_dotenvx_cls.return_value
        result = push_secrets_only(secrets_only_config, check=True)

    assert result["encrypted"] == 2  # both plaintext files would be encrypted
    assert result["already_encrypted"] == 0
    assert result["in_sync"] is False
    instance.encrypt.assert_not_called()  # dry run mutates nothing
    for f, content in before.items():
        assert f.read_bytes() == content


def test_push_secrets_only_check_dry_run_skips_unskip_when_fully_encrypted(
    secrets_only_config, secrets_dir
):
    """check=True on a fully-encrypted file reports in_sync and never touches git."""
    for f in secrets_dir.iterdir():
        f.write_text('KEY="encrypted:abc123"\n')

    with (
        patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_dotenvx_cls,
        patch("envdrift.core.partial_encryption._git_unskip_worktree") as mock_unskip,
    ):
        instance = mock_dotenvx_cls.return_value
        result = push_secrets_only(secrets_only_config, check=True)

    assert result["encrypted"] == 0
    assert result["already_encrypted"] == 2
    assert result["in_sync"] is True
    instance.encrypt.assert_not_called()
    # Dry run must not mutate git skip-worktree state for already-encrypted files.
    mock_unskip.assert_not_called()


def test_push_secrets_only_raises_when_dir_missing(tmp_path: Path):
    """push_secrets_only raises PartialEncryptionError when secrets_dir is absent."""
    config = PartialEncryptionEnvironmentConfig(
        name="prod",
        secrets_only=True,
        secrets_dir=str(tmp_path / "nonexistent"),
        pattern=".env*",
    )
    with pytest.raises(PartialEncryptionError, match="secrets_dir not found"):
        push_secrets_only(config)


# ---------------------------------------------------------------------------
# Secret-lockout guard reaches the partial-encryption paths too (#467)
#
# #457 added the [A-Za-z0-9._-] filename guard to DotenvxEncryptionBackend, but
# the partial-encryption push/lock paths (encrypt_secret_file /
# push_secrets_only) reach dotenvx through DotenvxWrapper directly, NOT the
# guarded backend. A space- or non-ASCII-named secret file therefore still hit
# the exact permanent lockout #457 set out to fix: dotenvx derives an invalid
# DOTENV_PRIVATE_KEY_<SLUG> from the filename, encrypts the value (exit 0), and
# the file is then undecryptable while the plaintext is destroyed.
#
# These drive the REAL wrapper guard (no DotenvxWrapper mock — the guard IS the
# behavior under test) and assert refusal with the plaintext preserved. The
# guard fires before dotenvx is invoked, so the tests need no dotenvx binary.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("entry_point", "filename"),
    [
        ("push_secrets_only", "my secret.env"),  # space -> invalid dotenvx key slug
        ("encrypt_secret_file", "café.env.secret"),  # non-ASCII -> invalid key slug
    ],
)
def test_partial_encryption_refuses_unsafe_filename_preserves_plaintext(
    tmp_path: Path, entry_point: str, filename: str
):
    """#467: a space/non-ASCII secret filename is refused, not silently locked out.

    Both partial-encryption entry points (``push_secrets_only`` for secrets-only,
    ``encrypt_secret_file`` for combine mode) reach dotenvx through
    ``DotenvxWrapper``, NOT the guarded backend. dotenvx derives
    ``DOTENV_PRIVATE_KEY_<SLUG>`` from the filename; a space or non-ASCII char
    yields an invalid key name, so the value encrypts (exit 0) but is then
    permanently undecryptable and the plaintext is destroyed — silent secret
    lockout. The wrapper guard must refuse pre-flight, leaving the file
    byte-for-byte intact. No ``DotenvxWrapper`` mock: the real guard IS the
    behavior under test, and it fires before the binary is invoked, so the test
    needs no dotenvx binary. Both entry points fail RED on ``main`` (DID NOT
    RAISE; the file is silently encrypted and the plaintext destroyed).
    """
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    target = secrets_dir / filename
    target.write_text("PASSWORD=keepme123\n", encoding="utf-8")
    before = target.read_bytes()

    if entry_point == "push_secrets_only":
        config = PartialEncryptionEnvironmentConfig(
            name="prod",
            secrets_only=True,
            secrets_dir=str(secrets_dir),
            pattern="*.env*",
        )
        with pytest.raises(PartialEncryptionError, match="Failed to encrypt"):
            push_secrets_only(config)
    else:
        config = PartialEncryptionEnvironmentConfig(
            name="prod",
            clear_file="",
            secret_file=str(target),
            combined_file="",
        )
        with pytest.raises(PartialEncryptionError, match="Failed to encrypt"):
            encrypt_secret_file(config)

    # The original plaintext survives byte-for-byte — never encrypted into an
    # unrecoverable file (pre-fix this destroyed it and raised nothing).
    assert target.read_bytes() == before
    assert b"encrypted:" not in target.read_bytes()


def test_pull_secrets_only_decrypts_encrypted_files(secrets_only_config, secrets_dir):
    """pull_secrets_only decrypts every encrypted file in secrets_dir."""
    for f in secrets_dir.iterdir():
        f.write_text(f.read_text() + 'KEY="encrypted:abc123"\n')

    with patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_dotenvx_cls:
        instance = mock_dotenvx_cls.return_value
        result = pull_secrets_only(secrets_only_config)

    assert result["decrypted"] == 2
    assert result["already_decrypted"] == 0
    assert instance.decrypt.call_count == 2


def test_pull_secrets_only_skips_plaintext_files(secrets_only_config):
    """pull_secrets_only skips files that are already plaintext."""
    with patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_dotenvx_cls:
        instance = mock_dotenvx_cls.return_value
        result = pull_secrets_only(secrets_only_config)

    assert result["decrypted"] == 0
    assert result["already_decrypted"] == 2
    instance.decrypt.assert_not_called()


def test_pull_secrets_only_raises_when_dir_missing(tmp_path: Path):
    """pull_secrets_only raises PartialEncryptionError when secrets_dir is absent."""
    config = PartialEncryptionEnvironmentConfig(
        name="prod",
        secrets_only=True,
        secrets_dir=str(tmp_path / "nonexistent"),
        pattern=".env*",
    )
    with pytest.raises(PartialEncryptionError, match="secrets_dir not found"):
        pull_secrets_only(config)


def test_pull_secrets_only_raises_on_decrypt_failure(secrets_only_config, secrets_dir):
    """pull_secrets_only wraps DotenvxError as PartialEncryptionError."""
    from envdrift.integrations.dotenvx import DotenvxError

    for f in secrets_dir.iterdir():
        f.write_text(f.read_text() + 'KEY="encrypted:abc123"\n')

    with patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_dotenvx_cls:
        mock_dotenvx_cls.return_value.decrypt.side_effect = DotenvxError("boom")
        with pytest.raises(PartialEncryptionError, match="Failed to decrypt"):
            pull_secrets_only(secrets_only_config)


def test_push_secrets_only_raises_when_dir_empty():
    """Empty secrets_dir must error — never fall back to the working directory."""
    config = PartialEncryptionEnvironmentConfig(
        name="prod",
        secrets_only=True,
        secrets_dir="",
        pattern=".env*",
    )
    with pytest.raises(PartialEncryptionError, match="secrets_dir must be set"):
        push_secrets_only(config)


def test_pull_secrets_only_raises_when_dir_empty():
    """Empty secrets_dir must error — never fall back to the working directory."""
    config = PartialEncryptionEnvironmentConfig(
        name="prod",
        secrets_only=True,
        secrets_dir="   ",
        pattern=".env*",
    )
    with pytest.raises(PartialEncryptionError, match="secrets_dir must be set"):
        pull_secrets_only(config)


def test_push_secrets_only_raises_when_path_is_file(tmp_path: Path):
    """secrets_dir that points at a file (not a directory) must error."""
    not_a_dir = tmp_path / "not-a-dir"
    not_a_dir.write_text("oops")
    config = PartialEncryptionEnvironmentConfig(
        name="prod",
        secrets_only=True,
        secrets_dir=str(not_a_dir),
        pattern=".env*",
    )
    with pytest.raises(PartialEncryptionError, match="not a directory"):
        push_secrets_only(config)


def test_secrets_only_respects_pattern(tmp_path: Path):
    """push_secrets_only only processes files matching the configured glob pattern."""
    sdir = tmp_path / "secrets"
    sdir.mkdir()
    (sdir / ".env.api").write_text("KEY=value\n")
    (sdir / "config.yaml").write_text("key: value\n")  # should not be touched
    (sdir / ".env.db").write_text("DB=postgres\n")

    config = PartialEncryptionEnvironmentConfig(
        name="prod",
        secrets_only=True,
        secrets_dir=str(sdir),
        pattern=".env*",
    )

    with patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_dotenvx_cls:
        instance = mock_dotenvx_cls.return_value
        # Honest mock (#471): the simulated encrypt must leave no plaintext.
        instance.encrypt.side_effect = _honest_encrypt_in_place
        result = push_secrets_only(config)

    # Only .env.api and .env.db should be processed, not config.yaml
    assert result["encrypted"] == 2
    assert instance.encrypt.call_count == 2


# ---------------------------------------------------------------------------
# Coverage for combine-mode helpers, error paths, and helper hoisting
# ---------------------------------------------------------------------------


def test_push_secrets_only_reuses_single_wrapper(secrets_only_config, secrets_dir):
    """DotenvxWrapper is instantiated once per call, not per file in the loop."""
    from envdrift.core.partial_encryption import push_secrets_only as _push

    with patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_cls:
        # Honest mock (#471): the simulated encrypt must leave no plaintext.
        mock_cls.return_value.encrypt.side_effect = _honest_encrypt_in_place
        _push(secrets_only_config)
    assert mock_cls.call_count == 1


def test_is_file_encrypted_returns_false_for_missing_file(tmp_path: Path):
    """is_file_encrypted returns False for paths that don't exist."""
    assert is_file_encrypted(tmp_path / "does-not-exist") is False


def test_encrypt_secret_file_skips_when_missing(tmp_path: Path):
    """encrypt_secret_file returns silently when secret_file does not exist."""
    from envdrift.core.partial_encryption import encrypt_secret_file

    config = PartialEncryptionEnvironmentConfig(
        name="test",
        clear_file=str(tmp_path / ".env.clear"),
        secret_file=str(tmp_path / ".env.missing.secret"),
        combined_file=str(tmp_path / ".env"),
    )
    with patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_cls:
        encrypt_secret_file(config)
    mock_cls.return_value.encrypt.assert_not_called()


def test_encrypt_secret_file_skips_already_encrypted(tmp_path: Path):
    """encrypt_secret_file skips files already marked encrypted."""
    from envdrift.core.partial_encryption import encrypt_secret_file

    secret_file = tmp_path / ".env.secret"
    secret_file.write_text('KEY="encrypted:abc"\n')
    config = PartialEncryptionEnvironmentConfig(
        name="test", clear_file="", secret_file=str(secret_file), combined_file=""
    )
    with patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_cls:
        encrypt_secret_file(config)
    mock_cls.return_value.encrypt.assert_not_called()


def test_encrypt_secret_file_wraps_dotenvx_error(tmp_path: Path):
    """encrypt_secret_file wraps DotenvxError as PartialEncryptionError."""
    from envdrift.core.partial_encryption import encrypt_secret_file
    from envdrift.integrations.dotenvx import DotenvxError

    secret_file = tmp_path / ".env.secret"
    secret_file.write_text("DB=plain\n")
    config = PartialEncryptionEnvironmentConfig(
        name="test", clear_file="", secret_file=str(secret_file), combined_file=""
    )
    with patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_cls:
        mock_cls.return_value.encrypt.side_effect = DotenvxError("boom")
        with pytest.raises(PartialEncryptionError, match="Failed to encrypt"):
            encrypt_secret_file(config)


def test_decrypt_secret_file_raises_when_missing(tmp_path: Path):
    """decrypt_secret_file raises when secret_file does not exist."""
    from envdrift.core.partial_encryption import decrypt_secret_file

    config = PartialEncryptionEnvironmentConfig(
        name="test",
        clear_file="",
        secret_file=str(tmp_path / ".env.missing.secret"),
        combined_file="",
    )
    with pytest.raises(PartialEncryptionError, match="Secret file not found"):
        decrypt_secret_file(config)


def test_decrypt_secret_file_skips_already_decrypted(tmp_path: Path):
    """decrypt_secret_file returns silently when file is plaintext."""
    from envdrift.core.partial_encryption import decrypt_secret_file

    secret_file = tmp_path / ".env.secret"
    secret_file.write_text("DB=plain\n")
    config = PartialEncryptionEnvironmentConfig(
        name="test", clear_file="", secret_file=str(secret_file), combined_file=""
    )
    with patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_cls:
        decrypt_secret_file(config)
    mock_cls.return_value.decrypt.assert_not_called()


def test_decrypt_secret_file_wraps_dotenvx_error(tmp_path: Path):
    """decrypt_secret_file wraps DotenvxError as PartialEncryptionError."""
    from envdrift.core.partial_encryption import decrypt_secret_file
    from envdrift.integrations.dotenvx import DotenvxError

    secret_file = tmp_path / ".env.secret"
    secret_file.write_text('KEY="encrypted:abc"\n')
    config = PartialEncryptionEnvironmentConfig(
        name="test", clear_file="", secret_file=str(secret_file), combined_file=""
    )
    with patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_cls:
        mock_cls.return_value.decrypt.side_effect = DotenvxError("boom")
        with pytest.raises(PartialEncryptionError, match="Failed to decrypt"):
            decrypt_secret_file(config)


def test_push_partial_encryption_encrypts_and_combines(tmp_path: Path):
    """push_partial_encryption encrypts the secret file and writes the combined output."""
    from envdrift.core.partial_encryption import push_partial_encryption

    clear_file = tmp_path / ".env.clear"
    secret_file = tmp_path / ".env.secret"
    combined_file = tmp_path / ".env"
    clear_file.write_text("DEBUG=true\n")
    secret_file.write_text("DB=secret\n")
    config = PartialEncryptionEnvironmentConfig(
        name="test",
        clear_file=str(clear_file),
        secret_file=str(secret_file),
        combined_file=str(combined_file),
    )
    with patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_cls:
        # Honest mock (#471): the simulated encrypt must leave no plaintext.
        mock_cls.return_value.encrypt.side_effect = _honest_encrypt_in_place
        stats = push_partial_encryption(config)
    assert combined_file.exists()
    assert stats["clear_lines"] == 1
    assert stats["secret_vars"] == 1


def test_pull_partial_encryption_returns_true_when_was_encrypted(tmp_path: Path):
    """pull_partial_encryption returns True when the file was encrypted before decryption."""
    from envdrift.core.partial_encryption import pull_partial_encryption

    secret_file = tmp_path / ".env.secret"
    secret_file.write_text('KEY="encrypted:abc"\n')
    config = PartialEncryptionEnvironmentConfig(
        name="test", clear_file="", secret_file=str(secret_file), combined_file=""
    )
    with patch("envdrift.core.partial_encryption.DotenvxWrapper"):
        assert pull_partial_encryption(config).was_decrypted is True


def test_pull_partial_encryption_returns_false_when_already_plain(tmp_path: Path):
    """pull_partial_encryption returns False when file was already plaintext."""
    from envdrift.core.partial_encryption import pull_partial_encryption

    secret_file = tmp_path / ".env.secret"
    secret_file.write_text("DB=plain\n")
    config = PartialEncryptionEnvironmentConfig(
        name="test", clear_file="", secret_file=str(secret_file), combined_file=""
    )
    with patch("envdrift.core.partial_encryption.DotenvxWrapper"):
        assert pull_partial_encryption(config).was_decrypted is False


def test_pull_partial_encryption_raises_when_secret_missing(tmp_path: Path):
    """pull_partial_encryption raises when secret_file does not exist."""
    from envdrift.core.partial_encryption import pull_partial_encryption

    config = PartialEncryptionEnvironmentConfig(
        name="test",
        clear_file="",
        secret_file=str(tmp_path / ".env.missing.secret"),
        combined_file="",
    )
    with pytest.raises(PartialEncryptionError, match="Secret file not found"):
        pull_partial_encryption(config)


# ---------------------------------------------------------------------------
# skip-worktree protection (Severity 2 fix)
# ---------------------------------------------------------------------------


def test_decrypt_secret_file_calls_skip_worktree(tmp_path: Path):
    """decrypt_secret_file marks the file skip-worktree after decryption."""
    from envdrift.core.partial_encryption import decrypt_secret_file

    secret_file = tmp_path / ".env.secret"
    secret_file.write_text('KEY="encrypted:abc"\n')
    config = PartialEncryptionEnvironmentConfig(
        name="test", clear_file="", secret_file=str(secret_file), combined_file=""
    )
    with (
        patch("envdrift.core.partial_encryption.DotenvxWrapper"),
        patch("envdrift.core.partial_encryption.subprocess.run") as mock_run,
    ):
        decrypt_secret_file(config)

    args = mock_run.call_args[0][0]
    assert "--skip-worktree" in args
    assert str(secret_file) in args


def test_encrypt_secret_file_calls_unskip_worktree(tmp_path: Path):
    """encrypt_secret_file un-marks skip-worktree after re-encryption."""
    from envdrift.core.partial_encryption import encrypt_secret_file

    secret_file = tmp_path / ".env.secret"
    secret_file.write_text("KEY=plain\n")
    config = PartialEncryptionEnvironmentConfig(
        name="test", clear_file="", secret_file=str(secret_file), combined_file=""
    )
    with (
        patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_cls,
        patch("envdrift.core.partial_encryption.subprocess.run") as mock_run,
    ):
        # Honest mock (#471): the simulated encrypt must leave no plaintext,
        # or the post-encrypt read-back (rightly) keeps the protection on.
        mock_cls.return_value.encrypt.side_effect = _honest_encrypt_in_place
        encrypt_secret_file(config)

    args = mock_run.call_args[0][0]
    assert "--no-skip-worktree" in args
    assert str(secret_file) in args


def test_skip_worktree_silent_on_git_unavailable(tmp_path: Path):
    """_git_skip_worktree does not raise when git is unavailable."""
    from envdrift.core.partial_encryption import _git_skip_worktree

    with patch(
        "envdrift.core.partial_encryption.subprocess.run",
        side_effect=FileNotFoundError("git not found"),
    ):
        _git_skip_worktree(tmp_path / ".env.secret")  # must not raise


def test_unskip_worktree_silent_on_subprocess_error(tmp_path: Path):
    """_git_unskip_worktree does not raise on subprocess errors."""
    import subprocess as _subprocess

    from envdrift.core.partial_encryption import _git_unskip_worktree

    with patch(
        "envdrift.core.partial_encryption.subprocess.run",
        side_effect=_subprocess.TimeoutExpired(["git"], 10),
    ):
        _git_unskip_worktree(tmp_path / ".env.secret")  # must not raise


def test_decrypt_secret_file_protects_already_plaintext(tmp_path: Path):
    """decrypt_secret_file still marks skip-worktree when the file is already plaintext."""
    from envdrift.core.partial_encryption import decrypt_secret_file

    secret_file = tmp_path / ".env.secret"
    secret_file.write_text("KEY=plain\n")  # not encrypted
    config = PartialEncryptionEnvironmentConfig(
        name="test", clear_file="", secret_file=str(secret_file), combined_file=""
    )
    with (
        patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_dotenvx_cls,
        patch("envdrift.core.partial_encryption.subprocess.run") as mock_run,
    ):
        decrypt_secret_file(config)

    mock_dotenvx_cls.return_value.decrypt.assert_not_called()  # early return, no decrypt
    args = mock_run.call_args[0][0]
    assert "--skip-worktree" in args
    assert str(secret_file) in args


def test_encrypt_secret_file_unskips_when_already_encrypted(tmp_path: Path):
    """encrypt_secret_file lifts stale skip-worktree even when already encrypted."""
    from envdrift.core.partial_encryption import encrypt_secret_file

    secret_file = tmp_path / ".env.secret"
    secret_file.write_text('KEY="encrypted:abc"\n')  # already encrypted
    config = PartialEncryptionEnvironmentConfig(
        name="test", clear_file="", secret_file=str(secret_file), combined_file=""
    )
    with (
        patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_dotenvx_cls,
        patch("envdrift.core.partial_encryption.subprocess.run") as mock_run,
    ):
        encrypt_secret_file(config)

    mock_dotenvx_cls.return_value.encrypt.assert_not_called()  # early return, no encrypt
    args = mock_run.call_args[0][0]
    assert "--no-skip-worktree" in args
    assert str(secret_file) in args


# ---------------------------------------------------------------------------
# skip-worktree protection in secrets_only mode
# ---------------------------------------------------------------------------


def test_pull_secrets_only_skip_worktrees_decrypted_files(secrets_only_config, secrets_dir):
    """pull_secrets_only marks every decrypted file skip-worktree."""
    for f in secrets_dir.iterdir():
        f.write_text(f.read_text() + 'KEY="encrypted:abc123"\n')

    with (
        patch("envdrift.core.partial_encryption.DotenvxWrapper"),
        patch("envdrift.core.partial_encryption.subprocess.run") as mock_run,
    ):
        pull_secrets_only(secrets_only_config)

    calls = [call.args[0] for call in mock_run.call_args_list]
    assert len(calls) == 2  # one per file in secrets_dir
    assert all("--skip-worktree" in argv for argv in calls)


def test_pull_secrets_only_protects_already_plaintext_files(secrets_only_config, secrets_dir):
    """pull_secrets_only marks skip-worktree even for files that were already plaintext."""
    with (
        patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_dotenvx_cls,
        patch("envdrift.core.partial_encryption.subprocess.run") as mock_run,
    ):
        pull_secrets_only(secrets_only_config)

    mock_dotenvx_cls.return_value.decrypt.assert_not_called()
    calls = [call.args[0] for call in mock_run.call_args_list]
    assert len(calls) == 2
    assert all("--skip-worktree" in argv for argv in calls)


def test_push_secrets_only_unskips_encrypted_files(secrets_only_config, secrets_dir):
    """push_secrets_only lifts skip-worktree on every file it encrypts."""
    with (
        patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_cls,
        patch("envdrift.core.partial_encryption.subprocess.run") as mock_run,
    ):
        # Honest mock (#471): the simulated encrypt must leave no plaintext,
        # or the post-encrypt read-back (rightly) keeps the protection on.
        mock_cls.return_value.encrypt.side_effect = _honest_encrypt_in_place
        push_secrets_only(secrets_only_config)

    calls = [call.args[0] for call in mock_run.call_args_list]
    assert len(calls) == 2
    assert all("--no-skip-worktree" in argv for argv in calls)


# ---------------------------------------------------------------------------
# .env.keys must never be encrypted/decrypted as a secret
# ---------------------------------------------------------------------------


def test_push_secrets_only_never_encrypts_keys_file(secrets_only_config, secrets_dir):
    """push_secrets_only must skip .env.keys even though it matches the .env* pattern."""
    # dotenvx-style private key file living alongside the secrets.
    (secrets_dir / ".env.keys").write_text('DOTENV_PRIVATE_KEY_PRODUCTION="abc123"\n')

    with patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_dotenvx_cls:
        instance = mock_dotenvx_cls.return_value
        # Honest mock (#471): the simulated encrypt must leave no plaintext.
        instance.encrypt.side_effect = _honest_encrypt_in_place
        result = push_secrets_only(secrets_only_config)

    encrypted_paths = [call.args[0].name for call in instance.encrypt.call_args_list]
    assert ".env.keys" not in encrypted_paths
    # The two real secret files are still encrypted; the keys file is not counted.
    assert result["encrypted"] == 2


def test_pull_secrets_only_never_decrypts_keys_file(secrets_only_config, secrets_dir):
    """pull_secrets_only must skip .env.keys even though it matches the .env* pattern."""
    # Encrypt the two real secret files; leave .env.keys as a plaintext key file.
    for name in (".env.api", ".env.db"):
        (secrets_dir / name).write_text('KEY="encrypted:abc123"\n')
    (secrets_dir / ".env.keys").write_text('DOTENV_PRIVATE_KEY_PRODUCTION="abc123"\n')

    with patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_dotenvx_cls:
        instance = mock_dotenvx_cls.return_value
        result = pull_secrets_only(secrets_only_config)

    decrypted_paths = [call.args[0].name for call in instance.decrypt.call_args_list]
    assert ".env.keys" not in decrypted_paths
    assert result["decrypted"] == 2


# ---------------------------------------------------------------------------
# git update-index helpers report success/failure
# ---------------------------------------------------------------------------


def test_git_skip_worktree_returns_true_on_success(tmp_path: Path):
    """_git_skip_worktree returns True when git exits 0."""
    from subprocess import CompletedProcess

    from envdrift.core.partial_encryption import _git_skip_worktree

    with patch(
        "envdrift.core.partial_encryption.subprocess.run",
        return_value=CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b""),
    ):
        assert _git_skip_worktree(tmp_path / ".env.secret") is True


def test_git_skip_worktree_returns_false_on_nonzero(tmp_path: Path, caplog):
    """_git_skip_worktree returns False and logs a warning when git exits non-zero."""
    import logging
    from subprocess import CompletedProcess

    from envdrift.core.partial_encryption import _git_skip_worktree

    with (
        patch(
            "envdrift.core.partial_encryption.subprocess.run",
            return_value=CompletedProcess(
                args=[], returncode=128, stdout=b"", stderr=b"fatal: not in the index"
            ),
        ),
        caplog.at_level(logging.WARNING),
    ):
        assert _git_skip_worktree(tmp_path / ".env.secret") is False
    assert "not in the index" in caplog.text


def test_git_skip_worktree_quiet_outside_repo(tmp_path: Path, caplog):
    """Outside a git repo, _git_skip_worktree returns False but stays quiet
    (debug, not warning) so push/pull in a non-repo dir don't print git noise."""
    import logging
    from subprocess import CompletedProcess

    from envdrift.core.partial_encryption import _git_skip_worktree

    with (
        patch(
            "envdrift.core.partial_encryption.subprocess.run",
            return_value=CompletedProcess(
                args=[],
                returncode=128,
                stdout=b"",
                stderr=b"fatal: not a git repository (or any of the parent directories): .git",
            ),
        ),
        caplog.at_level(logging.WARNING),
    ):
        assert _git_skip_worktree(tmp_path / ".env.secret") is False
    # The not-a-repo case must not emit a WARNING.
    assert "update-index" not in caplog.text


def test_git_unskip_worktree_returns_false_on_git_missing(tmp_path: Path):
    """_git_unskip_worktree returns False (not raising) when git is unavailable."""
    from envdrift.core.partial_encryption import _git_unskip_worktree

    with patch(
        "envdrift.core.partial_encryption.subprocess.run",
        side_effect=FileNotFoundError("git not found"),
    ):
        assert _git_unskip_worktree(tmp_path / ".env.secret") is False


# ---------------------------------------------------------------------------
# #371: non-ASCII values must round-trip regardless of the platform default
# encoding. read_text/write_text must pass encoding="utf-8".
#
# These run the functions in a CHILD interpreter under a hostile C locale
# (LC_ALL=C / LANG=C / PYTHONUTF8=0 / PYTHONIOENCODING=ascii). That is the only
# faithful way to exercise the bug: ``Path.read_text()`` with no ``encoding=``
# resolves its text-mode codec from the interpreter's startup/UTF-8 state, NOT
# from a runtime ``monkeypatch`` of ``locale.getpreferredencoding`` — so an
# in-process monkeypatch leaves ``read_text()`` decoding as UTF-8 and the bug
# stays hidden. In the child, the PRE-FIX code (no ``encoding=``) raises
# ``UnicodeDecodeError`` on the 0xC3 byte and exits non-zero; the fixed code
# (``encoding="utf-8"``) exits 0. We assert on the child exit status.
# ---------------------------------------------------------------------------

# Hostile, non-UTF-8 child environment. ``LC_ALL``/``LANG`` set the locale to
# the C codec; ``PYTHONUTF8=0`` disables UTF-8 mode (otherwise CPython would
# force UTF-8 regardless); ``PYTHONIOENCODING`` keeps stdio ascii too.
_ASCII_LOCALE_ENV = {
    "LC_ALL": "C",
    "LANG": "C",
    "LC_CTYPE": "C",
    "PYTHONUTF8": "0",
    "PYTHONIOENCODING": "ascii",
}


def _run_under_ascii_locale(body: str, *, cwd: Path) -> subprocess.CompletedProcess[str]:
    """Run ``body`` in a child interpreter under a hostile C locale.

    The child imports the REAL functions under test; ``cwd`` is the repo so the
    package is importable. Returns the completed process so the caller can
    assert on ``returncode`` (0 == the utf-8 read succeeded under C locale).
    """
    env = {**os.environ, **_ASCII_LOCALE_ENV}
    return subprocess.run(  # nosec B603
        [sys.executable, "-c", body],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )


# The repo root holds the importable ``src`` layout via the installed package;
# the child runs from there so ``import envdrift`` resolves.
_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_is_file_encrypted_handles_non_ascii_under_ascii_locale(tmp_path):
    """is_file_encrypted reads non-ASCII secrets without UnicodeError (#371).

    Fails on the pre-fix code (no ``encoding=``): the child raises
    ``UnicodeDecodeError`` under LC_ALL=C and exits non-zero.
    """
    secret = tmp_path / ".env.secret"
    # Accented + emoji value written as utf-8 bytes (0xC3 trips the ascii codec).
    secret.write_bytes("PASSWORD=héllo_café_\U0001f511\n".encode())

    body = (
        "import sys\n"
        "from envdrift.core.partial_encryption import is_file_encrypted\n"
        "from pathlib import Path\n"
        f"assert is_file_encrypted(Path(r{str(secret)!r})) is False\n"
        "sys.exit(0)\n"
    )
    result = _run_under_ascii_locale(body, cwd=_REPO_ROOT)

    assert result.returncode == 0, (
        "is_file_encrypted raised under C locale (pre-fix bug #371):\n" + result.stderr
    )


def test_combine_files_handles_non_ascii_under_ascii_locale(tmp_path):
    """combine_files reads/writes non-ASCII values without UnicodeError (#371).

    Fails on the pre-fix code (no ``encoding=``): reading the accented .clear /
    .secret files in the child raises ``UnicodeDecodeError`` under LC_ALL=C.
    """
    clear = tmp_path / ".env.test.clear"
    secret = tmp_path / ".env.test.secret"
    combined = tmp_path / ".env.test"
    clear.write_bytes("APP_NAME=café\n".encode())
    secret.write_bytes("PASSWORD=héllo_\U0001f511\n".encode())

    body = (
        "import sys\n"
        "from envdrift.config import PartialEncryptionEnvironmentConfig\n"
        "from envdrift.core.partial_encryption import combine_files\n"
        "cfg = PartialEncryptionEnvironmentConfig(\n"
        "    name='test',\n"
        f"    clear_file=r{str(clear)!r},\n"
        f"    secret_file=r{str(secret)!r},\n"
        f"    combined_file=r{str(combined)!r},\n"
        ")\n"
        "stats = combine_files(cfg)\n"
        "assert stats['clear_lines'] == 1, stats\n"
        "assert stats['secret_vars'] == 1, stats\n"
        "sys.exit(0)\n"
    )
    result = _run_under_ascii_locale(body, cwd=_REPO_ROOT)

    assert result.returncode == 0, (
        "combine_files raised under C locale (pre-fix bug #371):\n" + result.stderr
    )
    # Round-trip preserved the accented/emoji content (read back as utf-8).
    written = combined.read_bytes().decode("utf-8")
    assert "café" in written
    assert "héllo_\U0001f511" in written


# ---------------------------------------------------------------------------
# #471: push false success — unit twins of the real-binary e2e regressions.
#
# 1. combine_files must refuse to overwrite the combined file with an empty
#    scaffold when BOTH source files are missing (it may be the last copy of
#    the runtime env), and must write the combined artifact 0600 + atomically
#    (it carries the encrypted secret section, and pull --merge reuses the
#    same writer for DECRYPTED values).
# 2. encrypt_secret_file / push_secrets_only must refuse a file with no
#    variable assignments BEFORE invoking dotenvx (which would otherwise
#    scaffold ~13 placeholder secrets into it and exit 0), and must verify the
#    encryption actually took effect afterwards (dotenvx exits 0 WITHOUT
#    encrypting when .env.keys is unwritable/invalid).
# ---------------------------------------------------------------------------

# The exact production shape of a dotenvx-encrypted secret file (#485): the
# 4-line "#/" header block, the public-key assignment, the filename comment,
# then the ciphertext values.
_DOTENVX_ENCRYPTED_SECRET = (
    "#/-------------------[DOTENV_PUBLIC_KEY]--------------------/\n"
    "#/            public-key encryption for .env files          /\n"
    "#/       [how it works](https://dotenvx.com/encryption)     /\n"
    "#/----------------------------------------------------------/\n"
    'DOTENV_PUBLIC_KEY_TEST="03abc123..."\n'
    "\n"
    "# .env.test\n"
    'DATABASE_URL="encrypted:BDaLMxznvYWcHP..."\n'
)


def _honest_encrypt_in_place(path: Path) -> None:
    """Stand-in for a SUCCESSFUL dotenvx encrypt: plaintext values -> ciphertext.

    #471 added a post-encrypt read-back (``has_plaintext_secret_value``) to the
    push seam, so a bare ``MagicMock`` no-op "encrypt" now correctly trips it.
    Mocks that simulate a successful encrypt must therefore actually encrypt
    the file ("make the mock honest"); only the dotenvx subprocess seam is
    faked, never the read-back under test.
    """
    lines = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if stripped.startswith("#"):
            lines.append(raw)
            continue
        key, sep, value = stripped.partition("=")
        if not sep or not key.strip():
            lines.append(raw)
            continue
        bare = value.strip().strip('"').strip("'")
        if not bare or bare.startswith("encrypted:"):
            lines.append(raw)
            continue
        lines.append(f'{key}="encrypted:stub"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
