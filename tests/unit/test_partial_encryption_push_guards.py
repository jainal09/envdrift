"""#471 push-guard unit tests: refuse-empty, read-back verification, safe writes.

Split out of ``test_partial_encryption.py`` to keep that module under the
code-health function-count threshold. Fixtures are self-contained copies (the
host module keeps its own for its remaining tests).
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from envdrift.config import PartialEncryptionEnvironmentConfig
from envdrift.core.partial_encryption import (
    PartialEncryptionError,
    combine_files,
    encrypt_secret_file,
    push_secrets_only,
)

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


@pytest.fixture
def temp_env_files(tmp_path: Path):
    """Clear/secret/combined file triple (copy of the host module fixture)."""
    clear_file = tmp_path / ".env.test.clear"
    secret_file = tmp_path / ".env.test.secret"
    combined_file = tmp_path / ".env.test"
    clear_file.write_text("# Application Settings\nDEBUG=false\nLOG_LEVEL=info\nPORT=8080\n")
    secret_file.write_text(
        "# Database\nDATABASE_URL=postgres://user:pass@localhost/db\nJWT_SECRET=my-secret-key\n"
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


@pytest.fixture
def secrets_dir(tmp_path: Path):
    """Secrets dir with two plaintext env files (copy of the host module fixture)."""
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


def test_push_secrets_only_raises_on_encrypt_failure(secrets_only_config, secrets_dir):
    """push_secrets_only wraps DotenvxError as PartialEncryptionError."""
    from envdrift.integrations.dotenvx import DotenvxError

    with patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_dotenvx_cls:
        mock_dotenvx_cls.return_value.encrypt.side_effect = DotenvxError("boom")
        with pytest.raises(PartialEncryptionError, match="Failed to encrypt"):
            push_secrets_only(secrets_only_config)


@pytest.mark.parametrize("write", [True, False])
def test_combine_files_refuses_when_both_sources_missing(tmp_path: Path, write: bool):
    """Both sources missing -> error; the existing combined file survives (#471).

    Pre-fix, combine_files tolerated both files being absent and unconditionally
    overwrote the combined file with a header-only scaffold — under push's
    "[OK] Push complete!" banner. If the sources were deleted by mistake the
    combined file was the last copy of the runtime env, and push destroyed it.
    """
    combined_file = tmp_path / ".env.test"
    sentinel = '# valuable runtime artifact\nDEBUG=false\nAPI_KEY="encrypted:abc..."\n'
    combined_file.write_text(sentinel, encoding="utf-8")
    config = PartialEncryptionEnvironmentConfig(
        name="test",
        clear_file=str(tmp_path / ".env.test.clear"),
        secret_file=str(tmp_path / ".env.test.secret"),
        combined_file=str(combined_file),
    )

    with pytest.raises(PartialEncryptionError, match=r"[Nn]either"):
        combine_files(config, write=write)

    assert combined_file.read_text(encoding="utf-8") == sentinel, (
        "combine_files overwrote the combined file despite missing sources"
    )


def test_combine_files_refuses_missing_sources_even_without_existing_combined(tmp_path: Path):
    """A config typo (both paths wrong) errors even when no combined file exists yet."""
    config = PartialEncryptionEnvironmentConfig(
        name="test",
        clear_file=str(tmp_path / "typo.clear"),
        secret_file=str(tmp_path / "typo.secret"),
        combined_file=str(tmp_path / ".env.test"),
    )

    with pytest.raises(PartialEncryptionError, match=r"[Nn]either"):
        combine_files(config)

    assert not (tmp_path / ".env.test").exists()


def test_combine_files_writes_combined_owner_only_and_atomic(temp_env_files):
    """The combined file is written via atomic_write: 0600 fresh, no temp residue (#471).

    The combined artifact carries the encrypted secret section (and the same
    writer path serves pull --merge's DECRYPTED output), so it must be created
    owner-only like .env.keys — never at the process umask.
    """
    config = temp_env_files["config"]
    secret_file = temp_env_files["secret_file"]
    combined_file = temp_env_files["combined_file"]
    secret_file.write_text(_DOTENVX_ENCRYPTED_SECRET, encoding="utf-8")
    assert not combined_file.exists()

    combine_files(config)

    assert combined_file.exists()
    if sys.platform != "win32":
        import stat as _stat

        mode = _stat.S_IMODE(combined_file.stat().st_mode)
        assert mode == 0o600, f"combined file mode {oct(mode)} != 0o600"
    # Atomic write leaves no half-written temp file next to the secrets.
    leftovers = list(combined_file.parent.glob("*.envdrift-tmp"))
    assert leftovers == [], f"temp files left behind: {leftovers}"


@pytest.mark.parametrize(
    "body",
    ["", "# only a comment\n\n   \n"],
    ids=["empty", "comment-only"],
)
def test_encrypt_secret_file_refuses_file_with_no_assignments(tmp_path: Path, body: str):
    """An empty/comment-only .secret is refused BEFORE dotenvx runs (#471).

    Pre-fix, dotenvx scaffolded ~13 placeholder secrets (HELLO,
    AWS_ACCESS_KEY_ID, OPENAI_API_KEY, ...) into the file, encrypted them, and
    push reported "13 encrypted" under the success banner.
    """
    secret_file = tmp_path / ".env.secret"
    secret_file.write_text(body, encoding="utf-8")
    before = secret_file.read_bytes()
    config = PartialEncryptionEnvironmentConfig(
        name="test", clear_file="", secret_file=str(secret_file), combined_file=""
    )

    with patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_cls:
        with pytest.raises(PartialEncryptionError, match=r"[Nn]othing to encrypt"):
            encrypt_secret_file(config)

    mock_cls.return_value.encrypt.assert_not_called()
    assert secret_file.read_bytes() == before, "the empty secret file was modified"


def test_encrypt_secret_file_raises_when_plaintext_survives(tmp_path: Path):
    """dotenvx exiting 0 WITHOUT encrypting must fail the push seam (#471).

    Models the unwritable/invalid .env.keys failure: dotenvx prints a warning,
    exits 0, and leaves every value plaintext. Only the dotenvx subprocess seam
    is mocked (as a no-op); the post-encrypt read-back under test runs for real.
    The git skip-worktree protection must NOT be lifted — the file still holds
    plaintext.
    """
    secret_file = tmp_path / ".env.secret"
    secret_file.write_text("JWT_SECRET=leakme-" + "plaintext\n", encoding="utf-8")
    config = PartialEncryptionEnvironmentConfig(
        name="test", clear_file="", secret_file=str(secret_file), combined_file=""
    )

    with (
        patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_cls,
        patch("envdrift.core.partial_encryption.subprocess.run") as mock_run,
    ):
        mock_cls.return_value.encrypt.side_effect = lambda _p: None  # exit-0 no-op
        with pytest.raises(PartialEncryptionError, match="did not take effect"):
            encrypt_secret_file(config)

    # The still-plaintext file must keep its skip-worktree protection.
    unskip_calls = [c.args[0] for c in mock_run.call_args_list if "--no-skip-worktree" in c.args[0]]
    assert unskip_calls == [], "skip-worktree protection lifted despite surviving plaintext"
    assert "leakme-" + "plaintext" in secret_file.read_text(encoding="utf-8")


@pytest.mark.parametrize("check", [False, True], ids=["push", "push --check"])
def test_push_secrets_only_refuses_empty_file(tmp_path: Path, check: bool):
    """secrets-only push refuses an empty file instead of fabricating secrets (#471)."""
    sdir = tmp_path / "secrets"
    sdir.mkdir()
    empty = sdir / ".env.api"
    empty.write_text("", encoding="utf-8")
    config = PartialEncryptionEnvironmentConfig(
        name="prod", secrets_only=True, secrets_dir=str(sdir), pattern=".env*"
    )

    with patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_cls:
        with pytest.raises(PartialEncryptionError, match=r"[Nn]othing to encrypt"):
            push_secrets_only(config, check=check)

    mock_cls.return_value.encrypt.assert_not_called()
    assert empty.read_bytes() == b"", "the empty secrets-only file was modified"


def test_push_secrets_only_raises_when_plaintext_survives(secrets_only_config, secrets_dir):
    """secrets-only push fails when dotenvx exits 0 without encrypting (#471)."""
    with patch("envdrift.core.partial_encryption.DotenvxWrapper") as mock_cls:
        mock_cls.return_value.encrypt.side_effect = lambda _p: None  # exit-0 no-op
        with pytest.raises(PartialEncryptionError, match="did not take effect"):
            push_secrets_only(secrets_only_config)

    # The plaintext files were never destroyed.
    for f in sorted(secrets_dir.iterdir()):
        assert "encrypted:" not in f.read_text(encoding="utf-8")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_combine_files_tightens_preexisting_world_readable_combined(temp_env_files):
    """A combined file left 0o644 by the pre-#510 write_text is tightened to 0o600.

    ``atomic_write`` preserves a pre-existing destination mode, so without the
    ``max_permissions=0o600`` cap the very population #471(4) protects — users
    whose combined files were already created world-readable — would keep that
    exposure on every subsequent push/pull --merge (#510 review).
    """
    import stat as _stat

    config = temp_env_files["config"]
    secret_file = temp_env_files["secret_file"]
    combined_file = temp_env_files["combined_file"]
    secret_file.write_text(_DOTENVX_ENCRYPTED_SECRET, encoding="utf-8")
    combined_file.write_text("OLD=1\n", encoding="utf-8")
    combined_file.chmod(0o644)

    combine_files(config)

    mode = _stat.S_IMODE(combined_file.stat().st_mode)
    assert mode == 0o600, f"combined file kept world-readable mode {oct(mode)}"
