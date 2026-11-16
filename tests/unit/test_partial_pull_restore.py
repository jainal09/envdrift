"""pull-partial leaves a failed secret file as it was and reports the true tally.

#948: dotenvx decrypts value by value. With one value under another key it
writes the values it could decrypt and exits 1; ``decrypt_secret_file`` /
``pull_secrets_only`` then raised before marking the file skip-worktree, so the
plaintext stayed in a tracked file under ``Decrypted: 0``.

The real-binary proof is ``tests/integration/test_pull_partial_failure_e2e.py``.
Here only the dotenvx subprocess seam (``DotenvxWrapper``) is replaced, by a
stand-in that writes what the real binary writes; the restore, the read-back
and the counting run for real.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from envdrift.config import PartialEncryptionEnvironmentConfig
from envdrift.core.partial_encryption import (
    PartialEncryptionError,
    decrypt_secret_file,
    pull_partial_encryption,
    pull_secrets_only,
)
from envdrift.integrations.dotenvx import DotenvxError
from tests.helpers import unreadable_file

_FOREIGN = "STRIPE_API_KEY=encrypted:BFOREIGN\n"
_FAILURE = "dotenvx decryption failed: [DECRYPTION_FAILED] could not decrypt STRIPE_API_KEY"


def _encrypted(key: str) -> str:
    return f'DOTENV_PUBLIC_KEY_X="03abc"\n{key}=encrypted:BAAA\n'


def _dotenvx_stand_in(path: Path) -> None:
    """Decrypt every value it can; on a foreign value, write the rest and fail.

    This is what dotenvx 2.x does: the values under the file's own key are
    written back as plaintext, then it exits 1 naming the value it could not
    decrypt.
    """
    lines = []
    foreign = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("STRIPE_API_KEY="):
            foreign = True
            lines.append(line)
        elif "=encrypted:" in line:
            lines.append(line.split("=", 1)[0] + "=plain-" + "value")
        else:
            lines.append(line)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if foreign:
        raise DotenvxError(_FAILURE)


@pytest.fixture
def skip_worktree_calls():
    """Record ``git update-index --skip-worktree`` calls (git always succeeds)."""
    calls: list[Path] = []

    def _record(path: Path) -> bool:
        calls.append(path)
        return True

    with patch("envdrift.core.partial_encryption._git_skip_worktree", side_effect=_record):
        yield calls


class TestDecryptSecretFileRestores:
    def test_failed_decrypt_restores_and_does_not_mark_skip_worktree(
        self, tmp_path: Path, skip_worktree_calls: list[Path]
    ) -> None:
        secret = tmp_path / ".env.production.secret"
        original = _encrypted("JWT_SECRET") + _FOREIGN
        secret.write_text(original, encoding="utf-8")
        config = PartialEncryptionEnvironmentConfig(
            name="production", clear_file="", secret_file=str(secret), combined_file=""
        )

        with patch("envdrift.core.partial_encryption.DotenvxWrapper") as wrapper_cls:
            wrapper_cls.return_value.decrypt.side_effect = _dotenvx_stand_in
            with pytest.raises(PartialEncryptionError) as excinfo:
                decrypt_secret_file(config)

        assert secret.read_text(encoding="utf-8") == original
        message = str(excinfo.value)
        assert message.startswith(f"Failed to decrypt {secret}: ")
        assert "could not decrypt STRIPE_API_KEY" in message
        assert f"{secret} was left as it was: envdrift restored" in message
        assert skip_worktree_calls == []  # restored, so nothing to protect

    @pytest.mark.parametrize("pull", [decrypt_secret_file, pull_partial_encryption])
    def test_unreadable_secret_file_is_refused_before_dotenvx_runs(
        self, searchable_tmp_path: Path, pull
    ) -> None:
        """A file this process really cannot read, not a patched ``read_bytes``.

        The encrypted check reads the file before any snapshot, and its bare
        PermissionError was "Unexpected error" in pull-partial and a traceback in
        ``envdrift pull``.
        """
        secret = searchable_tmp_path / ".env.production.secret"
        secret.write_text(_encrypted("JWT_SECRET"), encoding="utf-8")
        config = PartialEncryptionEnvironmentConfig(
            name="production", clear_file="", secret_file=str(secret), combined_file=""
        )

        with patch("envdrift.core.partial_encryption.DotenvxWrapper") as wrapper_cls:
            with unreadable_file(secret), pytest.raises(PartialEncryptionError) as excinfo:
                pull(config)
            wrapper_cls.return_value.decrypt.assert_not_called()

        message = str(excinfo.value)
        assert message.startswith(f"Failed to decrypt {secret}: [Errno 13]"), message
        assert message.endswith(f"{secret} was left as it was."), message
        assert secret.read_text(encoding="utf-8") == _encrypted("JWT_SECRET")


class TestPullSecretsOnlyReportsTheTally:
    def test_failure_carries_the_counts_reached_before_it(
        self, tmp_path: Path, skip_worktree_calls: list[Path]
    ) -> None:
        from envdrift.core.partial_encryption import SecretsOnlyPullError

        secrets = tmp_path / "secrets"
        secrets.mkdir()
        (secrets / ".env.a-plain").write_text("PLAIN=value\n", encoding="utf-8")
        api = secrets / ".env.api"
        api.write_text(_encrypted("API_KEY"), encoding="utf-8")
        db = secrets / ".env.db"
        db_original = _encrypted("DB_PASS") + _FOREIGN
        db.write_text(db_original, encoding="utf-8")
        later = secrets / ".env.zz"
        later.write_text(_encrypted("LATER"), encoding="utf-8")
        config = PartialEncryptionEnvironmentConfig(
            name="production", secrets_only=True, secrets_dir=str(secrets), pattern=".env*"
        )

        with patch("envdrift.core.partial_encryption.DotenvxWrapper") as wrapper_cls:
            wrapper_cls.return_value.decrypt.side_effect = _dotenvx_stand_in
            with pytest.raises(SecretsOnlyPullError) as excinfo:
                pull_secrets_only(config)

        error = excinfo.value
        assert isinstance(error, PartialEncryptionError)  # existing handlers still match
        # The already-plaintext .env.a-plain is still marked skip-worktree but is
        # not counted as protected: only files this pull decrypted are (#998).
        assert (error.decrypted, error.already_decrypted, error.protected) == (1, 1, 1)
        assert error.unprotected == []
        assert "could not decrypt STRIPE_API_KEY" in str(error)
        assert f"{db} was left as it was" in str(error)
        # .env.api was decrypted and protected; the failing file was restored
        # and not protected; the pull stopped before the later file.
        assert "API_KEY=plain-value" in api.read_text(encoding="utf-8")
        assert db.read_text(encoding="utf-8") == db_original
        assert db not in skip_worktree_calls and api in skip_worktree_calls
        assert later.read_text(encoding="utf-8") == _encrypted("LATER")

    def test_an_unreadable_later_file_carries_the_counts(
        self, searchable_tmp_path: Path, skip_worktree_calls: list[Path]
    ) -> None:
        """Any failure keeps the tally, not only a PartialEncryptionError.

        A real unreadable file (a root-owned one left by a container, say) raised a
        bare PermissionError, which dropped the count and the warning for the files
        decrypted before it.
        """
        from envdrift.core.partial_encryption import SecretsOnlyPullError

        secrets = searchable_tmp_path / "secrets"
        secrets.mkdir()
        secrets.chmod(0o755)
        api = secrets / ".env.api"  # sorted first: decrypts
        api.write_text(_encrypted("API_KEY"), encoding="utf-8")
        api.chmod(0o666)  # as root the pull runs as nobody, who must write it
        db = secrets / ".env.db"  # sorted second: unreadable
        db.write_text(_encrypted("DB_PASS"), encoding="utf-8")
        config = PartialEncryptionEnvironmentConfig(
            name="production", secrets_only=True, secrets_dir=str(secrets), pattern=".env*"
        )

        with patch("envdrift.core.partial_encryption.DotenvxWrapper") as wrapper_cls:
            wrapper_cls.return_value.decrypt.side_effect = _dotenvx_stand_in
            with unreadable_file(db), pytest.raises(SecretsOnlyPullError) as excinfo:
                pull_secrets_only(config)

        error = excinfo.value
        assert (error.decrypted, error.already_decrypted, error.protected) == (1, 0, 1)
        assert str(error).startswith(f"Failed to decrypt {db}: [Errno 13]"), str(error)
        assert str(error).endswith(f"{db} was left as it was."), str(error)
        assert "API_KEY=plain-value" in api.read_text(encoding="utf-8")
        assert db.read_text(encoding="utf-8") == _encrypted("DB_PASS")
        assert skip_worktree_calls == [api]

    def test_any_dotenvx_failure_on_a_later_file_carries_the_counts(
        self, tmp_path: Path, skip_worktree_calls: list[Path]
    ) -> None:
        """Not only a ``DotenvxError``: dotenvx missing is reported with the tally."""
        from envdrift.core.partial_encryption import SecretsOnlyPullError
        from envdrift.integrations.dotenvx import DotenvxNotFoundError

        secrets = tmp_path / "secrets"
        secrets.mkdir()
        api = secrets / ".env.api"
        api.write_text(_encrypted("API_KEY"), encoding="utf-8")
        db = secrets / ".env.db"
        db.write_text(_encrypted("DB_PASS"), encoding="utf-8")
        config = PartialEncryptionEnvironmentConfig(
            name="production", secrets_only=True, secrets_dir=str(secrets), pattern=".env*"
        )

        def _decrypt(path: Path) -> None:
            if path == db:
                raise DotenvxNotFoundError("dotenvx binary not found")
            _dotenvx_stand_in(path)

        with patch("envdrift.core.partial_encryption.DotenvxWrapper") as wrapper_cls:
            wrapper_cls.return_value.decrypt.side_effect = _decrypt
            with pytest.raises(SecretsOnlyPullError) as excinfo:
                pull_secrets_only(config)

        error = excinfo.value
        assert (error.decrypted, error.protected, error.unprotected) == (1, 1, [])
        assert str(error) == (
            f"Failed to decrypt {db}: dotenvx binary not found\n{db} was left as it was."
        )
        assert skip_worktree_calls == [api]

    def test_a_directory_the_pattern_matches_is_skipped(
        self, tmp_path: Path, skip_worktree_calls: list[Path]
    ) -> None:
        secrets = tmp_path / "secrets"
        (secrets / ".env.d").mkdir(parents=True)  # matches .env*, but is not a file
        api = secrets / ".env.api"
        api.write_text(_encrypted("API_KEY"), encoding="utf-8")
        config = PartialEncryptionEnvironmentConfig(
            name="production", secrets_only=True, secrets_dir=str(secrets), pattern=".env*"
        )

        with patch("envdrift.core.partial_encryption.DotenvxWrapper") as wrapper_cls:
            wrapper_cls.return_value.decrypt.side_effect = _dotenvx_stand_in
            result = pull_secrets_only(config)

        assert (result["decrypted"], result["already_decrypted"]) == (1, 0)
        assert skip_worktree_calls == [api]

    def test_an_unexpected_failure_carries_the_counts(self, tmp_path: Path) -> None:
        """Whatever stops the pull keeps the tally, an exception of any type."""
        from envdrift.core.partial_encryption import SecretsOnlyPullError

        secrets = tmp_path / "secrets"
        secrets.mkdir()
        api = secrets / ".env.api"  # sorted first: decrypts
        api.write_text(_encrypted("API_KEY"), encoding="utf-8")
        plain = secrets / ".env.b"  # sorted second: plaintext already, and git fails
        plain.write_text("B=plain\n", encoding="utf-8")
        config = PartialEncryptionEnvironmentConfig(
            name="production", secrets_only=True, secrets_dir=str(secrets), pattern=".env*"
        )

        def _skip_worktree(path: Path) -> bool:
            if path == plain:
                raise RuntimeError("git exploded")
            return True

        with (
            patch("envdrift.core.partial_encryption._git_skip_worktree", _skip_worktree),
            patch("envdrift.core.partial_encryption.DotenvxWrapper") as wrapper_cls,
        ):
            wrapper_cls.return_value.decrypt.side_effect = _dotenvx_stand_in
            with pytest.raises(SecretsOnlyPullError) as excinfo:
                pull_secrets_only(config)

        error = excinfo.value
        assert (error.decrypted, error.already_decrypted, error.protected) == (1, 0, 1)
        assert str(error) == f"Failed to decrypt {plain}: git exploded"


def test_decrypt_in_place_refuses_a_file_it_cannot_read(searchable_tmp_path: Path) -> None:
    """Readable at the encrypted check, unreadable by the snapshot: dotenvx never runs."""
    from envdrift.core.partial_encryption import _decrypt_in_place

    secret = searchable_tmp_path / ".env.production.secret"
    secret.write_text(_encrypted("JWT_SECRET"), encoding="utf-8")
    wrapper = MagicMock()

    with unreadable_file(secret), pytest.raises(PartialEncryptionError) as excinfo:
        _decrypt_in_place(wrapper, secret)

    wrapper.decrypt.assert_not_called()
    message = str(excinfo.value)
    assert message.startswith(f"Failed to decrypt {secret}: [Errno 13]"), message
    assert message.endswith(f"{secret} was left as it was."), message


# ---------------------------------------------------------------------------
# #963: a decrypt that exits 0 but leaves ciphertext is a failure, never
# "Decrypted". dotenvx prints "no change" and exits 0 on a SOPS file.
# ---------------------------------------------------------------------------

# A SOPS-encrypted dotenv file, shaped like real sops output (values are
# ENC[AES256_GCM,...], plus the flat sops_* trailer). Built from fragments so it
# carries no real secret.
_SOPS_FILE = (
    "JWT_SECRET=ENC[AES256_GCM,data:" + "ko5Qpd==,iv:" + "JADK=,tag:" + "8grm==,type:str]\n"
    "sops_lastmodified=2026-10-29T18:15:20Z\n"
    "sops_mac=ENC[AES256_GCM,data:" + "iBjK==,iv:" + "a1b2=,tag:" + "c3d4==,type:str]\n"
    "sops_version=3.13.3\n"
)


def _dotenvx_no_change(path: Path) -> None:
    """dotenvx on a file it finds nothing to decrypt in: "no change", exit 0."""


def _dotenvx_silent_partial(path: Path) -> None:
    """A decrypt that writes one value back as plaintext but exits 0."""
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("JWT_SECRET=encrypted:BAAA", "JWT_SECRET=plain-value"))


class TestStillEncryptedAfterDecrypt:
    @pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
    def test_sops_secret_file_is_a_failure_not_a_decrypt(
        self, tmp_path: Path, skip_worktree_calls: list[Path], newline: str
    ) -> None:
        secret = tmp_path / ".env.production.secret"
        original = _SOPS_FILE.replace("\n", newline).encode("utf-8")
        secret.write_bytes(original)
        config = PartialEncryptionEnvironmentConfig(
            name="production", clear_file="", secret_file=str(secret), combined_file=""
        )

        # The real wrapper normalizes line endings before dotenvx runs; only
        # the dotenvx subprocess itself is replaced (it changes nothing).
        with patch(
            "envdrift.integrations.dotenvx.DotenvxWrapper._run",
            return_value=subprocess.CompletedProcess([], 0, "", "no change"),
        ):
            with pytest.raises(PartialEncryptionError) as excinfo:
                decrypt_secret_file(config)

        message = " ".join(str(excinfo.value).split())
        assert f"Failed to decrypt {secret}: it still holds SOPS ciphertext" in message
        assert f"`envdrift decrypt {secret} --backend sops`" in message
        assert f"{secret} was left as it was" in message
        # envdrift pull gives this message too, and `envdrift decrypt` alone left
        # the plaintext stageable: the remedy marks the file first.
        assert "pull-partial" not in message
        # git runs in the file's folder (git -C), so the command names the file by its name.
        mark = message.index(f"update-index --skip-worktree {secret.name}`")
        assert mark < message.index("`envdrift decrypt") < message.index("`envdrift push`")
        # Not marked skip-worktree, and byte for byte as it was (CRLF too).
        assert skip_worktree_calls == []
        assert secret.read_bytes() == original

    def test_leftover_dotenvx_ciphertext_is_restored_and_reported(
        self, tmp_path: Path, skip_worktree_calls: list[Path]
    ) -> None:
        secret = tmp_path / ".env.production.secret"
        original = _encrypted("JWT_SECRET") + "OTHER=encrypted:BBBB\n"
        secret.write_text(original, encoding="utf-8")
        config = PartialEncryptionEnvironmentConfig(
            name="production", clear_file="", secret_file=str(secret), combined_file=""
        )

        with patch("envdrift.core.partial_encryption.DotenvxWrapper") as wrapper_cls:
            wrapper_cls.return_value.decrypt.side_effect = _dotenvx_silent_partial
            with pytest.raises(PartialEncryptionError) as excinfo:
                decrypt_secret_file(config)

        message = " ".join(str(excinfo.value).split())
        assert "it still holds dotenvx ciphertext" in message
        assert "key may be missing or invalid" in message
        assert f"{secret} was left as it was: envdrift restored" in message
        assert secret.read_text(encoding="utf-8") == original  # no plaintext left
        assert skip_worktree_calls == []

    def test_secrets_only_sops_file_stops_the_pull_with_the_tally(
        self, tmp_path: Path, skip_worktree_calls: list[Path]
    ) -> None:
        from envdrift.core.partial_encryption import SecretsOnlyPullError

        secrets = tmp_path / "secrets"
        secrets.mkdir()
        api = secrets / ".env.api"
        api.write_text(_encrypted("API_KEY"), encoding="utf-8")
        sops = secrets / ".env.sops"
        sops.write_text(_SOPS_FILE, encoding="utf-8")
        config = PartialEncryptionEnvironmentConfig(
            name="production", secrets_only=True, secrets_dir=str(secrets), pattern=".env*"
        )

        def _decrypt(path: Path) -> None:
            if path == api:
                _dotenvx_stand_in(path)  # decrypts every value it holds

        with patch("envdrift.core.partial_encryption.DotenvxWrapper") as wrapper_cls:
            wrapper_cls.return_value.decrypt.side_effect = _decrypt
            with pytest.raises(SecretsOnlyPullError) as excinfo:
                pull_secrets_only(config)

        assert excinfo.value.decrypted == 1
        assert "still holds SOPS ciphertext" in str(excinfo.value)
        assert sops.read_text(encoding="utf-8") == _SOPS_FILE
        assert skip_worktree_calls == [api]


def test_leftover_ciphertext_names_the_format(tmp_path: Path) -> None:
    from envdrift.core.partial_encryption import _leftover_ciphertext

    plain = tmp_path / "plain"
    plain.write_text('DOTENV_PUBLIC_KEY_X="03abc"\nKEY=value\n', encoding="utf-8")
    dotenvx = tmp_path / "dotenvx"
    dotenvx.write_text(_encrypted("KEY"), encoding="utf-8")
    sops = tmp_path / "sops"
    sops.write_text(_SOPS_FILE, encoding="utf-8")

    assert _leftover_ciphertext(plain) is None
    assert _leftover_ciphertext(dotenvx) == "dotenvx"
    assert _leftover_ciphertext(sops) == "SOPS"
