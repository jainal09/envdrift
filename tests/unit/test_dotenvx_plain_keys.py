"""dotenvx's ``_PLAIN`` keys are not leftover plaintext, for dotenvx only (#1048).

dotenvx 2.38.2 never encrypts a key whose name ends with ``_PLAIN``, unless it reads an
``Envfile`` in its working directory. SOPS has no such convention. The real binary is
exercised in tests/integration/test_dotenvx_plain_keys_e2e.py.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from envdrift.cli_commands.sync_lock_helpers import _plaintext_values_remain
from envdrift.config import PartialEncryptionEnvironmentConfig
from envdrift.core.partial_encryption import (
    _line_has_plaintext_secret,
    combine_files,
    has_plaintext_secret_value,
    is_fully_encrypted,
)
from envdrift.encryption import EncryptionProvider
from envdrift.encryption.dotenvx import DotenvxEncryptionBackend
from envdrift.encryption.sops import SOPSEncryptionBackend
from envdrift.integrations.dotenvx_keys import is_plain_key, plain_keys_apply

_CIPHERTEXT = "encrypted:" + "BJcmM3MTYm+PjK7upMiPNCU1mwz76onUbudP="
_SOPS_VALUE = "ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]"


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A working directory without an Envfile, as dotenvx sees one."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


class TestIsPlainKey:
    """The name test dotenvx applies: ``/_PLAIN$/``, case-sensitive."""

    @pytest.mark.parametrize("name", ["NOTE_PLAIN", "_PLAIN", "dot.key_PLAIN", "A_B_PLAIN"])
    def test_plain(self, name: str) -> None:
        assert is_plain_key(name)

    @pytest.mark.parametrize(
        "name", ["note_plain", "NOTE_plain", "PLAIN", "PLAIN_NOTE", "X_PLAIN_Y", "X_PLAINS", ""]
    )
    def test_not_plain(self, name: str) -> None:
        assert not is_plain_key(name)


class TestPlainKeysApply:
    """dotenvx applies the rule unless an Envfile is in its working directory."""

    def test_without_an_envfile(self, project: Path) -> None:
        assert plain_keys_apply()
        assert plain_keys_apply(project)

    @pytest.mark.parametrize("kind", ["file", "directory", "dangling-link"])
    def test_with_an_envfile(self, project: Path, kind: str) -> None:
        envfile = project / "Envfile"
        if kind == "file":
            envfile.write_text("", encoding="utf-8")
        elif kind == "directory":
            envfile.mkdir()
        else:
            try:
                envfile.symlink_to(project / "missing")
            except OSError:
                pytest.skip("symlinks are not permitted here")

        assert not plain_keys_apply()
        assert not plain_keys_apply(str(project))

    def test_only_the_working_directory_counts(self, project: Path) -> None:
        (project / "sub").mkdir()
        (project / "sub" / "Envfile").write_text("", encoding="utf-8")

        assert plain_keys_apply()
        assert not plain_keys_apply(project / "sub")


class TestPlaintextChecks:
    """The outcome checks exempt a ``_PLAIN`` key only when asked to, for dotenvx."""

    def test_line_check(self) -> None:
        assert _line_has_plaintext_secret("NOTE_PLAIN=hello")  # the default, which SOPS uses
        assert not _line_has_plaintext_secret("NOTE_PLAIN=hello", plain_keys=True)
        assert not _line_has_plaintext_secret("export NOTE_PLAIN = hello", plain_keys=True)
        assert _line_has_plaintext_secret("note_plain=hello", plain_keys=True)

    def test_file_checks(self, project: Path) -> None:
        env_file = project / ".env"
        env_file.write_text(f"API_KEY={_CIPHERTEXT}\nNOTE_PLAIN=hello\n", encoding="utf-8")

        assert has_plaintext_secret_value(env_file)
        assert not has_plaintext_secret_value(env_file, plain_keys=True)
        assert not is_fully_encrypted(env_file)
        assert is_fully_encrypted(env_file, plain_keys=True)

    def test_other_plaintext_still_counts(self, project: Path) -> None:
        env_file = project / ".env"
        env_file.write_text(f"API_KEY={_CIPHERTEXT}\nNOTE_PLAIN=a\nNEW=b\n", encoding="utf-8")

        assert has_plaintext_secret_value(env_file, plain_keys=True)

    def test_a_sops_file_keeps_its_own_rules(self, project: Path) -> None:
        env_file = project / ".env.secret"
        env_file.write_text(
            f"API_KEY={_SOPS_VALUE}\nNOTE_PLAIN=hello\nsops_version=3.13.3\n", encoding="utf-8"
        )

        assert has_plaintext_secret_value(env_file, plain_keys=True)
        assert not is_fully_encrypted(env_file, plain_keys=True)

    def test_the_sops_backend_still_reports_a_plain_key(self) -> None:
        content = f"API_KEY={_SOPS_VALUE}\nNOTE_PLAIN=hello\nsops_version=3.13.3\n"

        assert SOPSEncryptionBackend()._plaintext_keys(content) == ["NOTE_PLAIN"]


class TestCombinedFileCount:
    """push's "encrypted" count leaves out a value dotenvx kept plaintext."""

    def _config(self, project: Path) -> PartialEncryptionEnvironmentConfig:
        (project / ".env.production.clear").write_text("APP=shop\n", encoding="utf-8")
        (project / ".env.production.secret").write_text(
            f"DB_PASSWORD={_CIPHERTEXT}\nREGION_PLAIN=eu\n", encoding="utf-8"
        )
        return PartialEncryptionEnvironmentConfig(
            name="production",
            clear_file=str(project / ".env.production.clear"),
            secret_file=str(project / ".env.production.secret"),
            combined_file=str(project / ".env.production"),
        )

    def test_the_plain_key_is_not_counted_as_encrypted(self, project: Path) -> None:
        stats = combine_files(self._config(project), write=False)

        assert stats["secret_vars"] == 1

    def test_with_an_envfile_every_key_counts(self, project: Path) -> None:
        (project / "Envfile").write_text("", encoding="utf-8")

        stats = combine_files(self._config(project), write=False)

        assert stats["secret_vars"] == 2


class TestDotenvxBackendOutcomeCheck:
    """``DotenvxEncryptionBackend.encrypt`` judges the outcome as dotenvx encrypts."""

    def _backend(self) -> DotenvxEncryptionBackend:
        def _encrypt(env_file: Path, **_kwargs: object) -> None:
            env_file.write_text(f"API_KEY={_CIPHERTEXT}\nNOTE_PLAIN=hello\n", encoding="utf-8")

        wrapper = MagicMock()
        wrapper.is_installed.return_value = True
        wrapper.encrypt.side_effect = _encrypt
        backend = DotenvxEncryptionBackend()
        backend._wrapper = wrapper
        return backend

    def test_a_plain_key_left_as_is_is_a_success(self, project: Path) -> None:
        env_file = project / ".env"
        env_file.write_text("API_KEY=abc\nNOTE_PLAIN=hello\n", encoding="utf-8")

        result = self._backend().encrypt(env_file)

        assert result.success, result.message

    def test_with_an_envfile_it_is_leftover_plaintext(self, project: Path) -> None:
        (project / "Envfile").write_text("", encoding="utf-8")
        env_file = project / ".env"
        env_file.write_text("API_KEY=abc\nNOTE_PLAIN=hello\n", encoding="utf-8")

        result = self._backend().encrypt(env_file)

        assert not result.success
        assert "did not take effect" in result.message

    def test_the_envfile_is_looked_for_where_dotenvx_runs(self, project: Path) -> None:
        elsewhere = project / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "Envfile").write_text("", encoding="utf-8")
        env_file = project / ".env"
        env_file.write_text("API_KEY=abc\nNOTE_PLAIN=hello\n", encoding="utf-8")

        result = self._backend().encrypt(env_file, cwd=elsewhere)

        assert not result.success


class TestLockDecision:
    """lock exempts a ``_PLAIN`` key for the dotenvx backend only."""

    def test_dotenvx_and_sops(self, project: Path) -> None:
        env_file = project / ".env.production"
        env_file.write_text(f"API_KEY={_CIPHERTEXT}\nNOTE_PLAIN=hello\n", encoding="utf-8")

        assert not _plaintext_values_remain(env_file, EncryptionProvider.DOTENVX)
        assert _plaintext_values_remain(env_file, EncryptionProvider.SOPS)

    def test_with_an_envfile(self, project: Path) -> None:
        (project / "Envfile").write_text("", encoding="utf-8")
        env_file = project / ".env.production"
        env_file.write_text(f"API_KEY={_CIPHERTEXT}\nNOTE_PLAIN=hello\n", encoding="utf-8")

        assert _plaintext_values_remain(env_file, EncryptionProvider.DOTENVX)
