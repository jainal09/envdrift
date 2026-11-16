"""``dotenvx_key_files`` names the ``.env.keys`` files dotenvx actually writes (#961).

``DotenvxWrapper`` passes ``-fk`` with the ``.env.keys`` next to the file it
encrypts, but ``push``/``pull-partial`` gitignored ``./.env.keys`` in the working
directory. Run from a repository subdirectory that entry did not cover the real
key file, and with a recursive secrets-only pattern no per-folder key file was
covered. The real-git/real-dotenvx proof is
``tests/integration/test_push_key_gitignore_e2e.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.config import PartialEncryptionEnvironmentConfig


def _key_files(config: PartialEncryptionEnvironmentConfig) -> list[Path]:
    from envdrift.core.partial_encryption import dotenvx_key_files

    return dotenvx_key_files(config)


def _secrets_only(secrets_dir: str, pattern: str = ".env*") -> PartialEncryptionEnvironmentConfig:
    return PartialEncryptionEnvironmentConfig(
        name="production", secrets_only=True, secrets_dir=secrets_dir, pattern=pattern
    )


class TestCombineMode:
    def test_key_file_sits_next_to_the_secret_file(self) -> None:
        config = PartialEncryptionEnvironmentConfig(
            name="production",
            clear_file="config/.env.production.clear",
            secret_file="config/.env.production.secret",
            combined_file="config/.env.production",
        )
        assert _key_files(config) == [Path("config/.env.keys")]

    def test_secret_file_in_the_working_directory(self) -> None:
        config = PartialEncryptionEnvironmentConfig(
            name="production",
            clear_file=".env.production.clear",
            secret_file=".env.production.secret",
            combined_file=".env.production",
        )
        assert _key_files(config) == [Path(".env.keys")]

    def test_no_secret_file_means_no_key_file(self) -> None:
        config = PartialEncryptionEnvironmentConfig(name="production", secret_file="  ")
        assert _key_files(config) == []


class TestSecretsOnlyMode:
    def test_flat_pattern_has_one_key_file_in_secrets_dir(self, tmp_path: Path) -> None:
        secrets = tmp_path / "secrets"
        secrets.mkdir()
        (secrets / ".env.api").write_text("K=v\n", encoding="utf-8")
        (secrets / ".env.db").write_text("K=v\n", encoding="utf-8")

        assert _key_files(_secrets_only(str(secrets))) == [secrets / ".env.keys"]

    def test_recursive_pattern_has_one_key_file_per_folder(self, tmp_path: Path) -> None:
        secrets = tmp_path / "secrets"
        (secrets / "api").mkdir(parents=True)
        (secrets / "db" / "replica").mkdir(parents=True)
        (secrets / "docs").mkdir()
        (secrets / "api" / ".env.api").write_text("K=v\n", encoding="utf-8")
        (secrets / "api" / ".env.api2").write_text("K=v\n", encoding="utf-8")
        (secrets / "db" / "replica" / ".env.db").write_text("K=v\n", encoding="utf-8")
        # A folder holding only a companion file is never encrypted by push.
        (secrets / "docs" / ".env.example").write_text("K=\n", encoding="utf-8")

        assert _key_files(_secrets_only(str(secrets), "**/.env*")) == [
            secrets / ".env.keys",
            secrets / "api" / ".env.keys",
            secrets / "db" / "replica" / ".env.keys",
        ]

    def test_missing_secrets_dir_still_names_its_key_file(self, tmp_path: Path) -> None:
        secrets = tmp_path / "not-yet"
        assert _key_files(_secrets_only(str(secrets))) == [secrets / ".env.keys"]

    @pytest.mark.parametrize("secrets_dir", ["", "   "])
    def test_unset_secrets_dir_names_nothing(self, secrets_dir: str) -> None:
        # Never the working directory: push refuses an unset secrets_dir.
        assert _key_files(_secrets_only(secrets_dir)) == []

    def test_unusable_pattern_falls_back_to_the_secrets_dir(self, tmp_path: Path) -> None:
        secrets = tmp_path / "secrets"
        secrets.mkdir()
        # Path.glob rejects an empty pattern; push reports that error itself.
        assert _key_files(_secrets_only(str(secrets), "")) == [secrets / ".env.keys"]

    def test_absolute_pattern_falls_back_to_the_secrets_dir(self, tmp_path: Path) -> None:
        # Path.glob raises NotImplementedError for an absolute pattern, which used to
        # escape and crash push and pull-partial before any environment ran.
        secrets = tmp_path / "secrets"
        secrets.mkdir()
        (secrets / ".env.api").write_text("K=v\n", encoding="utf-8")
        pattern = (tmp_path / ".env*").as_posix()

        assert _key_files(_secrets_only(str(secrets), pattern)) == [secrets / ".env.keys"]

    def test_secrets_dir_that_is_a_file_names_nothing(self, tmp_path: Path) -> None:
        # push refuses it ("not a directory"), so dotenvx writes no key under it, and a
        # key path below a regular file crashed git before any environment ran.
        not_a_dir = tmp_path / ".env.secrets"
        not_a_dir.write_text("A=1\n", encoding="utf-8")

        assert _key_files(_secrets_only(str(not_a_dir))) == []
