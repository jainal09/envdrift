"""Regression tests: `envdrift encrypt` gitignores the dotenvx `.env.keys`.

A new user who encrypts in a git repo must not be able to accidentally commit
the private decryption keys (which would defeat the encryption). Surfaced by
dogfooding the first-run flow.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import envdrift.cli_commands.encryption as enc
from envdrift.cli_commands.encryption import _protect_private_keys


def _git_init(path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)  # nosec B603, B607


class TestProtectPrivateKeys:
    """Tests for the .env.keys gitignore guard run after a successful encrypt."""

    def test_gitignores_env_keys_and_warns(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _git_init(tmp_path)
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=abc123\n")
        monkeypatch.chdir(tmp_path)

        warnings: list[str] = []
        monkeypatch.setattr(enc, "print_warning", warnings.append)

        _protect_private_keys(Path(".env"))

        assert ".env.keys" in (tmp_path / ".gitignore").read_text()
        assert any("never commit your private keys" in w for w in warnings)

    def test_noop_when_no_env_keys(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """SOPS (and any flow without a .env.keys) leaves no .gitignore behind."""
        _git_init(tmp_path)
        monkeypatch.chdir(tmp_path)

        warnings: list[str] = []
        monkeypatch.setattr(enc, "print_warning", warnings.append)

        _protect_private_keys(Path(".env"))

        assert not (tmp_path / ".gitignore").exists()
        assert warnings == []

    def test_no_duplicate_or_warning_when_already_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _git_init(tmp_path)
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY=abc\n")
        (tmp_path / ".gitignore").write_text(".env.keys\n")
        monkeypatch.chdir(tmp_path)

        warnings: list[str] = []
        monkeypatch.setattr(enc, "print_warning", warnings.append)

        _protect_private_keys(Path(".env"))

        # Already protected -> no duplicate entry and no (noisy) warning.
        assert (tmp_path / ".gitignore").read_text().count(".env.keys") == 1
        assert warnings == []
