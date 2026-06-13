"""CLI guard tests: encrypt/decrypt refuse companion files by name (#474).

``envdrift encrypt .env.keys`` previously encrypted the dotenvx private-key
store itself with ``[OK]``/exit 0, permanently locking out every encrypted file
in the project. The bare ``encrypt``/``decrypt`` commands must refuse companion
files (``.keys``/``.example``/``.sample``/``.template``) by name — for every
backend — using the same canonical predicate that already excludes them from
push/pull.

These drive the real Typer app via CliRunner; the guard fires pre-flight, so no
encryption binary is needed and the target file must stay byte-for-byte intact.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from envdrift.cli import app

runner = CliRunner()


def _fake_private_key(seed: str) -> str:
    """Build a 64-hex value shaped like a private key (assembled, not literal)."""
    return (seed * 64)[:64]


def _flat(output: str) -> str:
    """Normalize Rich output (line wraps, padding) for substring assertions."""
    return " ".join(output.split())


@pytest.fixture
def keys_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A realistic ``.env.keys`` private-key store in an isolated cwd."""
    monkeypatch.chdir(tmp_path)
    keys = tmp_path / ".env.keys"
    keys.write_text(
        "# .env\nDOTENV_PRIVATE_KEY=" + _fake_private_key("b") + "\n",
        encoding="utf-8",
    )
    return keys


class TestEncryptRefusesCompanionFiles:
    def test_encrypt_env_keys_refused(self, keys_file: Path) -> None:
        """#474: ``encrypt .env.keys`` exits 1 and leaves the key store intact."""
        before = keys_file.read_text(encoding="utf-8")

        result = runner.invoke(app, ["encrypt", ".env.keys"])

        output = _flat(result.output)
        assert result.exit_code == 1, output
        assert "Refusing to encrypt" in output, output
        assert "private-key store" in output, output
        assert keys_file.read_text(encoding="utf-8") == before

    def test_encrypt_env_keys_refused_for_sops_backend_too(self, keys_file: Path) -> None:
        """#474: the refusal is by name, before any backend is resolved."""
        result = runner.invoke(app, ["encrypt", ".env.keys", "--backend", "sops"])

        output = _flat(result.output)
        assert result.exit_code == 1, output
        assert "Refusing to encrypt" in output, output

    def test_encrypt_example_companion_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#474: plaintext companion files (.example) are refused as well."""
        monkeypatch.chdir(tmp_path)
        example = tmp_path / ".env.example"
        example.write_text("API_KEY=placeholder\n", encoding="utf-8")

        result = runner.invoke(app, ["encrypt", ".env.example"])

        output = _flat(result.output)
        assert result.exit_code == 1, output
        assert "Refusing to encrypt" in output, output
        assert example.read_text(encoding="utf-8") == "API_KEY=placeholder\n"


class TestDecryptRefusesCompanionFiles:
    def test_decrypt_env_keys_refused(self, keys_file: Path) -> None:
        """#474: ``decrypt .env.keys`` refuses by name instead of a fake no-op."""
        before = keys_file.read_text(encoding="utf-8")

        result = runner.invoke(app, ["decrypt", ".env.keys"])

        output = _flat(result.output)
        assert result.exit_code == 1, output
        assert "Refusing to decrypt" in output, output
        assert keys_file.read_text(encoding="utf-8") == before
