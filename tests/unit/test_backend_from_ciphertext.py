"""A file's backend comes from the ciphertext it holds, not a leftover header (#949).

``dotenvx decrypt`` keeps the ``DOTENV_PUBLIC_KEY`` header, and SOPS keeps that key's
name when it encrypts such a file. The real migration runs in
tests/integration/test_dotenvx_to_sops_migration_e2e.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.core.encryption import EncryptionDetector
from tests.helpers import DummyEncryptionBackend

runner = CliRunner()

_HEADER = (
    "#/-------------------[DOTENV_PUBLIC_KEY]--------------------/\n"
    "#/            public-key encryption for .env files          /\n"
    "#/       [how it works](https://dotenvx.com/encryption)     /\n"
    "#/----------------------------------------------------------/\n"
    'DOTENV_PUBLIC_KEY_PRODUCTION="02a3f53b749aecd26bba2f2986a54e822a9dade9b09890167b"\n'
)
# What dotenvx leaves after a decrypt: its header, plaintext values.
_DOTENVX_DECRYPTED = _HEADER + "\n# .env.production\nAPI_KEY=abc123\n"
# What SOPS writes for that file: the comments and values encrypted, the key name kept.
_SOPS_AFTER_DOTENVX = (
    "#ENC[AES256_GCM,data:yfvg,iv:a,tag:b,type:comment]\n"
    "DOTENV_PUBLIC_KEY_PRODUCTION=ENC[AES256_GCM,data:G1qL,iv:c,tag:d,type:str]\n"
    "API_KEY=ENC[AES256_GCM,data:CXE6,iv:e,tag:f,type:str]\n"
    "sops_mac=ENC[AES256_GCM,data:QQcB,iv:g,tag:h,type:str]\n"
    "sops_version=3.13.3\n"
)
_DOTENVX_ENCRYPTED = _HEADER + "API_KEY=encrypted:BJcmM3MTYm+PjK7upMiPNCU1mwz76onUbudP=\n"


class TestCiphertextBackends:
    """``ciphertext_backends`` names only ciphertext that is really there."""

    @pytest.mark.parametrize(
        ("content", "expected"),
        [
            (_DOTENVX_DECRYPTED, set()),
            (_DOTENVX_ENCRYPTED, {"dotenvx"}),
            (_SOPS_AFTER_DOTENVX, {"sops"}),
            (
                _DOTENVX_ENCRYPTED + "OTHER=ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\n",
                {"dotenvx", "sops"},
            ),
            ("NOTE=the key is stored encrypted: see docs\n", set()),
            # dotenvx cut hunter2#Spring2024! at its "#" and encrypted the rest.
            (_HEADER + "DB_PASSWORD=encrypted:BJcmM3MTYm+PjK7upMiPNC=#Spring2024!\n", {"dotenvx"}),
            ("# SOPS writes ENC[AES256_GCM,data:...] values\nAPI_KEY=abc123\n", set()),
        ],
        ids=[
            "dotenvx-decrypted",
            "dotenvx",
            "sops-after-dotenvx",
            "both",
            "mention",
            "dotenvx-cut-at-a-hash",
            "sops-envelope-in-a-comment",
        ],
    )
    def test_backends(self, content: str, expected: set[str]) -> None:
        assert EncryptionDetector().ciphertext_backends(content) == expected

    def test_a_reference_is_not_read_as_the_ciphertext_it_names(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CIPHER_949", "encrypted:abc")

        assert EncryptionDetector().ciphertext_backends("API_KEY=${CIPHER_949}\n") == set()

    def test_file_variant_tolerates_missing_and_binary_files(self, tmp_path: Path) -> None:
        detector = EncryptionDetector()
        blob = tmp_path / "blob.env"
        blob.write_bytes(b"\xff\xfe\x00API_KEY=encrypted:x")

        assert detector.ciphertext_backends_for_file(tmp_path / "missing.env") == set()
        assert detector.ciphertext_backends_for_file(blob) == set()


class TestDetectBackend:
    """The ciphertext names the backend; the header decides only without it."""

    def test_sops_file_with_a_dotenvx_key_name_is_sops(self) -> None:
        assert EncryptionDetector().detect_backend(_SOPS_AFTER_DOTENVX) == "sops"

    def test_dotenvx_decrypted_file_still_reads_as_dotenvx(self) -> None:
        # So `decrypt` keeps reporting its honest "Nothing to decrypt".
        assert EncryptionDetector().detect_backend(_DOTENVX_DECRYPTED) == "dotenvx"

    @pytest.mark.parametrize(
        ("content", "expected"),
        [
            ("API_KEY=abc123\n", None),
            ("VAULT_ADDR=https://sops:8200\n", None),
            ("API_KEY=encrypted:BJcmM3MTYm+PjK7upMiPNCU1mwz76onUbudP=\n", "dotenvx"),
            ("sops_version=3.13.3\n", "sops"),
        ],
        ids=["plaintext", "sops-in-a-value", "dotenvx-without-its-header", "sops-metadata-only"],
    )
    def test_a_file_of_one_backend_or_none(self, content: str, expected: str | None) -> None:
        """Found without a parse where no SOPS marker is, and the same as with one."""
        assert EncryptionDetector().detect_backend(content) == expected

    def test_both_backends_fall_back_to_the_headers(self) -> None:
        both = _DOTENVX_ENCRYPTED + "OTHER=ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\n"

        assert EncryptionDetector().detect_backend(both) == "dotenvx"

    def test_file_variant(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env.production"
        env_file.write_text(_SOPS_AFTER_DOTENVX, encoding="utf-8")

        assert EncryptionDetector().detect_backend_for_file(env_file) == "sops"


class TestEncryptRefusal:
    """``encrypt`` refuses ciphertext from another backend, and nothing else."""

    def _stub_backend(self, monkeypatch: pytest.MonkeyPatch, name: str) -> DummyEncryptionBackend:
        backend = DummyEncryptionBackend(name=name)
        monkeypatch.setattr(
            "envdrift.cli_commands.encryption.get_encryption_backend",
            lambda *_args, **_kwargs: backend,
        )
        return backend

    def test_sops_encrypts_a_file_dotenvx_decrypted(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        env_file = tmp_path / ".env.production"
        env_file.write_text(_DOTENVX_DECRYPTED, encoding="utf-8")
        backend = self._stub_backend(monkeypatch, "sops")

        result = runner.invoke(app, ["encrypt", str(env_file), "--backend", "sops"])

        assert result.exit_code == 0, result.output
        assert backend.encrypt_calls == [env_file]

    def test_dotenvx_refuses_a_sops_file_with_a_dotenvx_key_name(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        env_file = tmp_path / ".env.production"
        env_file.write_text(_SOPS_AFTER_DOTENVX, encoding="utf-8")
        backend = self._stub_backend(monkeypatch, "dotenvx")

        result = runner.invoke(app, ["encrypt", str(env_file), "--backend", "dotenvx"])

        out = " ".join(result.output.split())
        assert result.exit_code == 1, out
        assert "is already encrypted with sops, but the dotenvx backend was selected" in out
        assert backend.encrypt_calls == []
        assert env_file.read_text(encoding="utf-8") == _SOPS_AFTER_DOTENVX
