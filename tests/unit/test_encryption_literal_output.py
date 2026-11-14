"""encrypt, decrypt and vault-push print their instructions, names and paths as they are.

The SOPS install instructions tell the user to set ``[encryption.sops]
auto_install``; printed as markup, the table name vanished (``Set  auto_install
= true``). ``decrypt --verify-vault`` printed the secret name and the repair
commands as markup, so ``kv/app[/x]`` raised ``MarkupError`` and a path such as
``svc[bold]/.env.production`` was named ``svc/.env.production``. vault-push's
rows did the same with folders and secret names.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.encryption import EncryptionProvider
from envdrift.encryption.sops import SOPSEncryptionBackend
from envdrift.vault.base import SecretNotFoundError, SecretValue
from tests.helpers import DummyEncryptionBackend

runner = CliRunner()

_INSTRUCTION = "Set [encryption.sops] auto_install = true in envdrift.toml"


class _MissingSops(DummyEncryptionBackend):
    """SOPS as it is on a machine without the binary: its real instructions."""

    def __init__(self) -> None:
        super().__init__(name="sops", installed=False)

    def install_instructions(self) -> str:
        return SOPSEncryptionBackend().install_instructions()


class _Vault:
    def __init__(self, secrets: dict[str, str]) -> None:
        self.secrets = dict(secrets)

    def authenticate(self) -> None:
        return None

    def ensure_authenticated(self) -> None:
        return None

    def get_secret(self, name: str) -> SecretValue:
        if name not in self.secrets:
            raise SecretNotFoundError(f"Secret '{name}' not found")
        return SecretValue(name=name, value=self.secrets[name])

    def set_secret(self, name: str, value: str) -> SecretValue:
        self.secrets[name] = value
        return SecretValue(name=name, value=value)


def _invoke(*args: str):
    return runner.invoke(app, list(args), env={"COLUMNS": "250"})


def _flat(text: str) -> str:
    return " ".join(text.split())


def _use_vault(monkeypatch: pytest.MonkeyPatch, secrets: dict[str, str]) -> _Vault:
    vault = _Vault(secrets)
    monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_a, **_k: vault)
    return vault


def _use_backend(monkeypatch: pytest.MonkeyPatch, backend: DummyEncryptionBackend) -> None:
    monkeypatch.setattr(
        "envdrift.cli_commands.encryption_helpers.resolve_encryption_backend",
        lambda *_a, **_k: (backend, EncryptionProvider(backend.name), None),
    )


def _push_config(root: Path, folder: str, secret: str) -> Path:
    config = root / "envdrift.toml"
    config.write_text(
        '[vault]\nprovider = "aws"\n\n[vault.aws]\nregion = "us-east-1"\n\n'
        '[vault.sync]\nenv_keys_filename = ".env.keys"\n\n'
        "[[vault.sync.mappings]]\n"
        f"secret_name = {json.dumps(secret)}\n"
        f"folder_path = {json.dumps(folder)}\n"
        'environment = "production"\n',
        encoding="utf-8",
    )
    return config


@pytest.mark.parametrize("command", ["encrypt", "decrypt"])
def test_encrypt_and_decrypt_print_the_sops_instructions_literally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    env_file = tmp_path / ".env.production"
    env_file.write_text("API_TOKEN=value\n", encoding="utf-8")
    monkeypatch.setattr(
        "envdrift.cli_commands.encryption.get_encryption_backend",
        lambda *_a, **_k: _MissingSops(),
    )

    result = _invoke(command, str(env_file), "--backend", "sops")

    assert result.exit_code == 1, result.output
    assert _INSTRUCTION in result.output


def test_vault_push_prints_the_sops_instructions_literally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "svc").mkdir()
    config = _push_config(tmp_path, "svc", "app-key")
    _use_vault(monkeypatch, {})
    _use_backend(monkeypatch, _MissingSops())

    result = _invoke("vault-push", "--all", "-c", str(config))

    assert result.exit_code == 1, result.output
    assert _INSTRUCTION in result.output


def test_vault_push_rows_name_folders_secrets_and_files_as_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    folder = tmp_path / "svc[" / "x]"
    folder.mkdir(parents=True)
    (folder / ".env.production").write_text("API_TOKEN=value\n", encoding="utf-8")
    (folder / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=" + "a" * 64 + "\n")
    config = _push_config(tmp_path, "svc[/x]", "kv/app[/x]")
    _use_backend(monkeypatch, DummyEncryptionBackend())

    _use_vault(monkeypatch, {"kv/app[/x]": "existing"})
    skipped = _invoke("vault-push", "--all", "-c", str(config))

    assert skipped.exit_code == 0, skipped.output
    assert f"Skipped {Path('svc[/x]')}: Secret 'kv/app[/x]' already exists" in _flat(skipped.output)

    vault = _use_vault(monkeypatch, {})
    pushed = _invoke("vault-push", "--all", "-c", str(config))

    assert pushed.exit_code == 0, pushed.output
    out = _flat(pushed.output)
    assert f"Encrypting {Path('svc[/x]') / '.env.production'} with dotenvx..." in out
    assert "[OK] Pushed kv/app[/x]" in out
    assert "kv/app[/x]" in vault.secrets


def test_verify_vault_header_names_the_secret_as_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The header raised MarkupError before anything was checked."""
    env_file = tmp_path / ".env.production"
    env_file.write_text("API_TOKEN=value\n", encoding="utf-8")
    _use_vault(monkeypatch, {"kv/app[/x]": "DOTENV_PRIVATE_KEY_PRODUCTION=" + "a" * 64})

    result = _invoke(
        "decrypt", str(env_file), "--verify-vault", "-p", "aws", "--secret", "kv/app[/x]"
    )

    assert result.exception is None or isinstance(result.exception, SystemExit), repr(
        result.exception
    )
    assert "Provider: aws | Secret: kv/app[/x]" in _flat(result.output)


def test_verify_vault_failure_names_the_real_file_and_keeps_dotenvx_s_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The repair commands named ``svc/.env.production`` for ``svc[bold]/.env.production``.

    The vault key cannot decrypt the file. dotenvx's own message, which ends with a
    ``fix: [https://...]`` link, is the one dotenvx 2.38.2 prints for a key that does not
    match: the binary is replaced by that failure, the CLI and the vault flow are real.
    """
    from envdrift.integrations.dotenvx import DotenvxError, DotenvxWrapper

    monkeypatch.chdir(tmp_path)
    folder = tmp_path / "svc[bold]"
    folder.mkdir()
    (folder / ".env.production").write_text(
        'DOTENV_PUBLIC_KEY_PRODUCTION="03abc"\nAPI_TOKEN=encrypted:QUJD\n', encoding="utf-8"
    )
    failure = (
        "dotenvx decryption failed: ○ no change to .env.production (022 86B) via source unknown\n"
        "☠ [DECRYPTION_FAILED] could not decrypt API_TOKEN. "
        "fix: [https://github.com/dotenvx/dotenvx/issues/757]"
    )

    def refuse(*_args, **_kwargs):
        raise DotenvxError(failure)

    monkeypatch.setattr(DotenvxWrapper, "is_installed", lambda _self: True)
    monkeypatch.setattr(DotenvxWrapper, "decrypt", refuse)
    _use_vault(monkeypatch, {"app-key": "DOTENV_PRIVATE_KEY_PRODUCTION=" + "b" * 64})
    shown = Path("svc[bold]") / ".env.production"

    result = _invoke("decrypt", str(shown), "--verify-vault", "-p", "aws", "--secret", "app-key")

    assert result.exit_code == 1, result.output
    out = _flat(result.output)
    assert "Vault key CANNOT decrypt this file!" in out
    assert f"Error: {_flat(failure)}" in out
    assert f"1. Restore the encrypted file: git restore {shown}" in out
    assert f"3. Re-encrypt with the vault key: envdrift encrypt {shown}" in out
