"""Coverage-focused tests for envdrift.cli_commands.encryption.

These target previously-uncovered branches: config-loading error handling,
schema-load failures, SOPS encrypt kwargs, encrypt/decrypt failure paths,
and vault-verification edge cases.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.cli_commands.encryption import (
    _load_encryption_config,
    _resolve_config_path,
    _verify_decryption_with_vault,
)
from envdrift.config import ConfigNotFoundError, EncryptionConfig, EnvdriftConfig
from envdrift.core.schema import SchemaLoadError
from envdrift.encryption.base import (
    EncryptionNotFoundError,
    EncryptionResult,
)
from envdrift.integrations.dotenvx import DotenvxError
from tests.helpers import DummyEncryptionBackend

runner = CliRunner()

ENC_MOD = "envdrift.cli_commands.encryption"


def _no_hook_errors(monkeypatch):
    """Patch the git-hook check so command flow continues uninterrupted."""
    monkeypatch.setattr(
        "envdrift.integrations.hook_check.ensure_git_hook_setup",
        lambda *a, **k: [],
    )


# --------------------------------------------------------------------------
# _load_encryption_config  (lines 43-44)
# --------------------------------------------------------------------------


def test_load_encryption_config_handles_config_not_found(monkeypatch, tmp_path: Path):
    """A ConfigNotFoundError during load should warn and return defaults."""
    cfg_path = tmp_path / "envdrift.toml"
    cfg_path.write_text("[encryption]\n")

    warnings: list[str] = []
    monkeypatch.setattr(f"{ENC_MOD}.print_warning", lambda msg: warnings.append(str(msg)))
    monkeypatch.setattr("envdrift.config.find_config", lambda *a, **k: cfg_path)

    def _raise(_path):
        raise ConfigNotFoundError("no config here")

    monkeypatch.setattr("envdrift.config.load_config", _raise)

    config, returned_path = _load_encryption_config()

    assert isinstance(config, EnvdriftConfig)
    assert returned_path is None
    assert any("no config here" in w for w in warnings)


def test_load_encryption_config_no_config_file(monkeypatch):
    """When no config file is found, defaults are returned without warnings."""
    monkeypatch.setattr("envdrift.config.find_config", lambda *a, **k: None)

    config, returned_path = _load_encryption_config()

    assert isinstance(config, EnvdriftConfig)
    assert returned_path is None


# --------------------------------------------------------------------------
# _resolve_config_path  (line 56)
# --------------------------------------------------------------------------


def test_resolve_config_path_absolute_value_returned_as_is(tmp_path: Path):
    """An absolute value should be returned untouched even with a config_path."""
    config_path = tmp_path / "envdrift.toml"
    abs_value = (tmp_path / "keys" / "age.key").resolve()

    result = _resolve_config_path(config_path, abs_value)

    assert result == abs_value


def test_resolve_config_path_no_config_path_returns_plain_path(tmp_path: Path):
    """Without a config_path the value is wrapped in a Path and returned."""
    rel = "secrets/age.key"
    result = _resolve_config_path(None, rel)

    assert result == Path(rel)


def test_resolve_config_path_none_value_returns_none(tmp_path: Path):
    """A falsy value yields None."""
    assert _resolve_config_path(tmp_path, None) is None


# --------------------------------------------------------------------------
# encrypt_cmd: schema loading failure (lines 213-218)
# --------------------------------------------------------------------------


def test_encrypt_check_schema_load_error_warns(monkeypatch, tmp_path: Path):
    """A SchemaLoadError while loading the schema should warn and continue."""
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=plain-secret-value\n")

    _no_hook_errors(monkeypatch)
    monkeypatch.setattr(f"{ENC_MOD}._load_encryption_config", lambda: (EnvdriftConfig(), None))

    class FailingLoader:
        def load(self, _schema, _service_dir):
            raise SchemaLoadError("cannot import settings")

        def extract_metadata(self, _cls):  # pragma: no cover - not reached
            return None

    monkeypatch.setattr(f"{ENC_MOD}.SchemaLoader", FailingLoader)

    result = runner.invoke(
        app,
        ["encrypt", str(env_file), "--check", "--schema", "app.settings:Settings"],
    )

    # Continues despite schema failure (exit may be 0 or 1 from block decision).
    assert "Could not load schema" in result.output


def test_encrypt_check_schema_load_success(monkeypatch, tmp_path: Path):
    """A successful schema load reaches extract_metadata (lines 215-216)."""
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=plain-secret-value\n")

    _no_hook_errors(monkeypatch)
    monkeypatch.setattr(f"{ENC_MOD}._load_encryption_config", lambda: (EnvdriftConfig(), None))

    calls: dict[str, Any] = {}

    class OkLoader:
        def load(self, schema, service_dir):
            calls["load"] = (schema, service_dir)
            return object()

        def extract_metadata(self, cls):
            calls["extract"] = cls
            return None

    monkeypatch.setattr(f"{ENC_MOD}.SchemaLoader", OkLoader)

    runner.invoke(
        app,
        ["encrypt", str(env_file), "--check", "--schema", "app.settings:Settings"],
    )

    assert calls["load"] == ("app.settings:Settings", None)
    assert "extract" in calls


# --------------------------------------------------------------------------
# encrypt_cmd: SOPS encrypt kwargs (lines 266, 268, 270) + result failure
# --------------------------------------------------------------------------


def _sops_config() -> EnvdriftConfig:
    return EnvdriftConfig(
        encryption=EncryptionConfig(
            backend="sops",
            sops_kms_arn="arn:aws:kms:us-east-1:111:key/abc",
            sops_gcp_kms="projects/p/locations/l/keyRings/r/cryptoKeys/k",
            sops_azure_kv="https://kv.vault.azure.net/keys/k/v",
        )
    )


def test_encrypt_sops_passes_all_kms_kwargs(monkeypatch, tmp_path: Path):
    """SOPS backend forwards kms_arn, gcp_kms and azure_kv from config."""
    env_file = tmp_path / ".env.production"
    env_file.write_text("API_KEY=plain\n")

    _no_hook_errors(monkeypatch)
    monkeypatch.setattr(
        f"{ENC_MOD}._load_encryption_config",
        lambda: (_sops_config(), None),
    )

    dummy = DummyEncryptionBackend(name="sops")
    monkeypatch.setattr(
        f"{ENC_MOD}.get_encryption_backend",
        lambda *a, **k: dummy,
    )

    result = runner.invoke(app, ["encrypt", str(env_file), "--backend", "sops"])

    assert result.exit_code == 0
    assert dummy.encrypt_kwargs, "encrypt should have been called"
    kwargs = dummy.encrypt_kwargs[0]
    assert kwargs["kms_arn"] == "arn:aws:kms:us-east-1:111:key/abc"
    assert kwargs["gcp_kms"] == "projects/p/locations/l/keyRings/r/cryptoKeys/k"
    assert kwargs["azure_kv"] == "https://kv.vault.azure.net/keys/k/v"


def test_encrypt_result_failure_exits_nonzero(monkeypatch, tmp_path: Path):
    """A non-success EncryptionResult prints the message and exits 1 (289-290)."""
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=plain\n")

    _no_hook_errors(monkeypatch)
    monkeypatch.setattr(f"{ENC_MOD}._load_encryption_config", lambda: (EnvdriftConfig(), None))

    class FailingBackend(DummyEncryptionBackend):
        def encrypt(self, env_file, **kwargs):  # type: ignore[override]
            return EncryptionResult(
                success=False, message="boom-encrypt-failed", file_path=Path(env_file)
            )

    monkeypatch.setattr(
        f"{ENC_MOD}.get_encryption_backend",
        lambda *a, **k: FailingBackend(),
    )

    result = runner.invoke(app, ["encrypt", str(env_file)])

    assert result.exit_code == 1
    assert "boom-encrypt-failed" in result.output


def test_encrypt_not_found_error_exits_nonzero(monkeypatch, tmp_path: Path):
    """EncryptionNotFoundError raised during encryption exits 1 (293-294)."""
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=plain\n")

    _no_hook_errors(monkeypatch)
    monkeypatch.setattr(f"{ENC_MOD}._load_encryption_config", lambda: (EnvdriftConfig(), None))

    class MissingToolBackend(DummyEncryptionBackend):
        def encrypt(self, env_file, **kwargs):  # type: ignore[override]
            raise EncryptionNotFoundError("dotenvx binary missing")

    monkeypatch.setattr(
        f"{ENC_MOD}.get_encryption_backend",
        lambda *a, **k: MissingToolBackend(),
    )

    result = runner.invoke(app, ["encrypt", str(env_file)])

    assert result.exit_code == 1
    assert "dotenvx binary missing" in result.output


# --------------------------------------------------------------------------
# _verify_decryption_with_vault edge cases
# --------------------------------------------------------------------------


class _Vault:
    def __init__(self, secret):
        self._secret = secret

    def ensure_authenticated(self) -> None:
        return None

    def get_secret(self, name: str):
        return self._secret


def test_verify_vault_hashicorp_passes_url(monkeypatch, tmp_path: Path):
    """HashiCorp provider forwards url kwarg to the vault client (line 344)."""
    env_file = tmp_path / ".env.production"
    env_file.write_text("SECRET=encrypted")

    captured: dict[str, Any] = {}

    def fake_get_vault_client(provider, **kwargs):
        captured["provider"] = provider
        captured["kwargs"] = kwargs
        return _Vault(SimpleNamespace(value="DOTENV_PRIVATE_KEY_PRODUCTION=vault-key"))

    monkeypatch.setattr("envdrift.vault.get_vault_client", fake_get_vault_client)
    monkeypatch.setattr(
        "envdrift.integrations.dotenvx.DotenvxWrapper.is_installed",
        lambda self: True,
    )
    monkeypatch.setattr(
        "envdrift.integrations.dotenvx.DotenvxWrapper.decrypt",
        lambda *_, **__: None,
    )

    result = _verify_decryption_with_vault(
        env_file=env_file,
        provider="hashicorp",
        vault_url="https://vault.example.com:8200",
        region=None,
        project_id=None,
        secret_name="dotenv-key",
        ci=True,
    )

    assert result is True
    assert captured["provider"] == "hashicorp"
    assert captured["kwargs"]["url"] == "https://vault.example.com:8200"


def test_verify_vault_empty_secret_returns_false(monkeypatch, tmp_path: Path):
    """An empty SecretValue.value should report the secret as empty (358-359)."""
    env_file = tmp_path / ".env.production"
    env_file.write_text("SECRET=encrypted")

    monkeypatch.setattr(
        "envdrift.vault.get_vault_client",
        lambda *_, **__: _Vault(SimpleNamespace(value="")),
    )

    errors: list[str] = []
    monkeypatch.setattr(f"{ENC_MOD}.print_error", lambda msg: errors.append(str(msg)))

    result = _verify_decryption_with_vault(
        env_file=env_file,
        provider="aws",
        vault_url=None,
        region="us-east-1",
        project_id=None,
        secret_name="missing-key",
        ci=True,
    )

    assert result is False
    assert any("is empty in vault" in e for e in errors)


def test_verify_vault_non_str_secret_is_stringified(monkeypatch, tmp_path: Path):
    """A secret without .value that is not a str is coerced via str() (line 368)."""
    env_file = tmp_path / ".env.production"
    env_file.write_text("SECRET=encrypted")

    class RawSecret:
        """Truthy object with no .value attribute and a str() override."""

        def __str__(self) -> str:
            return "DOTENV_PRIVATE_KEY_PRODUCTION=coerced-key"

        def __bool__(self) -> bool:
            return True

    monkeypatch.setattr(
        "envdrift.vault.get_vault_client",
        lambda *_, **__: _Vault(RawSecret()),
    )
    monkeypatch.setattr(
        "envdrift.integrations.dotenvx.DotenvxWrapper.is_installed",
        lambda self: True,
    )

    captured: dict[str, Any] = {}

    def fake_decrypt(self, env_path, env_keys_file=None, env=None, cwd=None):
        captured["env"] = env

    monkeypatch.setattr(
        "envdrift.integrations.dotenvx.DotenvxWrapper.decrypt",
        fake_decrypt,
    )

    result = _verify_decryption_with_vault(
        env_file=env_file,
        provider="aws",
        vault_url=None,
        region="us-east-1",
        project_id=None,
        secret_name="raw-key",
        ci=True,
    )

    assert result is True
    assert captured["env"]["DOTENV_PRIVATE_KEY_PRODUCTION"] == "coerced-key"


def test_verify_vault_dotenvx_not_installed_returns_false(monkeypatch, tmp_path: Path):
    """If dotenvx is not installed verification cannot proceed (381-382)."""
    env_file = tmp_path / ".env.production"
    env_file.write_text("SECRET=encrypted")

    monkeypatch.setattr(
        "envdrift.vault.get_vault_client",
        lambda *_, **__: _Vault(SimpleNamespace(value="DOTENV_PRIVATE_KEY_PRODUCTION=k")),
    )
    monkeypatch.setattr(
        "envdrift.integrations.dotenvx.DotenvxWrapper.is_installed",
        lambda self: False,
    )

    errors: list[str] = []
    monkeypatch.setattr(f"{ENC_MOD}.print_error", lambda msg: errors.append(str(msg)))

    result = _verify_decryption_with_vault(
        env_file=env_file,
        provider="aws",
        vault_url=None,
        region="us-east-1",
        project_id=None,
        secret_name="dotenv-key",
        ci=True,
    )

    assert result is False
    assert any("dotenvx is not installed" in e for e in errors)


def test_verify_vault_raw_key_env_starting_with_underscore(monkeypatch, tmp_path: Path):
    """A .env.production filename yields PRODUCTION key var (covers 394-396 path)."""
    # ".env.production".stem == ".env" -> replace(".env","") then replace "." -> "production".
    # Use a leading-dot derived name to exercise the startswith("_") strip on line 396.
    env_file = tmp_path / ".env..local"
    env_file.write_text("SECRET=encrypted")

    monkeypatch.setattr(
        "envdrift.vault.get_vault_client",
        lambda *_, **__: _Vault("rawkeyvalue"),
    )
    monkeypatch.setattr(
        "envdrift.integrations.dotenvx.DotenvxWrapper.is_installed",
        lambda self: True,
    )

    captured: dict[str, Any] = {}

    def fake_decrypt(self, env_path, env_keys_file=None, env=None, cwd=None):
        captured["env"] = env

    monkeypatch.setattr(
        "envdrift.integrations.dotenvx.DotenvxWrapper.decrypt",
        fake_decrypt,
    )

    result = _verify_decryption_with_vault(
        env_file=env_file,
        provider="aws",
        vault_url=None,
        region="us-east-1",
        project_id=None,
        secret_name="raw-key",
        ci=True,
    )

    assert result is True
    # Exactly one DOTENV_PRIVATE_KEY_* var should be present, no leading underscore.
    key_vars = [k for k in captured["env"] if k.startswith("DOTENV_PRIVATE_KEY_")]
    assert len(key_vars) == 1
    suffix = key_vars[0][len("DOTENV_PRIVATE_KEY_") :]
    assert not suffix.startswith("_")


def test_verify_vault_failure_includes_region(monkeypatch, tmp_path: Path):
    """AWS failure guidance includes the --region flag (line 442)."""
    env_file = tmp_path / ".env.production"
    env_file.write_text("SECRET=encrypted")

    monkeypatch.setattr(
        "envdrift.vault.get_vault_client",
        lambda *_, **__: _Vault(SimpleNamespace(value="DOTENV_PRIVATE_KEY_PRODUCTION=vault-key")),
    )
    monkeypatch.setattr(
        "envdrift.integrations.dotenvx.DotenvxWrapper.is_installed",
        lambda self: True,
    )
    monkeypatch.setattr(
        "envdrift.integrations.dotenvx.DotenvxWrapper.decrypt",
        lambda *_, **__: (_ for _ in ()).throw(DotenvxError("bad key")),
    )

    printed: list[str] = []
    monkeypatch.setattr(
        "envdrift.output.rich.console.print",
        lambda msg="", *a, **k: printed.append(str(msg)),
    )

    result = _verify_decryption_with_vault(
        env_file=env_file,
        provider="aws",
        vault_url=None,
        region="eu-west-1",
        project_id=None,
        secret_name="dotenv-key",
        ci=True,
    )

    assert result is False
    assert "--region eu-west-1" in " ".join(printed)


def test_verify_vault_secret_not_found(monkeypatch, tmp_path: Path):
    """SecretNotFoundError yields a clear error and False (450-452)."""
    from envdrift.vault.base import SecretNotFoundError

    env_file = tmp_path / ".env.production"
    env_file.write_text("SECRET=encrypted")

    class MissingVault:
        def ensure_authenticated(self) -> None:
            return None

        def get_secret(self, name: str):
            raise SecretNotFoundError("nope")

    monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: MissingVault())

    errors: list[str] = []
    monkeypatch.setattr(f"{ENC_MOD}.print_error", lambda msg: errors.append(str(msg)))

    result = _verify_decryption_with_vault(
        env_file=env_file,
        provider="aws",
        vault_url=None,
        region="us-east-1",
        project_id=None,
        secret_name="dotenv-key",
        ci=True,
    )

    assert result is False
    assert any("not found in vault" in e for e in errors)


def test_verify_vault_vault_error(monkeypatch, tmp_path: Path):
    """A generic VaultError is reported and returns False (453-455)."""
    from envdrift.vault.base import VaultError

    env_file = tmp_path / ".env.production"
    env_file.write_text("SECRET=encrypted")

    class BrokenVault:
        def ensure_authenticated(self) -> None:
            raise VaultError("auth failed")

        def get_secret(self, name: str):  # pragma: no cover - not reached
            return None

    monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: BrokenVault())

    errors: list[str] = []
    monkeypatch.setattr(f"{ENC_MOD}.print_error", lambda msg: errors.append(str(msg)))

    result = _verify_decryption_with_vault(
        env_file=env_file,
        provider="aws",
        vault_url=None,
        region="us-east-1",
        project_id=None,
        secret_name="dotenv-key",
        ci=True,
    )

    assert result is False
    assert any("Vault error" in e for e in errors)


def test_verify_vault_import_error(monkeypatch, tmp_path: Path):
    """An ImportError from the vault layer is handled (456-458)."""
    env_file = tmp_path / ".env.production"
    env_file.write_text("SECRET=encrypted")

    def _raise(*_a, **_k):
        raise ImportError("missing sdk")

    monkeypatch.setattr("envdrift.vault.get_vault_client", _raise)

    errors: list[str] = []
    monkeypatch.setattr(f"{ENC_MOD}.print_error", lambda msg: errors.append(str(msg)))

    result = _verify_decryption_with_vault(
        env_file=env_file,
        provider="aws",
        vault_url=None,
        region="us-east-1",
        project_id=None,
        secret_name="dotenv-key",
        ci=True,
    )

    assert result is False
    assert any("Import error" in e for e in errors)


def test_verify_vault_unexpected_error(monkeypatch, tmp_path: Path):
    """An unexpected exception is logged and returns False (459-465)."""
    env_file = tmp_path / ".env.production"
    env_file.write_text("SECRET=encrypted")

    def _raise(*_a, **_k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr("envdrift.vault.get_vault_client", _raise)

    errors: list[str] = []
    monkeypatch.setattr(f"{ENC_MOD}.print_error", lambda msg: errors.append(str(msg)))

    result = _verify_decryption_with_vault(
        env_file=env_file,
        provider="aws",
        vault_url=None,
        region="us-east-1",
        project_id=None,
        secret_name="dotenv-key",
        ci=True,
    )

    assert result is False
    assert any("Unexpected error during vault verification" in e for e in errors)


# --------------------------------------------------------------------------
# decrypt_cmd: verify-vault validation + decrypt failures
# --------------------------------------------------------------------------


def test_decrypt_verify_vault_azure_requires_url(monkeypatch, tmp_path: Path):
    """Azure verify-vault without --vault-url exits 1 (604-605)."""
    env_file = tmp_path / ".env.production"
    env_file.write_text("SECRET=encrypted")

    _no_hook_errors(monkeypatch)
    monkeypatch.setattr(f"{ENC_MOD}._load_encryption_config", lambda: (EnvdriftConfig(), None))

    result = runner.invoke(
        app,
        [
            "decrypt",
            str(env_file),
            "--backend",
            "dotenvx",
            "--verify-vault",
            "--provider",
            "azure",
            "--secret",
            "dotenv-key",
        ],
    )

    assert result.exit_code == 1
    assert "requires --vault-url" in result.output


def test_decrypt_verify_vault_failure_exits_nonzero(monkeypatch, tmp_path: Path):
    """When vault verification fails, decrypt exits 1 (line 621)."""
    env_file = tmp_path / ".env.production"
    env_file.write_text("SECRET=encrypted")

    _no_hook_errors(monkeypatch)
    monkeypatch.setattr(f"{ENC_MOD}._load_encryption_config", lambda: (EnvdriftConfig(), None))
    monkeypatch.setattr(
        f"{ENC_MOD}._verify_decryption_with_vault",
        lambda *a, **k: False,
    )

    result = runner.invoke(
        app,
        [
            "decrypt",
            str(env_file),
            "--backend",
            "dotenvx",
            "--verify-vault",
            "--provider",
            "aws",
            "--secret",
            "dotenv-key",
        ],
    )

    assert result.exit_code == 1


def test_decrypt_result_failure_exits_nonzero(monkeypatch, tmp_path: Path):
    """A non-success decrypt result prints message and exits 1 (651-652)."""
    env_file = tmp_path / ".env"
    env_file.write_text('SECRET="encrypted:abc"\n')

    _no_hook_errors(monkeypatch)
    monkeypatch.setattr(f"{ENC_MOD}._load_encryption_config", lambda: (EnvdriftConfig(), None))

    class FailingBackend(DummyEncryptionBackend):
        def decrypt(self, env_file, **kwargs):  # type: ignore[override]
            return EncryptionResult(
                success=False, message="boom-decrypt-failed", file_path=Path(env_file)
            )

    monkeypatch.setattr(
        f"{ENC_MOD}.get_encryption_backend",
        lambda *a, **k: FailingBackend(),
    )

    result = runner.invoke(app, ["decrypt", str(env_file), "--backend", "dotenvx"])

    assert result.exit_code == 1
    assert "boom-decrypt-failed" in result.output


def test_decrypt_not_found_error_exits_nonzero(monkeypatch, tmp_path: Path):
    """EncryptionNotFoundError during decrypt exits 1 (655-656)."""
    env_file = tmp_path / ".env"
    env_file.write_text('SECRET="encrypted:abc"\n')

    _no_hook_errors(monkeypatch)
    monkeypatch.setattr(f"{ENC_MOD}._load_encryption_config", lambda: (EnvdriftConfig(), None))

    class MissingToolBackend(DummyEncryptionBackend):
        def decrypt(self, env_file, **kwargs):  # type: ignore[override]
            raise EncryptionNotFoundError("dotenvx binary missing")

    monkeypatch.setattr(
        f"{ENC_MOD}.get_encryption_backend",
        lambda *a, **k: MissingToolBackend(),
    )

    result = runner.invoke(app, ["decrypt", str(env_file), "--backend", "dotenvx"])

    assert result.exit_code == 1
    assert "dotenvx binary missing" in result.output


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
