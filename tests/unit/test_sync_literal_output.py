"""sync, pull and lock print secret names, profiles and paths exactly as they are.

Their prompts, headers and per-file rows interpolated names and paths into
Rich markup. ``Console.input`` also parses its prompt as markup and emoji codes
whatever the console's defaults. A secret such as ``kv/app[legacy]/key`` lost
its bracketed segment, and a closing tag such as ``[/x]`` raised
``MarkupError``: the prompt failed the service (pull exited 1), and a header or
a row stopped the command with a traceback.

The commands run for real against a real sync engine and real files; only the
vault and the encryption backend are stand-ins.
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

_LOCAL_KEY = "a" * 64
_VAULT_KEY = "b" * 64


class _Vault:
    """A vault holding ``DOTENV_PRIVATE_KEY_<ENV>=<key>`` secrets."""

    def __init__(self, secrets: dict[str, str]) -> None:
        self._secrets = secrets

    def authenticate(self) -> None:
        return None

    def ensure_authenticated(self) -> None:
        return None

    def is_authenticated(self) -> bool:
        return True

    def get_secret(self, name: str) -> SecretValue:
        if name not in self._secrets:
            raise SecretNotFoundError(f"Secret '{name}' not found")
        return SecretValue(name=name, value=self._secrets[name])


def _write_config(root: Path, mappings: list[dict[str, str]], extra: str = "") -> Path:
    lines = [
        "[vault]",
        'provider = "aws"',
        "",
        "[vault.aws]",
        'region = "us-east-1"',
        "",
        "[vault.sync]",
        'env_keys_filename = ".env.keys"',
        "",
    ]
    for mapping in mappings:
        lines.append("[[vault.sync.mappings]]")
        lines.extend(f"{key} = {json.dumps(value)}" for key, value in mapping.items())
        lines.append("")
    config = root / "envdrift.toml"
    config.write_text("\n".join(lines) + extra, encoding="utf-8")
    return config


def _service(root: Path, folder: str, *, key: str | None = _LOCAL_KEY) -> Path:
    path = root / folder
    path.mkdir(parents=True, exist_ok=True)
    (path / ".env.production").write_text("API_TOKEN=plain-value\n", encoding="utf-8")
    if key is not None:
        (path / ".env.keys").write_text(f"DOTENV_PRIVATE_KEY_PRODUCTION={key}\n", encoding="utf-8")
    return path


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A project directory with a stand-in vault and encryption backend."""
    monkeypatch.chdir(tmp_path)
    backend = DummyEncryptionBackend()

    def use_vault(secrets: dict[str, str]) -> None:
        vault = _Vault(secrets)
        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_a, **_k: vault)

    def use_backend(replacement: DummyEncryptionBackend) -> None:
        monkeypatch.setattr(
            "envdrift.cli_commands.encryption_helpers.resolve_encryption_backend",
            lambda *_a, **_k: (replacement, EncryptionProvider(replacement.name), None),
        )

    use_vault({})
    use_backend(backend)
    return tmp_path, use_vault, use_backend


def _invoke(*args: str, answer: str | None = None):
    return runner.invoke(app, list(args), input=answer, env={"COLUMNS": "250"})


def _flat(text: str) -> str:
    return " ".join(text.split())


def _vault_key(key: str = _VAULT_KEY) -> str:
    return f"DOTENV_PRIVATE_KEY_PRODUCTION={key}"


@pytest.mark.parametrize("command", ["pull", "sync"])
@pytest.mark.parametrize("secret", ["kv/app[legacy]/key", "kv/app[/x]"])
def test_mismatch_prompt_names_the_secret_as_written(project, command: str, secret: str):
    root, use_vault, _ = project
    _service(root, "svc")
    config = _write_config(
        root, [{"secret_name": secret, "folder_path": "svc", "environment": "production"}]
    )
    use_vault({secret: _vault_key()})

    result = _invoke(command, "-c", str(config), answer="n\n")

    assert result.exit_code == 0, result.output
    assert f"Value mismatch for {secret}:" in result.output
    assert "Update local file with vault value? (y/N):" in result.output
    # The row reports the declined update, not an error.
    assert f"= {Path('svc')} ({secret}, env: production) - skipped" in _flat(result.output)
    assert "Unexpected error" not in result.output
    # Declining kept the local key.
    assert _LOCAL_KEY in (root / "svc" / ".env.keys").read_text(encoding="utf-8")


def test_lock_encrypt_prompt_names_the_file_as_written(project) -> None:
    root, _, _ = project
    _service(root, "svc[/x]", key=None)
    config = _write_config(
        root, [{"secret_name": "app-key", "folder_path": "svc[/x]", "environment": "production"}]
    )

    result = _invoke("lock", "-c", str(config), answer="n\n")

    assert result.exit_code == 0, result.output
    env_file = Path("svc[/x]") / ".env.production"
    assert f"Encrypt {env_file}? (y/N):" in result.output
    assert f"= {env_file} - skipped (user declined)" in _flat(result.output)


def test_lock_check_names_a_missing_bracketed_folder(project) -> None:
    root, _, _ = project
    config = _write_config(
        root, [{"secret_name": "app-key", "folder_path": "gone[/x]", "environment": "production"}]
    )

    result = _invoke("lock", "-c", str(config), "--check")

    assert result.exit_code == 1, result.output
    assert isinstance(result.exception, SystemExit), repr(result.exception)
    out = _flat(result.output)
    folder = Path("gone[/x]")
    assert f"! {folder} - error: folder does not exist or is not a directory" in out
    assert f"• {folder}: folder does not exist or is not a directory" in out


@pytest.mark.parametrize(
    ("args", "header"),
    [
        (["sync"], "Vault Sync - Mode: Interactive | Profile: p[/x]"),
        (["pull", "--skip-sync"], "Pull - Decrypting env files (profile: p[/x])"),
        (
            ["lock", "--check"],
            "Lock - Verifying keys and encrypting env files (profile: p[/x])",
        ),
    ],
    ids=["sync", "pull", "lock"],
)
def test_headers_name_the_profile_as_written(project, args: list[str], header: str) -> None:
    root, use_vault, _ = project
    _service(root, "svc")
    config = _write_config(
        root,
        [
            {
                "secret_name": "app-key",
                "folder_path": "svc",
                "environment": "production",
                "profile": "p[/x]",
            }
        ],
    )
    use_vault({"app-key": _vault_key(_LOCAL_KEY)})

    result = _invoke(*args, "-c", str(config), "--profile", "p[/x]")

    assert isinstance(result.exception, SystemExit) or result.exception is None, repr(
        result.exception
    )
    assert header in _flat(result.output)


def test_pull_rows_name_bracketed_paths(project) -> None:
    root, _, _ = project
    _service(root, "svc[bold]")
    config = _write_config(
        root,
        [
            {"secret_name": "a-key", "folder_path": "svc[bold]", "environment": "production"},
            {"secret_name": "b-key", "folder_path": "gone[/x]", "environment": "production"},
        ],
    )

    result = _invoke("pull", "-c", str(config), "--skip-sync")

    assert result.exit_code == 1, result.output
    assert isinstance(result.exception, SystemExit), repr(result.exception)
    out = _flat(result.output)
    assert f"= {Path('svc[bold]') / '.env.production'} - skipped (not encrypted)" in out
    assert f"! {Path('gone[/x]')} - error: folder does not exist or is not a directory" in out


def test_pull_activation_row_names_the_path(project) -> None:
    root, _, _ = project
    _service(root, "svc")
    config = _write_config(
        root,
        [
            {
                "secret_name": "app-key",
                "folder_path": "svc",
                "environment": "production",
                "profile": "dev",
                "activate_to": "act[bold].env",
            }
        ],
    )

    result = _invoke("pull", "-c", str(config), "--skip-sync", "--profile", "dev")

    assert result.exit_code == 0, result.output
    activated = (root / "svc" / "act[bold].env").resolve()
    assert activated.exists()
    assert f"→ {activated} - activated from .env.production" in _flat(result.output)


def test_lock_verify_vault_rows_name_the_folder(project) -> None:
    root, use_vault, _ = project
    _service(root, "svc[/x]")
    config = _write_config(
        root, [{"secret_name": "app-key", "folder_path": "svc[/x]", "environment": "production"}]
    )
    use_vault({"app-key": _vault_key(_LOCAL_KEY)})

    result = _invoke("lock", "-c", str(config), "--verify-vault", "--check")

    assert result.exit_code == 1, result.output
    assert isinstance(result.exception, SystemExit), repr(result.exception)
    out = _flat(result.output)
    assert f"✓ {Path('svc[/x]')} - keys match vault" in out
    assert f"? {Path('svc[/x]') / '.env.production'} - would be encrypted" in out


def test_lock_all_partial_rows_name_the_files(project) -> None:
    root, _, _ = project
    _service(root, "svc")
    config = _write_config(
        root,
        [{"secret_name": "app-key", "folder_path": "svc", "environment": "production"}],
        extra=(
            "\n[partial_encryption]\nenabled = true\n\n"
            "[[partial_encryption.environments]]\n"
            'name = "production"\n'
            'clear_file = "cfg[/x]/.env.production.clear"\n'
            'secret_file = "cfg[/x]/.env.production.secret"\n'
            'combined_file = "cfg[/x]/.env.production"\n'
        ),
    )

    result = _invoke("lock", "-c", str(config), "--all", "--check")

    assert isinstance(result.exception, SystemExit), repr(result.exception)
    secret_file = Path("cfg[/x]/.env.production.secret")
    assert f"= {secret_file} - skipped (not found)" in _flat(result.output)


def test_pull_prints_the_sops_install_instructions_literally(project) -> None:
    """The instructions say to set ``[encryption.sops] auto_install``; the table was dropped."""
    root, _, use_backend = project
    _service(root, "svc")
    config = _write_config(
        root, [{"secret_name": "app-key", "folder_path": "svc", "environment": "production"}]
    )

    class MissingSops(DummyEncryptionBackend):
        def install_instructions(self) -> str:
            return SOPSEncryptionBackend().install_instructions()

    use_backend(MissingSops(name="sops", installed=False))

    result = _invoke("pull", "-c", str(config), "--skip-sync")

    assert result.exit_code == 1, result.output
    assert "Set [encryption.sops] auto_install = true in envdrift.toml" in result.output


def test_pull_error_row_keeps_dotenvx_s_own_link(project) -> None:
    """dotenvx ends a failure with ``fix: [https://...]``; as markup the link vanished."""
    from envdrift.encryption.base import EncryptionBackendError

    root, _, use_backend = project
    service = _service(root, "svc")
    (service / ".env.production").write_text(
        'DOTENV_PUBLIC_KEY_PRODUCTION="03abc"\nAPI_TOKEN=encrypted:QUJD\n', encoding="utf-8"
    )
    message = (
        "[DECRYPTION_FAILED] could not decrypt API_TOKEN. "
        "fix: [https://github.com/dotenvx/dotenvx/issues/757]"
    )
    use_backend(DummyEncryptionBackend(decrypt_side_effect=EncryptionBackendError(message)))
    config = _write_config(
        root, [{"secret_name": "app-key", "folder_path": "svc", "environment": "production"}]
    )

    result = _invoke("pull", "-c", str(config), "--skip-sync")

    assert result.exit_code == 1, result.output
    assert f"! {Path('svc') / '.env.production'} - error: {message}" in _flat(result.output)


# dotenvx 2.38.2's own failure for a value it cannot decrypt, as envdrift wraps it.
_DOTENVX_DECRYPT_FAILURE = (
    "dotenvx decryption failed: ○ no change to {path} (03A BC) via source unknown\n"
    "☠ [DECRYPTION_FAILED] could not decrypt API_TOKEN. "
    "fix: [https://github.com/dotenvx/dotenvx/issues/757]"
)
_DOTENVX_LINK = "fix: [https://github.com/dotenvx/dotenvx/issues/757]"


def _partial_config(root: Path, *, secrets_dir: str, secret_file: str) -> Path:
    combined = secret_file.removesuffix(".secret")
    return _write_config(
        root,
        [{"secret_name": "app-key", "folder_path": "svc", "environment": "production"}],
        extra=(
            "\n[partial_encryption]\nenabled = true\n\n"
            "[[partial_encryption.environments]]\n"
            'name = "only"\nsecrets_only = true\n'
            f"secrets_dir = {json.dumps(secrets_dir)}\n\n"
            "[[partial_encryption.environments]]\n"
            'name = "combined"\n'
            f"clear_file = {json.dumps(combined + '.clear')}\n"
            f"secret_file = {json.dumps(secret_file)}\n"
            f"combined_file = {json.dumps(combined)}\n"
        ),
    )


@pytest.mark.parametrize("folder", ["sec", "sec[/x]"])
def test_pull_partial_rows_print_dotenvx_s_message_as_it_is(
    project, monkeypatch: pytest.MonkeyPatch, folder: str
) -> None:
    """Both step-3 error rows lost dotenvx's link, and a ``[/x]`` path raised MarkupError."""
    from envdrift.core.partial_encryption import PartialEncryptionError

    root, _, _ = project
    _service(root, "svc")
    (root / folder).mkdir(parents=True)
    secret_file = f"{folder}/.env.prod.secret"
    (root / secret_file).write_text("API_TOKEN=encrypted:QUJD\n", encoding="utf-8")
    config = _partial_config(root, secrets_dir=folder, secret_file=secret_file)

    def failing(path: str):
        def fail(*_args, **_kwargs):
            message = _DOTENVX_DECRYPT_FAILURE.format(path=path)
            raise PartialEncryptionError(f"Failed to decrypt {path}: {message}")

        return fail

    monkeypatch.setattr(
        "envdrift.core.partial_encryption.pull_secrets_only", failing(f"{folder}/.env")
    )
    monkeypatch.setattr(
        "envdrift.core.partial_encryption.pull_partial_encryption", failing(secret_file)
    )

    result = _invoke("pull", "-c", str(config), "--skip-sync")

    assert result.exit_code == 1, result.output
    assert isinstance(result.exception, SystemExit), repr(result.exception)
    out = _flat(result.output)
    assert f"! {folder} - error: Failed to decrypt {folder}/.env:" in out
    assert f"! {Path(secret_file)} - error: Failed to decrypt {secret_file}:" in out
    assert out.count(_DOTENVX_LINK) == 4  # two rows, and the two errors listed after
