"""Read the key vault-push publishes and install the key vault-pull fetches.

Each refuses rather than guesses. vault-push does not publish one of two
different values under a key name, or a key the env file is not encrypted
with (#938, #943). vault-pull does not replace a different local key unless
``--force`` asks it to, and then only after a backup (#939).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Never

import typer

from envdrift.output.rich import console, print_error, print_warning
from envdrift.utils.text import styled_text

if TYPE_CHECKING:
    from .vault_helpers import VaultPullRequest, _BulkPushContext, _PushTarget


def push_key_problem(
    context: _BulkPushContext, target: _PushTarget, key_value: str, values: list[str]
) -> str | None:
    """Why ``key_value`` must not be published for ``target``, or None.

    ``values`` are every value the keys file holds under the key name: dotenvx
    may have used any of them, so two different ones are refused.
    """
    others = set(values) - {key_value}
    if others:
        return (
            f"{target.mapping.folder_path} holds {len(others) + 1} different values for "
            f"DOTENV_PRIVATE_KEY_{target.environment.upper()}; keep the one the file is "
            f"encrypted with and delete the other"
        )
    return _unmatched_push_key(context, target, key_value)


def _unmatched_push_key(
    context: _BulkPushContext, target: _PushTarget, key_value: str
) -> str | None:
    """Why the dotenvx file cannot be decrypted with ``key_value``, or None.

    The key must be one key dotenvx can use, and the file's public key must be
    its key's, as ``lock`` requires of the key it holds for a file.
    """
    from envdrift.encryption import EncryptionProvider
    from envdrift.integrations.dotenvx_keys import held_values_problem, unverifiable_ciphertext

    if context.backend_provider != EncryptionProvider.DOTENVX:
        return None
    env_file = target.env_file
    env_text = env_file.read_bytes().decode("utf-8") if env_file.is_file() else ""
    key_name = f"DOTENV_PRIVATE_KEY_{target.environment.upper()}"
    problem = held_values_problem(env_text, [key_value], key_name)
    if problem is not None:
        return f"{problem}, so the vault copy could not decrypt {env_file}"
    if unverifiable_ciphertext(env_text):
        return (
            f"{env_file} holds encrypted values but no DOTENV_PUBLIC_KEY, so {key_name} "
            f"cannot be checked against them; restore the file's header and push again"
        )
    return None


def read_push_key(env_keys_path: Path, key_name: str) -> str:
    """Read one required key with clean filesystem and missing-key errors.

    dotenvx loads every value of a repeated name, so publishing the first of
    two different ones could hand the team a key the files were not encrypted
    with (#938): that is refused.
    """
    from envdrift.sync.operations import EnvKeysFile

    if not env_keys_path.exists():
        print_error(f"File not found: {env_keys_path}")
        raise typer.Exit(code=1)
    try:
        values = EnvKeysFile(env_keys_path).read_values(key_name)
    except (OSError, ValueError) as e:
        print_error(f"Cannot read {env_keys_path}: {e}")
        raise typer.Exit(code=1) from None
    if not values or not values[0]:
        print_error(f"Key '{key_name}' not found in {env_keys_path}")
        raise typer.Exit(code=1)
    _refuse_ambiguous_push_key(env_keys_path, key_name, len(set(values)))
    return values[0]


def _refuse_ambiguous_push_key(env_keys_path: Path, key_name: str, distinct: int) -> None:
    """Stop when the keys file holds ``distinct`` > 1 values for ``key_name``."""
    if distinct > 1:
        print_error(
            f"{env_keys_path} holds {distinct} different values for '{key_name}'; "
            f"keep the one your files are encrypted with and delete the other. Nothing was pushed."
        )
        raise typer.Exit(code=1)


def _held_pull_values(env_keys_path: Path, key_name: str) -> list[str]:
    """Every value ``.env.keys`` holds under ``key_name``, exiting cleanly on a bad file."""
    from envdrift.sync.operations import EnvKeysFile

    try:
        return EnvKeysFile(env_keys_path).read_values(key_name)
    except (OSError, ValueError) as e:
        print_error(f"Cannot write {env_keys_path}: cannot read the existing keys file ({e})")
        raise typer.Exit(code=1) from None


def _refuse_pull_overwrite(env_keys_path: Path, key_name: str) -> Never:
    """Stop before a different local key would be replaced (#939)."""
    print_error(
        f"{env_keys_path} already holds a different {key_name}. vault-pull would replace "
        f"it with the vault's key, and anything encrypted with the local key could not be "
        f"decrypted any more. Nothing was changed."
    )
    console.print(
        styled_text(
            "  Push the local key first (envdrift vault-push), or re-run with --force to "
            "replace it; --force backs up {} before writing.",
            env_keys_path.name,
        )
    )
    raise typer.Exit(code=1)


def _backup_pull_keys(env_keys_path: Path) -> Path:
    """Back up ``.env.keys`` (gitignored) before a forced replacement."""
    from envdrift.sync.operations import EnvKeysFile

    try:
        return EnvKeysFile(env_keys_path).create_backup()
    except OSError as e:
        print_error(f"Cannot back up {env_keys_path}: {e}. Nothing was changed.")
        raise typer.Exit(code=1) from None


def write_pull_key(request: VaultPullRequest, key_name: str, key_value: str) -> Path | None:
    """Install fetched key material without destroying a different local key.

    Every value ``.env.keys`` already holds under ``key_name`` is compared with
    the vault's key, because ``write_key`` rewrites all of them: a matching
    first line must not hide a second, different key (#939). A different key
    is replaced only with ``--force``, after a backup. Returns ``None`` when
    the key was already there (nothing written).
    """
    from envdrift.sync.operations import EnvKeysFile

    env_keys_path = request.folder / ".env.keys"
    keys = EnvKeysFile(env_keys_path)
    held = _held_pull_values(env_keys_path, key_name)
    if set(held) == {key_value}:
        return None
    backup = None
    try:
        # A key that cannot be written needs no backup: check it first.
        keys.require_readable_value(key_name, key_value)
        if held:
            if not request.force:
                _refuse_pull_overwrite(env_keys_path, key_name)
            backup = _backup_pull_keys(env_keys_path)
        keys.write_key(key_name, key_value, environment=request.environment, expected=held)
    except (OSError, ValueError) as e:
        kept = f" The backup {backup} was kept." if backup else ""
        print_error(f"Cannot write {env_keys_path}: {e}{kept}")
        raise typer.Exit(code=1) from None
    if backup:
        print_warning(f"Replaced the local {env_keys_path.name} key; backup: {backup}")
    return env_keys_path
