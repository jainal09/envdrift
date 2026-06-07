"""Helpers for detecting environment files."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

EnvFileStatus = Literal["found", "folder_not_found", "multiple_found", "not_found"]

# Environment a dotenv file belongs to when its name encodes none of its own
# (a plain ``.env`` or ``<prefix>.env``). Mirrors ServiceMapping.effective_environment.
_DEFAULT_ENVIRONMENT = "production"

# Suffixes that mark a file as a non-secret companion (examples, keys), never the
# env file itself. Matched against the full filename, e.g. "service.env.example".
_EXCLUDED_ENV_SUFFIXES = (".example", ".sample", ".template", ".keys")


@dataclass(frozen=True)
class EnvFileDetection:
    """Result of auto-detecting an env file in a folder."""

    path: Path | None
    environment: str | None
    status: EnvFileStatus


def _is_excluded_env_file(name: str) -> bool:
    """Return True for companion files (.example/.sample/.template/.keys)."""
    return any(name.endswith(suffix) for suffix in _EXCLUDED_ENV_SUFFIXES)


def _name_encodes_environment(name: str, environment: str) -> bool:
    """Return True if dotenv file ``name`` belongs to ``environment``.

    Recognizes the conventions where the environment is encoded in the filename:
    - suffix:  ``.env.<env>`` / ``<prefix>.env.<env>``   ("service.env.docker")
    - infix:   ``<prefix>-<env>.env`` / ``.<env>.env`` / ``_<env>.env`` / ``<env>.env``
               ("service-local.env")

    A plain file that encodes no environment of its own (``.env`` or
    ``<prefix>.env``, e.g. "postgresql.env") belongs to the default environment,
    so it matches only when ``environment`` is the default. This keeps an
    environment-specific lookup (e.g. "docker") from grabbing a plain file, and
    avoids relabeling a plain file under a non-default environment.
    """
    # Suffix conventions ".env.<env>"/"<prefix>.env.<env>" and infix forms
    # "<prefix>-<env>.env" / ".<env>.env" / "_<env>.env". ``str.endswith`` accepts
    # a tuple, so all the encoded forms collapse to one check.
    encoded_suffixes = (
        f".env.{environment}",
        f"-{environment}.env",
        f".{environment}.env",
        f"_{environment}.env",
    )
    if name == f"{environment}.env" or name.endswith(encoded_suffixes):
        return True
    # Plain ".env" / "<prefix>.env" carries no encoded environment -> default only.
    return environment == _DEFAULT_ENVIRONMENT and name.endswith(".env")


def _match_env_files_for_environment(folder_path: Path, environment: str) -> list[Path]:
    """Return env files in ``folder_path`` whose name belongs to ``environment``."""
    if not folder_path.is_dir():
        return []
    matches = [
        f
        for f in folder_path.iterdir()
        if f.is_file()
        and not _is_excluded_env_file(f.name)
        and _name_encodes_environment(f.name, environment)
    ]
    return sorted(matches)


def _resolve_lone_env_file(env_file: Path, default_environment: str) -> EnvFileDetection:
    """Resolve a single ``.env.<suffix>`` file against the requested environment.

    Only adopt the suffix's environment when it matches ``default_environment``.
    A single ``.env.staging`` must NOT be claimed by a ``production`` lookup:
    doing so would sync that file under the wrong ``DOTENV_PRIVATE_KEY_<ENV>``
    (see #395). Mismatches report "not_found" so the caller SKIPS rather than
    silently operating on a different environment.
    """
    environment = env_file.name[len(".env.") :]  # .env.soak -> soak
    if environment == default_environment:
        return EnvFileDetection(env_file, environment, "found")
    return EnvFileDetection(None, None, "not_found")


def detect_env_file(folder_path: Path, default_environment: str = "production") -> EnvFileDetection:
    """
    Auto-detect a canonical .env file in a folder.

    Checks for:
    1. Plain .env file (returns default environment)
    2. Single .env.* file, but only when its suffix matches ``default_environment``

    A single ``.env.<suffix>`` whose suffix differs from ``default_environment``
    is *not* adopted: returning it would let a ``production`` lookup sync, say,
    ``.env.staging`` under ``DOTENV_PRIVATE_KEY_STAGING`` (see #395). Such a
    mismatch reports "not_found" so the caller skips instead.

    Custom service-prefixed names (e.g. ``service.env.docker``) are intentionally
    not handled here; that requires the mapping's environment and lives in
    :func:`resolve_mapping_env_file`.

    Returns an EnvFileDetection with status:
    - "found": env file found
    - "folder_not_found": folder doesn't exist (or isn't a directory)
    - "multiple_found": multiple .env.* files exist (ambiguous)
    - "not_found": no env files found (or the only .env.* file is for another env)
    """
    if not folder_path.is_dir():
        return EnvFileDetection(None, None, "folder_not_found")

    # First, check for plain .env file (takes precedence over any .env.* file)
    plain_env = folder_path / ".env"
    if plain_env.is_file():
        return EnvFileDetection(plain_env, default_environment, "found")

    env_files = [
        f
        for f in folder_path.iterdir()
        if f.is_file() and f.name.startswith(".env.") and not _is_excluded_env_file(f.name)
    ]

    if len(env_files) == 1:
        return _resolve_lone_env_file(env_files[0], default_environment)

    if len(env_files) > 1:
        return EnvFileDetection(None, None, "multiple_found")

    return EnvFileDetection(None, None, "not_found")


def resolve_custom_env_file(folder_path: Path, env_file: Path | str) -> Path:
    """Resolve a configured env filename under a service folder.

    The ``env_file`` setting is intentionally scoped to ``folder_path`` so a sync
    mapping cannot read or mutate an unrelated path via ``..`` or an absolute path.
    """
    env_file_path = Path(env_file)
    if env_file_path.is_absolute():
        raise ValueError("env_file must be relative to folder_path")
    if ".." in env_file_path.parts:
        raise ValueError("env_file must not contain '..'")

    resolved_folder = folder_path.resolve()
    resolved_file = (folder_path / env_file_path).resolve()
    try:
        resolved_file.relative_to(resolved_folder)
    except ValueError as e:
        raise ValueError("env_file must stay inside folder_path") from e

    return folder_path / env_file_path


def _resolve_explicit_env_file(
    folder_path: Path, env_file: Any, environment: str
) -> EnvFileDetection:
    """Resolve an explicitly-configured ``mapping.env_file`` under ``folder_path``.

    Returns "folder_not_found" when the folder is missing, "found" when the
    configured file exists, else "not_found" (the path is still surfaced so the
    caller can report where it looked).
    """
    if not folder_path.exists():
        return EnvFileDetection(None, environment, "folder_not_found")
    resolved = resolve_custom_env_file(folder_path, env_file)
    if resolved.exists() and resolved.is_file():
        return EnvFileDetection(resolved, environment, "found")
    return EnvFileDetection(resolved, environment, "not_found")


def resolve_mapping_env_file(mapping: Any) -> EnvFileDetection:
    """Resolve the env file for a sync mapping.

    Resolution order:
    1. Explicit ``mapping.env_file`` relative to ``mapping.folder_path``.
    2. Exact ``.env.<effective_environment>``.
    3. A custom-named file that belongs to the environment, such as
       ``service.env.<env>`` or ``service-<env>.env`` (and, for a default
       environment, a plain ``service.env``).
    4. Legacy auto-detection for a plain ``.env`` (default env) or a single
       ``.env.<effective_environment>`` file. A lone ``.env.*`` for a *different*
       environment is not adopted, so the mapping is skipped rather than synced
       under the wrong key (see #395).

    Custom filenames matched via steps 2-3 keep ``mapping.effective_environment``
    as the environment of record. This preserves canonical vault key names even
    when the dotenv filename uses a service-specific convention.
    """
    folder_path = Path(mapping.folder_path)
    effective_environment = mapping.effective_environment
    env_file = getattr(mapping, "env_file", None)

    if env_file is not None:
        return _resolve_explicit_env_file(folder_path, env_file, effective_environment)

    exact_env = folder_path / f".env.{effective_environment}"
    if exact_env.exists() and exact_env.is_file():
        return EnvFileDetection(exact_env, effective_environment, "found")

    # Match custom-named files that encode this environment (e.g.
    # "service.env.docker" or "service-local.env"). The configured environment
    # stays canonical so vault/dotenvx key names remain config-driven.
    env_matches = _match_env_files_for_environment(folder_path, effective_environment)
    if len(env_matches) == 1:
        return EnvFileDetection(env_matches[0], effective_environment, "found")
    if len(env_matches) > 1:
        return EnvFileDetection(None, effective_environment, "multiple_found")

    return detect_env_file(folder_path, effective_environment)
