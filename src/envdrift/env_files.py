"""Helpers for detecting environment files."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

EnvFileStatus = Literal["found", "folder_not_found", "multiple_found", "not_found"]


@dataclass(frozen=True)
class EnvFileDetection:
    """Result of auto-detecting an env file in a folder."""

    path: Path | None
    environment: str | None
    status: EnvFileStatus


def detect_env_file(folder_path: Path, default_environment: str = "production") -> EnvFileDetection:
    """
    Auto-detect .env file in a folder.

    Checks for:
    1. Plain .env file (returns default environment)
    2. Single .env.* file (returns environment from suffix)

    Returns an EnvFileDetection with status:
    - "found": env file found
    - "folder_not_found": folder doesn't exist
    - "multiple_found": multiple .env.* files exist (ambiguous)
    - "not_found": no env files found
    """
    if not folder_path.exists():
        return EnvFileDetection(None, None, "folder_not_found")

    # First, check for plain .env file
    plain_env = folder_path / ".env"
    if plain_env.exists() and plain_env.is_file():
        return EnvFileDetection(plain_env, default_environment, "found")

    # Find all .env.* files, excluding special files
    exclude_patterns = {".env.keys", ".env.example", ".env.sample", ".env.template"}
    env_files = []

    for f in folder_path.iterdir():
        if f.is_file() and f.name.startswith(".env.") and f.name not in exclude_patterns:
            env_files.append(f)

    if len(env_files) == 1:
        env_file = env_files[0]
        # Extract environment from filename: .env.soak -> soak
        environment = env_file.name[5:]  # Remove ".env." prefix
        return EnvFileDetection(env_file, environment, "found")

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

    resolved_folder = folder_path.resolve()
    resolved_file = (folder_path / env_file_path).resolve()
    try:
        resolved_file.relative_to(resolved_folder)
    except ValueError as e:
        raise ValueError("env_file must stay inside folder_path") from e

    return folder_path / env_file_path


def resolve_mapping_env_file(mapping: Any) -> EnvFileDetection:
    """Resolve the env file for a sync mapping.

    Resolution order:
    1. Explicit ``mapping.env_file`` relative to ``mapping.folder_path``.
    2. Exact ``.env.<effective_environment>``.
    3. Existing legacy auto-detection for ``.env`` or a single ``.env.*`` file.

    Explicit custom filenames keep ``mapping.effective_environment`` as the
    environment of record. This preserves canonical vault key names even when
    the dotenv filename uses a service-specific convention.
    """
    folder_path = Path(mapping.folder_path)
    effective_environment = mapping.effective_environment
    env_file = getattr(mapping, "env_file", None)

    if env_file is not None:
        if not folder_path.exists():
            return EnvFileDetection(None, effective_environment, "folder_not_found")

        resolved = resolve_custom_env_file(folder_path, env_file)
        if resolved.exists() and resolved.is_file():
            return EnvFileDetection(resolved, effective_environment, "found")
        return EnvFileDetection(resolved, effective_environment, "not_found")

    exact_env = folder_path / f".env.{effective_environment}"
    if exact_env.exists() and exact_env.is_file():
        return EnvFileDetection(exact_env, effective_environment, "found")

    return detect_env_file(folder_path)
