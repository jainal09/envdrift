"""Helpers for detecting environment files."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

EnvFileStatus = Literal["found", "folder_not_found", "multiple_found", "not_found"]

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


def _env_label_from_name(name: str, default_environment: str) -> str | None:
    """Return the environment a dotenv-shaped filename belongs to, else None.

    Recognizes both the canonical and common custom conventions:
    - ``.env``                       -> ``default_environment``
    - ``.env.<env>``                 -> ``<env>``           (e.g. ".env.docker")
    - ``<prefix>.env.<env>``         -> ``<env>``           ("service.env.docker")
    - ``<prefix>.env``               -> ``default_environment`` ("postgresql.env")

    Returns None for files that are not dotenv files (or are companion files).
    """
    if _is_excluded_env_file(name):
        return None
    if name == ".env":
        return default_environment
    if ".env." in name:
        # Environment is whatever follows ".env.": ".env.docker" / "svc.env.docker".
        return name.split(".env.", 1)[1] or None
    if name.endswith(".env"):
        # Prefixed plain file with no encoded environment, e.g. "postgresql.env".
        return default_environment
    return None


def _name_encodes_environment(name: str, environment: str) -> bool:
    """Return True if ``name`` is a dotenv file that encodes ``environment``.

    Covers the suffix convention (``<prefix>.env.<env>``) and the infix
    convention where the environment precedes the ``.env`` extension
    (``<prefix>-<env>.env`` / ``<prefix>.<env>.env`` / ``<prefix>_<env>.env`` /
    ``<env>.env``).
    """
    if name.endswith(f".env.{environment}"):
        return True
    if name == f"{environment}.env":
        return True
    return any(name.endswith(f"{sep}{environment}.env") for sep in ("-", ".", "_"))


def _match_env_files_for_environment(folder_path: Path, environment: str) -> list[Path]:
    """Return env files in ``folder_path`` whose name encodes ``environment``."""
    if not folder_path.exists():
        return []
    matches = [
        f
        for f in folder_path.iterdir()
        if f.is_file()
        and not _is_excluded_env_file(f.name)
        and _name_encodes_environment(f.name, environment)
    ]
    return sorted(matches)


def detect_env_file(folder_path: Path, default_environment: str = "production") -> EnvFileDetection:
    """
    Auto-detect the env file in a folder.

    Checks for:
    1. Plain .env file (returns default environment)
    2. A single dotenv-shaped file, including custom names such as
       ``service.env`` or ``service.env.docker`` (environment from suffix, or
       the default for files without an encoded environment)

    Returns an EnvFileDetection with status:
    - "found": env file found
    - "folder_not_found": folder doesn't exist
    - "multiple_found": multiple candidate env files exist (ambiguous)
    - "not_found": no env files found
    """
    if not folder_path.exists():
        return EnvFileDetection(None, None, "folder_not_found")

    # First, check for plain .env file (takes precedence over any other file)
    plain_env = folder_path / ".env"
    if plain_env.exists() and plain_env.is_file():
        return EnvFileDetection(plain_env, default_environment, "found")

    candidates: list[tuple[Path, str]] = []
    for f in folder_path.iterdir():
        if not f.is_file():
            continue
        environment = _env_label_from_name(f.name, default_environment)
        if environment is None:
            continue
        candidates.append((f, environment))

    if len(candidates) == 1:
        env_file, environment = candidates[0]
        return EnvFileDetection(env_file, environment, "found")

    if len(candidates) > 1:
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


def resolve_mapping_env_file(mapping: Any) -> EnvFileDetection:
    """Resolve the env file for a sync mapping.

    Resolution order:
    1. Explicit ``mapping.env_file`` relative to ``mapping.folder_path``.
    2. Exact ``.env.<effective_environment>``.
    3. A custom-named file that encodes the environment, such as
       ``service.env.<env>`` or ``service-<env>.env``.
    4. Existing legacy auto-detection for ``.env`` or a single dotenv file.

    Custom filenames matched via steps 2-3 keep ``mapping.effective_environment``
    as the environment of record. This preserves canonical vault key names even
    when the dotenv filename uses a service-specific convention.
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

    # Match custom-named files that encode this environment (e.g.
    # "service.env.docker" or "service-local.env"). The configured environment
    # stays canonical so vault/dotenvx key names remain config-driven.
    env_matches = _match_env_files_for_environment(folder_path, effective_environment)
    if len(env_matches) == 1:
        return EnvFileDetection(env_matches[0], effective_environment, "found")
    if len(env_matches) > 1:
        return EnvFileDetection(None, effective_environment, "multiple_found")

    return detect_env_file(folder_path, effective_environment)
