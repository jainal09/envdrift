"""Helpers for detecting environment files."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

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
