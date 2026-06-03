"""Tests for env file resolution helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.env_files import resolve_custom_env_file, resolve_mapping_env_file
from envdrift.sync.config import ServiceMapping


@pytest.mark.parametrize(
    ("filename", "environment"),
    [
        ("dotnet-service-template.env.sqa", "sqa"),
        ("dotnet-service-template-local.env", "local"),
        ("postgresql.env", "production"),
    ],
)
def test_resolve_mapping_env_file_uses_configured_env_file(
    tmp_path: Path,
    filename: str,
    environment: str,
) -> None:
    """A configured env_file is resolved relative to folder_path."""
    service_dir = tmp_path / "service"
    service_dir.mkdir()
    custom_env_file = service_dir / filename
    custom_env_file.write_text("SECRET=value\n")

    mapping = ServiceMapping(
        secret_name="dotenv-key",
        folder_path=service_dir,
        environment=environment,
        env_file=Path(filename),
    )

    detection = resolve_mapping_env_file(mapping)

    assert detection.status == "found"
    assert detection.path == custom_env_file
    assert detection.environment == environment


def test_resolve_mapping_env_file_missing_custom_file_reports_expected_path(
    tmp_path: Path,
) -> None:
    service_dir = tmp_path / "service"
    service_dir.mkdir()
    mapping = ServiceMapping(
        secret_name="dotenv-key",
        folder_path=service_dir,
        environment="production",
        env_file=Path("postgresql.env"),
    )

    detection = resolve_mapping_env_file(mapping)

    assert detection.status == "not_found"
    assert detection.path == service_dir / "postgresql.env"
    assert detection.environment == "production"


@pytest.mark.parametrize("env_file", ["../outside.env", "/tmp/outside.env"])
def test_resolve_custom_env_file_rejects_paths_outside_folder(
    tmp_path: Path,
    env_file: str,
) -> None:
    service_dir = tmp_path / "service"
    service_dir.mkdir()

    with pytest.raises(ValueError):
        resolve_custom_env_file(service_dir, env_file)


def test_resolve_mapping_env_file_preserves_legacy_exact_environment(
    tmp_path: Path,
) -> None:
    service_dir = tmp_path / "service"
    service_dir.mkdir()
    env_file = service_dir / ".env.production"
    env_file.write_text("SECRET=value\n")

    mapping = ServiceMapping(
        secret_name="dotenv-key",
        folder_path=service_dir,
        environment="production",
    )

    detection = resolve_mapping_env_file(mapping)

    assert detection.status == "found"
    assert detection.path == env_file
    assert detection.environment == "production"


def test_resolve_mapping_env_file_preserves_legacy_single_env_detection(
    tmp_path: Path,
) -> None:
    service_dir = tmp_path / "service"
    service_dir.mkdir()
    env_file = service_dir / ".env.sqa"
    env_file.write_text("SECRET=value\n")

    mapping = ServiceMapping(
        secret_name="dotenv-key",
        folder_path=service_dir,
        environment="production",
    )

    detection = resolve_mapping_env_file(mapping)

    assert detection.status == "found"
    assert detection.path == env_file
    assert detection.environment == "sqa"
