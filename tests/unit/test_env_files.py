"""Tests for env file resolution helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.env_files import (
    _is_excluded_env_file,
    detect_env_file,
    resolve_custom_env_file,
    resolve_mapping_env_file,
)
from envdrift.sync.config import ServiceMapping


@pytest.mark.parametrize(
    ("name", "excluded"),
    [
        (".env.keys", True),
        # #474: on macOS/Windows default case-insensitive filesystems,
        # ".env.KEYS" names the same file as ".env.keys" — a case-sensitive
        # check let the private-key store be encrypted (irreversible lockout).
        (".env.KEYS", True),
        (".env.Keys", True),
        ("service.env.EXAMPLE", True),
        (".env.SAMPLE", True),
        (".env.Template", True),
        (".env", False),
        (".env.production", False),
        ("keys.env", False),
    ],
)
def test_is_excluded_env_file_is_case_insensitive(name: str, excluded: bool) -> None:
    """Companion-file detection matches suffixes case-insensitively (#474)."""
    assert _is_excluded_env_file(name) is excluded


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


@pytest.mark.parametrize(
    "env_file",
    ["../outside.env", "/tmp/outside.env", "nested/../postgresql.env", "../service/inside.env"],
)
def test_resolve_custom_env_file_rejects_paths_outside_folder(
    tmp_path: Path,
    env_file: str,
) -> None:
    service_dir = tmp_path / "service"
    service_dir.mkdir()

    # Any '..' segment is rejected up front, even if it would resolve back inside.
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
    """A lone ``.env.<env>`` is adopted only when it matches the mapping's env."""
    service_dir = tmp_path / "service"
    service_dir.mkdir()
    env_file = service_dir / ".env.sqa"
    env_file.write_text("SECRET=value\n")

    mapping = ServiceMapping(
        secret_name="dotenv-key",
        folder_path=service_dir,
        environment="sqa",
    )

    detection = resolve_mapping_env_file(mapping)

    assert detection.status == "found"
    assert detection.path == env_file
    assert detection.environment == "sqa"


def test_resolve_mapping_env_file_skips_lone_other_environment_file(
    tmp_path: Path,
) -> None:
    """Regression for #395.

    A mapping for ``production`` with no ``.env.production`` (and no custom
    match) but exactly one ``.env.staging`` must NOT fall through to legacy
    detection and claim staging. Doing so would sync ``.env.staging`` under
    ``DOTENV_PRIVATE_KEY_STAGING`` for a production mapping. The resolver must
    report "not_found" so ``_sync_service`` SKIPS instead.
    """
    service_dir = tmp_path / "service"
    service_dir.mkdir()
    staging = service_dir / ".env.staging"
    staging.write_text("SECRET=value\n")

    mapping = ServiceMapping(
        secret_name="dotenv-key",
        folder_path=service_dir,
        environment="production",
    )

    detection = resolve_mapping_env_file(mapping)

    assert detection.status == "not_found"
    assert detection.path is None
    # Crucially, the staging suffix is never adopted as the environment of record.
    assert detection.environment != "staging"


@pytest.mark.parametrize(
    ("filename", "environment"),
    [
        ("dotnet-service-template.env.docker", "docker"),  # <prefix>.env.<env>
        ("dotnet-service-template-local.env", "local"),  # <prefix>-<env>.env
        ("app.staging.env", "staging"),  # <prefix>.<env>.env
        ("app_prod.env", "prod"),  # <prefix>_<env>.env
        ("docker.env", "docker"),  # <env>.env
    ],
)
def test_resolve_mapping_env_file_auto_detects_custom_named_file(
    tmp_path: Path,
    filename: str,
    environment: str,
) -> None:
    """Custom filenames encoding the environment are found without env_file config."""
    service_dir = tmp_path / "service"
    service_dir.mkdir()
    (service_dir / filename).write_text("SECRET=value\n")

    mapping = ServiceMapping(
        secret_name="dotenv-key",
        folder_path=service_dir,
        environment=environment,
    )

    detection = resolve_mapping_env_file(mapping)

    assert detection.status == "found"
    assert detection.path == service_dir / filename
    # Configured environment stays canonical, even with a custom filename.
    assert detection.environment == environment


def test_resolve_mapping_env_file_auto_detects_prefixed_plain_file(tmp_path: Path) -> None:
    """A single ``<prefix>.env`` file is found for a default-environment mapping."""
    service_dir = tmp_path / "postgresql"
    service_dir.mkdir()
    env_file = service_dir / "postgresql.env"
    env_file.write_text("SECRET=value\n")
    # Companion files must not interfere with detection.
    (service_dir / "postgresql.env.example").write_text("SECRET=example\n")
    (service_dir / "docker-entrypoint.sh").write_text("#!/bin/sh\n")

    mapping = ServiceMapping(secret_name="dotenv-key", folder_path=service_dir)

    detection = resolve_mapping_env_file(mapping)

    assert detection.status == "found"
    assert detection.path == env_file
    assert detection.environment == "production"


def test_resolve_mapping_env_file_picks_environment_from_multi_env_folder(
    tmp_path: Path,
) -> None:
    """One folder holding several env files resolves each environment to its file."""
    service_dir = tmp_path / "dotnet-service-template"
    service_dir.mkdir()
    for name in (
        "dotnet-service-template.env.docker",
        "dotnet-service-template.env.sqa",
        "dotnet-service-template-local.env",
        # Companion files for every environment must be ignored.
        "dotnet-service-template.env.example",
        "dotnet-service-template.env.sqa.example",
        "dotnet-service-template-local.env.example",
    ):
        (service_dir / name).write_text("SECRET=value\n")

    expected = {
        "docker": "dotnet-service-template.env.docker",
        "sqa": "dotnet-service-template.env.sqa",
        "local": "dotnet-service-template-local.env",
    }
    for environment, filename in expected.items():
        mapping = ServiceMapping(
            secret_name=f"key-{environment}",
            folder_path=service_dir,
            environment=environment,
        )
        detection = resolve_mapping_env_file(mapping)
        assert detection.status == "found", environment
        assert detection.path == service_dir / filename
        assert detection.environment == environment


def test_resolve_mapping_env_file_reports_ambiguous_environment_match(tmp_path: Path) -> None:
    """Two files encoding the same environment are ambiguous, not a silent guess."""
    service_dir = tmp_path / "service"
    service_dir.mkdir()
    (service_dir / "app.env.staging").write_text("SECRET=value\n")
    (service_dir / "app-staging.env").write_text("SECRET=value\n")

    mapping = ServiceMapping(
        secret_name="dotenv-key",
        folder_path=service_dir,
        environment="staging",
    )

    detection = resolve_mapping_env_file(mapping)

    assert detection.status == "multiple_found"
    assert detection.path is None


def test_resolve_mapping_env_file_default_ignores_other_environment_files(
    tmp_path: Path,
) -> None:
    """A default mapping picks the plain file, not the env-specific neighbor.

    Regression: a folder with ``service.env`` + ``service.env.staging`` must not
    look ambiguous to a production mapping just because two dotenv files exist.
    """
    service_dir = tmp_path / "service"
    service_dir.mkdir()
    plain = service_dir / "service.env"
    plain.write_text("SECRET=value\n")
    (service_dir / "service.env.staging").write_text("SECRET=staging\n")

    mapping = ServiceMapping(secret_name="dotenv-key", folder_path=service_dir)

    detection = resolve_mapping_env_file(mapping)

    assert detection.status == "found"
    assert detection.path == plain
    assert detection.environment == "production"


def test_resolve_mapping_env_file_env_specific_ignores_plain_file(tmp_path: Path) -> None:
    """An environment-specific mapping never grabs a plain ``<prefix>.env`` file."""
    service_dir = tmp_path / "service"
    service_dir.mkdir()
    (service_dir / "service.env").write_text("SECRET=value\n")
    docker = service_dir / "service.env.docker"
    docker.write_text("SECRET=docker\n")

    mapping = ServiceMapping(
        secret_name="dotenv-key",
        folder_path=service_dir,
        environment="docker",
    )

    detection = resolve_mapping_env_file(mapping)

    assert detection.status == "found"
    assert detection.path == docker
    assert detection.environment == "docker"


def test_detect_env_file_ignores_prefixed_plain_file(tmp_path: Path) -> None:
    """``detect_env_file`` stays narrow: ``<prefix>.env`` is resolve()'s job, not its."""
    (tmp_path / "keycloak.env").write_text("SECRET=value\n")

    detection = detect_env_file(tmp_path)

    assert detection.status == "not_found"
    assert detection.path is None


@pytest.mark.parametrize("resolver", ["resolve", "detect"])
def test_env_detection_handles_non_directory_path(tmp_path: Path, resolver: str) -> None:
    """A folder_path that is a file must not crash on iterdir()."""
    not_a_dir = tmp_path / "service"
    not_a_dir.write_text("oops, a file\n")

    if resolver == "detect":
        detection = detect_env_file(not_a_dir)
    else:
        mapping = ServiceMapping(secret_name="dotenv-key", folder_path=not_a_dir)
        detection = resolve_mapping_env_file(mapping)

    assert detection.status == "folder_not_found"
    assert detection.path is None


def test_resolve_mapping_env_file_reports_folder_not_found(tmp_path: Path) -> None:
    """A custom env_file under a missing folder reports folder_not_found."""
    mapping = ServiceMapping(
        secret_name="dotenv-key",
        folder_path=tmp_path / "does-not-exist",
        environment="production",
        env_file=Path("postgresql.env"),
    )

    detection = resolve_mapping_env_file(mapping)

    assert detection.status == "folder_not_found"
    assert detection.path is None
    assert detection.environment == "production"


def test_explicit_env_file_with_file_as_folder_is_folder_not_found(tmp_path: Path) -> None:
    """#488: folder_path pointing at a regular FILE + explicit env_file must be loud.

    exists() classified this broken config as a benign "not_found" skip
    (exit 0); it must report folder_not_found like the auto-detect path does.
    """
    not_a_dir = tmp_path / "service"
    not_a_dir.write_text("oops, a file\n")
    mapping = ServiceMapping(
        secret_name="dotenv-key",
        folder_path=not_a_dir,
        environment="production",
        env_file=Path("postgresql.env"),
    )

    detection = resolve_mapping_env_file(mapping)

    assert detection.status == "folder_not_found"
    assert detection.path is None
    assert detection.environment == "production"
