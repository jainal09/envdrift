"""sync --validate-schema checks values under dotenv alias names, like validate (#965).

An alias such as ``2FA_ENABLED`` or ``X-FEATURE-ENABLED`` is not a Python identifier, and
sync's schema check skipped the value bound to it while validate checked it.
"""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest
from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.cli_commands.sync_run_helpers import (
    SyncRequest,
    _new_sync_engine,
    _strict_extra,
    _SyncContext,
)
from envdrift.sync.config import ServiceMapping, SyncConfig
from envdrift.sync.engine import SyncEngine, SyncMode
from envdrift.sync.result import SyncAction
from tests.unit.test_sync_engine import _StoredVaultClient


@pytest.mark.parametrize("alias", ["2FA_ENABLED", "X-FEATURE-ENABLED", "ÉTAT_MODE"])
@pytest.mark.parametrize("case", [("true", True), ("maybe", False)])
def test_sync_validates_non_identifier_aliases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, alias: str, case: tuple[str, bool]
) -> None:
    """#965: sync and validate must both check values under dotenv alias names."""
    value, valid = case
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(alias, raising=False)
    env_file = tmp_path / ".env.production"
    env_file.write_text(f"{alias}={value}\n", encoding="utf-8")
    (tmp_path / "sync_alias_settings.py").write_text(
        dedent(
            f"""
            from pydantic import Field
            from pydantic_settings import BaseSettings

            class Settings(BaseSettings):
                enabled: bool = Field(default=False, alias={alias!r})
            """
        ).lstrip(),
        encoding="utf-8",
    )
    mapping = ServiceMapping(secret_name="test-key", folder_path=tmp_path)
    engine = SyncEngine(
        config=SyncConfig(mappings=[mapping]),
        vault_client=_StoredVaultClient({"test-key": "test-private-key"}),
        mode=SyncMode(validate_schema=True, schema_path="sync_alias_settings:Settings"),
    )

    cli_result = CliRunner().invoke(
        app,
        [
            "validate",
            str(env_file),
            "-s",
            "sync_alias_settings:Settings",
            "-d",
            str(tmp_path),
            "--ci",
        ],
    )
    assert cli_result.exit_code == (0 if valid else 1), cli_result.output

    result = engine.sync_all()

    assert result.services[0].action == SyncAction.CREATED
    assert result.services[0].schema_valid is valid


@pytest.mark.parametrize("strict_extra", [True, False], ids=["extra-forbidden", "extra-allowed"])
def test_sync_follows_strict_extra_as_validate_does(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, strict_extra: bool
) -> None:
    """sync's schema check reads ``[validation].strict_extra``, as validate does.

    With ``strict_extra = false``, ``validate --ci`` skips the check for variables the schema does
    not declare, but sync's check always ran it. Under an ``extra="forbid"`` schema, a file that
    validate passed failed sync, and the lenient parse brought names such as
    ``X-FEATURE-ENABLED``, which the strict parse skipped, into that check.
    """
    monkeypatch.chdir(tmp_path)
    for name in ("ENABLED", "X-FEATURE-ENABLED"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "envdrift.toml").write_text(
        f"[validation]\nstrict_extra = {str(strict_extra).lower()}\n", encoding="utf-8"
    )
    env_file = tmp_path / ".env.production"
    env_file.write_text("ENABLED=true\nX-FEATURE-ENABLED=1\n", encoding="utf-8")
    (tmp_path / "sync_extra_settings.py").write_text(
        dedent(
            """
            from pydantic_settings import BaseSettings, SettingsConfigDict

            class Settings(BaseSettings):
                model_config = SettingsConfigDict(extra="forbid")

                enabled: bool = False
            """
        ).lstrip(),
        encoding="utf-8",
    )
    valid = not strict_extra

    cli_result = CliRunner().invoke(
        app,
        ["validate", str(env_file), "-s", "sync_extra_settings:Settings", "-d", str(tmp_path)]
        + ["--ci"],
    )
    assert cli_result.exit_code == (0 if valid else 1), cli_result.output

    # The engine the sync command builds, which reads the config sync runs with.
    request = SyncRequest(
        config_file=None,
        provider="aws",
        vault_url=None,
        region=None,
        project_id=None,
        verify=False,
        force=True,
        profile=None,
        check_decryption=False,
        validate_schema=True,
        schema="sync_extra_settings:Settings",
        service_dir=tmp_path,
        ci=True,
    )
    context = _SyncContext(
        config=SyncConfig(mappings=[ServiceMapping(secret_name="test-key", folder_path=tmp_path)]),
        vault_client=_StoredVaultClient({"test-key": "test-private-key"}),
        provider="aws",
    )
    result = _new_sync_engine(request, context).sync_all()

    assert result.services[0].schema_valid is valid


def test_strict_extra_comes_from_the_config_sync_runs_with(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An explicit TOML config is the one read, a sync pairs file falls back to the config
    validate finds, and a config that cannot be read keeps the check."""
    monkeypatch.chdir(tmp_path)
    assert _strict_extra(None) is True  # no config anywhere: the default, which checks

    explicit = tmp_path / "sync.toml"
    explicit.write_text("[validation]\nstrict_extra = false\n", encoding="utf-8")
    assert _strict_extra(explicit) is False

    (tmp_path / "envdrift.toml").write_text(
        "[validation]\nstrict_extra = false\n", encoding="utf-8"
    )
    assert _strict_extra(tmp_path / "pairs.txt") is False

    broken = tmp_path / "broken.toml"
    broken.write_text("[validation\n", encoding="utf-8")
    assert _strict_extra(broken) is True
