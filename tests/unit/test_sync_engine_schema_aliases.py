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
