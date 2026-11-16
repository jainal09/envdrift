"""The sync engine checks a key before it backs it up or stages it (#938).

A vault key that dotenvx would read back as another value is refused before
any backup is made, a write refused after the backup names the backup it
leaves, and the decryption check stages one key, never a key ring of two.
"""

from __future__ import annotations

import subprocess  # nosec B404
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from envdrift.sync.config import ServiceMapping, SyncConfig
from envdrift.sync.engine import SyncEngine, SyncMode
from envdrift.sync.operations import EnvKeysFile
from envdrift.sync.result import DecryptionTestResult, SyncAction
from envdrift.vault.base import SecretValue

VAULT = "a" * 64
OTHER = "b" * 64
NAME = "DOTENV_PRIVATE_KEY_PRODUCTION"


def _engine(tmp_path: Path, vault_value: str, mode: SyncMode) -> SyncEngine:
    mapping = ServiceMapping(secret_name="app-key", folder_path=tmp_path, environment="production")
    (tmp_path / ".env.production").write_text("A=encrypted:x\n", encoding="utf-8")
    client = MagicMock()
    client.get_secret.return_value = SecretValue(name="app-key", value=f"{NAME}={vault_value}")
    return SyncEngine(config=SyncConfig(mappings=[mapping]), vault_client=client, mode=mode)


def _backups(folder: Path) -> list[Path]:
    return [path for path in folder.iterdir() if ".backup." in path.name]


def test_a_vault_key_it_would_not_write_gets_no_backup(tmp_path: Path) -> None:
    keys = tmp_path / ".env.keys"
    keys.write_text(f"{NAME}={OTHER}\n", encoding="utf-8")
    before = keys.read_bytes()

    result = _engine(tmp_path, f"{VAULT}#tail", SyncMode(force_update=True)).sync_all()

    service = result.services[0]
    assert service.action == SyncAction.ERROR
    assert "would not read" in (service.error or "")
    assert keys.read_bytes() == before
    assert _backups(tmp_path) == []


def test_a_write_refused_after_the_backup_names_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Another writer changes the key while sync backs it up: the backup is kept."""
    keys = tmp_path / ".env.keys"
    keys.write_text(f"{NAME}={OTHER}\n", encoding="utf-8")
    theirs = f"{NAME}=theirs\n"
    back_up = EnvKeysFile.create_backup

    def back_up_then_another_writer(self: EnvKeysFile) -> Path:
        backup = back_up(self)
        keys.write_text(theirs, encoding="utf-8")
        return backup

    monkeypatch.setattr(EnvKeysFile, "create_backup", back_up_then_another_writer)

    result = _engine(tmp_path, VAULT, SyncMode(force_update=True)).sync_all()

    service = result.services[0]
    assert service.action == SyncAction.ERROR
    assert "was kept" in (service.error or "")
    assert keys.read_text(encoding="utf-8") == theirs
    assert len(_backups(tmp_path)) == 1


def test_decryption_check_fails_a_first_value_of_two_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """dotenvx splits a value on "," into a key ring: two keys are no one key to test."""
    (tmp_path / ".env.keys").write_text(f"{NAME}={VAULT},{OTHER}\n", encoding="utf-8")
    monkeypatch.setattr("envdrift.sync.engine.shutil.which", lambda _: "/usr/bin/dotenvx")
    ran: list[object] = []
    monkeypatch.setattr(
        "envdrift.sync.engine.subprocess.run", lambda cmd, **kwargs: ran.append(cmd)
    )
    engine = _engine(tmp_path, VAULT, SyncMode())

    assert engine._test_decryption(engine.config.mappings[0]) == DecryptionTestResult.FAILED
    assert ran == []


@pytest.mark.parametrize(
    ("first_value", "staged_keys"),
    [
        pytest.param(
            f'"{VAULT}\nDOTENV_PRIVATE_KEY_STAGING={OTHER}"', f"{NAME}={VAULT}\n", id="line-break"
        ),
        pytest.param(
            f'"{VAULT}\\nDOTENV_PRIVATE_KEY_STAGING={OTHER}"', f"{NAME}={VAULT}\n", id="escaped"
        ),
        pytest.param(f'"zz\\nDOTENV_PRIVATE_KEY_STAGING={OTHER}"', None, id="no-usable-key"),
    ],
)
def test_decryption_check_stages_no_other_line_of_a_quoted_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, first_value: str, staged_keys: str | None
) -> None:
    """dotenvx reads a quoted value's key from its leading hex digits, and only that is staged.

    Staged as written, without its quotes, the value's second line was a key of
    its own, and dotenvx decrypts with any key in the file.
    """
    (tmp_path / ".env.keys").write_text(f"{NAME}={first_value}\n", encoding="utf-8")
    monkeypatch.setattr("envdrift.sync.engine.shutil.which", lambda _: "/usr/bin/dotenvx")
    staged: list[str | None] = []

    def fake_run(cmd, **kwargs):
        keys = Path(kwargs["cwd"]) / ".env.keys"
        staged.append(keys.read_text(encoding="utf-8") if keys.exists() else None)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr("envdrift.sync.engine.subprocess.run", fake_run)
    engine = _engine(tmp_path, VAULT, SyncMode())

    engine._test_decryption(engine.config.mappings[0])

    assert staged == [staged_keys]


def test_decryption_check_stages_a_ring_of_one_key_as_that_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".env.keys").write_text(f"{NAME}={VAULT},{VAULT.upper()}\n", encoding="utf-8")
    monkeypatch.setattr("envdrift.sync.engine.shutil.which", lambda _: "/usr/bin/dotenvx")
    staged: list[str] = []

    def fake_run(cmd, **kwargs):
        staged.append((Path(kwargs["cwd"]) / ".env.keys").read_text(encoding="utf-8"))
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr("envdrift.sync.engine.subprocess.run", fake_run)
    engine = _engine(tmp_path, VAULT, SyncMode())

    assert engine._test_decryption(engine.config.mappings[0]) == DecryptionTestResult.PASSED
    assert staged == [f"{NAME}={VAULT}\n"]
