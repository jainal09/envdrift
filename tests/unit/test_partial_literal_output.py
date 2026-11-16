"""push and pull-partial print environment names, paths and errors as they are.

Each environment's heading, its file rows and the error list interpolated the
configured name, paths and errors into Rich markup. An environment named
``p[/x]``, or an error that names a ``cfg[/x]/`` path, stopped either command
with ``MarkupError``, and the link dotenvx ends a failure with
(``fix: [https://github.com/...]``) vanished from the error lines.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.core.partial_encryption import PartialEncryptionError

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git binary not available")

runner = CliRunner()

_DOTENVX_LINK = "fix: [https://github.com/dotenvx/dotenvx/issues/757]"
# dotenvx 2.38.2's failures, as envdrift wraps them for the secret file.
_ENCRYPT_FAILURE = (
    "Failed to encrypt cfg[/x]/.env.prod.secret: dotenvx command failed (exit 1): "
    '☠ hex string expected, got non-hex character "zz" at index 0'
)
_DECRYPT_FAILURE = (
    "Failed to decrypt secrets/.env.prod.secret: dotenvx decryption failed: "
    "○ no change to secrets/.env.prod.secret (03A BC) via source unknown\n"
    f"☠ [DECRYPTION_FAILED] could not decrypt API_TOKEN. {_DOTENVX_LINK}"
)
_UNDECRYPTABLE = (
    '#/---BEGIN DOTENV ENCRYPTED---/\nDOTENV_PUBLIC_KEY_PROD="03abc"\nAPI_TOKEN="encrypted:QUJD"\n'
)


def _write_config(root: Path, name: str, folder: str = "cfg[/x]") -> None:
    (root / "envdrift.toml").write_text(
        "[partial_encryption]\nenabled = true\n\n"
        "[[partial_encryption.environments]]\n"
        f'name = "{name}"\n'
        f'clear_file = "{folder}/.env.prod.clear"\n'
        f'secret_file = "{folder}/.env.prod.secret"\n'
        f'combined_file = "{folder}/.env.prod"\n',
        encoding="utf-8",
    )


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    monkeypatch.chdir(tmp_path)
    folder = tmp_path / "cfg[" / "x]"
    folder.mkdir(parents=True)
    (folder / ".env.prod.clear").write_text("APP=1\n", encoding="utf-8")
    (folder / ".env.prod.secret").write_text("API_TOKEN=value\n", encoding="utf-8")
    _write_config(tmp_path, "p[/x]")
    return folder


def _invoke(*args: str):
    return runner.invoke(app, list(args), env={"COLUMNS": "250"})


def _flat(text: str) -> str:
    return " ".join(text.split())


def test_push_check_names_the_environment_and_file_as_written(project: Path) -> None:
    result = _invoke("push", "--check")

    assert result.exit_code == 1, result.output
    assert isinstance(result.exception, SystemExit), repr(result.exception)
    out = _flat(result.output)
    assert "→ p[/x]" in out
    assert "! cfg[/x]/.env.prod is out of date — run 'envdrift push'" in out


def test_pull_partial_names_the_environment_and_files_as_written(project: Path) -> None:
    result = _invoke("pull-partial")

    assert result.exit_code == 0, result.output
    out = _flat(result.output)
    assert "Updated .gitignore: cfg[/x]/.env.prod, .env.keys" in out
    assert "→ p[/x]" in out
    assert "= cfg[/x]/.env.prod.secret (already decrypted)" in out


def test_pull_partial_error_list_names_the_environment_as_written(project: Path) -> None:
    (project / ".env.prod.secret").write_text(_UNDECRYPTABLE, encoding="utf-8")

    result = _invoke("pull-partial")

    assert result.exit_code == 1, result.output
    assert isinstance(result.exception, SystemExit), repr(result.exception)
    out = _flat(result.output)
    assert "→ p[/x]" in out
    assert "• p[/x]:" in out


def _fail_with(message: str):
    def fail(*_args, **_kwargs):
        raise PartialEncryptionError(message)

    return fail


def test_push_error_line_prints_dotenvx_s_failure_as_it_is(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The error names the ``cfg[/x]/`` file, which raised MarkupError (partial.py push)."""
    _write_config(project.parents[1], "prod")
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.push_partial_encryption", _fail_with(_ENCRYPT_FAILURE)
    )

    result = _invoke("push")

    assert result.exit_code == 1, result.output
    assert isinstance(result.exception, SystemExit), repr(result.exception)
    out = _flat(result.output)
    assert f"✗ {_ENCRYPT_FAILURE}" in out
    assert f"• prod: {_ENCRYPT_FAILURE}" in out


def test_pull_partial_error_line_keeps_dotenvx_s_link(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """dotenvx's ``fix: [https://...]`` vanished from the error line (partial.py pull)."""
    root = project.parents[1]
    (root / "secrets").mkdir()
    (root / "secrets" / ".env.prod.secret").write_text(_UNDECRYPTABLE, encoding="utf-8")
    _write_config(root, "prod", folder="secrets")
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.pull_partial_encryption", _fail_with(_DECRYPT_FAILURE)
    )

    result = _invoke("pull-partial")

    assert result.exit_code == 1, result.output
    assert isinstance(result.exception, SystemExit), repr(result.exception)
    out = _flat(result.output)
    flat_failure = _flat(_DECRYPT_FAILURE)
    assert f"✗ {flat_failure}" in out
    assert f"• prod: {flat_failure}" in out
