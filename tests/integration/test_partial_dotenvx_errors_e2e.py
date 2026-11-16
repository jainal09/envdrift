"""push and pull-partial print dotenvx's failures literally (real dotenvx, real CLI subprocess).

Their error lines printed the failure as Rich markup: a ``cfg[/x]/`` path in it
raised ``MarkupError``, and the link dotenvx ends a decryption failure with,
``fix: [https://github.com/...]``, vanished from the line and the error list.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("dotenvx") is None, reason="dotenvx binary not installed"),
]

_LINK = "fix: [https://github.com/dotenvx/dotenvx/issues/757]"


@pytest.fixture
def project(git_repo: Path) -> Path:
    folder = git_repo / "cfg[" / "x]"
    folder.mkdir(parents=True)
    (folder / ".env.prod.clear").write_text("APP=1\n", encoding="utf-8")
    # Already ignored, so the run goes straight to the error line under test.
    (git_repo / ".gitignore").write_text("cfg[/x]/.env.prod\n.env.keys\n", encoding="utf-8")
    (git_repo / "envdrift.toml").write_text(
        "[partial_encryption]\nenabled = true\n\n"
        "[[partial_encryption.environments]]\n"
        'name = "prod"\n'
        'clear_file = "cfg[/x]/.env.prod.clear"\n'
        'secret_file = "cfg[/x]/.env.prod.secret"\n'
        'combined_file = "cfg[/x]/.env.prod"\n',
        encoding="utf-8",
    )
    return folder


def _run(args: list[str], *, cwd: Path, env: dict[str, str], cmd: list[str]) -> str:
    result = subprocess.run(
        [*cmd, *args],
        cwd=cwd,
        env={**env, "COLUMNS": "250"},
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    out = " ".join((result.stdout + result.stderr).split())
    assert "Traceback" not in out and "MarkupError" not in out, out
    return out


def test_push_error_names_the_bracketed_secret_file(
    project: Path, integration_env, envdrift_cmd
) -> None:
    """dotenvx refuses a malformed public key; the failure names ``cfg[/x]/``."""
    (project / ".env.prod.secret").write_text(
        'DOTENV_PUBLIC_KEY_PROD_SECRET="zz-not-hex"\nAPI_TOKEN=value\n', encoding="utf-8"
    )

    out = _run(["push"], cwd=project.parents[1], env=dict(integration_env), cmd=envdrift_cmd)

    failure = f"Failed to encrypt {Path('cfg[/x]/.env.prod.secret')}: dotenvx command failed"
    assert out.count(failure) == 2, out  # the error line and the error list
    assert "hex string expected" in out


def test_pull_partial_error_keeps_dotenvx_s_link(
    project: Path, integration_env, envdrift_cmd
) -> None:
    (project / ".env.prod.secret").write_text(
        '#/---BEGIN DOTENV ENCRYPTED---/\nDOTENV_PUBLIC_KEY_PROD="03abc"\n'
        'API_TOKEN="encrypted:QUJD"\n',
        encoding="utf-8",
    )

    out = _run(
        ["pull-partial"], cwd=project.parents[1], env=dict(integration_env), cmd=envdrift_cmd
    )

    failure = f"Failed to decrypt {Path('cfg[/x]/.env.prod.secret')}: dotenvx decryption failed"
    assert out.count(failure) == 2, out  # the error line and the error list
    assert "[DECRYPTION_FAILED]" in out
    assert out.count(_LINK) == 2, out
