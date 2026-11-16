"""pull prints dotenvx's failures literally (real dotenvx binary, real CLI subprocess).

dotenvx ends a decryption failure with a link, ``fix: [https://github.com/...]``.
pull printed its error rows as Rich markup, so the link vanished and ``fix:``
was left pointing at nothing, and a ``[/x]`` in a path raised ``MarkupError``.
The rows are the decrypt step's and both partial-encryption modes'.

``--skip-sync`` keeps the vault out of the run: the mapping is still loaded,
but no vault call is made.
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
# A file dotenvx 2.38.2 refuses to decrypt: no private key matches it.
_UNDECRYPTABLE = (
    '#/---BEGIN DOTENV ENCRYPTED---/\nDOTENV_PUBLIC_KEY="03abc"\nAPI_TOKEN=encrypted:QUJD\n'
)


def _config(work_dir: Path, partial: str = "") -> Path:
    config = work_dir / "envdrift.toml"
    config.write_text(
        '[vault]\nprovider = "aws"\n\n[vault.aws]\nregion = "us-east-1"\n\n'
        '[vault.sync]\nenv_keys_filename = ".env.keys"\n\n'
        "[[vault.sync.mappings]]\n"
        'secret_name = "app-key"\nfolder_path = "svc"\nenvironment = "production"\n' + partial,
        encoding="utf-8",
    )
    return config


def _pull(config: Path, *, cwd: Path, env: dict[str, str], cmd: list[str]) -> str:
    result = subprocess.run(
        [*cmd, "pull", "-c", str(config), "--skip-sync"],
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


def test_decrypt_row_keeps_dotenvx_s_message(git_repo: Path, integration_env, envdrift_cmd) -> None:
    (git_repo / "svc").mkdir()
    (git_repo / "svc" / ".env.production").write_text(_UNDECRYPTABLE, encoding="utf-8")

    out = _pull(_config(git_repo), cwd=git_repo, env=dict(integration_env), cmd=envdrift_cmd)

    assert f"{Path('svc') / '.env.production'} - error:" in out
    assert "[DECRYPTION_FAILED]" in out
    assert _LINK in out


def test_partial_encryption_rows_keep_dotenvx_s_message(
    git_repo: Path, integration_env, envdrift_cmd
) -> None:
    (git_repo / "svc").mkdir()
    (git_repo / "svc" / ".env.production").write_text("APP=1\n", encoding="utf-8")
    secrets = git_repo / "sec[" / "x]"
    secrets.mkdir(parents=True)
    (secrets / ".env.prod").write_text(_UNDECRYPTABLE, encoding="utf-8")
    combined = git_repo / "comb[" / "x]"
    combined.mkdir(parents=True)
    (combined / ".env.prod.secret").write_text(_UNDECRYPTABLE, encoding="utf-8")
    (combined / ".env.prod.clear").write_text("APP=1\n", encoding="utf-8")
    config = _config(
        git_repo,
        "\n[partial_encryption]\nenabled = true\n\n"
        "[[partial_encryption.environments]]\n"
        'name = "only"\nsecrets_only = true\nsecrets_dir = "sec[/x]"\n\n'
        "[[partial_encryption.environments]]\n"
        'name = "combined"\n'
        'clear_file = "comb[/x]/.env.prod.clear"\n'
        'secret_file = "comb[/x]/.env.prod.secret"\n'
        'combined_file = "comb[/x]/.env.prod"\n',
    )

    out = _pull(config, cwd=git_repo, env=dict(integration_env), cmd=envdrift_cmd)

    assert "sec[/x] - error: Failed to decrypt" in out
    secret_file = str(Path("comb[/x]/.env.prod.secret"))
    assert f"{secret_file} - error: Failed to decrypt {secret_file}" in out
    # Each failure is printed in its row and again in the error list after them.
    assert out.count(_LINK) == 4, out
