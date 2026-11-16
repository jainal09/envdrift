"""``encrypt`` gitignores the key file even when ``.gitignore`` is not UTF-8 (#1030).

git reads a ``.gitignore`` with a Latin-1 comment without complaint. envdrift read it
as UTF-8, so after dotenvx had written the private key to ``.env.keys``, ``encrypt``
crashed with a ``UnicodeDecodeError`` and left the key file stageable. The test runs
the real ``envdrift`` CLI, the real dotenvx binary and real git, and asks git whether
it ignores the key.
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


class _KnownCrashError(AssertionError):
    """The crash #1030 describes; any other failure stays a real test failure."""


@pytest.mark.xfail(
    strict=False,
    raises=_KnownCrashError,
    reason="a .gitignore that is not UTF-8 crashes the gitignore step (see #1030)",
)
def test_encrypt_ignores_the_key_file_when_gitignore_is_not_utf8(
    git_repo: Path, integration_env: dict[str, str], envdrift_cmd: list[str]
) -> None:
    (git_repo / ".gitignore").write_bytes(b"# caf\xe9\n*.log\n")
    (git_repo / ".env.production").write_text("API_TOKEN=value\n", encoding="utf-8")

    result = subprocess.run(
        [*envdrift_cmd, "encrypt", ".env.production"],
        cwd=git_repo,
        env=integration_env,
        capture_output=True,
        text=True,
        timeout=120,
    )

    output = " ".join((result.stdout + result.stderr).split())
    if "UnicodeDecodeError" in output:
        raise _KnownCrashError(output)
    assert result.returncode == 0, output
    assert (git_repo / ".env.keys").is_file(), output
    ignored = subprocess.run(["git", "check-ignore", "-q", ".env.keys"], cwd=git_repo, check=False)
    assert ignored.returncode == 0, (git_repo / ".gitignore").read_bytes()
