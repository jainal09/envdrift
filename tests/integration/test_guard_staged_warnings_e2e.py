"""``guard --staged`` names a file it did not scan by its path in the repository (#933).

``--staged`` scans copies of the staged blobs in a temporary mirror, which is deleted after the
scan. Findings are shown at the files' repository paths (#476), but a scanner warning still named
the copy: "Not scanned: /tmp/envdrift-staged-.../dump.sql is larger than ...", a file gone by the
time anyone read it. Each test runs the real CLI in a real git repository.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from envdrift.scanner._native_io import NATIVE_MAX_SCAN_BYTES

pytestmark = [pytest.mark.integration]

REPO_ROOT = Path(__file__).resolve().parents[2]
STAGED_DUMP = str(Path("sub") / "dump.sql")


def _too_large(shown_as: str) -> str:
    return (
        f"Not scanned: {shown_as} is larger than the native scanner's 10 MiB limit. Scan it with "
        "another scanner, or add it to [guard] ignore_paths to skip it on purpose."
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A repository with a text file over the native scanner's size limit staged in ``sub/``."""
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not available")
    root = tmp_path / "repo"
    (root / "sub").mkdir(parents=True)
    subprocess.run([git, "init", "-q", str(root)], check=True, capture_output=True)
    dump = root / "sub" / "dump.sql"
    # Text through the 8 KiB the scanner reads to tell text from binary, then sparse.
    dump.write_text("-- a row\n" * 2048)
    with dump.open("ab") as stream:
        stream.truncate(NATIVE_MAX_SCAN_BYTES + 1)
    subprocess.run([git, "-C", str(root), "add", "sub/dump.sql"], check=True, capture_output=True)
    return root


def _guard_staged(
    cwd: Path, *flags: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    run_env = os.environ.copy()
    run_env["PYTHONPATH"] = f"{REPO_ROOT / 'src'}{os.pathsep}{run_env.get('PYTHONPATH', '')}"
    run_env.update(env or {})
    return subprocess.run(
        [sys.executable, "-m", "envdrift.cli", "guard", "--staged", "--native-only", *flags],
        cwd=str(cwd),
        env=run_env,
        capture_output=True,
        text=True,
        timeout=300,
    )


@pytest.mark.parametrize(("where", "shown_as"), [(".", STAGED_DUMP), ("sub", "dump.sql")])
def test_the_json_warning_names_the_staged_file(repo: Path, where: str, shown_as: str):
    """As findings do: relative to the cwd, from the root or a subdirectory."""
    result = _guard_staged(repo / where, "--json")

    assert result.returncode == 0, result.stderr
    (native,) = json.loads(result.stdout)["scanner_results"]
    assert native["warnings"] == [_too_large(shown_as)]
    # The warning is repeated on stderr under --json: that copy too.
    assert _too_large(shown_as) in result.stderr
    assert "envdrift-staged-" not in result.stdout + result.stderr


def test_the_warning_names_the_staged_file_when_the_mirror_is_under_the_cwd(repo: Path):
    """With the temporary directory inside the checkout, the copy's path was a relative one."""
    inside = repo / ".tmp"
    inside.mkdir()
    env = {name: str(inside) for name in ("TMPDIR", "TEMP", "TMP")}

    result = _guard_staged(repo, "--json", env=env)

    assert result.returncode == 0, result.stderr
    (native,) = json.loads(result.stdout)["scanner_results"]
    assert native["warnings"] == [_too_large(STAGED_DUMP)]


def test_the_scanner_warnings_panel_names_the_staged_file(repo: Path):
    result = _guard_staged(repo)

    assert result.returncode == 0, result.stdout + result.stderr
    assert STAGED_DUMP in result.stdout
    assert "envdrift-staged-" not in result.stdout + result.stderr
