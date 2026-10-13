"""``envdrift guard`` with the real gitleaks and Infisical binaries on relative paths (#843).

``guard <subdir>``, ``guard <subdir>/<file>`` and ``guard --pr-base`` (which
passes cwd-relative paths for changed files on purpose) hand the scanners
relative paths. Both backends used to resolve such a path a second time inside
the directory they run the binary in, so the binary failed with ``stat proj:
no such file or directory`` and the scanner reported no findings, only an
error whose raw, colorized stderr leaked ANSI escapes into ``--json``.

Each test drives the real CLI as a subprocess and SKIPs cleanly when the
binary is not installed (no auto-install).
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404
import sys
from pathlib import Path

import pytest

from envdrift.scanner.gitleaks import GitleaksScanner
from envdrift.scanner.infisical import InfisicalScanner

pytestmark = [pytest.mark.integration, pytest.mark.slow]

REPO_ROOT = Path(__file__).resolve().parents[2]

# Fragment-assembled so GitHub push protection never sees the whole literal.
GITHUB_TOKEN = "ghp_" + "016C7eX9bQ2vYwN3kLmZpRtUaScDfGhJkL01"

_SCANNERS = [
    pytest.param(
        ("gitleaks", ["--gitleaks"], ".gitleaks.toml"),
        marks=pytest.mark.skipif(
            not GitleaksScanner(auto_install=False).is_installed(),
            reason="gitleaks not installed",
        ),
        id="gitleaks",
    ),
    pytest.param(
        ("infisical", ["--infisical", "--no-gitleaks"], ".infisical-scan.toml"),
        marks=pytest.mark.skipif(
            not InfisicalScanner(auto_install=False).is_installed(),
            reason="infisical not installed",
        ),
        id="infisical",
    ),
]


def _write_secret(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"GITHUB_TOKEN={GITHUB_TOKEN}\n")


def _guard(args: list[str], *, cwd: Path) -> tuple[subprocess.CompletedProcess, dict]:
    """Run ``envdrift guard <args> --json --no-auto-install`` and parse its document."""
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{REPO_ROOT / 'src'}{os.pathsep}{env.get('PYTHONPATH', '')}"
    result = subprocess.run(  # nosec B603
        [sys.executable, "-m", "envdrift.cli", "guard", *args, "--json", "--no-auto-install"],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    out = result.stdout
    assert "{" in out, f"no JSON document (rc={result.returncode})\n{out}\n{result.stderr}"
    # --pr-base prints a one-line progress notice ahead of the document.
    return result, json.loads(out[out.index("{") : out.rindex("}") + 1])


def _scanner_result(payload: dict, name: str) -> dict:
    results = [r for r in payload["scanner_results"] if r["name"] == name]
    assert len(results) == 1, payload["scanner_results"]
    return results[0]


def _scanner_paths(payload: dict, name: str) -> set[Path]:
    # Path, not str: Windows prints ``proj\\sub\\app.env``.
    return {Path(f["file_path"]) for f in payload["findings"] if f["scanner"] == name}


@pytest.mark.parametrize("scanner", _SCANNERS)
@pytest.mark.parametrize("target", ["proj", "proj/sub/app.env"])
def test_guard_relative_path_reports_relative_findings(tmp_path: Path, scanner, target: str):
    """``guard proj`` and ``guard proj/sub/app.env`` scan with no scanner error."""
    name, flags, _config = scanner
    _write_secret(tmp_path / "proj" / "sub" / "app.env")

    result, payload = _guard([target, *flags], cwd=tmp_path)

    assert result.returncode == 1, f"critical secret must exit 1\n{result.stderr}"
    assert _scanner_result(payload, name)["error"] is None
    # Displayed relative, the way guard passed the path in.
    assert _scanner_paths(payload, name) == {Path("proj/sub/app.env")}


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, capture_output=True, check=True)  # nosec B603 B607


def _feature_branch(repo: Path) -> None:
    """Commit a ``base`` branch and check out ``feature`` from it."""
    _git(repo, "checkout", "-q", "-b", "base")
    (repo / "readme.txt").write_text("hello\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "checkout", "-q", "-b", "feature")


@pytest.mark.parametrize("scanner", _SCANNERS)
def test_guard_pr_base_scans_changed_files_in_subdirectories(git_repo: Path, scanner):
    """``--pr-base`` hands scanners cwd-relative paths of the changed files."""
    name, flags, _config = scanner
    _feature_branch(git_repo)
    _write_secret(git_repo / "config" / "app.env")
    _write_secret(git_repo / "root.env")
    _git(git_repo, "add", "-A")
    _git(git_repo, "commit", "-q", "-m", "add secrets")

    # No ``origin`` remote: guard warns about the fetch and diffs the local ref.
    result, payload = _guard(["--pr-base", "base", *flags], cwd=git_repo)

    assert result.returncode == 1, f"critical secret must exit 1\n{result.stderr}"
    assert _scanner_result(payload, name)["error"] is None
    # gitleaks used to report a changed file in the cwd as ``root.env/root.env``.
    assert _scanner_paths(payload, name) == {Path("config/app.env"), Path("root.env")}


@pytest.mark.parametrize("scanner", _SCANNERS)
def test_guard_pr_base_history_reports_a_scrubbed_secret(git_repo: Path, scanner):
    """``--pr-base --history`` finds a secret the PR committed and then removed.

    The changed file is a cwd-relative file path, which Infisical's git mode
    cannot scan: it wrote an empty ``[]`` report and the run passed with exit 0
    and no scanner error, although the secret is in the PR's history (#843).
    """
    name, flags, _config = scanner
    _feature_branch(git_repo)
    _write_secret(git_repo / "config" / "settings.txt")
    _git(git_repo, "add", "-A")
    _git(git_repo, "commit", "-q", "-m", "add a secret")
    (git_repo / "config" / "settings.txt").write_text("GITHUB_TOKEN=scrubbed\n")
    _git(git_repo, "commit", "-q", "-am", "scrub the secret")

    result, payload = _guard(["--pr-base", "base", "--history", *flags], cwd=git_repo)

    assert _scanner_result(payload, name)["error"] is None
    findings = [f for f in payload["findings"] if f["scanner"] == name]
    assert findings, "the secret in the PR's history was not reported"
    # gitleaks reports its absolute history root, Infisical keeps guard's relative form.
    assert {(git_repo / f["file_path"]).resolve() for f in findings} == {
        (git_repo / "config" / "settings.txt").resolve()
    }
    assert all(f["commit_sha"] for f in findings)
    # The secret blocks at its severity's exit code (critical 1, high 2).
    assert result.returncode in (1, 2), f"rc={result.returncode}\n{result.stderr}"


@pytest.mark.parametrize("scanner", _SCANNERS)
def test_guard_history_outside_a_repository_exits_5(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner
):
    """A history scan that cannot run is a scanner error, so guard exits 5.

    Infisical's git mode exits 1 with an empty ``[]`` report for a directory
    outside a repository, which passed as a clean scan (#843).
    """
    name, flags, _config = scanner
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    (tmp_path / "plain").mkdir()
    (tmp_path / "plain" / "readme.txt").write_text("nothing to see\n")

    result, payload = _guard(["plain", "--history", *flags], cwd=tmp_path)

    error = _scanner_result(payload, name)["error"]
    assert error, "a history scan outside a repository must fail"
    assert "not inside a Git repository" in error
    assert result.returncode == 5, f"rc={result.returncode}\n{result.stderr}"


@pytest.mark.parametrize("scanner", _SCANNERS)
def test_guard_json_scanner_error_is_ansi_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner
):
    """A failing binary's colored stderr reaches ``--json`` without escapes.

    A malformed scanner config in the scanned directory makes the real binary
    exit with a colored ``FTL`` line. The integration conftest sets
    ``NO_COLOR``, which these binaries honour, so it is removed here.
    """
    name, flags, config = scanner
    monkeypatch.delenv("NO_COLOR", raising=False)
    _write_secret(tmp_path / "proj" / "app.env")
    (tmp_path / "proj" / config).write_text("[[rules]\nid = \n")

    result, payload = _guard(["proj", *flags], cwd=tmp_path)

    error = _scanner_result(payload, name)["error"]
    assert error, "a malformed scanner config must fail the scan"
    assert "config" in error
    assert "\x1b" not in error, repr(error)
    assert "○" not in error, f"gitleaks banner in error: {error!r}"
    assert "\x1b" not in result.stdout
    assert "\\u001b" not in result.stdout
    # The native scanner still reports the critical secret, and blocking
    # findings take precedence over the scanner error (docs/cli/guard.md).
    assert result.returncode == 1, result.stderr


@pytest.mark.parametrize("scanner", _SCANNERS)
@pytest.mark.xfail(
    strict=False,
    raises=AssertionError,
    reason="an absolute path is passed unchanged and the binaries do not walk into a "
    "symlinked root (see #853)",
)
def test_guard_absolute_symlinked_directory_is_scanned(tmp_path: Path, scanner):
    """An absolute path to a symlinked directory scans like the relative one."""
    name, flags, _config = scanner
    _write_secret(tmp_path / "repo" / "proj" / "sub" / "app.env")
    link = tmp_path / "linkproj"
    try:
        link.symlink_to(tmp_path / "repo" / "proj", target_is_directory=True)
    except OSError as exc:  # Windows without symlink privilege
        pytest.skip(f"cannot create a symlink here: {exc}")

    _result, payload = _guard([str(link), *flags], cwd=tmp_path)

    assert _scanner_result(payload, name)["error"] is None
    assert _scanner_paths(payload, name), f"{name} reported nothing for {link}"


@pytest.mark.skipif(
    not GitleaksScanner(auto_install=False).is_installed(), reason="gitleaks not installed"
)
@pytest.mark.xfail(
    strict=False,
    raises=AssertionError,
    reason="gitleaks runs in each changed file's directory, so a repo-root "
    ".gitleaksignore misses nested files (see #854)",
)
def test_guard_pr_base_honours_repo_root_gitleaksignore_for_nested_files(git_repo: Path):
    """A repo-root ``.gitleaksignore`` suppresses nested and root-level files alike."""
    _feature_branch(git_repo)
    _write_secret(git_repo / "config" / "settings.txt")
    _write_secret(git_repo / "top.txt")
    (git_repo / ".gitleaksignore").write_text(
        "config/settings.txt:github-pat:1\ntop.txt:github-pat:1\n"
    )
    _git(git_repo, "add", "-A")
    _git(git_repo, "commit", "-q", "-m", "feature")

    _result, payload = _guard(["--pr-base", "base", "--gitleaks"], cwd=git_repo)

    assert _scanner_result(payload, "gitleaks")["error"] is None
    assert _scanner_paths(payload, "gitleaks") == set()


@pytest.mark.skipif(
    not GitleaksScanner(auto_install=False).is_installed(), reason="gitleaks not installed"
)
@pytest.mark.xfail(
    strict=False,
    raises=AssertionError,
    reason="native resolves a directory target to absolute paths while gitleaks keeps "
    "the cwd-relative form (see #855)",
)
def test_guard_reports_one_path_form_per_file(tmp_path: Path):
    """Every scanner names ``proj/sub/app.env`` the same way in one report."""
    _write_secret(tmp_path / "proj" / "sub" / "app.env")

    _result, payload = _guard(["proj", "--gitleaks"], cwd=tmp_path)

    forms = {f["file_path"] for f in payload["findings"]}
    assert len(forms) == 1, sorted(forms)
