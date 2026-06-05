"""End-to-end integration tests for the ``envdrift guard`` CLI.

These tests drive the real ``envdrift guard`` command as a subprocess against a
real git repository and the native scanner only (``--native-only``). No external
scanner binaries are required, so every test runs both locally and in CI.

Coverage (highest value first):
- HP-03  test_pr_base_scan_catches_leak_with_fake_remote (P0)
- HP-12  test_ci_fail_on_high_suppresses_medium_finding_exit_zero (P0)
- BP-16  test_critical_finding_exit_code_one_non_ci (P0)
- BP-16  test_committed_private_key_exit_code_one (P0)
- BP-17  test_high_unencrypted_env_file_exit_code_two_non_ci (P0)
- BUG    test_staged_secret_dropped_when_run_from_subdirectory (P0)
- HP-17  test_allowed_clear_file_exempt_from_unencrypted_but_secrets_still_scanned (P0)
- HP-10  test_entropy_flag_enables_high_entropy_detection (P1)
- BP-01  test_path_not_found_exits_one (P1)
- EC-21  test_skip_clear_overrides_allowed_clear_files_allowlist (P1)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration]

REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHONPATH = str(REPO_ROOT / "src")

# A canonical 40-char AWS secret access key (same shape AWS itself documents).
# Placed after an ``aws_secret_access_key`` key so the native CRITICAL pattern
# ``aws-secret-access-key`` matches deterministically.
_AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def _run_envdrift(
    args: list[str], *, cwd: Path, env: dict[str, str] | None = None, check: bool = False
) -> subprocess.CompletedProcess:
    """Run the envdrift CLI as a subprocess (native scanner, real process)."""
    run_env = os.environ.copy()
    run_env["PYTHONPATH"] = f"{PYTHONPATH}{os.pathsep}{run_env.get('PYTHONPATH', '')}"
    if env:
        run_env.update(env)
    cmd = [sys.executable, "-m", "envdrift.cli", *args]
    result = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=run_env,
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"envdrift failed\ncmd: {' '.join(cmd)}\n"
            f"cwd: {cwd}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def _run_git(
    args: list[str], *, cwd: Path, env: dict[str, str] | None = None, check: bool = True
) -> subprocess.CompletedProcess:
    """Run a git command, gating cleanly if git is unavailable."""
    git_path = shutil.which("git")
    if git_path is None:
        pytest.skip("git is not available")

    git_env = os.environ.copy()
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
        git_env.pop(key, None)
    if env:
        git_env.update(env)

    result = subprocess.run(
        [git_path, *args],
        cwd=str(cwd),
        env=git_env,
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"git failed\ncmd: git {' '.join(args)}\n"
            f"cwd: {cwd}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def _guard_json(result: subprocess.CompletedProcess) -> dict:
    """Parse the JSON document printed by ``guard --json``.

    ``--json`` prints one JSON document on stdout. In ``--staged``/``--pr-base``
    modes a one-line progress notice ("Scanning N staged file(s)...") is printed
    ahead of it, so slice from the first ``{`` to the last ``}`` before decoding.
    """
    out = result.stdout
    start = out.index("{")
    end = out.rindex("}") + 1
    return json.loads(out[start:end])


def _rule_ids(payload: dict) -> list[str]:
    return [f["rule_id"] for f in payload["findings"]]


# --- HP-03 (P0): --pr-base diffs a fake remote, scans only changed files -------


def test_pr_base_scan_catches_leak_with_fake_remote(git_repo: Path) -> None:
    """``guard --pr-base origin/main`` scans only files changed since the base.

    A benign ``readme.txt`` lives on the base branch; the feature branch adds a
    single ``leak.py`` carrying an AWS secret. Only that one changed file must be
    scanned, the leak must fail the run (exit 1), and the untouched/benign
    ``readme.txt`` must never appear in the diff set.
    """
    work_dir = git_repo
    # Recreate the repo on an explicit ``main`` branch so origin/main is stable.
    shutil.rmtree(work_dir / ".git")
    _run_git(["init", "-b", "main"], cwd=work_dir)
    _run_git(["config", "user.email", "test@test.com"], cwd=work_dir)
    _run_git(["config", "user.name", "Test User"], cwd=work_dir)

    (work_dir / "readme.txt").write_text("hello world\n")
    _run_git(["add", "readme.txt"], cwd=work_dir)
    _run_git(["commit", "-m", "init"], cwd=work_dir)

    # Fake bare remote that origin/main can point at.
    remote = work_dir.parent / f"{work_dir.name}_remote.git"
    _run_git(["init", "--bare", str(remote)], cwd=work_dir.parent)
    _run_git(["remote", "add", "origin", str(remote)], cwd=work_dir)
    _run_git(["push", "origin", "main"], cwd=work_dir)

    # Feature branch: add exactly one new file with a leak.
    _run_git(["checkout", "-b", "feature"], cwd=work_dir)
    (work_dir / "leak.py").write_text(f'aws_secret_access_key = "{_AWS_SECRET}"\n')
    _run_git(["add", "leak.py"], cwd=work_dir)
    _run_git(["commit", "-m", "add leak"], cwd=work_dir)

    result = _run_envdrift(["guard", "--native-only", "--pr-base", "origin/main"], cwd=work_dir)
    combined = result.stdout + result.stderr

    assert result.returncode == 1, f"expected critical exit 1, got {result.returncode}\n{combined}"
    assert "Scanning 1 file(s) changed since origin/main" in combined, combined
    assert "critical" in combined.lower()
    # readme.txt is on the base, unchanged — it must not be in the diff/scan set.
    assert "readme.txt" not in combined, combined

    # Confirm the precise finding via JSON.
    json_result = _run_envdrift(
        ["guard", "--native-only", "--pr-base", "origin/main", "--json"], cwd=work_dir
    )
    payload = _guard_json(json_result)
    assert "aws-secret-access-key" in _rule_ids(payload)
    assert payload["summary"]["by_severity"]["critical"] >= 1


# --- HP-12 (P0): CI --fail-on high suppresses a below-threshold MEDIUM ----------


def test_ci_fail_on_high_suppresses_medium_finding_exit_zero(git_repo: Path) -> None:
    """``--ci --fail-on high`` downgrades a MEDIUM-only run to exit 0.

    A high-entropy string in a non-env file is a MEDIUM finding. With ``--ci
    --fail-on high`` it is below threshold and the run exits 0; the identical scan
    without ``--ci`` keeps the native exit code 3 (medium).
    """
    work_dir = git_repo
    target = work_dir / "settings.py"
    target.write_text('SESSION_TOKEN = "Xq7Lp2Vz9Kw4Nt8Rb3Yc6Hd1Mf5Gj0Sa"\n')
    _run_git(["add", "settings.py"], cwd=work_dir)

    # Sanity: the finding really is MEDIUM-only.
    json_result = _run_envdrift(
        ["guard", "--native-only", "--entropy", "--json", "settings.py"], cwd=work_dir
    )
    payload = _guard_json(json_result)
    assert "high-entropy-string" in _rule_ids(payload)
    by_sev = payload["summary"]["by_severity"]
    assert by_sev["medium"] >= 1
    assert by_sev["critical"] == 0 and by_sev["high"] == 0

    # Without --ci: medium -> native exit code 3.
    non_ci = _run_envdrift(["guard", "--native-only", "--entropy", "settings.py"], cwd=work_dir)
    assert non_ci.returncode == 3, f"expected 3, got {non_ci.returncode}\n{non_ci.stdout}"

    # With --ci --fail-on high: medium is below threshold -> exit 0.
    ci = _run_envdrift(
        ["guard", "--native-only", "--entropy", "--ci", "--fail-on", "high", "settings.py"],
        cwd=work_dir,
    )
    assert ci.returncode == 0, f"expected 0, got {ci.returncode}\n{ci.stdout}\n{ci.stderr}"


# --- BP-16 (P0): an AWS secret in a tracked file -> exit 1 (non-CI) -------------


def test_critical_finding_exit_code_one_non_ci(git_repo: Path) -> None:
    """A tracked AWS secret yields a CRITICAL finding and exit 1 in a non-CI run."""
    work_dir = git_repo
    target = work_dir / "config.py"
    target.write_text(f'aws_secret_access_key = "{_AWS_SECRET}"\n')
    _run_git(["add", "config.py"], cwd=work_dir)

    result = _run_envdrift(["guard", "--native-only", "config.py"], cwd=work_dir)
    assert result.returncode == 1, f"expected 1, got {result.returncode}\n{result.stdout}"
    assert "critical" in (result.stdout + result.stderr).lower()

    payload = _guard_json(
        _run_envdrift(["guard", "--native-only", "--json", "config.py"], cwd=work_dir)
    )
    assert "aws-secret-access-key" in _rule_ids(payload)
    assert payload["summary"]["by_severity"]["critical"] >= 1
    assert payload["exit_code"] == 1


# --- BP-16 (P0, second vector): tracked .env.keys -> committed-private-key ------


def test_committed_private_key_exit_code_one(git_repo: Path) -> None:
    """A tracked ``.env.keys`` private-key file is CRITICAL and exits 1."""
    work_dir = git_repo
    keys = work_dir / ".env.keys"
    keys.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=abc123def456\n")
    # The rule only fires when git tracks/stages the key file.
    _run_git(["add", "-f", ".env.keys"], cwd=work_dir)

    result = _run_envdrift(["guard", "--native-only", ".env.keys"], cwd=work_dir)
    assert result.returncode == 1, f"expected 1, got {result.returncode}\n{result.stdout}"
    assert "critical" in (result.stdout + result.stderr).lower()

    payload = _guard_json(
        _run_envdrift(["guard", "--native-only", "--json", ".env.keys"], cwd=work_dir)
    )
    assert "committed-private-key" in _rule_ids(payload)
    assert payload["summary"]["by_severity"]["critical"] >= 1
    assert payload["exit_code"] == 1


# --- BP-17 (P0): plaintext .env.production -> unencrypted-env-file HIGH, exit 2 --


def test_high_unencrypted_env_file_exit_code_two_non_ci(git_repo: Path) -> None:
    """A plaintext ``.env.production`` is a HIGH unencrypted-env-file (exit 2)."""
    work_dir = git_repo
    env_file = work_dir / ".env.production"
    env_file.write_text("API_KEY=plainvalue123\nDB_PASSWORD=hunter2\n")
    _run_git(["add", "-f", ".env.production"], cwd=work_dir)

    result = _run_envdrift(["guard", "--native-only", ".env.production"], cwd=work_dir)
    assert result.returncode == 2, f"expected 2, got {result.returncode}\n{result.stdout}"

    payload = _guard_json(
        _run_envdrift(["guard", "--native-only", "--json", ".env.production"], cwd=work_dir)
    )
    assert "unencrypted-env-file" in _rule_ids(payload)
    by_sev = payload["summary"]["by_severity"]
    assert by_sev["high"] >= 1
    assert by_sev["critical"] == 0
    assert payload["exit_code"] == 2


# --- BUG-SUBDIR-STAGED (P0): --staged from a subdirectory must catch the leak ---


def test_staged_secret_dropped_when_run_from_subdirectory(git_repo: Path) -> None:
    """``guard --staged`` must catch a staged leak regardless of the run cwd.

    From the repo root the staged AWS secret is correctly caught (exit 1). The
    desired behaviour is identical from a repo subdirectory: ``git diff --cached``
    yields repo-relative paths, so running from ``sub/`` currently makes
    ``Path(f).exists()`` false and the whole staged set is silently dropped to
    "No staged files to scan." (exit 0) — a real leak slips through. That
    subdirectory expectation is asserted under xfail so the bug is documented and
    will flip the test to a hard failure once the code resolves staged paths
    against the repo root.
    """
    work_dir = git_repo
    (work_dir / "sub").mkdir()
    leak = work_dir / "sub" / "leak.py"
    leak.write_text(f'aws_secret_access_key = "{_AWS_SECRET}"\n')
    _run_git(["add", "sub/leak.py"], cwd=work_dir)

    # From the repo root: the staged leak is caught.
    root_result = _run_envdrift(["guard", "--staged", "--native-only"], cwd=work_dir)
    assert root_result.returncode == 1, (
        f"staged scan from root must catch the leak, got {root_result.returncode}\n"
        f"{root_result.stdout}\n{root_result.stderr}"
    )
    root_json = _guard_json(
        _run_envdrift(["guard", "--staged", "--native-only", "--json"], cwd=work_dir)
    )
    assert "aws-secret-access-key" in _rule_ids(root_json)

    # From a subdirectory: desired behaviour is the SAME leak detection (exit 1).
    sub_dir = work_dir / "sub"
    sub_result = _run_envdrift(["guard", "--staged", "--native-only"], cwd=sub_dir)
    combined = sub_result.stdout + sub_result.stderr
    if sub_result.returncode == 0 and "No staged files to scan." in combined:
        pytest.xfail(
            "Known bug (#302): guard --staged from a repo subdirectory drops staged files "
            "(repo-relative paths fail Path.exists() against the subdir cwd) and "
            "exits 0 instead of catching the staged leak."
        )
    assert sub_result.returncode == 1, (
        f"staged scan from a subdir must catch the leak, got {sub_result.returncode}\n{combined}"
    )


# --- HP-17 (P0): allowed clear_file exempt from unencrypted, secrets still found -


_PARTIAL_CONFIG = textwrap.dedent(
    """\
    [partial_encryption]
    enabled = true

    [[partial_encryption.environments]]
    name = "production"
    clear_file = ".env.production.clear"
    secret_file = ".env.production.secret"
    combined_file = ".env.production"
    """
)


def test_allowed_clear_file_exempt_from_unencrypted_but_secrets_still_scanned(
    git_repo: Path,
) -> None:
    """A declared ``clear_file`` is exempt from unencrypted-env-file, not from secrets.

    The partial_encryption ``clear_file`` is intentionally plaintext, so it must
    NOT be flagged as ``unencrypted-env-file`` (HIGH). But an AWS secret embedded
    in it is still a real leak and must be reported as CRITICAL.
    """
    work_dir = git_repo
    (work_dir / "envdrift.toml").write_text(_PARTIAL_CONFIG)
    clear = work_dir / ".env.production.clear"
    clear.write_text(f"LOG_LEVEL=info\naws_secret_access_key={_AWS_SECRET}\n")
    _run_git(["add", "-f", ".env.production.clear", "envdrift.toml"], cwd=work_dir)

    result = _run_envdrift(["guard", "--native-only", ".env.production.clear"], cwd=work_dir)
    assert result.returncode == 1, f"expected 1, got {result.returncode}\n{result.stdout}"

    payload = _guard_json(
        _run_envdrift(["guard", "--native-only", "--json", ".env.production.clear"], cwd=work_dir)
    )
    rule_ids = _rule_ids(payload)
    assert "aws-secret-access-key" in rule_ids
    assert "unencrypted-env-file" not in rule_ids
    by_sev = payload["summary"]["by_severity"]
    assert by_sev["high"] == 0
    assert by_sev["critical"] >= 1


# --- HP-10 (P1): --entropy enables high-entropy detection on a non-env file -----


def test_entropy_flag_enables_high_entropy_detection(git_repo: Path) -> None:
    """``--entropy`` turns on high-entropy MEDIUM detection for non-env files.

    Without the flag, a high-entropy string in a ``.py`` file produces no findings;
    with ``--entropy`` it produces a MEDIUM ``high-entropy-string`` finding (exit 3).
    """
    work_dir = git_repo
    target = work_dir / "settings.py"
    target.write_text('SESSION_TOKEN = "Xq7Lp2Vz9Kw4Nt8Rb3Yc6Hd1Mf5Gj0Sa"\n')
    _run_git(["add", "settings.py"], cwd=work_dir)

    # Off by default for non-env files.
    off = _run_envdrift(["guard", "--native-only", "--json", "settings.py"], cwd=work_dir)
    off_payload = _guard_json(off)
    assert off_payload["findings"] == []
    assert off_payload["exit_code"] == 0

    # On with --entropy: a MEDIUM high-entropy finding (exit 3).
    on = _run_envdrift(
        ["guard", "--native-only", "--entropy", "--json", "settings.py"], cwd=work_dir
    )
    on_payload = _guard_json(on)
    high_entropy = [f for f in on_payload["findings"] if f["rule_id"] == "high-entropy-string"]
    assert high_entropy, on_payload["findings"]
    assert all(f["severity"] == "medium" for f in high_entropy)
    assert on_payload["exit_code"] == 3

    on_cli = _run_envdrift(["guard", "--native-only", "--entropy", "settings.py"], cwd=work_dir)
    assert on_cli.returncode == 3, f"expected 3, got {on_cli.returncode}\n{on_cli.stdout}"


# --- BP-01 (P1): scanning a nonexistent path exits 1 ----------------------------


def test_path_not_found_exits_one(git_repo: Path) -> None:
    """Scanning a path that does not exist exits 1 with a 'Path not found' message."""
    work_dir = git_repo
    result = _run_envdrift(["guard", "--native-only", "./does_not_exist.py"], cwd=work_dir)
    assert result.returncode == 1, f"expected 1, got {result.returncode}\n{result.stdout}"
    assert "Path not found" in (result.stdout + result.stderr)


# --- EC-21 (P1): --skip-clear overrides the allowed_clear_files allowlist --------


def test_skip_clear_overrides_allowed_clear_files_allowlist(git_repo: Path) -> None:
    """``--skip-clear`` skips a declared ``clear_file`` entirely (no findings at all).

    With the partial_encryption allowlist, the embedded AWS secret is normally
    reported. ``--skip-clear`` takes precedence and the ``.clear`` file is skipped
    outright, so the secret is never reported and the run exits 0.
    """
    work_dir = git_repo
    (work_dir / "envdrift.toml").write_text(_PARTIAL_CONFIG)
    clear = work_dir / ".env.production.clear"
    clear.write_text(f"LOG_LEVEL=info\naws_secret_access_key={_AWS_SECRET}\n")
    _run_git(["add", "-f", ".env.production.clear", "envdrift.toml"], cwd=work_dir)

    # Without --skip-clear: the embedded secret is reported (exit 1).
    without = _guard_json(
        _run_envdrift(["guard", "--native-only", "--json", ".env.production.clear"], cwd=work_dir)
    )
    assert "aws-secret-access-key" in _rule_ids(without)

    # With --skip-clear: the file is skipped entirely, no findings, exit 0.
    result = _run_envdrift(
        ["guard", "--native-only", "--skip-clear", ".env.production.clear"], cwd=work_dir
    )
    assert result.returncode == 0, f"expected 0, got {result.returncode}\n{result.stdout}"
    skipped = _guard_json(
        _run_envdrift(
            ["guard", "--native-only", "--skip-clear", "--json", ".env.production.clear"],
            cwd=work_dir,
        )
    )
    assert skipped["findings"] == []
    assert skipped["exit_code"] == 0
