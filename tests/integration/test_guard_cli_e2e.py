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
- #476   git-scoped collection must never silently pass (--pr-base / --staged / --history)
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

    ``git diff --cached`` yields repo-root-relative paths, so the guard must
    resolve them against the git toplevel rather than the process cwd. From the
    repo root and from a repo subdirectory the staged AWS secret is caught
    identically (exit 1). This is the regression guard for #302, where running
    from ``sub/`` made ``Path(f).exists()`` false and silently dropped the whole
    staged set to "No staged files to scan." (exit 0).
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

    # From a subdirectory: the SAME leak detection (exit 1) — repo-relative
    # staged paths are resolved against the git toplevel, not the subdir cwd.
    sub_dir = work_dir / "sub"
    sub_result = _run_envdrift(["guard", "--staged", "--native-only"], cwd=sub_dir)
    combined = sub_result.stdout + sub_result.stderr
    assert "No staged files to scan." not in combined, (
        f"staged scan from a subdir must not silently drop staged files\n{combined}"
    )
    assert sub_result.returncode == 1, (
        f"staged scan from a subdir must catch the leak, got {sub_result.returncode}\n{combined}"
    )
    sub_json = _guard_json(
        _run_envdrift(["guard", "--staged", "--native-only", "--json"], cwd=sub_dir)
    )
    assert "aws-secret-access-key" in _rule_ids(sub_json)


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


# --- #476: git-scoped collection must never silently pass ------------------------
#
# The three git-scoped collection modes each promised one thing and scanned
# another: an unresolvable --pr-base ref was conflated with "no changed files"
# (green CI pass), --staged scanned working-tree copies instead of the staged
# index blobs, and --history was silently dropped when no active scanner
# supports git history. Each test below drives the real CLI as a subprocess
# against a real git repository.

_LEAK_LINE = f'aws_secret_access_key = "{_AWS_SECRET}"\n'


def test_pr_base_unresolvable_ref_fails_loudly(git_repo: Path) -> None:
    """An unresolvable ``--pr-base`` ref is an error, never a green pass (#476).

    ``git diff <base>...HEAD`` exits 128 for a typo'd/unfetched base. Guard must
    exit non-zero with a structured error instead of reporting "No changed files
    to scan" with exit 0 — that green pass let a committed secret through CI.
    The fetch failure must also be surfaced on stderr (it was verbose-gated).
    """
    work_dir = git_repo
    (work_dir / "leak.py").write_text(_LEAK_LINE, encoding="utf-8")
    _run_git(["add", "leak.py"], cwd=work_dir)
    _run_git(["commit", "-m", "add leak"], cwd=work_dir)

    result = _run_envdrift(
        [
            "guard",
            "--pr-base",
            "does-not-exist-branch",
            "--native-only",
            "--no-auto-install",
            "--json",
        ],
        cwd=work_dir,
    )
    assert result.returncode == 1, (
        f"unresolvable --pr-base must exit 1, got {result.returncode}\n"
        f"{result.stdout}\n{result.stderr}"
    )
    # stdout stays a clean machine-readable error document.
    payload = json.loads(result.stdout)
    assert "error" in payload, payload
    assert "does-not-exist-branch" in payload["error"]
    # The failed `git fetch` is surfaced on stderr, not silently swallowed.
    assert "warning" in result.stderr.lower(), result.stderr

    # Human mode: explicit error, no "No changed files" green prose.
    human = _run_envdrift(
        ["guard", "--pr-base", "does-not-exist-branch", "--native-only", "--no-auto-install"],
        cwd=work_dir,
    )
    out = " ".join((human.stdout + human.stderr).split())
    assert human.returncode == 1, f"expected 1, got {human.returncode}\n{out}"
    assert "Error" in out, out
    assert "does-not-exist-branch" in out, out
    assert "No changed files to scan" not in out, out


def test_pr_base_resolvable_ref_with_empty_diff_still_passes(git_repo: Path) -> None:
    """A resolvable base with a genuinely empty diff keeps the clean exit 0 (#476).

    The unresolvable-ref fix must distinguish git failure (rc != 0) from an
    empty-but-successful diff: ``--pr-base HEAD`` resolves and produces no
    changed files, so guard still passes with an empty findings document.
    """
    work_dir = git_repo
    (work_dir / "readme.txt").write_text("hello world\n", encoding="utf-8")
    _run_git(["add", "readme.txt"], cwd=work_dir)
    _run_git(["commit", "-m", "init"], cwd=work_dir)

    result = _run_envdrift(
        ["guard", "--pr-base", "HEAD", "--native-only", "--no-auto-install", "--json"],
        cwd=work_dir,
    )
    assert result.returncode == 0, (
        f"empty diff against a resolvable base must exit 0, got {result.returncode}\n"
        f"{result.stdout}\n{result.stderr}"
    )
    payload = json.loads(result.stdout)
    assert payload["findings"] == []


def test_staged_scans_index_blob_not_worktree(git_repo: Path) -> None:
    """``--staged`` scans the staged index blob, not the working-tree copy (#476).

    Repro from the issue: a secret is staged, then the working-tree copy is
    overwritten with clean content. The about-to-be-committed secret lives only
    in the index — guard must flag it (exit 1), and the finding must point at
    the repo file, not at any temporary scan location.
    """
    work_dir = git_repo
    app = work_dir / "app.env"
    app.write_text(_LEAK_LINE, encoding="utf-8")
    _run_git(["add", "app.env"], cwd=work_dir)
    # Working tree now clean; the leak exists only in the staged index blob.
    app.write_text('aws_secret_access_key = "redacted"\n', encoding="utf-8")

    result = _run_envdrift(
        ["guard", "--staged", "--native-only", "--no-auto-install", "--json"], cwd=work_dir
    )
    assert result.returncode == 1, (
        f"staged-only secret must fail the gate, got {result.returncode}\n"
        f"{result.stdout}\n{result.stderr}"
    )
    payload = _guard_json(result)
    assert "aws-secret-access-key" in _rule_ids(payload), payload["findings"]
    reported = {f["file_path"] for f in payload["findings"]}
    assert "app.env" in reported, reported
    assert all("envdrift-staged-" not in p for p in reported), reported


def test_staged_file_deleted_from_worktree_still_scanned(git_repo: Path) -> None:
    """A staged file deleted from the working tree is still scanned (#476).

    The old collection resolved staged names to filesystem paths and dropped
    non-existent ones, so ``git add app.env; rm app.env`` produced "No staged
    files to scan." and exit 0 while the commit still shipped the secret.
    """
    work_dir = git_repo
    app = work_dir / "app.env"
    app.write_text(_LEAK_LINE, encoding="utf-8")
    _run_git(["add", "app.env"], cwd=work_dir)
    app.unlink()

    result = _run_envdrift(
        ["guard", "--staged", "--native-only", "--no-auto-install", "--json"], cwd=work_dir
    )
    combined = result.stdout + result.stderr
    assert "No staged files to scan" not in combined, combined
    assert result.returncode == 1, f"expected 1, got {result.returncode}\n{combined}"
    payload = _guard_json(result)
    assert "aws-secret-access-key" in _rule_ids(payload), payload["findings"]


def test_staged_worktree_only_secret_not_flagged(git_repo: Path) -> None:
    """A secret present only in the working tree is NOT a staged finding (#476).

    The sharp converse of the index-blob test: clean content is staged, then a
    secret is written to the working tree without ``git add``. The commit would
    ship the clean blob, so ``--staged`` must pass — flagging the unstaged
    worktree copy would prove the scan still reads the wrong content.
    """
    work_dir = git_repo
    app = work_dir / "app.env"
    app.write_text('aws_secret_access_key = "redacted"\n', encoding="utf-8")
    _run_git(["add", "app.env"], cwd=work_dir)
    # Secret exists only in the (unstaged) working tree.
    app.write_text(_LEAK_LINE, encoding="utf-8")

    result = _run_envdrift(
        ["guard", "--staged", "--native-only", "--no-auto-install", "--json"], cwd=work_dir
    )
    assert result.returncode == 0, (
        f"unstaged worktree secret must not fail --staged, got {result.returncode}\n"
        f"{result.stdout}\n{result.stderr}"
    )
    payload = _guard_json(result)
    assert payload["findings"] == []


def test_staged_private_key_file_still_critical(git_repo: Path) -> None:
    """A staged ``.env.keys`` keeps its CRITICAL committed-private-key rule (#476).

    The committed-private-key rule asks git whether the file is tracked/staged
    (``is_file_tracked``). Scanning staged index blobs must preserve that
    answer — every collected file IS staged — or the pre-commit gate generated
    by ``envdrift hook`` would silently stop blocking committed key files.
    """
    work_dir = git_repo
    keys = work_dir / ".env.keys"
    keys.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=abc123def456\n", encoding="utf-8")
    _run_git(["add", "-f", ".env.keys"], cwd=work_dir)

    result = _run_envdrift(
        ["guard", "--staged", "--native-only", "--no-auto-install", "--json"], cwd=work_dir
    )
    assert result.returncode == 1, (
        f"staged .env.keys must stay CRITICAL, got {result.returncode}\n"
        f"{result.stdout}\n{result.stderr}"
    )
    payload = _guard_json(result)
    assert "committed-private-key" in _rule_ids(payload), payload["findings"]


def test_staged_outside_git_repo_fails_loudly(tmp_path: Path) -> None:
    """``--staged`` outside a git repository is an error, not a green pass (#476).

    ``git diff --cached`` exits 128 outside a repo; the old collection conflated
    that with "no staged files" and passed with exit 0.
    """
    result = _run_envdrift(
        ["guard", "--staged", "--native-only", "--no-auto-install", "--json"], cwd=tmp_path
    )
    assert result.returncode == 1, (
        f"--staged outside a repo must exit 1, got {result.returncode}\n"
        f"{result.stdout}\n{result.stderr}"
    )
    payload = json.loads(result.stdout)
    assert "error" in payload, payload


def test_history_without_history_capable_scanner_fails_loudly(git_repo: Path) -> None:
    """``--history`` with only history-incapable scanners is an error (#476).

    The native scanner cannot scan git history, so ``--history --native-only``
    silently scanned nothing extra and reported a clean pass while a secret sat
    in an earlier commit. Guard must refuse the combination instead.
    """
    work_dir = git_repo
    leak = work_dir / "leak.py"
    leak.write_text(_LEAK_LINE, encoding="utf-8")
    _run_git(["add", "leak.py"], cwd=work_dir)
    _run_git(["commit", "-m", "add leak"], cwd=work_dir)
    leak.write_text("clean = true\n", encoding="utf-8")
    _run_git(["add", "leak.py"], cwd=work_dir)
    _run_git(["commit", "-m", "remove leak"], cwd=work_dir)

    result = _run_envdrift(
        ["guard", "--history", "--native-only", "--no-auto-install", "--json"], cwd=work_dir
    )
    assert result.returncode == 1, (
        f"--history with no history-capable scanner must exit 1, got {result.returncode}\n"
        f"{result.stdout}\n{result.stderr}"
    )
    payload = json.loads(result.stdout)
    assert "error" in payload, payload
    assert "history" in payload["error"].lower(), payload

    human = _run_envdrift(
        ["guard", "--history", "--native-only", "--no-auto-install"], cwd=work_dir
    )
    out = " ".join((human.stdout + human.stderr).split())
    assert human.returncode == 1, f"expected 1, got {human.returncode}\n{out}"
    assert "Error" in out, out
    assert "No secrets or policy violations detected" not in out, out


def test_staged_custom_mapped_env_file_policy_still_fires(git_repo: Path) -> None:
    """A staged custom mapped env file keeps its unencrypted-env-file rule (#476).

    Custom ``vault.sync`` env files are recognized by canonical absolute path
    (``mapped_env_files``). Scanning staged index blobs from a mirror must not
    break that match — ``envdrift hook`` relies on ``guard --staged`` blocking a
    plaintext mapped file at commit time.
    """
    work_dir = git_repo
    (work_dir / "envdrift.toml").write_text(
        textwrap.dedent(
            """\
            [vault]
            provider = "azure"

            [vault.sync]
            [[vault.sync.mappings]]
            secret_name = "test-postgresql-key"
            folder_path = "secrets/postgresql"
            environment = "production"
            env_file = "postgresql.env"
            """
        ),
        encoding="utf-8",
    )
    service_dir = work_dir / "secrets" / "postgresql"
    service_dir.mkdir(parents=True)
    env_file = service_dir / "postgresql.env"
    env_file.write_text("POSTGRES_PASSWORD=plaintext-leak\n", encoding="utf-8")
    _run_git(["add", "envdrift.toml", "secrets/postgresql/postgresql.env"], cwd=work_dir)

    result = _run_envdrift(
        ["guard", "--staged", "--native-only", "--no-auto-install", "--json"], cwd=work_dir
    )
    assert result.returncode != 0, (
        f"staged plaintext mapped env file must fail the gate, got {result.returncode}\n"
        f"{result.stdout}\n{result.stderr}"
    )
    payload = _guard_json(result)
    rule_ids = _rule_ids(payload)
    assert "unencrypted-env-file" in rule_ids, payload["findings"]
    mapped = [f for f in payload["findings"] if f["rule_id"] == "unencrypted-env-file"]
    assert any("postgresql.env" in f["file_path"] for f in mapped), mapped
