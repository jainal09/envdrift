"""End-to-end regression tests for guard exit-code truthfulness (#478).

Each test drives the real ``envdrift guard`` CLI as a subprocess, reproducing
the exact issue repros:

- A selected scanner that RAN AND FAILED (real talisman on a git repo with no
  commits) must fail the run with the dedicated scan-error exit 5 — not the
  green all-clear exit 0 — and the ``--json`` fields must agree.
- Under ``--ci --fail-on`` the ``--json``/``--sarif`` verdict fields must match
  the actual process exit in both directions.
- ``[guard] ignore_rules`` as a TOML list and a quoted ``entropy_threshold``
  must be clean config outcomes, never a mid-scan crash or a green false PASS.
- ``check_entropy = false`` must actually disable entropy detection.
- Operational errors exit 6, distinct from critical's exit 1.

Secret-shaped fixture values are built by string concatenation only, so no
realistic literal ever appears in the repository (GitHub push protection).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration]

REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHONPATH = str(REPO_ROOT / "src")

# Prefix-less, non-keyword high-entropy value: only the entropy gate flags it.
_ENTROPY_SECRET = "Zx9Kq2Wm7" + "Lp4Rt8Nv6" + "Bs3Yd1Hf5Gj0Qc"
# 64 hex chars, the issue's repro token shape for the entropy-threshold crash.
_HEX_TOKEN = "a1b2c3d4" * 8


def _run_envdrift(
    args: list[str], *, cwd: Path, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess:
    """Run the envdrift CLI as a real subprocess."""
    run_env = os.environ.copy()
    run_env["PYTHONPATH"] = f"{PYTHONPATH}{os.pathsep}{run_env.get('PYTHONPATH', '')}"
    if env:
        run_env.update(env)
    cmd = [sys.executable, "-m", "envdrift.cli", *args]
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=run_env,
        capture_output=True,
        text=True,
    )


def _guard_json(result: subprocess.CompletedProcess) -> dict:
    """Parse the JSON document printed by ``guard --json``.

    Parses the whole stdout strictly: the contract is that ``--json`` stdout
    IS the document, and ``json.JSONDecodeError`` shows what was printed.
    """
    return json.loads(result.stdout)


def _rule_ids(payload: dict) -> set[str]:
    return {f["rule_id"] for f in payload["findings"]}


def _init_repo_no_commits(path: Path) -> None:
    """Initialise a git repository with NO commits (talisman's real failure case)."""
    git_path = shutil.which("git")
    if git_path is None:
        pytest.skip("git is not available")
    subprocess.run(
        [git_path, "init", "-q", "-b", "main"], cwd=str(path), check=True, capture_output=True
    )


# --- scan error: real talisman failure on a no-commit repo ----------------------


@pytest.mark.skipif(shutil.which("talisman") is None, reason="talisman not installed")
def test_real_scanner_failure_exits_scan_error_not_zero(tmp_path: Path) -> None:
    """Talisman on a no-commit repo errors (exit status 128); guard must exit 5.

    Issue repro: before the fix the Scanner Errors panel was printed and the run
    still ended ``No secrets or policy violations detected`` with exit 0 — a CI
    gate passed while the requested scan never completed.
    """
    _init_repo_no_commits(tmp_path)

    result = _run_envdrift(
        [
            "guard",
            "--talisman",
            "--no-gitleaks",
            "--no-detect-secrets",
            "--no-auto-install",
            "--ci",
            ".",
        ],
        cwd=tmp_path,
    )
    combined = " ".join((result.stdout + result.stderr).split())
    assert result.returncode == 5, (
        f"a failed scanner must exit 5, got {result.returncode}\n{combined}"
    )
    assert "No secrets or policy violations detected" not in combined, (
        f"an errored scan must not be presented as a clean pass\n{combined}"
    )


@pytest.mark.skipif(shutil.which("talisman") is None, reason="talisman not installed")
def test_real_scanner_failure_json_fields_match_process_exit(tmp_path: Path) -> None:
    """``--json`` carries the scanner error AND an exit_code that matches reality."""
    _init_repo_no_commits(tmp_path)

    result = _run_envdrift(
        [
            "guard",
            "--talisman",
            "--no-gitleaks",
            "--no-detect-secrets",
            "--no-auto-install",
            "--ci",
            "--json",
            ".",
        ],
        cwd=tmp_path,
    )
    payload = _guard_json(result)
    talisman_errors = [
        r["error"] for r in payload["scanner_results"] if r["name"] == "talisman" and r["error"]
    ]
    assert talisman_errors, f"talisman must report its failure: {payload['scanner_results']}"
    assert result.returncode == 5, f"expected 5, got {result.returncode}\n{result.stdout}"
    assert payload["exit_code"] == 5, "JSON exit_code must match the process exit"
    assert payload["has_blocking_findings"] is False


# --- --ci --fail-on: machine fields agree with the process exit -----------------


def test_ci_fail_on_json_and_sarif_fields_match_process_exit(tmp_path: Path) -> None:
    """Both contradiction directions from the issue are closed.

    A HIGH finding under ``--fail-on critical`` passes CI: process 0, and the
    JSON/SARIF documents must say 0 / not blocking (they used to say 2 / true).
    The same finding under ``--fail-on high`` fails CI with 2, and the fields
    must agree.
    """
    (tmp_path / ".env").write_text("API_KEY=plainvalue123\n", encoding="utf-8")

    # Direction 1: gate passes, fields used to claim blocking.
    passing = _run_envdrift(
        [
            "guard",
            "--json",
            "--native-only",
            "--no-auto-install",
            "--ci",
            "--fail-on",
            "critical",
            ".",
        ],
        cwd=tmp_path,
    )
    assert passing.returncode == 0, f"expected 0, got {passing.returncode}\n{passing.stdout}"
    payload = _guard_json(passing)
    assert payload["exit_code"] == 0, "JSON exit_code must match the passing process exit"
    assert payload["has_blocking_findings"] is False
    # The findings themselves are still reported — only the verdict is gated.
    assert "unencrypted-env-file" in _rule_ids(payload)

    # Direction 2: gate fails, fields must say so.
    failing = _run_envdrift(
        [
            "guard",
            "--json",
            "--native-only",
            "--no-auto-install",
            "--ci",
            "--fail-on",
            "high",
            ".",
        ],
        cwd=tmp_path,
    )
    assert failing.returncode == 2
    payload = _guard_json(failing)
    assert payload["exit_code"] == 2
    assert payload["has_blocking_findings"] is True

    # SARIF carries the same verdict in the invocation object.
    sarif = _run_envdrift(
        [
            "guard",
            "--sarif",
            "--native-only",
            "--no-auto-install",
            "--ci",
            "--fail-on",
            "critical",
            ".",
        ],
        cwd=tmp_path,
    )
    assert sarif.returncode == 0
    invocation = json.loads(sarif.stdout)["runs"][0]["invocations"][0]
    assert invocation["exitCode"] == 0
    assert invocation["executionSuccessful"] is True


# --- ignore_rules list shape: clean config error before scanning ----------------


def test_ignore_rules_list_is_clean_config_error_not_crash(tmp_path: Path) -> None:
    """Issue repro: a TOML *list* ignore_rules used to TypeError mid-scan.

    Before the fix ``--json`` stdout was left empty (0 bytes) with a Rich
    traceback on stderr, exit 1 — and only on the first run with findings.
    """
    (tmp_path / ".env").write_text("API_KEY=plainvalue123\n", encoding="utf-8")
    (tmp_path / "envdrift.toml").write_text(
        '[guard]\nignore_rules = ["unencrypted-env-file"]\n', encoding="utf-8"
    )

    result = _run_envdrift(
        ["guard", "--json", "--native-only", "--no-auto-install", "."], cwd=tmp_path
    )
    assert result.returncode == 6, (
        f"expected operational-error exit 6, got {result.returncode}\n"
        f"{result.stdout}\n{result.stderr}"
    )
    payload = json.loads(result.stdout)  # stdout must be a clean JSON document
    assert "ignore_rules" in payload["error"]
    assert "Traceback" not in result.stdout
    assert "Traceback" not in result.stderr


# --- quoted entropy_threshold: coerced, scan completes with findings ------------


def test_quoted_entropy_threshold_does_not_green_pass(tmp_path: Path) -> None:
    """Issue repro: ``entropy_threshold = "3.5"`` used to crash native into exit 0.

    The crash swallowed even the unencrypted-.env HIGH finding. After the fix the
    quoted number is coerced, the scan completes, and the run fails on findings.
    """
    (tmp_path / ".env").write_text(f"TOKEN={_HEX_TOKEN}\n", encoding="utf-8")
    (tmp_path / "envdrift.toml").write_text(
        '[guard]\nscanners = ["native"]\ncheck_entropy = true\nentropy_threshold = "3.5"\n',
        encoding="utf-8",
    )

    result = _run_envdrift(["guard", "--json", "--no-auto-install", "."], cwd=tmp_path)
    payload = _guard_json(result)
    errors = [r["error"] for r in payload["scanner_results"] if r["error"]]
    assert errors == [], f"native must not crash on a quoted threshold: {errors}"
    assert "unencrypted-env-file" in _rule_ids(payload)
    assert result.returncode != 0, f"a run with findings must not exit 0\n{result.stdout}"
    assert payload["exit_code"] == result.returncode


# --- check_entropy = false is honored for env files ------------------------------


def test_check_entropy_false_disables_entropy_on_env_files(tmp_path: Path) -> None:
    """Issue repro: entropy ran unconditionally on env files, ignoring the knob."""
    (tmp_path / ".env").write_text(f"SOMEVALUE={_ENTROPY_SECRET}\n", encoding="utf-8")
    (tmp_path / "envdrift.toml").write_text("[guard]\ncheck_entropy = false\n", encoding="utf-8")

    result = _run_envdrift(
        ["guard", "--json", "--native-only", "--no-auto-install", "."], cwd=tmp_path
    )
    rule_ids = _rule_ids(_guard_json(result))
    assert "high-entropy-string" not in rule_ids, (
        f"check_entropy = false must disable entropy detection, got {rule_ids}"
    )
    # The env-file policy finding is unaffected by the entropy knob.
    assert "unencrypted-env-file" in rule_ids


# --- operational errors: distinct exit 6 -----------------------------------------


def test_operational_error_exit_distinct_from_critical(tmp_path: Path) -> None:
    """Issue repro: ``--config /nonexistent.toml`` used to exit 1 like a critical."""
    (tmp_path / "a.txt").write_text("HELLO=world\n", encoding="utf-8")

    result = _run_envdrift(
        ["guard", "--json", "--native-only", "--config", str(tmp_path / "nope.toml"), "."],
        cwd=tmp_path,
    )
    assert result.returncode == 6, (
        f"a config-load failure must exit 6 (not critical's 1), got {result.returncode}\n"
        f"{result.stdout}\n{result.stderr}"
    )
    payload = json.loads(result.stdout)
    assert "Could not load config" in payload["error"]


def test_non_string_fail_on_severity_is_clean_config_error(tmp_path: Path) -> None:
    """Review repro: ``fail_on_severity = 123`` used to AttributeError past the
    CLI's ``except ValueError`` — Rich traceback, empty ``--json`` stdout, exit 1."""
    (tmp_path / ".env").write_text("API_KEY=plainvalue123\n", encoding="utf-8")
    (tmp_path / "envdrift.toml").write_text("[guard]\nfail_on_severity = 123\n", encoding="utf-8")

    result = _run_envdrift(
        ["guard", "--json", "--native-only", "--no-auto-install", "."], cwd=tmp_path
    )
    assert result.returncode == 6, (
        f"expected operational-error exit 6, got {result.returncode}\n"
        f"{result.stdout}\n{result.stderr}"
    )
    payload = json.loads(result.stdout)  # stdout must be a clean JSON document
    assert "fail_on_severity" in payload["error"]
    assert "Traceback" not in result.stdout
    assert "Traceback" not in result.stderr


def test_git_not_found_staged_json_stdout_is_parseable(tmp_path: Path) -> None:
    """Review repro: ``--staged --json`` with no git on PATH exited 6 with prose
    (``Error: Git not found...``) on stdout instead of a JSON error document."""
    result = _run_envdrift(
        ["guard", "--staged", "--json", "--native-only"],
        cwd=tmp_path,
        env={"PATH": str(tmp_path / "empty-bin")},  # nothing resolves ``git``
    )
    assert result.returncode == 6, (
        f"expected operational-error exit 6, got {result.returncode}\n"
        f"{result.stdout}\n{result.stderr}"
    )
    payload = json.loads(result.stdout)
    assert "Git not found" in payload["error"]
