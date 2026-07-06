"""Regression tests for the native-scanner detection gaps in #477.

Each test drives the real ``envdrift guard`` CLI as a subprocess against a
scratch git repository, native scanner only (``--native-only
--no-auto-install``), so no external binaries are required.

Covered gaps (all reproduced on origin/main before the fix):

1. Tracked ``.env.local`` / ``.env.test`` were hard-ignored, so real secrets in
   them passed guard with exit 0.
2. UTF-16-encoded env files (with or without BOM) were classified as binary and
   skipped wholesale.
3. Trailing-``.env`` names (``production.env``) were not recognized as env
   files: no unencrypted-env-file policy and no entropy scan.
4. ``DEFAULT_GLOBAL_IGNORE_PATHS`` unconditionally suppressed even CRITICAL
   distinctive-prefix secrets in ``pyproject.toml`` / lock files.
5. Directory-scoped ignore patterns (``bin/**``, ``env/**``) were silently not
   applied when guard was invoked with a relative path (``guard .``).

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

# AWS access key id: AKIA + 16 uppercase/digit chars. Deliberately NOT the AWS
# documentation example key; built by concatenation (push protection).
_AWS_KEY_ID = "AKIA" + "ZZ7QF4N3XW2KLMNP"
# Canonical 40-char AWS secret access key shape, concatenated.
_AWS_SECRET = "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCY" + "EXAMPLEKEY"
# GitHub classic PAT shape: ghp_ + 36 alphanumerics, concatenated.
_GHP_TOKEN = "ghp_" + "0123456789" + "abcdefghijklmnopqrstuvwxyz"
# 32-char base62 value with no distinctive prefix and no secret-keyword var
# name: only the entropy gate can catch it.
_ENTROPY_SECRET = "Zx9Kq2Wm7" + "Lp4Rt8Nv6" + "Bs3Yd1Hf5Gj0Qc"


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


def _run_git(args: list[str], *, cwd: Path) -> subprocess.CompletedProcess:
    """Run a git command with explicit identity, gating cleanly if absent."""
    git_path = shutil.which("git")
    if git_path is None:
        pytest.skip("git is not available")

    git_env = os.environ.copy()
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
        git_env.pop(key, None)

    result = subprocess.run(
        [
            git_path,
            "-c",
            "user.email=test@test.com",
            "-c",
            "user.name=Test User",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=str(cwd),
        env=git_env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"git failed\ncmd: git {' '.join(args)}\n"
            f"cwd: {cwd}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def _init_repo(path: Path) -> None:
    _run_git(["init", "-b", "main"], cwd=path)


def _commit_all(path: Path) -> None:
    _run_git(["add", "-A", "-f"], cwd=path)
    _run_git(["commit", "-q", "-m", "fixture"], cwd=path)


def _guard_json(result: subprocess.CompletedProcess) -> dict:
    """Parse the JSON document printed by ``guard --json``."""
    out = result.stdout
    start = out.index("{")
    end = out.rindex("}") + 1
    return json.loads(out[start:end])


def _rule_ids(payload: dict) -> set[str]:
    return {f["rule_id"] for f in payload["findings"]}


def _finding_file_names(payload: dict, rule_id: str | None = None) -> set[str]:
    """Filename (basename) of every finding, optionally filtered by rule id."""
    return {
        Path(f["file_path"]).name
        for f in payload["findings"]
        if rule_id is None or f["rule_id"] == rule_id
    }


def _finding_rel_parts(payload: dict) -> set[str]:
    """``parent/name`` (POSIX) of every finding for OS-agnostic comparisons."""
    return {"/".join(Path(f["file_path"]).parts[-2:]) for f in payload["findings"]}


# --- Gap 1 (#477): tracked .env.local / .env.test must be scanned ---------------


@pytest.mark.parametrize("env_name", [".env.local", ".env.test"])
def test_tracked_env_local_and_test_with_secrets_are_flagged(tmp_path: Path, env_name: str) -> None:
    """A tracked plaintext ``.env.local``/``.env.test`` with real secrets fails guard.

    Before the fix both names sat in the native scanner's hard ignore list, so a
    committed file full of live credentials produced findings: [] and exit 0.
    """
    _init_repo(tmp_path)
    (tmp_path / env_name).write_text(
        f"AWS_ACCESS_KEY_ID={_AWS_KEY_ID}\n"
        f"AWS_SECRET_ACCESS_KEY={_AWS_SECRET}\n"
        f"GH_TOKEN={_GHP_TOKEN}\n",
        encoding="utf-8",
    )
    _commit_all(tmp_path)

    result = _run_envdrift(
        ["guard", "--native-only", "--no-auto-install", "--json", "."], cwd=tmp_path
    )
    payload = _guard_json(result)

    rule_ids = _rule_ids(payload)
    assert "aws-access-key-id" in rule_ids, f"{env_name} skipped: {payload}"
    assert "github-pat" in rule_ids, f"{env_name} skipped: {payload}"
    assert "unencrypted-env-file" in rule_ids, f"{env_name} missing policy: {payload}"
    assert env_name in _finding_file_names(payload)
    assert result.returncode == 1, (
        f"expected exit 1 (critical), got {result.returncode}\n{result.stdout}\n{result.stderr}"
    )


# --- Gap 2 (#477): UTF-16 env files must be decoded, not skipped as binary ------


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be"])
def test_utf16_env_file_flagged_like_utf8(tmp_path: Path, encoding: str) -> None:
    """A UTF-16 env file (BOM or BOM-less) is flagged exactly like its UTF-8 twin.

    Before the fix the ~50% NUL bytes of UTF-16 tripped the binary-ratio check
    and the whole file was skipped: "No secrets detected", exit 0.
    """
    _init_repo(tmp_path)
    content = f"AWS_ACCESS_KEY_ID={_AWS_KEY_ID}\nAWS_SECRET_ACCESS_KEY={_AWS_SECRET}\n"

    control = tmp_path / "ctrl.env"
    control.write_text(content, encoding="utf-8")
    target = tmp_path / "u16.env"
    target.write_text(content, encoding=encoding)

    ctrl_result = _run_envdrift(
        ["guard", "--native-only", "--no-auto-install", "--json", "ctrl.env"], cwd=tmp_path
    )
    ctrl_payload = _guard_json(ctrl_result)
    ctrl_rules = _rule_ids(ctrl_payload)
    assert "aws-access-key-id" in ctrl_rules  # sanity: control is detectable

    u16_result = _run_envdrift(
        ["guard", "--native-only", "--no-auto-install", "--json", "u16.env"], cwd=tmp_path
    )
    u16_payload = _guard_json(u16_result)
    u16_rules = _rule_ids(u16_payload)

    assert u16_rules == ctrl_rules, (
        f"UTF-16 ({encoding}) file scanned differently from UTF-8 control:\n"
        f"utf-8: {sorted(ctrl_rules)}\nutf-16: {sorted(u16_rules)}"
    )
    assert u16_result.returncode == ctrl_result.returncode == 1


# --- Gap 3 (#477): trailing-.env names get env-file policy + entropy scan -------


def test_trailing_env_name_gets_policy_and_entropy_coverage(tmp_path: Path) -> None:
    """A committed ``production.env`` is treated as an env file.

    Before the fix only leading-dot names matched ``_is_env_file``, so the
    unencrypted-env-file policy and the entropy gate never ran: a prefix-less
    high-entropy secret passed with exit 0.
    """
    _init_repo(tmp_path)
    (tmp_path / "production.env").write_text(f"DB_CONN_VALUE={_ENTROPY_SECRET}\n", encoding="utf-8")
    _commit_all(tmp_path)

    result = _run_envdrift(
        ["guard", "--native-only", "--no-auto-install", "--json", "."], cwd=tmp_path
    )
    payload = _guard_json(result)

    rule_ids = _rule_ids(payload)
    assert "unencrypted-env-file" in rule_ids, f"no env-file policy: {payload}"
    assert "high-entropy-string" in rule_ids, f"no entropy scan: {payload}"
    assert result.returncode == 2, (
        f"expected exit 2 (high), got {result.returncode}\n{result.stdout}\n{result.stderr}"
    )


# --- Gap 4 (#477): default ignores must not swallow distinctive-prefix secrets --


def test_distinctive_secret_in_pyproject_and_lockfile_not_suppressed(tmp_path: Path) -> None:
    """A GitHub PAT committed in ``pyproject.toml``/``package-lock.json`` is found.

    Before the fix ``DEFAULT_GLOBAL_IGNORE_PATHS`` (and the native scanner's own
    copies) dropped EVERY finding in those files, including zero-false-positive
    CRITICAL tokens. Noisy keyword/entropy findings must stay suppressed.
    """
    _init_repo(tmp_path)
    (tmp_path / "pyproject.toml").write_text(
        f'[tool.demo]\nrepo_token = "{_GHP_TOKEN}"\npassword = "{_ENTROPY_SECRET}"\n',
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        f'{{"name": "demo", "token": "{_GHP_TOKEN}"}}\n', encoding="utf-8"
    )
    # Positive control: same token in a non-ignored file.
    (tmp_path / "creds.config").write_text(f"TOKEN={_GHP_TOKEN}\n", encoding="utf-8")
    _commit_all(tmp_path)

    result = _run_envdrift(
        ["guard", "--native-only", "--no-auto-install", "--json", "."], cwd=tmp_path
    )
    payload = _guard_json(result)

    pat_files = _finding_file_names(payload, rule_id="github-pat")
    assert "creds.config" in pat_files  # sanity: detection works at all
    assert "pyproject.toml" in pat_files, f"pyproject.toml PAT suppressed: {payload}"
    assert "package-lock.json" in pat_files, f"lockfile PAT suppressed: {payload}"

    # The default ignore still suppresses noisy keyword findings in these files:
    # the generic-secret match for ``password = ...`` must NOT surface.
    generic_files = _finding_file_names(payload, rule_id="generic-secret")
    assert "pyproject.toml" not in generic_files, (
        f"noisy generic-secret no longer suppressed in pyproject.toml: {payload}"
    )
    assert result.returncode == 1


# --- Gap 5 (#477): dir-scoped ignores apply for relative path invocations -------


def test_relative_path_invocation_applies_directory_ignores(tmp_path: Path) -> None:
    """``guard .`` applies ``bin/**``-style ignores exactly like ``guard`` (no arg).

    Before the fix the unresolved relative base made ``relative_to`` raise, the
    fallback matched patterns against the absolute path, and every
    directory-scoped ignore silently stopped applying: ``guard`` and ``guard .``
    returned different findings for the same tree.
    """
    _init_repo(tmp_path)
    for sub in ("bin", "env", "config"):
        (tmp_path / sub).mkdir()
        (tmp_path / sub / "secrets.conf").write_text(f"TOKEN={_GHP_TOKEN}\n", encoding="utf-8")
    _commit_all(tmp_path)

    no_arg_result = _run_envdrift(
        ["guard", "--native-only", "--no-auto-install", "--json"], cwd=tmp_path
    )
    rel_arg_result = _run_envdrift(
        ["guard", "--native-only", "--no-auto-install", "--json", "."], cwd=tmp_path
    )
    # The non-ignored config/secrets.conf PAT is CRITICAL, so both spellings
    # must fail with exit 1 — findings parity alone would let a failure-mode
    # regression slip through as long as the JSON stayed parseable.
    assert no_arg_result.returncode == rel_arg_result.returncode == 1, (
        f"exit codes diverged or lost failure: no-arg={no_arg_result.returncode} "
        f"rel-arg={rel_arg_result.returncode}\n{no_arg_result.stderr}\n{rel_arg_result.stderr}"
    )
    no_arg = _guard_json(no_arg_result)
    rel_arg = _guard_json(rel_arg_result)

    rel_parts = _finding_rel_parts(rel_arg)
    assert "config/secrets.conf" in rel_parts  # sanity: non-ignored dir is scanned
    assert "bin/secrets.conf" not in rel_parts, f"bin/** ignore not applied: {rel_parts}"
    assert "env/secrets.conf" not in rel_parts, f"env/** ignore not applied: {rel_parts}"

    # Path spelling must not change the result set.
    assert rel_parts == _finding_rel_parts(no_arg)
