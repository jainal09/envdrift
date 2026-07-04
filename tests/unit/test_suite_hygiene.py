"""Suite-hygiene regression tests (#497).

These tests pin the lane contract the suite is built on:

1. Everything under ``tests/integration/`` carries the ``integration`` marker,
   so the unit lane (``-m "not integration"``) never runs binary/container
   tests by directory luck.
2. The real-binary ``Test*Integration`` classes in ``tests/scanner`` are
   selected by ``-m integration`` (previously they ran in NO lane: skipped in
   the unit lane when the binary was absent and deselected from the
   integration lane because they were unmarked).
3. The mock-SDK unit tests for the vault providers restore the real provider
   modules after ``importlib.reload()`` under fake SDKs, so a later test in
   the same process never gets a vault client that cannot fail.
4. No test is unconditionally ``pytest.mark.skip``-ed without a tracking
   issue reference (dead tests must be visible).

Each check drives the real pytest (as a subprocess) or scans the real test
tree -- nothing about the behavior under test is mocked.
"""

from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import TypeGuard

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_DIR = REPO_ROOT / "tests"


def _subprocess_env() -> dict[str, str]:
    """Environment for inner pytest runs: un-colorized, deterministic."""
    env = os.environ.copy()
    env.pop("FORCE_COLOR", None)
    env["NO_COLOR"] = "1"
    env["COLUMNS"] = "200"
    return env


def _run_pytest(*args: str) -> subprocess.CompletedProcess[str]:
    """Run the real pytest as a subprocess from the repo root."""
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "--no-cov",
        "-p",
        "no:cacheprovider",
        *args,
    ]
    return subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        env=_subprocess_env(),
        capture_output=True,
        text=True,
        timeout=300,
    )


def _collected_node_ids(result: subprocess.CompletedProcess[str]) -> list[str]:
    """Extract collected test node ids from ``--collect-only -q`` output."""
    return [line.strip() for line in result.stdout.splitlines() if "::" in line]


def test_integration_tree_is_excluded_from_unit_lane() -> None:
    """No test under tests/integration/ may be collected by ``-m "not integration"``.

    Regression for #497: test_kingfisher_scanner.py and test_ephemeral_keys.py
    carried no ``integration`` marker, leaking 16 binary/workflow tests into
    the unit lane.
    """
    result = _run_pytest(
        "tests/integration",
        "-m",
        "not integration",
        "--collect-only",
        "-q",
    )

    leaked = _collected_node_ids(result)
    assert leaked == [], (
        f"{len(leaked)} test(s) under tests/integration/ leak into the unit lane "
        f"(missing pytest.mark.integration):\n" + "\n".join(leaked)
    )


def test_scanner_binary_integration_classes_run_in_integration_lane() -> None:
    """The real-binary scanner Integration classes must be ``-m integration`` selectable.

    Regression for #497: the gitleaks/trufflehog/trivy/infisical/talisman
    Integration classes were unmarked, so they were skipped in the unit lane
    (binary absent) AND deselected from the integration lane -- running in no
    CI lane at all.
    """
    result = _run_pytest(
        "tests/scanner",
        "-m",
        "integration",
        "--collect-only",
        "-q",
    )

    collected = "\n".join(_collected_node_ids(result))
    expected_classes = [
        "TestGitleaksIntegration",
        "TestTrufflehogIntegration",
        "TestTrivyIntegration",
        "TestInfisicalIntegration",
        "TestTalismanIntegration",
    ]
    missing = [cls for cls in expected_classes if cls not in collected]
    assert missing == [], (
        f"Scanner integration classes not selected by -m integration: {missing}\n"
        f"stdout:\n{result.stdout}"
    )


# Checker script for test_vault_unit_tests_restore_real_provider_modules.
# It runs the four vault unit-test files with the real pytest *in the same
# process* as the assertions that follow -- deliberately: the contamination
# from #497 is only observable through a shared ``sys.modules`` (the Publish
# workflow runs the whole suite in one process), so a subprocess-isolated
# inner run would always see fresh modules and could never fail.
_VAULT_RESTORE_CHECKER_SCRIPT = textwrap.dedent(
    """
        import importlib.util
        import sys

        import pytest

        rc = pytest.main(
            [
                "tests/unit/test_vault_hashicorp.py",
                "tests/unit/test_vault_aws.py",
                "tests/unit/test_vault_azure.py",
                "tests/unit/test_vault_gcp.py",
                "-q",
                "--no-cov",
                "-p",
                "no:cacheprovider",
            ]
        )
        if rc != 0:
            print(f"inner pytest run failed with exit code {rc}")
            sys.exit(2)

        problems = []

        if importlib.util.find_spec("hvac") is not None:
            import hvac

            from envdrift.vault import hashicorp

            if hashicorp._hvac is not hvac:
                problems.append(
                    f"hashicorp._hvac is {hashicorp._hvac!r}, not the real hvac module"
                )
            if hashicorp.HVAC_AVAILABLE is not True:
                problems.append("hashicorp.HVAC_AVAILABLE is False despite hvac installed")

            # Behavioral symptom from #497: a client pointed at a closed port
            # must NOT authenticate successfully (port 9 is the reserved
            # discard port; nothing listens there).
            from envdrift.vault import get_vault_client

            client = get_vault_client(
                "hashicorp", url="http://127.0.0.1:9", token="not-a-real-token"
            )
            try:
                client.authenticate()
            except Exception:
                pass
            else:
                problems.append(
                    "hashicorp authenticate() against a closed port SUCCEEDED "
                    "(mock hvac SDK leaked out of the unit tests)"
                )

        if importlib.util.find_spec("boto3") is not None:
            import boto3

            from envdrift.vault import aws

            if aws._boto3 is not boto3:
                problems.append(f"aws._boto3 is {aws._boto3!r}, not the real boto3 module")
            if aws.AWS_AVAILABLE is not True:
                problems.append("aws.AWS_AVAILABLE is False despite boto3 installed")

        if importlib.util.find_spec("azure.keyvault.secrets") is not None:
            from azure.keyvault.secrets import SecretClient

            from envdrift.vault import azure

            if azure._SecretClient is not SecretClient:
                problems.append(
                    f"azure._SecretClient is {azure._SecretClient!r}, "
                    "not the real azure SecretClient"
                )
            if azure.AZURE_AVAILABLE is not True:
                problems.append("azure.AZURE_AVAILABLE is False despite azure SDK installed")

        if importlib.util.find_spec("google.cloud.secretmanager") is not None:
            from google.cloud import secretmanager

            from envdrift.vault import gcp

            if gcp._secretmanager is not secretmanager:
                problems.append(
                    f"gcp._secretmanager is {gcp._secretmanager!r}, "
                    "not the real google.cloud.secretmanager module"
                )
            if gcp.GCP_AVAILABLE is not True:
                problems.append("gcp.GCP_AVAILABLE is False despite GCP SDK installed")

        if problems:
            print("vault provider modules left poisoned after unit tests:")
            for problem in problems:
                print(f"  - {problem}")
            sys.exit(1)
        print("all vault provider modules restored")
        """
)


def test_vault_unit_tests_restore_real_provider_modules() -> None:
    """After the vault mock-SDK unit tests run, the real provider modules are intact.

    Regression for #497: four unit test modules ``importlib.reload()``-ed
    ``envdrift.vault.<provider>`` under MagicMock SDKs without restoring,
    leaving (e.g.) a HashiCorp client whose ``authenticate()`` succeeds
    against a closed port for the rest of the process.

    The checker script runs the four vault unit-test files with the real
    pytest in-process, then asserts each provider module is bound to the real
    SDK again -- including the behavioral symptom from the issue: a client
    pointed at a closed port must fail to authenticate.
    """
    result = subprocess.run(
        [sys.executable, "-c", _VAULT_RESTORE_CHECKER_SCRIPT],
        cwd=REPO_ROOT,
        env=_subprocess_env(),
        capture_output=True,
        text=True,
        timeout=300,
    )

    assert result.returncode == 0, (
        f"vault module restore check failed (exit {result.returncode}):\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


_ISSUE_REF_RE = re.compile(r"#\d+")


def _is_pytest_mark_skip(node: ast.AST) -> TypeGuard[ast.Attribute]:
    """True for a ``pytest.mark.skip`` attribute node (``skipif`` never matches)."""
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "skip"
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "mark"
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "pytest"
    )


def _skip_call_references_issue(call: ast.Call) -> bool:
    """True if any string argument of the skip call (e.g. ``reason``) cites ``#NNN``."""
    values = [*call.args, *(kw.value for kw in call.keywords)]
    return any(
        isinstance(value, ast.Constant)
        and isinstance(value.value, str)
        and _ISSUE_REF_RE.search(value.value)
        for value in values
    )


def _bare_skip_offenders(path: Path) -> list[int]:
    """Line numbers of ``pytest.mark.skip`` uses lacking a tracking-issue reference.

    Walks the AST, so comments and docstrings that merely mention
    ``pytest.mark.skip`` never match -- only real decorator/call sites do.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    skip_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _is_pytest_mark_skip(node.func)
    ]
    called_skip_funcs = {id(call.func) for call in skip_calls}
    offenders = [call.lineno for call in skip_calls if not _skip_call_references_issue(call)]
    # A bare ``@pytest.mark.skip`` (no call, so no reason at all) always offends.
    offenders += [
        node.lineno
        for node in ast.walk(tree)
        if _is_pytest_mark_skip(node) and id(node) not in called_skip_funcs
    ]
    return sorted(offenders)


def test_no_unconditional_skip_without_issue_reference() -> None:
    """Every unconditional ``pytest.mark.skip`` must reference a tracking issue.

    Regression for #497: the only non-default-region AWS client test was
    permanently dead behind a bare ``@pytest.mark.skip`` with no issue
    reference. ``skipif`` gates (environment-conditional) are fine; a flat
    ``skip`` hides a test on every environment forever, so it must cite the
    issue that tracks re-enabling it in one of its string arguments.
    """
    offenders = [
        f"{path.relative_to(REPO_ROOT)}:{line}"
        for path in sorted(TESTS_DIR.rglob("*.py"))
        for line in _bare_skip_offenders(path)
    ]

    assert offenders == [], (
        "Unconditional pytest.mark.skip without a tracking-issue reference "
        f"(fix the test or cite the issue in the reason): {offenders}"
    )


def test_bare_skip_scan_matches_code_not_comments_or_docstrings(tmp_path: Path) -> None:
    """The skip scan flags real skip sites only, never prose mentioning the rule.

    Regression for the text-search implementation, which flagged the literal
    string ``pytest.mark.skip`` anywhere in a file -- so a comment or
    docstring documenting this very rule (with no ``#NNN`` within 300
    characters) failed the hygiene check spuriously.
    """
    sample = tmp_path / "test_sample.py"
    sample.write_text(
        textwrap.dedent(
            '''
            """Docstring that mentions pytest.mark.skip without an issue."""
            import pytest

            # comment: pytest.mark.skip is banned without an issue reference

            @pytest.mark.skip
            def test_bare_decorator(): ...

            @pytest.mark.skip(reason="dead until reworked")
            def test_reason_without_issue(): ...

            @pytest.mark.skip(reason="tracked in #123")
            def test_reason_with_issue(): ...

            @pytest.mark.skipif(True, reason="conditional gates are fine")
            def test_skipif(): ...

            @pytest.mark.parametrize(
                "value",
                [pytest.param(1, marks=pytest.mark.skip(reason="see #456"))],
            )
            def test_param(value): ...
            '''
        ),
        encoding="utf-8",
    )

    # Only the bare decorator (line 7) and the issue-less reason (line 10).
    assert _bare_skip_offenders(sample) == [7, 10]
