"""Integration tests for external-binary secret scanners.

These tests exercise the REAL scanner binaries (talisman, trivy, infisical, trufflehog) and
the ScanEngine orchestration/filtering against real subprocess output. Each test
is gated on the binary being installed via ``shutil.which`` / ``is_installed()``
so it SKIPs cleanly when a tool is absent (e.g. in a minimal local env) and runs
in CI where the tools are provisioned.

No mocking of scanner behavior: findings come from running the actual tools on
real files in temporary directories / git repos.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import socket
import subprocess
import sys
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from envdrift.scanner.base import AggregatedScanResult, FindingSeverity, ScanFinding, ScanResult
from envdrift.scanner.engine import GuardConfig, ScanEngine
from envdrift.scanner.gitleaks import GitleaksScanner
from envdrift.scanner.infisical import InfisicalScanner
from envdrift.scanner.patterns import hash_secret
from envdrift.scanner.talisman import TalismanScanner
from envdrift.scanner.trivy import TrivyScanner
from envdrift.scanner.trufflehog import TrufflehogScanner

pytestmark = [pytest.mark.integration, pytest.mark.slow]

CRITICAL = FindingSeverity.CRITICAL


# --- Skip helpers ---------------------------------------------------------

_HAS_TALISMAN = TalismanScanner(auto_install=False).is_installed()
_HAS_TRIVY = TrivyScanner(auto_install=False).is_installed()
_HAS_INFISICAL = InfisicalScanner(auto_install=False).is_installed()
_HAS_TRUFFLEHOG = TrufflehogScanner(auto_install=False).is_installed()

requires_talisman = pytest.mark.skipif(
    not _HAS_TALISMAN, reason="talisman not installed (brew install talisman)"
)
requires_trivy = pytest.mark.skipif(
    not _HAS_TRIVY, reason="trivy not installed (brew install trivy)"
)
requires_infisical = pytest.mark.skipif(
    not _HAS_INFISICAL,
    reason="infisical not installed (brew install infisical/get-cli/infisical)",
)
requires_trufflehog = pytest.mark.skipif(
    not _HAS_TRUFFLEHOG, reason="trufflehog not installed (brew install trufflehog)"
)


# A realistic GitHub PAT + Stripe live key so trivy/talisman/infisical detect
# them as real secrets. Assembled from fragments at runtime so the full secret
# pattern never appears as a contiguous literal in source — this keeps GitHub
# push-protection from blocking the commit, while the scanners still see the
# complete value in the temp files the tests write.
GITHUB_TOKEN = "ghp_" + "016C7eX9bQ2vYwN3kLmZpRtUaScDfGhJkL01"
STRIPE_KEY = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc" + "ABCDEFGH"


def _write_secret_file(directory, name: str = "creds.env") -> None:
    """Write a file containing real-format secrets that scanners detect."""
    (directory / name).write_text(f"GITHUB_TOKEN={GITHUB_TOKEN}\nSTRIPE_KEY={STRIPE_KEY}\n")


# --- Talisman (P0) --------------------------------------------------------


@requires_talisman
def test_talisman_scans_committed_repo_and_parses_real_report_json(git_repo, tmp_path):
    """HP-12/EC-21: talisman scans a committed repo, writes report.json, scanner parses it.

    The real talisman binary exits non-zero when it finds (or even just runs a)
    scan, but it ALSO writes ``talisman_reports/data/report.json``. The scanner
    must resolve+parse that report and therefore NOT surface an error.
    """
    secret_file = git_repo / "app.env"
    secret_file.write_text(f"GITHUB_TOKEN={GITHUB_TOKEN}\n")
    # Talisman requires committed content; the git_repo fixture configures git.
    import subprocess  # nosec B404

    subprocess.run(["git", "add", "-A"], cwd=git_repo, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "add secret"],
        cwd=git_repo,
        capture_output=True,
        check=True,
    )

    scanner = TalismanScanner(auto_install=False)
    result = scanner.scan([git_repo])

    assert isinstance(result, ScanResult)
    assert result.scanner_name == "talisman"
    # Report was found and parsed -> no error even though talisman rc != 0.
    assert result.error is None, f"unexpected error: {result.error}"
    assert result.duration_ms >= 0
    assert isinstance(result.findings, list)
    # #301: real talisman report.json uses ``failure_list`` — the scanner must
    # parse it into at least one finding (a planted GitHub PAT in a committed
    # file is reliably flagged), not silently return zero (false negative).
    assert len(result.findings) >= 1, "talisman must surface the planted secret"
    for finding in result.findings:
        assert finding.scanner == "talisman"
        assert finding.rule_id.startswith("talisman-")
        # The raw secret is never exposed in the preview.
        assert GITHUB_TOKEN not in finding.secret_preview
    # #315: at least one finding carries a recovered secret preview/hash derived
    # from the message (the embedded base64/secret-pattern detection).
    assert any(f.secret_preview and f.secret_hash for f in result.findings), (
        "expected at least one finding with a recovered secret preview/hash"
    )


@requires_talisman
def test_talisman_no_commit_repo_returns_error_not_findings(git_repo, tmp_path):
    """BP-15: on a repo with NO commits talisman exits 128 and writes no report.

    With no parseable report and a non-zero exit code, the scanner must surface
    ``ScanResult.error`` (a non-empty string) and report zero findings rather
    than silently succeeding.
    """
    # git_repo is initialized but has NO commits.
    (git_repo / "app.env").write_text(f"GITHUB_TOKEN={GITHUB_TOKEN}\n")

    scanner = TalismanScanner(auto_install=False)
    result = scanner.scan([git_repo])

    assert result.scanner_name == "talisman"
    assert result.findings == []
    assert isinstance(result.error, str)
    assert result.error, "expected a non-empty error message on a no-commit repo"


# --- Trivy (P0) -----------------------------------------------------------


@requires_trivy
def test_trivy_detects_secrets_via_real_fs_secret_scanner(tmp_path):
    """HP-13: trivy fs --scanners secret parses Results[].Secrets[] into findings."""
    _write_secret_file(tmp_path, "creds.env")

    scanner = TrivyScanner(auto_install=False)
    result = scanner.scan([tmp_path])

    assert result.error is None, f"unexpected error: {result.error}"
    assert result.scanner_name == "trivy"
    assert len(result.findings) >= 1
    for finding in result.findings:
        assert finding.scanner == "trivy"
        assert finding.rule_id.startswith("trivy-")
    # The relative target "creds.env" must resolve under the scanned directory.
    assert any(f.file_path.name == "creds.env" for f in result.findings)
    # Trivy redacts the matched secret -> preview contains the masking char.
    assert any("*" in f.secret_preview for f in result.findings)


@requires_trivy
def test_trivy_nonzero_exit_with_stdout_is_parsed_anyway(tmp_path):
    """EC-26/BP-17: trivy may exit non-zero but still emit valid JSON on stdout.

    The scanner only treats a non-zero exit as an error when stdout is empty.
    Here we (a) verify scanner.scan succeeds, and (b) run real trivy with
    ``--exit-code 1`` to confirm the non-zero-rc-with-findings shape, then feed
    that JSON through the scanner's own ``_parse_output`` to confirm findings.
    """
    import json
    import subprocess  # nosec B404

    _write_secret_file(tmp_path, "creds.env")

    scanner = TrivyScanner(auto_install=False)
    result = scanner.scan([tmp_path])
    assert result.error is None
    assert isinstance(result.findings, list)

    # Force the non-zero-exit branch with the real binary.
    binary = shutil.which("trivy")
    assert binary is not None
    proc = subprocess.run(  # nosec B603
        [
            binary,
            "fs",
            "--scanners",
            "secret",
            "--format",
            "json",
            "--quiet",
            "--exit-code",
            "1",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode != 0, "expected non-zero rc when secrets are found"
    assert proc.stdout.strip(), "trivy still emits JSON on stdout despite non-zero rc"
    scan_data = json.loads(proc.stdout)
    findings, _ = scanner._parse_output(scan_data, tmp_path)
    assert len(findings) >= 1
    assert all(f.rule_id.startswith("trivy-") for f in findings)


# --- Infisical (P1) -------------------------------------------------------


@requires_infisical
def test_infisical_scan_no_git_parses_real_json_report(tmp_path):
    """HP-11/BP-17: infisical scan --no-git parses its JSON report (no login needed).

    Infisical exits non-zero when it finds leaks; because a non-empty report is
    written, the scanner treats that as success (error is None).
    """
    _write_secret_file(tmp_path, "app.env")

    scanner = InfisicalScanner(auto_install=False)
    result = scanner.scan([tmp_path])

    assert result.error is None, f"unexpected error: {result.error}"
    assert result.scanner_name == "infisical"
    assert isinstance(result.findings, list)
    # Infisical reliably flags the GitHub PAT; assert the parsed shape.
    assert len(result.findings) >= 1
    for finding in result.findings:
        assert finding.scanner == "infisical"
        assert finding.rule_id.startswith("infisical-")
        # Secret value is redacted (never the raw secret).
        assert GITHUB_TOKEN not in finding.secret_preview
        assert STRIPE_KEY not in finding.secret_preview


# A long-lived access key ID, its secret access key, and an STS session key ID,
# fragmented for push protection like the tokens above. High-entropy and not
# the AWS documentation example, so no scanner allowlist applies.
AWS_ACCESS_KEY_ID = "AKIA" + "KIT74Y7PUQ23N6CF"
AWS_SECRET_ACCESS_KEY = "Eg+RG/Xq82Tiq6vi" + "6Iqw0Dm7sdvmMBTnlFjGO5hh"
AWS_SESSION_KEY_ID = "ASIA" + "TE6A37WYKNWJ2AA2"


@requires_infisical
def test_infisical_detects_aws_credentials(tmp_path):
    """Every line of an AWS credential set must be flagged (#834).

    0.43.135 (gitleaks engine) flags all three lines. From 0.43.136 the
    betterleaks engine reports the key IDs on lines 1 and 3 as a composite
    ``aws-access-token`` match and nests the secret access key on line 2 under
    ``ComponentSets`` instead of reporting it, so the scanner has to surface
    those components itself, secret hash included.
    """
    (tmp_path / "aws.env").write_text(
        f"AWS_ACCESS_KEY_ID={AWS_ACCESS_KEY_ID}\n"
        f"AWS_SECRET_ACCESS_KEY={AWS_SECRET_ACCESS_KEY}\n"
        f"AWS_SESSION_KEY_ID={AWS_SESSION_KEY_ID}\n"
    )

    result = InfisicalScanner(auto_install=False).scan([tmp_path])

    assert result.error is None, f"unexpected error: {result.error}"
    flagged = {f.line_number for f in result.findings}
    assert flagged >= {1, 2, 3}, (
        f"infisical missed AWS credential lines {sorted({1, 2, 3} - flagged)}; "
        f"rules reported: {sorted({f.rule_id for f in result.findings})}"
    )
    assert any(
        f.line_number == 2 and f.secret_hash == hash_secret(AWS_SECRET_ACCESS_KEY)
        for f in result.findings
    ), "the secret access key itself must be captured, not just its line"
    for finding in result.findings:
        for raw in (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_KEY_ID):
            assert raw not in finding.secret_preview


def _infisical_runs_betterleaks() -> bool:
    """Whether the infisical binary in use is 0.43.136+, the betterleaks engine."""
    version = InfisicalScanner(auto_install=False).get_version() or ""
    parts = re.findall(r"\d+", version)[:3]
    # Fail loud: a silent False would skip the betterleaks-only assertions.
    assert len(parts) == 3, f"could not parse the infisical version from {version!r}"
    return tuple(int(part) for part in parts) >= (0, 43, 136)


@requires_infisical
def test_infisical_grades_aws_credentials_critical(tmp_path):
    """AWS key IDs and their secret access key must be CRITICAL (#844).

    Both engines report the key IDs on lines 1 and 3 under ``aws-access-token``.
    That rule ID used to fall back to HIGH, so ``--fail-on critical`` let a leaked
    key ID through. From 0.43.136 the secret on line 2 is nested under the key ID
    as ``aws-secret-access-key``, which must be CRITICAL as well. 0.43.135 has no
    rule for a secret access key and reports line 2 as ``generic-api-key`` (HIGH),
    so line 2 is checked only on the betterleaks engine.
    """
    (tmp_path / "aws.env").write_text(
        f"AWS_ACCESS_KEY_ID={AWS_ACCESS_KEY_ID}\n"
        f"AWS_SECRET_ACCESS_KEY={AWS_SECRET_ACCESS_KEY}\n"
        f"AWS_SESSION_KEY_ID={AWS_SESSION_KEY_ID}\n"
    )

    result = InfisicalScanner(auto_install=False).scan([tmp_path])

    assert result.error is None, f"unexpected error: {result.error}"
    graded = sorted((f.line_number, f.rule_id, f.severity.value) for f in result.findings)
    critical = {(f.line_number, f.rule_id) for f in result.findings if f.severity == CRITICAL}
    key_ids = {(1, "infisical-aws-access-token"), (3, "infisical-aws-access-token")}
    assert key_ids <= critical, f"AWS key IDs not graded CRITICAL: {graded}"
    aws_rules = {"infisical-aws-access-token", "infisical-aws-secret-access-key"}
    assert all(f.severity == CRITICAL for f in result.findings if f.rule_id in aws_rules), graded
    if _infisical_runs_betterleaks():
        reported = {(f.line_number, f.rule_id, f.severity, f.secret_hash) for f in result.findings}
        nested = (
            2,
            "infisical-aws-secret-access-key",
            CRITICAL,
            hash_secret(AWS_SECRET_ACCESS_KEY),
        )
        assert nested in reported, f"the nested secret access key is not CRITICAL: {graded}"


# An Azure storage account key: 64 random-looking bytes, base64-encoded to 88
# characters. Derived at runtime so no key literal appears in source.
AZURE_STORAGE_KEY = base64.b64encode(hashlib.sha512(b"envdrift-844-azure").digest()).decode()


@requires_infisical
def test_infisical_grades_azure_storage_account_keys_by_engine(tmp_path):
    """Pin which engine grades an Azure storage account key CRITICAL (#844).

    The betterleaks engine (0.43.136+) reports it as ``azure-storage-account-key``,
    which must be CRITICAL. 0.43.135, the pinned version, has no such rule and
    reports the key only as ``generic-api-key`` (HIGH), so ``--fail-on critical``
    does not block it on Infisical's findings alone. docs/cli/guard.md says so; if
    this branch fails, the engine changed and that page must change with it.
    """
    (tmp_path / "azure.env").write_text(
        "AZURE_STORAGE_CONNECTION_STRING=DefaultEndpointsProtocol=https;"
        f"AccountName=envdriftprobe;AccountKey={AZURE_STORAGE_KEY};"
        "EndpointSuffix=core.windows.net\n"
    )

    result = InfisicalScanner(auto_install=False).scan([tmp_path])

    assert result.error is None, f"unexpected error: {result.error}"
    graded = sorted((f.line_number, f.rule_id, f.severity.value) for f in result.findings)
    assert any(f.line_number == 1 for f in result.findings), f"key not detected: {graded}"
    if _infisical_runs_betterleaks():
        assert any(
            f.rule_id == "infisical-azure-storage-account-key"
            and f.severity == CRITICAL
            and f.secret_hash == hash_secret(AZURE_STORAGE_KEY)
            for f in result.findings
        ), f"the Azure storage account key is not CRITICAL: {graded}"
    else:
        assert graded == [(1, "infisical-generic-api-key", "high")], graded


@requires_infisical
def test_infisical_grades_stripe_live_keys_critical_and_test_keys_high(tmp_path):
    """Stripe live keys are CRITICAL, test-mode keys HIGH, on both engines (#844).

    Both engines report every Stripe secret and restricted key under
    ``stripe-access-token``, which used to fall back to HIGH. The test-mode
    downgrade reads the finding's ``Secret``, so this pins that the real report
    carries just the key there.
    """
    body = "4eC39HqLyjWDarjtT1zdp7dc" + "ABCDEFGH"
    (tmp_path / "stripe.env").write_text(
        f"STRIPE_SECRET_KEY={'sk_live_' + body}\n"
        f"STRIPE_RESTRICTED_KEY={'rk_live_' + body}\n"
        f"STRIPE_TEST_KEY={'sk_test_' + body}\n"
    )

    result = InfisicalScanner(auto_install=False).scan([tmp_path])

    assert result.error is None, f"unexpected error: {result.error}"
    graded = sorted((f.line_number, f.rule_id, f.severity.value) for f in result.findings)
    stripe = [
        (f.line_number, f.severity)
        for f in result.findings
        if f.rule_id == "infisical-stripe-access-token"
    ]
    assert sorted(stripe) == [(1, CRITICAL), (2, CRITICAL), (3, FindingSeverity.HIGH)], graded


def _run_guard(args: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    """Run the real ``envdrift guard`` CLI as a subprocess with ``env``.

    Pass the ``integration_env`` fixture: the autouse conftest fixture has
    already stripped ``FORCE_COLOR``, so the output is un-colorized.
    """
    return subprocess.run(
        [sys.executable, "-m", "envdrift.cli", "guard", *args],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )


@requires_infisical
def test_guard_infisical_fail_on_critical_blocks_an_aws_key_id(tmp_path, integration_env):
    """``guard --infisical --fail-on critical`` must fail on a leaked AWS key ID (#844).

    The native scanner's own AWS rules and Infisical's nested secret are ignored,
    so Infisical's key ID finding alone decides the exit: on 0.43.135 the secret
    on line 2 is a HIGH ``generic-api-key``, and once betterleaks#410 ships the
    betterleaks engine also reports a key ID with no secret nested under it. The
    key ID used to be graded HIGH, so this run exited 0.
    """
    (tmp_path / "aws.env").write_text(
        f"AWS_ACCESS_KEY_ID={AWS_ACCESS_KEY_ID}\nAWS_SECRET_ACCESS_KEY={AWS_SECRET_ACCESS_KEY}\n"
    )
    (tmp_path / "envdrift.toml").write_text(
        "[guard.ignore_rules]\n"
        '"aws-access-key-id" = ["*"]\n'
        '"aws-secret-access-key" = ["*"]\n'
        '"infisical-aws-secret-access-key" = ["*"]\n'
    )

    result = _run_guard(
        [
            ".",
            "--infisical",
            "--no-gitleaks",
            "--no-auto-install",
            "--ci",
            "--fail-on",
            "critical",
            "--json",
            "--config",
            "envdrift.toml",
        ],
        cwd=tmp_path,
        env=integration_env,
    )

    assert result.returncode == 1, (result.returncode, result.stdout, result.stderr)
    payload = json.loads(result.stdout)
    assert payload["exit_code"] == 1
    critical = [
        (f["rule_id"], f["line_number"]) for f in payload["findings"] if f["severity"] == "critical"
    ]
    assert critical == [("infisical-aws-access-token", 1)], payload["findings"]


# A generic high-entropy API key, fragmented like the tokens above.
GENERIC_API_KEY = "q8Zt3VnR7wXy2Lp9" + "Ks4Bd6Fh1Jm5Nc0Gx"


@requires_infisical
def test_infisical_reports_low_confidence_secrets(tmp_path):
    """Secrets betterleaks rates "low" confidence must still be reported (#834).

    From 0.43.136 infisical drops every finding below ``--confidence``, which
    defaults to "medium", and only its "low"-rated generic rules report a lone
    AWS secret access key or a generic API key. So the scanner passes
    ``--confidence low`` whenever the binary's ``scan --help`` lists the flag.
    0.43.135 has no such flag (it rejects it) and reports all three files
    without it.
    """
    files = {
        "secret.env": f"AWS_SECRET_ACCESS_KEY={AWS_SECRET_ACCESS_KEY}\n",
        "config.json": f'{{\n  "secretAccessKey": "{AWS_SECRET_ACCESS_KEY}"\n}}\n',
        "api.env": f"API_KEY={GENERIC_API_KEY}\n",
    }
    for name, text in files.items():
        (tmp_path / name).write_text(text)

    result = InfisicalScanner(auto_install=False).scan([tmp_path])

    assert result.error is None, f"unexpected error: {result.error}"
    flagged = {f.file_path.name for f in result.findings}
    assert flagged >= set(files), (
        f"infisical missed low-confidence secrets in {sorted(set(files) - flagged)}; "
        f"rules reported: {sorted({f.rule_id for f in result.findings})}"
    )
    for finding in result.findings:
        for raw in (AWS_SECRET_ACCESS_KEY, GENERIC_API_KEY):
            assert raw not in finding.secret_preview


@requires_infisical
def test_infisical_detects_lone_aws_access_key_ids(tmp_path):
    """An AWS key ID with no secret access key next to it must be flagged (#834).

    This is the test that keeps the Renovate hold on Infisical honest.
    0.43.135 flags every file here. From 0.43.136 the betterleaks
    ``aws-access-token`` rule fires only when a secret access key sits within
    a few lines of the key ID in the same file, at every ``--confidence``
    level (still so on 0.43.141), so none of its built-in rules report these.
    """
    files = {
        "app.env": f"AWS_ACCESS_KEY_ID={AWS_ACCESS_KEY_ID}\n",
        "session.env": f"AWS_SESSION_KEY_ID={AWS_SESSION_KEY_ID}\n",
        "credentials": f"[default]\naws_access_key_id = {AWS_ACCESS_KEY_ID}\nregion = us-east-1\n",
        "deploy.sh": f"aws configure set aws_access_key_id {AWS_ACCESS_KEY_ID}\n",
    }
    for name, text in files.items():
        (tmp_path / name).write_text(text)

    result = InfisicalScanner(auto_install=False).scan([tmp_path])

    assert result.error is None, f"unexpected error: {result.error}"
    flagged = {f.file_path.name for f in result.findings}
    assert flagged >= set(files), (
        f"infisical missed lone AWS key IDs in {sorted(set(files) - flagged)}; "
        f"rules reported: {sorted({f.rule_id for f in result.findings})}"
    )


# Secrets that betterleaks nests under another rule's finding, keyed by the
# (file, line) that must be flagged. Fragmented like the tokens above.
NESTED_SECRETS = {
    ("exoscale.env", 2): "Zq9Xw8Vu7Ts6Rq5Po4Nm" + "3Lk2Jh1Gf0EdCbAz9Yx8Wv7U",
    ("polymarket.env", 2): "q8Zt3VnR7wXy2Lp9Ks4B" + "d6Fh1Jm5Nc0GxW2eTt7Y/Ab+=",
    ("ovh.env", 4): "Pa6Hn2Wq8Ze4Rt1Y" + "u9Io3Kl7Mj5Xc0Bv",
    ("alibaba.env", 3): "CAISq8Zt3VnR7wXy2Lp9" + "Ks4Bd6Fh1Jm5Nc0GxW2e",
}


@requires_infisical
def test_infisical_reports_nested_secret_components(tmp_path):
    """Secrets nested under another rule's finding must be reported (#834).

    Besides the AWS secret access key, betterleaks (0.43.136+) nests the
    Exoscale and Polymarket API secrets, the OVH consumer key and the Alibaba
    STS security token under the composite rule's primary match instead of
    reporting them. 0.43.135 flags each of these lines as a generic API key.
    """
    secret = NESTED_SECRETS
    files = {
        "exoscale.env": (
            "EXOSCALE_API_KEY=EXO" + "a1B2c3D4e5F6g7H8i9J0k1L2\n"
            f"EXOSCALE_API_SECRET={secret['exoscale.env', 2]}\n"
        ),
        "polymarket.env": (
            "POLYMARKET_API_KEY=7c2e9f14-3b8a-4d6e-" + "a1f0-5b9c8d7e6f3a\n"
            f"POLYMARKET_API_SECRET={secret['polymarket.env', 2]}\n"
            "POLYMARKET_PASSPHRASE=c0rrect_h0rse_" + "b4ttery_st4ple\n"
        ),
        "ovh.env": (
            "OVH_ENDPOINT=ovh-eu\n"
            "OVH_APPLICATION_KEY=k7Qp2Xz9" + "Lm4Wn8Rt\n"
            "OVH_APPLICATION_SECRET=Vb3Mr8Sd5Fg1Jc0Y" + "eHq7Tz2Kp9Lw4Nx6\n"
            f"OVH_CONSUMER_KEY={secret['ovh.env', 4]}\n"
        ),
        "alibaba.env": (
            "ALIBABA_ACCESS_KEY_ID=STS." + "NUgYrLnoC2YtqMv8XzBk3pQw\n"
            "ALIBABA_ACCESS_KEY_SECRET=Hq7Tz2Kp9Lw4Nx6V" + "b3Mr8Sd5Fg1Jc0Ye\n"
            f"ALIBABA_SECURITY_TOKEN={secret['alibaba.env', 3]}\n"
        ),
    }
    for name, text in files.items():
        (tmp_path / name).write_text(text)

    result = InfisicalScanner(auto_install=False).scan([tmp_path])

    assert result.error is None, f"unexpected error: {result.error}"
    flagged = {(f.file_path.name, f.line_number) for f in result.findings}
    assert flagged >= set(NESTED_SECRETS), (
        f"infisical missed nested secrets at {sorted(set(NESTED_SECRETS) - flagged)}; "
        f"rules reported: {sorted({f.rule_id for f in result.findings})}"
    )
    for finding in result.findings:
        for raw in NESTED_SECRETS.values():
            assert raw not in finding.secret_preview


# Azure service-principal values and a password, fragmented like the tokens above.
AZURE_TENANT_ID = "3f2b8c1d-4e5a-4b6c-" + "9d7e-8f9a0b1c2d3e"
AZURE_CLIENT_ID = "a1b2c3d4-e5f6-4a7b-" + "8c9d-0e1f2a3b4c5d"
AZURE_CLIENT_SECRET = "Xy78Q~" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tV9wX1yZ3b"
DB_PASSWORD = "Tr0ub4dor" + "&3xK9pQ!vL2m"


@requires_infisical
def test_infisical_does_not_report_identifiers_paired_with_a_secret(tmp_path):
    """Tenant IDs, client IDs and usernames next to a secret are not secrets (#834).

    Betterleaks (0.43.136+) nests the Azure tenant and client IDs that sit near
    a client secret, and the username near a password, under ComponentSets.
    Reporting them would fail ``guard`` on values that are not secrets and
    that 0.43.135 never flagged. The client secret on line 3 is flagged by
    every release, which keeps this test from passing on an empty scan.
    """
    (tmp_path / "azure.env").write_text(
        f"AZURE_TENANT_ID={AZURE_TENANT_ID}\n"
        f"AZURE_CLIENT_ID={AZURE_CLIENT_ID}\n"
        f"AZURE_CLIENT_SECRET={AZURE_CLIENT_SECRET}\n"
    )
    (tmp_path / "db.env").write_text(f"DB_USERNAME=reporting_service\nDB_PASSWORD={DB_PASSWORD}\n")

    result = InfisicalScanner(auto_install=False).scan([tmp_path])

    assert result.error is None, f"unexpected error: {result.error}"
    flagged = {(f.file_path.name, f.line_number) for f in result.findings}
    assert ("azure.env", 3) in flagged, f"the client secret was missed; got {sorted(flagged)}"
    identifiers = {("azure.env", 1), ("azure.env", 2), ("db.env", 1)}
    assert not flagged & identifiers, (
        f"identifiers reported as secrets at {sorted(flagged & identifiers)}; "
        f"rules reported: {sorted({f.rule_id for f in result.findings})}"
    )


# --- trufflehog (#902) ----------------------------------------------------


def _github_token_findings(result: ScanResult) -> list[ScanFinding]:
    return [f for f in result.findings if f.secret_hash == hash_secret(GITHUB_TOKEN)]


@requires_trufflehog
def test_trufflehog_reports_a_github_token(tmp_path):
    """The real trufflehog's JSON lines become a finding for the token, redacted.

    envdrift runs it without verification, so the token is unverified and HIGH.
    """
    _write_secret_file(tmp_path)

    result = TrufflehogScanner(auto_install=False).scan([tmp_path])

    assert result.error is None, f"unexpected error: {result.error}"
    tokens = _github_token_findings(result)
    assert tokens, f"the GitHub token was missed; rules: {[f.rule_id for f in result.findings]}"
    for finding in tokens:
        assert (finding.file_path, finding.line_number) == (tmp_path / "creds.env", 1)
        assert finding.severity is FindingSeverity.HIGH
        assert finding.verified is False
        assert GITHUB_TOKEN not in finding.secret_preview


@requires_trufflehog
def test_trufflehog_scan_of_a_clean_directory_is_clean(tmp_path):
    """A directory without secrets has no findings and no error."""
    (tmp_path / "app.env").write_text("APP_NAME=demo\nDEBUG=false\n")

    result = TrufflehogScanner(auto_install=False).scan([tmp_path])

    assert result.error is None, f"unexpected error: {result.error}"
    assert result.findings == []


@requires_trufflehog
def test_trufflehog_reports_a_secret_in_the_history_of_a_repository(git_repo, monkeypatch):
    """A history scan of the repository root reports a token scrubbed from the working tree."""
    _write_secret_file(git_repo, "app.env")
    _commit_all(git_repo)
    (git_repo / "app.env").write_text("GITHUB_TOKEN=scrubbed\n")
    _commit_all(git_repo)
    monkeypatch.chdir(git_repo)

    result = TrufflehogScanner(auto_install=False).scan([Path()], include_git_history=True)

    assert result.error is None, f"unexpected error: {result.error}"
    tokens = _github_token_findings(result)
    assert tokens, "the committed token was not reported"
    assert {f.file_path.resolve() for f in tokens} == {(git_repo / "app.env").resolve()}
    assert all(f.commit_sha for f in tokens)


@requires_trufflehog
def test_trufflehog_scans_the_history_of_a_repository_whose_path_a_url_reserves(tmp_path):
    """A ``#``, ``%`` or space in the repository's path stays a path in trufflehog's URI.

    trufflehog parses the ``file://`` URI as a URL: a ``#`` started a fragment and a ``%`` an
    escape, so the scan failed. On Windows every path failed, as ``file://C:\\...`` does not parse.
    """
    repo = tmp_path / "c# 100% repo"
    repo.mkdir()
    for args in (["init"], ["config", "user.email", "t@example.com"], ["config", "user.name", "t"]):
        subprocess.run(["git", *args], cwd=repo, capture_output=True, check=True)
    _write_secret_file(repo, "app.env")
    _commit_all(repo)

    result = TrufflehogScanner(auto_install=False).scan([repo], include_git_history=True)

    assert result.error is None, f"unexpected error: {result.error}"
    tokens = _github_token_findings(result)
    assert tokens, "the committed token was not reported"
    assert {f.file_path.resolve() for f in tokens} == {(repo / "app.env").resolve()}
    assert all(f.commit_sha for f in tokens)


@requires_trufflehog
def test_trufflehog_history_scan_leaves_the_index_a_hook_exported_alone(
    git_repo, tmp_path_factory, monkeypatch
):
    """#916: a history scan does not write to the GIT_INDEX_FILE that git exports to a hook.

    trufflehog clones the repository and checks it out, and the checkout wrote its index to the
    inherited GIT_INDEX_FILE. In a hook that is the index git is about to commit, so the commit
    came out empty and the staged changes were unstaged.
    """
    _write_secret_file(git_repo, "app.env")
    _commit_all(git_repo)
    hook_repo = tmp_path_factory.mktemp("hook-repo")
    subprocess.run(["git", "init", "-q"], cwd=hook_repo, capture_output=True, check=True)
    (hook_repo / "notes.txt").write_text("hello\n")
    subprocess.run(["git", "add", "notes.txt"], cwd=hook_repo, capture_output=True, check=True)
    index = hook_repo / ".git" / "index"
    staged = index.read_bytes()
    monkeypatch.setenv("GIT_INDEX_FILE", str(index))

    result = TrufflehogScanner(auto_install=False).scan([git_repo], include_git_history=True)

    # Not an assert: only the assertion below is the known bug, and an error is not.
    if result.error is not None:
        pytest.fail(f"unexpected error: {result.error}")
    assert index.read_bytes() == staged, "the scan rewrote the index git was about to commit"


@requires_trufflehog
def test_commit_whose_hook_runs_a_trufflehog_history_scan_keeps_its_changes(
    git_repo, tmp_path_factory, integration_env
):
    """#916: a pre-commit hook that runs guard's trufflehog history scan leaves the commit whole.

    During ``git commit -a`` the hook gets GIT_INDEX_FILE, the index git is about to commit.
    trufflehog's clone wrote its own index there, so the commit came out empty and the staged
    changes were unstaged.
    """
    (git_repo / "app.txt").write_text("v1\n")
    _commit_all(git_repo)
    report = tmp_path_factory.mktemp("guard") / "report.json"
    hook = git_repo / ".git" / "hooks" / "pre-commit"
    hook.write_text(
        "#!/bin/sh\n"
        f'"{Path(sys.executable).as_posix()}" -m envdrift.cli guard --no-gitleaks --trufflehog '
        f'--history --no-auto-install --json . > "{report.as_posix()}"\n'
        "exit 0\n"
    )
    hook.chmod(0o755)
    (git_repo / "app.txt").write_text("v2\n")
    (git_repo / "added.txt").write_text("new\n")
    subprocess.run(["git", "add", "added.txt"], cwd=git_repo, capture_output=True, check=True)

    subprocess.run(
        ["git", "commit", "-qam", "v2"],
        cwd=git_repo,
        env=integration_env,
        capture_output=True,
        check=True,
    )

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=git_repo, capture_output=True, text=True, check=True
        ).stdout

    # The hook ran the history scan.
    results = json.loads(report.read_text())["scanner_results"]
    assert [r["error"] for r in results if r["name"] == "trufflehog"] == [None]
    assert sorted(git("show", "--name-only", "--format=", "HEAD").split()) == [
        "added.txt",
        "app.txt",
    ]
    assert git("status", "--porcelain") == ""


@requires_trufflehog
def test_guard_trufflehog_reports_a_github_token(tmp_path, integration_env):
    """``guard --trufflehog`` runs the real binary and reports its finding in ``--json``."""
    _write_secret_file(tmp_path)

    result = _run_guard(
        [".", "--trufflehog", "--no-gitleaks", "--no-auto-install", "--ci", "--json"],
        cwd=tmp_path,
        env=integration_env,
    )

    assert result.returncode == 1, (result.returncode, result.stdout, result.stderr)
    payload = json.loads(result.stdout)
    trufflehog = [f for f in payload["findings"] if f["scanner"] == "trufflehog"]
    assert trufflehog, payload["findings"]
    assert {(f["file_path"], f["line_number"]) for f in trufflehog} == {("creds.env", 1)}


@pytest.fixture
def recording_proxy(monkeypatch):
    """Route the HTTP(S) proxy of child processes to a local listener; yield what it was asked.

    The listener records the first line of each request (``CONNECT host:443 ...``) and refuses
    it, so nothing leaves the machine.
    """
    requests: list[str] = []
    server = socket.create_server(("127.0.0.1", 0))

    def serve() -> None:
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(5)
                try:
                    requests.append(conn.recv(4096).decode("latin-1").partition("\r\n")[0])
                    conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                except OSError:
                    pass

    threading.Thread(target=serve, daemon=True).start()
    proxy = f"http://127.0.0.1:{server.getsockname()[1]}"
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        monkeypatch.setenv(name, proxy)
    for name in ("NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    yield requests
    server.close()


@requires_trufflehog
def test_trufflehog_scan_does_not_run_its_self_updater(tmp_path, recording_proxy):
    """A scan must leave the pinned trufflehog binary as installed (#907).

    Unless given ``--no-update``, trufflehog asks oss.trufflehog.org for a newer release before
    every scan and writes it over its own binary. A scan without verification has nothing else
    to fetch, so it must make no request at all.
    """
    _write_secret_file(tmp_path)

    result = TrufflehogScanner(auto_install=False).scan([tmp_path])

    assert result.error is None, f"unexpected error: {result.error}"
    assert _github_token_findings(result), "the scan did not run"
    assert recording_proxy == [], f"trufflehog went online during a scan: {recording_proxy}"


# --- Relative and symlinked scan paths (#843, #853) ------------------------

_HAS_GITLEAKS = GitleaksScanner(auto_install=False).is_installed()
requires_gitleaks = pytest.mark.skipif(not _HAS_GITLEAKS, reason="gitleaks not installed")


_PATH_SCANNERS = [
    pytest.param(InfisicalScanner, marks=requires_infisical, id="infisical"),
    pytest.param(GitleaksScanner, marks=requires_gitleaks, id="gitleaks"),
    pytest.param(TrufflehogScanner, marks=requires_trufflehog, id="trufflehog"),
]


@pytest.mark.parametrize("scanner_cls", _PATH_SCANNERS)
@pytest.mark.parametrize(
    "case",  # (cwd, target, expected finding path)
    [
        (".", "proj", "proj/sub/app.env"),
        (".", "proj/sub/app.env", "proj/sub/app.env"),
        # A file in the cwd: gitleaks used to report ``app.env/app.env``.
        ("proj/sub", "app.env", "app.env"),
        ("proj/sub", "../../proj", "../../proj/sub/app.env"),
        (".", "<abs>/proj", "<abs>/proj/sub/app.env"),
        (".", "<abs>/proj/sub/app.env", "<abs>/proj/sub/app.env"),
    ],
    ids=["dir", "nested-file", "file-in-cwd", "parent-relative", "abs-dir", "abs-file"],
)
def test_scanner_scans_a_cwd_relative_path(tmp_path, monkeypatch, scanner_cls, case):
    """A path scans in any form and findings come back in that form (#843).

    ``guard <subdir>`` and ``guard --pr-base`` (which passes cwd-relative
    paths for changed files) hand scanners relative paths. Both backends ran
    the binary with ``cwd`` set to the path (or its parent) yet passed the
    relative path unchanged, so it resolved to ``proj/proj`` and the scan
    failed with ``stat proj: no such file or directory``. Relative in must be
    relative out (what guard displays and matches config paths against), and
    absolute in, absolute out.
    """
    cwd, target, expected = case
    (tmp_path / "proj" / "sub").mkdir(parents=True)
    _write_secret_file(tmp_path / "proj" / "sub", "app.env")
    monkeypatch.chdir(tmp_path / cwd)
    absolute = str(tmp_path)

    result = scanner_cls(auto_install=False).scan([Path(target.replace("<abs>", absolute))])

    assert result.error is None, f"unexpected error: {result.error}"
    assert result.findings, "the planted secrets were not reported"
    assert {f.file_path for f in result.findings} == {Path(expected.replace("<abs>", absolute))}
    for finding in result.findings:
        assert finding.file_path.is_file(), f"{finding.file_path} does not name the file"


@pytest.mark.parametrize("scanner_cls", _PATH_SCANNERS)
@pytest.mark.parametrize(
    "case",  # (target, expected finding path)
    [
        ("linkproj", "linkproj/sub/app.env"),
        ("<abs>/linkproj", "<abs>/linkproj/sub/app.env"),
        # A symlinked file is scanned as its target and reported as the link,
        # the name path-based ignores match it by.
        ("link.env", "link.env"),
        ("<abs>/link.env", "<abs>/link.env"),
    ],
    ids=["dir", "abs-dir", "file", "abs-file"],
)
def test_scanner_scans_a_symlinked_root(tmp_path, monkeypatch, scanner_cls, case):
    """A symlink given as the scan root is scanned, in any form (#853).

    Both binaries treat a symlink given as their root as a file and skip it
    without an error. A relative directory link worked only because the
    binary ran inside it; the absolute one reported nothing. A directory now
    gets a trailing separator, which makes the OS follow the link, and a
    symlinked file, which both skip even then, is given as its target and its
    findings are reported under the link.
    """
    target, expected = case
    (tmp_path / "proj" / "sub").mkdir(parents=True)
    _write_secret_file(tmp_path / "proj" / "sub", "app.env")
    try:
        (tmp_path / "linkproj").symlink_to(tmp_path / "proj", target_is_directory=True)
        (tmp_path / "link.env").symlink_to(tmp_path / "proj" / "sub" / "app.env")
    except OSError as exc:  # Windows without the symlink privilege
        pytest.skip(f"cannot create a symlink here: {exc}")
    monkeypatch.chdir(tmp_path)
    absolute = str(tmp_path)

    result = scanner_cls(auto_install=False).scan([Path(target.replace("<abs>", absolute))])

    assert result.error is None, f"unexpected error: {result.error}"
    assert result.findings, f"nothing reported for the symlinked {target}"
    assert {f.file_path for f in result.findings} == {Path(expected.replace("<abs>", absolute))}


@pytest.mark.parametrize("scanner_cls", _PATH_SCANNERS)
@pytest.mark.parametrize(
    "target",
    [
        "linkproj/..",
        pytest.param(
            "linkproj/../proj",
            marks=pytest.mark.skipif(
                sys.platform == "win32",
                reason="Windows resolves '..' lexically: the path names ./proj, which is absent",
            ),
        ),
        "<abs>/linkproj/..",
    ],
)
def test_scanner_scans_a_parent_reference_after_a_symlink(
    tmp_path, monkeypatch, scanner_cls, target
):
    """``..`` after a symlinked directory names its target's parent, and is scanned.

    Both binaries walk the directory the OS resolves but clean each walked
    path lexically, so every file below ``linkproj/..`` became a path below
    ``.`` that does not exist. They skipped it without an error: a clean scan
    of a directory holding a secret. 11.0.8 already missed the absolute form.
    """
    (tmp_path / "elsewhere" / "proj" / "sub").mkdir(parents=True)
    _write_secret_file(tmp_path / "elsewhere" / "proj" / "sub", "app.env")
    try:
        (tmp_path / "linkproj").symlink_to(
            tmp_path / "elsewhere" / "proj", target_is_directory=True
        )
    except OSError as exc:  # Windows without the symlink privilege
        pytest.skip(f"cannot create a symlink here: {exc}")
    monkeypatch.chdir(tmp_path)

    result = scanner_cls(auto_install=False).scan([Path(target.replace("<abs>", str(tmp_path)))])

    assert result.error is None, f"unexpected error: {result.error}"
    assert result.findings, f"nothing reported for {target}"
    secret_file = (tmp_path / "elsewhere" / "proj" / "sub" / "app.env").resolve()
    assert {f.file_path.resolve() for f in result.findings} == {secret_file}


def _commit_all(repo: Path) -> None:
    import subprocess  # nosec B404

    subprocess.run(["git", "add", "-A"], cwd=repo, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "secrets"], cwd=repo, capture_output=True, check=True)


@pytest.mark.parametrize("scanner_cls", _PATH_SCANNERS)
@pytest.mark.parametrize(
    "targets",
    [
        ("proj",),
        ("<abs>/proj",),
        (".",),
        # Files: Infisical's git mode cannot scan one and wrote an empty `[]`.
        ("proj/sub/app.env",),
        ("<abs>/proj/sub/app.env",),
        # ``guard --pr-base --history``: several changed files, one repository.
        ("proj/sub/app.env", "proj/other.txt", "proj"),
    ],
    ids=["subdir", "abs-subdir", "root", "file", "abs-file", "pr-base-files"],
)
def test_history_scan_of_a_subdirectory_names_the_real_file(
    git_repo, monkeypatch, scanner_cls, targets
):
    """History findings name the committed file whatever path is scanned (#843).

    History ``File`` values are repo-relative. Infisical joined them onto the
    scanned directory, so a subdirectory reported ``proj/proj/sub/app.env``, a
    relative one failed outright like the working-tree scan, and a file passed
    as clean. The secret is scrubbed from the working tree, so only the history
    can report it.
    """
    (git_repo / "proj" / "sub").mkdir(parents=True)
    _write_secret_file(git_repo / "proj" / "sub", "app.env")
    (git_repo / "proj" / "other.txt").write_text("nothing here\n")
    _commit_all(git_repo)
    (git_repo / "proj" / "sub" / "app.env").write_text("GITHUB_TOKEN=scrubbed\n")
    _commit_all(git_repo)
    monkeypatch.chdir(git_repo)
    paths = [Path(target.replace("<abs>", str(git_repo))) for target in targets]

    result = scanner_cls(auto_install=False).scan(paths, include_git_history=True)

    assert result.error is None, f"unexpected error: {result.error}"
    assert result.findings, "the committed secrets were not reported"
    secret_file = (git_repo / "proj" / "sub" / "app.env").resolve()
    assert {f.file_path.resolve() for f in result.findings} == {secret_file}
    assert all(f.commit_sha for f in result.findings)
    # One history scan per repository: several paths in it report each secret once.
    keys = [(f.rule_id, f.commit_sha, f.line_number, f.secret_hash) for f in result.findings]
    assert len(keys) == len(set(keys)), result.findings
    if scanner_cls is InfisicalScanner:
        # Relative in, relative out (gitleaks reports its absolute history root).
        assert all(
            f.file_path.is_absolute() == targets[0].startswith("<abs>") for f in result.findings
        )


@pytest.mark.parametrize("scanner_cls", _PATH_SCANNERS)
@pytest.mark.parametrize("case", ["plain-dir", "plain-file", "no-commits"])
def test_history_scan_that_cannot_run_is_an_error(tmp_path, monkeypatch, scanner_cls, case):
    """A path with no history to scan is an error, never a clean pass (#843).

    Infisical's git mode exits 1 with an empty ``[]`` report for a directory
    outside a repository or a file, and 0 with one for a repository without
    commits. All three used to read as a clean scan.
    """
    import subprocess  # nosec B404

    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    (tmp_path / "proj").mkdir()
    _write_secret_file(tmp_path / "proj", "app.env")
    if case == "no-commits":
        subprocess.run(["git", "init", "-q"], cwd=tmp_path / "proj", check=True)
    monkeypatch.chdir(tmp_path)
    target = Path("proj/app.env") if case == "plain-file" else Path("proj")

    result = scanner_cls(auto_install=False).scan([target], include_git_history=True)

    expected = "has no commits" if case == "no-commits" else "not inside a Git repository"
    assert result.error is not None, "a history scan that cannot run must fail"
    assert expected in result.error
    assert result.findings == []


_HOOK_SCANNERS = [
    *_PATH_SCANNERS,
    pytest.param(TalismanScanner, marks=requires_talisman, id="talisman"),
]


@pytest.mark.parametrize("scanner_cls", _HOOK_SCANNERS)
@pytest.mark.parametrize("include_git_history", [False, True], ids=["files", "history"])
def test_scan_reads_its_own_repository_under_a_hook_git_dir(
    git_repo, tmp_path_factory, scanner_cls, include_git_history
):
    """#915: another repository's GIT_DIR, as a git hook exports it, does not change the scan.

    The gitleaks and Infisical history scans read the hook repository's history and reported
    nothing, and Talisman failed.
    """
    _write_secret_file(git_repo, "app.env")
    _commit_all(git_repo)
    hook_repo = tmp_path_factory.mktemp("hook-repo")
    identity = ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"]
    for args in (["init", "-q"], [*identity, "commit", "-q", "--allow-empty", "-m", "init"]):
        subprocess.run(["git", *args], cwd=hook_repo, capture_output=True, check=True)
    scanner = scanner_cls(auto_install=False)

    # Only the scan runs under the hook's GIT_DIR: the commit above went to git_repo.
    with pytest.MonkeyPatch.context() as hook_env:
        hook_env.setenv("GIT_DIR", str(hook_repo / ".git"))
        result = scanner.scan([git_repo], include_git_history=include_git_history)

    assert result.error is None, f"unexpected error: {result.error}"
    assert any(Path(f.file_path).name == "app.env" for f in result.findings), result.findings


@pytest.mark.parametrize(
    ("scanner_cls", "config_name"),
    [
        pytest.param(InfisicalScanner, ".infisical-scan.toml", marks=requires_infisical, id="inf"),
        pytest.param(GitleaksScanner, ".gitleaks.toml", marks=requires_gitleaks, id="gitleaks"),
    ],
)
def test_scanner_error_is_ansi_clean(tmp_path, monkeypatch, scanner_cls, config_name):
    """A failing binary's error carries no ANSI escapes or banner (#843).

    Both binaries load ``<target>/<config_name>`` and exit with a colored
    ``FTL`` log line when it is malformed. The integration conftest sets
    ``NO_COLOR``, which these binaries honour, so it is removed here to get
    the colors a user's terminal environment produces.
    """
    monkeypatch.delenv("NO_COLOR", raising=False)
    (tmp_path / "proj").mkdir()
    _write_secret_file(tmp_path / "proj", "app.env")
    (tmp_path / "proj" / config_name).write_text("[[rules]\nid = \n")
    monkeypatch.chdir(tmp_path)

    result = scanner_cls(auto_install=False).scan([Path("proj")])

    assert result.error, "a malformed scanner config must fail the scan"
    assert "\x1b" not in result.error, repr(result.error)
    assert "config" in result.error
    assert "○" not in result.error, f"gitleaks banner in error: {result.error!r}"


# --- ScanEngine orchestration / filtering (P1) ----------------------------


@pytest.mark.skipif(
    not (_HAS_TRIVY and _HAS_TALISMAN),
    reason="needs BOTH trivy and talisman installed",
)
def test_scan_engine_parallel_multi_real_scanner_aggregation(git_repo):
    """HP-04: ScanEngine runs native+trivy+talisman in parallel and aggregates them."""
    import subprocess  # nosec B404

    (git_repo / "app.env").write_text(f"GITHUB_TOKEN={GITHUB_TOKEN}\nSTRIPE_KEY={STRIPE_KEY}\n")
    subprocess.run(["git", "add", "-A"], cwd=git_repo, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "secrets"],
        cwd=git_repo,
        capture_output=True,
        check=True,
    )

    config = GuardConfig(
        use_native=True,
        use_gitleaks=False,
        use_trivy=True,
        use_talisman=True,
        auto_install=False,
        skip_encrypted_files=False,
    )
    engine = ScanEngine(config)
    result = engine.scan([git_repo])

    assert isinstance(result, AggregatedScanResult)
    assert {"native", "trivy", "talisman"}.issubset(set(result.scanners_used))
    assert len(result.results) == 3
    # At least one real secret should be found and aggregation/dedup is consistent.
    assert len(result.unique_findings) >= 1
    assert result.total_findings >= len(result.unique_findings)
    # Findings should come from more than one scanner (native + trivy at minimum).
    # Use the per-scanner results, NOT unique_findings: ScanEngine deduplicates
    # after aggregation, so two scanners finding the same secret would collapse to
    # one entry in unique_findings and understate scanner participation.
    scanners_with_findings = {r.scanner_name for r in result.results if r.findings}
    assert len(scanners_with_findings) >= 2, (
        f"expected findings from >=2 scanners, got {scanners_with_findings}"
    )


@requires_trivy
def test_scan_engine_skip_encrypted_files_filters_real_scanner_findings(tmp_path):
    """HP-14: skip_encrypted_files drops findings on dotenvx ciphertext lines.

    A combined partial-encryption file interleaves a dotenvx-encrypted secret
    line ("encrypted:") with a cleartext secret line. With skip_encrypted_files
    on, findings on the ciphertext line are dropped but the cleartext finding
    survives; with it off, the unfiltered count is >= the filtered count.
    """
    combined = tmp_path / "combined.env"
    # Line 1: dotenvx marker forces the whole file to be "encrypted-aware".
    # Line 2: a ciphertext line (a real-format secret embedded after encrypted:).
    # Line 3: a cleartext secret on its own line that must survive filtering.
    combined.write_text(f"API_KEY=encrypted:BEx{GITHUB_TOKEN}\nGITHUB_TOKEN={GITHUB_TOKEN}\n")

    base = GuardConfig(
        use_native=True,
        use_gitleaks=False,
        use_trivy=True,
        auto_install=False,
    )

    filtered_cfg = replace(base, skip_encrypted_files=True)
    unfiltered_cfg = replace(base, skip_encrypted_files=False)

    filtered = ScanEngine(filtered_cfg).scan([tmp_path])
    unfiltered = ScanEngine(unfiltered_cfg).scan([tmp_path])

    # No surviving finding may point at the ciphertext (line 1) "encrypted:" line.
    for finding in filtered.unique_findings:
        if finding.file_path.name == "combined.env":
            assert finding.line_number != 1, "ciphertext-line finding should have been filtered out"
    # The cleartext secret on line 2 must still be reported by some scanner.
    cleartext_survivors = [
        f
        for f in filtered.unique_findings
        if f.file_path.name == "combined.env" and f.line_number == 2
    ]
    assert cleartext_survivors, "cleartext secret on line 2 should survive filtering"
    # Filtering never increases the finding count.
    assert len(unfiltered.unique_findings) >= len(filtered.unique_findings)


@requires_trivy
def test_scan_engine_filters_dotenvx_public_keys_from_real_output(tmp_path):
    """EC-12: ScanEngine filters dotenvx EC public keys via secret_hash (#370).

    Scanners only ever expose a *redacted* preview plus a one-way ``secret_hash``;
    the old length-66 preview check was dead (previews are ~8 chars). The filter
    now hashes the ``DOTENV_PUBLIC_KEY*`` value declared in a finding's file and
    drops findings whose ``secret_hash`` matches — this test exercises that
    hash-based contract.
    """
    from envdrift.scanner.base import FindingSeverity
    from envdrift.scanner.patterns import hash_secret

    _write_secret_file(tmp_path, "creds.env")
    # Plant a real dotenvx-style EC public key (66 hex, starts with 03), declared
    # on a DOTENV_PUBLIC_KEY line so the engine can hash + filter it.
    real_pubkey = "03" + "cd" * 32  # 66 hex chars
    (tmp_path / "keys.env").write_text(f"DOTENV_PUBLIC_KEY_PRODUCTION={real_pubkey}\n")

    config = GuardConfig(
        use_native=True,
        use_gitleaks=False,
        use_trivy=True,
        auto_install=False,
        skip_encrypted_files=False,
    )
    engine = ScanEngine(config)
    result = engine.scan([tmp_path])

    # No surviving finding may hash to the planted public key.
    planted_hash = hash_secret(real_pubkey)
    for finding in result.unique_findings:
        assert finding.secret_hash != planted_hash, (
            f"public key leaked through filter: {finding.rule_id} in {finding.file_path}"
        )

    # Control: a finding whose secret_hash matches a DOTENV_PUBLIC_KEY value in
    # its own file is removed; a normal secret (different hash) is kept.
    pubkey = "02" + "ab" * 32  # 66 hex chars, starts with 02
    ctrl = tmp_path / "ctrl.env"
    ctrl.write_text(f"DOTENV_PUBLIC_KEY_X={pubkey}\n")
    pubkey_finding = ScanFinding(
        file_path=ctrl,
        rule_id="trivy-generic",
        rule_description="Public Key",
        description="pubkey",
        severity=FindingSeverity.HIGH,
        scanner="trivy",
        secret_preview="02ab****abab",  # redacted, as a real scanner emits
        secret_hash=hash_secret(pubkey),
    )
    normal_finding = ScanFinding(
        file_path=ctrl,
        rule_id="trivy-github-pat",
        rule_description="GitHub PAT",
        description="secret",
        severity=FindingSeverity.HIGH,
        scanner="trivy",
        secret_preview="ghp_****abcd",
        secret_hash=hash_secret("ghp_realtokenvalue1234567890abcdEFGH"),
    )
    kept = engine._filter_public_keys([pubkey_finding, normal_finding])
    assert pubkey_finding not in kept
    assert normal_finding in kept


# --- Trivy redacted-Match dedup regression (#479) --------------------------

# A second GitHub PAT with the SAME shape and length as GITHUB_TOKEN (and the
# same variable name in fixtures below) so trivy's redacted ``Match`` lines are
# byte-identical for both files. Assembled from fragments for push protection.
GITHUB_TOKEN_B = "ghp_" + "92RkXwQ7tBn4MvCs" + "1LhJd8PfYg5WzEuA63To"


def _plant_same_shape_tokens(directory) -> None:
    """Two distinct same-shape secrets whose redacted Match lines collide."""
    (directory / "a.txt").write_text(f"TOKEN={GITHUB_TOKEN}\n", encoding="utf-8")
    (directory / "b.txt").write_text(f"TOKEN={GITHUB_TOKEN_B}\n", encoding="utf-8")


@requires_trivy
def test_trivy_distinct_secrets_survive_skip_duplicate_cli(tmp_path):
    """#479: ``guard --trivy --skip-duplicate`` must report BOTH distinct secrets.

    Exact issue repro through the real CLI subprocess and the real trivy
    binary: two files each hold a different GitHub PAT with the same variable
    name and length. Trivy redacts the matched span in ``Match`` to a
    same-length ``*`` run (``Secret`` is null), so hashing the Match line makes
    the two findings collide and ``--skip-duplicate`` silently drops one — a
    false negative.
    """
    import json as _json
    import os
    import subprocess  # nosec B404
    import sys
    from pathlib import Path

    assert len(GITHUB_TOKEN_B) == len(GITHUB_TOKEN) and GITHUB_TOKEN_B != GITHUB_TOKEN
    _plant_same_shape_tokens(tmp_path)

    repo_root = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{repo_root / 'src'}{os.pathsep}{env.get('PYTHONPATH', '')}"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "envdrift.cli",
            "guard",
            "--trivy",
            "--no-gitleaks",
            "--no-detect-secrets",
            "--no-auto-install",
            "--skip-duplicate",
            "--json",
            ".",
        ],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )

    out = proc.stdout
    # ``--json`` stdout is contractually a single clean JSON document (no
    # ANSI, no prose) -- parse it strictly so any stray output fails loudly.
    try:
        payload = _json.loads(out)
    except _json.JSONDecodeError as exc:  # pragma: no cover - failure path
        pytest.fail(
            f"guard --json stdout is not clean JSON: {exc}\nstdout:\n{out}\nstderr:\n{proc.stderr}"
        )
    # Native now scans untracked .txt files (#441), so cross-scanner duplicate
    # collapse may correctly retain the native-owned copy of each secret. The
    # companion direct-Trivy test below proves both raw hashes originate from
    # Trivy; this CLI assertion owns the aggregate contract that both distinct
    # values survive --skip-duplicate regardless of scanner attribution.
    reported_files = {Path(f["file_path"]).name for f in payload["findings"]}
    scanner_results = {result["name"]: result for result in payload["scanner_results"]}
    assert scanner_results["trivy"]["files_scanned"] == 2, scanner_results
    assert reported_files == {"a.txt", "b.txt"}, (
        f"--skip-duplicate must keep both distinct secrets, got {sorted(reported_files)}\n"
        f"stdout:\n{out}\nstderr:\n{proc.stderr}"
    )
    # Critical findings present -> guard exits 1.
    assert proc.returncode == 1, f"expected exit 1, got {proc.returncode}\nstderr: {proc.stderr}"


@requires_trivy
def test_trivy_hash_and_preview_recover_raw_secret_from_real_output(tmp_path):
    """#479: the adapter recovers the raw value trivy redacted in ``Match``.

    ``secret_hash`` must be the hash of the actual secret (so cross-scanner
    collapse keeps working) and ``secret_preview`` must preview the secret,
    not the redacted Match line.
    """
    from envdrift.scanner.patterns import hash_secret, redact_secret

    _plant_same_shape_tokens(tmp_path)

    scanner = TrivyScanner(auto_install=False)
    result = scanner.scan([tmp_path])

    assert result.error is None, f"unexpected error: {result.error}"
    by_file = {f.file_path.name: f for f in result.findings if f.rule_id == "trivy-github-pat"}
    assert set(by_file) == {"a.txt", "b.txt"}, f"got findings: {result.findings}"
    assert by_file["a.txt"].secret_hash == hash_secret(GITHUB_TOKEN)
    assert by_file["b.txt"].secret_hash == hash_secret(GITHUB_TOKEN_B)
    assert by_file["a.txt"].secret_preview == redact_secret(GITHUB_TOKEN)
    assert by_file["b.txt"].secret_preview == redact_secret(GITHUB_TOKEN_B)
    # The raw secrets never leak into previews.
    assert GITHUB_TOKEN not in by_file["a.txt"].secret_preview
    assert GITHUB_TOKEN_B not in by_file["b.txt"].secret_preview


@requires_trivy
def test_trivy_finding_collapses_with_native_for_same_secret_under_skip_duplicate(tmp_path):
    """#479: one secret found by trivy AND native collapses under skip_duplicate.

    The documented cross-scanner duplicate collapse keys on ``secret_hash``;
    that only works when trivy hashes the raw value rather than the redacted
    Match line (which can never match another scanner's hash).
    """
    from envdrift.scanner.patterns import hash_secret

    (tmp_path / "creds.env").write_text(f"GITHUB_TOKEN={GITHUB_TOKEN}\n", encoding="utf-8")

    config = GuardConfig(
        use_native=True,
        use_gitleaks=False,
        use_trivy=True,
        auto_install=False,
        skip_duplicate=True,
    )
    result = ScanEngine(config).scan([tmp_path])

    assert {"native", "trivy"}.issubset(set(result.scanners_used))
    token_hash = hash_secret(GITHUB_TOKEN)
    matching = [f for f in result.unique_findings if f.secret_hash == token_hash]
    assert len(matching) == 1, (
        f"the same secret must collapse to ONE finding, got {len(matching)}: {matching}"
    )
    # The old bug: trivy hashed the redacted Match line instead of the secret.
    masked_line_hash = hash_secret("GITHUB_TOKEN=" + "*" * len(GITHUB_TOKEN))
    assert all(f.secret_hash != masked_line_hash for f in result.unique_findings), (
        "a finding still hashes the redacted Match line as if it were the secret"
    )


@requires_trivy
def test_trivy_two_distinct_secrets_on_one_line_keep_distinct_hashes(tmp_path):
    """#479 same-line case: two distinct same-rule secrets on ONE line.

    Trivy censors ALL secret spans in the line before building each finding's
    ``Match``, so the two findings it emits are byte-identical dicts. Recovery
    is rejected (the differing span contains the unmasked separator), and the
    fallback hash must carry an occurrence index so the two real secrets do
    not collapse into one under ``--skip-duplicate``.
    """
    (tmp_path / "creds.env").write_text(
        f"T1={GITHUB_TOKEN} T2={GITHUB_TOKEN_B}\n", encoding="utf-8"
    )

    scanner = TrivyScanner(auto_install=False)
    result = scanner.scan([tmp_path])

    assert result.error is None, f"unexpected error: {result.error}"
    pats = [f for f in result.findings if f.rule_id == "trivy-github-pat"]
    assert len(pats) == 2, f"trivy must report both same-line secrets, got: {result.findings}"
    hashes = {f.secret_hash for f in pats}
    assert all(hashes), "fallback findings must still carry a non-empty hash"
    assert len(hashes) == 2, (
        "two distinct same-line secrets collapsed to one hash (#479 same-line case)"
    )
