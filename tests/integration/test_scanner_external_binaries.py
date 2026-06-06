"""Integration tests for external-binary secret scanners.

These tests exercise the REAL scanner binaries (talisman, trivy, infisical) and
the ScanEngine orchestration/filtering against real subprocess output. Each test
is gated on the binary being installed via ``shutil.which`` / ``is_installed()``
so it SKIPs cleanly when a tool is absent (e.g. in a minimal local env) and runs
in CI where the tools are provisioned.

No mocking of scanner behavior: findings come from running the actual tools on
real files in temporary directories / git repos.
"""

from __future__ import annotations

import shutil
from dataclasses import replace

import pytest

from envdrift.scanner.base import AggregatedScanResult, ScanFinding, ScanResult
from envdrift.scanner.engine import GuardConfig, ScanEngine
from envdrift.scanner.infisical import InfisicalScanner
from envdrift.scanner.talisman import TalismanScanner
from envdrift.scanner.trivy import TrivyScanner

pytestmark = [pytest.mark.integration, pytest.mark.slow]


# --- Skip helpers ---------------------------------------------------------

_HAS_TALISMAN = TalismanScanner(auto_install=False).is_installed()
_HAS_TRIVY = TrivyScanner(auto_install=False).is_installed()
_HAS_INFISICAL = InfisicalScanner(auto_install=False).is_installed()

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
