"""Real scanner output against the cross-scanner severity policy (#850).

``tests/scanner/test_severity_policy.py`` holds every scanner's table to
``tests/severity_policy.py``. These tests hold what the REAL tools report to it: gitleaks,
Infisical (whichever engine is installed: 0.43.135 is gitleaks', 0.43.136 and later betterleaks)
and detect-secrets scan a realistic sample file of each credential class, and every finding of
a class must carry the class's severity. They also pin which classes each tool recognises, so a
rule that is renamed in a tool upgrade (and would silently fall back to HIGH) fails here.

Each test skips when its tool is not installed. Nothing is mocked: the samples are built from
fragments at run time (GitHub push protection) and written to a temp directory.
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from tests.severity_policy import (
    POLICY,
    STRIPE_TEST_KEY_SEVERITY,
    STRIPE_TEST_SAMPLE,
    CredentialClass,
    class_samples,
)

from envdrift.scanner.base import FindingSeverity, ScanFinding
from envdrift.scanner.detect_secrets import DetectSecretsScanner
from envdrift.scanner.gitleaks import GitleaksScanner
from envdrift.scanner.infisical import InfisicalScanner

pytestmark = [pytest.mark.integration, pytest.mark.slow]

requires_gitleaks = pytest.mark.skipif(
    not GitleaksScanner(auto_install=False).is_installed(), reason="gitleaks not installed"
)
requires_infisical = pytest.mark.skipif(
    not InfisicalScanner(auto_install=False).is_installed(), reason="infisical not installed"
)
requires_detect_secrets = pytest.mark.skipif(
    importlib.util.find_spec("detect_secrets") is None,
    reason="detect-secrets not installed (pip install detect-secrets)",
)

# The classes each tool reports under one of the class's own rule IDs, taken from real runs of
# gitleaks 8.30.1, Infisical 0.43.135 and 0.43.141, and detect-secrets 1.5.0 over class_samples().
# gitleaks and Infisical 0.43.135 share the gitleaks rule set; betterleaks (0.43.136 and later)
# has rules the others lack and lacks a few they have. These sets are what BOTH Infisical engines
# recognise, so they hold whichever is installed.
NOT_IN_GITLEAKS = {
    "azure-storage-key",  # betterleaks only (gitleaks reports the key as generic-api-key)
    "gcp-service-account",  # betterleaks only, and only next to more fields than the sample has
    "ibm-cloud-iam-key",  # betterleaks only
    "supabase-token",  # betterleaks only
    "credentials-in-url",  # betterleaks only
}
INFISICAL_RECOGNISES = {
    "atlassian-api-token",
    "aws",
    "cloudflare-api-token",
    "digitalocean-token",
    "doppler-token",
    "facebook-access-token",
    "generic-secret",
    "github-token",
    "gitlab-token",
    "google-api-key",
    "heroku-api-key",
    "jwt",
    "linear-api-key",
    "mailchimp-api-key",
    "mailgun-api-key",
    "npm-token",
    "openai-api-key",
    "postman-api-key",
    "private-key",
    "pypi-token",
    "sendgrid-api-key",
    "shopify-token",
    "slack-token",
    "square-token",
    "stripe-live-key",
    "telegram-bot-token",
    "twilio-sid",
    "vault-token",
}
# detect-secrets verifies some secrets over the network and drops those a provider rejects
# (Slack, Stripe, AWS, Mailchimp, Telegram, ...), so only detectors without a verifier are
# pinned as recognised here; the others are still held to the policy when they do report.
DETECT_SECRETS_RECOGNISES = {
    "artifactory-credentials",
    "azure-storage-key",
    "credentials-in-url",
    "discord-bot-token",
    "generic-secret",
    "github-token",
    "gitlab-token",
    "jwt",
    "npm-token",
    "openai-api-key",
    "private-key",
    "pypi-token",
    "sendgrid-api-key",
    "square-token",
    "twilio-sid",
}

# Rules of CRITICAL providers that the first version of the shared table forgot, so they were
# HIGH. The sample files of ``class_samples()`` make each tool report them (real runs of
# gitleaks 8.30.1 and both Infisical engines), and each must now be CRITICAL.
ADDED_RULES_IN_GITLEAKS = {
    "age-secret-key",
    "aws-amazon-bedrock-api-key-long-lived",
    "discord-api-token",
    "discord-client-secret",
    "facebook-secret",
    "gitlab-feature-flag-client-token",
    "gitlab-session-cookie",
    "linear-client-secret",
}
ADDED_RULES_IN_BOTH_INFISICAL_ENGINES = ADDED_RULES_IN_GITLEAKS - {
    "aws-amazon-bedrock-api-key-long-lived"
}
ADDED_RULES_IN_BETTERLEAKS_ONLY = {
    "aws-amazon-bedrock-api-key-long-lived",
    "azure-app-configuration-connection-string",
    "azure-servicebus-connection-string",
    "gcp-application-default-credentials",
    "gcp-gemini-api",
    "gitlab-incoming-mail-address-token",
    "polymarket-private-key",
    "supabase-project-api-key",
}

RULE_OWNERS: dict[str, CredentialClass] = {r: c for c in POLICY for r in c.rules}
DETECTOR_OWNERS: dict[str, CredentialClass] = {d: c for c in POLICY for d in c.detect_secrets}


def _infisical_runs_betterleaks() -> bool:
    """Whether the installed Infisical is 0.43.136 or later, the betterleaks engine."""
    version = InfisicalScanner(auto_install=False).get_version() or ""
    numbers = tuple(int(part) for part in re.findall(r"\d+", version)[:3])
    return numbers >= (0, 43, 136)


@pytest.fixture(scope="module")
def samples_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One file per sample, named ``<class>__<file>``, in a directory outside any git repo."""
    root = tmp_path_factory.mktemp("severity-samples")
    for class_name, files in class_samples().items():
        for name, content in files.items():
            (root / f"{class_name}__{name.lstrip('.')}").write_text(content, encoding="utf-8")
    return root


def _sample_class(finding: ScanFinding) -> str:
    """The class a finding's sample file was written for."""
    return Path(finding.file_path).name.split("__")[0]


def _expected(owner: CredentialClass, finding: ScanFinding) -> FindingSeverity:
    """The policy's severity for ``finding``: a Stripe test key is graded below a live one."""
    if _sample_class(finding) == STRIPE_TEST_SAMPLE and finding.rule_id.endswith(
        "stripe-access-token"
    ):
        return STRIPE_TEST_KEY_SEVERITY
    return owner.severity


def _bare(rule_id: str, prefix: str) -> str:
    return rule_id.removeprefix(prefix + "-")


def _disagreements(
    findings: list[ScanFinding], owners: dict[str, CredentialClass], key: str, prefix: str = ""
) -> list[str]:
    bad = []
    for finding in findings:
        ident = finding.rule_description if key == "type" else _bare(finding.rule_id, prefix)
        owner = owners.get(ident)
        if owner is not None and finding.severity != _expected(owner, finding):
            bad.append(
                f"{Path(finding.file_path).name}: {ident} graded {finding.severity.value}, "
                f"policy says {_expected(owner, finding).value} ({owner.name})"
            )
    return sorted(set(bad))


def _recognised(
    findings: list[ScanFinding], owners: dict[str, CredentialClass], key: str, prefix: str = ""
) -> set[str]:
    """The classes a tool reported on that class's own sample file, under that class's id."""
    out = set()
    for finding in findings:
        ident = finding.rule_description if key == "type" else _bare(finding.rule_id, prefix)
        owner = owners.get(ident)
        if owner is not None and owner.name == _sample_class(finding):
            out.add(owner.name)
    return out


@pytest.fixture(scope="module")
def gitleaks_findings(samples_dir: Path) -> list[ScanFinding]:
    result = GitleaksScanner(auto_install=False).scan([samples_dir])
    assert result.error is None, result.error
    return result.findings


@pytest.fixture(scope="module")
def infisical_findings(samples_dir: Path) -> list[ScanFinding]:
    result = InfisicalScanner(auto_install=False).scan([samples_dir])
    assert result.error is None, result.error
    return result.findings


@pytest.fixture(scope="module")
def detect_secrets_findings(samples_dir: Path) -> list[ScanFinding]:
    # samples_dir is not in a git repo, which detect-secrets needs unless told to scan all
    # files (#851), so this also exercises that fix against the real package.
    result = DetectSecretsScanner(auto_install=False).scan([samples_dir])
    assert result.error is None, result.error
    return result.findings


@requires_gitleaks
def test_gitleaks_grades_every_class_as_the_policy_says(gitleaks_findings: list[ScanFinding]):
    assert gitleaks_findings, "gitleaks reported nothing over the samples"
    assert _disagreements(gitleaks_findings, RULE_OWNERS, "rule", "gitleaks") == []


@requires_gitleaks
def test_gitleaks_reports_the_classes_the_policy_lists_rules_for(
    gitleaks_findings: list[ScanFinding],
):
    """A policy rule ID gitleaks no longer emits would grade that class HIGH, silently."""
    expected = {c.name for c in POLICY if c.rules} - NOT_IN_GITLEAKS
    recognised = _recognised(gitleaks_findings, RULE_OWNERS, "rule", "gitleaks")
    assert expected - recognised == set(), (
        f"no policy rule matched the sample: {expected - recognised}"
    )


def _grades_of(findings: list[ScanFinding], prefix: str) -> dict[str, set[FindingSeverity]]:
    """The severities each rule of the tool graded, by the rule's bare ID."""
    graded: dict[str, set[FindingSeverity]] = {}
    for finding in findings:
        graded.setdefault(_bare(finding.rule_id, prefix), set()).add(finding.severity)
    return graded


@requires_gitleaks
def test_gitleaks_reports_the_rules_added_to_the_table_and_grades_them_critical(
    gitleaks_findings: list[ScanFinding],
):
    graded = _grades_of(gitleaks_findings, "gitleaks")
    assert ADDED_RULES_IN_GITLEAKS - graded.keys() == set(), "a rule was renamed or dropped"
    for rule in ADDED_RULES_IN_GITLEAKS:
        assert graded[rule] == {FindingSeverity.CRITICAL}, rule


@requires_gitleaks
def test_gitleaks_grades_stripe_test_keys_below_live_keys(gitleaks_findings: list[ScanFinding]):
    graded = {
        _sample_class(f): f.severity
        for f in gitleaks_findings
        if f.rule_id == "gitleaks-stripe-access-token"
    }
    assert graded[STRIPE_TEST_SAMPLE] == STRIPE_TEST_KEY_SEVERITY
    assert graded["stripe-live-key"] == FindingSeverity.CRITICAL


@requires_infisical
def test_infisical_grades_every_class_as_the_policy_says(infisical_findings: list[ScanFinding]):
    assert infisical_findings, "infisical reported nothing over the samples"
    assert _disagreements(infisical_findings, RULE_OWNERS, "rule", "infisical") == []


@requires_infisical
def test_infisical_reports_the_classes_both_engines_have_rules_for(
    infisical_findings: list[ScanFinding],
):
    recognised = _recognised(infisical_findings, RULE_OWNERS, "rule", "infisical")
    assert INFISICAL_RECOGNISES - recognised == set(), (
        f"no policy rule matched the sample: {INFISICAL_RECOGNISES - recognised}"
    )


@requires_infisical
def test_infisical_reports_the_rules_added_to_the_table_and_grades_them_critical(
    infisical_findings: list[ScanFinding],
):
    """Both engines report the first group; only betterleaks (0.43.136 and later) the second."""
    expected = set(ADDED_RULES_IN_BOTH_INFISICAL_ENGINES)
    if _infisical_runs_betterleaks():
        expected |= ADDED_RULES_IN_BETTERLEAKS_ONLY
    graded = _grades_of(infisical_findings, "infisical")
    assert expected - graded.keys() == set(), "a rule was renamed or dropped"
    for rule in expected:
        assert graded[rule] == {FindingSeverity.CRITICAL}, rule


@requires_infisical
def test_infisical_grades_stripe_test_keys_below_live_keys(infisical_findings: list[ScanFinding]):
    graded = {
        _sample_class(f): f.severity
        for f in infisical_findings
        if f.rule_id == "infisical-stripe-access-token"
    }
    assert graded[STRIPE_TEST_SAMPLE] == STRIPE_TEST_KEY_SEVERITY
    assert graded["stripe-live-key"] == FindingSeverity.CRITICAL


@requires_detect_secrets
def test_detect_secrets_grades_every_class_as_the_policy_says(
    detect_secrets_findings: list[ScanFinding],
):
    assert detect_secrets_findings, "detect-secrets reported nothing over the samples"
    assert _disagreements(detect_secrets_findings, DETECTOR_OWNERS, "type") == []


@requires_detect_secrets
def test_detect_secrets_reports_the_classes_the_policy_lists_detectors_for(
    detect_secrets_findings: list[ScanFinding],
):
    """A detector name a detect-secrets upgrade renames would grade that class HIGH, silently."""
    recognised = _recognised(detect_secrets_findings, DETECTOR_OWNERS, "type")
    assert DETECT_SECRETS_RECOGNISES - recognised == set(), (
        f"no policy detector matched the sample: {DETECT_SECRETS_RECOGNISES - recognised}"
    )


@requires_detect_secrets
def test_detect_secrets_grades_a_twilio_lookalike_high_not_critical(
    detect_secrets_findings: list[ScanFinding],
):
    """``CACHE_KEY=AC<32 hex>`` is no credential, yet detect-secrets reports a Twilio API key.

    The native scanner stopped flagging it (#355), so CRITICAL would be a false alarm at the
    top severity. Twilio SIDs are identifiers, graded HIGH like the other scanners do.
    """
    cache_key = [
        f for f in detect_secrets_findings if Path(f.file_path).name.endswith("cache-key.env")
    ]
    assert [f.rule_description for f in cache_key] == ["Twilio API Key"]
    assert [f.severity for f in cache_key] == [FindingSeverity.HIGH]


@requires_detect_secrets
def test_detect_secrets_grades_a_private_key_critical(detect_secrets_findings: list[ScanFinding]):
    """It was HIGH while the native scanner and Infisical graded private keys CRITICAL."""
    keys = [f for f in detect_secrets_findings if f.rule_description == "Private Key"]
    assert keys, "detect-secrets did not report the private key samples"
    assert {f.severity for f in keys} == {FindingSeverity.CRITICAL}


# --- The CLI verdict: ``--fail-on critical`` must block what gitleaks grades CRITICAL ---


def _guard(args: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Run the real ``envdrift guard`` CLI as a subprocess."""
    return subprocess.run(
        [sys.executable, "-m", "envdrift.cli", "guard", *args],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )


# The native scanner always runs and grades these same credentials CRITICAL (aws, stripe) or HIGH
# (the .env policy); ignoring them leaves gitleaks alone to decide the verdict, as it did in #850.
_IGNORE_NATIVE = (
    "[guard.ignore_rules]\n"
    '"aws-access-key-id" = ["*"]\n'
    '"stripe-secret-key" = ["*"]\n'
    '"github-pat" = ["*"]\n'
    '"unencrypted-env-file" = ["*"]\n'
    '"generic-api-key" = ["*"]\n'
    '"jwt-token" = ["*"]\n'
    '"high-entropy-string" = ["*"]\n'
)


@requires_gitleaks
@pytest.mark.parametrize(
    ("filename", "content", "fail_on", "exit_code", "severity"),
    [
        pytest.param(
            "aws.env",
            "AWS_ACCESS_KEY_ID=" + "AKIA" + "QYLPMN5HHHFPZAM2\n",
            "critical",
            1,
            "critical",
            id="aws-key-id-blocks-fail-on-critical",
        ),
        pytest.param(
            "stripe.env",
            "STRIPE_KEY=" + "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc" + "ABCDEFGH\n",
            "critical",
            1,
            "critical",
            id="stripe-live-key-blocks-fail-on-critical",
        ),
        pytest.param(
            "github.env",
            "GITHUB_TOKEN=" + "ghp_" + "016C7eX9bQ2vYwN3kLmZpRtUaScDfGhJkL01\n",
            "critical",
            1,
            "critical",
            id="github-token-blocks-fail-on-critical",
        ),
        pytest.param(
            "stripe-test.env",
            "STRIPE_TEST_KEY=" + "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc" + "ABCDEFGH\n",
            "critical",
            0,
            "high",
            id="stripe-test-key-is-high-so-fail-on-critical-passes",
        ),
        pytest.param(
            "stripe-test.env",
            "STRIPE_TEST_KEY=" + "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc" + "ABCDEFGH\n",
            "high",
            2,
            "high",
            id="stripe-test-key-still-blocks-fail-on-high",
        ),
        pytest.param(
            "jwt.env",
            class_samples()["jwt"]["session.env"],
            "high",
            2,
            "high",
            id="jwt-blocks-the-default-fail-on-high",
        ),
        pytest.param(
            "jwt.env",
            class_samples()["jwt"]["session.env"],
            "critical",
            0,
            "high",
            id="jwt-is-high-so-fail-on-critical-passes",
        ),
    ],
)
def test_guard_fail_on_follows_gitleaks_severity(
    tmp_path: Path,
    integration_env: dict[str, str],
    filename: str,
    content: str,
    fail_on: str,
    exit_code: int,
    severity: str,
):
    """gitleaks graded every finding HIGH, so ``--fail-on critical`` exited 0 on an AWS key (#850).

    Only gitleaks' finding decides here (the native rules for the same value are ignored), and
    the exit code is the severity-derived one: 1 for CRITICAL, 2 for HIGH.
    """
    (tmp_path / filename).write_text(content, encoding="utf-8")
    (tmp_path / "envdrift.toml").write_text(_IGNORE_NATIVE, encoding="utf-8")

    result = _guard(
        [".", "--ci", "--fail-on", fail_on, "--json", "--no-auto-install"]
        + ["--config", "envdrift.toml"],
        cwd=tmp_path,
        env=integration_env,
    )

    assert result.returncode == exit_code, (result.returncode, result.stdout, result.stderr)
    payload = json.loads(result.stdout)
    assert payload["exit_code"] == exit_code
    gitleaks = [f for f in payload["findings"] if f["scanner"] == "gitleaks"]
    assert [f["severity"] for f in gitleaks] == [severity], payload["findings"]
    # JSON severities are the plain lower-case names, with no escapes.
    assert re.fullmatch(r"[a-z]+", gitleaks[0]["severity"])
