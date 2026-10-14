"""Every scanner grades a credential class the same (#850).

``tests/severity_policy.py`` encodes the policy once: each credential class, the severity it
must have, and the identifiers (native pattern ids, gitleaks and Infisical rule IDs,
detect-secrets detector names, Kingfisher keywords, git-secrets rule types) that stand for it.
These tests hold every scanner's table to it, so an edit to one table that drifts from the
others fails here. They also hold the tables to the rule IDs of the real tools
(``tests/fixtures/scanner_rule_ids.json``): a provider with a CRITICAL class cannot have a rule
that falls back to HIGH unnoticed. The real-scanner counterpart is
``tests/integration/test_severity_policy_real.py``.
"""

from __future__ import annotations

import fnmatch
import itertools
import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

from envdrift.scanner import infisical, kingfisher
from envdrift.scanner.base import FindingSeverity
from envdrift.scanner.detect_secrets import DETECTOR_SEVERITY, DetectSecretsScanner
from envdrift.scanner.git_secrets import RULE_TYPE_SEVERITY, GitSecretsScanner
from envdrift.scanner.gitleaks import GitleaksScanner
from envdrift.scanner.infisical import InfisicalScanner
from envdrift.scanner.native import NativeScanner
from envdrift.scanner.patterns import ALL_PATTERNS
from envdrift.scanner.rule_severity import RULE_SEVERITY_MAP, rule_severity
from tests.severity_policy import (
    POLICY,
    STRIPE_TEST_KEY_SEVERITY,
    WAIVED_RULES,
    CredentialClass,
    class_samples,
)

CRITICAL = FindingSeverity.CRITICAL
HIGH = FindingSeverity.HIGH

ENTROPY_RULE = "high-entropy-string"  # emitted by native.py, not a pattern in patterns.py
PATTERN_SEVERITY = {pattern.id: pattern.severity for pattern in ALL_PATTERNS}
# No sample reaches these natively: the entropy rule needs a file of its own, and docker-auth
# matches a docker config's ``"auth"`` field.
NO_NATIVE_SAMPLE = {ENTROPY_RULE, "docker-auth"}
PLACEHOLDER_SECRET = "q8Zt3VnR7wXy2Lp9" + "Ks4Bd6Fh1Jm5Nc0Gx"
# The 40-character value of a secret access key (AWS documents this one as its example).
AWS_SECRET_VALUE = "wJalrXUtnFEMI/K7MDENG/bPxRfi" + "CYEXAMPLEKEY"

# The original rule IDs of the shared table. No built-in rule of any tool uses them, but a
# custom rules config may, so they stay; every other key must be a rule a tool really has.
LEGACY_RULE_IDS = {"aws-access-key-id", "google-api-key", "slack-token", "stripe-api-key"}

BETTERLEAKS_PREFIX = "betterleaks."
RULE_IDS_FILE = Path(__file__).resolve().parents[1] / "fixtures" / "scanner_rule_ids.json"


def _load_rule_ids() -> dict[str, list[str]]:
    with RULE_IDS_FILE.open(encoding="utf-8") as handle:
        document = json.load(handle)
    return {tool: ids for tool, ids in document.items() if not tool.startswith("_")}


REAL_RULE_IDS = _load_rule_ids()
KINGFISHER_RULE_IDS = REAL_RULE_IDS["kingfisher"]
# The rule IDs of gitleaks and both Infisical engines, plus the betterleaks rules Kingfisher
# embeds: all of them are looked up in the one shared table.
SHARED_RULE_IDS = sorted(
    {rid for tool, ids in REAL_RULE_IDS.items() if tool != "kingfisher" for rid in ids}
    | {
        rid.removeprefix(BETTERLEAKS_PREFIX)
        for rid in KINGFISHER_RULE_IDS
        if rid.startswith(BETTERLEAKS_PREFIX)
    }
)
# Kingfisher's other built-in rules (``veles.<id>``, its second rule source) are graded by a
# keyword. Each is named here with the grade it must get, so a new one has to be graded.
VELES_RULE_GRADES = {
    "bitbucketcredentials": HIGH,
    "bitwardenoauth2access": HIGH,
    "circleciproject": HIGH,
    "cloudflareapitoken": HIGH,
    "codecatalystcredentials": HIGH,
    "codecommitcredentials": HIGH,
    "denopatorg": HIGH,
    "digitaloceanapikey": CRITICAL,
    "grokxaiapikey": HIGH,
    "hcpclientcredentials": HIGH,
    "hcpclientcredentials-client-id": HIGH,
    "herokuplatformkey": CRITICAL,
    "npmjsaccesstoken": CRITICAL,
    "openrouter": HIGH,
    "packagistorgreadtoken": HIGH,
    "packagistorgreadtoken-repository": HIGH,
    "packagistorgupdatetoken": HIGH,
    "packagistorgupdatetoken-repository": HIGH,
    "packagistsecret": HIGH,
    "packagistsecret-api-key": HIGH,
    "postmanapikey": CRITICAL,
    "postmancollectiontoken": CRITICAL,
    "sendgrid": CRITICAL,
    "slackappconfigaccesstoken": CRITICAL,
    "slackappconfigrefreshtoken": CRITICAL,
    "slackappleveltoken": CRITICAL,
}

by_class = pytest.mark.parametrize("cls", POLICY, ids=lambda c: c.name)


def _duplicates(values: Iterable[str]) -> list[str]:
    return sorted(value for value, count in Counter(values).items() if count > 1)


def test_policy_names_each_class_and_identifier_once():
    """An identifier in two classes could not be held to either grade."""
    assert _duplicates(c.name for c in POLICY) == []
    for column in ("native", "rules", "detect_secrets", "kingfisher", "git_secrets"):
        identifiers = itertools.chain.from_iterable(getattr(c, column) for c in POLICY)
        assert _duplicates(identifiers) == [], column


def test_policy_native_ids_are_real_patterns():
    """A policy id no pattern has would never be held to its grade."""
    unknown = {i for c in POLICY for i in c.native} - set(PATTERN_SEVERITY) - {ENTROPY_RULE}
    assert not unknown, f"policy lists native ids that patterns.py does not define: {unknown}"


def test_every_native_pattern_belongs_to_a_class():
    """A pattern no class claims is not held to any grade, so an edit to it goes unnoticed.

    The patterns no other scanner has a class for are pinned by the policy at the grade they
    have: changing one is a decision, made in ``tests/severity_policy.py``.
    """
    claimed = {i for c in POLICY for i in c.native}
    unclaimed = (set(PATTERN_SEVERITY) | {ENTROPY_RULE}) - claimed
    assert not unclaimed, f"native patterns that no policy class claims: {sorted(unclaimed)}"


@by_class
def test_native_patterns_grade_the_class_as_the_policy_says(cls: CredentialClass):
    """The native scanner is the reference: its grade is the class's grade."""
    for pattern_id in cls.native:
        if pattern_id != ENTROPY_RULE:
            assert PATTERN_SEVERITY[pattern_id] == cls.severity, pattern_id


def test_native_entropy_findings_follow_the_policy(tmp_path: Path):
    """High-entropy strings come from native.py, not a pattern, so scan one."""
    (tmp_path / "blob.env").write_text("BLOB=" + PLACEHOLDER_SECRET + "P7wYe2Tq\n", "utf-8")

    result = NativeScanner(check_entropy=True).scan([tmp_path])

    entropy = [f for f in result.findings if f.rule_id == ENTROPY_RULE]
    assert entropy, [f.rule_id for f in result.findings]
    expected = next(c for c in POLICY if ENTROPY_RULE in c.native).severity
    assert {f.severity for f in entropy} == {expected}


@by_class
def test_shared_rule_table_grades_the_class_as_the_policy_says(cls: CredentialClass):
    """gitleaks and Infisical rule IDs, listed or falling back, get the class's grade."""
    for rule in cls.rules:
        assert rule_severity(rule, PLACEHOLDER_SECRET) == cls.severity, rule
        assert rule_severity(rule.upper(), PLACEHOLDER_SECRET) == cls.severity, rule


@by_class
def test_gitleaks_and_infisical_grade_through_the_shared_table(
    cls: CredentialClass, tmp_path: Path
):
    """Both scanners route their rule IDs through ``rule_severity``, the same table (#850)."""
    gitleaks, infisical_scanner = (
        GitleaksScanner(auto_install=False),
        InfisicalScanner(auto_install=False),
    )
    for rule in cls.rules:
        item: dict[str, Any] = {"RuleID": rule, "File": "a.env", "Secret": PLACEHOLDER_SECRET}
        for scanner in (gitleaks, infisical_scanner):
            finding = scanner._parse_finding(item, tmp_path)
            assert finding is not None
            assert finding.severity == cls.severity, (scanner.name, rule)


@by_class
def test_detect_secrets_grades_the_class_as_the_policy_says(cls: CredentialClass):
    scanner = DetectSecretsScanner(auto_install=False)
    for detector in cls.detect_secrets:
        assert DETECTOR_SEVERITY[detector] == cls.severity, detector
        secret = {"type": detector, "line_number": 1, "hashed_secret": "0123abcd"}
        finding = scanner._parse_secret(secret, Path("app.cfg"))
        assert finding is not None
        assert finding.severity == cls.severity, detector


@by_class
def test_kingfisher_grades_the_class_as_the_policy_says(cls: CredentialClass):
    """A rule that is not betterleaks' is graded by a keyword in its id or name."""
    for keyword in cls.kingfisher:
        severity = kingfisher._map_severity(f"kingfisher.{keyword}.1", f"{keyword} rule")
        assert severity == cls.severity, keyword


@by_class
def test_kingfisher_grades_betterleaks_rules_through_the_shared_table(cls: CredentialClass):
    """Its ``betterleaks.<id>`` rules get the grade gitleaks and Infisical give ``<id>``."""
    for rule in cls.rules:
        severity = kingfisher._map_severity(
            f"{BETTERLEAKS_PREFIX}{rule}", "whatever the rule is called", PLACEHOLDER_SECRET
        )
        assert severity == cls.severity, rule


def test_kingfisher_grades_every_published_betterleaks_rule_like_the_shared_table():
    betterleaks = [r for r in KINGFISHER_RULE_IDS if r.startswith(BETTERLEAKS_PREFIX)]
    assert len(betterleaks) > 100
    for rule_id in betterleaks:
        expected = rule_severity(rule_id.removeprefix(BETTERLEAKS_PREFIX), PLACEHOLDER_SECRET)
        assert kingfisher._map_severity(rule_id, "", PLACEHOLDER_SECRET) == expected, rule_id


def test_kingfisher_grades_a_rule_by_its_id_whatever_its_name_says():
    """A betterleaks rule's name must not turn it CRITICAL (``aws`` is in an Azure name too)."""
    assert kingfisher._map_severity("betterleaks.azure-client-id", "AWS Azure Client ID") == HIGH
    assert kingfisher._map_severity("BETTERLEAKS.AWS-ACCESS-TOKEN", "x") == CRITICAL


def test_kingfisher_veles_rules_are_all_graded_explicitly():
    """A Veles rule that Kingfisher adds fails here until it is graded."""
    published = {r for r in KINGFISHER_RULE_IDS if not r.startswith(BETTERLEAKS_PREFIX)}
    assert published == set(VELES_RULE_GRADES)


@pytest.mark.parametrize("prefix", ["veles.", ""], ids=["veles-namespace", "bare"])
def test_kingfisher_grades_the_veles_rules_by_keyword(prefix: str):
    for rule, expected in VELES_RULE_GRADES.items():
        assert kingfisher._map_severity(prefix + rule, rule) == expected, rule


def test_a_kingfisher_rule_no_class_lists_is_graded_like_the_generic_rules():
    """The fallback is HIGH here too, not MEDIUM: Kingfisher's rules are credential detectors."""
    generic = next(c for c in POLICY if c.name == "generic-secret")
    assert kingfisher._map_severity("kingfisher.unknown.1", "Unknown Rule") == generic.severity
    assert kingfisher._map_severity("betterleaks.unknown", "Unknown") == generic.severity


@by_class
def test_git_secrets_grades_the_class_as_the_policy_says(cls: CredentialClass, tmp_path: Path):
    scanner = GitSecretsScanner(auto_install=False)
    lines = {
        "aws-access-key": "AWS_ACCESS_KEY_ID=AKIA" + "QYLPMN5HHHFPZAM2",
        "aws-secret-key": "aws_secret_access_key = " + AWS_SECRET_VALUE,
        "private-key": "-----BEGIN RSA PRIVATE KEY-----",
        "password": "password=" + PLACEHOLDER_SECRET,
        "token": "api_token=" + PLACEHOLDER_SECRET,
        "api-key": "api_key=" + PLACEHOLDER_SECRET,
        "generic-secret": "some_value=" + PLACEHOLDER_SECRET,
    }
    for rule_type in cls.git_secrets:
        assert RULE_TYPE_SEVERITY[rule_type] == cls.severity, rule_type
        finding = scanner._create_finding("a.env", 1, lines[rule_type], tmp_path)
        assert finding.rule_id == f"git-secrets-{rule_type}"
        assert finding.severity == cls.severity, rule_type


def test_every_table_entry_belongs_to_a_class():
    """A rule, detector or keyword the policy does not know cannot be held to a grade.

    Adding an entry to a table without a class here fails, so a grade cannot be set in one
    scanner and forgotten in the others.
    """
    rules = {r for c in POLICY for r in c.rules}
    detectors = {d for c in POLICY for d in c.detect_secrets}
    critical_keywords = {k for c in POLICY if c.severity is CRITICAL for k in c.kingfisher}
    rule_types = {t for c in POLICY for t in c.git_secrets}

    assert set(RULE_SEVERITY_MAP) - rules == set()
    assert set(DETECTOR_SEVERITY) == detectors
    assert critical_keywords == kingfisher.CRITICAL_SEVERITY_RULES
    assert set(RULE_TYPE_SEVERITY) == rule_types


# --- The shared table against the rule IDs the real tools have ---


def test_the_rule_id_lists_of_the_real_tools_are_loaded():
    assert set(REAL_RULE_IDS) == {
        "gitleaks",
        "infisical (gitleaks engine)",
        "infisical (betterleaks engine)",
        "kingfisher",
    }
    assert all(len(ids) > 100 for ids in REAL_RULE_IDS.values()), "an empty rule ID list"


def test_every_key_of_the_shared_table_is_a_rule_a_tool_has():
    """A misspelt key is dead: its rule silently falls back to HIGH."""
    dead = set(RULE_SEVERITY_MAP) - set(SHARED_RULE_IDS) - LEGACY_RULE_IDS
    assert not dead, f"rule IDs that no tool has: {sorted(dead)}"


def test_every_real_rule_of_a_critical_provider_is_critical_or_waived():
    """A rule of a provider with a CRITICAL class that the table forgot would be HIGH.

    gitleaks and betterleaks keep adding rules, so each rule ID whose provider belongs to a
    CRITICAL class (``CredentialClass.rule_patterns``) must be graded CRITICAL by the shared
    table, or be waived in ``tests/severity_policy.py`` with the reason it is no credential.
    This is the check that finds a rule that a tool upgrade adds.
    """
    patterns = [p for c in POLICY if c.severity is CRITICAL for p in c.rule_patterns]
    missing = [
        rule
        for rule in SHARED_RULE_IDS
        if any(fnmatch.fnmatchcase(rule, pattern) for pattern in patterns)
        and rule not in WAIVED_RULES
        and rule_severity(rule, PLACEHOLDER_SECRET) != CRITICAL
    ]
    assert not missing, (
        f"rules of a CRITICAL provider graded below CRITICAL: {missing}. Grade each CRITICAL in "
        "rule_severity.py and list it in tests/severity_policy.py, or waive it there if it "
        "matches an identifier or a public value."
    )


def test_every_provider_pattern_matches_a_real_rule():
    """A pattern that matches nothing would check nothing."""
    for cls in POLICY:
        for pattern in cls.rule_patterns:
            assert any(fnmatch.fnmatchcase(rule, pattern) for rule in SHARED_RULE_IDS), pattern


def test_a_waived_rule_is_a_real_rule_of_a_critical_provider_graded_below_critical():
    patterns = [p for c in POLICY if c.severity is CRITICAL for p in c.rule_patterns]
    for rule, reason in WAIVED_RULES.items():
        assert reason, rule
        assert rule in SHARED_RULE_IDS, f"{rule} is waived but no tool has it"
        assert any(fnmatch.fnmatchcase(rule, p) for p in patterns), f"{rule} needs no waiver"
        assert rule_severity(rule, PLACEHOLDER_SECRET) != CRITICAL, rule


def test_a_rule_the_table_does_not_list_is_graded_like_the_generic_rules():
    """The fallback is the grade of the generic secret class, not an accident."""
    generic = next(c for c in POLICY if c.name == "generic-secret")
    assert rule_severity("some-rule-no-tool-has", PLACEHOLDER_SECRET) == generic.severity


def test_stripe_test_keys_are_graded_below_live_keys():
    """``stripe-access-token`` matches test-mode keys too, and those cannot move money."""
    body = "4eC39HqLyjWDarjtT1zdp7dc" + "ABCDEFGH"
    live = next(c for c in POLICY if c.name == "stripe-live-key")
    assert rule_severity("stripe-access-token", "sk_live_" + body) == live.severity
    assert rule_severity("stripe-access-token", "rk_live_" + body) == live.severity
    for prefix in ("sk_test_", "rk_test_"):
        assert rule_severity("stripe-access-token", prefix + body) == STRIPE_TEST_KEY_SEVERITY
    assert live.severity > STRIPE_TEST_KEY_SEVERITY


def test_kingfisher_grades_stripe_test_keys_below_live_keys_by_the_matched_value():
    body = "4eC39HqLyjWDarjtT1zdp7dc" + "ABCDEFGH"
    rule = f"{BETTERLEAKS_PREFIX}stripe-access-token"
    assert kingfisher._map_severity(rule, "Stripe", "sk_live_" + body) == CRITICAL
    assert kingfisher._map_severity(rule, "Stripe", "sk_test_" + body) == STRIPE_TEST_KEY_SEVERITY
    # Kingfisher does not always report the value; without it the grade is the live one.
    assert kingfisher._map_severity(rule, "Stripe") == CRITICAL


def test_infisical_still_exports_the_shared_table():
    """The table moved to ``rule_severity``; existing imports from here keep working."""
    assert infisical.RULE_SEVERITY_MAP is RULE_SEVERITY_MAP


def test_a_jwt_is_never_graded_below_high():
    """It was HIGH in gitleaks, Infisical and detect-secrets, and the native scanner agrees.

    Lowering it let the default gate (``--fail-on high``) pass a JWT, and a bearer token or a
    Supabase service_role key looks like a public one.
    """
    jwt = next(c for c in POLICY if c.name == "jwt")
    assert jwt.severity is HIGH
    assert PATTERN_SEVERITY["jwt-token"] is HIGH
    assert rule_severity("jwt", PLACEHOLDER_SECRET) is HIGH
    assert DETECTOR_SEVERITY["JSON Web Token"] is HIGH


def test_native_scan_of_each_class_sample_follows_the_policy(tmp_path: Path):
    """The native scanner flags a realistic sample of each class under the policy's id and grade.

    This runs the real scanner (no binary needed) over the sample files, so a pattern id the
    policy lists must exist and fire, and every finding of a class gets the class's grade.
    """
    owners: dict[str, CredentialClass] = {}
    for cls in POLICY:
        owners.update(dict.fromkeys(cls.native, cls))
    for cls_name, files in class_samples().items():
        for name, content in files.items():
            (tmp_path / f"{cls_name}__{name.lstrip('.')}").write_text(content, encoding="utf-8")

    result = NativeScanner(check_entropy=False).scan([tmp_path])

    assert result.error is None
    reported: dict[str, set[str]] = {}
    for finding in result.findings:
        owner = owners.get(finding.rule_id)
        if owner is None:
            continue
        assert finding.severity == owner.severity, (finding.rule_id, finding.file_path)
        reported.setdefault(owner.name, set()).add(finding.rule_id)
    for cls in POLICY:
        if set(cls.native) <= NO_NATIVE_SAMPLE or cls.name not in class_samples():
            continue
        assert cls.name in reported, f"native did not flag the {cls.name} sample"
