"""Infisical ``--confidence`` gating and ``ComponentSets`` parsing (#834).

Infisical CLI 0.43.136 replaced its gitleaks engine with betterleaks. Two
behaviours of the new engine silently cost envdrift findings:

* it drops everything rated below ``--confidence`` (default "medium"), which
  includes lone AWS secret access keys and generic API keys, while 0.43.135
  and older reject the flag with a usage error and write no report;
* its composite ``aws-access-token`` rule nests the paired secret access key
  under ``ComponentSets`` instead of reporting it as a finding.

The scanner therefore probes ``scan --help`` per binary and flattens the
components that are secrets, while skipping the identifiers (tenant and client
IDs, usernames, hosts) other composite rules nest the same way. The probe
tests drive a small POSIX shell stand-in for the binary that answers
``scan --help`` like each engine does, logs every invocation, and for the scan
itself writes a report shaped like real 0.43.141 output. The real-binary
checks live in ``tests/integration/test_scanner_external_binaries.py``.
"""

from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path

import pytest

from envdrift.scanner import infisical
from envdrift.scanner.base import FindingSeverity, ScanFinding
from envdrift.scanner.infisical import (
    InfisicalScanner,
    _probe_confidence_flag,
    _supports_confidence_flag,
)
from envdrift.scanner.patterns import hash_secret

posix_stub = pytest.mark.skipif(
    sys.platform == "win32", reason="the stand-in binary is a POSIX shell script"
)

# Fragmented so no full credential literal appears in source (push protection).
AKID = "AKIA" + "KIT74Y7PUQ23N6CF"
SECRET = "Eg+RG/Xq82Tiq6vi" + "6Iqw0Dm7sdvmMBTnlFjGO5hh"
ASIA = "ASIA" + "TE6A37WYKNWJ2AA2"

# `scan --help` excerpts: 0.43.136+ adds exactly the --confidence line.
BETTERLEAKS_HELP = """\
Flags:
  -b, --baseline-path string   path to baseline with issues that can be ignored
      --confidence string      minimum confidence to include (low, medium, high) (default "medium")
  -r, --report-path string     report file
"""
GITLEAKS_HELP = """\
Flags:
  -b, --baseline-path string   path to baseline with issues that can be ignored
  -r, --report-path string     report file
"""


def _composite(file: str, line: int, key_id: str, secret_line: int = 2) -> dict:
    """A betterleaks ``aws-access-token`` finding, as 0.43.141 writes it."""
    return {
        "RuleID": "aws-access-token",
        "Description": "Identified an AWS access key ID paired with a secret access key.",
        "StartLine": line,
        "EndLine": line,
        "StartColumn": 19,
        "Match": key_id,
        "Secret": key_id,
        "Attributes": {"confidence": "high"},
        "ComponentSets": [
            {
                "components": [
                    {
                        "RuleID": "aws-secret-access-key",
                        "Optional": False,
                        "StartLine": secret_line,
                        "EndLine": secret_line,
                        "StartColumn": 5,
                        "Match": f"SECRET_ACCESS_KEY={SECRET}",
                        "Secret": SECRET,
                    }
                ]
            }
        ],
        "File": file,
        "Commit": "",
        "Entropy": 3.92,
        "Author": "",
        "Email": "",
        "Date": "",
    }


# Azure service-principal and database values, fragmented like the keys above.
TENANT_ID = "3f2b8c1d-4e5a-4b6c-" + "9d7e-8f9a0b1c2d3e"
CLIENT_ID = "a1b2c3d4-e5f6-4a7b-" + "8c9d-0e1f2a3b4c5d"
AZURE_SECRET = "Xy78Q~" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tV9wX1yZ3b"
DB_PASSWORD = "Tr0ub4dor" + "&3xK9pQ!vL2m"

# The components of 0.43.141's composite rules that are secret material.
SECRET_COMPONENT_RULES = [
    "alibaba-sts-security-token",
    "aws-secret-access-key",
    "exoscale-api-secret",
    "ovh-consumer-key",
    "polymarket-api-secret",
    "polymarket-passphrase",
]

# Every component of a composite rule in the 0.43.141 default config that is
# an identifier, account name, host or URL rather than a secret.
NON_SECRET_COMPONENT_RULES = [
    "aikido-client-id",
    "algolia-application-id",
    "alibaba-access-key-id",
    "alibaba-sts-access-key-id",
    "artifactory-jfrog-url",
    "azure-client-id",
    "azure-storage-account-name",
    "azure-tenant-id",
    "canva-client-id",
    "clickhouse-cloud-key-id",
    "cloudinary-api-key",
    "cloudinary-cloud-name",
    "ebay-client-id",
    "generic-username",
    "lark-app-id",
    "mongodb-atlas-service-account-id",
    "ovh-application-key",
    "planetscale-id",
    "plivo-auth-id",
    "ramp-client-id",
    "salesforce-instance-url.1",
    "snowflake-account-host.1",
    "supabase-project-url",
    "tableau-personal-access-token-name.1",
    "tableau-server-host.1",
]


def _component(rule_id: str, line: int, match: str, secret: str, *, optional: bool = False) -> dict:
    """One ``ComponentSets`` member, as 0.43.141 writes it."""
    return {
        "RuleID": rule_id,
        "Optional": optional,
        "StartLine": line,
        "EndLine": line,
        "StartColumn": 1,
        "EndColumn": len(match),
        "Match": match,
        "Secret": secret,
    }


def _report_item(
    file: str, rule_id: str, line: int, secret: str, components: list, confidence: str
) -> dict:
    """A betterleaks finding with ``components``, in 0.43.141's report shape."""
    return {
        "RuleID": rule_id,
        "Description": rule_id,
        "StartLine": line,
        "EndLine": line,
        "StartColumn": 20,
        "EndColumn": 20 + len(secret),
        "Match": f"={secret}",
        "Secret": secret,
        "Attributes": {"confidence": confidence, "path": file, "resource": "fs.content"},
        "Tags": [],
        "ComponentSets": [{"components": components}],
        "Fingerprint": f"{file}:{rule_id}:{line}",
        "File": file,
        "SymlinkFile": "",
        "Commit": "",
        "Entropy": 4.78,
        "Author": "",
        "Email": "",
        "Date": "",
        "Message": "",
    }


def _azure_service_principal(file: str) -> dict:
    """0.43.141's report for a tenant ID, client ID and client secret on lines 1-3."""
    components = [
        _component("azure-tenant-id", 1, f"AZURE_TENANT_ID={TENANT_ID}", TENANT_ID),
        _component("azure-client-id", 2, f"AZURE_CLIENT_ID={CLIENT_ID}", CLIENT_ID),
    ]
    return _report_item(file, "azure-ad-client-secret", 3, AZURE_SECRET, components, "high")


def _generic_password(file: str) -> dict:
    """0.43.141's report for a username on line 1 and its password on line 2."""
    username = _component(
        "generic-username", 1, "_USERNAME=reporting_service", "reporting_service", optional=True
    )
    return _report_item(file, "generic-password", 2, DB_PASSWORD, [username], "low")


def _make_stub(
    directory: Path,
    help_text: str,
    *,
    help_rc: int = 0,
    rejects_confidence: bool = False,
    report: list | None = None,
    help_command: str | None = None,
) -> Path:
    """Write an executable stand-in for the infisical binary into ``directory``.

    ``scan --help`` appends to ``help.log`` and prints ``help_text`` (or runs
    ``help_command``). Any other invocation appends its argv to ``argv.log``
    and copies ``report`` to the ``--report-path`` file, exiting 1 like the
    real CLI does when it finds leaks, or 0 for an empty report: the real CLI
    never exits non-zero on a clean scan, and envdrift treats a non-zero exit
    with no findings as a failed scan (#843). With ``rejects_confidence`` it instead
    behaves like 0.43.135 given ``--confidence``: usage error, exit 1, no report.
    """
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "help.txt").write_text(help_text)
    (directory / "report.json").write_text(json.dumps(report or []))
    d = shlex.quote(str(directory))
    reject = (
        'for a in "$@"; do if [ "$a" = "--confidence" ]; then '
        'echo "Error: unknown flag: --confidence" >&2; exit 1; fi; done'
        if rejects_confidence
        else ":"
    )
    script = f"""#!/bin/sh
if [ "$1" = "scan" ] && [ "$2" = "--help" ]; then
  echo probe >> {d}/help.log
  {help_command or f"cat {d}/help.txt"}
  exit {help_rc}
fi
{{ printf '%s ' "$@"; echo; }} >> {d}/argv.log
{reject}
while [ $# -gt 0 ]; do
  if [ "$1" = "--report-path" ]; then cat {d}/report.json > "$2"; fi
  shift
done
exit {1 if report else 0}
"""
    stub = directory / "infisical"
    stub.write_text(script)
    stub.chmod(0o755)
    return stub


def _log_lines(stub: Path, name: str) -> list[str]:
    log = stub.parent / name
    return log.read_text().splitlines() if log.exists() else []


def _scanner(stub: Path) -> InfisicalScanner:
    scanner = InfisicalScanner(auto_install=False)
    scanner._binary_path = stub
    return scanner


@pytest.fixture(autouse=True)
def _fresh_probe_cache():
    """Keep each test's probe count independent of every other test's."""
    _probe_confidence_flag.cache_clear()
    yield
    _probe_confidence_flag.cache_clear()


@posix_stub
class TestConfidenceFlagProbe:
    """``_supports_confidence_flag`` reads the binary's own ``scan --help``."""

    def test_betterleaks_help_is_detected(self, tmp_path: Path):
        assert _supports_confidence_flag(_make_stub(tmp_path, BETTERLEAKS_HELP)) is True

    def test_gitleaks_era_help_is_not_detected(self, tmp_path: Path):
        assert _supports_confidence_flag(_make_stub(tmp_path, GITLEAKS_HELP)) is False

    def test_flag_named_only_in_prose_does_not_count(self, tmp_path: Path):
        """Only a flag definition line counts, not a mention in a description."""
        help_text = GITLEAKS_HELP + "  -v, --verbose   like --confidence, but louder\n"
        assert _supports_confidence_flag(_make_stub(tmp_path, help_text)) is False

    def test_longer_flag_sharing_the_prefix_does_not_count(self, tmp_path: Path):
        help_text = GITLEAKS_HELP + "      --confidence-file string   some other flag\n"
        assert _supports_confidence_flag(_make_stub(tmp_path, help_text)) is False

    def test_failing_help_command_fails_safe(self, tmp_path: Path):
        """A non-zero ``--help`` exit is "unsupported" even if the text matches."""
        stub = _make_stub(tmp_path, BETTERLEAKS_HELP, help_rc=2)
        assert _supports_confidence_flag(stub) is False

    def test_hanging_help_command_fails_safe(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(infisical, "_HELP_PROBE_TIMEOUT_SECONDS", 0.2)
        stub = _make_stub(tmp_path, BETTERLEAKS_HELP, help_command="exec sleep 5")
        assert _supports_confidence_flag(stub) is False

    def test_failed_probe_is_logged_and_not_cached(self, tmp_path: Path, caplog):
        """A failed probe must be visible and retried, not remembered as "no flag".

        On a betterleaks binary a failed probe means the scan silently runs at
        the default medium confidence, so it is logged, and it is not cached:
        a transient failure (a slow first run) must not stick for the process.
        """
        stub = _make_stub(tmp_path, BETTERLEAKS_HELP, help_rc=2)
        with caplog.at_level("WARNING", logger="envdrift.scanner.infisical"):
            assert _supports_confidence_flag(stub) is False
            assert _supports_confidence_flag(stub) is False
        assert _log_lines(stub, "help.log") == ["probe", "probe"]
        messages = " ".join(r.getMessage() for r in caplog.records)
        assert "exit code 2" in messages
        assert "drops low-confidence findings" in messages

    def test_probe_runs_once_per_binary(self, tmp_path: Path):
        stub = _make_stub(tmp_path, BETTERLEAKS_HELP)
        assert _supports_confidence_flag(stub) is True
        assert _supports_confidence_flag(stub) is True
        assert _log_lines(stub, "help.log") == ["probe"]

    def test_binary_replaced_in_place_is_probed_again(self, tmp_path: Path):
        """An upgrade at the same path must not keep the old answer."""
        stub = _make_stub(tmp_path, GITLEAKS_HELP)
        assert _supports_confidence_flag(stub) is False
        stub.write_text(stub.read_text() + "# upgraded to 0.43.141\n")
        (tmp_path / "help.txt").write_text(BETTERLEAKS_HELP)
        assert _supports_confidence_flag(stub) is True


class TestConfidenceFlagProbeUnrunnable:
    """Binaries that cannot answer at all must never break the scan."""

    def test_missing_binary_fails_safe(self, tmp_path: Path, caplog):
        with caplog.at_level("WARNING", logger="envdrift.scanner.infisical"):
            assert _supports_confidence_flag(tmp_path / "infisical") is False
        assert "scanning without it" in caplog.text

    def test_unexecutable_binary_fails_safe(self, tmp_path: Path):
        binary = tmp_path / "infisical"
        binary.write_text("not a program\n")
        binary.chmod(0o644)
        assert _supports_confidence_flag(binary) is False


@posix_stub
class TestScanCommandLine:
    """``scan()`` passes ``--confidence low`` exactly when the binary takes it."""

    def test_betterleaks_binary_scans_at_low_confidence(self, tmp_path: Path):
        src = tmp_path / "src"
        src.mkdir()
        stub = _make_stub(
            tmp_path / "bin", BETTERLEAKS_HELP, report=[_composite("aws.env", 1, AKID)]
        )

        result = _scanner(stub).scan([src])

        assert result.error is None, result.error
        (argv,) = _log_lines(stub, "argv.log")
        assert " --confidence low " in f" {argv} "
        # The paired secret access key, nested under ComponentSets, is surfaced.
        by_line = {f.line_number: f for f in result.findings}
        assert set(by_line) == {1, 2}
        assert by_line[2].rule_id == "infisical-aws-secret-access-key"
        assert by_line[2].file_path == src / "aws.env"
        assert by_line[2].secret_hash == hash_secret(SECRET)
        assert by_line[2].severity == FindingSeverity.CRITICAL
        assert SECRET not in by_line[2].secret_preview

    def test_gitleaks_binary_scans_without_the_flag(self, tmp_path: Path):
        """0.43.135 rejects --confidence (no report), so it must never get it."""
        src = tmp_path / "src"
        src.mkdir()
        report = [{"RuleID": "aws-access-token", "StartLine": 1, "File": "a.env", "Secret": AKID}]
        stub = _make_stub(tmp_path / "bin", GITLEAKS_HELP, rejects_confidence=True, report=report)

        result = _scanner(stub).scan([src])

        assert result.error is None, result.error
        (argv,) = _log_lines(stub, "argv.log")
        assert "--confidence" not in argv.split()
        assert [f.line_number for f in result.findings] == [1]

    def test_nothing_to_scan_skips_the_probe(self, tmp_path: Path):
        """No existing path means no scan, so the probe must not run either."""
        stub = _make_stub(tmp_path / "bin", BETTERLEAKS_HELP)

        result = _scanner(stub).scan([tmp_path / "missing"])

        assert result.error is None, result.error
        assert result.findings == []
        assert _log_lines(stub, "help.log") == []
        assert _log_lines(stub, "argv.log") == []

    def test_every_path_is_scanned_at_low_confidence_after_one_probe(self, tmp_path: Path):
        first, second = tmp_path / "one", tmp_path / "two"
        first.mkdir()
        second.mkdir()
        stub = _make_stub(tmp_path / "bin", BETTERLEAKS_HELP)

        result = _scanner(stub).scan([first, second])

        assert result.error is None, result.error
        assert _log_lines(stub, "help.log") == ["probe"]
        scans = _log_lines(stub, "argv.log")
        assert len(scans) == 2
        assert all(" --confidence low " in f" {argv} " for argv in scans)

    def test_identifiers_nested_next_to_a_secret_are_not_reported(self, tmp_path: Path):
        """Tenant and client IDs and usernames in ComponentSets are not secrets.

        0.43.141 nests them under the Azure client secret and the password it
        reports; turning them into HIGH findings would fail ``guard`` on values
        that are not secrets and that 0.43.135 never reported.
        """
        src = tmp_path / "src"
        src.mkdir()
        report = [_azure_service_principal("azure.env"), _generic_password("db.env")]
        stub = _make_stub(tmp_path / "bin", BETTERLEAKS_HELP, report=report)

        result = _scanner(stub).scan([src])

        assert result.error is None, result.error
        reported = sorted((f.file_path.name, f.line_number, f.rule_id) for f in result.findings)
        assert reported == [
            ("azure.env", 3, "infisical-azure-ad-client-secret"),
            ("db.env", 2, "infisical-generic-password"),
        ]


class TestComponentSets:
    """``_parse_components`` flattens betterleaks secret components into findings."""

    def test_component_inherits_file_and_commit_context(self, tmp_path: Path):
        item = _composite("aws.env", 1, AKID) | {"Commit": "abc123", "Author": "dev"}

        (finding,) = InfisicalScanner(auto_install=False)._parse_components([item], tmp_path, [])

        assert finding.file_path == tmp_path / "aws.env"
        assert finding.line_number == 2
        assert finding.column_number == 5
        assert finding.rule_id == "infisical-aws-secret-access-key"
        assert "aws-access-token" in finding.rule_description
        assert finding.commit_sha == "abc123"
        assert finding.commit_author == "dev"
        assert finding.secret_hash == hash_secret(SECRET)

    def test_paired_key_id_and_nested_secret_are_both_critical(self, tmp_path: Path):
        """0.43.141 reports the key ID under ``aws-access-token`` and nests the
        secret under it. Both must be CRITICAL; the key ID used to be graded
        HIGH, so ``--fail-on critical`` let it through (#844)."""
        report = [_composite("aws.env", 1, AKID)]
        scanner = InfisicalScanner(auto_install=False)

        key_id = scanner._parse_finding(report[0], tmp_path)
        (secret,) = scanner._parse_components(report, tmp_path, [])

        assert key_id is not None
        assert key_id.rule_id == "infisical-aws-access-token"
        assert key_id.severity == FindingSeverity.CRITICAL
        assert secret.rule_id == "infisical-aws-secret-access-key"
        assert secret.severity == FindingSeverity.CRITICAL

    def test_secret_shared_by_two_key_ids_is_reported_once(self, tmp_path: Path):
        report = [_composite("aws.env", 1, AKID), _composite("aws.env", 3, ASIA)]

        components = InfisicalScanner(auto_install=False)._parse_components(report, tmp_path, [])

        assert [f.line_number for f in components] == [2]

    @staticmethod
    def _existing(tmp_path: Path, rule: str, severity: FindingSeverity) -> ScanFinding:
        """A finding already parsed for the secret on line 2 of aws.env."""
        return ScanFinding(
            file_path=tmp_path / "aws.env",
            line_number=2,
            rule_id=f"infisical-{rule}",
            rule_description=rule,
            description=f"Secret detected: {rule}",
            severity=severity,
            scanner="infisical",
            secret_hash=hash_secret(SECRET),
        )

    def test_secret_already_reported_under_the_same_rule_is_not_duplicated(self, tmp_path: Path):
        existing = self._existing(tmp_path, "aws-secret-access-key", FindingSeverity.CRITICAL)
        report = [_composite("aws.env", 1, AKID)]

        scanner = InfisicalScanner(auto_install=False)
        assert scanner._parse_components(report, tmp_path, [existing]) == []

    def test_critical_component_survives_a_weaker_finding_of_another_rule(self, tmp_path: Path):
        """A HIGH generic finding on the same line and secret must not swallow
        the CRITICAL AWS secret component, or ``--fail-on critical`` passes."""
        existing = self._existing(tmp_path, "generic-api-key", FindingSeverity.HIGH)
        report = [_composite("aws.env", 1, AKID)]

        scanner = InfisicalScanner(auto_install=False)
        (component,) = scanner._parse_components(report, tmp_path, [existing])

        assert component.rule_id == "infisical-aws-secret-access-key"
        assert component.severity == FindingSeverity.CRITICAL
        assert component.line_number == 2

    @pytest.mark.parametrize(
        "component_sets",
        [None, {}, "x", 5, [None], [{"components": None}], [{"components": "x"}], [{}]],
    )
    def test_malformed_component_sets_are_ignored(self, tmp_path: Path, component_sets):
        item = _composite("aws.env", 1, AKID) | {"ComponentSets": component_sets}

        scanner = InfisicalScanner(auto_install=False)
        assert scanner._parse_components([item], tmp_path, []) == []

    def test_non_mapping_entries_are_skipped(self, tmp_path: Path):
        item = _composite("aws.env", 1, AKID)
        item["ComponentSets"][0]["components"].insert(0, "junk")
        report = ["junk", None, item]

        components = InfisicalScanner(auto_install=False)._parse_components(report, tmp_path, [])

        assert [f.line_number for f in components] == [2]

    def test_unparseable_component_is_skipped_not_fatal(self, tmp_path: Path):
        item = _composite("aws.env", 1, AKID)
        unparseable = {"RuleID": "aws-secret-access-key", "StartLine": 4, "Secret": 12345}
        item["ComponentSets"][0]["components"].insert(0, unparseable)

        components = InfisicalScanner(auto_install=False)._parse_components([item], tmp_path, [])

        assert [f.line_number for f in components] == [2]

    def test_findings_without_components_add_nothing(self, tmp_path: Path):
        report = [{"RuleID": "github-pat", "StartLine": 1, "File": "a.env", "Secret": "x"}]

        assert InfisicalScanner(auto_install=False)._parse_components(report, tmp_path, []) == []

    def test_allowlist_is_exactly_the_reviewed_secret_components(self):
        assert sorted(infisical._SECRET_COMPONENT_RULES) == SECRET_COMPONENT_RULES

    @pytest.mark.parametrize("rule_id", SECRET_COMPONENT_RULES)
    def test_every_listed_secret_component_is_reported(self, tmp_path: Path, rule_id: str):
        item = _composite("creds.env", 1, AKID)
        item["ComponentSets"][0]["components"][0]["RuleID"] = rule_id

        (finding,) = InfisicalScanner(auto_install=False)._parse_components([item], tmp_path, [])

        assert finding.rule_id == f"infisical-{rule_id}"
        assert finding.line_number == 2
        assert finding.secret_hash == hash_secret(SECRET)

    @pytest.mark.parametrize("rule_id", [*NON_SECRET_COMPONENT_RULES, "a-future-component"])
    def test_components_that_are_not_secrets_are_not_reported(self, tmp_path: Path, rule_id: str):
        """Identifiers, hosts and unknown component rules never become findings."""
        item = _composite("creds.env", 1, AKID)
        item["ComponentSets"][0]["components"][0]["RuleID"] = rule_id

        assert InfisicalScanner(auto_install=False)._parse_components([item], tmp_path, []) == []

    def test_real_azure_and_password_reports_add_no_components(self, tmp_path: Path):
        """0.43.141's tenant ID, client ID and username components are skipped."""
        report = [_azure_service_principal("azure.env"), _generic_password("db.env")]

        assert InfisicalScanner(auto_install=False)._parse_components(report, tmp_path, []) == []

    def test_only_the_secret_member_of_a_mixed_set_is_reported(self, tmp_path: Path):
        """OVH nests its application key (an ID) and consumer key (a secret) together."""
        app_key = "k7Qp2Xz9" + "Lm4Wn8Rt"
        consumer_key = "Pa6Hn2Wq8Ze4Rt1Y" + "u9Io3Kl7Mj5Xc0Bv"
        components = [
            _component("ovh-application-key", 2, f"OVH_APPLICATION_KEY={app_key}", app_key),
            _component("ovh-consumer-key", 4, f"OVH_CONSUMER_KEY={consumer_key}", consumer_key),
        ]
        app_secret = "Vb3Mr8Sd5Fg1Jc0Y" + "eHq7Tz2Kp9Lw4Nx6"
        item = _report_item("ovh.env", "ovh-application-secret", 3, app_secret, components, "high")

        (finding,) = InfisicalScanner(auto_install=False)._parse_components([item], tmp_path, [])

        assert finding.rule_id == "infisical-ovh-consumer-key"
        assert finding.line_number == 4
        assert finding.secret_hash == hash_secret(consumer_key)
