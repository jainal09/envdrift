"""A scanner that fails must say so, never report a clean scan (#872, #873, #874).

Each case here used to pass for a clean scan, or for a failed one with a blank error: an
exception with an empty message (#872), a report read in the platform's encoding instead of
UTF-8 (#873), and a report that cannot be parsed (#874).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from envdrift.scanner.base import ScannerBackend, ScanResult, exception_message
from envdrift.scanner.detect_secrets import DetectSecretsScanner
from envdrift.scanner.engine import GuardConfig, ScanEngine
from envdrift.scanner.git_secrets import GitSecretsScanner
from envdrift.scanner.gitleaks import GitleaksScanner
from envdrift.scanner.infisical import InfisicalScanner
from envdrift.scanner.kingfisher import KingfisherScanner
from envdrift.scanner.talisman import TalismanScanner
from envdrift.scanner.trivy import TrivyScanner
from envdrift.scanner.trufflehog import TrufflehogScanner

# A secret the reports below name, built so the literal never appears whole in the source.
SECRET = "ghp_" + "0123456789abcdefghij" + "ABCDEFGHIJKLMNOP"
# UTF-8 bytes D0 81: 0x81 has no character in cp1252, so a cp1252 read fails outright.
NON_ASCII_NAME = "Ё.env"


def _with_binary(scanner_cls: type[Any], tmp_path: Path) -> tuple[Any, Path]:
    scanner = scanner_cls(auto_install=False)
    binary = tmp_path / "bin" / scanner_cls.__name__
    binary.parent.mkdir(exist_ok=True)
    binary.touch()
    scanner._binary_path = binary
    return scanner, binary


def _scan(scanner: Any, binary: Path, paths: list[Path], run: Any) -> ScanResult:
    with (
        patch.object(scanner, "_find_binary", return_value=binary),
        patch("subprocess.run", side_effect=run),
    ):
        return scanner.scan(paths)


def _directories(tmp_path: Path, *names: str) -> list[Path]:
    directories = [tmp_path / name for name in names]
    for directory in directories:
        directory.mkdir()
    return directories


def _report_writer(option: str, content: bytes, returncode: int = 0) -> Any:
    """A ``subprocess.run`` that writes ``content`` to the path after ``option``."""

    def run(args: list[str], **_kwargs: Any) -> MagicMock:
        if option in args:
            Path(args[args.index(option) + 1]).write_bytes(content)
        return MagicMock(returncode=returncode, stdout="", stderr="")

    return run


def _talisman_report_writer(content: bytes, returncode: int = 0) -> Any:
    """A ``subprocess.run`` that writes ``content`` where Talisman 1.37 writes its report."""

    def run(args: list[str], **_kwargs: Any) -> MagicMock:
        report = Path(args[args.index("--reportDirectory") + 1])
        report = report / "talisman_reports" / "data" / "report.json"
        report.parent.mkdir(parents=True)
        report.write_bytes(content)
        return MagicMock(returncode=returncode, stdout="", stderr="")

    return run


@pytest.fixture
def cp1252_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``Path.read_text`` decode as Windows does before Python 3.15: cp1252 by default."""
    read_text = Path.read_text

    def read_text_cp1252(self: Path, encoding: str | None = None, *args: Any, **kwargs: Any) -> str:
        return read_text(self, encoding or "cp1252", *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_text_cp1252)


# --- #872: an exception without a message ---------------------------------------------


@pytest.mark.parametrize(
    ("error", "message"),
    [(RuntimeError(), "RuntimeError"), (MemoryError(), "MemoryError"), (OSError("gone"), "gone")],
)
def test_exception_message_names_an_exception_without_a_message(
    error: BaseException, message: str
) -> None:
    assert exception_message(error) == message


@pytest.mark.parametrize(
    "scanner_cls",
    [
        GitleaksScanner,
        InfisicalScanner,
        KingfisherScanner,
        TalismanScanner,
        TrivyScanner,
        TrufflehogScanner,
        GitSecretsScanner,
    ],
    ids=lambda cls: cls.__name__,
)
def test_an_exception_without_a_message_fails_the_scan(
    scanner_cls: type[Any], tmp_path: Path
) -> None:
    """gitleaks, Infisical and git-secrets passed this for clean; the others had no error text.

    The scan stops at the first path, so the second one is never scanned.
    """
    scanner, binary = _with_binary(scanner_cls, tmp_path)

    result = _scan(scanner, binary, _directories(tmp_path, "first", "second"), RuntimeError())

    assert result.success is False
    assert "RuntimeError" in (result.error or "")


def test_detect_secrets_exception_without_a_message_fails_the_scan(tmp_path: Path) -> None:
    scanner = DetectSecretsScanner(auto_install=False)

    with (
        patch.object(scanner, "_ensure_installed", return_value=True),
        patch("envdrift.scanner.detect_secrets._version_warnings", return_value=[]),
        patch("subprocess.run", side_effect=RuntimeError()),
    ):
        result = scanner.scan([tmp_path])

    assert result.success is False
    assert result.error == "RuntimeError"


def test_engine_names_a_scanner_that_raises_an_exception_without_a_message(
    tmp_path: Path,
) -> None:
    class Raising(ScannerBackend):
        name = "raising"
        description = "raises an exception without a message"

        def is_installed(self) -> bool:
            return True

        def scan(self, paths: list[Path], include_git_history: bool = False) -> ScanResult:
            raise RuntimeError()

    engine = ScanEngine(GuardConfig(use_native=False, use_gitleaks=False))
    engine.scanners = [Raising()]

    result = engine.scan([tmp_path])

    assert [r.error for r in result.results] == ["RuntimeError"]
    assert result.has_errors


def test_git_secrets_reports_a_path_it_could_not_scan_and_scans_the_others(
    tmp_path: Path,
) -> None:
    """git-secrets logged the exception at debug level and reported a clean scan."""
    scanner, binary = _with_binary(GitSecretsScanner, tmp_path)
    first, second = _directories(tmp_path, "first", "second")
    finding = MagicMock(returncode=1, stdout="", stderr=f"app.env:1:TOKEN={SECRET}\n")
    calls = iter([OSError("permission denied"), finding])

    def run(*_args: Any, **_kwargs: Any) -> MagicMock:
        outcome = next(calls)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    result = _scan(scanner, binary, [first, second], run)

    assert result.error == f"git-secrets could not scan {first}: permission denied"
    assert [f.file_path for f in result.findings] == [second / "app.env"]


@pytest.mark.parametrize(
    ("returncode", "stderr", "error"),
    [
        (
            # What git-secrets does when git cannot read its config: no patterns, no matches.
            0,
            "fatal: bad config line 15 in file .git/config\n" * 3,
            "git-secrets could not scan {path}: fatal: bad config line 15 in file .git/config",
        ),
        (
            128,
            "fatal: bad config line 15 in file .git/config\n",
            "git-secrets could not scan {path}: fatal: bad config line 15 in file .git/config",
        ),
        (
            129,
            "error: unknown option `bogus'\nusage: git secrets --scan [-r|--recursive]\n",
            "git-secrets could not scan {path}: error: unknown option `bogus'",
        ),
        (2, "", "git-secrets could not scan {path}: exit code 2"),
    ],
    ids=["git-config-unreadable", "git-fails", "unknown-option", "no-message"],
)
def test_git_secrets_failure_fails_the_scan(
    returncode: int, stderr: str, error: str, tmp_path: Path
) -> None:
    """A git-secrets run that failed read as a clean scan, whatever it exited with."""
    scanner, binary = _with_binary(GitSecretsScanner, tmp_path)
    (target,) = _directories(tmp_path, "project")
    run = [MagicMock(returncode=returncode, stdout="", stderr=stderr)]

    result = _scan(scanner, binary, [target], run)

    assert result.error == error.format(path=target)


def test_git_secrets_match_that_cannot_be_parsed_fails_the_scan(tmp_path: Path) -> None:
    """An exit of 1 means git-secrets matched; with no match parsed, the findings are unknown.

    The matched line is left out of the error: it holds the secret.
    """
    scanner, binary = _with_binary(GitSecretsScanner, tmp_path)
    (target,) = _directories(tmp_path, "project")
    stderr = f"TOKEN={SECRET}\n\n[ERROR] Matched one or more prohibited patterns\n"
    run = [MagicMock(returncode=1, stdout="", stderr=stderr)]

    result = _scan(scanner, binary, [target], run)

    assert result.error == f"git-secrets reported a match in {target} that envdrift cannot parse"


@pytest.mark.parametrize("returncode", [1, 2])
def test_git_secrets_never_quotes_a_matched_line(returncode: int, tmp_path: Path) -> None:
    """A matched line is no error message, even from a file named like one of git's."""
    scanner, binary = _with_binary(GitSecretsScanner, tmp_path)
    (target,) = _directories(tmp_path, "project")
    stderr = f"fatal: x.env:3:TOKEN={SECRET}\n\n[ERROR] Matched one or more prohibited patterns\n"
    run = [MagicMock(returncode=returncode, stdout="", stderr=stderr)]

    result = _scan(scanner, binary, [target], run)

    assert SECRET not in (result.error or "")
    if returncode == 1:
        assert result.error is None
        assert [f.line_number for f in result.findings] == [3]
    else:
        assert result.error == (
            f"git-secrets could not scan {target}: [ERROR] Matched one or more prohibited patterns"
        )


def test_git_secrets_timeout_keeps_the_errors_of_the_paths_before_it(tmp_path: Path) -> None:
    scanner, binary = _with_binary(GitSecretsScanner, tmp_path)
    first, second = _directories(tmp_path, "first", "second")
    outcomes = iter([OSError("permission denied"), subprocess.TimeoutExpired("git-secrets", 300)])

    def run(*_args: Any, **_kwargs: Any) -> MagicMock:
        raise next(outcomes)

    result = _scan(scanner, binary, [first, second], run)

    assert result.error == (
        f"git-secrets could not scan {first}: permission denied; Scan timed out for {second}"
    )


# --- #873: a report written in UTF-8 ------------------------------------------------


def test_gitleaks_reads_its_report_as_utf8(tmp_path: Path, cp1252_platform: None) -> None:
    scanner, binary = _with_binary(GitleaksScanner, tmp_path)
    (target,) = _directories(tmp_path, "project")
    report = [{"RuleID": "github-pat", "File": str(target / NON_ASCII_NAME), "Secret": SECRET}]
    content = json.dumps(report, ensure_ascii=False).encode()

    result = _scan(scanner, binary, [target], _report_writer("--report-path", content))

    assert result.error is None
    assert [f.file_path.name for f in result.findings] == [NON_ASCII_NAME]


def test_infisical_reads_its_report_as_utf8(tmp_path: Path, cp1252_platform: None) -> None:
    scanner, binary = _with_binary(InfisicalScanner, tmp_path)
    (target,) = _directories(tmp_path, "project")
    report = [{"RuleID": "github-pat", "File": str(target / NON_ASCII_NAME), "Secret": SECRET}]
    content = json.dumps(report, ensure_ascii=False).encode()

    # Infisical exits 1 when it reports leaks.
    result = _scan(scanner, binary, [target], _report_writer("--report-path", content, 1))

    assert result.error is None
    assert [f.file_path.name for f in result.findings] == [NON_ASCII_NAME]


def test_kingfisher_reads_its_report_as_utf8(tmp_path: Path, cp1252_platform: None) -> None:
    scanner, binary = _with_binary(KingfisherScanner, tmp_path)
    (target,) = _directories(tmp_path, "project")
    finding = {"path": str(target / NON_ASCII_NAME), "snippet": SECRET, "line": 1}
    report = {"findings": [{"rule": {"id": "github.pat", "name": "GitHub"}, "finding": finding}]}
    content = json.dumps(report, ensure_ascii=False).encode()

    # Kingfisher exits 200 when it reports findings.
    result = _scan(scanner, binary, [target], _report_writer("-o", content, 200))

    assert result.error is None
    assert [f.file_path.name for f in result.findings] == [NON_ASCII_NAME]


def test_talisman_reads_its_report_as_utf8(tmp_path: Path, cp1252_platform: None) -> None:
    scanner, binary = _with_binary(TalismanScanner, tmp_path)
    (target,) = _directories(tmp_path, "project")
    failure = {"type": "filecontent", "message": "Potential secret pattern", "severity": "high"}
    report = {"results": [{"filename": NON_ASCII_NAME, "failures": [failure]}]}
    content = json.dumps(report, ensure_ascii=False).encode()

    # Talisman exits 1 when it reports something.
    result = _scan(scanner, binary, [target], _talisman_report_writer(content, 1))

    assert result.error is None
    assert [f.file_path.name for f in result.findings] == [NON_ASCII_NAME]


# --- #874: a report that cannot be parsed ---------------------------------------------

# A report cut short (a full disk, a killed process), and a message where the report
# should be. Neither says what was found.
UNPARSABLE = [b'[{"RuleID": "github-pat", "File": "app.env", "Sec', b"error: out of memory\n"]


@pytest.mark.parametrize("content", UNPARSABLE, ids=["cut-short", "message"])
@pytest.mark.parametrize(
    ("scanner_cls", "option"),
    [
        (GitleaksScanner, "--report-path"),
        (InfisicalScanner, "--report-path"),
        (KingfisherScanner, "-o"),
    ],
    ids=["gitleaks", "infisical", "kingfisher"],
)
def test_a_report_that_cannot_be_parsed_fails_the_scan(
    scanner_cls: type[Any], option: str, content: bytes, tmp_path: Path
) -> None:
    scanner, binary = _with_binary(scanner_cls, tmp_path)
    (target,) = _directories(tmp_path, "project")

    result = _scan(scanner, binary, [target], _report_writer(option, content))

    assert result.success is False
    assert f"wrote a report for {target} that envdrift cannot parse" in (result.error or "")
    # The report is left out of the error: one cut short holds the secrets it found.
    assert "Sec" not in (result.error or "")


@pytest.mark.parametrize(
    ("scanner_cls", "option", "content"),
    [
        (GitleaksScanner, "--report-path", b'{"RuleID": "github-pat"}'),
        (InfisicalScanner, "--report-path", b'"no findings"'),
        (KingfisherScanner, "-o", b'[{"findings": []}]'),
        (KingfisherScanner, "-o", b'{"findings": {"rule": "github"}}'),
        (KingfisherScanner, "-o", b'{"findings": {}}'),
        (KingfisherScanner, "-o", b'{"findings": false}'),
    ],
    ids=[
        "gitleaks-object",
        "infisical-string",
        "kingfisher-list",
        "kingfisher-findings-object",
        "kingfisher-findings-empty-object",
        "kingfisher-findings-false",
    ],
)
def test_a_report_of_the_wrong_shape_fails_the_scan(
    scanner_cls: type[Any], option: str, content: bytes, tmp_path: Path
) -> None:
    scanner, binary = _with_binary(scanner_cls, tmp_path)
    (target,) = _directories(tmp_path, "project")

    result = _scan(scanner, binary, [target], _report_writer(option, content))

    assert result.success is False
    assert "cannot parse" in (result.error or "")


def _printing(stdout: str) -> Any:
    """A ``subprocess.run`` for a tool that prints its report."""
    return lambda *_args, **_kwargs: MagicMock(returncode=0, stdout=stdout, stderr="")


# Each report holds one finding with a field of the wrong type, as a new release of a tool
# could write it, so the scanner's parser fails on it. The finding used to be skipped, and the
# report read as clean.
MALFORMED_FINDING = {
    "gitleaks": (
        GitleaksScanner,
        _report_writer("--report-path", b'[{"RuleID": "github-pat", "File": 123}]'),
    ),
    "infisical": (
        InfisicalScanner,
        _report_writer("--report-path", b'[{"RuleID": "github-pat", "File": 123}]'),
    ),
    "kingfisher": (
        KingfisherScanner,
        _report_writer("-o", b'{"findings": [{"rule": {"id": "github"}, "finding": {"path": 1}}]}'),
    ),
    "talisman": (
        TalismanScanner,
        _talisman_report_writer(b'{"results": [{"filename": "a.env", "failure_list": ["oops"]}]}'),
    ),
    "trivy": (
        TrivyScanner,
        _printing('{"Results": [{"Target": 123, "Secrets": [{"RuleID": "github-pat"}]}]}'),
    ),
    "trufflehog": (
        TrufflehogScanner,
        _printing('{"SourceMetadata": {"Data": {"Filesystem": {"file": 123}}}, "Raw": "x"}'),
    ),
}


@pytest.mark.parametrize(
    ("scanner_cls", "run"), MALFORMED_FINDING.values(), ids=list(MALFORMED_FINDING)
)
def test_a_finding_that_cannot_be_parsed_fails_the_scan(
    scanner_cls: type[Any], run: Any, tmp_path: Path
) -> None:
    scanner, binary = _with_binary(scanner_cls, tmp_path)
    (target,) = _directories(tmp_path, "project")

    result = _scan(scanner, binary, [target], run)

    error = result.error or ""
    assert error.endswith(f" for {target} that envdrift cannot parse")
    assert error.split(" ")[0].lower() == scanner.name


@pytest.mark.parametrize("line", ["42", '"scanning"', "null", '[{"Raw": "x"}]'])
def test_trufflehog_json_that_is_not_a_finding_fails_the_scan(line: str, tmp_path: Path) -> None:
    """Every finding trufflehog prints is a JSON object; other JSON leaves them unknown."""
    scanner, binary = _with_binary(TrufflehogScanner, tmp_path)
    (target,) = _directories(tmp_path, "project")

    result = _scan(scanner, binary, [target], _printing(line))

    assert result.error == f"trufflehog printed a finding for {target} that envdrift cannot parse"


@pytest.mark.parametrize(
    ("scanner_cls", "option", "content"),
    [
        (GitleaksScanner, "--report-path", b"[]\n"),
        (GitleaksScanner, "--report-path", b"null\n"),
        (GitleaksScanner, "--report-path", b""),
        (InfisicalScanner, "--report-path", b"[]\n"),
        (InfisicalScanner, "--report-path", b"null\n"),
        (KingfisherScanner, "-o", b'{"findings": []}'),
        (KingfisherScanner, "-o", b"{}"),
        (KingfisherScanner, "-o", b""),
    ],
)
def test_a_report_that_holds_no_findings_is_a_clean_scan(
    scanner_cls: type[Any], option: str, content: bytes, tmp_path: Path
) -> None:
    """What the binaries write when they find nothing still reads as a clean scan."""
    scanner, binary = _with_binary(scanner_cls, tmp_path)
    (target,) = _directories(tmp_path, "project")

    result = _scan(scanner, binary, [target], _report_writer(option, content))

    assert result.error is None
    assert result.findings == []


def test_infisical_failure_wins_over_its_unparsable_report(tmp_path: Path) -> None:
    """A run that failed says why, rather than that its report cannot be parsed."""
    scanner, binary = _with_binary(InfisicalScanner, tmp_path)
    (target,) = _directories(tmp_path, "project")

    def run(args: list[str], **_kwargs: Any) -> MagicMock:
        if "--report-path" in args:
            Path(args[args.index("--report-path") + 1]).write_bytes(UNPARSABLE[0])
        return MagicMock(returncode=2, stdout="", stderr="cannot open the source")

    result = _scan(scanner, binary, [target], run)

    assert result.error == "cannot open the source"


@pytest.mark.parametrize("content", UNPARSABLE, ids=["cut-short", "message"])
def test_talisman_report_that_cannot_be_parsed_fails_the_scan(
    content: bytes, tmp_path: Path
) -> None:
    scanner, binary = _with_binary(TalismanScanner, tmp_path)
    (target,) = _directories(tmp_path, "project")

    result = _scan(scanner, binary, [target], _talisman_report_writer(content))

    assert result.error == f"talisman wrote a report for {target} that envdrift cannot parse"


@pytest.mark.parametrize(
    "content",
    [b"null", b'{"results": {}}', b'{"results": false}'],
    ids=["not-an-object", "results-empty-object", "results-false"],
)
def test_talisman_report_of_the_wrong_shape_fails_the_scan(content: bytes, tmp_path: Path) -> None:
    scanner, binary = _with_binary(TalismanScanner, tmp_path)
    (target,) = _directories(tmp_path, "project")

    result = _scan(scanner, binary, [target], _talisman_report_writer(content))

    assert result.error == f"talisman wrote a report for {target} that envdrift cannot parse"


def test_talisman_clean_report_is_a_clean_scan(tmp_path: Path) -> None:
    """Talisman 1.37 writes this report, and exits 0, when it finds nothing."""
    scanner, binary = _with_binary(TalismanScanner, tmp_path)
    (target,) = _directories(tmp_path, "project")
    clean = b'{"summary":{"types":{"filecontent":0,"filesize":0,"filename":0}},"results":[]}'

    result = _scan(scanner, binary, [target], _talisman_report_writer(clean))

    assert result.error is None
    assert result.findings == []


@pytest.mark.parametrize(
    "stdout",
    [
        '{"SchemaVersion": 2, "Resu',
        "FATAL: no space left on device",
        '{"SchemaVersion": 2, "Results": {}}',
        '{"SchemaVersion": 2, "Results": false}',
    ],
    ids=["cut-short", "message", "results-empty-object", "results-false"],
)
def test_trivy_output_that_is_not_a_report_fails_the_scan(stdout: str, tmp_path: Path) -> None:
    scanner, binary = _with_binary(TrivyScanner, tmp_path)
    (target,) = _directories(tmp_path, "project")

    result = _scan(scanner, binary, [target], [MagicMock(returncode=0, stdout=stdout, stderr="")])

    assert result.error == f"trivy printed a report for {target} that envdrift cannot parse"


# What trivy prints for a directory with no secrets: a report with no ``Results``.
TRIVY_CLEAN = '{"SchemaVersion": 2, "ArtifactName": "project", "ArtifactType": "filesystem"}'


@pytest.mark.parametrize("stdout", [TRIVY_CLEAN, "", "\n"], ids=["no-results", "empty", "blank"])
def test_trivy_output_that_reports_nothing_is_a_clean_scan(stdout: str, tmp_path: Path) -> None:
    scanner, binary = _with_binary(TrivyScanner, tmp_path)
    (target,) = _directories(tmp_path, "project")

    result = _scan(scanner, binary, [target], [MagicMock(returncode=0, stdout=stdout, stderr="")])

    assert result.error is None
    assert result.findings == []


def test_trivy_failure_with_output_that_is_not_a_report_says_why_without_the_output(
    tmp_path: Path,
) -> None:
    scanner, binary = _with_binary(TrivyScanner, tmp_path)
    (target,) = _directories(tmp_path, "project")
    stdout = '{"Results": [{"Secrets": [{"Match": "TOKEN=' + SECRET
    run = [MagicMock(returncode=1, stdout=stdout, stderr="FATAL: scan error\n")]

    result = _scan(scanner, binary, [target], run)

    assert result.error == (
        f"trivy printed a report for {target} that envdrift cannot parse (exit code 1): "
        "FATAL: scan error"
    )


def test_trufflehog_finding_cut_short_fails_the_scan(tmp_path: Path) -> None:
    """A line that starts as a finding but does not parse leaves the findings unknown.

    The findings that parse are still reported, and progress lines are still skipped.
    """
    scanner, binary = _with_binary(TrufflehogScanner, tmp_path)
    (target,) = _directories(tmp_path, "project")
    whole = {
        "SourceMetadata": {"Data": {"Filesystem": {"file": str(target / "a.env")}}},
        "DetectorName": "Github",
        "Raw": SECRET,
    }
    stdout = "\n".join(["scanning...", json.dumps(whole), '{"SourceMetadata": {"Data": {"Fil'])
    run = [MagicMock(returncode=0, stdout=stdout, stderr="")]

    result = _scan(scanner, binary, [target], run)

    assert result.error == f"trufflehog printed a finding for {target} that envdrift cannot parse"
    assert [f.file_path.name for f in result.findings] == ["a.env"]


def test_trufflehog_failure_never_puts_its_findings_in_the_error(tmp_path: Path) -> None:
    """The findings on stdout hold the raw secrets, so a failed run's error leaves them out."""
    scanner, binary = _with_binary(TrufflehogScanner, tmp_path)
    (target,) = _directories(tmp_path, "project")
    finding = {"SourceMetadata": {"Data": {"Filesystem": {"file": "a.env"}}}, "Raw": SECRET}
    run = [MagicMock(returncode=1, stdout=json.dumps(finding), stderr="")]

    result = _scan(scanner, binary, [target], run)

    assert result.error == f"trufflehog scan failed for {target} (exit code 1)"
    assert SECRET not in (result.error or "")


def test_a_scan_that_runs_out_of_time_is_still_reported_as_such(tmp_path: Path) -> None:
    """The handlers above do not swallow a timeout into a parse error."""
    scanner, binary = _with_binary(TrivyScanner, tmp_path)
    (target,) = _directories(tmp_path, "project")

    result = _scan(scanner, binary, [target], subprocess.TimeoutExpired("trivy", 300))

    assert result.error == f"Scan timed out for {target}"
