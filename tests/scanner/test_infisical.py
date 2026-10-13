"""Tests for infisical scanner integration."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from envdrift.scanner.base import FindingSeverity
from envdrift.scanner.infisical import (
    InfisicalInstaller,
    InfisicalInstallError,
    InfisicalNotFoundError,
    InfisicalScanner,
    _get_infisical_version,
    _history_target,
    _prepare_scan_targets,
    get_infisical_path,
    get_platform_info,
)
from tests.helpers import write_checksums_for

CRITICAL = FindingSeverity.CRITICAL
HIGH = FindingSeverity.HIGH

# Every rule ID seen in real reports from Infisical CLI 0.43.135 (gitleaks engine)
# and 0.43.141 (betterleaks), over a 66-shape fixture matrix plus probes for the
# GitHub refresh token and GitLab's routable PATs, and the severity each must get
# (#844). Rows marked 0.43.141 come only from the betterleaks engine, rows
# marked 0.43.135 only from the gitleaks one. The HIGH rows pin current
# behaviour, not policy: several are CRITICAL in the native scanner, and the
# cross-scanner severity policy is tracked in #850.
EMITTED_RULE_SEVERITIES = [
    ("aws-access-token", CRITICAL),
    ("aws-secret-access-key", CRITICAL),  # 0.43.141, nested under ComponentSets
    ("azure-storage-account-key", CRITICAL),  # 0.43.141
    ("gcp-service-account", CRITICAL),  # 0.43.141
    ("github-app-token", CRITICAL),
    ("github-fine-grained-pat", CRITICAL),
    ("github-oauth", CRITICAL),
    ("github-pat", CRITICAL),
    ("github-refresh-token", CRITICAL),
    ("gitlab-pat", CRITICAL),
    ("gitlab-pat-routable", CRITICAL),
    ("gitlab-pat-routable-versioned", CRITICAL),  # 0.43.141
    ("npm-access-token", CRITICAL),
    ("private-key", CRITICAL),
    ("pypi-upload-token", CRITICAL),
    ("stripe-access-token", CRITICAL),  # live keys; test-mode keys are HIGH
    ("azure-ad-client-secret", HIGH),
    ("curl-auth-header", HIGH),
    ("datadog-access-token", HIGH),  # 0.43.135
    ("datadog-api-key", HIGH),  # 0.43.141
    ("datadog-application-key", HIGH),  # 0.43.141
    ("gcp-api-key", HIGH),
    ("generic-api-key", HIGH),
    ("generic-credential-uri", HIGH),  # 0.43.141
    ("generic-password", HIGH),  # 0.43.141
    ("hashicorp-tf-password", HIGH),
    ("heroku-api-key", HIGH),
    ("heroku-api-key-v2", HIGH),  # 0.43.141
    ("jwt", HIGH),
    ("openai-api-key", HIGH),
    ("sendgrid-api-token", HIGH),
    ("slack-bot-token", HIGH),
    ("slack-user-token", HIGH),
    ("slack-webhook-url", HIGH),
    ("twilio-api-key", HIGH),
]

# Fragmented so no full credential literal appears in source (push protection).
PLACEHOLDER_SECRET = "q8Zt3VnR7wXy2Lp9" + "Ks4Bd6Fh1Jm5Nc0Gx"
STRIPE_KEY_BODY = "4eC39HqLyjWDarjtT1zdp7dc" + "ABCDEFGH"


class TestPlatformDetection:
    """Tests for platform detection utilities."""

    def test_get_platform_info_returns_tuple(self):
        """Test that get_platform_info returns system and machine."""
        system, machine = get_platform_info()
        assert isinstance(system, str)
        assert isinstance(machine, str)
        assert system in ("Darwin", "Linux", "Windows")

    @patch("platform.system", return_value="Darwin")
    @patch("platform.machine", return_value="arm64")
    def test_get_platform_info_darwin_arm64(self, mock_machine: MagicMock, mock_system: MagicMock):
        """Test platform detection for macOS ARM."""
        system, machine = get_platform_info()
        assert system == "Darwin"
        assert machine == "arm64"

    @patch("platform.system", return_value="Linux")
    @patch("platform.machine", return_value="x86_64")
    def test_get_platform_info_linux_amd64(self, mock_machine: MagicMock, mock_system: MagicMock):
        """Test platform detection for Linux AMD64."""
        system, machine = get_platform_info()
        assert system == "Linux"
        assert machine == "x86_64"


class TestGetInfisicalPath:
    """Tests for infisical binary path detection."""

    @patch("envdrift.scanner.infisical.get_venv_bin_dir")
    @patch("platform.system", return_value="Linux")
    def test_returns_infisical_path_linux(self, mock_system: MagicMock, mock_bin_dir: MagicMock):
        """Test infisical path on Linux."""
        mock_bin_dir.return_value = Path("/venv/bin")
        path = get_infisical_path()
        assert path == Path("/venv/bin/infisical")

    @patch("envdrift.scanner.infisical.get_venv_bin_dir")
    @patch("platform.system", return_value="Windows")
    def test_returns_infisical_exe_on_windows(
        self, mock_system: MagicMock, mock_bin_dir: MagicMock
    ):
        """Test infisical path on Windows includes .exe extension."""
        mock_bin_dir.return_value = Path("/venv/Scripts")
        path = get_infisical_path()
        assert path == Path("/venv/Scripts/infisical.exe")


class TestInfisicalInstaller:
    """Tests for InfisicalInstaller class."""

    def test_default_version_from_constants(self):
        """Test that installer uses version from constants."""
        installer = InfisicalInstaller()
        assert installer.version == _get_infisical_version()

    def test_custom_version(self):
        """Test that custom version can be specified."""
        installer = InfisicalInstaller(version="0.30.0")
        assert installer.version == "0.30.0"

    def test_progress_callback(self):
        """Test that progress callback is called."""
        messages: list[str] = []
        installer = InfisicalInstaller(progress_callback=messages.append)
        installer.progress("test message")
        assert messages == ["test message"]

    @patch("envdrift.scanner.infisical.get_platform_info")
    def test_get_download_url_darwin_arm64(self, mock_platform: MagicMock):
        """Test download URL for macOS ARM."""
        mock_platform.return_value = ("Darwin", "arm64")
        installer = InfisicalInstaller(version="0.31.1")
        url = installer.get_download_url()
        assert "darwin" in url.lower()
        assert "arm64" in url.lower()
        assert "0.31.1" in url

    @patch("envdrift.scanner.infisical.get_platform_info")
    def test_get_download_url_linux_amd64(self, mock_platform: MagicMock):
        """Test download URL for Linux AMD64."""
        mock_platform.return_value = ("Linux", "x86_64")
        installer = InfisicalInstaller(version="0.31.1")
        url = installer.get_download_url()
        assert "linux" in url.lower()
        assert "amd64" in url.lower()

    @patch("envdrift.scanner.infisical.get_platform_info")
    def test_get_download_url_windows(self, mock_platform: MagicMock):
        """Test download URL for Windows."""
        mock_platform.return_value = ("Windows", "x86_64")
        installer = InfisicalInstaller(version="0.31.1")
        url = installer.get_download_url()
        assert "windows" in url.lower()
        assert ".zip" in url

    @patch("envdrift.scanner.infisical.get_platform_info")
    def test_unsupported_platform_raises_error(self, mock_platform: MagicMock):
        """Test that unsupported platform raises error."""
        mock_platform.return_value = ("FreeBSD", "x86_64")
        installer = InfisicalInstaller()
        with pytest.raises(InfisicalInstallError, match="Unsupported platform"):
            installer.get_download_url()

    def test_platform_map_completeness(self):
        """Test that all common platforms are supported."""
        expected_platforms = {
            ("Darwin", "x86_64"),
            ("Darwin", "arm64"),
            ("Linux", "x86_64"),
            ("Linux", "arm64"),
            ("Windows", "x86_64"),
        }
        assert set(InfisicalInstaller.PLATFORM_MAP.keys()) == expected_platforms


class TestInfisicalScanner:
    """Tests for InfisicalScanner class."""

    def test_scanner_name(self):
        """Test scanner name property."""
        scanner = InfisicalScanner(auto_install=False)
        assert scanner.name == "infisical"

    def test_scanner_description(self):
        """Test scanner description property."""
        scanner = InfisicalScanner(auto_install=False)
        assert "infisical" in scanner.description.lower()
        assert "140+" in scanner.description

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.infisical.get_infisical_path")
    def test_is_installed_returns_false_when_not_found(
        self, mock_path: MagicMock, mock_which: MagicMock
    ):
        """Test is_installed returns False when binary not found."""
        mock_path.return_value = Path("/nonexistent/infisical")
        scanner = InfisicalScanner(auto_install=False)
        assert scanner.is_installed() is False

    @patch("shutil.which", return_value="/usr/bin/infisical")
    def test_is_installed_returns_true_when_in_path(self, mock_which: MagicMock):
        """Test is_installed returns True when in PATH."""
        scanner = InfisicalScanner(auto_install=False)
        assert scanner.is_installed() is True

    @patch("envdrift.scanner.infisical.get_infisical_path")
    def test_is_installed_returns_true_when_in_venv(self, mock_path: MagicMock, tmp_path: Path):
        """Test is_installed returns True when in venv."""
        binary = tmp_path / "infisical"
        binary.touch()
        mock_path.return_value = binary
        scanner = InfisicalScanner(auto_install=False)
        assert scanner.is_installed() is True

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.infisical.get_infisical_path")
    def test_scan_returns_error_when_not_installed(
        self, mock_path: MagicMock, mock_which: MagicMock, tmp_path: Path
    ):
        """Test scan returns error result when infisical not installed."""
        mock_path.return_value = Path("/nonexistent/infisical")
        scanner = InfisicalScanner(auto_install=False)
        result = scanner.scan([tmp_path])
        assert result.error is not None
        assert "not found" in result.error.lower()
        assert result.success is False

    def test_scan_with_nonexistent_path(self, tmp_path: Path):
        """Test scan handles nonexistent paths gracefully."""
        scanner = InfisicalScanner(auto_install=False)
        scanner._binary_path = Path("/fake/infisical")
        with patch.object(scanner, "_find_binary", return_value=Path("/fake/infisical")):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="[]", stderr="", returncode=0)
                result = scanner.scan([tmp_path / "nonexistent"])
                assert result.success is True
                assert len(result.findings) == 0


class TestFindingParsing:
    """Tests for infisical finding parsing."""

    @pytest.fixture
    def scanner(self) -> InfisicalScanner:
        """
        Create an InfisicalScanner configured to not auto-install for use in tests.

        Returns:
            scanner (InfisicalScanner): An InfisicalScanner instance with auto_install set to False.
        """
        return InfisicalScanner(auto_install=False)

    def test_parse_basic_finding(self, scanner: InfisicalScanner, tmp_path: Path):
        """Test parsing a basic infisical finding."""
        item: dict[str, Any] = {
            "Description": "AWS Access Key ID",
            "StartLine": 10,
            "StartColumn": 5,
            "File": "secrets.py",
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "RuleID": "aws-access-key-id",
        }
        finding = scanner._parse_finding(item, tmp_path)

        assert finding is not None
        assert finding.rule_id == "infisical-aws-access-key-id"
        assert finding.rule_description == "AWS Access Key ID"
        assert finding.line_number == 10
        assert finding.column_number == 5
        assert finding.severity == FindingSeverity.CRITICAL  # aws-access-key-id maps to CRITICAL
        assert finding.scanner == "infisical"
        assert "****" in finding.secret_preview  # Redacted

    @pytest.mark.parametrize(("rule_id", "expected"), EMITTED_RULE_SEVERITIES)
    def test_emitted_rule_ids_get_their_intended_severity(
        self,
        scanner: InfisicalScanner,
        tmp_path: Path,
        rule_id: str,
        expected: FindingSeverity,
    ):
        """Grade each rule ID by the name the CLI really emits (#844).

        The map used to be keyed on ``aws-access-key-id``, ``stripe-api-key``,
        ``google-api-key`` and ``slack-token``, which neither engine emits. So
        a leaked AWS key ID or Stripe live key fell back to HIGH and got past
        ``--fail-on critical``.
        """
        item: dict[str, Any] = {
            "RuleID": rule_id,
            "Description": rule_id,
            "StartLine": 1,
            "File": "a.env",
            "Secret": PLACEHOLDER_SECRET,
        }

        finding = scanner._parse_finding(item, tmp_path)

        assert finding is not None
        assert finding.rule_id == f"infisical-{rule_id}"
        assert finding.severity == expected

    @pytest.mark.parametrize(
        ("secret", "expected"),
        [
            pytest.param("sk_live_" + STRIPE_KEY_BODY, CRITICAL, id="sk_live"),
            pytest.param("rk_live_" + STRIPE_KEY_BODY, CRITICAL, id="rk_live"),
            pytest.param("sk_prod_" + STRIPE_KEY_BODY, CRITICAL, id="sk_prod"),
            pytest.param("sk_test_" + STRIPE_KEY_BODY, HIGH, id="sk_test"),
            pytest.param("rk_test_" + STRIPE_KEY_BODY, HIGH, id="rk_test"),
        ],
    )
    def test_stripe_live_keys_critical_test_keys_high(
        self,
        scanner: InfisicalScanner,
        tmp_path: Path,
        secret: str,
        expected: FindingSeverity,
    ):
        """``stripe-access-token`` matches test-mode keys too. They cannot move
        money and the native scanner does not flag them, so they stay HIGH."""
        item: dict[str, Any] = {"RuleID": "stripe-access-token", "File": "a.env", "Secret": secret}

        finding = scanner._parse_finding(item, tmp_path)

        assert finding is not None
        assert finding.severity == expected

    @pytest.mark.parametrize(
        ("rule_id", "expected"),
        [
            ("aws-access-key-id", CRITICAL),
            ("stripe-api-key", CRITICAL),
            ("google-api-key", HIGH),
            ("slack-token", HIGH),
        ],
    )
    def test_original_rule_ids_keep_their_severity(
        self,
        scanner: InfisicalScanner,
        tmp_path: Path,
        rule_id: str,
        expected: FindingSeverity,
    ):
        """No built-in rule emits the original keys, but a custom rules config may."""
        item: dict[str, Any] = {"RuleID": rule_id, "File": "a.env", "Secret": "x" * 20}

        finding = scanner._parse_finding(item, tmp_path)

        assert finding is not None
        assert finding.severity == expected

    def test_rule_ids_are_matched_case_insensitively(
        self, scanner: InfisicalScanner, tmp_path: Path
    ):
        """A custom rules config may spell a rule ID in another case."""
        item: dict[str, Any] = {"RuleID": "AWS-Access-Token", "File": "a.env", "Secret": "x" * 20}

        finding = scanner._parse_finding(item, tmp_path)

        assert finding is not None
        assert finding.severity == CRITICAL

    def test_parse_finding_with_commit_info(self, scanner: InfisicalScanner, tmp_path: Path):
        """Test parsing a finding with git commit information."""
        item: dict[str, Any] = {
            "Description": "GitHub Token",
            "StartLine": 5,
            "File": "config.py",
            "Secret": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "RuleID": "github-pat",
            "Commit": "abc123def456",
            "Author": "developer@example.com",
            "Email": "developer@example.com",
            "Date": "2024-01-15",
            "Entropy": 4.5,
        }
        finding = scanner._parse_finding(item, tmp_path)

        assert finding is not None
        assert finding.commit_sha == "abc123def456"
        assert finding.commit_author == "developer@example.com"
        assert finding.commit_date == "2024-01-15"
        assert finding.entropy == 4.5
        assert finding.severity == FindingSeverity.CRITICAL  # github-pat maps to CRITICAL

    def test_parse_finding_with_relative_path(self, scanner: InfisicalScanner, tmp_path: Path):
        """Test parsing finding with relative file path."""
        item: dict[str, Any] = {
            "Description": "Generic Secret",
            "File": "src/config/secrets.py",
            "Secret": "secret123",
            "RuleID": "generic-api-key",
        }
        finding = scanner._parse_finding(item, tmp_path)

        assert finding is not None
        assert finding.file_path == tmp_path / "src/config/secrets.py"
        assert finding.severity == FindingSeverity.HIGH  # generic-api-key maps to HIGH

    def test_parse_finding_with_empty_file(self, scanner: InfisicalScanner, tmp_path: Path):
        """Test parsing finding with empty file field."""
        item: dict[str, Any] = {
            "Description": "Secret",
            "File": "",
            "Secret": "secret",
            "RuleID": "test",
        }
        finding = scanner._parse_finding(item, tmp_path)

        assert finding is not None
        assert finding.file_path == tmp_path

    def test_parse_finding_handles_empty_data(self, scanner: InfisicalScanner, tmp_path: Path):
        """Test that empty data creates a finding with defaults."""
        item: dict[str, Any] = {}
        finding = scanner._parse_finding(item, tmp_path)
        assert finding is not None
        assert finding.file_path == tmp_path
        assert finding.rule_id == "infisical-unknown"

    def test_parse_finding_unknown_rule_gets_high_severity(
        self, scanner: InfisicalScanner, tmp_path: Path
    ):
        """Test that unknown rules get HIGH severity by default."""
        item: dict[str, Any] = {
            "Description": "Unknown Secret Type",
            "File": "test.py",
            "RuleID": "some-unknown-rule",
        }
        finding = scanner._parse_finding(item, tmp_path)

        assert finding is not None
        assert finding.severity == FindingSeverity.HIGH


class TestInfisicalScanExecution:
    """Tests for infisical scan execution with mocked subprocess."""

    @pytest.fixture
    def mock_scanner(self, tmp_path: Path) -> InfisicalScanner:
        """
        Create an InfisicalScanner instance whose binary path points to a temporary file.

        Parameters:
            tmp_path (Path): Temporary directory in which the mock infisical binary will be created.

        Returns:
            scanner (InfisicalScanner): Scanner with its `_binary_path` set to the created mock binary file.
        """
        scanner = InfisicalScanner(auto_install=False)
        binary_path = tmp_path / "infisical"
        binary_path.touch()
        scanner._binary_path = binary_path
        return scanner

    def test_scan_parses_json_output(self, mock_scanner: InfisicalScanner, tmp_path: Path):
        """Test that scan correctly parses JSON output from report file."""
        findings_json = json.dumps(
            [
                {
                    "Description": "AWS Key",
                    "StartLine": 1,
                    "File": "test.py",
                    "Secret": "AKIAIOSFODNN7EXAMPLE",
                    "RuleID": "aws-access-key-id",
                }
            ]
        )

        def write_report_file(*args, **kwargs):
            """
            Mock subprocess replacement that writes predefined JSON to the report file specified in the command arguments.

            Searches the provided command arguments for the "--report-path" flag, writes the module-level `findings_json` content to that path, and returns a process-like mock.

            Returns:
                process (unittest.mock.MagicMock): Mock process with `stdout` set to an empty string, `stderr` set to an empty string, and `returncode` set to 0.
            """
            cmd_args = args[0]
            report_idx = cmd_args.index("--report-path")
            report_path = Path(cmd_args[report_idx + 1])
            report_path.write_text(findings_json)
            return MagicMock(stdout="", stderr="", returncode=0)

        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run", side_effect=write_report_file):
                result = mock_scanner.scan([tmp_path])

        assert result.success is True
        assert len(result.findings) == 1
        assert result.findings[0].rule_id == "infisical-aws-access-key-id"

    def test_scan_handles_empty_output(self, mock_scanner: InfisicalScanner, tmp_path: Path):
        """Test that scan handles empty report file."""
        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    stdout="",
                    stderr="",
                    returncode=0,
                )
                result = mock_scanner.scan([tmp_path])

        assert result.success is True
        assert len(result.findings) == 0

    def test_scan_handles_invalid_json(self, mock_scanner: InfisicalScanner, tmp_path: Path):
        """Test that scan handles invalid JSON in report file gracefully."""

        def write_invalid_json(*args, **kwargs):
            """Mock subprocess that writes invalid JSON to report file."""
            cmd_args = args[0]
            report_idx = cmd_args.index("--report-path")
            report_path = Path(cmd_args[report_idx + 1])
            report_path.write_text("not valid json")
            return MagicMock(stdout="", stderr="", returncode=0)

        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run", side_effect=write_invalid_json):
                result = mock_scanner.scan([tmp_path])

        assert result.success is True
        assert len(result.findings) == 0

    def test_scan_handles_timeout(self, mock_scanner: InfisicalScanner, tmp_path: Path):
        """Test that scan handles subprocess timeout."""
        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = subprocess.TimeoutExpired(cmd="infisical", timeout=300)
                result = mock_scanner.scan([tmp_path])

        assert result.success is False
        assert result.error is not None
        assert "timed out" in result.error.lower()

    def test_scan_handles_nonzero_exit_code(self, mock_scanner: InfisicalScanner, tmp_path: Path):
        """Test that scan handles non-zero exit code with error."""
        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    stdout="",
                    stderr="infisical: command failed",
                    returncode=1,
                )
                result = mock_scanner.scan([tmp_path])

        assert result.success is False
        assert result.error is not None
        assert "command failed" in result.error.lower()

    def test_scan_uses_source_flag(self, mock_scanner: InfisicalScanner, tmp_path: Path):
        """Test that scan passes --source flag with correct path."""
        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="[]", stderr="", returncode=0)
                mock_scanner.scan([tmp_path])

        # Check that --source was passed with the correct path
        call_args = mock_run.call_args[0][0]
        assert "--source" in call_args
        source_idx = call_args.index("--source")
        assert call_args[source_idx + 1] == str(tmp_path)

    @pytest.mark.parametrize("history", [True, False], ids=["history", "no-history"])
    def test_scan_passes_no_git_only_without_history(
        self, mock_scanner: InfisicalScanner, tmp_path: Path, history: bool
    ):
        """``--no-git`` is passed exactly when git history is not scanned."""
        with (
            patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path),
            patch("envdrift.scanner.infisical._history_target", return_value=(tmp_path, None)),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(stdout="[]", stderr="", returncode=0)
            mock_scanner.scan([tmp_path], include_git_history=history)

        assert ("--no-git" in mock_run.call_args[0][0]) is not history

    def test_scan_multiple_paths(self, mock_scanner: InfisicalScanner, tmp_path: Path):
        """Test scanning multiple paths."""
        path1 = tmp_path / "dir1"
        path2 = tmp_path / "dir2"
        path1.mkdir()
        path2.mkdir()

        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="[]", stderr="", returncode=0)
                result = mock_scanner.scan([path1, path2])

        assert result.success is True
        # One scan per existing path; the `scan --help` flag probe is not a scan.
        scans = [c for c in mock_run.call_args_list if "--report-path" in c.args[0]]
        assert len(scans) == 2

    @pytest.mark.parametrize(
        ("target", "expected"),
        [
            ("proj", "proj/sub/app.env"),
            ("proj/sub/app.env", "proj/sub/app.env"),
        ],
    )
    def test_relative_target_is_resolved_once(
        self,
        mock_scanner: InfisicalScanner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        target: str,
        expected: str,
    ):
        """``--source`` is relative to the directory infisical runs in (#843).

        It used to get the cwd-relative path unchanged while running inside
        that path, which resolved ``proj`` to ``proj/proj``.
        """
        secret_file = tmp_path / "proj" / "sub" / "app.env"
        secret_file.parent.mkdir(parents=True)
        secret_file.write_text("X=1\n")
        monkeypatch.chdir(tmp_path)

        def fake_infisical(args: list[str], **kwargs):
            if "--report-path" not in args:  # the `scan --help` probe
                return MagicMock(stdout="", stderr="", returncode=0)
            # Like the real binary: --source is resolved against its cwd, and
            # a finding's File is that argument joined with the path below it.
            source = Path(args[args.index("--source") + 1])
            resolved = (Path(kwargs["cwd"]) / source).resolve()
            assert resolved == (tmp_path / target).resolve(), "target resolved twice"
            file_arg = source if resolved.is_file() else source / secret_file.relative_to(resolved)
            report = Path(args[args.index("--report-path") + 1])
            report.write_text(json.dumps([{"File": str(file_arg), "RuleID": "x", "Secret": "s3"}]))
            return MagicMock(stdout="", stderr="", returncode=1)

        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run", side_effect=fake_infisical):
                result = mock_scanner.scan([Path(target)])

        assert result.error is None
        assert [f.file_path for f in result.findings] == [Path(expected)]

    def test_scan_error_is_ansi_clean(self, mock_scanner: InfisicalScanner, tmp_path: Path):
        """The binary's colored stderr must not carry escapes into --json/SARIF (#843)."""
        # Infisical 0.43.141 stderr, verbatim, for a --source it cannot stat.
        stderr = (
            "\x1b[90m2026-10-13T04:30:26Z\x1b[0m \x1b[31mFTL\x1b[0m Failed to load config "
            '\x1b[36merror=\x1b[0m\x1b[31m\x1b[1m"stat proj: no such file or directory"'
            "\x1b[0m\x1b[0m\n"
        )
        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="", stderr=stderr, returncode=1)
                result = mock_scanner.scan([tmp_path])

        assert result.error == (
            '2026-10-13T04:30:26Z FTL Failed to load config error="stat proj: no such file '
            'or directory"'
        )


def _git_repo_with_subdir(root: Path, *, commit: bool = True) -> Path:
    """Initialize a git repository at ``root`` with a ``proj/sub`` directory."""
    (root / "proj" / "sub").mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=root, capture_output=True, check=True)
    if commit:
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "initial",
            ],
            cwd=root,
            capture_output=True,
            check=True,
        )
    return root


class TestHistoryTarget:
    """History scans run on the repository root, in the caller's form (#843)."""

    def test_absolute_subdirectory_maps_to_the_repository_root(self, tmp_path: Path):
        repo = _git_repo_with_subdir(tmp_path)

        target, error = _history_target(repo / "proj")

        assert error is None
        assert target is not None
        assert target.is_absolute()
        assert target.resolve() == repo.resolve()

    @pytest.mark.parametrize(
        ("cwd", "path", "expected"),
        [
            (".", ".", "."),
            (".", "proj", "."),
            (".", "proj/sub", "."),
            ("proj/sub", ".", "../.."),
            ("proj/sub", "..", "../.."),
        ],
    )
    def test_relative_path_maps_to_a_cwd_relative_root(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        cwd: str,
        path: str,
        expected: str,
    ):
        """A relative scan path keeps reporting cwd-relative findings."""
        repo = _git_repo_with_subdir(tmp_path)
        monkeypatch.chdir(repo / cwd)

        assert _history_target(Path(path)) == (Path(expected), None)

    def test_file_maps_to_its_repository_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Infisical's git mode cannot scan a file, so its repository is scanned."""
        repo = _git_repo_with_subdir(tmp_path)
        (repo / "proj" / "sub" / "app.env").write_text("X=1\n")
        monkeypatch.chdir(repo / "proj")

        assert _history_target(Path("sub/app.env")) == (Path(".."), None)

    def test_rejects_a_directory_outside_a_repository(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
        (tmp_path / "plain").mkdir()

        target, error = _history_target(tmp_path / "plain")

        assert target is None
        assert error is not None
        assert "not inside a Git repository" in error

    def test_rejects_a_repository_without_commits(self, tmp_path: Path):
        repo = _git_repo_with_subdir(tmp_path, commit=False)

        target, error = _history_target(repo / "proj")

        assert target is None
        assert error is not None
        assert "has no commits" in error

    def test_root_without_a_relative_form_stays_absolute(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """On Windows a root on another drive than the cwd has no relative form."""
        repo = _git_repo_with_subdir(tmp_path)
        monkeypatch.chdir(repo)

        def other_drive(*_args: object) -> str:
            raise ValueError("path is on mount 'D:', start on mount 'C:'")

        with patch("envdrift.scanner.infisical.os.path.relpath", side_effect=other_drive):
            target, error = _history_target(Path("proj"))

        assert error is None
        assert target is not None
        assert target.is_absolute()
        assert target.resolve() == repo.resolve()


class TestPrepareScanTargets:
    """One Infisical run gets one ``--source`` per target (#843)."""

    def test_working_tree_targets_are_the_existing_paths(self, tmp_path: Path):
        (tmp_path / "a").mkdir()
        (tmp_path / "b.env").write_text("X=1\n")
        paths = [tmp_path / "a", tmp_path / "missing", tmp_path / "b.env"]

        targets, errors = _prepare_scan_targets(paths, include_git_history=False)

        assert targets == [tmp_path / "a", tmp_path / "b.env"]
        assert errors == []

    def test_paths_in_one_repository_share_one_history_scan(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """``guard --pr-base --history`` with N changed files scans history once."""
        repo = _git_repo_with_subdir(tmp_path)
        (repo / "proj" / "sub" / "a.env").write_text("X=1\n")
        (repo / "proj" / "b.env").write_text("X=1\n")
        (repo / "root.env").write_text("X=1\n")
        monkeypatch.chdir(repo)
        paths = [Path("proj/sub/a.env"), Path("proj/b.env"), Path("root.env"), Path("proj")]

        targets, errors = _prepare_scan_targets(paths, include_git_history=True)

        assert targets == [Path()]
        assert errors == []

    @pytest.mark.parametrize("invalid_first", [True, False], ids=["invalid-first", "valid-first"])
    def test_invalid_history_target_keeps_the_valid_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid_first: bool
    ):
        monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
        repo = _git_repo_with_subdir(tmp_path / "repo")
        plain = tmp_path / "plain"
        plain.mkdir()
        paths = [plain, repo] if invalid_first else [repo, plain]

        targets, errors = _prepare_scan_targets(paths, include_git_history=True)

        assert [target.resolve() for target in targets] == [repo.resolve()]
        assert len(errors) == 1
        assert "not inside a Git repository" in errors[0]


class TestScanFailsClosed:
    """A scan that did not run must never read as a clean one (#843)."""

    @pytest.fixture
    def scanner(self, tmp_path: Path) -> InfisicalScanner:
        scanner = InfisicalScanner(auto_install=False)
        scanner._binary_path = tmp_path / "infisical"
        scanner._binary_path.touch()
        return scanner

    # Infisical 0.43.135 in git mode on a file source: rc=1, an empty `[]`
    # report and this stderr, verbatim (NO_COLOR=1).
    _PARTIAL_SCAN = (
        "2026-10-13T05:32:16Z INF scanning for exposed secrets...\n"
        "5:32AM ERR [git] fatal: cannot change to 's.txt': Not a directory\n"
        "5:32AM ERR skipping finding links: unable to parse remote URL "
        'error="fork/exec /usr/bin/git: not a directory"\n'
        '5:32AM ERR failed to scan Git repository error="stderr is not empty"\n'
        "2026-10-13T05:32:16Z WRN partial scan completed in 10.6ms\n"
        "2026-10-13T05:32:16Z WRN no leaks found in partial scan\n"
    )

    @staticmethod
    def _fake_infisical(report: str, returncode: int, stderr: str = ""):
        def run(args: list[str], **_kwargs: Any) -> MagicMock:
            if "--report-path" in args:
                Path(args[args.index("--report-path") + 1]).write_text(report)
            return MagicMock(stdout="", stderr=stderr, returncode=returncode)

        return run

    @pytest.mark.parametrize("report", ["[]\n", "", "not json", "{}"])
    def test_nonzero_exit_without_findings_is_an_error(
        self, scanner: InfisicalScanner, tmp_path: Path, report: str
    ):
        """Infisical exits non-zero on leaks only when it reports them."""
        with patch.object(scanner, "_find_binary", return_value=scanner._binary_path):
            with patch(
                "subprocess.run", side_effect=self._fake_infisical(report, 1, self._PARTIAL_SCAN)
            ):
                result = scanner.scan([tmp_path])

        assert result.success is False
        assert result.error is not None
        assert "no leaks found in partial scan" in result.error
        assert result.findings == []

    def test_nonzero_exit_without_output_names_the_path(
        self, scanner: InfisicalScanner, tmp_path: Path
    ):
        with patch.object(scanner, "_find_binary", return_value=scanner._binary_path):
            with patch("subprocess.run", side_effect=self._fake_infisical("[]", 2)):
                result = scanner.scan([tmp_path])

        assert result.error == f"infisical scan failed for {tmp_path} (exit code 2)"

    def test_zero_exit_with_an_empty_report_is_clean(
        self, scanner: InfisicalScanner, tmp_path: Path
    ):
        with patch.object(scanner, "_find_binary", return_value=scanner._binary_path):
            with patch("subprocess.run", side_effect=self._fake_infisical("[]\n", 0)):
                result = scanner.scan([tmp_path])

        assert result.success is True
        assert result.findings == []

    def test_history_outside_a_repository_never_runs_the_binary(
        self, scanner: InfisicalScanner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
        plain = tmp_path / "plain"
        plain.mkdir()

        with patch("subprocess.run", wraps=subprocess.run) as run:
            result = scanner.scan([plain], include_git_history=True)

        assert result.success is False
        assert result.error == f"Cannot scan Git history for {plain}: not inside a Git repository"
        assert not [c for c in run.call_args_list if "--report-path" in c.args[0]]

    def test_history_error_survives_a_valid_sibling(
        self, scanner: InfisicalScanner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """The valid repository is still scanned, and the run stays incomplete."""
        monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
        _git_repo_with_subdir(tmp_path / "repo")
        plain = tmp_path / "plain"
        plain.mkdir()
        monkeypatch.chdir(tmp_path)
        report = json.dumps(
            [{"File": "proj/sub/app.env", "RuleID": "x", "Secret": "s3", "Commit": "abc123"}]
        )
        calls: list[tuple[list[str], str]] = []
        real_run = subprocess.run

        def fake(args: list[str], **kwargs: Any) -> Any:
            if args[0] == "git":  # the preflight's real git calls
                return real_run(args, **kwargs)
            if "--report-path" not in args:  # the `scan --help` probe
                return MagicMock(stdout="", stderr="", returncode=0)
            calls.append((args, kwargs["cwd"]))
            Path(args[args.index("--report-path") + 1]).write_text(report)
            return MagicMock(stdout="", stderr="", returncode=1)

        with patch.object(scanner, "_find_binary", return_value=scanner._binary_path):
            with patch("subprocess.run", side_effect=fake):
                result = scanner.scan(
                    [Path("plain"), Path("repo/proj/sub"), Path("repo")], include_git_history=True
                )

        # One history scan, of the repository root, run inside it.
        assert len(calls) == 1
        args, cwd = calls[0]
        assert args[args.index("--source") + 1] == "."
        assert "--no-git" not in args
        assert Path(cwd) == Path("repo")
        # Repo-relative ``File`` joined onto the root, relative in, relative out.
        assert [f.file_path for f in result.findings] == [Path("repo/proj/sub/app.env")]
        assert result.error == "Cannot scan Git history for plain: not inside a Git repository"

    def test_history_preflight_error_joins_a_missing_binary(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
        repo = _git_repo_with_subdir(tmp_path / "repo")
        plain = tmp_path / "plain"
        plain.mkdir()
        scanner = InfisicalScanner(auto_install=False)

        with patch.object(scanner, "_find_binary", side_effect=InfisicalNotFoundError("gone")):
            result = scanner.scan([plain, repo], include_git_history=True)

        assert result.error == (
            f"gone; Cannot scan Git history for {plain}: not inside a Git repository"
        )


class TestInfisicalAutoInstall:
    """Tests for infisical auto-installation."""

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.infisical.get_infisical_path")
    @patch.object(InfisicalInstaller, "install")
    def test_auto_install_when_not_found(
        self,
        mock_install: MagicMock,
        mock_path: MagicMock,
        mock_which: MagicMock,
        tmp_path: Path,
    ):
        """Test that scanner auto-installs when binary not found."""
        mock_path.return_value = Path("/nonexistent/infisical")
        installed_path = tmp_path / "infisical"
        installed_path.touch()
        mock_install.return_value = installed_path

        scanner = InfisicalScanner(auto_install=True)
        binary = scanner._find_binary()

        assert binary == installed_path
        mock_install.assert_called_once()

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.infisical.get_infisical_path")
    @patch.object(InfisicalInstaller, "install")
    def test_auto_install_failure_raises_error(
        self,
        mock_install: MagicMock,
        mock_path: MagicMock,
        mock_which: MagicMock,
    ):
        """Test that auto-install failure raises appropriate error."""
        mock_path.return_value = Path("/nonexistent/infisical")
        mock_install.side_effect = InfisicalInstallError("Download failed")

        scanner = InfisicalScanner(auto_install=True)
        with pytest.raises(InfisicalNotFoundError, match="auto-install failed"):
            scanner._find_binary()


class TestExceptionClasses:
    """Tests for exception classes."""

    def test_infisical_not_found_error(self):
        """Test InfisicalNotFoundError."""
        error = InfisicalNotFoundError("Binary not found")
        assert str(error) == "Binary not found"
        assert isinstance(error, Exception)

    def test_infisical_install_error(self):
        """Test InfisicalInstallError."""
        error = InfisicalInstallError("Download failed")
        assert str(error) == "Download failed"
        assert isinstance(error, Exception)


class TestInfisicalInstallerDownload:
    """Tests for InfisicalInstaller download functionality."""

    @patch("envdrift.scanner.platform_utils.platform.system", return_value="Darwin")
    @patch("envdrift.scanner.platform_utils.platform.machine", return_value="arm64")
    def test_get_download_url_darwin_arm64(self, mock_machine: MagicMock, mock_system: MagicMock):
        """Test download URL generation for macOS ARM64."""
        installer = InfisicalInstaller()
        url = installer.get_download_url()
        assert "darwin" in url.lower()
        assert "arm64" in url.lower()
        assert installer.version in url

    @patch("envdrift.scanner.platform_utils.platform.system", return_value="Linux")
    @patch("envdrift.scanner.platform_utils.platform.machine", return_value="x86_64")
    def test_get_download_url_linux_x64(self, mock_machine: MagicMock, mock_system: MagicMock):
        """Test download URL generation for Linux x86_64."""
        installer = InfisicalInstaller()
        url = installer.get_download_url()
        assert "linux" in url.lower()

    @patch("envdrift.scanner.platform_utils.platform.system", return_value="Windows")
    @patch("envdrift.scanner.platform_utils.platform.machine", return_value="AMD64")
    def test_get_download_url_windows(self, mock_machine: MagicMock, mock_system: MagicMock):
        """Test download URL generation for Windows."""
        installer = InfisicalInstaller()
        url = installer.get_download_url()
        assert "windows" in url.lower()
        assert url.endswith(".zip")

    @patch("envdrift.scanner.platform_utils.platform.system", return_value="FreeBSD")
    @patch("envdrift.scanner.platform_utils.platform.machine", return_value="x86_64")
    def test_get_download_url_unsupported_platform(
        self, mock_machine: MagicMock, mock_system: MagicMock
    ):
        """Test download URL raises error for unsupported platform."""
        installer = InfisicalInstaller()
        with pytest.raises(InfisicalInstallError, match="Unsupported platform"):
            installer.get_download_url()

    def test_installer_with_custom_version(self):
        """Test installer with custom version."""
        installer = InfisicalInstaller(version="0.30.0")
        assert installer.version == "0.30.0"

    def test_installer_with_progress_callback(self):
        """Test installer with progress callback."""
        messages: list[str] = []
        installer = InfisicalInstaller(progress_callback=messages.append)
        installer.progress("Test message")
        assert "Test message" in messages


class TestInfisicalInstallerExtraction:
    """Tests for InfisicalInstaller extraction methods."""

    def test_extract_tar_gz(self, tmp_path: Path):
        """Test tar.gz extraction."""
        import io
        import tarfile

        archive_path = tmp_path / "test.tar.gz"
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()

        test_file_content = b"test content"
        with tarfile.open(archive_path, "w:gz") as tar:
            info = tarfile.TarInfo(name="testfile.txt")
            info.size = len(test_file_content)
            tar.addfile(info, io.BytesIO(test_file_content))

        installer = InfisicalInstaller()
        installer._extract_tar_gz(archive_path, extract_dir)

        assert (extract_dir / "testfile.txt").exists()
        assert (extract_dir / "testfile.txt").read_bytes() == test_file_content

    def test_extract_zip(self, tmp_path: Path):
        """Test zip extraction."""
        import zipfile

        archive_path = tmp_path / "test.zip"
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()

        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("testfile.txt", "test content")

        installer = InfisicalInstaller()
        installer._extract_zip(archive_path, extract_dir)

        assert (extract_dir / "testfile.txt").exists()
        assert (extract_dir / "testfile.txt").read_text() == "test content"

    def test_extract_tar_gz_path_traversal_blocked(self, tmp_path: Path):
        """Test that path traversal attacks are blocked in tar.gz."""
        import io
        import tarfile

        archive_path = tmp_path / "malicious.tar.gz"
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()

        with tarfile.open(archive_path, "w:gz") as tar:
            info = tarfile.TarInfo(name="../../../etc/passwd")
            info.size = 4
            tar.addfile(info, io.BytesIO(b"test"))

        installer = InfisicalInstaller()
        with pytest.raises(InfisicalInstallError, match="Unsafe path"):
            installer._extract_tar_gz(archive_path, extract_dir)

    def test_extract_zip_path_traversal_blocked(self, tmp_path: Path):
        """Test that path traversal attacks are blocked in zip."""
        import zipfile

        archive_path = tmp_path / "malicious.zip"
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()

        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("../../../etc/passwd", "test")

        installer = InfisicalInstaller()
        with pytest.raises(InfisicalInstallError, match="Unsafe path"):
            installer._extract_zip(archive_path, extract_dir)


class TestInfisicalInstallerInstall:
    """Tests for InfisicalInstaller.install method."""

    @patch("envdrift.scanner.infisical.get_infisical_path")
    @patch("envdrift.scanner.infisical.download_file")
    @patch("envdrift.scanner.platform_utils.platform.system", return_value="Linux")
    @patch("envdrift.scanner.platform_utils.platform.machine", return_value="x86_64")
    def test_install_success(
        self,
        mock_machine: MagicMock,
        mock_system: MagicMock,
        mock_download_file: MagicMock,
        mock_get_path: MagicMock,
        tmp_path: Path,
    ):
        """Test successful installation."""
        import io
        import tarfile

        target_path = tmp_path / "bin" / "infisical"
        target_path.parent.mkdir(parents=True, exist_ok=True)
        mock_get_path.return_value = target_path

        checksums_path = tmp_path / "stub-checksums.txt"

        def fake_download(url: str, dest: Path, **_kwargs) -> None:
            with tarfile.open(dest, "w:gz") as tar:
                info = tarfile.TarInfo(name="infisical")
                info.size = 4
                tar.addfile(info, io.BytesIO(b"fake"))
            write_checksums_for(Path(dest), checksums_path, url.rsplit("/", 1)[-1])

        mock_download_file.side_effect = fake_download

        installer = InfisicalInstaller()
        with patch.object(
            InfisicalInstaller,
            "get_checksums_url",
            lambda self: checksums_path.resolve().as_uri(),
        ):
            result = installer.install()

        assert result == target_path
        assert target_path.exists()

    @patch("envdrift.scanner.infisical.get_infisical_path")
    @patch("envdrift.scanner.infisical.download_file")
    @patch("envdrift.scanner.platform_utils.platform.system", return_value="Linux")
    @patch("envdrift.scanner.platform_utils.platform.machine", return_value="x86_64")
    def test_install_download_failure(
        self,
        mock_machine: MagicMock,
        mock_system: MagicMock,
        mock_download_file: MagicMock,
        mock_get_path: MagicMock,
        tmp_path: Path,
    ):
        """Test installation failure on download error."""
        mock_get_path.return_value = tmp_path / "infisical"
        mock_download_file.side_effect = Exception("Network error")

        installer = InfisicalInstaller()
        with pytest.raises(InfisicalInstallError, match="Download failed"):
            installer.install()

    @patch("envdrift.scanner.infisical.get_infisical_path")
    @patch("envdrift.scanner.infisical.download_file")
    @patch("envdrift.scanner.platform_utils.platform.system", return_value="Linux")
    @patch("envdrift.scanner.platform_utils.platform.machine", return_value="x86_64")
    def test_install_binary_not_found_in_archive(
        self,
        mock_machine: MagicMock,
        mock_system: MagicMock,
        mock_download_file: MagicMock,
        mock_get_path: MagicMock,
        tmp_path: Path,
    ):
        """Test installation failure when binary not found in archive."""
        import io
        import tarfile

        mock_get_path.return_value = tmp_path / "infisical"
        checksums_path = tmp_path / "stub-checksums.txt"

        def fake_download(url: str, dest: Path, **_kwargs) -> None:
            with tarfile.open(dest, "w:gz") as tar:
                info = tarfile.TarInfo(name="other_file.txt")
                info.size = 4
                tar.addfile(info, io.BytesIO(b"test"))
            write_checksums_for(Path(dest), checksums_path, url.rsplit("/", 1)[-1])

        mock_download_file.side_effect = fake_download

        installer = InfisicalInstaller()
        with (
            patch.object(
                InfisicalInstaller,
                "get_checksums_url",
                lambda self: checksums_path.resolve().as_uri(),
            ),
            pytest.raises(InfisicalInstallError, match="not found in archive"),
        ):
            installer.install()


# Real-binary tests: integration lane only, skip-gated on the binary (#497)
@pytest.mark.integration
@pytest.mark.skipif(
    not InfisicalScanner(auto_install=False).is_installed(),
    reason="infisical not installed",
)
class TestInfisicalIntegration:
    """Integration tests that require infisical to be installed."""

    def test_scan_clean_directory(self, tmp_path: Path):
        """Test scanning a directory with no secrets."""
        # Create a clean file
        (tmp_path / "clean.py").write_text("# No secrets here\nx = 1 + 1\n")

        scanner = InfisicalScanner(auto_install=False)
        result = scanner.scan([tmp_path])

        assert result.success is True
