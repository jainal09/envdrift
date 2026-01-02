"""Tests for envdrift.output.rich module."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from envdrift.core.diff import DiffResult, DiffType, VarDiff
from envdrift.core.encryption import EncryptionReport
from envdrift.core.schema import FieldMetadata, SchemaMetadata
from envdrift.core.validator import ValidationResult
from envdrift.output.rich import (
    console,
    print_diff_result,
    print_encryption_report,
    print_error,
    print_mismatch_warning,
    print_service_sync_status,
    print_success,
    print_sync_result,
    print_sync_summary,
    print_validation_result,
    print_warning,
)
from envdrift.sync.result import DecryptionTestResult, SyncAction


class TestPrintFunctions:
    """Tests for print utility functions."""

    def test_print_success(self):
        """Test print_success outputs green OK."""
        with patch.object(console, "print") as mock_print:
            print_success("Operation completed")
            mock_print.assert_called_once()
            call_args = str(mock_print.call_args)
            assert "OK" in call_args or "Operation completed" in call_args

    def test_print_error(self):
        """Test print_error outputs red ERROR."""
        with patch.object(console, "print") as mock_print:
            print_error("Something failed")
            mock_print.assert_called_once()
            call_args = str(mock_print.call_args)
            assert "ERROR" in call_args or "Something failed" in call_args

    def test_print_warning(self):
        """Test print_warning outputs yellow WARN."""
        with patch.object(console, "print") as mock_print:
            print_warning("Something suspicious")
            mock_print.assert_called_once()
            call_args = str(mock_print.call_args)
            assert "WARN" in call_args or "Something suspicious" in call_args


class TestConsole:
    """Tests for console object."""

    def test_console_exists(self):
        """Test console is a Console instance."""
        from rich.console import Console

        assert isinstance(console, Console)


class TestValidationOutput:
    """Tests for validation rendering."""

    def test_print_validation_result_failure_verbose(self):
        """Render validation failures with verbose sections."""

        schema = SchemaMetadata(
            class_name="Settings",
            module_path="app.config",
            fields={
                "REQ": FieldMetadata(
                    name="REQ",
                    required=True,
                    sensitive=False,
                    default=None,
                    description="Required field",
                    field_type=str,
                    annotation="str",
                ),
                "OPT": FieldMetadata(
                    name="OPT",
                    required=False,
                    sensitive=False,
                    default="x",
                    description=None,
                    field_type=str,
                    annotation="str",
                ),
                "SECRET": FieldMetadata(
                    name="SECRET",
                    required=True,
                    sensitive=True,
                    default=None,
                    description=None,
                    field_type=str,
                    annotation="str",
                ),
            },
            extra_policy="forbid",
        )

        result = ValidationResult(
            valid=False,
            missing_required={"REQ"},
            missing_optional={"OPT"},
            extra_vars={"EXTRA"},
            unencrypted_secrets={"SECRET"},
            type_errors={"REQ": "bad type"},
            warnings=["warn"],
        )

        with patch.object(console, "print") as mock_print:
            print_validation_result(result, Path(".env"), schema, verbose=True)

        joined = " ".join(" ".join(map(str, call.args)) for call in mock_print.call_args_list)
        assert "MISSING REQUIRED" in joined
        assert "EXTRA" in joined
        assert "PLAINTEXT" in joined or "encrypted" in joined.lower()
        assert "TYPE ERRORS" in joined
        assert "Summary" in joined


class TestDiffOutput:
    """Tests for diff rendering."""

    def test_print_diff_result_no_drift(self):
        """No drift path."""
        result = DiffResult(env1_path=Path("a.env"), env2_path=Path("b.env"), differences=[])
        with patch.object(console, "print") as mock_print:
            print_diff_result(result)
        joined = " ".join(" ".join(map(str, c.args)) for c in mock_print.call_args_list)
        assert "No drift" in joined

    def test_print_diff_result_with_drift(self):
        """Table rendering with drift and sensitive flag."""
        diffs = [
            VarDiff(
                name="NEW", diff_type=DiffType.ADDED, value1=None, value2="v", is_sensitive=False
            ),
            VarDiff(
                name="SECRET",
                diff_type=DiffType.CHANGED,
                value1="old",
                value2="new",
                is_sensitive=True,
            ),
        ]
        result = DiffResult(env1_path=Path("a.env"), env2_path=Path("b.env"), differences=diffs)

        with patch.object(console, "print") as mock_print:
            print_diff_result(result, show_unchanged=False)

        joined = " ".join(" ".join(map(str, c.args)) for c in mock_print.call_args_list)
        assert "Summary" in joined
        assert "Drift detected" in joined or "drift" in joined.lower()


class TestEncryptionOutput:
    """Tests for encryption report rendering."""

    def test_print_encryption_report_plaintext(self):
        """Render plaintext secrets path."""
        report = EncryptionReport(
            path=Path(".env"),
            is_fully_encrypted=False,
            encrypted_vars=set(),
            plaintext_vars={"A"},
            empty_vars=set(),
            plaintext_secrets={"SECRET"},
            warnings=["warn"],
        )

        with patch.object(console, "print") as mock_print:
            print_encryption_report(report)

        joined = " ".join(" ".join(map(str, c.args)) for c in mock_print.call_args_list)
        assert "PLAINTEXT" in joined
        assert "envdrift encrypt" in joined

    def test_print_encryption_report_sops_recommendation(self):
        """Render SOPS-specific recommendation."""
        report = EncryptionReport(
            path=Path(".env"),
            is_fully_encrypted=False,
            encrypted_vars=set(),
            plaintext_vars={"A"},
            empty_vars=set(),
            plaintext_secrets={"SECRET"},
            warnings=[],
            detected_backend="sops",
        )

        with patch.object(console, "print") as mock_print:
            print_encryption_report(report)

        joined = " ".join(" ".join(map(str, c.args)) for c in mock_print.call_args_list)
        assert "--backend sops" in joined


class TestSyncOutput:
    """Tests for sync output helpers."""

    def test_print_sync_summary(self):
        """Cover success and error branches."""
        with patch.object(console, "print") as mock_print:
            print_sync_summary(services_processed=2, created=1, updated=0, skipped=1, errors=0)
        assert any("All services" in " ".join(map(str, c.args)) for c in mock_print.call_args_list)

        with patch.object(console, "print") as mock_print:
            print_sync_summary(services_processed=1, created=0, updated=0, skipped=0, errors=1)
        assert any(
            "failed" in " ".join(map(str, c.args)).lower() for c in mock_print.call_args_list
        )

    def test_print_service_sync_status(self):
        """Render service sync details."""
        result = SimpleNamespace(
            action=SyncAction.UPDATED,
            folder_path="service",
            error="boom",
            local_value_preview="abc",
            vault_value_preview="def",
            backup_path="relative/backup",
            decryption_result=DecryptionTestResult.FAILED,
            schema_valid=False,
        )
        with patch.object(console, "print") as mock_print:
            print_service_sync_status(result)
        joined = " ".join(str(c.args[0]) for c in mock_print.call_args_list)
        assert "updated" in joined or "~" in joined
        assert "Error" in joined
        assert "Decryption" in joined
        assert "Schema" in joined

    def test_print_sync_result(self):
        """Render aggregate sync result with decryption stats."""
        sync_result = SimpleNamespace(
            total_processed=3,
            created_count=1,
            updated_count=1,
            skipped_count=1,
            error_count=1,
            has_errors=True,
            decryption_tested=2,
            decryption_passed=1,
            decryption_failed=1,
        )
        with patch.object(console, "print") as mock_print:
            print_sync_result(sync_result)
        joined = " ".join(" ".join(map(str, c.args)) for c in mock_print.call_args_list)
        assert "errors" in joined.lower()
        assert "Sync completed with errors" in joined

    def test_print_mismatch_warning(self):
        """Mismatch warning helper."""
        with patch.object(console, "print") as mock_print:
            print_mismatch_warning("svc", "local", "vault")
        joined = " ".join(" ".join(map(str, c.args)) for c in mock_print.call_args_list)
        assert "VALUE MISMATCH" in joined
