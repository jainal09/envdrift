"""Tests for envdrift.output.rich module."""

from __future__ import annotations

import io
from pathlib import Path
from types import SimpleNamespace
from typing import cast
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
from envdrift.sync.result import DecryptionTestResult, ServiceSyncResult, SyncAction, SyncResult


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

    def test_print_error_preserves_bracketed_toml_section(self):
        """Bracketed TOML table names survive print_error (#413).

        Rendering to a real (non-mocked) Console proves the message is escaped
        before Rich interprets markup: a literal ``[vault.sync]`` must NOT be
        swallowed as a console style tag.
        """
        from rich.console import Console

        from envdrift.output import rich as rich_module

        buf = io.StringIO()
        capture = Console(file=buf, force_terminal=False, no_color=True, width=200)
        with patch.object(rich_module, "console", capture):
            rich_module.print_error("Expected [vault.sync] section with [[vault.sync.mappings]]")
        output = buf.getvalue()
        assert "[vault.sync]" in output
        assert "[[vault.sync.mappings]]" in output

    def test_print_warning_preserves_bracketed_toml_section(self):
        """Bracketed TOML table names survive print_warning (#413)."""
        from rich.console import Console

        from envdrift.output import rich as rich_module

        buf = io.StringIO()
        capture = Console(file=buf, force_terminal=False, no_color=True, width=200)
        with patch.object(rich_module, "console", capture):
            rich_module.print_warning("Add a [tool.envdrift.vault.sync] block")
        assert "[tool.envdrift.vault.sync]" in buf.getvalue()


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
            secret_name="svc-secret",
            folder_path="service",
            environment="production",
            error="boom",
            local_value_preview="abc",
            vault_value_preview="def",
            backup_path="relative/backup",
            decryption_result=DecryptionTestResult.FAILED,
            schema_valid=False,
        )
        with patch.object(console, "print") as mock_print:
            print_service_sync_status(cast(ServiceSyncResult, result))
        joined = " ".join(str(c.args[0]) for c in mock_print.call_args_list)
        assert "updated" in joined or "~" in joined
        assert "Error" in joined
        assert "Decryption" in joined
        assert "Schema" in joined

    def test_service_sync_status_does_not_leak_secret_prefix(self):
        """Rendered mismatch must flag the diff WITHOUT printing the secret (or
        any long prefix of it). Drives the real renderer + real redaction
        pipeline used by the sync engine."""
        from envdrift.sync.operations import redact_value

        def _fake_secret(seed: str) -> str:
            # 64-hex, shaped like a DOTENV_PRIVATE_KEY_* value; built by concat
            # so the literal never appears as one token in source.
            return (seed * 64)[:64]

        local_secret = _fake_secret("ab")  # 'abab...ab'
        vault_secret = _fake_secret("cd")  # 'cdcd...cd' (different value)
        assert local_secret != vault_secret and len(local_secret) == 64

        result = SimpleNamespace(
            action=SyncAction.UPDATED,
            secret_name="svc-secret",
            folder_path="svc",
            environment="production",
            error=None,
            # exercise the same path the engine uses:
            local_value_preview=redact_value(local_secret),
            vault_value_preview=redact_value(vault_secret),
            backup_path=None,
            decryption_result=None,
            schema_valid=None,
        )

        with patch.object(console, "print") as mock_print:
            print_service_sync_status(cast(ServiceSyncResult, result))
        rendered = "\n".join(str(c.args[0]) for c in mock_print.call_args_list)

        # 1) the full secret never appears
        assert local_secret not in rendered
        assert vault_secret not in rendered
        # 2) no long prefix leaks (any >=8-char run of either secret)
        for secret in (local_secret, vault_secret):
            for i in range(len(secret) - 7):
                assert secret[i : i + 8] not in rendered, f"leaked 8-char window of {secret[:4]}..."
        # 3) but the renderer STILL signals a mismatch
        assert "Local" in rendered and "Vault" in rendered

    def test_print_sync_result(self):
        """Render aggregate sync result with decryption stats."""
        sync_result = SimpleNamespace(
            total_processed=3,
            created_count=1,
            updated_count=1,
            skipped_count=1,
            ephemeral_count=0,
            error_count=1,
            has_errors=True,
            decryption_tested=2,
            decryption_passed=1,
            decryption_failed=1,
        )
        with patch.object(console, "print") as mock_print:
            print_sync_result(cast(SyncResult, sync_result))
        joined = " ".join(" ".join(map(str, c.args)) for c in mock_print.call_args_list)
        assert "errors" in joined.lower()
        assert "Sync completed with errors" in joined

    def test_print_mismatch_warning(self):
        """Mismatch warning helper."""
        with patch.object(console, "print") as mock_print:
            print_mismatch_warning("svc", "local", "vault")
        joined = " ".join(" ".join(map(str, c.args)) for c in mock_print.call_args_list)
        assert "VALUE MISMATCH" in joined


class TestSyncStatusErrorAndEphemeralRendering:
    """#487: truthful per-service rows — reasons rendered, ephemeral != error."""

    def test_error_row_without_error_field_falls_back_to_message(self):
        """An ERROR row whose only explanation lives in ``message`` prints it (#487)."""
        result = ServiceSyncResult(
            secret_name="svc-secret",
            folder_path=Path("svc"),
            action=SyncAction.ERROR,
            message="Key file does not exist: svc/.env.keys",
        )
        with console.capture() as capture:
            print_service_sync_status(result)
        out = " ".join(capture.get().split())
        assert "Key file does not exist: svc/.env.keys" in out, out

    def test_ephemeral_row_renders_ephemeral_not_error(self):
        """A successful ephemeral sync must not render as a red error row (#487)."""
        result = ServiceSyncResult(
            secret_name="svc-secret",
            folder_path=Path("svc"),
            action=SyncAction.EPHEMERAL,
            message="Ephemeral mode: key fetched from vault (not stored locally)",
        )
        with console.capture() as capture:
            print_service_sync_status(result)
        out = " ".join(capture.get().split())
        assert "ephemeral" in out.lower(), out
        assert "error" not in out.lower(), out

    def test_sync_result_summary_surfaces_ephemeral_count(self):
        """The summary panel reports ephemeral services instead of hiding them (#487)."""
        sync_result = SyncResult(
            services=[
                ServiceSyncResult(
                    secret_name="svc-secret",
                    folder_path=Path("svc"),
                    action=SyncAction.EPHEMERAL,
                    message="Ephemeral mode: key fetched from vault (not stored locally)",
                ),
            ],
        )
        with console.capture() as capture:
            print_sync_result(sync_result)
        out = " ".join(capture.get().split())
        assert "Ephemeral: 1" in out, out
        assert "Errors: 0" in out, out
        assert "All services synced successfully" in out, out

    def test_sync_result_summary_omits_ephemeral_line_when_none(self):
        """No ephemeral services -> the summary stays unchanged (#487)."""
        sync_result = SyncResult(
            services=[
                ServiceSyncResult(
                    secret_name="svc-secret",
                    folder_path=Path("svc"),
                    action=SyncAction.SKIPPED,
                    message="Values match - no update needed",
                ),
            ],
        )
        with console.capture() as capture:
            print_sync_result(sync_result)
        out = " ".join(capture.get().split())
        assert "Ephemeral" not in out, out


class TestSyncStatusRowIdentity:
    """#441: rows identify the mapping, not just the folder."""

    def test_rows_sharing_a_folder_are_distinguishable(self):
        """Two mappings with the same folder_path render distinct rows (#441).

        Pre-#441 both rendered an identical "= svc - skipped", so a user could
        not tell which mapping (secret/environment) each row referred to.
        """
        results = [
            ServiceSyncResult(
                secret_name="test/svc-production",
                folder_path=Path("svc"),
                action=SyncAction.SKIPPED,
                message="No .env.production file found - skipping",
                environment="production",
            ),
            ServiceSyncResult(
                secret_name="test/svc-staging",
                folder_path=Path("svc"),
                action=SyncAction.SKIPPED,
                message="No .env.staging file found - skipping",
                environment="staging",
            ),
        ]
        rows = []
        for result in results:
            with console.capture() as capture:
                print_service_sync_status(result)
            rows.append(" ".join(capture.get().split()))

        assert rows[0] != rows[1], rows
        assert "test/svc-production" in rows[0] and "env: production" in rows[0], rows[0]
        assert "test/svc-staging" in rows[1] and "env: staging" in rows[1], rows[1]

    def test_row_without_environment_still_names_the_secret(self):
        """A result missing the optional environment still renders its secret."""
        result = ServiceSyncResult(
            secret_name="svc-secret",
            folder_path=Path("svc"),
            action=SyncAction.SKIPPED,
            message="Values match - no update needed",
        )
        with console.capture() as capture:
            print_service_sync_status(result)
        out = " ".join(capture.get().split())
        assert "svc-secret" in out, out
        assert "env:" not in out, out
