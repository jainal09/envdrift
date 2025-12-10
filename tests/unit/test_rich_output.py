"""Tests for envdrift.output.rich module."""

from __future__ import annotations

from unittest.mock import patch

from envdrift.output.rich import (
    console,
    print_error,
    print_success,
    print_warning,
)


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
