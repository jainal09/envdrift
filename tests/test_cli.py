"""Tests for CLI commands."""

from typer.testing import CliRunner

from envdrift.cli import app

runner = CliRunner()


def test_version() -> None:
    """Test version command."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "0.0.1" in result.stdout


def test_validate_coming_soon() -> None:
    """Test validate command shows coming soon message."""
    result = runner.invoke(app, ["validate"])
    assert result.exit_code == 0
    assert "Coming soon" in result.stdout


def test_diff_coming_soon() -> None:
    """Test diff command shows coming soon message."""
    result = runner.invoke(app, ["diff", ".env.dev", ".env.prod"])
    assert result.exit_code == 0
    assert "Coming soon" in result.stdout


def test_init_coming_soon() -> None:
    """Test init command shows coming soon message."""
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0
    assert "Coming soon" in result.stdout


def test_hook_without_install() -> None:
    """Test hook command without --install flag."""
    result = runner.invoke(app, ["hook"])
    assert result.exit_code == 0
    assert "--install" in result.stdout
