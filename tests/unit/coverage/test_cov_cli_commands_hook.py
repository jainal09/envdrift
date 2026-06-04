"""Coverage-focused tests for envdrift.cli_commands.hook.

Targets the ``except ImportError`` branch (lines 72-75) that fires when the
pre-commit integration cannot be imported during ``hook --install``.
"""

from __future__ import annotations

import builtins

from typer.testing import CliRunner

from envdrift.cli import app

runner = CliRunner()


def test_hook_install_import_error_exits_with_error(monkeypatch):
    """When the precommit integration import fails, hook --install must exit 1.

    Exercises lines 72-75: the ImportError handler prints an error, the manual
    fallback hint, and raises ``typer.Exit(code=1)``.
    """
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "envdrift.integrations.precommit":
            raise ImportError("simulated missing precommit integration")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    result = runner.invoke(app, ["hook", "--install"])

    assert result.exit_code == 1
    assert "not available" in result.output.lower()
    assert ".pre-commit-config.yaml" in result.output


def test_hook_install_import_error_does_not_print_success(monkeypatch):
    """The success message must not appear when the integration is unavailable."""
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "envdrift.integrations.precommit":
            raise ImportError("simulated missing precommit integration")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    result = runner.invoke(app, ["hook", "--install"])

    assert "installed" not in result.output.lower()
    assert "manually" in result.output.lower()
