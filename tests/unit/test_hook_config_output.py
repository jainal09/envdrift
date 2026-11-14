"""``hook --config`` prints the pre-commit snippet exactly as it is, ready to copy.

Rich wrapped the snippet at the terminal width: at 80 columns the commented
``envdrift decrypt --verify-vault`` entry broke in two, and its second half
landed on a line of its own, outside the comment. Copied into
``.pre-commit-config.yaml``, that line is invalid YAML.
"""

from __future__ import annotations

import yaml
from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.integrations.precommit import get_hook_config

runner = CliRunner()


def test_snippet_is_printed_verbatim_at_80_columns() -> None:
    result = runner.invoke(app, ["hook", "--config"], env={"COLUMNS": "80"})

    assert result.exit_code == 0, result.output
    assert get_hook_config().strip() in result.output
    snippet = result.output.split("Use --install")[0]
    assert yaml.safe_load(snippet) == yaml.safe_load(get_hook_config())
