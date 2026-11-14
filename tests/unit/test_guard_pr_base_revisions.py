"""``guard --pr-base`` with a revision that holds ``[``, ``*`` or ``?``.

The progress line interpolated the revision into Rich markup, so a valid
revision such as ``HEAD^{/[/x]}`` (the newest commit whose message matches
``[/x]``) raised ``MarkupError``: a traceback and exit 1, the code for a
critical finding. And ``git diff <base>...HEAD`` without ``--`` takes a base
holding glob characters that is not a revision for a path pattern: the diff
"succeeded" empty, so guard reported "No changed files" and exited 0 on a base
it never resolved. Both run against a real git repository.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.scanner.base import EXIT_OPERATIONAL_ERROR

runner = CliRunner()


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=envdrift", "-c", "user.email=envdrift@example.invalid", *args],
        cwd=repo,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Two commits: a base whose message holds ``[/x]``, then one changed file."""
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "commit", "-q", "--allow-empty", "-m", "base [/x]")
    (tmp_path / "notes.txt").write_text("nothing secret here\n", encoding="utf-8")
    _git(tmp_path, "add", "notes.txt")
    _git(tmp_path, "commit", "-q", "-m", "second")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_bracketed_revision_is_printed_in_the_progress_line(repo: Path) -> None:
    result = runner.invoke(
        app, ["guard", "--native-only", "--pr-base", "HEAD^{/[/x]}"], env={"COLUMNS": "200"}
    )

    assert result.exit_code == 0, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "Scanning 1 file(s) changed since HEAD^{/[/x]}..." in result.output
    assert "No secrets or policy violations detected" in result.output


@pytest.mark.parametrize("base", ["nope[/x]", "release/*", "v?"])
@pytest.mark.parametrize("machine", [False, True], ids=["human", "json"])
def test_a_base_git_would_read_as_a_path_pattern_fails_closed(
    repo: Path, base: str, machine: bool
) -> None:
    result = runner.invoke(
        app,
        ["guard", "--native-only", "--pr-base", base, *(["--json"] if machine else [])],
        env={"COLUMNS": "200"},
    )

    assert result.exit_code == EXIT_OPERATIONAL_ERROR, result.output
    expected = f"--pr-base '{base}' could not be diffed against"
    if machine:
        assert expected in json.loads(result.stdout)["error"]
    else:
        assert expected in " ".join(result.stderr.split())
        assert "No changed files" not in result.output
