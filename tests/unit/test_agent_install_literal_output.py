"""agent and install print project paths, registry paths and errors as they are.

Their messages interpolated paths into Rich markup. ``agent register
'proj[/x]'`` raised ``MarkupError`` after the project was registered, ``agent
list`` dropped ``[bold]`` from a path, and ``install agent`` crashed while
drawing its spinner once a download error quoted such a path: the spinner's
column parsed each description as markup and emoji codes. The column prints
them literally, and a failed download's description stays red.
"""

from __future__ import annotations

import http.server
import io
import json
import shutil
import threading
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

import envdrift.agent.registry as registry_module
from envdrift.cli import app
from envdrift.cli_commands.install import (
    _DescriptionColumn,
    _download_binary,
    _download_progress,
)

runner = CliRunner()


@pytest.fixture
def registry_at(monkeypatch: pytest.MonkeyPatch):
    """Point the agent registry singleton at a given file for one test."""

    def use(path: Path) -> Path:
        monkeypatch.setattr(registry_module, "_registry", registry_module.ProjectRegistry(path))
        return path

    yield use
    registry_module._registry = None


def _invoke(*args: str):
    return runner.invoke(app, list(args), env={"COLUMNS": "250"})


def _flat(text: str) -> str:
    return " ".join(text.split())


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "proj[" / "x]"
    project.mkdir(parents=True)
    return project


def test_register_and_unregister_name_the_project_as_written(tmp_path: Path, registry_at):
    registry_at(tmp_path / "registry" / "projects.json")
    project = _project(tmp_path)

    registered = _invoke("agent", "register", str(project), "--no-auto-enable")
    again = _invoke("agent", "register", str(project), "--no-auto-enable")
    unregistered = _invoke("agent", "unregister", str(project))

    assert registered.exit_code == 0, registered.output
    assert f"✓ Registered project: {project.resolve()}" in _flat(registered.output)
    assert again.exit_code == 0, again.output
    assert f"⚠ Project already registered: {project.resolve()}" in _flat(again.output)
    assert unregistered.exit_code == 0, unregistered.output
    assert f"✓ Unregistered project: {project.resolve()}" in _flat(unregistered.output)


def test_list_and_status_show_paths_as_written(tmp_path: Path, registry_at):
    registry = registry_at(tmp_path / "reg[/x]" / "projects.json")
    project = tmp_path / "proj[bold]"
    project.mkdir()
    assert _invoke("agent", "register", str(project), "--no-auto-enable").exit_code == 0

    listed = _invoke("agent", "list")
    status = _invoke("agent", "status")

    assert listed.exit_code == 0, listed.output
    assert str(project.resolve()) in listed.output
    assert f"Registry: {registry}" in _flat(listed.output)
    assert status.exit_code == 0, status.output
    assert f"• {project.resolve()}" in _flat(status.output)
    assert f"Registry: {registry}" in _flat(status.output)


def test_corrupt_registry_notice_names_the_file_as_written(tmp_path: Path, registry_at):
    path = tmp_path / "reg[/x]" / "projects.json"
    path.parent.mkdir(parents=True)
    path.write_text("{not json [/x]", encoding="utf-8")
    registry_at(path)

    result = _invoke("agent", "list")

    assert result.exit_code == 0, result.output
    out = _flat(result.output)
    assert f"⚠ Registry file was corrupt: {path}" in out
    assert "(invalid JSON:" in out


def test_install_check_names_the_registry_as_written(
    tmp_path: Path, registry_at, monkeypatch: pytest.MonkeyPatch
):
    path = registry_at(tmp_path / "reg[/x]" / "projects.json")
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"projects": []}), encoding="utf-8")
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))

    result = _invoke("install", "check")

    assert result.exit_code == 0, result.output
    assert f"✓ Registry at: {path}" in _flat(result.output)


def test_install_agent_reports_a_download_error_naming_a_bracketed_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The spinner parsed the failure description, which quotes the missing path."""
    install_path = tmp_path / "bin" / "envdrift-agent"
    install_path.parent.mkdir()
    release = tmp_path / "rel[" / "x]"
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    monkeypatch.setattr("envdrift.cli_commands.install._detect_platform", lambda: "linux-amd64")
    monkeypatch.setattr("envdrift.cli_commands.install._get_install_path", lambda: install_path)
    monkeypatch.setattr(
        "envdrift.cli_commands.install._resolve_agent_release_url",
        lambda: (release.as_uri(), release.as_uri() + "/checksums.txt"),
    )

    result = _invoke("install", "agent", "--skip-autostart", "--skip-register")

    assert result.exit_code == 1, result.output
    assert isinstance(result.exception, SystemExit), repr(result.exception)
    out = _flat(result.output)
    assert "Network Error:" in out
    assert "x]" in out and "rel[" in out
    assert "Failed to download agent binary" in out
    assert not install_path.exists()


@pytest.fixture
def not_found_url(monkeypatch: pytest.MonkeyPatch):
    """A local HTTP server that answers every request with 404."""

    class NotFound(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_error(404)

        def log_message(self, format: str, *args: object) -> None:
            pass

    for name in ("http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), NotFound)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/envdrift-agent"
    server.shutdown()
    server.server_close()


@pytest.mark.parametrize("failure", ["http", "network", "filesystem"])
def test_install_agent_describes_a_failed_download_literally_and_in_red(
    tmp_path: Path, not_found_url: str, failure: str
):
    """The spinner printed a failure description in red until it printed them literally."""
    release = tmp_path / "rel[" / "x]" / "envdrift-agent"
    dest = tmp_path / "bin" / "envdrift-agent"
    dest.parent.mkdir()
    if failure == "http":
        url, expected = not_found_url, "Download failed: HTTP 404"
    elif failure == "network":
        url, expected = release.as_uri(), "Download failed: "
    else:
        release.parent.mkdir(parents=True)
        release.write_bytes(b"agent")
        url, expected = release.as_uri(), "Installation failed: "
        dest = tmp_path / "missing[" / "x]" / "envdrift-agent"
    progress = _download_progress()

    assert _download_binary(url, dest, progress) is False

    [task] = progress.tasks
    column = progress.columns[-1]
    assert isinstance(column, _DescriptionColumn)
    description = column.render(task)
    assert description.plain.startswith(expected), description.plain
    if failure != "http":
        assert "x]" in description.plain and "[" in description.plain, description.plain
    rendered = io.StringIO()
    Console(file=rendered, force_terminal=True, color_system="standard", width=500).print(
        description
    )
    assert rendered.getvalue().startswith("\x1b[31m" + expected), repr(rendered.getvalue())


def test_install_agent_names_the_destination_when_the_error_names_no_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    """A failed install says where the binary was going when the error does not.

    ``shutil.move`` copies when it cannot rename, and on Windows the copy
    (``CopyFile2``) raises an error that names no file: ``[WinError 3] The system
    cannot find the path specified`` did not say which path was missing. The
    error is raised here in that shape, since Linux and macOS never raise it; the
    Windows CI legs run the real one in the ``filesystem`` case above.
    """
    release = tmp_path / "envdrift-agent"
    release.write_bytes(b"agent")
    dest = tmp_path / "missing[" / "x]" / "envdrift-agent"

    def copy_error(src: str, dst: str) -> None:
        raise FileNotFoundError(2, "The system cannot find the path specified")

    monkeypatch.setattr(shutil, "move", copy_error)
    progress = _download_progress()

    assert _download_binary(release.as_uri(), dest, progress) is False

    reason = f"[Errno 2] The system cannot find the path specified (installing to {dest})"
    [task] = progress.tasks
    column = progress.columns[-1]
    assert isinstance(column, _DescriptionColumn)
    assert column.render(task).plain == f"Installation failed: {reason}"
    # The console wraps the long temp path mid-word, so whitespace is dropped.
    printed = "".join(capsys.readouterr().out.split())
    assert "".join(f"File System Error: {reason}".split()) in printed
