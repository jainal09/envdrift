"""A tool a scanner runs is killed at the scanner's time limit, not left running (#900)."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

import envdrift
from envdrift.scanner import engine as engine_module
from envdrift.scanner.base import ScannerBackend, ScanResult, scanner_deadline, tool_timeout
from envdrift.scanner.engine import GuardConfig, ScanEngine

# A tool that never ends. It rewrites its heartbeat file, which holds its pid, every 50 ms, so a
# test on any platform can tell whether it still runs, even after the process that started it
# has exited.
HEARTBEAT = """
import os, sys, time
from pathlib import Path

beat = Path(sys.argv[1])
while True:
    beat.write_text(f"{os.getpid()} {time.monotonic()}")
    time.sleep(0.05)
"""

# The engine limit for these tests: long enough for the tool to start and beat.
LIMIT_SECONDS = 1.5


class HungTool(ScannerBackend):
    """Runs a tool that never ends with a timeout of 300 s, as the real scanners do."""

    def __init__(self, beat: Path) -> None:
        self.beat = beat

    @property
    def name(self) -> str:
        return "hung-tool"

    @property
    def description(self) -> str:
        return "runs a tool that never ends"

    def is_installed(self) -> bool:
        return True

    def scan(self, paths: list[Path], include_git_history: bool = False) -> ScanResult:
        try:
            subprocess.run(  # nosec B603
                [sys.executable, "-c", HEARTBEAT, str(self.beat)],
                capture_output=True,
                timeout=tool_timeout(300),
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ScanResult(scanner_name=self.name, error="the tool timed out")
        return ScanResult(scanner_name=self.name)


def _still_beating(beat: Path) -> bool:
    """Whether the tool writing ``beat`` still runs, given a few seconds to stop."""
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        before = beat.read_text() if beat.exists() else ""
        time.sleep(0.5)
        if (beat.read_text() if beat.exists() else "") == before:
            return False
    return True


def _stop(beat: Path) -> None:
    """Kill the tool if it still runs, so a failing test leaves nothing behind."""
    try:
        pid = int(beat.read_text().split()[0])
        os.kill(pid, signal.SIGTERM)
    except (OSError, ValueError, IndexError):
        pass


def test_tool_timeout_is_the_scanners_time_left(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])

    assert tool_timeout(300) == 300  # outside a scan, nothing caps it
    with scanner_deadline(1600.0):
        assert tool_timeout(300) == 300
        assert tool_timeout(900) == 600
        clock[0] = 1599.5
        assert tool_timeout(300) == 0.5
        clock[0] = 1700.0
        assert tool_timeout(300) == 0  # past the limit: a tool started now is killed at once
    assert tool_timeout(300) == 300


def test_a_timed_out_scanners_tool_is_killed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The engine stops waiting for the scanner at its limit, and its tool dies with it.

    The tool used to run until its own timeout of 300 s, long after the scan was over.
    """
    monkeypatch.setattr(engine_module, "_SCANNER_TIMEOUT_SECONDS", LIMIT_SECONDS)
    monkeypatch.setattr(engine_module, "_POLL_SECONDS", 0.05)
    beat = tmp_path / "beat"
    engine = ScanEngine(GuardConfig(use_native=False, use_gitleaks=False))
    engine.scanners = [HungTool(beat)]

    try:
        result = engine.scan([tmp_path])

        assert beat.exists(), "the tool never started"
        assert not _still_beating(beat), "the tool still runs after its scanner timed out"
    finally:
        _stop(beat)

    assert [r.scanner_name for r in result.results] == ["hung-tool"]
    assert result.results[0].error is not None


# The run above in a process of its own, which then exits, as guard does.
GUARD_EXITS = """
import sys
from pathlib import Path

import envdrift.scanner.engine as engine_module
from tests.scanner.test_tool_deadline import LIMIT_SECONDS, HungTool

engine_module._SCANNER_TIMEOUT_SECONDS = LIMIT_SECONDS
engine = engine_module.ScanEngine(engine_module.GuardConfig(use_native=False, use_gitleaks=False))
engine.scanners = [HungTool(Path(sys.argv[1]))]
result = engine.scan([Path(".")])
print("EXIT CODE", result.exit_code, flush=True)
"""


def test_a_timed_out_scanners_tool_does_not_outlive_guard(tmp_path: Path) -> None:
    """The issue as reported: after guard exits, the tool of a scanner that timed out is gone."""
    beat = tmp_path / "beat"
    package = str(Path(envdrift.__file__).resolve().parents[1])
    repo = str(Path(__file__).resolve().parents[2])  # for ``tests.scanner`` in the child
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([package, repo])}

    try:
        result = subprocess.run(  # nosec B603
            [sys.executable, "-c", GUARD_EXITS, str(beat)],
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
            check=False,
        )

        assert result.returncode == 0, result.stderr
        assert "EXIT CODE 5" in result.stdout, result.stdout
        assert beat.exists(), "the tool never started"
        assert not _still_beating(beat), "the tool still runs after guard exited"
    finally:
        _stop(beat)
