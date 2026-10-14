"""A scanner that never returns must not hold the run past its timeout (#870)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

import envdrift

# A scanner that blocks forever, as a native open() on a named pipe did (#863). The engine's
# clock jumps 700 s after a moment, so its limit of 600 s per scanner passes at once.
BLOCKED_SCANNER = """
import threading
import time
from pathlib import Path

import envdrift.scanner.engine as engine_module
from envdrift.scanner.base import ScannerBackend, ScanResult


class Blocker(ScannerBackend):
    name = "blocker"
    description = "never returns"

    def is_installed(self):
        return True

    def scan(self, paths, include_git_history=False):
        threading.Event().wait()
        return ScanResult(scanner_name="blocker")


real_time = time.time
start = real_time()
engine_module.time.time = lambda: real_time() + (700 if real_time() - start > 1.5 else 0)
engine = engine_module.ScanEngine(engine_module.GuardConfig(use_native=False, use_gitleaks=False))
engine.scanners = [Blocker()]
result = engine.scan([Path(".")])
print("RETURNED", [r.error for r in result.results])
"""


class ScanStillBlockedError(AssertionError):
    """``scan()`` did not return after a scanner timed out: the failure #870 describes."""


@pytest.mark.xfail(
    strict=False,
    raises=ScanStillBlockedError,
    reason="the timeout records an error but cannot free the blocked scanner thread (see #870)",
)
def test_a_scanner_that_never_returns_does_not_hold_the_run_past_its_timeout():
    """``scan()`` waits for every worker thread, so one that never returns holds it forever.

    Only that failure is expected: a child that cannot start or crashes fails the test.
    """
    # The child imports the same package as this process.
    source = str(Path(envdrift.__file__).resolve().parents[1])
    try:
        result = subprocess.run(  # nosec B603
            [sys.executable, "-c", BLOCKED_SCANNER],
            capture_output=True,
            text=True,
            timeout=6,
            env={**os.environ, "PYTHONPATH": source},
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScanStillBlockedError("scan() did not return after the scanner timed out") from exc

    assert result.returncode == 0, result.stderr
    assert "RETURNED ['Scanner timed out after 600s']" in result.stdout
