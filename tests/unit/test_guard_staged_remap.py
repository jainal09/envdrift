"""``guard --staged`` shows a staged file by its repository path in scanner warnings (#933).

The staged blobs are scanned as copies in a temporary mirror, deleted after the scan. Findings
were rewritten to repository paths (#476), warnings were not. The real CLI runs in
``tests/integration/test_guard_staged_warnings_e2e.py``; these tests pin the rewriting itself.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.cli_commands.guard import _mirror_renames, _remap_finding_paths, _remap_warnings
from envdrift.scanner.base import AggregatedScanResult, ScanResult


def _too_large(path: str) -> str:
    return f"Not scanned: {path} is larger than the native scanner's 10 MiB limit."


def test_a_path_is_never_rewritten_through_a_shorter_one_it_begins_with(tmp_path: Path):
    mirror = tmp_path / "mirror"
    renames = _mirror_renames({mirror / "a": Path("a"), mirror / "a.bak": Path("a.bak")})

    assert [len(form) for form, _ in renames] == sorted((len(f) for f, _ in renames), reverse=True)
    assert _remap_warnings(
        [_too_large(str(mirror / "a.bak")), _too_large(str(mirror / "a"))], renames
    ) == [_too_large("a.bak"), _too_large("a")]


def test_a_mirror_under_the_cwd_is_rewritten_in_its_relative_form(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """With the temporary directory inside the checkout, a warning names the copy relatively."""
    monkeypatch.chdir(tmp_path)
    copy = tmp_path / ".tmp" / "envdrift-staged-x" / "sub" / "dump.sql"
    shown = Path("sub") / "dump.sql"

    renames = _mirror_renames({copy: shown})

    relative = str(Path(".tmp") / "envdrift-staged-x" / "sub" / "dump.sql")
    assert _remap_warnings([_too_large(relative)], renames) == [_too_large(str(shown))]
    assert _remap_warnings([_too_large(str(copy))], renames) == [_too_large(str(shown))]


def test_remapping_rewrites_each_scanners_warnings_and_leaves_others(tmp_path: Path):
    copy = tmp_path / "mirror" / "dump.sql"
    result = AggregatedScanResult(
        results=[
            ScanResult(scanner_name="native", warnings=[_too_large(str(copy))]),
            ScanResult(scanner_name="gitleaks", warnings=["gitleaks 8.30 is older than pinned"]),
        ],
        total_findings=0,
        unique_findings=[],
        scanners_used=["native", "gitleaks"],
        total_duration_ms=1,
    )

    remapped = _remap_finding_paths(result, {copy.resolve(): Path("dump.sql")})

    assert [scan.warnings for scan in remapped.results] == [
        [_too_large("dump.sql")],
        ["gitleaks 8.30 is older than pinned"],
    ]
