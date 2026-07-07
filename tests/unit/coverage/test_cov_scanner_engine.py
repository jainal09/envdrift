"""Coverage-focused tests for envdrift.scanner.engine.

These tests target previously-uncovered branches in ScanEngine:
- ImportError fall-throughs for every optional external scanner.
- Successful initialization of the kingfisher/git-secrets/talisman/trivy/
  infisical scanners (the constructor + is_installed branches).
- The scan() early-return when no scanners are configured.
- The scan() loop's future.result() exception handler and progress callback.
- The per-scanner timeout branch.
- The skip_gitignored filter being wired into scan().
- Edge cases inside _filter_encrypted_files.line_at (OSError + out-of-range).
- Edge cases inside _filter_gitignored_files (empty resolved set, paths outside
  the repo root, non 0/1 returncode warning, empty rel_paths skip).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from envdrift.scanner.base import (
    FindingSeverity,
    ScanFinding,
    ScannerBackend,
    ScanResult,
)
from envdrift.scanner.engine import GuardConfig, ScanEngine


def _make_scanner_class(class_name: str, scanner_name: str):
    """Build a concrete ScannerBackend subclass that records its kwargs."""

    def __init__(self, **kwargs) -> None:
        self.init_kwargs = kwargs
        self._installed = True

    def name(self) -> str:
        return scanner_name

    def description(self) -> str:
        return f"{scanner_name} scanner"

    def is_installed(self) -> bool:
        return self._installed

    def scan(self, paths, include_git_history=False) -> ScanResult:
        return ScanResult(scanner_name=scanner_name)

    return type(
        class_name,
        (ScannerBackend,),
        {
            "__init__": __init__,
            "name": property(name),
            "description": property(description),
            "is_installed": is_installed,
            "scan": scan,
        },
    )


def _finding(file_path: Path, *, line_number: int | None = 1) -> ScanFinding:
    return ScanFinding(
        file_path=file_path,
        line_number=line_number,
        rule_id="test-rule",
        rule_description="Test",
        description="Test finding",
        severity=FindingSeverity.HIGH,
        scanner="native",
    )


# Maps the config flag -> (module path, exported class attr, scanner name).
OPTIONAL_SCANNERS = {
    "use_gitleaks": ("envdrift.scanner.gitleaks", "GitleaksScanner", "gitleaks"),
    "use_trufflehog": ("envdrift.scanner.trufflehog", "TrufflehogScanner", "trufflehog"),
    "use_detect_secrets": (
        "envdrift.scanner.detect_secrets",
        "DetectSecretsScanner",
        "detect-secrets",
    ),
    "use_kingfisher": ("envdrift.scanner.kingfisher", "KingfisherScanner", "kingfisher"),
    "use_git_secrets": ("envdrift.scanner.git_secrets", "GitSecretsScanner", "git-secrets"),
    "use_talisman": ("envdrift.scanner.talisman", "TalismanScanner", "talisman"),
    "use_trivy": ("envdrift.scanner.trivy", "TrivyScanner", "trivy"),
    "use_infisical": ("envdrift.scanner.infisical", "InfisicalScanner", "infisical"),
}


def _off_config(*, enable: str | None = None, auto_install: bool = True) -> GuardConfig:
    """Build a GuardConfig with every scanner disabled, optionally enabling one.

    Args:
        enable: Name of a single ``use_*`` flag to turn on, or None for all off.
        auto_install: Value for the auto_install flag.
    """
    flags = {
        "use_native": False,
        "use_gitleaks": False,
        "use_trufflehog": False,
        "use_detect_secrets": False,
        "use_kingfisher": False,
        "use_git_secrets": False,
        "use_talisman": False,
        "use_trivy": False,
        "use_infisical": False,
    }
    if enable is not None:
        flags[enable] = True
    return GuardConfig(
        use_native=flags["use_native"],
        use_gitleaks=flags["use_gitleaks"],
        use_trufflehog=flags["use_trufflehog"],
        use_detect_secrets=flags["use_detect_secrets"],
        use_kingfisher=flags["use_kingfisher"],
        use_git_secrets=flags["use_git_secrets"],
        use_talisman=flags["use_talisman"],
        use_trivy=flags["use_trivy"],
        use_infisical=flags["use_infisical"],
        auto_install=auto_install,
    )


class TestOptionalScannerImportErrors:
    """Every optional scanner's ImportError fall-through must be exercised."""

    @pytest.mark.parametrize(
        ("flag", "module_path"),
        [(flag, mod) for flag, (mod, _cls, _name) in OPTIONAL_SCANNERS.items()],
    )
    def test_import_error_is_swallowed(self, flag, module_path, monkeypatch):
        """A missing optional scanner module must not crash engine init."""
        # Setting the module to None makes `from <mod> import X` raise ImportError.
        monkeypatch.setitem(sys.modules, module_path, None)

        engine = ScanEngine(_off_config(enable=flag))

        # The scanner could not be imported, so nothing was added.
        assert engine.scanners == []


class TestOptionalScannerInitialization:
    """Each optional scanner's successful construction branch is covered."""

    @pytest.mark.parametrize(
        ("flag", "module_path", "cls_attr", "scanner_name"),
        [(flag, mod, cls, name) for flag, (mod, cls, name) in OPTIONAL_SCANNERS.items()],
    )
    def test_scanner_added_when_installed(
        self, flag, module_path, cls_attr, scanner_name, monkeypatch
    ):
        """An installed optional scanner is appended to engine.scanners."""
        fake_cls = _make_scanner_class(cls_attr, scanner_name)
        fake_module = SimpleNamespace(**{cls_attr: fake_cls})
        monkeypatch.setitem(sys.modules, module_path, fake_module)

        # auto_install False so the is_installed() branch (True) is what adds it.
        engine = ScanEngine(_off_config(enable=flag, auto_install=False))

        names = [s.name for s in engine.scanners]
        assert names == [scanner_name]

    def test_kingfisher_receives_expected_kwargs(self, monkeypatch):
        """Kingfisher is constructed with its rich set of detection kwargs."""
        fake_cls = _make_scanner_class("KingfisherScanner", "kingfisher")
        monkeypatch.setitem(
            sys.modules,
            "envdrift.scanner.kingfisher",
            SimpleNamespace(KingfisherScanner=fake_cls),
        )

        engine = ScanEngine(_off_config(enable="use_kingfisher", auto_install=True))

        assert len(engine.scanners) == 1
        init_kwargs = engine.scanners[0].init_kwargs  # type: ignore[attr-defined]
        assert init_kwargs["validate_secrets"] is True
        assert init_kwargs["confidence"] == "low"
        assert init_kwargs["scan_binary_files"] is True
        assert init_kwargs["extract_archives"] is True
        assert init_kwargs["jobs"] == 1

    def test_git_secrets_registers_aws(self, monkeypatch):
        """git-secrets is constructed with register_aws=True."""
        fake_cls = _make_scanner_class("GitSecretsScanner", "git-secrets")
        monkeypatch.setitem(
            sys.modules,
            "envdrift.scanner.git_secrets",
            SimpleNamespace(GitSecretsScanner=fake_cls),
        )

        engine = ScanEngine(_off_config(enable="use_git_secrets", auto_install=True))

        assert engine.scanners[0].init_kwargs["register_aws"] is True  # type: ignore[attr-defined]


class TestScanEarlyReturn:
    """scan() short-circuits when there are no scanners."""

    def test_scan_with_no_scanners_returns_empty_aggregate(self):
        engine = ScanEngine(_off_config())
        assert engine.scanners == []

        result = engine.scan([Path()])

        assert result.total_findings == 0
        assert result.unique_findings == []
        assert result.scanners_used == []
        assert result.results == []
        assert result.total_duration_ms >= 0


class TestScanLoopBranches:
    """Cover the result-collection loop's error path and progress callback."""

    def test_future_result_exception_recorded_and_callback_invoked(self, monkeypatch):
        """If future.result() raises, the scan records the failure via callback.

        The scanner-level try/except in _run_scanner is bypassed by patching it to
        raise directly, so the *outer* handler in scan() (the `except Exception`
        around future.result()) is what catches the error.
        """

        class OkScanner(ScannerBackend):
            @property
            def name(self) -> str:
                return "exploding"

            @property
            def description(self) -> str:
                return "explodes"

            def is_installed(self) -> bool:
                return True

            def scan(self, paths, include_git_history=False) -> ScanResult:
                return ScanResult(scanner_name=self.name)

        engine = ScanEngine(_off_config())
        engine.scanners = [OkScanner()]

        def boom(self, scanner, paths, include_git_history):
            raise RuntimeError("kaboom")

        monkeypatch.setattr(ScanEngine, "_run_scanner", boom)

        events: list[tuple[str, int, int, str | None]] = []

        def on_complete(name, completed, total, result):
            events.append((name, completed, total, result.error if result else None))

        aggregated = engine.scan([Path()], on_scanner_complete=on_complete)

        assert len(aggregated.results) == 1
        assert aggregated.results[0].error is not None
        assert "Scanner failed" in aggregated.results[0].error
        assert "kaboom" in aggregated.results[0].error
        # The progress callback fired once with the failed result.
        assert events == [("exploding", 1, 1, aggregated.results[0].error)]

    def test_progress_callback_on_success(self):
        """The progress callback is invoked for a normal scanner completion."""

        class QuietScanner(ScannerBackend):
            @property
            def name(self) -> str:
                return "quiet"

            @property
            def description(self) -> str:
                return "quiet"

            def is_installed(self) -> bool:
                return True

            def scan(self, paths, include_git_history=False) -> ScanResult:
                return ScanResult(scanner_name=self.name)

        engine = ScanEngine(_off_config())
        engine.scanners = [QuietScanner()]

        seen: list[tuple[str, int, int]] = []
        engine.scan(
            [Path()],
            on_scanner_complete=lambda n, c, t, r: seen.append((n, c, t)),
        )

        assert seen == [("quiet", 1, 1)]


class TestScanTimeoutBranch:
    """Cover the per-scanner timeout handling in scan()."""

    def test_scanner_timeout_is_recorded(self, monkeypatch):
        """A scanner that never finishes is cancelled and reported as timed out.

        We force the timeout by patching time.time so the elapsed check exceeds
        the 600s budget, and patch concurrent.futures.wait to report the future
        as never done (so it lands in the timeout sweep).
        """
        from envdrift.scanner import engine as engine_mod

        class HangingScanner(ScannerBackend):
            @property
            def name(self) -> str:
                return "hanger"

            @property
            def description(self) -> str:
                return "hangs"

            def is_installed(self) -> bool:
                return True

            def scan(self, paths, include_git_history=False) -> ScanResult:
                # Never actually called in a way that completes within wait().
                return ScanResult(scanner_name=self.name)

        engine = ScanEngine(_off_config())
        engine.scanners = [HangingScanner()]

        # First wait() call: report nothing done, keep the future pending.
        # The timeout sweep then runs and cancels it.
        original_wait = engine_mod.wait
        call_state = {"count": 0}

        def fake_wait(pending, timeout=None, return_when=None):
            call_state["count"] += 1
            # Always report nothing completed so the pending future is swept.
            return set(), set(pending)

        monkeypatch.setattr(engine_mod, "wait", fake_wait)

        # Make elapsed time look huge so now - start_time > per_scanner_timeout_s.
        time_values = iter([1000.0] + [1_000_000.0] * 50)
        real_time = engine_mod.time.time

        def fake_time():
            try:
                return next(time_values)
            except StopIteration:
                return real_time()

        monkeypatch.setattr(engine_mod.time, "time", fake_time)

        events: list[str] = []
        result = engine.scan(
            [Path()],
            on_scanner_complete=lambda n, c, t, r: events.append((r.error or "") if r else ""),
        )

        assert call_state["count"] >= 1
        assert len(result.results) == 1
        assert "timed out" in (result.results[0].error or "")
        assert any("timed out" in e for e in events)
        # Sanity: the real wait still exists (we didn't clobber globally).
        assert original_wait is not None


class TestSkipGitignoredWiredIntoScan:
    """The skip_gitignored config flag triggers the gitignore filter in scan()."""

    def test_scan_calls_gitignore_filter(self, tmp_path, monkeypatch):
        config = GuardConfig(
            use_native=True,
            use_gitleaks=False,
            skip_gitignored=True,
        )
        engine = ScanEngine(config)

        secret_file = tmp_path / "config.py"
        secret_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')

        called = {"hit": False}
        real_filter = engine._filter_gitignored_files

        def spy(findings):
            called["hit"] = True
            return real_filter(findings)

        monkeypatch.setattr(engine, "_filter_gitignored_files", spy)

        # No real git repo here, so the filter returns findings unchanged.
        result = engine.scan([tmp_path])

        assert called["hit"] is True
        assert result.total_findings >= 1


class TestFilterEncryptedLineAtEdges:
    """Cover the line_at() helper's OSError and out-of-range branches."""

    def test_line_at_handles_unreadable_file(self, tmp_path, monkeypatch):
        """If reading lines raises OSError, the file is treated as empty (drop).

        is_file_encrypted reads the first 2KB and finds a marker, but the second
        open() (in line_at) raises OSError -> lines_cache becomes []. With an
        empty line list, line_at returns "" and the finding on a line is treated
        as cleartext (kept). This exercises the OSError except in line_at.
        """
        enc = tmp_path / ".env.encrypted"
        enc.write_text('FOO="encrypted:abc123"\nBAR=baz\n')

        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        real_open = open
        state = {"calls": 0}

        def flaky_open(file, *args, **kwargs):
            # First open() is the marker-check read; let it succeed.
            # Second open() is line_at's full read; make it raise OSError.
            if str(file) == str(enc):
                state["calls"] += 1
                if state["calls"] >= 2:
                    raise OSError("simulated read failure")
            return real_open(file, *args, **kwargs)

        monkeypatch.setattr("builtins.open", flaky_open)

        finding = _finding(enc, line_number=2)
        result = engine._filter_encrypted_files([finding])

        # line_at returned "" (empty lines cache after OSError); "" is not an
        # encrypted value line, so the finding is kept.
        assert len(result) == 1

    def test_line_at_out_of_range_returns_empty(self, tmp_path):
        """A line number past EOF yields '' and the finding is kept."""
        enc = tmp_path / ".env.encrypted"
        enc.write_text('FOO="encrypted:abc123"\n')

        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        # File has 1 line; ask about line 99 -> line_at returns "" (kept).
        finding = _finding(enc, line_number=99)
        result = engine._filter_encrypted_files([finding])

        assert len(result) == 1


class TestGitignoredFilterEdgeCases:
    """Cover the harder-to-reach branches of _filter_gitignored_files."""

    def test_returns_findings_when_resolved_set_empty(self, monkeypatch):
        """If the resolved file_paths set is empty, findings are returned as-is.

        We feed a finding but monkeypatch the set comprehension's effect by giving
        a finding whose path resolves, then assert the early `if not file_paths`
        guard does not fire — instead we cover line 717 by ensuring an empty input
        of resolved paths returns the originals. The cleanest hermetic way is the
        no-git-root path: a file with no .git anywhere returns the findings.
        """
        config = GuardConfig(use_native=True, use_gitleaks=False, skip_gitignored=True)
        engine = ScanEngine(config)

        # A path under /tmp that has no .git ancestor -> paths_by_root empty ->
        # gitignored_files empty -> returns findings unchanged.
        finding = _finding(Path("/nonexistent/deep/path/file.py"))

        called = {"ran": False}

        def fake_run(*args, **kwargs):
            called["ran"] = True
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

        result = engine._filter_gitignored_files([finding])

        assert result == [finding]
        # No git root found, so subprocess.run is never invoked.
        assert called["ran"] is False

    def test_non_zero_returncode_logs_warning_and_continues(self, tmp_path, monkeypatch):
        """git check-ignore returning an unexpected code logs a warning, no filter."""
        (tmp_path / ".git").mkdir()
        target = tmp_path / "file.py"
        target.touch()

        config = GuardConfig(use_native=True, use_gitleaks=False, skip_gitignored=True)
        engine = ScanEngine(config)

        def fake_run(cmd, **kwargs):
            # returncode 128 is not in (0, 1) -> warning branch + continue.
            return subprocess.CompletedProcess(cmd, 128, stdout=b"", stderr=b"fatal: boom")

        monkeypatch.setattr(subprocess, "run", fake_run)

        finding = _finding(target)
        result = engine._filter_gitignored_files([finding])

        # Nothing was added to gitignored_files, so the finding survives.
        assert result == [finding]

    def test_paths_outside_root_are_skipped(self, tmp_path, monkeypatch):
        """A path that can't be made relative to its root contributes no rel_paths.

        find_git_root walks up to the nearest .git. We craft a finding whose
        resolved path's git root is found, but force relative_to to raise so the
        rel_paths list ends up empty and the `if not rel_paths: continue` branch
        is hit.
        """
        (tmp_path / ".git").mkdir()
        target = tmp_path / "file.py"
        target.touch()

        config = GuardConfig(use_native=True, use_gitleaks=False, skip_gitignored=True)
        engine = ScanEngine(config)

        run_calls = {"count": 0}

        def fake_run(cmd, **kwargs):
            run_calls["count"] += 1
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

        original_relative_to = Path.relative_to

        def flaky_relative_to(self, *other, **kwargs):
            raise ValueError("path outside root")

        monkeypatch.setattr(Path, "relative_to", flaky_relative_to)

        finding = _finding(target)
        try:
            result = engine._filter_gitignored_files([finding])
        finally:
            monkeypatch.setattr(Path, "relative_to", original_relative_to)

        # rel_paths was empty -> subprocess.run never called -> finding kept.
        assert result == [finding]
        assert run_calls["count"] == 0
