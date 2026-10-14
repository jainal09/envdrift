"""The scan engine shows one path per file and ignores by the names below the cwd (#855, #859)."""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.scanner.base import ScannerBackend
from envdrift.scanner.engine import GuardConfig, ScanEngine
from tests.scanner.finding_paths_helpers import (
    GITHUB_TOKEN,
    FixedScanner,
    make_finding,
    scan_engine,
    symlink,
)


class TestScanEngineDisplayPaths:
    """The engine shows every finding path in one form, after its filters (#855)."""

    @pytest.fixture(autouse=True)
    def _in_tmp(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        (tmp_path / "proj" / "sub").mkdir(parents=True)
        (tmp_path / "proj" / "sub" / "app.env").write_text(f"GITHUB_TOKEN={GITHUB_TOKEN}\n")
        monkeypatch.chdir(tmp_path)

    def test_one_form_per_file_across_scanners(self, tmp_path: Path):
        native = FixedScanner("native", [make_finding(tmp_path / "proj" / "sub" / "app.env")])
        gitleaks = FixedScanner(
            "gitleaks", [make_finding("proj/sub/app.env", scanner="gitleaks", rule="gitleaks-x")]
        )

        result = scan_engine(native, gitleaks).scan([Path("proj")])

        assert {f.file_path for f in result.unique_findings} == {Path("proj/sub/app.env")}
        assert {f.file_path for r in result.results for f in r.findings} == {
            Path("proj/sub/app.env")
        }

    def test_one_file_in_two_forms_from_one_scanner_is_one_finding(self, tmp_path: Path):
        """``guard proj proj/sub/app.env`` scans the file twice, in two forms."""
        scanner = FixedScanner(
            "native",
            [make_finding(tmp_path / "proj" / "sub" / "app.env"), make_finding("proj/sub/app.env")],
        )

        result = scan_engine(scanner).scan([Path("proj"), Path("proj/sub/app.env")])

        assert result.total_findings == 2
        assert [f.file_path for f in result.unique_findings] == [Path("proj/sub/app.env")]

    @pytest.mark.parametrize("pattern", ["**/proj/**", "proj/sub/app.env", "proj/**"])
    def test_path_ignores_give_one_verdict_per_file(self, tmp_path: Path, pattern: str):
        """A path pattern suppresses a file whichever form a scanner reported it in.

        ``**/proj/**`` needs a directory before ``proj``, so it matched the
        native scanner's absolute path and not gitleaks' relative one: the
        same file, shown the same way, was suppressed for one scanner and
        reported for the other, and ``guard`` and ``guard .`` disagreed.
        """
        native = FixedScanner("native", [make_finding(tmp_path / "proj" / "sub" / "app.env")])
        relative = FixedScanner(
            "gitleaks", [make_finding("proj/sub/app.env", scanner="gitleaks", rule="gitleaks-x")]
        )

        result = scan_engine(native, relative, ignore_paths=[pattern]).scan([Path("proj")])

        assert result.unique_findings == []

    def test_rule_path_ignores_match_the_shown_path(self, tmp_path: Path):
        native = FixedScanner("native", [make_finding(tmp_path / "proj" / "sub" / "app.env")])
        engine = scan_engine(native, ignore_rules={"github-pat": ["proj/sub/app.env"]})

        assert engine.scan([Path("proj")]).unique_findings == []

    def test_unmatched_path_pattern_still_reports(self, tmp_path: Path):
        native = FixedScanner("native", [make_finding(tmp_path / "proj" / "sub" / "app.env")])

        result = scan_engine(native, ignore_paths=["other/**"]).scan([Path("proj")])

        assert [f.file_path for f in result.unique_findings] == [Path("proj/sub/app.env")]

    def test_path_ignores_match_a_file_under_a_symlinked_scan_path(self, tmp_path: Path):
        """``linkproj/**`` suppresses what is shown as ``linkproj/...`` (#853, #855).

        The native scanner reports the file at its real location, which the
        pattern does not match.
        """
        symlink(tmp_path / "linkproj", tmp_path / "proj")
        real = (tmp_path / "proj" / "sub" / "app.env").resolve()
        native = FixedScanner("native", [make_finding(real)])
        binary = FixedScanner(
            "gitleaks",
            [make_finding("linkproj/sub/app.env", scanner="gitleaks", rule="gitleaks-x")],
        )

        result = scan_engine(native, binary, ignore_paths=["linkproj/**"]).scan([Path("linkproj")])

        assert result.unique_findings == []

    def test_inline_ignore_reads_the_file_a_relative_path_names(self, tmp_path: Path):
        (tmp_path / "proj" / "sub" / "app.env").write_text("X=1  # envdrift:ignore\n")
        scanner = FixedScanner("gitleaks", [make_finding("proj/sub/app.env", scanner="gitleaks")])

        assert scan_engine(scanner).scan([Path("proj")]).unique_findings == []

    def test_description_names_the_file_like_the_finding(self, tmp_path: Path):
        raw = tmp_path / "proj" / "sub" / "app.env"
        scanner = FixedScanner(
            "native", [make_finding(raw, description=f"Run 'envdrift encrypt {raw}' first.")]
        )

        (finding,) = scan_engine(scanner).scan([Path("proj")]).unique_findings

        assert finding.description == f"Run 'envdrift encrypt {Path('proj/sub/app.env')}' first."

    def test_native_findings_under_a_symlinked_directory_show_the_link(self, tmp_path: Path):
        """The real native scanner resolves the directory it walks (#853, #855)."""
        symlink(tmp_path / "linkproj", tmp_path / "proj")
        engine = ScanEngine(GuardConfig(use_native=True, use_gitleaks=False))

        result = engine.scan([Path("linkproj")])

        assert result.unique_findings, "the planted token was not reported"
        assert {f.file_path for f in result.unique_findings} == {Path("linkproj/sub/app.env")}


class TestScanEngineIgnoresBelowTheCwd:
    """Relative path ignores never match through the directories above the cwd (#859)."""

    @pytest.fixture
    def repo(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        """A checkout at ``<tmp>/build/repo`` holding ``proj/sub/app.env``, as the cwd."""
        repo = tmp_path / "build" / "repo"
        (repo / "proj" / "sub").mkdir(parents=True)
        (repo / "proj" / "sub" / "app.env").write_text(f"GITHUB_TOKEN={GITHUB_TOKEN}\n")
        monkeypatch.chdir(repo)
        return repo

    @staticmethod
    def _scanners(repo: Path) -> tuple[ScannerBackend, ScannerBackend, ScannerBackend]:
        """The native scanner's absolute report, and the binaries' ``guard .`` and
        ``guard ../repo/proj`` reports.
        """
        native = FixedScanner("native", [make_finding(repo / "proj" / "sub" / "app.env")])
        relative = FixedScanner(
            "gitleaks", [make_finding("proj/sub/app.env", scanner="gitleaks", rule="gitleaks-x")]
        )
        via_parent = FixedScanner(
            "infisical",
            [make_finding("../repo/proj/sub/app.env", scanner="infisical", rule="infisical-x")],
        )
        return native, relative, via_parent

    @pytest.mark.parametrize(
        "pattern", ["**/build/**", "build/**", "build/repo/**", "**/repo/**", "../repo/proj/**"]
    )
    def test_relative_pattern_naming_a_directory_above_the_cwd_reports_the_file(
        self, repo: Path, pattern: str
    ):
        """``**/build/**`` matched the native scanner's absolute path.

        So a checkout that merely lives under ``build/`` had every finding
        hidden with exit 0.
        """
        result = scan_engine(*self._scanners(repo), ignore_paths=[pattern]).scan([Path()])

        assert {(f.scanner, f.file_path) for f in result.unique_findings} == {
            ("native", Path("proj/sub/app.env")),
            ("gitleaks", Path("proj/sub/app.env")),
            ("infisical", Path("proj/sub/app.env")),
        }

    @pytest.mark.parametrize("pattern", ["**/build/**", "build/repo/proj/sub/app.env"])
    def test_rule_path_ignores_do_not_match_above_the_cwd_either(self, repo: Path, pattern: str):
        native, _relative, _via_parent = self._scanners(repo)
        engine = scan_engine(native, ignore_rules={"github-pat": [pattern]})

        assert [f.file_path for f in engine.scan([Path()]).unique_findings] == [
            Path("proj/sub/app.env")
        ]

    @pytest.mark.parametrize("prefix", ["<repo>/proj", "<tmp>/build"])
    def test_absolute_pattern_matches_every_report(self, repo: Path, tmp_path: Path, prefix: str):
        """An absolute pattern names the file whichever form a scanner reported it in.

        It matched only the absolute paths the native scanner and ``guard``
        with no path report, so ``guard .`` let gitleaks findings through.
        """
        anchor = prefix.replace("<repo>", repo.as_posix()).replace("<tmp>", tmp_path.as_posix())
        engine = scan_engine(*self._scanners(repo), ignore_paths=[f"{anchor}/**"])

        assert engine.scan([Path()]).unique_findings == []

    @pytest.mark.parametrize(
        ("pattern", "kept"), [("tmp/**", 1), ("**/envdrift-staged-*/**", 1), ("proj/**", 0)]
    )
    def test_scanned_copies_are_matched_by_the_files_they_copy(
        self, repo: Path, tmp_path: Path, pattern: str, kept: int
    ):
        """``guard --staged`` scans copies in a temporary directory (#859).

        Patterns matched the copy's path, so ``tmp/**`` hid every staged
        finding on a system whose temporary directory is ``/tmp``.
        """
        copy = tmp_path / "tmp" / "envdrift-staged-x" / "proj" / "sub" / "app.env"
        copy.parent.mkdir(parents=True)
        copy.write_text(f"GITHUB_TOKEN={GITHUB_TOKEN}\n")
        scanner = FixedScanner("native", [make_finding(copy)])

        result = scan_engine(scanner, ignore_paths=[pattern]).scan(
            [copy], aliases={(tmp_path / "tmp" / "envdrift-staged-x").resolve(): repo}
        )

        assert len(result.unique_findings) == kept

    @pytest.fixture
    def staged(
        self, repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> tuple[Path, dict[Path, Path]]:
        """The copy of a staged ``proj/sub/app.env`` and the aliases that map it back, from ``repo/other``."""
        (repo / "other").mkdir()
        monkeypatch.chdir(repo / "other")
        copies = tmp_path / "tmp" / "envdrift-staged-x"
        copy = copies / "proj" / "sub" / "app.env"
        copy.parent.mkdir(parents=True)
        copy.write_text(f"GITHUB_TOKEN={GITHUB_TOKEN}\n")
        return copy, {copies.resolve(): repo}

    @pytest.mark.parametrize(
        ("pattern", "kept"),
        [
            ("**/build/**", 1),
            ("build/**", 1),
            ("repo/**", 1),
            ("tmp/**", 1),
            ("proj/**", 0),
            ("**/proj/**", 0),
            ("<repo>/proj/**", 0),
        ],
    )
    def test_staged_file_outside_the_cwd_is_matched_by_its_path_in_the_repository(
        self, repo: Path, staged: tuple[Path, dict[Path, Path]], pattern: str, kept: int
    ):
        """``guard --staged`` from a subdirectory: a staged file elsewhere (#859).

        Matched by its absolute path, ``**/build/**`` hid it in a checkout under
        ``build/``, where its copy in the temporary directory never had.
        """
        copy, aliases = staged
        scanner = FixedScanner("native", [make_finding(copy)])
        ignore = pattern.replace("<repo>", repo.as_posix())

        result = scan_engine(scanner, ignore_paths=[ignore]).scan([copy], aliases=aliases)

        assert len(result.unique_findings) == kept
