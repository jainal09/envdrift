"""The scan engine shows one path per file and ignores by the names below the cwd (#855, #859)."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from envdrift.scanner.base import FindingSeverity, ScanFinding, ScannerBackend
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


class TestScanEngineAliasedScanPaths:
    """A directory scanned together with a symlink to it reports each secret once (#861)."""

    @pytest.fixture(autouse=True)
    def _tree(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        (tmp_path / "proj" / "sub").mkdir(parents=True)
        (tmp_path / "proj" / "sub" / "app.env").write_text(f"GITHUB_TOKEN={GITHUB_TOKEN}\n")
        symlink(tmp_path / "linkproj", tmp_path / "proj")
        monkeypatch.chdir(tmp_path)

    @staticmethod
    def _gitleaks(*findings: ScanFinding) -> FixedScanner:
        return FixedScanner("gitleaks", list(findings))

    @pytest.mark.parametrize(
        "scan_paths",
        [["."], ["linkproj"]],
        ids=["dot-first", "link-first"],
    )
    def test_the_two_names_of_a_file_are_one_finding_named_by_its_real_location(
        self, scan_paths: list[str]
    ):
        """``guard . linkproj`` made gitleaks report ``proj/...`` and ``linkproj/...``."""
        scanner = self._gitleaks(
            make_finding("proj/sub/app.env", scanner="gitleaks", rule="github-pat"),
            make_finding("linkproj/sub/app.env", scanner="gitleaks", rule="github-pat"),
        )
        scan_paths = [*scan_paths, *({".", "linkproj"} - set(scan_paths))]

        result = scan_engine(scanner).scan([Path(p) for p in scan_paths])

        assert result.total_findings == 2
        assert [f.file_path for f in result.unique_findings] == [Path("proj/sub/app.env")]

    def test_the_finding_order_does_not_change_the_name_shown(self):
        first = make_finding("proj/sub/app.env", scanner="gitleaks", rule="github-pat")
        second = make_finding("linkproj/sub/app.env", scanner="gitleaks", rule="github-pat")

        names = {
            tuple(
                f.file_path
                for f in scan_engine(self._gitleaks(*order))
                .scan([Path(), Path("linkproj")])
                .unique_findings
            )
            for order in ((first, second), (second, first))
        }

        assert names == {(Path("proj/sub/app.env"),)}

    def test_a_scan_of_the_link_alone_keeps_the_name_it_was_given(self):
        """Nothing to collapse: the file is shown below the scan path the caller gave (#853)."""
        scanner = self._gitleaks(
            make_finding("linkproj/sub/app.env", scanner="gitleaks", rule="github-pat")
        )

        result = scan_engine(scanner).scan([Path("linkproj")])

        assert [f.file_path for f in result.unique_findings] == [Path("linkproj/sub/app.env")]

    def test_findings_at_two_lines_stay_two_findings(self):
        lines = [
            make_finding("proj/sub/app.env", scanner="gitleaks", rule="github-pat"),
            make_finding("linkproj/sub/app.env", scanner="gitleaks", rule="github-pat"),
        ]
        second_line = [replace(f, line_number=2, secret_hash="4567ef01") for f in lines]

        result = scan_engine(self._gitleaks(*lines, *second_line)).scan([Path(), Path("linkproj")])

        assert sorted(f.line_number or 0 for f in result.unique_findings) == [1, 2]
        assert {f.file_path for f in result.unique_findings} == {Path("proj/sub/app.env")}

    def test_a_policy_finding_without_a_secret_is_one_finding_too(self):
        findings = [
            ScanFinding(
                file_path=Path(name),
                rule_id="unencrypted-env-file",
                rule_description="Unencrypted env file",
                description="Run 'envdrift encrypt'",
                severity=FindingSeverity.HIGH,
                scanner="native",
            )
            for name in ("proj/sub/app.env", "linkproj/sub/app.env")
        ]

        result = scan_engine(FixedScanner("native", findings)).scan([Path(), Path("linkproj")])

        assert [f.file_path for f in result.unique_findings] == [Path("proj/sub/app.env")]

    def test_a_hashless_duplicate_under_the_other_name_is_dropped(self):
        hashed = make_finding("proj/sub/app.env", scanner="gitleaks", rule="github-pat")
        hashless = replace(hashed, secret_hash="", file_path=Path("linkproj/sub/app.env"))

        result = scan_engine(self._gitleaks(hashed, hashless)).scan([Path(), Path("linkproj")])

        assert [f.file_path for f in result.unique_findings] == [Path("proj/sub/app.env")]
        assert [f.secret_hash for f in result.unique_findings] == [hashed.secret_hash]

    @pytest.mark.parametrize(
        ("worse", "better"),
        [
            ((FindingSeverity.HIGH, False), (FindingSeverity.CRITICAL, False)),
            ((FindingSeverity.CRITICAL, False), (FindingSeverity.CRITICAL, True)),
        ],
        ids=["severity", "verified"],
    )
    def test_severity_and_verification_decide_before_the_name(
        self, worse: tuple[FindingSeverity, bool], better: tuple[FindingSeverity, bool]
    ):
        """The finding that is worth more is kept, under the name it was reported by."""
        real = replace(
            make_finding("proj/sub/app.env", scanner="gitleaks"),
            severity=worse[0],
            verified=worse[1],
        )
        linked = replace(
            make_finding("linkproj/sub/app.env", scanner="gitleaks"),
            severity=better[0],
            verified=better[1],
        )

        result = scan_engine(self._gitleaks(real, linked)).scan([Path(), Path("linkproj")])

        assert [f.file_path for f in result.unique_findings] == [Path("linkproj/sub/app.env")]

    def test_two_different_files_are_not_collapsed(self, tmp_path: Path):
        (tmp_path / "proj" / "sub" / "other.env").write_text(f"GITHUB_TOKEN={GITHUB_TOKEN}\n")
        scanner = self._gitleaks(
            make_finding("proj/sub/app.env", scanner="gitleaks", rule="github-pat"),
            make_finding("proj/sub/other.env", scanner="gitleaks", rule="github-pat"),
        )

        result = scan_engine(scanner).scan([Path(), Path("linkproj")])

        assert {f.file_path for f in result.unique_findings} == {
            Path("proj/sub/app.env"),
            Path("proj/sub/other.env"),
        }


class TestScanEngineAliasesInsideTheTree:
    """Which name survives when a file is reached by a link inside a scanned tree (#861)."""

    @pytest.fixture(autouse=True)
    def _tree(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """``proj/sub/app.env``, ``proj/a_alias.env`` -> it (sorts first), links to ``proj``."""
        (tmp_path / "proj" / "sub").mkdir(parents=True)
        (tmp_path / "proj" / "sub" / "app.env").write_text(f"GITHUB_TOKEN={GITHUB_TOKEN}\n")
        symlink(tmp_path / "proj" / "a_alias.env", Path("sub/app.env"))
        symlink(tmp_path / "link1", tmp_path / "proj")
        symlink(tmp_path / "link2", tmp_path / "proj")
        monkeypatch.chdir(tmp_path)

    @staticmethod
    def _shown(engine: ScanEngine, scan_paths: list[str]) -> list[Path]:
        return [f.file_path for f in engine.scan([Path(p) for p in scan_paths]).unique_findings]

    def test_the_file_beats_a_link_to_it_below_a_symlinked_scan_path(self):
        scanner = FixedScanner(
            "gitleaks",
            [
                make_finding("link1/a_alias.env", scanner="gitleaks"),
                make_finding("link1/sub/app.env", scanner="gitleaks"),
            ],
        )

        assert self._shown(scan_engine(scanner), ["link1"]) == [Path("link1/sub/app.env")]

    def test_every_scanner_names_the_file_the_same_way(self, tmp_path: Path):
        """Native reports where the file really is, gitleaks the name it walked."""
        proj = (tmp_path / "proj").resolve()
        native = FixedScanner(
            "native",
            [make_finding(proj / "sub" / "app.env"), make_finding(proj / "a_alias.env")],
        )
        gitleaks = FixedScanner(
            "gitleaks",
            [
                make_finding("link1/a_alias.env", scanner="gitleaks", rule="gitleaks-x"),
                make_finding("link1/sub/app.env", scanner="gitleaks", rule="gitleaks-x"),
            ],
        )

        shown = scan_engine(native, gitleaks).scan([Path("link1")]).unique_findings

        assert {(f.scanner, f.file_path) for f in shown} == {
            ("native", Path("link1/sub/app.env")),
            ("gitleaks", Path("link1/sub/app.env")),
        }

    @pytest.mark.parametrize("scan_paths", [["link2", "link1"], ["link1", "link2"]])
    def test_two_links_to_one_directory_are_shown_under_the_first_one_given(
        self, scan_paths: list[str]
    ):
        first = scan_paths[0]
        native_real = (Path.cwd() / "proj" / "sub" / "app.env").resolve()
        native = FixedScanner("native", [make_finding(native_real)])
        gitleaks = FixedScanner(
            "gitleaks",
            [
                make_finding(f"{name}/sub/app.env", scanner="gitleaks", rule="gitleaks-x")
                for name in scan_paths
            ],
        )

        shown = scan_engine(native, gitleaks).scan([Path(p) for p in scan_paths]).unique_findings

        assert {f.file_path for f in shown} == {Path(first) / "sub" / "app.env"}

    def test_skip_duplicate_keeps_the_file_found_first_by_name_when_nothing_is_aliased(self):
        """Two different files with one secret: a symlinked scan path does not change which."""
        (Path.cwd() / "other").mkdir()
        scanner = FixedScanner(
            "gitleaks",
            [
                make_finding("other/b.env", scanner="gitleaks"),
                make_finding("link1/a.env", scanner="gitleaks"),
            ],
        )

        result = scan_engine(scanner, skip_duplicate=True).scan([Path("link1"), Path("other")])

        assert [f.file_path for f in result.unique_findings] == [Path("link1/a.env")]

    def test_skip_duplicate_collapses_findings_without_a_secret_value_by_where_the_file_is(self):
        bare = [
            replace(make_finding(name, scanner="gitleaks"), secret_hash="", secret_preview="")
            for name in ("link1/sub/app.env", "link2/sub/app.env")
        ]

        result = scan_engine(FixedScanner("gitleaks", bare), skip_duplicate=True).scan(
            [Path("link1"), Path("link2")]
        )

        assert [f.file_path for f in result.unique_findings] == [Path("link1/sub/app.env")]


class TestScanEngineBareNamesOutsideTheCwd:
    """A pattern without a separator hides what is below a scan path, not the checkout (#865)."""

    @pytest.fixture
    def repo(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        """A checkout at ``<tmp>/build/repo``, scanned from the sibling directory ``work``."""
        repo = tmp_path / "build" / "repo"
        (repo / "sub").mkdir(parents=True)
        (repo / "sub" / "app.env").write_text(f"GITHUB_TOKEN={GITHUB_TOKEN}\n")
        (tmp_path / "work").mkdir()
        monkeypatch.chdir(tmp_path / "work")
        return repo

    @pytest.mark.parametrize(
        ("pattern", "kept"),
        [("build", 2), ("repo", 2), ("sub", 0), ("app.env", 0), ("*.env", 0), ("nothing", 2)],
    )
    def test_the_verdict_is_the_same_for_every_scanner(self, repo: Path, pattern: str, kept: int):
        file = repo / "sub" / "app.env"
        native = FixedScanner("native", [make_finding(file)])
        gitleaks = FixedScanner(
            "gitleaks", [make_finding(file, scanner="gitleaks", rule="gitleaks-github-pat")]
        )

        result = scan_engine(native, gitleaks, ignore_paths=[pattern]).scan([repo])

        assert len(result.unique_findings) == kept

    def test_an_ignore_rule_is_matched_the_same_way(self, repo: Path):
        native = FixedScanner("native", [make_finding(repo / "sub" / "app.env")])

        hidden = scan_engine(native, ignore_rules={"github-pat": ["sub"]}).scan([repo])
        shown = scan_engine(native, ignore_rules={"github-pat": ["build"]}).scan([repo])

        assert (len(hidden.unique_findings), len(shown.unique_findings)) == (0, 1)
