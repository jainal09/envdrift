"""Tests for how path patterns see a file's names: path forms, relative and absolute (#855, #859)."""

from __future__ import annotations

from pathlib import Path, PureWindowsPath

import pytest

from envdrift.scanner.base import FindingSeverity, ScanFinding
from envdrift.scanner.ignores import (
    IgnoreConfig,
    IgnoreFilter,
    PathForms,
    is_absolute_pattern,
)


class TestIgnoreFilterPathForms:
    """#855, #859: path patterns match the names ``path_forms`` gives a file, not only its report."""

    @staticmethod
    def _finding(file_path: Path, rule_id: str = "github-pat") -> ScanFinding:
        return ScanFinding(
            rule_id=rule_id,
            rule_description=rule_id,
            file_path=file_path,
            line_number=1,
            description="finding",
            severity=FindingSeverity.CRITICAL,
            scanner="native",
        )

    @staticmethod
    def _forms(*extra: Path):
        return lambda path: PathForms((path, *extra))

    def test_global_ignore_matches_another_name(self, tmp_path: Path):
        finding = self._finding(tmp_path / "repo" / "proj" / "app.env")
        filter_ = IgnoreFilter(IgnoreConfig(ignore_paths=["linkproj/**"]))

        assert filter_.filter([finding]) == [finding]
        assert filter_.filter([finding], self._forms(Path("linkproj/app.env"))) == []

    def test_rule_path_ignore_matches_another_name(self, tmp_path: Path):
        finding = self._finding(tmp_path / "repo" / "app.env")
        filter_ = IgnoreFilter(IgnoreConfig(ignore_rules={"github-pat": ["link.env"]}))

        assert filter_.filter([finding], self._forms(Path("link.env"))) == []

    def test_noisy_rule_path_matches_another_name(self, tmp_path: Path):
        finding = self._finding(tmp_path / "real.json", rule_id="generic-secret")
        filter_ = IgnoreFilter(IgnoreConfig(noisy_rule_paths=["package-lock.json"]))

        assert filter_.filter([finding], self._forms(Path("package-lock.json"))) == []

    def test_no_name_matches(self, tmp_path: Path):
        finding = self._finding(tmp_path / "app.env")
        filter_ = IgnoreFilter(IgnoreConfig(ignore_paths=["other/**"]))

        assert filter_.filter([finding], self._forms(Path("app.env"))) == [finding]

    def test_inline_ignore_reads_the_reported_file(self, tmp_path: Path):
        """The other names are only matched; the comment is read from the reported file."""
        reported = tmp_path / "app.env"
        reported.write_text("TOKEN=x  # envdrift:ignore\n")
        finding = self._finding(reported)

        assert IgnoreFilter().filter([finding], self._forms(tmp_path / "missing.env")) == []

    def test_plain_names_are_each_matched_on_their_own(self, tmp_path: Path):
        """11.0.9 took plain paths from ``path_forms``: each is matched as given."""
        finding = self._finding(tmp_path / "repo" / "app.env")

        def names(path: Path) -> tuple[Path, ...]:
            return (path, Path("linkproj/app.env"))

        assert (
            IgnoreFilter(IgnoreConfig(ignore_paths=["linkproj/**"])).filter([finding], names) == []
        )
        absolute = IgnoreConfig(ignore_paths=[f"{(tmp_path / 'repo').as_posix()}/**"])
        assert IgnoreFilter(absolute).filter([finding], names) == []
        assert IgnoreFilter(IgnoreConfig(ignore_paths=["/linkproj/**"])).filter(
            [finding], names
        ) == [finding]


class TestPathFormsMatching:
    """#859: relative patterns see relative names, absolute patterns absolute names."""

    @pytest.mark.parametrize(
        "pattern", ["/repo/x", "//server/share/x", "C:/repo/x", "c:\\repo\\x", "\\\\server\\x"]
    )
    def test_absolute_patterns(self, pattern: str):
        assert is_absolute_pattern(pattern)

    @pytest.mark.parametrize(
        "pattern", ["x", "**/build/**", "./x", "../config/*", "*/x", "C:x", "[/]x", "?x"]
    )
    def test_relative_patterns(self, pattern: str):
        assert not is_absolute_pattern(pattern)

    def test_relative_pattern_matches_a_name_and_its_trailing_parts(self):
        forms = PathForms((Path("deploy/config/settings.txt"),))

        assert forms.match(["deploy/config/*"])
        assert forms.match(["config/settings.txt"])
        assert forms.match(["settings.txt"])
        assert not forms.match(["deploy/settings.txt"])

    def test_relative_pattern_never_sees_an_absolute_name(self):
        """A checkout under ``build/``: ``**/build/**`` must not match (#859)."""
        forms = PathForms(
            relative=(Path("proj/app.env"), Path("/proj/app.env")),
            absolute=(Path("/ci/build/repo/proj/app.env"),),
        )

        assert not forms.match(["**/build/**", "build/**", "build/repo/proj/*", "repo/**"])
        assert forms.match(["**/proj/**"])

    def test_absolute_pattern_matches_an_absolute_name_whole(self):
        forms = PathForms(
            relative=(Path("proj/app.env"), Path("/proj/app.env")),
            absolute=(Path("/ci/build/repo/proj/app.env"),),
        )

        assert forms.match(["/ci/build/repo/proj/**"])
        assert forms.match(["/ci/build/**"])
        # Not a trailing part, and not the name rooted at the cwd.
        assert not forms.match(["/repo/proj/**"])
        assert not forms.match(["/proj/**"])

    def test_names_on_their_own_keep_the_historical_matching(self, tmp_path: Path):
        """Without a display, a finding path is matched as given, with its trailing parts.

        Built from a real anchor: on Windows a path without a drive is not absolute.
        """
        root = Path(tmp_path.anchor)
        path = root / "ci" / "build" / "repo" / "app.env"
        absolute = PathForms.of(path)
        relative = PathForms.of(Path("proj/app.env"))

        assert absolute.relative == absolute.absolute == (path,)
        assert absolute.match(["**/build/**"])
        assert absolute.match([f"{(root / 'ci').as_posix()}/**"])
        assert relative.absolute == ()
        assert not relative.match(["/proj/**"])

    def test_windows_names_are_compared_with_forward_slashes(self):
        """Patterns use ``/``; a Windows path's backslashes and drive must not stop a match."""
        forms = PathForms(
            relative=(
                PureWindowsPath(r"proj\sub\app.env"),
                PureWindowsPath(r"\proj\sub\app.env"),
            ),
            absolute=(PureWindowsPath(r"C:\ci\build\repo\proj\sub\app.env"),),
        )

        assert forms.match(["proj/sub/*"])
        assert forms.match(["**/sub/**"])
        assert forms.match(["sub/app.env"])
        assert forms.match(["C:/ci/build/repo/proj/**"])
        assert not forms.match(["**/build/**"])
        assert not forms.match(["D:/ci/**"])

    def test_windows_unc_path_matches_an_unc_pattern(self):
        forms = PathForms.of(PureWindowsPath(r"\\server\share\repo\config\app.env"))

        assert forms.match(["//server/share/repo/**"])
        assert forms.match(["config/app.env"])

    def test_file_on_another_drive_is_matched_absolute_with_its_trailing_parts(self):
        """``os.path.relpath`` raises across drives, so the file is shown absolute."""
        forms = PathForms.of(PureWindowsPath(r"D:\shared\config\settings.txt"))

        assert forms.match(["config/*"])
        assert forms.match(["D:/shared/**"])
        assert not forms.match(["C:/shared/**"])
