"""Tests for how path patterns see a file's names: path forms, relative and absolute (#855, #859)."""

from __future__ import annotations

import os
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


class TestBareNamePatterns:
    """#865: ``proj`` hides the files below a ``proj`` directory for every scanner's findings."""

    @pytest.fixture(autouse=True)
    def _in_tmp(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The findings name files that do not exist; inline comments are read from the cwd."""
        monkeypatch.chdir(tmp_path)

    @staticmethod
    def _finding(file_path: str, rule_id: str = "github-pat") -> ScanFinding:
        return ScanFinding(
            rule_id=rule_id,
            rule_description=rule_id,
            file_path=Path(file_path),
            line_number=1,
            description="finding",
            severity=FindingSeverity.CRITICAL,
            scanner="gitleaks",
        )

    def test_a_bare_ignore_path_hides_what_is_below_that_directory(self):
        below = self._finding("proj/sub/app.env")
        elsewhere = self._finding("tests/t.env")
        filter_ = IgnoreFilter(IgnoreConfig(ignore_paths=["proj"]))

        assert filter_.filter([below, elsewhere]) == [elsewhere]

    def test_a_bare_ignore_rule_path_hides_that_rule_below_that_directory_only(self):
        github = self._finding("proj/sub/app.env")
        other_rule = self._finding("proj/sub/app.env", rule_id="aws-access-token")
        elsewhere = self._finding("tests/t.env")
        filter_ = IgnoreFilter(IgnoreConfig(ignore_rules={"github-pat": ["proj"]}))

        assert filter_.filter([github, other_rule, elsewhere]) == [other_rule, elsewhere]

    def test_a_bare_noisy_default_is_matched_by_a_directory_it_names(self):
        """``*.lock`` names a directory ``deps.lock`` too; a trailing part never matched it."""
        noisy = self._finding("deps.lock/x.json", rule_id="generic-api-key")
        token = self._finding("deps.lock/x.json", rule_id="github-pat")
        filter_ = IgnoreFilter(IgnoreConfig(noisy_rule_paths=["*.lock"]))

        assert filter_.filter([noisy, token]) == [token]


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

    @pytest.mark.parametrize(
        ("pattern", "name", "expected"),
        [
            # A directory of that name anywhere in the path hides everything below it (#865).
            ("proj", "proj/sub/app.env", True),
            ("proj", "a/proj/app.env", True),
            ("proj", "proj", True),
            ("node_*", "web/node_modules/lib/index.js", True),
            ("*.env", "a/b/app.env", True),
            (".env*", "sub/.env.local", True),
            # A name is not a substring: the whole part has to match.
            ("proj", "myproj/app.env", False),
            ("proj", "projx/app.env", False),
            ("proj", "a/proj.env", False),
            # ``*`` does not cross ``/``: the first letter of ``apps`` is not the file's (#505).
            ("[!.]*.test", "apps/web/.env.test", False),
            ("[!.]*.test", "apps/web/app.test", True),
            ("*.env", "a/app.env.bak/x.txt", False),
        ],
    )
    def test_a_pattern_without_a_separator_names_a_directory_or_a_file_anywhere(
        self, pattern: str, name: str, expected: bool
    ):
        """``ignore_paths = ["proj"]`` hid ``proj/sub/app.env`` from the built-in scanner only (#865)."""
        assert PathForms((Path(name),)).match([pattern]) is expected

    def test_the_root_of_a_rooted_name_is_not_a_part(self):
        """``/tests/x.py`` is a form of ``tests/x.py``: its ``/`` is not a directory name."""
        assert not PathForms((Path("/tests/x.py"),)).match(["?"])
        assert not PathForms((PureWindowsPath(r"C:\ci\repo\x.py"),)).match(["C:*"])
        assert PathForms((PureWindowsPath(r"C:\ci\repo\x.py"),)).match(["repo"])

    def test_bare_names_are_what_a_pattern_without_a_separator_sees(self):
        """A file outside the cwd: the scan path's directories are no part of the project (#865)."""
        forms = PathForms(
            relative=(Path("/ci/build/repo/sub/app.env"),),
            absolute=(Path("/ci/build/repo/sub/app.env"),),
            bare=(Path("sub/app.env"),),
        )

        assert forms.match(["sub"])
        assert forms.match(["app.env"])
        assert not forms.match(["build"])
        assert not forms.match(["repo"])
        # A path pattern keeps the relative names (#859), an absolute one the absolute names.
        assert forms.match(["**/build/**"])
        assert forms.match(["/ci/build/**"])

    def test_a_plain_absolute_path_is_matched_by_a_pattern_without_a_separator_on_its_name(
        self, tmp_path: Path
    ):
        """Nothing says which of the directories above it belong to the project."""
        # Absolute on this platform: a rooted path without a drive is no absolute path on Windows.
        native = PathForms.of(tmp_path / "ci" / "build" / "repo" / "x.py")
        windows = PathForms.of(PureWindowsPath(r"C:\ci\build\repo\x.py"))

        for forms in (native, windows):
            assert forms.match(["x.py"])
            assert forms.match(["*.py"])
            assert not forms.match(["build"])
            assert not forms.match(["repo"])
        assert native.match(["**/build/**"])
        assert windows.match(["**/build/**"])

    def test_a_plain_relative_path_is_matched_by_each_of_its_parts(self):
        forms = PathForms.of(Path("a/proj/x.py"))

        assert forms.match(["proj"])
        assert forms.match(["a"])
        assert not forms.match(["proj/x"])

    @pytest.mark.skipif(os.name != "nt", reason="a backslash separates only on Windows")
    def test_a_pattern_with_a_backslash_is_a_path_pattern_on_windows(self):
        """``config\\settings.txt`` has no ``/`` but is no bare name: it matches a trailing part."""
        forms = PathForms.of(Path(r"deploy\config\settings.txt"))

        assert forms.match([r"config\settings.txt"])
        assert not forms.match([r"config\other.txt"])

    def test_a_pattern_with_a_separator_is_still_matched_as_a_path(self):
        forms = PathForms((Path("deploy/config/settings.txt"),))

        assert forms.match(["config/settings.txt"])
        assert forms.match(["deploy/*"])
        assert forms.match(["config"])  # a bare name matches the directory
        assert not forms.match(["config/other.txt"])

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
