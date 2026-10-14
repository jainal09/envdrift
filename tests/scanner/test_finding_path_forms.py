"""The names path-based ignores match a finding's file by (#855, #859)."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from envdrift.scanner.finding_paths import FindingPathDisplay
from tests.scanner.finding_paths_helpers import (
    symlink,
)


class TestFindingPathForms:
    """``FindingPathDisplay.forms``: the names path-based ignores match a file by (#855, #859)."""

    def test_relative_and_absolute_reports_of_one_file_share_its_names(self, tmp_path: Path):
        """``guard .`` reports ``proj/app.env`` where ``guard`` reports it absolute."""
        (tmp_path / "proj").mkdir()
        display = FindingPathDisplay([Path()], cwd=tmp_path)

        forms = display.forms(Path("proj/app.env"))

        assert forms == display.forms(tmp_path / "proj" / "app.env")
        assert forms.relative == (Path("proj/app.env"), Path(os.sep) / "proj" / "app.env")
        assert tmp_path / "proj" / "app.env" in forms.absolute

    @pytest.mark.parametrize("reported", ["relative", "absolute", "resolved"])
    def test_relative_names_of_a_file_under_the_cwd_stay_below_the_cwd(
        self, tmp_path: Path, reported: str
    ):
        """``**/build/**`` must not match a checkout that lives under ``build/`` (#859).

        The native scanner reports a resolved absolute path and ``guard`` with
        no path makes gitleaks and Infisical report absolute paths too: those
        are absolute names only, never matched by a relative pattern.
        """
        cwd = tmp_path / "build" / "repo"
        (cwd / "src").mkdir(parents=True)
        display = FindingPathDisplay([Path()], cwd=cwd)
        path = {
            "relative": Path("src/app.txt"),
            "absolute": cwd / "src" / "app.txt",
            "resolved": (cwd / "src" / "app.txt").resolve(),
        }[reported]

        forms = display.forms(path)

        assert forms.relative == (Path("src/app.txt"), Path(os.sep) / "src" / "app.txt")
        assert cwd / "src" / "app.txt" in forms.absolute

    def test_absolute_names_are_the_shown_path_the_absolute_report_and_the_real_location(
        self, tmp_path: Path
    ):
        """An absolute pattern sees the file wherever a scanner placed it (#859)."""
        (tmp_path / "repo" / "proj").mkdir(parents=True)
        symlink(tmp_path / "linkproj", tmp_path / "repo" / "proj")
        display = FindingPathDisplay([Path("linkproj")], cwd=tmp_path)
        real = (tmp_path / "repo" / "proj" / "app.env").resolve()

        assert set(display.forms(Path("linkproj/app.env")).absolute) == {
            tmp_path / "linkproj" / "app.env",
            real,
        }
        # The native scanner's resolved report is that real location.
        assert set(display.forms(real).absolute) == {tmp_path / "linkproj" / "app.env", real}

    def test_real_location_outside_the_cwd_is_only_an_absolute_name(self, tmp_path: Path):
        """A symlink target outside the cwd is named by its absolute path alone (#859)."""
        cwd = tmp_path / "work"
        cwd.mkdir()
        (tmp_path / "build" / "proj").mkdir(parents=True)
        symlink(cwd / "linkproj", tmp_path / "build" / "proj")
        display = FindingPathDisplay([Path("linkproj")], cwd=cwd)
        real = (tmp_path / "build" / "proj" / "app.env").resolve()

        forms = display.forms(Path("linkproj/app.env"))

        assert forms.relative == (Path("linkproj/app.env"), Path(os.sep) / "linkproj" / "app.env")
        assert real in forms.absolute

    def test_file_outside_the_cwd_keeps_its_reported_and_absolute_names(self, tmp_path: Path):
        """Outside the cwd the names are what they were: ``../config/*`` matches the report."""
        cwd = tmp_path / "repo" / "sub"
        cwd.mkdir(parents=True)
        display = FindingPathDisplay([Path("../config/settings.txt")], cwd=cwd)
        shown = tmp_path / "repo" / "config" / "settings.txt"

        forms = display.forms(Path("../config/settings.txt"))

        assert forms.relative[0] == Path("../config/settings.txt")
        assert shown in forms.relative
        assert len(forms.relative) == len(set(forms.relative))
        assert forms.absolute == (shown,)

    def test_path_on_another_drive_is_named_like_a_file_outside_the_cwd(self, tmp_path: Path):
        """On Windows ``os.path.relpath`` raises ``ValueError`` across drives (#859).

        Such a file stays absolute, and its absolute path is matched with its
        trailing parts as for any file outside the cwd.
        """
        cwd = tmp_path / "repo"
        cwd.mkdir()
        elsewhere = tmp_path / "shared" / "config" / "settings.txt"

        def other_drive(*_args: object) -> str:
            raise ValueError("path is on mount 'D:', start on mount 'C:'")

        display = FindingPathDisplay([elsewhere], cwd=cwd)
        with patch("envdrift.scanner.finding_paths.os.path.relpath", side_effect=other_drive):
            assert display.path(elsewhere) == elsewhere
            forms = display.forms(elsewhere)

        assert forms.relative == (elsewhere,)
        assert forms.absolute == (elsewhere,)
        assert forms.match(["config/*"])

    def test_file_under_the_cwd_is_named_below_it_when_relpath_fails(self, tmp_path: Path):
        """Whether a file is under the cwd does not hang on ``os.path.relpath``."""
        (tmp_path / "build" / "repo").mkdir(parents=True)
        cwd = tmp_path / "build" / "repo"

        def other_drive(*_args: object) -> str:
            raise ValueError("path is on mount 'D:', start on mount 'C:'")

        display = FindingPathDisplay([Path()], cwd=cwd)
        with patch("envdrift.scanner.finding_paths.os.path.relpath", side_effect=other_drive):
            forms = display.forms(cwd / "config" / "settings.txt")

        assert forms.relative == (
            Path("config/settings.txt"),
            Path(os.sep) / "config" / "settings.txt",
        )
        assert not forms.match(["**/build/**"])

    @pytest.mark.parametrize("target", ["proj", "linkproj"])
    def test_path_through_another_spelling_of_the_cwd_is_named_below_the_cwd(
        self, tmp_path: Path, target: str
    ):
        """``guard "$PWD/proj"`` where ``/tmp`` links to ``/private/tmp`` (#859).

        The cwd is the physical directory, so a path through the symlinked
        spelling is shown absolute, and its trailing parts named the
        directories above the checkout: ``**/build/**`` hid the file. Below a
        symlink to elsewhere (``linkproj``) the real location does not tell.
        """
        physical = tmp_path / "private" / "x" / "build" / "repo"
        (physical / "proj").mkdir(parents=True)
        (tmp_path / "other" / "proj").mkdir(parents=True)
        symlink(physical / "linkproj", tmp_path / "other" / "proj")
        symlink(tmp_path / "tmp", tmp_path / "private" / "x")
        logical = tmp_path / "tmp" / "build" / "repo"
        display = FindingPathDisplay([logical / target], cwd=physical)
        reported = logical / target / "sub" / "app.env"

        forms = display.forms(reported)

        assert display.path(reported).is_absolute()
        assert forms.relative[:2] == (
            Path(target) / "sub" / "app.env",
            Path(os.sep) / target / "sub" / "app.env",
        )
        assert reported in forms.absolute
        assert not forms.match(["**/build/**", "**/tmp/**", "build/repo/**", "repo/**"])
        assert forms.match([f"{target}/**"])

    def test_real_location_under_the_cwd_names_a_file_shown_elsewhere(self, tmp_path: Path):
        """A symlink outside the cwd to a directory under it: the real location counts."""
        cwd = tmp_path / "build" / "repo"
        (cwd / "proj").mkdir(parents=True)
        (tmp_path / "elsewhere").mkdir()
        symlink(tmp_path / "elsewhere" / "link", cwd / "proj")
        display = FindingPathDisplay([tmp_path / "elsewhere" / "link"], cwd=cwd)
        reported = tmp_path / "elsewhere" / "link" / "sub" / "app.env"

        forms = display.forms(reported)

        assert forms.relative == (
            Path("proj/sub/app.env"),
            Path(os.sep) / "proj" / "sub" / "app.env",
        )
        assert reported in forms.absolute
        assert not forms.match(["**/build/**", "**/elsewhere/**", "link/**"])
        assert forms.match([f"{(tmp_path / 'elsewhere').as_posix()}/**"])

    def test_path_through_a_symlinked_cwd_is_named_below_its_real_location(self, tmp_path: Path):
        """A cwd given through a symlink (a Windows junction or ``subst`` drive).

        A scanner given the physical path reports a file that ``os.path.relpath``
        places outside the cwd's spelling, though it is under the cwd.
        """
        (tmp_path / "real" / "proj").mkdir(parents=True)
        symlink(tmp_path / "link", tmp_path / "real")
        display = FindingPathDisplay([tmp_path / "real" / "proj"], cwd=tmp_path / "link")
        reported = tmp_path / "real" / "proj" / "app.env"

        forms = display.forms(reported)

        assert display.path(reported).is_absolute()
        assert forms.relative == (Path("proj/app.env"), Path(os.sep) / "proj" / "app.env")
        assert not forms.match(["**/real/**"])
        assert forms.match([f"{(tmp_path / 'real').as_posix()}/**"])

    @pytest.mark.parametrize("absolute", [False, True], ids=["relative", "absolute"])
    def test_file_below_a_symlinked_scan_path_is_named_by_link_and_real_location(
        self, tmp_path: Path, absolute: bool
    ):
        (tmp_path / "repo" / "proj" / "sub").mkdir(parents=True)
        symlink(tmp_path / "linkproj", tmp_path / "repo" / "proj")
        scan_path = tmp_path / "linkproj" if absolute else Path("linkproj")
        display = FindingPathDisplay([scan_path], cwd=tmp_path)
        real = (tmp_path / "repo" / "proj" / "sub" / "app.env").resolve()

        for reported in (real, Path("linkproj/sub/app.env")):
            relative = display.forms(reported).relative
            assert Path("linkproj/sub/app.env") in relative
            assert Path(os.sep) / "linkproj" / "sub" / "app.env" in relative
            assert Path("repo/proj/sub/app.env") in relative
            assert Path(os.sep) / "repo" / "proj" / "sub" / "app.env" in relative

    def test_names_are_computed_once_per_path(self, tmp_path: Path):
        display = FindingPathDisplay([Path()], cwd=tmp_path)

        assert display.forms(Path("a.env")) is display.forms(Path("a.env"))

    def test_unresolvable_real_location_is_left_out(self, tmp_path: Path):
        display = FindingPathDisplay([Path()], cwd=tmp_path)
        real_resolve = Path.resolve

        def resolve(self: Path, strict: bool = False) -> Path:
            if self.name == "loop.env":
                raise RuntimeError(f"Symlink loop from {self!r}")
            return real_resolve(self, strict)

        with patch.object(Path, "resolve", resolve):
            forms = display.forms(Path("loop.env"))

        assert forms.relative == (Path("loop.env"), Path(os.sep) / "loop.env")
        assert forms.absolute == (tmp_path / "loop.env",)


class TestBareNamesOutsideTheCwd:
    """A pattern without a separator never sees the directories above a scan path (#865).

    Under the cwd it is matched by the names below it. Outside, the scan path is the only
    root there is, as for the built-in scanner, which matches the path below the scan path.
    """

    @pytest.fixture
    def work(self, tmp_path: Path) -> Path:
        """The cwd, next to a checkout at ``build/repo``."""
        cwd = tmp_path / "work"
        cwd.mkdir()
        repo = tmp_path / "build" / "repo"
        (repo / "sub").mkdir(parents=True)
        (repo / "sub" / "app.env").write_text("X=1\n")
        (repo / "node_modules" / "x").mkdir(parents=True)
        (repo / "node_modules" / "x" / "lib.js").write_text("x\n")
        return cwd

    @staticmethod
    def _repo(work: Path) -> Path:
        return work.parent / "build" / "repo"

    @pytest.mark.parametrize(
        ("scan_path", "above", "below"),
        [
            ("../build/repo", ["build", "repo"], ["sub", "app.env", "*.env"]),
            ("<repo>", ["build", "repo"], ["sub", "app.env", "*.env"]),
            ("../build", ["build"], ["repo", "sub", "app.env"]),
            ("<repo>/sub", ["build", "repo", "sub"], ["app.env"]),
        ],
        ids=["relative", "absolute", "parent", "subdirectory"],
    )
    def test_the_directories_at_and_above_the_scan_path_are_no_part_of_the_name(
        self, work: Path, scan_path: str, above: list[str], below: list[str]
    ):
        repo = self._repo(work)
        scan = Path(scan_path.replace("<repo>", str(repo)))
        forms = FindingPathDisplay([scan], cwd=work).forms(repo / "sub" / "app.env")

        assert not forms.match([work.parent.name]), "a directory of the temporary tree"
        for name in above:
            assert not forms.match([name]), name
        for name in below:
            assert forms.match([name]), name

    def test_every_directory_below_the_scan_path_is_a_part(self, work: Path):
        repo = self._repo(work)
        display = FindingPathDisplay([repo], cwd=work)

        forms = display.forms(repo / "node_modules" / "x" / "lib.js")

        assert forms.match(["node_modules"])
        assert forms.match(["x"])
        assert forms.match(["lib.js"])
        assert not forms.match(["build"])
        assert not forms.match(["repo"])

    def test_a_file_given_as_the_scan_path_has_only_its_own_name(self, work: Path):
        file = self._repo(work) / "sub" / "app.env"
        forms = FindingPathDisplay([file], cwd=work).forms(file)

        assert forms.match(["app.env"])
        assert not forms.match(["sub"])
        assert not forms.match(["build"])

    def test_a_file_below_no_scan_path_has_only_its_own_name(self, work: Path):
        """``--pr-base`` run from a subdirectory names changed files outside it one by one."""
        file = self._repo(work) / "sub" / "app.env"
        forms = FindingPathDisplay([work / "other.env"], cwd=work).forms(file)

        assert forms.match(["app.env"])
        assert not forms.match(["sub"])

    def test_the_scan_path_below_which_the_real_location_lies_is_looked_through(self, work: Path):
        """A native scanner reports the real location of a file below a symlinked scan path."""
        repo = self._repo(work)
        elsewhere = work.parent / "linked"
        symlink(elsewhere, repo)
        display = FindingPathDisplay([elsewhere], cwd=work)

        forms = display.forms(repo / "sub" / "app.env")

        assert forms.match(["sub"])
        assert not forms.match(["build"])
        assert not forms.match(["repo"])

    def test_a_path_pattern_still_sees_the_directories_above_the_scan_path(self, work: Path):
        """``**/build/**`` is documented to match here (#859); only bare names are scoped."""
        repo = self._repo(work)
        forms = FindingPathDisplay([repo], cwd=work).forms(repo / "sub" / "app.env")

        assert forms.match(["**/build/**"])
        assert forms.match(["repo/sub/*"])

    def test_a_file_under_the_cwd_is_named_below_the_cwd(self, tmp_path: Path):
        (tmp_path / "build" / "repo" / "sub").mkdir(parents=True)
        cwd = tmp_path / "build" / "repo"
        forms = FindingPathDisplay([Path()], cwd=cwd).forms(Path("sub/app.env"))

        assert forms.bare == ()
        assert forms.match(["sub"])
        assert not forms.match(["build"])
        assert not forms.match(["repo"])


class TestScannedCopyForms:
    """``guard --staged`` scans temporary copies: ignores match the staged file (#859)."""

    @pytest.fixture
    def mirror(self, tmp_path: Path) -> Path:
        """A copy of ``config/app.env`` in a temporary directory named like a glob would."""
        copy = tmp_path / "tmp" / "envdrift-staged-x" / "config" / "app.env"
        copy.parent.mkdir(parents=True)
        copy.write_text("X=1\n")
        return copy

    @pytest.fixture
    def repo(self, tmp_path: Path) -> Path:
        """The checkout the mirror copies, under a directory named ``build``."""
        repo = tmp_path / "build" / "repo"
        (repo / "sub").mkdir(parents=True)
        return repo

    @staticmethod
    def _aliases(mirror: Path, repo: Path) -> dict[Path, Path]:
        return {(mirror.parents[1]).resolve(): repo}

    def test_copy_is_named_by_the_staged_file_under_the_cwd(self, repo: Path, mirror: Path):
        display = FindingPathDisplay([mirror], cwd=repo, aliases=self._aliases(mirror, repo))

        forms = display.forms(mirror)

        assert forms.relative == (Path("config/app.env"), Path(os.sep) / "config" / "app.env")
        assert forms.absolute == (repo / "config" / "app.env",)
        assert not forms.match(["tmp/**", "**/envdrift-staged-*/**", "**/build/**"])
        # The copy itself is still shown where it is; guard rewrites it afterwards.
        assert display.path(mirror) == mirror

    def test_copy_of_a_file_outside_the_cwd_is_named_by_its_path_in_the_repository(
        self, repo: Path, mirror: Path
    ):
        """Run from a subdirectory, a staged file elsewhere is outside the cwd.

        Its absolute path named the directories above the checkout, so
        ``**/build/**`` hid it where its copy never had (#859).
        """
        staged = repo / "config" / "app.env"
        display = FindingPathDisplay(
            [mirror], cwd=repo / "sub", aliases=self._aliases(mirror, repo)
        )

        forms = display.forms(mirror)

        assert forms.relative == (Path("config/app.env"), Path(os.sep) / "config" / "app.env")
        assert forms.absolute == (staged,)
        assert not forms.match(["**/build/**", "build/**", "repo/**", "tmp/**"])
        # As the copy's path below the temporary directory always matched.
        assert forms.match(["config/*"])
        assert forms.match(["**/config/**"])
        assert forms.match([f"{repo.as_posix()}/config/**"])

    def test_path_that_cannot_be_resolved_is_no_copy(self, repo: Path, mirror: Path):
        real_resolve = Path.resolve

        def resolve(self: Path, strict: bool = False) -> Path:
            if self.name == "app.env":
                raise OSError("permission denied")
            return real_resolve(self, strict)

        display = FindingPathDisplay([mirror], cwd=repo, aliases=self._aliases(mirror, repo))
        with patch.object(Path, "resolve", resolve):
            forms = display.forms(mirror)

        assert forms.relative == (mirror,)

    def test_path_that_is_no_copy_keeps_its_own_names(
        self, tmp_path: Path, repo: Path, mirror: Path
    ):
        display = FindingPathDisplay([Path()], cwd=tmp_path, aliases=self._aliases(mirror, repo))

        assert display.forms(Path("other.env")).relative == (
            Path("other.env"),
            Path(os.sep) / "other.env",
        )
