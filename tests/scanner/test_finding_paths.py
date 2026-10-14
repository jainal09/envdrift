"""One display form for the file paths of scan findings (#853, #855)."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from envdrift.scanner.base import FindingSeverity, ScanFinding, ScannerBackend, ScanResult
from envdrift.scanner.engine import GuardConfig, ScanEngine
from envdrift.scanner.finding_paths import FindingPathDisplay, display_path

# Visibly synthetic, and fragment-assembled so GitHub push protection never
# sees the whole literal. It keeps the 36-character shape the detectors match.
GITHUB_TOKEN = "ghp_" + "SYNTHETIC0TEST0TOKEN0FOR0UNIT0TESTS0"


def _finding(
    path: Path | str,
    *,
    scanner: str = "native",
    rule: str = "github-pat",
    description: str = "Secret detected",
) -> ScanFinding:
    return ScanFinding(
        file_path=Path(path),
        rule_id=rule,
        rule_description=rule,
        description=description,
        severity=FindingSeverity.CRITICAL,
        scanner=scanner,
        line_number=1,
        secret_hash="0123abcd",
    )


def _symlink(link: Path, target: Path) -> None:
    """Create ``link`` -> ``target``, skipping where symlinks need a privilege."""
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except OSError as exc:  # Windows without the symlink privilege
        pytest.skip(f"cannot create a symlink here: {exc}")


class TestDisplayPath:
    """``display_path``: relative to the cwd when under it, absolute otherwise."""

    @pytest.fixture
    def cwd(self, tmp_path: Path) -> Path:
        return tmp_path / "work"

    @pytest.mark.parametrize(
        ("path", "shown"),
        [
            ("proj/sub/app.env", "proj/sub/app.env"),
            ("app.env", "app.env"),
            ("./proj/../proj/app.env", "proj/app.env"),
        ],
    )
    def test_relative_path_under_the_cwd_stays_relative(self, cwd: Path, path: str, shown: str):
        assert display_path(Path(path), cwd) == Path(shown)

    def test_absolute_path_under_the_cwd_becomes_relative(self, cwd: Path):
        assert display_path(cwd / "proj" / "app.env", cwd) == Path("proj/app.env")

    def test_the_cwd_itself_is_shown_as_dot(self, cwd: Path):
        assert display_path(cwd, cwd) == Path()

    def test_absolute_path_outside_the_cwd_stays_absolute(self, tmp_path: Path, cwd: Path):
        outside = tmp_path / "other" / "app.env"

        assert display_path(outside, cwd) == outside

    def test_sibling_sharing_the_cwd_name_prefix_is_outside(self, tmp_path: Path, cwd: Path):
        sibling = tmp_path / "work-other" / "app.env"

        assert display_path(sibling, cwd) == sibling

    def test_parent_relative_path_becomes_absolute(self, tmp_path: Path, cwd: Path):
        assert display_path(Path("../other/app.env"), cwd) == tmp_path / "other" / "app.env"

    def test_path_on_another_drive_stays_absolute(self, tmp_path: Path, cwd: Path):
        """On Windows ``os.path.relpath`` raises ``ValueError`` across drives."""

        def other_drive(*_args: object) -> str:
            raise ValueError("path is on mount 'D:', start on mount 'C:'")

        with patch("envdrift.scanner.finding_paths.os.path.relpath", side_effect=other_drive):
            shown = display_path(cwd / "app.env", cwd)

        assert shown == cwd / "app.env"
        assert shown.is_absolute()

    def test_defaults_to_the_current_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.chdir(tmp_path)

        assert display_path(tmp_path / "app.env") == Path("app.env")

    def test_symlinks_are_not_resolved(self, tmp_path: Path):
        (tmp_path / "real").mkdir()
        _symlink(tmp_path / "link", tmp_path / "real")

        assert display_path(tmp_path / "link" / "app.env", tmp_path) == Path("link/app.env")

    @pytest.mark.parametrize(
        ("path", "shown"),
        [
            ("linkproj/../other/x.env", "repo/other/x.env"),
            ("<tmp>/linkproj/../other/x.env", "repo/other/x.env"),
            # Symlinks after the last ``..`` keep their names.
            ("linkproj/../linkother/x.env", "repo/linkother/x.env"),
        ],
    )
    def test_parent_reference_after_a_symlink_names_the_real_file(
        self, tmp_path: Path, path: str, shown: str
    ):
        """On POSIX ``..`` after a symlink names the link target's parent.

        Collapsed lexically, ``linkproj/../other/x.env`` named ``other/x.env``,
        a file that is not there (or another one).
        """
        (tmp_path / "repo" / "proj").mkdir(parents=True)
        (tmp_path / "repo" / "other").mkdir()
        (tmp_path / "repo" / "other" / "x.env").write_text("X=1\n")
        _symlink(tmp_path / "linkproj", tmp_path / "repo" / "proj")
        _symlink(tmp_path / "repo" / "linkother", tmp_path / "repo" / "other")
        given = Path(path.replace("<tmp>", str(tmp_path)))

        result = display_path(given, tmp_path)

        assert (tmp_path / result).resolve() == (tmp_path / given).resolve()
        if sys.platform != "win32":  # Windows collapses ``..`` lexically itself.
            assert result == Path(shown)

    def test_parent_reference_through_a_logical_prefix_keeps_its_form(self, tmp_path: Path):
        """A ``..`` that names the same file either way is collapsed lexically."""
        (tmp_path / "real" / "sub").mkdir(parents=True)
        _symlink(tmp_path / "link", tmp_path / "real")

        assert display_path(tmp_path / "link" / "sub" / ".." / "x.env", tmp_path) == Path(
            "link/x.env"
        )

    def test_unresolvable_parent_reference_is_collapsed(self, tmp_path: Path):
        real_resolve = Path.resolve

        def resolve(self: Path, strict: bool = False) -> Path:
            if ".." in self.parts:
                raise OSError("permission denied")
            return real_resolve(self, strict)

        with patch.object(Path, "resolve", resolve):
            assert display_path(Path("a/../b.env"), tmp_path) == Path("b.env")


class TestFindingPathDisplay:
    """``FindingPathDisplay``: a resolved path moves back under the scan path given."""

    @pytest.fixture
    def tree(self, tmp_path: Path) -> Path:
        """``repo/proj/sub/app.env`` with ``linkproj`` -> ``repo/proj``."""
        (tmp_path / "repo" / "proj" / "sub").mkdir(parents=True)
        (tmp_path / "repo" / "proj" / "sub" / "app.env").write_text("X=1\n")
        _symlink(tmp_path / "linkproj", tmp_path / "repo" / "proj")
        return tmp_path

    def test_without_symlinks_only_the_form_changes(self, tmp_path: Path):
        display = FindingPathDisplay([Path("proj")], cwd=tmp_path)

        assert display.path(tmp_path / "proj" / "app.env") == Path("proj/app.env")
        assert display.path(Path("proj/app.env")) == Path("proj/app.env")
        assert display.path(Path("../elsewhere.env")) == tmp_path.parent / "elsewhere.env"

    @pytest.mark.parametrize("absolute", [False, True], ids=["relative", "absolute"])
    def test_resolved_path_moves_under_the_symlinked_scan_path(self, tree: Path, absolute: bool):
        """The native scanner resolves the directory it walks (#853)."""
        scan_path = tree / "linkproj" if absolute else Path("linkproj")
        display = FindingPathDisplay([scan_path], cwd=tree)

        real = (tree / "repo" / "proj" / "sub" / "app.env").resolve()
        assert display.path(real) == Path("linkproj/sub/app.env")
        # The binaries' form, already under the link, stays put.
        assert display.path(Path("linkproj/sub/app.env")) == Path("linkproj/sub/app.env")

    def test_resolved_scan_path_itself_moves_to_the_link(self, tree: Path):
        display = FindingPathDisplay([Path("linkproj")], cwd=tree)

        assert display.path((tree / "repo" / "proj").resolve()) == Path("linkproj")

    def test_path_outside_every_symlinked_scan_path_keeps_its_place(self, tree: Path):
        (tree / "other").mkdir()
        display = FindingPathDisplay([Path("linkproj")], cwd=tree)

        assert display.path(tree / "other" / "x.env") == Path("other/x.env")

    def test_path_below_a_scan_path_as_given_is_not_moved(self, tree: Path):
        """``guard . linkproj``: a file the ``.`` scan found keeps its real place."""
        display = FindingPathDisplay([Path(), Path("linkproj")], cwd=tree)

        real = tree / "repo" / "proj" / "sub" / "app.env"
        assert display.path(real) == Path("repo/proj/sub/app.env")

    def test_deepest_symlinked_scan_path_wins(self, tree: Path):
        _symlink(tree / "linkrepo", tree / "repo")
        display = FindingPathDisplay([Path("linkrepo"), Path("linkproj")], cwd=tree)

        real = tree / "repo" / "proj" / "sub" / "app.env"
        assert display.path(real) == Path("linkproj/sub/app.env")
        assert display.path(tree / "repo" / "readme.txt") == Path("linkrepo/readme.txt")

    def test_symlinked_file_scan_path(self, tree: Path):
        """A symlinked file is scanned as its target and shown as the link."""
        _symlink(tree / "link.env", tree / "repo" / "proj" / "sub" / "app.env")
        display = FindingPathDisplay([Path("link.env")], cwd=tree)

        assert display.path(Path("repo/proj/sub/app.env")) == Path("link.env")

    def test_file_that_is_itself_a_symlink_is_not_followed(self, tree: Path):
        """Only the directory is resolved: a linked file stays where it was found."""
        (tree / "elsewhere").mkdir()
        (tree / "elsewhere" / "x.env").write_text("X=1\n")
        _symlink(tree / "repo" / "proj" / "inner.env", tree / "elsewhere" / "x.env")
        display = FindingPathDisplay([Path("linkproj")], cwd=tree)

        real_dir = (tree / "repo" / "proj").resolve()
        assert display.path(real_dir / "inner.env") == Path("linkproj/inner.env")

    def test_unresolvable_directory_keeps_the_path(self, tree: Path):
        """A directory that cannot be resolved (a symlink loop) is left where it is."""
        display = FindingPathDisplay([Path("linkproj")], cwd=tree)
        real_resolve = Path.resolve
        calls: list[Path] = []

        def resolve(self: Path, strict: bool = False) -> Path:
            if self.name == "sub":
                calls.append(self)
                raise RuntimeError(f"Symlink loop from {self!r}")
            return real_resolve(self, strict)

        sub = tree / "repo" / "proj" / "sub"
        with patch.object(Path, "resolve", resolve):
            assert display.path(sub / "app.env") == Path("repo/proj/sub/app.env")
            assert display.path(sub / "other.env") == Path("repo/proj/sub/other.env")

        assert calls == [sub], "each directory is resolved once"

    def test_unresolvable_scan_path_is_not_treated_as_symlinked(self, tree: Path):
        real_resolve = Path.resolve

        def resolve(self: Path, strict: bool = False) -> Path:
            if self.name == "linkproj":
                raise OSError("permission denied")
            return real_resolve(self, strict)

        with patch.object(Path, "resolve", resolve):
            display = FindingPathDisplay([Path("linkproj")], cwd=tree)

        real = tree / "repo" / "proj" / "sub" / "app.env"
        assert display.path(real) == Path("repo/proj/sub/app.env")

    def test_defaults_to_the_current_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.chdir(tmp_path)

        assert FindingPathDisplay([Path()]).path(tmp_path / "app.env") == Path("app.env")

    def test_finding_names_the_file_in_its_description_too(self, tmp_path: Path):
        """Native says "Run 'envdrift encrypt <path>'": the message must match the path."""
        raw = tmp_path / "proj" / ".env"
        finding = _finding(raw, description=f"Run 'envdrift encrypt {raw}' before committing.")

        shown = FindingPathDisplay([Path("proj")], cwd=tmp_path).finding(finding)

        assert shown.file_path == Path("proj/.env")
        assert shown.description == f"Run 'envdrift encrypt {Path('proj/.env')}' before committing."
        assert shown.rule_id == finding.rule_id
        assert shown.secret_hash == finding.secret_hash

    def test_description_keeps_longer_names_that_start_or_end_like_the_path(self, tmp_path: Path):
        """Only the path itself is renamed, not ``a.env.bak`` or ``/other/a.env``."""
        raw = tmp_path / "proj" / "a.env"
        other = tmp_path / "other" / "a.env"
        description = f"Run 'envdrift encrypt {raw}'. Not {raw}.bak, {other} or x{raw}."
        finding = _finding(raw, description=description)

        shown = FindingPathDisplay([Path("proj")], cwd=tmp_path).finding(finding)

        assert shown.description == (
            f"Run 'envdrift encrypt {Path('proj/a.env')}'. Not {raw}.bak, {other} or x{raw}."
        )

    def test_finding_already_in_display_form_is_returned_as_is(self, tmp_path: Path):
        finding = _finding("proj/.env")

        assert FindingPathDisplay([Path("proj")], cwd=tmp_path).finding(finding) is finding

    def test_findings_keeps_the_order(self, tmp_path: Path):
        findings = [_finding(tmp_path / "b.env"), _finding("a.env"), _finding(tmp_path / "c.env")]

        shown = FindingPathDisplay([Path()], cwd=tmp_path).findings(findings)

        assert [f.file_path for f in shown] == [Path("b.env"), Path("a.env"), Path("c.env")]

    def test_scan_path_with_a_parent_reference_after_a_symlink(self, tree: Path):
        """``guard linkproj/..`` scans ``repo``, and its files are shown there."""
        display = FindingPathDisplay([Path("linkproj/..")], cwd=tree)

        real = (tree / "repo" / "proj" / "sub" / "app.env").resolve()
        assert display.path(real) == Path("repo/proj/sub/app.env")


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
        _symlink(tmp_path / "linkproj", tmp_path / "repo" / "proj")
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
        _symlink(cwd / "linkproj", tmp_path / "build" / "proj")
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
        _symlink(physical / "linkproj", tmp_path / "other" / "proj")
        _symlink(tmp_path / "tmp", tmp_path / "private" / "x")
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
        _symlink(tmp_path / "elsewhere" / "link", cwd / "proj")
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
        _symlink(tmp_path / "link", tmp_path / "real")
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
        _symlink(tmp_path / "linkproj", tmp_path / "repo" / "proj")
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


class _FixedScanner(ScannerBackend):
    """A scanner that reports the findings it was built with."""

    def __init__(self, name: str, findings: list[ScanFinding]) -> None:
        self._name = name
        self._findings = findings

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return f"{self._name} stand-in"

    def is_installed(self) -> bool:
        return True

    def scan(self, paths: list[Path], include_git_history: bool = False) -> ScanResult:
        return ScanResult(scanner_name=self._name, findings=list(self._findings))


def _engine(
    *scanners: ScannerBackend,
    ignore_paths: list[str] | None = None,
    ignore_rules: dict[str, list[str]] | None = None,
) -> ScanEngine:
    engine = ScanEngine(
        GuardConfig(
            use_native=False,
            use_gitleaks=False,
            ignore_paths=ignore_paths or [],
            ignore_rules=ignore_rules or {},
        )
    )
    engine.scanners = list(scanners)
    return engine


class TestScanEngineDisplayPaths:
    """The engine shows every finding path in one form, after its filters (#855)."""

    @pytest.fixture(autouse=True)
    def _in_tmp(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        (tmp_path / "proj" / "sub").mkdir(parents=True)
        (tmp_path / "proj" / "sub" / "app.env").write_text(f"GITHUB_TOKEN={GITHUB_TOKEN}\n")
        monkeypatch.chdir(tmp_path)

    def test_one_form_per_file_across_scanners(self, tmp_path: Path):
        native = _FixedScanner("native", [_finding(tmp_path / "proj" / "sub" / "app.env")])
        gitleaks = _FixedScanner(
            "gitleaks", [_finding("proj/sub/app.env", scanner="gitleaks", rule="gitleaks-x")]
        )

        result = _engine(native, gitleaks).scan([Path("proj")])

        assert {f.file_path for f in result.unique_findings} == {Path("proj/sub/app.env")}
        assert {f.file_path for r in result.results for f in r.findings} == {
            Path("proj/sub/app.env")
        }

    def test_one_file_in_two_forms_from_one_scanner_is_one_finding(self, tmp_path: Path):
        """``guard proj proj/sub/app.env`` scans the file twice, in two forms."""
        scanner = _FixedScanner(
            "native",
            [_finding(tmp_path / "proj" / "sub" / "app.env"), _finding("proj/sub/app.env")],
        )

        result = _engine(scanner).scan([Path("proj"), Path("proj/sub/app.env")])

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
        native = _FixedScanner("native", [_finding(tmp_path / "proj" / "sub" / "app.env")])
        relative = _FixedScanner(
            "gitleaks", [_finding("proj/sub/app.env", scanner="gitleaks", rule="gitleaks-x")]
        )

        result = _engine(native, relative, ignore_paths=[pattern]).scan([Path("proj")])

        assert result.unique_findings == []

    def test_rule_path_ignores_match_the_shown_path(self, tmp_path: Path):
        native = _FixedScanner("native", [_finding(tmp_path / "proj" / "sub" / "app.env")])
        engine = _engine(native, ignore_rules={"github-pat": ["proj/sub/app.env"]})

        assert engine.scan([Path("proj")]).unique_findings == []

    def test_unmatched_path_pattern_still_reports(self, tmp_path: Path):
        native = _FixedScanner("native", [_finding(tmp_path / "proj" / "sub" / "app.env")])

        result = _engine(native, ignore_paths=["other/**"]).scan([Path("proj")])

        assert [f.file_path for f in result.unique_findings] == [Path("proj/sub/app.env")]

    def test_path_ignores_match_a_file_under_a_symlinked_scan_path(self, tmp_path: Path):
        """``linkproj/**`` suppresses what is shown as ``linkproj/...`` (#853, #855).

        The native scanner reports the file at its real location, which the
        pattern does not match.
        """
        _symlink(tmp_path / "linkproj", tmp_path / "proj")
        real = (tmp_path / "proj" / "sub" / "app.env").resolve()
        native = _FixedScanner("native", [_finding(real)])
        binary = _FixedScanner(
            "gitleaks", [_finding("linkproj/sub/app.env", scanner="gitleaks", rule="gitleaks-x")]
        )

        result = _engine(native, binary, ignore_paths=["linkproj/**"]).scan([Path("linkproj")])

        assert result.unique_findings == []

    def test_inline_ignore_reads_the_file_a_relative_path_names(self, tmp_path: Path):
        (tmp_path / "proj" / "sub" / "app.env").write_text("X=1  # envdrift:ignore\n")
        scanner = _FixedScanner("gitleaks", [_finding("proj/sub/app.env", scanner="gitleaks")])

        assert _engine(scanner).scan([Path("proj")]).unique_findings == []

    def test_description_names_the_file_like_the_finding(self, tmp_path: Path):
        raw = tmp_path / "proj" / "sub" / "app.env"
        scanner = _FixedScanner(
            "native", [_finding(raw, description=f"Run 'envdrift encrypt {raw}' first.")]
        )

        (finding,) = _engine(scanner).scan([Path("proj")]).unique_findings

        assert finding.description == f"Run 'envdrift encrypt {Path('proj/sub/app.env')}' first."

    def test_native_findings_under_a_symlinked_directory_show_the_link(self, tmp_path: Path):
        """The real native scanner resolves the directory it walks (#853, #855)."""
        _symlink(tmp_path / "linkproj", tmp_path / "proj")
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
        native = _FixedScanner("native", [_finding(repo / "proj" / "sub" / "app.env")])
        relative = _FixedScanner(
            "gitleaks", [_finding("proj/sub/app.env", scanner="gitleaks", rule="gitleaks-x")]
        )
        via_parent = _FixedScanner(
            "infisical",
            [_finding("../repo/proj/sub/app.env", scanner="infisical", rule="infisical-x")],
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
        result = _engine(*self._scanners(repo), ignore_paths=[pattern]).scan([Path()])

        assert {(f.scanner, f.file_path) for f in result.unique_findings} == {
            ("native", Path("proj/sub/app.env")),
            ("gitleaks", Path("proj/sub/app.env")),
            ("infisical", Path("proj/sub/app.env")),
        }

    @pytest.mark.parametrize("pattern", ["**/build/**", "build/repo/proj/sub/app.env"])
    def test_rule_path_ignores_do_not_match_above_the_cwd_either(self, repo: Path, pattern: str):
        native, _relative, _via_parent = self._scanners(repo)
        engine = _engine(native, ignore_rules={"github-pat": [pattern]})

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
        engine = _engine(*self._scanners(repo), ignore_paths=[f"{anchor}/**"])

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
        scanner = _FixedScanner("native", [_finding(copy)])

        result = _engine(scanner, ignore_paths=[pattern]).scan(
            [copy], aliases={(tmp_path / "tmp" / "envdrift-staged-x").resolve(): repo}
        )

        assert len(result.unique_findings) == kept

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
        self,
        repo: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        pattern: str,
        kept: int,
    ):
        """``guard --staged`` from a subdirectory: a staged file elsewhere (#859).

        Matched by its absolute path, ``**/build/**`` hid it in a checkout under
        ``build/``, where its copy in the temporary directory never had.
        """
        (repo / "other").mkdir()
        monkeypatch.chdir(repo / "other")
        copy = tmp_path / "tmp" / "envdrift-staged-x" / "proj" / "sub" / "app.env"
        copy.parent.mkdir(parents=True)
        copy.write_text(f"GITHUB_TOKEN={GITHUB_TOKEN}\n")
        scanner = _FixedScanner("native", [_finding(copy)])
        ignore = pattern.replace("<repo>", repo.as_posix())

        result = _engine(scanner, ignore_paths=[ignore]).scan(
            [copy], aliases={(tmp_path / "tmp" / "envdrift-staged-x").resolve(): repo}
        )

        assert len(result.unique_findings) == kept
