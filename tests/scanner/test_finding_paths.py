"""One display form for the file paths of scan findings (#853, #855)."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from envdrift.scanner.finding_paths import FindingPathDisplay, display_path
from tests.scanner.finding_paths_helpers import (
    make_finding,
    symlink,
)


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
        symlink(tmp_path / "link", tmp_path / "real")

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
        symlink(tmp_path / "linkproj", tmp_path / "repo" / "proj")
        symlink(tmp_path / "repo" / "linkother", tmp_path / "repo" / "other")
        given = Path(path.replace("<tmp>", str(tmp_path)))

        result = display_path(given, tmp_path)

        assert (tmp_path / result).resolve() == (tmp_path / given).resolve()
        if sys.platform != "win32":  # Windows collapses ``..`` lexically itself.
            assert result == Path(shown)

    def test_parent_reference_through_a_logical_prefix_keeps_its_form(self, tmp_path: Path):
        """A ``..`` that names the same file either way is collapsed lexically."""
        (tmp_path / "real" / "sub").mkdir(parents=True)
        symlink(tmp_path / "link", tmp_path / "real")

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
        symlink(tmp_path / "linkproj", tmp_path / "repo" / "proj")
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
        symlink(tree / "linkrepo", tree / "repo")
        display = FindingPathDisplay([Path("linkrepo"), Path("linkproj")], cwd=tree)

        real = tree / "repo" / "proj" / "sub" / "app.env"
        assert display.path(real) == Path("linkproj/sub/app.env")
        assert display.path(tree / "repo" / "readme.txt") == Path("linkrepo/readme.txt")

    def test_symlinked_file_scan_path(self, tree: Path):
        """A symlinked file is scanned as its target and shown as the link."""
        symlink(tree / "link.env", tree / "repo" / "proj" / "sub" / "app.env")
        display = FindingPathDisplay([Path("link.env")], cwd=tree)

        assert display.path(Path("repo/proj/sub/app.env")) == Path("link.env")

    def test_file_that_is_itself_a_symlink_is_not_followed(self, tree: Path):
        """Only the directory is resolved: a linked file stays where it was found."""
        (tree / "elsewhere").mkdir()
        (tree / "elsewhere" / "x.env").write_text("X=1\n")
        symlink(tree / "repo" / "proj" / "inner.env", tree / "elsewhere" / "x.env")
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
        finding = make_finding(raw, description=f"Run 'envdrift encrypt {raw}' before committing.")

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
        finding = make_finding(raw, description=description)

        shown = FindingPathDisplay([Path("proj")], cwd=tmp_path).finding(finding)

        assert shown.description == (
            f"Run 'envdrift encrypt {Path('proj/a.env')}'. Not {raw}.bak, {other} or x{raw}."
        )

    def test_finding_already_in_display_form_is_returned_as_is(self, tmp_path: Path):
        finding = make_finding("proj/.env")

        assert FindingPathDisplay([Path("proj")], cwd=tmp_path).finding(finding) is finding

    def test_findings_keeps_the_order(self, tmp_path: Path):
        findings = [
            make_finding(tmp_path / "b.env"),
            make_finding("a.env"),
            make_finding(tmp_path / "c.env"),
        ]

        shown = FindingPathDisplay([Path()], cwd=tmp_path).findings(findings)

        assert [f.file_path for f in shown] == [Path("b.env"), Path("a.env"), Path("c.env")]

    def test_scan_path_with_a_parent_reference_after_a_symlink(self, tree: Path):
        """``guard linkproj/..`` scans ``repo``, and its files are shown there."""
        display = FindingPathDisplay([Path("linkproj/..")], cwd=tree)

        real = (tree / "repo" / "proj" / "sub" / "app.env").resolve()
        assert display.path(real) == Path("repo/proj/sub/app.env")
