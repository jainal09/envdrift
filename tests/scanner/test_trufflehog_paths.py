"""Unit tests for the trufflehog scanner's scan targets, finding paths and run errors (#906)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from envdrift.scanner.trufflehog import _git_uri, _logged_error, _scan_targets, _under


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def _repo_with_a_commit(root: Path) -> Path:
    root.mkdir(parents=True)
    _git(root, "init", "-q")
    (root / "app.env").write_text("APP_NAME=demo\n")
    _git(root, "add", "-A")
    _git(root, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", "init")
    return root


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
class TestHistoryTargets:
    """Which repository a history scan runs on, and when it cannot run (#906)."""

    @pytest.fixture(autouse=True)
    def _no_outer_repository(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # A repository around the test directory (say a mounted /tmp/.git) must not count.
        monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))

    def test_paths_in_one_repository_share_one_scan_of_its_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Relative in, relative out: the root comes back in the form of the path."""
        repo = _repo_with_a_commit(tmp_path / "repo")
        (repo / "sub").mkdir()
        monkeypatch.chdir(tmp_path)

        targets, errors = _scan_targets(
            [Path("repo/sub"), Path("repo/app.env"), repo], include_git_history=True
        )

        assert (targets, errors) == ([Path("repo")], [])

    def test_a_path_outside_a_repository_is_an_error(self, tmp_path: Path):
        """It used to be scanned as plain files, so a history scan quietly was none."""
        plain = tmp_path / "plain"
        plain.mkdir()

        targets, errors = _scan_targets([plain], include_git_history=True)

        assert targets == []
        assert errors == [f"Cannot scan Git history for {plain}: not inside a Git repository"]

    def test_a_repository_without_commits_is_an_error(self, tmp_path: Path):
        repo = tmp_path / "empty"
        repo.mkdir()
        _git(repo, "init", "-q")

        targets, errors = _scan_targets([repo], include_git_history=True)

        assert targets == []
        assert errors == [f"Cannot scan Git history for {repo}: the Git repository has no commits"]

    def test_a_path_that_cannot_be_scanned_keeps_the_others(self, tmp_path: Path):
        repo = _repo_with_a_commit(tmp_path / "repo")
        (tmp_path / "plain").mkdir()

        targets, errors = _scan_targets([tmp_path / "plain", repo], include_git_history=True)

        assert [target.resolve() for target in targets] == [repo.resolve()]
        assert len(errors) == 1

    def test_without_history_every_existing_path_is_a_target(self, tmp_path: Path):
        (tmp_path / "present").mkdir()

        targets, errors = _scan_targets(
            [tmp_path / "present", tmp_path / "missing"], include_git_history=False
        )

        assert (targets, errors) == ([tmp_path / "present"], [])


class TestGitUri:
    """The ``file://`` URI a history scan gives trufflehog, which parses it as a URL."""

    def test_a_posix_root_is_its_absolute_path(self):
        assert _git_uri(PurePosixPath("/work/repo")) == "file:///work/repo"

    def test_a_windows_drive_is_the_host_and_the_path_takes_forward_slashes(self):
        """``file://C:\\work\\repo`` does not parse: trufflehog tried it as an SSH URL."""
        assert _git_uri(PureWindowsPath(r"C:\work\repo")) == "file://C:/work/repo"

    def test_characters_a_url_reserves_are_percent_encoded(self):
        """A ``#`` would start a fragment and a ``%`` an escape."""
        assert _git_uri(PurePosixPath("/work/C#/100%/a b?")) == "file:///work/C%23/100%25/a%20b%3F"


class TestFindingPaths:
    """Files trufflehog names by the physical path it scanned are named under the target."""

    def test_a_file_below_the_physical_root_is_named_under_the_target(self):
        reported = Path("/work/elsewhere/proj/sub/app.env")

        named = _under(Path("linkproj"), Path("/work/elsewhere/proj"), reported)

        assert named == Path("linkproj/sub/app.env")

    def test_the_physical_file_itself_is_named_as_the_target(self):
        named = _under(Path("link.env"), Path("/work/app.env"), Path("/work/app.env"))

        assert named == Path("link.env")

    def test_a_path_already_under_the_target_is_kept(self):
        """A history path, relative to the repository root, was joined onto it already."""
        named = _under(Path("repo"), Path("/work/repo"), Path("repo/sub/app.env"))

        assert named == Path("repo/sub/app.env")


class TestLoggedError:
    """The error of a failed run is the message trufflehog logged, not its JSON log line."""

    def test_error_entries_are_quoted_as_message_and_error(self):
        stderr = (
            '{"level":"info-0","logger":"trufflehog","msg":"running source"}\n'
            '{"level":"error","logger":"trufflehog","msg":"error running scan",'
            '"error":"failed to scan Git: boom"}\n'
        )

        assert _logged_error(stderr) == "error running scan: failed to scan Git: boom"

    def test_output_that_is_no_json_log_is_kept(self):
        assert _logged_error("trufflehog: error: unknown flag\n") == (
            "trufflehog: error: unknown flag"
        )

    def test_a_log_without_an_error_entry_gives_nothing(self):
        assert _logged_error('{"level":"info-0","msg":"finished scanning"}\n') == ""
