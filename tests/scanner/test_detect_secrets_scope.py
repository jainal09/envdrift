"""Tests for which files detect-secrets scans: exclusions, scan plan, non-git and empty directories."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path, PurePath
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from envdrift.scanner import detect_secrets as detect_secrets_module
from envdrift.scanner.detect_secrets import (
    _EXCLUDED_DIRECTORIES,
    DetectSecretsScanner,
    _exclude_files_regex,
    _plan_scan,
    _scannable_tracked_names,
)
from tests.scanner.detect_secrets_helpers import (
    add_files,
    fake_detect_secrets,
    init_repo,
    no_version_probe,  # noqa: F401  (autouse)
)


class TestExcludePattern:
    """The ``--exclude-files`` pattern skips directories by name, never files or look-alikes."""

    @staticmethod
    def _path(separator: str, *parts: str) -> str:
        return separator.join(parts)

    @pytest.mark.parametrize("separator", ["/", "\\"])
    def test_a_directory_with_an_excluded_name_excludes_everything_below_it(self, separator: str):
        """git lists ``a/b``; a scan of all files builds ``a\\b`` on Windows (the OS separator)."""
        pattern = re.compile(_exclude_files_regex())

        for skipped in _EXCLUDED_DIRECTORIES:
            assert pattern.search(self._path(separator, skipped, "x.js")), skipped
            assert pattern.search(self._path(separator, "pkg", skipped, "deep", "x.js")), skipped

    @pytest.mark.parametrize("separator", ["/", "\\"])
    def test_look_alike_names_are_scanned(self, separator: str):
        pattern = re.compile(_exclude_files_regex())

        for scanned in (
            "app.py",
            "distance.py",
            "rebuild",
            "gitops",
            "node_modules_backup",
            "venv2",
        ):
            assert not pattern.search(self._path(separator, "src", scanned, "x.js")), scanned
            assert not pattern.search(self._path(separator, scanned, "x.js")), scanned

    @pytest.mark.parametrize("separator", ["/", "\\"])
    def test_a_file_named_like_an_excluded_directory_is_scanned(self, separator: str):
        """A script called ``build`` is a file, not a directory of build output."""
        pattern = re.compile(_exclude_files_regex())

        for name in _EXCLUDED_DIRECTORIES:
            assert not pattern.search(name), name
            assert not pattern.search(self._path(separator, "bin", name)), name

    def test_the_leading_components_are_never_looked_at(self):
        """They lead to the directory that was asked for, whatever it is called."""
        pattern = re.compile(_exclude_files_regex(2))

        assert not pattern.search("vendor/build/app.cfg")
        assert not pattern.search("build/dist/sub/app.cfg")
        assert not pattern.search("build/dist/build")
        assert pattern.search("vendor/app/node_modules/x.cfg")
        assert pattern.search("vendor\\app\\dist\\x.cfg")

    def test_no_leading_components_are_skipped_by_default(self):
        assert re.compile(_exclude_files_regex()).search("build/app.cfg")
        assert re.compile(_exclude_files_regex(0)).search("build/app.cfg")


class TestScanPlan:
    """``_plan_scan`` picks the directory detect-secrets runs in and the path it is given."""

    def test_a_file_is_scanned_from_its_own_directory(self, tmp_path: Path):
        target = tmp_path / "app.cfg"
        target.write_text("x = 1\n")

        plan = _plan_scan(target)

        assert plan.cwd == tmp_path
        assert plan.scan_path == "app.cfg"
        assert not plan.all_files
        assert plan.git_root is None

    def test_a_file_in_a_repository_is_scanned_the_same_way(self, tmp_path: Path):
        repo = init_repo(tmp_path)
        add_files(repo, "sub/app.cfg")

        plan = _plan_scan(repo / "sub" / "app.cfg")

        assert (plan.cwd, plan.scan_path, plan.all_files) == (repo / "sub", "app.cfg", False)

    def test_a_directory_outside_git_is_scanned_for_all_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setattr(detect_secrets_module, "get_git_root", lambda _path: None)

        plan = _plan_scan(tmp_path)

        assert (plan.cwd, plan.scan_path, plan.all_files) == (tmp_path, ".", True)
        assert plan.prefix == PurePath()
        assert plan.git_root is None
        assert plan.exclude == _exclude_files_regex()

    def test_the_top_level_of_a_repository_keeps_scanning_tracked_files(self, tmp_path: Path):
        repo = init_repo(tmp_path)

        plan = _plan_scan(repo)

        assert (plan.cwd, plan.scan_path, plan.all_files) == (repo, ".", False)
        assert plan.prefix == PurePath()
        assert plan.git_root is not None
        assert plan.git_root.samefile(repo)
        assert plan.exclude == _exclude_files_regex()

    def test_a_subdirectory_is_scanned_from_the_top_level_with_its_own_path(self, tmp_path: Path):
        """Run from the subdirectory, detect-secrets matches no file git lists (#851)."""
        repo = init_repo(tmp_path)
        (repo / "sub" / "deep").mkdir(parents=True)

        plan = _plan_scan(repo / "sub" / "deep")

        assert plan.cwd.samefile(repo)
        assert plan.scan_path == "sub/deep"
        assert not plan.all_files
        assert plan.prefix == PurePath("sub", "deep")
        assert plan.git_root is not None
        assert plan.git_root.samefile(repo)
        assert plan.exclude == _exclude_files_regex(2)

    def test_a_subdirectory_reached_through_a_symlink_is_planned_by_where_it_really_is(
        self, tmp_path: Path
    ):
        repo = tmp_path / "repo"
        repo.mkdir()
        init_repo(repo)
        (repo / "sub").mkdir()
        link = tmp_path / "link"
        try:
            link.symlink_to(repo, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("cannot create symlinks here")

        plan = _plan_scan(link / "sub")

        assert plan.prefix == PurePath("sub")
        assert plan.scan_path == "sub"

    def test_a_directory_whose_way_to_the_top_level_cannot_be_named_is_scanned_for_all_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Scanning every file beats scanning none."""
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        target = tmp_path / "target"
        target.mkdir()
        monkeypatch.setattr(detect_secrets_module, "get_git_root", lambda _path: elsewhere)

        plan = _plan_scan(target)

        assert (plan.cwd, plan.scan_path, plan.all_files) == (target, ".", True)
        assert plan.git_root is None


class TestFileNamesBelowTheScanPath:
    """The report names files from the directory detect-secrets ran in; findings are shown
    below the path the caller gave."""

    @staticmethod
    def _report(*names: str) -> dict[str, Any]:
        entry = {"type": "Slack Token", "line_number": 1, "hashed_secret": "ab"}
        return {"results": {name: [entry] for name in names}}

    def test_a_report_relative_to_the_scanned_directory_is_joined_to_it(self, tmp_path: Path):
        scanner = DetectSecretsScanner(auto_install=False)

        findings = scanner._parse_baseline(self._report("a.cfg", "deep/b.cfg"), tmp_path)

        assert [f.file_path for f in findings] == [tmp_path / "a.cfg", tmp_path / "deep" / "b.cfg"]

    def test_the_way_from_the_top_level_to_the_scanned_directory_is_dropped(self, tmp_path: Path):
        scanner = DetectSecretsScanner(auto_install=False)
        report = self._report("sub/deep/a.cfg", "sub/deep/more/b.cfg")

        findings = scanner._parse_baseline(report, tmp_path / "sub" / "deep", PurePath("sub/deep"))

        assert [f.file_path for f in findings] == [
            tmp_path / "sub" / "deep" / "a.cfg",
            tmp_path / "sub" / "deep" / "more" / "b.cfg",
        ]

    def test_a_name_that_does_not_start_with_the_prefix_is_kept_whole(self, tmp_path: Path):
        scanner = DetectSecretsScanner(auto_install=False)

        findings = scanner._parse_baseline(self._report("other/a.cfg"), tmp_path, PurePath("sub"))

        assert [f.file_path for f in findings] == [tmp_path / "other" / "a.cfg"]

    def test_a_prefix_that_is_only_part_of_a_name_is_not_dropped(self, tmp_path: Path):
        scanner = DetectSecretsScanner(auto_install=False)

        findings = scanner._parse_baseline(self._report("subway/a.cfg"), tmp_path, PurePath("sub"))

        assert [f.file_path for f in findings] == [tmp_path / "subway" / "a.cfg"]


class TestNonGitDirectories:
    """detect-secrets lists a directory's files with ``git ls-files``: nothing outside git."""

    @pytest.fixture
    def scanner(self) -> DetectSecretsScanner:
        return DetectSecretsScanner(auto_install=False)

    def _scan(self, scanner: DetectSecretsScanner, target: Path, **fake: Any):
        run, calls = fake_detect_secrets(**fake)
        with (
            patch.object(scanner, "_ensure_installed", return_value=None),
            patch("subprocess.run", side_effect=run),
        ):
            result = scanner.scan([target])
        (call,) = calls
        return result, call[0], call[1]

    def test_a_directory_outside_git_is_scanned_for_all_files(
        self, scanner: DetectSecretsScanner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setattr(detect_secrets_module, "get_git_root", lambda _path: None)

        _result, args, kwargs = self._scan(scanner, tmp_path)

        assert args[args.index("scan") + 1] == "--all-files"
        # The exclude pattern and the plugins are unchanged.
        assert args[args.index("--exclude-files") + 1] == _exclude_files_regex()
        assert "--force-use-all-plugins" in args
        assert args[-1] == "."
        assert Path(kwargs["cwd"]) == tmp_path

    def test_the_top_level_of_a_repository_keeps_scanning_tracked_files(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = init_repo(tmp_path)
        add_files(repo, "app.cfg")

        _result, args, kwargs = self._scan(scanner, repo)

        assert "--all-files" not in args
        assert args[-1] == "."
        assert Path(kwargs["cwd"]) == repo

    def test_a_subdirectory_of_a_repository_is_scanned_from_the_top_level(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        """From the subdirectory itself detect-secrets matched none of the files git lists."""
        repo = init_repo(tmp_path)
        add_files(repo, "sub/a.cfg")
        report = {
            "results": {
                "sub/a.cfg": [{"type": "Slack Token", "line_number": 1, "hashed_secret": "ab"}]
            }
        }

        result, args, kwargs = self._scan(scanner, repo / "sub", report=report)

        assert "--all-files" not in args
        assert args[-1] == "sub"
        assert Path(kwargs["cwd"]).samefile(repo)
        assert args[args.index("--exclude-files") + 1] == _exclude_files_regex(1)
        # The finding is shown below the path that was asked for.
        assert [f.file_path for f in result.findings] == [repo / "sub" / "a.cfg"]
        assert result.warnings == []

    def test_a_file_is_scanned_the_same_in_or_out_of_git(
        self, scanner: DetectSecretsScanner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        target = tmp_path / "app.cfg"
        target.write_text("x = 1\n")

        for in_git in (False, True):
            monkeypatch.setattr(
                detect_secrets_module,
                "get_git_root",
                lambda _path, in_git=in_git: tmp_path if in_git else None,
            )
            _result, args, kwargs = self._scan(scanner, target)
            assert "--all-files" not in args
            assert args[-1] == "app.cfg"
            assert Path(kwargs["cwd"]) == tmp_path

    def test_the_check_is_made_on_the_scanned_directory(
        self, scanner: DetectSecretsScanner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        sub = tmp_path / "sub"
        sub.mkdir()
        asked: list[Path] = []

        def get_git_root(path: Path) -> None:
            asked.append(path)

        monkeypatch.setattr(detect_secrets_module, "get_git_root", get_git_root)

        self._scan(scanner, sub)

        assert asked == [sub]

    def test_a_scan_that_listed_no_git_files_is_an_error_not_a_clean_run(
        self, scanner: DetectSecretsScanner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Belt and braces: if detect-secrets still finds no git work tree, nothing was scanned."""
        monkeypatch.setattr(detect_secrets_module, "get_git_root", lambda _path: None)
        notice = "Did not detect git repository. Try scanning all files instead."

        result, _args, _kwargs = self._scan(scanner, tmp_path, stderr=notice)

        assert result.error is not None
        assert "scanned nothing" in result.error
        assert str(tmp_path) in result.error
        assert result.findings == []


class TestNothingToScan:
    """In a repository detect-secrets scans what git tracks, and says nothing when that is
    nothing. The scanner must not let that pass for a clean run."""

    @pytest.fixture
    def scanner(self) -> DetectSecretsScanner:
        return DetectSecretsScanner(auto_install=False)

    @staticmethod
    def _scan(scanner: DetectSecretsScanner, target: Path):
        run, _calls = fake_detect_secrets()
        with (
            patch.object(scanner, "_ensure_installed", return_value=None),
            patch("subprocess.run", side_effect=run),
        ):
            return scanner.scan([target])

    def test_a_repository_that_tracks_nothing_warns(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = init_repo(tmp_path)
        (repo / "new.cfg").write_text("x = 1\n")

        result = self._scan(scanner, repo)

        assert result.error is None
        (warning,) = result.warnings
        assert warning.startswith("Scanned nothing in ")
        assert str(repo) in warning
        assert "git add" in warning

    def test_a_repository_that_tracks_a_file_does_not(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = init_repo(tmp_path)
        add_files(repo, "app.cfg")

        assert self._scan(scanner, repo).warnings == []

    def test_files_tracked_only_below_an_excluded_directory_count_as_nothing(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = init_repo(tmp_path)
        add_files(repo, "vendor/lib.cfg", "build/out.cfg")

        (warning,) = self._scan(scanner, repo).warnings

        assert warning.startswith("Scanned nothing in ")

    def test_a_subdirectory_that_tracks_nothing_warns_though_the_repository_does_not(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = init_repo(tmp_path)
        add_files(repo, "tracked/app.cfg")
        (repo / "untracked").mkdir()
        (repo / "untracked" / "new.cfg").write_text("x = 1\n")

        assert self._scan(scanner, repo / "tracked").warnings == []
        (warning,) = self._scan(scanner, repo / "untracked").warnings
        assert str(repo / "untracked") in warning

    def test_a_directory_named_like_an_excluded_one_is_not_nothing(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        """The directory that was asked for is scanned whatever it is called."""
        repo = init_repo(tmp_path)
        add_files(repo, "build/app.cfg")

        assert self._scan(scanner, repo / "build").warnings == []

    def test_a_directory_outside_git_is_never_warned_about(
        self, scanner: DetectSecretsScanner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setattr(detect_secrets_module, "get_git_root", lambda _path: None)

        assert self._scan(scanner, tmp_path).warnings == []

    def test_a_git_that_cannot_list_files_is_not_taken_for_an_empty_repository(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = init_repo(tmp_path)
        plan = _plan_scan(repo)
        real_run = subprocess.run

        def failing(args: list[str], **kwargs: Any):
            if args[:2] == ["git", "ls-files"]:
                return SimpleNamespace(returncode=128, stdout="", stderr="fatal")
            return real_run(args, **kwargs)

        with patch("subprocess.run", side_effect=failing):
            assert _scannable_tracked_names(plan) is None

        with patch("subprocess.run", side_effect=OSError("no git")):
            assert _scannable_tracked_names(plan) is None
