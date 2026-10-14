"""Tests for the file names detect-secrets is given: names git quotes, names like options."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from envdrift.scanner import detect_secrets as detect_secrets_module
from envdrift.scanner.detect_secrets import (
    DetectSecretsScanner,
    _check_git_file_list,
    _git_honors_config_env,
    _git_quotes,
    _is_undecodable,
)
from tests.scanner.detect_secrets_helpers import (
    add_files,
    fake_detect_secrets,
    init_repo,
    no_version_probe,  # noqa: F401  (autouse)
)


def _create_tracked(repo: Path, *names: str) -> None:
    """Like ``add_files``, but skips the test where the file system cannot hold such a name."""
    try:
        add_files(repo, *names)
    except OSError as exc:
        pytest.skip(f"this file system cannot hold the name: {exc}")


# Latin-1 "café": the byte 0xe9 that is not UTF-8, as Python reads it from a POSIX file name.
NOT_UTF8 = "caf\udce9.cfg"


NOT_UTF8_PLATFORM = pytest.mark.skipif(
    sys.platform == "win32", reason="Windows file names are UTF-16, never bytes that are not UTF-8"
)


class TestUnquotedGitPaths:
    """detect-secrets lists tracked files with ``git ls-files``, which quotes a name it escapes.

    Under git's default ``core.quotepath`` the list holds ``"caf\\303\\251.env"`` for ``café.env``.
    That names no file, so detect-secrets skipped the file in silence and the scan read as clean.
    The scan runs with the setting off instead, and says so for a name git quotes regardless.
    """

    @pytest.fixture
    def scanner(self) -> DetectSecretsScanner:
        return DetectSecretsScanner(auto_install=False)

    @pytest.fixture(autouse=True)
    def _no_git_settings_in_the_environment(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)

    @staticmethod
    def _scan(scanner: DetectSecretsScanner, target: Path):
        run, calls = fake_detect_secrets()
        with (
            patch.object(scanner, "_ensure_installed", return_value=None),
            patch("subprocess.run", side_effect=run),
        ):
            result = scanner.scan([target])
        (call,) = calls
        return result, call[1]["env"]

    @staticmethod
    def _quotepath_setting(env: dict[str, str]) -> tuple[str, str, str] | None:
        if "GIT_CONFIG_COUNT" not in env:
            return None
        return (env["GIT_CONFIG_COUNT"], env["GIT_CONFIG_KEY_0"], env["GIT_CONFIG_VALUE_0"])

    def test_the_scan_of_tracked_files_runs_with_core_quotepath_off(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = init_repo(tmp_path)
        add_files(repo, "app.cfg")

        result, env = self._scan(scanner, repo)

        assert self._quotepath_setting(env) == ("1", "core.quotepath", "false")
        assert result.warnings == []

    def test_the_rest_of_the_environment_is_passed_on(
        self, scanner: DetectSecretsScanner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("ENVDRIFT_TEST_MARKER", "kept")
        repo = init_repo(tmp_path)
        add_files(repo, "app.cfg")

        _result, env = self._scan(scanner, repo)

        assert env["ENVDRIFT_TEST_MARKER"] == "kept"

    def test_a_scan_that_does_not_use_gits_list_gets_the_environment_as_it_is(
        self, scanner: DetectSecretsScanner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setattr(detect_secrets_module, "get_git_root", lambda _path: None)

        _result, env = self._scan(scanner, tmp_path)

        assert self._quotepath_setting(env) is None

    def test_git_settings_the_user_already_exports_are_kept(self):
        environ = {
            "PATH": "/usr/bin",
            "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": "user.name",
            "GIT_CONFIG_VALUE_0": "someone",
            "GIT_CONFIG_KEY_1": "core.autocrlf",
            "GIT_CONFIG_VALUE_1": "input",
        }

        env = detect_secrets_module._with_unquoted_git_paths(environ)

        assert env == {
            **environ,
            "GIT_CONFIG_COUNT": "3",
            "GIT_CONFIG_KEY_2": "core.quotepath",
            "GIT_CONFIG_VALUE_2": "false",
        }
        # The mapping that was passed in is left alone.
        assert environ["GIT_CONFIG_COUNT"] == "2"
        assert "GIT_CONFIG_KEY_2" not in environ

    @pytest.mark.parametrize("count", ["", "junk", "-3", "1.5"])
    def test_a_count_git_cannot_use_is_replaced(self, count: str):
        env = detect_secrets_module._with_unquoted_git_paths({"GIT_CONFIG_COUNT": count})

        assert (env["GIT_CONFIG_COUNT"], env["GIT_CONFIG_KEY_0"], env["GIT_CONFIG_VALUE_0"]) == (
            "1",
            "core.quotepath",
            "false",
        )

    def test_a_non_ascii_name_is_scanned_not_reported(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = init_repo(tmp_path)
        _create_tracked(repo, "café.cfg", "sub/naïve.cfg")

        result, env = self._scan(scanner, repo)

        assert self._quotepath_setting(env) == ("1", "core.quotepath", "false")
        assert result.warnings == []

    @pytest.mark.skipif(sys.platform == "win32", reason="Windows file names cannot hold these")
    def test_names_git_quotes_whatever_the_setting_are_reported(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = init_repo(tmp_path)
        _create_tracked(repo, 'say "hi".cfg', "back\\slash.cfg", "new\nline.cfg", "plain.cfg")

        result, env = self._scan(scanner, repo)

        assert self._quotepath_setting(env) == ("1", "core.quotepath", "false")
        (warning,) = result.warnings
        assert warning.startswith(f"Not scanned in {repo}: git writes the name of 3 tracked ")
        for shown in (repr('say "hi".cfg'), repr("back\\slash.cfg"), repr("new\nline.cfg")):
            assert shown in warning
        assert "plain.cfg" not in warning
        # The message is one line of printable text, whatever the names hold.
        assert "\n" not in warning

    @pytest.mark.skipif(sys.platform == "win32", reason="Windows file names cannot hold these")
    def test_only_the_first_names_are_listed(self, scanner: DetectSecretsScanner, tmp_path: Path):
        repo = init_repo(tmp_path)
        _create_tracked(repo, *(f'q"{number}.cfg' for number in range(5)))

        (warning,) = self._scan(scanner, repo)[0].warnings

        assert "5 tracked file(s)" in warning
        assert warning.count('q"') == 3
        assert " and 2 more)" in warning

    @NOT_UTF8_PLATFORM
    def test_a_name_that_is_not_utf8_leaves_the_setting_alone_and_reports_every_quoted_name(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        """With the setting off detect-secrets cannot decode the list and fails the whole scan.

        The default is kept for such a repository, which skips every non-ASCII name, and each
        of them is reported.
        """
        repo = init_repo(tmp_path)
        _create_tracked(repo, NOT_UTF8, "café.cfg", "plain.cfg")

        result, env = self._scan(scanner, repo)

        assert self._quotepath_setting(env) is None
        (warning,) = result.warnings
        assert "the name of 2 tracked file(s)" in warning
        assert repr(NOT_UTF8) in warning
        assert repr("café.cfg") in warning
        assert "plain.cfg" not in warning

    @NOT_UTF8_PLATFORM
    def test_the_names_of_a_scan_below_a_subdirectory_are_those_below_it(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = init_repo(tmp_path)
        _create_tracked(repo, NOT_UTF8, "sub/plain.cfg")

        assert self._scan(scanner, repo / "sub")[0].warnings == []
        assert self._quotepath_setting(self._scan(scanner, repo / "sub")[1]) == (
            "1",
            "core.quotepath",
            "false",
        )

    def test_a_directory_that_tracks_nothing_gets_the_environment_as_it_is(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = init_repo(tmp_path)

        result, env = self._scan(scanner, repo)

        assert self._quotepath_setting(env) is None
        (warning,) = result.warnings
        assert warning.startswith("Scanned nothing in ")

    def test_a_git_that_cannot_list_files_leaves_the_environment_alone(self, tmp_path: Path):
        env, warnings = _check_git_file_list(tmp_path, None)

        assert warnings == []
        assert self._quotepath_setting(env) is None

    @pytest.mark.parametrize(
        ("output", "honors"),
        [
            ("git version 2.43.0\n", True),
            ("git version 2.31.0\n", True),
            ("git version 2.30.2\n", False),
            ("git version 2.25.1\n", False),
            ("git version 1.8.3.1\n", False),
            ("git version 2.39.3 (Apple Git-146)\n", True),
            ("git version 2.45.1.windows.1\n", True),
            ("git version 10.0.0\n", True),
            ("something else entirely\n", True),
            ("", True),
        ],
    )
    def test_which_gits_read_the_environment_setting(self, output: str, honors: bool):
        """``GIT_CONFIG_COUNT`` arrived in git 2.31; an older git ignores it."""
        with patch(
            "subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=output, stderr="")
        ):
            assert _git_honors_config_env() is honors

    @pytest.mark.parametrize("error", [OSError("no git"), subprocess.TimeoutExpired("git", 10)])
    def test_a_git_that_cannot_be_asked_is_taken_to_read_it(self, error: Exception):
        with patch("subprocess.run", side_effect=error):
            assert _git_honors_config_env() is True

    def test_an_old_git_leaves_the_environment_alone_and_non_ascii_names_are_reported(
        self, tmp_path: Path
    ):
        """It would ignore the setting, so a non-ASCII name stays quoted and is reported."""
        with patch.object(detect_secrets_module, "_git_honors_config_env", return_value=False):
            env, warnings = _check_git_file_list(tmp_path, ["café.cfg", "plain.cfg"])

        assert self._quotepath_setting(env) is None
        (warning,) = warnings
        assert "the name of 1 tracked file(s)" in warning
        assert repr("café.cfg") in warning
        assert "plain.cfg" not in warning

    def test_a_current_git_gets_the_setting(self, tmp_path: Path):
        with patch.object(detect_secrets_module, "_git_honors_config_env", return_value=True):
            env, warnings = _check_git_file_list(tmp_path, ["café.cfg", "plain.cfg"])

        assert self._quotepath_setting(env) == ("1", "core.quotepath", "false")
        assert warnings == []

    @pytest.mark.parametrize(
        ("name", "quotepath_off", "quoted"),
        [
            ("plain.cfg", False, False),
            ("with space/and-dash_1.cfg", False, False),
            ("café.cfg", False, True),
            ("café.cfg", True, False),
            ("文档/配置.cfg", False, True),
            ("文档/配置.cfg", True, False),
            ('say "hi".cfg', True, True),
            ("back\\slash.cfg", True, True),
            ("new\nline.cfg", True, True),
            ("tab\there.cfg", True, True),
            ("bell\x07.cfg", True, True),
            ("del\x7f.cfg", True, True),
            ("it's.cfg", True, False),
        ],
    )
    def test_which_names_git_quotes(self, name: str, quotepath_off: bool, quoted: bool):
        assert _git_quotes(name, quotepath_off=quotepath_off) is quoted

    def test_a_lone_surrogate_is_a_name_that_is_not_utf8(self):
        assert _is_undecodable(NOT_UTF8)
        assert not _is_undecodable("café.cfg")
        assert not _is_undecodable("plain.cfg")


class TestPathIsNotAnOption:
    """The path goes after ``--``, so a name that looks like an option stays a path.

    A tracked file called ``--exclude-files=^`` was read by argparse as an option that
    excludes everything, leaving no path to scan: the run printed an empty report and passed as
    clean. A directory called ``-sub`` made detect-secrets fail with a usage error instead.
    """

    @pytest.fixture
    def scanner(self) -> DetectSecretsScanner:
        return DetectSecretsScanner(auto_install=False)

    @staticmethod
    def _command(scanner: DetectSecretsScanner, target: Path) -> list[str]:
        run, calls = fake_detect_secrets()
        with (
            patch.object(scanner, "_ensure_installed", return_value=None),
            patch("subprocess.run", side_effect=run),
        ):
            scanner.scan([target])
        (call,) = calls
        return call[0]

    def test_a_file_named_like_an_option_follows_a_double_dash(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = init_repo(tmp_path)
        add_files(repo, "--exclude-files=^")

        args = self._command(scanner, repo / "--exclude-files=^")

        assert args[-2:] == ["--", "--exclude-files=^"]

    def test_a_directory_starting_with_a_dash_follows_a_double_dash(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = init_repo(tmp_path)
        add_files(repo, "-sub/a.cfg")

        args = self._command(scanner, repo / "-sub")

        assert args[-2:] == ["--", "-sub"]

    def test_the_options_come_before_the_double_dash(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = init_repo(tmp_path)
        add_files(repo, "app.cfg")

        args = self._command(scanner, repo)

        assert args.index("--force-use-all-plugins") < args.index("--exclude-files")
        assert args.index("--exclude-files") + 1 < args.index("--") == len(args) - 2
