"""Tests for the file names detect-secrets is given: names git quotes, names like options."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from envdrift.scanner import detect_secrets as detect_secrets_module
from envdrift.scanner.detect_secrets import (
    DetectSecretsScanner,
    _check_git_file_list,
    _plan_scan,
    _with_git_quotepath,
)
from tests.scanner.detect_secrets_helpers import (
    add_files,
    fake_detect_secrets,
    init_repo,
    isolated_git_config,  # noqa: F401  (fixture)
    no_version_probe,  # noqa: F401  (autouse)
    requires_git_config_env,
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


@pytest.mark.usefixtures("isolated_git_config")
class TestUnquotedGitPaths:
    """detect-secrets lists tracked files with ``git ls-files``, which quotes a name it escapes.

    Under git's default ``core.quotepath`` the list holds ``"caf\\303\\251.env"`` for ``café.env``.
    That names no file, so detect-secrets skipped the file in silence and the scan read as clean.
    The scan runs with the setting off instead, and says so for a name git quotes regardless.
    """

    @pytest.fixture
    def scanner(self) -> DetectSecretsScanner:
        return DetectSecretsScanner(auto_install=False)

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

        env = _with_git_quotepath(environ, quoted=False)

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
        env = _with_git_quotepath({"GIT_CONFIG_COUNT": count}, quoted=False)

        assert (env["GIT_CONFIG_COUNT"], env["GIT_CONFIG_KEY_0"], env["GIT_CONFIG_VALUE_0"]) == (
            "1",
            "core.quotepath",
            "false",
        )

    def test_quoting_can_be_asked_for_too(self):
        env = _with_git_quotepath({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "a.b"}, quoted=True)

        assert (env["GIT_CONFIG_COUNT"], env["GIT_CONFIG_KEY_1"], env["GIT_CONFIG_VALUE_1"]) == (
            "2",
            "core.quotepath",
            "true",
        )

    @requires_git_config_env
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
        assert warning.startswith(
            f"Not scanned in {repo}: detect-secrets cannot match the name of 3 tracked "
        )
        for shown in (repr('say "hi".cfg'), repr("back\\slash.cfg"), repr("new\nline.cfg")):
            assert shown in warning
        assert "plain.cfg" not in warning
        # The message is one line of printable text, whatever the names hold.
        assert "\n" not in warning

    @pytest.mark.skipif(sys.platform == "win32", reason="Windows file names cannot hold these")
    def test_a_carriage_return_in_a_name_is_reported_as_it_is(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        """git's output is read as bytes: a text-mode read turns the ``\\r`` into a newline."""
        repo = init_repo(tmp_path)
        _create_tracked(repo, "carriage\rreturn.cfg", "plain.cfg")

        (warning,) = self._scan(scanner, repo)[0].warnings

        assert repr("carriage\rreturn.cfg") in warning

    @pytest.mark.skipif(sys.platform == "win32", reason="Windows file names cannot hold these")
    def test_only_the_first_names_are_listed(self, scanner: DetectSecretsScanner, tmp_path: Path):
        repo = init_repo(tmp_path)
        _create_tracked(repo, *(f'q"{number}.cfg' for number in range(5)))

        (warning,) = self._scan(scanner, repo)[0].warnings

        assert "5 tracked file(s)" in warning
        assert warning.count('q"') == 3
        assert " and 2 more)" in warning

    @NOT_UTF8_PLATFORM
    def test_a_name_that_is_not_utf8_pins_quoting_on_and_reports_every_quoted_name(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        """With the setting off detect-secrets cannot decode the list and fails the whole scan.

        Quoting is asked for in such a repository, which skips every non-ASCII name, and each of
        them is reported.
        """
        repo = init_repo(tmp_path)
        _create_tracked(repo, NOT_UTF8, "café.cfg", "plain.cfg")

        result, env = self._scan(scanner, repo)

        assert self._quotepath_setting(env) == ("1", "core.quotepath", "true")
        (warning,) = result.warnings
        assert "the name of 2 tracked file(s)" in warning
        assert repr(NOT_UTF8) in warning
        assert repr("café.cfg") in warning
        assert "plain.cfg" not in warning

    @NOT_UTF8_PLATFORM
    def test_a_name_that_is_not_utf8_anywhere_in_the_repository_pins_quoting_on(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        """detect-secrets decodes the whole list git gives it, whichever directory is scanned.

        The name below ``other`` is not in the scan of ``sub``, and a name below ``vendor`` is
        excluded from every scan, yet each makes detect-secrets fail on the list when git writes
        names as they are.
        """
        repo = init_repo(tmp_path)
        _create_tracked(repo, "sub/plain.cfg", "other/" + NOT_UTF8, "vendor/" + NOT_UTF8)

        below, below_env = self._scan(scanner, repo / "sub")
        top, top_env = self._scan(scanner, repo)

        assert self._quotepath_setting(below_env) == ("1", "core.quotepath", "true")
        assert self._quotepath_setting(top_env) == ("1", "core.quotepath", "true")
        assert below.warnings == []
        (warning,) = top.warnings  # quoted, so not scanned: the one below ``other`` is in this scan
        assert repr("other/" + NOT_UTF8) in warning
        assert "vendor" not in warning

    @NOT_UTF8_PLATFORM
    @requires_git_config_env  # a git before 2.31 ignores the setting that overrides the user's
    def test_a_setting_of_the_user_that_turns_quoting_off_does_not_reach_detect_secrets(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        """A name that is not UTF-8 needs quoting on, so the user's own ``off`` is overridden."""
        repo = init_repo(tmp_path)
        subprocess.run(
            ["git", "config", "core.quotepath", "false"], cwd=repo, check=True, capture_output=True
        )
        _create_tracked(repo, NOT_UTF8, "plain.cfg")

        result, env = self._scan(scanner, repo)

        assert self._quotepath_setting(env) == ("1", "core.quotepath", "true")
        (warning,) = result.warnings
        assert repr(NOT_UTF8) in warning
        assert "plain.cfg" not in warning

    def test_names_a_line_separator_splits_are_reported(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        """``str.splitlines`` splits git's list at U+0085, U+2028 and U+2029 as it does at a newline.

        With quoting off git writes them as they are, so detect-secrets reads the name of such a
        file as two names that match nothing, and it dropped the file in silence.
        """
        names = ["line\u2028sep.cfg", "line\u2029sep.cfg", "line\u0085sep.cfg"]
        repo = init_repo(tmp_path)
        _create_tracked(repo, *names, "plain.cfg")

        result, _env = self._scan(scanner, repo)

        assert len(result.warnings) == 1, "files dropped from the scan were not reported"
        (warning,) = result.warnings
        assert "the name of 3 tracked file(s)" in warning
        for name in names:
            assert repr(name) in warning
        assert "plain.cfg" not in warning

    def test_a_setting_that_git_takes_from_git_config_parameters_is_noticed(
        self, scanner: DetectSecretsScanner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """``git -c core.quotepath=true`` exports it so, and it wins over ``GIT_CONFIG_COUNT``."""
        repo = init_repo(tmp_path)
        _create_tracked(repo, "café.cfg", "plain.cfg")
        monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'core.quotepath=true'")

        result, _env = self._scan(scanner, repo)

        assert len(result.warnings) == 1, "a file dropped from the scan was not reported"
        (warning,) = result.warnings
        assert "the name of 1 tracked file(s)" in warning
        assert repr("café.cfg") in warning
        assert "plain.cfg" not in warning

    @pytest.mark.skipif(sys.platform == "win32", reason="Windows file names cannot hold a colon")
    def test_a_directory_named_like_a_pathspec_is_not_nothing(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        """``git ls-files -- :magic`` reads the colon as pathspec magic and finds no file."""
        repo = init_repo(tmp_path)
        _create_tracked(repo, ":magic/app.cfg", ":!bang/app.cfg", "plain.cfg")

        assert self._scan(scanner, repo / ":magic")[0].warnings == []
        assert self._scan(scanner, repo / ":!bang")[0].warnings == []

    def test_the_names_below_a_directory_do_not_include_one_that_only_starts_like_it(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = init_repo(tmp_path)
        _create_tracked(repo, "sub/plain.cfg", 'sub2/say "hi".cfg')

        assert self._scan(scanner, repo / "sub")[0].warnings == []

    def test_a_repository_git_cannot_list_is_reported(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        """detect-secrets lists the files with the same command, gets nothing and scans nothing."""
        repo = init_repo(tmp_path)
        add_files(repo, "app.cfg")
        (repo / ".git" / "index").write_bytes(b"not an index")

        result, env = self._scan(scanner, repo)

        (warning,) = result.warnings
        assert warning.startswith(f"Could not list the files git tracks in {repo}")
        assert "index file" in warning
        assert self._quotepath_setting(env) is None

    def test_a_directory_that_tracks_nothing_gets_the_environment_as_it_is(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = init_repo(tmp_path)

        result, env = self._scan(scanner, repo)

        assert self._quotepath_setting(env) is None
        (warning,) = result.warnings
        assert warning.startswith("Scanned nothing in ")

    def test_a_scan_that_does_not_use_gits_list_says_nothing_about_it(self, tmp_path: Path):
        plan = _plan_scan(tmp_path / "missing.cfg")

        env, warnings = _check_git_file_list(tmp_path, plan)

        assert warnings == []
        assert self._quotepath_setting(env) is None

    @pytest.mark.parametrize("error", [OSError("no git"), subprocess.TimeoutExpired("git", 60)])
    def test_a_git_that_cannot_run_says_nothing(self, tmp_path: Path, error: Exception):
        repo = init_repo(tmp_path)
        plan = _plan_scan(repo)

        with patch("subprocess.run", side_effect=error):
            env, warnings = _check_git_file_list(repo, plan)

        assert warnings == []
        assert self._quotepath_setting(env) is None


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
