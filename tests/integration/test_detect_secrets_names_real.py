"""Integration tests for the file names detect-secrets is given, against the real package.

detect-secrets lists the files it scans with ``git ls-files`` and drops a file whose name it cannot
match in that list: a name git quotes, a name Python splits into lines, a name that looks like an
option. Each of these was a silent clean run. Findings come from real scans of real files in real
git repositories; nothing about the scanner is mocked.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess  # nosec B404
import sys
from pathlib import Path

import pytest
from tests.integration.detect_secrets_support import NPM_TOKEN_LINE, add_tracked, found
from tests.scanner.detect_secrets_helpers import requires_git_config_env

from envdrift.scanner.detect_secrets import DetectSecretsScanner

pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.skipif(
        importlib.util.find_spec("detect_secrets") is None,
        reason="detect-secrets not installed (pip install detect-secrets)",
    ),
]


def test_scan_of_paths_that_look_like_options_scans_them(git_repo: Path):
    """A file named ``--exclude-files=^`` is a path, not the option that excludes everything.

    argparse took it for the option, so detect-secrets had no path and nothing to scan, and the
    run passed as clean. A directory starting with ``-`` failed with a usage error instead.
    """
    option_like = "--exclude-files=^"
    add_tracked(git_repo, option_like, "-sub/a.cfg", "plain.cfg")
    scanner = DetectSecretsScanner(auto_install=False)

    file_result = scanner.scan([git_repo / option_like])
    dir_result = scanner.scan([git_repo / "-sub"])

    assert file_result.error is None, file_result.error
    assert dir_result.error is None, dir_result.error
    assert [Path(f.file_path).name for f in file_result.findings] == [option_like]
    assert found(dir_result.findings, git_repo) == ["-sub/a.cfg"]


@requires_git_config_env
def test_scan_of_tracked_files_with_non_ascii_names_reports_them(git_repo: Path):
    """A leaked token in ``café.cfg`` is reported, not skipped in silence.

    detect-secrets lists the tracked files with ``git ls-files``. Under git's default
    ``core.quotepath`` that writes a non-ASCII name as a quoted escape sequence
    (``"caf\\303\\251.cfg"``), which matches no file, so the file was dropped from the scan with no
    error, no warning and nothing on stderr, and the run read as clean.
    """
    subprocess.run(
        ["git", "config", "core.quotepath", "true"], cwd=git_repo, capture_output=True, check=True
    )
    add_tracked(git_repo, "café.cfg", "plain.cfg", "sub/naïve.cfg")
    scanner = DetectSecretsScanner(auto_install=False)

    top = scanner.scan([git_repo])
    sub = scanner.scan([git_repo / "sub"])

    assert top.error is None, top.error
    assert sub.error is None, sub.error
    assert found(top.findings, git_repo) == ["café.cfg", "plain.cfg", "sub/naïve.cfg"]
    assert found(sub.findings, git_repo) == ["sub/naïve.cfg"]


def _track_or_skip(repo: Path, *names: str) -> None:
    """``_add_tracked``, skipping where the file system cannot hold one of the names."""
    try:
        add_tracked(repo, *names)
    except OSError as exc:
        pytest.skip(f"this file system cannot hold the name: {exc}")


@pytest.mark.skipif(sys.platform == "win32", reason="Windows file names cannot hold these")
@requires_git_config_env
def test_scan_says_so_when_git_quotes_a_tracked_name_whatever_the_setting(git_repo: Path):
    """Git quotes a name with a double quote or a backslash even with ``core.quotepath`` off.

    detect-secrets cannot match such a name, so it drops the file. That is reported as a warning,
    where it used to be a clean run.
    """
    _track_or_skip(git_repo, 'say "hi".cfg', "plain.cfg", "café.cfg")

    result = DetectSecretsScanner(auto_install=False).scan([git_repo])

    assert result.error is None, result.error
    assert found(result.findings, git_repo) == ["café.cfg", "plain.cfg"]
    (warning,) = result.warnings
    assert warning.startswith(f"Not scanned in {git_repo}: ")
    assert repr('say "hi".cfg') in warning
    assert "plain.cfg" not in warning


@pytest.mark.skipif(sys.platform == "win32", reason="Windows file names are never non-UTF-8")
def test_scan_of_a_name_that_is_not_utf8_does_not_fail_and_says_what_it_skipped(git_repo: Path):
    """With ``core.quotepath`` off detect-secrets fails the whole scan on a name that is not UTF-8.

    The setting stays at its default for such a repository, so the files with plain names are
    still scanned, and every file whose name git then quotes is reported.
    """
    not_utf8 = "caf\udce9.cfg"  # Latin-1 "café": the byte 0xe9, which is not UTF-8
    subprocess.run(
        ["git", "config", "core.quotepath", "true"], cwd=git_repo, capture_output=True, check=True
    )
    _track_or_skip(git_repo, not_utf8, "plain.cfg", "naïve.cfg")

    result = DetectSecretsScanner(auto_install=False).scan([git_repo])

    assert result.error is None, result.error
    assert found(result.findings, git_repo) == ["plain.cfg"]
    (warning,) = result.warnings
    assert "the name of 2 tracked file(s)" in warning
    assert repr(not_utf8) in warning
    assert repr("naïve.cfg") in warning


@pytest.mark.skipif(sys.platform == "win32", reason="Windows file names are never non-UTF-8")
def test_scan_of_a_name_that_is_not_utf8_outside_the_scan_does_not_fail(git_repo: Path):
    """detect-secrets decodes the whole list git gives it, not only the part it scans.

    A name that is not UTF-8 in another directory (``other``) or in an excluded one (``vendor``)
    made it fail with a ``UnicodeDecodeError`` when git wrote names as they are.
    """
    not_utf8 = "caf\udce9.cfg"  # Latin-1 "café": the byte 0xe9, which is not UTF-8
    _track_or_skip(git_repo, "sub/ok.cfg", "ok.cfg", "other/" + not_utf8, "vendor/" + not_utf8)
    scanner = DetectSecretsScanner(auto_install=False)

    top = scanner.scan([git_repo])
    sub = scanner.scan([git_repo / "sub"])

    assert top.error is None, top.error
    assert sub.error is None, sub.error
    assert found(top.findings, git_repo) == ["ok.cfg", "sub/ok.cfg"]
    assert found(sub.findings, git_repo) == ["sub/ok.cfg"]
    assert sub.warnings == []
    (warning,) = top.warnings  # the one below ``other`` is in the scan and git quotes it
    assert repr("other/" + not_utf8) in warning
    assert "vendor" not in warning


@pytest.mark.skipif(sys.platform == "win32", reason="Windows file names are never non-UTF-8")
@requires_git_config_env  # a git before 2.31 ignores the setting that overrides the user's
def test_scan_of_a_name_that_is_not_utf8_when_the_user_turned_quoting_off(git_repo: Path):
    """A user's own ``core.quotepath = false`` (a common setting) must not reach detect-secrets.

    It reads the list as UTF-8, so a name that is not UTF-8 failed the whole scan with it off.
    """
    not_utf8 = "caf\udce9.cfg"
    subprocess.run(
        ["git", "config", "core.quotepath", "false"], cwd=git_repo, capture_output=True, check=True
    )
    _track_or_skip(git_repo, not_utf8, "plain.cfg")

    result = DetectSecretsScanner(auto_install=False).scan([git_repo])

    assert result.error is None, result.error
    assert found(result.findings, git_repo) == ["plain.cfg"]
    (warning,) = result.warnings
    assert repr(not_utf8) in warning


@pytest.mark.skipif(sys.platform == "win32", reason="Windows file names cannot hold these")
def test_scan_says_so_when_a_line_separator_splits_a_tracked_name(git_repo: Path):
    """detect-secrets splits git's list with ``str.splitlines``, which also splits at U+2028.

    The name of such a file reads as two names that match nothing, so the file was dropped from
    the scan with no error and no warning.
    """
    names = ["line\u2028sep.cfg", "line\u2029sep.cfg", "line\u0085sep.cfg"]
    _track_or_skip(git_repo, *names, "plain.cfg")

    result = DetectSecretsScanner(auto_install=False).scan([git_repo])

    assert result.error is None, result.error
    assert found(result.findings, git_repo) == ["plain.cfg"]
    assert len(result.warnings) == 1, "files dropped from the scan were not reported"
    (warning,) = result.warnings
    assert "the name of 3 tracked file(s)" in warning
    for name in names:
        assert repr(name) in warning


def test_scan_says_so_when_the_git_configuration_keeps_a_name_quoted(
    git_repo: Path, monkeypatch: pytest.MonkeyPatch
):
    """``git -c core.quotepath=true detect-secrets`` exports the setting in ``GIT_CONFIG_PARAMETERS``.

    It wins over the ``GIT_CONFIG_COUNT`` entry envdrift adds, so ``café.cfg`` stays quoted and
    is not scanned: said so, not left as a clean run.
    """
    _track_or_skip(git_repo, "café.cfg", "plain.cfg")
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'core.quotepath=true'")

    result = DetectSecretsScanner(auto_install=False).scan([git_repo])

    assert result.error is None, result.error
    assert found(result.findings, git_repo) == ["plain.cfg"]
    assert len(result.warnings) == 1, "a file dropped from the scan was not reported"
    (warning,) = result.warnings
    assert repr("café.cfg") in warning


# Names that git quotes, that Python splits, that look like options or pathspecs, or that no
# ASCII-only code reads right. Each is a tracked file holding a token.
AWKWARD_NAMES = [
    "plain.cfg",
    "with space.cfg",
    " leading space.cfg",
    "trailing space .cfg",
    "dir with space/inner file.cfg",
    "café.cfg",
    "sub/naïve.cfg",
    "文档/配置.cfg",
    "emoji-\U0001f600.cfg",
    "zero\u200bwidth.cfg",
    "bom\ufeff.cfg",
    "tab\there.cfg",
    "new\nline.cfg",
    "carriage\rreturn.cfg",
    "bell\x07.cfg",
    "form\x0cfeed.cfg",
    "vertical\x0btab.cfg",
    "separator\x1c.cfg",
    "del\x7f.cfg",
    "line\u0085next.cfg",
    "line\u2028separator.cfg",
    "paragraph\u2029separator.cfg",
    'double"quote.cfg',
    "single'quote.cfg",
    "back\\slash.cfg",
    "-dash.cfg",
    "#hash.cfg",
    "!bang.cfg",
    ":colon.cfg",
    "[bracket].cfg",
    "{brace}.cfg",
    "star*.cfg",
    "question?.cfg",
    "~tilde.cfg",
    "$dollar.cfg",
]


def _create_and_track(repo: Path, names: list[str]) -> None:
    """Write the token to each file and ``git add`` it, as a name and not as a pathspec.

    The test is skipped where the file system cannot hold one of the names.
    """
    try:
        for name in names:
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            (repo / name).write_text(NPM_TOKEN_LINE)
    except OSError as exc:
        pytest.skip(f"this file system cannot hold the name: {exc}")
    subprocess.run(
        ["git", "--literal-pathspecs", "add", "--", *names],
        cwd=repo,
        capture_output=True,
        check=True,
    )


def _reported(warnings: list[str]) -> int:
    """How many files the warnings say were not scanned (each says "the name of N tracked file")."""
    counts = (re.findall(r"the name of (\d+) tracked file", warning) for warning in warnings)
    return sum(int(count) for found_counts in counts for count in found_counts)


# The setting of ``core.quotepath`` in the repository (None: the machine's own) and whether a name
# that is not UTF-8 is tracked. The user's own ``off`` next to such a name needs git 2.31 or later
# to be overridden; an older git makes detect-secrets fail loudly instead.
INVARIANT_CASES = [
    pytest.param(None, False, id="default"),
    pytest.param("true", False, id="quotepath-on"),
    pytest.param("false", False, id="quotepath-off"),
    pytest.param(None, True, id="default-not-utf8"),
    pytest.param("true", True, id="quotepath-on-not-utf8"),
    pytest.param("false", True, id="quotepath-off-not-utf8", marks=requires_git_config_env),
]


@pytest.mark.skipif(sys.platform == "win32", reason="Windows file names cannot hold most of these")
@pytest.mark.parametrize(("quotepath", "not_utf8"), INVARIANT_CASES)
def test_no_tracked_file_is_dropped_in_silence(
    git_repo: Path, quotepath: str | None, not_utf8: bool
):
    """Every tracked file is scanned or reported, whatever its name and the git configuration.

    detect-secrets drops a file whose name it cannot match in git's list (a name git quotes, or
    that Python splits into lines) without an error or a word, which read as a clean run. The scan
    counts the files it reports against the ones git tracks, so nothing goes missing.
    """
    names = [*AWKWARD_NAMES, "caf\udce9.cfg"] if not_utf8 else AWKWARD_NAMES
    if quotepath is not None:
        subprocess.run(
            ["git", "config", "core.quotepath", quotepath],
            cwd=git_repo,
            capture_output=True,
            check=True,
        )
    _create_and_track(git_repo, names)

    result = DetectSecretsScanner(auto_install=False).scan([git_repo])

    assert result.error is None, result.error
    scanned, reported = len(result.findings), _reported(result.warnings)
    assert scanned + reported == len(names), (
        f"{len(names) - scanned - reported} tracked files were dropped in silence: "
        f"{scanned} scanned and {reported} reported of {len(names)}"
    )
    # A name that is plain is scanned, whatever else is in the repository.
    assert "plain.cfg" in found(result.findings, git_repo)
