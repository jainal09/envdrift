"""``envdrift guard`` with the real gitleaks and Infisical binaries on every path form.

``guard <subdir>``, ``guard <subdir>/<file>`` and ``guard --pr-base`` (which
passes cwd-relative paths for changed files on purpose) hand the scanners
relative paths. Both backends used to resolve such a path a second time inside
the directory they run the binary in, so the binary failed with ``stat proj:
no such file or directory`` and the scanner reported no findings, only an
error whose raw, colorized stderr leaked ANSI escapes into ``--json`` (#843).

Both binaries now run in guard's cwd on the path as given, so a symlinked
directory is scanned whatever its form (#853), their fingerprints match
``gitleaks dir <path>`` run by hand, so a repo-root ``.gitleaksignore`` covers
nested files under ``--pr-base`` (#854), and every scanner shows a file in one
form, relative to the cwd when it is under it (#855). History scans still run
gitleaks in the repository root. The tests at the end pin the paths that are
not what they look like: names that start with ``-``, ``..`` after a symlink,
and ignore patterns that must match the path guard shows, but never through the
directories above the one guard runs in (#859).

Each test drives the real CLI as a subprocess and SKIPs cleanly when the
binary is not installed (no auto-install).
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404
import sys
from pathlib import Path

import pytest

from envdrift.scanner.gitleaks import GitleaksScanner
from envdrift.scanner.infisical import InfisicalScanner

pytestmark = [pytest.mark.integration, pytest.mark.slow]

REPO_ROOT = Path(__file__).resolve().parents[2]

# Fragment-assembled so GitHub push protection never sees the whole literal.
GITHUB_TOKEN = "ghp_" + "016C7eX9bQ2vYwN3kLmZpRtUaScDfGhJkL01"

_SCANNERS = [
    pytest.param(
        ("gitleaks", ["--gitleaks"], ".gitleaks.toml"),
        marks=pytest.mark.skipif(
            not GitleaksScanner(auto_install=False).is_installed(),
            reason="gitleaks not installed",
        ),
        id="gitleaks",
    ),
    pytest.param(
        ("infisical", ["--infisical", "--no-gitleaks"], ".infisical-scan.toml"),
        marks=pytest.mark.skipif(
            not InfisicalScanner(auto_install=False).is_installed(),
            reason="infisical not installed",
        ),
        id="infisical",
    ),
]


def _write_secret(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"GITHUB_TOKEN={GITHUB_TOKEN}\n")


def _guard(args: list[str], *, cwd: Path) -> tuple[subprocess.CompletedProcess, dict]:
    """Run ``envdrift guard <args> --json --no-auto-install`` and parse its document."""
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{REPO_ROOT / 'src'}{os.pathsep}{env.get('PYTHONPATH', '')}"
    result = subprocess.run(  # nosec B603
        [sys.executable, "-m", "envdrift.cli", "guard", *args, "--json", "--no-auto-install"],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    out = result.stdout
    if "{" not in out:
        pytest.fail(f"no JSON document (rc={result.returncode})\n{out}\n{result.stderr}")
    # --pr-base prints a one-line progress notice ahead of the document.
    return result, json.loads(out[out.index("{") : out.rindex("}") + 1])


def _scanner_result(payload: dict, name: str) -> dict:
    results = [r for r in payload["scanner_results"] if r["name"] == name]
    if len(results) != 1:
        pytest.fail(f"expected one {name} result, got {payload['scanner_results']}")
    return results[0]


def _scanner_paths(payload: dict, name: str) -> set[Path]:
    # Path, not str: Windows prints ``proj\\sub\\app.env``.
    return {Path(f["file_path"]) for f in payload["findings"] if f["scanner"] == name}


@pytest.mark.parametrize("scanner", _SCANNERS)
@pytest.mark.parametrize("target", ["proj", "proj/sub/app.env"])
def test_guard_relative_path_reports_relative_findings(tmp_path: Path, scanner, target: str):
    """``guard proj`` and ``guard proj/sub/app.env`` scan with no scanner error."""
    name, flags, _config = scanner
    _write_secret(tmp_path / "proj" / "sub" / "app.env")

    result, payload = _guard([target, *flags], cwd=tmp_path)

    assert result.returncode == 1, f"critical secret must exit 1\n{result.stderr}"
    assert _scanner_result(payload, name)["error"] is None
    # Displayed relative, the way guard passed the path in.
    assert _scanner_paths(payload, name) == {Path("proj/sub/app.env")}


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, capture_output=True, check=True)  # nosec B603 B607


def _feature_branch(repo: Path) -> None:
    """Commit a ``base`` branch and check out ``feature`` from it."""
    _git(repo, "checkout", "-q", "-b", "base")
    (repo / "readme.txt").write_text("hello\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "checkout", "-q", "-b", "feature")


@pytest.mark.parametrize("scanner", _SCANNERS)
def test_guard_pr_base_scans_changed_files_in_subdirectories(git_repo: Path, scanner):
    """``--pr-base`` hands scanners cwd-relative paths of the changed files."""
    name, flags, _config = scanner
    _feature_branch(git_repo)
    _write_secret(git_repo / "config" / "app.env")
    _write_secret(git_repo / "root.env")
    _git(git_repo, "add", "-A")
    _git(git_repo, "commit", "-q", "-m", "add secrets")

    # No ``origin`` remote: guard warns about the fetch and diffs the local ref.
    result, payload = _guard(["--pr-base", "base", *flags], cwd=git_repo)

    assert result.returncode == 1, f"critical secret must exit 1\n{result.stderr}"
    assert _scanner_result(payload, name)["error"] is None
    # gitleaks used to report a changed file in the cwd as ``root.env/root.env``.
    assert _scanner_paths(payload, name) == {Path("config/app.env"), Path("root.env")}


@pytest.mark.parametrize("scanner", _SCANNERS)
def test_guard_pr_base_history_reports_a_scrubbed_secret(git_repo: Path, scanner):
    """``--pr-base --history`` finds a secret the PR committed and then removed.

    The changed file is a cwd-relative file path, which Infisical's git mode
    cannot scan: it wrote an empty ``[]`` report and the run passed with exit 0
    and no scanner error, although the secret is in the PR's history (#843).
    """
    name, flags, _config = scanner
    _feature_branch(git_repo)
    _write_secret(git_repo / "config" / "settings.txt")
    _git(git_repo, "add", "-A")
    _git(git_repo, "commit", "-q", "-m", "add a secret")
    (git_repo / "config" / "settings.txt").write_text("GITHUB_TOKEN=scrubbed\n")
    _git(git_repo, "commit", "-q", "-am", "scrub the secret")

    result, payload = _guard(["--pr-base", "base", "--history", *flags], cwd=git_repo)

    assert _scanner_result(payload, name)["error"] is None
    findings = [f for f in payload["findings"] if f["scanner"] == name]
    assert findings, "the secret in the PR's history was not reported"
    # Shown relative to the cwd: gitleaks used to show its absolute history root (#855).
    assert {Path(f["file_path"]) for f in findings} == {Path("config/settings.txt")}
    assert all(f["commit_sha"] for f in findings)
    # The secret blocks at its severity's exit code (critical 1, high 2).
    assert result.returncode in (1, 2), f"rc={result.returncode}\n{result.stderr}"


@pytest.mark.parametrize("scanner", _SCANNERS)
def test_guard_history_outside_a_repository_exits_5(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner
):
    """A history scan that cannot run is a scanner error, so guard exits 5.

    Infisical's git mode exits 1 with an empty ``[]`` report for a directory
    outside a repository, which passed as a clean scan (#843).
    """
    name, flags, _config = scanner
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    (tmp_path / "plain").mkdir()
    (tmp_path / "plain" / "readme.txt").write_text("nothing to see\n")

    result, payload = _guard(["plain", "--history", *flags], cwd=tmp_path)

    error = _scanner_result(payload, name)["error"]
    assert error, "a history scan outside a repository must fail"
    assert "not inside a Git repository" in error
    assert result.returncode == 5, f"rc={result.returncode}\n{result.stderr}"


@pytest.mark.parametrize("scanner", _SCANNERS)
def test_guard_json_scanner_error_is_ansi_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner
):
    """A failing binary's colored stderr reaches ``--json`` without escapes.

    A malformed scanner config in the scanned directory makes the real binary
    exit with a colored ``FTL`` line. The integration conftest sets
    ``NO_COLOR``, which these binaries honour, so it is removed here.
    """
    name, flags, config = scanner
    monkeypatch.delenv("NO_COLOR", raising=False)
    _write_secret(tmp_path / "proj" / "app.env")
    (tmp_path / "proj" / config).write_text("[[rules]\nid = \n")

    result, payload = _guard(["proj", *flags], cwd=tmp_path)

    error = _scanner_result(payload, name)["error"]
    assert error, "a malformed scanner config must fail the scan"
    assert "config" in error
    assert "\x1b" not in error, repr(error)
    assert "○" not in error, f"gitleaks banner in error: {error!r}"
    assert "\x1b" not in result.stdout
    assert "\\u001b" not in result.stdout
    # The native scanner still reports the critical secret, and blocking
    # findings take precedence over the scanner error (docs/cli/guard.md).
    assert result.returncode == 1, result.stderr


_requires_gitleaks = pytest.mark.skipif(
    not GitleaksScanner(auto_install=False).is_installed(), reason="gitleaks not installed"
)
_requires_infisical = pytest.mark.skipif(
    not InfisicalScanner(auto_install=False).is_installed(), reason="infisical not installed"
)
# Windows resolves ``..`` lexically, so ``linkproj/../proj`` names ``./proj``.
_posix_parent_refs = pytest.mark.skipif(
    sys.platform == "win32", reason="Windows resolves '..' lexically: ./proj does not exist"
)


def _symlink(link: Path, target: Path) -> None:
    """Create ``link`` -> ``target``, skipping where symlinks need a privilege."""
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except OSError as exc:  # Windows without the symlink privilege
        pytest.skip(f"cannot create a symlink here: {exc}")


def _finding_paths(payload: dict) -> set[Path]:
    """Every finding's path, whichever scanner reported it."""
    return {Path(f["file_path"]) for f in payload["findings"]}


@pytest.mark.parametrize("scanner", _SCANNERS)
def test_guard_absolute_symlinked_directory_is_scanned(tmp_path: Path, scanner):
    """An absolute path to a symlinked directory scans like the relative one (#853).

    Both binaries treat a symlink given as their root as a file and skip it
    without an error. The absolute form used to be passed unchanged, so it
    reported nothing and passed as a clean scan.
    """
    name, flags, _config = scanner
    _write_secret(tmp_path / "repo" / "proj" / "sub" / "app.env")
    link = tmp_path / "linkproj"
    _symlink(link, tmp_path / "repo" / "proj")

    result, payload = _guard([str(link), *flags], cwd=tmp_path)

    assert result.returncode == 1, f"critical secret must exit 1\n{result.stderr}"
    assert _scanner_result(payload, name)["error"] is None
    assert _scanner_paths(payload, name) == {Path("linkproj/sub/app.env")}
    # Every scanner, the native one included, shows the file under the link.
    assert _finding_paths(payload) == {Path("linkproj/sub/app.env")}


@pytest.mark.parametrize("scanner", _SCANNERS)
def test_guard_relative_symlinked_directory_is_shown_under_the_link(tmp_path: Path, scanner):
    """Every scanner shows a file below a symlinked directory under the link (#853, #855).

    The native scanner resolves a directory it walks, so it showed the link
    target's absolute path next to the binary's ``linkproj/sub/app.env``.
    """
    name, flags, _config = scanner
    _write_secret(tmp_path / "repo" / "proj" / "sub" / "app.env")
    _symlink(tmp_path / "linkproj", tmp_path / "repo" / "proj")

    result, payload = _guard(["linkproj", *flags], cwd=tmp_path)

    assert result.returncode == 1, result.stderr
    assert _scanner_result(payload, name)["error"] is None
    assert _finding_paths(payload) == {Path("linkproj/sub/app.env")}
    assert _scanner_paths(payload, name) == {Path("linkproj/sub/app.env")}


@pytest.mark.parametrize("scanner", _SCANNERS)
@pytest.mark.parametrize("scan_paths", [[".", "linkproj"], ["linkproj", "."]], ids=["dot", "link"])
def test_guard_of_a_directory_and_a_symlink_to_it_reports_each_secret_once(
    tmp_path: Path, scanner, scan_paths: list[str]
):
    """``guard . linkproj`` scans ``proj`` twice, and each binary used to report it twice (#861).

    The binaries name a file by the path they walked: ``proj/sub/app.env`` from ``.`` and
    ``linkproj/sub/app.env`` from the link. Dedup compared those names, so one secret in one
    file was two findings in ``--json`` and SARIF. The file is now one finding, named by where
    it really is, whichever scan path is listed first.
    """
    name, flags, _config = scanner
    _write_secret(tmp_path / "proj" / "sub" / "app.env")
    _symlink(tmp_path / "linkproj", tmp_path / "proj")

    result, payload = _guard([*scan_paths, *flags], cwd=tmp_path)

    assert result.returncode == 1, f"critical secret must exit 1\n{result.stderr}"
    assert _scanner_result(payload, name)["error"] is None
    own = [f for f in payload["findings"] if f["scanner"] == name]
    assert [Path(f["file_path"]) for f in own] == [Path("proj/sub/app.env")]
    # The native scanner's finding for the same file is named the same way.
    assert _finding_paths(payload) == {Path("proj/sub/app.env")}


@pytest.mark.parametrize("scanner", _SCANNERS)
@pytest.mark.parametrize(
    "scan_paths",
    [["link1"], ["link2", "link1"], ["link1", "link2"]],
    ids=["one-link", "link2-first", "link1-first"],
)
def test_guard_names_a_file_the_same_way_whichever_link_or_alias_reaches_it(
    tmp_path: Path, scanner, scan_paths: list[str]
):
    """A tree scanned through links holds a link to one of its files: one name, from every scanner.

    ``proj/a_alias.env`` -> ``sub/app.env`` sorts before the file it links to, and every
    name below a symlinked scan path differs from the file's real location, so the name that
    survived deduplication was the alias for the built-in scanner and the file for gitleaks
    and Infisical. With two links to one directory the scanners also disagreed on which link
    to show (#861).
    """
    name, flags, _config = scanner
    _write_secret(tmp_path / "proj" / "sub" / "app.env")
    _symlink(tmp_path / "proj" / "a_alias.env", Path("sub/app.env"))
    _symlink(tmp_path / "link1", tmp_path / "proj")
    _symlink(tmp_path / "link2", tmp_path / "proj")

    result, payload = _guard([*scan_paths, *flags], cwd=tmp_path)

    assert _scanner_result(payload, name)["error"] is None, result.stderr
    assert {f["scanner"] for f in payload["findings"]} == {"native", name}
    assert _finding_paths(payload) == {Path(scan_paths[0]) / "sub" / "app.env"}
    assert result.returncode == 1, result.stderr


@pytest.mark.parametrize("scanner", _SCANNERS)
@pytest.mark.parametrize("absolute", [False, True], ids=["relative", "absolute"])
def test_guard_symlinked_file_is_scanned(tmp_path: Path, scanner, absolute: bool):
    """A symlink to a file is scanned through to its target and shown as the link.

    Both binaries skip a symlinked file even when it is the path they are
    given, without an error, so ``guard link.env`` passed clean on their side.
    """
    name, flags, _config = scanner
    _write_secret(tmp_path / "real" / "app.env")
    link = tmp_path / "link.env"
    _symlink(link, tmp_path / "real" / "app.env")

    result, payload = _guard([str(link) if absolute else "link.env", *flags], cwd=tmp_path)

    assert result.returncode == 1, result.stderr
    assert _scanner_result(payload, name)["error"] is None
    assert _scanner_paths(payload, name) == {Path("link.env")}
    assert _finding_paths(payload) == {Path("link.env")}


@_requires_gitleaks
def test_guard_pr_base_honours_repo_root_gitleaksignore_for_nested_files(git_repo: Path):
    """A repo-root ``.gitleaksignore`` suppresses nested and root-level files alike (#854).

    gitleaks used to run once per changed file, inside that file's directory,
    so a nested file's fingerprint lost its directory (``settings.txt:...``)
    and the repo-root ignore file was not read for it at all.
    """
    _feature_branch(git_repo)
    _write_secret(git_repo / "config" / "settings.txt")
    _write_secret(git_repo / "top.txt")
    (git_repo / ".gitleaksignore").write_text(
        "config/settings.txt:github-pat:1\ntop.txt:github-pat:1\n"
    )
    _git(git_repo, "add", "-A")
    _git(git_repo, "commit", "-q", "-m", "feature")

    result, payload = _guard(["--pr-base", "base", "--gitleaks"], cwd=git_repo)

    assert _scanner_result(payload, "gitleaks")["error"] is None
    assert _scanner_paths(payload, "gitleaks") == set()
    # The native scanner, which .gitleaksignore does not cover, still blocks.
    assert _scanner_paths(payload, "native") == {Path("config/settings.txt"), Path("top.txt")}
    assert result.returncode == 1, result.stderr


@_requires_infisical
def test_guard_pr_base_does_not_read_infisicalignore(git_repo: Path):
    """Infisical reads no ignore file for a file target, so none applies under ``--pr-base``.

    Unlike gitleaks, Infisical reads ``.infisicalignore`` only from a
    directory it scans, never from the cwd, and ``--pr-base`` hands it the
    changed files. docs/cli/guard.md documents this.
    """
    _feature_branch(git_repo)
    _write_secret(git_repo / "config" / "settings.txt")
    _write_secret(git_repo / "top.txt")
    (git_repo / ".infisicalignore").write_text(
        "config/settings.txt:github-pat:1\ntop.txt:github-pat:1\n"
    )
    _git(git_repo, "add", "-A")
    _git(git_repo, "commit", "-q", "-m", "feature")

    result, payload = _guard(["--pr-base", "base", "--infisical", "--no-gitleaks"], cwd=git_repo)

    assert _scanner_result(payload, "infisical")["error"] is None
    assert _scanner_paths(payload, "infisical") == {Path("config/settings.txt"), Path("top.txt")}
    assert result.returncode == 1, result.stderr


def _ignore_case(
    name: str, args: list[str], ignore_dir: str, fingerprint: str, suppressed: bool, case_id: str
):
    marks = [_requires_gitleaks if name == "gitleaks" else _requires_infisical]
    return pytest.param(
        name, args, ignore_dir, fingerprint, suppressed, marks=marks, id=f"{name}-{case_id}"
    )


def _fingerprint_path(fingerprint: str, tmp_path: Path) -> str:
    """``<tmp>`` in ``fingerprint`` as the binaries print it: forward slashes.

    gitleaks reports ``File`` with forward slashes on Windows too, drive and
    all, and reads the path in an ignore entry with ``\\`` turned into ``/``.
    """
    return fingerprint.replace("<tmp>", tmp_path.as_posix())


_IGNORE_CASES = [
    # ``guard`` scans the absolute cwd and ``guard .`` scans ``.``, so their
    # fingerprints are absolute and cwd-relative, as they always were.
    _ignore_case("gitleaks", [], ".", "<tmp>/proj/sub/app.env", True, "no-path-absolute"),
    _ignore_case("gitleaks", [], ".", "proj/sub/app.env", False, "no-path-relative"),
    _ignore_case("gitleaks", ["."], ".", "proj/sub/app.env", True, "dot-relative"),
    _ignore_case("gitleaks", ["."], ".", "<tmp>/proj/sub/app.env", False, "dot-absolute"),
    # gitleaks reads the cwd's ignore file, so a fingerprint relative to the
    # cwd covers a file however it was reached (#854) ...
    _ignore_case("gitleaks", ["proj"], ".", "proj/sub/app.env", True, "subdir-cwd-ignore"),
    _ignore_case(
        "gitleaks", ["proj/sub/app.env"], ".", "proj/sub/app.env", True, "file-cwd-ignore"
    ),
    _ignore_case(
        "gitleaks", ["<tmp>/proj"], ".", "<tmp>/proj/sub/app.env", True, "absolute-cwd-ignore"
    ),
    _ignore_case(
        "gitleaks",
        ["<tmp>/proj/sub/app.env"],
        ".",
        "<tmp>/proj/sub/app.env",
        True,
        "absolute-file-cwd-ignore",
    ),
    # ... and the scanned directory's, with the same fingerprints.
    _ignore_case("gitleaks", ["proj"], "proj", "proj/sub/app.env", True, "subdir-own-ignore"),
    _ignore_case("gitleaks", ["proj"], "proj", "sub/app.env", False, "subdir-own-dir-relative"),
    # A scanned file's own directory is not read, in any form (11.0.8 read
    # ``app.env:...`` there).
    _ignore_case("gitleaks", ["proj/sub/app.env"], "proj/sub", "app.env", False, "file-own-dir"),
    _ignore_case(
        "gitleaks", ["proj/sub/app.env"], "proj/sub", "proj/sub/app.env", False, "file-own-ignore"
    ),
    _ignore_case(
        "gitleaks",
        ["<tmp>/proj/sub/app.env"],
        "proj/sub",
        "<tmp>/proj/sub/app.env",
        False,
        "absolute-file-own-ignore",
    ),
    _ignore_case("infisical", [], ".", "<tmp>/proj/sub/app.env", True, "no-path-absolute"),
    _ignore_case("infisical", ["."], ".", "proj/sub/app.env", True, "dot-relative"),
    # Infisical reads only the scanned directory's ignore file ...
    _ignore_case("infisical", ["proj"], "proj", "proj/sub/app.env", True, "subdir-own-ignore"),
    _ignore_case("infisical", ["proj"], ".", "proj/sub/app.env", False, "subdir-cwd-ignore"),
    # ... and none at all for a file.
    _ignore_case(
        "infisical", ["proj/sub/app.env"], ".", "proj/sub/app.env", False, "file-cwd-ignore"
    ),
    _ignore_case(
        "infisical", ["proj/sub/app.env"], "proj/sub", "proj/sub/app.env", False, "file-own-ignore"
    ),
]


@pytest.mark.parametrize(("name", "args", "ignore_dir", "fingerprint", "suppressed"), _IGNORE_CASES)
def test_guard_ignore_file_fingerprints(
    tmp_path: Path, name: str, args: list[str], ignore_dir: str, fingerprint: str, suppressed: bool
):
    """Which ignore file, and which fingerprint form, gitleaks and Infisical honour.

    Both binaries run in guard's cwd on the path as given, so a fingerprint
    is ``<file>:<rule>:<line>`` with the file named the way that path names
    it, as ``gitleaks dir <path>`` run by hand reports it (#854).
    docs/cli/guard.md describes these cases.
    """
    flags = ["--gitleaks"] if name == "gitleaks" else ["--infisical", "--no-gitleaks"]
    ignore_file = ".gitleaksignore" if name == "gitleaks" else ".infisicalignore"
    _write_secret(tmp_path / "proj" / "sub" / "app.env")
    (tmp_path / ignore_dir / ignore_file).write_text(
        f"{_fingerprint_path(fingerprint, tmp_path)}:github-pat:1\n"
    )

    result, payload = _guard(
        [*(arg.replace("<tmp>", str(tmp_path)) for arg in args), *flags], cwd=tmp_path
    )

    assert _scanner_result(payload, name)["error"] is None
    assert _scanner_paths(payload, name) == (set() if suppressed else {Path("proj/sub/app.env")})
    # The native scanner, which neither ignore file covers, still blocks.
    assert result.returncode == 1, result.stderr


def _history_repo(repo: Path) -> str:
    """Commit a GitHub token in ``repo/settings.txt``, scrub it, and return that commit.

    Only the history holds the secret, so the native scanner, which reads the
    working tree, finds nothing and the exit code is the binary's verdict.
    """
    repo.mkdir(exist_ok=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@test.com")
    _git(repo, "config", "user.name", "Test User")
    _write_secret(repo / "settings.txt")
    (repo / "pkg").mkdir()
    (repo / "pkg" / "readme.txt").write_text("nothing to see\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "add a secret")
    sha = subprocess.run(  # nosec B603 B607
        ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True
    ).stdout.strip()
    (repo / "settings.txt").write_text("GITHUB_TOKEN=scrubbed\n")
    _git(repo, "commit", "-q", "-am", "scrub the secret")
    return sha


def _history_case(name: str, ignore_dir: str, entry: str, cwd: str, suppressed: bool, case_id: str):
    marks = [_requires_gitleaks if name == "gitleaks" else _requires_infisical]
    return pytest.param(name, ignore_dir, entry, cwd, suppressed, marks=marks, id=case_id)


_HISTORY_IGNORE_CASES = [
    # gitleaks reads the repository root's .gitleaksignore, with commit or
    # repo-relative fingerprints, from wherever guard runs ...
    _history_case("gitleaks", ".", "<sha>:settings.txt", ".", True, "gitleaks-root"),
    _history_case("gitleaks", ".", "<sha>:settings.txt", "pkg", True, "gitleaks-root-from-sub"),
    _history_case("gitleaks", ".", "settings.txt", "pkg", True, "gitleaks-root-global"),
    # ... and never the cwd's: there ``settings.txt`` names pkg/settings.txt
    # (what ``guard .`` reports from pkg), not the root file in the history.
    _history_case("gitleaks", "pkg", "settings.txt", "pkg", False, "gitleaks-cwd"),
    _history_case("infisical", ".", "<sha>:settings.txt", "pkg", True, "infisical-root"),
    _history_case("infisical", "pkg", "settings.txt", "pkg", False, "infisical-cwd"),
]


@pytest.mark.parametrize(
    ("name", "ignore_dir", "entry", "cwd", "suppressed"), _HISTORY_IGNORE_CASES
)
def test_guard_history_ignore_files(
    tmp_path: Path, name: str, ignore_dir: str, entry: str, cwd: str, suppressed: bool
):
    """``--history`` reads the repository root's ignore file only.

    gitleaks also reads the .gitleaksignore in the directory it runs in. Run
    in guard's cwd, it matched a cwd-relative entry against repo-relative
    history fingerprints, so ``settings.txt:github-pat:1`` meant for
    pkg/settings.txt silently suppressed the secret committed in the root's.
    """
    repo = tmp_path / "repo"
    sha = _history_repo(repo)
    flags = ["--gitleaks"] if name == "gitleaks" else ["--infisical", "--no-gitleaks"]
    ignore_file = ".gitleaksignore" if name == "gitleaks" else ".infisicalignore"
    (repo / ignore_dir / ignore_file).write_text(f"{entry.replace('<sha>', sha)}:github-pat:1\n")

    result, payload = _guard(["--history", *flags], cwd=repo / cwd)

    assert _scanner_result(payload, name)["error"] is None
    findings = [f for f in payload["findings"] if f["scanner"] == name]
    if suppressed:
        assert findings == []
        assert result.returncode == 0, result.stderr
    else:
        assert findings, "a cwd ignore file suppressed a history finding"
        assert {(repo / cwd / f["file_path"]).resolve() for f in findings} == {
            (repo / "settings.txt").resolve()
        }
        assert result.returncode in (1, 2), f"rc={result.returncode}\n{result.stderr}"


@pytest.mark.parametrize("scanner", _SCANNERS)
def test_guard_staged_reads_no_ignore_file_entry(git_repo: Path, scanner):
    """``--staged`` scans temporary copies, so a repo-relative entry cannot match.

    docs/cli/guard.md tells users to ignore staged findings with inline
    comments or the ``[guard]`` ignores instead.
    """
    name, flags, _config = scanner
    _write_secret(git_repo / "config" / "app.env")
    ignore_file = ".gitleaksignore" if name == "gitleaks" else ".infisicalignore"
    (git_repo / ignore_file).write_text("config/app.env:github-pat:1\n")
    _git(git_repo, "add", "config/app.env")

    result, payload = _guard(["--staged", *flags], cwd=git_repo)

    assert _scanner_result(payload, name)["error"] is None
    assert _scanner_paths(payload, name) == {Path("config/app.env")}
    assert result.returncode == 1, result.stderr


@_requires_gitleaks
@pytest.mark.parametrize(
    ("ignore_dir", "entry", "suppressed"),
    [("sub", "../config/settings.txt", True), (".", "config/settings.txt", False)],
    ids=["cwd-ignore", "root-ignore"],
)
def test_guard_pr_base_from_a_subdirectory_uses_the_cwd_ignore_file(
    git_repo: Path, ignore_dir: str, entry: str, suppressed: bool
):
    """Run from a subdirectory, ``--pr-base`` passes ``../config/settings.txt``.

    gitleaks runs there, so the fingerprint is ``../config/settings.txt`` and
    the ignore file read is that directory's; the root's is not read. The
    file is shown absolute, the form every scanner shows a file outside the
    cwd in (11.0.8 showed ``../config/settings.txt``).
    """
    _feature_branch(git_repo)
    (git_repo / "sub").mkdir()
    (git_repo / "sub" / "readme.txt").write_text("nothing to see\n")
    _write_secret(git_repo / "config" / "settings.txt")
    (git_repo / ignore_dir / ".gitleaksignore").write_text(f"{entry}:github-pat:1\n")
    _git(git_repo, "add", "-A")
    _git(git_repo, "commit", "-q", "-m", "feature")

    result, payload = _guard(["--pr-base", "base", "--gitleaks"], cwd=git_repo / "sub")

    assert _scanner_result(payload, "gitleaks")["error"] is None
    shown = {git_repo / "config" / "settings.txt"}
    assert _scanner_paths(payload, "gitleaks") == (set() if suppressed else shown)
    assert _scanner_paths(payload, "native") == shown
    assert result.returncode == 1, result.stderr


@pytest.mark.parametrize("scanner", _SCANNERS)
@pytest.mark.parametrize(
    ("regex", "suppressed"),
    [(r"^proj/sub/app\.env$", True), (r"^sub/app\.env$", False), (r"(^|/)sub/app\.env$", True)],
    ids=["cwd-relative", "dir-relative", "unanchored"],
)
def test_guard_scanned_directory_config_paths_see_cwd_relative_files(
    tmp_path: Path, scanner, regex: str, suppressed: bool
):
    """A scanned directory's own scanner config matches ``File`` as reported.

    Both binaries read ``.gitleaks.toml`` / ``.infisical-scan.toml`` from the
    directory they scan and match its allowlist ``paths`` against ``File``,
    which for ``guard proj`` is ``proj/sub/app.env``, as with ``gitleaks dir
    proj`` run by hand. 11.0.8 ran them inside proj, where it was
    ``sub/app.env``. docs/cli/guard.md documents this.
    """
    name, flags, config = scanner
    _write_secret(tmp_path / "proj" / "sub" / "app.env")
    (tmp_path / "proj" / config).write_text(
        f"[extend]\nuseDefault = true\n\n[allowlist]\npaths = ['''{regex}''']\n"
    )

    result, payload = _guard(["proj", *flags], cwd=tmp_path)

    assert _scanner_result(payload, name)["error"] is None
    assert _scanner_paths(payload, name) == (set() if suppressed else {Path("proj/sub/app.env")})
    assert result.returncode == 1, result.stderr


@_requires_gitleaks
def test_guard_reports_one_path_form_per_file(tmp_path: Path):
    """Every scanner names ``proj/sub/app.env`` the same way in one report (#855).

    The native scanner resolves a directory target, so it showed the file's
    absolute path next to gitleaks' cwd-relative one.
    """
    _write_secret(tmp_path / "proj" / "sub" / "app.env")

    result, payload = _guard(["proj", "--gitleaks"], cwd=tmp_path)

    assert result.returncode == 1, result.stderr
    assert {f["scanner"] for f in payload["findings"]} == {"native", "gitleaks"}
    forms = {f["file_path"] for f in payload["findings"]}
    assert len(forms) == 1, sorted(forms)
    assert _finding_paths(payload) == {Path("proj/sub/app.env")}


@pytest.mark.parametrize("scanner", _SCANNERS)
@pytest.mark.parametrize(
    ("cwd", "args", "shown"),
    [
        # ``guard`` scans the absolute cwd, and used to show absolute paths.
        ("work", [], "proj/sub/app.env"),
        ("work", ["."], "proj/sub/app.env"),
        # Outside the cwd: absolute from every scanner (gitleaks showed ``../``).
        ("work/proj", ["../../outside"], "<tmp>/outside/app.env"),
        ("work", ["<tmp>/outside"], "<tmp>/outside/app.env"),
    ],
    ids=["no-path", "dot", "parent-relative", "absolute-outside"],
)
def test_guard_shows_a_file_relative_to_the_cwd_or_absolute(
    tmp_path: Path, scanner, cwd: str, args: list[str], shown: str
):
    """One display form per file: cwd-relative under the cwd, absolute outside it (#855)."""
    name, flags, _config = scanner
    _write_secret(tmp_path / "work" / "proj" / "sub" / "app.env")
    _write_secret(tmp_path / "outside" / "app.env")

    result, payload = _guard(
        [*(arg.replace("<tmp>", str(tmp_path)) for arg in args), *flags], cwd=tmp_path / cwd
    )

    assert result.returncode == 1, result.stderr
    assert _scanner_result(payload, name)["error"] is None
    assert {f["scanner"] for f in payload["findings"]} == {"native", name}
    assert _finding_paths(payload) == {Path(shown.replace("<tmp>", str(tmp_path)))}


@pytest.mark.parametrize("scanner", _SCANNERS)
def test_guard_history_through_a_symlinked_repository_shows_the_link(tmp_path: Path, scanner):
    """History findings are shown under the symlinked path guard was given (#853, #855).

    gitleaks hangs history findings off the repository root git reports, and
    Infisical off that root's cwd-relative form: both the link target's path.
    """
    name, flags, _config = scanner
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@test.com")
    _git(repo, "config", "user.name", "Test User")
    _write_secret(repo / "config" / "settings.txt")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "add a secret")
    (repo / "config" / "settings.txt").write_text("GITHUB_TOKEN=scrubbed\n")
    _git(repo, "commit", "-q", "-am", "scrub the secret")
    _symlink(tmp_path / "linkrepo", repo)

    result, payload = _guard(["linkrepo", "--history", *flags], cwd=tmp_path)

    assert _scanner_result(payload, name)["error"] is None
    findings = [f for f in payload["findings"] if f["scanner"] == name]
    assert findings, "the secret in the history was not reported"
    assert {Path(f["file_path"]) for f in findings} == {Path("linkrepo/config/settings.txt")}
    assert result.returncode in (1, 2), f"rc={result.returncode}\n{result.stderr}"


@pytest.mark.parametrize("scanner", _SCANNERS)
def test_guard_staged_shows_a_file_outside_the_cwd_absolute(git_repo: Path, scanner):
    """``--staged`` follows the display rule of every other mode (#855).

    Run from a subdirectory, ``--staged`` and ``--pr-base`` showed a file
    outside it as ``../config/app.env``, while the native scanner showed
    every file of a directory it scanned by its absolute path.
    """
    name, flags, _config = scanner
    _write_secret(git_repo / "config" / "app.env")
    (git_repo / "sub").mkdir()
    _git(git_repo, "add", "config/app.env")

    result, payload = _guard(["--staged", *flags], cwd=git_repo / "sub")

    assert result.returncode == 1, result.stderr
    assert _scanner_result(payload, name)["error"] is None
    assert {f["scanner"] for f in payload["findings"]} == {"native", name}
    assert _finding_paths(payload) == {git_repo / "config" / "app.env"}


# --- Paths that are not what they look like -------------------------------


@_requires_gitleaks
def test_guard_dash_prefixed_clean_directory_passes(tmp_path: Path):
    """gitleaks read ``-old/`` as flags (``-o``...) and failed the scan (exit 5)."""
    (tmp_path / "-old").mkdir()
    (tmp_path / "-old" / "readme.txt").write_text("nothing to see\n")

    result, payload = _guard(["./-old", "--gitleaks"], cwd=tmp_path)

    assert _scanner_result(payload, "gitleaks")["error"] is None
    assert payload["findings"] == []
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("scanner", _SCANNERS)
def test_guard_dash_prefixed_directory_is_scanned(tmp_path: Path, scanner):
    """gitleaks read ``-foo/`` as ``-f oo/`` and reported an error instead of the secret."""
    name, flags, _config = scanner
    _write_secret(tmp_path / "-foo" / "n.txt")

    result, payload = _guard(["./-foo", *flags], cwd=tmp_path)

    assert _scanner_result(payload, name)["error"] is None
    assert _scanner_paths(payload, name) == {Path("-foo/n.txt")}
    assert result.returncode == 1, result.stderr


@_requires_gitleaks
@pytest.mark.parametrize(
    "changed",
    ["--report-path=pwned/notes.txt", "--report-path=pwned.json"],
    ids=["nested", "root-level"],
)
def test_guard_pr_base_file_named_like_an_option_is_scanned(git_repo: Path, changed: str):
    """A changed file's name must not turn into gitleaks flags.

    A pull request that added ``--report-path=pwned/notes.txt`` turned
    gitleaks' report path into the checkout: gitleaks scanned the cwd, wrote
    its report there, left envdrift's report empty and the scan passed clean
    with no error. 11.0.8 already did this for a root-level file.
    """
    _feature_branch(git_repo)
    _write_secret(git_repo / changed)
    (git_repo / "pwned").mkdir()
    (git_repo / "pwned" / "keep.txt").write_text("nothing to see\n")
    _git(git_repo, "add", "-A")
    _git(git_repo, "commit", "-q", "-m", "feature")

    result, payload = _guard(["--pr-base", "base", "--gitleaks"], cwd=git_repo)

    assert _scanner_result(payload, "gitleaks")["error"] is None
    assert _scanner_paths(payload, "gitleaks") == {Path(changed)}
    assert not (git_repo / "pwned" / "notes.txt").exists(), "gitleaks wrote into the checkout"
    assert not (git_repo / "pwned.json").exists(), "gitleaks wrote into the checkout"
    assert result.returncode == 1, result.stderr


@pytest.mark.parametrize("scanner", _SCANNERS)
@pytest.mark.parametrize(
    "target",
    [
        "linkproj/..",
        pytest.param("linkproj/../proj", marks=_posix_parent_refs),
        "<tmp>/linkproj/..",
    ],
)
def test_guard_parent_reference_after_a_symlink_is_scanned(tmp_path: Path, scanner, target: str):
    """``..`` after a symlinked directory names its target's parent, and is scanned.

    Both binaries clean each walked path lexically, so every file below
    ``linkproj/..`` became a path below ``.`` that does not exist and was
    skipped without an error: exit 0 for a secret nobody scanned. The native
    scanner is kept from blocking so the binary's verdict decides the exit.
    """
    name, flags, _config = scanner
    _write_secret(tmp_path / "repo" / "proj" / "sub" / "settings.txt")
    _symlink(tmp_path / "linkproj", tmp_path / "repo" / "proj")
    (tmp_path / "envdrift.toml").write_text('[guard.ignore_rules]\n"github-pat" = ["**"]\n')

    result, payload = _guard([target.replace("<tmp>", str(tmp_path)), *flags], cwd=tmp_path)

    assert _scanner_result(payload, name)["error"] is None
    # Shown where it really is: collapsed lexically the path named ``proj/...``,
    # a file that is not there.
    assert _scanner_paths(payload, name) == {Path("repo/proj/sub/settings.txt")}
    assert result.returncode in (1, 2), f"rc={result.returncode}\n{result.stderr}"


@pytest.mark.parametrize("scanner", _SCANNERS)
@pytest.mark.parametrize(
    ("args", "pattern"),
    [
        (["link.env"], "link.env"),
        (["linkproj"], "linkproj/**"),
        (["<tmp>/linkproj"], "linkproj/**"),
        # The real location matches too, for every scanner.
        (["link.env"], "**/real/**"),
    ],
    ids=["file-link", "dir-link", "abs-dir-link", "file-target"],
)
def test_guard_ignore_paths_cover_a_symlinked_path(
    tmp_path: Path, scanner, args: list[str], pattern: str
):
    """``ignore_paths`` suppresses a file shown under a symlink, for every scanner.

    gitleaks and Infisical reported a symlinked file under its target, and the
    native scanner a file below a symlinked directory at its real location:
    patterns matched those paths, not the one guard shows, so an entry for
    the link name let the findings through.
    """
    name, flags, _config = scanner
    _write_secret(tmp_path / "real" / "app.env")
    _symlink(tmp_path / "link.env", tmp_path / "real" / "app.env")
    _symlink(tmp_path / "linkproj", tmp_path / "real")
    (tmp_path / "envdrift.toml").write_text(f'[guard]\nignore_paths = ["{pattern}"]\n')

    result, payload = _guard(
        [*(arg.replace("<tmp>", str(tmp_path)) for arg in args), *flags], cwd=tmp_path
    )

    assert _scanner_result(payload, name)["error"] is None
    assert payload["findings"] == []
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("scanner", _SCANNERS)
@pytest.mark.parametrize(
    ("args", "kept"),
    [
        ([], {Path("tests/t.env")}),
        (["."], {Path("tests/t.env")}),
        (["proj"], set()),
        (["<tmp>/proj"], set()),
    ],
    ids=["no-path", "dot", "dir", "absolute-dir"],
)
def test_guard_a_bare_ignore_path_hides_a_directory_from_every_scanner(
    tmp_path: Path, scanner, args: list[str], kept: set[Path]
):
    """``ignore_paths = ["proj"]`` hid ``proj/sub/app.env`` from the built-in scanner only (#865).

    A bare name is matched against each part of the path, as ``.gitignore`` reads it. The
    ignore filter the engine applies to gitleaks and Infisical matched it against the whole
    path or a trailing part, so a directory of that name hid nothing from them.
    """
    name, flags, _config = scanner
    _write_secret(tmp_path / "proj" / "sub" / "app.env")
    _write_secret(tmp_path / "tests" / "t.env")
    (tmp_path / "envdrift.toml").write_text('[guard]\nignore_paths = ["proj"]\n')

    result, payload = _guard(
        [*(arg.replace("<tmp>", str(tmp_path)) for arg in args), *flags], cwd=tmp_path
    )

    assert _scanner_result(payload, name)["error"] is None, result.stderr
    # The binary and the built-in scanner agree: one verdict for the file.
    assert _scanner_paths(payload, name) == kept
    assert _finding_paths(payload) == kept


@pytest.mark.parametrize("scanner", _SCANNERS)
@pytest.mark.parametrize(
    ("pattern", "suppressed"),
    [("build", False), ("repo", False), ("sub", True), ("app.env", True), ("*.env", True)],
    ids=["above", "scan-path-name", "below", "file", "glob"],
)
def test_guard_a_bare_ignore_name_never_matches_the_directories_above_a_scan_path_outside_the_cwd(
    tmp_path: Path, scanner, pattern: str, suppressed: bool
):
    """``guard ../build/repo`` from a sibling directory: ``build`` is not part of the project (#865).

    A bare name is matched part by part below the scan path, as the built-in scanner
    does, so a checkout that merely lives under a directory of that name is not hidden:
    the pattern is written for the project in the directory guard runs in, not for this one.
    """
    name, flags, _config = scanner
    repo = tmp_path / "build" / "repo"
    _write_secret(repo / "sub" / "app.env")
    work = tmp_path / "work"
    work.mkdir()
    _ignore_paths(work, pattern)

    result, payload = _guard(["../build/repo", *flags], cwd=work)

    _assert_verdict(result, payload, name, repo / "sub" / "app.env", suppressed)


@pytest.mark.parametrize("scanner", _SCANNERS)
def test_guard_a_bare_ignore_rule_path_hides_that_rule_below_the_directory(tmp_path: Path, scanner):
    name, flags, _config = scanner
    _write_secret(tmp_path / "proj" / "sub" / "app.env")
    _write_secret(tmp_path / "tests" / "t.env")
    # A binary's rules are named for it: ``gitleaks-github-pat``.
    (tmp_path / "envdrift.toml").write_text(
        f'[guard.ignore_rules]\n"{name}-github-pat" = ["proj"]\n'
    )

    result, payload = _guard(flags, cwd=tmp_path)

    assert _scanner_result(payload, name)["error"] is None, result.stderr
    assert _scanner_paths(payload, name) == {Path("tests/t.env")}


@pytest.mark.parametrize("scanner", _SCANNERS)
@pytest.mark.parametrize("args", [[], ["."], ["proj"], ["<tmp>/proj"]])
@pytest.mark.parametrize("pattern", ["**/proj/**", "proj/sub/app.env"])
def test_guard_ignore_paths_give_one_verdict_however_the_path_is_spelled(
    tmp_path: Path, scanner, args: list[str], pattern: str
):
    """One pattern, one verdict: ``guard`` and ``guard .`` used to disagree (#855).

    ``**/proj/**`` matched the absolute path ``guard`` reported and not the
    relative one ``guard .`` reported, so gitleaks and Infisical findings
    were suppressed by one and reported by the other.
    """
    name, flags, _config = scanner
    _write_secret(tmp_path / "proj" / "sub" / "app.env")
    (tmp_path / "envdrift.toml").write_text(f'[guard]\nignore_paths = ["{pattern}"]\n')

    result, payload = _guard(
        [*(arg.replace("<tmp>", str(tmp_path)) for arg in args), *flags], cwd=tmp_path
    )

    assert _scanner_result(payload, name)["error"] is None
    assert payload["findings"] == []
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("scanner", _SCANNERS)
@pytest.mark.parametrize("args", [[], ["."]])
def test_guard_ignore_glob_ignores_directories_above_the_checkout(
    tmp_path: Path, scanner, args: list[str]
):
    """``**/build/**`` must not hide a checkout that merely lives under ``build/``.

    The built-in scanner reports absolute paths, and ``guard`` with no path hands
    gitleaks and Infisical the absolute working directory, so the glob matched
    ``<tmp>/build/repo/...`` through the directory above the checkout and every
    finding disappeared with exit 0.
    """
    name, flags, _config = scanner
    repo = tmp_path / "build" / "repo"
    _write_secret(repo / "proj" / "sub" / "app.env")
    (repo / "envdrift.toml").write_text('[guard]\nignore_paths = ["**/build/**"]\n')

    result, payload = _guard([*args, *flags], cwd=repo)

    scanner_error = _scanner_result(payload, name)["error"]
    if scanner_error is not None:  # the scanner did not run: not the #859 failure
        pytest.fail(f"{name} failed: {scanner_error}")
    assert {"native", name} <= {f["scanner"] for f in payload["findings"]}
    assert _scanner_paths(payload, name) == {Path("proj/sub/app.env")}
    assert result.returncode == 1, result.stderr


@pytest.mark.parametrize("scanner", _SCANNERS)
def test_guard_ignore_pattern_naming_a_directory_above_the_cwd_matches_the_reported_path(
    git_repo: Path, scanner
):
    """``../config/*`` suppresses what ``--pr-base`` run from a subdirectory reports.

    Every scanner reports the changed file as ``../config/settings.txt`` there,
    and docs/cli/guard.md says such a pattern is matched against that path.
    """
    name, flags, _config = scanner
    _feature_branch(git_repo)
    _write_secret(git_repo / "config" / "settings.txt")
    (git_repo / "sub").mkdir()
    (git_repo / "sub" / "envdrift.toml").write_text('[guard]\nignore_paths = ["../config/*"]\n')
    _git(git_repo, "add", "-A")
    _git(git_repo, "commit", "-q", "-m", "add secret")

    result, payload = _guard(["--pr-base", "base", *flags], cwd=git_repo / "sub")

    assert _scanner_result(payload, name)["error"] is None
    assert payload["findings"] == []
    assert result.returncode == 0, result.stderr


def _ignore_paths(directory: Path, pattern: str, **anchors: Path) -> None:
    """Write ``envdrift.toml`` with ``ignore_paths = [pattern]``, ``<name>`` expanded.

    An absolute pattern is written with ``/``, the separator patterns use on
    every platform.
    """
    for anchor, path in anchors.items():
        pattern = pattern.replace(f"<{anchor}>", path.as_posix())
    (directory / "envdrift.toml").write_text(f"[guard]\nignore_paths = ['{pattern}']\n")


def _assert_verdict(
    result: subprocess.CompletedProcess, payload: dict, name: str, shown: Path, suppressed: bool
) -> None:
    """``name`` and the native scanner report ``shown``, or nothing reports anything."""
    assert _scanner_result(payload, name)["error"] is None
    if suppressed:
        assert payload["findings"] == []
        assert result.returncode == 0, result.stderr
    else:
        assert {f["scanner"] for f in payload["findings"]} == {"native", name}
        assert _finding_paths(payload) == {shown}
        assert result.returncode == 1, result.stderr


@pytest.mark.parametrize("scanner", _SCANNERS)
@pytest.mark.parametrize(
    "args",
    [[], ["."], ["proj"], ["<repo>/proj"], ["../repo/proj"]],
    ids=["no-path", "dot", "subdir", "absolute-subdir", "subdir-via-parent"],
)
@pytest.mark.parametrize(
    ("pattern", "suppressed"),
    [
        # A relative pattern sees only names below the directory guard runs in ...
        ("**/build/**", False),
        ("build/repo/**", False),
        ("../repo/proj/**", False),
        # ... an absolute one the file's absolute path, whatever directory it names.
        ("<repo>/proj/**", True),
        ("<tmp>/build/**", True),
        # A leading ``/`` makes a pattern absolute: not rooted at the cwd.
        ("/proj/**", False),
    ],
    ids=[
        "glob-above",
        "relative-above",
        "parent-reference",
        "absolute",
        "absolute-above",
        "rooted",
    ],
)
def test_guard_ignore_patterns_in_a_checkout_under_a_directory_they_name(
    tmp_path: Path, scanner, args: list[str], pattern: str, suppressed: bool
):
    """One verdict per pattern for every spelling of the scan path and every scanner (#859).

    The built-in scanner reports absolute paths, and ``guard`` with no path or
    an absolute path makes gitleaks and Infisical report them too. Relative
    patterns matched them through the directories above the checkout, and an
    absolute pattern matched them but not the relative paths ``guard .``
    reports, so each spelling gave its own verdict.
    """
    name, flags, _config = scanner
    repo = tmp_path / "build" / "repo"
    _write_secret(repo / "proj" / "sub" / "app.env")
    _ignore_paths(repo, pattern, repo=repo, tmp=tmp_path)

    result, payload = _guard(
        [*(arg.replace("<repo>", str(repo)) for arg in args), *flags], cwd=repo
    )

    _assert_verdict(result, payload, name, Path("proj/sub/app.env"), suppressed)


@pytest.mark.parametrize("scanner", _SCANNERS)
@pytest.mark.parametrize("args", [["linkproj"], ["<cwd>/linkproj"]], ids=["relative", "absolute"])
@pytest.mark.parametrize(
    ("pattern", "suppressed"),
    [
        ("linkproj/**", True),
        # The link's target lies outside the cwd, under build/: only an
        # absolute pattern names it.
        ("**/build/**", False),
        ("<tmp>/build/proj/**", True),
    ],
    ids=["link-name", "target-glob", "target-absolute"],
)
def test_guard_ignore_patterns_for_a_symlinked_directory_outside_the_cwd(
    tmp_path: Path, scanner, args: list[str], pattern: str, suppressed: bool
):
    """A file below a symlink matches a pattern for the link name or its real location.

    A relative pattern names the real location only when it is below the
    directory guard runs in; ``**/build/**`` matched the target's absolute
    path through ``build/`` (#859).
    """
    name, flags, _config = scanner
    cwd = tmp_path / "work"
    cwd.mkdir()
    _write_secret(tmp_path / "build" / "proj" / "sub" / "app.env")
    _symlink(cwd / "linkproj", tmp_path / "build" / "proj")
    _ignore_paths(cwd, pattern, tmp=tmp_path)

    result, payload = _guard([*(arg.replace("<cwd>", str(cwd)) for arg in args), *flags], cwd=cwd)

    _assert_verdict(result, payload, name, Path("linkproj/sub/app.env"), suppressed)


@pytest.mark.parametrize("scanner", _SCANNERS)
@pytest.mark.parametrize("args", [["real"], ["<tmp>/real"]], ids=["relative", "absolute"])
def test_guard_ignore_pattern_for_a_link_name_does_not_cover_its_real_location(
    tmp_path: Path, scanner, args: list[str]
):
    """A file scanned through its real location matches only patterns for that location.

    docs/cli/guard.md: name the real location when you scan both ways.
    """
    name, flags, _config = scanner
    _write_secret(tmp_path / "real" / "app.env")
    _symlink(tmp_path / "linkproj", tmp_path / "real")
    _ignore_paths(tmp_path, "linkproj/**")

    result, payload = _guard(
        [*(arg.replace("<tmp>", str(tmp_path)) for arg in args), *flags], cwd=tmp_path
    )

    _assert_verdict(result, payload, name, Path("real/app.env"), suppressed=False)


def _cwd_of_a_process_started_in(directory: Path) -> Path:
    """The working directory a child process started in ``directory`` sees.

    POSIX resolves the symlinks in it (macOS ``/tmp`` is ``/private/tmp``);
    Windows keeps the path as given.
    """
    out = subprocess.run(  # nosec B603
        [sys.executable, "-c", "import os; print(os.getcwd())"],
        cwd=str(directory),
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return Path(out.strip())


@pytest.mark.parametrize("scanner", _SCANNERS)
@pytest.mark.parametrize(
    ("args", "logical_spelling"),
    [
        ([], False),
        (["."], False),
        (["proj"], False),
        (["<logical>/proj"], True),
        (["<logical>"], True),
    ],
    ids=["no-path", "dot", "subdir", "logical-subdir", "logical-cwd"],
)
@pytest.mark.parametrize(
    ("pattern", "suppressed"),
    [
        ("**/build/**", False),
        ("**/tmp/**", False),
        ("build/repo/**", False),
        ("<physical>/proj/**", True),
        ("proj/sub/*", True),
    ],
    ids=["glob-above", "link-above", "relative-above", "physical-absolute", "relative"],
)
def test_guard_ignore_patterns_through_a_symlinked_parent_of_the_cwd(
    tmp_path: Path,
    scanner,
    args: list[str],
    logical_spelling: bool,
    pattern: str,
    suppressed: bool,
):
    """``guard "$PWD/proj"`` where ``/tmp`` links to ``/private/tmp``, as on macOS (#859).

    guard runs in the physical directory, so a path through the symlinked
    spelling of it is shown absolute. Its trailing parts named the
    directories above the checkout, so ``**/build/**`` hid every finding for
    that spelling while ``guard proj`` reported them.
    """
    name, flags, _config = scanner
    physical = tmp_path / "private" / "x" / "build" / "repo"
    _write_secret(physical / "proj" / "sub" / "app.env")
    _symlink(tmp_path / "tmp", tmp_path / "private" / "x")
    logical = tmp_path / "tmp" / "build" / "repo"
    _ignore_paths(physical, pattern, physical=physical)
    shown = Path("proj/sub/app.env")
    if logical_spelling:
        # Shown absolute where guard runs in the physical directory (POSIX),
        # relative where it keeps the symlinked spelling (Windows).
        shown = logical / shown
        cwd = _cwd_of_a_process_started_in(logical)
        if shown.is_relative_to(cwd):
            shown = shown.relative_to(cwd)

    result, payload = _guard(
        [*(arg.replace("<logical>", str(logical)) for arg in args), *flags], cwd=logical
    )

    _assert_verdict(result, payload, name, shown, suppressed)


@pytest.mark.parametrize("args", [[], ["."]], ids=["no-path", "dot"])
def test_guard_native_keeps_scanning_links_in_default_ignored_directories(
    tmp_path: Path, args: list[str]
):
    """A tracked link in ``build/`` or ``node_modules/`` to a file elsewhere is reported.

    The built-in scanner never applied its directory-scoped defaults to such a
    link, which no other scanner follows; matching the link where it was
    found would have dropped it silently. Each link has its own target: two
    links to one file would be one finding (#861).
    """
    repo = tmp_path / "repo"
    for directory in ("build", "node_modules/pkg"):
        target = tmp_path / "shared" / directory.replace("/", "-") / "prod.env"
        _write_secret(target)
        (repo / directory).mkdir(parents=True)
        _symlink(repo / directory / "creds.env", target)
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")

    result, payload = _guard([*args, "--native-only"], cwd=repo)

    assert _scanner_result(payload, "native")["error"] is None
    assert _finding_paths(payload) == {
        Path("build/creds.env"),
        Path("node_modules/pkg/creds.env"),
    }
    assert result.returncode == 1, result.stderr


@pytest.mark.parametrize("args", [["."], ["../.."], ["<tmp>"]], ids=["dot", "above", "absolute"])
@pytest.mark.parametrize("pattern", ["builds/**", "builds"])
def test_guard_native_matches_a_link_under_the_cwd_below_the_cwd(
    tmp_path: Path, args: list[str], pattern: str
):
    """``guard ../..`` from ``builds/repo``: a link to ``builds/shared.txt`` is reported.

    The built-in scanner matched the link by its target's path below the scan
    path, ``builds/shared.txt``, which names a directory above the cwd, so the
    patterns hid it there; ``guard .`` matched its absolute path, so ``builds``
    hid it too (#859).
    """
    cwd = tmp_path / "builds" / "repo"
    _write_secret(tmp_path / "builds" / "shared.txt")
    (cwd / "proj").mkdir(parents=True)
    _symlink(cwd / "proj" / "link.txt", tmp_path / "builds" / "shared.txt")
    _ignore_paths(cwd, pattern)

    result, payload = _guard(
        [*(arg.replace("<tmp>", str(tmp_path)) for arg in args), "--native-only"], cwd=cwd
    )

    assert _scanner_result(payload, "native")["error"] is None
    assert Path("proj/link.txt") in _finding_paths(payload)
    assert result.returncode == 1, result.stderr


@pytest.mark.parametrize(
    ("pattern", "suppressed"),
    [("builds/**", False), ("builds", False), ("repo", False), ("real.env", True)],
)
def test_guard_native_matches_a_link_outside_the_cwd_by_its_target_below_the_cwd(
    tmp_path: Path, pattern: str, suppressed: bool
):
    """``guard ../..`` from ``builds/repo``: ``builds/elsewhere/link.env`` -> ``real.env``.

    The link's real location is under the cwd, so it is matched by that
    location below the cwd, as the scan engine matches it. The built-in
    scanner matched the path below the scan path, ``builds/repo/real.env``,
    whose directories are above the cwd, so the patterns dropped the link
    (#859).
    """
    cwd = tmp_path / "builds" / "repo"
    _write_secret(cwd / "real.env")
    (tmp_path / "builds" / "elsewhere").mkdir()
    _symlink(tmp_path / "builds" / "elsewhere" / "link.env", cwd / "real.env")
    _ignore_paths(cwd, pattern)

    result, payload = _guard(["../..", "--native-only"], cwd=cwd)

    assert _scanner_result(payload, "native")["error"] is None
    if suppressed:
        assert payload["findings"] == []
        assert result.returncode == 0, result.stderr
    else:
        # The link and its target are one file, so one finding, named where the file really
        # is (#861); the link was shown absolute, below the resolved scan path.
        assert _finding_paths(payload) == {Path("real.env")}
        assert result.returncode == 1, result.stderr


@pytest.mark.parametrize(
    ("pattern", "suppressed"),
    [("build", False), ("**/build/**", False), ("proj/link.txt", True)],
    ids=["dir-name", "glob", "link-name"],
)
def test_guard_native_matches_a_symlinked_file_where_it_was_found(
    tmp_path: Path, pattern: str, suppressed: bool
):
    """A symlink whose target lies outside the scan path is matched by its own path.

    The built-in scanner matched such a file by its absolute path, so in a
    checkout under ``build/`` the patterns ``build`` and ``**/build/**`` hid
    the secret behind the link (#859).
    """
    repo = tmp_path / "build" / "repo"
    _write_secret(tmp_path / "shared" / "secret.txt")
    (repo / "proj").mkdir(parents=True)
    _symlink(repo / "proj" / "link.txt", tmp_path / "shared" / "secret.txt")
    _ignore_paths(repo, pattern)

    result, payload = _guard([".", "--native-only"], cwd=repo)

    assert _scanner_result(payload, "native")["error"] is None
    if suppressed:
        assert payload["findings"] == []
        assert result.returncode == 0, result.stderr
    else:
        assert _finding_paths(payload) == {Path("proj/link.txt")}
        assert result.returncode == 1, result.stderr


@pytest.mark.parametrize("scanner", _SCANNERS)
@pytest.mark.parametrize("pattern", ["builds", "builds/**", "repo"])
def test_guard_scan_path_above_the_cwd_keeps_its_directories_out_of_ignores(
    tmp_path: Path, scanner, pattern: str
):
    """``guard ../../..`` from ``builds/repo/proj`` reports the file below the cwd.

    The built-in scanner matched ``ignore_paths`` against the path below the
    scan path, ``builds/repo/proj/sub/app.env``, whose directories are above
    the cwd, and hid what gitleaks and Infisical reported (#859).
    """
    name, flags, _config = scanner
    cwd = tmp_path / "builds" / "repo" / "proj"
    _write_secret(cwd / "sub" / "app.env")
    _ignore_paths(cwd, pattern)

    result, payload = _guard(["../../..", *flags], cwd=cwd)

    _assert_verdict(result, payload, name, Path("sub/app.env"), suppressed=False)


@pytest.mark.parametrize("scanner", _SCANNERS)
@pytest.mark.parametrize(
    ("pattern", "suppressed"),
    [
        ("ci-temp/**", False),
        ("**/envdrift-staged-*/**", False),
        ("config/**", True),
        ("<repo>/config/**", True),
    ],
    ids=["temp-dir", "copy-dir", "relative", "absolute"],
)
def test_guard_staged_ignores_match_the_staged_file_not_its_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner, pattern: str, suppressed: bool
):
    """``--staged`` scans copies in the temporary directory; patterns match the staged file.

    Patterns matched the copy's path, so one naming the temporary directory
    (``tmp/**`` where that is ``/tmp``) hid every staged finding, and an
    absolute pattern for the staged file never matched it (#859).
    """
    name, flags, _config = scanner
    repo = tmp_path / "repo"
    repo.mkdir()
    (tmp_path / "ci-temp").mkdir()
    monkeypatch.setenv("TMPDIR", str(tmp_path / "ci-temp"))
    _git(repo, "init", "-q")
    _write_secret(repo / "config" / "app.env")
    _git(repo, "add", "config/app.env")
    _ignore_paths(repo, pattern, repo=repo)

    result, payload = _guard(["--staged", *flags], cwd=repo)

    _assert_verdict(result, payload, name, Path("config/app.env"), suppressed)


@pytest.mark.parametrize("scanner", _SCANNERS)
@pytest.mark.parametrize(
    ("pattern", "suppressed"),
    [
        ("**/build/**", False),
        ("build/**", False),
        ("repo/**", False),
        ("ci-temp/**", False),
        # As the copy's path below the temporary directory always matched.
        ("config/*", True),
        ("**/config/**", True),
        ("<repo>/config/**", True),
    ],
    ids=["glob-above", "relative-above", "repo-name", "temp-dir", "repo-path", "glob", "absolute"],
)
def test_guard_staged_from_a_subdirectory_matches_a_staged_file_elsewhere_in_the_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner, pattern: str, suppressed: bool
):
    """``--staged`` from ``sub/``, only ``config/app.env`` staged, in a checkout under ``build/``.

    The staged file is outside the cwd and shown absolute. Matched by that
    path's trailing parts, ``**/build/**`` hid it and the commit shipped the
    secret with exit 0, where matching its copy had reported it (#859).
    """
    name, flags, _config = scanner
    repo = tmp_path / "build" / "repo"
    (repo / "sub").mkdir(parents=True)
    (tmp_path / "ci-temp").mkdir()
    monkeypatch.setenv("TMPDIR", str(tmp_path / "ci-temp"))
    _git(repo, "init", "-q")
    _write_secret(repo / "config" / "app.env")
    _git(repo, "add", "config/app.env")
    _ignore_paths(repo / "sub", pattern, repo=repo)

    result, payload = _guard(["--staged", *flags], cwd=repo / "sub")

    _assert_verdict(result, payload, name, repo / "config" / "app.env", suppressed)
