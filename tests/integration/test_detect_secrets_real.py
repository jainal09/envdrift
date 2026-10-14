"""Integration tests for the detect-secrets scanner against the real package.

detect-secrets runs as ``python -m detect_secrets`` in envdrift's own
interpreter, so these tests skip unless the pinned package is importable there
(CI installs it from ``constants.json``). Findings come from real scans of real
files; nothing about the scanner is mocked.
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import json
import os
import pkgutil
import re
import shutil
import subprocess  # nosec B404
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from envdrift.scanner import detect_secrets as detect_secrets_module
from envdrift.scanner.base import FindingSeverity
from envdrift.scanner.detect_secrets import (
    DETECTOR_SEVERITY,
    DetectSecretsScanner,
    _get_detect_secrets_version,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.skipif(
        importlib.util.find_spec("detect_secrets") is None,
        reason="detect-secrets not installed (pip install detect-secrets)",
    ),
]


def _plugin_classes() -> Iterator[type]:
    """Yield every detector class the installed detect-secrets ships."""
    plugins = importlib.import_module("detect_secrets.plugins")
    base = importlib.import_module("detect_secrets.plugins.base").BasePlugin
    for module_info in pkgutil.iter_modules(plugins.__path__):
        module = importlib.import_module(f"detect_secrets.plugins.{module_info.name}")
        for _name, cls in inspect.getmembers(module, inspect.isclass):
            if issubclass(cls, base) and cls is not base:
                yield cls


def _emitted_secret_types() -> set[str]:
    """Return every ``secret_type`` the installed detect-secrets plugins emit."""
    secret_types = (getattr(cls, "secret_type", None) for cls in _plugin_classes())
    return {secret_type for secret_type in secret_types if isinstance(secret_type, str)}


def test_every_severity_key_is_a_type_detect_secrets_emits():
    """A DETECTOR_SEVERITY key no plugin emits is dead: its findings fall back to HIGH.

    Four keys were dead this way ("Cloudant", "npm credentials", "OpenAI API
    Key", "PyPI upload token"). This catches a rename on the next version bump.
    """
    emitted = _emitted_secret_types()
    assert emitted, "found no detect-secrets plugins to read secret types from"
    dead = sorted(set(DETECTOR_SEVERITY) - emitted)
    assert not dead, f"DETECTOR_SEVERITY keys no plugin emits: {dead}"


def test_real_scan_grades_credential_detectors_critical(git_repo: Path):
    """npm, OpenAI, PyPI and Cloudant credentials found by a real scan are CRITICAL.

    The values are assembled from fragments so no complete secret literal
    appears in source (GitHub push protection).
    """
    a20, b20 = "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0"
    files = {
        "npm.cfg": "//registry.npmjs.org/:_authToken=npm_" + "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0FeDcBa",
        "openai.cfg": "OPENAI=sk-" + a20 + "T3Blbk" + "FJ" + b20,
        "pypi.cfg": "TOKEN=pypi-AgEIcHlwaS5vcmc" + "Ab1-Cd2_Ef3Gh4" * 6,
        "cloudant.cfg": "cloudant_password='" + "0123456789abcdef" * 4 + "'",
    }
    for name, line in files.items():
        (git_repo / name).write_text(line + "\n")
    # The scanner only covers git-tracked files.
    subprocess.run(["git", "add", "-A"], cwd=git_repo, capture_output=True, check=True)

    result = DetectSecretsScanner(auto_install=False).scan([git_repo])

    assert result.error is None, result.error
    graded = {(Path(f.file_path).name, f.rule_description): f.severity for f in result.findings}
    expected = {
        ("npm.cfg", "NPM tokens"),
        ("openai.cfg", "OpenAI Token"),
        ("pypi.cfg", "PyPI Token"),
        ("cloudant.cfg", "Cloudant Credentials"),
    }
    missing = expected - graded.keys()
    assert not missing, f"detect-secrets did not report {sorted(missing)}; got {sorted(graded)}"
    for key in sorted(expected):
        assert graded[key] == FindingSeverity.CRITICAL, f"{key} graded {graded[key]}"


NPM_TOKEN_LINE = "//registry.npmjs.org/:_authToken=npm_" + "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0FeDcBa\n"
OTHER_NPM_TOKEN_LINE = (
    "//registry.npmjs.org/:_authToken=npm_" + "Qa1Wb2Ec3Rd4Tf5Yg6Uh7Ij8Ok9Pl0MnBvCx\n"
)


def test_scan_outside_a_git_repo_is_not_silently_clean(tmp_path: Path):
    """A secret in a non-git directory is reported, not skipped as a clean run (#851).

    detect-secrets lists a directory's files with ``git ls-files``: outside a repository that
    printed ``fatal: not a git repository``, exited 0 and reported no files at all, which
    envdrift took for a clean scan of a directory nothing had looked at.
    """
    (tmp_path / "npm.cfg").write_text(NPM_TOKEN_LINE)

    result = DetectSecretsScanner(auto_install=False).scan([tmp_path])

    assert result.error is None, result.error
    reported = [f for f in result.findings if f.rule_description == "NPM tokens"]
    assert [Path(f.file_path).name for f in reported] == ["npm.cfg"], (
        "detect-secrets covered nothing yet reported a clean run"
    )
    assert {f.severity for f in reported} == {FindingSeverity.CRITICAL}


def test_scan_outside_a_git_repo_still_skips_the_excluded_directories(tmp_path: Path):
    """``--all-files`` keeps the exclude pattern: vendored and build directories stay out."""
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "npm.cfg").write_text(NPM_TOKEN_LINE)
    for skipped in ("node_modules", ".venv", "dist", "build", "vendor"):
        (tmp_path / skipped).mkdir()
        (tmp_path / skipped / "npm.cfg").write_text(OTHER_NPM_TOKEN_LINE)

    result = DetectSecretsScanner(auto_install=False).scan([tmp_path])

    assert result.error is None, result.error
    assert sorted(Path(f.file_path).relative_to(tmp_path).as_posix() for f in result.findings) == [
        "app/npm.cfg"
    ]


def test_scan_inside_a_git_repo_covers_the_tracked_files_only(git_repo: Path):
    """In a repository detect-secrets scans what git tracks, as it always did (documented).

    A file that is not added yet is not scanned; ``git add`` it first.
    """
    (git_repo / "tracked.cfg").write_text(NPM_TOKEN_LINE)
    (git_repo / "untracked.cfg").write_text(OTHER_NPM_TOKEN_LINE)
    subprocess.run(["git", "add", "tracked.cfg"], cwd=git_repo, capture_output=True, check=True)

    result = DetectSecretsScanner(auto_install=False).scan([git_repo])

    assert result.error is None, result.error
    assert [Path(f.file_path).name for f in result.findings] == ["tracked.cfg"]


def test_scan_of_a_single_file_does_not_need_a_repository(tmp_path: Path):
    target = tmp_path / "npm.cfg"
    target.write_text(NPM_TOKEN_LINE)

    result = DetectSecretsScanner(auto_install=False).scan([target])

    assert result.error is None, result.error
    assert [f.rule_description for f in result.findings] == ["NPM tokens"]


def _guard(args: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Run the real ``envdrift guard`` CLI as a subprocess."""
    return subprocess.run(
        [sys.executable, "-m", "envdrift.cli", "guard", *args],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )


def test_guard_outside_a_git_repo_reports_what_detect_secrets_finds(
    tmp_path: Path, integration_env: dict[str, str]
):
    """The real CLI: ``guard --detect-secrets`` on a plain directory is not a clean run (#851)."""
    (tmp_path / "npm.cfg").write_text(NPM_TOKEN_LINE)

    result = _guard(
        [".", "--no-gitleaks", "--detect-secrets", "--no-auto-install", "--json"],
        cwd=tmp_path,
        env=integration_env,
    )

    payload = json.loads(result.stdout)
    found = [f for f in payload["findings"] if f["scanner"] == "detect-secrets"]
    assert [(Path(f["file_path"]).name, f["severity"]) for f in found] == [("npm.cfg", "critical")]
    scanner = next(r for r in payload["scanner_results"] if r["name"] == "detect-secrets")
    assert scanner["error"] is None
    assert result.returncode == 1, (result.returncode, result.stderr)


# --- A subdirectory of a git repository is scanned too (#851) ---


def _add_tracked(repo: Path, *names: str) -> None:
    """Write the npm token to each file and ``git add`` it, so detect-secrets lists it."""
    for name in names:
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(NPM_TOKEN_LINE)
    subprocess.run(["git", "add", "--", *names], cwd=repo, capture_output=True, check=True)


def _found(result_findings: list, below: Path) -> list[str]:
    return sorted(Path(f.file_path).relative_to(below).as_posix() for f in result_findings)


def test_scan_of_a_subdirectory_of_a_git_repo_covers_the_files_git_tracks_there(git_repo: Path):
    """From the subdirectory detect-secrets matched none of the files git lists, silently.

    ``git ls-files`` gives paths relative to the top level of the repository and detect-secrets
    builds the paths of the files it walks relative to its working directory. They agree only
    at the top level, so ``guard sub`` reported a clean run (exit 0, no error, no file) for a
    subdirectory that held a leaked token.
    """
    _add_tracked(git_repo, "top.cfg", "sub/a.cfg", "sub/deep/b.cfg", "other/c.cfg")
    scanner = DetectSecretsScanner(auto_install=False)

    top = scanner.scan([git_repo])
    sub = scanner.scan([git_repo / "sub"])
    deep = scanner.scan([git_repo / "sub" / "deep"])
    other = scanner.scan([git_repo / "other"])

    for result in (top, sub, deep, other):
        assert result.error is None, result.error
        assert result.warnings == []
    assert _found(top.findings, git_repo) == [
        "other/c.cfg",
        "sub/a.cfg",
        "sub/deep/b.cfg",
        "top.cfg",
    ]
    assert _found(sub.findings, git_repo) == ["sub/a.cfg", "sub/deep/b.cfg"]
    assert _found(deep.findings, git_repo) == ["sub/deep/b.cfg"]
    assert _found(other.findings, git_repo) == ["other/c.cfg"]
    assert {f.severity for f in sub.findings} == {FindingSeverity.CRITICAL}


def test_scan_of_a_subdirectory_skips_what_the_top_level_scan_skips(git_repo: Path):
    """The same files are scanned whichever directory of the repository you point it at."""
    _add_tracked(
        git_repo,
        "sub/a.cfg",
        "sub/vendor/v.cfg",
        "sub/deep/node_modules/n.cfg",
        "sub/build",  # a FILE called build: scanned
    )
    (git_repo / "sub" / "untracked.cfg").write_text(OTHER_NPM_TOKEN_LINE)
    scanner = DetectSecretsScanner(auto_install=False)

    sub = scanner.scan([git_repo / "sub"])
    top = scanner.scan([git_repo])

    expected = ["sub/a.cfg", "sub/build"]
    assert _found(sub.findings, git_repo) == expected
    assert _found(top.findings, git_repo) == expected


def test_scan_of_a_directory_named_like_an_excluded_one_scans_it(git_repo: Path):
    """The directory you name is scanned whatever it is called; only what is inside is skipped."""
    _add_tracked(git_repo, "build/a.cfg", "build/dist/skipped.cfg", "vendor/lib/b.cfg")
    scanner = DetectSecretsScanner(auto_install=False)

    build = scanner.scan([git_repo / "build"])
    lib = scanner.scan([git_repo / "vendor" / "lib"])

    assert _found(build.findings, git_repo) == ["build/a.cfg"]
    assert _found(lib.findings, git_repo) == ["vendor/lib/b.cfg"]


def test_scan_of_a_relative_subdirectory_from_inside_the_repository(
    git_repo: Path, monkeypatch: pytest.MonkeyPatch
):
    _add_tracked(git_repo, "sub/a.cfg", "sub/deep/b.cfg")
    monkeypatch.chdir(git_repo / "sub")
    scanner = DetectSecretsScanner(auto_install=False)

    dot = scanner.scan([Path()])
    deep = scanner.scan([Path("deep")])

    assert sorted(Path(f.file_path).as_posix() for f in dot.findings) == ["a.cfg", "deep/b.cfg"]
    assert [Path(f.file_path).as_posix() for f in deep.findings] == ["deep/b.cfg"]


def test_scan_of_a_directory_with_nothing_tracked_warns_instead_of_reporting_clean(
    git_repo: Path,
):
    """A new repository whose files are not added yet is not a clean scan.

    detect-secrets prints an empty report for it, exactly as for a directory with no secret.
    """
    (git_repo / "new.cfg").write_text(NPM_TOKEN_LINE)

    result = DetectSecretsScanner(auto_install=False).scan([git_repo])

    assert result.error is None, result.error
    assert result.findings == []
    (warning,) = result.warnings
    assert warning.startswith("Scanned nothing in ")
    assert "git add" in warning


def test_scan_of_paths_that_look_like_options_scans_them(git_repo: Path):
    """A file named ``--exclude-files=.`` is a path, not the option that excludes everything.

    argparse took it for the option, so detect-secrets had no path and nothing to scan, and the
    run passed as clean. A directory starting with ``-`` failed with a usage error instead.
    """
    option_like = "--exclude-files=."
    _add_tracked(git_repo, option_like, "-sub/a.cfg", "plain.cfg")
    scanner = DetectSecretsScanner(auto_install=False)

    file_result = scanner.scan([git_repo / option_like])
    dir_result = scanner.scan([git_repo / "-sub"])

    assert file_result.error is None, file_result.error
    assert dir_result.error is None, dir_result.error
    assert [Path(f.file_path).name for f in file_result.findings] == [option_like]
    assert _found(dir_result.findings, git_repo) == ["-sub/a.cfg"]


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
    _add_tracked(git_repo, "café.cfg", "plain.cfg", "sub/naïve.cfg")
    scanner = DetectSecretsScanner(auto_install=False)

    top = scanner.scan([git_repo])
    sub = scanner.scan([git_repo / "sub"])

    assert top.error is None, top.error
    assert sub.error is None, sub.error
    assert _found(top.findings, git_repo) == ["café.cfg", "plain.cfg", "sub/naïve.cfg"]
    assert _found(sub.findings, git_repo) == ["sub/naïve.cfg"]


def _track_or_skip(repo: Path, *names: str) -> None:
    """``_add_tracked``, skipping where the file system cannot hold one of the names."""
    try:
        _add_tracked(repo, *names)
    except OSError as exc:
        pytest.skip(f"this file system cannot hold the name: {exc}")


@pytest.mark.skipif(sys.platform == "win32", reason="Windows file names cannot hold these")
def test_scan_says_so_when_git_quotes_a_tracked_name_whatever_the_setting(git_repo: Path):
    """Git quotes a name with a double quote or a backslash even with ``core.quotepath`` off.

    detect-secrets cannot match such a name, so it drops the file. That is reported as a warning,
    where it used to be a clean run.
    """
    _track_or_skip(git_repo, 'say "hi".cfg', "plain.cfg", "café.cfg")

    result = DetectSecretsScanner(auto_install=False).scan([git_repo])

    assert result.error is None, result.error
    assert _found(result.findings, git_repo) == ["café.cfg", "plain.cfg"]
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
    assert _found(result.findings, git_repo) == ["plain.cfg"]
    (warning,) = result.warnings
    assert "the name of 2 tracked file(s)" in warning
    assert repr(not_utf8) in warning
    assert repr("naïve.cfg") in warning


@pytest.mark.parametrize("name", ["build", "dist", "vendor", "coverage"])
def test_scan_of_a_file_named_like_an_excluded_directory_scans_it(tmp_path: Path, name: str):
    """``build`` is a script here, not a directory: it was skipped, named or in a directory."""
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / name).write_text(NPM_TOKEN_LINE)
    (tmp_path / name).write_text(OTHER_NPM_TOKEN_LINE)
    scanner = DetectSecretsScanner(auto_install=False)

    named = scanner.scan([tmp_path / name])
    walked = scanner.scan([tmp_path])

    assert [Path(f.file_path).name for f in named.findings] == [name]
    assert _found(walked.findings, tmp_path) == [f"bin/{name}", name]


def test_scan_outside_a_git_repo_skips_dependency_and_cache_directories(tmp_path: Path):
    """``--all-files`` has no ``.gitignore`` to lean on, so the usual dependency trees are named."""
    (tmp_path / "app.cfg").write_text(NPM_TOKEN_LINE)
    for skipped in ("venv", ".tox", ".nox", "site-packages", ".mypy_cache", ".pytest_cache"):
        (tmp_path / "pkg" / skipped).mkdir(parents=True)
        (tmp_path / "pkg" / skipped / "npm.cfg").write_text(OTHER_NPM_TOKEN_LINE)

    result = DetectSecretsScanner(auto_install=False).scan([tmp_path])

    assert result.error is None, result.error
    assert _found(result.findings, tmp_path) == ["app.cfg"]


def test_guard_from_a_subdirectory_of_a_git_repo_reports_what_detect_secrets_finds(
    git_repo: Path, integration_env: dict[str, str]
):
    """The real CLI, run inside the repository: ``guard .`` in ``sub`` is not a clean run."""
    _add_tracked(git_repo, "top.cfg", "sub/a.cfg")

    result = _guard(
        [".", "--no-gitleaks", "--detect-secrets", "--no-auto-install", "--json"],
        cwd=git_repo / "sub",
        env=integration_env,
    )

    payload = json.loads(result.stdout)
    found = [f for f in payload["findings"] if f["scanner"] == "detect-secrets"]
    assert [(Path(f["file_path"]).as_posix(), f["severity"]) for f in found] == [
        ("a.cfg", "critical")
    ]
    assert result.returncode == 1, (result.returncode, result.stderr)


def test_guard_of_a_subdirectory_named_from_the_top_level_reports_it_too(
    git_repo: Path, integration_env: dict[str, str]
):
    _add_tracked(git_repo, "top.cfg", "sub/deeper/nested.cfg")

    result = _guard(
        ["sub", "--no-gitleaks", "--detect-secrets", "--no-auto-install", "--json"],
        cwd=git_repo,
        env=integration_env,
    )

    payload = json.loads(result.stdout)
    found = [f for f in payload["findings"] if f["scanner"] == "detect-secrets"]
    assert [Path(f["file_path"]).as_posix() for f in found] == ["sub/deeper/nested.cfg"]
    assert result.returncode == 1, (result.returncode, result.stderr)


def test_guard_says_so_when_detect_secrets_has_no_tracked_file_to_scan(
    git_repo: Path, integration_env: dict[str, str]
):
    (git_repo / "new.cfg").write_text("x = 1\n")

    result = _guard(
        [".", "--no-gitleaks", "--detect-secrets", "--no-auto-install", "--json"],
        cwd=git_repo,
        env=integration_env,
    )

    payload = json.loads(result.stdout)
    scanner = next(r for r in payload["scanner_results"] if r["name"] == "detect-secrets")
    (warning,) = scanner["warnings"]
    assert warning.startswith("Scanned nothing in ")
    assert f"Warning: detect-secrets: {warning}" in result.stderr
    # A notice, not a failure: nothing is wrong with the scan, and the exit code stays 0.
    assert scanner["error"] is None
    assert result.returncode == 0, (result.returncode, result.stderr)


# --- The installed detect-secrets is checked against the pin ---


def test_the_pinned_detect_secrets_is_installed_and_raises_no_warning():
    """CI installs the version from constants.json; nothing is said when it is the one in use."""
    pinned = _get_detect_secrets_version()
    assert detect_secrets_module._installed_version() == pinned, (
        f"envdrift is pinned to detect-secrets {pinned}: pip install detect-secrets=={pinned}"
    )
    assert detect_secrets_module._version_warnings() == []


def test_scan_with_the_pinned_version_carries_no_warning(tmp_path: Path):
    (tmp_path / "npm.cfg").write_text(NPM_TOKEN_LINE)

    result = DetectSecretsScanner(auto_install=False).scan([tmp_path])

    assert result.error is None, result.error
    assert result.warnings == []


@pytest.mark.parametrize("mode", ["--json", "--sarif", ""], ids=["json", "sarif", "human"])
def test_guard_with_the_pinned_version_prints_no_version_warning(
    tmp_path: Path, integration_env: dict[str, str], mode: str
):
    (tmp_path / "app.py").write_text("x = 1\n")

    result = _guard(
        [".", "--no-gitleaks", "--detect-secrets", "--no-auto-install", *([mode] if mode else [])],
        cwd=tmp_path,
        env=integration_env,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "Scanner Warnings" not in result.stdout
    assert "Warning:" not in result.stderr
    if mode == "--json":
        scanners = json.loads(result.stdout)["scanner_results"]
        assert [r["warnings"] for r in scanners] == [[], []]
    if mode == "--sarif":
        invocation = json.loads(result.stdout)["runs"][0]["invocations"][0]
        assert invocation["toolExecutionNotifications"] == []


@pytest.fixture(scope="module")
def other_detect_secrets(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, Path]:
    """A directory holding another detect-secrets release, to put first on PYTHONPATH.

    ``python -m detect_secrets`` is how envdrift runs it, so a child process whose PYTHONPATH
    leads with this directory uses that release while the environment keeps the pinned one.
    Skips when the release cannot be installed (no network, no installer) or cannot run.
    """
    pinned = _get_detect_secrets_version()
    version = next(v for v in ("1.4.0", "1.3.0") if v != pinned)
    target = tmp_path_factory.mktemp("other-detect-secrets")
    spec = f"detect-secrets=={version}"
    uv = shutil.which("uv")
    install = (
        [uv, "pip", "install", "--python", sys.executable, "--target", str(target)]
        if uv
        else [sys.executable, "-m", "pip", "install", "--target", str(target)]
    )
    try:
        done = subprocess.run(
            [*install, "--no-deps", "--quiet", spec],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"cannot install {spec}: {exc}")
    if done.returncode != 0:
        pytest.skip(f"cannot install {spec}: {done.stderr.strip()[:200]}")
    env = {**os.environ, "PYTHONPATH": str(target)}
    try:
        probe = subprocess.run(
            [sys.executable, "-m", "detect_secrets", "--version"],
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"{spec} does not run here: {exc}")
    if probe.returncode != 0 or version not in probe.stdout:
        pytest.skip(f"{spec} does not run here: {probe.stderr.strip()[:200]}")
    return version, target


@pytest.fixture
def other_version_env(
    other_detect_secrets: tuple[str, Path], integration_env: dict[str, str]
) -> tuple[str, dict[str, str]]:
    version, target = other_detect_secrets
    env = dict(integration_env)
    env["PYTHONPATH"] = os.pathsep.join([str(target), integration_env["PYTHONPATH"]])
    return version, env


@pytest.mark.parametrize("mode", ["--json", "--sarif", ""], ids=["json", "sarif", "human"])
def test_guard_warns_when_another_detect_secrets_is_installed(
    git_repo: Path, other_version_env: tuple[str, dict[str, str]], mode: str
):
    """The real CLI with a real older detect-secrets: a warning in every output mode.

    Not fatal: the scan still ran on a clean repository, so the exit code is 0, and nothing
    is reinstalled. The older release lacks detectors the pinned one has (PyPI, OpenAI,
    Telegram, GitLab), which is exactly why its severities cannot be trusted.
    """
    version, env = other_version_env
    pinned = _get_detect_secrets_version()
    (git_repo / "app.py").write_text("x = 1\n")
    subprocess.run(["git", "add", "-A"], cwd=git_repo, capture_output=True, check=True)

    result = _guard(
        [".", "--no-gitleaks", "--detect-secrets", "--no-auto-install", *([mode] if mode else [])],
        cwd=git_repo,
        env=env,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    if mode == "--json":
        payload = json.loads(result.stdout)
        scanner = next(r for r in payload["scanner_results"] if r["name"] == "detect-secrets")
        (warning,) = scanner["warnings"]
        assert scanner["error"] is None
        assert payload["exit_code"] == 0
        assert f"Warning: detect-secrets: {warning}" in result.stderr
    elif mode == "--sarif":
        invocation = json.loads(result.stdout)["runs"][0]["invocations"][0]
        (note,) = invocation["toolExecutionNotifications"]
        assert note["level"] == "warning"
        assert invocation["executionSuccessful"] is True
        warning = note["message"]["text"]
        assert f"Warning: {warning}" in result.stderr
    else:
        # The human panel wraps the text at the terminal width, so compare without its borders.
        assert "Scanner Warnings" in result.stdout
        warning = " ".join(re.sub(r"[│╭╮╰╯─]", " ", result.stdout).split())
        assert "Warning:" not in result.stderr
    assert f"The installed version is {version}" in warning
    assert f"version {pinned}" in warning
    assert "severities may be inaccurate" in warning
    assert f"pip install detect-secrets=={pinned}" in warning
