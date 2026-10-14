"""Gitleaks execution-truthfulness and history-reporting regressions."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from envdrift.scanner.gitleaks import (
    GitleaksScanner,
    _git_history_target,
    _prepare_scan_targets,
)


@pytest.fixture
def mock_scanner(tmp_path: Path) -> GitleaksScanner:
    """Create a scanner with a harmless stand-in binary."""
    scanner = GitleaksScanner(auto_install=False)
    binary_path = tmp_path / "gitleaks"
    binary_path.touch()
    scanner._binary_path = binary_path
    return scanner


def _initial_commit(path: Path) -> None:
    """Initialize ``path`` and create an empty commit without global Git config."""
    subprocess.run(["git", "init"], cwd=path, capture_output=True, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "--allow-empty",
            "-m",
            "initial",
        ],
        cwd=path,
        capture_output=True,
        check=True,
    )


class TestGitHistoryTarget:
    """The preflight prevents false-clean Gitleaks history scans."""

    def test_rejects_non_git_directory(self, tmp_path: Path):
        target, error = _git_history_target(tmp_path)

        assert target is None
        assert error is not None
        assert "not inside a Git repository" in error

    def test_rejects_repository_without_commits(self, tmp_path: Path):
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)

        target, error = _git_history_target(tmp_path)

        assert target is None
        assert error is not None
        assert "has no commits" in error

    def test_returns_repository_root(self, tmp_path: Path):
        _initial_commit(tmp_path)

        target, error = _git_history_target(tmp_path)

        assert target == tmp_path.resolve()
        assert error is None


class TestMixedHistoryTargets:
    """A preflight-failing target must not discard the valid targets (#641).

    One non-git argument used to abort the whole prepared-target list —
    regardless of argument order — silently suppressing the valid repository's
    history findings while the run reported only the preflight error.
    """

    @pytest.mark.parametrize("invalid_first", [True, False], ids=["invalid-first", "valid-first"])
    def test_valid_repository_survives_invalid_sibling(self, tmp_path: Path, invalid_first: bool):
        repo = tmp_path / "repo"
        repo.mkdir()
        _initial_commit(repo)
        plain = tmp_path / "plain"
        plain.mkdir()
        paths = [plain, repo] if invalid_first else [repo, plain]

        targets, errors = _prepare_scan_targets(paths, include_git_history=True)

        assert targets == [repo.resolve()]
        assert len(errors) == 1
        assert "not inside a Git repository" in errors[0]

    def test_all_invalid_targets_yield_only_diagnostics(self, tmp_path: Path):
        plain = tmp_path / "plain"
        plain.mkdir()
        no_commits = tmp_path / "empty-repo"
        no_commits.mkdir()
        subprocess.run(["git", "init"], cwd=no_commits, capture_output=True, check=True)

        targets, errors = _prepare_scan_targets([plain, no_commits], include_git_history=True)

        assert targets == []
        assert len(errors) == 2
        assert "not inside a Git repository" in errors[0]
        assert "has no commits" in errors[1]


@pytest.mark.parametrize(
    ("include_history", "command"),
    [(True, "git"), (False, "dir")],
    ids=["history", "working-tree"],
)
def test_scan_uses_modern_positional_command(
    mock_scanner: GitleaksScanner,
    tmp_path: Path,
    include_history: bool,
    command: str,
):
    """Gitleaks 8.x uses ``git``/``dir`` instead of deprecated ``detect``."""
    with (
        patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path),
        patch(
            "envdrift.scanner.gitleaks._git_history_target",
            return_value=(tmp_path, None),
        ),
        patch("subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(stdout="[]", stderr="", returncode=0)
        mock_scanner.scan([tmp_path], include_git_history=include_history)

    call_args = mock_run.call_args[0][0]
    assert call_args[1] == command
    assert "detect" not in call_args
    assert "--source" not in call_args
    assert "--no-git" not in call_args
    # The ASCII-art banner on stderr used to land in the scanner error (#843).
    assert "--no-banner" in call_args
    if include_history:
        # In the repository root, as before: gitleaks also reads its cwd's
        # .gitleaksignore, whose entries must not meet history fingerprints.
        assert call_args[-2:] == ["--", "."]
        assert mock_run.call_args.kwargs["cwd"] == tmp_path
    else:
        # In our cwd, on the directory as given, with the separator that
        # makes a symlinked root walk (#853).
        assert call_args[-2:] == ["--", f"{tmp_path}{os.sep}"]
        assert mock_run.call_args.kwargs["cwd"] is None


@pytest.mark.parametrize("target", ["-foo", "--report-path=pwned/notes.txt"])
def test_dash_prefixed_target_follows_the_end_of_options(
    mock_scanner: GitleaksScanner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str
):
    """A path that starts with ``-`` must not be parsed as gitleaks flags.

    Without ``--`` gitleaks read ``-foo/`` as ``-f oo/`` and failed, and a
    changed file named ``--report-path=pwned/notes.txt`` moved the report into
    the checkout and passed the scan clean.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / target).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / target).write_text("X=1\n")
    with (
        patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path),
        patch("subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        mock_scanner.scan([Path(target)])

    call_args = mock_run.call_args[0][0]
    assert call_args[-2:] == ["--", str(Path(target))]
    assert call_args.index("--") > call_args.index("--report-path")


def test_symlinked_file_findings_are_reported_under_the_link(
    mock_scanner: GitleaksScanner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """gitleaks scans a symlinked file as its target; its findings belong to the link.

    When path-based ignores matched only the reported path, a finding named
    after the target escaped an ``ignore_paths`` entry for the link guard was
    given. The link is the path guard shows, the name relative patterns match.
    """
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "app.env").write_text("X=1\n")
    try:
        (tmp_path / "link.env").symlink_to(tmp_path / "real" / "app.env")
    except OSError as exc:  # Windows without the symlink privilege
        pytest.skip(f"cannot create a symlink here: {exc}")
    monkeypatch.chdir(tmp_path)

    def fake_gitleaks(args: list[str], **kwargs):
        assert args[-1] == str(Path("real/app.env")), "a symlinked file is given as its target"
        report = Path(args[args.index("--report-path") + 1])
        report.write_text(
            json.dumps([{"File": args[-1], "RuleID": "x", "StartLine": 1, "Secret": "s3cr3t"}])
        )
        return MagicMock(stdout="", stderr="", returncode=0)

    with (
        patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path),
        patch("subprocess.run", side_effect=fake_gitleaks),
    ):
        result = mock_scanner.scan([Path("link.env")])

    assert result.error is None
    assert [f.file_path for f in result.findings] == [Path("link.env")]


# gitleaks 8.30.1 stderr, verbatim, for a scan path it cannot stat (#843).
_GITLEAKS_FTL = (
    "\x1b[90m4:30AM\x1b[0m \x1b[31mFTL\x1b[0m \x1b[1mstat proj: no such file or directory\x1b[0m\n"
)


@pytest.mark.parametrize("target", ["proj", "proj/sub/app.env"])
def test_relative_target_is_resolved_once(
    mock_scanner: GitleaksScanner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
):
    """gitleaks runs in our cwd and gets a cwd-relative target as given (#843, #854).

    It used to get the path unchanged while running inside that path, which
    resolved ``proj`` to ``proj/proj``. The finding must come back in the
    caller's (relative) form, not as ``app.env/app.env`` for a file target.
    """
    secret_file = tmp_path / "proj" / "sub" / "app.env"
    secret_file.parent.mkdir(parents=True)
    secret_file.write_text("X=1\n")
    monkeypatch.chdir(tmp_path)

    def fake_gitleaks(args: list[str], **kwargs):
        # Like the real binary: the argument is resolved against the cwd it
        # runs in, ours, and a finding's File is that argument joined with
        # the path below it.
        assert kwargs.get("cwd") is None, "gitleaks must run in our cwd"
        arg = Path(args[-1])
        resolved = arg.resolve()
        assert resolved == (tmp_path / target).resolve(), "target resolved twice"
        file_arg = arg if resolved.is_file() else arg / secret_file.relative_to(resolved)
        report = Path(args[args.index("--report-path") + 1])
        report.write_text(
            json.dumps([{"File": str(file_arg), "RuleID": "x", "StartLine": 1, "Secret": "s3cr3t"}])
        )
        return MagicMock(stdout="", stderr="", returncode=0)

    with (
        patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path),
        patch("subprocess.run", side_effect=fake_gitleaks),
    ):
        result = mock_scanner.scan([Path(target)])

    assert result.error is None
    assert [f.file_path for f in result.findings] == [Path("proj/sub/app.env")]


def test_scan_error_is_ansi_clean(mock_scanner: GitleaksScanner, tmp_path: Path):
    """The binary's colored stderr must not carry escapes into --json/SARIF (#843)."""
    with (
        patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path),
        patch("subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(stdout="", stderr=_GITLEAKS_FTL, returncode=1)
        result = mock_scanner.scan([tmp_path])

    assert result.error == "4:30AM FTL stat proj: no such file or directory"


def test_history_outside_git_is_an_error(mock_scanner: GitleaksScanner, tmp_path: Path):
    """A zero-commit Gitleaks false pass must not become a clean result."""
    with (
        patch(
            "envdrift.scanner.gitleaks._git_history_target",
            return_value=(None, "not inside a Git repository"),
        ),
        patch("subprocess.run") as mock_run,
    ):
        result = mock_scanner.scan([tmp_path], include_git_history=True)

    assert result.success is False
    assert result.error is not None
    assert "not inside a Git repository" in result.error
    mock_run.assert_not_called()


def test_history_scans_each_repository_once(mock_scanner: GitleaksScanner, tmp_path: Path):
    """Multiple requested paths in one repository do not duplicate the scan."""
    paths = [tmp_path / "first", tmp_path / "second"]
    for path in paths:
        path.mkdir()
    with (
        patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path),
        patch(
            "envdrift.scanner.gitleaks._git_history_target",
            return_value=(tmp_path, None),
        ),
        patch("subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(stdout="[]", stderr="", returncode=0)
        result = mock_scanner.scan(paths, include_git_history=True)

    assert result.success is True
    mock_run.assert_called_once()


@pytest.mark.integration
@pytest.mark.skipif(
    not GitleaksScanner(auto_install=False).is_installed(),
    reason="gitleaks not installed",
)
def test_real_history_reports_commit(tmp_path: Path):
    """The real Gitleaks 8.x history path returns commit-attributed findings."""
    token = "ghp_" + "016C7eX9bQ2vYwN3kLmZpRtUaScDfGhJkL01"
    _initial_commit(tmp_path)
    (tmp_path / "secret.txt").write_text(f"TOKEN={token}\n", encoding="utf-8")
    subprocess.run(["git", "add", "secret.txt"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-m",
            "add secret",
        ],
        cwd=tmp_path,
        capture_output=True,
        check=True,
    )

    result = GitleaksScanner(auto_install=False).scan([tmp_path], include_git_history=True)

    assert result.success is True, result.error
    assert result.findings
    assert all(finding.commit_sha for finding in result.findings)


@pytest.mark.integration
@pytest.mark.skipif(
    not GitleaksScanner(auto_install=False).is_installed(),
    reason="gitleaks not installed",
)
@pytest.mark.parametrize("invalid_first", [True, False], ids=["invalid-first", "valid-first"])
def test_real_mixed_targets_keep_history_finding(tmp_path: Path, invalid_first: bool):
    """A non-git sibling target must not suppress the repository's history
    finding — in either argument order (#641).

    The secret exists ONLY in git history (committed, then ``git rm``-ed), so a
    surviving finding proves the history scan of the valid repository ran. The
    invalid target stays visible as a per-target diagnostic in ``error``.
    """
    token = "ghp_" + "wJ2mX8kQ4tR7nY0cV5bL1sD3fG6hP9zA2eU4"
    repo = tmp_path / "repo"
    repo.mkdir()
    _initial_commit(repo)
    (repo / "creds.py").write_text(f'token = "{token}"\n', encoding="utf-8")
    git_identity = ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com"]
    subprocess.run(["git", "add", "creds.py"], cwd=repo, capture_output=True, check=True)
    subprocess.run(
        [*git_identity, "commit", "-m", "add creds"], cwd=repo, capture_output=True, check=True
    )
    subprocess.run(["git", "rm", "-q", "creds.py"], cwd=repo, capture_output=True, check=True)
    subprocess.run(
        [*git_identity, "commit", "-m", "remove creds"], cwd=repo, capture_output=True, check=True
    )

    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "readme.txt").write_text("nothing secret here\n", encoding="utf-8")
    paths = [plain, repo] if invalid_first else [repo, plain]

    result = GitleaksScanner(auto_install=False).scan(paths, include_git_history=True)

    assert result.findings, (
        "the valid repository's history finding must survive an invalid sibling target"
    )
    assert all(finding.commit_sha for finding in result.findings)
    assert result.error is not None
    assert "not inside a Git repository" in result.error
    assert result.success is False, "the invalid target keeps the run truthfully incomplete"
