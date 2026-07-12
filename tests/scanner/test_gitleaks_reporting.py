"""Gitleaks execution-truthfulness and history-reporting regressions."""

from __future__ import annotations

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

        assert [target for target, _base in targets] == [repo.resolve()]
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
    assert call_args[-1] == str(tmp_path)


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
