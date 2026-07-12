"""Gitleaks execution-truthfulness and history-reporting regressions."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from envdrift.scanner.gitleaks import GitleaksScanner, _git_history_target


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
