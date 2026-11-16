"""A history finding is judged by its file in the commit it was found in (#1014).

A history scan reports a secret at the line it had in an old commit. The engine's filters read
today's file at that line, so a secret committed before its file was encrypted was dropped when
the same line now held an encrypted value, and an ignore comment written there later dropped it
too. Each test commits real files to a real repository. A stub scanner reports the findings, as
gitleaks reports them from ``git log -p``; the engine's filters run for real.
"""

from __future__ import annotations

import subprocess  # nosec B404
from pathlib import Path

import pytest

from envdrift.scanner.base import FindingSeverity, ScanFinding, ScannerBackend, ScanResult
from envdrift.scanner.engine import GuardConfig, ScanEngine

_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLX"
_CIPHERTEXT = "encrypted:BEj2" + "Zq9yKxw0Lr3VtP8sN1mD5cH7aG4fU6eB2oI9kJ3lQ0wR5tY8uA1sD4fG7hJ0kL3z"


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True)
    return result.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "test@test.com")
    _git(tmp_path, "config", "user.name", "Test")
    return tmp_path


def _commit(repo: Path, name: str, second_line: str) -> str:
    """Commit ``name`` with ``second_line`` as its line 2; return the commit."""
    (repo / name).write_text(f"SETTING_1=value1\n{second_line}\nSETTING_3=value3\n")
    _git(repo, "add", "-f", "--", name)
    _git(repo, "commit", "-q", "-m", f"line 2 of {name}")
    return _git(repo, "rev-parse", "HEAD")


class _HistoryScanner(ScannerBackend):
    """Reports the findings it is given, as a scanner of git history does."""

    supports_git_history = True

    def __init__(self, findings: list[ScanFinding]) -> None:
        self._findings = findings

    @property
    def name(self) -> str:
        return "gitleaks"

    @property
    def description(self) -> str:
        return "reports the given findings"

    def is_installed(self) -> bool:
        return True

    def scan(self, paths: list[Path], include_git_history: bool = False) -> ScanResult:
        return ScanResult(scanner_name=self.name, findings=list(self._findings))


def _finding(repo: Path, commit: str | None, name: str = ".env.production") -> ScanFinding:
    """gitleaks' finding of the value on line 2 of ``name`` in ``commit``."""
    return ScanFinding(
        file_path=repo / name,
        rule_id="gitleaks-aws-access-token",
        rule_description="AWS",
        description="Secret detected: AWS",
        severity=FindingSeverity.CRITICAL,
        scanner="gitleaks",
        line_number=2,
        column_number=len("AWS_ACCESS_KEY_ID=") + 1,
        commit_sha=commit,
    )


def _reported(repo: Path, findings: list[ScanFinding], *, history: bool = True, **config) -> list:
    """The commits of the findings the engine reports, scanning ``repo`` from inside it."""
    engine = ScanEngine(
        GuardConfig(use_native=False, use_gitleaks=False, include_git_history=history, **config)
    )
    engine.scanners = [_HistoryScanner(findings)]
    result = engine.scan([repo])
    return [f.commit_sha for f in result.unique_findings]


def test_a_secret_in_history_is_kept_when_its_line_is_encrypted_now(repo: Path):
    plaintext = _commit(repo, ".env.production", f"AWS_ACCESS_KEY_ID={_KEY}")
    _commit(repo, ".env.production", f'SETTING_2="{_CIPHERTEXT}"')

    assert _reported(repo, [_finding(repo, plaintext)]) == [plaintext]


def test_a_history_finding_in_a_value_encrypted_in_its_commit_is_dropped(repo: Path):
    """Ciphertext is judged by its commit, though today's file holds plaintext there."""
    encrypted = _commit(repo, ".env.production", f'AWS_ACCESS_KEY_ID="{_CIPHERTEXT}"')
    _commit(repo, ".env.production", "AWS_ACCESS_KEY_ID=decrypted-later")

    assert _reported(repo, [_finding(repo, encrypted)]) == []


def test_a_history_finding_is_kept_when_git_cannot_show_its_commit(repo: Path):
    """A commit git cannot show leaves nothing to judge by, so the finding is kept."""
    _commit(repo, ".env.production", f'SETTING_2="{_CIPHERTEXT}"')
    unknown = "0123456789abcdef" * 2 + "01234567"

    assert _reported(repo, [_finding(repo, unknown)]) == [unknown]


def test_a_history_finding_with_a_commit_that_is_not_an_id_is_kept(repo: Path):
    """Text that is not a commit id is never handed to git, which could read it as an option."""
    _commit(repo, ".env.production", f'SETTING_2="{_CIPHERTEXT}"')

    assert _reported(repo, [_finding(repo, "--output=x")]) == ["--output=x"]
    assert not (repo / "x").exists()


def test_without_history_a_finding_is_judged_by_todays_file(repo: Path):
    """Outside a history scan a finding is in today's files, whatever commit it names."""
    commit = _commit(repo, ".env.production", f"AWS_ACCESS_KEY_ID={_KEY}")
    _commit(repo, ".env.production", f'SETTING_2="{_CIPHERTEXT}"')

    assert _reported(repo, [_finding(repo, commit)], history=False) == []


def test_an_ignore_comment_written_later_does_not_drop_a_history_finding(repo: Path):
    plaintext = _commit(repo, ".env.production", f"AWS_ACCESS_KEY_ID={_KEY}")
    _commit(repo, ".env.production", "SETTING_2=value2  # envdrift:ignore")

    assert _reported(repo, [_finding(repo, plaintext)]) == [plaintext]


def test_an_ignore_comment_in_its_commit_drops_a_history_finding(repo: Path):
    ignored = _commit(repo, ".env.production", f"AWS_ACCESS_KEY_ID={_KEY}  # envdrift:ignore")
    _commit(repo, ".env.production", f"AWS_ACCESS_KEY_ID={_KEY}")

    assert _reported(repo, [_finding(repo, ignored)]) == []


def test_skip_gitignored_keeps_a_secret_committed_before_its_file_was_ignored(repo: Path):
    """The file was committed in that commit, so the secret is in the history."""
    committed = _commit(repo, ".env", f"AWS_ACCESS_KEY_ID={_KEY}")
    _git(repo, "rm", "-q", "--cached", "--", ".env")
    (repo / ".gitignore").write_text(".env\n")
    _git(repo, "add", "--", ".gitignore")
    _git(repo, "commit", "-q", "-m", "ignore .env")
    today = _finding(repo, None, name=".env")

    reported = _reported(
        repo, [_finding(repo, committed, name=".env"), today], skip_gitignored=True
    )

    assert reported == [committed]
