"""A history finding is judged by its file in the commit it was found in (#1014).

A history scan reports a secret at the line it had in an old commit. The engine's filters read
today's file at that line, so a secret committed before its file was encrypted was dropped when
the same line now held an encrypted value, and an ignore comment written there later dropped it
too. Each test commits real files to a real repository. A stub scanner reports the findings, as
gitleaks reports them from ``git log -p``; the engine's filters run for real.
"""

from __future__ import annotations

import gc
import shutil
import subprocess  # nosec B404
import sys
import weakref
from pathlib import Path, PurePath

import pytest

from envdrift.scanner import history_files
from envdrift.scanner.base import FindingSeverity, ScanFinding, ScannerBackend, ScanResult
from envdrift.scanner.engine import GuardConfig, ScanEngine, _EncryptedFiles
from envdrift.scanner.history_files import CommittedFiles

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
    (repo / name).parent.mkdir(parents=True, exist_ok=True)
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


def _reported(
    repo: Path, findings: list[ScanFinding], *, paths: list[Path] | None = None, **config
) -> list:
    """The commits of the findings the engine reports, scanning ``paths`` (``repo`` alone).

    ``config`` sets ``GuardConfig`` fields; the scan is a history scan unless it says otherwise.
    """
    config.setdefault("include_git_history", True)
    engine = ScanEngine(GuardConfig(use_native=False, use_gitleaks=False, **config))
    engine.scanners = [_HistoryScanner(findings)]
    result = engine.scan(paths or [repo])
    return [f.commit_sha for f in result.unique_findings]


def _commit_bytes(repo: Path, name: str, content: bytes) -> str:
    """Commit ``content``, byte for byte, as ``name``; return the commit."""
    (repo / name).write_bytes(content)
    _git(repo, "add", "-f", "--", name)
    _git(repo, "commit", "-q", "-m", f"{name} as bytes")
    return _git(repo, "rev-parse", "HEAD")


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
    # As an option, git would have written its output to "x:.env.production".
    assert {path.name for path in repo.iterdir()} == {".git", ".env.production"}


def test_without_history_a_finding_is_judged_by_todays_file(repo: Path):
    """Outside a history scan a finding is in today's files, whatever commit it names."""
    commit = _commit(repo, ".env.production", f"AWS_ACCESS_KEY_ID={_KEY}")
    _commit(repo, ".env.production", f'SETTING_2="{_CIPHERTEXT}"')

    assert _reported(repo, [_finding(repo, commit)], include_git_history=False) == []


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


@pytest.mark.skipif(sys.platform == "win32", reason="a symbolic link needs a privilege on Windows")
def test_a_symlink_made_later_does_not_choose_the_file_a_history_finding_is_judged_by(
    repo: Path,
):
    """``.env.production`` is read as the commit held it, though it links elsewhere today.

    The committed file was found through today's symbolic link: the commit's ``decoy.env``,
    whose line 2 is encrypted, was read in place of the plaintext ``.env.production``.
    """
    _commit(repo, "decoy.env", f'SETTING_2="{_CIPHERTEXT}"')
    plaintext = _commit(repo, ".env.production", f"AWS_ACCESS_KEY_ID={_KEY}")
    (repo / ".env.production").unlink()
    (repo / ".env.production").symlink_to("decoy.env")

    assert _reported(repo, [_finding(repo, plaintext)]) == [plaintext]


@pytest.mark.skipif(sys.platform == "win32", reason="a symbolic link needs a privilege on Windows")
def test_a_folder_linked_elsewhere_later_does_not_choose_the_file_either(repo: Path):
    """``prod/app.env`` is read as the commit held it, though ``prod`` links to ``decoy`` today.

    The folder was resolved through today's link: the commit's ``decoy/app.env``, whose line 2
    is encrypted, was read in place of the plaintext ``prod/app.env``.
    """
    _commit(repo, "decoy/app.env", f'SETTING_2="{_CIPHERTEXT}"')
    plaintext = _commit(repo, "prod/app.env", f"AWS_ACCESS_KEY_ID={_KEY}")
    shutil.rmtree(repo / "prod")
    (repo / "prod").symlink_to("decoy", target_is_directory=True)

    assert _reported(repo, [_finding(repo, plaintext, name="prod/app.env")]) == [plaintext]


@pytest.mark.skipif(sys.platform == "win32", reason="a symbolic link needs a privilege on Windows")
def test_a_folder_linked_to_the_repository_later_does_not_choose_the_file_either(repo: Path):
    """``prod/app.env`` is read as the commit held it, though ``prod`` links to the root today.

    Through the link, ``prod/.git`` exists: ``prod`` was taken for the root, and the commit's
    root ``app.env``, whose line 2 is encrypted, was read in place of the plaintext
    ``prod/app.env``.
    """
    _commit(repo, "app.env", f'SETTING_2="{_CIPHERTEXT}"')
    plaintext = _commit(repo, "prod/app.env", f"AWS_ACCESS_KEY_ID={_KEY}")
    shutil.rmtree(repo / "prod")
    (repo / "prod").symlink_to(".", target_is_directory=True)

    assert _reported(repo, [_finding(repo, plaintext, name="prod/app.env")]) == [plaintext]


@pytest.mark.skipif(sys.platform == "win32", reason="a symbolic link needs a privilege on Windows")
def test_a_finding_below_a_folder_linked_to_the_repository_is_still_judged_by_its_commit(
    repo: Path,
):
    """The root is found above the link, so ``prod/app.env`` is judged by its commit, as before.

    Its line 2 was encrypted in that commit, so the finding is dropped. It was kept, judged by
    the commit's root ``app.env``, which held plaintext there.
    """
    _commit(repo, "app.env", f"AWS_ACCESS_KEY_ID={_KEY}")
    encrypted = _commit(repo, "prod/app.env", f'AWS_ACCESS_KEY_ID="{_CIPHERTEXT}"')
    shutil.rmtree(repo / "prod")
    (repo / "prod").symlink_to(".", target_is_directory=True)

    assert _reported(repo, [_finding(repo, encrypted, name="prod/app.env")]) == []


@pytest.mark.skipif(sys.platform == "win32", reason="a symbolic link needs a privilege on Windows")
def test_a_repository_reached_through_a_folder_link_is_not_the_findings(repo: Path):
    """A ``.git`` reached through a link is another folder's, even a clone with the same commits.

    ``a`` links to ``b`` today, and ``b/sub`` is a clone, so ``a/sub/.git`` exists through the
    link. ``a/sub`` was taken for the root, and the clone's root ``app.env`` in that commit, whose
    line 2 is encrypted, was read in place of the plaintext ``a/sub/app.env``.
    """
    _commit(repo, "app.env", f'SETTING_2="{_CIPHERTEXT}"')
    plaintext = _commit(repo, "a/sub/app.env", f"AWS_ACCESS_KEY_ID={_KEY}")
    _git(repo, "clone", "-q", "--", str(repo), str(repo / "b" / "sub"))
    shutil.rmtree(repo / "a")
    (repo / "a").symlink_to("b", target_is_directory=True)

    assert _reported(repo, [_finding(repo, plaintext, name="a/sub/app.env")]) == [plaintext]


def test_a_worktree_inside_the_repository_does_not_choose_the_file_either(repo: Path):
    """``prod/app.env`` is read from the scanned repository, though ``prod`` is a worktree today.

    A worktree of the repository was added at ``prod`` once ``prod/`` left it. Its ``.git``
    made ``prod`` the root, and as the worktree holds the same commits, the commit's root
    ``app.env``, whose line 2 is encrypted, was read in place of the plaintext ``prod/app.env``.
    """
    _commit(repo, "app.env", f'SETTING_2="{_CIPHERTEXT}"')
    plaintext = _commit(repo, "prod/app.env", f"AWS_ACCESS_KEY_ID={_KEY}")
    _git(repo, "rm", "-q", "-r", "--", "prod")
    _git(repo, "commit", "-q", "-m", "drop prod")
    _git(repo, "worktree", "add", "-q", "-b", "side", "--", "prod")

    assert _reported(repo, [_finding(repo, plaintext, name="prod/app.env")]) == [plaintext]


def test_a_finding_in_two_scanned_repositories_is_kept(repo: Path):
    """A file in two scanned repositories is read from neither: which history holds it is unknown.

    ``nested`` is a clone with the same commits, and both were scanned. Read from the clone, the
    commit's root ``app.env``, whose line 2 is encrypted, dropped the plaintext ``nested/app.env``
    that the outer repository holds.
    """
    _commit(repo, "app.env", f'SETTING_2="{_CIPHERTEXT}"')
    plaintext = _commit(repo, "nested/app.env", f"AWS_ACCESS_KEY_ID={_KEY}")
    _git(repo, "rm", "-q", "-r", "--", "nested")
    _git(repo, "commit", "-q", "-m", "drop nested")
    _git(repo, "clone", "-q", "--", str(repo), str(repo / "nested"))
    finding = _finding(repo, plaintext, name="nested/app.env")

    assert _reported(repo, [finding], paths=[repo, repo / "nested"]) == [plaintext]


@pytest.mark.skipif(sys.platform == "win32", reason="a symbolic link needs a privilege on Windows")
def test_a_path_that_reaches_the_repository_only_through_a_link_has_no_commit_file(
    repo: Path, tmp_path_factory: pytest.TempPathFactory
):
    """git names the scanned repository by its real path, so a path below a link to it is in no
    scanned repository: no commit is read for it, and its finding is kept."""
    commit = _commit(repo, "app.env", "A=1")
    link = tmp_path_factory.mktemp("elsewhere") / "link"
    link.symlink_to(repo, target_is_directory=True)
    committed = CommittedFiles(history=True, scanned=[repo])

    assert committed.line(repo / "app.env", commit, 2) == "A=1"
    assert committed.text(link / "app.env", commit) is None


def test_a_lone_carriage_return_does_not_move_a_history_findings_line(repo: Path):
    """Lines are counted at ``\\n``, as git counts them, so line 2 is the key's line.

    git show was read as text, which made the lone ``\\r`` a line break: line 2 was the ignore
    comment, and the committed key was dropped. The file is gone today, so only its commit holds
    the line.
    """
    committed = _commit_bytes(
        repo,
        ".env.production",
        b"PAD=x\rPAD=y  # envdrift:ignore\nAWS_ACCESS_KEY_ID=" + _KEY.encode() + b"\n",
    )
    (repo / ".env.production").unlink()

    assert _reported(repo, [_finding(repo, committed)]) == [committed]


def test_the_lines_of_a_commit_are_counted_at_lf_only():
    """A lone ``\\r`` stays in its line; a ``\\r\\n`` ends one, its ``\\r`` dropped, as
    ``split_lines`` reads a line today; a final line break starts no empty line."""
    assert history_files._lines("A=1\r\nB=2\rC=3\nD=4\n") == ["A=1", "B=2\rC=3", "D=4"]
    assert history_files._lines("A=1") == ["A=1"]
    assert history_files._lines("") == []


def test_a_value_encrypted_in_a_crlf_commit_is_still_dropped(repo: Path):
    """Each ``\\r\\n`` ends one line, and its ``\\r`` is no part of the value judged."""
    encrypted = _commit_bytes(
        repo,
        ".env.production",
        b'SETTING_1=value1\r\nAWS_ACCESS_KEY_ID="' + _CIPHERTEXT.encode() + b'"\r\n',
    )
    (repo / ".env.production").write_text(f"SETTING_1=value1\nAWS_ACCESS_KEY_ID={_KEY}\n")

    assert _reported(repo, [_finding(repo, encrypted)]) == []


def test_a_file_read_again_is_not_read_from_git_again(repo: Path, monkeypatch: pytest.MonkeyPatch):
    """Findings in a few (file, commit) pairs, interleaved, read each pair from git once.

    trufflehog reports the findings of a history in no particular order: a cache of the last
    16 pairs read most of them again, with a git show each time.
    """
    commits = [_commit(repo, ".env.production", f"SETTING_2=value{n}") for n in range(20)]
    reads: list[str] = []
    real = history_files.file_at_commit

    def counted(root: Path, relative_path: PurePath, commit: str) -> str | None:
        reads.append(commit)
        return real(root, relative_path, commit)

    monkeypatch.setattr(history_files, "file_at_commit", counted)
    committed = CommittedFiles(history=True, scanned=[repo])

    for _ in range(3):
        for number, commit in enumerate(commits):
            assert committed.line(repo / ".env.production", commit, 2) == f"SETTING_2=value{number}"

    assert sorted(reads) == sorted(commits), "a pair was read from git more than once"


def test_the_files_kept_in_memory_stay_within_their_budget(
    repo: Path, monkeypatch: pytest.MonkeyPatch
):
    """A history of large files does not keep every revision a finding points at."""
    commits = [_commit(repo, ".env.production", f"SETTING_2=value{n}") for n in range(10)]
    monkeypatch.setattr(history_files, "_CACHED_CHARACTERS", 200)
    committed = CommittedFiles(history=True, scanned=[repo])

    for number, commit in enumerate(commits):
        assert committed.line(repo / ".env.production", commit, 2) == f"SETTING_2=value{number}"

    assert 1 <= len(committed._files) < len(commits)
    assert committed._size <= 200


def test_the_files_read_are_freed_with_the_scan(repo: Path):
    """No cycle keeps the files read alive until the garbage collector runs."""
    commit = _commit(repo, ".env.production", f"AWS_ACCESS_KEY_ID={_KEY}")
    engine = ScanEngine(GuardConfig(use_native=False, use_gitleaks=False, include_git_history=True))
    gc.disable()
    try:
        committed = CommittedFiles(history=True, scanned=[repo])
        files = _EncryptedFiles(committed)
        assert files.keeps(_finding(repo, commit)) is True
        assert committed.line(repo / ".env.production", commit, 2)
        held = [weakref.ref(committed), weakref.ref(files)]
        del committed, files
        assert [ref() for ref in held] == [None, None], "a cycle holds them until the next GC"
    finally:
        gc.enable()
    assert engine is not None
