"""pull-partial never calls decrypted secrets protected when one is not (#998).

After decrypting, ``pull-partial`` marks each secret file skip-worktree so a
plain ``git add .`` does not stage its plaintext. The notice used to say the
files were protected when any one of them was marked, counting a file that was
plaintext already; an untracked decrypted file cannot be marked, and nothing
said so. Now the notice names each decrypted file it could not protect, with
the reason, and calls the set protected only when every decrypted file is.

``unprotected_reason`` runs against real git repositories here; the notice
tests drive the real ``pull-partial`` command through ``CliRunner``. The
real-binary proof is ``tests/integration/test_pull_protection_e2e.py``.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.config import PartialEncryptionEnvironmentConfig
from envdrift.core.partial_encryption import pull_secrets_only

runner = CliRunner()


def _reason(path: Path) -> str:
    from envdrift.core.partial_encryption import unprotected_reason

    return unprotected_reason(path)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, capture_output=True, check=True)


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A real git repository with one committed file; cwd is the repository."""
    if shutil.which("git") is None:
        pytest.skip("git not available")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "tracked.env").write_text("K=v\n", encoding="utf-8")
    _git(tmp_path, "add", "tracked.env")
    _git(tmp_path, "commit", "-q", "-m", "c")
    monkeypatch.chdir(tmp_path)
    return tmp_path


class TestUnprotectedReason:
    def test_untracked_file(self, repo: Path) -> None:
        (repo / "new.env").write_text("K=v\n", encoding="utf-8")
        assert _reason(Path("new.env")) == "untracked"

    def test_tracked_file_whose_mark_failed(self, repo: Path) -> None:
        # Another git process holds the index lock: the file is tracked, so
        # the mark itself failed.
        (repo / ".git" / "index.lock").write_text("", encoding="utf-8")
        assert _reason(Path("tracked.env")) == "skip-worktree failed"

    def test_outside_a_git_repository(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        if shutil.which("git") is None:
            pytest.skip("git not available")
        monkeypatch.chdir(tmp_path)
        (tmp_path / "plain.env").write_text("K=v\n", encoding="utf-8")
        assert _reason(Path("plain.env")) == "outside a git repository"

    def test_path_outside_the_current_repository(
        self, repo: Path, tmp_path_factory: pytest.TempPathFactory
    ) -> None:
        elsewhere = tmp_path_factory.mktemp("elsewhere") / "x.env"
        elsewhere.write_text("K=v\n", encoding="utf-8")
        assert _reason(elsewhere) == "outside a git repository"

    def test_git_not_installed(self, tmp_path: Path) -> None:
        with patch(
            "envdrift.core.partial_encryption.subprocess.run",
            side_effect=FileNotFoundError("git"),
        ):
            assert _reason(tmp_path / "x.env") == "skip-worktree failed: git is not installed"

    def test_git_timing_out(self, tmp_path: Path) -> None:
        with patch(
            "envdrift.core.partial_encryption.subprocess.run",
            side_effect=subprocess.TimeoutExpired(["git"], 10),
        ):
            assert _reason(tmp_path / "x.env").startswith("skip-worktree failed: ")


class TestPullSecretsOnlyCountsOnlyDecryptedFiles:
    def test_plaintext_files_are_marked_but_not_counted(self, tmp_path: Path) -> None:
        secrets = tmp_path / "secrets"
        secrets.mkdir()
        (secrets / ".env.a").write_text("A=plain\n", encoding="utf-8")  # already plaintext
        (secrets / ".env.b").write_text("B=encrypted:BAAA\n", encoding="utf-8")
        (secrets / ".env.c").write_text("C=encrypted:BCCC\n", encoding="utf-8")
        config = PartialEncryptionEnvironmentConfig(
            name="production", secrets_only=True, secrets_dir=str(secrets), pattern=".env*"
        )
        marked: list[str] = []

        def _skip_worktree(path: Path) -> bool:
            marked.append(path.name)
            return path.name != ".env.c"  # .env.c cannot be marked

        def _decrypt(path: Path) -> None:
            path.write_text(path.read_text().replace("=encrypted:", "=plain-"))

        with (
            patch("envdrift.core.partial_encryption.DotenvxWrapper") as wrapper_cls,
            patch(
                "envdrift.core.partial_encryption._git_skip_worktree", side_effect=_skip_worktree
            ),
        ):
            wrapper_cls.return_value.decrypt.side_effect = _decrypt
            result = pull_secrets_only(config)

        # .env.a was still marked, but only decrypted files count.
        assert marked == [".env.a", ".env.b", ".env.c"]
        assert result["decrypted"] == 2 and result["already_decrypted"] == 1
        assert result["protected"] == 1
        assert result["unprotected"] == [secrets / ".env.c"]


def _combine_env(tmp_path: Path, name: str) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        secrets_only=False,
        clear_file=str(tmp_path / f"{name}.clear"),
        secret_file=str(tmp_path / f"{name}.secret"),
        combined_file=str(tmp_path / name),
    )


def _flat(output: str) -> str:
    """Drop Rich's panel border and collapse whitespace: wrap-proof phrases."""
    return " ".join(output.replace("│", " ").split())


def _run_pull_partial(monkeypatch, environments, pull_partial=None, pull_secrets=None):
    # Wide enough that no tmp_path inside the panel is folded mid-path.
    monkeypatch.setenv("COLUMNS", "1000")
    config = SimpleNamespace(
        partial_encryption=SimpleNamespace(enabled=True, environments=environments)
    )
    monkeypatch.setattr("envdrift.cli_commands.partial.load_config", lambda: config)
    monkeypatch.setattr("envdrift.cli_commands.partial.ensure_gitignore_entries", lambda _: [])
    if pull_partial is not None:
        monkeypatch.setattr("envdrift.cli_commands.partial.pull_partial_encryption", pull_partial)
    if pull_secrets is not None:
        monkeypatch.setattr("envdrift.cli_commands.partial.pull_secrets_only", pull_secrets)
    # Stand in for the git query (tested for real above). raising=False keeps the
    # yellow-notice guard below meaningful against code that has no such name.
    monkeypatch.setattr(
        "envdrift.cli_commands.partial.unprotected_reason",
        lambda path: f"why-{path.name}",
        raising=False,
    )
    result = runner.invoke(app, ["pull-partial"])
    return result, _flat(result.output)


class TestPullPartialNotice:
    def test_a_mixed_set_is_never_called_protected(self, monkeypatch, tmp_path: Path) -> None:
        """One environment protected, one not: DANGER, naming the unprotected file."""
        protected_env = _combine_env(tmp_path, "staging")
        open_env = _combine_env(tmp_path, "production")
        outcomes = {"staging": (True, True), "production": (True, False)}

        result, output = _run_pull_partial(
            monkeypatch,
            [protected_env, open_env],
            pull_partial=lambda env: outcomes[env.name],
        )

        assert result.exit_code == 0, output  # decrypting succeeded
        assert "No Git Protection Applied" in output
        assert f"{open_env.secret_file} (why-production.secret)" in output
        assert "The other 1 decrypted file(s) are marked skip-worktree." in output
        assert "SECRET FILES ARE NOW PLAINTEXT" not in output  # the yellow notice

    def test_an_already_plaintext_protected_file_does_not_count(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        plain_env = _combine_env(tmp_path, "staging")  # plaintext already, marked
        open_env = _combine_env(tmp_path, "production")  # decrypted, not marked
        outcomes = {"staging": (False, True), "production": (True, False)}

        result, output = _run_pull_partial(
            monkeypatch,
            [plain_env, open_env],
            pull_partial=lambda env: outcomes[env.name],
        )

        assert result.exit_code == 0, output
        assert f"{open_env.secret_file} (why-production.secret)" in output
        assert "The other" not in output  # nothing this run decrypted is protected
        assert "SECRET FILES ARE NOW PLAINTEXT" not in output

    def test_secrets_only_files_are_named(self, monkeypatch, tmp_path: Path) -> None:
        env = SimpleNamespace(
            name="production",
            secrets_only=True,
            secrets_dir=str(tmp_path / "secrets"),
            pattern=".env*",
            combined_file="",
        )
        unprotected = [tmp_path / "secrets" / ".env.b", tmp_path / "secrets" / ".env.c"]

        result, output = _run_pull_partial(
            monkeypatch,
            [env],
            pull_secrets=lambda _env: {
                "decrypted": 3,
                "already_decrypted": 1,
                "protected": 1,
                "unprotected": unprotected,
            },
        )

        assert result.exit_code == 0, output
        for path in unprotected:
            assert f"{path} (why-{path.name})" in output
        assert "The other 1 decrypted file(s) are marked skip-worktree." in output

    def test_counts_alone_never_claim_protection(self, monkeypatch, tmp_path: Path) -> None:
        """A tally with fewer protected than decrypted files is DANGER, named or not."""
        env = SimpleNamespace(
            name="production",
            secrets_only=True,
            secrets_dir=str(tmp_path / "secrets"),
            pattern=".env*",
            combined_file="",
        )

        result, output = _run_pull_partial(
            monkeypatch,
            [env],
            pull_secrets=lambda _env: {"decrypted": 2, "already_decrypted": 0, "protected": 1},
        )

        assert result.exit_code == 0, output
        assert "could not be applied to the decrypted files." in output
        assert "SECRET FILES ARE NOW PLAINTEXT" not in output

    def test_every_decrypted_file_protected_keeps_the_yellow_notice(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        result, output = _run_pull_partial(
            monkeypatch,
            [_combine_env(tmp_path, "production")],
            pull_partial=lambda _env: (True, True),
        )

        assert result.exit_code == 0, output
        assert "SECRET FILES ARE NOW PLAINTEXT" in output
        assert "No Git Protection Applied" not in output


def _symlink(link: Path, target: str) -> None:
    if sys.platform == "win32":
        pytest.skip("git checks symlinks out as plain files on Windows by default")
    link.symlink_to(target)


def _flags(repo: Path, *paths: str) -> dict[str, str]:
    """``{path: flag}`` from ``git ls-files -v``: ``S`` skip-worktree, ``H`` tracked."""
    listed = subprocess.run(
        ["git", "ls-files", "-v", "--", *paths],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return {line[2:]: line[0] for line in listed.splitlines()}


class TestSymlinkedSecretFile:
    """The bit goes on the file the plaintext lands in, not on the link to it.

    dotenvx writes through a symlinked secret file into its target. Marking the
    link protected nothing: the tracked target held the plaintext, and
    ``git add .`` staged it while pull-partial said the files were protected.
    """

    def test_a_tracked_target_is_marked_and_unmarked(self, repo: Path) -> None:
        from envdrift.core.partial_encryption import _git_skip_worktree, _git_unskip_worktree

        (repo / "shared").mkdir()
        (repo / "shared" / "production.secret").write_text("K=v\n", encoding="utf-8")
        (repo / "config").mkdir()
        _symlink(repo / "config" / ".env.production.secret", "../shared/production.secret")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "symlinked secret")
        link = Path("config/.env.production.secret")
        both = ("config/.env.production.secret", "shared/production.secret")

        assert _git_skip_worktree(link) is True
        assert _flags(repo, *both) == {both[0]: "H", both[1]: "S"}
        # push lifts it from the same file, so the re-encrypted target shows up.
        assert _git_unskip_worktree(link) is True
        assert _flags(repo, *both) == {both[0]: "H", both[1]: "H"}

    def test_an_untracked_target_is_not_called_protected(self, repo: Path) -> None:
        from envdrift.core.partial_encryption import _git_skip_worktree

        (repo / "shared").mkdir()
        (repo / "shared" / "production.secret").write_text("K=v\n", encoding="utf-8")
        _symlink(repo / ".env.production.secret", "shared/production.secret")
        _git(repo, "add", ".env.production.secret")  # the link only
        _git(repo, "commit", "-q", "-m", "link to an untracked file")
        link = Path(".env.production.secret")

        assert _git_skip_worktree(link) is False
        assert _flags(repo, ".env.production.secret") == {".env.production.secret": "H"}
        assert _reason(link) == (
            "untracked; through a symlink, the plaintext is in shared/production.secret"
        )

    def test_a_symlinked_directory_on_the_way(self, repo: Path) -> None:
        from envdrift.core.partial_encryption import _git_skip_worktree

        (repo / "real").mkdir()
        (repo / "real" / ".env.secret").write_text("K=v\n", encoding="utf-8")
        _symlink(repo / "config", "real")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "symlinked directory")

        # git refuses a path "beyond a symbolic link"; the real file is marked.
        assert _git_skip_worktree(Path("config/.env.secret")) is True
        assert _flags(repo, "real/.env.secret") == {"real/.env.secret": "S"}
