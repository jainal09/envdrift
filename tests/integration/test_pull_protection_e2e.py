"""Decrypted secrets are never called protected when git cannot protect them.

Every test runs the real ``envdrift`` CLI as a subprocess with the real dotenvx
binary and real git, and checks git's own view of the files.

- #998: ``pull-partial`` marks each decrypted secret file skip-worktree so a
  plain ``git add .`` does not stage its plaintext. Its notice said the files
  were protected when any one was marked, counting a file that was plaintext
  already, while an untracked decrypted file (which cannot be marked) sat in
  ``git status`` ready to be added. The notice must name each decrypted file it
  could not protect, with the reason, and never call the set protected.
- #999: ``envdrift pull`` decrypts the same secret files and marks them the same
  way, but dropped the result: it printed "Setup complete!" with no warning
  while a decrypted secret file was untracked plaintext. It must give the same
  warning ``pull-partial`` gives. Decrypting succeeded, so it still exits 0.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which("dotenvx") is None,
        reason="dotenvx binary not installed (required for real decrypted secret files)",
    ),
]


def _run_envdrift(
    args: list[str],
    *,
    cwd: Path,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
) -> subprocess.CompletedProcess[str]:
    """Run the real envdrift CLI as a subprocess and capture its output."""
    env = os.environ.copy()
    env["PYTHONPATH"] = integration_pythonpath
    # Wide enough that no path inside a panel is folded mid-path.
    env["COLUMNS"] = "1000"
    return subprocess.run(
        [*envdrift_cmd, *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _flat(result: subprocess.CompletedProcess[str]) -> str:
    """stdout+stderr without Rich's panel border, whitespace collapsed (wrap-proof)."""
    return " ".join((result.stdout + result.stderr).replace("│", " ").split())


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True
    ).stdout


def _flag(repo: Path, path: str) -> str:
    """``S`` when git marks ``path`` skip-worktree, ``H`` for a normal tracked file."""
    return _git(repo, "ls-files", "-v", "--", path).split(" ", 1)[0]


def _cli(repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]):
    def run(*args: str) -> subprocess.CompletedProcess[str]:
        return _run_envdrift(
            list(args),
            cwd=repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

    return run


_SECRETS_ONLY = (
    "[partial_encryption]\n"
    "enabled = true\n\n"
    "[[partial_encryption.environments]]\n"
    'name = "production"\n'
    "secrets_only = true\n"
    'secrets_dir = "secrets"\n'
)


def _combine(name: str, folder: str = ".") -> str:
    prefix = "" if folder == "." else f"{folder}/"
    return (
        "[[partial_encryption.environments]]\n"
        f'name = "{name}"\n'
        f'clear_file = "{prefix}.env.{name}.clear"\n'
        f'secret_file = "{prefix}.env.{name}.secret"\n'
        f'combined_file = "{prefix}.env.{name}.merged"\n\n'
    )


def _write_combine_files(directory: Path, name: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f".env.{name}.clear").write_text("DEBUG=false\n", encoding="utf-8")
    secret = directory / f".env.{name}.secret"
    secret.write_text("JWT_SECRET=" + "super-" + "secret\n", encoding="utf-8")
    return secret


class TestPullPartialNeverCallsAnUnprotectedSetProtected:
    def test_untracked_decrypted_file_next_to_a_plaintext_tracked_one(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        """The #998 report: .env.a plaintext and committed, .env.b encrypted and untracked."""
        run = _cli(git_repo, integration_pythonpath, envdrift_cmd)
        (git_repo / "envdrift.toml").write_text(_SECRETS_ONLY, encoding="utf-8")
        secrets = git_repo / "secrets"
        secrets.mkdir()
        (secrets / ".env.a").write_text("A=" + "plain-a\n", encoding="utf-8")
        _git(git_repo, "add", "secrets/.env.a")
        _git(git_repo, "commit", "-q", "-m", "plaintext secret")
        (secrets / ".env.b").write_text("B=" + "secret-b\n", encoding="utf-8")
        enc = run("encrypt", "secrets/.env.b")
        assert enc.returncode == 0, _flat(enc)

        result = run("pull-partial")

        out = _flat(result)
        assert result.returncode == 0, out  # decrypting succeeded
        assert "Decrypted: 1" in out and "Skipped: 1" in out, out
        # Never the yellow "they are marked skip-worktree" notice.
        assert "SECRET FILES ARE NOW PLAINTEXT" not in out, out
        assert "No Git Protection Applied" in out, out
        assert "secrets/.env.b (untracked)" in out, out
        # .env.a was plaintext already: still marked, but it proves nothing
        # about the file this pull decrypted.
        assert "The other" not in out, out
        assert _flag(git_repo, "secrets/.env.a") == "S"
        status = _git(git_repo, "status", "--porcelain", "--untracked-files=all")
        assert "?? secrets/.env.b" in status, status

    def test_mixed_set_names_the_unprotected_file(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        """Both files decrypted, only the committed one could be marked."""
        run = _cli(git_repo, integration_pythonpath, envdrift_cmd)
        (git_repo / "envdrift.toml").write_text(_SECRETS_ONLY, encoding="utf-8")
        secrets = git_repo / "secrets"
        secrets.mkdir()
        (secrets / ".env.a").write_text("A=" + "secret-a\n", encoding="utf-8")
        (secrets / ".env.b").write_text("B=" + "secret-b\n", encoding="utf-8")
        push = run("push")
        assert push.returncode == 0, _flat(push)
        _git(git_repo, "add", "secrets/.env.a")
        _git(git_repo, "commit", "-q", "-m", "encrypted secret")

        result = run("pull-partial")

        out = _flat(result)
        assert result.returncode == 0, out
        assert "Decrypted: 2" in out, out
        assert "SECRET FILES ARE NOW PLAINTEXT" not in out, out
        assert "secrets/.env.b (untracked)" in out, out
        assert "The other 1 decrypted file(s) are marked skip-worktree." in out, out
        assert _flag(git_repo, "secrets/.env.a") == "S"

    def test_combine_mode_names_the_environment_left_unprotected(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        run = _cli(git_repo, integration_pythonpath, envdrift_cmd)
        (git_repo / "envdrift.toml").write_text(
            "[partial_encryption]\nenabled = true\n\n"
            + _combine("staging", "staging")
            + _combine("production", "production"),
            encoding="utf-8",
        )
        _write_combine_files(git_repo / "staging", "staging")
        _write_combine_files(git_repo / "production", "production")
        push = run("push")
        assert push.returncode == 0, _flat(push)
        _git(git_repo, "add", "staging/.env.staging.secret", "staging/.env.staging.clear")
        _git(git_repo, "commit", "-q", "-m", "staging only")

        result = run("pull-partial")

        out = _flat(result)
        assert result.returncode == 0, out
        assert "production/.env.production.secret (untracked)" in out, out
        assert "The other 1 decrypted file(s) are marked skip-worktree." in out, out
        assert "SECRET FILES ARE NOW PLAINTEXT" not in out, out

    def test_names_a_file_outside_a_git_repository(
        self, work_dir: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        run = _cli(work_dir, integration_pythonpath, envdrift_cmd)
        (work_dir / "envdrift.toml").write_text(
            "[partial_encryption]\nenabled = true\n\n" + _combine("production"),
            encoding="utf-8",
        )
        _write_combine_files(work_dir, "production")
        push = run("push")
        assert push.returncode == 0, _flat(push)

        result = run("pull-partial")

        out = _flat(result)
        assert result.returncode == 0, out
        assert ".env.production.secret (outside a git repository)" in out, out
        assert "SECRET FILES ARE NOW PLAINTEXT" not in out, out

    def test_names_a_tracked_file_git_could_not_mark(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        """Another git process holds the index lock: the mark itself fails."""
        run = _cli(git_repo, integration_pythonpath, envdrift_cmd)
        (git_repo / "envdrift.toml").write_text(
            "[partial_encryption]\nenabled = true\n\n" + _combine("production"),
            encoding="utf-8",
        )
        _write_combine_files(git_repo, "production")
        push = run("push")
        assert push.returncode == 0, _flat(push)
        _git(git_repo, "add", ".env.production.secret", ".env.production.clear")
        _git(git_repo, "commit", "-q", "-m", "encrypted secret")
        (git_repo / ".git" / "index.lock").write_text("", encoding="utf-8")

        result = run("pull-partial")

        out = _flat(result)
        assert result.returncode == 0, out
        assert ".env.production.secret (skip-worktree failed)" in out, out
        assert "SECRET FILES ARE NOW PLAINTEXT" not in out, out


# `pull` belongs to the vault-sync family, so it needs a [vault.sync] section.
# With --skip-sync it never contacts the (dummy) vault; the mapping's plaintext
# .env.production is skipped, and Step 3 decrypts the partial-encryption files.
_VAULT_SYNC = (
    "[vault]\n"
    'provider = "azure"\n\n'
    "[vault.azure]\n"
    'vault_url = "https://dummy.vault.azure.net/"\n\n'
    "[vault.sync]\n"
    'default_vault_name = "dummy"\n\n'
    "[[vault.sync.mappings]]\n"
    'secret_name = "unused"\n'
    'folder_path = "."\n'
    'environment = "production"\n\n'
)


def _pull_repo(repo: Path, partial: str) -> None:
    (repo / "envdrift.toml").write_text(_VAULT_SYNC + partial, encoding="utf-8")
    (repo / ".env.production").write_text("DEBUG=false\n", encoding="utf-8")


class TestPullWarnsAboutUnprotectedSecrets:
    def test_combine_mode_untracked_secret_file(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        """The #999 report: an encrypted, untracked .secret decrypted by pull."""
        run = _cli(git_repo, integration_pythonpath, envdrift_cmd)
        _pull_repo(
            git_repo,
            "[partial_encryption]\nenabled = true\n\n" + _combine("production", "config"),
        )
        _write_combine_files(git_repo / "config", "production")
        push = run("push")
        assert push.returncode == 0, _flat(push)

        result = run("pull", "--skip-sync")

        out = _flat(result)
        assert result.returncode == 0, out  # decrypting succeeded
        assert "Setup complete!" in out, out
        assert "No Git Protection Applied" in out, out
        assert "config/.env.production.secret (untracked)" in out, out
        # The warning comes last, after the success line, where it is seen.
        assert out.index("Setup complete!") < out.index("No Git Protection Applied"), out
        status = _git(git_repo, "status", "--porcelain", "--untracked-files=all")
        assert "?? config/.env.production.secret" in status, status

    def test_secrets_only_untracked_files(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        run = _cli(git_repo, integration_pythonpath, envdrift_cmd)
        _pull_repo(git_repo, _SECRETS_ONLY)
        secrets = git_repo / "secrets"
        secrets.mkdir()
        (secrets / ".env.a").write_text("A=" + "secret-a\n", encoding="utf-8")
        (secrets / ".env.b").write_text("B=" + "secret-b\n", encoding="utf-8")
        push = run("push")
        assert push.returncode == 0, _flat(push)
        _git(git_repo, "add", "secrets/.env.a")
        _git(git_repo, "commit", "-q", "-m", "one encrypted secret")

        result = run("pull", "--skip-sync")

        out = _flat(result)
        assert result.returncode == 0, out
        assert "secrets/.env.b (untracked)" in out, out
        assert "secrets/.env.a (" not in out, out
        assert "The other 1 decrypted file(s) are marked skip-worktree." in out, out
        assert _flag(git_repo, "secrets/.env.a") == "S"

    def test_warns_before_exiting_on_an_error(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        """Files decrypted before a secrets-only failure are plaintext too."""
        run = _cli(git_repo, integration_pythonpath, envdrift_cmd)
        _pull_repo(git_repo, _SECRETS_ONLY)
        secrets = git_repo / "secrets"
        secrets.mkdir()
        (secrets / ".env.a").write_text("A=" + "secret-a\n", encoding="utf-8")  # untracked
        db = secrets / ".env.db"
        db.write_text("DB=" + "secret-db\n", encoding="utf-8")
        push = run("push")
        assert push.returncode == 0, _flat(push)
        # One value of .env.db under another folder's key: its decrypt fails.
        other = git_repo / "other" / ".env.db"
        other.parent.mkdir()
        other.write_text("STRIPE_API_KEY=" + "sk_other\n", encoding="utf-8")
        enc = run("encrypt", "other/.env.db")
        assert enc.returncode == 0, _flat(enc)
        foreign = next(line for line in other.read_text().splitlines() if line.startswith("STRIPE"))
        db.write_text(db.read_text() + foreign + "\n", encoding="utf-8")

        result = run("pull", "--skip-sync")

        out = _flat(result)
        assert result.returncode == 1, out  # the failed decrypt is an error
        assert "secrets/.env.a (untracked)" in out, out
        assert "No Git Protection Applied" in out, out

    def test_no_warning_when_every_secret_file_is_protected(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        """Non-regression: a tracked secret file is marked and nothing is claimed."""
        run = _cli(git_repo, integration_pythonpath, envdrift_cmd)
        _pull_repo(
            git_repo,
            "[partial_encryption]\nenabled = true\n\n" + _combine("production", "config"),
        )
        _write_combine_files(git_repo / "config", "production")
        push = run("push")
        assert push.returncode == 0, _flat(push)
        _git(git_repo, "add", "config")
        _git(git_repo, "commit", "-q", "-m", "encrypted secret")

        result = run("pull", "--skip-sync")

        out = _flat(result)
        assert result.returncode == 0, out
        assert "No Git Protection Applied" not in out, out
        assert _flag(git_repo, "config/.env.production.secret") == "S"


def _write_symlinked_secret(repo: Path) -> Path:
    """``config/.env.production.secret`` is a symlink to ``shared/production.secret``."""
    if sys.platform == "win32":
        pytest.skip("git checks symlinks out as plain files on Windows by default")
    (repo / "envdrift.toml").write_text(
        "[partial_encryption]\nenabled = true\n\n" + _combine("production", "config"),
        encoding="utf-8",
    )
    (repo / "config").mkdir()
    (repo / "config" / ".env.production.clear").write_text("DEBUG=false\n", encoding="utf-8")
    target = repo / "shared" / "production.secret"
    target.parent.mkdir()
    target.write_text("JWT_SECRET=" + "super-" + "secret\n", encoding="utf-8")
    (repo / "config" / ".env.production.secret").symlink_to("../shared/production.secret")
    return target


class TestSymlinkedSecretFile:
    """dotenvx writes through a symlinked .secret: its target holds the plaintext.

    pull-partial marked the link skip-worktree and called the file protected,
    while the plaintext sat in the tracked target, which ``git add .`` staged.
    """

    def test_the_tracked_target_is_protected_and_push_lifts_it(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        run = _cli(git_repo, integration_pythonpath, envdrift_cmd)
        target = _write_symlinked_secret(git_repo)
        push = run("push")
        assert push.returncode == 0, _flat(push)
        _git(git_repo, "add", "-A")
        _git(git_repo, "commit", "-q", "-m", "symlinked secret file")

        result = run("pull-partial")

        out = _flat(result)
        assert result.returncode == 0, out
        assert "JWT_SECRET=super-secret" in target.read_text(encoding="utf-8")
        assert "SECRET FILES ARE NOW PLAINTEXT" in out, out
        assert "No Git Protection Applied" not in out, out
        assert _flag(git_repo, "shared/production.secret") == "S"
        _git(git_repo, "add", ".")
        assert _git(git_repo, "diff", "--cached", "--name-only") == ""

        # push re-encrypts through the link and lifts the bit from the same file,
        # so git sees the new ciphertext.
        repush = run("push")
        assert repush.returncode == 0, _flat(repush)
        assert "JWT_SECRET=encrypted:" in target.read_text(encoding="utf-8")
        assert _flag(git_repo, "shared/production.secret") == "H"
        changed = _git(git_repo, "diff", "--name-only").split()
        assert "shared/production.secret" in changed, changed

    def test_an_untracked_target_is_named_as_unprotected(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        run = _cli(git_repo, integration_pythonpath, envdrift_cmd)
        _write_symlinked_secret(git_repo)
        push = run("push")
        assert push.returncode == 0, _flat(push)
        _git(git_repo, "add", "envdrift.toml", ".gitignore", "config")  # not shared/
        _git(git_repo, "commit", "-q", "-m", "a link to an untracked file")

        result = run("pull-partial")

        out = _flat(result)
        assert result.returncode == 0, out
        assert "SECRET FILES ARE NOW PLAINTEXT" not in out, out
        assert "No Git Protection Applied" in out, out
        assert (
            "config/.env.production.secret (untracked; through a symlink, "
            "the plaintext is in shared/production.secret)"
        ) in out, out
        status = _git(git_repo, "status", "--porcelain", "--untracked-files=all")
        assert "?? shared/production.secret" in status, status


@pytest.mark.parametrize(
    ("folder", "entry"),
    [(":fire:", "secrets/:fire:/.env.keys"), ("[b]", "secrets/\\[b]/.env.keys")],
    ids=["emoji-code", "markup-tag"],
)
def test_paths_print_as_they_are(
    git_repo: Path,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
    folder: str,
    entry: str,
) -> None:
    """Paths in the DANGER warning and the .gitignore line are text, not Rich markup.

    ``escape()`` stops a tag but not an emoji code, so ``secrets/:fire:/.env.a`` was
    named ``secrets/🔥/.env.a``. The .gitignore line was markup: it lost the escaping
    backslash the entry has in .gitignore, and ``[b]`` before that.
    """
    if ":" in folder and sys.platform == "win32":
        pytest.skip("':' is not allowed in a Windows file name")
    run = _cli(git_repo, integration_pythonpath, envdrift_cmd)
    (git_repo / "envdrift.toml").write_text(
        _SECRETS_ONLY + 'pattern = "**/.env*"\n', encoding="utf-8"
    )
    (git_repo / "secrets" / folder).mkdir(parents=True)
    (git_repo / "secrets" / folder / ".env.a").write_text("A=" + "secret-a\n", encoding="utf-8")

    push = run("push")
    pull = run("pull-partial")  # .env.a is untracked, so it is named

    assert push.returncode == 0, _flat(push)
    assert pull.returncode == 0, _flat(pull)
    assert f"• secrets/{folder}/.env.a (untracked)" in _flat(pull), _flat(pull)
    assert f"Updated .gitignore: secrets/.env.keys, {entry}" in _flat(push), _flat(push)
    assert "🔥" not in push.stdout + pull.stdout
