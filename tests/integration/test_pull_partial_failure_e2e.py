"""``pull-partial`` / ``pull`` failure modes against the real CLI, dotenvx and git.

Every test runs the real ``envdrift`` CLI as a subprocess and asserts the true
outcome: the exit code, the summary, the bytes on disk, and git's view.

- #948: dotenvx decrypts value by value. With one value encrypted under another
  key it writes the values it could decrypt and exits 1. ``pull-partial`` then
  raised before marking the file skip-worktree, so the plaintext sat in a
  tracked file that ``git add .`` staged, under ``Decrypted: 0``. The failed
  file must be left as it was; in secrets-only mode the files decrypted before
  it must be counted, protected, and announced by the plaintext notice.
- #963: on a SOPS-encrypted secret file dotenvx finds nothing to decrypt,
  prints "no change" and exits 0. ``pull-partial`` reported ``Decrypted: 1``,
  exit 0, and marked the still-encrypted file skip-worktree. It must instead
  fail, name the file and the format, and leave the file as it was.
- A secrets-only pull that stops at a file it cannot even read (root-owned,
  mode 600) raised a bare PermissionError: the files decrypted before it were
  not counted and got no warning, and ``envdrift pull`` crashed.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which("dotenvx") is None,
        reason="dotenvx binary not installed (required for real pull-partial failures)",
    ),
]

# Built by concatenation so push protection never sees a whole secret literal.
_JWT_VALUE = "super-" + "secret-" + "key"
_API_VALUE = "api-" + "secret-" + "value"
_DB_VALUE = "db-" + "secret-" + "value"
_FOREIGN_VALUE = "sk_" + "other_" + "abc123"


def _run_envdrift(
    args: list[str],
    *,
    cwd: Path,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the real envdrift CLI as a subprocess and capture its output."""
    env = os.environ.copy()
    env["PYTHONPATH"] = integration_pythonpath
    env.update(extra_env or {})
    return subprocess.run(
        [*envdrift_cmd, *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _flat(result: subprocess.CompletedProcess[str]) -> str:
    """stdout+stderr with whitespace collapsed, so wrapping cannot split a phrase."""
    return " ".join((result.stdout + result.stderr).split())


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True
    ).stdout


def _append_foreign_value(
    repo: Path,
    target: Path,
    *,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
) -> None:
    """Append a ``STRIPE_API_KEY`` line encrypted under another folder's key."""
    other = repo / "other" / target.name
    other.parent.mkdir(exist_ok=True)
    other.write_text(f"STRIPE_API_KEY={_FOREIGN_VALUE}\n", encoding="utf-8")
    enc = _run_envdrift(
        ["encrypt", str(other.relative_to(repo))],
        cwd=repo,
        integration_pythonpath=integration_pythonpath,
        envdrift_cmd=envdrift_cmd,
    )
    assert enc.returncode == 0, _flat(enc)
    foreign = next(
        line
        for line in other.read_text(encoding="utf-8").splitlines()
        if line.startswith("STRIPE_API_KEY=")
    )
    with target.open("a", encoding="utf-8") as handle:
        handle.write(foreign + "\n")


def _push(repo: Path, *, integration_pythonpath: str, envdrift_cmd: list[str]) -> None:
    push = _run_envdrift(
        ["push"],
        cwd=repo,
        integration_pythonpath=integration_pythonpath,
        envdrift_cmd=envdrift_cmd,
    )
    assert push.returncode == 0, _flat(push)


def _skip_worktree_flag(repo: Path, path: str) -> str:
    """``S`` when git marks ``path`` skip-worktree, ``H`` for a normal tracked file."""
    return _git(repo, "ls-files", "-v", "--", path).split(" ", 1)[0]


# envdrift pull needs a [vault.sync] section; --skip-sync never contacts this dummy vault.
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


class TestPartlyFailedPullPartial:
    """#948: a pull that fails part way leaves nothing unprotected or uncounted."""

    def test_combine_mode_restores_the_secret_file(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        (git_repo / "envdrift.toml").write_text(
            "[partial_encryption]\n"
            "enabled = true\n\n"
            "[[partial_encryption.environments]]\n"
            'name = "production"\n'
            'clear_file = ".env.production.clear"\n'
            'secret_file = ".env.production.secret"\n'
            'combined_file = ".env.production"\n',
            encoding="utf-8",
        )
        (git_repo / ".env.production.clear").write_text("DEBUG=false\n", encoding="utf-8")
        secret = git_repo / ".env.production.secret"
        secret.write_text(f"JWT_SECRET={_JWT_VALUE}\n", encoding="utf-8")
        _push(git_repo, integration_pythonpath=integration_pythonpath, envdrift_cmd=envdrift_cmd)
        _append_foreign_value(
            git_repo,
            secret,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        _git(git_repo, "add", ".env.production.secret", ".env.production.clear")
        _git(git_repo, "commit", "-q", "-m", "secret with one value under another key")
        committed = secret.read_bytes()

        result = _run_envdrift(
            ["pull-partial"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        out = _flat(result)
        assert result.returncode == 1, out
        # The secret file is exactly the committed ciphertext: JWT_SECRET was
        # not left decrypted, so "Decrypted: 0" is now the truth.
        assert secret.read_bytes() == committed
        assert _JWT_VALUE not in secret.read_text(encoding="utf-8")
        assert "Decrypted: 0" in out and "Errors: 1" in out, out
        assert "STRIPE_API_KEY" in out, out
        assert ".env.production.secret was left as it was" in out, out
        # A routine `git add .` stages nothing from the secret file.
        _git(git_repo, "add", ".")
        staged = _git(git_repo, "diff", "--cached", "--name-only").split()
        assert ".env.production.secret" not in staged, staged

    def test_secrets_only_counts_and_protects_the_files_decrypted_first(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        (git_repo / "envdrift.toml").write_text(
            "[partial_encryption]\n"
            "enabled = true\n\n"
            "[[partial_encryption.environments]]\n"
            'name = "production"\n'
            "secrets_only = true\n"
            'secrets_dir = "secrets"\n',
            encoding="utf-8",
        )
        secrets = git_repo / "secrets"
        secrets.mkdir()
        api = secrets / ".env.api"  # sorted first: decrypts
        db = secrets / ".env.db"  # sorted second: one value under another key
        api.write_text(f"API_KEY={_API_VALUE}\n", encoding="utf-8")
        db.write_text(f"DB_PASS={_DB_VALUE}\n", encoding="utf-8")
        _push(git_repo, integration_pythonpath=integration_pythonpath, envdrift_cmd=envdrift_cmd)
        _append_foreign_value(
            git_repo,
            db,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        _git(git_repo, "add", "secrets/.env.api", "secrets/.env.db")
        _git(git_repo, "commit", "-q", "-m", "secrets-only files")
        db_committed = db.read_bytes()

        result = _run_envdrift(
            ["pull-partial"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        out = _flat(result)
        assert result.returncode == 1, out
        # The true tally: one file decrypted before the failure.
        assert "Decrypted: 1" in out and "Errors: 1" in out, out
        assert "STRIPE_API_KEY" in out, out
        # .env.api is plaintext, so the notice is shown despite the error, and
        # the file really is protected.
        assert "SECRET FILES ARE NOW PLAINTEXT" in out, out
        assert f"API_KEY={_API_VALUE}" in api.read_text(encoding="utf-8")
        assert _skip_worktree_flag(git_repo, "secrets/.env.api") == "S"
        # The failing file was left as it was and is not hidden from git.
        assert db.read_bytes() == db_committed
        assert _skip_worktree_flag(git_repo, "secrets/.env.db") == "H"
        assert "secrets/.env.db was left as it was" in out, out

    def test_pull_counts_the_secrets_only_files_decrypted_first(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        """``envdrift pull`` runs the same secrets-only step and reports the tally."""
        partial = (
            "[partial_encryption]\n"
            "enabled = true\n\n"
            "[[partial_encryption.environments]]\n"
            'name = "production"\n'
            "secrets_only = true\n"
            'secrets_dir = "secrets"\n'
        )
        (git_repo / "envdrift.toml").write_text(partial, encoding="utf-8")
        secrets = git_repo / "secrets"
        secrets.mkdir()
        (secrets / ".env.api").write_text(f"API_KEY={_API_VALUE}\n", encoding="utf-8")
        db = secrets / ".env.db"
        db.write_text(f"DB_PASS={_DB_VALUE}\n", encoding="utf-8")
        _push(git_repo, integration_pythonpath=integration_pythonpath, envdrift_cmd=envdrift_cmd)
        _append_foreign_value(
            git_repo,
            db,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        db_committed = db.read_bytes()
        # pull needs a [vault.sync] section; --skip-sync never contacts the
        # dummy vault, and the mapping's plaintext .env.production is skipped.
        (git_repo / ".env.production").write_text("DEBUG=false\n", encoding="utf-8")
        (git_repo / "envdrift.toml").write_text(
            "[vault]\n"
            'provider = "azure"\n\n'
            "[vault.azure]\n"
            'vault_url = "https://dummy.vault.azure.net/"\n\n'
            "[vault.sync]\n"
            'default_vault_name = "dummy"\n\n'
            "[[vault.sync.mappings]]\n"
            'secret_name = "unused"\n'
            'folder_path = "."\n'
            'environment = "production"\n\n' + partial,
            encoding="utf-8",
        )

        result = _run_envdrift(
            ["pull", "--skip-sync"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        out = _flat(result)
        assert result.returncode == 1, out
        summary = out.split("Partial Encryption Summary", 1)[1]
        assert "Decrypted: 1" in summary and "Errors: 1" in summary, out
        assert db.read_bytes() == db_committed


# Age keypair shared with the SOPS e2e suites. Encrypting needs only the public
# key; the private one is for following the SOPS remedy envdrift prints.
_AGE_PUBLIC_KEY = "age1c89jtrvyl72y0muvdp5lm3jpemvc2gr303up4g37tuq4uftcku3q4svqau"
_AGE_PRIVATE_KEY = "AGE-SECRET-KEY-1" + "HGE3ZE9NPEN5R76LVKKJ2Z3G9TYZJLW84P2CHAF6UGL43R7TWPUSZ89MK6"


def _sops_encrypt_in_place(path: Path) -> None:
    """Encrypt a dotenv file in place with the real sops binary."""
    sops = shutil.which("sops")
    if sops is None:
        pytest.skip("sops binary not installed (required for a real SOPS .secret)")
    completed = subprocess.run(
        [
            sops,
            "--encrypt",
            "--age",
            _AGE_PUBLIC_KEY,
            "--input-type",
            "dotenv",
            "--output-type",
            "dotenv",
            "--in-place",
            str(path),
        ],
        capture_output=True,
        text=True,
        cwd=path.parent,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "ENC[AES256_GCM," in path.read_text(encoding="utf-8")


class TestSopsSecretFileIsNotReportedAsDecrypted:
    """#963: a SOPS-encrypted secret file is a failure, never "Decrypted"."""

    @pytest.mark.parametrize("crlf", [False, True], ids=["lf", "crlf"])
    def test_combine_mode_reports_the_sops_file(
        self,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
        crlf: bool,
    ) -> None:
        (git_repo / "envdrift.toml").write_text(
            "[partial_encryption]\n"
            "enabled = true\n\n"
            "[[partial_encryption.environments]]\n"
            'name = "production"\n'
            'clear_file = ".env.production.clear"\n'
            'secret_file = ".env.production.secret"\n'
            'combined_file = ".env.production"\n',
            encoding="utf-8",
        )
        (git_repo / ".env.production.clear").write_text("DEBUG=false\n", encoding="utf-8")
        secret = git_repo / ".env.production.secret"
        secret.write_text(f"JWT_SECRET={_JWT_VALUE}\n", encoding="utf-8")
        _sops_encrypt_in_place(secret)
        if crlf:
            secret.write_bytes(secret.read_bytes().replace(b"\n", b"\r\n"))
        _git(git_repo, "add", ".env.production.secret", ".env.production.clear")
        _git(git_repo, "commit", "-q", "-m", "SOPS-encrypted secret file")
        committed = secret.read_bytes()

        result = _run_envdrift(
            ["pull-partial"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        out = _flat(result)
        assert result.returncode == 1, out
        assert "Decrypted: 0" in out and "Errors: 1" in out, out
        assert ".env.production.secret: it still holds SOPS ciphertext" in out, out
        assert "envdrift decrypt .env.production.secret --backend sops" in out, out
        assert "SECRET FILES ARE NOW PLAINTEXT" not in out, out
        # Left as it was (the wrapper's LF normalization undone) and not hidden
        # from git as if it were a decrypted file.
        assert secret.read_bytes() == committed
        assert _skip_worktree_flag(git_repo, ".env.production.secret") == "H"

    def test_secrets_only_reports_the_sops_file_and_counts_the_rest(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        (git_repo / "envdrift.toml").write_text(
            "[partial_encryption]\n"
            "enabled = true\n\n"
            "[[partial_encryption.environments]]\n"
            'name = "production"\n'
            "secrets_only = true\n"
            'secrets_dir = "secrets"\n',
            encoding="utf-8",
        )
        secrets = git_repo / "secrets"
        secrets.mkdir()
        api = secrets / ".env.api"  # sorted first: dotenvx, decrypts
        api.write_text(f"API_KEY={_API_VALUE}\n", encoding="utf-8")
        _push(git_repo, integration_pythonpath=integration_pythonpath, envdrift_cmd=envdrift_cmd)
        sops_file = secrets / ".env.sops"  # sorted second: SOPS
        sops_file.write_text(f"DB_PASS={_DB_VALUE}\n", encoding="utf-8")
        _sops_encrypt_in_place(sops_file)
        _git(git_repo, "add", "secrets/.env.api", "secrets/.env.sops")
        _git(git_repo, "commit", "-q", "-m", "dotenvx and SOPS secrets")
        committed = sops_file.read_bytes()

        result = _run_envdrift(
            ["pull-partial"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        out = _flat(result)
        assert result.returncode == 1, out
        assert "Decrypted: 1" in out and "Errors: 1" in out, out
        assert "secrets/.env.sops: it still holds SOPS ciphertext" in out, out
        assert sops_file.read_bytes() == committed
        assert _skip_worktree_flag(git_repo, "secrets/.env.sops") == "H"
        assert _skip_worktree_flag(git_repo, "secrets/.env.api") == "S"

    def test_pull_gives_a_remedy_that_keeps_the_plaintext_protected(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        """Right under ``envdrift pull`` too, and following it never exposes the plaintext.

        It said "pull-partial decrypts with dotenvx" under ``envdrift pull``, and its
        ``envdrift decrypt --backend sops`` left the plaintext in a tracked file that
        ``git add .`` staged.
        """

        def run(*args: str) -> subprocess.CompletedProcess[str]:
            return _run_envdrift(
                list(args),
                cwd=git_repo,
                integration_pythonpath=integration_pythonpath,
                envdrift_cmd=envdrift_cmd,
                extra_env={"SOPS_AGE_KEY": _AGE_PRIVATE_KEY},
            )

        # The mapping's plaintext .env.production is skipped; --skip-sync never
        # contacts the dummy vault.
        (git_repo / ".env.production").write_text("DEBUG=false\n", encoding="utf-8")
        (git_repo / "envdrift.toml").write_text(
            _VAULT_SYNC + "[partial_encryption]\n"
            "enabled = true\n\n"
            "[[partial_encryption.environments]]\n"
            'name = "staging"\n'
            'clear_file = ".env.staging.clear"\n'
            'secret_file = ".env.staging.secret"\n'
            'combined_file = ".env.staging"\n',
            encoding="utf-8",
        )
        (git_repo / ".env.staging.clear").write_text("DEBUG=false\n", encoding="utf-8")
        secret = git_repo / ".env.staging.secret"
        secret.write_text(f"JWT_SECRET={_JWT_VALUE}\n", encoding="utf-8")
        _sops_encrypt_in_place(secret)
        _git(git_repo, "add", "-A")
        _git(git_repo, "commit", "-q", "-m", "SOPS-encrypted secret file")

        result = run("pull", "--skip-sync")

        out = _flat(result)
        assert result.returncode == 1, out
        assert ".env.staging.secret: it still holds SOPS ciphertext" in out, out
        assert "pull-partial" not in out, out
        steps = [
            "`git update-index --skip-worktree .env.staging.secret`",
            "`envdrift decrypt .env.staging.secret --backend sops`",
            "`envdrift push`",
        ]
        assert all(step in out for step in steps), out
        assert [out.index(step) for step in steps] == sorted(out.index(step) for step in steps)

        # Follow it: the plaintext is never stageable, and push moves it to dotenvx.
        _git(git_repo, "update-index", "--skip-worktree", ".env.staging.secret")
        decrypt = run("decrypt", ".env.staging.secret", "--backend", "sops")
        assert decrypt.returncode == 0, _flat(decrypt)
        assert f"JWT_SECRET={_JWT_VALUE}" in secret.read_text(encoding="utf-8")
        _git(git_repo, "add", ".")
        staged = _git(git_repo, "diff", "--cached", "--name-only").split()
        assert ".env.staging.secret" not in staged, staged
        push = run("push")
        assert push.returncode == 0, _flat(push)
        assert "JWT_SECRET=encrypted:" in secret.read_text(encoding="utf-8")
        assert _skip_worktree_flag(git_repo, ".env.staging.secret") == "H"


class _Unprivileged:
    """A repository, and a CLI run there that really cannot read a file made unreadable.

    For a normal user ``chmod 000`` is enough. root reads any file, so as root the
    CLI runs as ``nobody`` instead, in a repository it owns outside
    ``/tmp/pytest-of-root`` (mode 0700, which ``nobody`` cannot enter), with a
    ``HOME`` of its own.
    """

    def __init__(self, base: Path, nobody: Any = None) -> None:
        self.base = base
        self.repo = base / "repo"
        self.repo.mkdir()
        self.nobody = nobody
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.email", "test@example.com")
        _git(self.repo, "config", "user.name", "Test")

    def make_unreadable(self, path: Path) -> None:
        """Make ``path`` unreadable to the CLI and everything else in the repository its own."""
        if self.nobody is None:
            path.chmod(0)
            return
        for owned in [self.base, *self.base.rglob("*")]:
            os.chown(owned, self.nobody.pw_uid, self.nobody.pw_gid, follow_symlinks=False)
        os.chown(path, 0, 0)
        path.chmod(0o600)

    def make_readable(self, path: Path) -> None:
        """Let this test read ``path`` again (root always could)."""
        if self.nobody is None:
            path.chmod(0o600)

    def run(
        self, args: list[str], *, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath
        kwargs: dict[str, Any] = {}
        if self.nobody is not None:
            home = self.base / "home"
            home.mkdir(exist_ok=True)
            os.chown(home, self.nobody.pw_uid, self.nobody.pw_gid)
            env["HOME"] = str(home)
            for name in ("XDG_CONFIG_HOME", "COVERAGE_PROCESS_START", "COVERAGE_PROCESS_CONFIG"):
                env.pop(name, None)
            kwargs = {
                "user": self.nobody.pw_uid,
                "group": self.nobody.pw_gid,
                "extra_groups": [],
            }
        return subprocess.run(
            [*envdrift_cmd, *args],
            cwd=self.repo,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
            **kwargs,
        )

    def git(self, *args: str) -> str:
        """git as this test's user, in a repository ``nobody`` may own by now."""
        return _git(self.repo, "-c", "safe.directory=*", *args)


@pytest.fixture
def unprivileged(tmp_path: Path) -> Iterator[_Unprivileged]:
    if sys.platform == "win32":
        pytest.skip("Windows has no POSIX mode bits to make a file unreadable")
    if os.geteuid() != 0:
        yield _Unprivileged(tmp_path)
        return
    import pwd

    try:
        nobody = pwd.getpwnam("nobody")
    except KeyError:
        pytest.skip("running as root, with no 'nobody' account to drop privileges to")
    base = Path(tempfile.mkdtemp(prefix="envdrift-unreadable-"))
    try:
        yield _Unprivileged(base, nobody)
    finally:
        shutil.rmtree(base, ignore_errors=True)


class TestUnreadableLaterSecretFile:
    """Any failure on a later file keeps the tally and the warning, not only a decrypt error."""

    @pytest.mark.parametrize("command", ["pull-partial", "pull"])
    def test_the_files_decrypted_before_it_are_counted_and_named(
        self,
        unprivileged: _Unprivileged,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
        command: str,
    ) -> None:
        repo = unprivileged.repo
        partial = (
            "[partial_encryption]\n"
            "enabled = true\n\n"
            "[[partial_encryption.environments]]\n"
            'name = "production"\n'
            "secrets_only = true\n"
            'secrets_dir = "secrets"\n'
        )
        (repo / "envdrift.toml").write_text(partial, encoding="utf-8")
        secrets = repo / "secrets"
        secrets.mkdir()
        api = secrets / ".env.api"  # sorted first: decrypts, and is untracked
        api.write_text(f"API_KEY={_API_VALUE}\n", encoding="utf-8")
        db = secrets / ".env.db"  # sorted second: unreadable
        db.write_text(f"DB_PASS={_DB_VALUE}\n", encoding="utf-8")
        _push(repo, integration_pythonpath=integration_pythonpath, envdrift_cmd=envdrift_cmd)
        unprivileged.git("add", "envdrift.toml", ".gitignore")
        unprivileged.git("commit", "-q", "-m", "config")
        args = ["pull-partial"]
        if command == "pull":
            # --skip-sync never contacts the dummy vault; the mapping's plaintext
            # .env.production is skipped.
            (repo / ".env.production").write_text("DEBUG=false\n", encoding="utf-8")
            (repo / "envdrift.toml").write_text(_VAULT_SYNC + partial, encoding="utf-8")
            args = ["pull", "--skip-sync"]
        db_before = db.read_bytes()
        unprivileged.make_unreadable(db)

        result = unprivileged.run(
            args, integration_pythonpath=integration_pythonpath, envdrift_cmd=envdrift_cmd
        )

        out = _flat(result)
        assert result.returncode == 1, out
        assert "Traceback" not in out, out
        summary = out.rsplit("Summary", 1)[1]
        assert "Decrypted: 1" in summary and "Errors: 1" in summary, out
        assert "Failed to decrypt secrets/.env.db: [Errno 13]" in out, out
        assert "secrets/.env.db was left as it was" in out, out
        # .env.api is untracked plaintext now, so it is named in the warning.
        assert "DANGER: No Git Protection Applied" in out, out
        assert "• secrets/.env.api (untracked)" in out, out
        assert f"API_KEY={_API_VALUE}" in api.read_text(encoding="utf-8")
        unprivileged.make_readable(db)
        assert db.read_bytes() == db_before
        untracked = unprivileged.git("status", "--porcelain", "--untracked-files=all", "secrets")
        assert "?? secrets/.env.api" in untracked, untracked


def test_pull_reports_any_secrets_only_failure_for_that_environment(
    git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
) -> None:
    """``envdrift pull`` caught only PartialEncryptionError, so anything else was a crash.

    An absolute ``pattern`` makes ``Path.glob`` raise NotImplementedError; pull-partial
    reports it for the environment, and so must ``pull``.
    """
    (git_repo / "secrets").mkdir()
    (git_repo / "secrets" / ".env.api").write_text(f"API_KEY={_API_VALUE}\n", encoding="utf-8")
    (git_repo / ".env.production").write_text("DEBUG=false\n", encoding="utf-8")
    (git_repo / "envdrift.toml").write_text(
        _VAULT_SYNC + "[partial_encryption]\n"
        "enabled = true\n\n"
        "[[partial_encryption.environments]]\n"
        'name = "production"\n'
        "secrets_only = true\n"
        'secrets_dir = "secrets"\n'
        f'pattern = "{(git_repo / ".env*").as_posix()}"\n',
        encoding="utf-8",
    )

    result = _run_envdrift(
        ["pull", "--skip-sync"],
        cwd=git_repo,
        integration_pythonpath=integration_pythonpath,
        envdrift_cmd=envdrift_cmd,
    )

    out = _flat(result)
    assert result.returncode == 1, out
    assert "Traceback" not in out, out
    summary = out.split("Partial Encryption Summary", 1)[1]
    assert "Errors: 1" in summary, out
    assert "• production: Non-relative patterns are unsupported" in out, out
