"""A key dotenvx never encrypts is not leftover plaintext, and still not safe (#1048).

dotenvx 2.38.2 never encrypts a key whose name ends with ``_PLAIN`` (its ``/_PLAIN$/``
test, case-sensitive), unless it reads an ``Envfile`` in its working directory, whose
policy then decides. envdrift counted such a key as plaintext the encryption missed:
``encrypt`` and ``push`` failed with "Encryption did not take effect ... the encryption
key was missing or invalid" after dotenvx had encrypted the rest, and ``lock --check``
never passed. The value is still unencrypted, so ``encrypt --check`` and guard keep
reporting a secret-looking one.

Every test runs the real dotenvx binary, and all but the first the real ``envdrift`` CLI.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which("dotenvx") is None,
        reason="dotenvx binary not installed (required to see which keys it encrypts)",
    ),
]

# Built by concatenation so push protection never sees a whole secret literal.
_API_KEY = "abc" + "123"
_STRIPE_LIVE = "sk_" + "live_" + "0" * 24  # an obviously made-up key of the live shape

_LOCK_CONFIG = """\
[vault]
provider = "aws"

[vault.aws]
region = "us-east-1"

[encryption]
backend = "dotenvx"

[[vault.sync.mappings]]
secret_name = "svc-key"
folder_path = "svc"
environment = "production"
"""

_PARTIAL_CONFIG = """\
[partial_encryption]
enabled = true

[[partial_encryption.environments]]
name = "production"
clear_file = ".env.production.clear"
secret_file = ".env.production.secret"
combined_file = ".env.production"
"""


_SECRETS_ONLY_CONFIG = """\
[partial_encryption]
enabled = true

[[partial_encryption.environments]]
name = "api"
secrets_only = true
secrets_dir = "secrets"
"""


def _run_envdrift(
    args: list[str], *, cwd: Path, integration_pythonpath: str, envdrift_cmd: list[str]
) -> subprocess.CompletedProcess[str]:
    """Run the real envdrift CLI as a subprocess and capture its output."""
    env = os.environ.copy()
    env["PYTHONPATH"] = integration_pythonpath
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


# An assignment dotenvx left as written: neither a comment nor its public key, nor ciphertext.
_LEFT_AS_WRITTEN_RE = re.compile(
    r"^(?!#|DOTENV_PUBLIC_KEY)(?:export )?([^=\s]+)\s*=(?!.*encrypted:)"
)


def _plaintext_names(env_file: Path) -> set[str]:
    """The names whose value dotenvx left as written, ``export`` or quotes aside."""
    lines = env_file.read_text(encoding="utf-8").splitlines()
    return {match.group(1) for match in map(_LEFT_AS_WRITTEN_RE.match, lines) if match}


class TestTheRuleIsTheBinarys:
    """envdrift's ``is_plain_key`` and ``plain_keys_apply`` match what dotenvx does."""

    _NAMES = [
        "NOTE_PLAIN",
        "_PLAIN",
        "note_plain",
        "NOTE_plain",
        "PLAIN",
        "PLAIN_NOTE",
        "X_PLAIN_Y",
        "X_PLAINS",
        "dot.key_PLAIN",
        "dash-key_PLAIN",
        "NOTE",
    ]

    def _encrypt(self, folder: Path) -> Path:
        env_file = folder / ".env"
        lines = [f"{name}=x" for name in self._NAMES]
        lines += ['QUOTED_PLAIN="x"', "SINGLE_PLAIN='x'", "export EXPORTED_PLAIN=x"]
        lines += ["export EXPORTED=x"]
        env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        subprocess.run(
            ["dotenvx", "encrypt", "-f", ".env", "-fk", ".env.keys"],
            cwd=folder,
            capture_output=True,
            check=True,
            timeout=120,
        )
        return env_file

    def test_dotenvx_leaves_exactly_the_plain_keys(self, tmp_path: Path) -> None:
        from envdrift.integrations.dotenvx_keys import is_plain_key, plain_keys_apply

        env_file = self._encrypt(tmp_path)

        names = [*self._NAMES, "QUOTED_PLAIN", "SINGLE_PLAIN", "EXPORTED_PLAIN", "EXPORTED"]
        assert plain_keys_apply(tmp_path)
        assert _plaintext_names(env_file) == {name for name in names if is_plain_key(name)}

    def test_an_envfile_in_the_working_directory_turns_the_rule_off(self, tmp_path: Path) -> None:
        from envdrift.integrations.dotenvx_keys import plain_keys_apply

        (tmp_path / "Envfile").write_text("", encoding="utf-8")

        env_file = self._encrypt(tmp_path)

        assert not plain_keys_apply(tmp_path)
        assert _plaintext_names(env_file) == set()


class TestEncryptAcceptsWhatDotenvxLeavesPlain:
    """``envdrift encrypt`` reports the encryption dotenvx did, not a key problem."""

    def test_encrypt_succeeds_and_keeps_the_plain_key(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        env_file = git_repo / ".env"
        env_file.write_text(f"API_KEY={_API_KEY}\nNOTE_PLAIN=hello\n", encoding="utf-8")

        result = _run_envdrift(
            ["encrypt", ".env"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        output = _flat(result)
        assert result.returncode == 0, output
        assert "Encrypted .env using dotenvx" in output
        assert "did not take effect" not in output
        text = env_file.read_text(encoding="utf-8")
        assert "API_KEY=encrypted:" in text and _API_KEY not in text
        assert "NOTE_PLAIN=hello" in text

    def test_a_secret_in_a_plain_key_is_still_reported(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        env_file = git_repo / ".env"
        env_file.write_text(f"API_KEY={_API_KEY}\nAPI_KEY_PLAIN={_STRIPE_LIVE}\n", encoding="utf-8")
        encrypted = _run_envdrift(
            ["encrypt", ".env"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        assert encrypted.returncode == 0, _flat(encrypted)
        assert _STRIPE_LIVE in env_file.read_text(encoding="utf-8")

        check = _run_envdrift(
            ["encrypt", "--check", ".env"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        guard = _run_envdrift(
            ["guard", "--native-only", "--json", ".env"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        output = _flat(check)
        assert check.returncode == 1, output
        assert "PLAINTEXT SECRETS DETECTED" in output
        assert "'API_KEY_PLAIN' has a value that looks like a secret" in output
        rules = {finding["rule_id"] for finding in json.loads(guard.stdout)["findings"]}
        assert "stripe-secret-key" in rules, _flat(guard)
        assert guard.returncode != 0, _flat(guard)


class TestLockAcceptsWhatDotenvxLeavesPlain:
    """``lock`` treats a dotenvx file with a ``_PLAIN`` key as fully encrypted."""

    def test_lock_check_and_lock_pass(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        (git_repo / "envdrift.toml").write_text(_LOCK_CONFIG, encoding="utf-8")
        env_file = git_repo / "svc" / ".env.production"
        env_file.parent.mkdir()
        env_file.write_text(f"API_KEY={_API_KEY}\nNOTE_PLAIN=hello\n", encoding="utf-8")

        def run(*args: str) -> subprocess.CompletedProcess[str]:
            return _run_envdrift(
                list(args),
                cwd=git_repo,
                integration_pythonpath=integration_pythonpath,
                envdrift_cmd=envdrift_cmd,
            )

        encrypted = run("encrypt", "svc/.env.production")
        assert encrypted.returncode == 0, _flat(encrypted)
        before = env_file.read_bytes()

        check = run("lock", "--check")
        lock = run("lock", "--force")

        assert check.returncode == 0, _flat(check)
        assert "skipped (already encrypted)" in _flat(check)
        assert "plaintext values remain" not in _flat(check)
        assert lock.returncode == 0, _flat(lock)
        assert env_file.read_bytes() == before


class TestPushAcceptsWhatDotenvxLeavesPlain:
    """The partial-encryption ``push`` encrypts the rest and counts only that as encrypted."""

    def test_push_succeeds_and_check_stays_in_sync(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        (git_repo / "envdrift.toml").write_text(_PARTIAL_CONFIG, encoding="utf-8")
        (git_repo / ".env.production.clear").write_text("APP=shop\n", encoding="utf-8")
        secret = git_repo / ".env.production.secret"
        secret.write_text(f"DB_PASSWORD={_API_KEY}\nREGION_PLAIN=eu\n", encoding="utf-8")

        def run(*args: str) -> subprocess.CompletedProcess[str]:
            return _run_envdrift(
                list(args),
                cwd=git_repo,
                integration_pythonpath=integration_pythonpath,
                envdrift_cmd=envdrift_cmd,
            )

        push = run("push")
        check = run("push", "--check")

        output = _flat(push)
        assert push.returncode == 0, output
        assert "(1 clear + 1 encrypted)" in output
        text = secret.read_text(encoding="utf-8")
        assert "DB_PASSWORD=encrypted:" in text and "REGION_PLAIN=eu" in text
        assert check.returncode == 0, _flat(check)


class TestAFileOfOnlyPlainKeysIsDone:
    """A file of nothing but ``_PLAIN`` keys, which dotenvx leaves as it is, is done (#1048).

    It holds no ciphertext, and never will, so lock and push --check called it unencrypted
    for ever: ``lock --check`` exited 1 after every lock, and ``push --check`` after every
    push.
    """

    @staticmethod
    def _runner(repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]):
        def run(*args: str) -> subprocess.CompletedProcess[str]:
            return _run_envdrift(
                list(args),
                cwd=repo,
                integration_pythonpath=integration_pythonpath,
                envdrift_cmd=envdrift_cmd,
            )

        return run

    def test_lock_check_passes_before_and_after_a_lock_that_changes_nothing(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        (git_repo / "envdrift.toml").write_text(_LOCK_CONFIG, encoding="utf-8")
        env_file = git_repo / "svc" / ".env.production"
        env_file.parent.mkdir()
        env_file.write_text("NOTE_PLAIN=hello\n", encoding="utf-8")
        run = self._runner(git_repo, integration_pythonpath, envdrift_cmd)

        results = [run("lock", "--check"), run("lock", "--force"), run("lock", "--check")]

        for result in results:
            output = _flat(result)
            assert result.returncode == 0, output
            assert "skipped (already encrypted)" in output
            assert "would be encrypted" not in output
        assert env_file.read_text(encoding="utf-8") == "NOTE_PLAIN=hello\n"

    def test_push_check_is_in_sync_after_a_push(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        (git_repo / "envdrift.toml").write_text(_PARTIAL_CONFIG, encoding="utf-8")
        (git_repo / ".env.production.clear").write_text("APP=shop\n", encoding="utf-8")
        secret = git_repo / ".env.production.secret"
        secret.write_text("NOTE_PLAIN=hello\n", encoding="utf-8")
        run = self._runner(git_repo, integration_pythonpath, envdrift_cmd)

        push = run("push")
        check = run("push", "--check")

        assert push.returncode == 0, _flat(push)
        assert "(1 clear + 0 encrypted)" in _flat(push)
        assert secret.read_text(encoding="utf-8") == "NOTE_PLAIN=hello\n"
        assert check.returncode == 0, _flat(check)
        assert "up to date" in _flat(check)

    def test_secrets_only_push_check_is_in_sync(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        (git_repo / "envdrift.toml").write_text(_SECRETS_ONLY_CONFIG, encoding="utf-8")
        secret = git_repo / "secrets" / ".env.api"
        secret.parent.mkdir()
        secret.write_text("NOTE_PLAIN=hello\n", encoding="utf-8")
        run = self._runner(git_repo, integration_pythonpath, envdrift_cmd)

        push = run("push")
        check = run("push", "--check")

        assert push.returncode == 0, _flat(push)
        assert check.returncode == 0, _flat(check)
        assert "not encrypted" not in _flat(check)
        assert secret.read_text(encoding="utf-8") == "NOTE_PLAIN=hello\n"


class TestAPlainKeyValueSpanningLines:
    """A quoted ``_PLAIN`` value that spans lines is one value, which dotenvx leaves as it is.

    Its line ``TOKEN=hello`` was read as an assignment of its own, and as plaintext the
    encryption missed: encrypt failed, and lock --check never passed (#1048).
    """

    _VALUE = 'NOTE_PLAIN="line one\nTOKEN=hello\nline three"'

    def test_encrypt_and_lock_check_pass(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        (git_repo / "envdrift.toml").write_text(_LOCK_CONFIG, encoding="utf-8")
        env_file = git_repo / "svc" / ".env.production"
        env_file.parent.mkdir()
        env_file.write_text(f"API_KEY={_API_KEY}\n{self._VALUE}\n", encoding="utf-8")
        run = TestAFileOfOnlyPlainKeysIsDone._runner(git_repo, integration_pythonpath, envdrift_cmd)

        encrypted = run("encrypt", "svc/.env.production")
        check = run("lock", "--check")

        assert encrypted.returncode == 0, _flat(encrypted)
        text = env_file.read_text(encoding="utf-8")
        assert "API_KEY=encrypted:" in text and self._VALUE in text, text
        assert check.returncode == 0, _flat(check)
        assert "plaintext values remain" not in _flat(check)


class TestTheRuleHoldsBesideAMentionOfSops:
    """A comment that names SOPS's envelope does not turn the ``_PLAIN`` rule off."""

    def test_encrypt_succeeds(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        env_file = git_repo / ".env"
        env_file.write_text(
            f"# SOPS writes ENC[AES256_GCM,data:...] values\nAPI_KEY={_API_KEY}\nNOTE_PLAIN=hi\n",
            encoding="utf-8",
        )

        result = _run_envdrift(
            ["encrypt", ".env"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        assert result.returncode == 0, _flat(result)
        assert "did not take effect" not in _flat(result)
        assert "NOTE_PLAIN=hi" in env_file.read_text(encoding="utf-8")


class TestAPlainKeyMayHoldAHash:
    """dotenvx encrypts none of a ``_PLAIN`` key, so a ``#`` in its value leaves none of it out.

    encrypt refused such a value as one dotenvx would cut at the ``#`` and leave partly
    unencrypted (#947), though it leaves the whole of it plaintext by design.
    """

    def test_encrypt_encrypts_the_rest(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        env_file = git_repo / ".env"
        env_file.write_text(
            f"DOCS_URL_PLAIN=https://example.com/docs#setup\nAPI_KEY={_API_KEY}\n",
            encoding="utf-8",
        )

        result = _run_envdrift(
            ["encrypt", ".env"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        output = _flat(result)
        assert result.returncode == 0, output
        assert "Refusing" not in output
        text = env_file.read_text(encoding="utf-8")
        assert "DOCS_URL_PLAIN=https://example.com/docs#setup\n" in text
        assert "API_KEY=encrypted:" in text and _API_KEY not in text

    def test_with_an_envfile_it_is_refused(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        """There dotenvx encrypts the ``_PLAIN`` keys too, and would cut this one at the ``#``."""
        (git_repo / "Envfile").write_text("", encoding="utf-8")
        env_file = git_repo / ".env"
        content = f"DOCS_URL_PLAIN=https://example.com/docs#setup\nAPI_KEY={_API_KEY}\n"
        env_file.write_text(content, encoding="utf-8")

        result = _run_envdrift(
            ["encrypt", ".env"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        output = _flat(result)
        assert result.returncode == 1, output
        assert "leave part of DOCS_URL_PLAIN unencrypted" in output
        assert env_file.read_text(encoding="utf-8") == content


class TestAColonAssignmentIsChecked:
    """dotenvx loads ``KEY: value``, and its encrypt leaves such a value plaintext.

    envdrift's checks read only ``KEY=value`` lines. Beside a ``_PLAIN`` key, such a secret
    passed encrypt, push, push --check and lock --check; beside ciphertext, it passed encrypt.
    """

    _SECRET_LINE = f"DB_PASSWORD: {_API_KEY}"

    def test_dotenvx_loads_it_and_leaves_it_plaintext(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text(f"API_KEY={_API_KEY}\n{self._SECRET_LINE}\n", encoding="utf-8")
        dotenvx = ["dotenvx", "encrypt", "-f", ".env", "-fk", ".env.keys"]
        subprocess.run(dotenvx, cwd=tmp_path, capture_output=True, check=True, timeout=120)

        loaded = subprocess.run(
            ["dotenvx", "get", "DB_PASSWORD", "-f", ".env", "-fk", ".env.keys"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        )

        assert loaded.stdout.strip() == _API_KEY
        text = env_file.read_text(encoding="utf-8")
        assert "API_KEY=encrypted:" in text and f"{self._SECRET_LINE}\n" in text

    @pytest.mark.parametrize(
        "beside", ["NOTE_PLAIN=hello", f"API_KEY={_API_KEY}"], ids=["a-plain-key", "a-secret"]
    )
    def test_encrypt_fails_while_it_is_plaintext(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str], beside: str
    ) -> None:
        env_file = git_repo / ".env"
        env_file.write_text(f"{beside}\n{self._SECRET_LINE}\n", encoding="utf-8")

        result = _run_envdrift(
            ["encrypt", ".env"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        output = _flat(result)
        assert result.returncode == 1, output
        assert "Encryption did not take effect" in output
        assert self._SECRET_LINE in env_file.read_text(encoding="utf-8")

    def test_encrypt_passes_beside_one_that_holds_only_a_comment(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        """dotenvx reads ``KEY: # a note`` as an empty value, which holds no secret to encrypt."""
        env_file = git_repo / ".env"
        env_file.write_text(
            f"API_KEY={_API_KEY}\nDB_PASSWORD: # set in production\n", encoding="utf-8"
        )

        result = _run_envdrift(
            ["encrypt", ".env"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        output = _flat(result)
        assert result.returncode == 0, output
        assert "did not take effect" not in output
        text = env_file.read_text(encoding="utf-8")
        assert "API_KEY=encrypted:" in text and _API_KEY not in text
        assert "DB_PASSWORD: # set in production\n" in text

    def test_lock_check_calls_it_unencrypted(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        (git_repo / "envdrift.toml").write_text(_LOCK_CONFIG, encoding="utf-8")
        env_file = git_repo / "svc" / ".env.production"
        env_file.parent.mkdir()
        env_file.write_text(f"NOTE_PLAIN=hello\n{self._SECRET_LINE}\n", encoding="utf-8")

        check = TestAFileOfOnlyPlainKeysIsDone._runner(
            git_repo, integration_pythonpath, envdrift_cmd
        )("lock", "--check")

        output = _flat(check)
        assert check.returncode == 1, output
        assert "would be encrypted" in output
        assert "skipped (already encrypted)" not in output

    def test_push_fails_and_check_calls_it_out_of_date(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        (git_repo / "envdrift.toml").write_text(_PARTIAL_CONFIG, encoding="utf-8")
        (git_repo / ".env.production.clear").write_text("APP=shop\n", encoding="utf-8")
        secret = git_repo / ".env.production.secret"
        secret.write_text(f"NOTE_PLAIN=hello\n{self._SECRET_LINE}\n", encoding="utf-8")
        run = TestAFileOfOnlyPlainKeysIsDone._runner(git_repo, integration_pythonpath, envdrift_cmd)

        push = run("push")
        check = run("push", "--check")

        assert push.returncode == 1, _flat(push)
        assert "Encryption did not take effect" in _flat(push)
        assert "Push complete" not in _flat(push)
        assert check.returncode == 1, _flat(check)
        assert "out of date" in _flat(check)
