"""Backtick-quoted dotenvx ciphertext counts as encrypted (#950).

dotenvx reads ``KEY=`value` `` as a quoted value and keeps the backticks around the
ciphertext it writes. These are the checks ``encrypt``, ``decrypt``, ``push`` and
``encrypt --check`` make, so each must see the ciphertext inside the backticks.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import typer

from envdrift.cli_commands.encryption import _encrypt_one_file
from envdrift.core.encryption import EncryptionDetector
from envdrift.core.parser import EncryptionStatus, EnvParser, strip_backtick_quotes
from envdrift.core.partial_encryption import (
    _is_quote_wrapped,
    _unquote_value,
    has_plaintext_secret_value,
    is_file_encrypted,
    is_fully_encrypted,
)
from envdrift.encryption.base import EncryptionResult

# Built by concatenation so push protection never sees a whole secret literal.
_SECRET = "sk_" + "test_" + "abc123"
_CIPHERTEXT = "encrypted:" + "BJcmM3MTYm+PjK7upMiPNCU1mwz76onUbudP="


class TestPartialEncryptionHelpers:
    """The raw-line checks behind encrypt's outcome check and decrypt's pre-check."""

    @pytest.mark.parametrize("quote", ['"', "'", "`"])
    def test_each_quote_style_wraps_a_value(self, quote: str) -> None:
        assert _is_quote_wrapped(f"{quote}x{quote}")

    @pytest.mark.parametrize("text", ["`x", "x`", "`", "`x'", "x"])
    def test_an_unbalanced_backtick_does_not_wrap(self, text: str) -> None:
        assert not _is_quote_wrapped(text)

    def test_unquote_strips_backticks_and_a_trailing_comment(self) -> None:
        assert _unquote_value(f" `{_CIPHERTEXT}` # note") == _CIPHERTEXT

    def test_backtick_ciphertext_is_encrypted_and_not_plaintext(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text(f"API_KEY=`{_CIPHERTEXT}`\n", encoding="utf-8")

        assert is_file_encrypted(env_file)
        assert not has_plaintext_secret_value(env_file)
        assert is_fully_encrypted(env_file)

    def test_backtick_plaintext_is_still_plaintext(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text(f"API_KEY=`{_SECRET}`\n", encoding="utf-8")

        assert not is_file_encrypted(env_file)
        assert has_plaintext_secret_value(env_file)


class TestParserReadsCiphertextInsideBackticks:
    """``EnvParser`` keeps python-dotenv's value but classifies the ciphertext inside."""

    def test_strip_backtick_quotes_removes_one_pair_only(self) -> None:
        assert strip_backtick_quotes("`a`") == "a"
        assert strip_backtick_quotes("``a``") == "`a`"
        assert strip_backtick_quotes("`a") == "`a"
        assert strip_backtick_quotes("`") == "`"
        assert strip_backtick_quotes('"a"') == '"a"'

    def test_backtick_ciphertext_is_encrypted_dotenvx(self) -> None:
        env = EnvParser().parse_string(f"API_KEY=`{_CIPHERTEXT}`\n")
        var = env.variables["API_KEY"]

        assert var.value == f"`{_CIPHERTEXT}`"  # python-dotenv keeps the backticks
        assert var.encryption_status == EncryptionStatus.ENCRYPTED
        assert var.encryption_backend == "dotenvx"

    def test_backtick_plaintext_stays_plaintext(self) -> None:
        env = EnvParser().parse_string(f"API_KEY=`{_SECRET}`\n")

        assert env.variables["API_KEY"].encryption_status == EncryptionStatus.PLAINTEXT

    def test_check_report_counts_the_backtick_ciphertext_as_encrypted(self) -> None:
        env = EnvParser().parse_string(f"API_KEY=`{_CIPHERTEXT}`\n", lenient=True)
        report = EncryptionDetector().analyze(env)

        assert report.encrypted_vars == {"API_KEY"}
        assert report.plaintext_secrets == set()
        assert report.is_fully_encrypted


class _FailingBackend:
    """A backend whose encryption wrote a new key, then failed its outcome check."""

    name = "dotenvx"

    def encrypt(self, env_file: Path, **_kwargs: object) -> EncryptionResult:
        (env_file.parent / ".env.keys").write_text("DOTENV_PRIVATE_KEY=abc\n", encoding="utf-8")
        return EncryptionResult(success=False, message="did not take effect", file_path=env_file)


def test_failed_encrypt_still_gitignores_the_key_it_wrote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=x\n", encoding="utf-8")

    with pytest.raises(typer.Exit) as exc:
        _encrypt_one_file(env_file, _FailingBackend(), {}, smart_enabled=False)  # type: ignore[arg-type]

    assert exc.value.exit_code == 1
    assert ".env.keys" in (tmp_path / ".gitignore").read_text(encoding="utf-8")
