"""A ``#`` touching an unquoted value: refused before dotenvx runs, never called encrypted (#947).

dotenvx ends an unquoted value at its first ``#`` and keeps the rest of the line as a
comment; python-dotenv starts a comment only at a ``#`` after whitespace. The real
binary is exercised in tests/integration/test_inline_hash_encrypt_e2e.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.core.parser import EncryptionStatus, EnvParser
from envdrift.core.partial_encryption import (
    _value_is_only_ciphertext,
    has_plaintext_secret_value,
    is_file_encrypted,
    is_fully_encrypted,
)
from envdrift.encryption.dotenvx import DotenvxEncryptionBackend
from envdrift.integrations.dotenvx import DotenvxValueError, DotenvxWrapper
from envdrift.integrations.dotenvx_keys import comment_cut_names

# Built by concatenation so push protection never sees a whole secret literal.
_PASSWORD = "hunter2" + "#" + "Spring2024!"
_CIPHERTEXT = "encrypted:" + "BJcmM3MTYm+PjK7upMiPNCU1mwz76onUbudP="


class TestCommentCutNames:
    """Which values dotenvx would end at a ``#`` that touches them."""

    @pytest.mark.parametrize(
        ("text", "names"),
        [
            (f"DB_PASSWORD={_PASSWORD}\n", ["DB_PASSWORD"]),
            ("COLOR=#FF0000\n", ["COLOR"]),
            ("TOKEN=abc\\#def\n", ["TOKEN"]),
            ("export TOKEN=a#b\n", ["TOKEN"]),
            ("  SPACED = a#b\n", ["SPACED"]),
            ("YAML: a#b\n", ["YAML"]),
            ("EMPTY=#\n", ["EMPTY"]),
            ("A=a#b\r\nB=c#d\r\n", ["A", "B"]),
            ("A=a#b\nA=c#d\n", ["A"]),
            (f"DB_PASSWORD={_CIPHERTEXT}#Spring2024!\n", ["DB_PASSWORD"]),
        ],
        ids=[
            "glued",
            "leading",
            "escaped",
            "export",
            "spaced",
            "colon",
            "bare-hash",
            "crlf",
            "repeated",
            "already-cut",
        ],
    )
    def test_a_touching_hash_is_found(self, text: str, names: list[str]) -> None:
        assert comment_cut_names(text) == names

    @pytest.mark.parametrize(
        "text",
        [
            "NOTE=plain # a comment\n",
            "NOTE= # empty value\n",
            "YAML: #comment\n",
            f'DB_PASSWORD="{_PASSWORD}"\n',
            f"DB_PASSWORD='{_PASSWORD}'\n",
            f"DB_PASSWORD=`{_PASSWORD}`\n",
            'QUOTED="a"#comment\n',
            "# A=a#b\n",
            "EMPTY=\n",
            "PLAIN=value\n",
        ],
        ids=[
            "spaced-comment",
            "empty-comment",
            "colon-comment",
            "double",
            "single",
            "tick",
            "after-quote",
            "comment-line",
            "empty",
            "no-hash",
        ],
    )
    def test_a_hash_that_is_a_comment_or_value_text_is_not(self, text: str) -> None:
        assert comment_cut_names(text) == []


class TestPlaintextAfterTheHash:
    """A ciphertext with plaintext glued after a ``#`` still holds plaintext."""

    def test_glued_tail_is_not_only_ciphertext(self) -> None:
        assert not _value_is_only_ciphertext(f"{_CIPHERTEXT}#Spring2024!")

    def test_spaced_comment_is_only_ciphertext(self) -> None:
        assert _value_is_only_ciphertext(f"{_CIPHERTEXT} # a comment")
        assert _value_is_only_ciphertext(f'"{_CIPHERTEXT}" # a comment')

    def test_file_with_a_glued_tail_holds_ciphertext_and_plaintext(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env.production.secret"
        env_file.write_text(f"DB_PASSWORD={_CIPHERTEXT}#Spring2024!\n", encoding="utf-8")

        assert is_file_encrypted(env_file)  # dotenvx can still decrypt it
        assert has_plaintext_secret_value(env_file)
        assert not is_fully_encrypted(env_file)

    def test_parser_calls_a_glued_tail_plaintext(self) -> None:
        env = EnvParser().parse_string(
            f"DB_PASSWORD={_CIPHERTEXT}#Spring2024!\nNOTE={_CIPHERTEXT} # c\n"
        )

        assert env.variables["DB_PASSWORD"].encryption_status == EncryptionStatus.PLAINTEXT
        assert env.variables["NOTE"].encryption_status == EncryptionStatus.ENCRYPTED


class TestEncryptRefusesBeforeDotenvxRuns:
    """The refusal needs no dotenvx: nothing runs and nothing is written."""

    def test_wrapper_refuses_and_changes_nothing(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env.production"
        content = f"DB_PASSWORD={_PASSWORD}\r\nAPI_KEY=abc\r\n"
        env_file.write_bytes(content.encode("utf-8"))
        wrapper = DotenvxWrapper(auto_install=False)

        def _no_dotenvx(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("dotenvx must not run")

        wrapper._run = _no_dotenvx  # type: ignore[method-assign]

        with pytest.raises(DotenvxValueError, match="DB_PASSWORD unencrypted"):
            wrapper.encrypt(env_file)

        assert env_file.read_bytes() == content.encode("utf-8")
        assert not (tmp_path / ".env.keys").exists()

    def test_backend_reports_the_refusal_as_a_failed_result(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env_file = tmp_path / ".env.production"
        env_file.write_text("COLOR=#FF0000\n", encoding="utf-8")
        backend = DotenvxEncryptionBackend()
        monkeypatch.setattr(backend, "is_installed", lambda: True)

        result = backend.encrypt(env_file)

        assert not result.success
        assert "Refusing to encrypt" in result.message
        assert "COLOR" in result.message
        assert "Nothing was changed." in result.message
        assert env_file.read_text(encoding="utf-8") == "COLOR=#FF0000\n"
