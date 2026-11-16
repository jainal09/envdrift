"""decrypt writes back exactly the text each value was encrypted from (#946).

dotenvx itself is replaced by a stand-in ``_run_raw`` that decrypts the copy envdrift
hands it the way ``dotenvx decrypt --stdout`` does: each single-quoted value is
printed as it is. The fake ciphertext is ``encrypted:`` plus the plaintext in base64.
The behavior under test is envdrift's: what goes into the copy, how the plaintext is
read back, and what is written into the file. The real binary is exercised in
tests/integration/test_decrypt_keeps_values_e2e.py.
"""

from __future__ import annotations

import base64
import errno
import os
import re
import subprocess
from pathlib import Path

import pytest

from envdrift.integrations.dotenvx import (
    DotenvxError,
    DotenvxNotFoundError,
    DotenvxWrapper,
    _stand_in_values,
    _with_plaintexts,
)
from envdrift.integrations.dotenvx_keys import CiphertextValue, ciphertext_values

# Built by concatenation so push protection never sees a whole secret literal.
_PASSWORD = "Xk9" + "$mQ2zz" + "!"
_PUBLIC_KEY = "02" + "a3" * 32


def _ct(plaintext: str) -> str:
    """The stand-in ciphertext of ``plaintext``."""
    return "encrypted:" + base64.b64encode(plaintext.encode()).decode()


class _StandInDotenvx:
    """``dotenvx decrypt --stdout`` for the copy: each quoted value printed decrypted."""

    def __init__(self, *, returncode: int = 0, stderr: str = "", stdout: bytes | None = None):
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = stdout
        self.copies: list[tuple[str, str]] = []

    def __call__(self, args, env=None, cwd=None) -> subprocess.CompletedProcess[bytes]:
        copy = Path(args[args.index("-f") + 1])
        text = copy.read_text(encoding="utf-8")
        self.copies.append((copy.name, text))
        decrypted = re.sub(
            r"'encrypted:([A-Za-z0-9+/=]*)'",
            lambda found: "'" + base64.b64decode(found.group(1)).decode() + "'",
            text,
        )
        stderr = re.sub(
            r"\{(\d+)\}", lambda m: re.findall(r"^(\S+?)='", text, re.M)[int(m[1])], self.stderr
        )
        stdout = self.stdout if self.stdout is not None else (decrypted + "\n").encode()
        return subprocess.CompletedProcess(args, self.returncode, stdout, stderr.encode())


def _wrapper(dotenvx: _StandInDotenvx) -> DotenvxWrapper:
    wrapper = DotenvxWrapper(auto_install=False)
    wrapper._run_raw = dotenvx  # type: ignore[method-assign]
    return wrapper


class TestCiphertextValues:
    """``ciphertext_values`` finds each value dotenvx decrypts, inside its quotes."""

    def test_every_quote_style_and_layout(self) -> None:
        ct = _ct("x")
        text = (
            f"A={ct}\n"
            f'B="{ct}"\n'
            f"C='{ct}'\n"
            f"D=`{ct}`\n"
            f"export E = {ct} # note\n"
            f"F={ct}#tail\n"
            f'DOTENV_PUBLIC_KEY="{_PUBLIC_KEY}"\n'
            "PLAIN=value\n"
            "EMPTY=\n"
            "COMMENTED=#note\n"
        )

        values = ciphertext_values(text)

        assert [value.name for value in values] == ["A", "B", "C", "D", "E", "F"]
        assert all(text[value.start : value.end] == ct == value.ciphertext for value in values)

    def test_a_line_inside_a_quoted_value_is_not_a_value(self) -> None:
        text = f'CERT="-----BEGIN\nKEY={_ct("x")}\n-----END"\n'

        assert ciphertext_values(text) == []


class TestStandInValues:
    """Reading the plaintexts back from what dotenvx printed."""

    def test_plaintexts_may_hold_quotes_and_line_breaks(self) -> None:
        output = b"X=\"1\"\nSTAND_0='it's\nline two'\nSTAND_1=''\n# STAND_END\n\n"

        assert _stand_in_values(output, "STAND_", 2) == ["it's\nline two", ""]

    @pytest.mark.parametrize(
        "output",
        [b"", b"STAND_0='a'\n", b"STAND_1='b'\n# STAND_END\n", b"\xff\xfe"],
        ids=["empty", "no-end-marker", "first-missing", "not-utf8"],
    )
    def test_missing_or_garbled_output_is_none(self, output: bytes) -> None:
        assert _stand_in_values(output, "STAND_", 2 if b"STAND_1" in output else 1) is None

    def test_plaintexts_replace_only_the_ciphertext(self) -> None:
        text = 'A=encrypted:x # c\nB="encrypted:yy"\n'
        values = [CiphertextValue("A", 2, 13, "encrypted:x"), CiphertextValue("B", 21, 33, "")]

        assert _with_plaintexts(text, values, ["$one", "two"]) == 'A=$one # c\nB="two"\n'


class TestDecrypt:
    """``DotenvxWrapper.decrypt`` with the stand-in dotenvx."""

    def test_values_come_back_exactly_and_other_lines_stay(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env.staging"
        env_file.write_bytes(
            (
                f'DOTENV_PUBLIC_KEY_STAGING="{_PUBLIC_KEY}"\r\n'
                f"DB_PASSWORD={_ct(_PASSWORD)}\r\n"
                f'QUOTED="{_ct("a$(b)c")}"\r\n'
                "PLAIN_REF=http://${HOST}/x\r\n"
                "SPACED = kept\r\n"
            ).encode()
        )
        dotenvx = _StandInDotenvx()

        _wrapper(dotenvx).decrypt(env_file)

        assert env_file.read_text(encoding="utf-8") == (
            f'DOTENV_PUBLIC_KEY_STAGING="{_PUBLIC_KEY}"\n'
            f"DB_PASSWORD={_PASSWORD}\n"
            'QUOTED="a$(b)c"\n'
            "PLAIN_REF=http://${HOST}/x\n"
            "SPACED = kept\n"
        )
        # dotenvx saw only the public key and the single-quoted ciphertext, under
        # stand-in names, in a copy that keeps the file's name.
        [(name, copy)] = dotenvx.copies
        assert name == ".env.staging"
        lines = copy.splitlines()
        assert lines[0] == f'DOTENV_PUBLIC_KEY_STAGING="{_PUBLIC_KEY}"'
        assert re.fullmatch(r"ENVDRIFT_[0-9a-f]{16}_0='encrypted:[^']+'", lines[1])
        assert re.fullmatch(r"ENVDRIFT_[0-9a-f]{16}_1='encrypted:[^']+'", lines[2])
        assert re.fullmatch(r"# ENVDRIFT_[0-9a-f]{16}_END", lines[3])
        assert len(lines) == 4 and "HOST" not in copy and "DB_PASSWORD" not in copy

    def test_a_file_without_ciphertext_is_left_byte_for_byte(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_bytes(b"A=$plain\r\n")
        dotenvx = _StandInDotenvx()

        _wrapper(dotenvx).decrypt(env_file)

        assert env_file.read_bytes() == b"A=$plain\r\n"
        assert dotenvx.copies == []

    def test_a_failure_names_the_real_key_and_changes_nothing(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env.production"
        content = f"JWT={_ct('a')}\nSTRIPE_API_KEY={_ct('b')}\n"
        env_file.write_text(content, encoding="utf-8")
        dotenvx = _StandInDotenvx(returncode=1, stderr="[DECRYPTION_FAILED] could not decrypt {1}")

        with pytest.raises(DotenvxError, match="could not decrypt STRIPE_API_KEY"):
            _wrapper(dotenvx).decrypt(env_file)

        assert env_file.read_text(encoding="utf-8") == content

    def test_unreadable_output_changes_nothing(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        content = f"A={_ct('a')}\n"
        env_file.write_text(content, encoding="utf-8")

        with pytest.raises(DotenvxError, match="did not hold every decrypted value"):
            _wrapper(_StandInDotenvx(stdout=b"nothing useful\n")).decrypt(env_file)

        assert env_file.read_text(encoding="utf-8") == content

    def test_a_non_utf8_file_is_refused_untouched(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_bytes(b"A=" + _ct("a").encode() + b"\nB=\xff\n")
        before = env_file.read_bytes()

        with pytest.raises(DotenvxError, match="not valid UTF-8"):
            _wrapper(_StandInDotenvx()).decrypt(env_file)

        assert env_file.read_bytes() == before

    def test_a_directory_is_refused(self, tmp_path: Path) -> None:
        folder = tmp_path / ".env"
        folder.mkdir()

        with pytest.raises(DotenvxError, match="Cannot read"):
            _wrapper(_StandInDotenvx()).decrypt(folder)

    def test_a_failed_write_changes_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env_file = tmp_path / ".env"
        content = f"A={_ct('a')}\n"
        env_file.write_text(content, encoding="utf-8")

        def _disk_full(_path: Path, _data: bytes) -> None:
            raise OSError(errno.ENOSPC, "No space left on device")

        monkeypatch.setattr("envdrift.integrations.dotenvx._replace_file", _disk_full)

        with pytest.raises(DotenvxError, match="Cannot write the decrypted values"):
            _wrapper(_StandInDotenvx()).decrypt(env_file)

        assert env_file.read_text(encoding="utf-8") == content

    @pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
    def test_a_symlinked_file_is_written_through_the_link(self, tmp_path: Path) -> None:
        target = tmp_path / "real.env"
        target.write_text(f"A={_ct('a')}\n", encoding="utf-8")
        link = tmp_path / ".env"
        try:
            link.symlink_to(target)
        except OSError:
            pytest.skip("symlinks are not permitted here")

        _wrapper(_StandInDotenvx()).decrypt(link)

        assert link.is_symlink()
        assert target.read_text(encoding="utf-8") == "A=a\n"


class TestRunRaw:
    """``_run_raw`` reports a hung or missing binary like ``_run``."""

    def _wrapper(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: Exception):
        binary = tmp_path / "dotenvx"
        binary.touch()
        wrapper = DotenvxWrapper(auto_install=False)
        wrapper._binary_path = binary

        def _raise(*_args, **_kwargs):
            raise error

        monkeypatch.setattr(subprocess, "run", _raise)
        return wrapper

    def test_timeout(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        wrapper = self._wrapper(tmp_path, monkeypatch, subprocess.TimeoutExpired("dotenvx", 120))

        with pytest.raises(DotenvxError, match="timed out"):
            wrapper._run_raw(["decrypt"], env=None, cwd=None)

    def test_binary_vanished(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        wrapper = self._wrapper(tmp_path, monkeypatch, FileNotFoundError("dotenvx"))

        with pytest.raises(DotenvxNotFoundError):
            wrapper._run_raw(["decrypt"], env=None, cwd=tmp_path)
