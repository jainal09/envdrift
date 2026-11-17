"""``diff`` compares every key python-dotenv loads, and ``--strict`` compares raw text (#954).

1. ``diff`` parsed in strict mode, which drops keys such as ``X-API-KEY`` and
   ``2FA_ENABLED`` that python-dotenv loads, and never said so: files that differed
   in only those keys reported "No drift detected" and exited 0 under ``--ci``. A
   multi-line value under such a key went further wrong: its inner lines were read
   as phantom variables.
2. ``--strict`` is documented as a raw string compare, yet ``${VAR}`` references were
   expanded from envdrift's own environment, so two different unresolved references
   compared equal, and a set variable's value was printed.

Every test runs the real ``envdrift diff`` CLI as a subprocess.
"""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration]

# Built by concatenation so push protection never sees a whole secret literal.
_STAGING_VALUE = "sk_" + "test_" + "staging123"
_PROD_VALUE = "sk_" + "live_" + "prod456"


_Run = Callable[..., "subprocess.CompletedProcess[str]"]


@pytest.fixture
def run_diff(tmp_path: Path, integration_pythonpath: str, envdrift_cmd: list[str]) -> _Run:
    """The real ``envdrift diff`` as a subprocess, run in ``tmp_path`` without stray STRIPE refs."""

    def run(
        args: list[str], *, extra_env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        env = {k: v for k, v in os.environ.items() if not k.endswith("_STRIPE_KEY")}
        env["PYTHONPATH"] = integration_pythonpath
        env.update(extra_env or {})
        return subprocess.run(
            [*envdrift_cmd, "diff", *args],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

    return run


def _flat(result: subprocess.CompletedProcess[str]) -> str:
    """stdout+stderr with whitespace collapsed, so wrapping cannot split a phrase."""
    return " ".join((result.stdout + result.stderr).split())


def _changed(result: subprocess.CompletedProcess[str]) -> dict[str, tuple[str, str]]:
    """The changed variables of a ``--format json`` run, with both values."""
    data = json.loads(result.stdout)
    return {
        d["name"]: (d["value_env1"], d["value_env2"])
        for d in data["differences"]
        if d["type"] == "changed"
    }


class TestDiffComparesKeysTheStrictParserDropped:
    """#954.1: non-identifier keys are compared, not silently dropped."""

    @pytest.mark.parametrize("mode", [[], ["--strict"]], ids=["normalize", "strict"])
    def test_non_identifier_keys_that_differ_are_drift(
        self,
        tmp_path: Path,
        run_diff: _Run,
        mode: list[str],
    ) -> None:
        (tmp_path / ".env.dev").write_text(
            "APP_NAME=shop\nX-API-KEY=dev-key\n2FA_ENABLED=false\n", encoding="utf-8"
        )
        (tmp_path / ".env.prod").write_text(
            "APP_NAME=shop\nX-API-KEY=prod-key\n2FA_ENABLED=true\n", encoding="utf-8"
        )

        table = run_diff([".env.dev", ".env.prod", "--ci", *mode])
        as_json = run_diff([".env.dev", ".env.prod", "--format", "json", *mode])

        assert table.returncode == 1, _flat(table)
        assert "No drift detected" not in _flat(table)
        assert as_json.returncode == 0, _flat(as_json)
        assert _changed(as_json) == {
            "X-API-KEY": ("dev-key", "prod-key"),
            "2FA_ENABLED": ("false", "true"),
        }

    def test_multiline_value_under_a_non_identifier_key_is_one_variable(
        self, tmp_path: Path, run_diff: _Run
    ) -> None:
        (tmp_path / ".env.dev").write_text(
            'X-CERT="-----BEGIN-----\ndGVzdA==\n-----END-----"\n', encoding="utf-8"
        )
        (tmp_path / ".env.prod").write_text(
            'X-CERT="-----BEGIN-----\nb3RoZXI=\n-----END-----"\n', encoding="utf-8"
        )

        result = run_diff([".env.dev", ".env.prod", "--format", "json"])

        names = [d["name"] for d in json.loads(result.stdout)["differences"]]
        assert names == ["X-CERT"], _flat(result)

    @pytest.mark.parametrize("fmt", ["table", "json"])
    def test_lines_no_parser_reads_are_named(
        self, tmp_path: Path, run_diff: _Run, fmt: str
    ) -> None:
        (tmp_path / ".env.dev").write_text('APP=shop\nBROKEN="a"junk\n', encoding="utf-8")
        (tmp_path / ".env.prod").write_text("APP=shop\n", encoding="utf-8")

        result = run_diff([".env.dev", ".env.prod", "--format", fmt])

        assert result.returncode == 0, _flat(result)
        warning = "Could not parse non-comment content on .env.dev line(s) 2"
        if fmt == "json":
            json.loads(result.stdout)  # the warning stays off stdout
            assert warning in " ".join(result.stderr.split())
        else:
            assert warning in _flat(result)


class TestStrictComparesRawText:
    """#954.2: ``--strict`` never expands ``${VAR}`` references."""

    def test_different_unresolved_references_are_drift(
        self, tmp_path: Path, run_diff: _Run
    ) -> None:
        (tmp_path / ".env.staging").write_text(
            "STRIPE_KEY=${STAGING_STRIPE_KEY}\n", encoding="utf-8"
        )
        (tmp_path / ".env.production").write_text(
            "STRIPE_KEY=${PROD_STRIPE_KEY}\n", encoding="utf-8"
        )

        result = run_diff([".env.staging", ".env.production", "--strict", "--ci"])

        output = _flat(result)
        assert result.returncode == 1, output
        assert "No drift detected" not in output
        assert "STRIPE_KEY" in output

    def test_set_variables_are_neither_compared_nor_printed(
        self, tmp_path: Path, run_diff: _Run
    ) -> None:
        (tmp_path / ".env.staging").write_text(
            "STRIPE_KEY=${STAGING_STRIPE_KEY}\n", encoding="utf-8"
        )
        (tmp_path / ".env.production").write_text(
            "STRIPE_KEY=${PROD_STRIPE_KEY}\n", encoding="utf-8"
        )

        result = run_diff(
            [".env.staging", ".env.production", "--strict", "--format", "json"],
            extra_env={"STAGING_STRIPE_KEY": _STAGING_VALUE, "PROD_STRIPE_KEY": _PROD_VALUE},
        )

        assert result.returncode == 0, _flat(result)
        assert _STAGING_VALUE not in result.stdout and _PROD_VALUE not in result.stdout
        assert _changed(result) == {
            "STRIPE_KEY": ("${STAGING_STRIPE_KEY}", "${PROD_STRIPE_KEY}"),
        }
