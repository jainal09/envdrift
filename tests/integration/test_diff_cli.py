"""Diff CLI End-to-End Integration Tests.

Real e2e coverage for ``envdrift diff`` over real ``.env`` files, exercising the
JSON output contract, sensitive-value masking via ``--schema``, value
normalization (whitespace / bool-alias / JSON-quote style), ``--strict`` raw
compare, schema-driven type coercion, ``--include-unchanged`` and a handful of
adversarial / unicode / duplicate-key edge cases.

Every test runs the real CLI as a subprocess (``python -m envdrift.cli diff``)
against files written to ``tmp_path`` — no mocks, no containers. ``sys.executable``
is the project venv interpreter (with all deps), and ``PYTHONPATH`` points at the
``src`` tree so the under-development package is imported.

Requires: pydantic-settings installed (provided by the project venv).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

# Mark all tests in this module
pytestmark = [pytest.mark.integration]


# --- Local helpers (kept here so conftest.py is never modified) ---


def _run_diff(
    args: list[str],
    cwd: Path,
    integration_pythonpath: str,
    timeout: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    """Run ``envdrift diff`` as a real subprocess and return the completed process.

    Mirrors the invocation style used by the other integration tests: the project
    venv interpreter (``sys.executable``) with ``PYTHONPATH`` set to the ``src``
    tree, so the real CLI and its dependencies are loaded.
    """
    env = os.environ.copy()
    env["PYTHONPATH"] = integration_pythonpath
    return subprocess.run(
        [sys.executable, "-m", "envdrift.cli", "diff", *args],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _run_diff_json(
    args: list[str],
    cwd: Path,
    integration_pythonpath: str,
    timeout: float = 30.0,
) -> tuple[subprocess.CompletedProcess[str], dict]:
    """Run ``envdrift diff --format json`` and return (process, parsed-json)."""
    result = _run_diff([*args, "--format", "json"], cwd, integration_pythonpath, timeout)
    assert result.returncode == 0, (
        f"diff exited {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    payload = json.loads(result.stdout)
    return result, payload


def _by_name(payload: dict, name: str) -> dict | None:
    """Return the single difference entry with the given variable name, or None."""
    matches = [d for d in payload["differences"] if d["name"] == name]
    assert len(matches) <= 1, f"unexpected duplicate diff entries for {name!r}: {matches}"
    return matches[0] if matches else None


_SCHEMA_MODULE = textwrap.dedent('''
    """Test schema for diff CLI integration tests."""
    from typing import Any

    from pydantic import Field
    from pydantic_settings import BaseSettings


    class Settings(BaseSettings):
        API_KEY: str = Field(default="", json_schema_extra={"sensitive": True})
        PUBLIC_URL: str = ""
        DEBUG: bool = False
        NUMS: list[int] = []
        DATA: Any = None

        model_config = {"extra": "ignore"}
''')


def _write_schema(tmp_path: Path) -> None:
    """Write the shared Pydantic Settings schema module into ``tmp_path``."""
    (tmp_path / "settings.py").write_text(_SCHEMA_MODULE)


# --- Tests ---


def test_diff_json_format_structure(tmp_path: Path, integration_pythonpath: str) -> None:
    """HP-09: ``--format json`` emits a valid, well-shaped JSON document."""
    (tmp_path / ".env.a").write_text("X=1\n")
    (tmp_path / ".env.b").write_text("X=2\n")

    _, payload = _run_diff_json([".env.a", ".env.b"], tmp_path, integration_pythonpath)

    # Top-level contract.
    assert set(payload) == {"env1", "env2", "summary", "differences"}
    assert payload["env1"] == ".env.a"
    assert payload["env2"] == ".env.b"

    summary = payload["summary"]
    assert set(summary) == {"added", "removed", "changed", "has_drift"}
    assert summary["added"] == 0
    assert summary["removed"] == 0
    assert summary["changed"] == 1
    assert summary["has_drift"] is True

    entry = _by_name(payload, "X")
    assert entry is not None
    assert entry["type"] == "changed"
    assert entry["value_env1"] == "1"
    assert entry["value_env2"] == "2"
    assert entry["sensitive"] is False


def test_diff_exit_on_drift_contract(tmp_path: Path, integration_pythonpath: str) -> None:
    """The real CLI gates drift only when requested and still emits parseable JSON."""
    (tmp_path / ".env.a").write_text("X=1\n")
    (tmp_path / ".env.b").write_text("X=2\n")

    default = _run_diff([".env.a", ".env.b"], tmp_path, integration_pythonpath)
    assert default.returncode == 0
    assert "Drift detected" in default.stdout

    for flag in ("--exit-on-drift", "--ci"):
        gated = _run_diff(
            [".env.a", ".env.b", "--format", "json", flag],
            tmp_path,
            integration_pythonpath,
        )
        assert gated.returncode == 1
        assert json.loads(gated.stdout)["summary"]["has_drift"] is True

    matching = _run_diff(
        [".env.a", ".env.a", "--exit-on-drift"],
        tmp_path,
        integration_pythonpath,
    )
    assert matching.returncode == 0
    assert "No drift" in matching.stdout


def test_diff_mask_values_via_schema(tmp_path: Path, integration_pythonpath: str) -> None:
    """HP-08: ``--schema`` marking API_KEY sensitive masks its values; PUBLIC_URL stays plaintext."""
    _write_schema(tmp_path)
    (tmp_path / "a.env").write_text("API_KEY=secret-a\nPUBLIC_URL=http://a\n")
    (tmp_path / "b.env").write_text("API_KEY=secret-b\nPUBLIC_URL=http://b\n")

    _, payload = _run_diff_json(
        ["a.env", "b.env", "--schema", "settings:Settings", "--service-dir", str(tmp_path)],
        tmp_path,
        integration_pythonpath,
    )

    api_key = _by_name(payload, "API_KEY")
    assert api_key is not None
    assert api_key["sensitive"] is True
    assert api_key["value_env1"] == "********"
    assert api_key["value_env2"] == "********"

    public_url = _by_name(payload, "PUBLIC_URL")
    assert public_url is not None
    assert public_url["sensitive"] is False
    assert public_url["value_env1"] == "http://a"
    assert public_url["value_env2"] == "http://b"


def test_diff_normalization_default_treats_equivalent_values_equal(
    tmp_path: Path, integration_pythonpath: str
) -> None:
    """HP-13: default ``--normalize`` treats bool-casing and JSON quote-style diffs as equal."""
    (tmp_path / "n1.env").write_text('B=true\nC=["x","y"]\n')
    (tmp_path / "n2.env").write_text("B=True\nC=['x', 'y']\n")

    _, payload = _run_diff_json(["n1.env", "n2.env"], tmp_path, integration_pythonpath)

    assert payload["summary"]["has_drift"] is False
    assert payload["differences"] == []


def test_diff_strict_disables_normalization(tmp_path: Path, integration_pythonpath: str) -> None:
    """EC-14: ``--strict`` disables normalization; masking is independent of ``--strict``."""
    _write_schema(tmp_path)
    # DEBUG differs only by bool casing; C differs only by quote style — both equal under
    # normalize, both CHANGED under --strict. API_KEY differs and must stay masked.
    (tmp_path / "s1.env").write_text('API_KEY=secret-a\nDEBUG=1\nC=["x","y"]\n')
    (tmp_path / "s2.env").write_text("API_KEY=secret-a\nDEBUG=true\nC=['x', 'y']\n")

    _, payload = _run_diff_json(
        [
            "s1.env",
            "s2.env",
            "--schema",
            "settings:Settings",
            "--service-dir",
            str(tmp_path),
            "--strict",
        ],
        tmp_path,
        integration_pythonpath,
    )

    # Only the two raw-string differences (DEBUG, C) count as changed; API_KEY is
    # identical so it is unchanged (and omitted from the default output).
    assert payload["summary"]["changed"] == 2

    debug = _by_name(payload, "DEBUG")
    assert debug is not None
    assert debug["type"] == "changed"
    assert debug["value_env1"] == "1"
    assert debug["value_env2"] == "true"

    # API_KEY is identical here, so to prove masking is still active under --strict we
    # additionally diff differing secret values and confirm the mask.
    (tmp_path / "s3.env").write_text("API_KEY=secret-b\n")
    _, masked = _run_diff_json(
        [
            "s1.env",
            "s3.env",
            "--schema",
            "settings:Settings",
            "--service-dir",
            str(tmp_path),
            "--strict",
        ],
        tmp_path,
        integration_pythonpath,
    )
    api_key = _by_name(masked, "API_KEY")
    assert api_key is not None
    assert api_key["sensitive"] is True
    assert api_key["value_env1"] == "********"
    assert api_key["value_env2"] == "********"


def test_diff_schema_coercion_makes_bool_equal(tmp_path: Path, integration_pythonpath: str) -> None:
    """HP-14: with ``--schema`` (DEBUG: bool), DEBUG=1 and DEBUG=true coerce equal."""
    _write_schema(tmp_path)
    (tmp_path / "c1.env").write_text("DEBUG=1\n")
    (tmp_path / "c2.env").write_text("DEBUG=true\n")

    _, payload = _run_diff_json(
        ["c1.env", "c2.env", "--schema", "settings:Settings", "--service-dir", str(tmp_path)],
        tmp_path,
        integration_pythonpath,
    )

    assert payload["summary"]["has_drift"] is False
    assert _by_name(payload, "DEBUG") is None


def test_diff_include_unchanged_emits_unchanged_entries(
    tmp_path: Path, integration_pythonpath: str
) -> None:
    """HP-20: ``--include-unchanged`` emits UNCHANGED entries alongside CHANGED ones."""
    (tmp_path / "iu1.env").write_text("X=1\nY=same\n")
    (tmp_path / "iu2.env").write_text("X=2\nY=same\n")

    _, payload = _run_diff_json(
        ["iu1.env", "iu2.env", "--include-unchanged"], tmp_path, integration_pythonpath
    )

    changed = _by_name(payload, "X")
    assert changed is not None
    assert changed["type"] == "changed"

    unchanged = _by_name(payload, "Y")
    assert unchanged is not None
    assert unchanged["type"] == "unchanged"
    assert unchanged["value_env1"] == "same"
    assert unchanged["value_env2"] == "same"


def test_diff_bool_aliases_equal_and_opposites_differ(
    tmp_path: Path, integration_pythonpath: str
) -> None:
    """EC-16: yes/on/true normalize equal; false vs true report drift."""
    # Equal case: yes vs on.
    (tmp_path / "ba1.env").write_text("FLAG=yes\n")
    (tmp_path / "ba2.env").write_text("FLAG=on\n")
    _, equal = _run_diff_json(["ba1.env", "ba2.env"], tmp_path, integration_pythonpath)
    assert equal["summary"]["has_drift"] is False
    assert equal["differences"] == []

    # Opposite case: false vs true.
    (tmp_path / "bo1.env").write_text("FLAG=false\n")
    (tmp_path / "bo2.env").write_text("FLAG=true\n")
    _, opposite = _run_diff_json(["bo1.env", "bo2.env"], tmp_path, integration_pythonpath)
    assert opposite["summary"]["has_drift"] is True
    flag = _by_name(opposite, "FLAG")
    assert flag is not None
    assert flag["type"] == "changed"
    assert flag["value_env1"] == "false"
    assert flag["value_env2"] == "true"


def test_diff_json_list_order_reports_drift_with_schema(
    tmp_path: Path, integration_pythonpath: str
) -> None:
    """EC-23: a reordered JSON list (NUMS: list[int]) reports drift — order is significant."""
    _write_schema(tmp_path)
    (tmp_path / "l1.env").write_text("NUMS=[1,2,3]\n")
    (tmp_path / "l2.env").write_text("NUMS=[3,2,1]\n")

    _, payload = _run_diff_json(
        ["l1.env", "l2.env", "--schema", "settings:Settings", "--service-dir", str(tmp_path)],
        tmp_path,
        integration_pythonpath,
    )

    assert payload["summary"]["has_drift"] is True
    nums = _by_name(payload, "NUMS")
    assert nums is not None
    assert nums["type"] == "changed"


def test_diff_adversarial_json_value_cannot_crash(
    tmp_path: Path, integration_pythonpath: str
) -> None:
    """XC-02: a deeply-nested adversarial JSON value cannot crash diff (loose-parse is guarded)."""
    depth = 2000
    (tmp_path / "adv1.env").write_text("DATA=" + ("[" * depth) + ("]" * depth) + "\n")
    (tmp_path / "adv2.env").write_text("DATA=" + ("[" * depth) + "1" + ("]" * depth) + "\n")

    result, payload = _run_diff_json(["adv1.env", "adv2.env"], tmp_path, integration_pythonpath)

    assert result.returncode == 0
    assert "Traceback" not in result.stderr
    # Loose-parse bails on the adversarial input and falls back to raw string compare,
    # which differ, so DATA is reported as changed rather than crashing.
    data = _by_name(payload, "DATA")
    assert data is not None
    assert data["type"] == "changed"


def test_diff_unicode_values_survive(tmp_path: Path, integration_pythonpath: str) -> None:
    """XC-06: unicode values round-trip through diff JSON without mojibake."""
    original = "héllo-wörld-日本語-😀"
    changed = "changed-héllo"
    (tmp_path / "u1.env").write_text(f"GREETING={original}\n", encoding="utf-8")
    (tmp_path / "u2.env").write_text(f"GREETING={changed}\n", encoding="utf-8")

    _, payload = _run_diff_json(["u1.env", "u2.env"], tmp_path, integration_pythonpath)

    greeting = _by_name(payload, "GREETING")
    assert greeting is not None
    assert greeting["type"] == "changed"
    assert greeting["value_env1"] == original
    assert greeting["value_env2"] == changed


def test_diff_duplicate_keys_last_wins(tmp_path: Path, integration_pythonpath: str) -> None:
    """EC-05: duplicate keys resolve last-one-wins; observable as no drift vs the single value."""
    (tmp_path / "dup1.env").write_text("DUP=first\nDUP=second\n")
    (tmp_path / "dup2.env").write_text("DUP=second\n")

    _, payload = _run_diff_json(["dup1.env", "dup2.env"], tmp_path, integration_pythonpath)

    assert payload["summary"]["has_drift"] is False
    assert payload["differences"] == []


def test_diff_json_no_ansi_under_force_color(tmp_path: Path, integration_pythonpath: str) -> None:
    """#333: `diff --format json` stays valid JSON with no ESC bytes even when FORCE_COLOR=1.

    The autouse `_deterministic_cli_output` fixture strips FORCE_COLOR from the
    parent env, so we re-set it on the child explicitly to reproduce the CI
    condition that surfaced the bug (FORCE_COLOR overrides NO_COLOR in Rich).
    """
    (tmp_path / ".env.a").write_text("X=1\n")
    (tmp_path / ".env.b").write_text("X=2\n")

    env = os.environ.copy()
    env["PYTHONPATH"] = integration_pythonpath
    env["FORCE_COLOR"] = "1"
    env.pop("NO_COLOR", None)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "envdrift.cli",
            "diff",
            ".env.a",
            ".env.b",
            "--format",
            "json",
        ],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=30.0,
    )

    assert result.returncode == 0, f"stderr:\n{result.stderr}"
    assert "\x1b" not in result.stdout, "JSON output contained ANSI escape bytes"
    payload = json.loads(result.stdout)
    assert payload["summary"]["changed"] == 1
    assert payload["summary"]["has_drift"] is True


def test_diff_json_schema_warning_stays_off_stdout(
    tmp_path: Path, integration_pythonpath: str
) -> None:
    """#413: a schema-load failure in `--format json` must not pollute stdout.

    The documented CI recipe is `diff ... --format json > drift.json` then
    `JSON.parse(...)`. A leading `[WARN] Could not load schema: ...` line on
    stdout breaks that parse. The warning belongs on stderr.
    """
    (tmp_path / ".env.a").write_text("X=1\n")
    (tmp_path / ".env.b").write_text("X=2\n")

    result = _run_diff(
        [".env.a", ".env.b", "--schema", "nonexistent.module:Settings", "--format", "json"],
        tmp_path,
        integration_pythonpath,
    )

    assert result.returncode == 0, f"stderr:\n{result.stderr}"
    # stdout is pure, parseable JSON with no warning text leaking in.
    assert "WARN" not in result.stdout
    assert "Could not load schema" not in result.stdout
    payload = json.loads(result.stdout)
    assert payload["summary"]["changed"] == 1
    # The warning is still surfaced — on stderr.
    assert "Could not load schema" in result.stderr


def test_diff_format_uppercase_json_accepted(tmp_path: Path, integration_pythonpath: str) -> None:
    """#413: `--format JSON` (uppercase) is lowercased and produces JSON, not a table."""
    (tmp_path / ".env.a").write_text("X=1\n")
    (tmp_path / ".env.b").write_text("X=2\n")

    result = _run_diff([".env.a", ".env.b", "--format", "JSON"], tmp_path, integration_pythonpath)

    assert result.returncode == 0, f"stderr:\n{result.stderr}"
    payload = json.loads(result.stdout)
    assert payload["summary"]["changed"] == 1


def test_diff_format_unknown_value_exits_1(tmp_path: Path, integration_pythonpath: str) -> None:
    """#413: an unknown `--format` value exits 1 instead of silently rendering a table."""
    (tmp_path / ".env.a").write_text("X=1\n")
    (tmp_path / ".env.b").write_text("X=2\n")

    result = _run_diff([".env.a", ".env.b", "--format", "bogus"], tmp_path, integration_pythonpath)

    assert result.returncode == 1
    combined = result.stdout + result.stderr
    assert "Invalid --format" in combined
    assert "bogus" in combined


class TestDiffRobustErrors:
    """#443: hostile inputs fail cleanly (no traceback), and ``--format json``
    stays pure parseable JSON with no ANSI even on the error path."""

    @staticmethod
    def _env(tmp_path: Path) -> Path:
        f = tmp_path / "a.env"
        f.write_text("A=1\n", encoding="utf-8")
        return f

    def test_directory_argument_errors_cleanly(self, tmp_path, integration_pythonpath):
        a = self._env(tmp_path)
        d = tmp_path / "adir"
        d.mkdir()
        result = _run_diff([str(a), str(d)], tmp_path, integration_pythonpath)
        assert result.returncode == 1
        assert "Traceback" not in result.stderr
        assert "Not a file" in result.stdout

    def test_binary_file_errors_cleanly(self, tmp_path, integration_pythonpath):
        a = self._env(tmp_path)
        b = tmp_path / "bin.env"
        b.write_bytes(bytes(range(256)))  # includes NUL + non-UTF-8 bytes
        result = _run_diff([str(a), str(b)], tmp_path, integration_pythonpath)
        assert result.returncode == 1
        assert "Traceback" not in result.stderr
        assert "UTF-8" in result.stdout

    def test_json_error_path_is_clean_json(self, tmp_path, integration_pythonpath):
        a = self._env(tmp_path)
        result = _run_diff(
            [str(a), str(tmp_path / "missing.env"), "--format", "json"],
            tmp_path,
            integration_pythonpath,
        )
        assert result.returncode == 1
        assert "Traceback" not in result.stderr
        # stdout must be a single parseable JSON object, not Rich prose.
        payload = json.loads(result.stdout)
        assert "error" in payload

    def test_json_error_has_no_ansi_under_force_color(self, tmp_path, integration_pythonpath):
        """Even with FORCE_COLOR=1, json error output carries no ANSI escapes."""
        a = self._env(tmp_path)
        b = tmp_path / "bin.env"
        b.write_bytes(bytes(range(256)))
        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath
        env["FORCE_COLOR"] = "1"
        env.pop("NO_COLOR", None)
        result = subprocess.run(
            [sys.executable, "-m", "envdrift.cli", "diff", str(a), str(b), "--format", "json"],
            cwd=str(tmp_path),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 1
        assert "\x1b" not in result.stdout, (
            f"ANSI escape leaked into json stdout: {result.stdout!r}"
        )
        json.loads(result.stdout)  # still parseable
