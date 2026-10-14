"""The severity of a credential decides the ``guard`` gate the same way in every scanner (#850).

The native scanner always runs, and it graded a JSON Web Token MEDIUM while gitleaks,
Infisical and detect-secrets grade it HIGH. A run without gitleaks (``--native-only``, or
``--no-gitleaks``) therefore passed a JWT at the default ``--fail-on high``, and a lowering of
the other scanners' grade would have let the default run pass it too. These drive the real
CLI over a real native scan; nothing is stubbed.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from envdrift.cli import app

runner = CliRunner()


def _jwt() -> str:
    """A JWT-shaped value (header, claims, signature) built at run time."""

    def part(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    claims = part(b'{"role":"service_role","iss":"supabase","iat":1516239022}')
    return part(b'{"alg":"HS256","typ":"JWT"}') + "." + claims + "." + "Zx9Kq2Wm7Lp4Rt8Nv6Bs3Yd"


@pytest.fixture
def jwt_project(tmp_path: Path) -> Path:
    (tmp_path / "config.py").write_text(f'SUPABASE_SERVICE_ROLE_KEY = "{_jwt()}"\n')
    return tmp_path


def _guard(path: Path, *args: str):
    return runner.invoke(app, ["guard", str(path), "--native-only", "--json", *args])


def test_a_jwt_found_by_the_native_scanner_is_high(jwt_project: Path):
    result = _guard(jwt_project)

    payload = json.loads(result.stdout)
    jwt = [f for f in payload["findings"] if f["rule_id"] == "jwt-token"]
    assert [f["severity"] for f in jwt] == ["high"], payload["findings"]


def test_the_default_ci_gate_blocks_a_jwt_the_native_scanner_found(jwt_project: Path):
    """``--fail-on`` defaults to high; a MEDIUM JWT passed it (exit 0)."""
    result = _guard(jwt_project, "--ci")

    assert result.exit_code == 2, result.output
    payload = json.loads(result.stdout)
    assert payload["exit_code"] == 2


def test_fail_on_critical_still_lets_a_jwt_through(jwt_project: Path):
    """A JWT is HIGH, not CRITICAL: only a threshold at or below HIGH blocks it."""
    result = _guard(jwt_project, "--ci", "--fail-on", "critical")

    assert result.exit_code == 0, result.output
