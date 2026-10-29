"""envdrift and the real scanners agree on line numbers after a form feed (#937).

git and the external scanners count only line breaks; envdrift also broke lines at a form feed.
So the native scanner put a finding a line lower than gitleaks, an inline ignore comment did not
suppress gitleaks' finding, the encrypted-line check dropped gitleaks' finding of a plaintext
secret, and envdrift could not read back the value trivy redacts. Each test runs the real CLI or
the real binary, and is skipped where the binary is not installed.

Secret-shaped values are built by concatenation, so no realistic literal is in the repository.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from envdrift.scanner.gitleaks import GitleaksScanner
from envdrift.scanner.patterns import hash_secret
from envdrift.scanner.trivy import TrivyScanner

pytestmark = [pytest.mark.integration]

REPO_ROOT = Path(__file__).resolve().parents[2]
AWS_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLX"
DOTENVX_CIPHERTEXT = (
    "encrypted:BEj2"
    + "Zq9yKxw0Lr3VtP8sN1mD5cH7aG4fU6eB2oI9kJ3lQ0wR5tY8uA1sD4fG7hJ0kL3zX6cV9bN2mQ5wE8rT1yU4iO7p"
    + "A0sD3fG6hJ9kL2zX5cV8bN1mQ4w=="
)

requires_gitleaks = pytest.mark.skipif(
    not GitleaksScanner(auto_install=False).is_installed(), reason="gitleaks is not installed"
)
requires_trivy = pytest.mark.skipif(
    not TrivyScanner(auto_install=False).is_installed(), reason="trivy is not installed"
)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not available")
    subprocess.run([git, "init", "-q", str(tmp_path)], check=True, capture_output=True)
    return tmp_path


def _write(path: Path, text: str) -> Path:
    path.write_bytes(text.encode("utf-8"))
    return path


def _guard(repo: Path, target: str) -> tuple[int, list[tuple[str, int]]]:
    """Run ``guard`` with native and gitleaks; return its exit code and (scanner, line) pairs."""
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{REPO_ROOT / 'src'}{os.pathsep}{env.get('PYTHONPATH', '')}"
    result = subprocess.run(
        [sys.executable, "-m", "envdrift.cli", "guard", "--gitleaks", "--no-trufflehog"]
        + ["--json", target],
        cwd=str(repo),
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )
    findings = json.loads(result.stdout)["findings"]
    return result.returncode, sorted((f["scanner"], f["line_number"]) for f in findings)


@requires_gitleaks
def test_native_and_gitleaks_put_a_finding_on_the_same_line(repo: Path):
    _write(repo / "app.py", f'import os\n\f\nAWS_ACCESS_KEY_ID = "{AWS_KEY}"\n')

    exit_code, located = _guard(repo, "app.py")

    assert exit_code == 1
    assert located == [("gitleaks", 3), ("native", 3)]


@requires_gitleaks
def test_an_ignore_comment_after_a_form_feed_suppresses_gitleaks_too(repo: Path):
    _write(repo / "app.py", f'import os\n\f\nAWS_ACCESS_KEY_ID = "{AWS_KEY}"  # envdrift:ignore\n')

    assert _guard(repo, "app.py") == (0, [])


@requires_gitleaks
def test_gitleaks_finding_of_a_plaintext_secret_in_an_encrypted_file_is_kept(repo: Path):
    _write(
        repo / ".env",
        f'\f\nAPI_TOKEN="{DOTENVX_CIPHERTEXT}"\nAWS_ACCESS_KEY_ID={AWS_KEY}\n',
    )

    exit_code, located = _guard(repo, ".env")

    assert exit_code == 1
    assert located == [("gitleaks", 3), ("native", 3)]


@requires_gitleaks
@pytest.mark.parametrize("separator", ["\f", " "], ids=["form-feed", "space"])
def test_a_plaintext_key_after_an_encrypted_value_is_found(repo: Path, separator: str):
    """Only the ciphertext is skipped, not its line: both scanners report the key after it."""
    _write(
        repo / ".env", f'API_TOKEN="{DOTENVX_CIPHERTEXT}"{separator}AWS_ACCESS_KEY_ID={AWS_KEY}\n'
    )

    exit_code, located = _guard(repo, ".env")

    assert exit_code == 1
    assert located == [("gitleaks", 1), ("native", 1)]


@requires_trivy
def test_the_value_trivy_redacts_is_read_back_after_a_form_feed(tmp_path: Path):
    path = _write(tmp_path / "app.py", f'import os\n\f\nAWS_ACCESS_KEY_ID = "{AWS_KEY}"\n')

    result = TrivyScanner(auto_install=False).scan([path])

    assert result.error is None
    assert [(f.line_number, f.secret_hash) for f in result.findings] == [(3, hash_secret(AWS_KEY))]
