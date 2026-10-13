"""Integration tests for the detect-secrets scanner against the real package.

detect-secrets runs as ``python -m detect_secrets`` in envdrift's own
interpreter, so these tests skip unless the pinned package is importable there
(CI installs it from ``constants.json``). Findings come from real scans of real
files; nothing about the scanner is mocked.
"""

from __future__ import annotations

import importlib
import importlib.util
import pkgutil
import subprocess  # nosec B404
from pathlib import Path

import pytest

from envdrift.scanner.base import FindingSeverity
from envdrift.scanner.detect_secrets import DETECTOR_SEVERITY, DetectSecretsScanner

pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.skipif(
        importlib.util.find_spec("detect_secrets") is None,
        reason="detect-secrets not installed (pip install detect-secrets)",
    ),
]


def _emitted_secret_types() -> set[str]:
    """Return every ``secret_type`` the installed detect-secrets plugins emit."""
    plugins = importlib.import_module("detect_secrets.plugins")
    base = importlib.import_module("detect_secrets.plugins.base").BasePlugin
    emitted: set[str] = set()
    for module_info in pkgutil.iter_modules(plugins.__path__):
        module = importlib.import_module(f"detect_secrets.plugins.{module_info.name}")
        for obj in vars(module).values():
            if isinstance(obj, type) and issubclass(obj, base) and obj is not base:
                secret_type = getattr(obj, "secret_type", None)
                if isinstance(secret_type, str):
                    emitted.add(secret_type)
    return emitted


def test_every_severity_key_is_a_type_detect_secrets_emits():
    """A DETECTOR_SEVERITY key no plugin emits is dead: its findings fall back to HIGH.

    Four keys were dead this way ("Cloudant", "npm credentials", "OpenAI API
    Key", "PyPI upload token"). This catches a rename on the next version bump.
    """
    emitted = _emitted_secret_types()
    assert emitted, "found no detect-secrets plugins to read secret types from"
    dead = sorted(set(DETECTOR_SEVERITY) - emitted)
    assert not dead, f"DETECTOR_SEVERITY keys no plugin emits: {dead}"


def test_real_scan_grades_credential_detectors_critical(git_repo: Path):
    """npm, OpenAI, PyPI and Cloudant credentials found by a real scan are CRITICAL.

    The values are assembled from fragments so no complete secret literal
    appears in source (GitHub push protection).
    """
    a20, b20 = "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0"
    files = {
        "npm.cfg": "//registry.npmjs.org/:_authToken=npm_" + "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0FeDcBa",
        "openai.cfg": "OPENAI=sk-" + a20 + "T3Blbk" + "FJ" + b20,
        "pypi.cfg": "TOKEN=pypi-AgEIcHlwaS5vcmc" + "Ab1-Cd2_Ef3Gh4" * 6,
        "cloudant.cfg": "cloudant_password='" + "0123456789abcdef" * 4 + "'",
    }
    for name, line in files.items():
        (git_repo / name).write_text(line + "\n")
    # The scanner only covers git-tracked files.
    subprocess.run(["git", "add", "-A"], cwd=git_repo, capture_output=True, check=True)

    result = DetectSecretsScanner(auto_install=False).scan([git_repo])

    assert result.error is None, result.error
    graded = {(Path(f.file_path).name, f.rule_description): f.severity for f in result.findings}
    expected = {
        ("npm.cfg", "NPM tokens"),
        ("openai.cfg", "OpenAI Token"),
        ("pypi.cfg", "PyPI Token"),
        ("cloudant.cfg", "Cloudant Credentials"),
    }
    missing = expected - graded.keys()
    assert not missing, f"detect-secrets did not report {sorted(missing)}; got {sorted(graded)}"
    for key in sorted(expected):
        assert graded[key] == FindingSeverity.CRITICAL, f"{key} graded {graded[key]}"


@pytest.mark.xfail(
    strict=False,
    raises=AssertionError,
    reason="detect-secrets lists files with git ls-files; outside a repo it finds nothing "
    "and envdrift reports a clean run (see #851)",
)
def test_scan_outside_a_git_repo_is_not_silently_clean(tmp_path: Path):
    """A secret in a non-git directory is reported, or the result carries an error."""
    (tmp_path / "npm.cfg").write_text(
        "//registry.npmjs.org/:_authToken=npm_" + "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0FeDcBa\n"
    )

    result = DetectSecretsScanner(auto_install=False).scan([tmp_path])

    reported = any(f.rule_description == "NPM tokens" for f in result.findings)
    assert reported or result.error, "detect-secrets covered nothing yet reported a clean run"
