"""End-to-end regression tests for ``guard --sarif`` portability (#489).

Each test drives the real ``envdrift guard`` CLI as a subprocess inside a
scratch git repository, reproducing the exact issue repros:

- The docs' default invocation (``envdrift guard --sarif`` with no path arg)
  must emit artifact URIs **relative to the git repository root** with
  ``uriBaseId: %SRCROOT%`` — not absolute filesystem paths — so GitHub/GitLab
  Code Scanning can map every alert to a repo file. The URIs must be identical
  whether guard runs from the repo root or a subdirectory.
- Two DISTINCT secrets on the same line must keep distinct fingerprints so
  Code Scanning does not merge them into one alert (the #348 intent).
- The tool driver must report the real package version and repository URL,
  not the ``0.1.0`` / ``your-org`` placeholders.

Secret-shaped fixture values are built by string concatenation only, so no
realistic literal ever appears in the repository (GitHub push protection).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import envdrift

pytestmark = [pytest.mark.integration]

REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHONPATH = str(REPO_ROOT / "src")

# Two DISTINCT AWS-access-key-shaped values (AKIA + 16 uppercase alnum chars),
# assembled by concatenation. Both sit on ONE line of the fixture .env file.
_AWS_KEY_ONE = "AKIA" + "IOSFODNN7" + "EXAMPLE"
_AWS_KEY_TWO = "AKIA" + "JQRSTUVWXYZ2" + "EXMP"

_SARIF_ARGS = ["guard", "--native-only", "--no-auto-install", "--sarif"]


def _run_envdrift(args: list[str], *, cwd: Path) -> subprocess.CompletedProcess:
    """Run the envdrift CLI as a real subprocess."""
    run_env = os.environ.copy()
    run_env["PYTHONPATH"] = f"{PYTHONPATH}{os.pathsep}{run_env.get('PYTHONPATH', '')}"
    cmd = [sys.executable, "-m", "envdrift.cli", *args]
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=run_env,
        capture_output=True,
        text=True,
    )


def _parse_sarif(result: subprocess.CompletedProcess) -> dict:
    """Parse the SARIF document printed by ``guard --sarif``."""
    out = result.stdout
    start = out.index("{")
    end = out.rindex("}") + 1
    return json.loads(out[start:end])


def _artifact_uris(sarif: dict) -> list[dict]:
    """Collect every result's ``artifactLocation`` object."""
    return [
        loc["physicalLocation"]["artifactLocation"]
        for res in sarif["runs"][0]["results"]
        for loc in res["locations"]
    ]


@pytest.fixture
def scratch_repo(tmp_path: Path) -> Path:
    """A scratch git repository with two distinct secrets on one .env line."""
    git_path = shutil.which("git")
    if git_path is None:
        pytest.skip("git is not available")
    subprocess.run(
        [git_path, "init", "-q", "-b", "main"],
        cwd=str(tmp_path),
        check=True,
        capture_output=True,
    )
    configs = tmp_path / "configs"
    configs.mkdir()
    (configs / ".env").write_text(
        f"KEYS={_AWS_KEY_ONE},{_AWS_KEY_TWO}\n",
        encoding="utf-8",
    )
    return tmp_path


class TestSarifRelativeUris:
    """Artifact URIs must be repo-root-relative, from any invocation cwd."""

    def test_default_invocation_from_repo_root_emits_repo_relative_uris(
        self, scratch_repo: Path
    ) -> None:
        """The docs' exact invocation must not emit absolute filesystem URIs."""
        result = _run_envdrift(_SARIF_ARGS, cwd=scratch_repo)
        assert result.returncode == 1, result.stderr
        sarif = _parse_sarif(result)

        locations = _artifact_uris(sarif)
        assert locations, "expected findings for the fixture secrets"
        for location in locations:
            uri = location["uri"]
            assert uri == "configs/.env", f"expected a repo-root-relative URI, got {uri!r}"
            assert location["uriBaseId"] == "%SRCROOT%"

    def test_invocation_from_subdirectory_keeps_repo_root_relative_uris(
        self, scratch_repo: Path
    ) -> None:
        """URIs must be stable: a subdirectory cwd still yields root-relative URIs."""
        result = _run_envdrift(_SARIF_ARGS, cwd=scratch_repo / "configs")
        assert result.returncode == 1, result.stderr
        sarif = _parse_sarif(result)

        locations = _artifact_uris(sarif)
        assert locations, "expected findings for the fixture secrets"
        for location in locations:
            assert location["uri"] == "configs/.env", (
                "URI must stay repo-root-relative when guard runs from a subdirectory, "
                f"got {location['uri']!r}"
            )
            assert location["uriBaseId"] == "%SRCROOT%"

    def test_srcroot_base_id_is_declared_in_original_uri_base_ids(self, scratch_repo: Path) -> None:
        """%SRCROOT% must be defined by an ``originalUriBaseIds`` entry per SARIF 2.1.0."""
        result = _run_envdrift(_SARIF_ARGS, cwd=scratch_repo)
        assert result.returncode == 1, result.stderr
        sarif = _parse_sarif(result)

        base_ids = sarif["runs"][0]["originalUriBaseIds"]
        srcroot = base_ids["SRCROOT"]["uri"]
        assert srcroot.startswith("file://")
        assert srcroot.endswith("/"), "SARIF base URIs must end with a slash"
        # The declared base must actually be the scratch repo root.
        assert srcroot == scratch_repo.resolve().as_uri() + "/"


class TestSarifFingerprints:
    """Two distinct secrets on one line must never share a fingerprint."""

    def test_two_distinct_secrets_on_one_line_keep_distinct_fingerprints(
        self, scratch_repo: Path
    ) -> None:
        result = _run_envdrift(_SARIF_ARGS, cwd=scratch_repo)
        assert result.returncode == 1, result.stderr
        sarif = _parse_sarif(result)

        aws_results = [r for r in sarif["runs"][0]["results"] if r["ruleId"] == "aws-access-key-id"]
        assert len(aws_results) == 2, "both same-line secrets must survive into SARIF"

        primaries = [r["fingerprints"]["primary"] for r in aws_results]
        assert primaries[0] != primaries[1], (
            "distinct secrets on the same line must not share fingerprints.primary "
            f"(both were {primaries[0]!r})"
        )
        partials = [r.get("partialFingerprints") for r in aws_results]
        if partials[0] is not None or partials[1] is not None:
            assert partials[0] != partials[1], (
                "distinct secrets must not share identical partialFingerprints"
            )

    def test_fingerprints_never_embed_raw_secret_values(self, scratch_repo: Path) -> None:
        """Fingerprints must use a stable hash, never the matched secret text."""
        result = _run_envdrift(_SARIF_ARGS, cwd=scratch_repo)
        assert result.returncode == 1, result.stderr

        assert _AWS_KEY_ONE not in result.stdout
        assert _AWS_KEY_TWO not in result.stdout


class TestSarifDriverMetadata:
    """The tool driver must carry real package metadata, not placeholders."""

    def test_driver_reports_real_version_and_repository(self, scratch_repo: Path) -> None:
        result = _run_envdrift(_SARIF_ARGS, cwd=scratch_repo)
        assert result.returncode == 1, result.stderr
        sarif = _parse_sarif(result)

        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "envdrift guard"
        assert driver["version"] == envdrift.__version__
        assert driver["version"] != "0.1.0"
        assert driver["informationUri"] == "https://github.com/jainal09/envdrift"
        assert "your-org" not in driver["informationUri"]


class TestSarifStructure:
    """Structural SARIF 2.1.0 sanity checks (Code Scanning upload shape)."""

    def test_sarif_document_passes_structural_schema_checks(self, scratch_repo: Path) -> None:
        result = _run_envdrift(_SARIF_ARGS, cwd=scratch_repo)
        assert result.returncode == 1, result.stderr
        sarif = _parse_sarif(result)

        assert sarif["version"] == "2.1.0"
        assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
        assert len(sarif["runs"]) == 1

        run = sarif["runs"][0]
        driver = run["tool"]["driver"]
        assert isinstance(driver["name"], str) and driver["name"]
        rule_ids = {rule["id"] for rule in driver["rules"]}

        for res in run["results"]:
            assert res["ruleId"] in rule_ids
            assert isinstance(res["message"]["text"], str) and res["message"]["text"]
            for loc in res["locations"]:
                physical = loc["physicalLocation"]
                uri = physical["artifactLocation"]["uri"]
                assert isinstance(uri, str) and uri
                assert "\\" not in uri, "SARIF URIs must use forward slashes"
                assert not uri.startswith("/"), "relative URIs must not start with '/'"
                start_line = physical["region"]["startLine"]
                assert isinstance(start_line, int) and start_line >= 1

        invocation = run["invocations"][0]
        assert invocation["executionSuccessful"] is True
        assert invocation["exitCode"] == result.returncode
