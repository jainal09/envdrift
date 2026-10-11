"""CI labels and commands must not repeat a version that Renovate bumps.

Renovate's built-in github-actions manager rewrites the literal version input
of a setup action (``python-version: "3.14"`` -> ``"3.15"`` in #840) and
touches nothing else. A job or step name, or a ``run:`` command in the same
job, that repeats the literal (``Set up Python 3.14``,
``apt-get remove python3.14-venv``) goes stale on that bump: the label
misreports what the job runs, and the command targets the wrong version.
Leave the version out of the label, or derive it at runtime from the
interpreter or tool under test.

Matrix-expression inputs (``${{ matrix.python-version }}``) are not literals,
so names built from the same expression are fine and are not flagged.

These parse the real workflow files, with no mocking of the behavior under
test.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOWS = _REPO_ROOT / ".github" / "workflows"
_NUMERIC_VERSION = re.compile(r"\d+(?:\.\d+)*")


def _workflow_files() -> list[Path]:
    """All workflow files, both extensions (Renovate matches ``ya?ml``)."""
    return sorted(p for ext in ("*.yml", "*.yaml") for p in _WORKFLOWS.glob(ext))


def _literal_versions(job: dict[str, Any]) -> set[tuple[str, str]]:
    """(input, version) pairs for every literal ``*version`` step input.

    These are the inputs Renovate's github-actions manager extracts:
    ``python-version`` / ``go-version`` / ``node-version`` on the setup
    actions and ``version`` on tool installers such as setup-uv. Only numeric
    versions count: Renovate never bumps aliases such as ``latest``,
    ``stable`` or ``lts/*``, and as whole tokens they would match ordinary
    words in a label.
    """
    found: set[tuple[str, str]] = set()
    for step in job.get("steps") or []:
        for key, value in (step.get("with") or {}).items():
            name = str(key)
            if name != "version" and not name.endswith("-version"):
                continue
            text = str(value).strip().removeprefix("v")
            if _NUMERIC_VERSION.fullmatch(text):
                found.add((name, text))
    return found


def _labels_and_commands(job: dict[str, Any]) -> list[tuple[str, str]]:
    """(kind, text) for the job name, each step name and each ``run:`` line."""
    texts: list[tuple[str, str]] = []
    if job.get("name"):
        texts.append(("job name", str(job["name"])))
    for step in job.get("steps") or []:
        if step.get("name"):
            texts.append(("step name", str(step["name"])))
        texts.extend(("run", line.strip()) for line in str(step.get("run") or "").splitlines())
    return texts


def _version_mirrors(workflow: dict[Any, Any], source: str) -> list[str]:
    """Each label/command that repeats a literal version input of its job.

    The match is scoped to one job: a sibling job's label may describe a
    different version source (publish.yml's ``Test matrix (3.11-3.14)`` names
    its matrix, not the release job's setup-python literal). A version only
    matches as a whole token, so node-version ``24`` does not match
    ``ubuntu-24.04`` and ``3.14`` does not match ``3.14.2`` or ``13.14``.
    """
    violations: list[str] = []
    for job_id, job in (workflow.get("jobs") or {}).items():
        texts = _labels_and_commands(job)
        for key, version in sorted(_literal_versions(job)):
            token = re.compile(rf"(?<![\d.]){re.escape(version)}(?!\.?\d)")
            violations.extend(
                f"{source} job {job_id!r}: {kind} {text!r} repeats {key}: {version!r}"
                for kind, text in texts
                if token.search(text)
            )
    return violations


def _load_workflows() -> dict[str, dict[Any, Any]]:
    """Every workflow file, parsed, keyed by file name."""
    files = _workflow_files()
    assert files, "no workflow files found — did .github/workflows move?"
    return {wf.name: yaml.safe_load(wf.read_text(encoding="utf-8")) for wf in files}


def _all_literal_versions(workflows: dict[str, dict[Any, Any]]) -> set[tuple[str, str]]:
    """The literal version inputs of every job in every workflow."""
    jobs = (job for wf in workflows.values() for job in (wf.get("jobs") or {}).values())
    return {pair for job in jobs for pair in _literal_versions(job)}


def test_workflow_labels_do_not_repeat_renovate_bumped_versions() -> None:
    """No workflow label or command may go stale on a setup-action bump (#840)."""
    workflows = _load_workflows()

    # A guard that finds no literal inputs checks nothing; fail loudly instead.
    assert any(key == "python-version" for key, _ in _all_literal_versions(workflows)), (
        "no literal setup-python versions found — the guard would be vacuous"
    )

    violations = [
        violation
        for name, workflow in workflows.items()
        for violation in _version_mirrors(workflow, name)
    ]
    assert violations == [], "\n".join(violations)


_SETUP_PYTHON = {"uses": "actions/setup-python@v7", "with": {"python-version": "3.14"}}


@pytest.mark.parametrize(
    ("jobs", "expected"),
    [
        pytest.param(
            {
                "j": {
                    "name": "Unix venv fallback - ubuntu-latest / Python 3.14",
                    "steps": [_SETUP_PYTHON],
                }
            },
            ["job name"],
            id="pre-fix-job-name",
        ),
        pytest.param(
            {"j": {"steps": [{"name": "Set up Python 3.14", **_SETUP_PYTHON}]}},
            ["step name"],
            id="pre-fix-step-name",
        ),
        pytest.param(
            {
                "j": {
                    "steps": [
                        _SETUP_PYTHON,
                        {"run": "sudo apt-get remove -y python3-venv python3.14-venv || true"},
                    ]
                }
            },
            ["run"],
            id="pre-fix-apt-command",
        ),
        pytest.param(
            {
                "j": {
                    "steps": [
                        {"uses": "astral-sh/setup-uv@v10", "with": {"version": "0.13.0"}},
                        {"name": "Install uv 0.13.0", "run": "uv sync"},
                    ]
                }
            },
            ["step name"],
            id="setup-uv-version-input",
        ),
        pytest.param(
            {
                "j": {
                    "name": "Unix venv fallback - ubuntu-latest",
                    "steps": [
                        {"name": "Set up Python", **_SETUP_PYTHON},
                        {
                            "run": "PYV=$(python3 -c 'import sys; print(sys.version_info[1])')\n"
                            'sudo apt-get remove -y "python3.${PYV}-venv" || true'
                        },
                    ],
                }
            },
            [],
            id="version-agnostic",
        ),
        pytest.param(
            {
                "j": {
                    "name": "Python ${{ matrix.python-version }}",
                    "steps": [
                        {
                            "uses": "actions/setup-python@v7",
                            "with": {"python-version": "${{ matrix.python-version }}"},
                        }
                    ],
                }
            },
            [],
            id="matrix-expression",
        ),
        pytest.param(
            {
                "test": {"name": "Test matrix (3.11-3.14)", "steps": [{"run": "uv run pytest"}]},
                "publish": {"name": "Publish", "steps": [_SETUP_PYTHON]},
            },
            [],
            id="other-job-scope",
        ),
        pytest.param(
            {
                "j": {
                    "steps": [
                        {"uses": "actions/setup-node@v6", "with": {"node-version": "24"}},
                        _SETUP_PYTHON,
                        {"run": "echo ubuntu-24.04 && pip install x==13.14 y==3.14.2"},
                    ]
                }
            },
            [],
            id="whole-token-only",
        ),
        pytest.param(
            {
                "j": {
                    "name": "Lint with the stable toolchain",
                    "steps": [
                        {"uses": "actions/setup-go@v6", "with": {"go-version": "stable"}},
                        {"uses": "actions/setup-node@v6", "with": {"node-version": "lts/*"}},
                        {"name": "Use latest", "run": "go vet ./... # stable"},
                    ],
                }
            },
            [],
            id="non-numeric-aliases",
        ),
    ],
)
def test_version_mirror_guard_catches_each_shape(jobs: dict[str, Any], expected: list[str]) -> None:
    """The guard itself must flag each stale-on-bump shape and nothing else."""
    violations = _version_mirrors({"jobs": jobs}, "synthetic.yml")

    assert len(violations) == len(expected), violations
    for kind, violation in zip(expected, violations, strict=True):
        assert f": {kind} " in violation
