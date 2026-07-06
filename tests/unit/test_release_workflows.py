"""Regression tests pinning the release workflows to real guarantees (#495).

The release pipelines must enforce what they appear to:

- ``vscode-release.yml`` must run the extension test suites un-masked (no
  ``|| echo`` arm that converts a SIGSEGV into success) with ``xvfb-run`` for
  the Electron suite, mirroring ``vscode-ci.yml`` — a failing test step must
  fail the release.
- The ``.vsix`` packager/publisher must be the lockfile-pinned
  ``@vscode/vsce`` devDependency (installed via ``npm ci``), never an ad-hoc
  ``npx vsce`` network fetch of the deprecated ``vsce`` package at release time.
- Exactly one release pipeline per tag: a workflow with a ``push: tags``
  trigger must not *also* be invoked as a reusable workflow by
  ``release-please.yml`` (the PAT tag push already fires it), and the release
  workflows carry a per-tag ``concurrency`` group as a backstop so two runs
  can't race binaries against ``checksums.txt``.
- Workflows holding write credentials or minting checksum-verified artifacts
  pin third-party actions to full commit SHAs (the publish.yml policy, #365).

These parse the real workflow/package files — no mocking of the behavior
under test.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOWS = _REPO_ROOT / ".github" / "workflows"
_VSCODE_DIR = _REPO_ROOT / "envdrift-vscode"

# Workflows that hold write credentials (releases, PAT) or publish the
# checksum-verified artifacts / benchmark results (#495 finding 4).
_PRIVILEGED_WORKFLOWS = (
    "agent-release.yml",
    "vscode-release.yml",
    "release-please.yml",
    "codspeed.yml",
)

_FULL_SHA = re.compile(r"[0-9a-f]{40}")


def _load_workflow(name: str) -> dict[Any, Any]:
    # dict[Any, Any]: YAML 1.1 parses the bare `on:` trigger key as boolean
    # True, so workflow mappings genuinely carry a non-str key.
    return yaml.safe_load((_WORKFLOWS / name).read_text(encoding="utf-8"))


def _triggers(workflow: dict[Any, Any]) -> dict[str, Any]:
    raw = workflow.get("on", workflow.get(True)) or {}
    return raw if isinstance(raw, dict) else {}


def _run_commands(workflow: dict[Any, Any], job: str) -> list[str]:
    return [step.get("run", "") for step in workflow["jobs"][job]["steps"]]


def _step_uses(workflow: dict[Any, Any]) -> list[str]:
    refs: list[str] = []
    for job in workflow["jobs"].values():
        for step in job.get("steps", []):
            if "uses" in step:
                refs.append(step["uses"])
    return refs


def test_vscode_release_runs_tests_unmasked() -> None:
    """The vscode release build must let test failures fail the release (#495).

    Pre-fix the step was ``npm test || echo "Tests skipped - no test runner
    configured"``: v0.1.5 shipped after the suite SIGSEGV'd (no X server) with
    a false "skipped" log line. The build job must run the headless unit suite
    plus the Electron suite under ``xvfb-run`` (the vscode-ci.yml pattern),
    with nothing swallowing a non-zero exit.
    """
    workflow = _load_workflow("vscode-release.yml")
    runs = _run_commands(workflow, "build")
    masked = [r for r in runs if "|| echo" in r or "|| true" in r]
    assert not masked, (
        f"vscode-release.yml build job masks failures: {masked!r}; a failing "
        "or crashing test step must fail the release (#495)."
    )
    assert any(r.strip() == "npm run test:unit" for r in runs), (
        "vscode-release.yml build job must run the headless unit suite "
        "(npm run test:unit) before packaging (#495)."
    )
    assert any("xvfb-run" in r and "npm test" in r for r in runs), (
        "vscode-release.yml build job must run the Electron suite under "
        "xvfb-run on the Linux runner, like vscode-ci.yml (#495)."
    )
    for step in workflow["jobs"]["build"]["steps"]:
        assert not step.get("continue-on-error"), (
            f"build step {step.get('name')!r} sets continue-on-error; release "
            "gates must be allowed to fail (#495)."
        )


def test_vsce_is_a_lockfile_pinned_devdependency() -> None:
    """@vscode/vsce must be a devDependency under package-lock control (#495).

    Pre-fix no vsce was declared anywhere, so ``npx vsce`` fetched the
    deprecated ``vsce`` package (frozen at 2.15.0, Jan 2023) from the registry
    at release time — a tool CI never exercises.
    """
    package = json.loads((_VSCODE_DIR / "package.json").read_text(encoding="utf-8"))
    assert "@vscode/vsce" in package.get("devDependencies", {}), (
        "envdrift-vscode/package.json must declare @vscode/vsce as a "
        "devDependency so packaging/publishing tooling is lockfile-pinned "
        "(#495)."
    )
    lock = json.loads((_VSCODE_DIR / "package-lock.json").read_text(encoding="utf-8"))
    assert "node_modules/@vscode/vsce" in lock.get("packages", {}), (
        "envdrift-vscode/package-lock.json must pin @vscode/vsce (#495)."
    )


def _assert_vsce_invocations_pinned(name: str, job_name: str, runs: list[str]) -> None:
    """Assert one job's vsce runs use the lockfile-pinned local bin (#495)."""
    vsce_runs = [r for r in runs if "vsce" in r]
    for run in vsce_runs:
        assert "npm install -g" not in run and "npx vsce" not in run, (
            f"{name}:{job_name} fetches vsce ad-hoc ({run.strip()!r}); "
            "use the lockfile-pinned node_modules/.bin/vsce (#495)."
        )
    assert any("node_modules/.bin/vsce" in r for r in vsce_runs), (
        f"{name}:{job_name} must invoke the local node_modules/.bin/vsce (#495)."
    )
    assert any(r.strip() == "npm ci" for r in runs), (
        f"{name}:{job_name} invokes vsce without running `npm ci` "
        "first; the local bin must come from the lockfile (#495)."
    )


def test_vscode_workflows_never_fetch_vsce_ad_hoc() -> None:
    """Every vsce invocation must resolve the local lockfile-pinned bin (#495).

    A bare ``npx vsce`` (or a global ``npm install -g``) fetches whatever the
    registry serves at run time; the job that publishes the Marketplace
    artifact pre-fix never even ran ``npm ci``, so it always downloaded the
    deprecated ``vsce``. All invocations must go through
    ``node_modules/.bin/vsce`` after an ``npm ci``.
    """
    for name in ("vscode-release.yml", "vscode-ci.yml"):
        workflow = _load_workflow(name)
        for job_name, job in workflow["jobs"].items():
            runs = [step.get("run", "") for step in job.get("steps", [])]
            if any("vsce" in r for r in runs):
                _assert_vsce_invocations_pinned(name, job_name, runs)


def test_release_tags_have_exactly_one_trigger_path() -> None:
    """A tag-push release workflow must not also be invoked via workflow_call.

    Pre-fix every agent/vscode release ran TWICE concurrently: once from the
    PAT tag push and once via ``workflow_call`` from release-please.yml. Two
    jobs raced uploading binaries and checksums.txt to the same GitHub
    release, so checksums.txt from build A could pair with a binary from
    build B and the fail-closed installers would abort (#495). Scan *every*
    workflow for callers — not just release-please.yml — so a future caller
    can't quietly reopen the race.
    """
    for caller_path in sorted(_WORKFLOWS.glob("*.yml")) + sorted(_WORKFLOWS.glob("*.yaml")):
        caller = yaml.safe_load(caller_path.read_text(encoding="utf-8"))
        for job_name, job in (caller.get("jobs") or {}).items():
            called = job.get("uses")
            if not called:
                continue
            called_file = called.split("@", 1)[0].rsplit("/", 1)[-1]
            if not (_WORKFLOWS / called_file).is_file():
                # Reusable workflow from another repository — no local
                # push-tags trigger to double-fire.
                continue
            called_workflow = _load_workflow(called_file)
            push = _triggers(called_workflow).get("push") or {}
            assert not push.get("tags"), (
                f"{caller_path.name}:{job_name} calls {called_file}, which is "
                "also triggered by its own `push: tags` — every release would "
                "run twice and race the release assets (#495). Keep exactly one "
                "trigger path per tag."
            )


def test_release_workflows_define_per_tag_concurrency() -> None:
    """Release pipelines need a per-tag concurrency group as a backstop (#495).

    Even with a single trigger path, a re-run or manual re-tag must queue
    behind an in-flight run instead of racing asset uploads for the same tag.
    """
    for name in ("agent-release.yml", "vscode-release.yml"):
        workflow = _load_workflow(name)
        concurrency = workflow.get("concurrency")
        assert isinstance(concurrency, dict), (
            f"{name} must define a workflow-level concurrency group (#495)."
        )
        group = concurrency.get("group", "")
        assert "inputs.tag_name" in group or "github.ref" in group, (
            f"{name} concurrency group {group!r} must key on the release tag "
            "so runs for the same tag serialize (#495)."
        )
        assert concurrency.get("cancel-in-progress") is False, (
            f"{name} must queue (cancel-in-progress: false), not kill an "
            "in-flight release mid-upload (#495)."
        )
    release_please = _load_workflow("release-please.yml")
    assert isinstance(release_please.get("concurrency"), dict), (
        "release-please.yml must serialize its runs on main so overlapping "
        "pushes can't race release PRs / tag pushes (#495)."
    )


def test_privileged_workflows_pin_third_party_actions_to_commit_shas() -> None:
    """Third-party actions in privileged workflows pin to full SHAs (#495).

    ``softprops/action-gh-release`` (contents:write) publishes the binaries
    and the checksums.txt the installers verify against;
    ``release-please-action`` holds the PAT. A hijacked mutable tag could swap
    binaries AND emit a matching checksums.txt, silently defeating the
    fail-closed install gate. Pin to commit SHAs like publish.yml (#365).
    """
    unpinned: list[str] = []
    for name in _PRIVILEGED_WORKFLOWS:
        for ref in _step_uses(_load_workflow(name)):
            owner = ref.split("/", 1)[0]
            # GitHub-owned namespaces are first-party; local workflow paths
            # have no ref to pin.
            if owner in ("actions", "github") or ref.startswith("./"):
                continue
            _, _, pinned_ref = ref.partition("@")
            if not _FULL_SHA.fullmatch(pinned_ref):
                unpinned.append(f"{name}: {ref}")
    assert not unpinned, (
        "Third-party actions in privileged workflows must be pinned to full "
        f"commit SHAs (#495, policy from publish.yml/#365): {unpinned}"
    )
