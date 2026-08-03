"""Renovate configuration must match upstream reality.

Split from ``test_dev_stack_hygiene.py`` (CodeScene: 8 responsibilities in one
module). This module owns exactly one concern: every Renovate manager tracks a
real dependency stream, and every dependency the repo pins has a manager.

The motivating incident: a custom manager pointed at the wrong GitHub
repository for the Infisical CLI, so the pin froze at 0.41.90 for a year while
Renovate reported "up to date" with zero diagnostics. Every guard here exists
to make that class of silent non-coverage loud.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOWS = _REPO_ROOT / ".github" / "workflows"
_RENOVATE_PATH = _REPO_ROOT / "renovate.json"


def _renovate_config() -> dict[str, Any]:
    return json.loads(_RENOVATE_PATH.read_text(encoding="utf-8"))


def _constants() -> dict[str, Any]:
    path = _REPO_ROOT / "src" / "envdrift" / "constants.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_custom_manager_regexes_match_the_constants_they_target() -> None:
    """Every ``constants.json`` custom manager must actually match its key.

    A ``matchStrings`` regex that no longer matches makes Renovate report
    "up to date" forever with ZERO diagnostics — the pin silently freezes.
    This is not hypothetical: the infisical manager targeted the wrong
    repository's tag format, so the CLI sat at 0.41.90 while upstream moved
    to a different repo entirely.
    """
    constants_text = (_REPO_ROOT / "src" / "envdrift" / "constants.json").read_text(
        encoding="utf-8"
    )
    managers = [
        m
        for m in _renovate_config().get("customManagers", [])
        if any("constants" in p for p in m.get("managerFilePatterns", []))
    ]
    assert managers, "expected custom managers targeting constants.json"

    for manager in managers:
        dep = manager.get("depNameTemplate", "<unnamed>")
        for pattern in manager["matchStrings"]:
            # Renovate regexes use JS-style named groups; Python wants (?P<n>...).
            py_pattern = re.sub(r"\(\?<(\w+)>", r"(?P<\1>", pattern)
            assert re.search(py_pattern, constants_text), (
                f"renovate.json custom manager for {dep} has a matchStrings "
                f"regex that matches nothing in constants.json: {pattern!r}. "
                "Renovate would silently never update this pin."
            )


def test_every_versioned_tool_has_a_custom_manager() -> None:
    """No ``<tool>_version`` key may exist without Renovate tracking it."""
    versioned = {key.removesuffix("_version") for key in _constants() if key.endswith("_version")}
    covered = {
        tool
        for tool in versioned
        for m in _renovate_config().get("customManagers", [])
        for pattern in m.get("matchStrings", [])
        if f"{tool}_version" in pattern
    }
    missing = sorted(versioned - covered)
    assert not missing, (
        f"constants.json pins {missing} with no Renovate custom manager. "
        "Hardcoded versions must always be Renovate-managed."
    )


# --- Renovate manager <-> upstream reality -----------------------------------
#
# The earlier guards in this module only proved that each `matchStrings` regex
# matches constants.json and that every `<tool>_version` key has SOME manager.
# Neither touches `depNameTemplate` or `extractVersionTemplate` — the two fields
# that actually froze the Infisical pin. That manager was internally consistent
# (its regex matched, its tag template matched its own download URL) while being
# detached from upstream: the CLI had moved repository, so the configured repo
# published no tags of the configured shape and Renovate reported "up to date"
# forever with zero diagnostics.

_GH_RELEASE_URL = re.compile(
    r"https://github\.com/(?P<repo>[^/]+/[^/]+)/releases/download/(?P<tag>.+)/[^/]+$"
)


def _github_managers() -> list[dict[str, Any]]:
    return [
        m
        for m in _renovate_config().get("customManagers", [])
        if m.get("datasourceTemplate") == "github-releases" and m.get("depNameTemplate")
    ]


def _tool_for_manager(manager: dict[str, Any]) -> str | None:
    """The constants.json tool prefix a manager targets, e.g. ``infisical``."""
    for pattern in manager.get("matchStrings", []):
        found = re.search(r'"(\w+)_version"', pattern)
        if found:
            return found.group(1)
    return None


def _download_urls_for(constants: dict[str, Any], tool: str) -> dict[str, str]:
    """Download URL templates for ``tool``, however constants.json spells them.

    dotenvx predates the ``<tool>_download_urls`` convention and still lives at
    the top-level ``download_urls`` key. Looking only for the prefixed name made
    the guards below silently ``continue`` past it — leaving one of the seven
    github-releases managers unvalidated, which is exactly the kind of quiet
    coverage hole these tests exist to prevent.
    """
    urls = constants.get(f"{tool}_download_urls")
    if urls is None and tool == "dotenvx":
        urls = constants.get("download_urls")
    return urls or {}


def test_manager_repo_matches_the_configured_download_url() -> None:
    """``depNameTemplate`` must be the same repo the download URLs point at.

    A mismatch means Renovate watches releases in one repository while the
    installer downloads from another — the pin then tracks a stream that has
    nothing to do with the artifact actually installed.
    """
    constants = _constants()
    for manager in _github_managers():
        tool = _tool_for_manager(manager)
        urls = _download_urls_for(constants, tool) if tool else {}
        assert urls, f"{tool}: no download URLs found in constants.json"
        for platform_key, url in urls.items():
            parsed = _GH_RELEASE_URL.match(url)
            assert parsed, f"{tool}.{platform_key}: unparsable GitHub release URL {url!r}"
            assert parsed.group("repo") == manager["depNameTemplate"], (
                f"{tool}: Renovate watches {manager['depNameTemplate']!r} but "
                f"{platform_key} downloads from {parsed.group('repo')!r}. The pin "
                "would track a repository that does not publish this artifact."
            )


def test_manager_tag_template_matches_the_download_url_tag() -> None:
    """``extractVersionTemplate`` must match the tag shape the URLs encode."""
    constants = _constants()
    for manager in _github_managers():
        tool = _tool_for_manager(manager)
        urls = _download_urls_for(constants, tool) if tool else {}
        extract = manager.get("extractVersionTemplate")
        assert urls, f"{tool}: no download URLs found in constants.json"
        if not extract:
            continue
        py_extract = re.sub(r"\(\?<(\w+)>", r"(?P<\1>", extract)
        sample_tag = next(iter(urls.values()))
        parsed = _GH_RELEASE_URL.match(sample_tag)
        assert parsed
        concrete = parsed.group("tag").replace("{version}", "1.2.3")
        assert re.match(py_extract, concrete), (
            f"{tool}: extractVersionTemplate {extract!r} does not match the tag "
            f"{concrete!r} encoded in its download URL. Renovate would extract no "
            "version and silently report the pin as up to date."
        )


# A missing/renamed repository IS the regression the upstream-tag guard exists
# to catch, so it must never be downgraded to a skip. Only genuinely
# environmental failures (no credentials, rate limit, transient network) may.
_REPO_GONE = re.compile(r"\b(404|Not Found|Could not resolve to a Repository)\b", re.I)


def _fetch_release_tags(repo: str) -> list[str]:
    """Recent release tags for ``repo``; fails on a missing repo, skips on env."""
    result = subprocess.run(
        ["gh", "api", f"repos/{repo}/releases?per_page=100", "--jq", ".[].tag_name"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode == 0:
        return [tag for tag in result.stdout.split() if tag]

    stderr = result.stderr.strip()
    if _REPO_GONE.search(stderr):
        pytest.fail(
            f"{repo} does not exist or is not reachable ({stderr[:160]}). "
            "A Renovate manager pointing at a missing repository is the exact "
            "failure mode this test exists to catch — the pin would freeze with "
            "no diagnostic."
        )
    pytest.skip(f"cannot query GitHub for {repo}: {stderr[:160]}")


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("gh") is None, reason="gh CLI not installed")
def test_every_manager_matches_a_real_upstream_tag() -> None:
    """Each manager must match tags the configured repo ACTUALLY publishes.

    This is the regression test for the Infisical freeze, and the only check
    here that would have failed before that fix: the static guards all passed
    on the broken config because the manager was self-consistent. What it was
    not, was connected to reality — ``Infisical/infisical`` had stopped
    publishing ``infisical-cli/v*`` tags entirely, so the regex matched none of
    the 100 most recent releases and Renovate had nothing to compare the pin
    against.

    Network-gated (integration marker + ``gh``) because it queries GitHub. CI
    must export ``GH_TOKEN`` where ``-m integration`` runs, otherwise ``gh``
    is unauthenticated on a clean runner, every call fails, and this test
    skips — leaving all required checks green while the only guard that checks
    upstream reality never executes.
    """
    for manager in _github_managers():
        extract = manager.get("extractVersionTemplate")
        if not extract:
            continue
        repo = manager["depNameTemplate"]
        tags = _fetch_release_tags(repo)
        assert tags, f"{repo} published no releases at all"

        py_extract = re.sub(r"\(\?<(\w+)>", r"(?P<\1>", extract)
        matching = [tag for tag in tags if re.match(py_extract, tag)]
        assert matching, (
            f"{repo}: extractVersionTemplate {extract!r} matches NONE of the "
            f"{len(tags)} most recent release tags (e.g. {tags[:3]}). Renovate "
            "cannot extract a version, so this pin is frozen with no diagnostic "
            "— exactly how infisical sat at 0.41.90 after the CLI moved repos."
        )


# --- Renovate coverage invariants from the 2026-08 audit ------------------------


def test_go_indirect_dependencies_are_tracked() -> None:
    """Renovate must not silently skip the agent's indirect Go modules.

    The gomod extractor stamps ``enabled: false`` on every ``// indirect``
    require (absent a Go 1.24+ ``tool`` directive), removing them from updates
    AND the dashboard with no diagnostic. That left 12 of the agent's modules
    invisible — including golang.org/x/sys with GO-2026-5024 package-imported
    in the shipped Windows binary. The rule below is the only thing keeping
    them visible; grouping keeps the weekend run from opening ~12 PRs at once.
    """
    rules = [
        r
        for r in _renovate_config().get("packageRules", [])
        if r.get("matchManagers") == ["gomod"] and r.get("matchDepTypes") == ["indirect"]
    ]
    assert rules, "renovate.json lost the gomod indirect packageRule"
    assert rules[0].get("enabled") is True
    assert rules[0].get("groupName"), (
        "indirect Go updates must be grouped, or one weekend run opens a PR "
        "per module against a repo that freezes new work at ~20 open PRs"
    )
    assert "gomodTidy" in _renovate_config().get("postUpdateOptions", []), (
        "postUpdateOptions must keep gomodTidy: without it Renovate adds new "
        "go.sum hashes but never prunes stale ones"
    )


def test_go_floor_supports_current_x_sys() -> None:
    """go.mod's floor must stay >= what golang.org/x/sys requires.

    x/sys v0.44.0 (the GO-2026-5024 fix) declares ``go 1.25.0``. If the module
    floor or any CI matrix leg drops below that, the indirect-deps rule opens
    an un-mergeable PR and the CVE fix is unreachable — silent non-coverage
    with extra steps.
    """
    go_mod = (_REPO_ROOT / "envdrift-agent" / "go.mod").read_text(encoding="utf-8")
    directive = re.search(r"(?m)^go (\d+)\.(\d+)", go_mod)
    assert directive, "envdrift-agent/go.mod lost its go directive"
    assert (int(directive.group(1)), int(directive.group(2))) >= (1, 25), (
        f"go.mod declares go {directive.group(0)[3:]} but x/sys >= 0.44.0 "
        "requires 1.25; the indirect-update PR cannot merge below that"
    )
    ci = yaml.safe_load((_WORKFLOWS / "agent-ci.yml").read_text(encoding="utf-8"))
    matrix_go = ci["jobs"]["test"]["strategy"]["matrix"]["go"]
    for leg in matrix_go:
        major, minor = (int(x) for x in str(leg).split(".")[:2])
        assert (major, minor) >= (1, 25), (
            f"agent-ci.yml matrix leg go {leg} is below the go.mod floor"
        )


def _setup_uv_steps() -> list[tuple[str, dict[str, Any]]]:
    """Every (workflow-name, step) pair whose step uses astral-sh/setup-uv."""
    return [
        (wf.name, step)
        for wf in sorted(_WORKFLOWS.glob("*.yml"))
        for job in (yaml.safe_load(wf.read_text(encoding="utf-8")).get("jobs") or {}).values()
        for step in job.get("steps") or []
        if "astral-sh/setup-uv" in str(step.get("uses", ""))
    ]


def test_setup_uv_steps_pin_the_uv_version() -> None:
    """Every setup-uv step must pin `version:` — and never via a regex annotation.

    Unpinned, `latest` uv drives all 12 required checks and `uv build`/`uv
    publish` on the release path. The `version:` input is extracted by
    Renovate's BUILT-IN github-actions manager as astral-sh/uv, so a
    `# renovate:` comment on these steps would double-track the same dep.
    """
    steps = _setup_uv_steps()
    assert steps, "no setup-uv steps found — did the workflows move?"

    bare = sorted({name for name, step in steps if not (step.get("with") or {}).get("version")})
    assert not bare, f"setup-uv steps without a pinned uv version: {bare}"

    annotated = sorted(
        wf.name
        for wf in _WORKFLOWS.glob("*.yml")
        if "depName=astral-sh/uv" in wf.read_text(encoding="utf-8")
    )
    assert not annotated, (
        f"remove the astral-sh/uv regex annotations in {annotated} — the "
        "github-actions manager already tracks the version input, so an "
        "annotation creates a duplicate dependency"
    )


def test_makefile_tool_pins_are_renovate_visible() -> None:
    """Every `# renovate:` annotated pin in the Makefile must match the manager.

    The Lint check runs `npx markdownlint-cli2@$(MARKDOWNLINT_VERSION)`; the
    pin only stays fresh if the Makefile customManager's regex actually
    matches it (the Infisical lesson: a manager whose regex matches nothing
    reports up-to-date forever).
    """
    makefile = (_REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    managers = [
        m
        for m in _renovate_config().get("customManagers", [])
        if any("Makefile" in p for p in m.get("managerFilePatterns", []))
    ]
    assert managers, "renovate.json lost the Makefile customManager"
    pattern = re.sub(r"\(\?<(\w+)>", r"(?P<\1>", managers[0]["matchStrings"][0])
    matches = {m.group("depName"): m.group("currentValue") for m in re.finditer(pattern, makefile)}
    assert "markdownlint-cli2" in matches, (
        "the Makefile manager regex no longer matches the markdownlint-cli2 "
        f"pin (matched: {matches or 'nothing'})"
    )
    # And the pin must actually be used by the recipe, not just declared.
    assert "markdownlint-cli2@$(MARKDOWNLINT_VERSION)" in makefile, (
        "lint-docs no longer interpolates MARKDOWNLINT_VERSION - the pin is decorative"
    )
