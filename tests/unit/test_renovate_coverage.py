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


def _constants_managers() -> list[dict[str, Any]]:
    """github-releases managers that pin tools via constants.json.

    Only these carry download URLs to cross-check. Managers that pin a command
    in docs (the golangci-lint CONTRIBUTING.md one) have no artifact URLs by
    design; the live upstream-tag test covers them by asserting real release
    tags match the verbatim v-shape those managers embed.
    """
    return [
        m
        for m in _github_managers()
        if any("constants" in p for p in m.get("managerFilePatterns", []))
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
    for manager in _constants_managers():
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
    for manager in _constants_managers():
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
        # A manager without extractVersionTemplate embeds the tag VERBATIM in
        # the file it updates (the doc-pin manager writes `@v2.12.2`, and
        # `go install pkg@2.12.2` without the v is rejected by Go — verified).
        # Skipping those here left them with zero upstream-reality coverage,
        # so instead assert real tags match the verbatim v-shape.
        if not extract:
            extract = r"^v\d+\.\d+\.\d+"
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


def _agent_ci() -> dict[str, Any]:
    return yaml.safe_load((_WORKFLOWS / "agent-ci.yml").read_text(encoding="utf-8"))


def _agent_matrix_go() -> list[str]:
    return [str(leg) for leg in _agent_ci()["jobs"]["test"]["strategy"]["matrix"]["go"]]


def _agent_step_running(needle: str) -> dict[str, Any]:
    steps = [
        step for step in _agent_ci()["jobs"]["test"]["steps"] if needle in str(step.get("run", ""))
    ]
    assert steps, f"agent-ci.yml lost the step running {needle!r}"
    return steps[0]


def test_go_floor_supports_current_x_sys() -> None:
    """go.mod's floor must stay >= what golang.org/x/sys requires.

    x/sys v0.44.0 (the GO-2026-5024 fix) declares ``go 1.25.0``. If the module
    floor or any CI matrix leg drops below that, the indirect-deps rule opens
    an un-mergeable PR and the CVE fix is unreachable — silent non-coverage
    with extra steps.
    """
    go_mod = (_REPO_ROOT / "envdrift-agent" / "go.mod").read_text(encoding="utf-8")
    directive = re.search(r"(?m)^go (\d+)\.(\d+)(?:\.(\d+))?", go_mod)
    assert directive, "envdrift-agent/go.mod lost its go directive"
    floor = (
        int(directive.group(1)),
        int(directive.group(2)),
        int(directive.group(3) or 0),
    )
    # Patch level matters: the go directive is the MANDATORY minimum (a
    # `toolchain` directive is only a suggestion that GOTOOLCHAIN=local
    # ignores), and GO-2026-4602 (stdlib os, symbol-reachable via fsnotify)
    # is fixed in go1.25.8. A directive below that admits compilers that
    # ship the vulnerable os package into the released agent binaries.
    assert floor >= (1, 25, 8), (
        f"go.mod declares go {'.'.join(map(str, floor))}, below the "
        "GO-2026-4602 stdlib security floor (1.25.8) — GOTOOLCHAIN=local "
        "builders would ship the vulnerable os package"
    )
    for leg in _agent_matrix_go():
        major, minor = (int(x) for x in leg.split(".")[:2])
        assert (major, minor) >= (1, 25), (
            f"agent-ci.yml matrix leg go {leg} is below the go.mod floor"
        )

    # The floor exists FOR the x/sys security fix, so also assert the module
    # actually selected is at or past it — a floor bump that still ships the
    # vulnerable version would pass the directive checks while GO-2026-5024
    # stays package-linked in the released Windows binary.
    x_sys = re.search(r"golang\.org/x/sys v(\d+)\.(\d+)\.(\d+)", go_mod)
    assert x_sys, "envdrift-agent/go.mod no longer requires golang.org/x/sys"
    selected = tuple(int(g) for g in x_sys.groups())
    assert selected >= (0, 44, 0), (
        f"golang.org/x/sys v{'.'.join(map(str, selected))} is selected, but "
        "every version below v0.44.0 is affected by GO-2026-5024 "
        "(package-imported in the shipped windows-amd64 binary)"
    )


@pytest.mark.parametrize(
    ("gate", "needle"),
    [("go mod tidy", "go mod tidy -diff"), ("govulncheck", "govulncheck ./...")],
)
def test_agent_gates_survive_matrix_rotation(gate: str, needle: str) -> None:
    """Each CI gate's `if:` must reference a leg in the CURRENT matrix.

    Both gates pin a literal leg; a matrix rotation (e.g. ['1.27','1.28'])
    would make the condition permanently false and the gate would evaporate
    with zero diagnostics — the silent-guard-death mode this module exists to
    prevent.
    """
    condition = str(_agent_step_running(needle).get("if", "") or "")
    if not condition:
        return  # no condition = the gate runs on every leg, the robust form
    matrix_go = _agent_matrix_go()
    assert any(f"'{leg}'" in condition or f'"{leg}"' in condition for leg in matrix_go), (
        f"the {gate} gate's condition ({condition!r}) references no current "
        f"matrix leg ({matrix_go}) — the gate would never run again"
    )


def test_govulncheck_gate_analyses_the_windows_build() -> None:
    """Dropping the GOOS=windows pass re-blinds the gate to its founding CVE.

    GO-2026-5024 was invisible to native analysis and only surfaced under
    GOOS=windows analysis of the released windows-amd64 binary.
    """
    run = str(_agent_step_running("govulncheck ./...").get("run", ""))
    assert "GOOS=windows" in run, (
        "the govulncheck gate lost its windows coverage — the class of "
        "vulnerability that motivated it (GO-2026-5024) only shows up there"
    )
    # Binary mode, not just source mode: `GOOS=windows govulncheck ./...` is a
    # build-constraint approximation, while -mode=binary audits an exe built
    # from the same package as the release artifact.
    assert "-mode=binary" in run, (
        "the govulncheck gate no longer analyses a built windows binary — "
        "source-mode-only coverage oversells what is being audited"
    )


def test_go_install_manager_matches_the_workflow() -> None:
    """The go-install customManager's regex must match agent-ci.yml.

    A regex matching nothing reports up-to-date forever (the Infisical mode),
    leaving the pinned govulncheck version frozen with no diagnostic.
    """
    managers = [
        m
        for m in _renovate_config().get("customManagers", [])
        if any("go install" in ms for ms in m.get("matchStrings", []))
        and any("workflows" in pat for pat in m.get("managerFilePatterns", []))
    ]
    assert managers, "renovate.json lost the workflow go-install customManager"
    workflow_text = (_WORKFLOWS / "agent-ci.yml").read_text(encoding="utf-8")
    for manager in managers:
        for match_string in manager["matchStrings"]:
            pattern = re.sub(r"\(\?<(\w+)>", r"(?P<\1>", match_string)
            found = re.search(pattern, workflow_text)
            assert found, f"go-install manager regex matches nothing: {match_string!r}"
            assert found.group("depName") == "golang.org/x/vuln"


def _workflow_files() -> list[Path]:
    """All workflow files, both extensions.

    renovate.json's workflows managerFilePatterns accept `ya?ml`; a guard that
    globs only `*.yml` would let a future `.yaml` workflow escape every assert
    while Renovate half-tracks it.
    """
    return sorted(p for ext in ("*.yml", "*.yaml") for p in _WORKFLOWS.glob(ext))


def _setup_uv_steps() -> list[tuple[str, dict[str, Any]]]:
    """Every (workflow-name, step) pair whose step uses astral-sh/setup-uv."""
    return [
        (wf.name, step)
        for wf in sorted(_workflow_files())
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
        for wf in _workflow_files()
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
    matches: dict[str, str] = {}
    for manager in managers:
        for match_string in manager["matchStrings"]:
            pattern = re.sub(r"\(\?<(\w+)>", r"(?P<\1>", match_string)
            found = list(re.finditer(pattern, makefile))
            assert found, (
                f"Makefile manager matchString matches nothing: {match_string!r} "
                "- an unmatched regex reports up-to-date forever"
            )
            matches.update((m.group("depName"), m.group("currentValue")) for m in found)
    assert "markdownlint-cli2" in matches, (
        "the Makefile manager regex no longer matches the markdownlint-cli2 "
        f"pin (matched: {matches or 'nothing'})"
    )
    # And the pin must actually be used by the recipe, not just declared.
    assert "markdownlint-cli2@$(MARKDOWNLINT_VERSION)" in makefile, (
        "lint-docs no longer interpolates MARKDOWNLINT_VERSION - the pin is decorative"
    )


def test_golangci_lint_doc_pin_matches_the_workflow_pin() -> None:
    """The contributor-doc install command must match the CI pin exactly.

    Both copies are Renovate-visible (agent-ci.yml via the annotation manager,
    CONTRIBUTING.md via its own customManager targeting the same depName), so
    one Renovate PR updates both. This guard is the belt-and-braces: if either
    manager silently stops matching — the Infisical failure mode — the copies
    drift and this fails loud instead.
    """
    doc = (_REPO_ROOT / "envdrift-agent" / "CONTRIBUTING.md").read_text(encoding="utf-8")
    doc_pin = re.search(r"golangci-lint/v2/cmd/golangci-lint@(v\d+\.\d+\.\d+)", doc)
    assert doc_pin, "CONTRIBUTING.md lost its pinned golangci-lint install command"

    workflow = (_WORKFLOWS / "agent-ci.yml").read_text(encoding="utf-8")
    ci_pin = re.search(r"depName=golangci/golangci-lint\s+version:\s*(v\d+\.\d+\.\d+)", workflow)
    assert ci_pin, "agent-ci.yml lost its annotated golangci-lint version"
    assert doc_pin.group(1) == ci_pin.group(1), (
        f"CONTRIBUTING.md installs golangci-lint {doc_pin.group(1)} but CI runs "
        f"{ci_pin.group(1)} — contributors would lint with a different toolchain"
    )

    # And the doc manager's regex must actually match the doc, or Renovate
    # will silently never update that copy.
    managers = [
        m
        for m in _renovate_config().get("customManagers", [])
        if any("CONTRIBUTING" in pat for pat in m.get("managerFilePatterns", []))
    ]
    assert managers, "renovate.json lost the CONTRIBUTING.md customManager"
    for manager in managers:
        for match_string in manager["matchStrings"]:
            pattern = re.sub(r"\(\?<(\w+)>", r"(?P<\1>", match_string)
            assert re.search(pattern, doc), (
                f"CONTRIBUTING.md manager regex matches nothing: {match_string!r} "
                "- Renovate would report up-to-date forever (the Infisical mode)"
            )
