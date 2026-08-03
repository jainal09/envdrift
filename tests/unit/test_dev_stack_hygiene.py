"""Regression tests pinning local/CI dev-stack parity and Renovate copy (#500).

Two hygiene properties the repo must keep true:

- ``tests/docker-compose.test.yml`` and the ``integration-tests.yml`` service
  containers must pin the *same* image tags, so local runs exercise the same
  backends CI does. #332 established this once; CI-only Renovate bumps then
  re-diverged the stacks again (when #500 was filed the compose file ran
  localstack 4.0 against CI's 4.14; lowkey-vault had drifted the same way
  until #522/#543 re-aligned it at 7.3.0). Every stack image line carries a
  keep-in-sync pointer at its counterpart file, and ``renovate.json`` keeps
  the compose file Renovate-visible and groups the stack images so one
  Renovate PR moves both files together.
- The Renovate PR body template must describe the merge policy the repo
  actually enforces: ``automerge-version-bump.yml`` squash-merges minor/patch
  bumps with zero human review, so the template must not claim
  "Requires review and approval" for them.

These parse the real compose/workflow/Renovate files — no mocking of the
behavior under test.
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
_COMPOSE_PATH = _REPO_ROOT / "tests" / "docker-compose.test.yml"
_WORKFLOWS = _REPO_ROOT / ".github" / "workflows"
_INTEGRATION_WORKFLOW_PATH = _WORKFLOWS / "integration-tests.yml"
_AUTOMERGE_WORKFLOW_PATH = _WORKFLOWS / "automerge-version-bump.yml"
_RENOVATE_PATH = _REPO_ROOT / "renovate.json"

# The backends the integration suite drives (LocalStack/AWS, HashiCorp Vault,
# Lowkey-Vault/Azure). Both stacks must define all three.
_STACK_SERVICES = ("localstack", "vault", "lowkey-vault")
_STACK_IMAGES = frozenset({"localstack/localstack", "hashicorp/vault", "nagyesta/lowkey-vault"})

_IMAGE_LINE = re.compile(r"^\s*-?\s*image:\s")


def _service_images(services: dict[str, Any]) -> dict[str, str]:
    """Map service name -> image, skipping services without an ``image`` key.

    A ``build:``-only service defines no image pin, so there is nothing for
    the hygiene checks to compare; it must not crash them either.
    """
    return {
        name: svc["image"]
        for name, svc in services.items()
        if isinstance(svc, dict) and "image" in svc
    }


def _compose_images() -> dict[str, str]:
    compose = yaml.safe_load(_COMPOSE_PATH.read_text(encoding="utf-8"))
    return _service_images(compose["services"])


def _ci_service_images() -> dict[str, str]:
    workflow = yaml.safe_load(_INTEGRATION_WORKFLOW_PATH.read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    job = jobs.get("integration-tests")
    assert job is not None, (
        "integration-tests.yml no longer defines an 'integration-tests' job "
        f"(found: {sorted(jobs)}) — update _ci_service_images() in this file (#500)."
    )
    return _service_images(job["services"])


def _is_stack_image(image: str) -> bool:
    return image.rpartition(":")[0] in _STACK_IMAGES


def _carries_sync_pointer(lines: list[str], index: int, counterpart: str) -> bool:
    """True if ``lines[index]`` or the comment block directly above it names ``counterpart``."""
    block = [lines[index]]
    for candidate in reversed(lines[:index]):
        if not candidate.lstrip().startswith("#"):
            break
        block.append(candidate)
    return any(counterpart in line for line in block)


def _renovate_config() -> dict[str, Any]:
    return json.loads(_RENOVATE_PATH.read_text(encoding="utf-8"))


def test_service_images_skips_build_only_services() -> None:
    """A ``build:``-only service must be skipped, not crash the scan (#500)."""
    services = {
        "helper": {"build": "."},
        "localstack": {"image": "localstack/localstack:4.14"},
    }
    assert _service_images(services) == {"localstack": "localstack/localstack:4.14"}


def test_sync_pointer_found_in_comment_block_above_image_line() -> None:
    """The pointer counts anywhere in the comment block above the pin (#500)."""
    lines = [
        "  lowkey-vault:",
        "    # Keep in sync with integration-tests.yml.",
        "    # 7.3.0+ is required by the SDK api-version.",
        "    image: nagyesta/lowkey-vault:7.3.0",
    ]
    assert _carries_sync_pointer(lines, 3, "integration-tests.yml")
    assert not _carries_sync_pointer(lines, 3, "docker-compose.test.yml")


def test_compose_stack_pins_same_images_as_ci_service_containers() -> None:
    """Local compose images must equal the CI service-container images (#500).

    When #500 was filed the local stack ran localstack 4.0 — fourteen minors
    behind CI's 4.14 — so a locally-green integration run proved nothing
    about the backends CI exercises. #332 fixed the same drift once; CI-only
    Renovate bumps re-created it.
    """
    compose = _compose_images()
    ci = _ci_service_images()
    for service in _STACK_SERVICES:
        assert service in compose, (
            f"tests/docker-compose.test.yml lost the {service!r} service (#500)."
        )
        assert service in ci, (
            f"integration-tests.yml lost the {service!r} service container (#500)."
        )
    # Compare over the *union* of service names so a stack image added to only
    # one file is a failure, not a silent skip; services running a non-stack
    # image (e.g. a future dev-only helper) need no CI counterpart.
    mismatched: dict[str, dict[str, str | None]] = {}
    for service in sorted(set(compose) | set(ci)):
        images = (compose.get(service), ci.get(service))
        if not any(image and _is_stack_image(image) for image in images):
            continue
        if images[0] != images[1]:
            mismatched[service] = {"compose": images[0], "ci": images[1]}
    assert not mismatched, (
        "Local compose stack diverged from CI service containers (#500, "
        f"previously #332) — bump both together: {mismatched}"
    )


def test_every_image_pins_an_explicit_version_tag() -> None:
    """Every image in both files pins an explicit non-latest tag (#500).

    Deliberately broader than the ``_STACK_IMAGES`` scope the other checks
    use: tag parity is only meaningful with explicit pins, and *any* unpinned
    image — stack backend or future dev-only helper — makes the local stack
    non-reproducible. Unlike the keep-in-sync scan, every service can satisfy
    this by simply pinning a tag, so the broad scope cannot force a spurious
    failure on a service that has no counterpart file.
    """
    for source, images in (
        ("tests/docker-compose.test.yml", _compose_images()),
        ("integration-tests.yml", _ci_service_images()),
    ):
        for service, image in images.items():
            repository, _, tag = image.rpartition(":")
            assert repository and tag and tag != "latest", (
                f"{source}: service {service!r} image {image!r} must pin an "
                "explicit version tag (#500)."
            )


def test_every_stack_image_line_carries_keep_in_sync_pointer() -> None:
    """Each stack image line names its counterpart file in a comment (#500).

    Pre-fix only the CI vault entry carried a keep-in-sync comment; the other
    five image lines gave a human editor (or a reviewer of a Renovate diff)
    no hint that a second copy of the pin exists. Only lines pinning one of
    the ``_STACK_IMAGES`` need the pointer — a dev-only service running some
    other image has no counterpart to stay in sync with. The pointer may sit
    inline or anywhere in the comment block directly above the image line.
    """
    missing: list[str] = []
    for path, counterpart in (
        (_COMPOSE_PATH, "integration-tests.yml"),
        (_INTEGRATION_WORKFLOW_PATH, "docker-compose.test.yml"),
    ):
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if not _IMAGE_LINE.match(line):
                continue
            if not any(repository in line for repository in _STACK_IMAGES):
                continue
            if not _carries_sync_pointer(lines, index, counterpart):
                missing.append(f"{path.name}:{index + 1}: {line.strip()}")
    assert not missing, (
        "Every stack image line must carry a keep-in-sync comment naming the "
        f"counterpart file (#500): {missing}"
    )


def test_renovate_ignore_paths_keep_the_compose_file_visible() -> None:
    """Renovate must extract deps from tests/docker-compose.test.yml (#500).

    The repo extends ``config:recommended``, which pulls in
    ``:ignoreModulesAndTests`` and its ``ignorePaths`` entry ``**/tests/**``
    — skipping every package file under tests/ *before* dependency
    extraction. The only local copy of the stack pins lives there, so without
    a repo-level ``ignorePaths`` override Renovate would bump the CI workflow
    but never the compose file, and the parity test above would fail on every
    stack bump instead of producing one auto-mergeable grouped PR.
    """
    ignore_paths = _renovate_config().get("ignorePaths")
    assert ignore_paths is not None, (
        "renovate.json must override ignorePaths: config:recommended's "
        ":ignoreModulesAndTests preset ignores **/tests/**, hiding "
        "tests/docker-compose.test.yml from Renovate entirely (#500)."
    )
    offending = [pattern for pattern in ignore_paths if "tests/**" in pattern]
    assert not offending, (
        f"renovate.json ignorePaths {offending} would hide "
        "tests/docker-compose.test.yml from Renovate — the compose stack pins "
        "must stay Renovate-visible (#500)."
    )


def test_renovate_groups_stack_images_across_both_files() -> None:
    """Renovate must group the stack image bumps into one branch (#500).

    Pre-fix nothing tied the two copies of each pin together, so Renovate
    bumps landed in CI only and the stacks re-diverged (the regression #332
    had already fixed). A ``groupName`` rule over the three docker packages
    makes a single Renovate PR move tests/docker-compose.test.yml and
    integration-tests.yml together.
    """
    rules = _renovate_config().get("packageRules", [])
    grouping = [
        rule
        for rule in rules
        if rule.get("groupName")
        and "docker" in rule.get("matchDatasources", [])
        and _STACK_IMAGES.issubset(rule.get("matchPackageNames", []))
    ]
    assert grouping, (
        "renovate.json must contain a packageRule grouping the integration "
        f"stack images {sorted(_STACK_IMAGES)} (matchDatasources: docker, "
        "groupName) so one PR bumps the compose file and the CI workflow "
        "together (#500)."
    )


def test_renovate_pr_body_copy_matches_automerge_reality() -> None:
    """The Renovate PR body must describe the real merge policy (#500).

    automerge-version-bump.yml squash-merges every ``minor-version-bump``
    labeled PR once CI is green — branch protection requires zero approvals —
    yet pre-fix every PR body claimed "Minor/Patch updates: Requires review
    and approval". The copy must match the automation it documents.
    """
    automerge = _AUTOMERGE_WORKFLOW_PATH.read_text(encoding="utf-8")
    # The premise: the workflow really does merge minor/patch bumps unreviewed.
    assert "minor-version-bump" in automerge and "pulls.merge" in automerge, (
        "automerge-version-bump.yml no longer auto-merges minor-version-bump "
        "PRs — update this test AND the renovate.json prBodyTemplate copy "
        "together (#500)."
    )

    body = _renovate_config()["prBodyTemplate"]
    lines = [line for line in body.splitlines() if line.strip()]
    minor_lines = [line for line in lines if "Minor/Patch" in line]
    major_lines = [line for line in lines if "Major" in line]
    assert minor_lines and major_lines, (
        "renovate.json prBodyTemplate must document both the Minor/Patch and "
        "the Major update policy (#500)."
    )
    for line in minor_lines:
        assert "requires review" not in line.lower(), (
            f"prBodyTemplate claims review for minor/patch bumps ({line!r}) "
            "but automerge-version-bump.yml merges them with zero human "
            "review (#500)."
        )
        assert re.search(r"auto-?merge", line, re.IGNORECASE), (
            f"prBodyTemplate minor/patch line ({line!r}) must state that the "
            "automerge-version-bump workflow merges these once CI passes "
            "(#500)."
        )
    for line in major_lines:
        assert re.search(r"manual review", line, re.IGNORECASE), (
            f"prBodyTemplate major line ({line!r}) must keep requiring manual "
            "review — automerge-version-bump.yml refuses major bumps (#500)."
        )


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


def test_localstack_pins_the_canonical_calver_form() -> None:
    """LocalStack must stay on the canonical zero-padded CalVer tag.

    Upstream publishes 2026.07.1 alongside equivalent aliases (2026.7.1,
    2026.07, 2026) that Renovate's docker versioning treats as EQUAL, so
    without an allowedVersions constraint the pinned literal can silently flip
    form between bumps and desynchronise the two stack files.

    The constraint also blocks a regression to the pre-2026.03 4.x line. 4.14.0
    was the last tokenless release; everything after it is account-gated.
    """
    rules = _renovate_config().get("packageRules", [])
    guard = [
        rule
        for rule in rules
        if "localstack/localstack" in rule.get("matchPackageNames", [])
        and "allowedVersions" in rule
    ]
    assert guard, (
        "renovate.json must constrain localstack/localstack with allowedVersions "
        "so the CalVer tag literal cannot flip between equivalent forms."
    )
    pattern = guard[0]["allowedVersions"].strip("/")
    assert re.fullmatch(pattern, "2026.07.1"), (
        f"allowedVersions {pattern!r} rejects the canonical padded form"
    )
    assert not re.fullmatch(pattern, "2026.7.1"), (
        f"allowedVersions {pattern!r} admits the unpadded alias"
    )

    for source, images in (
        ("tests/docker-compose.test.yml", _compose_images()),
        ("integration-tests.yml", _ci_service_images()),
    ):
        _, _, tag = images.get("localstack", "").rpartition(":")
        assert re.fullmatch(pattern, tag), (
            f"{source}: localstack tag {tag!r} is not the canonical CalVer form."
        )


# Services the free Hobby tier actually exposes, confirmed 2026-08-02 by
# booting localstack/localstack:2026.07.1 with a Hobby token and reading
# /_localstack/health. Anything outside this set needs a PAID plan.
_HOBBY_TIER_SERVICES = frozenset({"kms", "lambda", "s3", "secretsmanager", "sts"})


def _declared_services() -> dict[str, set[str]]:
    """SERVICES declared for localstack in the compose file and the CI job."""
    compose = yaml.safe_load(_COMPOSE_PATH.read_text(encoding="utf-8"))
    env = compose["services"]["localstack"]["environment"]
    # compose uses a KEY=VALUE list; the workflow uses a mapping.
    compose_services = ""
    for item in env:
        if isinstance(item, str) and item.startswith("SERVICES="):
            compose_services = item.split("=", 1)[1]

    workflow = yaml.safe_load(_INTEGRATION_WORKFLOW_PATH.read_text(encoding="utf-8"))
    ci_env = workflow["jobs"]["integration-tests"]["services"]["localstack"]["env"]
    return {
        "tests/docker-compose.test.yml": {
            s.strip() for s in compose_services.split(",") if s.strip()
        },
        "integration-tests.yml": {
            s.strip() for s in str(ci_env.get("SERVICES", "")).split(",") if s.strip()
        },
    }


def test_localstack_services_stay_within_the_free_hobby_tier() -> None:
    """Never enable a LocalStack service that requires a paid plan.

    LocalStack is account-gated since 2026.03.0 and this project runs on the
    free Hobby tier. Hobby covers a subset of services; enabling one outside it
    would make the stack silently require a paid licence — breaking CI for
    anyone without one, including every fork.
    """
    for source, services in _declared_services().items():
        assert services, f"{source}: localstack declares no SERVICES"
        paid_only = sorted(services - _HOBBY_TIER_SERVICES)
        assert not paid_only, (
            f"{source}: SERVICES includes {paid_only}, which the free Hobby tier "
            f"does not provide. Hobby exposes {sorted(_HOBBY_TIER_SERVICES)}. "
            "Adding a paid-tier service would require a paid LocalStack plan."
        )


# A committed LocalStack token. Deliberately NOT anchored on a trailing hyphen:
# real tokens are `ls-` followed by an opaque suffix that may be entirely
# alphanumeric, so requiring a second hyphen missed a whole class of leak.
_LITERAL_TOKEN = re.compile(r"ls-[A-Za-z0-9]{8,}")


def _localstack_env() -> dict[str, dict[str, str]]:
    """The localstack environment as PARSED config, not raw text.

    Parsing matters: a raw-text search for "LOCALSTACK_AUTH_TOKEN" is satisfied
    by the surrounding comments alone, so the guard would still pass if the
    actual setting were deleted.
    """
    compose = yaml.safe_load(_COMPOSE_PATH.read_text(encoding="utf-8"))
    raw_env = compose["services"]["localstack"]["environment"]
    compose_env: dict[str, str] = {}
    for item in raw_env:  # compose uses a KEY=VALUE list
        if isinstance(item, str) and "=" in item:
            key, _, value = item.partition("=")
            compose_env[key.strip()] = value

    workflow = yaml.safe_load(_INTEGRATION_WORKFLOW_PATH.read_text(encoding="utf-8"))
    ci_env = workflow["jobs"]["integration-tests"]["services"]["localstack"]["env"]
    return {
        "tests/docker-compose.test.yml": compose_env,
        "integration-tests.yml": {k: str(v) for k, v in ci_env.items()},
    }


def test_localstack_requires_an_auth_token_in_both_stacks() -> None:
    """Both stacks must actually SET LOCALSTACK_AUTH_TOKEN, not just mention it."""
    for source, env in _localstack_env().items():
        assert "LOCALSTACK_AUTH_TOKEN" in env, (
            f"{source}: localstack does not set LOCALSTACK_AUTH_TOKEN. The "
            "container exits(55) without it since LocalStack 2026.03.0."
        )
        value = env["LOCALSTACK_AUTH_TOKEN"]
        assert value.strip(), f"{source}: LOCALSTACK_AUTH_TOKEN is set but empty."
        # Must be indirected through the environment or a GitHub secret.
        assert value.lstrip().startswith("${"), (
            f"{source}: LOCALSTACK_AUTH_TOKEN must be interpolated from the "
            f"environment or a repository secret, got {value[:40]!r}."
        )


def test_no_literal_localstack_token_is_committed() -> None:
    """A real token must never appear in the stack files."""
    for source, path in (
        ("tests/docker-compose.test.yml", _COMPOSE_PATH),
        ("integration-tests.yml", _INTEGRATION_WORKFLOW_PATH),
        (".gitignore", _REPO_ROOT / ".gitignore"),
    ):
        text = path.read_text(encoding="utf-8")
        assert not _LITERAL_TOKEN.search(text), (
            f"{source}: a literal LocalStack token appears to be committed. "
            "Tokens must come from the environment or a repository secret."
        )


def test_literal_token_matcher_actually_matches_a_token() -> None:
    """Guard the guard: a matcher that matches nothing is worse than none.

    The previous pattern required a hyphen AFTER the suffix, so an
    all-alphanumeric token was invisible to it. The sample below is assembled
    by concatenation so the whole literal never appears in source (GitHub push
    protection rejects realistic secret literals).
    """
    hyphenated = "ls-" + "sAQofABI" + "-cubI-9429"
    alphanumeric = "ls-" + "abc123def456ghi"
    for sample in (hyphenated, alphanumeric):
        assert _LITERAL_TOKEN.search(f"  - LOCALSTACK_AUTH_TOKEN={sample}\n"), (
            f"the literal-token matcher fails to detect {sample[:6]}... — a "
            "committed token of this shape would slip through."
        )
    # ...and it must not fire on the legitimate interpolated form.
    assert not _LITERAL_TOKEN.search("- LOCALSTACK_AUTH_TOKEN=${LOCALSTACK_AUTH_TOKEN:?msg}")


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


def test_manager_repo_matches_the_configured_download_url() -> None:
    """``depNameTemplate`` must be the same repo the download URLs point at.

    A mismatch means Renovate watches releases in one repository while the
    installer downloads from another — the pin then tracks a stream that has
    nothing to do with the artifact actually installed.
    """
    constants = _constants()
    for manager in _github_managers():
        tool = _tool_for_manager(manager)
        urls = constants.get(f"{tool}_download_urls") if tool else None
        if not urls:
            continue
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
        urls = constants.get(f"{tool}_download_urls") if tool else None
        extract = manager.get("extractVersionTemplate")
        if not urls or not extract:
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


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("gh") is None, reason="gh CLI not installed")
def test_every_manager_matches_a_real_upstream_tag() -> None:
    """Each manager must match tags the configured repo ACTUALLY publishes.

    This is the regression test for the Infisical freeze, and it is the only
    check here that would have failed before that fix: the static guards all
    passed on the broken config because the manager was self-consistent. What
    it was not, was connected to reality — ``Infisical/infisical`` had stopped
    publishing ``infisical-cli/v*`` tags entirely, so the regex matched none of
    the 100 most recent releases and Renovate had nothing to compare the pin
    against.

    Network-gated (integration marker + ``gh``) because it queries GitHub.
    """
    for manager in _github_managers():
        repo = manager["depNameTemplate"]
        extract = manager.get("extractVersionTemplate")
        if not extract:
            continue
        result = subprocess.run(
            ["gh", "api", f"repos/{repo}/releases?per_page=100", "--jq", ".[].tag_name"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if result.returncode != 0:
            pytest.skip(f"could not query {repo} releases: {result.stderr[:120]}")

        tags = [t for t in result.stdout.split() if t]
        assert tags, f"{repo} published no releases at all"

        py_extract = re.sub(r"\(\?<(\w+)>", r"(?P<\1>", extract)
        matching = [t for t in tags if re.match(py_extract, t)]
        assert matching, (
            f"{repo}: extractVersionTemplate {extract!r} matches NONE of the "
            f"{len(tags)} most recent release tags (e.g. {tags[:3]}). Renovate "
            "cannot extract a version, so this pin is frozen with no diagnostic "
            "— exactly how infisical sat at 0.41.90 after the CLI moved repos."
        )
