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
from pathlib import Path
from typing import Any

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
