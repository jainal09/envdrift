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

import contextlib
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
# booting localstack/localstack:2026.07.4 with a Hobby token and reading
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
    # Obviously-synthetic on purpose. The matcher only needs the SHAPE
    # (`ls-` + 8 or more alphanumerics, optionally hyphenated), and a sample
    # that reads like plausible token material invites secret-scanner noise and
    # copy/paste confusion — in the very test whose job is keeping real tokens
    # out of the tree. Still assembled by concatenation so no whole literal
    # appears in source.
    hyphenated = "ls-" + "testABCD" + "-fake-0000"
    alphanumeric = "ls-" + "examplefake9999"
    for sample in (hyphenated, alphanumeric):
        assert _LITERAL_TOKEN.search(f"  - LOCALSTACK_AUTH_TOKEN={sample}\n"), (
            f"the literal-token matcher fails to detect {sample[:6]}... — a "
            "committed token of this shape would slip through."
        )
    # ...and it must not fire on the legitimate interpolated form.
    assert not _LITERAL_TOKEN.search("- LOCALSTACK_AUTH_TOKEN=${LOCALSTACK_AUTH_TOKEN:?msg}")


# The endpoint both stacks' LocalStack health checks must probe: the gateway
# port and health path, as seen from inside the container.
_LOCALSTACK_HEALTH_URL = "http://localhost:4566/_localstack/health"


def _healthcheck_argv(test: object) -> list[str]:
    """The argv Docker runs for a compose ``healthcheck.test`` value.

    ``["CMD", *argv]`` is exec form. ``["CMD-SHELL", cmd]`` and a bare string go
    through ``/bin/sh -c``; ``shlex.split`` is that shell's word splitting for
    the plain quoting a health command uses.
    """
    match test:
        case str():
            return shlex.split(test)
        case ["CMD", *argv]:
            return [str(arg) for arg in argv]
        case ["CMD-SHELL", str(command)]:
            return shlex.split(command)
    raise AssertionError(f"unsupported compose healthcheck test: {test!r}")


def _localstack_healthchecks() -> dict[str, list[str]]:
    """The LocalStack health-check argv that each stack makes Docker run."""
    compose = yaml.safe_load(_COMPOSE_PATH.read_text(encoding="utf-8"))
    compose_test = compose["services"]["localstack"].get("healthcheck", {}).get("test")
    assert compose_test, "tests/docker-compose.test.yml: localstack has no healthcheck test."

    workflow = yaml.safe_load(_INTEGRATION_WORKFLOW_PATH.read_text(encoding="utf-8"))
    options = workflow["jobs"]["integration-tests"]["services"]["localstack"].get("options", "")
    # The runner hands `options` to `docker create`, which stores --health-cmd
    # as CMD-SHELL: the value runs through /bin/sh -c inside the container.
    tokens = shlex.split(options)
    health_cmds = []
    for index, token in enumerate(tokens):
        if token.startswith("--health-cmd="):
            health_cmds.append(token.partition("=")[2])
        elif token == "--health-cmd" and index + 1 < len(tokens):
            health_cmds.append(tokens[index + 1])
    assert len(health_cmds) == 1, (
        f"integration-tests.yml: expected one localstack --health-cmd, got {health_cmds}."
    )
    return {
        "tests/docker-compose.test.yml": _healthcheck_argv(compose_test),
        "integration-tests.yml": shlex.split(health_cmds[0]),
    }


def test_localstack_healthcheck_uses_python3_not_curl() -> None:
    """The LocalStack health check must run python3: the image has no curl.

    Since 2026.10.0 the localstack/localstack image installs curl only to
    download Node.js and purges it in the same layer (there is no wget
    either), so the old ``curl -f .../_localstack/health`` probe exits 127
    ("curl: not found") on every attempt. The service container never turns
    healthy and all four Integration Tests jobs die at "Initialize containers"
    although LocalStack logs "Ready." (Renovate's 2026.09.1 -> 2026.10.4 bump,
    PR #883). The image's own HEALTHCHECK moved to python3 in the same
    release; python3 is the interpreter LocalStack itself runs on.
    """
    for source, argv in _localstack_healthchecks().items():
        assert argv[:2] == ["python3", "-c"], (
            f"{source}: the localstack health check runs {argv[:2]}, but the "
            "LocalStack image ships no curl or wget since 2026.10. Probe with "
            "`python3 -c`, as the image's own HEALTHCHECK does."
        )
        assert argv[-1] == _LOCALSTACK_HEALTH_URL, (
            f"{source}: the localstack health check must end with the URL it "
            f"probes, {_LOCALSTACK_HEALTH_URL} (got {argv[-1]!r})."
        )


def test_localstack_healthcheck_is_identical_in_both_stacks() -> None:
    """Compose and CI must probe LocalStack with the same command (#500 parity).

    CI only ever runs the workflow's copy; the compose copy runs only under
    ``make test-integration-up`` (``--wait``). A probe fixed in one file and
    not the other leaves the second broken with nothing to flag it.
    """
    checks = _localstack_healthchecks()
    assert len({tuple(argv) for argv in checks.values()}) == 1, (
        f"The localstack health checks differ between the stacks: {checks}"
    )


@contextlib.contextmanager
def _health_endpoint(status: int) -> Iterator[str]:
    """Serve ``status`` for /_localstack/health on an ephemeral localhost port."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # http.server handler API name
            body = b'{"services": {"secretsmanager": "running"}}'
            self.send_response(status if self.path == "/_localstack/health" else 404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/_localstack/health"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _unused_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _run_localstack_probes(url: str) -> dict[str, subprocess.CompletedProcess[str]]:
    """Run each stack's committed LocalStack probe against ``url``.

    Only the interpreter (the host may have no ``python3`` on PATH) and the
    target URL are swapped. A dead HTTP proxy is configured and no_proxy is
    cleared: Docker can inject proxy variables into containers, and the probe
    must still reach the local gateway directly.
    """
    dead_proxy = f"http://127.0.0.1:{_unused_local_port()}"
    env = {
        key: value
        for key, value in os.environ.items()
        if key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}
    }
    env["HTTP_PROXY"] = env["HTTPS_PROXY"] = dead_proxy
    results = {}
    for source, argv in _localstack_healthchecks().items():
        assert argv[:2] == ["python3", "-c"] and argv[-1] == _LOCALSTACK_HEALTH_URL, (
            f"{source}: not a `python3 -c <code> {_LOCALSTACK_HEALTH_URL}` probe: {argv}"
        )
        results[source] = subprocess.run(
            [sys.executable, *argv[1:-1], url],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    return results


@pytest.mark.parametrize(("status", "healthy"), [(200, True), (503, False)])
def test_localstack_probe_passes_only_on_a_2xx_health_response(status: int, healthy: bool) -> None:
    """The probe must fail closed like ``curl -f`` did: healthy on 2xx only.

    A probe that cannot fail (one ending in ``|| exit 0``, say) would let CI
    run the suite against a LocalStack that never came up.
    """
    with _health_endpoint(status) as url:
        results = _run_localstack_probes(url)
    for source, result in results.items():
        assert (result.returncode == 0) is healthy, (
            f"{source}: probe exited {result.returncode} for HTTP {status} "
            f"(expected {'success' if healthy else 'failure'}): {result.stderr[-500:]}"
        )


def test_localstack_probe_fails_when_nothing_listens() -> None:
    """Before the gateway binds :4566 the probe must report unhealthy."""
    url = f"http://127.0.0.1:{_unused_local_port()}/_localstack/health"
    for source, result in _run_localstack_probes(url).items():
        assert result.returncode != 0, f"{source}: probe passed with nothing listening."
