"""Regression tests pinning user docs to real CLI/library behavior (#413).

These assert the *rendered* docs match what the code actually produces, so the
docs can't drift back to the stale state the audit found:

- ``docs/cli/decrypt.md`` must not hardcode a dotenvx version (it comes from
  ``constants.json`` / Renovate) — CLAUDE.md: never hardcode binary versions.
- ``docs/cli/push.md``'s warning-header example must match the generated header
  ``_build_warning_header`` emits verbatim (correct "To make changes:" order).
- ``docs/cli/init.md`` must document the real ``--force`` / ``-f`` option and the
  "already exists" error the command actually prints.
- ``docs/cli/sync.md`` must not claim ``vault_name`` overrides/routes to another
  vault (the sync/push engine ignores it).

They read the real files — no mocking of the behavior under test.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from envdrift.core.partial_encryption import _build_warning_header
from envdrift.integrations.dotenvx import DOTENVX_VERSION

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DOCS = _REPO_ROOT / "docs" / "cli"


def _read(name: str) -> str:
    return (_DOCS / name).read_text(encoding="utf-8")


def test_decrypt_md_does_not_hardcode_dotenvx_version() -> None:
    """decrypt.md must not embed a concrete dotenvx version (#413).

    Pre-fix the doc showed ``--version=1.70.0`` while the install hint emits the
    pinned version from constants.json. Hardcoding any literal version drifts the
    moment Renovate bumps it, so the doc must use a placeholder instead.
    """
    text = _read("decrypt.md")
    # A concrete dotenvx version literal next to the install command is the bug.
    leaks = re.findall(r"--version=\d+\.\d+\.\d+", text)
    assert not leaks, (
        f"decrypt.md hardcodes a dotenvx version {leaks}; use a placeholder and "
        "let envdrift fill the pinned version from constants.json (#413)."
    )
    # The current pinned version must also not appear anywhere as a bare literal.
    assert DOTENVX_VERSION not in text, (
        f"decrypt.md contains the literal pinned version {DOTENVX_VERSION!r}; "
        "it must reference constants.json, not a hardcoded value (#413)."
    )
    # The placeholder the code substitutes into must be documented.
    assert "<pinned version>" in text


def test_push_md_warning_header_matches_generated_header() -> None:
    """push.md's example header must match the real generated header (#413).

    Pre-fix the doc's "To make changes:" block listed edit-clear/edit-secret
    before ``pull-partial``, but the code emits ``pull-partial`` first. Each
    instruction line of the generated header must appear verbatim in the doc.
    """
    generated = _build_warning_header(".env.production.clear", ".env.production.secret")
    text = _read("push.md")

    instruction_lines = [
        "  1. Run:  envdrift pull-partial (decrypts the .secret file)",
        "  2. Edit: .env.production.clear",
        "  3. Edit: .env.production.secret",
        "  4. Run:  envdrift push (re-encrypts .secret and regenerates this)",
    ]
    # Sanity: the lines we assert on are really the ones the code generates,
    # in this exact order.
    last = -1
    for line in instruction_lines:
        idx = generated.find(line)
        assert idx != -1, f"generated header changed: missing {line!r}"
        assert idx > last, f"generated header reordered around {line!r}"
        last = idx

    # The doc must contain each instruction verbatim *and in the same order* the
    # code emits them (ignoring the box border), so a reordered push.md example
    # fails the test instead of silently drifting from _build_warning_header.
    last = -1
    for line in instruction_lines:
        idx = text.find(line)
        assert idx != -1, (
            f"push.md is missing the generated header line {line!r} (#413); the "
            "documented 'To make changes:' order must match _build_warning_header."
        )
        assert idx > last, (
            f"push.md lists {line!r} out of order (#413); the documented "
            "'To make changes:' steps must appear in the same order the code emits."
        )
        last = idx


def test_init_md_documents_force_option() -> None:
    """init.md must document the real --force/-f option and its error (#413)."""
    text = _read("init.md")
    assert "--force" in text and "-f" in text, (
        "init.md omits the --force/-f option that init actually supports (#413)."
    )
    # The exact 'already exists' remedy the command prints must be documented.
    assert "Output file already exists" in text
    assert "use --force to overwrite" in text


def test_init_md_documents_leading_underscore_aliasing() -> None:
    """init.md must document leading-underscore keys as aliased, not bare (#467/#460).

    #460 made ``init`` sanitize a key that natively starts with ``_`` (e.g.
    ``_PRIVATE``) because Pydantic rejects field names with a leading underscore.
    Such a key passes ``str.isidentifier()``, so the old blanket claim ("a key
    that passes ``str.isidentifier()`` becomes a bare field with no alias") was
    wrong for it. Pin the doc to the REAL sanitizer output so it can't drift back.
    """
    from envdrift.cli_commands.init_cmd import _sanitize_identifier

    text = _read("init.md")

    # Ground truth from the real sanitizer: a leading-underscore key is aliased,
    # while a valid non-ASCII identifier (CAFÉ) stays bare.
    assert _sanitize_identifier("_PRIVATE") == "field__PRIVATE"
    assert _sanitize_identifier("CAFÉ") == "CAFÉ"

    # The doc must show that exact aliasing, matching the generated field line.
    assert "field__PRIVATE: str = Field(alias='_PRIVATE')" in text, (
        "init.md must document that a leading-underscore key like _PRIVATE is "
        "aliased (field__PRIVATE), not emitted as a bare field (#467/#460)."
    )
    # The 'kept verbatim' claim must now carve out leading-underscore keys rather
    # than make a blanket isidentifier() statement.
    assert "does not start with `_`" in text, (
        "init.md's 'kept verbatim' claim must exclude leading-underscore keys (#467)."
    )


def test_sync_md_does_not_claim_vault_name_routes() -> None:
    """sync.md must not claim vault_name overrides/routes to another vault (#413).

    The sync/push engine fetches/pushes every secret from the single configured
    client, so vault_name is informational only. The doc must say so and must not
    use the old misleading "Override default" phrasing.
    """
    text = _read("sync.md")
    assert "informational only" in text, (
        "sync.md must state vault_name is informational only (#413)."
    )
    # Both phrases are part of the documented fix, so require each independently —
    # an `or` would let a future edit drop one of them silently.
    assert "does NOT route" in text, (
        "sync.md must contain 'does NOT route' to clarify vault_name behaviour (#413)."
    )
    assert "do not switch the vault" in text, (
        "sync.md must contain 'do not switch the vault' in the admonition title (#413)."
    )
    # The old misleading inline comment must be gone.
    assert "# Override default\n" not in text


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
