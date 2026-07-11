"""Regression tests pinning user docs to real CLI/library behavior (#413, #498, #499).

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

Plus the #498 sweep — recipes/keys the shipped tools reject or ignore:

- ``docs/support/faq.md``'s CI decrypt recipe must write the environment-suffixed
  ``DOTENV_PRIVATE_KEY_PRODUCTION`` (a bare ``DOTENV_PRIVATE_KEY`` can never
  decrypt ``.env.production``).
- ``docs/guides/env-file-sync.md`` must not advertise dotenvx v1's removed
  local rotation command; dotenvx v2 has no safe drop-in replacement.
- no docs page may mention the fabricated ``DOTENV_KEYS_PATH`` variable.
- ``docs/reference/configuration.md`` (and the in-source ``EXAMPLE_CONFIG``)
  must not document ``[envdrift] schema``/``environments`` or ``[precommit]`` —
  nothing consumes them.
- ``docs/reference/api.md`` must describe ``init()``'s real alias-everything
  behavior, not the stale skip-and-UserWarning contract.

And the #499 sweep — examples that contradicted live library/CLI behavior:

- the nested-settings FAQ must configure Pydantic's ``env_nested_delimiter``;
- dotenvx examples must show every value encrypted and the suffixed public key;
- sync mismatch previews must be redacted and backup names include microseconds;
- guard docs must identify unencrypted environment files as HIGH / exit 2.

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
_DOCS_ROOT = _REPO_ROOT / "docs"


def _read(name: str) -> str:
    return (_DOCS / name).read_text(encoding="utf-8")


def _read_docs_page(relpath: str) -> str:
    return (_DOCS_ROOT / relpath).read_text(encoding="utf-8")


def test_faq_nested_settings_recipe_configures_delimiter(monkeypatch: pytest.MonkeyPatch) -> None:
    """The FAQ recipe must load DATABASE__* through Pydantic's real delimiter (#499)."""
    from pydantic_settings import BaseSettings, SettingsConfigDict

    class DatabaseSettings(BaseSettings):
        URL: str
        POOL_SIZE: int = 5

    class Settings(BaseSettings):
        model_config = SettingsConfigDict(env_nested_delimiter="__")

        DATABASE: DatabaseSettings

    monkeypatch.setenv("DATABASE__URL", "postgres://example.test/app")
    monkeypatch.setenv("DATABASE__POOL_SIZE", "10")
    settings = Settings()
    assert settings.DATABASE.URL == "postgres://example.test/app"
    assert settings.DATABASE.POOL_SIZE == 10

    text = _read_docs_page("support/faq.md")
    assert "from pydantic_settings import BaseSettings, SettingsConfigDict" in text
    assert 'SettingsConfigDict(env_nested_delimiter="__")' in text


@pytest.mark.parametrize(
    ("relpath", "expected_debug"),
    [
        ("getting-started/quickstart.md", "DEBUG=encrypted:BD2QpRf..."),
        ("guides/encryption.md", "DEBUG=encrypted:BDQEfalse1234567890..."),
        ("concepts/encryption-backends.md", "DEBUG=encrypted:BD2QpRf..."),
        ("concepts/index.md", "DEBUG=encrypted:..."),
        ("cli/encrypt.md", "DEBUG=encrypted:BDQEfalse1234567890..."),
    ],
)
def test_dotenvx_examples_encrypt_every_value(relpath: str, expected_debug: str) -> None:
    """Every dotenvx example must encrypt DEBUG instead of teaching selectivity (#499)."""
    text = _read_docs_page(relpath)
    assert expected_debug in text, f"{relpath} must show dotenvx encrypting DEBUG"

    if relpath in {"getting-started/quickstart.md", "concepts/encryption-backends.md"}:
        assert not re.search(r"(?m)^DOTENV_PUBLIC_KEY=", text), (
            f"{relpath} must suffix the dotenvx public-key name with the environment"
        )


def test_sync_examples_redact_values_and_show_collision_safe_backup_name() -> None:
    """sync.md must mirror the redaction and microsecond backup contracts (#499)."""
    from envdrift.sync.operations import redact_value

    # Ground truth: real previews never contain plaintext and use this shape.
    preview = redact_value("a" * 64)
    assert preview is not None
    assert re.fullmatch(r"<redacted len=64 sha=[0-9a-f]{8}>", preview)

    text = _read("sync.md")
    assert "abc123def456..." not in text
    assert "xyz789abc012..." not in text
    assert len(re.findall(r"Local:\s+<redacted len=64 sha=[0-9a-f]{8}>", text)) >= 2
    assert len(re.findall(r"Vault:\s+<redacted len=64 sha=[0-9a-f]{8}>", text)) >= 2
    assert re.search(r"\.env\.keys\.backup\.\d{8}_\d{6}_\d{6}", text)


def test_guard_docs_classify_unencrypted_env_as_high(tmp_path: Path) -> None:
    """guard.md must match the native rule's HIGH severity and exit 2 (#499)."""
    from envdrift.scanner.base import FindingSeverity
    from envdrift.scanner.native import NativeScanner

    env_file = tmp_path / ".env"
    env_file.write_text("FOO=bar\nGREETING=hello\n", encoding="utf-8")
    result = NativeScanner().scan([tmp_path])
    finding = next(f for f in result.findings if f.rule_id == "unencrypted-env-file")
    assert finding.severity == FindingSeverity.HIGH

    text = _read("guard.md")
    assert "An unencrypted environment file is HIGH" in text
    assert "| 2 | High findings (including unencrypted environment files) |" in text
    assert "Low findings (policy violations, e.g. unencrypted file)" not in text

    base_text = (_REPO_ROOT / "src" / "envdrift" / "scanner" / "base.py").read_text(
        encoding="utf-8"
    )
    assert "LOW: Policy violation (e.g., unencrypted file)" not in base_text


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


def test_init_md_qualifies_nfkc_aliasing() -> None:
    """init.md's 'kept verbatim' bullet must carve out non-NFKC keys too (#469).

    Python folds identifiers with NFKC at compile time, so ``_resolve_field_name``
    aliases any key whose NFKC fold differs from the raw key (an NFD-composed
    ``CAFÉ``, the ligature ``ﬁle``) even though it passes ``str.isidentifier()``
    and has no leading underscore. The doc's case analysis must not send such a
    key to the bare-field bullet. Ground truth is the REAL resolver.
    """
    import unicodedata

    from envdrift.cli_commands.init_cmd import _resolve_field_name

    nfc_cafe = unicodedata.normalize("NFC", "CAFÉ")
    nfd_cafe = unicodedata.normalize("NFD", "CAFÉ")
    ligature = "ﬁle"  # "ﬁle" — NFKC-folds to "file"

    # Real behavior: NFC stays bare; NFD/ligature keys are aliased.
    assert _resolve_field_name(nfc_cafe, set()) == (nfc_cafe, None)
    assert _resolve_field_name(nfd_cafe, set()) == (nfd_cafe, nfd_cafe)
    assert _resolve_field_name(ligature, set()) == (ligature, ligature)

    text = _read("init.md")
    assert "NFKC-normalized" in text, (
        "init.md's 'kept verbatim' bullet must require the key to be "
        "NFKC-normalized — an NFD/ligature key is aliased (#469)."
    )
    assert "NFKC at compile time" in text, (
        "init.md must explain WHY (Python NFKC-folds identifiers at compile "
        "time), as _resolve_field_name's docstring does (#469)."
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


@pytest.mark.parametrize("doc", ["push.md", "encrypt.md"])
def test_doc_documents_unsafe_filename_refusal(doc: str) -> None:
    """push.md/encrypt.md must document the unsafe-filename lockout guard (#467).

    #457 made the bare ``encrypt`` backend refuse filenames dotenvx cannot turn
    into a valid ``DOTENV_PRIVATE_KEY_<SLUG>`` name (the value encrypts, dotenvx
    exits 0, and the file is permanently undecryptable), and #467/#468 extended
    the same guard to the partial-encryption push/lock paths — but neither change
    documented the refusal. Pin both docs to the REAL shared predicate so the
    guarantee can't drift out of the docs again (CLAUDE.md: keep docs in sync).
    """
    from envdrift.integrations.dotenvx import is_dotenvx_safe_filename

    # Ground truth from the real shared predicate (#457/#467): a space or
    # non-ASCII character is refused, normal dotenv names are not. The predicate
    # is ASCII-only (`[A-Za-z0-9._-]`), so an accented "letter" is rejected —
    # the docs must say "ASCII letters", not merely "letters".
    assert not is_dotenvx_safe_filename("my secret.env")
    assert not is_dotenvx_safe_filename("café.env.secret")
    assert not is_dotenvx_safe_filename("résumé.env")
    assert is_dotenvx_safe_filename(".env.production")

    text = _read(doc)
    assert "permanently undecryptable" in text, (
        f"{doc} must explain WHY unsafe filenames are refused — the file would "
        "be permanently undecryptable (#467)."
    )
    assert "ASCII letters, digits" in text, (
        f"{doc} must name the safe character set as ASCII-only, since the guard's "
        "[A-Za-z0-9._-] set rejects accented letters like résumé.env (#467)."
    )


def test_faq_ci_decrypt_recipe_writes_suffixed_private_key() -> None:
    """faq.md's CI decrypt Option 1 must write DOTENV_PRIVATE_KEY_PRODUCTION (#498).

    Pre-fix the snippet wrote a bare ``DOTENV_PRIVATE_KEY`` into ``.env.keys``.
    On dotenvx v1 that could never decrypt ``.env.production`` (it looked the key
    up only under the env-suffixed name); dotenvx v2 accepts the bare key as a
    fallback, but the suffixed name is still the one ``envdrift encrypt`` writes
    and the clearer, version-independent recipe to publish. Ground truth comes
    from the real key-name resolver envdrift itself uses when pushing/pulling keys.
    """
    from envdrift.sync.config import ServiceMapping

    expected = ServiceMapping(
        secret_name="x", folder_path=Path(), environment="production"
    ).env_key_name
    assert expected == "DOTENV_PRIVATE_KEY_PRODUCTION"

    text = _read_docs_page("support/faq.md")
    assert 'echo "DOTENV_PRIVATE_KEY=$DOTENV_PRIVATE_KEY" > .env.keys' not in text, (
        "faq.md's CI recipe writes a bare DOTENV_PRIVATE_KEY into .env.keys; "
        "publish the suffixed name envdrift generates — it is unambiguous and "
        "version-independent (#498)."
    )
    assert f'echo "{expected}=${expected}" > .env.keys' in text, (
        f"faq.md's CI recipe must write {expected} into .env.keys — the name "
        "`envdrift encrypt` itself generates for .env.production (#498)."
    )
    # The CI secret feeding the snippet must carry the same suffixed name.
    assert f"{expected}: ${{{{ secrets.{expected} }}}}" in text, (
        f"faq.md must name the CI secret {expected} so the recipe is copy-pasteable (#498)."
    )


def test_env_file_sync_rotation_recipe_matches_dotenvx_v2() -> None:
    """The guide must not advertise dotenvx v1's removed local rotate recipe (#585)."""
    text = _read_docs_page("guides/env-file-sync.md")
    assert "--rotate" not in text, (
        "env-file-sync.md references a --rotate option that no shipped tool has (#498)."
    )
    assert "dotenvx rotate -f .env.production" not in text, (
        "env-file-sync.md advertises dotenvx v1's removed local rotation command (#585)."
    )
    assert "dotenvx v2 has no local `rotate` subcommand" in text, (
        "env-file-sync.md must explain the pinned dotenvx v2 rotation limitation (#585)."
    )


def test_no_docs_page_references_fabricated_dotenv_keys_path() -> None:
    """No docs page may mention DOTENV_KEYS_PATH — nothing reads it (#498).

    Pre-fix monorepo-setup.md told users to "Set DOTENV_KEYS_PATH"; the variable
    exists in neither envdrift nor dotenvx, so the tip silently does nothing.
    """
    offenders = [
        str(path.relative_to(_REPO_ROOT))
        for path in sorted(_DOCS_ROOT.rglob("*.md"))
        if "DOTENV_KEYS_PATH" in path.read_text(encoding="utf-8")
    ]
    assert offenders == [], (
        f"docs pages reference the fabricated DOTENV_KEYS_PATH variable: {offenders} "
        "— use dotenvx's -fk/--env-keys-file flag or a symlink instead (#498)."
    )


def test_monorepo_shared_keys_tip_documents_real_mechanisms() -> None:
    """monorepo-setup.md's shared-keys tip must name mechanisms that exist (#498).

    The real options are dotenvx's ``-fk/--env-keys-file`` flag and a symlink —
    both verified live in ``tests/integration/test_docs_recipes.py``.
    """
    text = _read_docs_page("guides/monorepo-setup.md")
    assert "--env-keys-file" in text, (
        "monorepo-setup.md must document dotenvx's real --env-keys-file flag for "
        "pointing at a shared .env.keys (#498)."
    )
    assert "ln -s" in text, (
        "monorepo-setup.md must keep the working symlink mechanism for sharing .env.keys (#498)."
    )


def test_configuration_md_drops_unconsumed_envdrift_and_precommit_keys() -> None:
    """configuration.md must not document config keys nothing consumes (#498).

    ``[envdrift] schema``/``environments`` and the whole ``[precommit]`` section
    are parsed into ``EnvdriftConfig`` but have zero consumers — with all three
    set, ``envdrift validate`` still errors "--schema is required". Documenting
    them as functional sends users into silently-ignored config.
    """
    text = _read_docs_page("reference/configuration.md")
    # Match the exact TOML table headers on their own line, not as substrings:
    # `[precommit.schemas]` is a legitimate user-defined-key example in the
    # unknown-key exemption note, and `[tool.envdrift]` is the real namespace —
    # a substring check on `[precommit]`/`[envdrift]` would false-fail on those.
    assert not re.search(r"(?m)^\[precommit\]\s*$", text), (
        "configuration.md documents a [precommit] section that no code consumes (#498)."
    )
    assert not re.search(r"(?m)^\[envdrift\]\s*$", text), (
        "configuration.md documents an [envdrift] table (schema/environments) "
        "that no code consumes (#498)."
    )
    assert "environments = [" not in text, (
        "configuration.md documents an `environments` key that no code consumes (#498)."
    )
    # The sections that ARE consumed must survive the cleanup.
    for real_section in ("[validation]", "[guard]", "[encryption]", "[vault]"):
        assert real_section in text


def test_example_config_template_drops_unconsumed_keys() -> None:
    """The in-source EXAMPLE_CONFIG must not advertise dead config keys (#498).

    It is the canonical envdrift.toml template; shipping ``[envdrift] schema`` /
    ``environments`` / ``[precommit]`` in it re-creates the configuration.md bug
    in code form.
    """
    from envdrift.config import EXAMPLE_CONFIG

    assert "[precommit]" not in EXAMPLE_CONFIG, (
        "EXAMPLE_CONFIG ships a [precommit] section that no code consumes (#498)."
    )
    assert "[envdrift]" not in EXAMPLE_CONFIG, (
        "EXAMPLE_CONFIG ships an [envdrift] table (schema/environments) that no "
        "code consumes (#498)."
    )
    assert "environments = [" not in EXAMPLE_CONFIG


def test_glossary_toml_example_sets_only_consumed_keys() -> None:
    """glossary.md's TOML example must not set the dead top-level ``schema`` (#498)."""
    text = _read_docs_page("glossary.md")
    assert '\nschema = "' not in text, (
        "glossary.md's [tool.envdrift] example sets a top-level `schema` key that "
        "no code consumes (#498)."
    )


def test_api_md_init_documents_alias_everything_not_skip_and_warn(tmp_path: Path) -> None:
    """api.md must describe init()'s real alias-everything behavior (#498).

    Pre-fix api.md claimed non-identifier keys are *skipped* and a ``UserWarning``
    names them; since #423 every key is kept under a sanitized field name with a
    Pydantic alias, and no warning is emitted. Ground truth: the real ``init()``
    on a .env containing both documented examples.
    """
    import warnings

    from envdrift import init

    env_file = tmp_path / ".env"
    env_file.write_text("2FA_ENABLED=true\nMY-DASH-VAR=v\n", encoding="utf-8")
    output = tmp_path / "settings.py"
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        init(env_file=env_file, output=output)
    user_warnings = [w for w in caught if issubclass(w.category, UserWarning)]
    assert user_warnings == [], "init() must not warn — every key is kept and aliased"

    generated = output.read_text(encoding="utf-8")
    assert "field_2FA_ENABLED" in generated
    assert "alias='2FA_ENABLED'" in generated
    assert "MY_DASH_VAR" in generated
    assert "alias='MY-DASH-VAR'" in generated

    text = _read_docs_page("reference/api.md")
    # The stale skip-and-warn contract must be gone…
    assert "UserWarning" not in text, (
        "api.md still claims init() emits a UserWarning for non-identifier keys; "
        "the shipped init() never warns (#498)."
    )
    assert "are skipped" not in text, (
        "api.md still claims init() skips non-identifier keys; the shipped init() "
        "keeps every key under a sanitized, aliased field (#498)."
    )
    # …replaced by the sanitize-plus-alias contract, shown with the exact field
    # names the generator emits for the documented examples.
    assert "field_2FA_ENABLED" in text, (
        "api.md must show the real sanitized field (field_2FA_ENABLED) the "
        "generator emits for a leading-digit key (#498)."
    )
    assert "alias='2FA_ENABLED'" in text
    assert "MY_DASH_VAR" in text


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
