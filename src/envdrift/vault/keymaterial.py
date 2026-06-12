"""Centralized normalization/validation of vault-fetched dotenvx key material.

Every path that installs a vault secret into a ``.env.keys`` file (the sync
engine, ``vault-pull``, ``lock --verify-vault``) must parse the secret the same
way, or the same secret converges on one path and corrupts ``.env.keys`` on
another (#356, #413, #480). This module is that single parser:

- :func:`normalize_vault_key_value` reduces the raw secret string to bare key
  material — stripping quotes/whitespace and a ``DOTENV_PRIVATE_KEY_<ENV>=``
  prefix, extracting the matching field from JSON key/value documents (the AWS
  console's native storage shape, or a KV-v2 dict), and extracting the matching
  key line from multi-line ``.env.keys`` file blobs (e.g. pushed via
  ``az keyvault secret set --file .env.keys``).
- :func:`validate_key_material` is the final shape check: the value must look
  like a single dotenvx key token, never a document.
- :func:`extract_key_material` is the one-stop entry point for install paths;
  it also rejects provider-marked binary payloads
  (``SecretValue.metadata["encoding"] == "base64"``).

Unusable shapes raise :class:`KeyMaterialError` (a :class:`VaultError`) with a
message that names the secret's layout — never the secret values themselves —
so a wrong shape fails loudly instead of being installed under a success
banner and surfacing later as an opaque dotenvx ``INVALID_PRIVATE_KEY``.
"""

from __future__ import annotations

import json
import re

from envdrift.vault.base import SecretValue, VaultError

# Field name of a dotenvx private key, capturing the environment suffix.
DOTENV_PRIVATE_KEY_NAME_RE = re.compile(r"DOTENV_PRIVATE_KEY_([A-Za-z0-9_]+)")

# Match a `DOTENV_PRIVATE_KEY_<SUFFIX>=<value>` line, capturing the environment
# suffix and the bare value.
_DOTENV_PRIVATE_KEY_LINE_RE = re.compile(r"^DOTENV_PRIVATE_KEY_([A-Za-z0-9_]+)=(.+)$")


class KeyMaterialError(VaultError):
    """The vault secret's shape is not usable as dotenvx key material."""


def _strip_one_quote_layer(value: str) -> str:
    """Remove a single layer of matching surrounding single/double quotes."""
    if len(value) >= 2 and (
        (value[0] == '"' and value[-1] == '"') or (value[0] == "'" and value[-1] == "'")
    ):
        return value[1:-1]
    return value


def _normalize_inner(value: str) -> str:
    """Strip whitespace plus one quote layer from a post-``=`` / field value."""
    return _strip_one_quote_layer(value.strip())


def _extract_from_keys_blob(text: str, expected_environment: str | None) -> tuple[str, str | None]:
    """Extract the key from a multi-line ``.env.keys``-style document.

    Comment/blank lines are ignored; ``DOTENV_PRIVATE_KEY_<SUFFIX>=`` lines are
    collected. The line matching ``expected_environment`` wins; a lone key line
    is returned even on suffix mismatch so callers raise their established
    env-mismatch error. Anything else is rejected naming the layout.
    """
    entries: list[tuple[str, str]] = []  # (suffix, value)
    for line in text.splitlines():
        stripped = _normalize_inner(line)
        if not stripped or stripped.startswith("#"):
            continue
        match = _DOTENV_PRIVATE_KEY_LINE_RE.match(stripped)
        if match:
            entries.append((match.group(1), _normalize_inner(match.group(2))))

    if not entries:
        raise KeyMaterialError(
            "value is a multi-line document with no DOTENV_PRIVATE_KEY_<ENV> line; "
            "store the bare private key or a single DOTENV_PRIVATE_KEY_<ENV>=<key> line"
        )
    if expected_environment is not None:
        wanted = expected_environment.upper()
        matching = [entry for entry in entries if entry[0].upper() == wanted]
        if len(matching) == 1:
            suffix, value = matching[0]
            return value, suffix
        if len(matching) > 1:
            raise KeyMaterialError(
                f"value is a multi-line keys document with duplicate "
                f"DOTENV_PRIVATE_KEY_{wanted} lines; cannot determine which key to install"
            )
    if len(entries) == 1:
        suffix, value = entries[0]
        return value, suffix
    suffixes = ", ".join(sorted(f"DOTENV_PRIVATE_KEY_{suffix}" for suffix, _ in entries))
    raise KeyMaterialError(
        f"value is a multi-line keys document with multiple DOTENV_PRIVATE_KEY lines "
        f"({suffixes}) and none matches the target environment; cannot determine which "
        f"key to install"
    )


def _extract_from_json_document(
    text: str, expected_environment: str | None
) -> tuple[str, str | None]:
    """Extract the key from a JSON key/value document (AWS console / KV dict)."""
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        # Not actually JSON: treat as an opaque single-line value. The final
        # validate_key_material shape check rejects it in key flows.
        return text, None

    if not isinstance(document, dict):
        raise KeyMaterialError(
            "value is a JSON document (not a key/value object) and cannot be used "
            "as a dotenvx private key"
        )

    fields: list[tuple[str, str]] = []  # (suffix, value)
    for key, val in document.items():
        match = DOTENV_PRIVATE_KEY_NAME_RE.fullmatch(key)
        if match and isinstance(val, str):
            fields.append((match.group(1), _normalize_inner(val)))

    if expected_environment is not None:
        wanted = expected_environment.upper()
        matching = [field for field in fields if field[0].upper() == wanted]
        if len(matching) == 1:
            suffix, value = matching[0]
            return value, suffix
    if len(fields) == 1:
        suffix, value = fields[0]
        return value, suffix
    if len(document) == 1 and isinstance(document.get("value"), str):
        # The documented single-`value` storage shape, JSON-encoded somewhere
        # along the way: unwrap and parse the inner value normally.
        return normalize_vault_key_value(document["value"], expected_environment)

    field_names = ", ".join(sorted(document)) or "<empty>"
    raise KeyMaterialError(
        f"value is a JSON key/value document (fields: {field_names}) without a usable "
        f"DOTENV_PRIVATE_KEY_<ENV> field; store the private key under its "
        f"DOTENV_PRIVATE_KEY_<ENV> name or as the bare key value"
    )


def normalize_vault_key_value(
    raw: str, expected_environment: str | None = None
) -> tuple[str, str | None]:
    """Normalize a raw vault secret value to its bare key material.

    Strips surrounding whitespace, then a single layer of surrounding quotes,
    then a ``DOTENV_PRIVATE_KEY_<SUFFIX>=`` prefix if present. The value *after*
    that prefix is itself stripped and dequoted, exactly as
    ``EnvKeysFile.read_key`` treats the post-``=`` part — so the two converge
    even when the vault stores ``DOTENV_PRIVATE_KEY_PROD="abc"`` or
    ``DOTENV_PRIVATE_KEY_PROD=  abc`` (without this, verify-vault false-mismatched
    and the engine wrote literal quotes/whitespace as key material). Multi-line
    ``.env.keys`` blobs and JSON key/value documents are reduced to the key
    matching ``expected_environment`` (or their single key); unusable shapes
    raise :class:`KeyMaterialError` naming the layout (#480). Returns
    ``(value, suffix)`` where ``suffix`` is the environment label the key was
    stored under (uppercase as stored) or ``None`` when there was no label.

    The sync engine, ``vault-pull``, and ``lock --verify-vault`` all use it so
    they parse identically (#356, #413, #480). Order matters: outer quotes come
    off before the prefix, so a quoted full ``"DOTENV_PRIVATE_KEY_PROD=abc"``
    line still has its prefix stripped. The caller decides what to do with a
    suffix that does not match the target environment (the engine and
    ``vault-pull`` raise; verify reports a mismatch).
    """
    value = _strip_one_quote_layer(raw.strip())
    if "\n" in value:
        return _extract_from_keys_blob(value, expected_environment)
    if value[:1] in ("{", "["):
        return _extract_from_json_document(value, expected_environment)
    match = _DOTENV_PRIVATE_KEY_LINE_RE.match(value)
    if match:
        return _normalize_inner(match.group(2)), match.group(1)
    return value, None


def validate_key_material(value: str, *, secret_name: str | None = None) -> str:
    """Final shape check before key material may be written to ``.env.keys``.

    A dotenvx private key is a single opaque token: non-empty, no whitespace,
    not a structured document. The check deliberately stops short of enforcing
    the exact hex alphabet so non-dotenvx/opaque key material keeps working —
    it exists to catch documents and blobs masquerading as keys. Error messages
    never include the value itself (it is secret material).
    """
    label = f"secret '{secret_name}'" if secret_name else "vault secret"
    if not value:
        raise KeyMaterialError(f"{label} normalized to an empty value; cannot install an empty key")
    if any(ch.isspace() for ch in value):
        raise KeyMaterialError(
            f"{label} still contains whitespace after normalization and does not "
            f"look like a dotenvx private key"
        )
    if value[0] in ("{", "["):
        raise KeyMaterialError(
            f"{label} looks like a JSON/structured document, not a dotenvx private key"
        )
    return value


def extract_key_material(
    secret: SecretValue, expected_environment: str | None = None
) -> tuple[str, str | None]:
    """Normalize and shape-validate a fetched secret for key installation.

    One-stop entry point for every install path (sync engine, ``vault-pull``):
    rejects provider-marked binary payloads (AWS ``SecretBinary`` / GCP non-text
    payloads set ``metadata["encoding"] == "base64"``), normalizes the value via
    :func:`normalize_vault_key_value`, and applies the final
    :func:`validate_key_material` shape check. Raises :class:`KeyMaterialError`
    (a :class:`VaultError`) naming the secret and its layout when the secret
    cannot be used as dotenvx key material.
    """
    if secret.metadata.get("encoding") == "base64":
        raise KeyMaterialError(
            f"secret '{secret.name}' holds binary data (the stored bytes are not "
            f"valid UTF-8 text and were base64-encoded on fetch), not a dotenvx "
            f"private key"
        )
    try:
        value, suffix = normalize_vault_key_value(secret.value, expected_environment)
    except KeyMaterialError as exc:
        raise KeyMaterialError(f"secret '{secret.name}': {exc}") from exc
    validate_key_material(value, secret_name=secret.name)
    return value, suffix
