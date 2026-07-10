"""Value-scan / fully-SOPS-encrypted ``.secret`` unit tests (#416).

Split out of ``test_partial_encryption.py`` so each unit module stays within the
code-health function-count threshold. This module owns the
``has_plaintext_secret_value`` value-scan behaviour and the regression coverage
for a fully **SOPS**-encrypted ``.secret``: such a file carries a flat plaintext
metadata trailer (``sops_version=``, ``sops_lastmodified=``,
``sops_unencrypted_suffix=``, the recipient public key; only ``sops_mac=`` is
ciphertext) that must NOT be flagged as a leftover plaintext secret.

These are pure unit tests (no real binary): the SOPS dotenv content is a constant
fixture mirroring byte-for-byte what the real sops binary writes. The
binary-backed counterparts live in
``tests/integration/test_partial_encryption_sops_e2e.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.config import PartialEncryptionEnvironmentConfig
from envdrift.core.partial_encryption import combine_files, push_partial_encryption


def test_has_plaintext_secret_value_fully_encrypted_is_false(tmp_path: Path):
    """A fully-encrypted file (every value ciphertext) has no plaintext secret."""
    from envdrift.core.partial_encryption import has_plaintext_secret_value

    f = tmp_path / ".env.secret"
    f.write_text(
        'DOTENV_PUBLIC_KEY_TEST="03abc123..."\n'
        'API_KEY="encrypted:abc..."\n'
        'DB_PASS="encrypted:def..."\n'
    )
    assert has_plaintext_secret_value(f) is False


@pytest.mark.parametrize(
    ("line", "has_plaintext"),
    [
        ('API_KEY="encrypted:abc..." # rotated 2026-06', False),
        ("DB_PASS='ENC[AES256_GCM,data:abc]' # rotated", False),
        ('API_KEY="plaintext-value" # rotated', True),
        ('API_KEY="encrypted:abc..." trailing-text', True),
    ],
)
def test_has_plaintext_secret_value_quoted_value_with_suffix(
    tmp_path: Path, line: str, has_plaintext: bool
):
    """Only an inline comment after quoted ciphertext is safe to trim (#578)."""
    from envdrift.core.partial_encryption import has_plaintext_secret_value

    f = tmp_path / ".env.secret"
    f.write_text(line + "\n", encoding="utf-8")

    assert has_plaintext_secret_value(f) is has_plaintext


def test_has_plaintext_secret_value_mixed_is_true(tmp_path: Path):
    """A MIXED file (ciphertext + one plaintext value) has a plaintext secret."""
    from envdrift.core.partial_encryption import has_plaintext_secret_value

    f = tmp_path / ".env.secret"
    f.write_text(
        'API_KEY="encrypted:abc..."\n'  # already encrypted
        "NEW_LEAKED_SECRET=plaintext_leak_value\n"  # newly added, plaintext
    )
    assert has_plaintext_secret_value(f) is True


def test_has_plaintext_secret_value_ignores_public_key_and_comments(tmp_path: Path):
    """The DOTENV_PUBLIC_KEY line, comments and empty assignments are not secrets."""
    from envdrift.core.partial_encryption import has_plaintext_secret_value

    f = tmp_path / ".env.secret"
    f.write_text(
        'DOTENV_PUBLIC_KEY_TEST="03abc123..."\n'  # public key (plaintext but not a secret)
        "# a comment\n"
        "EMPTY=\n"  # empty assignment carries no secret
        'API_KEY="encrypted:abc..."\n'
    )
    assert has_plaintext_secret_value(f) is False


def test_has_plaintext_secret_value_quoted_empty_values_are_not_secrets(tmp_path: Path):
    """Quoted empty placeholders (KEY="" / KEY='') carry no secret to leak.

    Regression for the cubic P2 finding on #416: ``KEY=""`` has a non-empty
    raw value (the two quote chars), so the old ``if not value.strip()`` guard
    did not skip it and ``_value_is_ciphertext('""')`` returned False — flagging
    a fully-encrypted file with empty placeholders as still holding plaintext,
    causing repeated re-encryption / spurious out-of-sync.
    """
    from envdrift.core.partial_encryption import has_plaintext_secret_value

    f = tmp_path / ".env.secret"
    f.write_text(
        'API_KEY="encrypted:abc..."\n'
        'EMPTY_DQ=""\n'  # quoted-empty double
        "EMPTY_SQ=''\n"  # quoted-empty single
        'PADDED=" "\n'  # quotes around whitespace only
    )
    assert has_plaintext_secret_value(f) is False


def test_has_plaintext_secret_value_quoted_plaintext_is_secret(tmp_path: Path):
    """A quoted NON-empty plaintext value is still a leaking secret."""
    from envdrift.core.partial_encryption import has_plaintext_secret_value

    f = tmp_path / ".env.secret"
    f.write_text('API_KEY="encrypted:abc..."\nLEAK="plaintext_value"\n')
    assert has_plaintext_secret_value(f) is True


def _sops_ciphertext(data: str) -> str:
    """Build a SOPS ENC[...] value of the canonical shape (no real secret)."""
    return "ENC[AES256_GCM,data:" + data + ",iv:" + "ab" * 16 + ",tag:" + "cd" * 8 + ",type:str]"


# A realistic, fully SOPS-encrypted dotenv file: the secret VALUES are real
# ENC[AES256_GCM,...] ciphertext, but SOPS appends a flat PLAINTEXT metadata
# trailer (version / timestamp / unencrypted-suffix / recipient public key);
# only sops_mac= is ciphertext. This mirrors byte-for-byte the trailer that
# `sops --encrypt --input-type dotenv --output-type dotenv` writes (verified
# against the real sops 3.x binary). Built from constant tokens so it carries no
# real secret and never trips push-protection.
_SOPS_ENCRYPTED_DOTENV = (
    "DB_PASSWORD=" + _sops_ciphertext("U5dotp3cMQ==") + "\n"
    "API_KEY=" + _sops_ciphertext("oNgtRJRCHtOh669puic=") + "\n"
    "sops_age__list_0__map_recipient="
    "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n"
    "sops_lastmodified=2026-06-08T14:15:34Z\n"
    "sops_mac=" + _sops_ciphertext("iBjKMupTM") + "\n"
    "sops_unencrypted_suffix=_unencrypted\n"
    "sops_version=3.13.1\n"
)


def test_has_plaintext_secret_value_sops_metadata_trailer_is_not_plaintext(tmp_path: Path):
    """A fully SOPS-encrypted .secret is NOT flagged as holding plaintext secrets (#416).

    Regression for the #416 review-bot HIGH finding. A genuine SOPS dotenv file
    carries a flat PLAINTEXT metadata trailer — ``sops_version=``,
    ``sops_lastmodified=``, ``sops_unencrypted_suffix=``, the recipient public
    key (only ``sops_mac=`` is ciphertext). Pre-fix, ``has_plaintext_secret_value``
    treated each of those non-comment ``KEY=value`` lines as a leftover plaintext
    secret and returned True, so ``_is_fully_encrypted`` returned False and the
    push path re-encrypted (or flagged out-of-sync) an already-SOPS-encrypted
    file. The fix excludes the ``sops_*`` metadata family from the scan.
    """
    from envdrift.core.partial_encryption import has_plaintext_secret_value

    f = tmp_path / ".env.secret"
    f.write_text(_SOPS_ENCRYPTED_DOTENV, encoding="utf-8")
    assert has_plaintext_secret_value(f) is False


def test_has_plaintext_secret_value_sops_with_freshly_added_plaintext_is_true(tmp_path: Path):
    """A SOPS file with a NEW plaintext (non-sops_) secret still leaks (#416 guard).

    The ``sops_*`` exclusion must be narrow: it ignores only the SOPS metadata
    family, not a freshly-added user secret. A mixed SOPS file (real ENC[...]
    values + metadata trailer + one new plaintext ``KEY=value``) must still
    report a plaintext secret so the push path re-encrypts it.
    """
    from envdrift.core.partial_encryption import has_plaintext_secret_value

    f = tmp_path / ".env.secret"
    f.write_text(_SOPS_ENCRYPTED_DOTENV + "NEW_LEAK=plaintext-value\n", encoding="utf-8")
    assert has_plaintext_secret_value(f) is True


def test_has_plaintext_secret_value_user_var_with_sops_prefix_is_scanned(tmp_path: Path):
    """A user var named ``sops_<x>`` (NOT a real SOPS metadata key) still leaks (#416).

    Regression for the review-bot MEDIUM finding: the SOPS-trailer exclusion was a
    bare ``startswith("sops_")`` PREFIX match, so a real user variable whose name
    merely begins with ``sops_`` (``sops_token``, ``sops_api_key``,
    ``sops_config``, ``sops_agent``) was wrongly excluded from the plaintext scan.
    In a mixed-state file that value would be reported as fully encrypted and ship
    verbatim into the committed ``.secret`` — the exact leak class #416 targets.

    The fix matches the EXACT SOPS metadata key family, so these user vars are
    still flagged. Fails on the prefix-match code (returns False).
    """
    from envdrift.core.partial_encryption import has_plaintext_secret_value

    for user_key in ("sops_token", "sops_api_key", "sops_config", "sops_agent", "sops_keys"):
        f = tmp_path / ".env.secret"
        f.write_text(
            "API_KEY="
            + _sops_ciphertext("oNgtRJRCHtOh669puic=")
            + "\n"
            + user_key
            + "=AKIAIOSFODNN7EXAMPLE-brand-new-plaintext-secret\n",
            encoding="utf-8",
        )
        assert has_plaintext_secret_value(f) is True, (
            f"user var {user_key} must still be scanned as a plaintext secret"
        )


def test_has_plaintext_secret_value_genuine_sops_metadata_keys_excluded(tmp_path: Path):
    """Genuine SOPS metadata keys (scalar + nested provider) stay excluded (#416).

    Counterpart to the prefix-match regression: the exact-family matcher must keep
    ignoring every real SOPS trailer key — the flat scalars and the nested
    ``sops_<provider>__list_N__map_M_<field>`` recipient entries — so a genuine
    fully-SOPS-encrypted file is not flagged as holding leftover plaintext.
    """
    from envdrift.core.partial_encryption import has_plaintext_secret_value

    f = tmp_path / ".env.secret"
    f.write_text(
        "API_KEY=" + _sops_ciphertext("oNgtRJRCHtOh669puic=") + "\n"
        "sops_version=3.13.1\n"
        "sops_mac=" + _sops_ciphertext("iBjKMupTM") + "\n"
        "sops_lastmodified=2026-06-08T14:15:34Z\n"
        "sops_unencrypted_suffix=_unencrypted\n"
        "sops_mac_only_encrypted=false\n"
        "sops_shamir_threshold=2\n"
        "sops_age__list_0__map_recipient="
        "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n"
        "sops_age__list_0__map_enc=-----BEGIN-AGE-ENCRYPTED-FILE-----\n"
        "sops_pgp__list_0__map_fp=85D77543B3D624B63CEA9E6DBC17301B491B3F21\n"
        "sops_kms__list_0__map_arn=arn:aws:kms:us-east-1:111:key/abc\n",
        encoding="utf-8",
    )
    assert has_plaintext_secret_value(f) is False


def test_is_sops_metadata_key_exact_family(tmp_path: Path):
    """``_is_sops_metadata_key`` matches the family but not lookalike user keys (#416)."""
    from envdrift.core.partial_encryption import _is_sops_metadata_key

    assert _is_sops_metadata_key("sops_version") is True
    assert _is_sops_metadata_key("sops_mac") is True
    assert _is_sops_metadata_key("sops_age__list_0__map_recipient") is True
    assert _is_sops_metadata_key("sops_pgp__list_0__map_fp") is True
    assert _is_sops_metadata_key("sops_kms__list_0__map_arn") is True
    # User vars that merely start with ``sops_`` are NOT metadata.
    assert _is_sops_metadata_key("sops_token") is False
    assert _is_sops_metadata_key("sops_api_key") is False
    assert _is_sops_metadata_key("sops_config") is False
    assert _is_sops_metadata_key("sops_agent") is False  # not the ``age`` provider
    assert _is_sops_metadata_key("sops_version_override") is False


def test_is_fully_encrypted_true_for_sops_metadata_trailer(tmp_path: Path):
    """_is_fully_encrypted recognises a fully SOPS-encrypted .secret as done (#416).

    ``is_file_encrypted`` already returns True (the ENC[...] values / sops_mac
    trip it); pairing it with the fixed ``has_plaintext_secret_value`` must yield
    True so neither the encrypt path nor ``push --check`` treats a genuine SOPS
    file as needing a re-encrypt / out-of-sync.
    """
    from envdrift.core.partial_encryption import _is_fully_encrypted, is_file_encrypted

    f = tmp_path / ".env.secret"
    f.write_text(_SOPS_ENCRYPTED_DOTENV, encoding="utf-8")
    assert is_file_encrypted(f) is True
    assert _is_fully_encrypted(f) is True


def test_push_partial_check_in_sync_for_sops_encrypted_secret(tmp_path: Path):
    """--check reports a fully SOPS-encrypted .secret as in sync, not perpetually drifted (#416).

    End-to-end at the ``push --check`` call site: a fully SOPS-encrypted .secret
    whose combined file is byte-for-byte current must report ``in_sync`` True.
    Pre-fix the SOPS metadata trailer made ``_is_fully_encrypted`` return False,
    so the dry-run forced ``in_sync`` False — a false positive that would break a
    ``push --check`` CI gate for every SOPS-using project.
    """
    clear_file = tmp_path / ".env.test.clear"
    secret_file = tmp_path / ".env.test.secret"
    combined_file = tmp_path / ".env.test"
    clear_file.write_text("DEBUG=false\n")
    secret_file.write_text(_SOPS_ENCRYPTED_DOTENV, encoding="utf-8")

    config = PartialEncryptionEnvironmentConfig(
        name="test",
        clear_file=str(clear_file),
        secret_file=str(secret_file),
        combined_file=str(combined_file),
    )

    # Build the combined file from the already-SOPS-encrypted secret so the text
    # is byte-for-byte current; the secret on disk is fully encrypted.
    combine_files(config)

    stats = push_partial_encryption(config, check=True)

    assert stats["in_sync"] is True
