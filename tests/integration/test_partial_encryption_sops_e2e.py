"""Partial-encryption e2e for fully SOPS-encrypted ``.secret`` files (#416).

A fully SOPS-encrypted ``.secret`` carries a flat **plaintext** metadata trailer
(``sops_version=``, ``sops_lastmodified=``, ``sops_unencrypted_suffix=``, the
recipient public key; only ``sops_mac=`` is ciphertext).
``has_plaintext_secret_value()`` must **not** flag that trailer as leftover
plaintext secrets, or ``_is_fully_encrypted()`` returns ``False`` and the push
path re-encrypts (corrupting / double-wrapping the SOPS file) or ``push --check``
reports a genuine SOPS file perpetually out of sync.

These tests are driven against the **real sops binary** so the metadata trailer
is genuine. They live in a focused sibling module (split out of
``test_partial_encryption_e2e.py``) so each e2e module stays within the
code-health line-count threshold.

Gating: the sops binary is required and the whole module skips if it is absent
(CI provisions it; dev machines usually do not have it).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

# Real sops + real git only — no container needed. Skip the whole module locally
# when sops is not installed (CI installs it).
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which("sops") is None,
        reason="sops binary not installed (required for SOPS-encrypted .secret e2e)",
    ),
]


class TestSopsEncryptedSecretIsFullyEncryptedRealBinary:
    """A real SOPS-encrypted .secret is recognised as fully encrypted (#416)."""

    # Age recipient shared with the SOPS e2e suite; no .sops.yaml is needed
    # because we pass --age explicitly.
    _AGE_PUBLIC_KEY = "age1c89jtrvyl72y0muvdp5lm3jpemvc2gr303up4g37tuq4uftcku3q4svqau"

    def _sops_encrypt_dotenv_inplace(self, tmp_path: Path) -> Path:
        """Encrypt a dotenv .secret in place with the real sops binary.

        Skips when sops is absent (dev machines); CI provisions it. Produces the
        genuine flat metadata trailer (sops_version=/sops_mac=/…) that the unit
        fixture mirrors.
        """
        sops_bin = shutil.which("sops")
        if not sops_bin:
            pytest.skip("sops binary not available (installed in CI, absent on dev machines)")
        secret = tmp_path / ".env.production.secret"
        # Plaintext built by concatenation so push-protection never sees a secret.
        secret.write_text(
            "DB_PASSWORD=" + "hunter" + "2\n" + "API_KEY=" + "sk_live_" + "abc123" + "\n"
        )
        completed = subprocess.run(
            [
                sops_bin,
                "--encrypt",
                "--age",
                self._AGE_PUBLIC_KEY,
                "--input-type",
                "dotenv",
                "--output-type",
                "dotenv",
                "--in-place",
                str(secret),
            ],
            capture_output=True,
            text=True,
            cwd=tmp_path,
            check=False,
        )
        assert completed.returncode == 0, f"sops encrypt failed: {completed.stderr}"
        return secret

    def test_real_sops_secret_is_fully_encrypted(self, tmp_path: Path):
        """is_file_encrypted True, has_plaintext_secret_value False, fully encrypted True."""
        from envdrift.core.partial_encryption import (
            _is_fully_encrypted,
            has_plaintext_secret_value,
            is_file_encrypted,
        )

        secret = self._sops_encrypt_dotenv_inplace(tmp_path)
        content = secret.read_text()
        # Sanity: a genuine SOPS dotenv trailer with plaintext bookkeeping lines.
        assert "sops_version=" in content
        assert "ENC[AES256_GCM," in content

        assert is_file_encrypted(secret) is True
        # The sops_* metadata trailer must NOT count as leftover plaintext (#416).
        assert has_plaintext_secret_value(secret) is False
        assert _is_fully_encrypted(secret) is True

    def test_real_sops_secret_push_check_in_sync(self, tmp_path: Path):
        """push --check reports a fully SOPS-encrypted .secret as in sync (#416)."""
        from envdrift.config import PartialEncryptionEnvironmentConfig
        from envdrift.core.partial_encryption import combine_files, push_partial_encryption

        secret = self._sops_encrypt_dotenv_inplace(tmp_path)
        clear_file = tmp_path / ".env.production.clear"
        clear_file.write_text("DEBUG=false\n")
        cfg = PartialEncryptionEnvironmentConfig(
            name="production",
            clear_file=str(clear_file),
            secret_file=str(secret),
            combined_file=str(tmp_path / ".env.production"),
        )
        # Build the combined file from the already-SOPS-encrypted secret so the
        # combined text is byte-for-byte current.
        combine_files(cfg)

        stats = push_partial_encryption(cfg, check=True)

        assert stats["in_sync"] is True
