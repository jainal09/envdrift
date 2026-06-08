"""End-to-end integration tests for the SOPS encryption backend.

These exercise the real ``sops`` binary (CI-installed) driven through
``SOPSEncryptionBackend`` with a real age keypair. ``sops`` and ``age`` are not
installed on developer machines, so every test gates on the binary and SKIPs
when it is absent (they run in CI where the binaries are provisioned).

The age keypair is reused from ``test_encryption_tools.py``.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from envdrift.encryption.base import (
    EncryptionBackendError,
    EncryptionStatus,
)
from envdrift.encryption.sops import SOPSEncryptionBackend

pytestmark = pytest.mark.integration

# Age keypair shared with test_encryption_tools.py.
AGE_PUBLIC_KEY = "age1c89jtrvyl72y0muvdp5lm3jpemvc2gr303up4g37tuq4uftcku3q4svqau"
AGE_PRIVATE_KEY = "AGE-SECRET-KEY-1HGE3ZE9NPEN5R76LVKKJ2Z3G9TYZJLW84P2CHAF6UGL43R7TWPUSZ89MK6"

# A second, non-matching age keypair used to prove decryption rejects the wrong key.
WRONG_AGE_PUBLIC_KEY = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
WRONG_AGE_PRIVATE_KEY = "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX"


def _require_sops() -> Path:
    """Skip the test unless a real sops binary is resolvable; return its path."""
    sops_path = shutil.which("sops")
    if not sops_path:
        pytest.skip("sops binary not available (installed in CI, absent on dev machines)")
    return Path(sops_path)


@pytest.fixture
def sops_workspace(tmp_path: Path) -> Path:
    """Create a work dir with an age key file and a .sops.yaml recipient rule.

    The recipient rule matches any ``.env*`` file. Returns the work dir.
    """
    work_dir = tmp_path / "sops_ws"
    work_dir.mkdir()

    (work_dir / "age.key").write_text(
        textwrap.dedent(
            f"""\
            # created: 2026-01-01T23:59:46-05:00
            # public key: {AGE_PUBLIC_KEY}
            {AGE_PRIVATE_KEY}
            """
        )
    )
    (work_dir / ".sops.yaml").write_text(
        textwrap.dedent(
            f"""\
            creation_rules:
              - path_regex: \\.env.*$
                age: {AGE_PUBLIC_KEY}
            """
        )
    )
    return work_dir


def _make_backend(sops_workspace: Path) -> SOPSEncryptionBackend:
    """Build a backend wired to the workspace .sops.yaml + age key file."""
    return SOPSEncryptionBackend(
        config_file=sops_workspace / ".sops.yaml",
        age_key_file=sops_workspace / "age.key",
    )


def _write_and_encrypt(
    backend: SOPSEncryptionBackend, work_dir: Path, name: str, content: str
) -> Path:
    """Write a plaintext env file and encrypt it in place; return its path."""
    env_file = work_dir / name
    env_file.write_text(content)
    result = backend.encrypt(env_file, age_recipients=AGE_PUBLIC_KEY, cwd=work_dir)
    assert result.success, f"encrypt failed: {result.message}"
    return env_file


def _sops_encrypt_inplace(sops_bin: Path, config_free_dir: Path, name: str, content: str) -> Path:
    """Encrypt a YAML/JSON file in place by driving the real sops binary directly.

    The backend's ``encrypt`` is dotenv-specific (it forces
    ``--input-type/--output-type dotenv``), so for YAML/JSON we invoke sops
    itself; the format is inferred from the file extension. ``config_free_dir``
    MUST be a directory with no ``.sops.yaml`` on its path to root (sops walks
    parents), so sops uses the explicit ``--age`` recipient instead of the
    workspace ``.sops.yaml`` (whose only rule matches ``.env*``).
    """
    src = config_free_dir / name
    src.write_text(content)
    completed = subprocess.run(
        [str(sops_bin), "--encrypt", "--age", AGE_PUBLIC_KEY, "--in-place", str(src)],
        capture_output=True,
        text=True,
        cwd=config_free_dir,
        check=False,
    )
    assert completed.returncode == 0, f"sops encrypt failed: {completed.stderr}"
    return src


# --------------------------------------------------------------------------- #
# P0
# --------------------------------------------------------------------------- #


def test_exec_env_injects_decrypted_secrets_without_writing_disk(
    tmp_path: Path, sops_workspace: Path
) -> None:
    """HP-10 (regression for #329): exec_env runs a child process with the
    decrypted secrets injected as env vars (never written to disk); the on-disk
    file stays encrypted. Drives the real sops binary."""
    _require_sops()
    backend = _make_backend(sops_workspace)
    # Filename MUST end in `.env` so sops exec-env infers the dotenv format from
    # the extension (sops exec-env ignores --input-type; a non-.env suffix such
    # as ".env.exec" is parsed as JSON and fails to unmarshal).
    env_file = _write_and_encrypt(
        backend,
        sops_workspace,
        "secrets.env",
        "DB_PASSWORD=hunter2\n",
    )
    encrypted_snapshot = env_file.read_text()
    assert "ENC[AES256_GCM," in encrypted_snapshot
    assert "hunter2" not in encrypted_snapshot

    # Child prints the injected secret to stdout (never written to disk).
    cp = backend.exec_env(
        env_file,
        [sys.executable, "-c", "import os; print(os.environ['DB_PASSWORD'])"],
    )

    assert cp.returncode == 0, f"exec-env failed: {cp.stderr}"
    assert cp.stdout.strip() == "hunter2"
    # The on-disk file is still the encrypted snapshot (no plaintext leaked).
    assert env_file.read_text() == encrypted_snapshot
    assert "hunter2" not in env_file.read_text()


def test_exec_env_propagates_child_exit_code(tmp_path: Path, sops_workspace: Path) -> None:
    """#329: exec_env returns the child's exit code; the secret is sourced from
    the encrypted file (the child exits 0 only if it saw the injected value)."""
    _require_sops()
    backend = _make_backend(sops_workspace)
    env_file = _write_and_encrypt(backend, sops_workspace, "child.env", "DB_PASSWORD=hunter2\n")
    cp = backend.exec_env(
        env_file,
        [
            sys.executable,
            "-c",
            "import os,sys; sys.exit(0 if os.environ.get('DB_PASSWORD')=='hunter2' else 3)",
        ],
    )
    # Child saw the injected secret -> exits 0; if missing it would be 3.
    assert cp.returncode == 0, f"secret not injected: {cp.stderr}"
    # File is still encrypted (not the original plaintext).
    assert env_file.read_text() != "DB_PASSWORD=hunter2\n"
    assert "ENC[AES256_GCM," in env_file.read_text()


def test_decrypt_in_place_false_no_output_fails_without_discarding_plaintext(
    tmp_path: Path, sops_workspace: Path
) -> None:
    """EC-07 (regression for #307): decrypt(in_place=False) with no output_file
    must report failure instead of silently discarding the decrypted plaintext to
    stdout while claiming success. The on-disk file stays encrypted and untouched."""
    _require_sops()
    backend = _make_backend(sops_workspace)
    env_file = _write_and_encrypt(
        backend,
        sops_workspace,
        ".env.discard",
        "DB_PASSWORD=hunter2\n",
    )
    encrypted_snapshot = env_file.read_text()
    assert "ENC[AES256_GCM," in encrypted_snapshot

    result = backend.decrypt(env_file, in_place=False)

    # No false success: the plaintext would have been discarded, so this fails.
    assert result.success is False
    assert "output_file" in result.message
    assert result.file_path == env_file
    # The file is left exactly as it was: still encrypted, no plaintext leaked.
    assert env_file.read_text() == encrypted_snapshot
    assert "hunter2" not in env_file.read_text()


def test_encrypt_in_place_false_no_output_fails_without_discarding_ciphertext(
    tmp_path: Path, sops_workspace: Path
) -> None:
    """EC-08 (regression for #360): encrypt(in_place=False) with no output_file
    must report failure instead of streaming the ciphertext to discarded stdout
    while leaving the on-disk file as PLAINTEXT yet claiming success. The
    plaintext file stays exactly as written and is never silently consumed."""
    _require_sops()
    backend = _make_backend(sops_workspace)
    env_file = sops_workspace / ".env.discard-enc"
    env_file.write_text("DB_PASSWORD=hunter2\n")
    plaintext_snapshot = env_file.read_text()

    result = backend.encrypt(
        env_file, age_recipients=AGE_PUBLIC_KEY, in_place=False, cwd=sops_workspace
    )

    # No false success: the ciphertext would have been discarded to stdout.
    assert result.success is False
    assert "output_file" in result.message
    assert result.file_path == env_file
    # The file is untouched: still the original plaintext, not silently lost.
    assert env_file.read_text() == plaintext_snapshot
    assert "ENC[AES256_GCM," not in env_file.read_text()


def test_encrypt_with_output_file_writes_ciphertext(tmp_path: Path, sops_workspace: Path) -> None:
    """HP-11 (regression for #360): encrypt(in_place=False, output_file=...) writes
    real sops ciphertext to the output file via --output. The output is genuinely
    encrypted (ENC[...] + sops metadata) and differs from the plaintext, while the
    source file is left unmodified."""
    _require_sops()
    backend = _make_backend(sops_workspace)
    env_file = sops_workspace / ".env.src"
    env_file.write_text("DB_PASSWORD=hunter2\n")
    plaintext_snapshot = env_file.read_text()
    output_file = sops_workspace / ".env.out"

    result = backend.encrypt(
        env_file,
        age_recipients=AGE_PUBLIC_KEY,
        in_place=False,
        output_file=output_file,
        cwd=sops_workspace,
    )

    assert result.success is True, f"encrypt failed: {result.message}"
    assert result.file_path == output_file
    # The output file holds genuine sops ciphertext (markers + metadata).
    assert output_file.exists()
    ciphertext = output_file.read_text()
    assert "ENC[AES256_GCM," in ciphertext
    assert "hunter2" not in ciphertext
    assert ciphertext != plaintext_snapshot
    assert backend.has_encrypted_header(ciphertext) is True
    # The source plaintext file is left unmodified.
    assert env_file.read_text() == plaintext_snapshot


def test_decrypt_with_wrong_age_key_raises_backend_error(
    tmp_path: Path, sops_workspace: Path
) -> None:
    """BP-13: decrypting with a non-matching age key raises EncryptionBackendError."""
    _require_sops()
    backend = _make_backend(sops_workspace)
    env_file = _write_and_encrypt(
        backend,
        sops_workspace,
        ".env.wrongkey",
        "DB_PASSWORD=hunter2\n",
    )
    encrypted_snapshot = env_file.read_text()

    # A second backend pointed at a different (non-recipient) age key.
    wrong_key_file = sops_workspace / "wrong-age.key"
    wrong_key_file.write_text(
        textwrap.dedent(
            f"""\
            # public key: {WRONG_AGE_PUBLIC_KEY}
            {WRONG_AGE_PRIVATE_KEY}
            """
        )
    )
    wrong_backend = SOPSEncryptionBackend(
        config_file=sops_workspace / ".sops.yaml",
        age_key_file=wrong_key_file,
    )

    with pytest.raises(EncryptionBackendError) as exc:
        wrong_backend.decrypt(env_file)

    message = str(exc.value)
    assert message.startswith("SOPS decryption failed:")
    # Real sops stderr reports that no configured key could recover the data key.
    lowered = message.lower()
    assert (
        "data key" in lowered or "no key could decrypt" in lowered or "but none were" in lowered
    ), f"unexpected sops stderr: {message!r}"
    # The file was not mutated.
    assert env_file.read_text() == encrypted_snapshot


# --------------------------------------------------------------------------- #
# P1
# --------------------------------------------------------------------------- #


def test_get_version_parses_real_sops_version(tmp_path: Path, sops_workspace: Path) -> None:
    """HP-07: get_version() returns the token parsed from real `sops --version`."""
    _require_sops()
    backend = _make_backend(sops_workspace)

    version = backend.get_version()

    assert version is not None
    assert re.fullmatch(r"\d+\.\d+\.\d+.*", version), f"unexpected version token: {version!r}"
    assert backend.is_installed() is True


def test_decrypt_to_output_file_leaves_source_encrypted(
    tmp_path: Path, sops_workspace: Path
) -> None:
    """HP-14 + EC-16: decrypt with output_file writes plaintext to a separate file;
    the source stays encrypted and result.file_path is the output."""
    _require_sops()
    backend = _make_backend(sops_workspace)
    env_file = _write_and_encrypt(
        backend,
        sops_workspace,
        ".env.outsrc",
        "DB_PASSWORD=hunter2\n",
    )
    encrypted_snapshot = env_file.read_text()
    out = sops_workspace / ".env.plaintext.out"

    result = backend.decrypt(env_file, output_file=out)

    assert result.success is True
    assert result.file_path == out
    out_content = out.read_text()
    assert "DB_PASSWORD=hunter2" in out_content
    assert "ENC[" not in out_content
    # Source unchanged and still encrypted.
    assert env_file.read_text() == encrypted_snapshot
    assert "ENC[AES256_GCM," in env_file.read_text()


def test_config_file_passed_before_positional_args_end_to_end(
    tmp_path: Path, sops_workspace: Path
) -> None:
    """HP-11 + EC-17: a relative .sops.yaml passed via --config (resolved against
    cwd) is placed before the positional file, enabling an end-to-end roundtrip."""
    _require_sops()
    # The backend prepends `--config <path>` before the positional file. We run
    # with cwd=sops_workspace and an absolute config so the encrypt/decrypt
    # roundtrip succeeds end-to-end, proving the --config flag is ordered ahead
    # of the positional argument (sops rejects late flags as extra paths).
    backend = SOPSEncryptionBackend(
        config_file=sops_workspace / ".sops.yaml",
        age_key_file=sops_workspace / "age.key",
    )

    env_file = sops_workspace / ".env.cfgorder"
    env_file.write_text("DB_PASSWORD=hunter2\n")

    enc = backend.encrypt(env_file, age_recipients=AGE_PUBLIC_KEY, cwd=sops_workspace)
    assert enc.success
    assert "ENC[" in env_file.read_text()

    dec = backend.decrypt(env_file, cwd=sops_workspace)
    assert dec.success
    final = env_file.read_text()
    assert "DB_PASSWORD=hunter2" in final
    assert "ENC[" not in final


def test_encrypt_missing_file_returns_failure_result(tmp_path: Path, sops_workspace: Path) -> None:
    """BP-01: encrypt() on a non-existent file returns failure without raising."""
    _require_sops()
    backend = _make_backend(sops_workspace)
    missing = sops_workspace / ".env.does-not-exist"

    result = backend.encrypt(missing, age_recipients=AGE_PUBLIC_KEY)

    assert result.success is False
    assert "File not found" in result.message
    assert result.file_path == missing


def test_decrypt_missing_file_returns_failure_result(tmp_path: Path, sops_workspace: Path) -> None:
    """BP-03: decrypt() on a non-existent file returns failure without raising."""
    _require_sops()
    backend = _make_backend(sops_workspace)
    missing = sops_workspace / ".env.also-missing"

    result = backend.decrypt(missing)

    assert result.success is False
    assert "File not found" in result.message
    assert result.file_path == missing


def test_decrypt_nonencrypted_file_raises_backend_error_with_stderr(
    tmp_path: Path, sops_workspace: Path
) -> None:
    """BP-06: real sops exits non-zero decrypting a non-sops file -> error w/ stderr."""
    _require_sops()
    backend = _make_backend(sops_workspace)
    plain = sops_workspace / ".env.plain"
    plain.write_text("DB_PASSWORD=hunter2\n")

    with pytest.raises(EncryptionBackendError) as exc:
        backend.decrypt(plain)

    message = str(exc.value)
    prefix = "SOPS decryption failed:"
    assert message.startswith(prefix)
    # Real stderr was captured (message is more than the bare prefix).
    assert len(message) > len(prefix)
    # The plaintext file was not corrupted.
    assert plain.read_text() == "DB_PASSWORD=hunter2\n"


def test_has_encrypted_header_plaintext_sops_substring_not_encrypted(
    tmp_path: Path, sops_workspace: Path
) -> None:
    """EC-04 (regression for #324): plaintext that merely contains the literal
    substring 'sops:' (e.g. a repo URL) must NOT be misclassified as encrypted.
    Only a real SOPS header (ENC[AES256_GCM, ...) or a line-anchored SOPS
    metadata block counts as encrypted."""
    backend = _make_backend(sops_workspace)

    content = "REPO=https://github.com/getsops/sops:main\n"
    assert backend.has_encrypted_header(content) is False
    # Value-level classification is not fooled either.
    assert (
        backend.detect_encryption_status("https://github.com/getsops/sops:main")
        == EncryptionStatus.PLAINTEXT
    )


@pytest.mark.parametrize(
    "content",
    [
        "REPO=https://github.com/getsops/sops:main\n",  # 'sops:' in a URL
        'config = "sops: see the docs"\n',  # 'sops:' in prose
        '{"note": "we use sops:age for secrets"}\n',  # 'sops:' substring in JSON-ish text
        "DB_PASSWORD=hunter2\nOTHER=plain\n",  # ordinary plaintext .env
        "SOPS_VERSION_NOTE=we pin 3.13.1\n",  # dotenv-ish but not a sops_version= marker
    ],
)
def test_has_encrypted_header_false_on_plaintext_with_sops_substring(
    tmp_path: Path, sops_workspace: Path, content: str
) -> None:
    """#324: plaintext containing the literal 'sops:' substring (or a sops-ish
    key name) is NOT encrypted. Pure-Python; no sops binary required."""
    backend = _make_backend(sops_workspace)
    assert backend.has_encrypted_header(content) is False


def test_encrypt_twice_is_idempotent_clean_noop(tmp_path: Path, sops_workspace: Path) -> None:
    """Regression for #413 (cluster G, HIGH): re-encrypting an already
    SOPS-encrypted file is a clean no-op success, not an exit-1 failure.

    Real sops refuses to encrypt a file that already carries a top-level ``sops``
    metadata block and exits non-zero; without the short-circuit the backend
    would raise ``EncryptionBackendError`` on the second run (a pre-commit hook
    firing twice, a CI re-run, a documented re-run). Drives the real sops binary.
    """
    _require_sops()
    backend = _make_backend(sops_workspace)
    env_file = sops_workspace / ".env.idempotent"
    env_file.write_text("DB_PASSWORD=hunter2\n")

    first = backend.encrypt(env_file, age_recipients=AGE_PUBLIC_KEY, cwd=sops_workspace)
    assert first.success is True
    encrypted_snapshot = env_file.read_text()
    assert "ENC[AES256_GCM," in encrypted_snapshot

    # Second run on the already-encrypted file: clean success, file untouched.
    second = backend.encrypt(env_file, age_recipients=AGE_PUBLIC_KEY, cwd=sops_workspace)
    assert second.success is True, f"second encrypt failed: {second.message}"
    assert "already encrypted" in second.message.lower()
    assert second.file_path == env_file
    # The on-disk ciphertext is byte-for-byte identical (no re-encrypt, no churn).
    assert env_file.read_text() == encrypted_snapshot

    # And it still round-trips: the no-op did not corrupt the ciphertext.
    dec = backend.decrypt(env_file, cwd=sops_workspace)
    assert dec.success is True
    assert "DB_PASSWORD=hunter2" in env_file.read_text()


def test_encrypt_plaintext_with_enc_substring_is_actually_encrypted(
    tmp_path: Path, sops_workspace: Path
) -> None:
    """cubic P1: a plaintext file whose *content* merely contains the literal
    ``ENC[AES256_GCM,`` substring (e.g. in a comment) is NOT mistaken for an
    already-encrypted file. The idempotency short-circuit keys off the genuine
    line-anchored SOPS metadata block, so sops is still invoked and the file is
    really encrypted instead of a false ``already encrypted`` no-op. Drives real
    sops."""
    _require_sops()
    backend = _make_backend(sops_workspace)
    env_file = sops_workspace / ".env.substring"
    # The marker appears only inside a dotenv comment; there is no sops metadata.
    env_file.write_text(
        "# sample ciphertext looks like ENC[AES256_GCM,data:x]\nDB_PASSWORD=hunter2\n"
    )

    result = backend.encrypt(env_file, age_recipients=AGE_PUBLIC_KEY, cwd=sops_workspace)

    assert result.success is True, f"encrypt failed: {result.message}"
    assert "already encrypted" not in result.message.lower()
    encrypted = env_file.read_text()
    # The real secret value is now genuinely encrypted (not left plaintext).
    assert "hunter2" not in encrypted
    assert "DB_PASSWORD=ENC[AES256_GCM," in encrypted
    assert backend._has_sops_metadata_block(encrypted) is True


def test_encrypt_explicit_missing_config_raises_clear_error(
    tmp_path: Path, sops_workspace: Path
) -> None:
    """Regression for #413 (cluster G, MEDIUM): an explicit but missing
    ``--config`` path raises a clear ``EncryptionBackendError`` rather than being
    silently dropped (which would let sops fall back to an ambient .sops.yaml with
    the wrong keys and exit 0). The plaintext file is left untouched.
    """
    _require_sops()
    missing_config = sops_workspace / "nope" / "missing.sops.yaml"
    assert not missing_config.exists()
    backend = SOPSEncryptionBackend(
        config_file=missing_config,
        age_key_file=sops_workspace / "age.key",
    )

    env_file = sops_workspace / ".env.missing-config"
    env_file.write_text("DB_PASSWORD=hunter2\n")

    with pytest.raises(EncryptionBackendError) as exc:
        backend.encrypt(env_file, age_recipients=AGE_PUBLIC_KEY, cwd=sops_workspace)

    message = str(exc.value)
    assert "SOPS config file not found" in message
    assert str(missing_config) in message
    # The plaintext file was never encrypted with the wrong (ambient) keys.
    assert env_file.read_text() == "DB_PASSWORD=hunter2\n"
    assert "ENC[AES256_GCM," not in env_file.read_text()


def test_has_encrypted_header_true_on_genuinely_encrypted_dotenv(
    tmp_path: Path, sops_workspace: Path
) -> None:
    """#324: a real sops-encrypted dotenv file is classified encrypted."""
    _require_sops()
    backend = _make_backend(sops_workspace)
    env_file = _write_and_encrypt(
        backend, sops_workspace, ".env.enc-dotenv", "DB_PASSWORD=hunter2\n"
    )
    content = env_file.read_text()
    assert "ENC[AES256_GCM," in content
    assert backend.has_encrypted_header(content) is True
    assert backend.is_file_encrypted(env_file) is True


@pytest.mark.parametrize(
    ("name", "plaintext"),
    [
        ("secrets.yaml", "DB_PASSWORD: hunter2\n"),
        ("secrets.json", '{"DB_PASSWORD": "hunter2"}\n'),
    ],
)
def test_has_encrypted_header_true_on_genuinely_encrypted_yaml_json(
    tmp_path: Path, sops_workspace: Path, name: str, plaintext: str
) -> None:
    """#324: real sops-encrypted YAML and JSON files are classified encrypted.

    Driven by the real sops binary directly (the backend's encrypt is
    dotenv-only); sops infers the YAML/JSON format from the file extension and
    emits a line-anchored ``sops:`` / ``"sops":`` metadata block plus
    ``ENC[AES256_GCM,`` values.
    """
    sops_bin = _require_sops()
    backend = _make_backend(sops_workspace)
    # Encrypt under tmp_path (NOT sops_workspace), which has no .sops.yaml on its
    # path to root, so sops honours the explicit --age recipient.
    src = _sops_encrypt_inplace(sops_bin, tmp_path, name, plaintext)

    content = src.read_text()
    assert "ENC[AES256_GCM," in content
    assert backend.has_encrypted_header(content) is True
    assert backend.is_file_encrypted(src) is True
