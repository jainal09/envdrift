"""Tests for SOPS encryption backend."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from envdrift.encryption.base import EncryptionBackendError
from envdrift.encryption.sops import SOPSEncryptionBackend


def test_sops_find_binary_cached():
    """Test regarding the binary path caching mechanism."""

    # Setup - mock exists() to be true
    with patch("pathlib.Path.exists", return_value=True):
        backend = SOPSEncryptionBackend()
        # Manually set the cached binary path
        mock_path = Path("/mock/sops")
        backend._binary_path = mock_path

        # Should return cached path immediately without lock
        assert backend._find_binary() == mock_path


def test_sops_find_binary_with_lock(tmp_path):
    """Test finding binary with lock when not cached initially."""

    with patch("envdrift.integrations.sops.get_sops_path") as mock_get_path:
        mock_venv_sops = tmp_path / "venv" / "sops"
        mock_get_path.return_value = mock_venv_sops

        # Mock exists to return True for our venv path
        with patch("pathlib.Path.exists", side_effect=lambda: True):
            backend = SOPSEncryptionBackend()

            # Should find it in venv
            assert backend._find_binary() == mock_venv_sops
            # Should cache it
            assert backend._binary_path == mock_venv_sops


def test_sops_find_binary_system_path():
    """Test finding sops in system PATH."""

    with patch("envdrift.integrations.sops.get_sops_path") as mock_get_path:
        # Simulate RuntimeError (no venv)
        mock_get_path.side_effect = RuntimeError("No venv")

        with patch("shutil.which", return_value="/usr/bin/sops"):
            backend = SOPSEncryptionBackend()
            assert backend._find_binary() == Path("/usr/bin/sops")


def test_sops_find_binary_install_error():
    """Test auto-install failure."""

    from envdrift.integrations.sops import SopsInstallError

    with (
        patch("envdrift.integrations.sops.get_sops_path") as mock_get_path,
        patch("shutil.which", return_value=None),
        patch("envdrift.integrations.sops.SopsInstaller") as mock_installer_cls,
        patch("pathlib.Path.exists", return_value=False),
    ):
        mock_get_path.return_value = Path("/nonexistent")

        mock_installer = MagicMock()
        mock_installer.install.side_effect = SopsInstallError("Install failed")
        mock_installer_cls.return_value = mock_installer

        backend = SOPSEncryptionBackend(auto_install=True)
        assert backend._find_binary() is None


def test_sops_find_binary_auto_install():
    """Test auto-install when binary not found."""

    with (
        patch("envdrift.integrations.sops.get_sops_path") as mock_get_path,
        patch("shutil.which", return_value=None),
        patch("envdrift.integrations.sops.SopsInstaller") as mock_installer_cls,
        patch("pathlib.Path.exists", return_value=False),
    ):
        # Venv sops does not exist
        mock_get_path.return_value = Path("/nonexistent")

        # Setup mock installer
        mock_installer = MagicMock()
        mock_installed_path = Path("/installed/sops")
        mock_installer.install.return_value = mock_installed_path
        mock_installer_cls.return_value = mock_installer

        # Enable auto_install
        backend = SOPSEncryptionBackend(auto_install=True)
        assert backend._find_binary() == mock_installed_path
        assert backend._binary_path == mock_installed_path


def test_sops_find_binary_not_found():
    """Test when binary is not found anywhere."""

    with (
        patch("envdrift.integrations.sops.get_sops_path") as mock_get_path,
        patch("shutil.which", return_value=None),
        patch("pathlib.Path.exists", return_value=False),
    ):
        # Venv sops does not exist
        mock_get_path.return_value = Path("/nonexistent")

        backend = SOPSEncryptionBackend(auto_install=False)
        assert backend._find_binary() is None


def test_encrypt_already_encrypted_is_idempotent_noop(tmp_path, monkeypatch):
    """Regression for #413 (cluster G, HIGH): re-encrypting an already
    SOPS-encrypted file is a clean no-op success, never invoking sops (which
    refuses to re-encrypt a file with a top-level metadata block and exits 1).

    Without the short-circuit, ``_run`` would be called and a non-zero return
    code would raise ``EncryptionBackendError`` -> exit 1 on the second run.
    """
    env_file = tmp_path / ".env"
    # A genuine SOPS-encrypted dotenv carries ENC[AES256_GCM, values plus flat
    # ``sops_*`` metadata, including the recipient it was encrypted to (#475:
    # the no-op only holds when the requested recipient is already present).
    content = (
        "DB_PASSWORD=ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]\n"
        "sops_age__list_0__map_recipient=age1abc\n"
        "sops_version=3.13.1\n"
    )
    env_file.write_text(content, encoding="utf-8")

    backend = SOPSEncryptionBackend()
    monkeypatch.setattr(backend, "is_installed", lambda: True)

    ran = {"called": False}

    def fail_run(*args, **kwargs):
        ran["called"] = True
        raise AssertionError("sops must not run for an already-encrypted file")

    monkeypatch.setattr(backend, "_run", fail_run)

    result = backend.encrypt(env_file, age_recipients="age1abc")

    assert result.success is True
    assert "already encrypted" in result.message.lower()
    assert result.file_path == env_file
    assert ran["called"] is False
    # The encrypted file is left byte-for-byte unchanged.
    assert env_file.read_text(encoding="utf-8") == content


def test_encrypt_plaintext_still_runs_sops(tmp_path, monkeypatch):
    """The idempotency short-circuit must NOT fire for a plaintext file: sops is
    still invoked so a genuine first encryption proceeds."""
    env_file = tmp_path / ".env"
    env_file.write_text("DB_PASSWORD=hunter2\n")

    backend = SOPSEncryptionBackend()
    monkeypatch.setattr(backend, "is_installed", lambda: True)

    ran = {"called": False}

    def fake_run(*args, **kwargs):
        ran["called"] = True
        return MagicMock(returncode=0, stderr="", stdout="")

    monkeypatch.setattr(backend, "_run", fake_run)

    result = backend.encrypt(env_file, age_recipients="age1abc")

    assert result.success is True
    assert ran["called"] is True


def test_run_explicit_missing_config_raises(tmp_path, monkeypatch):
    """Regression for #413 (cluster G, MEDIUM): an explicit but missing SOPS
    config path raises a clear ``EncryptionBackendError`` instead of being
    silently dropped (which would let sops fall back to an ambient .sops.yaml
    with the wrong keys and exit 0 — a data-integrity hazard)."""
    missing_config = tmp_path / "does-not-exist.sops.yaml"
    assert not missing_config.exists()

    backend = SOPSEncryptionBackend(config_file=missing_config)
    # Pretend a binary exists so _run gets past the install check and reaches
    # the explicit-config validation.
    binary = tmp_path / "sops"
    binary.write_text("")
    backend._binary_path = binary

    # _run must never reach subprocess.run; the missing config is fatal first.
    def boom(*args, **kwargs):
        raise AssertionError("subprocess.run must not be reached")

    monkeypatch.setattr("envdrift.encryption.sops.subprocess.run", boom)

    with pytest.raises(EncryptionBackendError, match="SOPS config file not found"):
        backend._run(["--encrypt", str(tmp_path / ".env")])


def test_run_explicit_present_config_is_used(tmp_path):
    """An explicit config path that DOES exist is still passed through as
    ``--config`` (the fix only rejects missing explicit paths)."""
    config = tmp_path / ".sops.yaml"
    config.write_text("creation_rules: []\n")
    env_file = tmp_path / ".env"
    env_file.write_text("KEY=value\n")
    binary = tmp_path / "sops"
    binary.write_text("")

    backend = SOPSEncryptionBackend(config_file=config)
    backend._binary_path = binary

    with patch("envdrift.encryption.sops.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
        backend._run(["--encrypt", str(env_file)])

    cmd = mock_run.call_args[0][0]
    assert "--config" in cmd
    assert str(config) in cmd


def test_run_no_config_does_not_add_flag(tmp_path):
    """With no config_file at all (fully-implicit auto-discovery), --config is
    omitted and no error is raised."""
    env_file = tmp_path / ".env"
    env_file.write_text("KEY=value\n")
    binary = tmp_path / "sops"
    binary.write_text("")

    backend = SOPSEncryptionBackend()  # no config_file
    backend._binary_path = binary

    with patch("envdrift.encryption.sops.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
        backend._run(["--encrypt", str(env_file)])

    cmd = mock_run.call_args[0][0]
    assert "--config" not in cmd


def test_run_relative_config_resolved_against_cwd(tmp_path):
    """A *relative* explicit config path is resolved against the subprocess ``cwd``
    (where sops actually runs), not the process cwd. A config that exists relative
    to ``cwd`` is accepted and passed through as an absolute ``--config`` path."""
    work_dir = tmp_path / "ws"
    work_dir.mkdir()
    config = work_dir / ".sops.yaml"
    config.write_text("creation_rules: []\n")
    env_file = work_dir / ".env"
    env_file.write_text("KEY=value\n")
    binary = tmp_path / "sops"
    binary.write_text("")

    # config_file is RELATIVE; it only exists relative to work_dir, not process cwd.
    backend = SOPSEncryptionBackend(config_file=Path(".sops.yaml"))
    backend._binary_path = binary

    with patch("envdrift.encryption.sops.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
        backend._run(["--encrypt", str(env_file)], cwd=work_dir)

    cmd = mock_run.call_args[0][0]
    assert "--config" in cmd
    # Resolved against cwd -> the absolute config path is what's passed.
    config_arg = Path(cmd[cmd.index("--config") + 1])
    assert config_arg.is_absolute()
    assert config_arg == (work_dir / ".sops.yaml").resolve()


def test_run_relative_config_and_relative_cwd_not_applied_twice(tmp_path, monkeypatch):
    """cubic P2 (re-review): when *cwd itself* is relative, the resolved
    ``--config`` path must be made absolute so SOPS (which runs with that cwd) does
    not re-resolve it and apply cwd a second time. The flag must point at the real
    file, not ``cwd/cwd/config``."""
    work_dir = tmp_path / "ws"
    work_dir.mkdir()
    (work_dir / ".sops.yaml").write_text("creation_rules: []\n")
    binary = tmp_path / "sops"
    binary.write_text("")

    # Run from tmp_path so a *relative* cwd ("ws") points at work_dir.
    monkeypatch.chdir(tmp_path)

    backend = SOPSEncryptionBackend(config_file=Path(".sops.yaml"))
    backend._binary_path = binary

    with patch("envdrift.encryption.sops.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
        backend._run(["--encrypt", "ws/.env"], cwd="ws")  # relative cwd

    cmd = mock_run.call_args[0][0]
    config_arg = Path(cmd[cmd.index("--config") + 1])
    # Absolute and anchored to the real file -> no cwd/cwd/.sops.yaml double-apply.
    assert config_arg.is_absolute()
    assert config_arg == (work_dir / ".sops.yaml").resolve()
    assert config_arg.exists()


def test_run_relative_config_no_cwd_uses_process_dir(tmp_path, monkeypatch):
    """A relative explicit config with no ``cwd`` is validated/passed as-is (it is
    interpreted against the process working directory, mirroring sops with no cwd
    override)."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".sops.yaml").write_text("creation_rules: []\n")
    binary = tmp_path / "sops"
    binary.write_text("")

    backend = SOPSEncryptionBackend(config_file=Path(".sops.yaml"))
    backend._binary_path = binary

    with patch("envdrift.encryption.sops.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
        backend._run(["--encrypt", str(tmp_path / ".env")])  # no cwd

    cmd = mock_run.call_args[0][0]
    assert "--config" in cmd
    assert ".sops.yaml" in cmd[cmd.index("--config") + 1]


def test_run_relative_config_missing_under_cwd_raises(tmp_path):
    """A relative explicit config that does NOT exist under ``cwd`` raises, instead
    of being silently dropped (which would let sops fall back to ambient keys)."""
    work_dir = tmp_path / "ws"
    work_dir.mkdir()
    binary = tmp_path / "sops"
    binary.write_text("")

    backend = SOPSEncryptionBackend(config_file=Path("missing.sops.yaml"))
    backend._binary_path = binary

    with patch("envdrift.encryption.sops.subprocess.run") as boom:
        boom.side_effect = AssertionError("subprocess.run must not be reached")
        with pytest.raises(EncryptionBackendError, match="SOPS config file not found"):
            backend._run(["--encrypt", str(work_dir / ".env")], cwd=work_dir)


def test_has_sops_metadata_block_distinguishes_substring_from_block():
    """The idempotency signal (``_has_sops_metadata_block``) is stricter than
    ``has_encrypted_header``: a bare ``ENC[AES256_GCM,`` substring in plaintext is
    NOT a metadata block, while a genuine line-anchored ``sops_version=`` marker is.
    """
    backend = SOPSEncryptionBackend()

    # Plaintext that merely mentions the ciphertext marker (e.g. a doc comment).
    plaintext_with_substring = "# example value looks like ENC[AES256_GCM,data:...]\nKEY=real\n"
    assert backend.has_encrypted_header(plaintext_with_substring) is True
    assert backend._has_sops_metadata_block(plaintext_with_substring) is False

    # A genuine SOPS metadata block.
    genuine = "KEY=ENC[AES256_GCM,data:x]\nsops_version=3.13.1\n"
    assert backend._has_sops_metadata_block(genuine) is True


def test_encrypt_substring_only_plaintext_still_runs_sops(tmp_path, monkeypatch):
    """cubic P1: a plaintext file that merely *contains* the literal
    ``ENC[AES256_GCM,`` substring (with no genuine SOPS metadata block) must NOT be
    treated as already-encrypted. sops is still invoked so the file gets encrypted,
    rather than a false ``already encrypted`` no-op that leaves secrets plaintext."""
    env_file = tmp_path / ".env"
    # No sops metadata block; the marker appears only inside a comment/value.
    env_file.write_text("# ciphertext looks like ENC[AES256_GCM,data:...]\nDB_PASSWORD=hunter2\n")

    backend = SOPSEncryptionBackend()
    monkeypatch.setattr(backend, "is_installed", lambda: True)

    ran = {"called": False}

    def fake_run(*args, **kwargs):
        ran["called"] = True
        return MagicMock(returncode=0, stderr="", stdout="")

    monkeypatch.setattr(backend, "_run", fake_run)

    result = backend.encrypt(env_file, age_recipients="age1abc")

    assert result.success is True
    assert "already encrypted" not in result.message.lower()
    assert ran["called"] is True


def test_encrypt_unreadable_file_skips_noop_and_runs_sops(tmp_path, monkeypatch):
    """When the target cannot be read as text (e.g. undecodable bytes), the
    idempotency short-circuit cannot prove it is already encrypted, so it must NOT
    no-op: sops is still invoked so a real (binary-ish) file is handed to sops
    rather than silently skipped. Exercises the read-error branch."""
    env_file = tmp_path / ".env"
    # Bytes that are not valid UTF-8 -> read_text() raises UnicodeDecodeError.
    env_file.write_bytes(b"\xff\xfe\x00DB=1\n")

    backend = SOPSEncryptionBackend()
    monkeypatch.setattr(backend, "is_installed", lambda: True)

    ran = {"called": False}

    def fake_run(*args, **kwargs):
        ran["called"] = True
        return MagicMock(returncode=0, stderr="", stdout="")

    monkeypatch.setattr(backend, "_run", fake_run)

    result = backend.encrypt(env_file, age_recipients="age1abc")

    assert result.success is True
    assert "already encrypted" not in result.message.lower()
    assert ran["called"] is True


def test_encrypt_missing_config_raises_before_idempotency_noop(tmp_path, monkeypatch):
    """greptile P1: an explicit but missing ``--sops-config`` is surfaced even when
    the target is already encrypted. The config-path guard runs *before* the
    idempotency short-circuit, so a misconfiguration is never masked by a false
    ``already encrypted (no change)`` success."""
    missing_config = tmp_path / "nope.sops.yaml"
    assert not missing_config.exists()

    env_file = tmp_path / ".env"
    # Already-encrypted: carries a genuine sops metadata block.
    env_file.write_text("DB_PASSWORD=ENC[AES256_GCM,data:abc]\nsops_version=3.13.1\n")

    backend = SOPSEncryptionBackend(config_file=missing_config)
    monkeypatch.setattr(backend, "is_installed", lambda: True)

    def boom(*args, **kwargs):
        raise AssertionError("_run must not be reached when the config is missing")

    monkeypatch.setattr(backend, "_run", boom)

    with pytest.raises(EncryptionBackendError, match="SOPS config file not found"):
        backend.encrypt(env_file, age_recipients="age1abc")


# --------------------------------------------------------------------------- #
# #475: truthful results for already-encrypted files, env precedence, install
# --------------------------------------------------------------------------- #

# A genuinely SOPS-encrypted dotenv body as the real binary writes it (flat
# ``sops_*`` metadata keys, age recipient recorded, default unencrypted suffix).
_ENCRYPTED_DOTENV = (
    "DB_PASSWORD=ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]\n"
    "sops_age__list_0__map_recipient=age1abc\n"
    "sops_lastmodified=2026-06-01T00:00:00Z\n"
    "sops_mac=ENC[AES256_GCM,data:mac,iv:def,tag:ghi,type:str]\n"
    "sops_unencrypted_suffix=_unencrypted\n"
    "sops_version=3.13.1\n"
)


def _backend_that_must_not_run_sops(monkeypatch) -> SOPSEncryptionBackend:
    """Backend whose ``_run`` seam asserts sops is never invoked.

    Only discovery seams are patched (``is_installed``/``_run``); the verification
    logic under test runs for real against the file content.
    """
    backend = SOPSEncryptionBackend()
    monkeypatch.setattr(backend, "is_installed", lambda: True)

    def fail_run(*args, **kwargs):
        raise AssertionError("sops must not run for a metadata-bearing in-place target")

    monkeypatch.setattr(backend, "_run", fail_run)
    return backend


def test_encrypt_metadata_file_with_surviving_plaintext_fails(tmp_path, monkeypatch):
    """Regression for #475: a SOPS-metadata-bearing file that still contains a
    plaintext value must NOT be blessed as ``already encrypted`` — sops itself
    refuses such a file (exit 203) and the value is unprotected on disk."""
    env_file = tmp_path / ".env"
    content = "NEW_SECRET=plaintextleak999\n" + _ENCRYPTED_DOTENV
    env_file.write_text(content, encoding="utf-8")

    backend = _backend_that_must_not_run_sops(monkeypatch)
    result = backend.encrypt(env_file, age_recipients="age1abc")

    assert result.success is False
    assert "NEW_SECRET" in result.message
    assert "plaintext" in result.message.lower()
    # The file is left untouched (no partial mutation).
    assert env_file.read_text(encoding="utf-8") == content


def test_encrypt_metadata_file_unencrypted_suffix_values_are_clean_noop(tmp_path, monkeypatch):
    """Keys carrying the recorded ``sops_unencrypted_suffix`` are intentionally
    plaintext; they must not trip the surviving-plaintext failure."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "FEATURE_FLAG_unencrypted=on\n" + _ENCRYPTED_DOTENV,
        encoding="utf-8",
    )

    backend = _backend_that_must_not_run_sops(monkeypatch)
    result = backend.encrypt(env_file, age_recipients="age1abc")

    assert result.success is True
    assert result.changed is False
    assert "already encrypted" in result.message.lower()


def test_encrypt_selective_encryption_metadata_skips_plaintext_check(tmp_path, monkeypatch):
    """Files encrypted with ``encrypted_regex``-style selective rules keep
    intentional plaintext; the check cannot infer intent and must stay silent."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "PUBLIC_URL=https://example.com\n"
        "DB_PASSWORD=ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]\n"
        "sops_age__list_0__map_recipient=age1abc\n"
        "sops_encrypted_regex=^(DB_).*\n"
        "sops_version=3.13.1\n",
        encoding="utf-8",
    )

    backend = _backend_that_must_not_run_sops(monkeypatch)
    result = backend.encrypt(env_file, age_recipients="age1abc")

    assert result.success is True
    assert result.changed is False


def test_encrypt_already_encrypted_missing_requested_recipient_fails(tmp_path, monkeypatch):
    """Regression for #475: requesting ``--age <new key>`` on an already-encrypted
    file must not silently no-op with ``[OK] Encrypted`` — that is a false access
    grant (the new recipient cannot decrypt). It must fail and point at
    ``sops rotate --add-age`` / ``sops updatekeys``."""
    env_file = tmp_path / ".env"
    env_file.write_text(_ENCRYPTED_DOTENV, encoding="utf-8")

    backend = _backend_that_must_not_run_sops(monkeypatch)
    result = backend.encrypt(env_file, age_recipients="age1newteammate")

    assert result.success is False
    assert "age1newteammate" in result.message
    assert "rotate" in result.message or "updatekeys" in result.message
    # Metadata untouched: the new recipient was NOT silently dropped into success.
    assert env_file.read_text(encoding="utf-8") == _ENCRYPTED_DOTENV


def test_encrypt_already_encrypted_mixed_recipient_list_reports_only_missing(tmp_path, monkeypatch):
    """A comma-separated ``--age`` list reports only the recipients that are
    genuinely absent from the metadata."""
    env_file = tmp_path / ".env"
    env_file.write_text(_ENCRYPTED_DOTENV, encoding="utf-8")

    backend = _backend_that_must_not_run_sops(monkeypatch)
    result = backend.encrypt(env_file, age_recipients="age1abc, age1missing")

    assert result.success is False
    assert "age1missing" in result.message
    assert "age1abc," not in result.message


def test_encrypt_already_encrypted_missing_kms_arn_fails(tmp_path, monkeypatch):
    """The recipient check covers --kms as well: a requested KMS ARN absent from
    the metadata is an error, not a silent no-op."""
    env_file = tmp_path / ".env"
    env_file.write_text(_ENCRYPTED_DOTENV, encoding="utf-8")

    backend = _backend_that_must_not_run_sops(monkeypatch)
    arn = "arn:aws:kms:us-east-1:123456789012:key/aaaa-bbbb"
    result = backend.encrypt(env_file, kms_arn=arn)

    assert result.success is False
    assert arn in result.message


def test_encrypt_already_encrypted_with_requested_recipient_is_noop_changed_false(
    tmp_path, monkeypatch
):
    """The idempotent re-run (recipients already present, nothing plaintext) stays
    a clean success, and now reports ``changed=False`` so the CLI can print an
    honest "no change" instead of "Encrypted"."""
    env_file = tmp_path / ".env"
    env_file.write_text(_ENCRYPTED_DOTENV, encoding="utf-8")

    backend = _backend_that_must_not_run_sops(monkeypatch)
    result = backend.encrypt(env_file, age_recipients="age1abc")

    assert result.success is True
    assert result.changed is False
    assert "already encrypted" in result.message.lower()
    assert env_file.read_text(encoding="utf-8") == _ENCRYPTED_DOTENV


def test_build_env_explicit_age_key_file_overrides_ambient_env(tmp_path, monkeypatch):
    """Regression for #475: an explicit ``--age-key-file``/TOML ``age_key_file``
    must override an ambient ``SOPS_AGE_KEY_FILE`` — the documented setup exports
    the env var, which made the explicit flag dead."""
    ambient = tmp_path / "wrong.txt"
    explicit = tmp_path / "good.txt"
    monkeypatch.setenv("SOPS_AGE_KEY_FILE", str(ambient))

    backend = SOPSEncryptionBackend(age_key_file=explicit)
    env = backend._build_env()

    assert env["SOPS_AGE_KEY_FILE"] == str(explicit)


def test_build_env_explicit_age_key_overrides_ambient_env(monkeypatch):
    """Same precedence defect for SOPS_AGE_KEY: explicit config wins."""
    # Key material is concatenated so no realistic secret literal is committed.
    ambient_key = "AGE-SECRET-KEY-" + "AMBIENT"
    explicit_key = "AGE-SECRET-KEY-" + "EXPLICIT"
    monkeypatch.setenv("SOPS_AGE_KEY", ambient_key)

    backend = SOPSEncryptionBackend(age_key=explicit_key)
    env = backend._build_env()

    assert env["SOPS_AGE_KEY"] == explicit_key


def test_build_env_per_call_env_still_wins_over_config(tmp_path):
    """An explicit per-call ``env`` dict is the most specific request and keeps
    precedence over the constructor config."""
    backend = SOPSEncryptionBackend(age_key_file=tmp_path / "cfg.txt")
    per_call = str(tmp_path / "call.txt")

    env = backend._build_env({"SOPS_AGE_KEY_FILE": per_call})

    assert env["SOPS_AGE_KEY_FILE"] == per_call


def test_encrypt_surfaces_auto_install_failure_cause(tmp_path, monkeypatch):
    """Regression for #475: when auto-install fails, the not-installed error must
    surface the cause instead of recommending the auto_install that just failed.
    The download URL points at a real refused local port (fail-fast, no mock of
    the installer logic)."""
    import socket

    from envdrift.encryption.base import EncryptionNotFoundError

    # Grab a port that is guaranteed closed: bind, read it back, close.
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    refused_port = probe.getsockname()[1]
    probe.close()

    monkeypatch.setattr(
        "envdrift.integrations.sops.get_sops_path",
        lambda: tmp_path / "missing-venv" / "sops",
    )
    monkeypatch.setattr("shutil.which", lambda _name: None)
    monkeypatch.setattr(
        "envdrift.integrations.sops.SopsInstaller._get_download_url",
        lambda self: f"http://127.0.0.1:{refused_port}/sops",
    )

    env_file = tmp_path / ".env"
    env_file.write_text("FOO=bar\n", encoding="utf-8")

    backend = SOPSEncryptionBackend(auto_install=True)
    with pytest.raises(EncryptionNotFoundError) as exc:
        backend.encrypt(env_file)

    message = str(exc.value)
    assert "auto-install failed" in message.lower()
    # The recorded cause is exposed for CLI callers that pre-check is_installed().
    assert backend.install_error
    assert backend.install_error in message


def test_encrypt_metadata_file_with_sops_named_plaintext_secret_fails(tmp_path, monkeypatch):
    """Regression for the bug-#416 class resurfacing in #475: a real user secret
    merely NAMED ``sops_token`` must not be misclassified as SOPS bookkeeping by
    a bare ``sops_`` prefix match — that would bless the plaintext leak as
    "already encrypted (no change)"."""
    env_file = tmp_path / ".env"
    # Secret-looking value built by concatenation so the literal never appears
    # whole in the source (GitHub push-protection).
    leaked = "AKIA" + "IOSFODNN7EXAMPLE"
    content = f"sops_token={leaked}\n" + _ENCRYPTED_DOTENV
    env_file.write_text(content, encoding="utf-8")

    backend = _backend_that_must_not_run_sops(monkeypatch)
    result = backend.encrypt(env_file, age_recipients="age1abc")

    assert result.success is False
    assert "sops_token" in result.message
    assert "plaintext" in result.message.lower()
    assert env_file.read_text(encoding="utf-8") == content


def test_has_plaintext_values_flags_sops_named_secret_but_not_metadata():
    """``has_plaintext_values`` uses the canonical exact SOPS-metadata-key family:
    genuine bookkeeping keys are skipped, but a user variable that merely starts
    with ``sops_`` is a plaintext secret."""
    backend = SOPSEncryptionBackend()

    # Pure metadata + encrypted values: clean.
    assert backend.has_plaintext_values(_ENCRYPTED_DOTENV) is False
    # A plaintext user secret named sops_token is NOT bookkeeping.
    assert backend.has_plaintext_values("sops_token=hunter2\n" + _ENCRYPTED_DOTENV) is True
    # Same for sops_api_key (group-key prefix 'sops_a…' must not fuzzy-match age).
    assert backend.has_plaintext_values("sops_api_key=hunter2\n" + _ENCRYPTED_DOTENV) is True


def test_encrypt_already_encrypted_rejects_recipient_prefix_of_recorded_key(tmp_path, monkeypatch):
    """Regression for #475: recipient matching is exact and line-anchored. A
    requested key that is a strict PREFIX of the recorded recipient previously
    passed the bare substring scan and silently no-opped."""
    env_file = tmp_path / ".env"
    env_file.write_text(_ENCRYPTED_DOTENV, encoding="utf-8")

    backend = _backend_that_must_not_run_sops(monkeypatch)
    # Recorded recipient is age1abc; request its prefix.
    result = backend.encrypt(env_file, age_recipients="age1ab")

    assert result.success is False
    assert "age1ab" in result.message
    assert env_file.read_text(encoding="utf-8") == _ENCRYPTED_DOTENV


# Azure KV metadata as the real binary records it: the key URL is split across
# vault_url/name/version entries (never stored as one URL).
_AZURE_KV_ENCRYPTED_DOTENV = (
    "DB_PASSWORD=ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]\n"
    "sops_azure_kv__list_0__map_vault_url=https://myvault.vault.azure.net\n"
    "sops_azure_kv__list_0__map_name=mykey\n"
    "sops_azure_kv__list_0__map_version=abc123\n"
    "sops_lastmodified=2026-06-01T00:00:00Z\n"
    "sops_mac=ENC[AES256_GCM,data:mac,iv:def,tag:ghi,type:str]\n"
    "sops_unencrypted_suffix=_unencrypted\n"
    "sops_version=3.13.1\n"
)


def test_encrypt_already_encrypted_azure_kv_wrong_version_fails(tmp_path, monkeypatch):
    """Regression for #475: a short Azure KV URL component (key version ``1``)
    must not be declared present just because unrelated metadata digits contain
    a ``1`` (``sops_version=3.13.1``) — the recorded key version is abc123."""
    env_file = tmp_path / ".env"
    env_file.write_text(_AZURE_KV_ENCRYPTED_DOTENV, encoding="utf-8")

    backend = _backend_that_must_not_run_sops(monkeypatch)
    requested = "https://myvault.vault.azure.net/keys/mykey/1"
    result = backend.encrypt(env_file, azure_kv=requested)

    assert result.success is False
    assert requested in result.message


def test_encrypt_already_encrypted_azure_kv_exact_components_noop(tmp_path, monkeypatch):
    """The decomposed Azure KV URL still matches when every component is recorded
    exactly, keeping the idempotent re-run a clean no-op."""
    env_file = tmp_path / ".env"
    env_file.write_text(_AZURE_KV_ENCRYPTED_DOTENV, encoding="utf-8")

    backend = _backend_that_must_not_run_sops(monkeypatch)
    result = backend.encrypt(env_file, azure_kv="https://myvault.vault.azure.net/keys/mykey/abc123")

    assert result.success is True
    assert result.changed is False


def test_missing_recipients_public_wrapper_matches_internal_check():
    """``missing_recipients`` (used by lock's already-encrypted branch) reports
    exactly the recipients absent from the metadata."""
    backend = SOPSEncryptionBackend()

    missing = backend.missing_recipients(
        _ENCRYPTED_DOTENV, age_recipients="age1abc,age1newteammate"
    )

    assert missing == ["age1newteammate"]


def test_encrypt_flags_plaintext_duplicate_hidden_by_later_encrypted_line(tmp_path, monkeypatch):
    """Regression: the surviving-plaintext scan is line-based, not dict-based.
    With duplicate keys the parser's variables dict keeps only the LAST
    assignment, so an earlier plaintext duplicate of an encrypted key would be
    hidden and the leak blessed as "already encrypted (no change)"."""
    env_file = tmp_path / ".env"
    content = (
        "DB_PASSWORD=plaintextleak999\n"  # earlier plaintext duplicate (the leak)
        + _ENCRYPTED_DOTENV  # later DB_PASSWORD=ENC[...] + metadata
    )
    env_file.write_text(content, encoding="utf-8")

    backend = _backend_that_must_not_run_sops(monkeypatch)
    result = backend.encrypt(env_file, age_recipients="age1abc")

    assert result.success is False
    assert "DB_PASSWORD" in result.message
    assert "plaintext" in result.message.lower()
    assert env_file.read_text(encoding="utf-8") == content


def test_recipient_check_ignores_scalar_metadata_values(tmp_path, monkeypatch):
    """Regression: only the recipient-carrying key-group family satisfies the
    recipient check. A scalar bookkeeping value equal to a short Azure KV URL
    component (sops_shamir_threshold=1 vs key version "1") must not declare the
    recipient present."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "DB_PASSWORD=ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]\n"
        "sops_azure_kv__list_0__map_vault_url=https://myvault.vault.azure.net\n"
        "sops_azure_kv__list_0__map_name=mykey\n"
        "sops_azure_kv__list_0__map_version=abc123\n"
        "sops_shamir_threshold=1\n"
        "sops_unencrypted_suffix=_unencrypted\n"
        "sops_version=3.13.1\n",
        encoding="utf-8",
    )

    backend = _backend_that_must_not_run_sops(monkeypatch)
    requested = "https://myvault.vault.azure.net/keys/mykey/1"
    result = backend.encrypt(env_file, azure_kv=requested)

    assert result.success is False
    assert requested in result.message


def test_has_metadata_block_public_wrapper():
    """``has_metadata_block`` (used by the CLI-layer encrypted/decryptable
    checks) keys off the genuine metadata block, not a bare ENC token."""
    backend = SOPSEncryptionBackend()

    assert backend.has_metadata_block(_ENCRYPTED_DOTENV) is True
    # A bare ENC token in a value carries no metadata block: sops can neither
    # re-encrypt-refuse nor decrypt such a file.
    assert (
        backend.has_metadata_block("API_KEY=ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\n") is False
    )
