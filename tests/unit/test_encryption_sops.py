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
    # A genuine SOPS-encrypted dotenv carries ENC[AES256_GCM, values plus a
    # flat ``sops_version=`` metadata marker.
    env_file.write_text(
        "DB_PASSWORD=ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]\nsops_version=3.13.1\n"
    )

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
    assert env_file.read_text() == (
        "DB_PASSWORD=ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]\nsops_version=3.13.1\n"
    )


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
