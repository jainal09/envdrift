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
