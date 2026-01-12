"""Tests for SOPS encryption backend."""

from pathlib import Path
from unittest.mock import MagicMock, patch

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
