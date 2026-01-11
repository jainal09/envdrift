"""Tests for DotenvxWrapper integration."""

from unittest.mock import MagicMock, patch

from envdrift.integrations.dotenvx import DotenvxWrapper


def test_dotenvx_get_success(tmp_path):
    """Test getting a value successfully."""
    wrapper = DotenvxWrapper(auto_install=False)
    env_file = tmp_path / ".env"

    with patch.object(wrapper, "_run") as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "value\n"
        mock_run.return_value = mock_result

        result = wrapper.get(env_file, "KEY")

        assert result == "value"
        mock_run.assert_called_once_with(["get", "-f", str(env_file), "KEY"], check=False)


def test_dotenvx_get_failure(tmp_path):
    """Test getting a value that doesn't exist."""
    wrapper = DotenvxWrapper(auto_install=False)
    env_file = tmp_path / ".env"

    with patch.object(wrapper, "_run") as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_run.return_value = mock_result

        result = wrapper.get(env_file, "KEY")

        assert result is None
        mock_run.assert_called_once_with(["get", "-f", str(env_file), "KEY"], check=False)


def test_dotenvx_set_success(tmp_path):
    """Test setting a value successfully."""
    wrapper = DotenvxWrapper(auto_install=False)
    env_file = tmp_path / ".env"

    with patch.object(wrapper, "_run") as mock_run:
        wrapper.set(env_file, "KEY", "value")

        mock_run.assert_called_once_with(["set", "-f", str(env_file), "KEY", "value"])
