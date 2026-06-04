"""Coverage-focused tests for envdrift.vault.hashicorp.

These tests exercise previously-uncovered error branches and edge cases:
- the ImportError fallback block when hvac is not installed (lines 21-26),
- the ``_get_hvac`` ImportError guard (line 32),
- the authenticate() Unauthorized/Forbidden branch (line 89),
- the is_authenticated() exception swallow (lines 104-105),
- the generic Exception -> VaultError branches in get_secret /
  list_secrets / create_or_update_secret (lines 160-161, 187-188, 231-232),
- and the list_secrets Unauthorized/Forbidden branch (lines 185-186).

All hvac access is mocked so the tests are hermetic and require no network.
"""

from __future__ import annotations

import builtins
import importlib

import pytest

import envdrift.vault.hashicorp as hashicorp
from envdrift.vault.base import AuthenticationError, VaultError
from envdrift.vault.hashicorp import HashiCorpVaultClient


@pytest.fixture
def authed_client(monkeypatch: pytest.MonkeyPatch):
    """Return a HashiCorpVaultClient with a mocked, authenticated hvac client.

    The factory lets each test install its own MagicMock client and have it
    returned by ``hvac.Client(...)`` and reported as authenticated.
    """
    from unittest.mock import MagicMock

    def _make(secret_client: MagicMock) -> HashiCorpVaultClient:
        secret_client.is_authenticated.return_value = True
        mock_hvac = MagicMock()
        mock_hvac.Client.return_value = secret_client
        monkeypatch.setattr(hashicorp, "_hvac", mock_hvac)
        monkeypatch.setattr(hashicorp, "HVAC_AVAILABLE", True)
        client = HashiCorpVaultClient(url="http://localhost:8200", token="t")
        client.authenticate()
        return client

    return _make


class TestImportFallback:
    """Cover the ImportError fallback block (lines 21-26)."""

    def test_import_without_hvac_sets_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Reloading the module while hvac import fails flips HVAC_AVAILABLE off.

        This forces execution of the ``except ImportError`` branch that assigns
        the sentinel Exception aliases and ``_hvac = None``.
        """
        import sys

        real_import = builtins.__import__

        def fake_import(name: str, *args: object, **kwargs: object):
            if name == "hvac" or name.startswith("hvac."):
                raise ImportError("hvac blocked for test")
            return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

        # Drop any cached hvac modules so the import statement re-runs.
        for mod in list(sys.modules):
            if mod == "hvac" or mod.startswith("hvac."):
                monkeypatch.delitem(sys.modules, mod, raising=False)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        try:
            importlib.reload(hashicorp)

            assert hashicorp.HVAC_AVAILABLE is False
            assert hashicorp._hvac is None
            # Sentinel aliases collapse to the base Exception type.
            assert hashicorp.InvalidPath is Exception
            assert hashicorp.Forbidden is Exception
            assert hashicorp.Unauthorized is Exception
        finally:
            # Restore real import and reload a clean module for other tests.
            monkeypatch.setattr(builtins, "__import__", real_import)
            importlib.reload(hashicorp)

    def test_get_hvac_raises_when_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``_get_hvac`` raises ImportError when hvac is unavailable (line 32)."""
        monkeypatch.setattr(hashicorp, "HVAC_AVAILABLE", False)
        monkeypatch.setattr(hashicorp, "_hvac", None)

        with pytest.raises(ImportError, match="hvac not installed"):
            hashicorp._get_hvac()

    def test_init_raises_when_hvac_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Constructing the client verifies hvac availability via _get_hvac."""
        monkeypatch.setattr(hashicorp, "HVAC_AVAILABLE", False)
        monkeypatch.setattr(hashicorp, "_hvac", None)

        with pytest.raises(ImportError, match="hvac not installed"):
            HashiCorpVaultClient(url="http://localhost:8200", token="t")


class TestAuthenticateErrorBranches:
    """Cover authenticate() and is_authenticated() error handling."""

    def test_authenticate_unauthorized_raises_auth_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Unauthorized during Client construction -> AuthenticationError (line 89)."""
        from unittest.mock import MagicMock

        mock_hvac = MagicMock()
        mock_hvac.Client.side_effect = hashicorp.Unauthorized("bad token")
        monkeypatch.setattr(hashicorp, "_hvac", mock_hvac)
        monkeypatch.setattr(hashicorp, "HVAC_AVAILABLE", True)

        client = HashiCorpVaultClient(url="http://localhost:8200", token="t")

        with pytest.raises(AuthenticationError, match="authentication failed"):
            client.authenticate()

    def test_authenticate_forbidden_raises_auth_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Forbidden during is_authenticated() -> AuthenticationError (line 89)."""
        from unittest.mock import MagicMock

        secret_client = MagicMock()
        secret_client.is_authenticated.side_effect = hashicorp.Forbidden("denied")
        mock_hvac = MagicMock()
        mock_hvac.Client.return_value = secret_client
        monkeypatch.setattr(hashicorp, "_hvac", mock_hvac)
        monkeypatch.setattr(hashicorp, "HVAC_AVAILABLE", True)

        client = HashiCorpVaultClient(url="http://localhost:8200", token="t")

        with pytest.raises(AuthenticationError, match="authentication failed"):
            client.authenticate()

    def test_is_authenticated_swallows_exception(self, authed_client) -> None:
        """is_authenticated() returns False if the hvac call raises (lines 104-105)."""
        from unittest.mock import MagicMock

        secret_client = MagicMock()
        client = authed_client(secret_client)
        # After authentication, make subsequent checks blow up.
        secret_client.is_authenticated.side_effect = RuntimeError("connection lost")

        assert client.is_authenticated() is False


class TestGenericErrorBranches:
    """Cover the generic Exception -> VaultError branches."""

    def test_get_secret_generic_error_raises_vault_error(self, authed_client) -> None:
        """Unexpected error in get_secret -> VaultError (lines 160-161)."""
        from unittest.mock import MagicMock

        secret_client = MagicMock()
        client = authed_client(secret_client)
        secret_client.secrets.kv.v2.read_secret_version.side_effect = RuntimeError("boom")

        with pytest.raises(VaultError, match="Vault error"):
            client.get_secret("some/path")

    def test_list_secrets_unauthorized_raises_auth_error(self, authed_client) -> None:
        """Unauthorized in list_secrets -> AuthenticationError (lines 185-186)."""
        from unittest.mock import MagicMock

        secret_client = MagicMock()
        client = authed_client(secret_client)
        secret_client.secrets.kv.v2.list_secrets.side_effect = hashicorp.Unauthorized("nope")

        with pytest.raises(AuthenticationError, match="Access denied to list secrets"):
            client.list_secrets(prefix="x/")

    def test_list_secrets_forbidden_raises_auth_error(self, authed_client) -> None:
        """Forbidden in list_secrets -> AuthenticationError (lines 185-186)."""
        from unittest.mock import MagicMock

        secret_client = MagicMock()
        client = authed_client(secret_client)
        secret_client.secrets.kv.v2.list_secrets.side_effect = hashicorp.Forbidden("nope")

        with pytest.raises(AuthenticationError, match="Access denied to list secrets"):
            client.list_secrets()

    def test_list_secrets_generic_error_raises_vault_error(self, authed_client) -> None:
        """Unexpected error in list_secrets -> VaultError (lines 187-188)."""
        from unittest.mock import MagicMock

        secret_client = MagicMock()
        client = authed_client(secret_client)
        secret_client.secrets.kv.v2.list_secrets.side_effect = RuntimeError("boom")

        with pytest.raises(VaultError, match="Vault error"):
            client.list_secrets()

    def test_create_or_update_secret_generic_error_raises_vault_error(self, authed_client) -> None:
        """Unexpected error in create_or_update_secret -> VaultError (lines 231-232)."""
        from unittest.mock import MagicMock

        secret_client = MagicMock()
        client = authed_client(secret_client)
        secret_client.secrets.kv.v2.create_or_update_secret.side_effect = RuntimeError("boom")

        with pytest.raises(VaultError, match="Vault error"):
            client.create_or_update_secret("p", {"value": "v"})
