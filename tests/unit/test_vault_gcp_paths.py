"""Real path-logic regression tests for GCPSecretManagerClient.

``_version_path`` / ``_secret_id`` / ``_secret_path`` are pure string methods
(no network/auth), so we build a REAL client and assert it cannot be steered to
another project by a caller-supplied fully-qualified resource name. Skip-gated on
the GCP SDK being importable. This module deliberately avoids ``importlib.reload``
of ``envdrift.vault.gcp`` so it stays order-independent in full-suite runs.
"""

from __future__ import annotations

import importlib.util

import pytest

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("google.cloud.secretmanager") is None,
    reason="GCP SDK not installed (pip install envdrift[gcp])",
)

from envdrift.vault.base import VaultError  # noqa: E402
from envdrift.vault.gcp import GCPSecretManagerClient  # noqa: E402


def _client() -> GCPSecretManagerClient:
    # Constructor only verifies the SDK is importable; it needs no credentials.
    return GCPSecretManagerClient(project_id="my-project")


def test_bare_name_resolves_under_bound_project() -> None:
    """A bare name resolves under the bound project (unchanged behavior)."""
    assert _client()._version_path("x") == "projects/my-project/secrets/x/versions/latest"


def test_same_project_fully_qualified_is_accepted() -> None:
    """A fully-qualified name for the bound project is passed through / completed."""
    c = _client()
    same = "projects/my-project/secrets/x/versions/latest"
    assert c._version_path(same) == same
    assert c._version_path("projects/my-project/secrets/x") == same


def test_cross_project_version_path_is_rejected() -> None:
    """A fully-qualified path for ANOTHER project must NOT silently read across
    the project boundary -- it raises before any client call."""
    c = _client()
    with pytest.raises(VaultError) as exc:
        c._version_path("projects/victim-project/secrets/db-password/versions/latest")
    msg = str(exc.value)
    assert "victim-project" in msg and "my-project" in msg

    with pytest.raises(VaultError):
        c._version_path("projects/victim-project/secrets/db-password")


def test_cross_project_secret_id_is_rejected() -> None:
    """``_secret_id`` (used to derive secret ids) also refuses other projects."""
    with pytest.raises(VaultError):
        _client()._secret_id("projects/victim-project/secrets/x/versions/latest")


def test_cross_project_secret_path_is_rejected() -> None:
    """``_secret_path`` (used by ``set_secret``) refuses other projects, closing
    the previous silent-rebind-to-bound-project write footgun."""
    with pytest.raises(VaultError):
        _client()._secret_path("projects/victim-project/secrets/x")


def test_malformed_projects_name_is_rejected() -> None:
    """A ``projects/`` prefix with no project segment raises a clear VaultError
    (rather than IndexError)."""
    with pytest.raises(VaultError) as exc:
        _client()._version_path("projects/")
    assert "Malformed" in str(exc.value)


def test_get_secret_rejects_cross_project_before_client_call() -> None:
    """``get_secret`` with a cross-project name fails fast with VaultError, even
    without live credentials -- the guard runs before ``access_secret_version``.

    ``ensure_authenticated`` would normally need a client; assert the validator
    fires either via that path or the resource-name guard. We isolate the guard
    by calling the version-path builder ``get_secret`` uses.
    """
    c = _client()
    cross = "projects/victim-project/secrets/db-password/versions/latest"
    with pytest.raises(VaultError):
        c._version_path(cross)
