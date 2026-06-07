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


def _gcp_sdk_available() -> bool:
    # find_spec raises ModuleNotFoundError when a *parent* package is missing
    # (e.g. google.cloud absent), so guard it rather than letting collection crash.
    try:
        return importlib.util.find_spec("google.cloud.secretmanager") is not None
    except ModuleNotFoundError:
        return False


pytestmark = pytest.mark.skipif(
    not _gcp_sdk_available(),
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


@pytest.mark.parametrize(
    "bad",
    [
        "projects/my-project",  # no /secrets/<S> segment — would be rewritten synthetically
        "projects/my-project/other/x",  # third segment isn't 'secrets'
        "projects/my-project/secrets/",  # empty secret id
        "projects/my-project/secrets/x/versions",  # 'versions' with no version id
        "projects/my-project/secrets/x/versions/",  # empty version id
        "projects/my-project/secrets/x/foo/latest",  # fifth segment isn't 'versions'
    ],
)
def test_malformed_fully_qualified_names_are_rejected(bad: str) -> None:
    """Fully-qualified names that don't match ``projects/<P>/secrets/<S>[/versions/<V>]``
    hard-fail with a clear VaultError instead of being silently rewritten into a
    synthetic secret/version path (even when the project matches the bound one)."""
    with pytest.raises(VaultError) as exc:
        _client()._version_path(bad)
    assert "Malformed" in str(exc.value)


def test_get_secret_rejects_cross_project_before_client_call() -> None:
    """``get_secret`` (not just the path builder) rejects a cross-project name
    with VaultError BEFORE any ``access_secret_version`` call — proven with a spy
    client that fails if it is ever reached."""
    c = _client()

    class _SpyClient:
        def __init__(self) -> None:
            self.called = False

        def access_secret_version(self, request):  # pragma: no cover - must not run
            self.called = True
            raise AssertionError("access_secret_version must not run for a cross-project name")

    spy = _SpyClient()
    c._client = spy  # pre-set so ensure_authenticated is a no-op (no real network)

    cross = "projects/victim-project/secrets/db-password/versions/latest"
    with pytest.raises(VaultError):
        c.get_secret(cross)
    assert spy.called is False
