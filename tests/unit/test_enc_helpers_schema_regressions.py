"""Regression tests for #348a/b/c (encryption_helpers + schema loader)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from envdrift.cli_commands.encryption_helpers import (
    resolve_encryption_backend,
    should_skip_reencryption,
)
from envdrift.core.schema import SchemaLoader
from envdrift.encryption.sops import SOPSEncryptionBackend


def test_relative_sops_config_resolves_from_other_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#348a: a relative sops config_file resolves against the toml dir, not cwd."""
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / ".sops.yaml").write_text("creation_rules: []\n")
    toml = cfg / "envdrift.toml"
    toml.write_text(
        '[encryption]\nbackend = "sops"\n\n[encryption.sops]\nconfig_file = ".sops.yaml"\n'
    )

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    backend, _provider, _config = resolve_encryption_backend(toml)

    assert isinstance(backend, SOPSEncryptionBackend)
    resolved = backend._config_file
    assert resolved is not None
    assert resolved.resolve() == (cfg / ".sops.yaml").resolve()
    assert resolved.exists()


def test_preexisting_tmp_file_not_clobbered(tmp_path: Path) -> None:
    """#348b: smart-encryption must not overwrite/delete a pre-existing temp-named file."""
    env_file = tmp_path / ".env.production"
    env_file.write_text("SECRET=value")

    sentinel = env_file.with_name(f".{env_file.name}.envdrift-tmp")
    sentinel.write_text("KEEP=me")

    backend = MagicMock()
    backend.name = "dotenvx"

    def _decrypt(path: Path) -> SimpleNamespace:
        path.write_text("SECRET=value")
        return SimpleNamespace(success=True, message="")

    backend.decrypt = _decrypt

    with (
        patch("envdrift.cli_commands.encryption_helpers.is_file_tracked", return_value=True),
        patch(
            "envdrift.cli_commands.encryption_helpers.get_file_from_git",
            return_value="encrypted:blob",
        ),
        patch("envdrift.cli_commands.encryption_helpers.restore_file_from_git", return_value=True),
    ):
        should_skip_reencryption(env_file, backend, enabled=True)

    assert sentinel.exists(), "pre-existing temp-named file was deleted"
    assert sentinel.read_text() == "KEEP=me", "pre-existing temp-named file was overwritten"


def test_monorepo_same_named_schema_isolation(tmp_path: Path) -> None:
    """#348c: same-named schema modules in two service dirs load their OWN class."""
    svc_a = tmp_path / "svc_a"
    svc_b = tmp_path / "svc_b"
    svc_a.mkdir()
    svc_b.mkdir()
    (svc_a / "service_settings.py").write_text(
        "from pydantic_settings import BaseSettings\n\n"
        'class Settings(BaseSettings):\n    A_ONLY: str = "a"\n'
    )
    (svc_b / "service_settings.py").write_text(
        "from pydantic_settings import BaseSettings\n\n"
        'class Settings(BaseSettings):\n    B_ONLY: str = "b"\n'
    )

    loader = SchemaLoader()
    cls_a = loader.load("service_settings:Settings", service_dir=svc_a)
    cls_b = loader.load("service_settings:Settings", service_dir=svc_b)

    assert set(cls_a.model_fields) == {"A_ONLY"}
    assert set(cls_b.model_fields) == {"B_ONLY"}
    assert cls_a is not cls_b


def test_monorepo_dotted_package_schema_isolation(tmp_path: Path) -> None:
    """#348c: same-named *package* modules (config.settings) load their OWN class.

    A cached parent package pins the first service's directory via __path__, so
    evicting only the leaf module is not enough — the whole root namespace must
    be evicted. This exercises that path with a dotted import.
    """
    svc_c = tmp_path / "svc_c"
    svc_d = tmp_path / "svc_d"
    for svc, only in ((svc_c, "C_ONLY"), (svc_d, "D_ONLY")):
        pkg = svc / "config"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("")
        (pkg / "settings.py").write_text(
            "from pydantic_settings import BaseSettings\n\n"
            f'class ProdSettings(BaseSettings):\n    {only}: str = "x"\n'
        )

    loader = SchemaLoader()
    cls_c = loader.load("config.settings:ProdSettings", service_dir=svc_c)
    cls_d = loader.load("config.settings:ProdSettings", service_dir=svc_d)

    assert set(cls_c.model_fields) == {"C_ONLY"}
    assert set(cls_d.model_fields) == {"D_ONLY"}
    assert cls_c is not cls_d


def test_schema_load_no_service_dir_leak(tmp_path: Path) -> None:
    """#348c: loading with a service_dir does not leak that dir onto sys.path."""
    import sys

    svc = tmp_path / "svc_leak"
    svc.mkdir()
    (svc / "service_settings.py").write_text(
        "from pydantic_settings import BaseSettings\n\n"
        'class Settings(BaseSettings):\n    LEAK_ONLY: str = "x"\n'
    )

    before = list(sys.path)
    loader = SchemaLoader()
    loader.load("service_settings:Settings", service_dir=svc)

    assert str(svc.resolve()) not in sys.path
    assert sys.path == before
