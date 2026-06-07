"""Regression tests for #348a/b/c (encryption_helpers + schema loader)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from envdrift.cli_commands.encryption_helpers import (
    _resolve_relative,
    resolve_encryption_backend,
    should_skip_reencryption,
)
from envdrift.core.schema import SchemaLoader
from envdrift.encryption.sops import SOPSEncryptionBackend


def test_resolve_relative_absolute_and_no_base_passthrough(tmp_path: Path) -> None:
    """#348a: absolute paths (and a missing base_dir) are returned unchanged."""
    abs_path = str(tmp_path / "abs.sops.yaml")
    # Absolute path: returned as-is regardless of base_dir.
    assert _resolve_relative(abs_path, tmp_path / "elsewhere") == abs_path
    # base_dir None: no resolution, the expanded candidate string is returned.
    assert _resolve_relative("rel.sops.yaml", None) == "rel.sops.yaml"


def test_schema_load_evicts_precached_same_named_module(tmp_path: Path) -> None:
    """#348c: a stale same-named module already in sys.modules is evicted, so the
    fresh service directory is loaded instead of the cached one."""
    import sys
    import types

    svc = tmp_path / "svc"
    svc.mkdir()
    (svc / "myschema.py").write_text(
        "from pydantic_settings import BaseSettings\n\n"
        "class Settings(BaseSettings):\n    fresh: int = 1\n"
    )
    stale = types.ModuleType("myschema")
    stale.MARKER = "stale"  # type: ignore[attr-defined]
    sys.modules["myschema"] = stale  # simulate a pre-cached collision
    try:
        cls = SchemaLoader().load("myschema:Settings", service_dir=svc)
        assert cls.__name__ == "Settings"
        assert hasattr(cls, "model_fields") and "fresh" in cls.model_fields
    finally:
        sys.modules.pop("myschema", None)


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


def test_monorepo_same_named_sibling_module_isolation(tmp_path: Path) -> None:
    """#391: two services each shipping a same-named top-level *sibling* module
    (e.g. ``common.py``) must not bleed across loads.

    Each service's settings module does ``from common import TAG``; svc_a's
    ``common`` carries ``TAG="AAA"`` and svc_b's carries ``TAG="BBB"``. Before the
    fix, the first-loaded ``common`` stayed pinned in ``sys.modules`` and svc_b
    silently reused svc_a's ``common`` (seeing ``AAA``). The loader must evict
    *every* module the import transitively added, not just ``root_pkg.*``.
    """
    import sys

    svc_a = tmp_path / "svc_a_sib"
    svc_b = tmp_path / "svc_b_sib"
    for svc, tag in ((svc_a, "AAA"), (svc_b, "BBB")):
        svc.mkdir()
        (svc / "common.py").write_text(f'TAG = "{tag}"\n')
        (svc / "settings_mod.py").write_text(
            "from pydantic_settings import BaseSettings\n"
            "from common import TAG\n\n"
            "WHO = TAG\n\n"
            "class Settings(BaseSettings):\n    placeholder: str = WHO\n"
        )

    # Snapshot the keys we might touch so the full-suite run (one process) is not
    # polluted regardless of pass/fail.
    saved = {k: sys.modules.get(k) for k in ("common", "settings_mod")}
    try:
        loader = SchemaLoader()
        cls_a = loader.load("settings_mod:Settings", service_dir=svc_a)
        cls_b = loader.load("settings_mod:Settings", service_dir=svc_b)

        # The default carries the TAG resolved at import time via `from common ...`.
        assert cls_a.model_fields["placeholder"].default == "AAA"
        assert cls_b.model_fields["placeholder"].default == "BBB", (
            "svc_b reused svc_a's cached sibling `common` (saw AAA, expected BBB)"
        )
        # svc_a's `common` must not leak into / persist after svc_b's load.
        leaked = sys.modules.get("common")
        assert leaked is None or getattr(leaked, "TAG", None) != "AAA", (
            "svc_a's `common` (TAG=AAA) leaked into sys.modules after svc_b load"
        )
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


def test_get_schema_metadata_func_monorepo_isolation(tmp_path: Path) -> None:
    """#413: get_schema_metadata_func must isolate same-named modules like load().

    Two services each ship a ``schema_meta.py`` exposing ``get_schema_metadata``
    that returns service-specific metadata. Before the fix, the first service's
    module stayed cached in sys.modules (and its dir leaked onto sys.path), so
    the second service silently reused the first's metadata.
    """
    import sys

    svc_a = tmp_path / "svc_a_meta"
    svc_b = tmp_path / "svc_b_meta"
    for svc, who in ((svc_a, "AAA"), (svc_b, "BBB")):
        svc.mkdir()
        (svc / "schema_meta.py").write_text(
            f'def get_schema_metadata():\n    return {{"service": "{who}"}}\n'
        )

    saved = {k: sys.modules.get(k) for k in ("schema_meta",)}
    before_path = list(sys.path)
    try:
        loader = SchemaLoader()
        meta_a = loader.get_schema_metadata_func("schema_meta", service_dir=svc_a)
        meta_b = loader.get_schema_metadata_func("schema_meta", service_dir=svc_b)

        assert meta_a == {"service": "AAA"}
        assert meta_b == {"service": "BBB"}, (
            "svc_b reused svc_a's cached schema_meta module (saw AAA, expected BBB)"
        )

        # Neither service dir may leak onto sys.path after the calls.
        assert str(svc_a.resolve()) not in sys.path
        assert str(svc_b.resolve()) not in sys.path
        assert sys.path == before_path
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v
