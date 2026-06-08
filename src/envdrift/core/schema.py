"""Schema loader for Pydantic Settings classes."""

from __future__ import annotations

import contextlib
import importlib
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from pydantic_settings import BaseSettings

# Environment variable to signal schema extraction mode
ENVDRIFT_SCHEMA_EXTRACTION = "ENVDRIFT_SCHEMA_EXTRACTION"


@dataclass
class FieldMetadata:
    """Metadata about a settings field."""

    name: str
    required: bool
    sensitive: bool
    default: Any
    description: str | None
    field_type: type
    annotation: str

    @property
    def is_optional(self) -> bool:
        """
        Indicates that the field can be omitted because it has a default value.

        Returns:
            `true` if the field can be omitted because it has a default value, `false` otherwise.
        """
        return not self.required


@dataclass
class SchemaMetadata:
    """Complete schema metadata."""

    class_name: str
    module_path: str
    fields: dict[str, FieldMetadata] = field(default_factory=dict)
    extra_policy: str = "ignore"  # "forbid", "ignore", "allow"

    @property
    def required_fields(self) -> list[str]:
        """
        List the names of fields marked as required in the schema.

        Returns:
            list[str]: Field names for which FieldMetadata.required is True.
        """
        return [name for name, f in self.fields.items() if f.required]

    @property
    def optional_fields(self) -> list[str]:
        """
        List optional field names from the schema.

        Returns:
            list[str]: Field names whose corresponding FieldMetadata.required is False.
        """
        return [name for name, f in self.fields.items() if not f.required]

    @property
    def sensitive_fields(self) -> list[str]:
        """
        List names of fields that are marked as sensitive.

        Returns:
            list[str]: Field names for which the corresponding FieldMetadata.sensitive is True.
        """
        return [name for name, f in self.fields.items() if f.sensitive]


class SchemaLoadError(Exception):
    """Error loading schema."""

    pass


@contextlib.contextmanager
def _isolated_import(module_path: str, service_dir: Path | str | None):
    """Import ``module_path`` with the service dir and module cache isolated.

    Yields the imported module while ``service_dir`` is prepended to ``sys.path``
    and the module cache is snapshotted, so a same-named module from another
    service can't leak in or out (#348c/#391/#413). The body runs *inside* the
    isolated context — any lazy imports a user callable performs (e.g. a
    ``get_schema_metadata()`` that does ``from common import TAG``) resolve
    against this service dir, not the restored caller environment. On exit the
    inserted path entry is removed, every module the import transitively added is
    evicted, and the previously-cached modules are restored.

    Prepending the service dir at the *front* ensures the right service wins when
    several expose the same module name; evicting the whole root-package
    namespace (not just the leaf) is required because a cached parent package
    pins the first service's directory via ``__path__``, and snapshotting the
    full keyset catches same-named top-level siblings imported transitively.
    """
    root_pkg = module_path.split(".", 1)[0]

    inserted_path: str | None = None
    if service_dir:
        inserted_path = str(Path(service_dir).resolve())
        sys.path.insert(0, inserted_path)

    saved_modules = {
        name: mod
        for name, mod in list(sys.modules.items())
        if name == root_pkg or name.startswith(root_pkg + ".")
    }
    for name in saved_modules:
        del sys.modules[name]
    before = set(sys.modules)

    try:
        importlib.invalidate_caches()
        module = importlib.import_module(module_path)
        yield module
    finally:
        if inserted_path is not None:
            with contextlib.suppress(ValueError):
                sys.path.remove(inserted_path)
        # Drop every module this import (and any nested user import) added, then
        # restore the modules we evicted so sys.modules is left as we found it.
        for name in set(sys.modules) - before:
            del sys.modules[name]
        sys.modules.update(saved_modules)


class SchemaLoader:
    """Load and introspect Pydantic Settings classes."""

    def load(self, dotted_path: str, service_dir: Path | str | None = None) -> type[BaseSettings]:
        """
        Load a Pydantic BaseSettings subclass specified by a dotted path.

        Parameters:
            dotted_path (str): Dotted import path with class name separated by `:`, e.g. "module.path:SettingsClass".
            service_dir (Path | str | None): Optional directory to temporarily add to sys.path to assist imports.

        Returns:
            type[BaseSettings]: The resolved Pydantic Settings class.

        Raises:
            SchemaLoadError: If the path format is invalid, the module cannot be imported, the class is missing,
                             or the resolved object is not a subclass of `BaseSettings`.
        """
        # Parse the dotted path
        if ":" not in dotted_path:
            raise SchemaLoadError(
                f"Invalid schema path '{dotted_path}'. Expected format: 'module.path:ClassName'"
            )

        module_path, class_name = dotted_path.rsplit(":", 1)

        # Import under shared service-dir / module-cache isolation (#348c/#391).
        # Resolve the class *inside* the context so the import is fully isolated;
        # the returned class keeps its own reference once the context restores
        # sys.modules. Set ENVDRIFT_SCHEMA_EXTRACTION so user code can skip
        # Settings instantiation during import.
        os.environ[ENVDRIFT_SCHEMA_EXTRACTION] = "1"
        try:
            with _isolated_import(module_path, service_dir) as module:
                settings_cls = self._resolve_settings_class(module, module_path, class_name)
        except ImportError as e:
            raise SchemaLoadError(f"Cannot import module '{module_path}': {e}") from e
        finally:
            os.environ.pop(ENVDRIFT_SCHEMA_EXTRACTION, None)

        return settings_cls

    @staticmethod
    def _resolve_settings_class(
        module: Any, module_path: str, class_name: str
    ) -> type[BaseSettings]:
        """Resolve and validate the named BaseSettings subclass on ``module``."""
        try:
            settings_cls = getattr(module, class_name)
        except AttributeError as e:
            raise SchemaLoadError(
                f"Class '{class_name}' not found in module '{module_path}'"
            ) from e

        if not isinstance(settings_cls, type) or not issubclass(settings_cls, BaseSettings):
            raise SchemaLoadError(f"'{class_name}' is not a Pydantic BaseSettings subclass")

        return settings_cls

    def extract_metadata(self, settings_cls: type[BaseSettings]) -> SchemaMetadata:
        """
        Builds a SchemaMetadata instance describing the given Pydantic BaseSettings class, including each field's metadata and the model's extra policy.

        Inspects the class's model_config.extra (defaulting to "ignore") and model_fields to populate FieldMetadata entries; for required fields the stored default is None, sensitivity is read from a field's json_schema_extra["sensitive"] if present, and type annotations fall back to "Any" when not available.

        Parameters:
            settings_cls (type[BaseSettings]): The Pydantic BaseSettings subclass to inspect.

        Returns:
            SchemaMetadata: Metadata for the settings class, including field map and extra policy.
        """
        schema = SchemaMetadata(
            class_name=settings_cls.__name__,
            module_path=settings_cls.__module__,
        )

        # Determine extra policy from model_config
        model_config = getattr(settings_cls, "model_config", {})
        if isinstance(model_config, dict):
            extra = model_config.get("extra", "ignore")
        else:
            # SettingsConfigDict object
            extra = getattr(model_config, "extra", "ignore")

        schema.extra_policy = extra if extra else "ignore"

        # Extract field metadata
        for field_name, field_info in settings_cls.model_fields.items():
            # Check if field is required
            is_required = field_info.is_required()

            # Check if marked as sensitive
            extra_schema = field_info.json_schema_extra
            is_sensitive = False
            if isinstance(extra_schema, dict):
                raw_sensitive = extra_schema.get("sensitive", False)
                is_sensitive = raw_sensitive if isinstance(raw_sensitive, bool) else False

            # Get default value
            default_value = None if is_required else field_info.default

            # Get description
            description = field_info.description

            # Get type annotation as string
            annotation = field_info.annotation
            if annotation is not None:
                if hasattr(annotation, "__name__"):
                    type_str = annotation.__name__
                else:
                    type_str = str(annotation)
            else:
                type_str = "Any"

            schema.fields[field_name] = FieldMetadata(
                name=field_name,
                required=is_required,
                sensitive=is_sensitive,
                default=default_value,
                description=description,
                field_type=annotation if annotation else type(None),
                annotation=type_str,
            )

        return schema

    def get_schema_metadata_func(
        self, module_path: str, service_dir: Path | str | None = None
    ) -> dict[str, Any] | None:
        """
        Invoke a module-level get_schema_metadata() function if present and return its result.

        Parameters:
            module_path (str): Dotted module path to import (e.g., "config.settings").
            service_dir (Path | str | None): Optional directory to add to sys.path to aid importing the module.

        Returns:
            dict[str, Any] | None: The dictionary returned by get_schema_metadata() if callable and executed successfully,
            or `None` if the module cannot be imported or the function is absent.
        """
        # Import (and call get_schema_metadata) under the same service-dir /
        # module-cache isolation load() uses (#348c/#391/#413). The call happens
        # *inside* the context so any lazy import the user's get_schema_metadata()
        # performs (e.g. `from common import TAG`) resolves against this service's
        # dir, not the restored caller environment — and two services with
        # same-named config modules each see their own metadata.
        try:
            with _isolated_import(module_path, service_dir) as module:
                func = getattr(module, "get_schema_metadata", None)
                if callable(func):
                    return cast(dict[str, Any] | None, func())
        except ImportError:
            return None

        return None

    def load_and_extract(
        self, dotted_path: str, service_dir: Path | str | None = None
    ) -> SchemaMetadata:
        """
        Convenience method that loads a Pydantic BaseSettings class from a dotted path and returns its SchemaMetadata.

        Parameters:
            dotted_path (str): Dotted import path with class name, e.g. "config.settings:ProductionSettings".
            service_dir (Path | str | None): Optional directory to add to sys.path to assist imports.

        Returns:
            SchemaMetadata: Metadata describing the loaded settings class and its fields.
        """
        settings_cls = self.load(dotted_path, service_dir)
        return self.extract_metadata(settings_cls)
