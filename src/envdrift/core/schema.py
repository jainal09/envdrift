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
        root_pkg = module_path.split(".", 1)[0]

        # Put the service directory at the *front* of sys.path for this import so
        # the right service wins when multiple services expose the same module
        # name, and remove it again afterwards (#348c). Leaving stale service
        # dirs on the path would let a later load resolve a repeated module name
        # against an earlier service's directory.
        inserted_path: str | None = None
        if service_dir:
            service_dir = Path(service_dir).resolve()
            inserted_path = str(service_dir)
            sys.path.insert(0, inserted_path)

        # Isolate the import from the module cache so monorepos with repeated
        # module names (e.g. two services each exposing `settings.py`) don't
        # return a stale, previously-cached class (#348c). We evict the target
        # module *and its whole root-package namespace* (a cached parent package
        # pins the first service's directory via __path__), import fresh against
        # the service dir we just prepended, then restore the prior cache.
        #
        # Evicting only the root namespace is not enough, though: a schema module
        # often `import`s a same-named *top-level sibling* (e.g. each service dir
        # ships its own `common.py` and the settings module does
        # `from common import TAG`). The first-loaded `common` would stay cached
        # and the second service would silently reuse it (#391). So we also
        # snapshot the full sys.modules keyset before importing and evict *every*
        # module the import transitively added afterwards.
        saved_modules = {
            name: mod
            for name, mod in list(sys.modules.items())
            if name == root_pkg or name.startswith(root_pkg + ".")
        }
        for name in saved_modules:
            del sys.modules[name]
        before = set(sys.modules)

        # Set environment variable to signal schema extraction mode
        # This allows user code to skip Settings instantiation during import
        os.environ[ENVDRIFT_SCHEMA_EXTRACTION] = "1"
        try:
            importlib.invalidate_caches()
            module = importlib.import_module(module_path)
        except ImportError as e:
            raise SchemaLoadError(f"Cannot import module '{module_path}': {e}") from e
        finally:
            # Clean up the environment variable
            os.environ.pop(ENVDRIFT_SCHEMA_EXTRACTION, None)
            # Remove the service dir we prepended (only the first match, in case
            # it was already present for another reason).
            if inserted_path is not None:
                with contextlib.suppress(ValueError):
                    sys.path.remove(inserted_path)
            # Drop every module this import added — including transitively
            # imported same-named siblings (`common`, etc.) outside the root
            # namespace — then restore the modules we evicted so we leave
            # sys.modules as we found it (the returned class keeps its own
            # reference regardless).
            for name in set(sys.modules) - before:
                del sys.modules[name]
            sys.modules.update(saved_modules)

        try:
            settings_cls = getattr(module, class_name)
        except AttributeError as e:
            raise SchemaLoadError(
                f"Class '{class_name}' not found in module '{module_path}'"
            ) from e

        # Verify it's a BaseSettings subclass
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
        # Mirror load()'s sys.path / sys.modules isolation (#348c/#391, #413):
        # prepend the service dir at the *front* so the right service wins when
        # several expose the same module name, snapshot the cache, evict every
        # module this import added, and restore + remove the path entry in
        # finally. Without this, a stale cached module from another service (or a
        # leaked sys.path entry) would make two services with same-named config
        # modules resolve to each other's metadata.
        root_pkg = module_path.split(".", 1)[0]
        inserted_path: str | None = None
        if service_dir:
            service_dir = Path(service_dir).resolve()
            inserted_path = str(service_dir)
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
        except ImportError:
            return None
        finally:
            if inserted_path is not None:
                with contextlib.suppress(ValueError):
                    sys.path.remove(inserted_path)
            for name in set(sys.modules) - before:
                del sys.modules[name]
            sys.modules.update(saved_modules)

        func = getattr(module, "get_schema_metadata", None)
        if callable(func):
            result = func()
            return cast(dict[str, Any] | None, result)

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
