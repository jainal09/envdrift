"""Schema loader for Pydantic Settings classes."""

from __future__ import annotations

import contextlib
import importlib
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from pydantic import AliasChoices, AliasPath
from pydantic.fields import FieldInfo
from pydantic_settings import BaseSettings

# Environment variable to signal schema extraction mode
ENVDRIFT_SCHEMA_EXTRACTION = "ENVDRIFT_SCHEMA_EXTRACTION"

# Field types whose validation is fully covered by the name-based type check, so
# a schema using only these (with no constraints/validators) needs no real
# model_validate pass.
_PLAIN_SCALARS = (str, int, float, bool)


def _effective_env_binding(
    field_name: str, field_info: FieldInfo, raw_env_prefix: Any
) -> tuple[str | None, tuple[str, ...]]:
    """Return the model input alias and ordered environment bindings."""
    alias_candidate = field_info.validation_alias or field_info.alias

    if isinstance(alias_candidate, AliasChoices):
        binding_names = tuple(
            binding_name
            for choice in alias_candidate.choices
            if (binding_name := _alias_binding_name(choice)) is not None
        )
        if binding_names:
            return binding_names[0], binding_names

    binding_name = _alias_binding_name(alias_candidate)
    if binding_name is not None:
        return binding_name, (binding_name,)

    env_prefix = raw_env_prefix if isinstance(raw_env_prefix, str) else ""
    return None, (f"{env_prefix}{field_name}",)


def _alias_binding_name(alias: Any) -> str | None:
    """Return the environment name represented by one alias candidate."""
    if isinstance(alias, str):
        return alias
    if isinstance(alias, AliasPath) and alias.path:
        first_component = alias.path[0]
        if isinstance(first_component, str):
            return first_component
    return None


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
    # The effective Pydantic validation alias used as the input key for
    # ``model_validate``. ``validation_alias`` takes precedence over ``alias``.
    alias: str | None = None
    # The effective environment binding name. Plain fields include the model's
    # ``env_prefix``; explicit aliases bypass the prefix, matching
    # pydantic-settings. Kept separate from ``alias`` because model validation
    # expects field names/aliases, never prefixed environment names (#669).
    # For a multi-alias field this remains the first candidate for backward
    # compatibility; ``binding_names`` contains the complete ordered set.
    env_name: str | None = None
    # Every environment name the field can bind to, in pydantic-settings'
    # first-match-wins order. Plain fields have one prefixed name; explicit
    # aliases, including every AliasChoices candidate, bypass ``env_prefix``.
    binding_names: tuple[str, ...] = ()
    # The field's ``FieldInfo.metadata`` — pydantic strips ``Annotated[...]``
    # extras (constraint markers, ``pydantic.Json``, ...) into it, and the
    # env-source complexity/coercion decision needs it: a ``Json`` marker makes
    # the field non-complex, so the raw string must pass through untouched.
    type_metadata: tuple[Any, ...] = ()

    @property
    def is_optional(self) -> bool:
        """
        Indicates that the field can be omitted because it has a default value.

        Returns:
            `true` if the field can be omitted because it has a default value, `false` otherwise.
        """
        return not self.required


def _extract_field_metadata(
    field_name: str, field_info: FieldInfo, raw_env_prefix: Any
) -> tuple[FieldMetadata, bool]:
    """Build one field's metadata and report whether it needs constraint validation."""
    is_required = field_info.is_required()

    extra_schema = field_info.json_schema_extra
    is_sensitive = False
    if isinstance(extra_schema, dict):
        raw_sensitive = extra_schema.get("sensitive", False)
        is_sensitive = raw_sensitive if isinstance(raw_sensitive, bool) else False

    annotation = field_info.annotation
    has_constraints = bool(field_info.metadata) or annotation not in _PLAIN_SCALARS
    if annotation is None:
        type_str = "Any"
    elif hasattr(annotation, "__name__"):
        type_str = annotation.__name__
    else:
        type_str = str(annotation)

    # Keep model-validation input separate from environment binding: plain
    # fields add env_prefix while explicit aliases do not.
    field_alias, binding_names = _effective_env_binding(field_name, field_info, raw_env_prefix)

    return (
        FieldMetadata(
            name=field_name,
            required=is_required,
            sensitive=is_sensitive,
            default=None if is_required else field_info.default,
            description=field_info.description,
            field_type=annotation if annotation else type(None),
            annotation=type_str,
            alias=field_alias,
            env_name=binding_names[0],
            binding_names=binding_names,
            type_metadata=tuple(field_info.metadata),
        ),
        has_constraints,
    )


@dataclass
class SchemaMetadata:
    """Complete schema metadata."""

    class_name: str
    module_path: str
    fields: dict[str, FieldMetadata] = field(default_factory=dict)
    extra_policy: str = "ignore"  # "forbid", "ignore", "allow"
    # The live Settings class, when available, so validation can run the real
    # Pydantic field-constraint checks (ge/le, Literal, min_length, pattern, ...)
    # rather than only the name-based type heuristics derived from the metadata.
    model_class: type[BaseSettings] | None = None
    # True when at least one field carries validation beyond a plain scalar type
    # (a constraint, a Literal/special/nested type, or a custom validator). Lets
    # the validator skip the (relatively expensive) real model_validate pass for
    # trivially-typed schemas, where the name-based type check already suffices.
    has_constraints: bool = False
    # Mirrors SettingsConfigDict(env_ignore_empty=...): when True the env source
    # drops empty values (the field is unset), so validation must skip them too;
    # when False (the pydantic-settings default) the model sees the empty string
    # and e.g. ``PORT=`` crashes an int field at startup (#472).
    env_ignore_empty: bool = False
    # Mirrors SettingsConfigDict(case_sensitive=...). Environment binding names
    # are folded only when False, the pydantic-settings default.
    case_sensitive: bool = False

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
        except SchemaLoadError:
            raise  # already a clean error (missing class / not a BaseSettings)
        except ImportError as e:
            raise SchemaLoadError(f"Cannot import module '{module_path}': {e}") from e
        except Exception as e:
            # Any other error raised *while importing the schema module*
            # (SyntaxError, NameError, RuntimeError, ...) used to escape as a raw
            # traceback; surface it as a clean schema-load error (#443 #21).
            raise SchemaLoadError(f"Error importing schema module '{module_path}': {e}") from e
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
            model_class=settings_cls,
        )

        # Determine extra policy from model_config
        model_config = getattr(settings_cls, "model_config", {})
        if isinstance(model_config, dict):
            extra = model_config.get("extra", "ignore")
            raw_env_prefix = model_config.get("env_prefix", "")
            case_sensitive = model_config.get("case_sensitive", False)
        else:
            # SettingsConfigDict object
            extra = getattr(model_config, "extra", "ignore")
            raw_env_prefix = getattr(model_config, "env_prefix", "")
            case_sensitive = getattr(model_config, "case_sensitive", False)

        schema.extra_policy = extra if extra else "ignore"
        schema.case_sensitive = bool(case_sensitive)

        # env_ignore_empty changes what the env source does with empty values
        # (drop vs pass through), which changes what validation must check (#472).
        if isinstance(model_config, dict):
            ignore_empty = model_config.get("env_ignore_empty", False)
        else:
            ignore_empty = getattr(model_config, "env_ignore_empty", False)
        schema.env_ignore_empty = bool(ignore_empty)

        # Track whether any field needs real Pydantic validation (a constraint, a
        # non-plain-scalar type such as Literal/EmailStr/a nested model, or a
        # custom validator). A model with only plain str/int/float/bool fields is
        # fully covered by the name-based type check, so the validator can skip
        # the expensive model_validate pass for it.
        has_constraints = False

        # Extract field metadata
        for field_name, field_info in settings_cls.model_fields.items():
            field_metadata, field_has_constraints = _extract_field_metadata(
                field_name, field_info, raw_env_prefix
            )
            schema.fields[field_name] = field_metadata
            has_constraints = has_constraints or field_has_constraints

        # A custom @field_validator / @model_validator can reject otherwise
        # plainly-typed values, so it too requires the real validator.
        decorators = getattr(settings_cls, "__pydantic_decorators__", None)
        if decorators is not None and (
            getattr(decorators, "field_validators", None)
            or getattr(decorators, "model_validators", None)
            or getattr(decorators, "validators", None)
        ):
            has_constraints = True

        schema.has_constraints = has_constraints
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
