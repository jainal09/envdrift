"""Validation logic for .env files against Pydantic schemas."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal, Union, get_args, get_origin

from envdrift.core.parser import EncryptionStatus, EnvFile
from envdrift.core.schema import FieldMetadata, SchemaMetadata

_COERCIBLE_SCALARS = (str, int, float, bool)


def _is_string_coercible(tp: object) -> bool:
    """True if model_validate can validate a *raw env string* against ``tp``.

    Pydantic-settings parses complex types (``list``/``dict``/nested models) from
    their env string via JSON in its env source; ``model_validate`` of the raw
    string does not, so feeding it such a field would wrongly reject a config the
    real schema accepts. Only scalars, ``Literal``, and Optionals of those accept
    a string directly, so only those are checked via model_validate.
    """
    if tp in _COERCIBLE_SCALARS:
        return True
    origin = get_origin(tp)
    if origin is Literal:
        return True
    if origin is Union:  # Optional[X] / X | None
        return all(arg is type(None) or _is_string_coercible(arg) for arg in get_args(tp))
    return False


@dataclass
class ValidationResult:
    """Result of schema validation."""

    valid: bool
    missing_required: set[str] = field(default_factory=set)
    missing_optional: set[str] = field(default_factory=set)
    extra_vars: set[str] = field(default_factory=set)
    unencrypted_secrets: set[str] = field(default_factory=set)
    type_errors: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        """
        Return whether the validation contains any errors (exclude warnings).

        Checks for missing required variables, type errors, or extra variables
        present when the schema forbids extras. Unencrypted secrets are warnings,
        not errors - use `envdrift encrypt --check` for strict enforcement.

        Returns:
            True if any errors are present, False otherwise.
        """
        return bool(self.missing_required) or bool(self.type_errors) or bool(self.extra_vars)

    @property
    def error_count(self) -> int:
        """
        Compute the total number of validation error entries.

        Returns:
            int: Sum of missing required variables, type errors, and extra variables.
        """
        return len(self.missing_required) + len(self.type_errors) + len(self.extra_vars)

    @property
    def warning_count(self) -> int:
        """
        Compute the total number of warning entries.

        Combines explicit warnings, missing optional variables, and unencrypted secrets.

        Returns:
            The total count of warnings as an integer.
        """
        return len(self.warnings) + len(self.missing_optional) + len(self.unencrypted_secrets)


class Validator:
    """Validate .env files against Pydantic schemas."""

    # Patterns that suggest a value is a secret
    SECRET_PATTERNS = [
        re.compile(r"^sk[-_]", re.IGNORECASE),  # API keys (Stripe, OpenAI)
        re.compile(r"^pk[-_]", re.IGNORECASE),  # Public/private keys
        re.compile(r"password", re.IGNORECASE),  # Passwords
        re.compile(r"secret", re.IGNORECASE),  # Secrets
        re.compile(r"^ghp_"),  # GitHub personal tokens
        re.compile(r"^gho_"),  # GitHub OAuth tokens
        re.compile(r"^ghu_"),  # GitHub user tokens
        re.compile(r"^xox[baprs]-"),  # Slack tokens
        re.compile(r"^AKIA[0-9A-Z]{16}$"),  # AWS access keys
        re.compile(r"^postgres://.*:.*@"),  # DB URLs with credentials
        re.compile(r"^postgresql://.*:.*@"),
        re.compile(r"^mysql://.*:.*@"),
        re.compile(r"^redis://.*:.*@"),
        re.compile(r"^mongodb://.*:.*@"),
        re.compile(r"^mongodb\+srv://.*:.*@"),
        re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ"),  # JWT tokens
    ]

    # Variable names that suggest sensitive content
    SENSITIVE_VAR_PATTERNS = [
        re.compile(r".*_KEY$", re.IGNORECASE),
        re.compile(r".*_SECRET$", re.IGNORECASE),
        re.compile(r".*_TOKEN$", re.IGNORECASE),
        re.compile(r".*_PASSWORD$", re.IGNORECASE),
        re.compile(r".*_PASS$", re.IGNORECASE),
        re.compile(r".*_CREDENTIAL.*", re.IGNORECASE),
        re.compile(r".*_API_KEY$", re.IGNORECASE),
        re.compile(r"^JWT_.*", re.IGNORECASE),
        re.compile(r"^AUTH_.*", re.IGNORECASE),
        re.compile(r".*_DSN$", re.IGNORECASE),  # Sentry DSN
    ]

    def validate(
        self,
        env_file: EnvFile,
        schema: SchemaMetadata,
        check_encryption: bool = True,
        check_extra: bool = True,
    ) -> ValidationResult:
        """Validate env file against schema.

        Checks:
        1. All required vars exist
        2. No unexpected vars (if schema has extra="forbid")
        3. Sensitive vars are encrypted
        4. Values match expected types (basic check)

        Args:
            env_file: Parsed env file
            schema: Schema metadata
            check_encryption: Whether to check if sensitive vars are encrypted
            check_extra: Whether to check for extra variables

        Returns:
            ValidationResult with all issues found
        """
        result = ValidationResult(valid=True)

        # Pydantic Settings defaults to case_sensitive=False, loading e.g.
        # `API_KEY` from a conventional UPPERCASE .env into a lowercase
        # `api_key` field. Mirror that here by matching names case-insensitively
        # so an UPPERCASE .env against a lowercase schema is not falsely
        # reported as both missing_required and extra_vars (see issue #306).
        # A field is matched against the .env by its alias when it has one (the
        # real env-var name, e.g. ``X-API-KEY`` for attribute ``X_API_KEY``),
        # else by its attribute name — mirroring how pydantic-settings binds.
        def _lookup_key(fm: FieldMetadata) -> str:
            return (fm.alias or fm.name).lower()

        schema_names_lower = {_lookup_key(fm) for fm in schema.fields.values()}

        # One pass over the env vars derives everything case-insensitive matching
        # needs (Pydantic Settings defaults to case_insensitive):
        #   - env_names_lower: lower-cased names present (missing/extra checks)
        #   - env_by_lower:    lower-cased name -> env var, last-wins like Pydantic
        #   - env_groups:      lower-cased name -> every original name, so a
        #     case-only collision (e.g. ``API_KEY`` + ``api_key``) is surfaced as
        #     a warning instead of silently dropping a value (see issue #306).
        env_names_lower: set[str] = set()
        env_by_lower = {}
        env_groups: dict[str, list[str]] = {}
        for name, env_var in env_file.variables.items():
            lower = name.lower()
            env_names_lower.add(lower)
            env_by_lower[lower] = env_var  # last-wins, mirroring Pydantic Settings
            env_groups.setdefault(lower, []).append(name)

        for lower_name, names in env_groups.items():
            if len(names) > 1:
                kept = names[-1]
                dropped = ", ".join(repr(n) for n in names[:-1])
                result.warnings.append(
                    f"Case-insensitive name collision for {lower_name!r}: "
                    f"{', '.join(repr(n) for n in names)} all map to the same field; "
                    f"value from {kept!r} is used, {dropped} ignored"
                )

        # Check for missing required variables
        for field_name, field_meta in schema.fields.items():
            if field_meta.required and _lookup_key(field_meta) not in env_names_lower:
                result.missing_required.add(field_name)

        # Check for missing optional variables (as warning)
        for field_name, field_meta in schema.fields.items():
            if not field_meta.required and _lookup_key(field_meta) not in env_names_lower:
                result.missing_optional.add(field_name)

        # Check for extra variables
        if check_extra:
            extra = {name for name in env_file.variables if name.lower() not in schema_names_lower}
            if extra:
                if schema.extra_policy == "forbid":
                    result.extra_vars = extra
                else:
                    # Just a warning when extra is "ignore" or "allow"
                    for var_name in extra:
                        result.warnings.append(f"Extra variable '{var_name}' not in schema")

        # Check encryption status for sensitive variables
        if check_encryption:
            for field_name, field_meta in schema.fields.items():
                env_var = env_by_lower.get(_lookup_key(field_meta))
                if env_var is None:
                    continue

                # Check schema-defined sensitive fields
                if field_meta.sensitive:
                    if env_var.encryption_status == EncryptionStatus.PLAINTEXT:
                        result.unencrypted_secrets.add(field_name)

            # Also check for suspicious plaintext values
            sensitive_lower = {name.lower() for name in schema.sensitive_fields}
            for var_name, env_var in env_file.variables.items():
                if env_var.encryption_status == EncryptionStatus.PLAINTEXT:
                    if self.is_value_suspicious(env_var.value):
                        if var_name.lower() not in sensitive_lower:
                            result.warnings.append(
                                f"'{var_name}' looks like a secret but "
                                "is not marked sensitive in schema"
                            )
                    if self.is_name_suspicious(var_name):
                        if var_name.lower() not in sensitive_lower:
                            result.warnings.append(
                                f"'{var_name}' has a name suggesting sensitive data "
                                "but is not marked sensitive in schema"
                            )

        # Basic type validation (name-based). Produces envdrift's own messages and
        # skips encrypted/empty values; kept as the source of base-type errors.
        for field_name, field_meta in schema.fields.items():
            env_var = env_by_lower.get(_lookup_key(field_meta))
            if env_var is None:
                continue

            type_error = self._check_type(env_var.value, field_meta.field_type)
            if type_error:
                result.type_errors[field_name] = type_error

        # Field-constraint validation (ge/le, Literal, min_length, pattern, ...).
        # The heuristic above only parses base types, so a config the real schema
        # rejects on a *constraint* used to pass as valid (#443). Instantiate the
        # live Settings class with the type-valid, non-encrypted, non-empty values
        # and surface the constraint errors the heuristic cannot see. Skipped for
        # trivially-typed schemas (no constraints), where it would only add cost.
        if schema.model_class is not None and schema.has_constraints:
            from pydantic import ValidationError

            values: dict[str, str] = {}
            for field_name, field_meta in schema.fields.items():
                env_var = env_by_lower.get(_lookup_key(field_meta))
                if env_var is None:
                    continue
                value = env_var.value
                # Mirror _check_type's skips: ciphertext and empty (= unset).
                if value == "" or value.startswith(("encrypted:", "ENC[")):
                    continue
                # Only feed fields whose raw env string model_validate can check.
                # Complex types (list/dict/nested) are JSON-parsed by the env source
                # at runtime, which model_validate of the raw string does not do, so
                # including them would wrongly reject a valid config (#443 review).
                if not _is_string_coercible(field_meta.field_type):
                    continue
                values[field_meta.alias or field_name] = value

            try:
                schema.model_class.model_validate(values)
            except ValidationError as exc:
                alias_to_field = {(fm.alias or name): name for name, fm in schema.fields.items()}
                for err in exc.errors():
                    # missing/extra are reported via missing_required / extra_vars;
                    # don't override a base-type message the heuristic already set.
                    if err.get("type") in ("missing", "extra_forbidden"):
                        continue
                    loc = err.get("loc") or ()
                    key = str(loc[0]) if loc else ""
                    field_name = alias_to_field.get(key, key)
                    if field_name in schema.fields and field_name not in result.type_errors:
                        result.type_errors[field_name] = err.get("msg", "invalid value")
            except Exception:
                # A model-level @model_validator / model_post_init can raise a
                # non-ValidationError; the base-type check already ran, so a
                # constraint-pass failure must not crash validate (#443 review).
                pass

        # Determine overall validity
        # Note: unencrypted_secrets are warnings, not errors
        # Use `envdrift encrypt --check` for strict encryption enforcement
        result.valid = not (result.missing_required or result.type_errors or result.extra_vars)

        return result

    def is_value_suspicious(self, value: str) -> bool:
        """
        Determine whether a plaintext value matches any known secret-like pattern.

        Returns:
            `true` if the value matches any secret-like pattern, `false` otherwise.
        """
        for pattern in self.SECRET_PATTERNS:
            if pattern.search(value):
                return True
        return False

    def is_name_suspicious(self, name: str) -> bool:
        """
        Determine whether an environment variable name indicates it contains sensitive data.

        Parameters:
            name (str): Environment variable name to evaluate.

        Returns:
            bool: `True` if the variable name matches a sensitive pattern, `False` otherwise.
        """
        for pattern in self.SENSITIVE_VAR_PATTERNS:
            if pattern.match(name):
                return True
        return False

    def _check_type(self, value: str, expected_type: type) -> str | None:
        """
        Validate a plaintext .env value against an expected Python type.

        Parameters:
            value (str): The raw value read from a .env file.
            expected_type (type): The Python type expected for the value (e.g., int, float, bool, list).

        Notes:
            If `expected_type` is None or `value` is an empty string, no type check is performed and the function returns None.

        Returns:
            str | None: An error message describing the type mismatch, or `None` if the value is acceptable or no check was performed.
        """
        if expected_type is None or value == "":
            return None

        # Skip type check for encrypted values (supports both dotenvx and SOPS)
        # dotenvx format: encrypted:...
        # SOPS format: ENC[AES256_GCM,...
        if value.startswith("encrypted:") or value.startswith("ENC["):
            return None

        type_name = getattr(expected_type, "__name__", str(expected_type))

        # Handle int
        if type_name == "int":
            try:
                int(value)
            except ValueError:
                return f"Expected integer, got '{value}'"

        # Handle float
        elif type_name == "float":
            try:
                float(value)
            except ValueError:
                return f"Expected float, got '{value}'"

        # Handle bool
        elif type_name == "bool":
            if value.lower() not in ("true", "false", "1", "0", "yes", "no"):
                return f"Expected boolean, got '{value}'"

        # Handle list (basic check for list-like structure)
        elif type_name == "list":
            # Lists in .env are typically comma-separated or JSON
            # We'll accept anything here, just check it's not obviously wrong
            pass

        return None

    def generate_fix_template(self, result: ValidationResult, schema: SchemaMetadata) -> str:
        """
        Generate a .env snippet that provides assignments for any missing schema variables.

        Parameters:
            result (ValidationResult): Validation outcome containing `missing_required` and `missing_optional` sets.
            schema (SchemaMetadata): Schema metadata used to include field descriptions, defaults, and sensitivity flags.

        Returns:
            template (str): A newline-separated .env template. Required sensitive fields use the placeholder
            `encrypted:YOUR_VALUE_HERE`; optional fields include commented defaults when available.
        """
        lines = []

        if result.missing_required:
            lines.append("# Missing required variables:")
            for var_name in sorted(result.missing_required):
                field_meta = schema.fields.get(var_name)
                if field_meta and field_meta.description:
                    lines.append(f"# {field_meta.description}")
                if field_meta and field_meta.sensitive:
                    lines.append(f'{var_name}="encrypted:YOUR_VALUE_HERE"')
                else:
                    lines.append(f"{var_name}=")
                lines.append("")

        if result.missing_optional:
            lines.append("# Missing optional variables (have defaults):")
            for var_name in sorted(result.missing_optional):
                field_meta = schema.fields.get(var_name)
                if field_meta and field_meta.description:
                    lines.append(f"# {field_meta.description}")
                default = field_meta.default if field_meta else None
                if default is not None:
                    lines.append(f"# {var_name}={default}")
                else:
                    lines.append(f"# {var_name}=")
                lines.append("")

        return "\n".join(lines)
