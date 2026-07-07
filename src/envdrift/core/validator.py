"""Validation logic for .env files against Pydantic schemas."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from envdrift.core.encryption import is_dotenvx_public_key_var
from envdrift.core.env_semantics import coerce_env_value, field_complexity
from envdrift.core.parser import EncryptionStatus, EnvFile
from envdrift.core.schema import FieldMetadata, SchemaMetadata


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

        # The parser strips a leading UTF-8 BOM so reports name the variable
        # the user wrote — but pydantic-settings reads .env files as plain
        # UTF-8 (dotenv_values default), so at startup the app sees the first
        # key BOM-prefixed and a required field backed by it comes up missing.
        # Surface that loudly instead of a silent false PASS (#486 review).
        if env_file.leading_bom:
            result.warnings.append(
                "File starts with a UTF-8 BOM: pydantic-settings reads .env files "
                "as plain UTF-8, so the app will see the first key with an "
                "invisible '\\ufeff' prefix and a required field backed by it "
                "will come up missing at startup. Remove the BOM or set "
                "env_file_encoding='utf-8-sig' on the model config."
            )

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

        # Check for missing required variables. With env_ignore_empty=True the
        # real env source drops empty values entirely, so a required field
        # assigned ``FIELD=`` is missing at startup exactly as if the line were
        # absent (#517 review) — the empty-value skips below must not turn that
        # crash into a false PASS.
        for field_name, field_meta in schema.fields.items():
            if not field_meta.required:
                continue
            env_var = env_by_lower.get(_lookup_key(field_meta))
            if env_var is None or (env_var.value == "" and schema.env_ignore_empty):
                result.missing_required.add(field_name)

        # Check for missing optional variables (as warning)
        for field_name, field_meta in schema.fields.items():
            if not field_meta.required and _lookup_key(field_meta) not in env_names_lower:
                result.missing_optional.add(field_name)

        # Check for extra variables. dotenvx's DOTENV_PUBLIC_KEY* artifact is
        # exempt: every dotenvx-encrypted file carries it, so flagging it would
        # fail the documented init -> encrypt -> validate loop on an
        # extra="forbid" schema (#472).
        if check_extra:
            extra = {
                name
                for name in env_file.variables
                if name.lower() not in schema_names_lower and not is_dotenvx_public_key_var(name)
            }
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

            # Also check for suspicious plaintext values. The dotenvx public-key
            # artifact is, by definition, public — its ``*_KEY`` name must not
            # produce a bogus "mark it sensitive" warning (#472).
            sensitive_lower = {name.lower() for name in schema.sensitive_fields}
            for var_name, env_var in env_file.variables.items():
                if is_dotenvx_public_key_var(var_name):
                    continue
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

        # Base type validation against the value pydantic-settings will see.
        # Coercion runs through the shared env_semantics module (the same one
        # diff uses) so the two commands cannot disagree (#472). An empty value
        # is only "unset" when the schema says so (env_ignore_empty) — by
        # default pydantic-settings passes '' through, so ``PORT=`` must fail
        # an int field here exactly as it fails the real app at startup.
        for field_name, field_meta in schema.fields.items():
            env_var = env_by_lower.get(_lookup_key(field_meta))
            if env_var is None:
                continue
            if env_var.value == "" and schema.env_ignore_empty:
                continue

            type_error = self._check_type(
                env_var.value, field_meta.field_type, field_meta.type_metadata
            )
            if type_error:
                result.type_errors[field_name] = type_error

        # Field-constraint validation (ge/le, Literal, min_length, pattern, ...).
        # The base check above only parses base types, so a config the real schema
        # rejects on a *constraint* used to pass as valid (#443). Instantiate the
        # live Settings class the way pydantic-settings feeds it: raw strings for
        # scalar fields, JSON-decoded values for complex fields (#472), skipping
        # only ciphertext (and empties when env_ignore_empty says they're unset).
        # Skipped for trivially-typed schemas (no constraints), where it would
        # only add cost.
        if schema.model_class is not None and schema.has_constraints:
            from pydantic import ValidationError

            values: dict[str, Any] = {}
            for field_name, field_meta in schema.fields.items():
                env_var = env_by_lower.get(_lookup_key(field_meta))
                if env_var is None:
                    continue
                value = env_var.value
                if value.startswith(("encrypted:", "ENC[")):
                    continue
                if value == "" and schema.env_ignore_empty:
                    continue
                is_complex, allow_parse_failure = field_complexity(
                    field_meta.field_type, field_meta.type_metadata
                )
                if is_complex:
                    # Mirror the env source: JSON-decode complex values; a union
                    # with a complex member falls back to the raw string. Plain
                    # complex fields with invalid JSON were already reported by
                    # the base check, so they are simply not re-fed here.
                    try:
                        values[field_meta.alias or field_name] = json.loads(value)
                    except ValueError:
                        if allow_parse_failure:
                            values[field_meta.alias or field_name] = value
                else:
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

    def _check_type(
        self, value: str, expected_type: type, metadata: tuple[Any, ...] = ()
    ) -> str | None:
        """
        Validate a plaintext .env value the way pydantic-settings would (#472).

        Coercion is delegated to :mod:`envdrift.core.env_semantics` (shared with
        diff): scalars are validated with pydantic's lax string rules (the full
        bool alias set, ASCII-only int parsing, ...) and complex types are
        JSON-decoded first, exactly like the real env source. Encrypted values
        and uncheckable annotations are skipped.

        Parameters:
            value (str): The raw value read from a .env file.
            expected_type (type): The field's annotation (e.g., int, bool, list[str]).
            metadata (tuple): The field's ``FieldInfo.metadata`` (e.g. a
                ``pydantic.Json`` marker, which makes the field non-complex).

        Returns:
            str | None: An error message describing the mismatch, or `None` if the
            value is acceptable or no check was performed.
        """
        if expected_type is None or expected_type is type(None):
            return None

        # Skip type check for encrypted values (supports both dotenvx and SOPS)
        # dotenvx format: encrypted:...
        # SOPS format: ENC[AES256_GCM,...
        if value.startswith("encrypted:") or value.startswith("ENC["):
            return None

        coerced = coerce_env_value(expected_type, value, metadata)
        if coerced.status != "fail":
            return None

        # Keep envdrift's friendly messages for the plain scalar types; fall
        # back to pydantic's own message everywhere else.
        type_name = getattr(expected_type, "__name__", str(expected_type))
        if type_name == "int":
            return f"Expected integer, got '{value}'"
        if type_name == "float":
            return f"Expected float, got '{value}'"
        if type_name == "bool":
            return f"Expected boolean, got '{value}'"
        return coerced.error or "invalid value"

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
