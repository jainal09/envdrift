"""Validation logic for .env files against Pydantic schemas."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from envdrift.core.parser import EncryptionStatus, EnvFile
from envdrift.core.schema import SchemaMetadata


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

        env_var_names = set(env_file.variables.keys())
        schema_field_names = set(schema.fields.keys())

        # Check for missing required variables
        for field_name, field_meta in schema.fields.items():
            if field_meta.required and field_name not in env_var_names:
                result.missing_required.add(field_name)

        # Check for missing optional variables (as warning)
        for field_name, field_meta in schema.fields.items():
            if not field_meta.required and field_name not in env_var_names:
                result.missing_optional.add(field_name)

        # Check for extra variables
        if check_extra:
            extra = env_var_names - schema_field_names
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
                if field_name not in env_file.variables:
                    continue

                env_var = env_file.variables[field_name]

                # Check schema-defined sensitive fields
                if field_meta.sensitive:
                    if env_var.encryption_status == EncryptionStatus.PLAINTEXT:
                        result.unencrypted_secrets.add(field_name)

            # Also check for suspicious plaintext values
            for var_name, env_var in env_file.variables.items():
                if env_var.encryption_status == EncryptionStatus.PLAINTEXT:
                    if self.is_value_suspicious(env_var.value):
                        if var_name not in schema.sensitive_fields:
                            result.warnings.append(
                                f"'{var_name}' looks like a secret but "
                                "is not marked sensitive in schema"
                            )
                    if self.is_name_suspicious(var_name):
                        if var_name not in schema.sensitive_fields:
                            result.warnings.append(
                                f"'{var_name}' has a name suggesting sensitive data "
                                "but is not marked sensitive in schema"
                            )

        # Basic type validation
        for field_name, field_meta in schema.fields.items():
            if field_name not in env_file.variables:
                continue

            env_var = env_file.variables[field_name]
            type_error = self._check_type(env_var.value, field_meta.field_type)
            if type_error:
                result.type_errors[field_name] = type_error

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

        # Skip type check for encrypted values
        if value.startswith("encrypted:"):
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
