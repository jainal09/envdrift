"""Cross-environment diff engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from envdrift.core.parser import EnvFile
from envdrift.core.schema import SchemaMetadata


class DiffType(Enum):
    """Type of difference between environments."""

    ADDED = "added"  # In env2 but not env1
    REMOVED = "removed"  # In env1 but not env2
    CHANGED = "changed"  # Different values
    UNCHANGED = "unchanged"  # Same values


@dataclass
class VarDiff:
    """Difference for a single variable."""

    name: str
    diff_type: DiffType
    value1: str | None  # Value in env1 (masked if sensitive)
    value2: str | None  # Value in env2 (masked if sensitive)
    is_sensitive: bool
    line_number1: int | None = None  # Line in env1
    line_number2: int | None = None  # Line in env2


@dataclass
class DiffResult:
    """Result of comparing two env files."""

    env1_path: Path
    env2_path: Path
    differences: list[VarDiff] = field(default_factory=list)

    @property
    def added_count(self) -> int:
        """
        Number of variables that are present in env2 but not in env1.

        Returns:
            int: Count of variables classified as `ADDED`.
        """
        return sum(1 for d in self.differences if d.diff_type == DiffType.ADDED)

    @property
    def removed_count(self) -> int:
        """
        Number of variables that are present in the first environment but missing in the second.

        Returns:
            int: Count of diffs with type `DiffType.REMOVED`.
        """
        return sum(1 for d in self.differences if d.diff_type == DiffType.REMOVED)

    @property
    def changed_count(self) -> int:
        """
        Number of variables whose values differ between the two environments.

        Returns:
            int: Count of VarDiff entries whose `diff_type` is `DiffType.CHANGED`.
        """
        return sum(1 for d in self.differences if d.diff_type == DiffType.CHANGED)

    @property
    def unchanged_count(self) -> int:
        """
        Return the number of variables that are unchanged between the two environments.

        Returns:
            int: Count of VarDiff entries whose `diff_type` is `DiffType.UNCHANGED`.
        """
        return sum(1 for d in self.differences if d.diff_type == DiffType.UNCHANGED)

    @property
    def has_drift(self) -> bool:
        """
        Determine whether there is any drift between the two environments.

        Returns:
            True if at least one variable was added, removed, or changed, False otherwise.
        """
        return self.added_count + self.removed_count + self.changed_count > 0

    def get_added(self) -> list[VarDiff]:
        """
        List VarDiff entries that are present only in the second environment.

        Returns:
            list[VarDiff]: VarDiff objects whose `diff_type` is `DiffType.ADDED`.
        """
        return [d for d in self.differences if d.diff_type == DiffType.ADDED]

    def get_removed(self) -> list[VarDiff]:
        """
        Retrieve variables present in the first environment but absent in the second.

        Returns:
            list[VarDiff]: VarDiff objects whose `diff_type` is `DiffType.REMOVED`.
        """
        return [d for d in self.differences if d.diff_type == DiffType.REMOVED]

    def get_changed(self) -> list[VarDiff]:
        """
        Return all variables whose values differ between the two environments.

        Returns:
            list[VarDiff]: List of VarDiff entries whose `diff_type` is `DiffType.CHANGED`.
        """
        return [d for d in self.differences if d.diff_type == DiffType.CHANGED]


class DiffEngine:
    """Compare two .env files."""

    MASK_VALUE = "********"

    def diff(
        self,
        env1: EnvFile,
        env2: EnvFile,
        schema: SchemaMetadata | None = None,
        mask_values: bool = True,
        include_unchanged: bool = False,
    ) -> DiffResult:
        """
        Compute differences between two environment files and return a structured DiffResult.

        Parameters:
            env1 (EnvFile): First environment file (left-hand side of comparison).
            env2 (EnvFile): Second environment file (right-hand side of comparison).
            schema (SchemaMetadata | None): Optional schema used to identify sensitive fields.
            mask_values (bool): If True, sensitive variable values are replaced with a mask in the result.
            include_unchanged (bool): If True, variables with identical values in both files are included.

        Returns:
            DiffResult: Aggregated comparison result containing a list of VarDiff entries and summary counts.
        """
        result = DiffResult(env1_path=env1.path, env2_path=env2.path)

        env1_vars = set(env1.variables.keys())
        env2_vars = set(env2.variables.keys())

        all_vars = env1_vars | env2_vars
        sensitive_fields = set(schema.sensitive_fields) if schema else set()

        for var_name in sorted(all_vars):
            in_env1 = var_name in env1_vars
            in_env2 = var_name in env2_vars
            is_sensitive = var_name in sensitive_fields

            var1 = env1.variables.get(var_name)
            var2 = env2.variables.get(var_name)

            # Get values (potentially masked)
            value1 = var1.value if var1 else None
            value2 = var2.value if var2 else None

            if mask_values and is_sensitive:
                display_value1 = self.MASK_VALUE if value1 else None
                display_value2 = self.MASK_VALUE if value2 else None
            else:
                display_value1 = value1
                display_value2 = value2

            # Determine diff type
            if not in_env1 and in_env2:
                diff_type = DiffType.ADDED
            elif in_env1 and not in_env2:
                diff_type = DiffType.REMOVED
            elif value1 != value2:
                diff_type = DiffType.CHANGED
            else:
                diff_type = DiffType.UNCHANGED
                if not include_unchanged:
                    continue

            var_diff = VarDiff(
                name=var_name,
                diff_type=diff_type,
                value1=display_value1,
                value2=display_value2,
                is_sensitive=is_sensitive,
                line_number1=var1.line_number if var1 else None,
                line_number2=var2.line_number if var2 else None,
            )

            result.differences.append(var_diff)

        return result

    def to_dict(self, result: DiffResult) -> dict:
        """
        Convert a DiffResult into a JSON-serializable dictionary.

        Args:
            result: DiffResult instance to convert.

        Returns:
            dict: Mapping with keys:
                - "env1": string path of the first env file
                - "env2": string path of the second env file
                - "summary": dict with counts ("added", "removed", "changed") and "has_drift" flag
                - "differences": list of dicts for each variable containing "name", "type", "value_env1", "value_env2", and "sensitive"
        """
        return {
            "env1": str(result.env1_path),
            "env2": str(result.env2_path),
            "summary": {
                "added": result.added_count,
                "removed": result.removed_count,
                "changed": result.changed_count,
                "has_drift": result.has_drift,
            },
            "differences": [
                {
                    "name": d.name,
                    "type": d.diff_type.value,
                    "value_env1": d.value1,
                    "value_env2": d.value2,
                    "sensitive": d.is_sensitive,
                }
                for d in result.differences
            ],
        }
