"""Unit tests for envdrift.core.env_semantics (#472).

The shared coercion module must mirror pydantic-settings exactly, and must
return ``skip`` (never a false verdict) for annotations it cannot check.
"""

from __future__ import annotations

from typing import Annotated, Any

import pytest
from pydantic import BeforeValidator

from envdrift.core.env_semantics import coerce_env_value, field_complexity


class TestFieldComplexity:
    """Mirror of pydantic-settings' complex-field decision."""

    @pytest.mark.parametrize(
        ("tp", "expected"),
        [
            (str, (False, False)),
            (int, (False, False)),
            (bool, (False, False)),
            (bytes, (False, False)),
            (int | None, (False, False)),
            (list[str], (True, False)),
            (dict[str, int], (True, False)),
            (set[int], (True, False)),
            (tuple[int, ...], (True, False)),
            (list, (True, False)),
            # Annotated wrapping is unwrapped before the decision.
            (Annotated[list[str], "meta"], (True, False)),
            # A union containing a complex member tolerates JSON parse failure.
            (list[str] | None, (True, True)),
            (list[str] | str, (True, True)),
        ],
    )
    def test_complexity_matrix(self, tp, expected):
        assert field_complexity(tp) == expected


class TestCoerceEnvValue:
    """Verdict semantics: ok / fail / skip."""

    def test_uncheckable_annotations_skip(self):
        assert coerce_env_value(None, "x").status == "skip"
        assert coerce_env_value(Any, "x").status == "skip"
        assert coerce_env_value(type(None), "x").status == "skip"

    def test_unadaptable_annotation_skips(self):
        # A dict is unhashable (uncached path) and TypeAdapter can't build for
        # it - the module must return skip, not crash or guess.
        weird = {"not": "a type"}
        assert coerce_env_value(weird, "x").status == "skip"

    def test_non_validation_error_from_scalar_validator_skips(self):
        def boom(value: object) -> object:
            raise RuntimeError("boom")

        weird = Annotated[int, BeforeValidator(boom)]
        assert coerce_env_value(weird, "5").status == "skip"

    def test_non_validation_error_from_complex_validator_skips(self):
        def boom(value: object) -> object:
            raise RuntimeError("boom")

        weird = Annotated[list[int], BeforeValidator(boom)]
        assert coerce_env_value(weird, "[1, 2]").status == "skip"

    def test_complex_union_falls_back_to_raw_string(self):
        result = coerce_env_value(list[str] | str, "not-json")
        assert result.status == "ok"
        assert result.value == "not-json"

    def test_complex_field_bad_json_fails_with_message(self):
        result = coerce_env_value(list[str], "a,b,c")
        assert result.status == "fail"
        assert "JSON" in (result.error or "")

    def test_scalar_failure_carries_pydantic_message(self):
        result = coerce_env_value(int, "not-a-number")
        assert result.status == "fail"
        assert "integer" in (result.error or "").lower()

    def test_adapter_cache_round_trip(self):
        # Same annotation twice: second call hits the cache and must agree.
        first = coerce_env_value(int, "42")
        second = coerce_env_value(int, "43")
        assert (first.status, first.value) == ("ok", 42)
        assert (second.status, second.value) == ("ok", 43)
