"""Unit tests for envdrift.core.env_semantics (#472).

The shared coercion module must mirror pydantic-settings exactly, and must
return ``skip`` (never a false verdict) for annotations it cannot check.
"""

from __future__ import annotations

from typing import Annotated, Any, TypeVar, get_args

import pytest
from pydantic import BeforeValidator, Json, RootModel
from typing_extensions import TypeAliasType

from envdrift.core.env_semantics import coerce_env_value, field_complexity

# `type Hosts = list[str]` is 3.12+ syntax; TypeAliasType is what it compiles
# to, and typing_extensions provides it on every supported Python.
Hosts = TypeAliasType("Hosts", list[str])
Port = TypeAliasType("Port", int)
_T = TypeVar("_T")
# `type Pair[T] = list[T]` — a *subscripted* alias resolves via its origin.
Pair = TypeAliasType("Pair", list[_T], type_params=(_T,))
# The Json() marker instance exactly as pydantic stores it in FieldInfo.metadata.
_JSON_MARKERS = get_args(Json[list[str]])[1:]


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
            # ... including when the inner type is a union (#517 review):
            # get_origin(tp) is Annotated, so the union branch must run on the
            # peeled type, not the wrapper.
            (Annotated[list[str] | None, "meta"], (True, True)),
            # A union containing a complex member tolerates JSON parse failure.
            (list[str] | None, (True, True)),
            (list[str] | str, (True, True)),
            # A pydantic Json marker suppresses complexity: the raw string
            # passes through the env source and Json decodes it at validation.
            (Json[list[str]], (False, False)),
            (Json[list[str]] | None, (False, False)),
            # PEP 695 `type X = ...` aliases resolve to their value first.
            (Hosts, (True, False)),
            (Port, (False, False)),
            (Hosts | None, (True, True)),
            (Pair[str], (True, False)),
            # RootModel complexity is judged by the *root* annotation.
            (RootModel[str], (False, False)),
            (RootModel[list[str]], (True, False)),
        ],
    )
    def test_complexity_matrix(self, tp, expected):
        assert field_complexity(tp) == expected

    def test_json_marker_in_field_metadata_is_not_complex(self):
        # pydantic strips `Json[list[str]]` to annotation=list[str] with
        # metadata=[Json()]; the mirror must honor the metadata the same way
        # the real _annotation_is_complex(annotation, metadata) does.
        assert field_complexity(list[str], _JSON_MARKERS) == (False, False)


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

    def test_json_metadata_field_accepts_json_string(self):
        # A Json[list[str]] field arrives as (list[str], metadata=[Json()]):
        # the raw string is not pre-decoded, the Json type parses it (#517).
        result = coerce_env_value(list[str], '["a","b"]', _JSON_MARKERS)
        assert result.status == "ok"
        assert result.value == ["a", "b"]

    def test_json_metadata_field_rejects_non_json(self):
        result = coerce_env_value(list[str], "a,b,c", _JSON_MARKERS)
        assert result.status == "fail"
        assert "JSON" in (result.error or "")

    def test_type_alias_list_is_json_decoded(self):
        result = coerce_env_value(Hosts, '["a","b"]')
        assert result.status == "ok"
        assert result.value == ["a", "b"]

    def test_type_alias_list_rejects_csv(self):
        result = coerce_env_value(Hosts, "a,b")
        assert result.status == "fail"

    def test_root_model_str_accepts_plain_string(self):
        result = coerce_env_value(RootModel[str], "plain")
        assert result.status == "ok"

    def test_root_model_list_is_json_decoded(self):
        result = coerce_env_value(RootModel[list[str]], '["a","b"]')
        assert result.status == "ok"
        assert coerce_env_value(RootModel[list[str]], "a,b").status == "fail"
