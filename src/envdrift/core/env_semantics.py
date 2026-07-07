"""Pydantic-settings parity semantics for raw .env values.

``validate`` and ``diff`` must answer "how would the real pydantic-settings env
source see this raw string for this field type?" through this single module so
their verdicts cannot diverge (#472).

Ground truth is pydantic-settings itself:

* scalar fields receive the raw env string and are validated with pydantic's
  lax string rules (``TypeAdapter.validate_strings`` — the same core rules the
  model applies at startup, e.g. the full bool alias set ``on/off/t/f/y/n/...``
  and ASCII-only int parsing);
* complex fields (list/dict/set/tuple/nested models/dataclasses) are
  JSON-decoded by the env source first (``SettingsError`` on bad JSON), then
  validated — mirrored here by ``json.loads`` + ``validate_python``;
* a union containing a complex member tolerates JSON-decode failure and falls
  back to the raw string (pydantic-settings' ``allow_parse_failure``).
"""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, is_dataclass
from types import UnionType
from typing import Annotated, Any, Literal, Union, get_args, get_origin

from pydantic import BaseModel, Json, RootModel, TypeAdapter, ValidationError
from typing_inspection import typing_objects

#: Coercion verdicts. ``ok``: the real app accepts the value (``value`` holds
#: the parsed result). ``fail``: the real app rejects it at startup (``error``
#: holds a message). ``skip``: the type carries no checkable semantics
#: (``Any`` / ``None`` / un-adaptable annotations) — callers must not draw a
#: verdict from it.
CoercionStatus = Literal["ok", "fail", "skip"]


@dataclass(frozen=True)
class CoercionResult:
    """Outcome of coercing a raw env string through a field's type."""

    status: CoercionStatus
    value: Any = None
    error: str | None = None


_adapter_cache: dict[Any, TypeAdapter[Any] | None] = {}


def _build_adapter(tp: Any) -> TypeAdapter[Any] | None:
    """Build a TypeAdapter, returning None for un-adaptable annotations."""
    try:
        return TypeAdapter(tp)
    except Exception:  # arbitrary user annotations can raise anything
        return None


def _adapter_for(tp: Any) -> TypeAdapter[Any] | None:
    """Cached TypeAdapter for ``tp`` (uncached when the annotation is unhashable)."""
    try:
        if tp in _adapter_cache:
            return _adapter_cache[tp]
    except TypeError:
        return _build_adapter(tp)
    adapter = _build_adapter(tp)
    _adapter_cache[tp] = adapter
    return adapter


def _annotation_is_complex_inner(tp: Any) -> bool:
    """Mirror of pydantic-settings' ``_annotation_is_complex_inner``."""
    if tp is None:
        return False
    if isinstance(tp, type):
        if issubclass(tp, (str, bytes)):
            return False
        if issubclass(tp, (BaseModel, Mapping, Sequence, tuple, set, frozenset, deque)):
            return True
    return is_dataclass(tp)


def _resolve_type_alias(tp: Any) -> Any:
    """Resolve a PEP 695 ``type X = ...`` alias to its underlying value.

    Mirrors pydantic-settings' ``_resolve_type_alias`` for the complexity
    decision: a subscripted alias resolves to its unsubstituted value, which
    is enough to decide list-ness/dict-ness (the TypeAdapter still validates
    against the original, fully-parameterized annotation).
    """
    if typing_objects.is_typealiastype(tp):
        return tp.__value__
    origin = get_origin(tp)
    if typing_objects.is_typealiastype(origin):
        return origin.__value__
    return tp


def _annotation_is_complex(tp: Any, metadata: Sequence[Any] = ()) -> bool:
    """Mirror of pydantic-settings' ``_annotation_is_complex(annotation, metadata)``.

    True when the env source JSON-decodes the raw string before validation.
    PEP 695 aliases resolve to their value first, a ``RootModel`` is judged by
    its *root* annotation, and a ``pydantic.Json`` marker in ``metadata`` makes
    the field non-complex (the raw string passes through untouched and the
    ``Json`` type decodes it during model validation). Bare unions are
    deliberately *not* complex here — pydantic-settings treats them separately
    (see :func:`field_complexity`).
    """
    tp = _resolve_type_alias(tp)
    if isinstance(tp, type) and issubclass(tp, RootModel) and tp is not RootModel:
        root_annotation = tp.model_fields["root"].annotation
        if root_annotation is not None:
            tp = root_annotation
    if any(isinstance(md, Json) for md in metadata):  # type: ignore[misc]
        return False
    origin = get_origin(tp)
    if origin is Annotated:
        inner, *meta = get_args(tp)
        return _annotation_is_complex(inner, meta)
    return _annotation_is_complex_inner(tp) or _annotation_is_complex_inner(origin)


def field_complexity(tp: Any, metadata: Sequence[Any] = ()) -> tuple[bool, bool]:
    """``(is_complex, allow_parse_failure)`` for a field annotation.

    Mirrors ``EnvSettingsSource._field_is_complex``: a directly-complex
    annotation is decoded strictly (bad JSON = startup error), while a union
    that merely *contains* a complex member tolerates JSON-decode failure and
    passes the raw string through to model validation.

    ``metadata`` is the field's ``FieldInfo.metadata`` — pydantic strips
    ``Annotated[...]`` extras (constraint markers, ``Json``, ...) into it
    before the real check ever sees the annotation. An ``Annotated`` passed
    directly here is peeled the same way so both call shapes agree.
    """
    if get_origin(tp) is Annotated:
        inner, *meta = get_args(tp)
        return field_complexity(inner, [*meta, *metadata])
    if _annotation_is_complex(tp, metadata):
        return True, False
    origin = get_origin(tp)
    if origin is Union or origin is UnionType:
        if any(_annotation_is_complex(arg, metadata) for arg in get_args(tp)):
            return True, True
    return False, False


def _first_error_msg(exc: ValidationError) -> str:
    """The first pydantic error message, as validate's type-error text."""
    errors = exc.errors()
    return str(errors[0].get("msg", "invalid value")) if errors else "invalid value"


def _coerce_complex(
    adapter: TypeAdapter[Any], raw: str, allow_parse_failure: bool
) -> CoercionResult:
    """Complex-field path: JSON-decode like the env source, then validate.

    The env source JSON-decodes complex values (``decode_complex_value``);
    non-JSON garbage raises ``SettingsError`` at startup unless the field is a
    union whose complex member tolerates parse failure (raw string fallback).
    """
    try:
        parsed: Any = json.loads(raw)
    except ValueError:
        if not allow_parse_failure:
            return CoercionResult(
                "fail", error=f"Expected valid JSON for complex type, got '{raw}'"
            )
        parsed = raw
    try:
        return CoercionResult("ok", value=adapter.validate_python(parsed))
    except ValidationError as exc:
        return CoercionResult("fail", error=_first_error_msg(exc))
    except Exception:
        # A custom type's validation can raise arbitrarily; no verdict.
        return CoercionResult("skip")


def coerce_env_value(tp: Any, raw: str, metadata: Sequence[Any] = ()) -> CoercionResult:
    """Coerce a raw .env string exactly the way pydantic-settings would.

    ``metadata`` is the field's ``FieldInfo.metadata``; a ``pydantic.Json``
    marker there routes the raw string through the ``Json`` decoder the way
    model validation does. Returns ``ok`` with the parsed value when the real
    app would accept the string, ``fail`` with a message when it would crash
    at startup, and ``skip`` when the annotation carries no checkable
    semantics.
    """
    if tp is None or tp is Any or tp is type(None):
        return CoercionResult("skip")
    json_markers = [md for md in metadata if isinstance(md, Json)]  # type: ignore[misc]
    adapter_tp = Annotated[(tp, *json_markers)] if json_markers else tp
    adapter = _adapter_for(adapter_tp)
    if adapter is None:
        return CoercionResult("skip")

    is_complex, allow_parse_failure = field_complexity(tp, metadata)
    if is_complex:
        return _coerce_complex(adapter, raw, allow_parse_failure)

    try:
        return CoercionResult("ok", value=adapter.validate_strings(raw))
    except ValidationError as exc:
        return CoercionResult("fail", error=_first_error_msg(exc))
    except Exception:
        return CoercionResult("skip")
