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

from pydantic import BaseModel, TypeAdapter, ValidationError

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


def _annotation_is_complex(tp: Any) -> bool:
    """Mirror of pydantic-settings' ``_annotation_is_complex`` (annotation-only).

    True when the env source JSON-decodes the raw string before validation.
    Bare unions are deliberately *not* complex here — pydantic-settings treats
    them separately (see :func:`field_complexity`).
    """
    origin = get_origin(tp)
    if origin is Annotated:
        return _annotation_is_complex(get_args(tp)[0])
    return _annotation_is_complex_inner(tp) or _annotation_is_complex_inner(origin)


def field_complexity(tp: Any) -> tuple[bool, bool]:
    """``(is_complex, allow_parse_failure)`` for a field annotation.

    Mirrors ``EnvSettingsSource._field_is_complex``: a directly-complex
    annotation is decoded strictly (bad JSON = startup error), while a union
    that merely *contains* a complex member tolerates JSON-decode failure and
    passes the raw string through to model validation.
    """
    if _annotation_is_complex(tp):
        return True, False
    origin = get_origin(tp)
    if origin is Union or origin is UnionType:
        if any(_annotation_is_complex(arg) for arg in get_args(tp)):
            return True, True
    return False, False


def _first_error_msg(exc: ValidationError) -> str:
    """The first pydantic error message, as validate's type-error text."""
    errors = exc.errors()
    return str(errors[0].get("msg", "invalid value")) if errors else "invalid value"


def coerce_env_value(tp: Any, raw: str) -> CoercionResult:
    """Coerce a raw .env string exactly the way pydantic-settings would.

    Returns ``ok`` with the parsed value when the real app would accept the
    string, ``fail`` with a message when it would crash at startup, and
    ``skip`` when the annotation carries no checkable semantics.
    """
    if tp is None or tp is Any or tp is type(None):
        return CoercionResult("skip")
    adapter = _adapter_for(tp)
    if adapter is None:
        return CoercionResult("skip")

    is_complex, allow_parse_failure = field_complexity(tp)
    if is_complex:
        # The env source JSON-decodes complex values (decode_complex_value);
        # non-JSON garbage raises SettingsError at startup.
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

    try:
        return CoercionResult("ok", value=adapter.validate_strings(raw))
    except ValidationError as exc:
        return CoercionResult("fail", error=_first_error_msg(exc))
    except Exception:
        return CoercionResult("skip")
