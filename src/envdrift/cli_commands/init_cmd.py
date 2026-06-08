"""Schema generation command for envdrift."""

from __future__ import annotations

import keyword
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated

import typer
from pydantic_settings import BaseSettings

from envdrift.core.encryption import EncryptionDetector
from envdrift.core.parser import EnvFile, EnvParser
from envdrift.output.rich import console, print_error, print_success, print_warning

# Matches the left-hand side of any `KEY=value` assignment in a raw .env file,
# accepting keys the strict EnvParser.LINE_PATTERN rejects (leading digits,
# dashes, etc.) so init can warn about variables it would otherwise drop.
_RAW_ASSIGNMENT_PATTERN = re.compile(r"^\s*(?:export\s+)?([^\s=#]+)\s*=")

# Pydantic protects the ``model_`` attribute namespace: a BaseModel/BaseSettings
# field whose name starts with this prefix either raises at import (``model_dump``
# -> "conflicts with member ... of protected namespace 'model_'") or silently
# shadows class machinery (``model_config`` -> the generated env binding is
# dropped). Such names must be sanitized + aliased exactly like keywords are.
_PROTECTED_NAMESPACE_PREFIX = "model_"

# Names already bound as attributes/methods on BaseSettings (and its BaseModel
# base) — ``schema``, ``copy``, ``dict``, ``json``, ``validate`` and the like.
# A field reusing one emits a "shadows an attribute in parent" warning and
# overrides real model machinery, so these are treated as unsafe too. Derived
# from the live class so the set tracks the installed pydantic rather than a
# hardcoded list (dunders excluded: never valid bare .env-key attribute names).
_RESERVED_ATTRIBUTES = frozenset(
    name for name in dir(BaseSettings) if not (name.startswith("__") and name.endswith("__"))
)


def _is_pydantic_reserved(name: str) -> bool:
    """True when ``name`` collides with pydantic's reserved attribute namespace.

    Covers both the protected ``model_`` prefix and any concrete BaseSettings/
    BaseModel attribute (``schema``, ``copy``, ``dict``, ``json``, ``validate``,
    …). Used as a bare field name these either raise at import or silently shadow
    model internals, so they must be sanitized + aliased like keywords are.
    """
    return name.startswith(_PROTECTED_NAMESPACE_PREFIX) or name in _RESERVED_ATTRIBUTES


@dataclass
class SettingsGeneration:
    """Result of rendering a Settings module from an .env file."""

    source: str
    sensitive_vars: set[str] = field(default_factory=set)
    aliased_count: int = 0
    # .env keys present in the raw text but rejected by the strict parser.
    unparsed_keys: list[str] = field(default_factory=list)


def _sanitize_identifier(name: str) -> str:
    """Turn an arbitrary .env key into a valid, non-keyword, non-reserved identifier.

    Non-identifier characters become ``_``; a leading digit (or empty result)
    gets a ``field_`` prefix; a Python keyword/soft-keyword gets a ``_`` suffix.
    A name colliding with pydantic's reserved attribute namespace (``model_``
    prefix, or a BaseSettings/BaseModel attribute such as ``schema``/``dict``) is
    given a ``field_`` prefix so it cannot raise at import or shadow model
    internals. The original name is preserved separately as a Pydantic alias so
    the schema still round-trips against the real environment variable.
    """
    sanitized = re.sub(r"\W", "_", name)
    if not sanitized or sanitized[0].isdigit():
        sanitized = f"field_{sanitized}"
    if _is_pydantic_reserved(sanitized):
        sanitized = f"field_{sanitized}"
    while keyword.iskeyword(sanitized) or keyword.issoftkeyword(sanitized):
        sanitized = f"{sanitized}_"
    return sanitized


def _raw_assignment_keys(text: str) -> list[str]:
    """Extract every assignment key from raw .env text (parser-independent)."""
    keys: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _RAW_ASSIGNMENT_PATTERN.match(line)
        if match:
            keys.append(match.group(1))
    return keys


def _needs_sanitizing(name: str) -> bool:
    """True when ``name`` cannot be used as a bare Settings attribute name.

    Flags non-identifiers, Python keywords, and names colliding with pydantic's
    reserved attribute namespace (``model_`` prefix or a BaseSettings/BaseModel
    member) — all of which produce a broken or non-importable module if emitted
    as a bare field annotation.
    """
    return not name.isidentifier() or keyword.iskeyword(name) or _is_pydantic_reserved(name)


def _bump_until_unique(name: str, used_names: set[str]) -> str:
    """Append ``_`` until ``name`` is absent from ``used_names``."""
    while name in used_names:
        name = f"{name}_"
    return name


def _resolve_field_name(var_name: str, used_names: set[str]) -> tuple[str, str | None]:
    """Pick a unique, importable attribute name for ``var_name``.

    Returns ``(field_name, alias)`` where ``alias`` is the original env var name
    whenever the attribute name differs from it (so pydantic-settings still binds
    to the real variable). ``used_names`` is updated in place with the chosen name.

    The alias is set whenever a rename happens — both when sanitizing a
    non-identifier/keyword key *and* when bumping a name that collides with an
    already-used one. Without the collision-case alias, a key like ``class_`` that
    collapses onto the sanitized form of ``class`` would be renamed to ``class__``
    and silently lose its binding to the ``class_`` env var.
    """
    sanitize = _needs_sanitizing(var_name)
    field_name = _sanitize_identifier(var_name) if sanitize else var_name
    # Any rename (sanitize or collision bump) must alias back to the original key.
    alias = var_name if sanitize or field_name in used_names else None
    field_name = _bump_until_unique(field_name, used_names)
    used_names.add(field_name)
    return field_name, alias


def _infer_type(value: str) -> tuple[str, object | None]:
    """Infer a Python type hint and literal default from a raw .env value.

    Returns ``(type_hint, default)`` where ``default`` is ``None`` for values
    that should stay required (plain strings). ``str.isdigit()`` is True for some
    non-ASCII digits that ``int()`` rejects, so the ASCII guard avoids a crash.
    """
    if value.lower() in ("true", "false"):
        return "bool", value.lower() == "true"
    if value.isascii() and value.isdigit():
        return "int", int(value)
    return "str", None


def _field_call_args(
    default_val: object | None, alias: str | None, is_sensitive: bool
) -> list[str]:
    """Assemble the keyword arguments for a generated ``Field(...)`` call."""
    args: list[str] = []
    if alias is not None:
        args.append(f"alias={alias!r}")
    if default_val is not None:
        args.append(f"default={default_val!r}")
    if is_sensitive:
        args.append('json_schema_extra={"sensitive": True}')
    return args


def _render_field_line(
    field_name: str,
    type_hint: str,
    default_val: object | None,
    alias: str | None,
    is_sensitive: bool,
) -> str:
    """Render a single Settings field line for the generated module.

    Reaches for ``Field(...)`` only when metadata is needed (an alias for a
    non-identifier name or the sensitive marker); the common case stays the plain
    ``KEY: type`` / ``KEY: type = default`` form.
    """
    if alias is not None or is_sensitive:
        args = ", ".join(_field_call_args(default_val, alias, is_sensitive))
        return f"    {field_name}: {type_hint} = Field({args})"
    if default_val is not None:
        return f"    {field_name}: {type_hint} = {default_val!r}"
    return f"    {field_name}: {type_hint}"


def _module_header(class_name: str, env_file: Path) -> list[str]:
    """Build the static import/class/model_config preamble for the module.

    The ``env_file`` path is emitted with ``repr()`` so it survives as a correct
    Python literal: a Windows path (``C:\\new\\test``) or one containing quotes
    would otherwise be mangled by string-escape interpretation.
    """
    env_file_literal = repr(str(env_file))
    return [
        '"""Auto-generated Pydantic Settings class."""',
        "",
        "from pydantic import Field",
        "from pydantic_settings import BaseSettings, SettingsConfigDict",
        "",
        "",
        f"class {class_name}(BaseSettings):",
        f'    """Settings generated from {env_file}."""',
        "",
        "    model_config = SettingsConfigDict(",
        f"        env_file={env_file_literal},",
        '        extra="forbid",',
        "    )",
        "",
    ]


def _unparsed_keys(env_file: Path, env: EnvFile) -> list[str]:
    """Return raw .env keys present in the file but rejected by the strict parser.

    The ``EnvParser`` only accepts identifier-style keys, so ``2FA_ENABLED`` or
    ``MY-DASH-VAR`` never become variables. These are surfaced to the caller to
    warn about rather than silently drop (``validate`` would later reject them as
    forbidden extras under ``extra="forbid"``).
    """
    raw_keys = _raw_assignment_keys(env_file.read_text(encoding="utf-8"))
    return [k for k in dict.fromkeys(raw_keys) if k not in env.variables]


def _detect_sensitive_vars(env: EnvFile) -> set[str]:
    """Return the set of variable names flagged sensitive by name or value."""
    detector = EncryptionDetector()
    return {
        name
        for name, var in env.variables.items()
        if detector.is_name_sensitive(name) or detector.is_value_suspicious(var.value)
    }


def _render_fields(env: EnvFile, sensitive_vars: set[str]) -> tuple[list[str], int]:
    """Render every Settings field line; return the lines and the alias count.

    Walks the variables in sorted order so output is deterministic, resolving each
    to a unique importable attribute name (with an alias when renamed) and an
    inferred type/default.
    """
    field_lines: list[str] = []
    aliased_count = 0
    used_names: set[str] = set()
    for var_name, env_var in sorted(env.variables.items()):
        field_name, alias = _resolve_field_name(var_name, used_names)
        if alias is not None:
            aliased_count += 1
        type_hint, default_val = _infer_type(env_var.value)
        field_lines.append(
            _render_field_line(
                field_name, type_hint, default_val, alias, var_name in sensitive_vars
            )
        )
    return field_lines, aliased_count


def generate_settings_module(
    env_file: Path,
    class_name: str = "Settings",
    detect_sensitive: bool = True,
) -> SettingsGeneration:
    """Render a Pydantic ``BaseSettings`` module from an .env file.

    Shared by the ``init`` CLI command and the public ``envdrift.api.init`` so
    both entry points generate the same safe, importable Python.

    Guarantees the emitted module is importable:
      * ``class_name`` is validated as a real (non-keyword) identifier.
      * Each field whose .env key is not a valid identifier (or is a keyword) is
        emitted with a sanitized attribute name plus a Pydantic ``alias`` so the
        schema still binds to the original environment variable.

    Raises:
        ValueError: If ``class_name`` is not a valid Python identifier.
    """
    if _needs_sanitizing(class_name):
        raise ValueError(f"Invalid class name: {class_name!r} is not a valid Python identifier")

    env = EnvParser().parse(env_file)
    unparsed_keys = _unparsed_keys(env_file, env)
    sensitive_vars = _detect_sensitive_vars(env) if detect_sensitive else set()

    field_lines, aliased_count = _render_fields(env, sensitive_vars)
    lines = [*_module_header(class_name, env_file), *field_lines, ""]

    return SettingsGeneration(
        source="\n".join(lines),
        sensitive_vars=sensitive_vars,
        aliased_count=aliased_count,
        unparsed_keys=unparsed_keys,
    )


def _print_generation_summary(result: SettingsGeneration) -> None:
    """Print the dim post-generation summary (sensitive + aliased counts)."""
    if result.sensitive_vars:
        names = ", ".join(sorted(result.sensitive_vars))
        console.print(
            f"[dim]Detected {len(result.sensitive_vars)} sensitive variable(s): {names}[/dim]"
        )
    if result.aliased_count:
        console.print(
            f"[dim]Aliased {result.aliased_count} variable(s) whose attribute name "
            "differs from the original (non-identifier, keyword, or name collision)[/dim]"
        )


def _print_next_step(output: Path, class_name: str) -> None:
    """Point the user at the exact command to validate against the new schema.

    Without this, a new user runs the obvious ``validate --schema settings:Settings``
    and hits ``No module named 'settings'`` because the schema is in the cwd.
    ``validate`` now defaults ``--service-dir`` to the cwd, so this command works
    as-is from the project directory.
    """
    console.print(
        f"\n[bold]Next:[/bold] validate your .env against it — "
        f"[cyan]envdrift validate --schema {output.stem}:{class_name}[/cyan]"
    )


def _generate_or_exit(
    env_file: Path, class_name: str, detect_sensitive: bool
) -> SettingsGeneration:
    """Validate the env file exists and render the module, or exit nonzero.

    Surfaces a missing file and an invalid class name (which would produce a
    SyntaxError module) as clean CLI errors instead of writing a broken file.
    """
    if not env_file.exists():
        print_error(f"ENV file not found: {env_file}")
        raise typer.Exit(code=1)
    try:
        return generate_settings_module(env_file, class_name, detect_sensitive)
    except ValueError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


def init(
    env_file: Annotated[
        Path, typer.Argument(help="Path to .env file to generate schema from")
    ] = Path(".env"),
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Output file for Settings class")
    ] = Path("settings.py"),
    class_name: Annotated[
        str, typer.Option("--class-name", "-c", help="Name for the Settings class")
    ] = "Settings",
    detect_sensitive: Annotated[
        bool, typer.Option("--detect-sensitive", help="Auto-detect sensitive variables")
    ] = True,
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Overwrite an existing output file")
    ] = False,
) -> None:
    """
    Generate a Pydantic BaseSettings subclass from variables in an .env file.

    Writes a Python module containing a Pydantic `BaseSettings` subclass with fields
    inferred from the .env variables. Detected sensitive variables are annotated
    with `json_schema_extra={"sensitive": True}` and fields without a sensible
    default are left required.

    Parameters:
        env_file (Path): Path to the source .env file.
        output (Path): Path to write the generated Python module (e.g., settings.py).
        class_name (str): Name to use for the generated `BaseSettings` subclass.
        detect_sensitive (bool): If true, attempt to auto-detect sensitive variables
            (by name and value) and mark them in the generated fields.
        force (bool): If true, overwrite an existing output file; otherwise the
            command errors when the output already exists.
    """
    result = _generate_or_exit(env_file, class_name, detect_sensitive)

    _write_init_output(result, output, force=force)
    _print_next_step(output, class_name)


def _write_init_output(result: SettingsGeneration, output: Path, *, force: bool) -> None:
    """Warn about dropped keys, guard against clobbering, then write the module."""
    if result.unparsed_keys:
        print_warning(
            "Skipped .env variable(s) the parser cannot read "
            f"(non-identifier keys): {', '.join(result.unparsed_keys)}"
        )

    # Guard against clobbering an existing (possibly hand-edited) file.
    if output.exists() and not force:
        print_error(f"Output file already exists: {output} (use --force to overwrite)")
        raise typer.Exit(code=1)

    output.write_text(result.source)
    print_success(f"Generated {output}")
    _print_generation_summary(result)
