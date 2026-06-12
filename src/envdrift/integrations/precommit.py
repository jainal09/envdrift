"""Pre-commit hook integration for envdrift."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator


class PrecommitConfigError(ValueError):
    """A ``.pre-commit-config.yaml`` could not be parsed or has an unexpected shape."""


# Markers wrapping the repo block that ``install_hooks`` inserts, so
# ``uninstall_hooks`` can remove exactly what was added without re-serializing
# (and thereby reformatting) the rest of the user's file (#493).
HOOK_BLOCK_BEGIN = "# >>> envdrift pre-commit hooks >>>"
HOOK_BLOCK_END = "# <<< envdrift pre-commit hooks <<<"

# Hook entries that work out of the box. The validate hook is *not* here: it
# requires a --schema pointing at the user's Settings class, which envdrift
# cannot guess, so it ships as a commented example instead (#493).
HOOK_ENTRY: dict[str, Any] = {
    "repo": "local",
    "hooks": [
        {
            "id": "envdrift-encryption",
            "name": "Check env encryption status",
            "entry": "envdrift encrypt --check",
            "language": "system",
            "files": r"^\.env\.(production|staging)$",
            "pass_filenames": True,  # nosec B105 - not a password
            "description": "Ensures sensitive .env files are encrypted",
        },
        {
            "id": "envdrift-guard",
            "name": "Guard staged env files",
            "entry": "envdrift guard --staged --native-only --ci",
            "language": "system",
            "always_run": True,
            "pass_filenames": False,  # nosec B105 - not a password
            "description": "Scans staged files, including vault.sync env_file mappings",
        },
    ],
}

# Commented example for the schema validation hook. ``envdrift validate``
# accepts multiple env-file arguments, so ``pass_filenames: true`` is safe.
_VALIDATE_EXAMPLE_LINES = [
    "# Uncomment the validate hook once you have a Pydantic Settings class and",
    "# point --schema at it (envdrift validate accepts multiple env files):",
    "# - id: envdrift-validate",
    "#   name: Validate env files against schema",
    "#   entry: envdrift validate --ci --schema app.config:Settings",
    "#   language: system",
    "#   files: ^\\.env\\.(production|staging|development)$",
    "#   pass_filenames: true",
]

# Optional vault-verify example only shown in the printed template.
_VAULT_VERIFY_EXAMPLE_LINES = [
    "# Optional: verify encryption keys match vault (prevents key drift)",
    "# - id: envdrift-vault-verify",
    "#   name: Verify vault key can decrypt",
    "#   entry: envdrift decrypt --verify-vault -p azure"
    " --vault-url https://myvault.vault.azure.net --secret myapp-dotenvx-key --ci",
    "#   language: system",
    "#   files: ^\\.env\\.production$",
    "#   pass_filenames: true",
]


def _active_hook_ids() -> list[str]:
    """Ids of the hooks that install_hooks adds as active entries."""
    return [str(hook["id"]) for hook in HOOK_ENTRY["hooks"]]


def _render_hook_lines(hook: dict[str, Any]) -> list[str]:
    """Render one hook mapping as YAML sequence-item lines (zero indent)."""
    lines: list[str] = []
    prefix = "- "
    for key, value in hook.items():
        text = ("true" if value else "false") if isinstance(value, bool) else str(value)
        lines.append(f"{prefix}{key}: {text}")
        prefix = "  "
    return lines


def _render_repo_block(
    hook_ids: list[str],
    indent: str,
    include_vault_example: bool = False,
) -> str:
    """Render the marker-wrapped ``- repo: local`` block at the given indent."""
    lines = [
        f"{indent}{HOOK_BLOCK_BEGIN}",
        f"{indent}- repo: local",
        f"{indent}  hooks:",
    ]
    hook_indent = indent + "    "
    lines.extend(f"{hook_indent}{line}" for line in _VALIDATE_EXAMPLE_LINES)
    for hook in HOOK_ENTRY["hooks"]:
        if hook["id"] in hook_ids:
            lines.extend(f"{hook_indent}{line}" for line in _render_hook_lines(hook))
    if include_vault_example:
        lines.extend(f"{hook_indent}{line}" for line in _VAULT_VERIFY_EXAMPLE_LINES)
    lines.append(f"{indent}{HOOK_BLOCK_END}")
    return "\n".join(lines) + "\n"


# Pre-commit hook configuration template (what `envdrift hook --config` prints).
HOOK_CONFIG = (
    "# envdrift pre-commit hooks\n"
    "# Add this to your .pre-commit-config.yaml\n"
    "\n"
    "repos:\n" + _render_repo_block(_active_hook_ids(), "  ", include_vault_example=True)
)


def get_hook_config() -> str:
    """
    Provide the default pre-commit hook configuration template for envdrift.

    Returns:
        The YAML string containing the pre-commit configuration for envdrift hooks.
    """
    return HOOK_CONFIG


def find_precommit_config(start_dir: Path | None = None) -> Path | None:
    """
    Locate a .pre-commit-config.yaml file by searching the given directory and its parents.

    Parameters:
        start_dir (Path | None): Directory to start the search from. If None, the current working directory is used.

    Returns:
        Path | None: Path to the first .pre-commit-config.yaml found while walking upward, or `None` if no file is found.
    """
    if start_dir is None:
        start_dir = Path.cwd()

    current = start_dir.resolve()

    while True:
        config_path = current / ".pre-commit-config.yaml"
        if config_path.exists():
            return config_path
        if current == current.parent:
            # Reached filesystem root
            break
        current = current.parent

    return None


def _require_yaml() -> Any:
    try:
        import yaml
    except ImportError:
        raise ImportError(
            "PyYAML is required for pre-commit integration. Install with: pip install pyyaml"
        ) from None
    return yaml


def _parse_precommit_config(yaml_mod: Any, content: str, config_path: Path) -> dict[str, Any]:
    """Parse a pre-commit config, raising :class:`PrecommitConfigError` on bad input."""
    try:
        config = yaml_mod.safe_load(content)
    except yaml_mod.YAMLError as e:
        raise PrecommitConfigError(f"Could not parse {config_path}: {e}") from e
    if config is None:
        return {}
    if not isinstance(config, dict):
        raise PrecommitConfigError(
            f"{config_path} must contain a YAML mapping at the top level, "
            f"got {type(config).__name__}"
        )
    repos = config.get("repos")
    if repos is not None and not isinstance(repos, list):
        raise PrecommitConfigError(
            f"{config_path} has a 'repos' key that is not a list (got {type(repos).__name__})"
        )
    return config


def _iter_local_hooks(config: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield hook mappings from ``repo: local`` entries, skipping odd shapes."""
    repos = config.get("repos") or []
    if not isinstance(repos, list):
        return
    for repo in repos:
        if not isinstance(repo, dict) or repo.get("repo") != "local":
            continue
        hooks = repo.get("hooks") or []
        if not isinstance(hooks, list):
            continue
        for hook in hooks:
            if isinstance(hook, dict):
                yield hook


def _existing_envdrift_hook_ids(config: dict[str, Any]) -> set[str]:
    """Ids of envdrift hooks already present in a parsed config."""
    return {
        str(hook.get("id", ""))
        for hook in _iter_local_hooks(config)
        if str(hook.get("id", "")).startswith("envdrift-")
    }


def _fresh_config_text(hook_ids: list[str]) -> str:
    return "repos:\n" + _render_repo_block(hook_ids, "  ")


def _block_sequence_indent(content: str, repos_value: Any) -> str:
    """Indent (dash column) of an existing block-style repos sequence."""
    return " " * repos_value.start_mark.column


def _insert_lines(content: str, line_index: int, block: str) -> str:
    """Insert ``block`` (newline-terminated) before ``line_index`` of ``content``."""
    lines = content.splitlines(keepends=True)
    if line_index >= len(lines):
        if content and not content.endswith("\n"):
            content += "\n"
        return content + block
    return "".join(lines[:line_index]) + block + "".join(lines[line_index:])


def _insert_hook_block(
    yaml_mod: Any, content: str, config: dict[str, Any], hook_ids: list[str], config_path: Path
) -> str:
    """Insert the envdrift repo block into ``content`` without rewriting the rest.

    The insertion is a targeted text edit: existing comments, ordering and
    formatting are preserved byte for byte (#493).
    """
    if "repos" not in config:
        if content and not content.endswith("\n"):
            content += "\n"
        return content + _fresh_config_text(hook_ids)

    node = yaml_mod.compose(content, Loader=yaml_mod.SafeLoader)
    repos_key = None
    repos_value = None
    for key_node, value_node in node.value:
        if getattr(key_node, "value", None) == "repos":
            repos_key, repos_value = key_node, value_node
            break
    if repos_key is None or repos_value is None:  # pragma: no cover - parse guard
        raise PrecommitConfigError(f"Could not locate the 'repos' key in {config_path}")

    key_indent = " " * (repos_key.start_mark.column + 2)

    if isinstance(repos_value, yaml_mod.nodes.ScalarNode):
        # `repos:` with a null value — start the list right below the key.
        block = _render_repo_block(hook_ids, key_indent)
        return _insert_lines(content, repos_key.end_mark.line + 1, block)

    if not isinstance(repos_value, yaml_mod.nodes.SequenceNode):  # pragma: no cover - shape guard
        raise PrecommitConfigError(f"{config_path} has a 'repos' key that is not a list")

    if repos_value.flow_style:
        if repos_value.value:
            raise PrecommitConfigError(
                f"{config_path} uses a flow-style 'repos' list; "
                "add the envdrift hooks manually (see `envdrift hook --config`)"
            )
        # `repos: []` — replace the empty flow list with a block-style list.
        block = _render_repo_block(hook_ids, key_indent)
        start = repos_value.start_mark.index
        end = repos_value.end_mark.index
        return content[:start] + "\n" + block.rstrip("\n") + content[end:]

    # Block-style sequence: append after its last item, before the next key.
    indent = _block_sequence_indent(content, repos_value)
    block = _render_repo_block(hook_ids, indent)
    return _insert_lines(content, repos_value.end_mark.line, block)


def install_hooks(
    config_path: Path | None = None,
    create_if_missing: bool = True,
) -> bool:
    """Install envdrift hooks into .pre-commit-config.yaml via targeted insertion.

    The user's file is never re-serialized: comments, ordering and formatting
    are preserved, and the envdrift block is wrapped in begin/end markers so it
    can be removed surgically later.

    Args:
        config_path: Path to pre-commit config (auto-detected if None)
        create_if_missing: Create config file if it doesn't exist

    Returns:
        True if hooks were added, False if every envdrift hook was already present.

    Raises:
        FileNotFoundError: If config not found and create_if_missing=False
        PrecommitConfigError: If the config is malformed, is not a mapping, or
            the hooks could not be inserted safely.
    """
    yaml_mod = _require_yaml()

    if config_path is None:
        config_path = find_precommit_config()

    if config_path is None:
        if create_if_missing:
            config_path = Path.cwd() / ".pre-commit-config.yaml"
        else:
            raise FileNotFoundError(
                ".pre-commit-config.yaml not found. "
                "Run from repository root or specify --config path."
            )

    if not config_path.exists():
        config_path.write_text(_fresh_config_text(_active_hook_ids()), encoding="utf-8")
        return True

    content = config_path.read_text(encoding="utf-8")
    config = _parse_precommit_config(yaml_mod, content, config_path)

    existing = _existing_envdrift_hook_ids(config)
    missing = [hook_id for hook_id in _active_hook_ids() if hook_id not in existing]
    if not missing:
        return False

    new_content = _insert_hook_block(yaml_mod, content, config, missing, config_path)

    # Verify the post-condition before touching the file: the result must
    # still parse and actually contain the hooks we set out to add.
    new_config = _parse_precommit_config(yaml_mod, new_content, config_path)
    if not set(missing) <= _existing_envdrift_hook_ids(new_config):  # pragma: no cover - guard
        raise PrecommitConfigError(
            f"Failed to add envdrift hooks to {config_path}; "
            "add them manually (see `envdrift hook --config`)"
        )

    config_path.write_text(new_content, encoding="utf-8")
    return True


def _remove_marker_blocks(content: str) -> tuple[str, bool]:
    """Remove every marker-delimited envdrift block from ``content``."""
    lines = content.splitlines(keepends=True)
    kept: list[str] = []
    removed = False
    in_block = False
    for line in lines:
        stripped = line.strip()
        if not in_block and stripped == HOOK_BLOCK_BEGIN:
            in_block = True
            removed = True
            continue
        if in_block:
            if stripped == HOOK_BLOCK_END:
                in_block = False
            continue
        kept.append(line)
    if in_block:
        # Unbalanced markers — leave the file alone rather than guess.
        return content, False
    return "".join(kept), removed


def uninstall_hooks(config_path: Path | None = None) -> bool:
    """
    Remove any envdrift hooks from a .pre-commit-config.yaml file.

    Marker-delimited blocks written by :func:`install_hooks` are removed with a
    targeted text edit that leaves the rest of the file untouched. Hooks added
    by older versions (or by hand) fall back to a parse-and-rewrite pass.

    Parameters:
        config_path (Path | None): Path to the pre-commit config file. If None, the repository tree is searched upward to locate .pre-commit-config.yaml.

    Returns:
        bool: `True` if one or more envdrift hooks were removed and the file was updated, `False` otherwise.

    Raises:
        ImportError: If PyYAML is not available.
    """
    yaml_mod = _require_yaml()

    if config_path is None:
        config_path = find_precommit_config()

    if config_path is None or not config_path.exists():
        return False

    content = config_path.read_text(encoding="utf-8")

    new_content, removed_blocks = _remove_marker_blocks(content)
    if removed_blocks:
        try:
            remaining = _parse_precommit_config(yaml_mod, new_content, config_path)
        except PrecommitConfigError:
            remaining = None
        if remaining is not None and not _existing_envdrift_hook_ids(remaining):
            if "repos" in remaining and remaining.get("repos") is None:
                # Removing our block emptied the list; keep the file meaningful.
                new_content = "".join(
                    "repos: []\n" if line.rstrip("\r\n").rstrip() == "repos:" else line
                    for line in new_content.splitlines(keepends=True)
                )
            config_path.write_text(new_content, encoding="utf-8")
            return True

    # Legacy path: envdrift hooks installed without markers. This re-serializes
    # the file, which loses comments, but only runs for pre-#493 installs.
    try:
        config = _parse_precommit_config(yaml_mod, content, config_path)
    except PrecommitConfigError:
        return False

    if "repos" not in config:
        return False

    modified = False

    for repo in config["repos"]:
        if isinstance(repo, dict) and repo.get("repo") == "local":
            hooks = repo.get("hooks") or []
            if not isinstance(hooks, list):
                continue
            original_count = len(hooks)

            # Remove envdrift hooks
            repo["hooks"] = [
                hook
                for hook in hooks
                if not (isinstance(hook, dict) and str(hook.get("id", "")).startswith("envdrift-"))
            ]

            if len(repo["hooks"]) != original_count:
                modified = True

    if modified:
        # Remove empty local repos
        config["repos"] = [
            repo
            for repo in config["repos"]
            if not (
                isinstance(repo, dict) and repo.get("repo") == "local" and not repo.get("hooks")
            )
        ]

        with open(config_path, "w", encoding="utf-8") as f:
            yaml_mod.dump(config, f, default_flow_style=False, sort_keys=False)

    return modified


def verify_hooks_installed(config_path: Path | None = None) -> dict[str, bool]:
    """
    Check which envdrift pre-commit hooks are present in a given pre-commit configuration.

    Parameters:
        config_path (Path | None): Path to a .pre-commit-config.yaml file. If None, the file is searched for by walking up from the current working directory.

    Returns:
        dict[str, bool]: Mapping of hook id to installation status. Returns all
        hooks as `False` if the config file is missing or unreadable, or if the
        PyYAML package is not available.
    """
    empty_result: dict[str, bool] = dict.fromkeys(_active_hook_ids(), False)
    try:
        import yaml
    except ImportError:
        return empty_result

    if config_path is None:
        config_path = find_precommit_config()

    if config_path is None or not config_path.exists():
        return empty_result

    try:
        content = config_path.read_text(encoding="utf-8")
        config = yaml.safe_load(content) or {}
    except (OSError, yaml.YAMLError):
        return empty_result

    if not isinstance(config, dict):
        return empty_result

    result = empty_result.copy()

    for hook in _iter_local_hooks(config):
        hook_id = str(hook.get("id", ""))
        if hook_id in result:
            result[hook_id] = True

    return result
