"""Pre-commit hook integration for envdrift."""

from __future__ import annotations

from pathlib import Path

# Pre-commit hook configuration template
HOOK_CONFIG = """# envdrift pre-commit hooks
# Add this to your .pre-commit-config.yaml

repos:
  - repo: local
    hooks:
      - id: envdrift-validate
        name: Validate env files against schema
        entry: envdrift validate --ci
        language: system
        files: ^\\.env\\.(production|staging|development)$
        pass_filenames: true
        description: Validates .env files match Pydantic schema

      - id: envdrift-encryption
        name: Check env encryption status
        entry: envdrift encrypt --check
        language: system
        files: ^\\.env\\.(production|staging)$
        pass_filenames: true
        description: Ensures sensitive .env files are encrypted
"""

# Minimal hook entry for injection
HOOK_ENTRY = {
    "repo": "local",
    "hooks": [
        {
            "id": "envdrift-validate",
            "name": "Validate env files against schema",
            "entry": "envdrift validate --ci",
            "language": "system",
            "files": r"^\.env\.(production|staging|development)$",
            "pass_filenames": True,
        },
        {
            "id": "envdrift-encryption",
            "name": "Check env encryption status",
            "entry": "envdrift encrypt --check",
            "language": "system",
            "files": r"^\.env\.(production|staging)$",
            "pass_filenames": True,
        },
    ],
}


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


def install_hooks(
    config_path: Path | None = None,
    create_if_missing: bool = True,
) -> bool:
    """Install envdrift hooks to .pre-commit-config.yaml.

    Args:
        config_path: Path to pre-commit config (auto-detected if None)
        create_if_missing: Create config file if it doesn't exist

    Returns:
        True if hooks were installed/updated

    Raises:
        FileNotFoundError: If config not found and create_if_missing=False
    """
    try:
        import yaml
    except ImportError:
        raise ImportError(
            "PyYAML is required for pre-commit integration. Install with: pip install pyyaml"
        )

    # Find or create config
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

    # Load existing config or create new
    if config_path.exists():
        content = config_path.read_text()
        config = yaml.safe_load(content) or {}
    else:
        config = {}

    # Initialize repos list if needed
    if "repos" not in config:
        config["repos"] = []

    # Check if envdrift hooks already exist
    has_envdrift = False
    for repo in config["repos"]:
        if repo.get("repo") == "local":
            hooks = repo.get("hooks", [])
            for hook in hooks:
                if hook.get("id", "").startswith("envdrift-"):
                    has_envdrift = True
                    break

    # Add hooks if not present
    if not has_envdrift:
        # Find existing local repo or create new one
        local_repo = None
        for repo in config["repos"]:
            if repo.get("repo") == "local":
                local_repo = repo
                break

        if local_repo:
            # Add to existing local repo
            if "hooks" not in local_repo:
                local_repo["hooks"] = []
            local_repo["hooks"].extend(HOOK_ENTRY["hooks"])
        else:
            # Add new local repo entry
            config["repos"].append(HOOK_ENTRY)

    # Write config
    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    return True


def uninstall_hooks(config_path: Path | None = None) -> bool:
    """
    Remove any envdrift hooks from a .pre-commit-config.yaml file.

    Parameters:
        config_path (Path | None): Path to the pre-commit config file. If None, the repository tree is searched upward to locate .pre-commit-config.yaml.

    Returns:
        bool: `True` if one or more envdrift hooks were removed and the file was updated, `False` otherwise.

    Raises:
        ImportError: If PyYAML is not available.
    """
    try:
        import yaml
    except ImportError:
        raise ImportError("PyYAML is required for pre-commit integration.")

    if config_path is None:
        config_path = find_precommit_config()

    if config_path is None or not config_path.exists():
        return False

    content = config_path.read_text()
    config = yaml.safe_load(content) or {}

    if "repos" not in config:
        return False

    modified = False

    for repo in config["repos"]:
        if repo.get("repo") == "local":
            hooks = repo.get("hooks", [])
            original_count = len(hooks)

            # Remove envdrift hooks
            repo["hooks"] = [
                hook for hook in hooks if not hook.get("id", "").startswith("envdrift-")
            ]

            if len(repo["hooks"]) != original_count:
                modified = True

    if modified:
        # Remove empty local repos
        config["repos"] = [
            repo
            for repo in config["repos"]
            if not (repo.get("repo") == "local" and not repo.get("hooks"))
        ]

        with open(config_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    return modified


def verify_hooks_installed(config_path: Path | None = None) -> dict[str, bool]:
    """
    Check which envdrift pre-commit hooks are present in a given pre-commit configuration.

    Parameters:
        config_path (Path | None): Path to a .pre-commit-config.yaml file. If None, the file is searched for by walking up from the current working directory.

    Returns:
        dict[str, bool]: Mapping of hook id to installation status: `{"envdrift-validate": bool, "envdrift-encryption": bool}`. Returns both `False` if the config file is missing or unreadable, or if the PyYAML package is not available.
    """
    try:
        import yaml
    except ImportError:
        return {"envdrift-validate": False, "envdrift-encryption": False}

    if config_path is None:
        config_path = find_precommit_config()

    if config_path is None or not config_path.exists():
        return {"envdrift-validate": False, "envdrift-encryption": False}

    content = config_path.read_text()
    config = yaml.safe_load(content) or {}

    result = {"envdrift-validate": False, "envdrift-encryption": False}

    for repo in config.get("repos", []):
        if repo.get("repo") == "local":
            for hook in repo.get("hooks", []):
                hook_id = hook.get("id", "")
                if hook_id in result:
                    result[hook_id] = True

    return result
