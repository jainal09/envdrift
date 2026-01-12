"""Hook checks for git integrations."""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404
import tomllib
from collections.abc import Iterable
from pathlib import Path

from envdrift.config import (
    ConfigNotFoundError,
    EnvdriftConfig,
    GitHookCheckConfig,
    find_config,
)
from envdrift.integrations.precommit import verify_hooks_installed

_PRECOMMIT_METHODS = {
    "precommit",
    "pre-commit",
    "precommit.yaml",
    "precommit.yml",
    ".pre-commit-config.yaml",
    "pre-commit-config.yaml",
}
_DIRECT_METHODS = {
    "direct",
    "direct git hook",
    "direct git hooks",
    "git",
    "git hook",
    "git hooks",
}
_ENVDRIFT_HOOK_MARKER = "# >>> envdrift hook"
_PRE_COMMIT_HOOK_LINES = [
    "# >>> envdrift hook: pre-commit",
    "if ! command -v envdrift >/dev/null 2>&1; then",
    '  echo "envdrift not found; aborting commit" >&2',
    "  exit 1",
    "fi",
    "staged_files=$(git diff --cached --name-only --diff-filter=ACM)",
    'key_files=$(printf "%s\\n" "$staged_files" | grep -E "(^|/)\\.env\\.keys(\\.|$)" || true)',
    'env_files=$(printf "%s\\n" "$staged_files" | grep -E "(^|/)\\.env(\\.|$)" || true)',
    'if [ -n "$key_files" ]; then',
    '  echo "envdrift: refusing to commit .env.keys files" >&2',
    "  exit 1",
    "fi",
    'if [ -n "$env_files" ]; then',
    "  failed=0",
    "  for f in $env_files; do",
    '    envdrift encrypt --check "$f" || failed=1',
    "  done",
    "  if [ $failed -ne 0 ]; then",
    '    echo "envdrift: encryption check failed" >&2',
    "    exit 1",
    "  fi",
    "fi",
    "# <<< envdrift hook: pre-commit",
]
_PRE_PUSH_HOOK_LINES = [
    "# >>> envdrift hook: pre-push",
    "if ! command -v envdrift >/dev/null 2>&1; then",
    '  echo "envdrift not found; aborting push" >&2',
    "  exit 1",
    "fi",
    "if ! envdrift lock --check; then",
    '  echo "envdrift: lock --check failed" >&2',
    "  exit 1",
    "fi",
    "# <<< envdrift hook: pre-push",
]


def normalize_hook_method(value: str | None) -> str | None:
    """Normalize hook method values to 'precommit' or 'direct'."""
    if not value:
        return None
    normalized = value.strip().lower()
    if normalized in _PRECOMMIT_METHODS:
        return "precommit"
    if normalized in _DIRECT_METHODS:
        return "direct"
    return None


def resolve_precommit_config_path(
    config_path: Path | None, precommit_config: str | None
) -> Path | None:
    """Resolve a pre-commit config path relative to the TOML file."""
    if not precommit_config:
        return None
    path = Path(precommit_config)
    if config_path and not path.is_absolute():
        return (config_path.parent / path).resolve()
    return path


def _format_hook_block(lines: list[str]) -> str:
    return "\n".join(lines) + "\n"


def _inject_hook_block(content: str, block_lines: list[str]) -> tuple[str, bool]:
    if _ENVDRIFT_HOOK_MARKER in content:
        return content, False

    block = _format_hook_block(block_lines)
    if not content:
        return block, True

    lines = content.splitlines(keepends=True)
    last_nonempty = None
    for idx in range(len(lines) - 1, -1, -1):
        if lines[idx].strip():
            last_nonempty = idx
            break

    if last_nonempty is not None and lines[last_nonempty].strip() == "exit 0":
        new_lines = [*lines[:last_nonempty], block, *lines[last_nonempty:]]
        return "".join(new_lines), True

    if content.endswith("\n"):
        return content + block, True

    return content + "\n" + block, True


def _ensure_hook_file(path: Path, block_lines: list[str]) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        content = path.read_text()
        new_content, updated = _inject_hook_block(content, block_lines)
    else:
        new_content = "#!/bin/sh\n\n" + _format_hook_block(block_lines)
        updated = True

    if updated:
        path.write_text(new_content)

    try:
        mode = path.stat().st_mode
        if not (mode & 0o111):
            path.chmod(mode | 0o111)
    except OSError:
        pass  # Best-effort; hook may not be executable on some filesystems.

    return updated


def install_direct_hooks(hooks_dir: Path) -> dict[str, bool]:
    """Install or update direct git hook scripts with envdrift checks."""
    hooks_dir.mkdir(parents=True, exist_ok=True)
    return {
        "pre-commit": _ensure_hook_file(hooks_dir / "pre-commit", _PRE_COMMIT_HOOK_LINES),
        "pre-push": _ensure_hook_file(hooks_dir / "pre-push", _PRE_PUSH_HOOK_LINES),
    }


def _load_config_for_hook_check(
    config_file: Path | None,
) -> tuple[EnvdriftConfig | None, Path | None]:
    if config_file is not None and config_file.suffix.lower() != ".toml":
        return None, None

    config_path = config_file or find_config()
    if not config_path:
        return None, None

    try:
        from envdrift.config import load_config

        return load_config(config_path), config_path
    except (ConfigNotFoundError, tomllib.TOMLDecodeError, OSError):
        return None, config_path


def _read_git_path(*args: str) -> Path | None:
    git_path = shutil.which("git")
    if not git_path:
        return None
    env = os.environ.copy()
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
        env.pop(key, None)
    try:
        result = subprocess.run(  # nosec B603
            [git_path, *args],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    output = result.stdout.strip()
    if not output:
        return None
    return Path(output)


def resolve_git_hooks_path(start_dir: Path | None = None) -> Path | None:
    """Resolve the git hooks directory using git metadata if available."""
    start_dir = start_dir or Path.cwd()

    root_path = _read_git_path("-C", str(start_dir), "rev-parse", "--show-toplevel")
    hooks_path = _read_git_path("-C", str(start_dir), "rev-parse", "--git-path", "hooks")

    if root_path and hooks_path:
        if hooks_path.is_absolute():
            return hooks_path
        return (root_path / hooks_path).resolve()

    git_dir = _find_git_dir(start_dir)
    if not git_dir:
        return None

    hooks_dir = git_dir / "hooks"
    if hooks_dir.exists():
        return hooks_dir

    commondir = git_dir / "commondir"
    if commondir.exists():
        common_root = _resolve_commondir(git_dir, commondir)
        if common_root:
            common_hooks = common_root / "hooks"
            if common_hooks.exists():
                return common_hooks

    return None


def _find_git_dir(start_dir: Path) -> Path | None:
    current = start_dir.resolve()
    while True:
        git_path = current / ".git"
        if git_path.is_dir():
            return git_path
        if git_path.is_file():
            git_dir = _parse_gitdir_file(current, git_path)
            if git_dir:
                return git_dir
        if current == current.parent:
            return None
        current = current.parent


def _parse_gitdir_file(root: Path, git_file: Path) -> Path | None:
    try:
        content = git_file.read_text().strip()
    except OSError:
        return None
    if not content.startswith("gitdir:"):
        return None
    path_value = content.split(":", 1)[1].strip()
    git_dir = Path(path_value)
    if not git_dir.is_absolute():
        git_dir = (root / git_dir).resolve()
    return git_dir


def _resolve_commondir(git_dir: Path, commondir_file: Path) -> Path | None:
    try:
        content = commondir_file.read_text().strip()
    except OSError:
        return None
    if not content:
        return None
    common_dir = Path(content)
    if not common_dir.is_absolute():
        common_dir = (git_dir / common_dir).resolve()
    return common_dir


def _hook_contains_envdrift(hook_path: Path) -> bool:
    try:
        content = hook_path.read_text(errors="ignore")
    except OSError:
        return False
    return "envdrift" in content


def check_direct_hooks(hooks_dir: Path | None) -> dict[str, bool]:
    """Check direct git hook scripts for envdrift usage."""
    hook_status = {"pre-commit": False, "pre-push": False}
    if not hooks_dir or not hooks_dir.exists():
        return hook_status

    for hook_name in hook_status:
        hook_path = hooks_dir / hook_name
        if hook_path.is_file() and os.access(hook_path, os.X_OK):
            hook_status[hook_name] = _hook_contains_envdrift(hook_path)

    return hook_status


def check_precommit_hooks(
    precommit_path: Path | None, required_hooks: Iterable[str] | None = None
) -> dict[str, bool]:
    """Check for envdrift hooks in a pre-commit config."""
    if required_hooks is None:
        required_hooks = ("envdrift-encryption",)
    required = dict.fromkeys(required_hooks, False)

    if not precommit_path:
        return required

    installed = verify_hooks_installed(config_path=precommit_path)
    for hook_id in required:
        required[hook_id] = installed.get(hook_id, False)
    return required


def ensure_git_hook_setup(
    *,
    config: EnvdriftConfig | None = None,
    config_path: Path | None = None,
    config_file: Path | None = None,
    start_dir: Path | None = None,
    auto_fix: bool = True,
) -> list[str]:
    """Ensure git hook setup based on configuration and return errors."""
    if config is None:
        config, config_path = _load_config_for_hook_check(config_file)
    if not config:
        return []

    hook_check: GitHookCheckConfig = config.git_hook_check
    method = normalize_hook_method(hook_check.method)
    if not method:
        if hook_check.method:
            return [
                "Unknown git_hook_check.method value. Use 'precommit.yaml' or 'direct git hook'."
            ]
        return []

    if method == "precommit":
        if not hook_check.precommit_config:
            return ["git_hook_check.precommit_config is required for precommit checks."]

        precommit_path = resolve_precommit_config_path(config_path, hook_check.precommit_config)
        if not precommit_path:
            return ["Pre-commit config path could not be resolved."]

        if auto_fix:
            try:
                from envdrift.integrations.precommit import install_hooks

                install_hooks(config_path=precommit_path, create_if_missing=True)
            except ImportError as e:
                return [str(e)]
            except OSError as e:
                return [f"Failed to update pre-commit config: {e}"]
        elif not precommit_path.exists():
            return [f"Pre-commit config not found: {precommit_path}"]

        required = check_precommit_hooks(precommit_path)
        missing = [hook_id for hook_id, ok in required.items() if not ok]
        if missing:
            hooks_list = ", ".join(missing)
            return [f"Missing envdrift pre-commit hook(s) in {precommit_path}: {hooks_list}"]
        return []

    hooks_dir = resolve_git_hooks_path(start_dir=start_dir)
    if not hooks_dir:
        return ["Git hooks directory not found; cannot verify direct hooks."]

    if auto_fix:
        try:
            install_direct_hooks(hooks_dir)
        except OSError as e:
            return [f"Failed to update git hooks in {hooks_dir}: {e}"]

    installed = check_direct_hooks(hooks_dir)
    missing = [hook_name for hook_name, ok in installed.items() if not ok]
    if missing:
        hooks_list = ", ".join(missing)
        return [f"Missing envdrift git hook(s) in {hooks_dir}: {hooks_list}"]

    return []


def check_git_hook_setup(
    *,
    config: EnvdriftConfig | None = None,
    config_path: Path | None = None,
    config_file: Path | None = None,
    start_dir: Path | None = None,
) -> list[str]:
    """Check git hook setup without modifying files."""
    return ensure_git_hook_setup(
        config=config,
        config_path=config_path,
        config_file=config_file,
        start_dir=start_dir,
        auto_fix=False,
    )
