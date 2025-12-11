"""Atomic file operations for sync."""

from __future__ import annotations

import re
import shutil
from datetime import datetime
from pathlib import Path

# dotenvx header format
DOTENVX_HEADER = """#/------------------!DOTENV_PRIVATE_KEYS!-------------------\\#
#/ private decryption keys. DO NOT commit to source control \\#
#/ [how it works](https://dotenvx.com/encryption) \\#
#/----------------------------------------------------------\\#"""


class EnvKeysFile:
    """Read and write .env.keys files with dotenvx format preservation."""

    def __init__(self, path: Path):
        """Initialize with path to .env.keys file."""
        self.path = path

    def exists(self) -> bool:
        """Check if the file exists."""
        return self.path.exists()

    def read_key(self, key_name: str) -> str | None:
        """
        Read a specific key value from the file.

        Returns None if file doesn't exist or key not found.
        """
        if not self.path.exists():
            return None

        content = self.path.read_text()
        pattern = rf"^{re.escape(key_name)}=(.+)$"

        for line in content.splitlines():
            match = re.match(pattern, line)
            if match:
                value = match.group(1).strip()
                # Remove quotes if present
                if (value.startswith('"') and value.endswith('"')) or (
                    value.startswith("'") and value.endswith("'")
                ):
                    value = value[1:-1]
                return value

        return None

    def write_key(self, key_name: str, value: str, environment: str = "production") -> None:
        """
        Write/update a key, preserving existing content and header.

        Creates the file with proper header if it doesn't exist.
        """
        if self.path.exists():
            content = self.path.read_text()
            lines = content.splitlines()

            # Check if key already exists
            key_pattern = rf"^{re.escape(key_name)}="
            key_found = False
            new_lines = []

            for line in lines:
                if re.match(key_pattern, line):
                    new_lines.append(f"{key_name}={value}")
                    key_found = True
                else:
                    new_lines.append(line)

            if not key_found:
                # Add environment comment if not present
                env_comment = f"# .env.{environment}"
                if env_comment not in content:
                    new_lines.append(env_comment)
                new_lines.append(f"{key_name}={value}")

            new_content = "\n".join(new_lines)
            if not new_content.endswith("\n"):
                new_content += "\n"

            atomic_write(self.path, new_content)
        else:
            # Create new file with header
            content = f"{DOTENVX_HEADER}\n# .env.{environment}\n{key_name}={value}\n"
            atomic_write(self.path, content)

    def has_dotenvx_header(self) -> bool:
        """Check if file has the dotenvx header."""
        if not self.path.exists():
            return False
        content = self.path.read_text()
        return "DOTENV_PRIVATE_KEYS" in content

    def create_backup(self) -> Path:
        """Create timestamped backup of the file."""
        if not self.path.exists():
            raise FileNotFoundError(f"Cannot backup non-existent file: {self.path}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self.path.parent / f"{self.path.name}.backup.{timestamp}"
        shutil.copy2(self.path, backup_path)
        return backup_path


def atomic_write(path: Path, content: str, permissions: int = 0o600) -> None:
    """
    Write file atomically with proper permissions.

    Uses a temporary file and rename to ensure atomicity.
    """
    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    tmp_path = path.with_suffix(".tmp")
    try:
        tmp_path.write_text(content)
        tmp_path.chmod(permissions)
        tmp_path.replace(path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def ensure_directory(path: Path) -> None:
    """Create directory if it doesn't exist."""
    path.mkdir(parents=True, exist_ok=True)


def preview_value(value: str, length: int = 32) -> str:
    """Return a preview of the value (first N chars + ...)."""
    if len(value) <= length:
        return value
    return f"{value[:length]}..."
