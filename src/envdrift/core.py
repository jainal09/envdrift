"""Core functionality for envdrift."""

from pathlib import Path


def validate(env_file: Path | str = ".env", schema: str | None = None) -> bool:
    """Validate an .env file against a Pydantic schema.

    Args:
        env_file: Path to the .env file to validate
        schema: Dotted path to the Pydantic Settings class (e.g., 'app.config:Settings')

    Returns:
        True if validation passes, False otherwise

    Raises:
        NotImplementedError: This feature is coming soon
    """
    raise NotImplementedError("Coming soon in v0.1.0")


def diff(env1: Path | str, env2: Path | str) -> dict[str, tuple[str | None, str | None]]:
    """Compare two .env files and return differences.

    Args:
        env1: Path to first .env file
        env2: Path to second .env file

    Returns:
        Dictionary of differences: {key: (value_in_env1, value_in_env2)}

    Raises:
        NotImplementedError: This feature is coming soon
    """
    raise NotImplementedError("Coming soon in v0.1.0")


def init(output: Path | str = "settings.py") -> None:
    """Generate a Pydantic Settings class from an existing .env file.

    Args:
        output: Path where to write the generated Settings class

    Raises:
        NotImplementedError: This feature is coming soon
    """
    raise NotImplementedError("Coming soon in v0.1.0")
