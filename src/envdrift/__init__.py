"""Prevent environment variable drift with Pydantic schema validation.

envdrift helps you:
- Validate .env files against Pydantic schemas
- Detect drift between environments (dev, staging, prod)
- Integrate with pre-commit hooks and CI/CD pipelines
- Support dotenvx encryption for secure .env files
"""

__version__ = "0.0.1"
__author__ = "Jainal Gosaliya"
__email__ = "gosaliya.jainal@gmail.com"

from envdrift.core import validate, diff, init

__all__ = ["validate", "diff", "init", "__version__"]
