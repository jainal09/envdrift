"""Prevent environment variable drift with Pydantic schema validation.

envdrift helps you:
- Validate .env files against Pydantic schemas
- Detect drift between environments (dev, staging, prod)
- Integrate with pre-commit hooks and CI/CD pipelines
- Support dotenvx encryption for secure .env files
"""

import logging

try:
    from envdrift._version import __version__
except ImportError:
    # Fallback for editable installs before build
    try:
        from importlib.metadata import PackageNotFoundError, version
    except ImportError:
        # Very old Python without importlib.metadata
        __version__ = "0.0.0+unknown"
    else:
        try:
            __version__ = version("envdrift")
        except PackageNotFoundError:
            __version__ = "0.0.0+unknown"

__author__ = "Jainal Gosaliya"
__email__ = "gosaliya.jainal@gmail.com"

from envdrift.api import diff, init, validate

# Standard library-package practice (Logging HOWTO): a NullHandler on the
# package logger so library log records (e.g. the scan engine's skip warnings)
# never leak to stderr through logging's lastResort handler when the
# application configures no handlers — the CLI prints its own "Warning:" line,
# so the leak duplicated it (#641). SDK users who configure logging still
# receive every record.
logging.getLogger("envdrift").addHandler(logging.NullHandler())

__all__ = ["__version__", "diff", "init", "validate"]
