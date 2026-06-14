"""``python -m envdrift`` entry-point regression tests (#481).

The Go background agent falls back to ``python -m envdrift ...`` when the
``envdrift`` binary is not on PATH, and the docs tell users to run
``python -m envdrift --version``. Before #481 the package had no
``__main__.py``, so every such invocation failed with
"No module named envdrift.__main__" (exit 1).
"""

import subprocess
import sys

from envdrift import __version__


def test_python_dash_m_envdrift_version():
    """Real subprocess: ``python -m envdrift --version`` must work (#481)."""
    result = subprocess.run(
        [sys.executable, "-m", "envdrift", "--version"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert __version__ in result.stdout


def test_main_module_import_does_not_invoke_cli():
    """Importing envdrift.__main__ must not run the CLI (no name-guard bypass)."""
    import envdrift.__main__  # noqa: F401 - import side effects are the test
