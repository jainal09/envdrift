"""Shared helpers for the integration tests that run the real detect-secrets package."""

from __future__ import annotations

import subprocess  # nosec B404
from pathlib import Path

# Synthetic npm tokens of the real length, ending in a visible FAKE marker. detect-secrets
# finds them all the same, and no scanner can take them for a credential in this file.
NPM_TOKEN_LINE = "//registry.npmjs.org/:_authToken=npm_" + "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0FeFAKE\n"
OTHER_NPM_TOKEN_LINE = (
    "//registry.npmjs.org/:_authToken=npm_" + "Qa1Wb2Ec3Rd4Tf5Yg6Uh7Ij8Ok9Pl0MnFAKE\n"
)


def add_tracked(repo: Path, *names: str) -> None:
    """Write the npm token to each file and ``git add`` it, so detect-secrets lists it."""
    for name in names:
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(NPM_TOKEN_LINE)
    subprocess.run(["git", "add", "--", *names], cwd=repo, capture_output=True, check=True)


def found(result_findings: list, below: Path) -> list[str]:
    return sorted(Path(f.file_path).relative_to(below).as_posix() for f in result_findings)
