# Engineering conventions (envdrift)

Guidance for contributors and AI agents (Claude Code, etc.) working in this repo.
These are the conventions we actually enforce — follow them on every change.

## Testing

- **Real tests, not mocks of the behavior under test.** Integration tests drive
  real backends: the container stack (LocalStack `:4566` / HashiCorp Vault `:8200`
  / Lowkey-Vault `:8443` via `tests/docker-compose.test.yml`), real binaries
  (`dotenvx`, `sops`, the secret scanners), or the real `envdrift` CLI as a
  subprocess. `unittest.mock`/`monkeypatch` is fine for env vars / cwd, not for
  faking the thing you're testing.
- **Markers:** `integration` (container/binary-backed), plus `aws` / `vault` /
  `azure` / `gcp` / `slow`. Container/cred tests must **skip-gate** cleanly when a
  binary or credential is absent (`shutil.which` / `importlib.util.find_spec` /
  `pytest.importorskip`) so the suite is green locally and runs fully in CI.
- **Every bug fix ships a real regression test.** For a confirmed bug you are
  *not* fixing in this PR, add a test asserting the correct behavior and mark it
  `@pytest.mark.xfail(strict=False, reason="… (see #NNN)")`, referencing the
  filed issue. Flip the `xfail` to a passing assertion in the PR that fixes it.
- **Coverage:** touched files stay **≥ 80%** line coverage (codecov `patch` and
  `project` must stay green). Add focused unit tests for new lines/branches.
- **CI runs tests two ways.** PR `CI` splits them (`-m "not integration"` then
  `-m integration`); the `Publish` workflow runs the **whole suite in one
  process** (`uv run pytest`). Tests must be order-independent — never
  `importlib.reload()` a package module (e.g. `envdrift.vault`): it rebuilds
  enums/classes with a new identity and breaks unrelated tests in full-suite runs.
- **Integration subprocesses must be deterministic.** CI sets `FORCE_COLOR=1`;
  the integration `conftest.py` strips it (an autouse fixture) so CLI output is
  un-colorized and `--format json` stays parseable. Don't reintroduce a
  color-dependent assertion.

## External binary versions — never hardcode

- Pinned versions for the external tools (`dotenvx`, `sops`, `gitleaks`,
  `trufflehog`, `talisman`, `trivy`, `infisical`, `detect-secrets`) live in
  **`src/envdrift/constants.json`** and are bumped by **Renovate**
  (`renovate.json` custom managers). Most also carry a download-URL template
  there; `detect-secrets` is installed via pip (Renovate's `pypi` datasource).
  Add a Renovate manager when you add a tool.
- CI install steps and source code read the version/URL from `constants.json`
  (load it with `json` and pull the `<tool>_version` / `<tool>_download_urls`
  key) — do **not** pin a literal version in a workflow, install script, or test.
- Version-assertion tests read the expected value **dynamically** from
  `constants.json` (e.g. `assert installer.version == _get_<tool>_version()`), so
  Renovate bumps don't break CI.

## CLI & code

- `--format json` (and any machine-readable output) must emit clean JSON with no
  ANSI/Rich colorization, regardless of `FORCE_COLOR` / TTY.
- Resolve git-diff paths against `git rev-parse --show-toplevel` (they're
  repo-root-relative), but display/scan with paths relative to cwd so output
  stays short and config matching is stable.

## Pre-existing issues

If you discover a pre-existing bug while working, **fix it or file a GitHub
issue** — don't silently leave it. Cite `file:line` and evidence in the issue.

## Pull requests

- **Small, themed PRs by subsystem.** Don't bundle unrelated fixes into a mega-PR;
  don't open a separate PR per trivial change (CodeRabbit is rate-limited).
- **Batch review fixes into one commit/push**, resolve threads online on GitHub,
  and wait for CodeRabbit + other bots to finish before pushing again.
- **Keep docs in sync** — update `docs/` in the same PR as the behavior change.
- The branch may be auto-updated with `main` (a merge commit appears on the
  remote); `git fetch` + rebase before pushing rather than racing it.

## Local gates (all must pass)

```bash
uv sync --all-extras          # required in a fresh git worktree, or pyrefly fails on vault SDK imports
uv run ruff check src tests
uv run ruff format --check .
uv run pyrefly check
uv run bandit -r src -c pyproject.toml
uv run pytest                 # full suite (containers via `make test-integration-up`)
```

Commits follow Conventional Commits (commitlint + `semantic-pr` enforce it).
