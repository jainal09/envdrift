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

## Gotchas / hard-won lessons

These have bitten us in CI or review and aren't obvious from the code alone.

- **release-please force-pushes its release-PR branches.** On every push to
  `main` it rebases each open `release-please--branches--main--components--*`
  branch onto the new `main` and **regenerates** the CHANGELOG + manifest from
  commit subjects — discarding any manual commit you pushed there. To fix a
  changelog typo, wait until all release PRs merge, then edit the released
  section in a normal `docs(changelog)` PR (release-please won't rewrite already
  released sections) and `gh release edit <tag>` the published notes. Corollary:
  keep internal cluster/sprint labels out of Conventional-Commit subjects —
  they're copied verbatim into user-facing release notes.
- **CLI output assertions must be width-independent.** `CliRunner` unit tests
  that assert a phrase in `result.output` can pass locally and fail in CI: a
  long pytest `tmp_path` prefix pushes Rich's soft-wrap point into the phrase
  (`keys match vault` → `keys` + newline + `match vault`) at CI's narrower
  width. Collapse whitespace first — `" ".join(result.output.split())` — and
  assert `result.exit_code` explicitly (output-only checks miss failure-mode
  regressions that still print the expected text).
- **GitHub push-protection blocks realistic secret literals in fixtures.** A
  scanner test that embeds a real-looking key as one token gets the push
  rejected. Build the fixture by concatenation (e.g. `"AKIA" + "IOSF..."`) so
  the literal never appears whole in the source.
- **Docs CI runs markdownlint (MD013, 150-char prose).** Wrap long lines and run
  `make lint-docs` before pushing a `docs/` change; grep all docs for a repeated
  claim so every copy stays in sync.
- **A stricter guard/parser breaks pre-existing sibling tests.** When you tighten
  validation or a parser, grep the whole test tree and run
  `pytest -m "not integration"` — not just the file you touched — because other
  suites may assert the old behavior.
- **`pyrefly` skips `tests/` inside `.claude/worktrees/`.** A worktree under the
  gitignored `.claude/` makes pyrefly's ignore resolution drop the whole `tests/`
  tree (`WARN Skipping include pattern … tests/**`), so a type error in a test
  file passes locally but fails the `Tests & Coverage` CI job. Create scratch
  worktrees as **siblings of the repo** (`../envdrift-<name>`), and always run the
  **full** `uv run pyrefly check` (never scope it to `src/...`) — test-file types
  are part of the gate.

## CI, branch protection & merging

- `main` is **strict up-to-date** + **requires conversation resolution** + 12
  required checks: `Lint`, `Tests & Coverage`, the four
  `Integration Tests (Python 3.11/3.12/3.13/3.14)`, `semantic-pr`, `commitlint`,
  and the four `Analyze (python/go/javascript-typescript/actions)`. CodeScene,
  codecov, `Agent Lint`, `VS Code Lint`, cubic and the CodeRabbit check are
  **not** required — they don't block merge.
- `mergeStateStatus` decoded: **`UNSTABLE`** (only a non-required check is red) is
  still mergeable; **`BEHIND`** needs `gh pr update-branch`; green-but-**`BLOCKED`**
  is almost always an **unresolved review thread** (conversation resolution), not
  CI — `gh pr merge <n> --admin` prints the real reason ("A conversation must be
  resolved …") so you can diagnose without actually admin-merging.
- Strict up-to-date makes merging several PRs **serial**: each merge re-`BEHIND`s
  the rest, so it's `update-branch` → wait CI green → merge, one PR at a time.
- Transient infra failures — Docker Hub 429s, an "Initialize containers" step, the
  occasional `commitlint` hiccup — are not your code: `gh run rerun <id> --failed`.
  release-please PRs are merged by the repo's "Auto-merge Version Bumps" workflow.

## CodeRabbit & review bots

- CodeRabbit is rate-limited (~1 review/hour) and **silently skips** the
  incremental review on commits pushed in a burst — no "skipped" notice. **Green
  CI + zero unresolved threads does NOT mean it reviewed your latest commits.**
  Verify by the walkthrough's coverage range: the trailing SHA in
  `between <40hex> and <40hex>` must equal the PR head
  (`gh pr view <n> --json headRefOid`). A plain `@coderabbitai review` is a no-op
  unless auto-review is paused — use `@coderabbitai full review` to force one.
- Treat any unresolved review thread (CodeRabbit, Greptile, the review-bot) as the
  PR being **incomplete**: fix the underlying bug with a regression test, then
  resolve the thread — never resolve-to-unblock. An `update-branch` merge commit
  can re-trigger fresh review threads, so re-check after updating.

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
commitlint also caps the **header at ≤ 100 chars and every body line at ≤ 100** —
hard-wrap commit bodies with real newlines (not one long paragraph); merge
commits are exempt.
