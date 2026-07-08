# Agent operating guide

Guidance for AI agents (Claude Code and any other tool) doing substantial work in
this repo. It is the detailed companion to [`CLAUDE.md`](./CLAUDE.md) — CLAUDE.md
holds the always-loaded essentials; this file holds the depth. When they overlap,
they must agree: update both in the same PR (grep for the claim so every copy
stays in sync).

This guide was distilled from a large, mostly-autonomous campaign that merged the
entire open-PR backlog. It captures *how to work here*, not *what the code does*.

---

## 0. North star: reliability first

**Until the existing features are production-ready, every change is judged by one
question: does it make the tool more reliable?** Features come second. A change
that adds capability but can silently corrupt data, lie about success, or crash on
a common input is a regression even if it "works" in the happy path.

Concretely, reliability-first means:

- **Fail loud, fail closed.** Never report success while the real outcome failed.
  A refused operation that preserves the user's data beats a "succeeded" that
  destroyed it. (Half the real bugs found in the campaign were "exit 0 while the
  secret was silently lost / never encrypted / permanently undecryptable.")
- **Every bug fix ships a regression test that fails before the fix.** No
  exceptions. Prove the bug exists, then prove the fix closes it.
- **No known-broken merges** — not even in a secondary artifact. If a change ships
  a VS Code extension that crashes on activation, or a binary install that can
  corrupt an existing binary, it is not done, even if an issue is filed. Fix it or
  don't merge it.
- **Fix-or-file for pre-existing bugs.** If you find a real bug you're not fixing
  in this PR, file a GitHub issue with `file:line` + a minimal repro and, where the
  behavior is testable, add an `@pytest.mark.xfail(strict=False, reason="… #NNN")`
  so the day it's fixed the suite tells you.

---

## 1. Daily working discipline

- **Verify, then fix. Never fix a report you haven't reproduced.** Review-bot
  findings, triage notes, and even your own earlier conclusions go stale. Reproduce
  the failure first; if it doesn't reproduce, say so and rebut with evidence rather
  than "fixing" a non-bug.
- **Surgical changes.** Match the surrounding code's idiom, naming, and comment
  density. Re-express your delta on top of the current structure; don't restructure
  to make a diff cleaner.
- **Read the whole file after a conflict resolution.** A textually-clean merge can
  be semantically wrong — e.g. a guard that lands where its variable is unbound, or
  a test mock that no longer matches the real function's contract. Both shipped as
  green PRs in the campaign and only failed on CI or a sibling test.
- **Grep the whole tree when you tighten a guard, rename a message, or change a
  behavior.** A stricter parser/validator breaks sibling tests that asserted the
  old behavior; a reworded error breaks tests that matched the old phrase. Run the
  *full* suite, not just the file you touched.

---

## 2. Local gates (all must pass before you push)

```bash
uv sync --all-extras          # required in a fresh worktree, or pyrefly fails on vault SDK imports
uv run ruff check src tests
uv run ruff format --check .
uv run pyrefly check          # run the WHOLE project — never scope to src/…; test-file types are gated
uv run bandit -r src -c pyproject.toml
uv run pytest -m "not integration"   # fast pre-push gate
make lint-docs                # if you touched ANY .md — it lints all **/*.md, incl. root
```

`pytest -m "not integration"` is the fast pre-push subset; the complete run is
`uv run pytest` (the whole suite, with the container stack up via
`make test-integration-up`) as listed in `CLAUDE.md`. For anything that drives a
real backend/binary, run the relevant integration tests — and for a **core-binary or
cross-cutting change, run the FULL integration suite** (`uv run pytest -m
integration`), not a keyword-filtered subset. A selective `-k` run once hid a real
dotenvx-v2 regression that CI caught only because CI runs everything.

---

## 3. Testing & verification standards

- **Real backends, not mocks of the thing under test.** Integration tests drive the
  container stack (LocalStack / Vault / Lowkey-Vault via
  `tests/docker-compose.test.yml`), real binaries (`dotenvx`, `sops`, the scanners),
  or the real `envdrift` CLI as a subprocess. `monkeypatch`/`unittest.mock` is fine
  for env vars / cwd, not for faking the behavior you're testing.
- **Battle-test against the pinned binary.** External tool versions live in
  `src/envdrift/constants.json` and are bumped by Renovate. Install the pinned
  version and exercise the real thing; derive expectations from its actual output,
  never hardcode a version or a header.
- **Cross-platform bugs need cross-platform proof.** This dev box is WSL2 with
  Windows interop: `powershell.exe -NoProfile -Command '…'` runs *real* Windows
  (PowerShell 5.1, git, `C:\Python314\python.exe`). Several real bugs were
  Windows-only (drive-letter paths, cp1252 decodes, CRLF, `os.replace` on an open
  file, filename-suffix parsing). Prove the fix on real Windows: reproduce the
  failure on the old code, show it passing on the new. **⚠️ Work laptop: corporate
  security blocks execution from arbitrary paths — do ALL Windows clone/test work
  under `C:\DBSW` (`/mnt/c/DBSW` from WSL), a per-task subdir, cleaned up after.**
  Single-quote the `-Command` on the bash side or bash eats `$variables`.
- **Machine output stays machine-readable.** `--format json` / SARIF must be
  ANSI-clean regardless of `FORCE_COLOR`/TTY. Watch the fixture trap: a
  *session-scoped* fixture that snapshots `os.environ` before the autouse
  `FORCE_COLOR`-strip fixture runs will bake color into every child process for the
  whole session — build child envs from a helper that pops `FORCE_COLOR`.
- **CLI assertions must be width-independent.** A long `tmp_path` prefix soft-wraps
  Rich output mid-phrase at CI's narrower width. Collapse whitespace
  (`" ".join(out.split())`) before asserting a phrase, and assert `exit_code`
  explicitly (output-only checks miss failure-mode regressions that still print the
  expected text).
- **Realistic secret literals get push-protection-rejected.** Build fixtures by
  concatenation (`"AKIA" + "IOSF…"`) so the whole literal never appears in source.

---

## 4. Working autonomously on long tasks

The user should not have to babysit a long task or repeat instructions. Drive it to
completion; surface only genuine decisions, real bugs, and the finish.

### The merge gate (every PR clears all of these before merge)

1. **CI green on the *exact* head SHA** — verify the check run's commit, not just
   "the PR is green" (a stale run can be green on an old head).
2. **Zero unresolved review threads** — and threads are resolved by *fixing*, never
   to unblock (see §6).
3. **CodeRabbit has reviewed the current head** — its walkthrough's trailing SHA
   must equal the PR head. CodeRabbit is rate-limited (~1/hr) and silently skips
   burst-pushed commits; a plain `@coderabbitai review` is a no-op when auto-review
   is active — use `@coderabbitai full review`.

### Serial merges under strict up-to-date

`main` is strict-up-to-date, so **every merge re-`BEHIND`s every other open PR** —
merging is serial: `update-branch → wait CI green → merge`, one at a time. Arming
several PRs' auto-merge at once is fine (CI runs in parallel), but expect a
BEHIND-cascade after each merge and batch the `update-branch`es.

### The autonomy loop (watchdog + wake timers)

Reusable scripts live in [`scripts/agent/`](./scripts/agent/):

- **`gate-watchdog.sh`** — one GraphQL snapshot of all open PRs every ~2 min; exits
  (waking the agent) on any actionable change: a PR merged/closed, an *armed* PR
  gaining unresolved threads, an armed PR going BEHIND/DIRTY, or an armed PR stuck
  BLOCKED long enough to suspect a CI failure. Relaunch it after each handling round.
- **`limit-wake-timer.sh "4:10am" [attempt]`** — on a **session-limit** kill
  ("resets 4:10am"), sleep until just past the reset then wake to resume agents;
  exponential backoff via `attempt` if the resume hits the limit again.

Two failure modes are **distinct**: a *session limit* is time-based (use the wake
timer, it self-clears); *credit exhaustion* ("out of usage credits") is model-scoped
and a timer would wake into the same wall — the fix is a model switch, then resume.
The main loop's `gh`/git work is unaffected by subagent limits, so keep merging and
resolving threads while agents are down.

**Discipline that keeps the watchdog quiet:** disarm auto-merge on any PR that has
an agent actively pushing to it — otherwise the watchdog re-fires every cycle on a
DIRTY/BEHIND state you're already handling. Re-arm only after the agent's final push.

### Subagents & worktree isolation

- One fix per sibling worktree: `../envdrift-<n>` (siblings of the repo), created
  with `git worktree add … --detach origin/<branch>` — use `--detach origin/` and
  fetch first; a plain local ref goes stale during active update-branch churn and
  your push gets rejected non-fast-forward.
- **Never create worktrees under `.claude/`** — pyrefly silently drops the whole
  `tests/` tree there, so a test-file type error passes locally and fails CI.
- Tell each agent to **end cleanly after its push** — report and stop, do NOT poll
  for late bot threads. The master owns post-push thread handling; a self-polling
  agent re-wakes forever on stale state.

---

## 5. Stacked PRs & releases

- **Deleting a branch that has an open child PR CLOSES the child permanently here**
  — it does not retarget it. This cost two PRs before the pattern was learned. The
  safe choreography when a parent merges:
  1. merge the parent **without** `--delete-branch`,
  2. `gh api -X PATCH repos/<owner>/<repo>/pulls/<child> -f base=main` while the child is still open,
  3. **then** delete the parent branch.
  A child killed this way is recovered by opening a successor PR from its surviving
  head branch.
- After a parent squash-merges, the child needs a **child-after-squash merge**: both
  sides carry the parent's commits under different identities, so `git merge
  origin/main` conflicts — resolve by taking main's copy of shared content and
  re-expressing only the child's own delta; audit `git diff origin/main...HEAD` is
  exactly the child's intended change.
- **release-please**: it force-pushes and regenerates its release branches on every
  push to `main`. Never hand-edit them. Component releases (`agent`, `vscode`) are
  independent of the main package release and can merge on their own; the main
  release should wait until the last feature PR lands so its changelog includes it.
  Merging one release PR rewrites the shared manifest, so a sibling release PR goes
  DIRTY until release-please regenerates it — expected; wait and merge.

---

## 6. Review bots

Treat any unresolved review thread as the PR being **incomplete**. Fix the
underlying issue with a regression test, then resolve — **never resolve-to-unblock.**

- **CodeRabbit / cubic / Greptile** raise real correctness/security findings
  (confidence-scored). Verify each against the actual code; fix real ones with a
  test, rebut non-issues with a concrete runnable repro. These bots caught genuine
  bugs late into the campaign — do not wave them off.
- **CodeScene** is a **non-required** code-health advisory. When a threshold-edge
  finding is the direct, unavoidable cost of a mandated fix (e.g. +1 cyclomatic
  complexity from a fail-loud `except` branch), decline it **with reasoning and a
  precedent/tracking-issue reference** — don't degrade real code to satisfy a metric.
  For genuinely large pre-existing hotspots, file a tracking issue with an extraction
  plan and cite it.
- Bots re-review on every push and often post fresh threads after an
  `update-branch` merge commit (many are retarget-window artifacts flagging main's
  code, not your delta — decline those with `git diff origin/main...HEAD` evidence).
  Re-check threads after every push; green CI + zero threads at one moment does not
  mean the latest push was reviewed.

---

## 7. Environment & tooling gotchas

- **`gh` token lacks `workflow` scope** — it cannot API-merge a PR that edits
  `.github/workflows/**`. Use `gh pr merge --auto` (GitHub merges server-side), or
  push the branch update over SSH. A local `git push` over SSH is unaffected.
- **GitHub GraphQL intermittently 502s** — prefer REST (`gh api repos/…`) for reads;
  thread resolution needs the GraphQL `resolveReviewThread` mutation, so retry it
  ~3× with a short sleep.
- **`mergeStateStatus` decode:** `BEHIND` needs `update-branch`; `UNSTABLE` (only a
  non-required check red) is still mergeable; green-but-`BLOCKED` is almost always an
  unresolved-conversation gate, not CI — `gh pr merge --admin` prints the real reason
  without actually admin-merging.
- **Required checks** are `Lint`, `Tests & Coverage`, the four `Integration Tests`,
  `semantic-pr`, `commitlint`, and the four `Analyze`. CodeScene, codecov,
  CodeRabbit, and the Cross-Platform matrix are **not** required — but a red
  Cross-Platform run still means a real cross-OS bug; fix it (a Windows-only
  `os.replace` race broke it once and was a genuine defect).
- **Never `pkill -f` a background script by name from a foreground compound command**
  — it can signal the shell itself. Launch long watchers as tracked background tasks,
  not inline `&` (inline gives no completion signal).
- The session scratchpad is cleared periodically; keep durable tooling in the repo
  (that's why the automation lives in `scripts/agent/`).

---

## 8. Commits & PRs

- Conventional Commits (commitlint + `semantic-pr` enforce it): header ≤ 100 chars,
  every body line ≤ 100, hard-wrapped with real newlines. Merge commits are exempt.
- Small, themed PRs by subsystem; keep `docs/` in sync in the same PR as the
  behavior change.
- Any PR touching `pyproject.toml` must regenerate `uv.lock` in the same PR or
  `uv sync --locked` fails in CI.
