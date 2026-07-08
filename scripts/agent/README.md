# Agent automation

Reusable tooling for AI-agent-driven maintenance campaigns (bulk PR review + merge).
The operating manual that explains when and why to use these is [`AGENTS.md`](../../AGENTS.md).

These are helpers for a human-or-agent maintainer running a long, mostly-autonomous
session; they are not part of the shipped package and are not on the docs site.

| Script | What it does |
|--------|--------------|
| `gate-watchdog.sh` | Polls all open PRs every ~2 min and exits on the first actionable change (a merge, an armed PR gaining threads, an armed PR going BEHIND/DIRTY, or a long-BLOCKED armed PR). Run it as a background task so its exit wakes the agent; relaunch after each handling round. |
| `limit-wake-timer.sh` | On a time-based session-limit kill, sleeps until just past the reset (with backoff) then exits to wake the agent to resume its subagents. |

Both default to the `jainal09/envdrift` repo; override with `ENVDRIFT_REPO=owner/name`.
They require an authenticated `gh` CLI.

```bash
# watch until the next actionable PR event (run in the background)
bash scripts/agent/gate-watchdog.sh

# wake ~5 min past a "resets 4:10am" session limit
bash scripts/agent/limit-wake-timer.sh "4:10am"
```
