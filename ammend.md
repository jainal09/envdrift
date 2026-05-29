# Amendment Tracker

Track issues found during playground testing. One entry per finding.
Format: `## [FEATURE] Short title` → status → notes.

Status values: `OPEN` | `IN PROGRESS` | `FIXED` | `WONT FIX`

---

## How to add an entry

```
## [FEATURE] Short description of the issue
- **Status:** OPEN
- **Found:** YYYY-MM-DD
- **Playground step:** e.g. Feature 1c
- **Command:** `envdrift validate .env.extra-keys ...`
- **Observed:** what actually happened
- **Expected:** what should have happened
- **Notes:** any additional context
```

---

<!-- Entries go below this line -->

## [PARTIAL-ENCRYPT] Severity 1 — Combined file had contradictory commit instructions

- **Status:** FIXED
- **Found:** 2026-05-29
- **Observed:** `push()` docstring said "should be committed to git"; docs said
  `git add .env.production`; yet the CLI auto-gitignores the combined file and
  the scanner warns if it is NOT gitignored — three contradictory contracts.
- **Root cause:** The combined file is a runtime artifact, not a committed file.
  Scanner and CLI behavior were correct; docstring and guide were wrong.
- **Fix:** Updated docstring, guide workflows (setup, daily, migration),
  git-setup section, tips, and `cli/push.md`. Added explicit "After git pull"
  section explaining how to regenerate the combined file.

## [PARTIAL-ENCRYPT] Severity 2 — Plaintext `.secret` after pull-partial was committable

- **Status:** FIXED
- **Found:** 2026-05-29
- **Observed:** `pull-partial` decrypted `.secret` in place. `git add .` would
  happily stage plaintext secrets. No guardrail existed unless `guard` was
  separately wired into pre-commit.
- **Fix:** `decrypt_secret_file` now calls `git update-index --skip-worktree`
  on the secret file after decryption; `encrypt_secret_file` calls
  `--no-skip-worktree` after re-encryption. While skip-worktree is active,
  `git add .` and `git status` ignore changes to the file, making accidental
  commit of plaintext secrets structurally impossible. `pull_cmd` also prints
  a prominent yellow warning panel.

## [PARTIAL-ENCRYPT] Severity 3 — `.env.keys` gitignore concern

- **Status:** NOT A BUG
- **Found:** 2026-05-29
- **Investigation:** dotenvx 1.51.4 automatically adds `.env.keys` to
  `.gitignore` when encrypting. Confirmed gitignored in this repo.
  `DOTENV_PRIVATE_KEY_PRODUCTION` at repo root is a directory, not key
  material — not a risk.
