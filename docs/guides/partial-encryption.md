# Partial Encryption Feature

## Overview

Partial encryption has two modes depending on how your project is structured:

| Mode | Use when… |
|------|-----------|
| **Combine mode** (default) | You want a single merged `.env` file for apps. envdrift merges a plaintext `.clear` file and an encrypted `.secret` file into one output file. |
| **Secrets-only mode** | Your project already separates configs and secrets into distinct directories. envdrift encrypts/decrypts the secrets directory in place — it has zero awareness of your configs directory and produces no combined output. |

---

## Combine Mode

Partial encryption allows you to separate cleartext (non-sensitive) variables from
encrypted (sensitive) variables while maintaining a single combined file for apps.

## File Structure

- **Source files (you edit and commit)**:
  - `.env.production.clear` — Cleartext variables (committed to git)
  - `.env.production.secret` — Sensitive variables (committed to git, always encrypted)

- **Generated runtime file (NOT committed)**:
  - `.env.production` — Combined output for the application; auto-added to `.gitignore` by `envdrift push`

## Configuration

Add to your `envdrift.toml`:

```toml
[partial_encryption]
enabled = true

[[partial_encryption.environments]]
name = "production"
clear_file = ".env.production.clear"
secret_file = ".env.production.secret"
combined_file = ".env.production"

[[partial_encryption.environments]]
name = "staging"
clear_file = ".env.staging.clear"
secret_file = ".env.staging.secret"
combined_file = ".env.staging"
```

## Workflow

### 1. Setup (Initial)

Create your source files:

```bash
# Create cleartext file
cat > .env.production.clear <<EOF
DEBUG=false
LOG_LEVEL=info
PORT=8080
APP_NAME=myapp
EOF

# Create secret file (will be encrypted)
cat > .env.production.secret <<EOF
DATABASE_URL=postgres://user:pass@localhost/db
JWT_SECRET=super-secret-key
STRIPE_API_KEY=sk_live_abc123
EOF

# Push (encrypt + combine). Also auto-adds .env.production to .gitignore.
envdrift push

# Commit only the source files — the combined file is gitignored
git add .env.production.clear .env.production.secret
git commit -m "Add environment configuration"
```

### 2. Daily Development

```bash
# Pull (decrypt secret file for editing)
envdrift pull-partial

# Edit source files
vim .env.production.clear    # Non-sensitive changes
vim .env.production.secret   # Sensitive changes (now decrypted)

# Push (re-encrypt + regenerate combined, lifts git-protection on .secret)
envdrift push

# Commit source files only — combined file is gitignored
git add .env.production.clear .env.production.secret
git commit -m "Update configuration"
```

## Commands

### `envdrift push`

Encrypt secret files and combine with clear files:

```bash
# All environments
envdrift push

# Specific environment
envdrift push --env production
```

**What it does:**

1. Encrypts `.env.{env}.secret` using dotenvx
2. Combines `.clear` + encrypted `.secret` → `.{env}`
3. Adds warning header to generated file

**Safety guarantees** (see [push](../cli/push.md#safety-guarantees) for details):

- `push` re-reads the `.secret` file after encrypting and **fails** if any plaintext
  value survived (e.g. an unwritable or malformed `.env.keys` makes dotenvx warn and
  exit 0 without encrypting) — it never prints the success banner over plaintext.
- An empty or comment-only `.secret` file is refused ("Nothing to encrypt") instead
  of letting dotenvx scaffold placeholder secrets into it. The same applies to
  secrets-only files.
- When **both** the `.clear` and `.secret` files are missing, `push` errors out and
  leaves the existing combined file untouched instead of overwriting it with an
  empty scaffold.
- Combined files are written atomically with owner-only permissions (`0600` on
  POSIX, like `.env.keys`). `envdrift pull --merge` writes the merged file — which
  holds **decrypted** secret values — the same way.

### `envdrift pull-partial`

Decrypt secret files for editing:

```bash
# All environments
envdrift pull-partial

# Specific environment
envdrift pull-partial --env production
```

**What it does:**

1. Decrypts `.env.{env}.secret` in-place
2. Makes it available for editing

## Git Setup

`envdrift push` automatically adds the combined file **and** the dotenvx
private-key file (`.env.keys`) to `.gitignore`. You only need:

```gitignore
*.bak
*.tmp
```

**What to commit:**

| File | Commit? | Why |
|------|---------|-----|
| `.env.production.clear` | ✅ Yes | Plain text, safe in history |
| `.env.production.secret` | ✅ Yes | Always encrypted when committed |
| `.env.production` | ❌ No | Runtime artifact, auto-gitignored |
| `.env.keys` | ❌ No | dotenvx **private** decryption key, auto-gitignored |

### Verify in CI

To guard against committing a stale combined file (e.g. someone edited a
`.clear` file but forgot to re-run `push`), run a dry-run check that writes
nothing and exits non-zero when a `push` is needed:

```bash
envdrift push --check
```

`--check` reports out of sync when the `.secret` file is not **fully** encrypted —
a plaintext file, or a mixed-state file (a newly-added plaintext value alongside
existing ciphertext), both fail the check because a real `push` would re-encrypt them.
A fully SOPS-encrypted `.secret` is recognized as fully encrypted: its plaintext
`sops_*` metadata trailer (`sops_version=`, `sops_lastmodified=`, the recipient key;
only `sops_mac=` is ciphertext) is SOPS bookkeeping, not a leftover plaintext secret.

## After `git pull`

If a teammate updated `.env.production.clear` or `.env.production.secret`, the combined
runtime file is stale. Regenerate it:

```bash
git pull
envdrift pull-partial   # decrypt .secret so push can re-encrypt with any key changes
envdrift push           # regenerates .env.production from the updated source files
```

The combined file is never committed, so there are no merge conflicts on it.

## Benefits

1. ✅ **Git-friendly** - Cleartext vars visible in diffs
2. ✅ **Simple workflow** - Edit source files directly
3. ✅ **One file for apps** - Applications read `.env.production`
4. ✅ **Clear separation** - Know exactly what's sensitive
5. ✅ **Warning header** - Generated file clearly marked

## Example Generated File

```bash
#/--------------------------------------------------------------/
#/ WARNING: AUTO-GENERATED FILE                                 /
#/ DO NOT EDIT THIS FILE DIRECTLY                               /
#/                                                              /
#/ This file is generated by: envdrift push                     /
#/                                                              /
#/ To make changes:                                             /
#/   1. Run:  envdrift pull-partial (decrypts .secret)          /
#/   2. Edit: .env.production.clear                             /
#/   3. Edit: .env.production.secret                            /
#/   4. Run:  envdrift push (re-encrypts and regenerates this)  /
#/--------------------------------------------------------------/

# From .env.production.clear
DEBUG=false
LOG_LEVEL=info
PORT=8080

# From .env.production.secret (encrypted)
DATABASE_URL="encrypted:BD7HQzbvYWcHPy8jGI..."
JWT_SECRET="encrypted:BD9XKwmZvYWcHPz9kHJ..."
STRIPE_API_KEY="encrypted:BDaLMxznvYWcHPy8lKL..."
```

## Migration from Full Encryption

If you have existing encrypted `.env` files:

```bash
# 1. Decrypt existing file
envdrift decrypt .env.production

# 2. Manually split into clear and secret
# Copy non-sensitive vars to .env.production.clear
# Copy sensitive vars to .env.production.secret

# 3. Enable partial encryption in config
# Add [partial_encryption] section to envdrift.toml

# 4. Generate combined file
envdrift push

# 5. Commit source files only (.env.production is now gitignored)
git add .env.production.clear .env.production.secret
git commit -m "Migrate to partial encryption"
```

## Tips

- ✅ **Always edit source files** (`.clear` and `.secret`), never the combined file
- ✅ **Run `push` before committing** to re-encrypt `.secret` and regenerate the combined file
- ✅ **Run `pull-partial` + `push` after `git pull`** to regenerate the combined file from updated sources
- ✅ **Never commit the combined file** — it is a runtime artifact, auto-gitignored by `push`
- ✅ **The `.secret` file is git-protected while decrypted** — `git add .` won't stage it until `push` re-encrypts it
- ✅ **The pre-commit hook is a hard block** — if a plaintext `.secret` (or
  `.env.keys`) is staged, the commit is refused. The plaintext `.clear` half
  commits normally, and an encrypted `.secret` passes. Install it with
  `envdrift hook --install` (or set `[git_hook_check] method = "direct git hook"`).
  `guard --staged` enforces the same rule (`unencrypted-secret-file`, CRITICAL) in CI.

---

## Secrets-Only Mode

Use this mode when your application already keeps plaintext config and secrets in
**separate directories** and you simply want envdrift to encrypt/decrypt the secrets
directory in place. There is no combine step and no merged output file — envdrift
never reads or touches your configs directory at all.

### File Structure

```text
project/
├── configs/                  ← plain text, never touched by envdrift
│   ├── .env.app
│   └── .env.logging
└── secrets/
    └── production/           ← envdrift only operates here
        ├── .env.api          ← encrypted in place on push
        └── .env.db           ← encrypted in place on push
```

### Configuration

```toml
[partial_encryption]
enabled = true

[[partial_encryption.environments]]
name = "production"
secrets_only = true
secrets_dir = "secrets/production/"
pattern = ".env*"          # optional glob, default ".env*"
```

`pattern` is a standard glob applied inside `secrets_dir`. Only files matching it
are encrypted/decrypted; everything else in the directory is left untouched.
The dotenvx key file `.env.keys` is **always excluded**, even if it matches the
pattern — encrypting it would lock away the private keys needed to decrypt everything else.

> **Note — non-recursive by default.** `pattern` is matched with `Path.glob`, which
> does **not** descend into subdirectories unless the pattern itself contains `**`.
> Use `**/.env*` if your secrets live in nested folders.
>
> **`secrets_dir` is required.** envdrift refuses to load a config where
> `secrets_only = true` but `secrets_dir` is missing or empty. This prevents the
> path from defaulting to the working directory and silently encrypting files
> that were never meant to be touched.

### Workflow

#### Setup (first time)

```bash
# Encrypt all secret files in place
envdrift push --env production

# Commit the encrypted files
git add secrets/production/
git commit -m "Encrypt production secrets"
```

#### Daily development

```bash
# 1. Decrypt for editing
envdrift pull-partial --env production

# 2. Edit secret files directly
vim secrets/production/.env.api
vim secrets/production/.env.db

# 3. Re-encrypt before committing
envdrift push --env production

# 4. Commit
git add secrets/production/
git commit -m "Update production secrets"
```

### Git Setup

Only the secrets directory needs gitignore consideration.
The configs directory is committed as-is since it is never modified by envdrift.

```gitignore
# Optionally ignore decrypted backups if your editor creates them
secrets/**/*.bak
```

### Benefits

1. ✅ **Zero impact on configs** — envdrift never reads or writes your configs directory
2. ✅ **No merge step** — no generated combined file to manage
3. ✅ **Directory-level operation** — one config entry handles all files in `secrets_dir`
4. ✅ **Idempotent** — fully-encrypted files are skipped on push; already-decrypted files
   are skipped on pull. A file in a **mixed state** (some values already encrypted plus a
   newly-added plaintext value) is re-encrypted on push, so a new secret can never leak into
   the committed file

---

## Alternative: Using `lock --all`

If you prefer to use `envdrift lock` for all encryption (including partial encryption files),
you can use the `--all` flag:

```bash
# Lock everything, including partial encryption files
envdrift lock -f --all
```

This will:

1. Encrypt all regular `.env.*` files
2. Encrypt all `.secret` files — like `push`, a mixed-state `.secret` (encrypted values
   plus a freshly added plaintext value) is re-encrypted, never skipped
3. Delete the combined files (since they're generated)

This is useful when you want a single command to lock all files before committing,
rather than using separate `push` and `lock` commands.

> **Note:** Secrets-only environments stay managed by `envdrift push`. `lock --all` skips
> them, and if a skipped environment still holds plaintext secrets it exits 1 and points
> you at `envdrift push` instead of claiming everything is ready to commit.
