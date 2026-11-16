# envdrift pull-partial

Decrypt secret files for editing in partial encryption workflows.

## Synopsis

```bash
envdrift pull-partial [OPTIONS]
```

## Description

The `pull-partial` command is part of the [partial encryption](../guides/partial-encryption.md)
workflow. Its exact behaviour depends on the mode configured for each environment:

**Combine mode** (default): decrypts `.secret` files in place so you can edit sensitive
variables. After editing, run `envdrift push` to re-encrypt and regenerate the combined file.

**Secrets-only mode** (`secrets_only = true`): decrypts every file matching `pattern`
inside `secrets_dir` in place. No combined file is involved. The `pattern` glob is
non-recursive by default; use `**/.env*` if your secrets are in nested
subdirectories. `secrets_dir` is required — pulling with `secrets_only = true`
but no `secrets_dir` is rejected at config-load time.

The summary panel reports `Decrypted: N` (files actually decrypted on this run)
and `Skipped: M` (files that were already decrypted, including those skipped in
environments where some other files were decrypted). In secrets-only mode a pull
stops at the first file it cannot decrypt, for whatever reason (a file it cannot
even read, say); the files decrypted before it are still counted in
`Decrypted: N`, and named in the DANGER warning if git could not protect them.

Like `push`, `pull-partial` first makes sure `.gitignore` lists each combined file
and the dotenvx private-key file next to each secret file (`<secret dir>/.env.keys`,
or one per folder in secrets-only mode), so a key you place there for the pull is
never committed. If git still does not ignore a key file (a `!` rule re-includes it,
or git already tracks it),
or cannot say whether it does, it exits 1 before decrypting anything. See
[push](push.md#description).

This command requires partial encryption to be configured in `envdrift.toml`.

## Options

### `--env`, `-e`

Decrypt only a specific environment instead of all configured environments.

```bash
envdrift pull-partial --env production
```

Partial encryption always uses dotenvx for decryption; there is no backend option
to select. A SOPS-encrypted secret file is reported as an error, not decrypted (see
[When a decrypt fails](#when-a-decrypt-fails)).

## Configuration

Partial encryption must be enabled in `envdrift.toml`:

```toml
[partial_encryption]
enabled = true

# Combine mode
[[partial_encryption.environments]]
name = "staging"
clear_file = ".env.staging.clear"
secret_file = ".env.staging.secret"
combined_file = ".env.staging"

# Secrets-only mode
[[partial_encryption.environments]]
name = "production"
secrets_only = true
secrets_dir = "secrets/production/"
pattern = ".env*"
```

## Examples

### Decrypt All Environments

```bash
envdrift pull-partial
```

Decrypts secret files for all configured environments.

### Decrypt Specific Environment

```bash
envdrift pull-partial --env production
```

Only decrypts the production secret file.

### Typical Workflow

```bash
# 1. Pull latest changes
git pull

# 2. Decrypt secret files for editing
envdrift pull-partial

# 3. Edit source files
vim .env.production.clear    # Non-sensitive changes
vim .env.production.secret   # Sensitive changes (now decrypted)

# 4. Re-encrypt and combine
envdrift push

# 5. Commit source files only — the combined file is gitignored
git add .env.production.clear .env.production.secret
git commit -m "Update configuration"
```

## Plaintext protection

While a secret file is decrypted, `pull-partial` marks it `skip-worktree` in your
local clone so a plain `git add .` will not stage it. `envdrift push` lifts the
protection once the file is re-encrypted. This is a local guardrail only — it is not
shared with teammates and can be bypassed with `git add -f`, so never force-add a
decrypted secret file. The same protection applies to every file decrypted in
secrets-only mode.

The plaintext notice is printed whenever this run decrypted at least one file,
even when another environment failed and the command exits 1.

git can only mark a file it tracks. The yellow notice ("They are marked
skip-worktree") appears only when every file this run decrypted was marked. When
any decrypted file could not be marked, a red DANGER warning names each such file
with the reason:

- `untracked`: git does not track the file, so `git add .` would stage it.
- `outside a git repository`: there is no repository to protect it in.
- `skip-worktree failed`: git tracks the file but could not mark it, for example
  while another git process holds the index lock.

```text
Decryption succeeded, but git skip-worktree could not be applied to these decrypted files:
  • secrets/.env.b (untracked)
The other 1 decrypted file(s) are marked skip-worktree.
```

envdrift still tries to mark a file that was plaintext already `skip-worktree`, but it
does not count it as protected, because this run did not decrypt it, and it does not
warn when that mark fails. Decrypting succeeded,
so the command still exits 0 when only the protection failed; re-encrypt with
`envdrift push` before you commit.

A secret file that is a symlink, or sits in a symlinked directory, is decrypted
into the file the link points to, so that is the file marked `skip-worktree` (and
the one `push` lifts the mark from). When git does not track that file, the
warning names the link and where the plaintext is:
`config/.env.production.secret (untracked; through a symlink, the plaintext is in
shared/production.secret)`. A secret file in a git submodule is marked in the
submodule, the repository that tracks it.

That holds in a git hook too (a superproject's `pre-commit`, or a linked
worktree's `post-checkout`, say), though git exports `GIT_DIR`, `GIT_INDEX_FILE`
and the like to its hooks. A secret file of the hook's own repository is marked in
the index the hook is about to commit, and one of another repository, such as a
submodule, in that repository's own index. `push` lifts the mark the same way.

## When a decrypt fails

dotenvx decrypts value by value. When one value was encrypted under another key
(for example after a merge, or through key drift), dotenvx writes the values it
could decrypt and then fails. `pull-partial` takes a byte-for-byte copy of each
secret file before dotenvx runs and writes it back on failure, so the file is left
as it was (still encrypted, CRLF line endings included) instead of half decrypted
and unprotected. The error names the value dotenvx could not decrypt:

```text
✗ Failed to decrypt .env.production.secret: dotenvx decryption failed: ☠ [DECRYPTION_FAILED] could not decrypt STRIPE_API_KEY. ...
.env.production.secret was left as it was: envdrift restored the bytes it had before the decrypt.
```

The copy goes back whole or not at all: envdrift writes it to a temporary file next
to the secret file and renames that over it, so a write that fails (a full disk,
for example) leaves the file as dotenvx wrote it, never cut short. The message then
says the file may now hold decrypted plaintext, marks it `skip-worktree`, and says
whether that protection worked and how to recover:
`git update-index --no-skip-worktree <file>` and then `git checkout -- <file>` for a
file it marked, `git checkout -- <file>` for a tracked file it could not mark, and
`envdrift encrypt <file>` for one git has no copy of. The git commands act on the
file the plaintext is in, in the repository that tracks it. For a symlinked secret
file that is the file the link points to, and git runs in that file's directory
when it is not the current one (a submodule, for example), as in
`git -C shared checkout -- production.secret`.

`pull-partial` also reads each secret file back after dotenvx exits 0, because the
exit code alone can lie. A SOPS-encrypted secret file is one example: dotenvx finds
nothing it can decrypt, prints "no change" and exits 0. A file that still holds
ciphertext is reported as a failure that names the file and the format. It is not
counted as decrypted and not marked `skip-worktree`, and it is left as it was:

```text
✗ Failed to decrypt .env.production.secret: it still holds SOPS ciphertext. Partial encryption decrypts
with dotenvx, which does not read SOPS files. To move it to dotenvx, run
`git update-index --skip-worktree .env.production.secret` so `git add .` cannot stage its plaintext
(git can mark only a tracked file), then `envdrift decrypt .env.production.secret --backend sops`,
then `envdrift push` before you stage anything: push encrypts it with dotenvx and lifts the mark.
```

The mark comes first because `envdrift decrypt` does not set it: decrypted on its
own, the file is plaintext that a plain `git add .` stages. For a file in another
folder the mark runs git there (`git -C <folder> update-index --skip-worktree
<name>`), in the repository that tracks the file: a file in a git submodule is marked
in the submodule, since the superproject tracks only the submodule's commit.
`envdrift pull` gives the same message for its partial-encryption step.

A file name that needs quotes is quoted for the shell you paste the commands into:
in single quotes on Linux and macOS, and in double quotes on Windows. A name that
starts with `-` gets a leading `./` (`.\` on Windows), so neither git nor envdrift
reads it as an option. Inside double quotes cmd.exe still expands `%NAME%` and
PowerShell `$NAME`, and no quoting stops both. So on Windows, when a name holds `%`,
`!`, `$`, a backtick or a curly quote, the message adds a sentence that says to check
that your shell passes the name as it is before you run the commands.

Leftover dotenvx ciphertext is reported the same way (`it still holds dotenvx
ciphertext`), which usually means the decryption key is missing or invalid.

## Exit Codes

| Code | Meaning                                  |
| :--- | :--------------------------------------- |
| 0    | Decryption completed successfully        |
| 1    | Error (missing config, file not found, decryption failed) |

## See Also

- [push](push.md) - Encrypt and combine files
- [Partial Encryption Guide](../guides/partial-encryption.md) - Full workflow documentation
- [decrypt](decrypt.md) - Standard decryption command
