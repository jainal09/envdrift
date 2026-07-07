# envdrift hook

Manage pre-commit hook integration.

## Synopsis

```bash
envdrift hook [OPTIONS]
```

## Description

The `hook` command helps integrate envdrift with [pre-commit](https://pre-commit.com/). It can:

- **Show configuration** - Display the pre-commit config snippet
- **Install hooks** - Automatically add hooks to your project

Pre-commit hooks ensure that:

- Schema validation runs before every commit
- Unencrypted secrets are blocked from being committed
- Environment drift is caught early

## Options

### `--config`

Show the pre-commit configuration snippet to copy into your `.pre-commit-config.yaml`.

```bash
envdrift hook --config
```

### `--install`, `-i`

Automatically install the hooks into your `.pre-commit-config.yaml`.

```bash
envdrift hook --install
```

Requires `pyyaml` to be installed.

## Examples

### View Configuration

```bash
envdrift hook
```

Output:

```yaml
# envdrift pre-commit hooks
# Add this to your .pre-commit-config.yaml

repos:
  # >>> envdrift pre-commit hooks >>>
  - repo: local
    hooks:
      # Uncomment the validate hook once you have a Pydantic Settings class and
      # point --schema at it (envdrift validate accepts multiple env files):
      # - id: envdrift-validate
      #   name: Validate env files against schema
      #   entry: envdrift validate --ci --schema app.config:Settings
      #   language: system
      #   files: ^\.env\.(production|staging|development)$
      #   pass_filenames: true
      - id: envdrift-encryption
        name: Check env encryption status
        entry: envdrift encrypt --check
        language: system
        files: ^\.env\.(production|staging)$
        pass_filenames: true
        description: Ensures sensitive .env files are encrypted
      - id: envdrift-guard
        name: Guard staged env files
        entry: envdrift guard --staged --native-only --ci
        language: system
        always_run: true
        pass_filenames: false
        description: Scans staged files, including vault.sync env_file mappings
      # Optional: verify encryption keys match vault (prevents key drift)
      # - id: envdrift-vault-verify
      #   name: Verify vault key can decrypt
      #   entry: envdrift decrypt --verify-vault -p azure --vault-url https://myvault.vault.azure.net --secret myapp-dotenvx-key --ci
      #   language: system
      #   files: ^\.env\.production$
      #   pass_filenames: true
  # <<< envdrift pre-commit hooks <<<
```

The validate hook ships commented out because it needs a `--schema` pointing at your
Settings class, which envdrift cannot guess — uncomment it and set the schema path once
you have one. Both `validate` and `encrypt --check` accept multiple env-file arguments,
so `pass_filenames: true` hooks keep working when several matched files are staged.

Use `envdrift hook --install` to add these hooks to `.pre-commit-config.yaml`.

### Show Config Snippet Only

```bash
envdrift hook --config
```

### Install Hooks

```bash
envdrift hook --install
```

This adds the envdrift block to your `.pre-commit-config.yaml` with a targeted text
edit: existing comments, ordering, and formatting are preserved, and the block is
wrapped in `# >>> envdrift pre-commit hooks >>>` / `# <<< envdrift pre-commit hooks <<<`
markers so it can be removed cleanly later. Re-running the command when the hooks are
already present is a no-op (it reports "already installed"). If the file is malformed
YAML or its top level is not a mapping, the command fails with a clean error and exit
code 1 without touching the file.

## Manual Setup

If you prefer manual setup:

1. **Create `.pre-commit-config.yaml`**:

   ```yaml
   repos:
     - repo: local
       hooks:
         - id: envdrift-validate
           name: Validate env schema
           entry: envdrift validate --ci --schema config.settings:Settings
           language: system
           files: ^\.env\.(production|staging|development)$
           pass_filenames: true
   ```

2. **Install pre-commit**:

   ```bash
   pip install pre-commit
   pre-commit install
   ```

3. **Test the hook**:

   ```bash
   pre-commit run envdrift-validate --all-files
   ```

## Hook Configuration

### Validation Hook

```yaml
- id: envdrift-validate
  name: Validate env schema
  entry: envdrift validate --ci --schema config.settings:Settings
  language: system
  files: ^\.env\.(production|staging|development)$
  pass_filenames: true
```

| Option           | Description                            |
| :--------------- | :------------------------------------- |
| `entry`          | Command to run (customize schema path) |
| `files`          | Regex matching .env files to validate  |
| `pass_filenames` | Pass matched files as arguments        |

This hook is installed commented out: `--schema` must point at your Settings class
before it can pass. `envdrift validate` accepts multiple env-file arguments, so the
hook keeps working when pre-commit appends several matched staged files at once.

### Encryption Hook

```yaml
- id: envdrift-encryption
  name: Check env encryption
  entry: envdrift encrypt --check
  language: system
  files: ^\.env\.(production|staging)$
  pass_filenames: true
```

This blocks commits with unencrypted secrets in production/staging files that
match the hook regex.

### Guard Hook

```yaml
- id: envdrift-guard
  name: Guard staged env files
  entry: envdrift guard --staged --native-only --ci
  language: system
  always_run: true
  pass_filenames: false
```

This runs the config-aware staged scanner. It covers normal `.env*` files,
partial-encryption `.secret` files, `.env.keys`, and custom
`[vault.sync].mappings.env_file` names such as `postgresql.env`.

## Customization

### Different Schemas per Environment

```yaml
repos:
  - repo: local
    hooks:
      - id: envdrift-validate-prod
        name: Validate production env
        entry: envdrift validate --ci --schema config.settings:ProductionSettings
        language: system
        files: ^\.env\.production$
        pass_filenames: true

      - id: envdrift-validate-dev
        name: Validate development env
        entry: envdrift validate --ci --schema config.settings:DevelopmentSettings
        language: system
        files: ^\.env\.development$
        pass_filenames: true
```

### Skip Encryption Check for Development

```yaml
- id: envdrift-encryption
  name: Check env encryption
  entry: envdrift encrypt --check
  language: system
  files: ^\.env\.(production|staging)$  # Excludes development
  pass_filenames: true
```

### Add Service Directory

```yaml
- id: envdrift-validate
  name: Validate env schema
  entry: envdrift validate --ci --schema config.settings:Settings --service-dir ./backend
  language: system
  files: ^\.env\..*$
  pass_filenames: true
```

## Workflow

### Developer Experience

1. Developer adds a new required field to the schema
2. Developer tries to commit without updating .env
3. Pre-commit hook runs `envdrift validate`
4. Commit is blocked with clear error message
5. Developer adds the missing variable
6. Commit succeeds

### Example Blocked Commit

```text
$ git commit -m "Add new feature"
Validate env schema.....................................................Failed
- hook id: envdrift-validate
- exit code: 1

Validating: .env.production

Validation FAILED

MISSING REQUIRED VARIABLES:
  * NEW_API_KEY - API key for external service

Summary: 1 error(s), 0 warning(s)
```

## Troubleshooting

### Hook Not Running

Ensure pre-commit is installed:

```bash
pre-commit install
```

### Schema Import Errors

Add `--service-dir` to point to your project root:

```yaml
entry: envdrift validate --ci --schema config.settings:Settings --service-dir .
```

### Skip Hook Temporarily

```bash
git commit --no-verify -m "WIP"
```

Use sparingly!

## See Also

- [validate](validate.md) - Validation command details
- [encrypt](encrypt.md) - Encryption check details
