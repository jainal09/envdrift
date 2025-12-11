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
# Add to .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: envdrift-validate
        name: Validate env files
        entry: envdrift validate --ci
        language: system
        files: ^\.env\.(production|staging|development)$
        pass_filenames: true

      - id: envdrift-encryption
        name: Check env encryption
        entry: envdrift encrypt --check
        language: system
        files: ^\.env\.(production|staging)$
        pass_filenames: true
```

### Show Config Snippet Only

```bash
envdrift hook --config
```

### Install Hooks

```bash
envdrift hook --install
```

This modifies your `.pre-commit-config.yaml` directly.

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

### Encryption Hook

```yaml
- id: envdrift-encryption
  name: Check env encryption
  entry: envdrift encrypt --check
  language: system
  files: ^\.env\.(production|staging)$
  pass_filenames: true
```

This blocks commits with unencrypted secrets in production/staging files.

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

Validation FAILED for .env.production

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
