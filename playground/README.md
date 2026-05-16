# envdrift Playground

Hands-on test area for every CLI feature. Run commands from **inside this directory**:

```bash
cd playground
```

The venv is at `../.venv`. Activate it or prefix every command with `../.venv/bin/envdrift`.

```bash
source ../.venv/bin/activate
```

---

## Files in this playground

| File | Purpose |
|------|---------|
| `.env.dev` | Valid dev env — all required keys, correct types |
| `.env.staging` | Valid staging env — all required keys + optional keys |
| `.env.prod` | Valid prod env — all required keys + extra key `EXTRA_PROD_ONLY_VAR` |
| `.env.missing-keys` | Missing `DATABASE_URL`, `SECRET_KEY`, `API_KEY` |
| `.env.extra-keys` | All required keys + unknown extras (`UNKNOWN_VAR_1`, `LEGACY_CONFIG`) |
| `.env.bad-types` | `DEBUG=not-a-bool`, `PORT=not-a-number` |
| `.env.staging.clear` | Partial encryption — non-sensitive half |
| `.env.staging.secret` | Partial encryption — sensitive half (to be encrypted) |
| `schemas/settings.py` | Pydantic Settings class used by all validate/diff tests |
| `envdrift.toml` | Local config (guard settings, partial encryption config) |

The schema import path for all commands: `schemas.settings:Settings`
Run with `--service-dir .` so Python can resolve the `schemas` package.

---

## Feature 1 — `validate`

### 1a. Happy path (valid file)
```bash
envdrift validate .env.dev --schema schemas.settings:Settings --service-dir .
```
Expected: all green, no errors.

### 1b. Missing required keys — with fix template
```bash
envdrift validate .env.missing-keys --schema schemas.settings:Settings --service-dir . --fix
```
Expected: validation fails, fix template printed for missing vars.

### 1c. Extra keys not in schema
```bash
envdrift validate .env.extra-keys --schema schemas.settings:Settings --service-dir .
```
Expected: warns about `UNKNOWN_VAR_1` and `LEGACY_CONFIG`.

### 1d. Wrong types
```bash
envdrift validate .env.bad-types --schema schemas.settings:Settings --service-dir .
```
Expected: type errors for `DEBUG` and `PORT`.

### 1e. CI mode (non-zero exit on failure)
```bash
envdrift validate .env.missing-keys --schema schemas.settings:Settings --service-dir . --ci; echo "Exit: $?"
```
Expected: exit code 1.

### 1f. Verbose output
```bash
envdrift validate .env.dev --schema schemas.settings:Settings --service-dir . --verbose
```
Expected: additional field details shown.

### 1g. Skip encryption check
```bash
envdrift validate .env.dev --schema schemas.settings:Settings --service-dir . --no-check-encryption
```

---

## Feature 2 — `diff`

### 2a. Dev vs staging (table format)
```bash
envdrift diff .env.dev .env.staging
```
Expected: table showing added, removed, changed vars. Sensitive values masked.

### 2b. Dev vs prod (show sensitive values)
```bash
envdrift diff .env.dev .env.prod --show-values
```

### 2c. Include unchanged vars
```bash
envdrift diff .env.dev .env.staging --include-unchanged
```

### 2d. JSON output (for scripting)
```bash
envdrift diff .env.dev .env.prod --format json
```

### 2e. With schema (for better sensitive detection)
```bash
envdrift diff .env.dev .env.prod --schema schemas.settings:Settings --service-dir .
```

---

## Feature 3 — `init` (generate schema from .env)

### 3a. Generate schema from dev env
```bash
envdrift init .env.dev --output generated_settings.py --class-name DevSettings
```
Expected: `generated_settings.py` created with inferred types.

### 3b. Without sensitive detection
```bash
envdrift init .env.dev --output generated_settings_plain.py --no-detect-sensitive
```

Inspect the output:
```bash
cat generated_settings.py
```

---

## Feature 4 — `guard` (secret scanning)

### 4a. Scan current directory (native scanner)
```bash
envdrift guard .
```
Expected: findings for plaintext secrets in `.env.*` files.

### 4b. Scan a specific file
```bash
envdrift guard .env.prod
```

### 4c. JSON output
```bash
envdrift guard . --format json
```

### 4d. SARIF output (for IDE integration)
```bash
envdrift guard . --format sarif
```

### 4e. Set minimum severity threshold
```bash
envdrift guard . --fail-on-severity low
```

---

## Feature 5 — `encrypt` / `decrypt`

> Requires `dotenvx` installed. Check: `dotenvx --version`

### 5a. Encrypt a file with dotenvx
```bash
cp .env.dev .env.dev.bak
envdrift encrypt .env.dev --provider dotenvx
```

### 5b. Verify encryption marker present
```bash
grep "DOTENV_PUBLIC_KEY\|encrypted" .env.dev
```

### 5c. Decrypt
```bash
envdrift decrypt .env.dev --provider dotenvx
```

### 5d. Restore original
```bash
mv .env.dev.bak .env.dev
```

---

## Feature 6 — `push` / `pull-partial` (partial encryption)

Config is in `envdrift.toml`. Source files: `.env.staging.clear` + `.env.staging.secret`.

### 6a. Push (encrypt secrets + combine)
```bash
envdrift push --env staging
```
Expected: `.env.staging.combined` created with clear vars + encrypted secrets.

### 6b. Inspect combined file
```bash
cat .env.staging.combined
```

### 6c. Pull-partial (decrypt + split back)
```bash
envdrift pull-partial --env staging
```

---

## Feature 7 — `hook`

### 7a. Show hook status
```bash
envdrift hook --help
```

---

## Feature 8 — `install`

### 8a. List install subcommands
```bash
envdrift install --help
```

---

## Feature 9 — `agent`

### 9a. List agent subcommands
```bash
envdrift agent --help
```

---

## Feature 10 — `version`

```bash
envdrift version
envdrift --version
```

---

## Cleanup

```bash
rm -f generated_settings.py generated_settings_plain.py .env.staging.combined
```
