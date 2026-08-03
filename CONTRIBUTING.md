# Contributing

Thanks for taking the time to contribute to envdrift.

## Before you start

- Search existing issues and pull requests to avoid duplicates.
- For security issues, see `SECURITY.md`.

## Development setup

```bash
# Install dependencies
uv sync --all-extras

# Run tests
uv run pytest

# Lint and format
uv run ruff check .
uv run ruff format .
```

Optional (recommended) pre-commit hooks:

```bash
pre-commit install
```

## Integration tests need a free LocalStack token

The integration suite drives a real container stack (LocalStack, HashiCorp
Vault, Lowkey-Vault). Since LocalStack 2026.03.0 the image is account-gated:
without `LOCALSTACK_AUTH_TOKEN` it exits with code 55 and
`License activation failed`.

A **free Hobby token** covers everything this suite needs — no paid plan, and
there are no CI credit limits.

1. Sign up at <https://app.localstack.cloud> and copy your **Personal Auth
   Token** (also called a Developer Token). This one is for *local* use.
2. Make it available locally, either way:

   ```bash
   export LOCALSTACK_AUTH_TOKEN=ls-...
   # or, persisted and gitignored:
   echo 'LOCALSTACK_AUTH_TOKEN=ls-...' > tests/.env
   ```

3. Start the stack and run the suite:

   ```bash
   make test-integration-up
   uv run pytest -m integration
   ```

`make test-integration-up` fails with these instructions if no token is found.
Never commit a token — a hygiene test fails the build if an `ls-...` literal
appears in the stack files.

Keep `SERVICES` inside the free Hobby set (`kms`, `lambda`, `s3`,
`secretsmanager`, `sts`). Anything outside it requires a paid LocalStack plan,
and `tests/unit/test_dev_stack_hygiene.py` will fail.

### If you are contributing from a fork

GitHub does not expose repository secrets to pull requests opened from a fork,
and service containers start before any workflow step runs. There is therefore
no way for the four `Integration Tests` jobs to obtain a token on your PR —
**they will fail at container initialisation, and that is expected**. It is a
GitHub platform limitation, not something wrong with your change.

Please do this instead, so your change is still verified:

1. **Run the integration suite locally** using your own free token (steps
   above) and say so in the PR description. This is the important one.
2. Optionally, validate in your own fork's CI: add `LOCALSTACK_AUTH_TOKEN` as
   an Actions secret under **Settings -> Secrets and variables -> Actions** in
   *your fork*, then run the **Integration Tests** workflow from the Actions
   tab via *Run workflow* (`workflow_dispatch`). Note this requires the
   workflow file to exist on your fork's default branch, so sync your fork's
   `main` first.

   For CI, LocalStack recommends a dedicated **CI Auth Token** (workspace
   scope, managed in the LocalStack console) rather than your personal
   Developer Token. A personal token does activate the licence in CI, but it
   ties shared automation to an individual identity — use a CI Auth Token if
   your workspace has one.

A maintainer will run the suite for your change before merging — either
locally with the upstream token, or by pushing your branch to this repository
so CI gets the secret. Re-running the failed workflow does **not** help:
GitHub withholds repository secrets from fork-PR runs even on re-run, and
"Approve and run" grants execution, not secrets.

Branches pushed directly to this repository — including Renovate and
Dependabot — are unaffected and get the token normally.

## Pull requests

- Keep changes focused and describe the intent in the PR description.
- Add or update tests when behavior changes.
- Update docs when user-facing behavior changes.
- Use Conventional Commits for PR titles and commit messages, for example:
  - `fix: handle missing config`
  - `feat: add new drift report format`
  - `docs: clarify release process`

## Reporting bugs

Use the bug report template and include steps to reproduce, expected behavior,
actual behavior, and relevant logs.

## Requesting features

Use the feature request template and explain the problem you're solving.
