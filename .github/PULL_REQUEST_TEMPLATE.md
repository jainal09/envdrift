## Summary

## Changes

## Related issues

<!-- Closes #NNN -->

## Testing

- [ ] `uv run pytest` (note any skipped container/binary suites)
- [ ] Not run (explain why)

## Checklist

See [CLAUDE.md](../CLAUDE.md) for the full conventions.

- [ ] New/changed behavior has a **real** regression test (containers/binaries/CLI, not mocks)
- [ ] Confirmed-but-unfixed bugs are `xfail(strict=False)` with an issue ref
- [ ] Touched files keep **≥ 80%** coverage (codecov green)
- [ ] No hardcoded binary versions — read from `src/envdrift/constants.json` (Renovate-managed)
- [ ] `ruff check` / `ruff format` / `pyrefly` / `bandit` clean
- [ ] Docs (`docs/`) updated for any behavior change
- [ ] Any pre-existing bug found was fixed or filed as an issue
- [ ] No `FORCE_COLOR`-dependent integration output; no `importlib.reload()` of package modules
