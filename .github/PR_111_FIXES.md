# PR #111 Fixes - Action Plan

## Issues Summary

### 1. CI Failures
- [ ] commitlint: Fix merge commit message
- [ ] Test failure: `test_install_help` - `--force` flag assertion
- [ ] codecov: 0% patch coverage (182 lines missing)

### 2. Critical Review Comments (Priority)
- [ ] Add checksum verification for binary downloads (Security)
- [ ] Fix Windows binary URL (missing .exe extension)
- [ ] Add PATH warning when installing to ~/.local/bin
- [ ] Add comment to empty except clause
- [ ] Handle running agent before force reinstall
- [ ] Improve error logging for subprocess failures

### 3. Test Coverage Gaps
- [ ] Add tests for successful installation flow
- [ ] Add tests for install path selection logic  
- [ ] Add tests for subprocess version/status checks
- [ ] Add tests for 32-bit architecture detection
- [ ] Move imports to module level in tests

### 4. Minor Improvements
- [ ] Increase download timeout or make it configurable
- [ ] Remove/document 32-bit x86 (386) architecture support
- [ ] Improve path existence check documentation

## Execution Order

1. Fix commitlint (rebase/amend merge commit)
2. Fix test failure
3. Add comprehensive test coverage
4. Address critical security/functionality issues
5. Add missing features (checksum, PATH warning)
6. Push and verify CI passes

## Current Branch
feat/agent-phase-2b-install

## Notes
- The `--force` flag IS defined in the command (lines 192-199)
- Need to run test locally to understand why assertion fails
- Consider if all 21 Copilot comments need addressing in this PR
