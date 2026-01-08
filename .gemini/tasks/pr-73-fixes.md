# PR #73 Fix Tasks: feat(guard): add --staged and --pr-base flags

**PR URL:** https://github.com/jainal09/envdrift/pull/73  
**Branch:** `feat/guard-staged-pr-base`  
**Created:** 2026-01-08

---

## 📊 Current Status

| Check | Status |
|-------|--------|
| CI/Tests & Coverage | ❌ FAILING |
| codecov/patch | ❌ FAILING |
| codecov/project | ❌ FAILING (9.93%, -72.55%) |
| CodeQL | ✅ PASSING |
| Integration Tests | ✅ PASSING |
| CodeRabbit Review | ⚠️ Has review comments |

---

## 🔴 TASK 1: Fix Failing Unit Test

**Priority:** HIGH  
**File:** `tests/unit/test_guard_cli.py`  
**Error:** `AttributeError("'DummyEngine' object has no attribute 'scanners'")`

### Problem
The `DummyEngine` mock in the test doesn't have a `scanners` attribute, which is now required by the guard command to display scanner info.

### Fix
Update the `DummyEngine` mock in `test_guard_defaults_to_cwd` to include the `scanners` attribute.

### Steps
1. Open `tests/unit/test_guard_cli.py`
2. Find the `DummyEngine` class/mock used in `test_guard_defaults_to_cwd`
3. Add `scanners = []` attribute to the mock
4. Run: `uv run pytest tests/unit/test_guard_cli.py::test_guard_defaults_to_cwd -v`

---

## 🔴 TASK 2: Fix Empty Scanner List Crash

**Priority:** HIGH  
**File:** `src/envdrift/scanner/engine.py`  
**Lines:** 211-240  
**Review Comment:** P2 - CodeRabbit

### Problem
If `self.scanners` is empty, `max_workers = min(len(self.scanners), 4)` becomes 0, causing `ThreadPoolExecutor(max_workers=0)` to raise `ValueError`.

### Fix (Option A - Preferred)
Add early return when no scanners:
```python
if not self.scanners:
    return AggregatedScanResult(
        results=[],
        total_findings=0,
        unique_findings=[],
        scanners_used=[],
        total_duration_ms=int((time.time() - start_time) * 1000),
    )
```

### Fix (Option B - Alternative)
```python
max_workers = min(len(self.scanners), 4) if self.scanners else 1
```

### Steps
1. Open `src/envdrift/scanner/engine.py`
2. Add early return check before line 211 (ThreadPoolExecutor)
3. Run tests to verify

---

## 🔴 TASK 3: Fix Exception Chaining (Ruff B904)

**Priority:** HIGH  
**File:** `src/envdrift/cli_commands/guard.py`  
**Lines:** 205, 208, 238, 241

### Problem
Exceptions within `except` clauses should use `raise ... from err` pattern.

### Fix
```python
# Line 205-208 (--staged handlers)
except subprocess.TimeoutExpired as err:
    console.print("[red]Error:[/red] Git command timed out")
    raise typer.Exit(code=1) from err
except FileNotFoundError as err:
    console.print("[red]Error:[/red] Git not found. --staged requires git.")
    raise typer.Exit(code=1) from err

# Line 238-241 (--pr-base handlers)  
except subprocess.TimeoutExpired as err:
    console.print("[red]Error:[/red] Git command timed out")
    raise typer.Exit(code=1) from err
except FileNotFoundError as err:
    console.print("[red]Error:[/red] Git not found. --pr-base requires git.")
    raise typer.Exit(code=1) from err
```

### Steps
1. Open `src/envdrift/cli_commands/guard.py`
2. Add `as err` to exception handlers at lines 205, 208, 238, 241
3. Change `raise typer.Exit(code=1)` to `raise typer.Exit(code=1) from err`

---

## 🟡 TASK 4: Fix Overly Permissive Path Matching

**Priority:** MEDIUM  
**File:** `src/envdrift/scanner/native.py`  
**Lines:** 531-550  
**Review Comment:** Major issue - CodeRabbit

### Problem
`_is_allowed_clear_file` uses `allowed in path_str` which is too broad. Example: `allowed=".env.local"` would match `/path/.env.local.backup`.

### Fix
```python
def _is_allowed_clear_file(self, path: Path) -> bool:
    if not self._allowed_clear_files:
        return False
    
    name = path.name
    for allowed in self._allowed_clear_files:
        allowed_path = Path(allowed)
        # Match by filename if allowed is just a filename
        if allowed_path.name == allowed and name == allowed:
            return True
        # Match by path suffix for relative paths
        if str(path).endswith(f"/{allowed}") or str(path) == allowed:
            return True
    return False
```

### Steps
1. Open `src/envdrift/scanner/native.py`
2. Replace `_is_allowed_clear_file` method with stricter matching
3. Add test case for this edge case

---

## 🟡 TASK 5: Fix Generic-Secret False Negative Filter

**Priority:** MEDIUM  
**File:** `src/envdrift/scanner/native.py`  
**Line:** 618  
**Review Comment:** P2 - CodeRabbit

### Problem
The filter skips secrets containing `.` or `?`, which could exclude real secrets like OAuth tokens (`ya29.a0ARrdaM...`).

### Fix
Narrow the filter to specific code patterns instead of blanket punctuation:
```python
# Instead of:
if "." in secret or "?" in secret:
    return False

# Use:
# Skip if it looks like a method call or URL pattern, but allow dots in tokens
if re.match(r'^[a-zA-Z_]\w*\.\w+\(', secret):  # method call pattern
    return False
```

### Steps
1. Review the intent of the filter
2. Make the pattern more specific to code constructs
3. Add test cases for OAuth tokens with dots

---

## 🟢 TASK 6: Add Tests for New Flags (Coverage)

**Priority:** HIGH  
**Issue:** Coverage dropped to 9.93% (-72.55%)

### Problem
No unit tests for the new `--staged` and `--pr-base` flags.

### Tests Needed
```python
class TestGuardStagedFlag:
    def test_staged_with_no_staged_files(self):
        """Test --staged with no staged changes."""
        
    def test_staged_scans_only_staged_files(self):
        """Test --staged only scans git staged files."""
        
    def test_staged_without_git_fails(self):
        """Test --staged fails gracefully without git."""

class TestGuardPrBaseFlag:
    def test_pr_base_scans_diff_files(self):
        """Test --pr-base only scans files changed since base."""
        
    def test_pr_base_with_invalid_ref(self):
        """Test --pr-base with invalid git ref."""
        
    def test_pr_base_without_git_fails(self):
        """Test --pr-base fails gracefully without git."""
```

### Steps
1. Create test file or add to `tests/unit/test_guard_cli.py`
2. Mock subprocess calls for git commands
3. Verify exit codes and behavior
4. Run: `uv run pytest tests/unit/test_guard_cli.py -v --cov`

---

## 🟢 TASK 7: Fix Ruff Linting Issues

**Priority:** LOW (nitpick)  
**Files:** Multiple

### Issues
1. `S603` - subprocess call: check for execution of untrusted input
2. `S607` - Starting a process with a partial executable path
3. `BLE001` - Do not catch blind exception
4. `RUF010` - Use explicit conversion flag

### Steps
1. Add `# noqa: S603` comments where subprocess is intentional
2. Add `# noqa: S607` where partial path is acceptable
3. For line 238: Change `f"Scanner failed: {str(e)}"` to `f"Scanner failed: {e!s}"`
4. Run: `uv run ruff check src/envdrift/`

---

## � TASK 8: Update Documentation for Guard Changes

**Priority:** MEDIUM  
**Status:** NEW

### Changes Needed
1. Update guard command documentation with new flags:
   - `--staged` / `-s` flag for pre-commit scanning
   - `--pr-base` flag for CI/CD PR scanning
   - `--history` / `-H` flag for git history scanning
2. Update config documentation for new options:
   - `[guard].include_history`
   - `[guard].check_entropy`
   - `[guard].scanners` list configuration
3. Add examples for CI/CD integration with `--pr-base`
4. Add pre-commit hook usage example

### Files to Update
- `docs/usage/guard.md` (or create if missing)
- `docs/configuration.md`
- `docs/getting-started/` examples

---

## 🟡 TASK 9: Verify Integration Tests

**Priority:** MEDIUM  
**Status:** NEW

### Check Required
1. Review existing integration tests for guard command
2. Ensure new flags (`--staged`, `--pr-base`, `--history`) are tested
3. Add integration tests if missing for:
   - Scanning only staged files
   - Scanning PR diff against base branch
   - Git history scanning with trufflehog

### Files to Check
- `tests/integration/test_guard*.py`
- `tests/integration/test_scanner*.py`

---

## �📋 Execution Order

1. **TASK 1** - Fix failing test (blocking CI)
2. **TASK 3** - Fix exception chaining (blocking CI - Ruff)
3. **TASK 2** - Fix empty scanner crash
4. **TASK 6** - Add tests for new flags (fix coverage)
5. **TASK 4** - Fix path matching
6. **TASK 5** - Fix false negative filter
7. **TASK 7** - Fix remaining lint issues

---

## 🔧 Commands to Verify Fixes

```bash
# Switch to PR branch
git checkout feat/guard-staged-pr-base

# Run unit tests
uv run pytest tests/unit/ -v

# Run specific failing test
uv run pytest tests/unit/test_guard_cli.py::test_guard_defaults_to_cwd -v

# Run linter
uv run ruff check src/envdrift/

# Run coverage
uv run pytest tests/unit/ --cov=src/envdrift --cov-report=term-missing

# Push fixes
git add -A && git commit -m "fix: address PR review comments" && git push
```

---

## 📝 Resolve Comments via GitHub CLI

After fixing each issue, resolve the review comment:
```bash
# List pending review comments
gh api repos/jainal09/envdrift/pulls/73/comments --jq '.[] | "\(.id): \(.path):\(.line)"'

# Resolve a comment (reply with fix)
gh api repos/jainal09/envdrift/pulls/73/comments -X POST \
  -f body="Fixed in commit <SHA>. Applied the suggested change." \
  -f in_reply_to=<COMMENT_ID>
```
