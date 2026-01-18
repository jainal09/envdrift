# Smart Encryption (Deterministic Re-encryption) Specification

## Overview

This specification describes the "Smart Encryption" feature for envdrift, which addresses
the issue of non-deterministic encryption causing unnecessary git noise when using dotenvx
or SOPS encryption backends.

## Problem Statement

### The Issue

Both dotenvx and SOPS use encryption algorithms that produce different ciphertext each
time, even when encrypting identical plaintext:

- **dotenvx**: Uses ECIES (Elliptic Curve Integrated Encryption Scheme) with ephemeral keys
- **SOPS**: Uses different initialization vectors (IVs) and produces different MAC values

This means that running `envdrift lock` or `envdrift encrypt` on an already-encrypted file
(that was decrypted but not modified) will produce different encrypted output. This creates:

1. **Git noise**: Meaningless changes in version control
2. **Confusing diffs**: Obscures actual content changes in code reviews
3. **Increased merge conflicts**: More frequent conflicts in encrypted files

### Example Scenario

```text
1. Developer decrypts .env.production for local development
2. Makes no changes to the content
3. Runs `envdrift lock` before committing
4. File shows as "modified" in git (different ciphertext)
5. Git history becomes cluttered with non-changes
```

## Solution

### Smart Encryption Algorithm

When re-encrypting a file, smart encryption:

1. **Check if file is tracked in git** - Skip if not in version control
2. **Get encrypted version from git (HEAD)** - Retrieve the committed ciphertext
3. **Decrypt git version to temp file** - Get the plaintext from git
4. **Compare decrypted content with current file** - Check if any actual changes exist
5. **If identical**: Restore original encrypted file from git (no re-encryption)
6. **If different**: Proceed with normal encryption

### Implementation Details

The feature is implemented in `src/envdrift/cli_commands/encryption_helpers.py`:

```python
def should_skip_reencryption(
    env_file: Path,
    backend: EncryptionBackend,
    *,
    enabled: bool = False,  # Opt-in parameter
) -> tuple[bool, str]:
    """
    Determine if re-encryption should be skipped because content is unchanged.

    Returns:
        A tuple of (should_skip, reason)
    """
```

### Opt-in Configuration

**Important**: This feature is opt-in to ensure backward compatibility.

Configuration option in `envdrift.toml` or `pyproject.toml`:

```toml
[encryption]
backend = "dotenvx"
smart_encryption = true  # Enable smart encryption (default: false)
```

This feature is configured via `smart_encryption` and does not have a CLI flag.

## Implementation Progress

### Phase 1: Core Implementation [COMPLETED]

- [x] Rebase branch onto main (resolved 7 merge conflicts)
- [x] Git utility functions (`src/envdrift/utils/git.py`)
  - [x] `is_git_repo()` - Check if path is in git repo
  - [x] `get_git_root()` - Get git root directory
  - [x] `is_file_tracked()` - Check if file is tracked
  - [x] `get_file_from_git()` - Get file content from git ref
  - [x] `restore_file_from_git()` - Restore file from git ref
  - [x] `is_file_modified()` - Check if file has modifications
- [x] `should_skip_reencryption()` helper function
- [x] Integration with `lock` command

### Phase 2: Configuration & Opt-in [COMPLETED]

- [x] Add `smart_encryption` config option to `EncryptionConfig` dataclass
- [x] Parse config in `from_dict()` method
- [x] Change default to `enabled=False` (opt-in)
- [x] Wire up config value in `sync.py` lock command
- [x] Add to example config with documentation

### Phase 3: Unit Tests [COMPLETED]

- [x] Tests for `is_git_repo()`
- [x] Tests for `get_git_root()`
- [x] Tests for `is_file_tracked()`
- [x] Tests for `get_file_from_git()`
- [x] Tests for `restore_file_from_git()`
- [x] Tests for `is_file_modified()`
- [x] Tests for `ensure_gitignore_entries()`
- [x] Tests for `should_skip_reencryption()`
  - [x] Test: disabled by default
  - [x] Test: unsupported backend
  - [x] Test: untracked file
  - [x] Test: git version not encrypted
  - [x] Test: content unchanged (restore)
  - [x] Test: content changed (re-encrypt)
  - [x] Test: decrypt fails
  - [x] Test: restore fails
  - [x] Test: exception handling
  - [x] Test: SOPS backend support

### Phase 4: Integration Tests [COMPLETED]

- [x] Smart encryption with dotenvx (decrypt + re-encrypt same content)
- [x] Smart encryption with SOPS

### Phase 5: Documentation [COMPLETED]

- [x] Update `docs/cli/lock.md` - Add smart encryption section
- [x] Created `docs/specs/smart-encryption-spec.md` - Full specification

### Phase 6: Final Verification [COMPLETED]

- [x] Run unit tests - 34 passed
- [ ] Run full test suite (optional)
- [ ] Run linting (optional)

## Files Modified

### Source Files

| File | Status | Description |
|------|--------|-------------|
| `src/envdrift/utils/__init__.py` | Modified | Export git utilities |
| `src/envdrift/utils/git.py` | Modified | Git helper functions |
| `src/envdrift/cli_commands/encryption_helpers.py` | Modified | Added `should_skip_reencryption()` |
| `src/envdrift/cli_commands/sync.py` | Modified | Integrated smart encryption in `lock` |
| `src/envdrift/cli_commands/encryption.py` | Modified | Wire up config in encrypt command |
| `src/envdrift/config/__init__.py` | Modified | Add config option |

### Test Files

| File | Status | Description |
|------|--------|-------------|
| `tests/unit/test_git_utils.py` | Modified | Unit tests for git utilities |
| `tests/unit/test_smart_encryption.py` | Modified | Unit tests for smart encryption helper |
| `tests/integration/test_encryption_tools.py` | Modified | Integration tests |

### Documentation Files

| File | Status | Description |
|------|--------|-------------|
| `docs/specs/smart-encryption-spec.md` | Created | This specification |
| `docs/cli/lock.md` | Updated | CLI documentation |

## API Reference

### Git Utilities (`envdrift.utils.git`)

```python
def is_git_repo(path: Path) -> bool:
    """Check if path is inside a git repository."""

def get_git_root(path: Path) -> Path | None:
    """Get the root directory of the git repository."""

def is_file_tracked(file_path: Path) -> bool:
    """Check if a file is tracked by git."""

def get_file_from_git(file_path: Path, ref: str = "HEAD") -> str | None:
    """Get file content from a git ref."""

def restore_file_from_git(file_path: Path, ref: str = "HEAD") -> bool:
    """Restore a file from a git ref."""

def is_file_modified(file_path: Path) -> bool:
    """Check if a file has been modified compared to HEAD."""
```

### Smart Encryption Helper (`envdrift.cli_commands.encryption_helpers`)

```python
def should_skip_reencryption(
    env_file: Path,
    backend: EncryptionBackend,
    *,
    enabled: bool = False,
) -> tuple[bool, str]:
    """
    Determine if re-encryption should be skipped.

    Parameters:
        env_file: Path to the environment file
        backend: The encryption backend
        enabled: Whether smart encryption is enabled (opt-in)

    Returns:
        Tuple of (should_skip, reason)
    """
```

## Edge Cases & Considerations

### Handled Cases

1. **File not in git repo** - Skip smart encryption, proceed normally
2. **File not tracked** - Skip smart encryption, proceed normally
3. **Git version not encrypted** - Skip smart encryption, proceed normally
4. **Decryption fails** - Skip smart encryption, proceed normally
5. **Line ending differences** - Normalized before comparison (CRLF → LF)
6. **Trailing whitespace** - Stripped before comparison

### Not Handled (Documented Limitations)

1. **Binary files** - Smart encryption only works with text-based .env files
2. **Submodules** - File tracking may not work correctly in submodules
3. **Shallow clones** - May not have full git history

## Security Considerations

1. **Temp file cleanup** - Decrypted content is written to temp file and cleaned up
   immediately after comparison
2. **No secrets in git history** - The encrypted version is restored, never the
   decrypted content
3. **Subprocess security** - All git commands use `subprocess` with proper timeouts
   and error handling

## Backward Compatibility

- **Non-breaking change**: Feature is opt-in via configuration
- **Default behavior unchanged**: Without explicit opt-in, encryption works as before
- **Graceful degradation**: If smart encryption fails, falls back to normal encryption
