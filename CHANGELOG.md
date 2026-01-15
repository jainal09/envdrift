# Changelog

## v9.0.0

### Breaking Changes

- `auto_install` for dotenvx and SOPS is now opt-in. Set
  `encryption.dotenvx.auto_install = true` and/or
  `encryption.sops.auto_install = true` to restore auto-install behavior.

### Added

- **Windows filename validation**: envdrift now detects problematic filenames
  like `.env.local` that cause dotenvx to fail on Windows with "Input string
  must contain hex characters" error. A clear error message with workaround
  suggestions is shown.
- **Cross-platform line ending normalization**: Automatically converts CRLF
  line endings to LF before encryption/decryption for seamless cross-platform
  compatibility.
- **Improved error detection**: Added detection for hex parsing errors in
  dotenvx output that were previously silently ignored.
- **Duplicate header cleanup**: When encrypting files that were renamed (e.g.,
  `.env.local` → `.env.localenv`), envdrift now automatically removes mismatched
  dotenvx header blocks that would otherwise cause duplicate headers.
