# Changelog

## [10.1.0](https://github.com/jainal09/envdrift/compare/v10.0.0...v10.1.0) (2026-01-18)


### Features

* **encryption:** add opt-in smart encryption to skip unchanged files ([#102](https://github.com/jainal09/envdrift/issues/102)) ([8f9c34c](https://github.com/jainal09/envdrift/commit/8f9c34c5a85000b983a1ec3384900aade991ae1f))


### Bug Fixes

* **docs:** update release process guide ([#98](https://github.com/jainal09/envdrift/issues/98)) ([c3d4ef8](https://github.com/jainal09/envdrift/commit/c3d4ef83a31788a31e277a977d4b36a5e4c0ebba))

## v9.0.0

### Breaking Changes

* `auto_install` for dotenvx and SOPS is now opt-in. Set
  `encryption.dotenvx.auto_install = true` and/or
  `encryption.sops.auto_install = true` to restore auto-install behavior.

### Added

* **Windows filename validation**: envdrift now detects problematic filenames
  like `.env.local` that cause dotenvx to fail on Windows with "Input string
  must contain hex characters" error. A clear error message with workaround
  suggestions is shown.
* **Cross-platform line ending normalization**: Automatically converts CRLF
  line endings to LF before encryption/decryption for seamless cross-platform
  compatibility.
* **Improved error detection**: Added detection for hex parsing errors in
  dotenvx output that were previously silently ignored.
* **Duplicate header cleanup**: When encrypting files that were renamed (e.g.,
  `.env.local` → `.env.localenv`), envdrift now automatically removes mismatched
  dotenvx header blocks that would otherwise cause duplicate headers.
