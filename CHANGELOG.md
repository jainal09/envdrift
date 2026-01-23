# Changelog

## [10.5.0](https://github.com/jainal09/envdrift/compare/v10.4.0...v10.5.0) (2026-01-23)


### Features

* **agent:** Phase 2B - install command ([#111](https://github.com/jainal09/envdrift/issues/111)) ([f6ce51e](https://github.com/jainal09/envdrift/commit/f6ce51e523887288d74be004aaadc6eef067680d))

## [10.4.0](https://github.com/jainal09/envdrift/compare/v10.3.0...v10.4.0) (2026-01-23)


### Features

* **guard:** add --skip-gitignored option to filter findings from gitignored files ([#118](https://github.com/jainal09/envdrift/issues/118)) ([6a9030c](https://github.com/jainal09/envdrift/commit/6a9030cee57d8da156dfaf849ba29164c666bf11))

## [10.3.0](https://github.com/jainal09/envdrift/compare/v10.2.1...v10.3.0) (2026-01-22)


### Features

* **guard:** add Talisman, Trivy, and Infisical scanners ([#113](https://github.com/jainal09/envdrift/issues/113)) ([d8b078a](https://github.com/jainal09/envdrift/commit/d8b078a3c5922b822e578d1eea5af3e6ae29a152))

## [10.2.1](https://github.com/jainal09/envdrift/compare/v10.2.0...v10.2.1) (2026-01-18)


### Documentation

* add community health files ([#108](https://github.com/jainal09/envdrift/issues/108)) ([89f90f4](https://github.com/jainal09/envdrift/commit/89f90f48f276dbdf95a99f07c0e2bffa209d98ff))

## [10.2.0](https://github.com/jainal09/envdrift/compare/v10.1.0...v10.2.0) (2026-01-18)


### Features

* **agent:** Phase 2A - Project Registration & Guardian Config ([#103](https://github.com/jainal09/envdrift/issues/103)) ([d2e7625](https://github.com/jainal09/envdrift/commit/d2e76256ed94c665b6bd8afabafa787191013494))

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
