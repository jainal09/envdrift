# Changelog

## [10.9.1](https://github.com/jainal09/envdrift/compare/v10.9.0...v10.9.1) (2026-04-05)


### Bug Fixes

* **deps:** update module github.com/pelletier/go-toml/v2 to v2.3.0 ([#189](https://github.com/jainal09/envdrift/issues/189)) ([0a06fc4](https://github.com/jainal09/envdrift/commit/0a06fc4ffc09a5c6d690d4f60c6cf7c8fbbfc6f4))

## [10.9.0](https://github.com/jainal09/envdrift/compare/v10.8.0...v10.9.0) (2026-02-28)


### Features

* add universal installer for macOS, Linux, and Windows ([#156](https://github.com/jainal09/envdrift/issues/156)) ([3b70431](https://github.com/jainal09/envdrift/commit/3b704319959c8e289063b096d30011aee6bc9a1e))


### Bug Fixes

* prevent download() from clobbering caller variables in install.sh ([#159](https://github.com/jainal09/envdrift/issues/159)) ([bb76c56](https://github.com/jainal09/envdrift/commit/bb76c56281a30ded51ae1dd33ad47945069162cd))
* **release:** unblock release-please from legacy grouped PR title ([#162](https://github.com/jainal09/envdrift/issues/162)) ([8c0fb2d](https://github.com/jainal09/envdrift/commit/8c0fb2d73f0800a06a94104871609638142bcd97))
* resolve agent download URL from GitHub API instead of /releases/latest ([#158](https://github.com/jainal09/envdrift/issues/158)) ([47f862b](https://github.com/jainal09/envdrift/commit/47f862be7d0a9ef2e8c645b511b6dce5a520d614))
* **vscode:** update stale pip install references to universal installer ([#161](https://github.com/jainal09/envdrift/issues/161)) ([078eb5f](https://github.com/jainal09/envdrift/commit/078eb5f72c5aac05c7566a62d6947cb9203d2567))

## [10.8.0](https://github.com/jainal09/envdrift/compare/v10.7.0...v10.8.0) (2026-02-21)


### Features

* **release:** add multi-package release-please configuration ([#140](https://github.com/jainal09/envdrift/issues/140)) ([338ba6a](https://github.com/jainal09/envdrift/commit/338ba6a88364ffd057d848bdf15c6c5d49b4dc92))

## [10.7.0](https://github.com/jainal09/envdrift/compare/v10.6.0...v10.7.0) (2026-01-25)


### Features

* **agent:** add Phase 2D - per-project watching with individual configs ([#124](https://github.com/jainal09/envdrift/issues/124)) ([f7150b9](https://github.com/jainal09/envdrift/commit/f7150b91c9dd7fb2e8c22c1551b6a743de2ba148))
* **vscode:** add Phase 2E - agent status indicator ([#125](https://github.com/jainal09/envdrift/issues/125)) ([532edf1](https://github.com/jainal09/envdrift/commit/532edf133390c0c43825d17bdbdc2843674dd3bc))

## [10.6.0](https://github.com/jainal09/envdrift/compare/v10.5.0...v10.6.0) (2026-01-23)


### Features

* **guard:** improve determinism, deduplication accuracy, and UX ([#120](https://github.com/jainal09/envdrift/issues/120)) ([dc3893c](https://github.com/jainal09/envdrift/commit/dc3893cb10ac9b0e5071fa56d6130de86150cd0c))

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
