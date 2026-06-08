# Changelog

## [10.13.8](https://github.com/jainal09/envdrift/compare/v10.13.7...v10.13.8) (2026-06-08)


### Bug Fixes

* **agent:** harden watcher, lockcheck, registry, and stop reliability ([#413](https://github.com/jainal09/envdrift/issues/413)) ([#424](https://github.com/jainal09/envdrift/issues/424)) ([b9f9993](https://github.com/jainal09/envdrift/commit/b9f99939680b61274e60582c49b26caaa1e17297))
* **cli:** keep guard/diff machine output clean and unescape TOML in error messages ([#418](https://github.com/jainal09/envdrift/issues/418)) ([cbd2f56](https://github.com/jainal09/envdrift/commit/cbd2f566d14019068657214b52ab246b8902fb0a))
* **config:** defer guardian/partial validation; harden schema metadata isolation ([#425](https://github.com/jainal09/envdrift/issues/425)) ([f9ccd49](https://github.com/jainal09/envdrift/commit/f9ccd494dbf585eccf31c47d85eb85c5a625820b))
* **init:** generate safe, importable Python for keyword and non-identifier vars ([#423](https://github.com/jainal09/envdrift/issues/423)) ([e17a103](https://github.com/jainal09/envdrift/commit/e17a1037f6b8132e6f0ba0039e8eb2dea83dbfcc))
* normalize Windows path separators in git lookup and clear-file match ([#420](https://github.com/jainal09/envdrift/issues/420)) ([a8adbc9](https://github.com/jainal09/envdrift/commit/a8adbc9c687d542ec4e498d04b5f71e2a241f73d))
* **partial-encryption:** re-encrypt mixed-state .secret files to stop plaintext leak ([#416](https://github.com/jainal09/envdrift/issues/416)) ([34d7590](https://github.com/jainal09/envdrift/commit/34d759019c59e0093bfaa8405732d452c3ed054d))
* **scanner:** harden scanner/guard correctness against false negatives ([#413](https://github.com/jainal09/envdrift/issues/413)) ([#419](https://github.com/jainal09/envdrift/issues/419)) ([47fbd18](https://github.com/jainal09/envdrift/commit/47fbd18db94c4e32059a0425b5ebe0684bebe00d))
* **sops:** make encrypt idempotent and validate explicit config path ([#422](https://github.com/jainal09/envdrift/issues/422)) ([9439795](https://github.com/jainal09/envdrift/commit/9439795abd3e68dde4025085d4504b585358da42))
* **sync:** gitignore decrypted merge artifact and guard non-UTF-8 env reads ([#415](https://github.com/jainal09/envdrift/issues/415)) ([a4717b1](https://github.com/jainal09/envdrift/commit/a4717b1c6953feb520234e44ab5dae6c00b3c468))
* **vault:** wrap transport errors and coerce non-string HashiCorp values ([#417](https://github.com/jainal09/envdrift/issues/417)) ([e5696d9](https://github.com/jainal09/envdrift/commit/e5696d9f2290952f4871e663357063280715726e))


### Documentation

* **cli:** align sync/decrypt/push/init docs with real behavior ([#413](https://github.com/jainal09/envdrift/issues/413)) ([#421](https://github.com/jainal09/envdrift/issues/421)) ([d5edb2d](https://github.com/jainal09/envdrift/commit/d5edb2dde386012f756301270d252a76fa59aee4))

## [10.13.7](https://github.com/jainal09/envdrift/compare/v10.13.6...v10.13.7) (2026-06-07)


### Bug Fixes

* **ci:** gate vscode publish on env, not secrets, in step if ([#400](https://github.com/jainal09/envdrift/issues/400)) ([eca1a72](https://github.com/jainal09/envdrift/commit/eca1a723801a8dbd9b21108612b27e00a3a38b6b))
* **ci:** test env + vault image + fail-closed checksums + SHA pins + key cleanup ([#331](https://github.com/jainal09/envdrift/issues/331),[#332](https://github.com/jainal09/envdrift/issues/332),[#334](https://github.com/jainal09/envdrift/issues/334),[#365](https://github.com/jainal09/envdrift/issues/365),[#374](https://github.com/jainal09/envdrift/issues/374),[#348](https://github.com/jainal09/envdrift/issues/348)) ([#394](https://github.com/jainal09/envdrift/issues/394)) ([8a54859](https://github.com/jainal09/envdrift/commit/8a54859a0b99cd5a17e776773b574e41f3a1c6be))
* **parser:** export prefix + inline comments + vault quote convergence + init guard ([#351](https://github.com/jainal09/envdrift/issues/351),[#357](https://github.com/jainal09/envdrift/issues/357),[#356](https://github.com/jainal09/envdrift/issues/356),[#372](https://github.com/jainal09/envdrift/issues/372)) ([#385](https://github.com/jainal09/envdrift/issues/385)) ([6fa155e](https://github.com/jainal09/envdrift/commit/6fa155e6a80364513a506cdf6adf5660aeb8414d))
* **partial-encryption:** ciphertext-anchored is_file_encrypted + companion/utf-8 ([#352](https://github.com/jainal09/envdrift/issues/352),[#358](https://github.com/jainal09/envdrift/issues/358),[#371](https://github.com/jainal09/envdrift/issues/371)) ([#378](https://github.com/jainal09/envdrift/issues/378)) ([22431e4](https://github.com/jainal09/envdrift/commit/22431e4d879cc0d0ecf2cd53c18f2b0c0670d4a7))
* **scanner:** native-scanner false-positive/negative correctness ([#354](https://github.com/jainal09/envdrift/issues/354),[#355](https://github.com/jainal09/envdrift/issues/355),[#368](https://github.com/jainal09/envdrift/issues/368),[#369](https://github.com/jainal09/envdrift/issues/369),[#370](https://github.com/jainal09/envdrift/issues/370)) ([#377](https://github.com/jainal09/envdrift/issues/377)) ([eec72e2](https://github.com/jainal09/envdrift/commit/eec72e237612439672f40ebea897260a2a084ede))
* **scanner:** report all secrets per line via finditer ([#406](https://github.com/jainal09/envdrift/issues/406)) ([883fdb7](https://github.com/jainal09/envdrift/commit/883fdb7658a93c2958bb30427996c4cfbc2db8f6))
* **scanner:** structure-aware encryption detection in native scanner ([#404](https://github.com/jainal09/envdrift/issues/404)) ([f61d930](https://github.com/jainal09/envdrift/commit/f61d9304d5e8a3a00954dfb967fe9f603e0a01f7))
* **security:** redact secret previews in sync output + enforce GCP project boundary ([#348](https://github.com/jainal09/envdrift/issues/348)) ([#393](https://github.com/jainal09/envdrift/issues/393)) ([13aab54](https://github.com/jainal09/envdrift/commit/13aab548fefcc4a07cdb852590b230e63347deb1))
* **sops:** anchor metadata markers + correct exec-env invocation ([#324](https://github.com/jainal09/envdrift/issues/324), [#329](https://github.com/jainal09/envdrift/issues/329)) ([#350](https://github.com/jainal09/envdrift/issues/350)) ([b724cdf](https://github.com/jainal09/envdrift/commit/b724cdfbef3599b99f6c4708ddb14fda4aabaa3e))
* **sync:** atomic_write via mkstemp to block predictable-tmp symlink ([#405](https://github.com/jainal09/envdrift/issues/405)) ([3e9e40d](https://github.com/jainal09/envdrift/commit/3e9e40d2577b14aa072e568a979f3963d23a886e))
* **sync:** lock --check read-only + vault push --all correctness ([#303](https://github.com/jainal09/envdrift/issues/303),[#318](https://github.com/jainal09/envdrift/issues/318),[#325](https://github.com/jainal09/envdrift/issues/325),[#347](https://github.com/jainal09/envdrift/issues/347)) ([#376](https://github.com/jainal09/envdrift/issues/376)) ([5d550a5](https://github.com/jainal09/envdrift/commit/5d550a50e450398c766e85d63478acf5ac950dbd))
* **sync:** skip lone mismatched .env.&lt;env&gt; in auto-detect ([#407](https://github.com/jainal09/envdrift/issues/407)) ([906d438](https://github.com/jainal09/envdrift/commit/906d438ea6bd0e087919e04b9197e53e8e82b5c0))
* **sync:** validate DOTENV_PRIVATE_KEY env suffix on vault pull ([#403](https://github.com/jainal09/envdrift/issues/403)) ([d502f5d](https://github.com/jainal09/envdrift/commit/d502f5d93910de36ab172805a892576101470a68))
* vault auth-state + config correctness ([#304](https://github.com/jainal09/envdrift/issues/304)/[#305](https://github.com/jainal09/envdrift/issues/305)/[#308](https://github.com/jainal09/envdrift/issues/308)/[#313](https://github.com/jainal09/envdrift/issues/313)/[#326](https://github.com/jainal09/envdrift/issues/326)-328) ([#340](https://github.com/jainal09/envdrift/issues/340)) ([721f10e](https://github.com/jainal09/envdrift/commit/721f10e00134ee7a482e29ad9bbd75c0c9bc62e9))


### Documentation

* fix init --watch, per-mapping providers, and secret/data prefix claims ([#366](https://github.com/jainal09/envdrift/issues/366),[#367](https://github.com/jainal09/envdrift/issues/367),[#375](https://github.com/jainal09/envdrift/issues/375)) ([#392](https://github.com/jainal09/envdrift/issues/392)) ([8d655eb](https://github.com/jainal09/envdrift/commit/8d655ebb96e536d471361fdb718132600230daf6))

## [10.13.6](https://github.com/jainal09/envdrift/compare/v10.13.5...v10.13.6) (2026-06-05)


### Bug Fixes

* dotenvx decrypt/install hardening + agent status parse ([#309](https://github.com/jainal09/envdrift/issues/309)-312/[#320](https://github.com/jainal09/envdrift/issues/320)/[#323](https://github.com/jainal09/envdrift/issues/323)) ([#341](https://github.com/jainal09/envdrift/issues/341)) ([e368d91](https://github.com/jainal09/envdrift/commit/e368d9138b686032749a85d0ca47bed65e599fa5))

## [10.13.5](https://github.com/jainal09/envdrift/compare/v10.13.4...v10.13.5) (2026-06-05)


### Bug Fixes

* validator case-insensitivity, partial header, GuardConfig, git-secrets ([#306](https://github.com/jainal09/envdrift/issues/306)/[#314](https://github.com/jainal09/envdrift/issues/314)/[#316](https://github.com/jainal09/envdrift/issues/316)/[#322](https://github.com/jainal09/envdrift/issues/322)) ([#342](https://github.com/jainal09/envdrift/issues/342)) ([1a708f4](https://github.com/jainal09/envdrift/commit/1a708f4fc9b3dd65480e6eae285a3370c1397964))

## [10.13.4](https://github.com/jainal09/envdrift/compare/v10.13.3...v10.13.4) (2026-06-05)


### Bug Fixes

* resolve 6 security false-negatives (scanner/guard/sops/gitleaks) ([#337](https://github.com/jainal09/envdrift/issues/337)) ([f4521a0](https://github.com/jainal09/envdrift/commit/f4521a027533a66e28b588da59f447c81944a8c4))

## [10.13.3](https://github.com/jainal09/envdrift/compare/v10.13.2...v10.13.3) (2026-06-05)


### Documentation

* add CLAUDE.md engineering conventions + PR checklist ([#343](https://github.com/jainal09/envdrift/issues/343)) ([d1f7341](https://github.com/jainal09/envdrift/commit/d1f73417500d166c88b37c42886baa1971519c6f))

## [10.13.2](https://github.com/jainal09/envdrift/compare/v10.13.1...v10.13.2) (2026-06-05)


### Bug Fixes

* **test:** main Publish CI flake — gcp test reloads envdrift.vault and corrupts VaultProvider enum ([#338](https://github.com/jainal09/envdrift/issues/338)) ([a0300f3](https://github.com/jainal09/envdrift/commit/a0300f380b77f5612ab9875360ce9e93feb2e734))

## [10.13.1](https://github.com/jainal09/envdrift/compare/v10.13.0...v10.13.1) (2026-06-05)


### Bug Fixes

* **vault-sync:** auto-detect custom dotenv filenames without env_file ([#300](https://github.com/jainal09/envdrift/issues/300)) ([b428fdc](https://github.com/jainal09/envdrift/commit/b428fdc87aaaff7c8b192e99e8cf2515d72b4f18))

## [10.13.0](https://github.com/jainal09/envdrift/compare/v10.12.4...v10.13.0) (2026-06-04)


### Features

* **vault-sync:** support custom dotenv filenames via env_file ([#296](https://github.com/jainal09/envdrift/issues/296)) ([d102597](https://github.com/jainal09/envdrift/commit/d1025973a8796e67fe5fd5f69a90f08f7823c24f))


### Bug Fixes

* remove stale verify-vault sync config hint ([#294](https://github.com/jainal09/envdrift/issues/294)) ([a1367bc](https://github.com/jainal09/envdrift/commit/a1367bc4d8eea7b5721a75d40b31302e2ba426b5))

## [10.12.4](https://github.com/jainal09/envdrift/compare/v10.12.3...v10.12.4) (2026-06-03)


### Documentation

* fix 141 stale/incorrect claims across the docs (audit + lint-gated) ([#291](https://github.com/jainal09/envdrift/issues/291)) ([8952dc3](https://github.com/jainal09/envdrift/commit/8952dc327aefb29e49fb5dc4ddfeba5ad1d811fc))

## [10.12.3](https://github.com/jainal09/envdrift/compare/v10.12.2...v10.12.3) (2026-06-03)


### Documentation

* Env File Sync guide follow-ups ([#285](https://github.com/jainal09/envdrift/issues/285)) — card title, de-dup install, config link ([#287](https://github.com/jainal09/envdrift/issues/287)) ([916974e](https://github.com/jainal09/envdrift/commit/916974eac1cefe9354af478f3de19cadd1a1ffe5))

## [10.12.2](https://github.com/jainal09/envdrift/compare/v10.12.1...v10.12.2) (2026-06-03)


### Documentation

* **sops:** add dedicated SOPS backend guide + fix backend docs ([#288](https://github.com/jainal09/envdrift/issues/288)) ([8eb0e7e](https://github.com/jainal09/envdrift/commit/8eb0e7e999c04ae455185724a2060b4b2553f341))

## [10.12.1](https://github.com/jainal09/envdrift/compare/v10.12.0...v10.12.1) (2026-06-03)


### Documentation

* Env File Sync guide (crown-jewel rewrite/rename + top-level) + remove dead env_file_pattern ([#285](https://github.com/jainal09/envdrift/issues/285)) ([6e45c2a](https://github.com/jainal09/envdrift/commit/6e45c2a709dd777d1470a1ddae9e7132e419c442))

## [10.12.0](https://github.com/jainal09/envdrift/compare/v10.11.3...v10.12.0) (2026-06-02)


### Features

* **vault:** add config-free vault-pull command (symmetric to vault-push) ([#283](https://github.com/jainal09/envdrift/issues/283)) ([8c62fee](https://github.com/jainal09/envdrift/commit/8c62fee44fb543e1dccb1d7b80761344b319afb2))

## [10.11.3](https://github.com/jainal09/envdrift/compare/v10.11.2...v10.11.3) (2026-05-29)


### Bug Fixes

* **partial-encryption:** close remaining review items (S4, S2 hard block, committed-private-key, docs) ([#276](https://github.com/jainal09/envdrift/issues/276)) ([cd35710](https://github.com/jainal09/envdrift/commit/cd35710b2363ebd7d6e46101b96a097c8264351a))

## [10.11.2](https://github.com/jainal09/envdrift/compare/v10.11.1...v10.11.2) (2026-05-29)


### Bug Fixes

* **partial-encryption:** address sev5-9 — counts, alignment, --check, scanner, .env.keys ([#270](https://github.com/jainal09/envdrift/issues/270)) ([0f5f916](https://github.com/jainal09/envdrift/commit/0f5f916be96302f1b71d1bea91000411a9e4065f))

## [10.11.1](https://github.com/jainal09/envdrift/compare/v10.11.0...v10.11.1) (2026-05-29)


### Bug Fixes

* **deps:** resolve serialize-javascript security advisories ([#11](https://github.com/jainal09/envdrift/issues/11), [#20](https://github.com/jainal09/envdrift/issues/20)) ([#272](https://github.com/jainal09/envdrift/issues/272)) ([257e3d3](https://github.com/jainal09/envdrift/commit/257e3d3b35029df7144f3d1ed3eb8b9a30d57380))

## [10.11.0](https://github.com/jainal09/envdrift/compare/v10.10.1...v10.11.0) (2026-05-29)


### Features

* **partial-encryption:** add secrets-only mode + fix combined-file contract ([#267](https://github.com/jainal09/envdrift/issues/267)) ([f77801b](https://github.com/jainal09/envdrift/commit/f77801b9efd67ffd9ead958f4df341ababd5e6b5))

## [10.10.1](https://github.com/jainal09/envdrift/compare/v10.10.0...v10.10.1) (2026-05-19)


### Bug Fixes

* **diff:** normalize trivially-equivalent values before comparing ([#251](https://github.com/jainal09/envdrift/issues/251)) ([#252](https://github.com/jainal09/envdrift/issues/252)) ([5707cbe](https://github.com/jainal09/envdrift/commit/5707cbef0c23a8a06f85685e95e238a786b54021))

## [10.10.0](https://github.com/jainal09/envdrift/compare/v10.9.3...v10.10.0) (2026-05-19)


### Features

* **partial-encryption:** add secrets-only mode ([#249](https://github.com/jainal09/envdrift/issues/249)) ([142703c](https://github.com/jainal09/envdrift/commit/142703c8771c45f31279c5b2b5cbb118bca981dc))

## [10.9.3](https://github.com/jainal09/envdrift/compare/v10.9.2...v10.9.3) (2026-05-05)


### Bug Fixes

* **deps:** update module github.com/fsnotify/fsnotify to v1.10.0 ([#227](https://github.com/jainal09/envdrift/issues/227)) ([a25e627](https://github.com/jainal09/envdrift/commit/a25e627914c60cd8efd9dcd3041a337281cdf6ab))
* **release:** exclude component paths from root releases ([#231](https://github.com/jainal09/envdrift/issues/231)) ([4eb245d](https://github.com/jainal09/envdrift/commit/4eb245de03e6745f7c626db42b99e59ef337bd09))

## [10.9.2](https://github.com/jainal09/envdrift/compare/v10.9.1...v10.9.2) (2026-05-03)


### Bug Fixes

* **deps:** update module github.com/pelletier/go-toml/v2 to v2.3.1 ([#222](https://github.com/jainal09/envdrift/issues/222)) ([13e19db](https://github.com/jainal09/envdrift/commit/13e19dbb25075bc8e8afa0215d22a19a529fffe0))

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
