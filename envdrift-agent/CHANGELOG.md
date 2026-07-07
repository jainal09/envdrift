# Changelog

All notable changes to the EnvDrift Agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.4](https://github.com/jainal09/envdrift/compare/agent-v1.1.3...agent-v1.1.4) (2026-07-07)


### Bug Fixes

* **agent:** make auto-encryption pipeline functional end-to-end ([#504](https://github.com/jainal09/envdrift/issues/504)) ([dc02fb5](https://github.com/jainal09/envdrift/commit/dc02fb54a22b2eac05bffd77758ca97cedf55f95))
* **agent:** wire global config, survive registry corruption, unwedge guardian, rotate logs ([#524](https://github.com/jainal09/envdrift/issues/524)) ([bf06709](https://github.com/jainal09/envdrift/commit/bf067096d0909771b74970f5c4a43b283f08c9a1))
* **deps:** update module github.com/pelletier/go-toml/v2 to v2.4.2 ([#551](https://github.com/jainal09/envdrift/issues/551)) ([1c050d6](https://github.com/jainal09/envdrift/commit/1c050d67ab613319b75d6f04969d812bceca5bb9))
* **deps:** update module github.com/pelletier/go-toml/v2 to v2.4.3 ([#569](https://github.com/jainal09/envdrift/issues/569)) ([a08475a](https://github.com/jainal09/envdrift/commit/a08475aae53aac63a23c2ae8de0165fd2fd166f0))

## [1.1.3](https://github.com/jainal09/envdrift/compare/agent-v1.1.2...agent-v1.1.3) (2026-06-08)


### Documentation

* **changelog:** strip stray "cluster J" shorthand from release notes ([#428](https://github.com/jainal09/envdrift/issues/428)) ([0999683](https://github.com/jainal09/envdrift/commit/09996832f86b1dad4ffe227b918ef11d4b729298))

## [1.1.2](https://github.com/jainal09/envdrift/compare/agent-v1.1.1...agent-v1.1.2) (2026-06-08)


### Bug Fixes

* **agent:** harden watcher, lockcheck, registry, and stop reliability ([#413](https://github.com/jainal09/envdrift/issues/413)) ([#424](https://github.com/jainal09/envdrift/issues/424)) ([b9f9993](https://github.com/jainal09/envdrift/commit/b9f99939680b61274e60582c49b26caaa1e17297))

## [1.1.1](https://github.com/jainal09/envdrift/compare/agent-v1.1.0...agent-v1.1.1) (2026-06-07)


### Bug Fixes

* **agent:** data race + goroutine leak + 6 correctness bugs ([#361](https://github.com/jainal09/envdrift/issues/361), [#362](https://github.com/jainal09/envdrift/issues/362), [#348](https://github.com/jainal09/envdrift/issues/348)) ([#386](https://github.com/jainal09/envdrift/issues/386)) ([63eb476](https://github.com/jainal09/envdrift/commit/63eb47669a0a15a7963ccf01c7dc7b4e68bb3d4e))

## [1.1.0](https://github.com/jainal09/envdrift/compare/agent-v1.0.4...agent-v1.1.0) (2026-06-04)


### Features

* **vault-sync:** support custom dotenv filenames via env_file ([#296](https://github.com/jainal09/envdrift/issues/296)) ([d102597](https://github.com/jainal09/envdrift/commit/d1025973a8796e67fe5fd5f69a90f08f7823c24f))

## [1.0.4](https://github.com/jainal09/envdrift/compare/agent-v1.0.3...agent-v1.0.4) (2026-05-09)


### Bug Fixes

* **deps:** update module github.com/fsnotify/fsnotify to v1.10.1 ([#237](https://github.com/jainal09/envdrift/issues/237)) ([13017d1](https://github.com/jainal09/envdrift/commit/13017d109a4181745e9eaf8df690853d114367da))

## [1.0.3](https://github.com/jainal09/envdrift/compare/agent-v1.0.2...agent-v1.0.3) (2026-05-05)


### Bug Fixes

* **deps:** update module github.com/fsnotify/fsnotify to v1.10.0 ([#227](https://github.com/jainal09/envdrift/issues/227)) ([a25e627](https://github.com/jainal09/envdrift/commit/a25e627914c60cd8efd9dcd3041a337281cdf6ab))

## [1.0.2](https://github.com/jainal09/envdrift/compare/agent-v1.0.1...agent-v1.0.2) (2026-05-03)


### Bug Fixes

* **deps:** update module github.com/pelletier/go-toml/v2 to v2.3.1 ([#222](https://github.com/jainal09/envdrift/issues/222)) ([13e19db](https://github.com/jainal09/envdrift/commit/13e19dbb25075bc8e8afa0215d22a19a529fffe0))

## [1.0.1](https://github.com/jainal09/envdrift/compare/agent-v1.0.0...agent-v1.0.1) (2026-04-05)


### Bug Fixes

* **deps:** update module github.com/pelletier/go-toml/v2 to v2.3.0 ([#189](https://github.com/jainal09/envdrift/issues/189)) ([0a06fc4](https://github.com/jainal09/envdrift/commit/0a06fc4ffc09a5c6d690d4f60c6cf7c8fbbfc6f4))

## 1.0.0 (2026-02-21)

### Features

* add envdrift-agent Go background encryption daemon ([#54](https://github.com/jainal09/envdrift/issues/54)) ([55f75b1](https://github.com/jainal09/envdrift/commit/55f75b1c49eacadbdd8aab87650dfcd72390ac1e))
* **agent:** add Phase 2D - per-project watching with individual configs ([#124](https://github.com/jainal09/envdrift/issues/124)) ([f7150b9](https://github.com/jainal09/envdrift/commit/f7150b91c9dd7fb2e8c22c1551b6a743de2ba148))
