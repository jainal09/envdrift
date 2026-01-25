# EnvDrift Agent - Specification

This document outlines improvements for the envdrift-agent and VS Code extension.

## Implementation Status

### Phase 2: Core Features

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 2A | Configuration Improvements (CLI commands, projects.json, [guardian] section) | ✅ Done |
| Phase 2B | CLI Install Command (`envdrift install agent`) | ✅ Done |
| Phase 2C | Build Pipelines (agent + VS Code release workflows) | ✅ Done |
| Phase 2D | Agent Improvements (per-project watching) | ✅ Done |
| Phase 2E | VS Code Agent Status Indicator | ✅ Done |
| Phase 2F | CI/Testing (VS Code lint/tests, Go E2E integration tests) | ✅ Done |

### Phase 3: Publishing, Security & Team Features

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 3A | Publishing & Distribution (VS Code Marketplace, Homebrew, shell completions) | ❌ Not Started |
| Phase 3B | Security & Key Management (key rotation, backup/restore, pre-commit hook) | ❌ Not Started |
| Phase 3C | User Experience (doctor command, desktop notifications, edit workflow) | ❌ Not Started |
| Phase 3D | Observability (audit logging, metrics, error improvements) | ❌ Not Started |
| Phase 3E | Team Features (key sharing, environment-specific keys) | ❌ Not Started |

---

## Current Issues

### 1. Aggressive Default Watching

- **Problem**: Default behavior watches `~` recursively, causing CPU spikes
- **Solution**: Require explicit directory registration, no auto-watch

### 2. Separate Config Files

- **Problem**: `guardian.toml` is separate from `envdrift.toml`
- **Solution**: Add `[guardian]` section to `envdrift.toml` ✅ **DONE**

### 3. Config Discovery

- **Problem**: Agent doesn't know where `envdrift.toml` files are located
- **Solution**: User registers projects with the agent ✅ **DONE** (via `envdrift agent register`)

---

## Phase 2A: Configuration Improvements

### Merge guardian.toml into envdrift.toml

```toml
# envdrift.toml (per-project)
[guardian]
enabled = true
idle_timeout = "5m"
notify = true
```

### Agent Global Config

```toml
# ~/.envdrift/agent.toml (global, minimal)
[agent]
enabled = true
registered_projects = [
  "~/projects/myapp",
  "~/code/api-server"
]
```

### New CLI Commands

```bash
# Register a project with the agent
envdrift agent register          # Register current directory
envdrift agent register ~/myapp  # Register specific directory

# Unregister
envdrift agent unregister

# List registered projects
envdrift agent list

# Agent status
envdrift agent status
```

### CLI-Agent Communication

Two approaches for registering directories with the agent:

#### Option A: CLI Flag

```bash
# Add --watch flag to enable agent watching
envdrift init --watch
envdrift lock --watch

# Or dedicated command
envdrift watch enable
envdrift watch disable
```

#### Option B: Config Setting (Preferred)

```toml
# envdrift.toml
[guardian]
enabled = true        # Registers this directory with the agent
idle_timeout = "5m"
notify = true
```

When `[guardian].enabled = true`:

1. CLI automatically calls agent to register directory
2. Agent reads settings from project's `envdrift.toml`
3. No separate registration step needed

#### Communication Mechanism

```text
┌──────────────────┐     IPC/File      ┌──────────────────┐
│   envdrift CLI   │ ◄──────────────► │  envdrift-agent  │
│   (Python)       │                   │  (Go)            │
└──────────────────┘                   └──────────────────┘

Options:
1. Unix socket: ~/.envdrift/agent.sock
2. File-based: ~/.envdrift/projects.json (agent watches)
3. Signal: Agent reloads config on SIGHUP
```

**Recommended**: File-based (`projects.json`) - simplest, cross-platform

### Central Registry Architecture

**One `projects.json` per machine** at `~/.envdrift/projects.json` acts as the central
registry of all projects the agent should watch on this machine.

```text
Machine (your laptop)
│
├── ~/.envdrift/
│   └── projects.json          ← CENTRAL registry (1 per machine)
│
├── ~/myapp/
│   └── envdrift.toml          ← Project-specific settings
│
├── ~/api-server/
│   └── envdrift.toml
│
└── ~/frontend/
    └── envdrift.toml
```

### projects.json Format

```json
{
  "projects": [
    {"path": "/Users/dev/myapp", "added": "2025-01-01T00:00:00Z"},
    {"path": "/Users/dev/api", "added": "2025-01-02T00:00:00Z"}
  ]
}
```

### How It Works

1. **User runs** `envdrift init --watch` or sets `[guardian].enabled = true`
2. **CLI adds** the project path to `~/.envdrift/projects.json`
3. **Agent watches** `projects.json` for changes (via fsnotify)
4. **Agent reads** each project's `envdrift.toml` for patterns/excludes
5. **Agent encrypts** based on each project's individual config

### Benefits

- ✅ **One file to manage** - no config sprawl
- ✅ **Agent only watches registered projects** - no CPU spike
- ✅ **Cross-platform** - JSON file works everywhere
- ✅ **Hot reload** - Agent auto-updates when projects.json changes

---

## Phase 2B: CLI Install Command ✅

### `envdrift install agent`

New command in Python CLI to install the Go background agent:

```bash
envdrift install agent
```

**Command Options:**

```bash
envdrift install agent              # Install with defaults
envdrift install agent --force      # Force reinstall
envdrift install agent --skip-autostart  # Skip auto-start setup
envdrift install agent --skip-register   # Skip project registration
envdrift install check              # Check installation status
```

**Behavior:**

1. Detect platform (macOS/Linux/Windows + arch: amd64, arm64)
2. Download latest binary from GitHub releases
3. Install to standard location:
   - **Unix**: `/usr/local/bin` → `/opt/homebrew/bin` → `~/.local/bin`
   - **Windows**: `%LOCALAPPDATA%\Programs\envdrift\envdrift-agent.exe`
4. Run `envdrift-agent install` to set up auto-start (unless `--skip-autostart`)
5. Register current directory if has `envdrift.toml` (unless `--skip-register`)

### Implementation

**File:** `src/envdrift/cli_commands/install.py`

Key functions:

- `_detect_platform()` - Returns platform string like `darwin-arm64`, `linux-amd64`
- `_get_install_path()` - Returns appropriate install path for the OS
- `_download_binary()` - Downloads from GitHub with progress indication
- `_run_agent_install()` - Runs `envdrift-agent install` for auto-start

### `envdrift install check`

Reports installation status of all components:

- Python CLI location and version
- Agent installation path and version
- Agent running status (⚡ Running / ⭕ Not running)
- Project registry info

---

## Phase 2C: Build Pipelines ✅

### Agent Release Workflow

**File:** `.github/workflows/agent-release.yml`

**Trigger:** Push tags matching `agent-v*` (e.g., `agent-v1.0.0`)

**Build Matrix (5 platforms):**

| Runner | GOOS | GOARCH | Artifact |
|--------|------|--------|----------|
| ubuntu-latest | linux | amd64 | `envdrift-agent-linux-amd64` |
| ubuntu-latest | linux | arm64 | `envdrift-agent-linux-arm64` |
| macos-latest | darwin | amd64 | `envdrift-agent-darwin-amd64` |
| macos-latest | darwin | arm64 | `envdrift-agent-darwin-arm64` |
| windows-latest | windows | amd64 | `envdrift-agent-windows-amd64.exe` |

**Build Features:**

- Go 1.22 with dependency caching
- `CGO_ENABLED=0` for fully static binaries
- Version injection via ldflags: `-X github.com/jainal09/envdrift-agent/internal/cmd.Version=$VERSION`
- Stripped binaries (`-s -w` flags)

**Release Job:**

- Waits for all builds to complete
- Collects all artifacts into `release/` folder
- Creates GitHub Release with:
  - Installation instructions (CLI and manual)
  - Platform-specific binary list
  - Usage examples
  - Pre-release detection (if version contains `-`)

### VS Code Extension Release Workflow

**File:** `.github/workflows/vscode-release.yml`

**Trigger:** Push tags matching `vscode-v*` (e.g., `vscode-v1.0.0`)

**Build Job:**

1. Setup Node.js 20 with npm caching
2. `npm ci` - Install dependencies
3. `npm run compile` - TypeScript compilation
4. `npm test` - Run tests (non-blocking; failures are logged and release continues)
5. `npx vsce package` - Package as VSIX

**Release Job:**

- Creates GitHub Release with:
  - Marketplace installation instructions
  - Manual VSIX installation steps
  - Features list
  - Requirements (VS Code 1.80.0+, envdrift Python package)
  - Pre-release detection

**Publish Job (stable releases only):**

- Only runs for tags without `-rc`, `-beta`, or `-alpha` suffixes
- Publishes to VS Code Marketplace via `npx vsce publish`
- Uses `VSCE_PAT` secret (Personal Access Token)
- Continue-on-error (allows manual PAT setup)

### Release Tag Examples

```bash
# Agent releases
git tag agent-v1.0.0     # Stable release
git tag agent-v1.1.0-rc1 # Pre-release

# VS Code extension releases
git tag vscode-v1.0.0    # Stable (published to marketplace)
git tag vscode-v1.1.0-beta # Pre-release (GitHub only)

# Push tags
git push origin agent-v1.0.0
git push origin vscode-v1.0.0
```

---

## Phase 2D: Agent Improvements ✅

### Watch Strategy

Instead of watching entire directories, the agent:

1. Only watches registered project roots (from `~/.envdrift/projects.json`)
2. Uses each project's `envdrift.toml` for patterns/excludes
3. Respects project-specific idle timeouts and notification settings

### Implementation

**New Go Packages:**

| Package | File | Purpose |
|---------|------|---------|
| `registry` | `internal/registry/registry.go` | Loads and watches `~/.envdrift/projects.json` |
| `project` | `internal/project/config.go` | Loads per-project `[guardian]` settings from `envdrift.toml` |

**Refactored Guardian:**

The guardian now creates a `ProjectWatcher` for each enabled project:

```go
// internal/guardian/guardian.go

type ProjectWatcher struct {
    projectPath string
    config      *project.GuardianConfig  // Per-project settings
    watcher     *watcher.Watcher
    lastMod     map[string]time.Time
}

type Guardian struct {
    projects        map[string]*ProjectWatcher  // path -> watcher
    registryWatcher *registry.RegistryWatcher   // Watches projects.json
}
```

**Key Features:**

- **Per-project patterns**: Each project uses its own `.env*` patterns and excludes
- **Per-project idle timeout**: Projects can have different encryption delays
- **Per-project notifications**: Enable/disable desktop notifications per project
- **Dynamic registry watching**: Agent auto-reloads when projects are added/removed
- **Only enabled projects**: Projects with `guardian.enabled = false` are skipped

### Architecture

```text
┌─────────────────────────────────────────┐
│      ~/.envdrift/projects.json          │
│  (registry watcher monitors changes)    │
└─────────────────┬───────────────────────┘
                  │
    ┌─────────────┼─────────────┐
    ▼             ▼             ▼
┌───────┐    ┌───────┐    ┌───────┐
│ Proj A│    │ Proj B│    │ Proj C│
│ toml  │    │ toml  │    │ toml  │
└───┬───┘    └───┬───┘    └───┬───┘
    │            │            │
    ▼            ▼            ▼
┌────────┐  ┌────────┐  ┌────────┐
│Project │  │Project │  │Project │
│Watcher │  │Watcher │  │Watcher │
│(5m,    │  │(1m,    │  │(10m,   │
│notify) │  │quiet)  │  │notify) │
└────────┘  └────────┘  └────────┘
    │            │            │
    └────────────┼────────────┘
                 ▼
         ┌─────────────┐
         │  Guardian   │
         │ (aggregates │
         │   events)   │
         └─────────────┘
```

### Configuration Example

```toml
# Project A: envdrift.toml - quick encryption with notifications
[guardian]
enabled = true
idle_timeout = "1m"
patterns = [".env*", ".secret*"]
exclude = [".env.example"]
notify = true

# Project B: envdrift.toml - slow encryption, no notifications
[guardian]
enabled = true
idle_timeout = "10m"
notify = false
```

---

## Phase 2E: VS Code Agent Status Indicator

### Feature

Add a status indicator in VS Code that shows whether the background agent is running and healthy.

### Status Bar Display

| Status | Icon | Color | Meaning |
|--------|------|-------|---------|
| Running | $(zap) Agent | Green text | Agent is running and healthy |
| Stopped | $(circle-slash) Agent | Warning background | Agent is not running |
| Not Installed | $(alert) Agent | Error background | Agent binary not found |
| Error | $(warning) Agent | Error background | Agent has issues |

### Implementation

**New file: `src/agentStatus.ts`**

```typescript
export type AgentStatus = 'running' | 'stopped' | 'not_installed' | 'error';

export interface AgentStatusInfo {
    status: AgentStatus;
    version?: string;
    error?: string;
}

// Check agent status via CLI command
export async function checkAgentStatus(): Promise<AgentStatusInfo> {
    const installed = await isAgentInstalled();
    if (!installed) return { status: 'not_installed' };

    const { stdout } = await execAsync('envdrift-agent status');
    if (stdout.includes('running')) {
        const version = await getAgentVersion();
        return { status: 'running', version };
    }
    return { status: 'stopped' };
}

// Periodic status checking every 30 seconds
export function startStatusChecking(onChange?: StatusChangeCallback): void;
export function stopStatusChecking(): void;

// Agent control
export async function startAgent(): Promise<boolean>;
export async function stopAgent(): Promise<boolean>;
```

**Updated: `src/statusBar.ts`**

- Added second status bar item for agent status
- `updateAgentStatusBar()` function updates icon/color based on status

**Updated: `src/extension.ts`**

- Integrated agent status checking on activation
- Added click handler with QuickPick menu for agent actions

### New Commands

| Command | Title | Description |
|---------|-------|-------------|
| `envdrift.startAgent` | Start Background Agent | Start the envdrift-agent |
| `envdrift.stopAgent` | Stop Background Agent | Stop the envdrift-agent |
| `envdrift.refreshAgentStatus` | Refresh Agent Status | Force refresh status check |

### Status Bar Click Actions

- **If running**: QuickPick with Show Info, Stop Agent, Refresh options
- **If stopped**: QuickPick with Start Agent, Refresh options
- **If not installed**: Show installation instructions with copy command
- **If error**: QuickPick with Refresh, Get Help (opens GitHub issues)

### Communication with Agent

Extension communicates via CLI commands:

1. **Status check**: `envdrift-agent status`
2. **Version**: `envdrift-agent --version`
3. **Start**: `envdrift-agent start`
4. **Stop**: `envdrift-agent stop`

---

## Phase 2F: CI/Testing Improvements

### Overview

Add comprehensive CI workflows and testing for all components.

### VS Code Extension CI (`.github/workflows/vscode-ci.yml`)

**Trigger:** PRs touching `envdrift-vscode/**`

| Stage | Description |
|-------|-------------|
| **Lint** | ESLint with TypeScript rules |
| **Unit Tests** | Jest/Mocha tests for extension logic |
| **E2E Tests** | VS Code extension test runner |

**Implementation:**

```yaml
name: VS Code Extension CI

on:
  pull_request:
    paths:
      - 'envdrift-vscode/**'

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: npm ci
        working-directory: envdrift-vscode
      - run: npm run lint
        working-directory: envdrift-vscode

  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: npm ci
        working-directory: envdrift-vscode
      - run: npm run test
        working-directory: envdrift-vscode

  e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: npm ci
        working-directory: envdrift-vscode
      - run: xvfb-run -a npm run test:e2e
        working-directory: envdrift-vscode
```

### Go Agent E2E Integration Tests

**Add to:** `.github/workflows/agent-ci.yml`

| Stage | Description |
|-------|-------------|
| **Real E2E Tests** | Full integration with actual file system operations |
| **Registry Integration** | Test projects.json loading and watching |
| **Encryption Integration** | Test actual encryption with envdrift CLI |

**Test Scenarios:**

```go
// internal/guardian/guardian_e2e_test.go

func TestGuardian_E2E_RegisterAndWatch(t *testing.T) {
    // 1. Create temp project directory
    // 2. Add envdrift.toml with [guardian] enabled
    // 3. Register project to projects.json
    // 4. Start guardian
    // 5. Create .env file
    // 6. Wait for idle timeout
    // 7. Verify file is encrypted
}

func TestGuardian_E2E_DynamicProjectAdd(t *testing.T) {
    // 1. Start guardian with no projects
    // 2. Add project to projects.json
    // 3. Verify guardian picks up new project
    // 4. Create .env in new project
    // 5. Verify encryption works
}

func TestGuardian_E2E_ProjectRemove(t *testing.T) {
    // 1. Start guardian with project
    // 2. Remove project from projects.json
    // 3. Verify watcher is stopped
}
```

**CI Workflow Addition:**

```yaml
  e2e-tests:
    name: E2E Integration Tests
    runs-on: ubuntu-latest
    needs: build
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Set up Python (for envdrift CLI)
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install envdrift CLI
        run: pip install envdrift

      - name: Download agent binary
        uses: actions/download-artifact@v4
        with:
          name: envdrift-agent-linux-amd64
          path: ./bin

      - name: Make executable
        run: chmod +x ./bin/envdrift-agent-linux-amd64

      - name: Run E2E tests
        run: go test -v -tags=e2e ./...
        working-directory: envdrift-agent
        env:
          ENVDRIFT_AGENT_PATH: ${{ github.workspace }}/bin/envdrift-agent-linux-amd64
```

### Test Coverage Requirements

| Component | Unit Tests | Integration Tests | E2E Tests |
|-----------|------------|-------------------|-----------|
| Python CLI | ✅ Existing | ✅ Existing | - |
| Go Agent | ✅ Existing | ✅ Basic | ❌ **Add** |
| VS Code Extension | ❌ **Add** | - | ❌ **Add** |

---

## Phase 2F: CI/Testing

### VS Code Extension CI

New workflow `.github/workflows/vscode-ci.yml`:

```yaml
jobs:
  lint:
    # ESLint with TypeScript support
    - npm run lint

  build:
    # TypeScript compilation
    - npm run compile

  test:
    # Unit tests (mocha)
    - npm run test:unit
    # Extension tests (VS Code test framework)
    - npm test

  package:
    # Package VSIX artifact
    - vsce package
```

**New files:**

- `eslint.config.mjs` - ESLint flat config with TypeScript
- `src/utils.ts` - Pure utility functions (testable outside VS Code)
- `src/test/unit/config.test.ts` - Unit tests for utilities
- `src/test/suite/extension.test.ts` - VS Code extension tests

**Test coverage:**

- Pattern matching (`matchesPatterns`)
- Exclusion logic (`isExcluded`)
- Encryption detection (`isContentEncrypted`)
- Extension activation and command registration

### Go Agent CI

Existing workflow `.github/workflows/agent-ci.yml` already includes:

- golangci-lint for code quality
- Unit tests with coverage (`go test -race -coverprofile`)
- Integration tests on Linux, macOS, Windows
- Multi-platform builds

---

## Implementation Order

1. **Phase 2A** - Config improvements (merge configs, project registration)
2. **Phase 2B** - CLI install command (download from releases)
3. **Phase 2C** - Build pipelines (auto-release on tag)
4. **Phase 2D** - Agent improvements (per-project watching)
5. **Phase 2E** - VS Code agent status indicator
6. **Phase 2F** - CI/Testing (VS Code lint/tests)

---

## Phase 2 Complete

All Phase 2 features have been implemented:

- ✅ Configuration improvements with project registration
- ✅ CLI install command for agent binary
- ✅ Release workflows for agent and VS Code extension
- ✅ Per-project watching with individual configs
- ✅ VS Code agent status indicator
- ✅ CI/Testing for VS Code extension and Go agent

---

## Phase 3: Publishing, Security & Team Features

---

### Phase 3A: Publishing & Distribution

### VS Code Marketplace Publishing

Auto-publish to VS Code Marketplace when a `vscode-v*` tag is pushed.

```yaml
# .github/workflows/vscode-release.yml (updated)
- name: Publish to VS Code Marketplace
  env:
    VSCE_PAT: ${{ secrets.VSCE_PAT }}
  run: |
    npx vsce publish -p $VSCE_PAT
```

**Setup required:**

1. Create publisher account at <https://marketplace.visualstudio.com>
2. Generate Personal Access Token (PAT)
3. Add `VSCE_PAT` secret to GitHub repository

### Homebrew Formula

Create Homebrew tap for easy macOS/Linux installation:

```bash
# Install via Homebrew
brew tap jainal09/envdrift
brew install envdrift-agent
```

**Formula location:** `homebrew-envdrift/Formula/envdrift-agent.rb`

```ruby
class EnvdriftAgent < Formula
  desc "Background agent for automatic .env file encryption"
  homepage "https://github.com/jainal09/envdrift"
  version "1.0.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/jainal09/envdrift/releases/download/agent-v#{version}/envdrift-agent-darwin-arm64"
      sha256 "..."
    else
      url "https://github.com/jainal09/envdrift/releases/download/agent-v#{version}/envdrift-agent-darwin-amd64"
      sha256 "..."
    end
  end

  on_linux do
    url "https://github.com/jainal09/envdrift/releases/download/agent-v#{version}/envdrift-agent-linux-amd64"
    sha256 "..."
  end

  def install
    bin.install "envdrift-agent-*" => "envdrift-agent"
  end

  service do
    run [opt_bin/"envdrift-agent", "run"]
    keep_alive true
    log_path var/"log/envdrift-agent.log"
    error_log_path var/"log/envdrift-agent.error.log"
  end
end
```

### Shell Completions

Generate shell completions for bash, zsh, and fish.

```bash
# Generate completions
envdrift completion bash > /etc/bash_completion.d/envdrift
envdrift completion zsh > ~/.zfunc/_envdrift
envdrift completion fish > ~/.config/fish/completions/envdrift.fish
```

**Implementation:**

```python
# src/envdrift/cli_commands/completion.py

@cli.command()
@click.argument('shell', type=click.Choice(['bash', 'zsh', 'fish']))
def completion(shell: str):
    """Generate shell completion script."""
    if shell == 'bash':
        click.echo(_BASH_COMPLETION)
    elif shell == 'zsh':
        click.echo(_ZSH_COMPLETION)
    elif shell == 'fish':
        click.echo(_FISH_COMPLETION)
```

---

## Phase 3B: Security & Key Management

### Key Rotation

Rotate encryption keys without re-encrypting all files manually.

```bash
# Rotate keys for current project
envdrift keys rotate

# Rotate keys for specific environment
envdrift keys rotate --env production

# Rotate with automatic re-encryption
envdrift keys rotate --reencrypt
```

**Workflow:**

```text
┌─────────────────────────────────────────────────────────────┐
│                     Key Rotation Flow                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Generate new keypair                                     │
│     └─► New public/private key created                       │
│                                                              │
│  2. Decrypt all .env files with OLD key                      │
│     └─► Temporary plaintext in memory                        │
│                                                              │
│  3. Re-encrypt all .env files with NEW key                   │
│     └─► Files updated with new encryption                    │
│                                                              │
│  4. Update .env.keys with new private key                    │
│     └─► Old key archived (optional)                          │
│                                                              │
│  5. Commit changes                                           │
│     └─► New encrypted files + updated .env.keys              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Configuration:**

```toml
# envdrift.toml
[keys]
rotation_reminder = "90d"    # Remind to rotate after 90 days
archive_old_keys = true      # Keep old keys in .env.keys.archive
```

### Key Backup & Restore

Securely backup and restore encryption keys.

```bash
# Backup keys to encrypted file
envdrift keys backup --output ~/secure/envdrift-backup.enc
# Prompts for encryption password

# Backup to cloud (AWS Secrets Manager)
envdrift keys backup --to aws --secret-name envdrift/myproject

# Restore from backup
envdrift keys restore --input ~/secure/envdrift-backup.enc

# Restore from cloud
envdrift keys restore --from aws --secret-name envdrift/myproject
```

**Backup format:**

```json
{
  "version": 1,
  "created": "2025-01-23T00:00:00Z",
  "project": "/path/to/project",
  "keys": {
    "default": {
      "public": "...",
      "private": "encrypted:..."
    },
    "production": {
      "public": "...",
      "private": "encrypted:..."
    }
  }
}
```

### Pre-commit Hook

Prevent committing unencrypted .env files.

```bash
# Install pre-commit hook
envdrift hooks install

# Or add to .pre-commit-config.yaml
repos:
  - repo: https://github.com/jainal09/envdrift
    rev: v1.0.0
    hooks:
      - id: envdrift-check
        name: Check .env files are encrypted
```

**Hook implementation:**

```python
# src/envdrift/hooks/pre_commit.py

def check_env_files_encrypted():
    """Pre-commit hook to verify all .env files are encrypted."""
    config = load_config()
    unencrypted = []

    for pattern in config.patterns:
        for env_file in glob.glob(pattern):
            if is_excluded(env_file, config.exclude):
                continue
            if not is_encrypted(env_file):
                unencrypted.append(env_file)

    if unencrypted:
        print("ERROR: Unencrypted .env files detected:")
        for f in unencrypted:
            print(f"  - {f}")
        print("\nRun 'envdrift lock' to encrypt them.")
        sys.exit(1)

    print("✓ All .env files are encrypted")
    sys.exit(0)
```

**What the hook checks:**

| Check | Description |
|-------|-------------|
| Encryption status | Verifies files have `encrypted:` values |
| Public key header | Checks for `DOTENV_PUBLIC_KEY` comment |
| Excluded files | Skips `.env.example`, `.env.sample`, etc. |
| New files | Catches newly added unencrypted files |

---

## Phase 3C: User Experience

### `envdrift doctor` Command

Diagnose common setup issues and provide fixes.

```bash
$ envdrift doctor

EnvDrift Health Check
======================

✓ envdrift CLI installed (v1.5.0)
✓ dotenvx available (v1.51.4)
✓ envdrift-agent installed (v1.2.0)
✗ envdrift-agent not running
  → Run: envdrift-agent start

✓ Project registered with agent
✓ envdrift.toml found
✗ .env.keys not in .gitignore
  → Add '.env.keys' to .gitignore

✓ Pre-commit hook installed
✗ Keys not backed up (last backup: never)
  → Run: envdrift keys backup

Summary: 2 issues found
```

**Checks performed:**

| Category | Check |
|----------|-------|
| Installation | CLI version, dotenvx available, agent binary |
| Agent | Running status, registered projects |
| Configuration | envdrift.toml exists, valid syntax |
| Security | .env.keys in .gitignore, keys backed up |
| Git | Pre-commit hook installed, no unencrypted files staged |

### Desktop Notifications

System-level notifications for encryption events (not just VS Code).

```bash
# Enable desktop notifications
envdrift config set notifications.desktop true

# Configure notification level
envdrift config set notifications.level info  # info, warn, error
```

**Implementation (Go agent):**

```go
// internal/notify/notify.go

type Notifier interface {
    Send(title, message string, level Level) error
}

// Platform-specific implementations
func NewNotifier() Notifier {
    switch runtime.GOOS {
    case "darwin":
        return &MacOSNotifier{}  // Uses osascript
    case "linux":
        return &LinuxNotifier{}  // Uses notify-send
    case "windows":
        return &WindowsNotifier{} // Uses toast notifications
    }
}
```

**Notification events:**

| Event | Level | Message |
|-------|-------|---------|
| File encrypted | Info | "Encrypted .env.production" |
| Encryption failed | Error | "Failed to encrypt .env: key not found" |
| Agent started | Info | "EnvDrift agent is now running" |
| Key rotation due | Warn | "Keys haven't been rotated in 90 days" |

### Edit Workflow (Temporary Decrypt)

Safely edit encrypted .env files with automatic re-encryption.

```bash
# Open .env in editor, auto re-encrypt on save
envdrift edit .env.production

# Edit with specific editor
envdrift edit .env.production --editor vim

# Edit without auto re-encrypt (manual lock needed)
envdrift edit .env.production --no-auto-lock
```

**Workflow:**

```text
┌──────────────────────────────────────────────────────────────┐
│                      Edit Workflow                            │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  $ envdrift edit .env.production                              │
│                                                               │
│  1. Decrypt .env.production to temp file                      │
│     └─► /tmp/envdrift-xxxxx/.env.production                   │
│                                                               │
│  2. Open temp file in $EDITOR                                 │
│     └─► User edits the file                                   │
│                                                               │
│  3. Wait for editor to close                                  │
│     └─► Detect file changes                                   │
│                                                               │
│  4. If changed, re-encrypt and update original                │
│     └─► .env.production now has new encrypted values          │
│                                                               │
│  5. Securely delete temp file                                 │
│     └─► shred/srm the decrypted content                       │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

**Security considerations:**

- Temp file created with `0600` permissions
- Temp directory has `0700` permissions
- File is securely deleted (overwritten) after editing
- Watchdog timer: auto-lock if editor open > 30 minutes
- Agent pauses watching during edit to prevent double-encryption

---

## Phase 3D: Observability

### Audit Logging

Track all encryption/decryption operations.

```bash
# View audit log
envdrift audit log

# Filter by date
envdrift audit log --since 2025-01-01

# Filter by action
envdrift audit log --action encrypt

# Export to JSON
envdrift audit log --format json > audit.json
```

**Log location:** `~/.envdrift/audit.log`

**Log format:**

```json
{
  "timestamp": "2025-01-23T10:30:00Z",
  "action": "encrypt",
  "file": "/Users/dev/myapp/.env.production",
  "project": "/Users/dev/myapp",
  "user": "dev",
  "hostname": "macbook.local",
  "key_id": "abc123...",
  "success": true,
  "duration_ms": 45
}
```

**Logged events:**

| Action | Description |
|--------|-------------|
| `encrypt` | File was encrypted |
| `decrypt` | File was decrypted (edit workflow) |
| `rotate` | Keys were rotated |
| `backup` | Keys were backed up |
| `restore` | Keys were restored |
| `agent_start` | Agent started |
| `agent_stop` | Agent stopped |

### Agent Metrics & Health Endpoint

Expose metrics for monitoring.

```bash
# Check agent health
envdrift-agent health

# Output:
{
  "status": "healthy",
  "uptime": "2d 5h 30m",
  "version": "1.2.0",
  "projects_watched": 3,
  "files_encrypted_today": 12,
  "last_encryption": "2025-01-23T10:30:00Z",
  "memory_mb": 15.2,
  "cpu_percent": 0.1
}
```

**Optional HTTP endpoint:**

```toml
# ~/.envdrift/agent.toml
[agent]
health_endpoint = "127.0.0.1:9847"  # localhost only
```

```bash
curl http://localhost:9847/health
curl http://localhost:9847/metrics  # Prometheus format
```

### Improved Error Messages

Context-aware error messages with troubleshooting hints.

**Before:**

```text
Error: encryption failed
```

**After:**

```text
Error: Failed to encrypt .env.production

Cause: Private key not found in .env.keys

This can happen when:
  1. The .env.keys file was not created (run 'envdrift init')
  2. The .env.keys file was accidentally deleted
  3. You're trying to encrypt a file from another project

To fix:
  → If this is a new project: envdrift init
  → If keys were lost: envdrift keys restore --from <backup>
  → If wrong project: cd /correct/project && envdrift lock

Documentation: https://envdrift.dev/docs/troubleshooting#key-not-found
```

---

## Phase 3E: Team Features

### Team Key Sharing Workflow

Securely share encryption keys with team members.

#### The Problem

When multiple developers work on a project:

- Each developer needs the private key to decrypt `.env` files
- `.env.keys` contains the private key and should NOT be committed
- How do team members get the key securely?

#### Solution: Key Distribution Strategies

##### Strategy 1: Secure Channel (Manual)

```bash
# Developer A (has the keys)
envdrift keys export --format base64
# Output: eyJwcml2YXRlIjoiLi4uIiwicHVibGljIjoiLi4uIn0=

# Share via secure channel (1Password, encrypted Slack, in-person)

# Developer B (needs the keys)
envdrift keys import eyJwcml2YXRlIjoiLi4uIiwicHVibGljIjoiLi4uIn0=
```

##### Strategy 2: Cloud Secret Manager

```bash
# Team lead stores keys in cloud
envdrift keys push --to aws --secret-name mycompany/myproject/envdrift-keys
envdrift keys push --to vault --path secret/myproject/envdrift-keys
envdrift keys push --to azure --vault-name mycompany-vault

# Team members pull keys
envdrift keys pull --from aws --secret-name mycompany/myproject/envdrift-keys
```

##### Strategy 3: Encrypted Key File in Repo

Store an encrypted version of the keys in the repository:

```bash
# Initialize team key sharing
envdrift team init

# This creates:
# - .envdrift-team.enc (encrypted team keys, safe to commit)
# - Team master password (share via secure channel)
```

```text
┌─────────────────────────────────────────────────────────────┐
│                 Team Key Distribution                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Repository contains:                                        │
│  ├── .env.production (encrypted with project key)            │
│  ├── .envdrift-team.enc (project key encrypted with          │
│  │                       team master password)               │
│  └── .env.keys (NOT committed, generated locally)            │
│                                                              │
│  New team member onboarding:                                 │
│  1. Clone repository                                         │
│  2. Get team master password from team lead (1Password, etc) │
│  3. Run: envdrift team unlock                                │
│  4. Enter master password → .env.keys is generated           │
│  5. Can now decrypt .env files                               │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### Team Commands

```bash
# Initialize team sharing for a project
envdrift team init
# Prompts for master password, creates .envdrift-team.enc

# Unlock keys using team master password
envdrift team unlock
# Prompts for password, creates local .env.keys

# Change team master password
envdrift team rotate-password

# Add a new environment's keys to team file
envdrift team add-env staging

# List team members who have accessed (audit)
envdrift team audit
```

#### Configuration

```toml
# envdrift.toml
[team]
enabled = true
key_file = ".envdrift-team.enc"
require_unlock = true  # Require 'envdrift team unlock' before decrypt
```

### Environment-Specific Keys

Different encryption keys for different environments (dev, staging, production).

#### Why Different Keys?

| Reason | Explanation |
|--------|-------------|
| Security isolation | Production secrets don't leak if dev keys are compromised |
| Access control | Not everyone needs production access |
| Compliance | Audit requirements may mandate separate keys |
| Key rotation | Rotate production keys without affecting dev |

#### File Structure

```text
myproject/
├── .env                    # Local development (shared key)
├── .env.staging            # Staging environment (staging key)
├── .env.production         # Production environment (production key)
├── .env.keys               # Contains ALL keys (or separate files)
└── envdrift.toml
```

#### Key Organization Options

##### Option A: Single .env.keys with multiple keys

```bash
# .env.keys
#/-------------------[DOTENV_PRIVATE_KEY_DEFAULT]-------------------/
DOTENV_PRIVATE_KEY="abc123..."

#/-------------------[DOTENV_PRIVATE_KEY_STAGING]-------------------/
DOTENV_PRIVATE_KEY_STAGING="def456..."

#/-------------------[DOTENV_PRIVATE_KEY_PRODUCTION]-------------------/
DOTENV_PRIVATE_KEY_PRODUCTION="ghi789..."
```

##### Option B: Separate key files per environment

```text
myproject/
├── .env.keys               # Default/development key
├── .env.keys.staging       # Staging key
├── .env.keys.production    # Production key (restricted access)
```

#### Commands

```bash
# Initialize with environment-specific keys
envdrift init --environments dev,staging,production

# Lock specific environment
envdrift lock .env.production

# Lock all environments
envdrift lock --all-envs

# Specify key explicitly
envdrift lock .env.staging --key-env staging
```

#### Configuration

```toml
# envdrift.toml
[environments]
default = "dev"

[environments.dev]
key_file = ".env.keys"
files = [".env", ".env.local", ".env.development"]

[environments.staging]
key_file = ".env.keys.staging"
files = [".env.staging"]
team_access = ["developers", "qa"]

[environments.production]
key_file = ".env.keys.production"
files = [".env.production"]
team_access = ["leads", "devops"]
require_mfa = true  # Future: require MFA to decrypt
```

#### Access Control Matrix

```text
┌─────────────────────────────────────────────────────────────┐
│              Environment Access Control                      │
├──────────────┬─────────┬─────────┬────────────┬─────────────┤
│ Role         │ Dev     │ Staging │ Production │ Key Mgmt    │
├──────────────┼─────────┼─────────┼────────────┼─────────────┤
│ Developer    │ ✓       │ ✓       │ ✗          │ ✗           │
│ Senior Dev   │ ✓       │ ✓       │ Read-only  │ ✗           │
│ Tech Lead    │ ✓       │ ✓       │ ✓          │ Rotate      │
│ DevOps       │ ✓       │ ✓       │ ✓          │ Full        │
├──────────────┴─────────┴─────────┴────────────┴─────────────┤
│ Note: Access controlled by who has which .env.keys file     │
└─────────────────────────────────────────────────────────────┘
```

#### Workflow Example

```bash
# DevOps sets up production for the first time
envdrift init --env production
envdrift keys push --env production --to aws \
  --secret-name mycompany/myapp/prod-keys

# Only authorized users can pull production keys
envdrift keys pull --env production --from aws \
  --secret-name mycompany/myapp/prod-keys

# Verify access
envdrift keys list
# Output:
# Environment    Key File               Status
# -----------    --------               ------
# dev            .env.keys              ✓ Available
# staging        .env.keys.staging      ✓ Available
# production     .env.keys.production   ✗ Not available (request access)
```

---

## Phase 3 Implementation Order

1. **Phase 3A** - Publishing (Marketplace, Homebrew, completions)
2. **Phase 3B** - Security (pre-commit hook, key rotation, backup)
3. **Phase 3C** - UX (doctor, notifications, edit workflow)
4. **Phase 3D** - Observability (audit, metrics, errors)
5. **Phase 3E** - Team (key sharing, environment keys)

---

## Future Considerations

Potential Phase 4 features (not yet planned):

- **Secret scanning** - Detect accidentally committed secrets
- **CI/CD integration** - Decrypt in pipelines securely
- **Secret versioning** - Track changes to secrets over time
- **Expiring secrets** - Auto-rotate secrets after TTL
- **Hardware key support** - YubiKey/HSM for key storage
