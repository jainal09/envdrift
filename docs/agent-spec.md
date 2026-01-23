# EnvDrift Agent - Phase 2 Specification

This document outlines future improvements for the envdrift-agent and VS Code extension.

## Implementation Status

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 2A | Configuration Improvements (CLI commands, projects.json, [guardian] section) | ✅ Done |
| Phase 2B | CLI Install Command (`envdrift install agent`) | ✅ Done |
| Phase 2C | Build Pipelines (agent + vscode release workflows) | ✅ Done |
| Phase 2D | Agent Improvements (per-project watching) | ✅ Done |
| Phase 2E | VS Code Agent Status Indicator | ❌ Not Started |
| Phase 2F | CI/Testing (VS Code lint/tests, Go E2E integration tests) | ❌ Not Started |

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

## Phase 2B: CLI Install Command

### `envdrift install agent`

New command in Python CLI to install the Go background agent:

```bash
envdrift install agent
```

**Behavior:**

1. Detect platform (macOS/Linux/Windows + arch)
2. Download latest binary from GitHub releases
3. Install to standard location (`/usr/local/bin`, etc.)
4. Run `envdrift-agent install` to set up auto-start
5. Register current directory if has `envdrift.toml`

### Implementation

```python
# src/envdrift/cli_commands/install.py

@cli.command()
def install_agent():
    """Install the envdrift background agent."""
    platform = detect_platform()  # darwin-arm64, linux-amd64, etc.
    
    # Download from GitHub releases
    url = f"https://github.com/jainal09/envdrift/releases/latest/download/envdrift-agent-{platform}"
    
    # Install binary
    install_path = get_install_path()  # /usr/local/bin or equivalent
    download_and_install(url, install_path)
    
    # Run agent install
    subprocess.run([install_path, "install"])
    
    # Register current project
    if Path("envdrift.toml").exists():
        subprocess.run([install_path, "register", "."])
```

---

## Phase 2C: Build Pipelines

### Agent Release Workflow

```yaml
# .github/workflows/agent-release.yml
name: Release Agent

on:
  push:
    tags:
      - 'agent-v*'
    paths:
      - 'envdrift-agent/**'

jobs:
  build:
    strategy:
      matrix:
        include:
          - os: macos-latest
            goos: darwin
            goarch: arm64
          - os: macos-latest
            goos: darwin
            goarch: amd64
          - os: ubuntu-latest
            goos: linux
            goarch: amd64
          - os: windows-latest
            goos: windows
            goarch: amd64
    
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - run: |
          cd envdrift-agent
          GOOS=${{ matrix.goos }} GOARCH=${{ matrix.goarch }} go build -o bin/envdrift-agent-${{ matrix.goos }}-${{ matrix.goarch }}
      - uses: softprops/action-gh-release@v1
        with:
          files: envdrift-agent/bin/*
```

### VS Code Extension Release Workflow

```yaml
# .github/workflows/vscode-release.yml
name: Release VS Code Extension

on:
  push:
    tags:
      - 'vscode-v*'
    paths:
      - 'envdrift-vscode/**'

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: |
          cd envdrift-vscode
          npm install
          npm run compile
          npx vsce package
      - uses: softprops/action-gh-release@v1
        with:
          files: envdrift-vscode/*.vsix
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
| Running | ⚡ | 🟢 Green | Agent is running and healthy |
| Stopped | ⭕ | 🔴 Red | Agent is not running |
| Error | ⚠️ | 🟡 Yellow | Agent has issues |

### Implementation

```typescript
// src/agentStatus.ts

async function checkAgentStatus(): Promise<'running' | 'stopped' | 'error'> {
    try {
        // Check if agent process is running
        const result = await execCommand('envdrift-agent status');
        if (result.includes('running')) return 'running';
        return 'stopped';
    } catch {
        return 'error';
    }
}

// Update status bar every 30 seconds
setInterval(updateAgentStatusBar, 30000);
```

### Status Bar Click Actions

- **If running**: Show info message with agent version
- **If stopped**: Offer to start agent or install it
- **If error**: Show error details and troubleshooting link

### Communication with Agent

Extension can read agent status from:

1. **Process check**: `envdrift-agent status` command
2. **Status file**: `~/.envdrift/agent.status` (JSON)
3. **Health endpoint**: Future HTTP API (optional)

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

## Implementation Order

1. **Phase 2A** - Config improvements (merge configs, project registration)
2. **Phase 2B** - CLI install command (download from releases)
3. **Phase 2C** - Build pipelines (auto-release on tag)
4. **Phase 2D** - Agent improvements (per-project watching)
5. **Phase 2E** - VS Code agent status indicator
6. **Phase 2F** - CI/Testing improvements (VS Code lint/tests, Go E2E tests)

---

## Completed Features

The following features have been implemented:

- ✅ Config merge (guardian → envdrift.toml) - Phase 2A
- ✅ Project registration commands (`envdrift agent register/unregister/list/status`) - Phase 2A
- ✅ `envdrift install agent` command with `check` subcommand - Phase 2B
- ✅ Agent release workflow (5 platforms) - Phase 2C
- ✅ VS Code extension release workflow with marketplace publishing - Phase 2C
- ✅ Per-project watching with individual configs - Phase 2D
- ✅ Dynamic registry watching (hot reload on project add/remove) - Phase 2D

## Not Implementing Now

These features are deferred to future phases:

- ❌ VS Code agent status indicator (Phase 2E)
- ❌ VS Code extension CI (lint, unit tests, E2E tests) (Phase 2F)
- ❌ Go agent E2E integration tests with real encryption (Phase 2F)
