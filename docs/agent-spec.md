# EnvDrift Agent - Phase 2 Specification

This document outlines future improvements for the envdrift-agent and VS Code extension.

## Implementation Status

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 2A | Configuration Improvements (CLI commands, projects.json, [guardian] section) | ✅ Completed |
| Phase 2B | CLI Install Command (`envdrift install agent`) | ✅ In Progress |
| Phase 2C | Build Pipelines (agent + vscode release workflows) | ❌ Not Started |
| Phase 2D | Agent Improvements (per-project watching) | ❌ Not Started |
| Phase 2E | VS Code Agent Status Indicator | ❌ Not Started |

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

## Phase 2D: Agent Improvements

### Watch Strategy

Instead of watching entire directories, the agent:

1. Only watches registered project roots
2. Uses `envdrift.toml` from each project for patterns/excludes
3. Respects project-specific settings

### Architecture

```text
┌─────────────────────────────────────────┐
│           ~/.envdrift/agent.toml        │
│  registered_projects = [A, B, C]        │
└─────────────────┬───────────────────────┘
                  │
    ┌─────────────┼─────────────┐
    ▼             ▼             ▼
┌───────┐    ┌───────┐    ┌───────┐
│ Proj A│    │ Proj B│    │ Proj C│
│ toml  │    │ toml  │    │ toml  │
└───┬───┘    └───┬───┘    └───┬───┘
    │            │            │
    └────────────┼────────────┘
                 ▼
         ┌─────────────┐
         │ Guardian    │
         │ (per-proj   │
         │  settings)  │
         └─────────────┘
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

## Implementation Order

1. **Phase 2A** - Config improvements (merge configs, project registration)
2. **Phase 2B** - CLI install command (download from releases)
3. **Phase 2C** - Build pipelines (auto-release on tag)
4. **Phase 2D** - Agent improvements (per-project watching)
5. **Phase 2E** - VS Code agent status indicator

---

## Not Implementing Now

These features are deferred to a future branch:

- ❌ Release workflows
- ❌ Per-project watching
- ❌ VS Code agent status indicator

Current branch focuses on:

- ✅ CLI install command (in progress)
- ✅ Config merge (guardian → envdrift.toml)
- ✅ Project registration commands
- ✅ Basic agent functionality
- ✅ VS Code extension
- ✅ Documentation
