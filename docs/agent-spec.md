# EnvDrift Agent - Phase 2 Specification

This document outlines future improvements for the envdrift-agent and VS Code extension.

## Implementation Status

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 2A | Configuration Improvements (CLI commands, projects.json, [guardian] section) | ✅ Done |
| Phase 2B | CLI Install Command (`envdrift install agent`) | ✅ Done |
| Phase 2C | Build Pipelines (agent + VS Code release workflows) | ✅ Done |
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

1. Detect platform (macOS/Linux/Windows + arch: amd64, arm64, 386)
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

## Completed Features

The following features have been implemented:

- ✅ Config merge (guardian → envdrift.toml) - Phase 2A
- ✅ Project registration commands (`envdrift agent register/unregister/list/status`) - Phase 2A
- ✅ `envdrift install agent` command with `check` subcommand - Phase 2B
- ✅ Agent release workflow (5 platforms) - Phase 2C
- ✅ VS Code extension release workflow with marketplace publishing - Phase 2C

## Not Implementing Now

These features are deferred to future phases:

- ❌ Per-project watching (Phase 2D)
- ❌ VS Code agent status indicator (Phase 2E)
