# EnvDrift Agent - Phase 2 Specification

This document outlines future improvements for the envdrift-agent and VS Code extension.

## Current Issues

### 1. Aggressive Default Watching
- **Problem**: Default behavior watches `~` recursively, causing CPU spikes
- **Solution**: Require explicit directory registration, no auto-watch

### 2. Separate Config Files
- **Problem**: `guardian.toml` is separate from `envdrift.toml`
- **Solution**: Add `[guardian]` section to `envdrift.toml`

### 3. Config Discovery
- **Problem**: Agent doesn't know where `envdrift.toml` files are located
- **Solution**: User registers projects with the agent

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

```
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

## Implementation Order

1. **Phase 2A** - Config improvements (merge configs, project registration)
2. **Phase 2B** - CLI install command (download from releases)
3. **Phase 2C** - Build pipelines (auto-release on tag)
4. **Phase 2D** - Agent improvements (per-project watching)

---

## Not Implementing Now

These features are deferred to a future branch:
- ❌ Config merge (guardian → envdrift.toml)
- ❌ Project registration commands
- ❌ `envdrift install agent` command
- ❌ Release workflows
- ❌ Per-project watching

Current branch focuses on:
- ✅ Basic agent functionality
- ✅ VS Code extension
- ✅ Documentation
