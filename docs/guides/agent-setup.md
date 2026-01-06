# EnvDrift Agent Setup Guide

The EnvDrift Agent is a background daemon that automatically encrypts `.env` files
when they're not in active use. This guide covers installation, configuration,
and troubleshooting.

## Overview

The agent runs silently in the background and:

- **Watches** directories for `.env` file modifications
- **Detects** when files are idle (not being edited)
- **Verifies** files aren't open by other processes
- **Encrypts** using `envdrift lock` (respects your `envdrift.toml`)
- **Notifies** you via desktop notifications (optional)

## Prerequisites

Before installing the agent, ensure you have:

### 1. envdrift installed

```bash
pip install envdrift
```

### 2. dotenvx (used internally by envdrift)

```bash
# macOS
brew install dotenvx/brew/dotenvx

# Any platform
npm install -g @dotenvx/dotenvx
```

## Installation

### From Binary (Recommended)

Download pre-built binaries from [Releases](https://github.com/jainal09/envdrift/releases):

```bash
# macOS / Linux
chmod +x envdrift-agent-*
./envdrift-agent-* install

# Windows (PowerShell as Admin)
.\envdrift-agent-windows-amd64.exe install
```

### From Source

```bash
cd envdrift-agent
make build
./bin/envdrift-agent install
```

## Commands

| Command | Description |
|---------|-------------|
| `envdrift-agent install` | Install as system service (auto-starts on boot) |
| `envdrift-agent uninstall` | Remove from system startup |
| `envdrift-agent status` | Check if agent is installed and running |
| `envdrift-agent start` | Run in foreground (for debugging) |
| `envdrift-agent stop` | Stop the running agent |
| `envdrift-agent config` | Show/create configuration file |
| `envdrift-agent version` | Print version information |

## Configuration

The agent uses a TOML configuration file at `~/.envdrift/guardian.toml`:

```toml
[guardian]
enabled = true
idle_timeout = "5m"     # Encrypt after 5 minutes of no changes
patterns = [".env*"]    # File patterns to watch
exclude = [".env.example", ".env.sample", ".env.keys"]
notify = true           # Show desktop notifications

[directories]
watch = ["~/projects", "~/code"]  # Directories to monitor
recursive = true                   # Watch subdirectories
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `guardian.enabled` | bool | `true` | Enable/disable the agent |
| `guardian.idle_timeout` | duration | `"5m"` | Time to wait before encrypting |
| `guardian.patterns` | string[] | `[".env*"]` | Glob patterns for files to watch |
| `guardian.exclude` | string[] | `[".env.example", ...]` | Patterns to exclude |
| `guardian.notify` | bool | `true` | Show desktop notifications |
| `directories.watch` | string[] | `["~"]` | Directories to monitor |
| `directories.recursive` | bool | `true` | Watch subdirectories |

### Duration Format

The `idle_timeout` accepts Go duration strings:

- `"30s"` - 30 seconds
- `"5m"` - 5 minutes
- `"1h"` - 1 hour
- `"1h30m"` - 1 hour 30 minutes

## How It Works

```text
                    ┌─────────────────┐
                    │ File System     │
                    │ (.env files)    │
                    └────────┬────────┘
                             │ fsnotify events
                             ▼
                    ┌─────────────────┐
                    │ Watcher         │
                    │ (pattern match) │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Guardian        │
                    │ (idle tracking) │
                    └────────┬────────┘
                             │ idle_timeout expired?
                             ▼
                    ┌─────────────────┐
                    │ Lock Check      │
                    │ (file in use?)  │
                    └────────┬────────┘
                             │ not locked?
                             ▼
                    ┌─────────────────┐
                    │ Encrypt         │
                    │ (envdrift lock) │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Notify          │
                    │ (desktop alert) │
                    └─────────────────┘
```

1. **Watcher** - Uses `fsnotify` to detect file changes matching patterns
2. **Guardian** - Tracks last modification time, checks for idle timeout
3. **Lock Check** - Verifies file isn't open (`lsof` on Unix, `handle.exe` on Windows)
4. **Encrypt** - Calls `envdrift lock` which respects your `envdrift.toml`
5. **Notify** - Shows desktop notification if enabled

## Platform Details

### macOS

- **Auto-start**: LaunchAgent (`~/Library/LaunchAgents/com.envdrift.guardian.plist`)
- **Lock detection**: `lsof`
- **Logs**: `~/Library/Logs/envdrift-agent.log`

### Linux

- **Auto-start**: systemd user service (`~/.config/systemd/user/envdrift-agent.service`)
- **Lock detection**: `lsof`
- **Logs**: `journalctl --user -u envdrift-agent`

### Windows

- **Auto-start**: Task Scheduler
- **Lock detection**: `handle.exe` (Sysinternals) or PowerShell fallback
- **Logs**: `%USERPROFILE%\AppData\Local\envdrift\agent.log`

## Integration with envdrift.toml

The agent calls `envdrift lock`, which means it respects all settings in your project's `envdrift.toml`:

- **Partial encryption** - Only secrets are encrypted
- **Vault integration** - Keys are pushed to vault if configured
- **Ephemeral keys** - Keys never touch disk if enabled

## Troubleshooting

### Agent not starting

```bash
# Check status
envdrift-agent status

# Run in foreground to see errors
envdrift-agent start
```

### Files not being encrypted

1. **Check patterns match**: Ensure file matches `patterns` in config
2. **Check exclusions**: File might be in `exclude` list
3. **Check idle timeout**: File might still be within timeout
4. **Check lock detection**: File might still be open

```bash
# See what files are being watched
envdrift-agent start  # Watch the output
```

### envdrift not found

```bash
# Ensure envdrift is installed and in PATH
which envdrift
pip install envdrift

# Or try python module directly
python -m envdrift --version
```

### Permission issues

```bash
# macOS/Linux: Check the agent can access watched directories
ls -la ~/projects

# Windows: Run as Administrator for initial install
```

## Uninstalling

```bash
# Remove from system startup
envdrift-agent uninstall

# Delete configuration
rm -rf ~/.envdrift/
```

## See Also

- [VS Code Extension Guide](./vscode-extension.md)
- [Encryption Guide](./encryption.md)
- [Vault Sync Guide](./vault-sync.md)
- [Configuration Reference](../reference/configuration.md)
