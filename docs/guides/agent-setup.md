# EnvDrift Agent Setup Guide

The EnvDrift Agent is a background daemon that automatically encrypts `.env` files
when they're not in active use. This guide covers installation, configuration,
and troubleshooting.

## Overview

The agent runs silently in the background and:

- **Watches** directories for `.env` file modifications
- **Detects** when files are idle (not being edited)
- **Verifies** files aren't open by other processes
- **Encrypts** using `envdrift encrypt <file>` (respects your `envdrift.toml`)
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
| `envdrift-agent stop` | Stop the running agent (stays installed; restarts on next boot) |
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
watch = ["~/projects", "~/code"]  # Display only — see note below
recursive = true                   # Watch subdirectories
```

!!! note "`[directories].watch` does not select what the agent watches"
    The `[directories].watch` value is loaded into the config but is only echoed
    back by `envdrift-agent config` — the agent never uses it to add watched
    directories. To choose what gets watched, register projects with
    `envdrift agent register` (see
    [Selecting which projects to watch](#selecting-which-projects-to-watch)).

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `guardian.enabled` | bool | `true` | Enable/disable the agent |
| `guardian.idle_timeout` | duration | `"5m"` | Time to wait before encrypting |
| `guardian.patterns` | string[] | `[".env*"]` | Glob patterns for files to watch |
| `guardian.exclude` | string[] | `[".env.example", ...]` | Patterns to exclude |
| `guardian.notify` | bool | `true` | Show desktop notifications |
| `directories.watch` | string[] | `["~/projects"]` | Directories to monitor (display only — not used to select watched directories; see [Selecting which projects to watch](#selecting-which-projects-to-watch)) |
| `directories.recursive` | bool | `true` | Watch subdirectories |

When a project has `[guardian] enabled = true`, custom
`[vault.sync].mappings.env_file` names are added to the effective watch patterns
automatically. This lets the agent react to files such as `postgresql.env` even
though the global default is `.env*`.

### Duration Format

The `idle_timeout` accepts duration strings:

- `"30s"` - 30 seconds
- `"5m"` - 5 minutes
- `"1h"` - 1 hour
- `"2d"` - 2 days
- `"1h30m"` - 1 hour 30 minutes (any Go duration string works)

Configs written by older agent versions stored `idle_timeout` as a raw
nanosecond integer; those files still load, and the agent rewrites the value
in the documented string form the next time it saves the config.

## Selecting which projects to watch

The agent does **not** scan the `[directories].watch` paths from `guardian.toml`.
Instead, it watches the projects listed in the registry at
`~/.envdrift/projects.json`, which you populate with `envdrift agent register`.

Register the project you want the agent to watch (defaults to the current
directory):

```bash
envdrift agent register
```

```text
✓ Registered project: /Users/you/projects/my-app

⚠ Guardian is not enabled in envdrift.toml
  Add this to your envdrift.toml to enable auto-encryption:

  [guardian]
  enabled = true
```

Registration alone is not enough: the agent only watches a project whose
config has the guardian turned on. The per-project default is
`enabled = false`, so add the `[guardian]` section shown above to each project
you want auto-encrypted.

The agent discovers a project's config the same way the CLI does: it walks up
from the project directory toward the filesystem root and uses the first
`envdrift.toml` it finds, or the first `pyproject.toml` containing a
`[tool.envdrift]` table (use `[tool.envdrift.guardian]` for the guardian
section there). A project registered via `pyproject.toml` or a parent-dir
`envdrift.toml` is therefore watched too.

List the registered projects at any time:

```bash
envdrift agent list
```

```text
                      Registered Projects
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Path                        ┃ Registered       ┃ Has Config ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ /Users/you/projects/my-app  │ 2026-06-03 16:05 │ ✓          │
└─────────────────────────────┴──────────────────┴────────────┘

Registry: /Users/you/.envdrift/projects.json
```

Use `envdrift agent unregister [PATH]` to stop watching a project and
`envdrift agent status` to see the agent state and registered project count.

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
                    ┌─────────────────────┐
                    │ Encrypt             │
                    │ (envdrift encrypt)  │
                    └────────┬────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Notify          │
                    │ (desktop alert) │
                    └─────────────────┘
```

1. **Watcher** - Uses `fsnotify` to detect file changes matching patterns
2. **Guardian** - Tracks last modification time, checks for idle timeout. A file
   counts as encrypted only when **every** value is ciphertext — a plaintext
   secret added to an already-encrypted file is re-encrypted, not dropped
3. **Lock Check** - Verifies file isn't open by **another** process (`lsof` on
   Unix, `handle.exe` on Windows); the agent's own watcher handles are ignored
4. **Encrypt** - Calls `envdrift encrypt <file>` which respects your `envdrift.toml`
5. **Notify** - Shows desktop notification if enabled

## Platform Details

### macOS

- **Auto-start**: LaunchAgent (`~/Library/LaunchAgents/com.envdrift.guardian.plist`)
- **Lock detection**: `lsof`
- **Logs**: `/tmp/envdrift-agent.log` (stdout) and `/tmp/envdrift-agent.err` (stderr)

### Linux

- **Auto-start**: systemd user service (`~/.config/systemd/user/envdrift-guardian.service`)
- **Lock detection**: `lsof`
- **Logs**: `journalctl --user -u envdrift-guardian`

### Windows

- **Auto-start**: Task Scheduler (scheduled task `EnvDriftGuardian`)
- **Lock detection**: `handle.exe` (Sysinternals) or PowerShell fallback
- **Logs**: not captured to a file — the scheduled task runs without stdout/stderr redirection

## Integration with envdrift.toml

The agent calls `envdrift encrypt <file>`, which means it respects all settings in your project's `envdrift.toml`:

- **Partial encryption** - Only secrets are encrypted
- **Vault integration** - Keys are pushed to vault if configured
- **Ephemeral keys** - Keys never touch disk if enabled
- **Custom env filenames** - `vault.sync.mappings.env_file` names are watched
  automatically when project guardian config is enabled

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
- [Env File Sync Guide](./env-file-sync.md)
- [Configuration Reference](../reference/configuration.md)
