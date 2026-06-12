# EnvDrift Agent

A lightweight cross-platform background agent that watches `.env` files and automatically encrypts them when not in active use.

## Features

- 🔒 **Auto-encryption** - Encrypts `.env` files after configurable idle timeout
- 👁️ **File watching** - Monitors directories for `.env` file changes
- 🔐 **Lock detection** - Won't encrypt files that are still open
- 🖥️ **Desktop notifications** - Optional alerts when files are encrypted
- 🚀 **Runs at startup** - Install once and forget
- 🌍 **Cross-platform** - macOS, Linux, and Windows support

## Installation

### From Binary Release

Download the latest release for your platform from [Releases](https://github.com/jainal09/envdrift/releases).

```bash
# macOS / Linux
chmod +x envdrift-agent-*
./envdrift-agent-* install

# Windows
.\envdrift-agent-windows-amd64.exe install
```

### From Source

```bash
cd envdrift-agent
make build
./bin/envdrift-agent install
```

## Prerequisites

This agent uses [envdrift](https://github.com/jainal09/envdrift) for encryption:

```bash
pip install envdrift
```

envdrift requires [dotenvx](https://dotenvx.com/) which will be used internally:

```bash
# macOS
brew install dotenvx/brew/dotenvx

# npm (any platform)
npm install -g @dotenvx/dotenvx
```

## Usage

### Install as System Service

```bash
# Install and start on system boot
envdrift-agent install

# Check status
envdrift-agent status

# Remove from startup
envdrift-agent uninstall
```

### Run in Foreground (Debug)

```bash
envdrift-agent start
```

### Configuration

```bash
# Show/create config file
envdrift-agent config
```

Config file location: `~/.envdrift/guardian.toml`

```toml
[guardian]
enabled = true
idle_timeout = "5m"           # Encrypt after 5 minutes idle
patterns = [".env*"]          # Files to watch
exclude = [".env.example", ".env.sample", ".env.keys"]
notify = true                 # Desktop notifications

[directories]
watch = ["~/projects"]        # Directories to monitor
recursive = true
```

## How It Works

1. **Watches** directories for `.env*` file modifications
2. **Tracks** last modification time for each file
3. **Checks** if file is idle (not modified for `idle_timeout`)
4. **Verifies** file is not open by another process
5. **Encrypts** using `envdrift encrypt <file>` (respects `envdrift.toml`)
6. **Notifies** (optional) via desktop notification

Project-level `vault.sync.mappings.env_file` names are added to the effective
watch patterns when `[guardian] enabled = true`, so custom dotenv filenames such
as `postgresql.env` can be encrypted automatically.

> 📖 **See the [comprehensive setup guide](../docs/guides/agent-setup.md) for detailed configuration and troubleshooting.**

## Platform-Specific Details

| Platform | Auto-Start Method | Lock Detection |
|----------|-------------------|----------------|
| macOS | LaunchAgent | `lsof` |
| Linux | systemd user service | `lsof` |
| Windows | Task Scheduler | `handle.exe` / PowerShell |

## Development

### Build

```bash
make build           # Build for current platform
make build-all       # Cross-compile for all platforms
make test            # Run tests
make lint            # Run linter
```

### Project Structure

```text
envdrift-agent/
├── cmd/envdrift-agent/     # Entry point
├── internal/
│   ├── cmd/                # CLI commands
│   ├── config/             # Configuration
│   ├── daemon/             # System service installer
│   ├── encrypt/            # dotenvx integration
│   ├── guardian/           # Core orchestrator
│   ├── lockcheck/          # File-in-use detection
│   ├── notify/             # Desktop notifications
│   └── watcher/            # File system watcher
├── go.mod
└── Makefile
```

## License

MIT License - see [LICENSE](../LICENSE) for details.
