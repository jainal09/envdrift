# EnvDrift VS Code Extension

Automatically encrypt `.env` files when you close them in VS Code.

## Features

- 🔐 **Auto-Encryption** - Encrypts `.env` files when closed
- 📊 **Status Bar** - Shows encryption status with toggle
- ⚙️ **Configurable** - Custom patterns and exclusions
- 🔔 **Notifications** - Optional success/failure alerts
- 🔗 **envdrift Integration** - Respects your `envdrift.toml` settings

## Requirements

[envdrift](https://github.com/jainal09/envdrift) must be installed:

```bash
# macOS / Linux
curl -sSL https://raw.githubusercontent.com/jainal09/envdrift/main/install.sh | sh

# Windows (PowerShell)
irm https://raw.githubusercontent.com/jainal09/envdrift/main/install.ps1 | iex

# Or download and inspect first:
# curl -sSL https://raw.githubusercontent.com/jainal09/envdrift/main/install.sh -o install.sh
# less install.sh && sh install.sh
```

## Quick Start

1. Install the extension
2. Open a `.env` file
3. Make changes and close the file
4. ✅ File is automatically encrypted!

## Extension Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `envdrift.enabled` | `true` | Enable auto-encryption |
| `envdrift.patterns` | `[".env*"]` | File patterns to watch |
| `envdrift.exclude` | `[".env.example", ...]` | Patterns to exclude |
| `envdrift.showNotifications` | `true` | Show notifications |

## Commands

- **EnvDrift: Enable Auto-Encryption** - Turn on auto-encryption
- **EnvDrift: Disable Auto-Encryption** - Turn off auto-encryption
- **EnvDrift: Encrypt Current File** - Manually encrypt open file
- **EnvDrift: Show Status** - Display current settings
- **EnvDrift: Show Logs** - Open the EnvDrift output channel

## Status Bar

| Icon | Meaning |
|------|---------|
| 🔐 | Auto-encryption **enabled** - click to disable |
| 🔓 | Auto-encryption **disabled** - click to enable |

## How It Works

1. Open a `.env` file in VS Code
2. Make your changes
3. Close the file (or close VS Code)
4. EnvDrift calls `envdrift encrypt <file>` to encrypt it
5. Your `envdrift.toml` `[encryption]` settings are respected (backend choice, smart encryption)

## Documentation

📖 **See the [comprehensive guide](https://github.com/jainal09/envdrift/blob/main/docs/guides/vscode-extension.md) for:**

- Detailed configuration options
- Troubleshooting
- Integration with envdrift.toml
- Security considerations
- Comparison with background agent

## License

MIT
