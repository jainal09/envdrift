# EnvDrift VS Code Extension

Automatically encrypt `.env` files when you close them in VS Code.

## Features

- 🔐 **Auto-Encryption** - Encrypts `.env` files when closed
- 📊 **Status Bar** - Shows encryption status with toggle
- ⚙️ **Configurable** - Custom patterns, exclusions, and dotenvx path
- 🔔 **Notifications** - Optional success/failure alerts

## Requirements

- [dotenvx](https://dotenvx.com/) must be installed:
  ```bash
  npm install -g @dotenvx/dotenvx
  ```

## Extension Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `envdrift.enabled` | `true` | Enable auto-encryption |
| `envdrift.patterns` | `[".env*"]` | File patterns to watch |
| `envdrift.exclude` | `[".env.example", ...]` | Patterns to exclude |
| `envdrift.dotenvxPath` | `""` | Custom dotenvx path |
| `envdrift.showNotifications` | `true` | Show notifications |

## Commands

- **EnvDrift: Enable Auto-Encryption** - Turn on auto-encryption
- **EnvDrift: Disable Auto-Encryption** - Turn off auto-encryption
- **EnvDrift: Encrypt Current File** - Manually encrypt open file
- **EnvDrift: Show Status** - Display current settings

## How It Works

1. Open a `.env` file in VS Code
2. Make your changes
3. Close the file (or close VS Code)
4. EnvDrift automatically encrypts it using dotenvx

## Status Bar

The status bar shows:
- 🔐 **Lock icon** - Auto-encryption is enabled
- 🔓 **Unlock icon** - Auto-encryption is disabled

Click the icon to toggle!

## License

MIT
