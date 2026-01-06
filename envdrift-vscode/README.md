# EnvDrift VS Code Extension

Automatically encrypt `.env` files when you close them in VS Code.

## Features

- 🔐 **Auto-Encryption** - Encrypts `.env` files when closed
- 📊 **Status Bar** - Shows encryption status with toggle
- ⚙️ **Configurable** - Custom patterns and exclusions
- 🔔 **Notifications** - Optional success/failure alerts

## Requirements

[envdrift](https://github.com/jainal09/envdrift) must be installed:

```bash
pip install envdrift
```

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

## How It Works

1. Open a `.env` file in VS Code
2. Make your changes
3. Close the file (or close VS Code)
4. EnvDrift automatically encrypts it using `envdrift lock`

## Status Bar

The status bar shows:

- 🔐 **Lock icon** - Auto-encryption is enabled
- 🔓 **Unlock icon** - Auto-encryption is disabled

Click the icon to toggle!

## License

MIT
