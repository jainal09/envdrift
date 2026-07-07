# EnvDrift VS Code Extension Guide

The EnvDrift VS Code Extension automatically encrypts `.env` files when you close them. This guide covers installation, configuration, and usage.

## Overview

The extension provides:

- **Auto-encryption** - Encrypts `.env` files when you close them
- **Status bar indicator** - Shows encryption status at a glance
- **Manual encryption** - Command to encrypt on demand
- **Configurable patterns** - Choose which files to watch
- **Integration with envdrift** - Respects your `envdrift.toml` settings

## Prerequisites

Before using the extension, ensure you have:

### 1. VS Code version 1.85.0 or later

### 2. envdrift installed

```bash
# macOS / Linux
curl -sSL https://raw.githubusercontent.com/jainal09/envdrift/main/install.sh | sh

# Windows (PowerShell)
irm https://raw.githubusercontent.com/jainal09/envdrift/main/install.ps1 | iex
```

Alternatively, install from PyPI with `pip install envdrift`.

### 3. dotenvx (used internally by envdrift)

```bash
npm install -g @dotenvx/dotenvx
```

## Installation

### From VS Code Marketplace

1. Open VS Code
2. Go to Extensions (`Cmd+Shift+X` / `Ctrl+Shift+X`)
3. Search for "EnvDrift"
4. Click Install

### From VSIX

1. Download the `.vsix` file from [Releases](https://github.com/jainal09/envdrift/releases)
2. In VS Code: `Extensions > ... > Install from VSIX...`

### For Development

```bash
cd envdrift-vscode
npm install
npm run compile
# Press F5 in VS Code to launch Extension Development Host
```

## Configuration

Access settings via `Code > Preferences > Settings > Extensions > EnvDrift`

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `envdrift.enabled` | boolean | `true` | Enable auto-encryption |
| `envdrift.patterns` | string[] | `[".env*"]` | File patterns to watch |
| `envdrift.exclude` | string[] | `[".env.example", ".env.sample", ".env.keys"]` | Files to exclude |
| `envdrift.showNotifications` | boolean | `true` | Show encryption notifications |

### Example settings.json

```json
{
  "envdrift.enabled": true,
  "envdrift.patterns": [".env*", "*.env", "postgresql.env"],
  "envdrift.exclude": [
    ".env.example",
    ".env.sample", 
    ".env.keys",
    ".env.template"
  ],
  "envdrift.showNotifications": true
}
```

## Commands

Access via Command Palette (`Cmd+Shift+P` / `Ctrl+Shift+P`):

| Command | Description |
|---------|-------------|
| `EnvDrift: Enable Auto-Encryption` | Turn on auto-encryption |
| `EnvDrift: Disable Auto-Encryption` | Turn off auto-encryption |
| `EnvDrift: Encrypt Current File` | Manually encrypt the active file |
| `EnvDrift: Show Status` | Display current settings and status |
| `EnvDrift: Show Logs` | Open the EnvDrift output channel |
| `EnvDrift: Start Background Agent` | Start the envdrift background agent |
| `EnvDrift: Stop Background Agent` | Stop the envdrift background agent |
| `EnvDrift: Refresh Agent Status` | Re-check the agent status |

## How It Works

```text
┌─────────────────────────────────────────────────────┐
│                    VS Code                          │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌─────────────┐      ┌─────────────────────────┐   │
│  │ .env file    │      │ EnvDrift Extension      │   │
│  │ opened      │─────▶│                         │   │
│  └─────────────┘      │  1. File Close Listener │   │
│                       │  2. Pattern Matching    │   │
│  ┌─────────────┐      │  3. Encryption Check    │   │
│  │ File closed │─────▶│  4. envdrift encrypt    │   │
│  └─────────────┘      │  5. Notification         │   │
│                       └─────────────────────────┘   │
│                                                     │
│  ┌─────────────────────────────────────────────┐    │
│  │ Status Bar:  $(lock) EnvDrift               │    │
│  └─────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
```

1. **File Close Listener** - Detects when configured env file patterns are closed
2. **Pattern Matching** - Checks if file matches configured patterns
3. **Encryption Check** - Verifies file isn't already encrypted
4. **envdrift encrypt** - Calls `envdrift encrypt <file>` and verifies the file
   really ends up encrypted before reporting success
5. **Notification** - Shows success/failure message (also logged to the
   EnvDrift output channel)

## Status Bar

The extension adds a status bar item at the bottom of VS Code:

| Icon | Meaning |
|------|---------|
| `$(lock)` (closed padlock) | Auto-encryption **enabled** |
| `$(unlock)` (open padlock, warning background) | Auto-encryption **disabled** |

**Click the icon to toggle auto-encryption on/off.**

## Integration with envdrift.toml

The extension calls `envdrift encrypt <file>` on the closed file, which
respects the `[encryption]` settings in your project's `envdrift.toml`:

```toml
# envdrift.toml in your project root
[encryption]
backend = "dotenvx"       # or "sops"
smart_encryption = true   # skip re-encrypting when content is unchanged
```

When the extension encrypts a file:

- **Backend choice** (`dotenvx` or `sops`) applies if configured
- **Smart encryption** applies if configured (avoids ciphertext churn in git)

Vault-driven flows are terminal workflows, not extension ones: the extension
never syncs keys with a vault. Run `envdrift lock --sync-keys`, `envdrift
pull`, or `envdrift vault-push --all` from the terminal for vault key
management and ephemeral-key flows.

For custom env file names, add the filename to `envdrift.patterns` in VS Code
settings. The extension calls `envdrift encrypt` after a matching file closes,
but pattern matching itself is controlled by the extension settings.

## Workflow Examples

### Basic Workflow

1. Open `.env` in VS Code
2. Add/edit secrets: `API_KEY=sk-secret-123`
3. Save the file (`Cmd+S`)
4. Close the file tab
5. ✅ File is automatically encrypted

### Team Workflow

1. Pull latest from git
2. Run `envdrift pull` to get keys from vault
3. Open `.env` and make changes
4. Close file → automatically encrypted
5. Commit and push (encrypted file is safe to commit)

### Manual Encryption

1. Open `.env` file
2. `Cmd+Shift+P` → "EnvDrift: Encrypt Current File"
3. ✅ File encrypted immediately

## Troubleshooting

### Extension not activating

1. Check VS Code version is 1.85.0+
2. Reload window: `Cmd+Shift+P` → "Developer: Reload Window"

### Files not being encrypted

1. **Check patterns**: Ensure file matches `envdrift.patterns`
2. **Check exclusions**: File might be in `envdrift.exclude`
3. **Check status bar**: Is auto-encryption enabled? (`$(lock)` vs `$(unlock)`)
4. **Check notifications setting**: Enable `showNotifications` to see errors

### "envdrift not found" error

```bash
# Ensure envdrift is installed (macOS / Linux)
curl -sSL https://raw.githubusercontent.com/jainal09/envdrift/main/install.sh | sh

# Windows (PowerShell)
irm https://raw.githubusercontent.com/jainal09/envdrift/main/install.ps1 | iex

# Add to PATH if needed
which envdrift
```

### Encryption failing

1. Check the Output panel: `View > Output > EnvDrift` (or run
   `EnvDrift: Show Logs`) — every encryption attempt and CLI error is
   logged there, even with notifications disabled
2. Verify `envdrift.toml` is valid
3. Ensure dotenvx is installed

```bash
npm install -g @dotenvx/dotenvx
```

### File already encrypted

If a file is already encrypted, the extension skips it. Look for:

- A real `DOTENV_PUBLIC_KEY=...` assignment
- The `encrypted:` prefix at the start of values
- SOPS `ENC[AES256_GCM,...` envelopes at the start of values

## Security Considerations

- The extension only encrypts on file **close**, not on every save
- Encryption uses `envdrift encrypt`, which calls `dotenvx encrypt`
  (or SOPS when configured)
- With dotenvx, private keys live in `.env.keys`; with SOPS, keys are managed by
  your configured SOPS source (an age key file, KMS, or PGP via `.sops.yaml`) and
  never `.env.keys`
- The extension never syncs keys with a vault — vault and ephemeral-key flows are
  terminal-only (see the envdrift.toml section)

## Performance

- The extension is lightweight and only activates when needed
- File pattern matching uses optimized glob patterns
- Encryption happens asynchronously to not block the UI
- 30-second timeout prevents hung operations

## Comparison: Extension vs Agent

| Feature | VS Code Extension | Background Agent |
|---------|-------------------|------------------|
| **When encrypts** | On file close | After idle timeout |
| **Editor required** | Yes (VS Code) | No (any editor) |
| **Desktop notifications** | VS Code notifications | System notifications |
| **Configuration** | VS Code settings | `~/.envdrift/guardian.toml` |
| **Best for** | VS Code users | IDE-agnostic automation |

**Recommendation**: Use the extension if you primarily use VS Code. Use the agent if you use multiple editors or want system-wide coverage.

## See Also

- [Agent Setup Guide](./agent-setup.md)
- [Encryption Guide](./encryption.md)
- [Env File Sync Guide](./env-file-sync.md)
- [Configuration Reference](../reference/configuration.md)
