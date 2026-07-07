# Installation

## Universal Installer (Recommended)

The universal installer sets up an isolated environment with all vault backends included.

### macOS / Linux

```bash
curl -sSL https://raw.githubusercontent.com/jainal09/envdrift/main/install.sh | sh
```

Or with options:

```bash
# Skip agent binary download
curl -sSL https://raw.githubusercontent.com/jainal09/envdrift/main/install.sh | sh -s -- --no-agent

# Install a specific version
curl -sSL https://raw.githubusercontent.com/jainal09/envdrift/main/install.sh | sh -s -- --version 1.2.3

# Skip agent checksum verification (unsafe — installs an unverified binary)
curl -sSL https://raw.githubusercontent.com/jainal09/envdrift/main/install.sh | sh -s -- --insecure-skip-checksum

# Uninstall
curl -sSL https://raw.githubusercontent.com/jainal09/envdrift/main/install.sh | sh -s -- --uninstall
```

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/jainal09/envdrift/main/install.ps1 | iex
```

The installer works in both the OS-default Windows PowerShell 5.1 and PowerShell 7+ (`pwsh`),
and the generated wrappers support install paths with non-ASCII characters.

Or with options (use environment variables when piping):

```powershell
# Skip agent binary download
$env:ENVDRIFT_NO_AGENT = "1"; irm https://raw.githubusercontent.com/jainal09/envdrift/main/install.ps1 | iex

# Install a specific version
$env:ENVDRIFT_VERSION = "1.2.3"; irm https://raw.githubusercontent.com/jainal09/envdrift/main/install.ps1 | iex

# Skip agent checksum verification (unsafe — installs an unverified binary)
$env:ENVDRIFT_INSECURE_SKIP_CHECKSUM = "1"; irm https://raw.githubusercontent.com/jainal09/envdrift/main/install.ps1 | iex

# Uninstall
$env:ENVDRIFT_UNINSTALL = "1"; irm https://raw.githubusercontent.com/jainal09/envdrift/main/install.ps1 | iex
```

If running the script directly (saved locally), you can use parameters instead:

```powershell
.\install.ps1 -NoAgent
.\install.ps1 -Version 1.2.3
.\install.ps1 -InsecureSkipChecksum
.\install.ps1 -Uninstall
```

### What the Installer Does

1. Detects your platform (OS and architecture)
2. Finds Python 3.11+ on your system
3. Creates an isolated virtual environment at `~/.envdrift/venv`
4. Installs `envdrift[vault]` (all vault backends)
5. Creates a wrapper script at `~/.envdrift/bin/envdrift`
6. Optionally downloads the envdrift-agent binary (SHA256-verified against the
   release `checksums.txt`; the install **aborts** if the checksum is missing or
   does not match, unless you pass `--insecure-skip-checksum`)

Add `~/.envdrift/bin` to your `PATH` to use `envdrift` from anywhere.

## pip Install

```bash
pip install envdrift
# or with uv
uv add envdrift
```

## Optional Dependencies

envdrift has optional features that require additional packages:

### Vault Backends

```bash
# Azure Key Vault
pip install envdrift[azure]

# AWS Secrets Manager
pip install envdrift[aws]

# HashiCorp Vault
pip install envdrift[hashicorp]

# GCP Secret Manager
pip install envdrift[gcp]

# All vault backends
pip install envdrift[vault]
```

### Pre-commit Integration

```bash
pip install envdrift[precommit]
```

### Everything

```bash
pip install envdrift[all]
```

## Verify Installation

```bash
envdrift version
# Output: envdrift 10.12.3
```

## Requirements

- Python 3.11 or higher
- pydantic >= 2.0
- pydantic-settings >= 2.0
