# envdrift universal installer for Windows
# Usage: irm https://raw.githubusercontent.com/jainal09/envdrift/main/install.ps1 | iex
#    or: Save and run with parameters: .\install.ps1 -NoAgent
#
# When piped via irm | iex, parameters cannot be passed directly.
# Use environment variables instead:
#   $env:ENVDRIFT_NO_AGENT = "1"; irm ... | iex
#   $env:ENVDRIFT_VERSION = "1.2.3"; irm ... | iex
#   $env:ENVDRIFT_AGENT_VERSION = "0.5.0"; irm ... | iex
#   $env:ENVDRIFT_UNINSTALL = "1"; irm ... | iex
#
# Options (when running script directly):
#   -NoAgent            Skip downloading the envdrift-agent binary
#   -Version X.Y.Z      Install a specific envdrift version
#   -AgentVersion X.Y.Z Install a specific agent version
#   -Uninstall          Remove envdrift installation
#   -Help               Show this help message

param(
    [switch]$NoAgent,
    [string]$Version = "",
    [string]$AgentVersion = "",
    [switch]$Uninstall,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

# -------------------------------------------------------------------
# Environment variable overrides (for irm | iex usage)
# -------------------------------------------------------------------
if ($env:ENVDRIFT_NO_AGENT -eq "1") { $NoAgent = [switch]::new($true) }
if ($env:ENVDRIFT_VERSION) { $Version = $env:ENVDRIFT_VERSION }
if ($env:ENVDRIFT_AGENT_VERSION) { $AgentVersion = $env:ENVDRIFT_AGENT_VERSION }
if ($env:ENVDRIFT_UNINSTALL -eq "1") { $Uninstall = [switch]::new($true) }

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------
$InstallDir = Join-Path $HOME ".envdrift"
$VenvDir = Join-Path $InstallDir "venv"
$BinDir = Join-Path $InstallDir "bin"
$GitHubRepo = "jainal09/envdrift"
$MinPythonMajor = 3
$MinPythonMinor = 11

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
function Write-Info  { param([string]$Msg) Write-Host "  > $Msg" -ForegroundColor Blue }
function Write-Ok    { param([string]$Msg) Write-Host "  [OK] $Msg" -ForegroundColor Green }
function Write-Warn  { param([string]$Msg) Write-Host "  [WARN] $Msg" -ForegroundColor Yellow }
function Write-Err   { param([string]$Msg) Write-Host "  [ERROR] $Msg" -ForegroundColor Red }

function Stop-WithError {
    param([string]$Msg)
    Write-Err $Msg
    exit 1
}

function Get-Download {
    param([string]$Url, [string]$Dest)
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -ErrorAction Stop
    }
    catch {
        throw "Download failed: $_"
    }
}

# -------------------------------------------------------------------
# Help
# -------------------------------------------------------------------
if ($Help) {
    Write-Host @"
envdrift installer

Usage:
  .\install.ps1 [options]

  Via pipe (use env vars for options):
    `$env:ENVDRIFT_NO_AGENT = "1"; irm https://raw.githubusercontent.com/jainal09/envdrift/main/install.ps1 | iex

Options:
  -NoAgent              Skip downloading the envdrift-agent binary
  -Version X.Y.Z        Install a specific envdrift Python package version
  -AgentVersion X.Y.Z   Install a specific agent binary version
  -Uninstall            Remove the envdrift installation (~/.envdrift)
  -Help                 Show this help message

Environment Variables (for irm | iex):
  ENVDRIFT_NO_AGENT=1         Same as -NoAgent
  ENVDRIFT_VERSION=X.Y.Z      Same as -Version
  ENVDRIFT_AGENT_VERSION=X.Y.Z Same as -AgentVersion
  ENVDRIFT_UNINSTALL=1         Same as -Uninstall
"@
    exit 0
}

# -------------------------------------------------------------------
# Uninstall
# -------------------------------------------------------------------
if ($Uninstall) {
    Write-Info "Uninstalling envdrift..."
    if (Test-Path $VenvDir) {
        Remove-Item -Recurse -Force $VenvDir
        Write-Ok "Removed $VenvDir"
    }
    if (Test-Path $BinDir) {
        Remove-Item -Recurse -Force $BinDir
        Write-Ok "Removed $BinDir"
    }
    if (Test-Path $InstallDir) {
        $remaining = Get-ChildItem $InstallDir -Force -ErrorAction SilentlyContinue
        if (-not $remaining) {
            Remove-Item -Force $InstallDir
            Write-Ok "Removed $InstallDir"
        }
        else {
            Write-Warn "$InstallDir not empty - kept remaining files (e.g. projects.json)"
        }
    }
    Write-Ok "envdrift uninstalled"
    exit 0
}

# -------------------------------------------------------------------
# Banner
# -------------------------------------------------------------------
Write-Host ""
Write-Host "  envdrift installer" -ForegroundColor White
Write-Host ""

# -------------------------------------------------------------------
# Detect platform
# -------------------------------------------------------------------
function Get-Platform {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLower()

    switch ($arch) {
        "x64"   { $arch = "amd64" }
        "arm64" { $arch = "arm64" }
        default { Stop-WithError "Unsupported architecture: $arch" }
    }

    $script:Platform = "windows-$arch"
    Write-Info "Detected platform: $script:Platform"
}

# -------------------------------------------------------------------
# Find Python >= 3.11
# -------------------------------------------------------------------
function Find-Python {
    # Try common commands
    foreach ($cmd in @("python3", "python", "py")) {
        $exe = Get-Command $cmd -ErrorAction SilentlyContinue
        if ($exe) {
            try {
                if ($cmd -eq "py") {
                    $verStr = & $cmd -3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
                    if ($LASTEXITCODE -eq 0 -and $verStr) {
                        $parts = $verStr.Trim().Split(".")
                        $major = [int]$parts[0]
                        $minor = [int]$parts[1]
                        if ($major -eq $MinPythonMajor -and $minor -ge $MinPythonMinor) {
                            $script:PythonCmd = @($cmd, "-3")
                            Write-Info "Found Python $verStr via py -3"
                            return
                        }
                    }
                }
                else {
                    $verStr = & $cmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
                    if ($LASTEXITCODE -eq 0 -and $verStr) {
                        $parts = $verStr.Trim().Split(".")
                        $major = [int]$parts[0]
                        $minor = [int]$parts[1]
                        if ($major -eq $MinPythonMajor -and $minor -ge $MinPythonMinor) {
                            $script:PythonCmd = @($cmd)
                            Write-Info "Found Python $verStr at $(($exe).Source)"
                            return
                        }
                    }
                }
            }
            catch {
                # Ignore errors, try next command
            }
        }
    }

    # Try py launcher with specific versions (3.19 down to 3.11)
    $pyExe = Get-Command "py" -ErrorAction SilentlyContinue
    if ($pyExe) {
        for ($m = 19; $m -ge $MinPythonMinor; $m--) {
            try {
                $verStr = & py "-3.$m" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
                if ($LASTEXITCODE -eq 0 -and $verStr) {
                    $script:PythonCmd = @("py", "-3.$m")
                    Write-Info "Found Python $($verStr.Trim()) via py -3.$m"
                    return
                }
            }
            catch {
                # Ignore, try next
            }
        }
    }

    Stop-WithError "Python ${MinPythonMajor}.${MinPythonMinor}+ is required but not found. Please install Python first."
}

# -------------------------------------------------------------------
# Create / reuse virtual environment
# -------------------------------------------------------------------
function Initialize-Venv {
    $venvPython = Join-Path $VenvDir "Scripts" "python.exe"

    if ((Test-Path $VenvDir) -and (Test-Path $venvPython)) {
        Write-Info "Reusing existing venv at $VenvDir"
    }
    else {
        Write-Info "Creating virtual environment at $VenvDir"
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        & @script:PythonCmd -m venv $VenvDir
        if ($LASTEXITCODE -ne 0) {
            Stop-WithError "Failed to create virtual environment"
        }
    }

    $script:VenvPython = $venvPython
    $script:VenvPip = Join-Path $VenvDir "Scripts" "pip.exe"

    # Upgrade pip silently
    & $script:VenvPython -m pip install --upgrade pip 2>$null | Out-Null
}

# -------------------------------------------------------------------
# Install envdrift Python package
# -------------------------------------------------------------------
function Install-Envdrift {
    $pkg = "envdrift[vault]"
    if ($Version) {
        $pkg = "envdrift[vault]==$Version"
    }

    Write-Info "Installing $pkg ..."
    & $script:VenvPip install --upgrade $pkg
    if ($LASTEXITCODE -ne 0) {
        Stop-WithError "pip install failed"
    }
    Write-Ok "envdrift Python package installed"
}

# -------------------------------------------------------------------
# Create wrapper scripts
# -------------------------------------------------------------------
function New-Wrappers {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null

    $venvEnvdrift = Join-Path $VenvDir "Scripts" "envdrift.exe"

    # CMD wrapper (UTF8 to support non-ASCII paths)
    $cmdWrapper = Join-Path $BinDir "envdrift.cmd"
    @"
@echo off
"$venvEnvdrift" %*
"@ | Set-Content -Path $cmdWrapper -Encoding ASCII
    Write-Ok "Created CMD wrapper at $cmdWrapper"

    # PowerShell wrapper
    $ps1Wrapper = Join-Path $BinDir "envdrift.ps1"
    @"
#!/usr/bin/env pwsh
# envdrift wrapper - delegates to the venv installation
& "$venvEnvdrift" @args
"@ | Set-Content -Path $ps1Wrapper -Encoding UTF8
    Write-Ok "Created PowerShell wrapper at $ps1Wrapper"
}

# -------------------------------------------------------------------
# Download agent binary
# -------------------------------------------------------------------
function Install-Agent {
    if ($NoAgent) {
        Write-Info "Skipping agent download (-NoAgent)"
        return
    }

    if ($AgentVersion) {
        $baseUrl = "https://github.com/$GitHubRepo/releases/download/agent-v$AgentVersion"
    }
    else {
        # /releases/latest may point to a non-agent release (e.g. vscode extension).
        # Query GitHub API for the latest agent-v* tag instead.
        $apiUrl = "https://api.github.com/repos/$GitHubRepo/releases"
        try {
            $releases = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing -ErrorAction Stop
            $agentRelease = $releases | Where-Object { $_.tag_name -match '^agent-v' } | Select-Object -First 1
            if ($agentRelease) {
                $baseUrl = "https://github.com/$GitHubRepo/releases/download/$($agentRelease.tag_name)"
            }
            else {
                Write-Warn "No agent release found on GitHub"
                Write-Warn "The agent can be installed later with: envdrift install agent"
                return
            }
        }
        catch {
            Write-Warn "Could not determine latest agent version from GitHub API"
            Write-Warn "The agent can be installed later with: envdrift install agent"
            return
        }
    }

    $binaryName = "envdrift-agent-${script:Platform}.exe"
    $agentUrl = "$baseUrl/$binaryName"
    $checksumUrl = "$baseUrl/checksums.txt"
    $dest = Join-Path $BinDir "envdrift-agent.exe"

    Write-Info "Downloading envdrift-agent for $script:Platform ..."

    $tmpBinary = [System.IO.Path]::GetTempFileName()
    try {
        try {
            Get-Download -Url $agentUrl -Dest $tmpBinary
        }
        catch {
            Write-Warn "Could not download agent binary from $agentUrl"
            Write-Warn "The agent can be installed later with: envdrift install agent"
            return
        }

        # Verify checksum (best-effort)
        Test-Checksum -File $tmpBinary -Name $binaryName -Url $checksumUrl

        try {
            Move-Item -Force $tmpBinary $dest
        }
        catch {
            Stop-WithError "Failed to install agent binary. Is envdrift-agent currently running? Stop it first and retry."
        }
        Write-Ok "Installed envdrift-agent to $dest"
    }
    finally {
        Remove-Item $tmpBinary -Force -ErrorAction SilentlyContinue
    }
}

# -------------------------------------------------------------------
# SHA256 checksum verification
# -------------------------------------------------------------------
function Test-Checksum {
    param([string]$File, [string]$Name, [string]$Url)

    $tmpChecksums = [System.IO.Path]::GetTempFileName()
    try {
        Get-Download -Url $Url -Dest $tmpChecksums
    }
    catch {
        Write-Warn "Checksums file not available - skipping verification"
        Remove-Item $tmpChecksums -Force -ErrorAction SilentlyContinue
        return
    }

    $expected = $null
    foreach ($line in (Get-Content $tmpChecksums)) {
        $parts = $line -split '\s+'
        if ($parts.Count -ge 2 -and $parts[-1] -eq $Name) {
            $expected = $parts[0].ToLower()
            break
        }
    }
    Remove-Item $tmpChecksums -Force -ErrorAction SilentlyContinue

    if (-not $expected) {
        Write-Warn "No checksum entry for $Name - skipping verification"
        return
    }

    $hash = (Get-FileHash -Path $File -Algorithm SHA256).Hash.ToLower()
    if ($hash -ne $expected) {
        Stop-WithError "Checksum mismatch! Expected $expected, got $hash. Aborting."
    }

    Write-Ok "Checksum verified"
}

# -------------------------------------------------------------------
# PATH instructions
# -------------------------------------------------------------------
function Test-PathContains {
    param([string]$PathValue, [string]$TargetDir)
    if (-not $PathValue) { return $false }
    foreach ($entry in ($PathValue -split ';')) {
        $trimmed = $entry.Trim()
        if (-not $trimmed) { continue }
        try {
            $normalized = [System.IO.Path]::GetFullPath($trimmed).TrimEnd('\', '/')
        }
        catch {
            continue
        }
        if ($normalized -eq $TargetDir) { return $true }
    }
    return $false
}

function Show-PathInstructions {
    try {
        $normalizedBinDir = [System.IO.Path]::GetFullPath($BinDir).TrimEnd('\', '/')
    }
    catch {
        $normalizedBinDir = $BinDir.TrimEnd('\', '/')
    }

    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if (Test-PathContains -PathValue $userPath -TargetDir $normalizedBinDir) {
        return
    }

    if (Test-PathContains -PathValue $env:PATH -TargetDir $normalizedBinDir) {
        return
    }

    Write-Host ""
    Write-Warn "$BinDir is not in your PATH."
    Write-Host ""
    Write-Info "Add it to your user PATH by running:"
    Write-Host ""
    Write-Host "    `$currentPath = [Environment]::GetEnvironmentVariable('PATH', 'User')" -ForegroundColor Cyan
    Write-Host "    [Environment]::SetEnvironmentVariable('PATH', `"$BinDir;`$currentPath`", 'User')" -ForegroundColor Cyan
    Write-Host ""
    Write-Info "Then restart your terminal, or run directly with: $BinDir\envdrift.cmd"
}

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
Get-Platform
Find-Python
Initialize-Venv
Install-Envdrift
New-Wrappers
Install-Agent
Show-PathInstructions

Write-Host ""
Write-Host "  [OK] envdrift installation complete!" -ForegroundColor Green
Write-Host ""
