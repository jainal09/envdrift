"""Regression tests for the ``install.ps1`` Windows execution contract (#483, #501).

The documented install flow (``irm ... | iex``) runs in the OS-default Windows
PowerShell 5.1 on every stock Windows box, so ``install.ps1`` must stay within
the 5.1 language/cmdlet surface:

- ``Join-Path`` in 5.1 has no ``-AdditionalChildPath``: the 3-argument form
  (``Join-Path a b c``) is PowerShell 6+ only and dies with a parameter binding
  error. The script must nest two-argument calls instead.
- The ``envdrift.cmd`` wrapper used to embed the absolute venv path written with
  ``-Encoding ASCII``, mangling non-ASCII profile paths (``José`` -> ``Jos?``)
  into a dead wrapper. The wrapper must resolve the venv at runtime so it works
  for any user-profile path.
- The py launcher is represented as a command plus a version selector. Splatting
  both at the call-operator position joins them into one nonexistent executable;
  the installer must invoke the executable and its arguments separately.

These drive the *real* installer code under a real PowerShell engine — no
re-implementation of the behavior under test. They are deliberately not marked
``integration``: PowerShell is preinstalled on every GitHub runner (like git),
and the cross-platform Windows unit lane is the only lane that can exercise the
genuine Windows PowerShell 5.1 binder.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALL_PS1 = _REPO_ROOT / "install.ps1"

# Windows PowerShell 5.1 ships only these Join-Path parameters (plus the common
# parameters). -AdditionalChildPath — what the 3-argument positional form binds
# to — exists only in PowerShell 6+.
_AST_SCAN_HARNESS = """
param([string]$ScriptPath)
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $ScriptPath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) {
    foreach ($e in $errors) { [Console]::Error.WriteLine($e.ToString()) }
    exit 2
}
$violations = @()
$commands = $ast.FindAll(
    { param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
foreach ($cmd in $commands) {
    if ($cmd.GetCommandName() -ne 'Join-Path') { continue }
    $elements = @($cmd.CommandElements | Select-Object -Skip 1)
    $positional = 0
    $badParams = @()
    for ($i = 0; $i -lt $elements.Count; $i++) {
        $e = $elements[$i]
        if ($e -is [System.Management.Automation.Language.CommandParameterAst]) {
            if (@('Path', 'ChildPath', 'Resolve', 'Credential') -notcontains $e.ParameterName) {
                $badParams += $e.ParameterName
            }
            # Non-switch parameters consume the next element as their value.
            if ($e.ParameterName -ne 'Resolve' -and $null -eq $e.Argument) { $i++ }
        }
        else {
            $positional++
        }
    }
    if ($positional -gt 2 -or $badParams.Count -gt 0) {
        $violations += [pscustomobject]@{
            Line = $cmd.Extent.StartLineNumber
            Text = $cmd.Extent.Text
        }
    }
}
ConvertTo-Json -InputObject @($violations) -Compress
"""

# Evaluates every Join-Path call from install.ps1 under the *running* engine's
# real parameter binder (dummy values for the script's path variables). Under
# Windows PowerShell 5.1 a 3-argument call throws a binding error.
_BINDER_HARNESS = """
param([string]$ScriptPath)
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $ScriptPath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { exit 2 }
$failures = @()
$commands = $ast.FindAll(
    { param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
foreach ($cmd in $commands) {
    if ($cmd.GetCommandName() -ne 'Join-Path') { continue }
    $vars = $cmd.FindAll(
        { param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] },
        $true)
    foreach ($var in $vars) {
        $name = $var.VariablePath.UserPath -replace '^(script|global|local|private):', ''
        Set-Variable -Name $name -Value 'C:\\probe' -Force -ErrorAction SilentlyContinue
    }
    try {
        $null = Invoke-Expression $cmd.Extent.Text
    }
    catch {
        $failures += [pscustomobject]@{
            Line  = $cmd.Extent.StartLineNumber
            Text  = $cmd.Extent.Text
            Error = $_.Exception.Message
        }
    }
}
ConvertTo-Json -InputObject @($failures) -Compress
"""

# Dot-sources every function definition from the real install.ps1 (verbatim, via
# the AST) and runs the real New-Wrappers against a caller-chosen install dir.
_WRAPPER_HARNESS = """
param([string]$ScriptPath, [string]$InstallDir)
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $ScriptPath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) {
    foreach ($e in $errors) { [Console]::Error.WriteLine($e.ToString()) }
    exit 2
}
$functions = $ast.FindAll(
    { param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] },
    $true)
foreach ($fn in $functions) {
    . ([scriptblock]::Create($fn.Extent.Text))
}
$VenvDir = Join-Path $InstallDir 'venv'
$BinDir = Join-Path $InstallDir 'bin'
New-Wrappers
"""

# Dot-sources the real Initialize-Venv and dot-invokes it from a caller whose
# $ErrorActionPreference is not "Stop". A normal function call cannot observe
# the old hardcoded restore (a preference-variable write inside a function is
# function-local), but dot-invocation runs the body in the caller's scope —
# there the hardcode really did clobber the caller's preference with "Stop".
# A --without-pip venv makes the best-effort pip upgrade fail on native stderr
# — the exact 2>$null trigger that is a terminating NativeCommandError under
# 5.1 with "Stop" — without touching the network.
_EAP_RESTORE_HARNESS = """
param([string]$ScriptPath, [string]$PythonExe, [string]$InstallDir)
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $ScriptPath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) {
    foreach ($e in $errors) { [Console]::Error.WriteLine($e.ToString()) }
    exit 2
}
$functions = $ast.FindAll(
    { param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] },
    $true)
foreach ($fn in $functions) {
    . ([scriptblock]::Create($fn.Extent.Text))
}
$VenvDir = Join-Path $InstallDir 'venv'
& $PythonExe -m venv --without-pip $VenvDir
if ($LASTEXITCODE -ne 0) { exit 3 }
$ErrorActionPreference = 'SilentlyContinue'
. Initialize-Venv
[Console]::Out.WriteLine("EAP_AFTER=$ErrorActionPreference")
"""

# Runs the real Initialize-Venv with the same multi-element command shape used
# for the py launcher. ``-X utf8`` is a valid interpreter-level option and lets
# the test use CI's selected Python without assuming a particular py registration.
# PIP_NO_INDEX makes the function's best-effort pip upgrade deterministic and
# network-free after the venv has been created.
_MULTI_ARG_PYTHON_HARNESS = """
param([string]$ScriptPath, [string]$PythonExe, [string]$InstallDir)
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $ScriptPath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) {
    foreach ($e in $errors) { [Console]::Error.WriteLine($e.ToString()) }
    exit 2
}
$functions = $ast.FindAll(
    { param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] },
    $true)
foreach ($fn in $functions) {
    . ([scriptblock]::Create($fn.Extent.Text))
}
$script:InstallDir = $InstallDir
$script:VenvDir = Join-Path $InstallDir 'venv'
$script:PythonCmd = @($PythonExe, '-X', 'utf8')
$env:PIP_NO_INDEX = '1'
$env:PIP_DISABLE_PIP_VERSION_CHECK = '1'
Initialize-Venv
if (-not (Test-Path $script:VenvPython)) { exit 3 }
[Console]::Out.WriteLine("MULTI_ARG_PYTHON_OK")
"""


def _powershell() -> str | None:
    """Best available PowerShell: pwsh (7+) anywhere, else Windows PowerShell."""
    return shutil.which("pwsh") or shutil.which("powershell")


def _windows_powershell_51() -> str | None:
    """The genuine Windows PowerShell 5.1 engine (Windows only)."""
    if sys.platform != "win32":
        return None
    return shutil.which("powershell")


requires_powershell = pytest.mark.skipif(
    _powershell() is None, reason="PowerShell (pwsh/powershell) not installed"
)
requires_windows_powershell_51 = pytest.mark.skipif(
    _windows_powershell_51() is None,
    reason="Windows PowerShell 5.1 only exists on Windows",
)


def _run_harness(
    exe: str, harness: str, tmp_path: Path, *args: str
) -> subprocess.CompletedProcess[str]:
    harness_file = tmp_path / "harness.ps1"
    # utf-8-sig: Windows PowerShell 5.1 decodes BOM-less files as legacy ANSI,
    # so the BOM keeps any future non-ASCII harness content from being mangled.
    harness_file.write_text(harness, encoding="utf-8-sig")
    # -ExecutionPolicy Bypass is process-scoped: stock Windows boxes default to
    # "Restricted", which rejects -File outright (GitHub runners allow scripts,
    # so CI never sees it). pwsh accepts and ignores the flag on non-Windows.
    return subprocess.run(
        [
            exe,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(harness_file),
            *args,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        # Windows PowerShell 5.1 writes console output in the OEM codepage
        # (e.g. 0x82 for an accented e), which is not valid UTF-8. Only ASCII
        # markers/JSON are parsed from stdout, so replacement is lossless.
        errors="replace",
        env=os.environ.copy(),
        check=False,
        timeout=120,
    )


def _norm(path: str) -> str:
    """Normalize a Windows- or POSIX-style path string for comparison."""
    return posixpath.normpath(path.replace("\\", "/"))


def test_install_ps1_is_ascii_or_carries_a_bom() -> None:
    """install.ps1 must stay readable by Windows PowerShell 5.1 (#483).

    5.1 decodes BOM-less script files in the legacy ANSI codepage, silently
    corrupting any UTF-8 multi-byte sequence. The script must therefore be
    pure ASCII (or explicitly carry a UTF-8 BOM).
    """
    raw = INSTALL_PS1.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        return
    non_ascii = [
        (i + 1, line) for i, line in enumerate(raw.splitlines()) if any(b > 127 for b in line)
    ]
    assert non_ascii == [], (
        f"install.ps1 has BOM-less non-ASCII lines (mojibake under PowerShell 5.1): {non_ascii}"
    )


@requires_powershell
def test_install_ps1_parses_without_errors(tmp_path: Path) -> None:
    """install.ps1 must parse cleanly (guards against future syntax breakage)."""
    proc = _run_harness(_powershell() or "", _AST_SCAN_HARNESS, tmp_path, str(INSTALL_PS1))
    assert proc.returncode == 0, f"install.ps1 failed to parse:\n{proc.stderr}"


@requires_powershell
def test_join_path_calls_are_windows_powershell_51_compatible(tmp_path: Path) -> None:
    """No Join-Path call may use the PowerShell 6+-only 3-argument form (#483).

    Pre-fix, install.ps1:223/:238/:267 used ``Join-Path $VenvDir "Scripts" <exe>``,
    which Windows PowerShell 5.1 rejects with "A positional parameter cannot be
    found that accepts argument", killing the documented ``irm | iex`` install
    inside Initialize-Venv on every stock Windows 10/11 box.
    """
    proc = _run_harness(_powershell() or "", _AST_SCAN_HARNESS, tmp_path, str(INSTALL_PS1))
    assert proc.returncode == 0, f"AST scan failed:\n{proc.stderr}"
    violations = json.loads(proc.stdout.strip())
    assert violations == [], (
        "install.ps1 contains Join-Path calls that do not bind under Windows "
        f"PowerShell 5.1 (nest two-argument calls instead): {violations}"
    )


@requires_windows_powershell_51
def test_join_path_calls_bind_under_real_windows_powershell_51(tmp_path: Path) -> None:
    """Every Join-Path call must bind under the genuine 5.1 binder (#483)."""
    proc = _run_harness(_windows_powershell_51() or "", _BINDER_HARNESS, tmp_path, str(INSTALL_PS1))
    assert proc.returncode == 0, f"binder harness failed:\n{proc.stderr}"
    failures = json.loads(proc.stdout.strip())
    assert failures == [], (
        f"Join-Path calls in install.ps1 fail to bind under Windows PowerShell 5.1: {failures}"
    )


@requires_windows_powershell_51
def test_initialize_venv_restores_caller_error_action_preference(tmp_path: Path) -> None:
    """Initialize-Venv must restore the entry $ErrorActionPreference.

    The function relaxes the preference to "Continue" around the best-effort
    pip upgrade (under 5.1, native stderr + ``2>$null`` is a terminating
    NativeCommandError with "Stop"). It must restore whatever value was active
    on entry — not hardcode "Stop". A normal call can't leak the write (it is
    function-local), so the harness dot-invokes the function: with the old
    hardcode that replaced a "SilentlyContinue" caller's preference with
    "Stop" for the rest of the session.
    """
    install_dir = tmp_path / "install"
    proc = _run_harness(
        _windows_powershell_51() or "",
        _EAP_RESTORE_HARNESS,
        tmp_path,
        str(INSTALL_PS1),
        sys.executable,
        str(install_dir),
    )
    assert proc.returncode == 0, f"EAP restore harness failed:\n{proc.stdout}\n{proc.stderr}"
    assert "EAP_AFTER=SilentlyContinue" in proc.stdout, (
        "Initialize-Venv must restore the caller's $ErrorActionPreference "
        f"instead of hardcoding 'Stop':\n{proc.stdout}"
    )


@requires_windows_powershell_51
def test_initialize_venv_accepts_python_command_with_arguments(tmp_path: Path) -> None:
    """Initialize-Venv must keep launcher arguments separate from its executable.

    Find-Python stores the py-launcher fallback as ``@('py', '-3')``. Passing
    that array directly to ``&`` joins it into a command name such as ``py -3``,
    which does not exist and aborts py-launcher-only installs (#501).
    """
    install_dir = tmp_path / "multi-arg-python"
    proc = _run_harness(
        _windows_powershell_51() or "",
        _MULTI_ARG_PYTHON_HARNESS,
        tmp_path,
        str(INSTALL_PS1),
        sys.executable,
        str(install_dir),
    )
    assert proc.returncode == 0, (
        f"Initialize-Venv rejected a multi-part Python command:\n{proc.stdout}\n{proc.stderr}"
    )
    assert "MULTI_ARG_PYTHON_OK" in proc.stdout


@requires_powershell
def test_cmd_wrapper_survives_non_ascii_install_path(tmp_path: Path) -> None:
    """The envdrift.cmd wrapper must work from a non-ASCII profile path (#483).

    Pre-fix, New-Wrappers embedded the absolute venv path and wrote the file
    with ``-Encoding ASCII``: a profile like ``C:\\Users\\José`` became
    ``C:\\Users\\Jos?\\...`` — a dead wrapper ("The system cannot find the path
    specified") while the installer reported success.
    """
    install_dir = tmp_path / "José Müller" / ".envdrift"
    proc = _run_harness(
        _powershell() or "", _WRAPPER_HARNESS, tmp_path, str(INSTALL_PS1), str(install_dir)
    )
    assert proc.returncode == 0, f"New-Wrappers failed:\n{proc.stdout}\n{proc.stderr}"

    bin_dir = install_dir / "bin"
    cmd_wrapper = bin_dir / "envdrift.cmd"
    assert cmd_wrapper.is_file(), "envdrift.cmd was not created"
    raw = cmd_wrapper.read_bytes()

    # A BOM (or any junk) before `@echo off` breaks cmd.exe's first line.
    assert raw.startswith(b"@echo off"), f"cmd wrapper must start with @echo off: {raw[:16]!r}"

    text = raw.decode("utf-8")
    exec_lines = [line for line in text.splitlines() if "%*" in line]
    assert len(exec_lines) == 1, f"expected exactly one exec line in wrapper:\n{text}"
    match = re.match(r'^"(?P<target>.+)" %\*$', exec_lines[0].strip())
    assert match, f"unexpected exec line shape: {exec_lines[0]!r}"

    # Resolve what cmd.exe would execute (%~dp0 = the wrapper's own directory).
    target = match["target"].replace("%~dp0", f"{bin_dir}/")
    expected = install_dir / "venv" / "Scripts" / "envdrift.exe"
    assert _norm(target) == _norm(str(expected)), (
        "envdrift.cmd does not resolve to the venv executable for a non-ASCII "
        f"install path: wrapper targets {target!r}, expected {str(expected)!r}"
    )

    # The wrapper must stay encoding-proof: pure ASCII content, no absolute
    # (potentially non-ASCII) install path baked in.
    assert all(b < 128 for b in raw), "cmd wrapper content must be pure ASCII"

    # The PowerShell wrapper is written as UTF-8 and must keep the real path.
    ps1_wrapper = bin_dir / "envdrift.ps1"
    assert ps1_wrapper.is_file(), "envdrift.ps1 was not created"
    ps1_text = ps1_wrapper.read_text(encoding="utf-8-sig")
    assert _norm(str(expected)) in ps1_text.replace("\\", "/"), (
        "envdrift.ps1 must reference the real venv executable path"
    )
