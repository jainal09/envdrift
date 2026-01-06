// Package lockcheck detects if a file is open by another process.
package lockcheck

import (
	"bytes"
	"os/exec"
	"runtime"
	"strings"
)

// IsFileOpen checks if a file is currently open by any process.
// IsFileOpen reports whether the file at path is currently open by any process.
// On Darwin and Linux it checks via lsof; on Windows it uses handle.exe with a PowerShell fallback.
// It returns true if the file is open, and false if the file is not open, the check cannot be performed, or the platform is unsupported.
func IsFileOpen(path string) bool {
	switch runtime.GOOS {
	case "darwin", "linux":
		return isFileOpenUnix(path)
	case "windows":
		return isFileOpenWindows(path)
	default:
		return false // Assume not open on unknown platforms
	}
}

// isFileOpenUnix reports whether the file at path is open by any process on Unix-like systems.
// It invokes `lsof` for the path and returns `true` if `lsof` reports any output; if the command fails or returns no output it returns `false`.
func isFileOpenUnix(path string) bool {
	// lsof exits with 0 if file is open, 1 if not
	cmd := exec.Command("lsof", "--", path)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	err := cmd.Run()
	if err != nil {
		// Exit code 1 means file is not open
		return false
	}

	// If we got output, file is open
	return strings.TrimSpace(stdout.String()) != ""
}

// isFileOpenWindows uses handle.exe to check if file is open
// isFileOpenWindows reports whether the file at path is open by any process on Windows.
// It uses `handle.exe -nobanner` when available; if `handle.exe` is unavailable or returns an error,
// it falls back to a PowerShell-based exclusive-open check.
func isFileOpenWindows(path string) bool {
	// First try handle.exe (Sysinternals)
	cmd := exec.Command("handle.exe", "-nobanner", path)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	err := cmd.Run()
	if err != nil {
		// handle.exe not available or error, try PowerShell fallback
		return isFileOpenWindowsPowerShell(path)
	}

	output := strings.TrimSpace(stdout.String())
	// handle.exe returns "No matching handles found." if not open
	return !strings.Contains(output, "No matching handles found")
}

// isFileOpenWindowsPowerShell attempts to determine whether the file at path is open by another process using a PowerShell-based exclusive open attempt.
// It returns true if the open attempt fails (indicating the file is locked), false otherwise.
func isFileOpenWindowsPowerShell(path string) bool {
	// Use PowerShell with proper argument escaping
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		"try { $fs = [System.IO.File]::Open($args[0], 'Open', 'ReadWrite', 'None'); $fs.Close(); exit 0 } catch { exit 1 }",
		path)
	err := cmd.Run()
	return err != nil // Error means file is locked
}

// GetOpenProcesses returns list of processes that have the file open.
// GetOpenProcesses returns the process IDs of processes that have the specified file open.
// It runs `lsof -t -- <path>` on Darwin and Linux and returns a slice of PID strings.
// Returns nil on non-Darwin/Linux platforms, if `lsof` fails, or if no processes are found.
func GetOpenProcesses(path string) []string {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return nil
	}

	cmd := exec.Command("lsof", "-t", "--", path)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return nil
	}

	output := strings.TrimSpace(stdout.String())
	if output == "" {
		return nil
	}

	return strings.Split(output, "\n")
}