// Package lockcheck detects if a file is open by another process.
package lockcheck

import (
	"bytes"
	"os/exec"
	"runtime"
	"strings"
)

// IsFileOpen checks if a file is currently open by any process.
// Uses lsof on Unix systems and handle.exe on Windows.
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

// isFileOpenUnix uses lsof to check if file is open
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
// Requires handle.exe from Sysinternals to be in PATH
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

// isFileOpenWindowsPowerShell fallback using PowerShell
func isFileOpenWindowsPowerShell(path string) bool {
	// Try to open file exclusively - if it fails, it's open
	script := `
		try {
			$fs = [System.IO.File]::Open('` + path + `', 'Open', 'ReadWrite', 'None')
			$fs.Close()
			exit 0
		} catch {
			exit 1
		}
	`
	cmd := exec.Command("powershell", "-NoProfile", "-Command", script)
	err := cmd.Run()
	return err != nil // Error means file is locked
}

// GetOpenProcesses returns list of processes that have the file open.
// Returns empty slice if file is not open or on error.
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
