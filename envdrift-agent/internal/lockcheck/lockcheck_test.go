// Package lockcheck tests
package lockcheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestIsFileOpenNonexistent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("File lock detection behaves differently on Windows")
	}
	// Nonexistent file should not be considered open
	result := IsFileOpen("/nonexistent/path/to/file.env")
	if result {
		t.Error("Nonexistent file should not be reported as open")
	}
}

func TestIsFileOpenClosedFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("File lock detection behaves differently on Windows")
	}
	// Create a temp file and close it
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, ".env.test")

	f, err := os.Create(filePath)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	_, _ = f.WriteString("TEST=value\n")
	if err := f.Close(); err != nil {
		t.Fatalf("Failed to close test file: %v", err)
	}

	// File should not be open
	result := IsFileOpen(filePath)
	if result {
		t.Error("Closed file should not be reported as open")
	}
}

func TestIsFileOpenOpenFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("File locking behaves differently on Windows")
	}

	// Create a temp file and keep it open
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, ".env.test")

	f, err := os.Create(filePath)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Fatalf("Failed to close test file: %v", err)
		}
	}()

	_, _ = f.WriteString("TEST=value\n")

	// File should be open (our process has it open)
	result := IsFileOpen(filePath)
	// Note: lsof might not detect our own process's open file
	// This test is primarily to ensure no panic
	t.Logf("IsFileOpen result for open file: %v", result)
}

// TestIsFileOpenUnixMissingLsof is the #413 regression: when lsof is absent
// from PATH, isFileOpenUnix must conservatively return true (treat the file as
// open/unknown) so the guardian skips encrypting a file it cannot vouch for,
// instead of silently bypassing the open-file safety check. On the unfixed code
// the *exec.Error from a missing binary was collapsed into "not open" (false).
func TestIsFileOpenUnixMissingLsof(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("isFileOpenUnix is Unix-only")
	}

	// Point PATH at an empty temp dir so exec.Command("lsof", ...) fails to find
	// the binary, producing an *exec.Error rather than a clean exit-1.
	emptyDir := t.TempDir()
	t.Setenv("PATH", emptyDir)

	// Sanity: lsof really must be unresolvable now.
	if _, err := exec.LookPath("lsof"); err == nil {
		t.Skip("lsof still resolvable despite cleared PATH; cannot exercise missing-binary path")
	}

	tempFile := filepath.Join(emptyDir, ".env.test")
	if err := os.WriteFile(tempFile, []byte("X=1\n"), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	if got := isFileOpenUnix(tempFile); !got {
		t.Errorf("isFileOpenUnix with lsof absent = false; want true (conservative open/unknown) (#413)")
	}
}

func TestGetOpenProcessesNonexistent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("GetOpenProcesses not implemented for Windows")
	}

	processes := GetOpenProcesses("/nonexistent/path/to/file.env")
	if len(processes) != 0 {
		t.Errorf("Expected empty slice for nonexistent file, got %v", processes)
	}
}

func TestGetOpenProcessesClosedFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("GetOpenProcesses not implemented for Windows")
	}

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, ".env.test")

	f, err := os.Create(filePath)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	_, _ = f.WriteString("TEST=value\n")
	if err := f.Close(); err != nil {
		t.Fatalf("Failed to close test file: %v", err)
	}

	processes := GetOpenProcesses(filePath)
	if len(processes) != 0 {
		t.Errorf("Expected empty slice for closed file, got %v", processes)
	}
}
