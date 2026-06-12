// Package lockcheck tests
package lockcheck

import (
	"errors"
	"fmt"
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

// TestIsFileOpenIgnoresOwnProcess is the core #481 regression, run against the
// REAL lsof: a file held open only by the agent's own process must NOT count
// as "still open". On macOS the fsnotify/kqueue watcher keeps an fd open on
// every watched file, so the pre-#481 code (no self-PID filter) reported every
// watched file permanently busy and never encrypted anything.
func TestIsFileOpenIgnoresOwnProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("isFileOpenUnix is Unix-only")
	}
	if _, err := exec.LookPath("lsof"); err != nil {
		t.Skip("lsof not on PATH; cannot exercise the real PID lister")
	}

	// Create a temp file and keep it open from THIS process, like the kqueue
	// watcher does.
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, ".env.test")
	if err := os.WriteFile(filePath, []byte("TEST=value\n"), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	f, err := os.Open(filePath)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Fatalf("Failed to close test file: %v", err)
		}
	}()

	if IsFileOpen(filePath) {
		t.Errorf("IsFileOpen = true for a file held open only by our own process; "+
			"want false — the agent must not block on its own watcher fds (#481). lsof PIDs: %v",
			GetOpenProcesses(filePath))
	}
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

// withFakePIDLister swaps the openPIDs process-lister seam for the duration of
// a test, so the self-PID-exclusion logic is unit-testable on every platform
// (the lsof-backed lister is Unix-only).
func withFakePIDLister(t *testing.T, fake func(string) ([]int, error)) {
	t.Helper()
	orig := openPIDs
	openPIDs = fake
	t.Cleanup(func() { openPIDs = orig })
}

// TestIsFileOpenUnixExcludesSelfPID: only the agent's own PID holds the file —
// it must not count as open (#481).
func TestIsFileOpenUnixExcludesSelfPID(t *testing.T) {
	withFakePIDLister(t, func(string) ([]int, error) {
		return []int{os.Getpid()}, nil
	})

	if isFileOpenUnix("/some/.env") {
		t.Error("isFileOpenUnix = true when only our own PID holds the file; want false (#481)")
	}
}

// TestIsFileOpenUnixOtherProcessBlocks: any OTHER process's handle still counts
// as open, with or without our own PID in the list.
func TestIsFileOpenUnixOtherProcessBlocks(t *testing.T) {
	cases := []struct {
		name string
		pids []int
	}{
		{"other process only", []int{1}},
		{"own PID plus other process", []int{os.Getpid(), 1}},
		{"unparseable lsof entry counts as other process", []int{-1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withFakePIDLister(t, func(string) ([]int, error) {
				return tc.pids, nil
			})

			if !isFileOpenUnix("/some/.env") {
				t.Errorf("isFileOpenUnix = false with PIDs %v; want true", tc.pids)
			}
		})
	}
}

// TestIsFileOpenUnixNoProcesses: an empty PID list means not open.
func TestIsFileOpenUnixNoProcesses(t *testing.T) {
	withFakePIDLister(t, func(string) ([]int, error) {
		return nil, nil
	})

	if isFileOpenUnix("/some/.env") {
		t.Error("isFileOpenUnix = true with no PIDs; want false")
	}
}

// TestIsFileOpenUnixListerErrors: a missing tool or any ambiguous lister error
// must stay conservative (treat the file as open/unknown), as before #481.
func TestIsFileOpenUnixListerErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"lock tool unavailable", fmt.Errorf("%w: lsof gone", errLockToolUnavailable)},
		{"ambiguous failure", errors.New("lsof exploded")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withFakePIDLister(t, func(string) ([]int, error) {
				return nil, tc.err
			})

			if !isFileOpenUnix("/some/.env") {
				t.Errorf("isFileOpenUnix = false on lister error %v; want conservative true", tc.err)
			}
		})
	}
}

func TestParsePIDs(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   []int
	}{
		{"empty", "", nil},
		{"single pid", "123\n", []int{123}},
		{"multiple pids with blank lines", "123\n\n456\n", []int{123, 456}},
		{"whitespace-padded pid", "  789  \n", []int{789}},
		{"unparseable line becomes -1", "123\nnot-a-pid\n", []int{123, -1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parsePIDs(tc.output)
			if len(got) != len(tc.want) {
				t.Fatalf("parsePIDs(%q) = %v, want %v", tc.output, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("parsePIDs(%q) = %v, want %v", tc.output, got, tc.want)
					break
				}
			}
		})
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
