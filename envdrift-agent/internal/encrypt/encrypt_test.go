// Package encrypt tests
package encrypt

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIsEncrypted(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name:     "encrypted file",
			content:  "DATABASE_URL=\"encrypted:abc123\"\nAPI_KEY=\"encrypted:xyz789\"",
			expected: true,
		},
		{
			name:     "plaintext file",
			content:  "DATABASE_URL=\"postgres://localhost:5432/db\"\nAPI_KEY=\"sk-secret-key\"",
			expected: false,
		},
		{
			name:     "mixed case encrypted marker",
			content:  "SECRET=\"ENCRYPTED:abc123\"",
			expected: true,
		},
		{
			name:     "empty file",
			content:  "",
			expected: false,
		},
		{
			name:     "comments only",
			content:  "# This is a comment\n# Another comment",
			expected: false,
		},
		{
			name:     "encrypted in comment",
			content:  "# encrypted: values below\nKEY=value",
			expected: false, // Comments should be ignored
		},
		{
			name:     "value with encrypted marker, no quotes",
			content:  "API_KEY=encrypted:abc",
			expected: true,
		},
		{
			// Regression for #348 G6: a plaintext value that merely contains
			// the substring "encrypted:" must not be reported as encrypted.
			name:     "plaintext value containing encrypted substring",
			content:  "NOTE=not encrypted: yet",
			expected: false,
		},
		{
			// The anchor is the value side: "encrypted:" appearing only in the
			// key/free-text without an = value must not match.
			name:     "plaintext mention without assignment",
			content:  "this line says encrypted: nope",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file
			tempDir := t.TempDir()
			filePath := filepath.Join(tempDir, ".env.test")
			if err := os.WriteFile(filePath, []byte(tt.content), 0644); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			result, err := IsEncrypted(filePath)
			if err != nil {
				t.Fatalf("IsEncrypted returned error: %v", err)
			}

			if result != tt.expected {
				t.Errorf("IsEncrypted(%q) = %v, expected %v", tt.name, result, tt.expected)
			}
		})
	}
}

func TestIsEncryptedMissingFile(t *testing.T) {
	_, err := IsEncrypted("/nonexistent/path/.env")
	if err == nil {
		t.Error("Expected error for missing file")
	}
}

func TestIsEnvdriftAvailable(t *testing.T) {
	// This test just ensures the function doesn't panic
	// Result depends on whether envdrift is installed
	available := IsEnvdriftAvailable()
	t.Logf("envdrift available: %v", available)
}

// writeFakeExe writes an executable shell script named name into dir.
func writeFakeExe(t *testing.T, dir, name, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-exe shell script not supported on windows")
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatalf("write fake exe: %v", err)
	}
	return p
}

// TestBuildEncryptCommand_PythonUsesModuleFlag is the #348 G1 regression: when
// findEnvdrift resolves to a python interpreter, buildEncryptCommand must emit
// `python -m envdrift lock <file>`, not `python lock <file>`.
func TestBuildEncryptCommand_PythonUsesModuleFlag(t *testing.T) {
	dir := t.TempDir()
	// Fake python that succeeds only for `-m envdrift --version` so findEnvdrift
	// selects the python fallback path.
	writeFakeExe(t, dir, "python", `
case "$1 $2 $3" in
  "-m envdrift --version") echo "envdrift 10.0.0"; exit 0 ;;
esac
exit 1
`)
	// PATH contains ONLY our temp dir: no real `envdrift`, no real `python3`.
	t.Setenv("PATH", dir)

	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("A=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd, err := buildEncryptCommand(envPath)
	if err != nil {
		t.Fatalf("buildEncryptCommand: %v", err)
	}

	if got := filepath.Base(cmd.Path); !strings.Contains(got, "python") {
		t.Fatalf("expected python interpreter, got cmd.Path=%q", cmd.Path)
	}
	joined := strings.Join(cmd.Args, " ")
	if !strings.Contains(joined, "-m envdrift") {
		t.Errorf("python invocation missing `-m envdrift`: %v", cmd.Args)
	}
	// Tail must be `... -m envdrift lock .env`.
	tail := cmd.Args[len(cmd.Args)-4:]
	want := []string{"-m", "envdrift", "lock", ".env"}
	for i := range want {
		if tail[i] != want[i] {
			t.Errorf("args tail = %v, want %v (full: %v)", tail, want, cmd.Args)
			break
		}
	}
}

// TestBuildEncryptCommand_BinaryNoModuleFlag asserts that a standalone envdrift
// binary is invoked directly as `envdrift lock <file>` (no `-m envdrift`).
func TestBuildEncryptCommand_BinaryNoModuleFlag(t *testing.T) {
	dir := t.TempDir()
	bin := writeFakeExe(t, dir, "envdrift", `exit 0`)
	t.Setenv("PATH", dir)

	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("A=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd, err := buildEncryptCommand(envPath)
	if err != nil {
		t.Fatalf("buildEncryptCommand: %v", err)
	}

	if cmd.Path != bin {
		t.Errorf("cmd.Path = %q, want %q", cmd.Path, bin)
	}
	wantArgs := []string{bin, "lock", ".env"}
	if len(cmd.Args) != len(wantArgs) {
		t.Fatalf("args = %v, want %v", cmd.Args, wantArgs)
	}
	for i := range wantArgs {
		if cmd.Args[i] != wantArgs[i] {
			t.Errorf("args = %v, want %v", cmd.Args, wantArgs)
			break
		}
	}
}
