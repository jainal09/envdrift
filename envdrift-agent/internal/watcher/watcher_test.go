// Package watcher tests
package watcher

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	w, err := New([]string{".env*"}, []string{".env.example"}, true)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}
	defer w.Stop()

	if w == nil {
		t.Fatal("Watcher should not be nil")
	}
}

func TestMatchesPattern(t *testing.T) {
	w, _ := New([]string{".env*", "*.env"}, []string{}, false)
	defer w.Stop()

	tests := []struct {
		path     string
		expected bool
	}{
		{".env", true},
		{".env.local", true},
		{".env.production", true},
		{"config.env", true},
		{"README.md", false},
		{"package.json", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := w.matchesPattern(tt.path)
			if result != tt.expected {
				t.Errorf("matchesPattern(%q) = %v, expected %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestIsExcluded(t *testing.T) {
	w, _ := New([]string{".env*"}, []string{".env.example", ".env.sample"}, false)
	defer w.Stop()

	tests := []struct {
		path     string
		expected bool
	}{
		{".env.example", true},
		{".env.sample", true},
		{".env.production", false},
		{".env", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := w.isExcluded(tt.path)
			if result != tt.expected {
				t.Errorf("isExcluded(%q) = %v, expected %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestExpandPath(t *testing.T) {
	home, _ := os.UserHomeDir()

	tests := []struct {
		input    string
		expected string
	}{
		{"~/projects", filepath.Join(home, "projects")},
		{"/absolute/path", "/absolute/path"},
		{"relative/path", "relative/path"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := expandPath(tt.input)
			if result != tt.expected {
				t.Errorf("expandPath(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestAddDirectory(t *testing.T) {
	tempDir := t.TempDir()

	w, err := New([]string{".env*"}, []string{}, false)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}
	defer w.Stop()

	err = w.AddDirectory(tempDir)
	if err != nil {
		t.Fatalf("Failed to add directory: %v", err)
	}
}

func TestEventsChannel(t *testing.T) {
	w, _ := New([]string{".env*"}, []string{}, false)
	defer w.Stop()

	events := w.Events()
	if events == nil {
		t.Error("Events channel should not be nil")
	}
}

func TestLastModified(t *testing.T) {
	w, _ := New([]string{".env*"}, []string{}, false)
	defer w.Stop()

	// Initially should be zero time
	modTime := w.LastModified("/some/path")
	if !modTime.IsZero() {
		t.Error("LastModified should return zero time for unknown path")
	}
}

func TestFileEventChange(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping file event test in short mode")
	}

	tempDir := t.TempDir()

	w, err := New([]string{".env*"}, []string{}, false)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}
	defer w.Stop()

	err = w.AddDirectory(tempDir)
	if err != nil {
		t.Fatalf("Failed to add directory: %v", err)
	}

	w.Start()

	// Create a .env file
	envPath := filepath.Join(tempDir, ".env.test")
	if err := os.WriteFile(envPath, []byte("TEST=value\n"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Wait for event (with timeout)
	select {
	case event := <-w.Events():
		if event.Path != envPath {
			t.Errorf("Expected path %s, got %s", envPath, event.Path)
		}
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for file event")
	}
}
