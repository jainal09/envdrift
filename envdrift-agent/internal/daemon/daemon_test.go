// Package daemon tests
package daemon

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLaunchAgentPath(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-only test")
	}

	path, err := launchAgentPath()
	if err != nil {
		t.Fatalf("launchAgentPath failed: %v", err)
	}
	if path == "" {
		t.Error("Launch agent path should not be empty")
	}

	if filepath.Ext(path) != ".plist" {
		t.Errorf("Expected .plist extension, got %s", filepath.Ext(path))
	}
}

func TestSystemdPath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}

	path, err := systemdPath()
	if err != nil {
		t.Fatalf("systemdPath failed: %v", err)
	}
	if path == "" {
		t.Error("Systemd path should not be empty")
	}

	if !strings.HasSuffix(path, ".service") {
		t.Errorf("Expected .service suffix, got %s", path)
	}
}

func TestIsInstalled(t *testing.T) {
	// Just ensure this doesn't panic
	_ = IsInstalled()
}

func TestIsRunning(t *testing.T) {
	// Just ensure this doesn't panic
	_ = IsRunning()
}
