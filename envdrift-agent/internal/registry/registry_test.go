package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_NoFile(t *testing.T) {
	// Create a temp directory and set HOME to it
	tmpDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", originalHome)

	reg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if reg == nil {
		t.Fatal("Load() returned nil registry")
	}

	if len(reg.Projects) != 0 {
		t.Errorf("Expected empty projects, got %d", len(reg.Projects))
	}
}

func TestLoad_ValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", originalHome)

	// Create .envdrift directory and projects.json
	envdriftDir := filepath.Join(tmpDir, ".envdrift")
	if err := os.MkdirAll(envdriftDir, 0755); err != nil {
		t.Fatal(err)
	}

	registry := Registry{
		Projects: []ProjectEntry{
			{Path: "/home/user/project1", Added: "2025-01-01T00:00:00Z"},
			{Path: "/home/user/project2", Added: "2025-01-02T00:00:00Z"},
		},
	}

	data, _ := json.Marshal(registry)
	if err := os.WriteFile(filepath.Join(envdriftDir, "projects.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	reg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(reg.Projects) != 2 {
		t.Errorf("Expected 2 projects, got %d", len(reg.Projects))
	}

	if reg.Projects[0].Path != "/home/user/project1" {
		t.Errorf("Expected path /home/user/project1, got %s", reg.Projects[0].Path)
	}
}

func TestRegistry_GetProjectPaths(t *testing.T) {
	reg := &Registry{
		Projects: []ProjectEntry{
			{Path: "/path/a", Added: "2025-01-01T00:00:00Z"},
			{Path: "/path/b", Added: "2025-01-02T00:00:00Z"},
		},
	}

	paths := reg.GetProjectPaths()

	if len(paths) != 2 {
		t.Errorf("Expected 2 paths, got %d", len(paths))
	}

	if paths[0] != "/path/a" || paths[1] != "/path/b" {
		t.Errorf("Unexpected paths: %v", paths)
	}
}

func TestRegistry_HasProject(t *testing.T) {
	reg := &Registry{
		Projects: []ProjectEntry{
			{Path: "/path/a", Added: "2025-01-01T00:00:00Z"},
		},
	}

	if !reg.HasProject("/path/a") {
		t.Error("Expected HasProject to return true for /path/a")
	}

	if reg.HasProject("/path/b") {
		t.Error("Expected HasProject to return false for /path/b")
	}
}
