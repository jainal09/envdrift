// Package config tests
package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.Guardian.Enabled {
		t.Error("Expected Guardian.Enabled to be true by default")
	}

	if cfg.Guardian.IdleTimeout != 5*time.Minute {
		t.Errorf("Expected IdleTimeout to be 5m, got %v", cfg.Guardian.IdleTimeout)
	}

	if len(cfg.Guardian.Patterns) == 0 {
		t.Error("Expected at least one pattern in Patterns")
	}

	if cfg.Guardian.Patterns[0] != ".env*" {
		t.Errorf("Expected first pattern to be '.env*', got %s", cfg.Guardian.Patterns[0])
	}

	if !cfg.Guardian.Notify {
		t.Error("Expected Notify to be true by default")
	}

	if !cfg.Directories.Recursive {
		t.Error("Expected Recursive to be true by default")
	}
}

func TestConfigPath(t *testing.T) {
	path := ConfigPath()

	if path == "" {
		t.Error("ConfigPath should not be empty")
	}

	if !filepath.IsAbs(path) {
		t.Errorf("ConfigPath should be absolute, got %s", path)
	}

	if filepath.Base(path) != "guardian.toml" {
		t.Errorf("Expected filename 'guardian.toml', got %s", filepath.Base(path))
	}
}

func TestLoadMissingConfig(t *testing.T) {
	// Temporarily change HOME to a temp dir
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	if err := os.Setenv("HOME", tempDir); err != nil {
		t.Fatalf("Failed to set HOME: %v", err)
	}
	defer func() {
		if err := os.Setenv("HOME", originalHome); err != nil {
			t.Fatalf("Failed to restore HOME: %v", err)
		}
	}()

	// Windows uses USERPROFILE
	if runtime.GOOS == "windows" {
		originalProfile := os.Getenv("USERPROFILE")
		if err := os.Setenv("USERPROFILE", tempDir); err != nil {
			t.Fatalf("Failed to set USERPROFILE: %v", err)
		}
		defer func() {
			if err := os.Setenv("USERPROFILE", originalProfile); err != nil {
				t.Fatalf("Failed to restore USERPROFILE: %v", err)
			}
		}()
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load should return defaults when config missing: %v", err)
	}

	if cfg == nil {
		t.Fatal("Config should not be nil")
	}

	if !cfg.Guardian.Enabled {
		t.Error("Should return default config with Enabled=true")
	}
}

func TestSaveAndLoad(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	if err := os.Setenv("HOME", tempDir); err != nil {
		t.Fatalf("Failed to set HOME: %v", err)
	}
	defer func() {
		if err := os.Setenv("HOME", originalHome); err != nil {
			t.Fatalf("Failed to restore HOME: %v", err)
		}
	}()

	// Windows uses USERPROFILE
	if runtime.GOOS == "windows" {
		originalProfile := os.Getenv("USERPROFILE")
		if err := os.Setenv("USERPROFILE", tempDir); err != nil {
			t.Fatalf("Failed to set USERPROFILE: %v", err)
		}
		defer func() {
			if err := os.Setenv("USERPROFILE", originalProfile); err != nil {
				t.Fatalf("Failed to restore USERPROFILE: %v", err)
			}
		}()
	}

	// Create and save config
	cfg := DefaultConfig()
	cfg.Guardian.IdleTimeout = 10 * time.Minute
	cfg.Guardian.Patterns = []string{".env", ".env.local"}

	if err := Save(cfg); err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Load it back
	loadedCfg, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if loadedCfg.Guardian.IdleTimeout != 10*time.Minute {
		t.Errorf("IdleTimeout mismatch: expected 10m, got %v", loadedCfg.Guardian.IdleTimeout)
	}

	if len(loadedCfg.Guardian.Patterns) != 2 {
		t.Errorf("Expected 2 patterns, got %d", len(loadedCfg.Guardian.Patterns))
	}
}

func TestExcludePatterns(t *testing.T) {
	cfg := DefaultConfig()

	expectedExcludes := []string{".env.example", ".env.sample", ".env.keys"}
	if len(cfg.Guardian.Exclude) != len(expectedExcludes) {
		t.Errorf("Expected %d exclude patterns, got %d", len(expectedExcludes), len(cfg.Guardian.Exclude))
	}

	for i, expected := range expectedExcludes {
		if i < len(cfg.Guardian.Exclude) && cfg.Guardian.Exclude[i] != expected {
			t.Errorf("Exclude[%d]: expected %s, got %s", i, expected, cfg.Guardian.Exclude[i])
		}
	}
}
