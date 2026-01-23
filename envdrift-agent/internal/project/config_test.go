package project

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseIdleTimeout(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{"5m", 5 * time.Minute, false},
		{"30s", 30 * time.Second, false},
		{"1h", 1 * time.Hour, false},
		{"2d", 48 * time.Hour, false},
		{"10m", 10 * time.Minute, false},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseIdleTimeout(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseIdleTimeout(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.expected {
				t.Errorf("ParseIdleTimeout(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestDefaultGuardianConfig(t *testing.T) {
	cfg := DefaultGuardianConfig()

	if cfg.Enabled != false {
		t.Errorf("Expected Enabled=false, got %v", cfg.Enabled)
	}

	if cfg.IdleTimeout != 5*time.Minute {
		t.Errorf("Expected IdleTimeout=5m, got %v", cfg.IdleTimeout)
	}

	if len(cfg.Patterns) != 1 || cfg.Patterns[0] != ".env*" {
		t.Errorf("Unexpected patterns: %v", cfg.Patterns)
	}

	if cfg.Notify != true {
		t.Errorf("Expected Notify=true, got %v", cfg.Notify)
	}
}

func TestLoadProjectConfig_NoFile(t *testing.T) {
	tmpDir := t.TempDir()

	cfg, err := LoadProjectConfig(tmpDir)
	if err != nil {
		t.Fatalf("LoadProjectConfig() error = %v", err)
	}

	// Should return defaults
	if cfg.Enabled != false {
		t.Errorf("Expected Enabled=false, got %v", cfg.Enabled)
	}
}

func TestLoadProjectConfig_WithGuardianSection(t *testing.T) {
	tmpDir := t.TempDir()

	tomlContent := `
[guardian]
enabled = true
idle_timeout = "10m"
patterns = [".env*", ".secret*"]
exclude = [".env.example"]
notify = false
`
	if err := os.WriteFile(filepath.Join(tmpDir, "envdrift.toml"), []byte(tomlContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadProjectConfig(tmpDir)
	if err != nil {
		t.Fatalf("LoadProjectConfig() error = %v", err)
	}

	if cfg.Enabled != true {
		t.Errorf("Expected Enabled=true, got %v", cfg.Enabled)
	}

	if cfg.IdleTimeout != 10*time.Minute {
		t.Errorf("Expected IdleTimeout=10m, got %v", cfg.IdleTimeout)
	}

	if len(cfg.Patterns) != 2 {
		t.Errorf("Expected 2 patterns, got %d", len(cfg.Patterns))
	}

	if len(cfg.Exclude) != 1 || cfg.Exclude[0] != ".env.example" {
		t.Errorf("Unexpected exclude: %v", cfg.Exclude)
	}

	if cfg.Notify != false {
		t.Errorf("Expected Notify=false, got %v", cfg.Notify)
	}
}

func TestLoadProjectConfig_PartialConfig(t *testing.T) {
	tmpDir := t.TempDir()

	// Only set some fields, others should use defaults
	tomlContent := `
[guardian]
enabled = true
idle_timeout = "1m"
`
	if err := os.WriteFile(filepath.Join(tmpDir, "envdrift.toml"), []byte(tomlContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadProjectConfig(tmpDir)
	if err != nil {
		t.Fatalf("LoadProjectConfig() error = %v", err)
	}

	if cfg.Enabled != true {
		t.Errorf("Expected Enabled=true, got %v", cfg.Enabled)
	}

	if cfg.IdleTimeout != 1*time.Minute {
		t.Errorf("Expected IdleTimeout=1m, got %v", cfg.IdleTimeout)
	}

	// Should use defaults for unset fields
	if len(cfg.Patterns) != 1 || cfg.Patterns[0] != ".env*" {
		t.Errorf("Expected default patterns, got %v", cfg.Patterns)
	}

	if cfg.Notify != true {
		t.Errorf("Expected default Notify=true, got %v", cfg.Notify)
	}
}

func TestLoadAllProjectConfigs(t *testing.T) {
	// Create two project directories
	proj1 := t.TempDir()
	proj2 := t.TempDir()
	proj3 := t.TempDir() // No config

	// proj1: enabled
	os.WriteFile(filepath.Join(proj1, "envdrift.toml"), []byte(`
[guardian]
enabled = true
idle_timeout = "5m"
`), 0644)

	// proj2: disabled
	os.WriteFile(filepath.Join(proj2, "envdrift.toml"), []byte(`
[guardian]
enabled = false
`), 0644)

	// proj3: no envdrift.toml (defaults to disabled)

	configs, err := LoadAllProjectConfigs([]string{proj1, proj2, proj3})
	if err != nil {
		t.Fatalf("LoadAllProjectConfigs() error = %v", err)
	}

	// Only proj1 should be returned (enabled)
	if len(configs) != 1 {
		t.Errorf("Expected 1 enabled project, got %d", len(configs))
	}

	if configs[0].Path != proj1 {
		t.Errorf("Expected path %s, got %s", proj1, configs[0].Path)
	}
}
