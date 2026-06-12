// Package config tests
package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
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

// setTempHome points the config path at a fresh temp dir for the test.
func setTempHome(t *testing.T) string {
	t.Helper()
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tempDir)
	}
	return tempDir
}

// writeGuardianToml writes content to the guardian.toml the config package reads.
func writeGuardianToml(t *testing.T, content string) {
	t.Helper()
	configPath := ConfigPath()
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestLoadDocumentedDurationString is the #481 regression: the documented
// guardian.toml form `idle_timeout = "5m"` crashed the agent at startup
// ("cannot decode TOML string into ... time.Duration"), which under launchd
// KeepAlive / systemd Restart=always became a crash-respawn loop.
func TestLoadDocumentedDurationString(t *testing.T) {
	setTempHome(t)
	writeGuardianToml(t, "[guardian]\nenabled = true\nidle_timeout = \"5m\"\n")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() rejected the documented duration-string form (#481): %v", err)
	}
	if cfg.Guardian.IdleTimeout != 5*time.Minute {
		t.Errorf("IdleTimeout = %v, want 5m", cfg.Guardian.IdleTimeout)
	}
	// Fields absent from the file keep their defaults.
	if len(cfg.Guardian.Patterns) == 0 || cfg.Guardian.Patterns[0] != ".env*" {
		t.Errorf("Patterns lost defaults: %v", cfg.Guardian.Patterns)
	}
	if !cfg.Guardian.Notify {
		t.Error("Notify lost its default (true)")
	}
}

// TestLoadExtendedDurationUnits: the "2d" day suffix the per-project parser
// accepts must work in the global config too.
func TestLoadExtendedDurationUnits(t *testing.T) {
	setTempHome(t)
	writeGuardianToml(t, "[guardian]\nidle_timeout = \"2d\"\n")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Guardian.IdleTimeout != 48*time.Hour {
		t.Errorf("IdleTimeout = %v, want 48h", cfg.Guardian.IdleTimeout)
	}
}

// TestLoadLegacyNanosecondInteger: configs written by the pre-#481 Save hold
// raw nanoseconds (idle_timeout = 300000000000); they must keep loading so the
// fix doesn't introduce its own crash loop.
func TestLoadLegacyNanosecondInteger(t *testing.T) {
	setTempHome(t)
	writeGuardianToml(t, "[guardian]\nidle_timeout = 300000000000\n")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() rejected the legacy nanosecond-integer form: %v", err)
	}
	if cfg.Guardian.IdleTimeout != 5*time.Minute {
		t.Errorf("IdleTimeout = %v, want 5m", cfg.Guardian.IdleTimeout)
	}
}

// TestLoadInvalidDurationString: garbage stays an error (with the offending
// key named), not a silent default.
func TestLoadInvalidDurationString(t *testing.T) {
	setTempHome(t)
	writeGuardianToml(t, "[guardian]\nidle_timeout = \"soon\"\n")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() accepted idle_timeout = \"soon\"; want an error")
	}
	if !strings.Contains(err.Error(), "idle_timeout") {
		t.Errorf("error %q does not name guardian.idle_timeout", err)
	}
}

// TestSaveWritesDocumentedDurationString is the #481 regression for Save: it
// must serialize idle_timeout in the documented string form ("5m"), not
// time.Duration's raw nanoseconds.
func TestSaveWritesDocumentedDurationString(t *testing.T) {
	setTempHome(t)

	cfg := DefaultConfig()
	cfg.Guardian.IdleTimeout = 5 * time.Minute
	if err := Save(cfg); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		t.Fatal(err)
	}

	var saved struct {
		Guardian struct {
			IdleTimeout any `toml:"idle_timeout"`
		} `toml:"guardian"`
	}
	if err := toml.Unmarshal(data, &saved); err != nil {
		t.Fatalf("saved config is not valid TOML: %v\n%s", err, data)
	}
	got, ok := saved.Guardian.IdleTimeout.(string)
	if !ok {
		t.Fatalf("saved idle_timeout = %v (%T); want the documented string form (#481)\nfile:\n%s",
			saved.Guardian.IdleTimeout, saved.Guardian.IdleTimeout, data)
	}
	if got != "5m" {
		t.Errorf("saved idle_timeout = %q, want \"5m\"", got)
	}
}

func TestFormatIdleTimeout(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{5 * time.Minute, "5m"},
		{30 * time.Second, "30s"},
		{2 * time.Hour, "2h"},
		{48 * time.Hour, "48h"},
		{90 * time.Second, "90s"},
		{time.Minute + 30*time.Second + 500*time.Millisecond, "1m30.5s"},
	}
	for _, tc := range cases {
		if got := FormatIdleTimeout(tc.d); got != tc.want {
			t.Errorf("FormatIdleTimeout(%v) = %q, want %q", tc.d, got, tc.want)
		}
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
