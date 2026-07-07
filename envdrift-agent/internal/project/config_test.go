package project

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
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

func TestLoadProjectConfig_AppendsVaultEnvFilePatterns(t *testing.T) {
	tmpDir := t.TempDir()

	tomlContent := `
[guardian]
enabled = true
patterns = [".env*", "service.env"]

[vault.sync]
[[vault.sync.mappings]]
folder_path = "secrets/postgresql"
environment = "production"
secret_name = "postgresql-key"
env_file = "postgresql.env"

[[vault.sync.mappings]]
folder_path = "secrets/keycloak"
environment = "production"
secret_name = "keycloak-key"
env_file = "keycloak/keycloak-local.env"

[[vault.sync.mappings]]
folder_path = "secrets/ignored"
environment = "production"
secret_name = "ignored-key"
env_file = "../outside.env"

[[vault.sync.mappings]]
folder_path = "secrets/already-covered"
environment = "production"
secret_name = "already-covered-key"
env_file = "service.env"
`
	if err := os.WriteFile(filepath.Join(tmpDir, "envdrift.toml"), []byte(tomlContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadProjectConfig(tmpDir)
	if err != nil {
		t.Fatalf("LoadProjectConfig() error = %v", err)
	}

	if !patternListMatches(cfg.Patterns, "postgresql.env") {
		t.Errorf("Expected postgresql.env to be covered, got %v", cfg.Patterns)
	}

	if !patternListMatches(cfg.Patterns, "keycloak-local.env") {
		t.Errorf("Expected keycloak-local.env to be covered, got %v", cfg.Patterns)
	}

	if patternListMatches(cfg.Patterns, "outside.env") {
		t.Errorf("Expected escaping env_file to be ignored, got %v", cfg.Patterns)
	}

	servicePatternCount := 0
	for _, pattern := range cfg.Patterns {
		if pattern == "service.env" {
			servicePatternCount++
		}
	}
	if servicePatternCount != 1 {
		t.Errorf("Expected service.env to stay de-duplicated, got %v", cfg.Patterns)
	}
}

// writeFile is a tiny helper for the discovery tests below.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestLoadProjectConfig_PyprojectGuardian is the #481 regression: a project
// whose guardian config lives in pyproject.toml [tool.envdrift.guardian] was
// registered successfully by the CLI (find_config blesses pyproject.toml) but
// silently never watched — the agent read only <path>/envdrift.toml.
func TestLoadProjectConfig_PyprojectGuardian(t *testing.T) {
	tmpDir := t.TempDir()
	writeFile(t, filepath.Join(tmpDir, "pyproject.toml"), `
[project]
name = "demo"

[tool.envdrift.guardian]
enabled = true
idle_timeout = "10m"
patterns = [".env*", ".secret*"]
notify = false
`)

	cfg, err := LoadProjectConfig(tmpDir)
	if err != nil {
		t.Fatalf("LoadProjectConfig() error = %v", err)
	}

	if !cfg.Enabled {
		t.Error("Enabled = false: pyproject.toml [tool.envdrift.guardian] was ignored (#481)")
	}
	if cfg.IdleTimeout != 10*time.Minute {
		t.Errorf("IdleTimeout = %v, want 10m", cfg.IdleTimeout)
	}
	if len(cfg.Patterns) != 2 {
		t.Errorf("Patterns = %v, want 2 entries", cfg.Patterns)
	}
	if cfg.Notify {
		t.Error("Notify = true, want false")
	}
}

// TestLoadProjectConfig_ParentDirEnvdriftToml is the #481 regression for the
// parent-dir half of the discovery contract: the CLI's find_config walks up to
// the filesystem root, so a project registered from a subdirectory of a repo
// with a root envdrift.toml was blessed at register time but never watched.
func TestLoadProjectConfig_ParentDirEnvdriftToml(t *testing.T) {
	parent := t.TempDir()
	project := filepath.Join(parent, "services", "api")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(parent, "envdrift.toml"), `
[guardian]
enabled = true
idle_timeout = "3m"
`)

	cfg, err := LoadProjectConfig(project)
	if err != nil {
		t.Fatalf("LoadProjectConfig() error = %v", err)
	}

	if !cfg.Enabled {
		t.Error("Enabled = false: parent-dir envdrift.toml was ignored (#481)")
	}
	if cfg.IdleTimeout != 3*time.Minute {
		t.Errorf("IdleTimeout = %v, want 3m", cfg.IdleTimeout)
	}
}

// TestLoadProjectConfig_EnvdriftTomlWinsOverPyproject: within one directory,
// envdrift.toml takes precedence over pyproject.toml (find_config order).
func TestLoadProjectConfig_EnvdriftTomlWinsOverPyproject(t *testing.T) {
	tmpDir := t.TempDir()
	writeFile(t, filepath.Join(tmpDir, "envdrift.toml"), `
[guardian]
enabled = true
idle_timeout = "7m"
`)
	writeFile(t, filepath.Join(tmpDir, "pyproject.toml"), `
[tool.envdrift.guardian]
enabled = true
idle_timeout = "9m"
`)

	cfg, err := LoadProjectConfig(tmpDir)
	if err != nil {
		t.Fatalf("LoadProjectConfig() error = %v", err)
	}
	if cfg.IdleTimeout != 7*time.Minute {
		t.Errorf("IdleTimeout = %v, want 7m (envdrift.toml must win over pyproject.toml)", cfg.IdleTimeout)
	}
}

// TestLoadProjectConfig_PyprojectWinsOverParentEnvdriftToml: a same-dir
// pyproject.toml with [tool.envdrift] beats a parent-dir envdrift.toml — the
// walk checks both files per level before moving up (find_config order).
func TestLoadProjectConfig_PyprojectWinsOverParentEnvdriftToml(t *testing.T) {
	parent := t.TempDir()
	project := filepath.Join(parent, "child")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(parent, "envdrift.toml"), `
[guardian]
enabled = true
idle_timeout = "3m"
`)
	writeFile(t, filepath.Join(project, "pyproject.toml"), `
[tool.envdrift.guardian]
enabled = true
idle_timeout = "9m"
`)

	cfg, err := LoadProjectConfig(project)
	if err != nil {
		t.Fatalf("LoadProjectConfig() error = %v", err)
	}
	if cfg.IdleTimeout != 9*time.Minute {
		t.Errorf("IdleTimeout = %v, want 9m (same-dir pyproject.toml must win over parent envdrift.toml)",
			cfg.IdleTimeout)
	}
}

// TestLoadProjectConfig_PyprojectSkippedAndWalkContinues: a child pyproject.toml
// that is unusable for discovery — either missing [tool.envdrift] or malformed —
// is skipped (matching the CLI's find_config), so the walk continues up to the
// parent envdrift.toml rather than stopping or erroring.
func TestLoadProjectConfig_PyprojectSkippedAndWalkContinues(t *testing.T) {
	cases := []struct {
		name      string
		pyproject string
	}{
		{"pyproject without [tool.envdrift]", "\n[project]\nname = \"demo\"\n"},
		{"malformed pyproject", "this is { not TOML\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			project := filepath.Join(parent, "child")
			if err := os.MkdirAll(project, 0o755); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(project, "pyproject.toml"), tc.pyproject)
			writeFile(t, filepath.Join(parent, "envdrift.toml"), "\n[guardian]\nenabled = true\n")

			cfg, err := LoadProjectConfig(project)
			if err != nil {
				t.Fatalf("LoadProjectConfig() error = %v", err)
			}
			if !cfg.Enabled {
				t.Error("Enabled = false: discovery did not continue to the parent envdrift.toml")
			}
		})
	}
}

// TestLoadProjectConfig_PyprojectVaultMappings: vault sync env_file patterns
// are honored from pyproject.toml too, like envdrift.toml.
func TestLoadProjectConfig_PyprojectVaultMappings(t *testing.T) {
	tmpDir := t.TempDir()
	writeFile(t, filepath.Join(tmpDir, "pyproject.toml"), `
[tool.envdrift.guardian]
enabled = true

[[tool.envdrift.vault.sync.mappings]]
folder_path = "secrets/postgresql"
environment = "production"
secret_name = "postgresql-key"
env_file = "postgresql.env"
`)

	cfg, err := LoadProjectConfig(tmpDir)
	if err != nil {
		t.Fatalf("LoadProjectConfig() error = %v", err)
	}
	if !patternListMatches(cfg.Patterns, "postgresql.env") {
		t.Errorf("vault env_file pattern from pyproject.toml not appended: %v", cfg.Patterns)
	}
}

func TestLoadAllProjectConfigs(t *testing.T) {
	// Create two project directories
	proj1 := t.TempDir()
	proj2 := t.TempDir()
	proj3 := t.TempDir() // No config

	// proj1: enabled
	if err := os.WriteFile(filepath.Join(proj1, "envdrift.toml"), []byte(`
[guardian]
enabled = true
idle_timeout = "5m"
`), 0644); err != nil {
		t.Fatal(err)
	}

	// proj2: disabled
	if err := os.WriteFile(filepath.Join(proj2, "envdrift.toml"), []byte(`
[guardian]
enabled = false
`), 0644); err != nil {
		t.Fatal(err)
	}

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

// TestLoadAllProjectConfigs_LogsDroppedProjectOnLoadError is the #504-review
// regression: a project whose envdrift.toml (here, an unreadable ancestor) can
// not be loaded must be reported — pre-fix the bare `continue` dropped it
// silently, so the operator had no idea the project was no longer watched.
func TestLoadAllProjectConfigs_LogsDroppedProjectOnLoadError(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("chmod-000 unreadability is not enforced on Windows or for root")
	}
	project := projectUnderUnreadableAncestor(t)
	logbuf := captureLog(t)

	configs, err := LoadAllProjectConfigs([]string{project})
	if err != nil {
		t.Fatalf("LoadAllProjectConfigs() error = %v", err)
	}
	if len(configs) != 0 {
		t.Errorf("expected the unreadable project to be dropped, got %d configs", len(configs))
	}
	out := logbuf.String()
	if !strings.Contains(out, "Skipping project") || !strings.Contains(out, project) {
		t.Errorf("dropped project was not logged; log output:\n%s", out)
	}
}

// projectUnderUnreadableAncestor returns a child project path whose discovery
// walk hits an existing-but-unreadable ancestor envdrift.toml (a real load
// error), cleaning the permissions up afterwards.
func projectUnderUnreadableAncestor(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	project := filepath.Join(parent, "child")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	ancestor := filepath.Join(parent, "envdrift.toml")
	writeFile(t, ancestor, "\n[guardian]\nenabled = true\n")
	if err := os.Chmod(ancestor, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ancestor, 0o600) })
	return project
}

// captureLog redirects the standard logger into a buffer for the duration of
// the test and restores stderr afterwards.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

// TestLoadProjectConfigWithDefaults_AppliesAndOverrides is the project-level
// half of #494: caller-supplied defaults (built from the global
// ~/.envdrift/guardian.toml) must fill every key the project's [guardian]
// section does not set, and project-set keys must win.
func TestLoadProjectConfigWithDefaults_AppliesAndOverrides(t *testing.T) {
	defaults := &GuardianConfig{
		Enabled:     false,
		IdleTimeout: 42 * time.Second,
		Patterns:    []string{"*.secret"},
		Exclude:     []string{".env.staging"},
		Notify:      false,
	}

	t.Run("no config file: defaults returned as-is", func(t *testing.T) {
		cfg, err := LoadProjectConfigWithDefaults(t.TempDir(), defaults)
		if err != nil {
			t.Fatalf("LoadProjectConfigWithDefaults: %v", err)
		}
		// One assertion per field: a single compound conditional both trips
		// CodeScene's complexity threshold and hides which field regressed.
		if cfg.Enabled {
			t.Error("Enabled = true, want the false default")
		}
		if cfg.IdleTimeout != 42*time.Second {
			t.Errorf("IdleTimeout = %v, want the 42s default", cfg.IdleTimeout)
		}
		if !reflect.DeepEqual(cfg.Patterns, []string{"*.secret"}) {
			t.Errorf("Patterns = %v, want the [*.secret] default", cfg.Patterns)
		}
		if !reflect.DeepEqual(cfg.Exclude, []string{".env.staging"}) {
			t.Errorf("Exclude = %v, want the [.env.staging] default", cfg.Exclude)
		}
		if cfg.Notify {
			t.Error("Notify = true, want the false default")
		}
	})

	t.Run("opt-in only project inherits defaults", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "envdrift.toml"),
			[]byte("[guardian]\nenabled = true\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadProjectConfigWithDefaults(dir, defaults)
		if err != nil {
			t.Fatalf("LoadProjectConfigWithDefaults: %v", err)
		}
		if !cfg.Enabled {
			t.Error("project enabled=true lost")
		}
		if cfg.IdleTimeout != 42*time.Second {
			t.Errorf("IdleTimeout = %v, want the 42s default", cfg.IdleTimeout)
		}
		if !reflect.DeepEqual(cfg.Patterns, []string{"*.secret"}) {
			t.Errorf("Patterns = %v, want the [*.secret] default", cfg.Patterns)
		}
		if cfg.Notify {
			t.Error("Notify = true, want the false default")
		}
	})

	t.Run("project keys override defaults", func(t *testing.T) {
		dir := t.TempDir()
		toml := "[guardian]\nenabled = true\nidle_timeout = \"9m\"\nnotify = true\n"
		if err := os.WriteFile(filepath.Join(dir, "envdrift.toml"), []byte(toml), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadProjectConfigWithDefaults(dir, defaults)
		if err != nil {
			t.Fatalf("LoadProjectConfigWithDefaults: %v", err)
		}
		if cfg.IdleTimeout != 9*time.Minute || !cfg.Notify {
			t.Errorf("project overrides lost: %+v", cfg)
		}
		// Unset keys still come from the defaults.
		if !reflect.DeepEqual(cfg.Exclude, []string{".env.staging"}) {
			t.Errorf("Exclude = %v, want the default", cfg.Exclude)
		}
	})

	t.Run("nil defaults fall back to package defaults", func(t *testing.T) {
		cfg, err := LoadProjectConfigWithDefaults(t.TempDir(), nil)
		if err != nil {
			t.Fatalf("LoadProjectConfigWithDefaults: %v", err)
		}
		if cfg.IdleTimeout != DefaultIdleTimeout || !reflect.DeepEqual(cfg.Patterns, DefaultPatterns) {
			t.Errorf("nil defaults must mean DefaultGuardianConfig, got %+v", cfg)
		}
	})
}

// TestLoadProjectConfigWithDefaults_DoesNotMutateDefaults guards the clone:
// per-project parsing (including the vault env_file pattern append) must never
// write through to the shared defaults value the guardian reuses for every
// project.
func TestLoadProjectConfigWithDefaults_DoesNotMutateDefaults(t *testing.T) {
	defaults := &GuardianConfig{
		Enabled:     false,
		IdleTimeout: 42 * time.Second,
		Patterns:    []string{"*.secret"},
		Exclude:     []string{".env.staging"},
		Notify:      false,
	}

	dir := t.TempDir()
	toml := `[guardian]
enabled = true

[[vault.sync.mappings]]
env_file = "postgresql.env"
`
	if err := os.WriteFile(filepath.Join(dir, "envdrift.toml"), []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadProjectConfigWithDefaults(dir, defaults)
	if err != nil {
		t.Fatalf("LoadProjectConfigWithDefaults: %v", err)
	}
	if !reflect.DeepEqual(cfg.Patterns, []string{"*.secret", "postgresql.env"}) {
		t.Errorf("vault env_file not appended to inherited patterns: %v", cfg.Patterns)
	}

	if !reflect.DeepEqual(defaults.Patterns, []string{"*.secret"}) {
		t.Errorf("defaults.Patterns mutated by project load: %v", defaults.Patterns)
	}
	if !reflect.DeepEqual(defaults.Exclude, []string{".env.staging"}) {
		t.Errorf("defaults.Exclude mutated by project load: %v", defaults.Exclude)
	}
}

// TestLoadAllProjectConfigsWithDefaults mirrors TestLoadAllProjectConfigs for
// the defaults-aware variant: disabled/unconfigured projects are excluded and
// enabled ones carry the supplied defaults.
func TestLoadAllProjectConfigsWithDefaults(t *testing.T) {
	defaults := &GuardianConfig{
		IdleTimeout: 42 * time.Second,
		Patterns:    []string{"*.secret"},
		Exclude:     []string{".env.staging"},
	}

	enabled := t.TempDir()
	if err := os.WriteFile(filepath.Join(enabled, "envdrift.toml"),
		[]byte("[guardian]\nenabled = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	unconfigured := t.TempDir() // no config at all -> stays opted out

	configs, err := LoadAllProjectConfigsWithDefaults([]string{enabled, unconfigured}, defaults)
	if err != nil {
		t.Fatalf("LoadAllProjectConfigsWithDefaults: %v", err)
	}
	if len(configs) != 1 || configs[0].Path != enabled {
		t.Fatalf("want only the enabled project, got %+v", configs)
	}
	if configs[0].Guardian.IdleTimeout != 42*time.Second {
		t.Errorf("defaults not applied through LoadAll: %+v", configs[0].Guardian)
	}
}
