// Package guardian regression tests for #494: the documented global
// guardian.toml settings (idle_timeout, patterns, exclude, notify) must act as
// defaults for per-project configs instead of being dead config.
package guardian

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jainal09/envdrift-agent/internal/config"
	"github.com/jainal09/envdrift-agent/internal/registry"
)

// makeProjectWithToml creates a project dir containing the given envdrift.toml.
func makeProjectWithToml(t *testing.T, toml string) string {
	t.Helper()
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "envdrift.toml"), []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}
	return d
}

// TestGuardian_GlobalConfigDefaultsApplyToProjects is the #494 regression for
// the dead global settings: ~/.envdrift/guardian.toml documents idle_timeout,
// patterns, exclude and notify, but pre-fix only guardian.enabled was ever
// consumed — per-project watchers were built exclusively from hardcoded
// defaults (5m / [".env*"] / ...), so editing the documented global settings
// had zero effect. The global values must act as defaults for every registered
// project, overridden by the project's own [guardian] section.
func TestGuardian_GlobalConfigDefaultsApplyToProjects(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	// A project that opts in but configures nothing else: it must inherit the
	// global values, not the hardcoded package defaults.
	inheriting := makeProjectWithToml(t, "[guardian]\nenabled = true\n")

	// A project with its own overrides: those must win over the global values
	// for the keys it sets, while unset keys (exclude) still inherit.
	overriding := makeProjectWithToml(t, `[guardian]
enabled = true
idle_timeout = "9m"
patterns = ["*.custom"]
notify = true
`)

	cfg := config.DefaultConfig()
	cfg.Guardian.Enabled = true
	cfg.Guardian.IdleTimeout = 42 * time.Second
	cfg.Guardian.Patterns = []string{"*.secret"}
	cfg.Guardian.Exclude = []string{".env.staging"}
	cfg.Guardian.Notify = false

	g, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	g.loadProjects(&registry.Registry{Projects: []registry.ProjectEntry{
		{Path: inheriting, Added: "now"},
		{Path: overriding, Added: "now"},
	}})
	defer g.stopAllProjects()

	g.mu.RLock()
	inheritPW, okInherit := g.projects[inheriting]
	overridePW, okOverride := g.projects[overriding]
	g.mu.RUnlock()

	if !okInherit || !okOverride {
		t.Fatalf("projects not loaded: inherit=%v override=%v", okInherit, okOverride)
	}

	// The opted-in-only project inherits every global value.
	got := inheritPW.config
	if got.IdleTimeout != 42*time.Second {
		t.Errorf("global idle_timeout is dead: got %v, want 42s (#494)", got.IdleTimeout)
	}
	if !reflect.DeepEqual(got.Patterns, []string{"*.secret"}) {
		t.Errorf("global patterns are dead: got %v, want [*.secret] (#494)", got.Patterns)
	}
	if !reflect.DeepEqual(got.Exclude, []string{".env.staging"}) {
		t.Errorf("global exclude is dead: got %v, want [.env.staging] (#494)", got.Exclude)
	}
	if got.Notify {
		t.Errorf("global notify=false is dead: got notify=true (#494)")
	}

	// The overriding project keeps its own values for keys it sets...
	got = overridePW.config
	if got.IdleTimeout != 9*time.Minute {
		t.Errorf("project idle_timeout override lost: got %v, want 9m", got.IdleTimeout)
	}
	if !reflect.DeepEqual(got.Patterns, []string{"*.custom"}) {
		t.Errorf("project patterns override lost: got %v, want [*.custom]", got.Patterns)
	}
	if !got.Notify {
		t.Errorf("project notify=true override lost: got notify=false")
	}
	// ...and still inherits the global default for keys it does not set.
	if !reflect.DeepEqual(got.Exclude, []string{".env.staging"}) {
		t.Errorf("global exclude not inherited by overriding project: got %v", got.Exclude)
	}
}

// TestGuardian_GlobalEnabledDoesNotOptProjectsIn pins the boundary of the
// defaults inheritance: guardian.enabled in the GLOBAL config is the agent's
// master switch, not a per-project opt-in. A registered project without its
// own config must stay unwatched even when the global file says enabled=true.
func TestGuardian_GlobalEnabledDoesNotOptProjectsIn(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	unconfigured := t.TempDir() // registered, but no envdrift.toml at all

	cfg := config.DefaultConfig()
	cfg.Guardian.Enabled = true

	g, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	g.loadProjects(&registry.Registry{Projects: []registry.ProjectEntry{
		{Path: unconfigured, Added: "now"},
	}})
	defer g.stopAllProjects()

	g.mu.RLock()
	_, watched := g.projects[unconfigured]
	g.mu.RUnlock()
	if watched {
		t.Fatalf("global enabled=true must not opt in a project without its own [guardian] enabled = true")
	}
}
