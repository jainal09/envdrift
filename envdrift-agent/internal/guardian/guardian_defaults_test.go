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
	"github.com/jainal09/envdrift-agent/internal/project"
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

// TestGuardian_ReloadKeepsWatcherOnTransientConfigError is the #494 reload
// robustness regression (ironic for a robustness PR): when a registered
// project's envdrift.toml transiently fails to parse during a registry reload,
// its already-running watcher must NOT be stopped. Pre-fix loadEnabledConfigs
// dropped the failed project from the enabled set, so stopRemovedProjects tore
// its watcher down as if the project had been removed — a transient read/parse
// error silently stopped a healthy running watcher.
func TestGuardian_ReloadKeepsWatcherOnTransientConfigError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	proj := makeProjectWithToml(t, "[guardian]\nenabled = true\n")

	g, err := New(config.DefaultConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer g.stopAllProjects()

	reg := &registry.Registry{Projects: []registry.ProjectEntry{{Path: proj, Added: "now"}}}

	// Initial reload: the enabled project is watched.
	g.onRegistryChange(reg)
	g.mu.RLock()
	pw, watched := g.projects[proj]
	g.mu.RUnlock()
	if !watched {
		t.Fatal("project not watched after the initial reload")
	}

	// Corrupt the project's envdrift.toml so the config load fails on the next
	// reload, then reload again with the SAME registry (project still present).
	if err := os.WriteFile(filepath.Join(proj, "envdrift.toml"), []byte("[unclosed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Sanity: the corrupt file really does fail to load.
	if _, loadErr := project.LoadProjectConfigWithDefaults(proj, g.projectDefaults()); loadErr == nil {
		t.Fatal("test setup: corrupt envdrift.toml unexpectedly loaded without error")
	}

	g.onRegistryChange(reg)

	g.mu.RLock()
	pw2, stillWatched := g.projects[proj]
	g.mu.RUnlock()
	if !stillWatched {
		t.Fatal("a transient config parse error must not stop the running watcher (#494)")
	}
	if pw2 != pw {
		t.Error("the existing watcher must be kept as-is on a transient load error, not replaced")
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
