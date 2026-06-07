// Package guardian tests.
package guardian

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jainal09/envdrift-agent/internal/config"
	"github.com/jainal09/envdrift-agent/internal/registry"
)

// writeRegistry writes ~/.envdrift/projects.json under the test HOME.
func writeRegistry(t *testing.T, home string, paths ...string) {
	t.Helper()
	dir := filepath.Join(home, ".envdrift")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var reg registry.Registry
	for _, p := range paths {
		reg.Projects = append(reg.Projects, registry.ProjectEntry{Path: p, Added: "now"})
	}
	data, err := json.Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "projects.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// makeProject creates a project dir with an enabled envdrift.toml.
func makeProject(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	toml := "[guardian]\nenabled = true\nidle_timeout = \"1s\"\n"
	if err := os.WriteFile(filepath.Join(d, "envdrift.toml"), []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}
	return d
}

// TestGuardian_Start_DisabledIsNoOp is the #348 G3 regression: when the global
// guardian switch is off, Start returns immediately (nil) without standing up
// a registry watcher or loading projects.
func TestGuardian_Start_DisabledIsNoOp(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	cfg := config.DefaultConfig()
	cfg.Guardian.Enabled = false // globally disabled

	g, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- g.Start(ctx) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start with Enabled=false should be a clean no-op, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start with Enabled=false should return immediately, but it blocked")
	}

	if g.registryWatcher != nil {
		t.Errorf("Start should not create a registry watcher when disabled")
	}
	g.mu.RLock()
	n := len(g.projects)
	g.mu.RUnlock()
	if n != 0 {
		t.Errorf("Start should not load projects when disabled, got %d", n)
	}
}
