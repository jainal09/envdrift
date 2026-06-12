package registry

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoad_NoFile(t *testing.T) {
	// Create a temp directory and set HOME to it
	tmpDir := t.TempDir()
	// Set both HOME (Unix) and USERPROFILE (Windows) for cross-platform support
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)

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
	// Set both HOME (Unix) and USERPROFILE (Windows) for cross-platform support
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)

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
		t.Fatalf("Expected 2 projects, got %d", len(reg.Projects))
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

// writeRegistry writes a projects.json with the given paths under the test HOME.
func writeRegistry(t *testing.T, paths ...string) {
	t.Helper()
	dir := filepath.Dir(RegistryPath())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir registry dir: %v", err)
	}
	entries := make([]ProjectEntry, 0, len(paths))
	for _, p := range paths {
		entries = append(entries, ProjectEntry{Path: p, Added: "2025-01-01T00:00:00Z"})
	}
	data, _ := json.Marshal(Registry{Projects: entries})
	if err := os.WriteFile(RegistryPath(), data, 0o644); err != nil {
		t.Fatalf("write registry: %v", err)
	}
}

// waitForArmedTimer blocks until rw's debounce timer has been armed (a registry
// write was observed and scheduleReload ran) or fails the test after a deadline.
// It makes the "Stop() inside the debounce window" tests deterministic instead
// of relying on a fixed sleep.
func waitForArmedTimer(t *testing.T, rw *RegistryWatcher) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		rw.timerMu.Lock()
		armed := rw.debounceTimer != nil
		rw.timerMu.Unlock()
		if armed {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("debounce timer was not armed within the deadline")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestRegistryWatcher_StopIsIdempotent is the #413 regression: Stop() must be
// safe to call more than once. The bare close(rw.done) panicked with "close of
// closed channel" on a second call; the sync.Once guard makes it idempotent
// (mirroring Watcher.Stop from #362).
func TestRegistryWatcher_StopIsIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)

	rw, err := NewRegistryWatcher(func(*Registry) {})
	if err != nil {
		t.Fatalf("NewRegistryWatcher: %v", err)
	}
	if err := rw.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	rw.Stop()
	rw.Stop() // must not panic on the second call (#413)
}

// TestRegistryWatcher_ReloadAfterStopDoesNotFireOnChange is the #413 regression:
// a debounce reload that was already scheduled (its time.AfterFunc goroutine has
// fired and is about to call reload()) must NOT invoke onChange once Stop() has
// run. Previously Stop() neither cancelled the in-flight timer nor did reload()
// check a stopped flag, so a late reload re-added project watchers after the
// guardian tore them down — leaking fsnotify watchers/FDs and goroutines past
// shutdown.
//
// We model the already-fired-timer scenario directly: Stop() the watcher, then
// invoke reload() (exactly what the orphaned AfterFunc goroutine would do). On
// the unfixed code reload() runs onChange unconditionally; the fix makes reload()
// early-return when stopped is set.
func TestRegistryWatcher_ReloadAfterStopDoesNotFireOnChange(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)

	writeRegistry(t) // empty registry so Load() succeeds

	var onChangeCount int32
	rw, err := NewRegistryWatcher(func(*Registry) {
		atomic.AddInt32(&onChangeCount, 1)
	})
	if err != nil {
		t.Fatalf("NewRegistryWatcher: %v", err)
	}
	if err := rw.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Shut down, then simulate an AfterFunc goroutine that had already fired and
	// is now executing reload() after Stop() returned.
	rw.Stop()
	rw.reload()

	if n := atomic.LoadInt32(&onChangeCount); n != 0 {
		t.Fatalf("reload() after Stop() fired onChange %d time(s); want 0 (#413: leaked reload past shutdown)", n)
	}
}

// TestRegistryWatcher_NoOnChangeAfterStop exercises the same #413 guard through
// the real fsnotify path: arm the debounce via a registry write, Stop() inside
// the window, and assert onChange never lands after Stop. It is the end-to-end
// companion to the direct reload() test above.
func TestRegistryWatcher_NoOnChangeAfterStop(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping fs event test in short mode")
	}

	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)

	writeRegistry(t) // empty registry so initial Load() succeeds

	var afterStopFire int32
	stopped := make(chan struct{})

	rw, err := NewRegistryWatcher(func(*Registry) {
		select {
		case <-stopped:
			atomic.AddInt32(&afterStopFire, 1)
		default:
		}
	})
	if err != nil {
		t.Fatalf("NewRegistryWatcher: %v", err)
	}
	if err := rw.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Arm the 100ms debounce timer, then Stop() inside the window. Poll until the
	// timer is actually armed instead of sleeping a fixed duration: a fixed sleep
	// can race the fsnotify+debounce plumbing and let the test pass without ever
	// exercising the pending-debounce-after-Stop path this guards.
	writeRegistry(t, "/tmp/some/project")
	waitForArmedTimer(t, rw)
	close(stopped)
	rw.Stop()

	// Wait past the debounce so any leaked timer would have fired.
	time.Sleep(300 * time.Millisecond)

	if n := atomic.LoadInt32(&afterStopFire); n != 0 {
		t.Fatalf("onChange fired %d time(s) after Stop() (#413: leaked reload past shutdown)", n)
	}
}

// captureLog redirects the stdlib logger into a buffer for the duration of the
// test. The tests below drive registry code synchronously (no watcher
// goroutines are started), so reading the buffer afterwards does not race.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

// TestNewRegistryWatcher_CorruptRegistryRecovers is the #494 startup-path
// regression: a corrupt/truncated ~/.envdrift/projects.json made
// NewRegistryWatcher fail, guardian.Start return an error, and the process
// exit 1 — which launchd KeepAlive / systemd Restart=always turned into a
// perpetual crash-respawn loop. The watcher must instead log the parse error
// loudly, preserve the corrupt file at projects.json.bak, and continue with an
// empty registry.
func TestNewRegistryWatcher_CorruptRegistryRecovers(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)

	corrupt := []byte(`{"projects": [{"path": `)
	if err := os.MkdirAll(filepath.Dir(RegistryPath()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(RegistryPath(), corrupt, 0o644); err != nil {
		t.Fatal(err)
	}

	logBuf := captureLog(t)

	rw, err := NewRegistryWatcher(func(*Registry) {})
	if err != nil {
		t.Fatalf("NewRegistryWatcher must not fail on a corrupt registry (crash-respawn loop, #494): %v", err)
	}
	defer rw.Stop()

	reg := rw.GetRegistry()
	if reg == nil || len(reg.Projects) != 0 {
		t.Fatalf("expected an empty registry after corruption recovery, got %+v", reg)
	}

	// The recovery must be loud, not silent.
	if out := logBuf.String(); !strings.Contains(out, "empty registry") {
		t.Errorf("corruption recovery was silent; want a log line mentioning the empty-registry fallback, got: %q", out)
	}

	// The corrupt file must be preserved for the user to inspect/repair.
	backup, err := os.ReadFile(RegistryPath() + ".bak")
	if err != nil {
		t.Fatalf("corrupt registry was not preserved at projects.json.bak (#494): %v", err)
	}
	if string(backup) != string(corrupt) {
		t.Errorf("backup content mismatch: got %q, want %q", backup, corrupt)
	}
}

// TestRegistryWatcher_ReloadCorruptKeepsLastGoodAndLogs is the #494
// runtime-path regression: when projects.json becomes corrupt while the agent
// is running, reload() previously returned silently before any log statement —
// the agent kept watching a stale project set with zero diagnostics. The
// last-good registry must be kept AND the parse error must be logged.
func TestRegistryWatcher_ReloadCorruptKeepsLastGoodAndLogs(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)

	writeRegistry(t, "/some/project")

	var onChangeCount int32
	rw, err := NewRegistryWatcher(func(*Registry) {
		atomic.AddInt32(&onChangeCount, 1)
	})
	if err != nil {
		t.Fatalf("NewRegistryWatcher: %v", err)
	}

	// Corrupt the registry, then drive the debounce callback directly (what the
	// fsnotify path invokes); no watcher goroutine is needed.
	if err := os.WriteFile(RegistryPath(), []byte(`{"projects": [{`), 0o644); err != nil {
		t.Fatal(err)
	}

	logBuf := captureLog(t)
	rw.reload()

	reg := rw.GetRegistry()
	if len(reg.Projects) != 1 || reg.Projects[0].Path != "/some/project" {
		t.Fatalf("last-good registry was not kept after a corrupt reload: %+v", reg)
	}
	if n := atomic.LoadInt32(&onChangeCount); n != 0 {
		t.Fatalf("onChange fired %d time(s) for a corrupt reload; want 0", n)
	}

	// Pre-fix this path was completely silent (#494).
	if out := logBuf.String(); !strings.Contains(out, "last-good") {
		t.Errorf("corrupt runtime reload was silent; want a log line mentioning the kept last-good registry, got: %q", out)
	}
}
